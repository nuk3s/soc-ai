"""Discover a deployment's internal domain suffixes + bare hostnames from ES.

The Oracle egress sanitizer must redact a deployment's *own* internal
identifiers (its internal domain suffix, its bare hostnames) before a payload
leaves for the cloud second-opinion model. Those identifiers are arbitrary
per-LAN — hardcoding any guess is wrong and relying on the operator to
hand-configure means most deployments silently fail to redact. This module
**learns** them from Security Onion data and upserts them into the managed
``internal_identifier`` table as ``detected`` rows.

What it does, per scan (Increment 3 — suffixes + hosts + CIDRs):

1. Resolve the effective internal CIDR set (env config overlaid with the managed
   list) — "internal" means a ``source.ip`` in one of those CIDRs.
2. Aggregate four signals over the ``discovery_lookback_days`` window, each with
   a ``cardinality`` sub-agg on ``source.ip`` for the distinct-internal-host count.
   Every Zeek/DNS field is resolved ECS-first via the field-resolution layer
   (:mod:`soc_ai.so_client.fields`): on a modern grid the live field is
   ``dns.query.name`` / ``dns.resolved_ip``; on older SO and the synth fixtures
   it falls back to ``zeek.dns.*``. The signals:
   (a) ``host.name`` over internal-source events — what an internal host IS;
   (b) the DNS answer (``dns.resolved_ip``→``zeek.dns.answers``) of reverse-zone
   (``*.in-addr.arpa``/``*.ip6.arpa``) queries — the PTR FQDN of an internal IP,
   also what it IS;
   (c) a domain whose **resolved IP is internal** — the DNS query name
   (``dns.query.name``→``zeek.dns.query``) bucketed with a sub-terms over its
   resolved IP (``dns.resolved_ip``→``zeek.dns.answers``); a name that resolves
   to an address inside the effective internal CIDRs is the host's *forward*
   record, the STRONGEST internal-identity signal; and
   (d) the raw DNS query name over internal-source DNS events — what an internal
   host merely LOOKS UP. Signals (a), (b) and (c) are ASSOCIATED (a strong
   internal-identity signal); (d) is NOT (a weak signal, demoted at
   classification — see below). When SO's computed
   ``dns.highest_registered_domain`` is present it is PREFERRED as the suffix.
3. From each candidate FQDN derive the **registrable suffix** (the parent domain —
   the FQDN minus its leftmost label, e.g. ``dc01.corp.acme.com`` → ``.corp.acme.com``)
   and classify it. Single-label ``host.name`` values become bare-host candidates.
4. Classify each candidate to an ``initial_state`` (the safety-critical rule —
   see :func:`classify_suffix` / :func:`classify_host`) and ``upsert_detected``.
5. **CIDR discovery (suggest-first):** aggregate ``source.ip`` AND
   ``destination.ip`` over the window, keep RFC1918 private addresses NOT already
   covered by the effective CIDR set, cluster them into /24s, and suggest each /24
   carrying ≥ ``discovery_min_hosts`` distinct private IPs. A detected CIDR is
   ALWAYS upserted ``muted`` — a CIDR is two-directional (it flips hosts
   internal↔external, changing triage verdicts/enrichment), so it is NEVER
   auto-activated regardless of count. The operator un-mutes to apply it.

THE DISCRIMINATOR is **internal association**, not the TLD. A candidate seen ONLY
as an outbound ``zeek.dns.query`` (what internal hosts look up — e.g. the malware
CDN ``update-cdn.click`` or ``apple.com`` resolved by many hosts) is a weak signal
and is **NEVER** auto-activated. If it is a PUBLIC registrable domain it is now
**dropped entirely** (not even suggested) — a lookup-only public name is an
external service, not the deployment's own domain, and surfacing it is just
false-positive noise; the deployment's own domain is found via the associated
signals instead. A lookup-only *clearly-internal* name (reserved TLD / no public
form) still lands ``muted`` (a suggestion). This guarantees a benign — or
malicious — external lookup never becomes a silent redaction rule. The "public
TLD" test uses a **vendored IANA TLD snapshot** (``data/iana_tlds.txt``) so new
gTLDs (``click``/``top``/``xyz``/…) are recognised as public, not mistaken for
internal.

An ASSOCIATED candidate — seen as ``host.name`` or the PTR answer of an internal
IP (what an internal host IS) — activates when seen on ≥ ``discovery_min_hosts``
distinct internal hosts; below that it is a muted suggestion. This holds even when
the suffix is a public registrable domain: the deployment's own AD domain
``corp.acme.com`` (the internal hosts' own name) is provably internal via real
host.name signal and is eligible to auto-activate, whereas the same name seen only
as a lookup would not be. Reserved-default suffixes (``lan``/``local``/``corp``/
``internal``) are dropped (already covered by the sanitizer floor); reverse-zone
(``*.in-addr.arpa``/``*.ip6.arpa``) names are skipped (a pointer record is never a
host's identity).

Graceful degradation: a missing field / mapping or an ES error on one sub-query
is caught, recorded in ``summary.errors``, and the scan continues with whatever
other signal is available. Zero yield is a valid result — never crash the scan.

``upsert_detected`` only ever **adds/refreshes**; it preserves an operator's
mute/unmute across scans (a muted detected row is a tombstone).
"""

from __future__ import annotations

import functools
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from soc_ai.oracle.identifiers import effective_internal_identifiers
from soc_ai.so_client import fields
from soc_ai.so_client.fields import resolve_agg_field
from soc_ai.store.internal_identifiers import upsert_detected

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from soc_ai.config import Settings
    from soc_ai.oracle.identifiers import IpNetwork
    from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)

# Reserved / special-use TLDs that are never public. A suffix whose right-most
# label is one of these is "clearly internal" and may auto-activate.
# (RFC 6762 .local, RFC 8375 home.arpa, RFC 6761, plus the common ad-hoc
# special-use labels SO operators actually deploy.)
RESERVED_TLDS: frozenset[str] = frozenset(
    {"lan", "local", "internal", "corp", "home", "intranet", "alt", "arpa"}
)

# Reserved multi-label special-use suffixes (checked against the full suffix).
RESERVED_SUFFIXES: frozenset[str] = frozenset({"home.arpa"})

# Reserved-default suffixes already covered by the sanitizer floor
# (settings.oracle_internal_suffixes falls back to these). No point
# re-detecting them — drop the candidate. Stored without the leading dot here.
RESERVED_DEFAULT_SUFFIXES: frozenset[str] = frozenset({"lan", "local", "internal", "corp"})

# Vendored IANA TLD snapshot — the authoritative source for "is this a public
# (delegated) TLD?". A suffix whose registrable 2-label form ends in one of these
# is treated as a PUBLIC registrable domain and is NEVER auto-activated unless it
# is ALSO internal-associated (host.name/PTR of internal hosts). The full list
# (≈1.4k entries incl. new gTLDs like ``click``/``top``/``xyz`` and ``xn--*``
# punycode) ships in the wheel via ``packages=["soc_ai"]`` in pyproject.toml —
# the same mechanism that ships ``so_client/oql_fields.json``. Loaded + cached at
# first use (see :func:`_load_public_tlds`).
_IANA_TLDS_PATH = Path(__file__).parent / "data" / "iana_tlds.txt"

# Read-failure floor. If the vendored snapshot is missing/unreadable we fall back
# to this small built-in core set so the public-domain safety gate NEVER silently
# disappears (fail-safe: more domains classed public, never fewer). These are the
# common public TLDs that show up in real DNS noise.
_PUBLIC_TLDS_FALLBACK: frozenset[str] = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "io",
        "co",
        "us",
        "uk",
        "de",
        "fr",
        "nl",
        "eu",
        "ca",
        "au",
        "jp",
        "cn",
        "ru",
        "br",
        "in",
        "it",
        "es",
        "se",
        "ch",
        "be",
        "info",
        "biz",
        "app",
        "dev",
        "cloud",
        "ai",
        "me",
        "tv",
        "xyz",
    }
)


@functools.cache
def _load_public_tlds(path: Path = _IANA_TLDS_PATH) -> frozenset[str]:
    """Load the vendored IANA TLD snapshot (lowercased, comments stripped).

    Cached for the process lifetime. On a missing/unreadable file, fall back to
    the small built-in core set so the public-domain safety gate NEVER silently
    disappears (fail-safe: more domains classed public, never fewer).
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        _LOGGER.warning(
            "discovery: vendored IANA TLD list unreadable at %s; using core fallback",
            path,
        )
        return _PUBLIC_TLDS_FALLBACK
    tlds = {ln.strip().lower() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")}
    return frozenset(tlds) or _PUBLIC_TLDS_FALLBACK


@dataclass
class DiscoverySummary:
    """Outcome of one discovery scan (returned to the CLI / scan-now endpoint)."""

    scanned_events: int = 0
    internal_hosts_seen: int = 0
    suffixes_found: int = 0
    hosts_found: int = 0
    suffixes_active: int = 0
    suffixes_muted: int = 0
    cidrs_found: int = 0
    cidrs_suggested: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class _Candidate:
    """An aggregated suffix/host candidate before classification."""

    value: str  # normalized-ish value WITHOUT a leading dot for suffixes
    host_count: int = 0
    event_count: int = 0
    samples: list[str] = field(default_factory=list)
    # Seen as host.name OR as the PTR answer of an internal IP — i.e. what an
    # internal host *is*, not merely what it looked up. The strong internal
    # signal. A query-only candidate (associated=False) is never auto-active.
    associated: bool = False

    def merge_sample(self, fqdn: str) -> None:
        if fqdn and fqdn not in self.samples and len(self.samples) < 5:
            self.samples.append(fqdn)


_AGG_SIZE = 500  # cap distinct FQDN buckets per query
_SAMPLE_LIMIT = 5


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested directly)
# ---------------------------------------------------------------------------


def derive_suffix(fqdn: str) -> str | None:
    """Derive the registrable suffix (parent domain) of *fqdn*, sans leading dot.

    Choice: the parent domain — the FQDN minus its left-most label. So
    ``dc01.corp.acme.com`` → ``corp.acme.com`` and ``host.lan`` → ``lan``.
    A single-label value (no dot) has no suffix → ``None`` (it's a bare host,
    handled separately). The trailing-dot root form is stripped.

    Returns the suffix lowercased without a leading dot, or ``None``.
    """
    name = fqdn.strip().rstrip(".").lower()
    if not name or "." not in name:
        return None
    # parent = everything after the first label
    parent = name.split(".", 1)[1]
    if not parent or ("." in parent and parent.startswith(".")):
        return None
    return parent or None


def registrable_form(suffix: str) -> str:
    """The registrable 2-label form of *suffix* (sans leading dot), for the
    public-TLD check. ``corp.acme.com`` → ``acme.com``; ``acme.com`` → ``acme.com``;
    ``lan`` → ``lan``.
    """
    labels = suffix.strip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def is_public_registrable(suffix: str) -> bool:
    """True iff *suffix* looks like a PUBLIC registrable domain.

    A suffix is public iff it has a public registrable 2-label form — i.e. its
    right-most label is a known public TLD AND there is a label in front of it
    (a registrable ``name.tld``). A bare public TLD on its own (``com``) or a
    reserved/special-use TLD (``lan``) is NOT public-registrable here.
    """
    s = suffix.strip(".").lower()
    if not s or "." not in s:
        return False  # single label — not a registrable public domain
    if s in RESERVED_SUFFIXES:
        return False
    tld = s.rsplit(".", 1)[-1]
    if tld in RESERVED_TLDS:
        return False
    return tld in _load_public_tlds()


def is_clearly_internal_suffix(suffix: str) -> bool:
    """True iff *suffix* is clearly internal (reserved TLD / no public form).

    Clearly internal = its effective TLD is a reserved/special-use one, OR it is
    single-label, OR it has no public registrable form. The inverse of
    :func:`is_public_registrable` for multi-label names, plus single-label names.
    """
    s = suffix.strip(".").lower()
    if not s:
        return False
    if s in RESERVED_SUFFIXES:
        return True
    if "." not in s:
        return True  # single-label suffix (e.g. "lan") — never public
    tld = s.rsplit(".", 1)[-1]
    if tld in RESERVED_TLDS:
        return True
    # multi-label: internal iff NOT a public registrable domain
    return not is_public_registrable(s)


def classify_suffix(candidate: _Candidate, min_hosts: int) -> str | None:
    """Return the ``initial_state`` for a suffix candidate, or ``None`` to drop.

    THE DISCRIMINATOR is **internal association** — whether the suffix was seen
    as ``host.name`` / the PTR answer of an internal IP (what internal hosts
    *ARE*), not merely as an outbound ``zeek.dns.query`` (what they *look up*).

    The decision table:

    * reserved-default suffix (.lan/.local/.internal/.corp) → drop (``None``) —
      already covered by the sanitizer floor.
    * NOT associated (query-only) + PUBLIC registrable → DROP (``None``). A public
      domain an internal host merely looked up (``apple.com``, ``google.com``,
      ``update-cdn.click``) is almost certainly an EXTERNAL service, not the
      deployment's own domain — surfacing it (even as a muted suggestion) is just
      false-positive noise. The deployment's own domain is detected via the
      associated signals (host.name / PTR / forward-internal), so dropping the
      lookup-only public case costs no real detection.
    * NOT associated (query-only) + clearly-internal (reserved TLD / no public
      form, e.g. ``printers.lan``) → ``"muted"``. A lookup-only internal-looking
      name is a weak suggestion worth surfacing, never auto-active.
    * associated + public registrable (e.g. the org's own AD domain
      ``corp.acme.com``, seen as host.name of internal hosts) → ``"active"`` at/
      above *min_hosts*, else ``"muted"``. It is provably the deployment's own
      domain, so it is eligible despite the public TLD.
    * associated + clearly-internal → ``"active"`` at/above *min_hosts*, else
      ``"muted"`` (unchanged behaviour).

    THE SAFETY CONTRACT (a benign external lookup never becomes a silent
    redaction rule) is preserved and tightened: a non-associated public domain is
    now dropped outright, not even suggested. An associated public domain is the
    deployment's own name and may activate from real host.name/PTR signal.
    """
    s = candidate.value.strip(".").lower()
    if not s:
        return None
    if s in RESERVED_DEFAULT_SUFFIXES:
        return None  # already a reserved default — no point re-detecting
    # Query-only signal: what internal hosts LOOK UP, not what they ARE.
    if not candidate.associated:
        # A public registrable domain seen only as a lookup is an external
        # service (apple.com, google.com) — drop it, don't even suggest it.
        if is_public_registrable(s):
            return None
        # A clearly-internal lookup-only name is a weak suggestion (never active).
        return "muted"
    # Associated (host.name / PTR-internal): both a public registrable parent
    # (the org's own AD domain) and a clearly-internal suffix are eligible to
    # activate from real internal-identity signal.
    if is_public_registrable(s) or is_clearly_internal_suffix(s):
        return "active" if candidate.host_count >= min_hosts else "muted"
    # Fallthrough (shouldn't happen): be conservative, suggest only.
    return "muted"


def classify_host(candidate: _Candidate, min_hosts: int) -> str:
    """Return the ``initial_state`` for a bare-hostname candidate.

    A bare hostname is clearly internal only if it is internal-ASSOCIATED — seen
    as ``host.name`` or the PTR answer of an internal IP. A bare name seen only
    as an outbound ``zeek.dns.query`` is a weak, query-only signal and is muted.
    An associated bare host is active at/above *min_hosts*, else muted.
    """
    if not candidate.associated:
        return "muted"
    return "active" if candidate.host_count >= min_hosts else "muted"


def _internal_source_filter(cidrs: list[IpNetwork]) -> dict[str, Any]:
    """Build an ES filter clause selecting events whose ``source.ip`` ∈ *cidrs*.

    An OR (``should``) over per-CIDR ``term`` clauses on ``source.ip`` — ES
    matches an IP-typed or keyword ``source.ip`` against a CIDR string. Returns
    a ``bool`` with ``minimum_should_match: 1``. Empty *cidrs* → a never-match.
    """
    if not cidrs:
        return {"bool": {"must_not": {"match_all": {}}}}
    shoulds = [{"term": {"source.ip": str(net)}} for net in cidrs]
    return {"bool": {"should": shoulds, "minimum_should_match": 1}}


def _base_query(cidrs: list[IpNetwork], lookback_days: int) -> dict[str, Any]:
    """Internal-source events within the lookback window."""
    return {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": f"now-{lookback_days}d"}}},
                _internal_source_filter(cidrs),
            ]
        }
    }


def _terms_with_card(field_name: str) -> dict[str, Any]:
    """Terms agg on *field_name* with a distinct-internal-source-IP cardinality
    sub-agg (``distinct_hosts``)."""
    return {
        "candidates": {
            "terms": {"field": field_name, "size": _AGG_SIZE},
            "aggs": {"distinct_hosts": {"cardinality": {"field": "source.ip"}}},
        }
    }


def _terms_with_resolved(query_field: str, resolved_field: str) -> dict[str, Any]:
    """Terms agg on the DNS query name with a resolved-IP sub-terms + a
    distinct-internal-source-IP cardinality sub-agg (``distinct_hosts``).

    Used by the resolved-internal signal: each query-name bucket carries the
    addresses it resolved to (``resolved_ips``) so we can tell whether the name
    is an internal forward record.
    """
    reg_field = fields.DNS_REGISTERED_DOMAIN[0]
    return {
        "candidates": {
            "terms": {"field": query_field, "size": _AGG_SIZE},
            "aggs": {
                "distinct_hosts": {"cardinality": {"field": "source.ip"}},
                "resolved_ips": {"terms": {"field": resolved_field, "size": 10}},
                # SO's computed registrable parent — PREFERRED for suffix
                # derivation when present (an empty/unmapped agg is just absent
                # on older SO, and we fall back to derive_suffix).
                "registered_domain": {"terms": {"field": reg_field, "size": 1}},
            },
        }
    }


def _is_internal_ip(value: str, cidrs: list[IpNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in cidrs)


# ---------------------------------------------------------------------------
# CIDR discovery (Increment 3 — SUGGEST-FIRST)
# ---------------------------------------------------------------------------
#
# A discovered CIDR is two-directional: activating it flips hosts inside it
# internal↔external, which changes triage verdicts and enrichment. That is NOT
# fail-safe, so a detected CIDR is NEVER auto-activated regardless of volume —
# it ALWAYS lands ``muted`` (a suggestion the operator un-mutes to apply). The
# always-muted guarantee lives in :func:`run_discovery` (the only call site) and
# is asserted directly by the safety test.

# Aggregate this many distinct source/destination IPs per query before
# clustering — a generous cap so a busy /24 is fully represented.
_IP_AGG_SIZE = 2000


@dataclass
class _CidrCandidate:
    """A /24 network aggregated from RFC1918 IPs before suggesting it."""

    network: str  # canonical "10.50.0.0/24"
    hosts: set[str] = field(default_factory=set)  # distinct private IPs in the /24
    event_count: int = 0

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    def sample(self) -> list[str]:
        return sorted(self.hosts)[:_SAMPLE_LIMIT]


# The three RFC1918 private-use IPv4 blocks. Deliberately NARROWER than
# ``IPv4Address.is_private`` (which also covers loopback 127/8, link-local
# 169.254/16, CGNAT 100.64/10, etc.) — CIDR discovery suggests only genuine
# RFC1918 LAN subnets, never a host's loopback or a link-local self-address.
_RFC1918_BLOCKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def _is_rfc1918(value: str) -> ipaddress.IPv4Address | None:
    """Return the parsed address iff *value* is an RFC1918 private IPv4 address.

    RFC1918 = 10/8, 172.16/12, 192.168/16 ONLY. Anything else (public, loopback,
    link-local, CGNAT, IPv6, garbage) → ``None``. We restrict CIDR discovery to
    these three blocks so a public — or a non-LAN special-use — address never
    gets suggested as an internal subnet.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not isinstance(addr, ipaddress.IPv4Address):
        return None
    return addr if any(addr in block for block in _RFC1918_BLOCKS) else None


def _slash24(addr: ipaddress.IPv4Address) -> ipaddress.IPv4Network:
    """The /24 network containing *addr* (e.g. 10.50.0.7 → 10.50.0.0/24)."""
    return ipaddress.IPv4Network(f"{addr}/24", strict=False)


def _ingest_ip_buckets(
    buckets: list[dict[str, Any]],
    covered: list[IpNetwork],
    candidates: dict[str, _CidrCandidate],
) -> None:
    """Fold terms buckets of IP values into per-/24 candidate clusters.

    Keeps only RFC1918 IPs NOT already covered by the effective CIDR set
    (*covered*), clusters each into its /24, and accumulates the distinct IPs +
    event volume. A bucket key that is public / non-IPv4 / already-covered is
    skipped — discovery only ever SUGGESTS genuinely-new internal subnets.
    """
    for bucket in buckets:
        key = str(bucket.get("key", "")).strip()
        if not key:
            continue
        addr = _is_rfc1918(key)
        if addr is None:
            continue
        if any(addr in net for net in covered):
            continue  # already an internal CIDR — nothing to suggest
        net = _slash24(addr)
        cand = candidates.setdefault(str(net), _CidrCandidate(network=str(net)))
        cand.hosts.add(str(addr))
        cand.event_count += int(bucket.get("doc_count", 0))


def _cidr_evidence(cand: _CidrCandidate) -> dict[str, Any]:
    return {
        "host_count": cand.host_count,
        "event_count": cand.event_count,
        "first_seen": None,
        "last_seen": None,
        "sample": cand.sample(),
    }


# ---------------------------------------------------------------------------
# ES querying (one sub-query per signal; each degrades independently)
# ---------------------------------------------------------------------------


async def _aggregate_field(
    es_client: ElasticClient,
    index: str,
    query: dict[str, Any],
    field_name: str,
    summary: DiscoverySummary,
) -> list[dict[str, Any]]:
    """Run one terms+cardinality aggregation; return its buckets (or []).

    On any ES error / missing-field, records the error in *summary* and returns
    an empty list so the caller continues with other signal.
    """
    try:
        res = await es_client.search(
            index,
            query,
            size=0,
            aggs=_terms_with_card(field_name),
            track_total_hits=True,
        )
    except Exception as exc:
        summary.errors.append(f"{field_name}: {type(exc).__name__}: {exc}")
        _LOGGER.warning("discovery: aggregation on %s failed: %s", field_name, exc)
        return []
    summary.scanned_events += int(res.total)
    aggs = res.aggregations or {}
    cand = aggs.get("candidates") or {}
    buckets = cand.get("buckets") or []
    return list(buckets)


async def _aggregate_resolved_internal(
    es_client: ElasticClient,
    index: str,
    query: dict[str, Any],
    query_field: str,
    resolved_field: str,
    summary: DiscoverySummary,
) -> list[dict[str, Any]]:
    """Run the forward-record aggregation (query name + resolved-IP sub-terms).

    Each returned bucket is a DNS query name carrying a ``resolved_ips`` sub-agg
    (and SO's ``registered_domain`` when present). On any ES error / missing
    field, records the error in *summary* and returns ``[]`` so the scan
    continues (zero yield is valid).
    """
    try:
        res = await es_client.search(
            index,
            query,
            size=0,
            aggs=_terms_with_resolved(query_field, resolved_field),
            track_total_hits=True,
        )
    except Exception as exc:
        summary.errors.append(f"{query_field}+resolved: {type(exc).__name__}: {exc}")
        _LOGGER.warning("discovery: resolved-internal aggregation failed: %s", exc)
        return []
    summary.scanned_events += int(res.total)
    candidates = (res.aggregations or {}).get("candidates") or {}
    return list(candidates.get("buckets") or [])


async def _aggregate_ip_field(
    es_client: ElasticClient,
    index: str,
    query: dict[str, Any],
    field_name: str,
    summary: DiscoverySummary,
) -> list[dict[str, Any]]:
    """Run one plain terms aggregation over an IP field; return buckets (or []).

    Used by CIDR discovery to enumerate the distinct ``source.ip`` /
    ``destination.ip`` values seen in the window. No cardinality sub-agg (we
    cluster the keys ourselves). On any ES error / missing field, records the
    error in *summary* and returns ``[]`` so the scan continues (zero yield is
    valid).
    """
    try:
        res = await es_client.search(
            index,
            query,
            size=0,
            aggs={"candidates": {"terms": {"field": field_name, "size": _IP_AGG_SIZE}}},
            track_total_hits=True,
        )
    except Exception as exc:
        summary.errors.append(f"{field_name}: {type(exc).__name__}: {exc}")
        _LOGGER.warning("discovery: IP aggregation on %s failed: %s", field_name, exc)
        return []
    aggs = res.aggregations or {}
    cand = aggs.get("candidates") or {}
    buckets = cand.get("buckets") or []
    return list(buckets)


async def _discover_name_signals(
    es_client: ElasticClient,
    index: str,
    cidrs: list[IpNetwork],
    lookback: int,
    summary: DiscoverySummary,
) -> tuple[dict[str, _Candidate], dict[str, _Candidate]]:
    """Aggregate the four name signals into ``(suffixes, hosts)`` candidate maps.

    DNS field names are resolved ECS-first against THIS deployment (modern grid →
    ``dns.query.name`` / ``dns.resolved_ip``; older SO / synth → ``zeek.dns.*``).
    The signals, in increasing-then-decreasing strength:

    * (a) ``host.name`` over internal-source events → ASSOCIATED (what a host IS).
    * (b) DNS answers of reverse-zone (``*.in-addr.arpa``/``*.ip6.arpa``) queries
      → ASSOCIATED (the PTR FQDN of an internal IP).
    * (c) forward records whose resolved IP is INTERNAL → ASSOCIATED (STRONGEST:
      the host's own forward record; SO's ``dns.highest_registered_domain`` is
      preferred as the suffix when present).
    * (d) raw outbound DNS query names → NOT associated (weak: what hosts LOOK UP,
      demoted so a mere lookup never auto-activates).

    The ``event.dataset`` gate stays ``zeek.dns`` — dataset VALUES remain
    ``zeek.*`` on modern SO even when field NAMES are ECS.
    """
    suffixes: dict[str, _Candidate] = {}
    hosts: dict[str, _Candidate] = {}

    dns_query_field = await resolve_agg_field(es_client, index, fields.DNS_QUERY)
    dns_resolved_field = await resolve_agg_field(es_client, index, fields.DNS_RESOLVED_IP)

    # (a) host.name.
    host_query = _base_query(cidrs, lookback)
    host_buckets = await _aggregate_field(es_client, index, host_query, "host.name", summary)
    _ingest_buckets(host_buckets, cidrs, suffixes, hosts, associated=True)

    # (b) PTR answers for internal IPs (reverse zone).
    ptr_query = _base_query(cidrs, lookback)
    ptr_query["bool"]["filter"].append({"term": {"event.dataset": "zeek.dns"}})
    ptr_query["bool"]["filter"].append(
        {
            "bool": {
                "should": [
                    {"wildcard": {dns_query_field: "*.in-addr.arpa"}},
                    {"wildcard": {dns_query_field: "*.ip6.arpa"}},
                ],
                "minimum_should_match": 1,
            }
        }
    )
    ptr_buckets = await _aggregate_field(es_client, index, ptr_query, dns_resolved_field, summary)
    _ingest_buckets(ptr_buckets, cidrs, suffixes, hosts, associated=True)

    # (c) forward records that resolve INTERNAL (strongest signal).
    resolved_query = _base_query(cidrs, lookback)
    resolved_query["bool"]["filter"].append({"term": {"event.dataset": "zeek.dns"}})
    resolved_buckets = await _aggregate_resolved_internal(
        es_client, index, resolved_query, dns_query_field, dns_resolved_field, summary
    )
    _ingest_resolved_internal_buckets(resolved_buckets, cidrs, suffixes, hosts)

    # (d) raw outbound DNS query names (weak, not associated).
    dns_query = _base_query(cidrs, lookback)
    dns_query["bool"]["filter"].append({"term": {"event.dataset": "zeek.dns"}})
    dns_buckets = await _aggregate_field(es_client, index, dns_query, dns_query_field, summary)
    _ingest_buckets(dns_buckets, cidrs, suffixes, hosts, associated=False)

    return suffixes, hosts


async def _discover_cidrs(
    es_client: ElasticClient,
    index: str,
    cidrs: list[IpNetwork],
    lookback: int,
    summary: DiscoverySummary,
) -> dict[str, _CidrCandidate]:
    """Enumerate candidate new private /24s for SUGGEST-FIRST CIDR discovery.

    Two signals, folded into the SAME /24 clustering:

    * Raw ``source.ip`` / ``destination.ip`` volume over the window (NOT scoped
      to internal-source — we're hunting NEW private subnets). Keep RFC1918
      addresses not already covered by the effective CIDR set.
    * Corroboration from Zeek's own local-endpoint flags: on a modern grid
      ``connection.local.originator``=true marks ``source.ip`` as a local
      (internal) endpoint and ``connection.local.responder``=true marks
      ``destination.ip`` as local (``zeek.conn.local_orig``/``local_resp`` on
      older SO). These are Zeek's judgement of which side is on the monitored
      network.

    Every surviving /24 is upserted MUTED by the caller regardless of signal — a
    CIDR is two-directional, so it is never auto-activated.
    """
    candidates: dict[str, _CidrCandidate] = {}
    window_query = {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{lookback}d"}}}]}}
    for ip_field in ("source.ip", "destination.ip"):
        ip_buckets = await _aggregate_ip_field(es_client, index, window_query, ip_field, summary)
        _ingest_ip_buckets(ip_buckets, cidrs, candidates)

    local_orig_field = await resolve_agg_field(es_client, index, fields.CONN_LOCAL_ORIG)
    local_resp_field = await resolve_agg_field(es_client, index, fields.CONN_LOCAL_RESP)
    for flag_field, ip_field in (
        (local_orig_field, "source.ip"),
        (local_resp_field, "destination.ip"),
    ):
        flagged_query = {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{lookback}d"}}},
                    {"term": {flag_field: True}},
                ]
            }
        }
        flagged_buckets = await _aggregate_ip_field(
            es_client, index, flagged_query, ip_field, summary
        )
        _ingest_ip_buckets(flagged_buckets, cidrs, candidates)
    return candidates


def _is_reverse_zone_name(name: str) -> bool:
    """True iff *name* is a reverse-DNS (PTR) zone name, not a host FQDN.

    Reverse lookups carry an ``*.in-addr.arpa`` / ``*.ip6.arpa`` query *name* —
    that is a pointer record, never a host's own FQDN. Such names must never
    become an internal identifier (``arpa`` is a reserved TLD, so a bare
    ``7.0.10.10.in-addr.arpa`` would otherwise classify "clearly internal").
    """
    n = name.strip(".").lower()
    return (
        n in ("arpa", "in-addr.arpa", "ip6.arpa")
        or n.endswith(".in-addr.arpa")
        or n.endswith(".ip6.arpa")
    )


def _ingest_buckets(
    buckets: list[dict[str, Any]],
    cidrs: list[IpNetwork],
    suffixes: dict[str, _Candidate],
    hosts: dict[str, _Candidate],
    *,
    associated: bool,
) -> None:
    """Fold terms buckets into suffix/host candidate maps.

    Each bucket key is an FQDN (or bare host). Multi-label → a suffix candidate
    keyed by its parent domain; single-label → a bare-host candidate. The
    ``distinct_hosts`` cardinality is the distinct-internal-source-IP count
    behind that name; we accumulate it per derived suffix/host (an upper-bound
    approximation across sibling FQDNs — see module note).

    *associated* marks the provenance of this signal: ``True`` for host.name /
    PTR-answer buckets (what internal hosts ARE — a strong internal signal),
    ``False`` for raw outbound ``zeek.dns.query`` buckets (what they LOOK UP — a
    weak signal). The flag is OR-ed into each candidate so a domain seen via both
    paths inherits the strong signal; ``host_count`` / ``event_count`` still
    accumulate across both for evidence volume.
    """
    for bucket in buckets:
        key = str(bucket.get("key", "")).strip()
        if not key:
            continue
        doc_count = int(bucket.get("doc_count", 0))
        distinct = bucket.get("distinct_hosts") or {}
        host_count = int(distinct.get("value", 0)) or 0
        # Drop a key that is itself an IP (host.name sometimes carries the IP).
        if _is_internal_ip(key, cidrs):
            continue
        # Drop reverse-zone (PTR) names — a pointer record, never a host FQDN.
        if _is_reverse_zone_name(key):
            continue
        suffix = derive_suffix(key)
        if suffix is None:
            # single-label → bare host candidate (case preserved for the value)
            host_key = key
            cand = hosts.setdefault(host_key, _Candidate(value=host_key))
            cand.associated = cand.associated or associated
            cand.host_count += host_count
            cand.event_count += doc_count
            cand.merge_sample(key)
            continue
        # A derived suffix that is itself a reverse zone (e.g. parent of
        # ``a.7.0.10.10.in-addr.arpa``) must never become an identifier either.
        if _is_reverse_zone_name(suffix):
            continue
        cand = suffixes.setdefault(suffix, _Candidate(value=suffix))
        cand.associated = cand.associated or associated
        cand.host_count += host_count
        cand.event_count += doc_count
        cand.merge_sample(key)


def _ingest_resolved_internal_buckets(
    buckets: list[dict[str, Any]],
    cidrs: list[IpNetwork],
    suffixes: dict[str, _Candidate],
    hosts: dict[str, _Candidate],
) -> None:
    """Fold DNS-query buckets carrying a resolved-IP sub-agg.

    Each bucket key is a DNS query NAME; its ``resolved_ips`` sub-terms are the
    addresses that name resolved to. A name that resolves to an address inside
    *cidrs* is the deployment's own *forward* record (``app.corp.acme.com`` →
    ``10.50.0.7``) — the STRONGEST internal-identity signal — so it is ingested
    ASSOCIATED. A name whose resolved IPs are all external is ignored here (it is
    still picked up as a weak query-only signal by the raw-query aggregation).

    When SO's computed registrable parent (``dns.highest_registered_domain``) is
    present on the bucket it is PREFERRED as the suffix over the
    label-stripping :func:`derive_suffix` heuristic.
    """
    for bucket in buckets:
        key = str(bucket.get("key", "")).strip()
        if not key:
            continue
        resolved = bucket.get("resolved_ips") or {}
        ip_buckets = resolved.get("buckets") or []
        resolves_internal = any(
            _is_internal_ip(str(ib.get("key", "")).strip(), cidrs) for ib in ip_buckets
        )
        if not resolves_internal:
            continue
        # PREFER SO's computed registrable domain for the suffix when present.
        reg = bucket.get("registered_domain") or {}
        reg_buckets = reg.get("buckets") or []
        reg_domain = str(reg_buckets[0].get("key", "")).strip() if reg_buckets else ""
        if reg_domain and not _is_reverse_zone_name(reg_domain) and "." in reg_domain:
            distinct = bucket.get("distinct_hosts") or {}
            host_count = int(distinct.get("value", 0)) or 0
            cand = suffixes.setdefault(reg_domain.lower(), _Candidate(value=reg_domain.lower()))
            cand.associated = True
            cand.host_count += host_count
            cand.event_count += int(bucket.get("doc_count", 0))
            cand.merge_sample(key)
            continue
        # Re-use the standard fold as a single ASSOCIATED bucket so suffix
        # derivation, reverse-zone / IP-key dropping, and accounting stay
        # identical to the other signals.
        _ingest_buckets([bucket], cidrs, suffixes, hosts, associated=True)


def _evidence(cand: _Candidate) -> dict[str, Any]:
    return {
        "host_count": cand.host_count,
        "event_count": cand.event_count,
        "first_seen": None,
        "last_seen": None,
        "sample": cand.samples[:_SAMPLE_LIMIT],
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def run_discovery(
    es_client: ElasticClient,
    db_sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> DiscoverySummary:
    """Scan ES for internal suffixes + bare hostnames and upsert detected rows.

    Resolves the effective internal CIDRs, resolves the live DNS field names
    ECS-first, then aggregates ``host.name`` (associated), reverse-zone PTR DNS
    answers (associated), forward records that resolve to an internal IP
    (associated — the strongest signal) + raw DNS query names (not associated)
    over internal-source events in the lookback window, classifies each
    candidate, and upserts via :func:`upsert_detected`. CIDR discovery is
    additionally corroborated by Zeek's ``connection.local.originator``/
    ``responder`` flags. Returns a :class:`DiscoverySummary`. Never raises on a
    bad sub-query — degrades and records the error. ``started_at``/
    ``finished_at`` are stamped here.
    """
    summary = DiscoverySummary(started_at=datetime.now(UTC).isoformat())

    # 1. Effective internal CIDRs (open a session via the sessionmaker).
    async with db_sessionmaker() as db:
        eff = await effective_internal_identifiers(db, settings)
    cidrs = eff.cidrs
    if not cidrs:
        summary.errors.append("no internal CIDRs configured; cannot scope internal source")
        summary.finished_at = datetime.now(UTC).isoformat()
        return summary

    index = settings.events_index_pattern
    lookback = settings.discovery_lookback_days
    min_hosts = settings.discovery_min_hosts

    # 2. Name signals: host.name + PTR + internal-resolution + raw DNS query.
    suffixes, hosts = await _discover_name_signals(es_client, index, cidrs, lookback, summary)

    # Distinct internal hosts seen across both signals (best-effort: the max
    # per-candidate cardinality we observed — a floor on the deployment's size).
    summary.internal_hosts_seen = max(
        (c.host_count for c in [*suffixes.values(), *hosts.values()]),
        default=0,
    )

    # 3. CIDR discovery (SUGGEST-FIRST). Enumerate new private /24s from raw IP
    #    volume plus Zeek's local-endpoint flags. Always-muted (see upsert loop).
    cidr_candidates = await _discover_cidrs(es_client, index, cidrs, lookback, summary)

    # 4. Classify + upsert.
    async with db_sessionmaker() as db:
        for cand in suffixes.values():
            state = classify_suffix(cand, min_hosts)
            if state is None:
                continue  # dropped (reserved default)
            await upsert_detected(db, "suffix", "." + cand.value, _evidence(cand), state)
            summary.suffixes_found += 1
            if state == "active":
                summary.suffixes_active += 1
            else:
                summary.suffixes_muted += 1

        for cand in hosts.values():
            state = classify_host(cand, min_hosts)
            await upsert_detected(db, "host", cand.value, _evidence(cand), state)
            summary.hosts_found += 1

        for cidr_cand in cidr_candidates.values():
            if cidr_cand.host_count < min_hosts:
                continue  # too few distinct private IPs to suggest this /24
            # ALWAYS muted — a CIDR is two-directional, never auto-activated.
            await upsert_detected(db, "cidr", cidr_cand.network, _cidr_evidence(cidr_cand), "muted")
            summary.cidrs_found += 1
            summary.cidrs_suggested += 1

    summary.finished_at = datetime.now(UTC).isoformat()
    return summary


__all__ = [
    "DiscoverySummary",
    "classify_host",
    "classify_suffix",
    "derive_suffix",
    "is_clearly_internal_suffix",
    "is_public_registrable",
    "registrable_form",
    "run_discovery",
]
