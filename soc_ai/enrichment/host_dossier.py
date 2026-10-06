"""The host-dossier network sweep: keep a current idea of what every host IS.

One pass over the deployment's internal network. For each host it collects
observations from Elasticsearch, classifies them with the deterministic rules in
:mod:`soc_ai.dossier.infer`, and writes the result into the dossier's inference
lane. The operator lane is read (to notice a standing disagreement) and never
written — an override survives every sweep structurally, because there is no
"current value" column for a build to clobber.

Five properties decide whether this can be left running against a live grid:

**The census is aggregations only.** Enumerating the network is one ``size=0``
search with a terms agg per endpoint, plus — where the grid carries them — one
that asks the network's agents what they are and which addresses they hold, and
one that asks what the network's DNS answers call each address. Three searches
for the whole network, whatever its size. Pulling documents to find out which
hosts exist would scan the whole window's event volume every sweep, which is the
difference between a cheap nightly job and one that hammers the grid it is
watching.

**A machine that self-reports is a network member. So is one the network's
DNS can name.** The network census only sees hosts that talk; a VM that answers nothing
had no dossier row at all, and an investigation naming its address had nothing to
resolve. Every address exactly one agent claims is adopted as a census member
(see :func:`_ingest_agent_claims`), and so is every address the network's DNS
answers agree on a name for (:func:`_ingest_dns_names`) — the quiet machine is
usually the one whose identity turns out to matter.

**A run is stamped even when it did nothing.** ``discovery``'s equivalent
timestamp lives on ``app.state`` and its due-check treats ``None`` as due, so a
restart loop re-sweeps the entire network on every boot. Here the stamp is a
``dossier_run`` row written *before* the work starts and closed after it, and a
stable network — which finds nothing new almost every sweep — still advances it.
Gating a last-run stamp on "did some work" is exactly what had auto-triage
re-running full ES planning every 60 seconds.

**One bad host cannot abort the sweep.** Every host is built inside its own
timeout and its own ``try``/``except``; a failure writes ``build_error`` on that
host's row (and still advances its build stamp, or the broken host would be
retried first on every sweep forever) and the sweep moves on.

**Hosts are built sequentially.** Not for simplicity — the connection pool has
frozen this app once already, and fanning out over hundreds of hosts, each
costing seven ES round trips and a DB session, is how that happens again. The
per-sweep host cap bounds the wall clock instead.

**A build that could not look writes nothing.** The collector never raises, so
an Elasticsearch outage arrives looking exactly like a host that went quiet —
and running that through the inference lane would stamp ``inferred_retracted_at``
across the network, one bad night erasing what the system knew about every asset.
A build whose queries all failed records ``build_error`` and skips the write:
absence of evidence is not evidence of absence.

**A fired prod is delivered, not just counted.** Firing advances
``conflict_last_prompted_at`` and ``conflict_prompt_count`` inside the build's
transaction, which burns the 14-day rate limit and escalates the "keep mine"
backoff — so a prod with no surface is worse than none, because the operator
first meets the question already snoozed toward the 90-day cap. Each one emits
``dossier_conflict_nudge`` here and becomes a bell entry in
``routes_meta.list_notifications``.

Every knob is re-read from ``settings`` on entry, so a config-console change
applies to the next sweep without a restart: ``hot=True`` on a setting spec is
only a claim that the singleton gets ``setattr``'d, and a job that cached the
value at import time would make that claim false.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, nulls_first, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai.config import Settings
from soc_ai.dossier import profile_job
from soc_ai.dossier.infer import infer_host_facts

# The three borrowed privates are deliberate: `_agg_datetime` is the collector's
# own date-agg reader, and `_is_internal_ip` / `_junk_host_reason` are the rules
# discovery already applies to the same two questions ("is this address ours"
# and "can this string be a hostname"). Re-implementing either here is how two
# jobs end up disagreeing about which names get redacted.
from soc_ai.dossier.observe import (
    _agg_datetime,
    collect_agent_inventory,
    collect_dhcp_leases,
    collect_dns_names,
    collect_host_observations,
)
from soc_ai.dossier.stages import StageClock, counting
from soc_ai.dossier.types import (
    AgentInventory,
    AgentSelfReport,
    DhcpLeaseInventory,
    DnsNameInventory,
    Fact,
    HostObservations,
    identity_bearing_ip,
)
from soc_ai.enrichment.discovery import SELF_REPORTED_SIGNALS, _is_internal_ip, _junk_host_reason
from soc_ai.oracle.identifiers import effective_internal_identifiers
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store import host_machines
from soc_ai.store.auth import utcnow
from soc_ai.store.internal_identifiers import upsert_detected
from soc_ai.store.models import DossierRun, HostDossier, HostDossierField
from soc_ai.tools._synth_scope import synth_scope_must_not

if TYPE_CHECKING:  # pragma: no cover - typing only
    # Type-only: `audit.logger` drags in the ES client and the redaction stack,
    # and this module is imported by the scheduler on every boot.
    from soc_ai.audit.logger import AuditLogger

_LOGGER = logging.getLogger(__name__)

# The audit kind for a fired prod, as a STRING LITERAL on purpose: the
# docs-vs-code accuracy gate scans for literal emissions, and the AuditKind
# enum lives in a module this one does not own (routes_dossier does the same).
_AUDIT_CONFLICT_NUDGE = "dossier_conflict_nudge"

# Bounds on the census terms agg. The size itself is derived from
# `dossier_max_hosts` (see `_census_agg_size`) rather than fixed, so the census
# can enumerate the table it fills; the floor keeps a shrunken cap from blinding
# the sweep to a /22, and the ceiling keeps a runaway cap from turning one
# nightly search into an Elasticsearch circuit-breaker trip.
_MIN_CENSUS_AGG_SIZE = 1000
_MAX_CENSUS_AGG_SIZE = 10_000

# Wall-clock ceiling on one host's build. Seven ES round trips at a healthy
# ~150ms is a second; twenty seconds means the grid is in trouble, and the
# remaining hosts are worth more than waiting for this one.
_PER_HOST_TIMEOUT_SECONDS = 20.0

# Census addresses per batched upsert and per transaction. One transaction
# over 4,000 rows holds a write lock for the length of the pass; one per row is
# 4,000 commits.
_CENSUS_COMMIT_CHUNK = 200

# `dossier_run` rows kept. An operations trail, not an archive.
_RUN_HISTORY = 50

# Per-host failures recorded on the run row. A network-wide outage would
# otherwise write one JSON string per host into a single column.
_MAX_RECORDED_ERRORS = 50

# Shortest hostname worth pushing into the redaction vocabulary. Two characters
# is a word, not a name, and it would rewrite unrelated prose.
_MIN_PUSHED_HOSTNAME = 3

# The ladder rungs on which a name is the HOST's own claim about itself.
_FIRST_PARTY_SOURCES = frozenset({"banner", "hostlog"})

# ...and the one rung that is NOT a first-party claim but is still proposed. See
# `_proposable` for the whole argument; the short version is that identity
# correctness and redactability are different questions.
_TELEMETRY_SOURCE = "telemetry"

# The concrete signal behind a hostname, as `infer` writes it: "pve01 (from dhcp)".
_SIGNAL_RE = re.compile(r"\(from ([^)]+)\)\s*$")

# The identity signals the fingerprint is built from, in the order of the
# store's part labels (`IDENTITY_PARTS`: h, m). Each is hashed SEPARATELY and
# the digests stored as labelled parts — never one hash over the concatenation.
# A single hash makes "the MAC aged out of the window" and "a different machine
# answers here now" the same event, which is the flap that re-stamped
# `identity_rebound_at` on every sweep (a 30-day DHCP lease against a 14-day
# window) and left the operator a rebound prod they could never settle.
_IDENTITY_COMPONENTS = ("hostname", "mac")
_COMPONENT_DIGEST_CHARS = 16


@dataclass
class DossierSummary:
    """Outcome of one network sweep (returned to the CLI / rebuild endpoint)."""

    hosts_seen: int = 0
    hosts_built: int = 0
    fields_written: int = 0
    conflicts_detected: int = 0
    conflicts_prompted: int = 0
    hosts_pruned: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    # Genuine failures — a query broke, a host could not be observed, the DB
    # refused a write. A non-empty list means part of the sweep degraded.
    errors: list[str] = field(default_factory=list)
    # Advisory notes from a healthy sweep — a truncated cap, a cadence ceiling.
    # Kept apart from `errors` so a run that built every host and hit zero
    # failures does not report an error count every night: level-triggered
    # noise in the error channel is what makes an operator stop reading it, the
    # same failure the alarm work fixed elsewhere in this codebase.
    notes: list[str] = field(default_factory=list)
    # Hosts whose served-port read came back partial, so the sweep kept their
    # previous role and services. The first reason rides with the count.
    partial_reads: int = 0
    partial_reason: str | None = None
    # Machines the sweep wrote at its end. 0 when it kept the previous ones.
    machines: int = 0
    # Wall time and searches per stage, in run order. The log carries the same
    # numbers, one line per stage. The run row has no column for them.
    stages: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _Candidate:
    """One internal address the census found, before its dossier is built."""

    ip: str
    events: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    # Which datasets and which shippers' documents carry the address. An
    # address an agent's endpoint sensor sees is a container candidate.
    datasets: set[str] = field(default_factory=set)
    shippers: set[str] = field(default_factory=set)
    # The shipper sub-agg fell short: another agent may see the address too.
    partial_shippers: bool = False


# Sub-agg caps on each census address bucket. Small on purpose: the container
# test needs to know "an endpoint dataset, and which agents ship", nothing more.
_SOURCE_DATASET_AGG_SIZE = 4
_SOURCE_SHIPPER_AGG_SIZE = 3


# ---------------------------------------------------------------------------
# The census — one size=0 search
# ---------------------------------------------------------------------------


def _internal_endpoint_filter(cidrs: list[Any]) -> dict[str, Any]:
    """Events with EITHER endpoint inside the internal CIDRs.

    Both directions, unlike ``discovery``'s source-only filter: a printer or a
    hypervisor management interface that only ever answers would otherwise never
    appear in the census of its own network, and "what does this host serve" is the dossier's
    central question.
    """
    shoulds: list[dict[str, Any]] = []
    for net in cidrs:
        shoulds.append({"term": {"source.ip": str(net)}})
        shoulds.append({"term": {"destination.ip": str(net)}})
    return {"bool": {"should": shoulds, "minimum_should_match": 1}}


def _census_query(cidrs: list[Any], lookback_days: int) -> dict[str, Any]:
    """Internal-endpoint events in the window, synthetic-eval docs excluded.

    The kill-switch is not optional: a synth fixture that reached a dossier
    would become durable, prompt-injected asset context for a real host.
    """
    return {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": f"now-{lookback_days}d"}}},
                _internal_endpoint_filter(cidrs),
            ],
            "must_not": list(synth_scope_must_not(False)),
        }
    }


def _census_agg_size(settings: Settings) -> int:
    """How many address buckets one census may return.

    Derived from ``dossier_max_hosts`` rather than fixed: a hard 2,000 under a
    5,000-host table put a silent ceiling on how many hosts could be seen — the
    census could not even enumerate the table it fills, and the hosts it dropped were the quietest
    ones (terms aggs order by ``doc_count``), which are exactly the assets an
    analyst has no other context for. Clamped at both ends: the floor keeps a
    shrunken cap from blinding the sweep to a /22, the ceiling keeps a runaway
    cap from turning one nightly search into a circuit-breaker trip.
    """
    return max(_MIN_CENSUS_AGG_SIZE, min(int(settings.dossier_max_hosts), _MAX_CENSUS_AGG_SIZE))


def _endpoint_agg(field_name: str, size: int) -> dict[str, Any]:
    """Terms agg over an IP field, carrying each address's lifetime.

    The min/max sub-aggs are why the census needs no documents: a host's first
    and last sighting come back with the bucket.

    Ordering is left at Elasticsearch's ``doc_count`` default, deliberately.
    Ordering by ``_key`` would make truncation deterministic on the ADDRESS —
    the top of every large subnet permanently invisible — where volume ordering
    at least lets a quiet host appear the week it starts talking. Past the cap
    the honest answer is a composite agg paging the whole network; until then
    :func:`_note_truncation` makes the ceiling something an operator can see
    rather than something the dossier hides.
    """
    return {
        "terms": {"field": field_name, "size": size},
        "aggs": {
            "first_seen": {"min": {"field": "@timestamp"}},
            "last_seen": {"max": {"field": "@timestamp"}},
            # Who reports the address: the container rule needs an address an
            # agent's endpoint sensor sees.
            "datasets": {"terms": {"field": "event.dataset", "size": _SOURCE_DATASET_AGG_SIZE}},
            "shippers": {"terms": {"field": "host.name", "size": _SOURCE_SHIPPER_AGG_SIZE}},
        },
    }


def _ingest_buckets(
    buckets: list[dict[str, Any]], cidrs: list[Any], out: dict[str, _Candidate]
) -> None:
    """Fold one endpoint's buckets into the candidate map, internal addresses only.

    A bucket key that is not an address (a mapping artefact) is skipped rather
    than raised on: the census is the one place that sees whatever the grid
    happens to hold.
    """
    for bucket in buckets:
        raw = str(bucket.get("key") or "")
        if not _is_internal_ip(raw, cidrs):
            continue
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:  # pragma: no cover - _is_internal_ip already parsed it
            continue
        candidate = out.setdefault(ip, _Candidate(ip=ip))
        candidate.events += int(bucket.get("doc_count") or 0)
        _widen_lifetime(
            candidate,
            _agg_datetime(bucket.get("first_seen")),
            _agg_datetime(bucket.get("last_seen")),
        )
        for name, held in (("datasets", candidate.datasets), ("shippers", candidate.shippers)):
            agg = bucket.get(name) or {}
            if name == "shippers" and int(agg.get("sum_other_doc_count") or 0) > 0:
                candidate.partial_shippers = True
            held.update(str(b.get("key")) for b in agg.get("buckets") or () if b.get("key"))


def _widen_lifetime(candidate: _Candidate, first: datetime | None, last: datetime | None) -> None:
    """Grow a candidate's lifetime to cover another sighting of it.

    Monotone, never narrowing: the census folds several sources into one row
    (both endpoint aggs, the agents' reporting windows, the DNS answer window)
    and a later source with a shorter window must not shrink what an earlier one
    proved. A row with no lifetime at all sorts first for pruning, which is how
    a quiet host gets deleted the sweep after it is discovered.
    """
    if first is not None and (candidate.first_seen is None or first < candidate.first_seen):
        candidate.first_seen = first
    if last is not None and (candidate.last_seen is None or last > candidate.last_seen):
        candidate.last_seen = last


async def _census(
    es_client: ElasticClient,
    index: str,
    cidrs: list[Any],
    lookback_days: int,
    summary: DossierSummary,
    *,
    agg_size: int,
    page_cap: int = 0,
) -> dict[str, _Candidate]:
    """Enumerate the internal network. One round trip, no documents.

    A failed census is recorded and returns nothing: the sweep still runs its
    bookkeeping (and rebuilds already-known hosts) rather than raising.

    The one search holds at most :data:`_MAX_CENSUS_AGG_SIZE` addresses per
    direction, whatever ``dossier_max_hosts`` says. When a direction fills it
    and ``page_cap`` is larger, that direction is read again in composite
    pages, up to ``page_cap`` addresses. An estate of 20,000 hosts lost half
    its addresses to the cap, and the note told the operator to raise a
    setting that could not raise it.

    The recorded reason and the log line both changed wording on this branch
    ("estate pass" / "dossier: estate aggregation failed" became "census"), and
    that break is ACCEPTED rather than shimmed. Both are operator-facing prose —
    ``dossier_run.errors`` is a trail the run row renders and the refresh
    endpoint returns, not a field anything parses — the feature is days old, and
    keeping the old spelling would mean a persisted string carrying the one word
    the product decided not to use. An external log alert keyed on the old text
    stops matching; that is the whole cost, and it is a one-line re-key.
    """
    try:
        result = await es_client.search(
            index,
            _census_query(cidrs, lookback_days),
            size=0,
            aggs={
                "src": _endpoint_agg("source.ip", agg_size),
                "dst": _endpoint_agg("destination.ip", agg_size),
            },
            track_total_hits=True,
        )
    except Exception as exc:
        summary.errors.append(f"{_CENSUS_FAILURE_PREFIX} {type(exc).__name__}: {exc}")
        _LOGGER.warning("dossier: census aggregation failed: %s", exc)
        return {}

    aggs = dict(result.aggregations or {})
    candidates: dict[str, _Candidate] = {}
    for key, field_name in (("src", "source.ip"), ("dst", "destination.ip")):
        agg = aggs.get(key) or {}
        if int(agg.get("sum_other_doc_count") or 0) > 0 and page_cap > agg_size:
            paged = await _census_pages(
                es_client, index, cidrs, lookback_days, field_name, cap=page_cap, summary=summary
            )
            if paged is not None:
                aggs[key] = agg = paged
                if paged["capped"]:
                    _record_note(
                        summary,
                        f"census stopped at {page_cap} addresses on {field_name}. "
                        "Raise dossier_max_hosts or narrow internal_cidrs.",
                    )
        _ingest_buckets(list(agg.get("buckets") or []), cidrs, candidates)
    _note_truncation(aggs, summary, agg_size=agg_size)
    return candidates


# Addresses per composite page of the census. Each address carries up to
# seven sub-buckets, so a page stays under a quarter of the default
# ``search.max_buckets``.
_CENSUS_PAGE = 2000


async def _census_pages(
    es_client: Any,
    index: str,
    cidrs: list[Any],
    lookback_days: int,
    field_name: str,
    *,
    cap: int,
    summary: DossierSummary,
) -> dict[str, Any] | None:
    """Every internal address on one side of the flows, read in composite pages.

    Returns the buckets in the shape of the terms read, and ``capped`` True
    when ``cap`` stopped the paging. Returns ``None`` when a page fails: the
    caller keeps the terms read it has, and its truncation note stands.

    The query keeps to internal addresses on ``field_name``. A page of
    internet addresses is a page the census drops.
    """
    base = _census_query(cidrs, lookback_days)
    query = {
        "bool": {
            "filter": [base, {"terms": {field_name: [str(net) for net in cidrs]}}],
        }
    }
    sub_aggs = _endpoint_agg(field_name, _CENSUS_PAGE)["aggs"]
    buckets: list[dict[str, Any]] = []
    after: dict[str, Any] | None = None
    capped = False
    while True:
        composite: dict[str, Any] = {
            "size": _CENSUS_PAGE,
            "sources": [{"ip": {"terms": {"field": field_name}}}],
        }
        if after is not None:
            composite["after"] = after
        try:
            result = await es_client.search(
                index,
                query,
                size=0,
                aggs={"page": {"composite": composite, "aggs": sub_aggs}},
            )
        except Exception as exc:
            _record_error(summary, f"census page on {field_name}: {type(exc).__name__}: {exc}")
            _LOGGER.warning("dossier: census page on %s failed: %s", field_name, exc)
            return None
        page = (result.aggregations or {}).get("page") or {}
        rows = list(page.get("buckets") or [])
        for bucket in rows:
            buckets.append({**bucket, "key": (bucket.get("key") or {}).get("ip")})
        after = page.get("after_key")
        if not rows or after is None:
            break
        if len(buckets) >= cap:
            # The table cannot hold more. The caller notes the stop.
            capped = True
            break
    return {"buckets": buckets[:cap], "sum_other_doc_count": 0, "capped": capped}


def _note_truncation(aggs: dict[str, Any], summary: DossierSummary, *, agg_size: int) -> None:
    """Say so when the census hit its bucket cap instead of dropping hosts quietly.

    ``sum_other_doc_count`` is Elasticsearch's only signal that terms fell off
    the end of ``size``, and the ones that fall off are the LOWEST-volume
    addresses. An honestly small inventory beats a silently truncated one: a
    truncated dossier looks complete while the assets an analyst has least
    context for are precisely the ones it never describes.
    """
    dropped = 0
    for key in ("src", "dst"):
        dropped += int((aggs.get(key) or {}).get("sum_other_doc_count") or 0)
    if dropped:
        # A note, not a failure: the cap was hit, the census still ran. Routing
        # it through `_record_note` keeps the error channel for things that
        # actually broke.
        _record_note(
            summary,
            f"census truncated at {agg_size} address buckets. "
            f"{dropped} event(s) sit in addresses that did not fit. "
            "Raise dossier_max_hosts or narrow internal_cidrs.",
        )


def _ingest_agent_claims(
    inventory: AgentInventory, cidrs: list[Any], out: dict[str, _Candidate]
) -> None:
    """Adopt every address exactly one host-log agent claims as a network member.

    The census enumerates hosts from NETWORK traffic, which silently
    excludes the machines that matter most here: a VM that answers nothing and
    initiates a handful of SSH sessions has almost no presence in a terms agg
    over ``source.ip`` / ``destination.ip``, so it never got a dossier row — and
    an investigation naming its address had nothing to resolve. That is exactly
    the machine whose identity mattered in the pivot incident.

    A machine reporting its own logs is an asset, so it becomes a first-class
    census member. Three limits are deliberate:

    * only UNIQUELY claimed addresses (see :class:`AgentInventory`) — a shared
      bridge gateway names nobody and must not be adopted as anybody's row;
    * only addresses inside the configured internal CIDRs, the same gate the
      network census applies — "internal" is the operator's definition, and an
      agent on a machine with a public address must not put the internet in the
      table;
    * an address the network census counted keeps its NETWORK event count. An
      address no network sensor sees counts the agent's own documents that
      carry it in ``host.ip``. The census wrote 0 for it before, and the Hosts
      screen's default view (events above 0) hid the machine.

    The lifetime IS widened from the agent's own documents for the address, or
    from its reporting window when the address carries no span: the machine was
    demonstrably alive then (it said so), and a row with no lifetime at all
    sorts first for pruning, which would delete the quiet host on the next sweep.
    """
    for ip, report in inventory.unique_claims().items():
        if not _is_internal_ip(ip, cidrs):
            continue
        candidate = out.setdefault(ip, _Candidate(ip=ip))
        held = report.addresses.get(ip)
        if candidate.events == 0 and held is not None:
            candidate.events = held.docs
        if held is not None and (held.first_seen or held.last_seen):
            _widen_lifetime(candidate, held.first_seen, held.last_seen)
        else:
            _widen_lifetime(candidate, report.first_report, report.last_report)


def _ingest_dns_names(
    inventory: DnsNameInventory, cidrs: list[Any], out: dict[str, _Candidate]
) -> None:
    """Adopt every internal address the network's DNS answers agree on a name for.

    The sibling of :func:`_ingest_agent_claims`, one rung lower and reaching much
    further: the ``hostlog`` lane only sees machines that run a log agent — 13 of
    them against ~134 rows on the network this was built for — while DNS names
    the printer, the appliance and the VM that answer nothing at all. Those are
    the rows whose hostname was blank, which was the whole complaint.

    The same three limits as the agent lane, for the same reasons:

    * only addresses whose names AGREE (see
      :class:`~soc_ai.dossier.types.DnsNameInventory`) — a tie names nobody, and
      adopting one would make the row flap between two names sweep to sweep;
    * only addresses inside the configured internal CIDRs. The collector already
      applied that gate; it is repeated here because "internal" is the operator's
      definition and this is the function that decides what enters the table;
    * ``events`` is left alone. It counts NETWORK events in the window, and
      inventing one out of DNS answer volume would make a silent machine look
      busy on a screen that means something else by it.

    The lifetime IS widened from the answer window: something asked for this name
    and got this address, repeatedly, across that span. A row with no lifetime
    sorts first for pruning, so a host discovered by this lane would otherwise be
    deleted on the next sweep.
    """
    for ip, claim in inventory.consensus().items():
        if not _is_internal_ip(ip, cidrs):
            continue
        candidate = out.setdefault(ip, _Candidate(ip=ip))
        _widen_lifetime(candidate, claim.first_answer, claim.last_answer)


_LIMITED_BROADCAST = "255.255.255.255"


def _broadcast_addresses(cidrs: list[Any]) -> frozenset[str]:
    """Every broadcast address the estate's CIDRs define, plus the limited one.

    The last address of an IPv4 network is its broadcast address. A frame to it
    reaches every host on the segment and comes from none of them, so it is no
    host. The census listed one with 3,733 events. A /31 and a /32 have no
    broadcast address, and IPv6 has none at all.
    """
    out = {_LIMITED_BROADCAST}
    for net in cidrs:
        if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 30:
            out.add(str(net.broadcast_address))
    return frozenset(out)


def _drop_broadcast(candidates: dict[str, _Candidate], cidrs: list[Any]) -> list[str]:
    """Remove broadcast addresses from the census. Returns the addresses removed."""
    doomed = sorted(ip for ip in candidates if ip in _broadcast_addresses(cidrs))
    for ip in doomed:
        del candidates[ip]
    return doomed


async def _record_census(
    db_sessionmaker: async_sessionmaker[AsyncSession],
    candidates: dict[str, _Candidate],
    summary: DossierSummary,
) -> None:
    """Upsert the host headers the census found (monotone lifetime, window count).

    Deliberately separate from the build: every candidate gets a row now, so a
    sweep whose per-host budget runs out still leaves the overflow discoverable
    and correctly prioritised (``last_built_at IS NULL`` sorts first) for the
    next one.

    One batched upsert and one commit per chunk of addresses. One upsert per
    address was most of this stage at 20,000 hosts. A chunk the batch refuses
    is written again one address at a time, so a bad address costs its own row
    and its own error line, and the rest of the chunk still lands.
    """
    rows = [
        dossier_store.HostUpsert(
            ip=candidate.ip,
            first_seen=candidate.first_seen,
            last_seen=candidate.last_seen,
            event_count=candidate.events,
        )
        for candidate in candidates.values()
    ]
    async with db_sessionmaker() as db:
        for start in range(0, len(rows), _CENSUS_COMMIT_CHUNK):
            chunk = rows[start : start + _CENSUS_COMMIT_CHUNK]
            try:
                await dossier_store.upsert_hosts(db, chunk)
            except Exception:
                for row in chunk:
                    try:
                        await dossier_store.upsert_hosts(db, [row])
                    except Exception as exc:
                        _record_error(
                            summary, f"census upsert {row.ip}: {type(exc).__name__}: {exc}"
                        )
            await db.commit()


# ---------------------------------------------------------------------------
# Per-host build
# ---------------------------------------------------------------------------


async def _due_hosts(db_sessionmaker: async_sessionmaker[AsyncSession], limit: int) -> list[str]:
    """The *limit* stalest hosts, never-built first.

    Staleness is an ORDER BY, not a filter: a small network should be rebuilt on
    every sweep, and a large one drains oldest-first across sweeps. Priority is
    recomputed from the durable ``last_built_at`` each time, so a restart resumes
    where the last sweep stopped instead of starting the network over.

    Read as plain strings in one short session: holding an ORM identity map open
    across a multi-minute sweep is how a background job pins a pool connection.
    """
    async with db_sessionmaker() as db:
        rows = await db.scalars(
            select(HostDossier.ip)
            .order_by(nulls_first(HostDossier.last_built_at.asc()), HostDossier.id.asc())
            .limit(max(1, limit))
        )
        return [str(ip) for ip in rows.all()]


def _component_digest(value: str | None) -> str:
    """Hash one identity component, or ``""`` when this build did not see it.

    Case- and whitespace-folded: ``PVE01`` and ``pve01`` are one machine, and a
    Windows box that announces its name in caps to NTLM and in lower case to
    DHCP must not read as two.
    """
    folded = (value or "").strip().casefold()
    if not folded:
        return ""
    return hashlib.sha256(folded.encode("utf-8")).hexdigest()[:_COMPONENT_DIGEST_CHARS]


def _identity_fingerprint(facts: dict[str, Fact], prior: str | None) -> str | None:
    """This build's identity fingerprint, or ``None`` when it saw no signal.

    Per-component digests in the store's labelled shape, ``h:<hex>|m:<hex>``,
    and a component this build did NOT see is carried over from *prior* rather
    than emptied. That carry-over is the
    fix for the flap: signals age out of the lookback window independently (a
    30-day DHCP lease against a 14-day window drops the MAC while the name keeps
    being announced), and a fingerprint that changed on absence oscillated
    between two non-null values — re-stamping ``identity_rebound_at`` on every
    sweep, so the operator was asked "is this a different machine?" forever and
    could never durably answer. Only a component moving to a DIFFERENT non-empty
    value is a rebind now.

    ``None`` is load-bearing too: a fingerprint over two empty strings would be
    identical for every headless host on the grid, and the first DHCP lease one
    of them ever emitted would read as a machine swap.

    A *prior* in the plain ``<hex>:<hex>`` shape of the previous build is read
    part by part, so the change of shape is no change of machine. A *prior*
    older than that (one digest over the whole) reads as no parts: it is
    ignored rather than half-parsed, and the store never stamps a part that
    appears.
    """
    carried = dossier_store.fingerprint_parts(prior)
    parts: dict[str, str] = {}
    for label, name in zip(dossier_store.IDENTITY_PARTS, _IDENTITY_COMPONENTS, strict=True):
        fact = facts.get(name)
        digest = _component_digest(fact.value if fact is not None else None)
        parts[label] = digest or carried.get(label, "")
    return dossier_store.compose_fingerprint(parts)


def _hostname_signal(fact: Fact) -> str:
    """The concrete signal behind the winning name (``dhcp`` / ``ntlm`` / ``smb``).

    ``infer`` writes evidence winner-first in the ``"pve01 (from dhcp)"`` shape,
    so the first entry names the source of the value. Falls back to the ladder
    rung if that convention ever changes — this is a provenance label on an
    evidence record, not a decision input.
    """
    for entry in fact.evidence:
        match = _SIGNAL_RE.search(entry)
        if match:
            return match.group(1)
    return fact.source


def _proposable(fact: Fact) -> bool:
    """Is this name worth PROPOSING to the identifier store?

    Two questions get asked of the same ladder and they have different answers.

    "Whose claim is this?" is about identity CORRECTNESS, and the ladder already
    settles it: a PTR answer names the address and a proxy's ``host.name`` names
    the proxy, so ``telemetry`` sits under ``banner`` and ``hostlog`` and a
    machine's own account of itself wins the field.

    "Can the guard redact this?" is about EGRESS, and provenance has nothing to
    do with it. Internal identifiers are the redaction vocabulary:
    ``guard.sanitize_text`` rewrites what ``effective_internal_identifiers``
    knows about and nothing else. The DNS-consensus lane names roughly the whole
    previously-nameless population (~134 hosts on the network this was built
    for), and those names reach investigations, both chats, the hunt planner and
    the hunt console seed. Excluded from this function, they were never even
    OFFERED to an operator — not as a rule, not as a suggestion — so on a
    cloud-egress deployment they left in the clear unless they happened to end
    in a configured suffix. That is the gap this closes.

    Closes it by making it CLOSABLE, which is all a proposal ever does: a muted
    row contributes nothing to the effective identifier set until an operator
    accepts it. Same posture as the first-party rungs, which are also muted.

    STRONG telemetry only, and that is the DNS consensus. Verified against
    ``infer._hostname_candidates``: the rung carries three labels, and the other
    two — a proxy's ECS ``host.name`` and a PTR answer — are ``weak``, which is
    0.5 against a default ``dossier_min_confidence`` of 0.6, so the resolver
    hides them and they never reach a prompt at all. A name with no egress gap
    has nothing to close, and filing a proxy's name under this host's address
    would put a suggestion in the review queue that the operator cannot judge.
    """
    if fact.source in _FIRST_PARTY_SOURCES:
        return True
    return fact.source == _TELEMETRY_SOURCE and fact.strength == "strong"


async def _push_hostname(
    db: AsyncSession, ip: str, fact: Fact | None, *, cidrs: list[Any], observed: datetime | None
) -> bool:
    """PROPOSE a hostname the dossier just learned to the identifier store.

    The WINNING name for the host, and only it — see :func:`_proposable` for
    which rungs qualify and why the DNS consensus is on the list despite not
    being a first-party claim. Filing every candidate a window offered would
    turn the identifier review queue into a list of guesses.

    ``hostlog`` is in the first-party set for a reason beyond symmetry: it
    OUTRANKS ``banner``, so gating on the banner rung alone would have stopped
    proposing names for every host where an agent reports one — and a
    newly-named machine is precisely the one whose name most needs to be
    redactable.

    Upserted ``muted`` — a suggestion awaiting review, the same suggest-first
    rule ``discovery.classify_host`` applies to a candidate it cannot
    corroborate. Internal identifiers ARE egress-redaction policy, and a
    first-party announcement is attacker-chosen input: a DHCP request carries
    whatever hostname its client feels like sending, so auto-activating one lets
    anyone who can take a lease write a redaction rule (and a name chosen to
    collide with common prose would rewrite unrelated text network-wide). The
    DNS lane is no safer for being second-hand — whoever can write the zone
    chooses the string. Length and the junk check are noise filters, not
    authorisation.

    ``upsert_detected`` preserves an existing state, so an operator who accepts
    the suggestion keeps it: the next sweep refreshes the evidence and leaves
    ``active`` alone.
    """
    if fact is None or fact.value is None or not _proposable(fact):
        return False
    name = fact.value.strip()
    signal = _hostname_signal(fact)
    # The agent's own host.name and a DHCP lease name skip the TLD rule, as
    # they do in `infer`. "nexus" is a gTLD and a real machine.
    junk = _junk_host_reason(name, self_reported=signal in SELF_REPORTED_SIGNALS)
    if len(name) < _MIN_PUSHED_HOSTNAME or junk is not None:
        return False
    if not _is_internal_ip(ip, cidrs):
        return False
    evidence = {
        "source": "host_dossier",
        "ip": ip,
        "signal": signal,
        "last_seen": observed.isoformat() if observed is not None else None,
    }
    await upsert_detected(db, "host", name, evidence, "muted")
    return True


# The fields the served-port read decides. A partial read of the port set
# rewrote a domain controller (tcp/88, tcp/389) as a server that "responds on
# tcp/53", and the sweep report said errors=[].
_PORT_FIELDS: tuple[str, ...] = ("role", "services_offered", "management_plane")
# The main pass is the one that reads the ports. Its error lines carry these
# prefixes (soc_ai.dossier.observe._run_main_pass).
_MAIN_PASS_PREFIXES: tuple[str, ...] = ("reduced-agg fallback:", "multi-agg pass failed:")
# A grid that could not answer in full: shard failures, a timeout, a 503. A
# chronic 400 on a text-mapped field is not one, and must not freeze a role.
_DEGRADED_RE = re.compile(
    r"partial search results|timed? ?out|timeout|\b503\b|unavailable|circuit_breaking",
    re.IGNORECASE,
)
# A port set that shrank to under half of the previous build's is a short read
# until a full one says otherwise. Below this prior size a drop is ordinary.
_PORT_DROP_MIN_PRIOR = 4


def _port_count(value_json: Any) -> int | None:
    """How many ports a services payload lists, or ``None`` for another shape."""
    if isinstance(value_json, list):
        return len(value_json)
    if isinstance(value_json, dict) and isinstance(value_json.get("ports"), list):
        return len(value_json["ports"])
    return None


def _partial_port_read(
    observations: HostObservations,
    facts: dict[str, Fact],
    prior: dict[str, HostDossierField],
) -> str | None:
    """Name the reason the served-port read is partial, or ``None`` when it is whole.

    Two tests. The main pass that reads the ports reported a degraded grid
    (shard failures, a timeout, a 503). Or the read returned fewer than half the
    ports the previous build held for this host. The second catches a grid
    that answers partial results with no error, which is what a deployment
    with ``es_fail_on_partial_results`` off receives.
    """
    for error in observations.errors:
        if error.startswith(_MAIN_PASS_PREFIXES) and _DEGRADED_RE.search(error):
            return f"the served-port read was partial: {error[:200]}"
    held = prior.get("services_offered")
    before = _port_count(held.inferred_value_json) if held is not None else None
    fact = facts.get("services_offered")
    now = _port_count(fact.value_json) if fact is not None else None
    if before is not None and before >= _PORT_DROP_MIN_PRIOR and (now or 0) * 2 < before:
        return f"the read returned {now or 0} served ports where the previous build had {before}"
    return None


def _activity(observations: HostObservations) -> tuple[int, datetime | None]:
    """The event count and the last sighting the build writes for one address.

    The count is the network's count, always. The agent's own documents carry
    every address the agent has in ``host.ip``, so a per-address copy of that
    figure made each bridge address of one machine read as its busiest
    address and summed the same documents once per address. The machine
    carries the agent's documents once (``host_machines``). An address that
    only its agent reports keeps the network's 0 and takes the agent's newest
    timestamp as its last sighting, so it is not read as unseen.
    """
    if observations.total_events or observations.agent_report is None:
        return observations.total_events, observations.last_seen
    key = identity_bearing_ip(observations.ip) or observations.ip
    held = observations.agent_report.addresses.get(key)
    if held is None or held.docs <= 0:
        return observations.total_events, observations.last_seen
    last = held.last_seen or observations.agent_report.last_report or observations.last_seen
    return observations.total_events, last


def _collection_failure(observations: HostObservations) -> str | None:
    """Name the outage when a build could not QUERY, or ``None`` when it looked.

    ``collect_host_observations`` never raises: a failed sub-query lands in
    ``errors`` and leaves its slice empty, so an Elasticsearch outage arrives
    looking exactly like a host that has gone silent. Writing that through the
    inference lane stamps ``inferred_retracted_at`` on every field of every
    host — one bad night wiping what the system knew about the whole network.

    The test is "errors, and not one signal came back". A build with events, an
    identity record or a PTR answer looked successfully and its emptiness
    elsewhere is real; a build with nothing but failures is not evidence of
    absence, and absence of evidence must not retract a belief.
    """
    if not observations.errors:
        return None
    saw_something = (
        observations.total_events
        or observations.datasets
        or observations.ptr_name
        or observations.dhcp
        or observations.ssh_banners
        or observations.windows_identity
        or observations.software
        or observations.host_names
        or observations.user_agents
    )
    if saw_something:
        return None
    return (
        f"could not observe {observations.ip}. Every Elasticsearch query failed: "
        f"{observations.errors[0]}. The dossier is unchanged."
    )


async def _prior_fingerprint(db: AsyncSession, ip: str) -> str | None:
    """The fingerprint the last build wrote, for the component carry-over."""
    try:
        key = dossier_store.normalize_host_key(ip)
    except ValueError:  # pragma: no cover - the census only yields addresses
        return None
    value = await db.scalar(
        select(HostDossier.identity_fingerprint).where(HostDossier.host_key == key)
    )
    return str(value) if value is not None else None


async def _expire_rebind(
    db: AsyncSession, host: HostDossier, *, now: datetime, ttl: timedelta
) -> None:
    """Drop a rebind stamp nothing is still asking about.

    ``identity_rebound_at`` was write-only: once stamped it stayed forever, so a
    single address reuse left "a different machine may hold this address" on the
    entity card for the life of the row. It is cleared here when it is older than
    the observation window — past that no query the builder makes can still see
    the evidence that raised it — and ONLY when no operator value predates it. An
    override older than the rebind is the exact shape ``_conflict_kind`` reads as
    ``rebound``: that is an open question, and ageing it out would lose it.

    An operator who re-affirms the override settles it structurally instead:
    ``set_override`` stamps ``operator_set_at = now``, which is then newer than
    the rebind, and the conflict stops firing on the next build.
    """
    stamp = host.identity_rebound_at
    if stamp is None or now - stamp <= ttl:
        return
    contested = await db.scalar(
        select(func.count(HostDossierField.id)).where(
            HostDossierField.dossier_id == host.id,
            or_(
                HostDossierField.operator_value.is_not(None),
                HostDossierField.operator_value_json.is_not(None),
            ),
            HostDossierField.operator_set_at.is_not(None),
            HostDossierField.operator_set_at < stamp,
        )
    )
    if contested:
        return
    host.identity_rebound_at = None
    await db.flush()


def _nudge_payload(ip: str, write: dossier_store.InferredWrite) -> dict[str, Any]:
    """The audit body for one fired prod, read INSIDE the build's session."""
    row = write.row
    return {
        "ip": ip,
        "field": row.field,
        "action": "raised",
        "conflict_kind": write.conflict_kind,
        "operator_value": row.operator_value,
        "inferred_value": row.inferred_value,
        "inferred_confidence": row.inferred_confidence,
        "observations": row.conflict_observations,
        "prompt_count": row.conflict_prompt_count,
        "first_seen_at": (
            row.conflict_first_seen_at.isoformat() if row.conflict_first_seen_at else None
        ),
    }


async def _emit_nudges(audit: AuditLogger | None, ip: str, payloads: list[dict[str, Any]]) -> None:
    """Deliver the prods this build fired. Best-effort, after the commit.

    Without this the state machine was write-only: ``conflict_last_prompted_at``
    and ``conflict_prompt_count`` advanced, burning the 14-day rate limit and
    escalating the "keep mine" backoff, while nothing an operator could see was
    ever produced. The first question they were actually asked already carried a
    90-day snooze.

    Emitted after the transaction commits (never nag about a write that rolled
    back) and swallowed on failure: the field write is already durable, and
    losing the audit line is strictly the lesser loss.
    """
    if audit is None or not payloads:
        return
    for payload in payloads:
        try:
            await audit.log_kind(
                session_id=f"dossier:{ip}",
                kind=_AUDIT_CONFLICT_NUDGE,
                payload=payload,
                user="system",
            )
        except Exception:
            _LOGGER.warning("dossier: conflict nudge audit write failed (continuing)")


async def _build_host(
    es_client: ElasticClient,
    db_sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
    ip: str,
    *,
    cidrs: list[Any],
    window_hours: int,
    summary: DossierSummary,
    audit: AuditLogger | None = None,
    agent_inventory: AgentInventory | None = None,
    dns_names: DnsNameInventory | None = None,
) -> None:
    """Observe, classify and persist one host. One DB transaction, one commit.

    The conflict state machine has to land in the same transaction as the field
    write it is derived from, or a prod could fire against values that were then
    rolled back — nagging the operator about evidence the dossier does not hold.

    ``agent_inventory`` and ``dns_names`` are the sweep's two network-wide passes,
    handed down rather than re-collected: this host's slice of each is a lookup.
    """
    async with asyncio.timeout(_PER_HOST_TIMEOUT_SECONDS):
        observations = await collect_host_observations(
            ip,
            elastic=es_client,
            settings=settings,
            window_hours=window_hours,
            agent_inventory=agent_inventory,
            dns_names=dns_names,
        )
        failure = _collection_failure(observations)
        if failure is not None:
            # Not a build: nothing is written through the inference lane, so no
            # belief is retracted. The stamp still advances (via
            # `_record_build_error`) or this host sorts first on every sweep for
            # as long as the outage lasts, spending the sweep's per-run host
            # budget on it and starving every host still waiting to be rebuilt.
            _record_error(summary, failure)
            _LOGGER.warning("dossier: %s", failure)
            await _record_build_error(db_sessionmaker, ip, failure)
            return
        facts = infer_host_facts(
            observations,
            min_events=int(settings.dossier_min_events),
            # The resolver's render floor, read at build time too: selection must
            # not let a name the resolver would hide shadow one it would show.
            min_confidence=float(settings.dossier_min_confidence),
        )
        now = datetime.now(UTC)
        prods: list[dict[str, Any]] = []
        async with db_sessionmaker() as db:
            prior = await _prior_fingerprint(db, ip)
            held = await dossier_store.get_dossier(db, ip)
            prior_fields = {row.field: row for row in (held[1] if held is not None else [])}
            # A partial port read must not overwrite a stronger prior answer.
            # The fields it decides keep their previous values, and the host
            # row says why: a stale read is not a clean build.
            partial = _partial_port_read(observations, facts, prior_fields)
            kept: tuple[str, ...] = ()
            if partial is not None:
                kept = tuple(
                    name
                    for name in _PORT_FIELDS
                    if name in prior_fields
                    and (
                        prior_fields[name].inferred_value is not None
                        or prior_fields[name].inferred_value_json is not None
                    )
                )
            stale_read = (
                f"Stale read. The sweep kept the previous {', '.join(kept)}. Reason: {partial}."
                if kept
                else None
            )
            if stale_read is not None:
                summary.partial_reads += 1
                if summary.partial_reason is None:
                    summary.partial_reason = partial
            events, last_seen = _activity(observations)
            host = await dossier_store.upsert_host(
                db,
                ip,
                first_seen=observations.first_seen,
                last_seen=last_seen,
                last_observed_at=last_seen,
                event_count=events,
                identity_fingerprint=_identity_fingerprint(facts, prior),
                last_built_at=now,
                build_error=stale_read,
                now=now,
            )
            # Before the field writes: `upsert_inferred` reads the host's rebind
            # stamp to decide `rebound`, so a spent one has to be gone by then.
            await _expire_rebind(
                db,
                host,
                now=now.replace(tzinfo=None),
                ttl=timedelta(hours=max(1, window_hours)),
            )
            for fact in facts.values():
                if fact.field in kept:
                    continue
                write = await dossier_store.upsert_inferred(
                    db,
                    host,
                    fact,
                    now=now,
                    min_confidence=float(settings.dossier_min_confidence),
                    min_observations=int(settings.dossier_conflict_min_observations),
                    prompt_interval_hours=int(settings.dossier_conflict_prompt_interval_hours),
                )
                summary.fields_written += 1
                if write.conflict_kind is not None:
                    summary.conflicts_detected += 1
                if write.prompted:
                    summary.conflicts_prompted += 1
                    prods.append(_nudge_payload(ip, write))
            await _push_hostname(
                db,
                ip,
                facts.get("hostname"),
                cidrs=cidrs,
                observed=observations.last_seen,
            )
            await db.commit()
    summary.hosts_built += 1
    # Outside the per-host timeout on purpose: the build is done and committed,
    # and a slow audit index must not turn a good build into a recorded failure
    # (the TimeoutError would land in `build_error` on a host whose dossier is
    # perfectly fine).
    await _emit_nudges(audit, ip, prods)


async def _record_build_error(
    db_sessionmaker: async_sessionmaker[AsyncSession], ip: str, detail: str
) -> None:
    """Write a failed build's reason onto the host's own row.

    The build stamp advances with it. A host that never advanced would sort
    first on every subsequent sweep, spending the per-run host budget on a
    failure that may be permanent while the rest of the table goes unrebuilt.
    """
    try:
        async with db_sessionmaker() as db:
            await dossier_store.upsert_host(
                db, ip, last_built_at=datetime.now(UTC), build_error=detail
            )
            await db.commit()
    except Exception as exc:
        _LOGGER.warning("dossier: could not record build error for %s: %s", ip, exc)


# ---------------------------------------------------------------------------
# The durable run stamp
# ---------------------------------------------------------------------------


async def _open_run(
    db_sessionmaker: async_sessionmaker[AsyncSession], *, trigger: str
) -> int | None:
    """Claim the run row BEFORE any ES work, so a crash mid-sweep still stamps.

    Returns ``None`` when the row cannot be written, and the caller abandons the
    sweep: if the database will not take one insert it will not take the ~2,400
    upserts a full sweep produces either, and spending hundreds of ES
    aggregations to discover that is the wrong order to find out.
    """
    try:
        async with db_sessionmaker() as db:
            row = DossierRun(started_at=utcnow(), trigger=trigger)
            db.add(row)
            await db.commit()
            return int(row.id)
    except Exception as exc:
        _LOGGER.warning("dossier: could not open a run row: %s", exc)
        return None


async def _close_run(
    db_sessionmaker: async_sessionmaker[AsyncSession], run_id: int, summary: DossierSummary
) -> None:
    """Stamp the counters and finish time, then trim the history."""
    try:
        async with db_sessionmaker() as db:
            await db.execute(
                update(DossierRun)
                .where(DossierRun.id == run_id)
                .values(
                    finished_at=utcnow(),
                    hosts_seen=summary.hosts_seen,
                    hosts_built=summary.hosts_built,
                    fields_written=summary.fields_written,
                    conflicts_detected=summary.conflicts_detected,
                    conflicts_prompted=summary.conflicts_prompted,
                    errors=summary.errors or None,
                    notes=summary.notes or None,
                )
                .execution_options(synchronize_session=False)
            )
            await _prune_runs(db)
            await db.commit()
    except Exception as exc:
        _LOGGER.warning("dossier: could not close run %s: %s", run_id, exc)


async def _prune_runs(db: AsyncSession) -> None:
    keep = list(
        (
            await db.scalars(
                select(DossierRun.id)
                .order_by(DossierRun.started_at.desc(), DossierRun.id.desc())
                .limit(_RUN_HISTORY)
            )
        ).all()
    )
    if len(keep) < _RUN_HISTORY:
        return
    await db.execute(
        sa_delete(DossierRun)
        .where(DossierRun.id.not_in(keep))
        .execution_options(synchronize_session=False)
    )


async def latest_run_started_at(
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> datetime | None:
    """When the newest sweep STARTED, as an aware UTC timestamp, or ``None``.

    The scheduler's due-check reads this rather than an in-process stamp, which
    is the whole reason ``dossier_run`` exists: an ``app.state`` timestamp is
    ``None`` after every restart, and a restart loop would re-sweep the network
    on each boot. ``None`` here genuinely means "never swept" and is due.

    Start, not finish: a sweep that died partway through has already spent its ES
    budget, and re-running it immediately on the next wake is the behaviour the
    durable stamp exists to prevent.
    """
    async with db_sessionmaker() as db:
        stamp = await db.scalar(
            select(DossierRun.started_at).order_by(DossierRun.started_at.desc()).limit(1)
        )
    if stamp is None:
        return None
    return stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)


def _note_cadence(settings: Settings, summary: DossierSummary) -> None:
    """Say so when the configured rate cannot keep the network inside the gate.

    ``dossier_max_hosts_per_run`` hosts every ``dossier_schedule_interval_hours``
    refreshes at most that many times ``staleness / interval`` hosts before the
    oldest dossier ages out of ``dossier_staleness_hours`` — 600 at the defaults
    (200 x 24h, 72h gate). Past that, some host is ALWAYS stale, and the resolver
    answers "unknown, reason=stale" for it while every screen still says the
    feature is on. A throughput ceiling the operator cannot see is indis-
    tinguishable from a broken feature; this makes it a line on the run row.
    """
    interval = max(1, int(settings.dossier_schedule_interval_hours))
    sweeps = max(1, int(settings.dossier_staleness_hours) // interval)
    capacity = max(1, int(settings.dossier_max_hosts_per_run)) * sweeps
    if summary.hosts_seen <= capacity:
        return
    # A throughput ceiling is an advisory the operator should see, not a failure
    # of this sweep — it goes to the notes channel.
    _record_note(
        summary,
        f"the configured cadence cannot keep {summary.hosts_seen} host(s) fresh. "
        f"{settings.dossier_max_hosts_per_run} hosts per run every {interval} h "
        f"refreshes about {capacity} hosts inside the "
        f"{settings.dossier_staleness_hours} h staleness gate. "
        "Raise dossier_max_hosts_per_run or shorten dossier_schedule_interval_hours.",
    )


# The prefix `_census` writes on a failed census pass.
_CENSUS_FAILURE_PREFIX = "census pass:"

# The dataset prefix of an agent's endpoint sensor (Elastic Defend).
_ENDPOINT_DATASET_PREFIX = "endpoint."


def _agent_key(report: AgentSelfReport) -> str:
    """The machine key part of an agent: its id, else its name."""
    return report.agent_id or report.host_name


def _sightings(
    candidates: dict[str, _Candidate], inventory: AgentInventory
) -> list[host_machines.ContainerSighting]:
    """The census addresses an agent's endpoint sensor sees.

    An endpoint dataset carries the address, and an agent is among its
    shippers: one sighting per such agent. Other datasets may carry the address
    too. Production had 172.18.0.5 with 582 events that zeek also saw, and the
    old "endpoint datasets only" test left it a machine of its own beside the
    containers of its host. The clustering decides: the address must sit in a
    bridge the agent owns, no other agent may claim it, and no DHCP lease may
    name it. A shipper list that fell short may hide a second claim, so it
    says nothing. A short dataset list still proves the datasets it holds.
    """
    by_name = {report.host_name.casefold(): _agent_key(report) for report in inventory.hosts}
    out: list[host_machines.ContainerSighting] = []
    for ip, candidate in candidates.items():
        if candidate.partial_shippers:
            continue
        if not any(d.startswith(_ENDPOINT_DATASET_PREFIX) for d in candidate.datasets):
            continue
        agents = {by_name.get(shipper.casefold()) for shipper in candidate.shippers}
        for agent in sorted(a for a in agents if a is not None):
            out.append(host_machines.ContainerSighting(ip=ip, agent_id=agent))
    return out


def _agent_claims(inventory: AgentInventory) -> list[host_machines.AgentClaim]:
    out: list[host_machines.AgentClaim] = []
    for report in inventory.hosts:
        os_name = " ".join(
            part for part in (report.os.get("name"), report.os.get("version")) if part
        )
        out.append(
            host_machines.AgentClaim(
                agent_id=_agent_key(report),
                name=report.host_name,
                os=os_name or None,
                macs=report.macs,
                addresses=report.ips,
                last_report=report.last_report,
                # The agent's own documents, once. Every address in host.ip
                # carries the same figure, so the largest is the agent's total.
                docs=max((held.docs for held in report.addresses.values()), default=0),
            )
        )
    return out


async def _build_machines(
    db_sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    agent_inventory: AgentInventory,
    leases: DhcpLeaseInventory,
    dns_names: DnsNameInventory,
    sightings: list[host_machines.ContainerSighting],
    summary: DossierSummary,
) -> None:
    """Group the census addresses into machines and write them. The last step.

    A pass that failed this sweep would turn its machines into single
    addresses for one sweep and back on the next, and the keys in an analyst's
    open links would break. So a failed census, agent or lease pass keeps the
    previous machines, and the sweep says so.
    """
    failed = [
        name
        for name, broken in (
            ("census", _census_failed(summary)),
            ("agent inventory", bool(agent_inventory.errors)),
            ("DHCP lease", bool(leases.errors)),
        )
        if broken
    ]
    if failed:
        _record_error(
            summary,
            f"the sweep kept the previous machines. The {', '.join(failed)} pass failed.",
        )
        return
    now = datetime.now(UTC)
    try:
        async with db_sessionmaker() as db:
            facts = await host_machines.load_address_facts(
                db,
                dns_names={ip: claim.name for ip, claim in dns_names.consensus().items()},
                now=now,
                min_confidence=float(settings.dossier_min_confidence),
                staleness_hours=int(settings.dossier_staleness_hours),
            )
            prior = await host_machines.load_prior(db)
        clustering = host_machines.cluster_machines(
            facts,
            agents=_agent_claims(agent_inventory),
            leases=leases.leases,
            sightings=sightings,
            prior=prior,
        )
        async with db_sessionmaker() as db:
            stats = await host_machines.persist_clustering(
                db,
                clustering,
                facts,
                now=now,
                stale_days=int(getattr(settings, "dossier_stale_address_days", 30)),
            )
    except Exception as exc:
        _record_error(summary, f"machines: {type(exc).__name__}: {exc}")
        _LOGGER.warning("dossier: machine build failed: %s", exc)
        return
    summary.machines = stats.machines


def _census_failed(summary: DossierSummary) -> bool:
    """True when this sweep's census could not read the grid."""
    return any(error.startswith(_CENSUS_FAILURE_PREFIX) for error in summary.errors)


async def _prune_stale(
    db_sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
    seen_now: set[str],
    summary: DossierSummary,
) -> None:
    """Remove the addresses no census has seen for ``dossier_stale_address_days``.

    Read fresh from settings on every sweep, like every other knob here.
    """
    days = max(1, int(getattr(settings, "dossier_stale_address_days", 30)))
    try:
        async with db_sessionmaker() as db:
            gone = await dossier_store.prune_stale(db, older_than_days=days, seen_now=seen_now)
    except Exception as exc:
        _record_error(summary, f"stale prune: {type(exc).__name__}: {exc}")
        _LOGGER.warning("dossier: stale prune failed: %s", exc)
        return
    summary.hosts_pruned += len(gone)


def _record_error(summary: DossierSummary, detail: str) -> None:
    """Append a failure, bounded. A network-wide outage is one error, repeated."""
    if len(summary.errors) < _MAX_RECORDED_ERRORS:
        summary.errors.append(detail)
    elif len(summary.errors) == _MAX_RECORDED_ERRORS:
        summary.errors.append(f"... further failures suppressed after {_MAX_RECORDED_ERRORS}")


def _record_note(summary: DossierSummary, detail: str) -> None:
    """Append an advisory note, bounded — the twin of :func:`_record_error`.

    A note is a healthy-sweep observation (a truncated cap, a cadence ceiling),
    NOT a failure. Keeping the two channels apart is the whole fix: a run-row
    "N error(s)" that is nonzero every night stops being read, and a genuine
    census or collection failure then hides among permanent truncation notes.
    """
    if len(summary.notes) < _MAX_RECORDED_ERRORS:
        summary.notes.append(detail)
    elif len(summary.notes) == _MAX_RECORDED_ERRORS:
        summary.notes.append(f"... further notes suppressed after {_MAX_RECORDED_ERRORS}")


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------


async def run_dossier_refresh(
    es_client: ElasticClient,
    db_sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    trigger: str = "schedule",
    audit: AuditLogger | None = None,
) -> DossierSummary:
    """Sweep the internal network and refresh every host's dossier.

    Census (one ``size=0`` search) → header upserts → the stalest
    ``dossier_max_hosts_per_run`` hosts, each observed, classified and written
    under its own timeout → table prune → run stamp. Never raises: a sub-query
    failure, a bad host or a broken database all land in
    :attr:`DossierSummary.errors`, because this runs from a background loop
    where an exception is an app-level incident.

    Args:
        es_client: client for the SO ES cluster.
        db_sessionmaker: sessions are opened short and closed per phase; a
            multi-minute sweep must not hold a pooled connection.
        settings: read fresh on entry, so a config-console change applies to the
            next sweep with no restart.
        trigger: ``schedule`` | ``manual`` | ``inline`` — recorded on the run row
            so an operator can tell a nightly sweep from a Rebuild-now press.
        audit: where a fired conflict prod is delivered. Optional so a CLI probe
            or a test can sweep without an ES-backed audit index, but a caller
            that omits it advances the prod's rate limit with nothing to show
            for it — the bell entry derived in ``routes_meta`` is the other half
            of the same delivery and does not depend on this.

    Returns:
        A :class:`DossierSummary`. ``errors`` non-empty is not a failed sweep;
        it is the parts of one that degraded.
    """
    summary = DossierSummary(started_at=datetime.now(UTC).isoformat())

    if not settings.dossier_enabled:
        # No run row: nothing was swept, and stamping one would tell the
        # scheduler the dossier is fresh when the feature is simply off.
        summary.errors.append("host dossier disabled. dossier_enabled is off.")
        summary.finished_at = datetime.now(UTC).isoformat()
        return summary

    run_id = await _open_run(db_sessionmaker, trigger=trigger)
    if run_id is None:
        summary.errors.append("could not open a dossier_run row. The sweep did not run.")
        summary.finished_at = datetime.now(UTC).isoformat()
        return summary

    try:
        await _sweep(es_client, db_sessionmaker, settings, summary=summary, audit=audit)
    except Exception as exc:  # pragma: no cover - defence in depth
        _record_error(summary, f"sweep: {type(exc).__name__}: {exc}")
        _LOGGER.exception("dossier: sweep failed")

    summary.finished_at = datetime.now(UTC).isoformat()
    await _close_run(db_sessionmaker, run_id, summary)

    if summary.hosts_built or summary.hosts_pruned or summary.conflicts_prompted:
        _LOGGER.info(
            "dossier sweep (%s): %d/%d host(s) built, %d field(s), %d conflict(s), "
            "%d prod(s), %d pruned, %d error(s), %d note(s)",
            trigger,
            summary.hosts_built,
            summary.hosts_seen,
            summary.fields_written,
            summary.conflicts_detected,
            summary.conflicts_prompted,
            summary.hosts_pruned,
            len(summary.errors),
            len(summary.notes),
        )
    return summary


async def _sweep(
    es_client: ElasticClient,
    db_sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    summary: DossierSummary,
    audit: AuditLogger | None = None,
) -> None:
    """The body of one sweep, with the run row already claimed.

    Each stage is timed and its searches counted. The numbers go to the log,
    one INFO line per stage, and to :attr:`DossierSummary.stages`.
    """
    grid = counting(es_client)
    clock = StageClock(label="dossier sweep", grid=grid, logger=_LOGGER)
    try:
        await _sweep_stages(
            grid, db_sessionmaker, settings, summary=summary, audit=audit, clock=clock
        )
    finally:
        summary.stages = clock.as_dicts()


async def _sweep_stages(  # noqa: PLR0915 - one procedure, read top to bottom
    es_client: Any,
    db_sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    summary: DossierSummary,
    audit: AuditLogger | None,
    clock: StageClock,
) -> None:
    async with db_sessionmaker() as db:
        cidrs = (await effective_internal_identifiers(db, settings)).cidrs
    if not cidrs:
        # Without CIDRs "internal" is undefined. Sweeping every address the grid
        # has seen would build dossiers for the internet.
        summary.errors.append("no internal CIDRs configured. soc-ai cannot scope the network.")
        return

    lookback_days = max(1, int(settings.dossier_lookback_days))
    window_hours = lookback_days * 24
    index = settings.events_index_pattern

    # TWO aggregations for the network, before the census, because both phases
    # need them: the census adopts the addresses they name, and every host build
    # reads its own slice out of them. Per-host they would be two extra
    # aggregations per address, for answers that do not vary by address.
    with clock.stage("agent inventory") as stage:
        agent_inventory = await collect_agent_inventory(
            elastic=es_client, settings=settings, window_hours=window_hours
        )
        stage.detail = f"{len(agent_inventory.hosts)} agents"
    with clock.stage("dns names") as stage:
        dns_names = await collect_dns_names(
            elastic=es_client, settings=settings, window_hours=window_hours, cidrs=cidrs
        )
        stage.detail = f"{len(dns_names.claims)} claims"
    with clock.stage("dhcp leases") as stage:
        leases = await collect_dhcp_leases(
            elastic=es_client, settings=settings, window_hours=window_hours, cidrs=cidrs
        )
        stage.detail = f"{len(leases.leases)} leases"
    for detail in (*agent_inventory.errors, *dns_names.errors, *leases.errors):
        _record_error(summary, detail)
    # The DNS/agent passes' truncation notes ride the notes channel, never the
    # error one — a hit cap is a healthy-but-capped pass (see `_dns_truncation`).
    for note in (*agent_inventory.notes, *dns_names.notes, *leases.notes):
        _record_note(summary, note)

    with clock.stage("census") as stage:
        candidates = await _census(
            es_client,
            index,
            cidrs,
            lookback_days,
            summary,
            agg_size=_census_agg_size(settings),
            page_cap=int(settings.dossier_max_hosts),
        )
        _ingest_agent_claims(agent_inventory, cidrs, candidates)
        _ingest_dns_names(dns_names, cidrs, candidates)
        _drop_broadcast(candidates, cidrs)
        stage.detail = f"{len(candidates)} addresses"
    with clock.stage("census record"):
        # A row an older census wrote for a broadcast address goes too.
        try:
            async with db_sessionmaker() as db:
                await dossier_store.delete_hosts(db, sorted(_broadcast_addresses(cidrs)))
        except Exception as exc:
            _record_error(summary, f"broadcast cleanup: {type(exc).__name__}: {exc}")
        summary.hosts_seen = len(candidates)
        if candidates:
            await _record_census(db_sessionmaker, candidates, summary)
        _note_cadence(settings, summary)
        if not _census_failed(summary):
            # Before the builds, so the sweep spends no host budget on an address
            # that left the network weeks ago.
            await _prune_stale(db_sessionmaker, settings, set(candidates), summary)

    with clock.stage("host builds") as stage:
        due = await _due_hosts(db_sessionmaker, int(settings.dossier_max_hosts_per_run))
        for ip in due:
            try:
                await _build_host(
                    es_client,
                    db_sessionmaker,
                    settings,
                    ip,
                    cidrs=cidrs,
                    window_hours=window_hours,
                    summary=summary,
                    audit=audit,
                    agent_inventory=agent_inventory,
                    dns_names=dns_names,
                )
            except Exception as exc:
                detail = f"{ip}: {type(exc).__name__}: {exc}"
                _record_error(summary, detail)
                _LOGGER.warning("dossier: build failed for %s: %s", ip, exc)
                await _record_build_error(db_sessionmaker, ip, detail)
        stage.detail = f"{len(due)} hosts"

    if summary.partial_reads:
        # An error, not a note: the run did not read the grid in full, and the
        # Hosts screen marks a run with errors as degraded.
        _record_error(
            summary,
            f"partial read on {summary.partial_reads} host(s). The sweep kept their "
            f"previous role and services. First reason: {summary.partial_reason}",
        )

    with clock.stage("prune"):
        try:
            async with db_sessionmaker() as db:
                summary.hosts_pruned += await dossier_store.prune(
                    db, max_hosts=int(settings.dossier_max_hosts)
                )
        except Exception as exc:
            _record_error(summary, f"prune: {type(exc).__name__}: {exc}")
            _LOGGER.warning("dossier: prune failed: %s", exc)

    # Over the table as the builds and the prunes left it.
    with clock.stage("machines") as stage:
        await _build_machines(
            db_sessionmaker,
            settings,
            agent_inventory=agent_inventory,
            leases=leases,
            dns_names=dns_names,
            sightings=_sightings(candidates, agent_inventory),
            summary=summary,
        )
        stage.detail = f"{summary.machines} machines"

    # Last, so the build reads this sweep's census and machines. The build
    # batches its searches by the hosts the census holds, and it skips a host
    # whose profile is fresh and whose last activity the census dates. Run
    # before the census, it read the previous sweep's dates and missed the
    # hosts this sweep found.
    with clock.stage("profile build") as stage:
        build = await profile_job.build_profiles(es_client, db_sessionmaker, settings, cidrs)
        stage.detail = f"{build.written} rows"
    for detail in build.errors:
        _record_error(summary, detail)
    for note in build.notes:
        _record_note(summary, note)


__all__ = ["DossierSummary", "latest_run_started_at", "run_dossier_refresh"]
