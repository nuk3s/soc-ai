"""Local-only IOC enrichment.

v1 enrichment sources, in order of preference:

1. **Internal CIDR check** (free, instant) - flags an IP as belonging to one
   of the operator-configured ``INTERNAL_CIDRS``. Cheap signal that almost
   always changes the analyst's interpretation.
2. **BlocklistDB** (optional) - if a BlocklistDB was loaded at start-up,
   probes the in-memory dict/set for this indicator. Zero network egress.
3. **MaxMind GeoLite2** (optional) - local .mmdb file lookups for ASN +
   city-level GeoIP data.  Zero network egress.
4. **CloudPrefixDB** (optional) - local prefix-list lookup to tag the IP as
   belonging to a cloud provider (AWS/GCP/Azure/Cloudflare).  Zero egress.
5. **MISP** (optional) - if ``MISP_URL`` and ``MISP_API_KEY`` are set,
   queries the MISP REST API for matching attributes. Read-only.

External services (VT, OTX, Shodan, GreyNoise) are **out of scope for v1**;
the function signatures here are stable so they can be filled in later
without churning the agent's tool surface.
"""

from __future__ import annotations

import asyncio
import ipaddress as _ipaddress
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from soc_ai.config import Settings
from soc_ai.demo.guard import assert_egress_allowed
from soc_ai.enrichment.blocklists import (
    FEED_PROFILES,
    BlocklistDB,
    BlocklistHit,
    IndicatorKind,
    feed_of_hit,
)
from soc_ai.enrichment.cloud_tags import CloudPrefixDB
from soc_ai.enrichment.maxmind import AsnInfo, GeoIpInfo, MaxmindReader
from soc_ai.enrichment.refresh import cloud_prefix_staleness_days
from soc_ai.tools._registry import tool

_LOGGER = logging.getLogger(__name__)


ReputationStatus = Literal["listed", "not_listed", "not_checked"]
LISTED: ReputationStatus = "listed"
NOT_LISTED: ReputationStatus = "not_listed"
NOT_CHECKED: ReputationStatus = "not_checked"
NotCheckedReason = Literal["no_feed", "stale_feed", "lookup_failed", "internal_address"]


class Finding(BaseModel):
    """One enrichment hit, traceable to a single source."""

    source: str  # e.g. "internal_cidr", "misp"
    category: str  # e.g. "internal_network", "ioc_match"
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class EnrichmentResult(BaseModel):
    """Aggregated enrichment for a single indicator.

    Legacy shape kept for backwards compat. New callers should use
    ``IndicatorEnrichment``.
    """

    indicator: str
    indicator_type: str  # "ip", "domain", "hash:md5", "hash:sha256", ...
    findings: list[Finding] = Field(default_factory=list)


class IndicatorEnrichment(BaseModel):
    """Structured enrichment for one indicator (IP / domain / hash).

    New shape introduced by the synth-first redesign (Task 8). Replaces
    the legacy ``EnrichmentResult`` for the synth-first pipeline; the
    legacy ``EnrichmentResult`` stays as a wire-compat alias so existing
    callers keep working until they migrate.
    """

    indicator: str
    indicator_type: str  # "ip" | "domain" | "sha256"
    internal: bool = False
    blocklist_hits: list[BlocklistHit] = Field(default_factory=list)
    reputation_status: ReputationStatus | None = None
    """What the feeds support about this indicator.

    - ``listed``: a feed lists the indicator. ``feeds_matched`` names it.
    - ``not_listed``: a malware feed that holds this indicator type is loaded,
      and no checked feed lists the indicator. The miss is evidence for the
      feeds in ``feeds_checked`` and for no other feed.
    - ``not_checked``: no malware feed that holds this indicator type is
      loaded. The empty ``blocklist_hits`` is an absence of data.
    - ``None``: the record does not say. It predates this field.

    The older shape named the loaded feeds in ``blocklist_sources`` and set
    ``blocklist_checked: true`` when one feed loaded. A production host loaded
    the Tor exit list alone. Each lookup then read ``blocklist_checked: true``,
    the prompt counted the miss as positive evidence, and two hunts read
    ``blocklist_sources: ["tor"]`` with no hit as a Tor hit.
    """
    feeds_matched: list[str] = Field(default_factory=list)
    """The feeds that list the indicator. Empty on a miss."""
    feeds_checked: list[str] = Field(default_factory=list)
    """The loaded feeds that hold this indicator type. Each one was checked.

    A feed in this list did not match unless ``feeds_matched`` also names it.
    """
    not_checked_reason: NotCheckedReason | None = None
    """Why the status is ``not_checked``. ``None`` for each other status.

    - ``no_feed``: no fresh malware feed that indexes this indicator type is
      loaded.
    - ``stale_feed``: the malware feeds of this type are loaded and stale.
    - ``lookup_failed``: the lookup raised an error.
    - ``internal_address``: the address is internal. The feeds list public
      infrastructure, so a miss says nothing. This reason is not a gap in the
      feeds: the gates and the timeline do not treat it as one.
    """
    feeds_stale: list[str] = Field(default_factory=list)
    """The loaded feeds of this indicator type whose file is too old.

    A match on a stale feed is still a match. A miss on a stale feed is not
    evidence, so a stale feed is not in ``feeds_checked``.
    """
    feeds_not_loaded: list[str] = Field(default_factory=list)
    """The configured feeds that are not loaded. They answered nothing."""
    reputation_note: str | None = None
    """One plain statement of what the result supports."""
    blocklist_sources: list[str] | None = Field(default=None, exclude=True)
    """The loaded feeds, in the older shape. Not in the dump.

    Kept as an input so that a record stored before ``reputation_status``
    still reads: ``None`` says nothing, ``[]`` says that no feed was loaded,
    and a list says that those feeds were loaded. A reader of the dump could
    take the name for a list of matches, so the dump no longer holds it.
    """
    asn: AsnInfo | None = None
    geoip: GeoIpInfo | None = None
    cloud_provider: str | None = None
    misp_hits: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}

    @property
    def blocklist_checked(self) -> bool | None:
        """Whether a miss here is evidence, or ``None`` if the record does not say.

        ``False`` for ``not_checked`` with a gap in the feeds: no feed, a stale
        feed or a failed lookup. ``None`` for ``not_checked`` on an internal
        address, which says nothing about the feeds. A record of the older
        shape reads as it did: ``False`` when no feed was loaded. The value is
        not in the dump: ``reputation_status`` carries it there.
        """
        if self.reputation_status is not None:
            if self.reputation_status != NOT_CHECKED:
                return True
            # An internal address is not a gap in the feeds. The record makes
            # no claim about them.
            return None if self.not_checked_reason == "internal_address" else False
        if self.blocklist_sources is None:
            return None
        return bool(self.blocklist_sources)


@dataclass
class EnrichmentContext:
    """Bundle of local enrichment sources passed to enrich_* tools.

    The orchestrator constructs ONE EnrichmentContext per process at
    startup and reuses it across alerts. Keeps the t_enrich_* tools
    ignorant of the file-loading mechanics.
    """

    blocklist: BlocklistDB
    maxmind: MaxmindReader
    cloud: CloudPrefixDB


def build_local_enrichment_context(settings: Settings) -> EnrichmentContext:
    """Build a populated :class:`EnrichmentContext` from settings.

    Reads BlocklistDB / MaxMind / CloudPrefixDB from their on-disk data dirs.
    Fail-open: each loader logs warnings + falls back to empty if its files are
    missing/malformed, so this never raises. Used by the FastAPI app, the
    synth-first pipeline, and the MCP server so every entry point gets the same
    local enrichment sources.
    """
    blocklist = BlocklistDB.from_dir(
        settings.blocklist_data_dir,
        sources=settings.blocklist_sources,
        spamhaus_license_acknowledged=settings.spamhaus_license_acknowledged,
    )
    # One high-signal warning when NOTHING loaded — the Docker deploy seeds the
    # blocklist volume with a manual `soc-ai blocklists refresh`, and if that step
    # is skipped the agent silently loses the local-threat-intel signal (every IOC
    # lookup misses). Point the operator straight at the remediation instead of
    # only emitting a per-source "file missing" line buried in the logs.
    if not blocklist.loaded_sources:
        _LOGGER.warning(
            "no blocklist sources loaded from %s — local IOC reputation is DISABLED. "
            "Seed it with `soc-ai blocklists refresh` (Docker: "
            "`docker compose run --rm soc-ai soc-ai blocklists refresh`); some feeds "
            "(abuse.ch urlhaus/threatfox/feodo) also require ABUSE_CH_AUTH_KEY.",
            settings.blocklist_data_dir,
        )
    maxmind = MaxmindReader.from_dir(settings.maxmind_data_dir)
    cloud = CloudPrefixDB.from_dir(settings.cloud_prefix_data_dir)
    return EnrichmentContext(blocklist=blocklist, maxmind=maxmind, cloud=cloud)


class MispClient:
    """Minimal read-only MISP REST client.

    Built around ``POST /attributes/restSearch``, which is the canonical
    endpoint for IOC lookup and supports filtering by ``value`` and ``type``.

    The client is intentionally narrow: v1 only needs to ask "is this
    indicator known to the operator's MISP instance, and what comments / tags
    are attached?" Search returns the raw ``Attribute`` list so callers can
    show the analyst whatever fields are most relevant to their workflow.
    """

    def __init__(self, settings: Settings) -> None:
        assert_egress_allowed(settings, "misp")
        if settings.misp_url is None:
            raise ValueError("MISP_URL is not configured")
        api_key = settings.misp_api_key.get_secret_value() if settings.misp_api_key else ""
        # TLS verification: prefer a pinned CA bundle, else the boolean toggle.
        # Default secure (verify=True) — the API key transits this channel, so a
        # passive MITM on an unverified link could harvest it. Homelab MISP using
        # a self-signed cert sets MISP_CA_BUNDLE (or MISP_VERIFY_SSL=false to opt
        # out of verification explicitly).
        verify: bool | str = settings.misp_verify_ssl
        if settings.misp_ca_bundle is not None:
            verify = str(settings.misp_ca_bundle)
        self._client = httpx.AsyncClient(
            base_url=str(settings.misp_url).rstrip("/"),
            headers={
                "Authorization": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(20.0, connect=5.0),
            verify=verify,
        )

    async def search_ioc(
        self,
        value: str,
        ioc_type: str | list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """POST /attributes/restSearch and return the ``Attribute`` array.

        Returns ``[]`` on transport / HTTP / decode failures - enrichment is
        a soft dependency, never a triage blocker.
        """
        body: dict[str, Any] = {"value": value, "returnFormat": "json"}
        if ioc_type:
            body["type"] = ioc_type
        try:
            resp = await self._client.post("/attributes/restSearch", json=body)
            resp.raise_for_status()
            payload = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            _LOGGER.warning("MISP lookup failed for %s: %s", value, e)
            return []
        response = payload.get("response", {})
        attribute = response.get("Attribute", [])
        return list(attribute) if isinstance(attribute, list) else []

    async def aclose(self) -> None:
        await self._client.aclose()


_NO_FEEDS_LOADED = (
    "blocklist: no sources loaded, so no reputation lookup ran. An empty "
    "blocklist_hits here is an absence of data, NOT a clean result. Refresh the "
    "feeds with `soc-ai blocklists refresh`."
)

_KIND_WORD: dict[IndicatorKind, str] = {
    "ip": "addresses",
    "domain": "domains",
    "md5": "MD5 hashes",
    "sha1": "SHA-1 hashes",
    "sha256": "SHA-256 hashes",
}


def _names(feeds: Sequence[str]) -> str:
    quoted = [f"`{feed}`" for feed in feeds]
    if len(quoted) <= 1:
        return "".join(quoted)
    return ", ".join(quoted[:-1]) + " and " + quoted[-1]


def _feed_word(feeds: Sequence[str]) -> str:
    return "feed" if len(feeds) == 1 else "feeds"


def _reputation_note(
    status: ReputationStatus,
    kind: IndicatorKind,
    matched: Sequence[str],
    checked: Sequence[str],
    not_loaded: Sequence[str],
    *,
    stale: Sequence[str] = (),
    internal: bool = False,
    failed: bool = False,
) -> str:
    """The plain statement of what the reputation result supports."""
    sentences: list[str] = []
    if status == LISTED:
        verb = "lists" if len(matched) == 1 else "list"
        sentences.append(f"The {_feed_word(matched)} {_names(matched)} {verb} this indicator.")
    elif status == NOT_LISTED:
        verb = "does" if len(checked) == 1 else "do"
        sentences.append(
            f"The {_feed_word(checked)} {_names(checked)} {verb} not list this indicator. "
            "The miss is evidence for the checked feeds only."
        )
    elif failed:
        sentences.append(
            "The lookup failed, so no feed was checked. "
            "The reputation of this indicator is not checked. "
            "The empty blocklist_hits is not a clean result."
        )
    elif internal:
        sentences.append(
            "This is an internal address. The feeds list public infrastructure, so a miss "
            "says nothing about it. The reputation of this indicator is not checked."
        )
    else:
        sentences.append(
            f"No {'fresh ' if stale else ''}malware feed that holds "
            f"{_KIND_WORD.get(kind, 'this indicator type')} is loaded. "
            "The reputation of this indicator is not checked. "
            "The empty blocklist_hits is not a clean result."
        )
        if checked:
            verb = "does" if len(checked) == 1 else "do"
            sentences.append(
                f"The {_feed_word(checked)} {_names(checked)} {verb} not list it. "
                "That miss does not clear the indicator."
            )
    if stale and status != LISTED:
        verb = "is" if len(stale) == 1 else "are"
        sentences.append(
            f"The {_feed_word(stale)} {_names(stale)} {verb} stale. "
            "A miss on a stale feed is not evidence."
        )
    if not_loaded:
        verb = "is" if len(not_loaded) == 1 else "are"
        sentences.append(
            f"The {_feed_word(not_loaded)} {_names(not_loaded)} {verb} configured and not loaded."
        )
    return " ".join(sentences)


def _stale_feeds(
    blocklist: BlocklistDB, feeds: Sequence[str], settings: Settings | None
) -> list[str]:
    """The feeds whose file is older than ``blocklist_stale_threshold_days``.

    A feed with no recorded file time is not called stale: a database that a
    test or a caller built in memory has no file.
    """
    if settings is None:
        return []
    limit = timedelta(days=max(1, int(settings.blocklist_stale_threshold_days)))
    now = datetime.now(UTC)
    out: list[str] = []
    for feed in feeds:
        stamp = blocklist.file_mtimes.get(feed)
        if stamp is None:
            continue
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        if now - stamp > limit:
            out.append(feed)
    return out


def _record_blocklist_scope(
    enrichment: IndicatorEnrichment,
    blocklist: BlocklistDB | None,
    kind: IndicatorKind,
    *,
    settings: Settings | None = None,
    failed: bool = False,
) -> None:
    """Record what the feeds support about the indicator.

    Four lists and one status. ``feeds_matched`` names the feeds of the hits.
    ``feeds_checked`` names the loaded, fresh feeds whose loader indexes this
    indicator type: the Tor exit list holds addresses, so it is not checked for
    a domain, and URLhaus indexes no hash, so it is not checked for an MD5.
    ``feeds_stale`` names the feeds of that type whose file is too old.
    ``feeds_not_loaded`` names the configured feeds that did not load.

    A miss is ``not_listed`` only when a fresh malware feed was checked. Each
    other miss is ``not_checked``: a miss on the Tor exit list says only that
    the address is not a Tor exit, a miss on a stale file says what the feed
    held weeks ago, a miss for an internal address says nothing because the
    feeds list public infrastructure, and a lookup that failed checked nothing.

    Silence is not a negative signal, and the only way the model learns the
    difference is if the result says it.
    """
    loaded = list(blocklist.loaded_sources) if blocklist else []
    holding = blocklist.feeds_for(kind) if blocklist and not failed else []
    stale = _stale_feeds(blocklist, holding, settings) if blocklist else []
    checked = [feed for feed in holding if feed not in stale]
    matched: dict[str, None] = {}
    for hit in enrichment.blocklist_hits:
        matched.setdefault(feed_of_hit(hit), None)
    not_loaded = list(dict.fromkeys(blocklist.missing_sources)) if blocklist else []
    if matched:
        status = LISTED
    elif (
        not failed
        and not enrichment.internal
        and any(FEED_PROFILES[feed].malware for feed in checked)
    ):
        status = NOT_LISTED
    else:
        status = NOT_CHECKED
    reason: NotCheckedReason | None = None
    if status == NOT_CHECKED:
        if failed:
            reason = "lookup_failed"
        elif enrichment.internal and any(FEED_PROFILES[feed].malware for feed in checked):
            reason = "internal_address"
        elif any(FEED_PROFILES[feed].malware for feed in stale):
            reason = "stale_feed"
        else:
            reason = "no_feed"
    enrichment.reputation_status = status
    enrichment.not_checked_reason = reason
    enrichment.feeds_matched = list(matched)
    enrichment.feeds_checked = checked
    enrichment.feeds_stale = stale
    enrichment.feeds_not_loaded = not_loaded
    enrichment.reputation_note = _reputation_note(
        status,
        kind,
        list(matched),
        checked,
        not_loaded,
        stale=stale,
        internal=reason == "internal_address",
        failed=failed,
    )
    enrichment.blocklist_sources = loaded
    if not loaded:
        enrichment.errors.append(_NO_FEEDS_LOADED)


def _finding_from_misp(m: dict[str, Any]) -> Finding:
    return Finding(
        source="misp",
        category=m.get("category", "ioc_match"),
        description=m.get("comment") or f"MISP attribute {m.get('id', '?')}",
        metadata=m,
    )


@tool(
    read_only=True,
    description=(
        "Enrich an IP via internal-CIDR check, blocklist, MaxMind,"
        " cloud-provider tagging, and optional MISP."
    ),
)
async def enrich_ip(
    ip: str,
    *,
    settings: Settings,
    misp: MispClient | None = None,
    blocklist: BlocklistDB | None = None,
    maxmind: MaxmindReader | None = None,
    cloud: CloudPrefixDB | None = None,
    internal_cidrs: Sequence[Any] | None = None,
) -> IndicatorEnrichment:
    """Local-only IP enrichment.

    All enrichment sources are optional. When None, the corresponding
    lookup is skipped. Internal IPs short-circuit the external-only
    lookups (MaxMind, cloud, MISP) since those would either return
    empty or be wasted compute on a private address.

    ``internal_cidrs`` overrides the internal-IP determination set. When
    provided (a sequence of ``ip_network`` objects), the ``internal`` flag is
    computed against it instead of ``settings.internal_cidrs``; the orchestrator
    threads its *effective* CIDR set (``settings.internal_cidrs`` union active
    ``cidr`` identifier rows minus muted) here so a discovered/manual CIDR an
    operator activated classifies hosts consistently across the Phase-A
    enrichment and the internal-IP downgrade path within one investigation. When
    ``None`` (the default), the read falls back to ``settings.internal_cidrs`` —
    behavior unchanged; the function stays pure (no DB access, the caller
    resolves the effective set).
    """
    enrichment = IndicatorEnrichment(indicator=ip, indicator_type="ip")

    try:
        addr = _ipaddress.ip_address(ip)
    except ValueError:
        enrichment.errors.append(f"invalid IP: {ip}")
        return enrichment

    cidrs = settings.internal_cidrs if internal_cidrs is None else internal_cidrs
    for net in cidrs:
        if addr in net:
            enrichment.internal = True
            break

    failed = False
    if blocklist is not None:
        try:
            enrichment.blocklist_hits = blocklist.lookup_ip(ip)
        except Exception as e:  # fail-open
            failed = True
            enrichment.errors.append(f"blocklist lookup failed: {e}")
    _record_blocklist_scope(enrichment, blocklist, "ip", settings=settings, failed=failed)

    if maxmind is not None and not enrichment.internal:
        try:
            # mmdb Reader.asn/.city are synchronous file reads — offload to a
            # thread so they don't block the single-worker event loop.
            enrichment.asn = await asyncio.to_thread(maxmind.lookup_asn, ip)
            enrichment.geoip = await asyncio.to_thread(maxmind.lookup_geoip, ip)
        except Exception as e:  # fail-open
            enrichment.errors.append(f"maxmind lookup failed: {e}")

    if cloud is not None and not enrichment.internal:
        try:
            tag = cloud.lookup_ip(ip)
            if tag is not None:
                enrichment.cloud_provider = tag.provider
            elif isinstance(addr, _ipaddress.IPv6Address):
                # IPv6 is not yet covered by the vendored prefix lists (v1.1).
                # Distinguish "not a cloud IP" from "can't tell" so the agent
                # doesn't interpret silence as a negative signal.
                enrichment.errors.append("cloud_tag: IPv6 not supported (v1.1)")
        except Exception as e:  # fail-open
            enrichment.errors.append(f"cloud-tag lookup failed: {e}")

        # Warn when the cloud-prefix data is stale so the agent knows a
        # None result might be a coverage gap, not a negative signal.
        try:
            threshold = settings.cloud_prefix_stale_threshold_days
            age = cloud_prefix_staleness_days(settings.cloud_prefix_data_dir)
            if age is not None and age > threshold:
                enrichment.errors.append(
                    f"cloud_tag: prefix data stale (last refresh {age:.0f} days ago)"
                )
        except Exception as e:  # fail-open — staleness check must never break triage
            _LOGGER.debug("cloud prefix staleness check failed: %s", e)

    if misp is not None and not enrichment.internal:
        try:
            # MISP stores IP IOCs under any of these attribute types. A malicious
            # C2 *destination* is conventionally ip-dst, so querying ip-src alone
            # silently misses the destination IOCs that matter most for triage.
            misp_results = await misp.search_ioc(
                ip, ioc_type=["ip-src", "ip-dst", "ip-src|port", "ip-dst|port"]
            )
            enrichment.misp_hits = [_finding_from_misp(m) for m in misp_results]
        except Exception as e:  # fail-open
            enrichment.errors.append(f"misp lookup failed: {e}")

    return enrichment


@tool(read_only=True, description="Enrich a domain via blocklist lookup and optional MISP.")
async def enrich_domain(
    domain: str,
    *,
    settings: Settings,
    misp: MispClient | None = None,
    blocklist: BlocklistDB | None = None,
) -> IndicatorEnrichment:
    """Local-only domain enrichment (BlocklistDB + optional MISP)."""
    enrichment = IndicatorEnrichment(indicator=domain, indicator_type="domain")
    failed = False
    if blocklist is not None:
        try:
            enrichment.blocklist_hits = blocklist.lookup_domain(domain)
        except Exception as e:  # fail-open
            failed = True
            enrichment.errors.append(f"blocklist lookup failed: {e}")
    _record_blocklist_scope(enrichment, blocklist, "domain", settings=settings, failed=failed)
    if misp is not None:
        try:
            misp_results = await misp.search_ioc(domain, ioc_type=["domain", "hostname"])
            enrichment.misp_hits = [_finding_from_misp(m) for m in misp_results]
        except Exception as e:  # fail-open
            enrichment.errors.append(f"misp lookup failed: {e}")
    return enrichment


_HASH_TYPES: dict[str, str] = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
}


@tool(read_only=True, description="Enrich a file hash via blocklist lookup and optional MISP.")
async def enrich_hash(
    hash_value: str,
    algo: str,
    *,
    settings: Settings,
    misp: MispClient | None = None,
    blocklist: BlocklistDB | None = None,
) -> IndicatorEnrichment:
    """Local-only file-hash enrichment (BlocklistDB + optional MISP).

    ``algo`` is one of ``md5``, ``sha1``, ``sha256``, ``sha512`` (case-insensitive).
    Other values still produce a result, but the MISP lookup is skipped.
    """
    indicator_type = _HASH_TYPES.get(algo.lower(), algo.lower())
    enrichment = IndicatorEnrichment(indicator=hash_value, indicator_type=indicator_type)
    failed = False
    if blocklist is not None:
        try:
            enrichment.blocklist_hits = blocklist.lookup_hash(hash_value)
        except Exception as e:  # fail-open
            failed = True
            enrichment.errors.append(f"blocklist lookup failed: {e}")
    # One type for each algorithm: a feed that indexes no MD5 cannot clear one.
    _record_blocklist_scope(enrichment, blocklist, indicator_type, settings=settings, failed=failed)
    misp_type = _HASH_TYPES.get(algo.lower())
    if misp is not None and misp_type is not None:
        try:
            misp_results = await misp.search_ioc(hash_value, ioc_type=misp_type)
            enrichment.misp_hits = [_finding_from_misp(m) for m in misp_results]
        except Exception as e:  # fail-open
            enrichment.errors.append(f"misp lookup failed: {e}")
    return enrichment
