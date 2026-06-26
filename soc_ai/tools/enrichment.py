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

import ipaddress as _ipaddress
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import BaseModel, Field

from soc_ai.config import Settings
from soc_ai.enrichment.blocklists import BlocklistDB, BlocklistHit
from soc_ai.enrichment.cloud_tags import CloudPrefixDB
from soc_ai.enrichment.maxmind import AsnInfo, GeoIpInfo, MaxmindReader
from soc_ai.enrichment.refresh import cloud_prefix_staleness_days
from soc_ai.tools._registry import tool

_LOGGER = logging.getLogger(__name__)


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
    asn: AsnInfo | None = None
    geoip: GeoIpInfo | None = None
    cloud_provider: str | None = None
    misp_hits: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}


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
        ioc_type: str | None = None,
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

    if blocklist is not None:
        try:
            enrichment.blocklist_hits = blocklist.lookup_ip(ip)
        except Exception as e:  # fail-open
            enrichment.errors.append(f"blocklist lookup failed: {e}")

    if maxmind is not None and not enrichment.internal:
        try:
            enrichment.asn = maxmind.lookup_asn(ip)
            enrichment.geoip = maxmind.lookup_geoip(ip)
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
            misp_results = await misp.search_ioc(ip, ioc_type="ip-src")
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
    if blocklist is not None:
        try:
            enrichment.blocklist_hits = blocklist.lookup_domain(domain)
        except Exception as e:  # fail-open
            enrichment.errors.append(f"blocklist lookup failed: {e}")
    if misp is not None:
        try:
            misp_results = await misp.search_ioc(domain, ioc_type="domain")
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
    if blocklist is not None:
        try:
            enrichment.blocklist_hits = blocklist.lookup_hash(hash_value)
        except Exception as e:  # fail-open
            enrichment.errors.append(f"blocklist lookup failed: {e}")
    misp_type = _HASH_TYPES.get(algo.lower())
    if misp is not None and misp_type is not None:
        try:
            misp_results = await misp.search_ioc(hash_value, ioc_type=misp_type)
            enrichment.misp_hits = [_finding_from_misp(m) for m in misp_results]
        except Exception as e:  # fail-open
            enrichment.errors.append(f"misp lookup failed: {e}")
    return enrichment
