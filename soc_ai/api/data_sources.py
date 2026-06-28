"""Introspect the agent's enrichment DATA SOURCES for the config console.

Surfaces every source the triage agent draws on — the local-mirror feeds
(refreshed out-of-band, zero-egress) and the opt-in online lookups — each with
its freshness and key/enable status, so an operator can see at a glance WHAT
data is in play, HOW FRESH it is, and whether it needs an API key. This is the
single tracker that extends to RAG corpora once that lands.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from soc_ai.config import Settings


class DataSourceOut(BaseModel):
    id: str
    name: str
    category: str  # "Local feed" | "Online lookup" | "External service"
    egress: str  # "none" | "on-lookup"
    enabled: bool  # the source would actually be used (flag on + key present if needed)
    present: bool  # local data exists / the service is configured
    last_refreshed: str | None  # ISO timestamp of the freshest local file (local feeds only)
    needs_key: bool
    key_configured: bool
    note: str


def _files(d: Path, *patterns: str) -> list[Path]:
    out: list[Path] = []
    for pat in patterns:
        try:
            out.extend(p for p in d.glob(pat) if p.is_file())
        except OSError:
            continue
    return out


def _iso_mtime(paths: list[Path]) -> str | None:
    """ISO timestamp of the freshest file in *paths*, or None if none exist."""
    times = []
    for p in paths:
        try:
            times.append(p.stat().st_mtime)
        except OSError:
            continue
    if not times:
        return None
    return datetime.fromtimestamp(max(times), tz=UTC).isoformat()


def collect_data_sources(settings: Settings) -> list[DataSourceOut]:
    """Introspect every enrichment data source against the live config + filesystem."""
    out: list[DataSourceOut] = []

    # ── Local-mirror feeds (zero-egress; refreshed by `soc-ai blocklists refresh`) ──
    blocklists = _files(settings.blocklist_data_dir, "*.csv", "*.txt", "*.json")
    out.append(
        DataSourceOut(
            id="blocklists",
            name="Blocklists (URLhaus / Feodo / Tor / Spamhaus)",
            category="Local feed",
            egress="none",
            enabled=True,
            present=bool(blocklists),
            last_refreshed=_iso_mtime(blocklists),
            needs_key=False,
            key_configured=False,
            note="Refresh with `soc-ai blocklists refresh`. abuse.ch feeds need ABUSE_CH_AUTH_KEY.",
        )
    )
    maxmind = _files(settings.maxmind_data_dir, "*.mmdb")
    out.append(
        DataSourceOut(
            id="maxmind",
            name="MaxMind GeoLite2 (GeoIP / ASN)",
            category="Local feed",
            egress="none",
            enabled=True,
            present=bool(maxmind),
            last_refreshed=_iso_mtime(maxmind),
            needs_key=True,
            key_configured=settings.maxmind_license_key is not None,
            note="Needs MAXMIND_LICENSE_KEY to refresh.",
        )
    )
    cloud = _files(settings.cloud_prefix_data_dir, "*.json")
    out.append(
        DataSourceOut(
            id="cloud_prefixes",
            name="Cloud prefixes (AWS / GCP / Azure / Cloudflare)",
            category="Local feed",
            egress="none",
            enabled=True,
            present=bool(cloud),
            last_refreshed=_iso_mtime(cloud),
            needs_key=False,
            key_configured=False,
            note="Azure's URL rotates — set AZURE_SERVICE_TAGS_URL if azure tagging fails.",
        )
    )

    # ── Optional external threat-intel service ──
    misp_on = bool(str(settings.misp_url or "").strip())
    out.append(
        DataSourceOut(
            id="misp",
            name="MISP (threat-intel matches)",
            category="External service",
            egress="on-lookup",
            enabled=misp_on,
            present=misp_on,
            last_refreshed=None,
            needs_key=True,
            key_configured=settings.misp_api_key is not None,
            note="Optional. Set MISP_URL + MISP_API_KEY to enable.",
        )
    )

    # ── Opt-in ONLINE lookups (egress; default off) ──
    online = settings.allow_online_enrichment
    out.append(
        DataSourceOut(
            id="shodan_internetdb",
            name="Shodan InternetDB (external host posture)",
            category="Online lookup",
            egress="on-lookup",
            enabled=online,
            present=online,
            last_refreshed=None,
            needs_key=False,
            key_configured=False,
            note="Free, no key. Enabled by the Online enrichment master switch.",
        )
    )
    gn_key = settings.greynoise_api_key is not None
    out.append(
        DataSourceOut(
            id="greynoise",
            name="GreyNoise (internet scanner-noise)",
            category="Online lookup",
            egress="on-lookup",
            enabled=online and gn_key,
            present=gn_key,
            last_refreshed=None,
            needs_key=True,
            key_configured=gn_key,
            note="Needs the Online enrichment switch + GREYNOISE_API_KEY in .env.",
        )
    )
    shodan_key = settings.shodan_api_key is not None
    out.append(
        DataSourceOut(
            id="shodan_host",
            name="Shodan host (full /shodan/host — banners, services, vulns)",
            category="Online lookup",
            egress="on-lookup",
            enabled=online and shodan_key,
            present=shodan_key,
            last_refreshed=None,
            needs_key=True,
            key_configured=shodan_key,
            note="Paid. Needs the Online enrichment switch + SHODAN_API_KEY in .env.",
        )
    )
    out.append(
        DataSourceOut(
            id="cvedb",
            name="Shodan CVEDB (CVE → CVSS / EPSS / KEV)",
            category="Online lookup",
            egress="on-lookup",
            enabled=online,
            present=online,
            last_refreshed=None,
            needs_key=False,
            key_configured=False,
            note="Free, no key. Enabled by the Online enrichment master switch.",
        )
    )
    return out
