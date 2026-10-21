"""Introspect the agent's enrichment DATA SOURCES for the config console.

Surfaces every source the triage agent draws on — the local-mirror feeds
(refreshed out-of-band, zero-egress) and the opt-in online lookups — each with
its freshness and key/enable status, so an operator can see at a glance WHAT
data is in play, HOW FRESH it is, and whether it needs an API key. This is the
single tracker that extends to RAG corpora once that lands.

It also owns the freshness rule of the local feeds (:func:`local_feed_health`).
The Data sources panel and the Agent tools panel both read it, so a feed the
panel calls stale is the feed whose tool the agent-tools panel calls degraded.
The rule for the blocklists is the doctor's (``soc_ai.doctor.check_blocklists``):
a configured feed file older than ``blocklist_stale_threshold_days`` is stale,
and an absent one is missing. tests/test_data_sources.py pins the two together.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, SecretStr

from soc_ai.config import Settings
from soc_ai.enrichment.refresh import cloud_prefix_staleness_days

# Source -> on-disk filename of each refreshable blocklist feed. The loaders in
# soc_ai.enrichment.blocklists read exactly these files. internal_seed is left
# out on purpose: it is operator data with no refresh, so its age says nothing.
# The same map as soc_ai.doctor._BLOCKLIST_FEED_FILES (a test pins the two).
BLOCKLIST_FEED_FILES: dict[str, str] = {
    "urlhaus": "urlhaus.csv",
    "threatfox": "threatfox.json",
    "feodo": "feodo.csv",
    "tor": "tor_exits.txt",
    "spamhaus_drop": "spamhaus_drop.txt",
}

# The name of each refreshable feed in the row title. The title named
# Spamhaus, which is off by default, and left out ThreatFox, which is on
# (dogfood round 2, V2-8). The title now names the feeds the config loads.
BLOCKLIST_FEED_NAMES: dict[str, str] = {
    "urlhaus": "URLhaus",
    "threatfox": "ThreatFox",
    "feodo": "Feodo",
    "tor": "Tor",
    "spamhaus_drop": "Spamhaus DROP",
}

# The two files MaxmindReader.from_dir opens.
MAXMIND_FILES: tuple[str, ...] = ("GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb")

# The provider files CloudPrefixDB.from_dir loads.
CLOUD_PREFIX_FILES: tuple[str, ...] = ("aws.json", "gcp.json", "azure.json", "cloudflare.json")

FeedFileState = Literal["fresh", "stale", "missing"]
LocalFeedState = Literal["active", "stale", "partial", "missing", "off"]


@dataclass(frozen=True)
class BlocklistFeedFile:
    """The state of one configured blocklist feed file."""

    source: str
    state: FeedFileState
    age_days: float | None  # None when the file is missing


@dataclass(frozen=True)
class LocalFeedHealth:
    """The state of one local feed group and the facts behind it.

    ``reason`` is operator prose in STE: one sentence per fact, empty when the
    feed is active.
    """

    state: LocalFeedState
    reason: str


def _join(names: list[str]) -> str:
    if len(names) <= 1:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def blocklist_feed_files(
    settings: Settings, *, now: datetime | None = None
) -> list[BlocklistFeedFile]:
    """Each configured refreshable feed, judged by the doctor's rule.

    A feed counts only if ``blocklist_sources`` names it. A file older than
    ``blocklist_stale_threshold_days`` is stale. An absent file is missing.
    """
    configured = [s for s in settings.blocklist_sources if s in BLOCKLIST_FEED_FILES]
    threshold_days = settings.blocklist_stale_threshold_days
    now = now or datetime.now(UTC)
    out: list[BlocklistFeedFile] = []
    for source in configured:
        path = settings.blocklist_data_dir / BLOCKLIST_FEED_FILES[source]
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        except OSError:
            out.append(BlocklistFeedFile(source, "missing", None))
            continue
        age_days = (now - mtime).total_seconds() / 86400.0
        state: FeedFileState = "stale" if age_days > threshold_days else "fresh"
        out.append(BlocklistFeedFile(source, state, age_days))
    return out


def _blocklists_health(settings: Settings, now: datetime | None) -> LocalFeedHealth:
    files = blocklist_feed_files(settings, now=now)
    if not files:
        return LocalFeedHealth("off", "BLOCKLIST_SOURCES names no refreshable feed.")
    missing = [f.source for f in files if f.state == "missing"]
    stale = [f for f in files if f.state == "stale"]
    facts: list[str] = []
    if missing:
        facts.append(f"soc-ai finds no file for {_join(missing)}.")
    facts.extend(f"The {f.source} feed is {f.age_days or 0:.0f} days old." for f in stale)
    if stale:
        facts.append(f"A feed is stale after {settings.blocklist_stale_threshold_days} days.")
    reason = " ".join(facts)
    if len(missing) == len(files):
        return LocalFeedHealth("missing", reason)
    if stale:
        return LocalFeedHealth("stale", reason)
    if missing:
        return LocalFeedHealth("partial", reason)
    return LocalFeedHealth("active", "")


def _maxmind_health(settings: Settings) -> LocalFeedHealth:
    absent = [n for n in MAXMIND_FILES if not (settings.maxmind_data_dir / n).is_file()]
    if not absent:
        return LocalFeedHealth("active", "")
    reason = f"soc-ai finds no {_join(absent)} in MAXMIND_DATA_DIR."
    return LocalFeedHealth("missing" if len(absent) == len(MAXMIND_FILES) else "partial", reason)


def _cloud_prefixes_health(settings: Settings) -> LocalFeedHealth:
    d = settings.cloud_prefix_data_dir
    if not any((d / n).is_file() for n in CLOUD_PREFIX_FILES):
        return LocalFeedHealth("missing", "soc-ai finds no cloud prefix file.")
    # The rule enrich_ip applies before it warns the model about stale data.
    try:
        age = cloud_prefix_staleness_days(d)
    except Exception:  # a bad status file must not break the panel
        age = None
    threshold = settings.cloud_prefix_stale_threshold_days
    if age is not None and age > threshold:
        return LocalFeedHealth(
            "stale",
            f"The cloud prefix data is {age:.0f} days old. It is stale after {threshold} days.",
        )
    return LocalFeedHealth("active", "")


def local_feed_health(
    settings: Settings, *, now: datetime | None = None
) -> dict[str, LocalFeedHealth]:
    """The state of each local feed group, keyed by its data source id."""
    return {
        "blocklists": _blocklists_health(settings, now),
        "maxmind": _maxmind_health(settings),
        "cloud_prefixes": _cloud_prefixes_health(settings),
    }


class DataSourceOut(BaseModel):
    id: str
    name: str
    category: str  # "Grid" | "Local feed" | "Online lookup" | "External service"
    egress: str  # "none" | "on-lookup"
    enabled: bool  # the source would actually be used (flag on + key present if needed)
    present: bool  # local data exists / the service is configured
    last_refreshed: str | None  # ISO timestamp of the freshest local file (local feeds only)
    needs_key: bool
    key_configured: bool
    note: str
    # The status the panel shows: "active", "stale", "partial", "missing",
    # "needs_key" or "off". A local feed reads it from local_feed_health, so a
    # stale feed never reads "active" (dogfood 2026-10-19, H1-D11). The grid
    # row adds "down", "slow" and "unknown" from the health probe.
    state: str = "off"


def _service_state(*, enabled: bool, needs_key: bool, key_configured: bool) -> str:
    """The state of an online lookup or an external service."""
    if enabled:
        return "active"
    if needs_key and not key_configured:
        return "needs_key"
    return "off"


def _with_reason(reason: str, note: str) -> str:
    return f"{reason} {note}" if reason else note


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


def _secret_set(val: SecretStr | None) -> bool:
    """A key counts as configured only when it holds a non-blank value.

    A bare ``KEY=`` line reads as ``None`` from the env, but a caller can still
    hand us ``SecretStr("")``; the lookup tools treat that as not configured, and
    the catalog has to say the same or the page shows a lookup as enabled that
    every request refuses.
    """
    return val is not None and bool(val.get_secret_value().strip())


def blocklists_title(settings: Settings) -> str:
    """The row title: "Blocklists (URLhaus, ThreatFox, Feodo and Tor)"."""
    names = [
        BLOCKLIST_FEED_NAMES[s] for s in settings.blocklist_sources if s in BLOCKLIST_FEED_NAMES
    ]
    return f"Blocklists ({_join(names)})" if names else "Blocklists"


def _grid_row(settings: Settings, grid: Mapping[str, Mapping[str, Any]] | None) -> DataSourceOut:
    """The grid itself: Security Onion and Elasticsearch, from the health probe.

    Data sources listed every enrichment feed and no row for the grid that
    every alert and event comes from (dogfood 2026-10-19, R5-D30). ``grid`` is
    the result of the health probe, ``{"es": {...}, "so": {...}}``. None
    means no probe result yet.
    """
    pattern = str(getattr(settings, "events_index_pattern", "") or "logs-*")
    base = (
        f"soc-ai reads alerts and events from the index pattern `{pattern}`. It writes "
        "acknowledgements and cases through the Security Onion API. Set the connections "
        "in Settings > Connections."
    )
    es = dict((grid or {}).get("es") or {})
    so = dict((grid or {}).get("so") or {})
    if grid is None:
        state, reason = "unknown", "soc-ai has not probed the grid yet."
    elif not es.get("ok"):
        if es.get("state") == "slow":
            state, reason = "slow", "Elasticsearch answers the health probe late."
        else:
            state, reason = "down", "The health probe cannot read Elasticsearch."
    elif not so.get("ok"):
        state, reason = (
            "partial",
            "The health probe cannot reach the Security Onion API. soc-ai reads the grid. "
            "Acknowledgements and cases fail.",
        )
    else:
        state, reason = "active", ""
    return DataSourceOut(
        id="grid",
        name="Grid (Security Onion and Elasticsearch)",
        category="Grid",
        egress="none",
        enabled=True,
        present=bool(es.get("ok")),
        last_refreshed=None,
        needs_key=False,
        key_configured=False,
        note=_with_reason(reason, base),
        state=state,
    )


def collect_data_sources(
    settings: Settings, *, grid: Mapping[str, Mapping[str, Any]] | None = None
) -> list[DataSourceOut]:
    """Introspect every data source against the live config + filesystem.

    The first row is the grid. ``grid`` is the health probe result the route
    passes. The enrichment feeds and lookups follow.
    """
    out: list[DataSourceOut] = [_grid_row(settings, grid)]
    health = local_feed_health(settings)

    # ── Local-mirror feeds (zero-egress; refreshed by `soc-ai blocklists refresh`) ──
    blocklists = _files(settings.blocklist_data_dir, "*.csv", "*.txt", "*.json")
    out.append(
        DataSourceOut(
            id="blocklists",
            name=blocklists_title(settings),
            category="Local feed",
            egress="none",
            enabled=True,
            present=bool(blocklists),
            last_refreshed=_iso_mtime(blocklists),
            needs_key=False,
            key_configured=False,
            note=_with_reason(
                health["blocklists"].reason,
                "Run `soc-ai blocklists refresh` to fetch the feeds. The abuse.ch feeds "
                "need an abuse.ch auth key. Set it in Settings > API keys.",
            ),
            state=health["blocklists"].state,
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
            # No command consumes the key, so the row must not read "Needs
            # key": the files are copied by hand, and that is the whole ask.
            needs_key=False,
            key_configured=_secret_set(settings.maxmind_license_key),
            note=_with_reason(
                health["maxmind"].reason,
                "No command downloads these files. Copy GeoLite2-City.mmdb and "
                "GeoLite2-ASN.mmdb into MAXMIND_DATA_DIR. Then restart soc-ai.",
            ),
            state=health["maxmind"].state,
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
            note=_with_reason(
                health["cloud_prefixes"].reason,
                "Run `soc-ai blocklists refresh` to fetch the prefixes. The Azure URL "
                "rotates. Set AZURE_SERVICE_TAGS_URL when Azure tagging fails.",
            ),
            state=health["cloud_prefixes"].state,
        )
    )

    # ── Optional external threat-intel service ──
    misp_on = bool(str(settings.misp_url or "").strip())
    misp_key = _secret_set(settings.misp_api_key)
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
            key_configured=misp_key,
            note=(
                "Optional. Set the MISP URL in Settings > Online enrichment. Set the "
                "MISP API key in Settings > API keys."
            ),
            # The URL turns the client on. A URL with no key reads "needs_key".
            state=("needs_key" if not misp_key else "active") if misp_on else "off",
        )
    )

    # ── Opt-in ONLINE lookups (egress; default off) ──
    online = settings.allow_online_enrichment
    keyless_note = "Free. It needs no key. The switch in Settings > Online enrichment turns it on."
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
            note=keyless_note,
            state=_service_state(enabled=online, needs_key=False, key_configured=False),
        )
    )
    gn_key = _secret_set(settings.greynoise_api_key)
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
            note=(
                "It needs the switch in Settings > Online enrichment. It also needs a "
                "GreyNoise API key. Set the key in Settings > API keys."
            ),
            state=_service_state(enabled=online and gn_key, needs_key=True, key_configured=gn_key),
        )
    )
    shodan_key = _secret_set(settings.shodan_api_key)
    out.append(
        DataSourceOut(
            id="shodan_host",
            name="Shodan host (owner, banners, services, vulnerabilities)",
            category="Online lookup",
            egress="on-lookup",
            enabled=online and shodan_key,
            present=shodan_key,
            last_refreshed=None,
            needs_key=True,
            key_configured=shodan_key,
            note=(
                "Paid. It needs the switch in Settings > Online enrichment. It also "
                "needs a Shodan API key. Set the key in Settings > API keys."
            ),
            state=_service_state(
                enabled=online and shodan_key, needs_key=True, key_configured=shodan_key
            ),
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
            note=keyless_note,
            state=_service_state(enabled=online, needs_key=False, key_configured=False),
        )
    )
    return out
