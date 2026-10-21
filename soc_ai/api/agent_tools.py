"""Introspect the TOOLS available to the triage/chat agent for the config console.

Companion to :mod:`soc_ai.api.data_sources`: where that surfaces the enrichment
DATA an analyst can see, this surfaces the agent's CAPABILITIES — every tool the
agent can call, a one-line description, whether it reads or writes, and the
config/resources it depends on (Elasticsearch, PCAP, an API key, the online-
enrichment switch, …) so an operator can see at a glance what's available and
what a given tool needs turned on.

The catalogue is curated (not pure registry reflection) so each tool carries an
accurate human description + its real dependency predicates. A test cross-checks
that every registered read-only tool appears here, so the two can't silently
drift.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from soc_ai.api.data_sources import LocalFeedHealth, local_feed_health
from soc_ai.config import Settings


def _secret_set(val: Any) -> bool:
    raw = val.get_secret_value() if hasattr(val, "get_secret_value") else val
    return bool(raw and str(raw).strip())


def _flag(attr: str) -> Callable[[Settings], bool]:
    return lambda s: bool(getattr(s, attr, False))


def _str_set(attr: str) -> Callable[[Settings], bool]:
    return lambda s: bool(str(getattr(s, attr, "") or "").strip())


def _key_set(attr: str) -> Callable[[Settings], bool]:
    return lambda s: _secret_set(getattr(s, attr, None))


def _es(s: Settings) -> bool:
    return bool(getattr(s, "es_hosts", None))


def _online(s: Settings) -> bool:
    return bool(getattr(s, "allow_online_enrichment", False))


@dataclass(frozen=True)
class _Req:
    label: str
    ok: Callable[[Settings], bool]


@dataclass(frozen=True)
class _Feed:
    """A local feed a tool looks in. ``source_id`` keys local_feed_health."""

    label: str
    source_id: str


@dataclass(frozen=True)
class _ToolDef:
    name: str
    category: str
    read_only: bool
    description: str
    reqs: tuple[_Req, ...] = field(default_factory=tuple)
    # The local feeds the tool looks in. With none of them usable and no MISP,
    # an empty answer reads as "no hit" while the tool had nothing to search,
    # so the row is unavailable. With some of them stale or absent it is
    # degraded (dogfood 2026-10-19, R5-D9).
    feeds: tuple[_Feed, ...] = field(default_factory=tuple)


class AgentToolOut(BaseModel):
    name: str
    category: str
    read_only: bool
    description: str
    requires: list[str]  # every requirement label
    missing: list[str]  # the unmet ones (empty ⇒ available)
    available: bool
    # Requirements that are configured but down right now, per the live
    # health probe. They are in ``missing`` too, so the row reads unavailable.
    unreachable: list[str] = []
    # Local feeds the tool reads that are stale or absent while the tool still
    # has data to look in. The row stays available and reads degraded.
    degraded: list[str] = []
    # Why the row is degraded, or unavailable for want of a local feed. STE
    # prose for the operator. None when every feed the tool reads is fresh.
    state_reason: str | None = None


_ES = _Req("Elasticsearch", _es)
_ONLINE = _Req("Online enrichment", _online)
_SO = _Req("Security Onion", _str_set("so_host"))

_BLOCKLISTS = _Feed("Local blocklists", "blocklists")
_GEOIP = _Feed("MaxMind GeoLite2", "maxmind")
_CLOUD = _Feed("Cloud prefixes", "cloud_prefixes")

# Curated catalogue. Order = display order within a category.
_CATALOG: tuple[_ToolDef, ...] = (
    # ── Context & queries (Elasticsearch) ────────────────────────────────────
    _ToolDef(
        "get_alert_context",
        "Query",
        True,
        "Load the full enriched context of an alert. This is the first evidence.",
        (_ES,),
    ),
    _ToolDef(
        "query_events_oql", "Query", True, "Search Security Onion events with an OQL query.", (_ES,)
    ),
    _ToolDef(
        "query_zeek_logs",
        "Query",
        True,
        "Query the raw Zeek logs for a host or a flow: conn, dns, http, ssl, ja3 and files.",
        (_ES,),
    ),
    _ToolDef(
        "query_detections",
        "Query",
        True,
        "Inspect the Security Onion detection rules that fired.",
        (_ES,),
    ),
    _ToolDef(
        "get_rule_content",
        "Query",
        True,
        "Fetch the full text of a detection rule by SID or title. The text shows what the "
        "signature matches.",
        (_ES,),
    ),
    _ToolDef(
        "decode_payload",
        "Query",
        True,
        "Decode the base64 or hex payload bytes of an alert into strings, indicators "
        "and protocol facts. The decode runs locally with no egress.",
        (),
    ),
    _ToolDef(
        "query_cases",
        "Query",
        True,
        "Search the Security Onion cases for related or earlier work.",
        (_ES,),
    ),
    _ToolDef(
        "prevalence",
        "Query",
        True,
        "Measure how common an IP, a domain or a hash is across the grid.",
        (_ES,),
    ),
    _ToolDef(
        "rule_prevalence",
        "Query",
        True,
        "Measure how noisy a detection rule is: the fires per day and the distinct hosts.",
        (_ES,),
    ),
    _ToolDef(
        "suggest_rule_tuning",
        "Query",
        True,
        "Find out if a rule fires mostly false positives and is a candidate to mute. The "
        "tool reads the volume and the acknowledge and escalate trend.",
        (_ES,),
    ),
    _ToolDef(
        "host_summary",
        "Query",
        True,
        "Describe a host by IP: the identity, the OS and user-agent fingerprint, and the "
        "recent alert history.",
        (_ES,),
    ),
    _ToolDef(
        "get_event_raw",
        "Query",
        True,
        "Fetch the raw document of one event by id. The chat uses it.",
        (_ES,),
    ),
    _ToolDef(
        "get_playbooks",
        "Query",
        True,
        "Fetch the Security Onion playbooks for a detection.",
        (_ES,),
    ),
    _ToolDef(
        "lookup_runbook",
        "Query",
        True,
        "Look up the analyst runbook for a detection or technique.",
        (),
    ),
    _ToolDef(
        "describe_dataset",
        "Query",
        True,
        "Find the fields that a dataset fills. The tool samples recent documents "
        "to learn the schema before a query.",
        (_ES,),
    ),
    _ToolDef(
        "field_values",
        "Query",
        True,
        "List the top values of a field with a terms aggregation.",
        (_ES,),
    ),
    _ToolDef(
        "beacon_profile",
        "Query",
        True,
        "Sweep zeek.conn for beacon cadence. The tool measures the inter-arrival "
        "coefficient of variation for each source and destination pair. Only a "
        "hunt uses it. Triage has no equivalent.",
        (_ES,),
    ),
    _ToolDef(
        "dns_entropy_scan",
        "Query",
        True,
        "Sweep zeek.dns for DNS entropy. The tool groups the query names by parent "
        "domain. It flags DGA and tunnel candidates by the mean Shannon entropy of "
        "the subdomain labels and by the query volume. Only a hunt uses it.",
        (_ES,),
    ),
    _ToolDef(
        "dcerpc_histogram",
        "Query",
        True,
        "Count the operations in zeek.dce_rpc. The tool flags the dangerous "
        "operations: Zerologon-style NetrServerAuthenticate*, the DCSync "
        "DRSGetNCChanges and DsGetNCChanges, and remote service creation. It also "
        "flags an operation that is rare against a busy baseline. Only a hunt uses it.",
        (_ES,),
    ),
    _ToolDef(
        "first_seen",
        "Query",
        True,
        "Sweep for new external destinations. The tool compares a recent window "
        "with a baseline window that ends where the recent window begins. It "
        "reports each destination with no sighting in the baseline. Only a hunt "
        "uses it.",
        (_ES,),
    ),
    # ── Enrichment (local-mirror feeds; online opt-in) ───────────────────────
    _ToolDef(
        "enrich_ip",
        "Enrichment",
        True,
        "Enrich an IP against local feeds: blocklists, GeoIP/ASN and cloud prefixes.",
        (),
        (_BLOCKLISTS, _GEOIP, _CLOUD),
    ),
    _ToolDef(
        "enrich_domain",
        "Enrichment",
        True,
        "Enrich a domain against the local blocklists, and against MISP if MISP is configured.",
        (),
        (_BLOCKLISTS,),
    ),
    _ToolDef(
        "enrich_hash",
        "Enrichment",
        True,
        "Enrich a file hash against the local blocklists, and against MISP if MISP is configured.",
        (),
        (_BLOCKLISTS,),
    ),
    _ToolDef(
        "shodan_internetdb",
        "Enrichment",
        True,
        "Read the free Shodan InternetDB record of a public IP: the ports, CPEs and CVEs.",
        (_ONLINE,),
    ),
    _ToolDef(
        "cve_lookup",
        "Enrichment",
        True,
        "Score a CVE with Shodan CVEDB: CVSS, EPSS and CISA-KEV. The lookup is free "
        "and needs no key.",
        (_ONLINE,),
    ),
    _ToolDef(
        "greynoise",
        "Enrichment",
        True,
        "Ask GreyNoise if an external IP is a mass internet scanner.",
        (_ONLINE, _Req("GreyNoise API key", _key_set("greynoise_api_key"))),
    ),
    _ToolDef(
        "shodan_host",
        "Enrichment",
        True,
        "Look up a host in the full Shodan record: the owner, banners, services and "
        "vulnerabilities. The lookup needs a paid key.",
        (_ONLINE, _Req("Shodan API key", _key_set("shodan_api_key"))),
    ),
    # ── Web research ─────────────────────────────────────────────────────────
    _ToolDef(
        "web_search",
        "Web research",
        True,
        "Search the web through SearXNG for threat intelligence and context.",
        (
            _Req("Web search enabled", _flag("web_search_enabled")),
            _Req("SearXNG URL", _str_set("searxng_url")),
        ),
    ),
    _ToolDef(
        "crawl_page",
        "Web research",
        True,
        "Read the content of a web page through crawl4ai. The tool reads a search hit in full.",
        (
            _Req("Page read enabled", _flag("crawl4ai_enabled")),
            _Req("crawl4ai URL", _str_set("crawl4ai_url")),
        ),
    ),
    # ── PCAP ─────────────────────────────────────────────────────────────────
    _ToolDef(
        "get_pcap",
        "PCAP",
        True,
        "Get the packet facts for a flow from the Security Onion sensor. The tool reads the "
        "full PCAP over SSH.",
        (
            _Req("PCAP enabled", _flag("pcap_enabled")),
            _Req("SSH sensor host", _str_set("so_ssh_host")),
        ),
    ),
    # ── Actions (write — analyst-executed) ───────────────────────────────────
    _ToolDef(
        "ack_alert",
        "Action",
        False,
        "Acknowledge an alert in Security Onion. The analyst runs this action.",
        (_SO,),
    ),
    _ToolDef(
        "escalate_to_case",
        "Action",
        False,
        "Escalate an alert to a new Security Onion case. The analyst runs this action.",
        (_SO,),
    ),
    _ToolDef(
        "add_case_comment",
        "Action",
        False,
        "Add a comment to a Security Onion case. The analyst runs this action.",
        (_SO,),
    ),
)

# Category display order.
CATEGORY_ORDER: tuple[str, ...] = ("Query", "Enrichment", "Web research", "PCAP", "Action")


def collect_agent_tools(
    settings: Settings, live: dict[str, bool] | None = None
) -> list[AgentToolOut]:
    """Introspect every agent tool against the live config and the live state.

    ``live`` maps a requirement label ("Elasticsearch", "Security Onion") to
    whether the health probe reached it. Configured is not available: the
    panel listed 17 Elasticsearch tools as available while /health said the
    grid was down (fleet 2026-10-01, RC6). A label absent from ``live`` is
    judged on config alone.
    """
    live = live or {}
    health = local_feed_health(settings)
    misp_on = bool(str(getattr(settings, "misp_url", None) or "").strip())
    out: list[AgentToolOut] = []
    for t in _CATALOG:
        missing = [r.label for r in t.reqs if not r.ok(settings)]
        unreachable = [
            r.label for r in t.reqs if r.label not in missing and live.get(r.label) is False
        ]
        feed_missing, degraded, reason = _feed_state(t.feeds, health, misp_on=misp_on)
        out.append(
            AgentToolOut(
                name=t.name,
                category=t.category,
                read_only=t.read_only,
                description=t.description,
                requires=[r.label for r in t.reqs] + [f.label for f in t.feeds],
                missing=missing + unreachable + feed_missing,
                available=not missing and not unreachable and not feed_missing,
                unreachable=unreachable,
                degraded=degraded,
                state_reason=reason,
            )
        )
    return out


def _feed_state(
    feeds: tuple[_Feed, ...], health: dict[str, LocalFeedHealth], *, misp_on: bool
) -> tuple[list[str], list[str], str | None]:
    """(missing feed labels, degraded feed labels, reason) for one tool.

    The rule for each feed is local_feed_health, the rule the Data sources
    panel shows. A feed in state "missing" or "off" has no data to look in.
    """
    if not feeds:
        return [], [], None
    states = [(f, health[f.source_id]) for f in feeds]
    not_active = [(f, h) for f, h in states if h.state != "active"]
    if not not_active:
        return [], [], None
    facts = " ".join(h.reason for _f, h in not_active if h.reason)
    usable = [f for f, h in states if h.state not in ("missing", "off")]
    if not usable and not misp_on:
        reason = f"{facts} The tool has no data to look in.".strip()
        return [f.label for f in feeds], [], reason
    reason = f"{facts} An empty answer can come from a gap in a feed.".strip()
    return [], [f.label for f, _h in not_active], reason


def catalog_tool_names() -> set[str]:
    """Tool names present in the curated catalogue (for the drift cross-check)."""
    return {t.name for t in _CATALOG}
