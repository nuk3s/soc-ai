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
class _ToolDef:
    name: str
    category: str
    read_only: bool
    description: str
    reqs: tuple[_Req, ...] = field(default_factory=tuple)


class AgentToolOut(BaseModel):
    name: str
    category: str
    read_only: bool
    description: str
    requires: list[str]  # every requirement label
    missing: list[str]  # the unmet ones (empty ⇒ available)
    available: bool


_ES = _Req("Elasticsearch", _es)
_ONLINE = _Req("Online enrichment", _online)
_SO = _Req("Security Onion", _str_set("so_host"))

# Curated catalogue. Order = display order within a category.
_CATALOG: tuple[_ToolDef, ...] = (
    # ── Context & queries (Elasticsearch) ────────────────────────────────────
    _ToolDef(
        "get_alert_context",
        "Query",
        True,
        "Prefetch an alert's full enriched context — the starting evidence.",
        (_ES,),
    ),
    _ToolDef(
        "query_events_oql", "Query", True, "Search Security Onion events with an OQL query.", (_ES,)
    ),
    _ToolDef(
        "query_zeek_logs",
        "Query",
        True,
        "Query raw Zeek logs (conn, dns, http, ssl/ja3, files) for a host or flow.",
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
        "Fetch a detection rule's full text (what the signature matches) by SID or title.",
        (_ES,),
    ),
    _ToolDef(
        "decode_payload",
        "Query",
        True,
        "Decode alert payload bytes (base64/hex) into strings, indicators, and "
        "protocol facts — local, no egress.",
        (),
    ),
    _ToolDef(
        "query_cases", "Query", True, "Search existing SO cases for related or prior work.", (_ES,)
    ),
    _ToolDef(
        "prevalence",
        "Query",
        True,
        "How common is an indicator (IP/domain/hash) across the grid — rare vs ubiquitous.",
        (_ES,),
    ),
    _ToolDef(
        "rule_prevalence",
        "Query",
        True,
        "How noisy is a detection rule — fires/day and distinct hosts.",
        (_ES,),
    ),
    _ToolDef(
        "suggest_rule_tuning",
        "Query",
        True,
        "Detection tuning: is a rule a noisy FP nuisance to mute? Volume + ack/escalate trend.",
        (_ES,),
    ),
    _ToolDef(
        "host_summary",
        "Query",
        True,
        "Profile a host by IP: identity, OS/UA fingerprint, recent alert history.",
        (_ES,),
    ),
    _ToolDef(
        "get_event_raw",
        "Query",
        True,
        "Fetch one event's raw document by id (chat deep-dive).",
        (_ES,),
    ),
    _ToolDef(
        "get_playbooks", "Query", True, "Fetch the SO playbooks relevant to a detection.", (_ES,)
    ),
    _ToolDef(
        "lookup_runbook",
        "Query",
        True,
        "Look up the analyst runbook for a detection or technique.",
        (),
    ),
    # ── Enrichment (local-mirror feeds; online opt-in) ───────────────────────
    _ToolDef(
        "enrich_ip",
        "Enrichment",
        True,
        "Enrich an IP against local feeds — blocklists, GeoIP/ASN, cloud prefixes.",
        (),
    ),
    _ToolDef(
        "enrich_domain",
        "Enrichment",
        True,
        "Enrich a domain against local feeds (blocklists, MISP if configured).",
        (),
    ),
    _ToolDef(
        "enrich_hash",
        "Enrichment",
        True,
        "Enrich a file hash against local feeds (blocklists, MISP if configured).",
        (),
    ),
    _ToolDef(
        "shodan_internetdb",
        "Enrichment",
        True,
        "Free Shodan InternetDB view of a public IP (ports, CPEs, CVEs).",
        (_ONLINE,),
    ),
    _ToolDef(
        "cve_lookup",
        "Enrichment",
        True,
        "Score a CVE via Shodan CVEDB — CVSS, EPSS, CISA-KEV (free, no key).",
        (_ONLINE,),
    ),
    _ToolDef(
        "greynoise",
        "Enrichment",
        True,
        "GreyNoise: is an external IP indiscriminate internet scanner-noise?",
        (_ONLINE, _Req("GreyNoise API key", _key_set("greynoise_api_key"))),
    ),
    _ToolDef(
        "shodan_host",
        "Enrichment",
        True,
        "Full Shodan host lookup — owner, banners, services, vulns (paid key).",
        (_ONLINE, _Req("Shodan API key", _key_set("shodan_api_key"))),
    ),
    # ── Web research ─────────────────────────────────────────────────────────
    _ToolDef(
        "web_search",
        "Web research",
        True,
        "Search the web via SearXNG for threat-intel / context.",
        (
            _Req("Web search enabled", _flag("web_search_enabled")),
            _Req("SearXNG URL", _str_set("searxng_url")),
        ),
    ),
    _ToolDef(
        "crawl_page",
        "Web research",
        True,
        "Read a web page's content via crawl4ai (deep read of a search hit).",
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
        "Pull packet-level facts for a flow from the SO sensor (full PCAP via SSH).",
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
        "Acknowledge an alert in Security Onion (analyst-executed).",
        (_SO,),
    ),
    _ToolDef(
        "escalate_to_case",
        "Action",
        False,
        "Escalate an alert to a new SO case (analyst-executed).",
        (_SO,),
    ),
    _ToolDef(
        "add_case_comment",
        "Action",
        False,
        "Add a comment to an SO case (analyst-executed).",
        (_SO,),
    ),
)

# Category display order.
CATEGORY_ORDER: tuple[str, ...] = ("Query", "Enrichment", "Web research", "PCAP", "Action")


def collect_agent_tools(settings: Settings) -> list[AgentToolOut]:
    """Introspect every agent tool against the live config — availability + deps."""
    out: list[AgentToolOut] = []
    for t in _CATALOG:
        missing = [r.label for r in t.reqs if not r.ok(settings)]
        out.append(
            AgentToolOut(
                name=t.name,
                category=t.category,
                read_only=t.read_only,
                description=t.description,
                requires=[r.label for r in t.reqs],
                missing=missing,
                available=not missing,
            )
        )
    return out


def catalog_tool_names() -> set[str]:
    """Tool names present in the curated catalogue (for the drift cross-check)."""
    return {t.name for t in _CATALOG}
