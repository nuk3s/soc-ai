"""Investigation detail view-model builders (timeline / actions / oracle) shared across routes."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel

from soc_ai.api.webui._event_timeline import EventTimelineOut
from soc_ai.config import Settings
from soc_ai.event_time import WAVE_GAP_SECONDS, as_utc, gap_words
from soc_ai.secret_scrub import scrub_secrets
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import get_dotted
from soc_ai.store.models import Investigation
from soc_ai.webui import (
    timeline_labels,
)

_LOGGER = logging.getLogger(__name__)

# ── Investigation detail ───────────────────────────────────────────────────

_TL_GROUP = {
    "session_start": "Prefetch & pivots",
    "investigation_loop_entered": "Prefetch & pivots",
    "alert_context": "Indicator enrichment",
    "enriched_alert_context": "Indicator enrichment",
    "tool_call": "Tool calls",
    "tool_result": "Tool calls",
    "model_response": "Tool calls",
    "decision_template_match": "Decision",
    "template_ceiling": "Decision",
    "triage_report": "Decision",
    "approval_request": "Decision",
    "approval_required": "Decision",
    "template_grounds_adopted": "Validators",
    "investigator_evidence_carried": "Validators",
    "citation_validation": "Validators",
    "citation_cap": "Validators",
    "confidence_floor_raise": "Validators",
    "evidence_gate_pivot_exemption": "Validators",
    # A run that failed is not a check that passed. The error sat under
    # "Validators" with a green check, on a run that reached no verdict
    # (dogfood 2026-10-06). It has its own group, and the page draws it with
    # a warning icon.
    "error": "Error",
    # A taken action (auto-ack on a high-confidence FP) is a verdict
    # consequence, not an investigative tool call — a "no tools" heuristic run
    # must not grow a "Tool calls" timeline section from its own auto-ack.
    "auto_ack": "Decision",
    # Sibling alerts acknowledged off this verdict by auto-triage inheritance,
    # appended after the run finished. A consequence of the verdict, like the
    # auto-ack above — never an investigative tool call.
    "inherited_ack": "Decision",
    # Proactive context budgeting happens during prefetch assembly.
    "context_trimmed": "Prefetch & pivots",
    # E4.2 memory recall happens while assembling the round-1 prompt (before
    # any synthesis/decision), so it reads as part of the prefetch story.
    "prior_outcomes": "Prefetch & pivots",
    # Chat-transcript memory recall — same prompt-assembly moment as priors.
    "chat_memory": "Prefetch & pivots",
    # The same-session lookup runs during prompt assembly too, before any
    # synthesis, so it belongs with the rest of the prefetch story.
    "session_prior": "Prefetch & pivots",
    # The analyst verdict on this alert, read while the prompt is assembled.
    "analyst_verdict": "Prefetch & pivots",
    # Holding a verdict is a decision, not a lookup.
    "session_verdict_conflict": "Decision",
    # The "Tool calls" group holds tool calls and nothing else, because the
    # page counts its rows as the run's tool calls (P10, 2026-10-01). Every
    # other kind is filed by what it is. The dossier block is prompt assembly.
    "host_dossier": "Prefetch & pivots",
    "rubric_derivation": "Prefetch & pivots",
    "retask": "Prefetch & pivots",
    "retask_skipped_no_closeable_gap": "Prefetch & pivots",
    "targeted_dispatch": "Tool calls",
    # An auto-ack that did not fire is a decision about the verdict, the same
    # as the auto-ack that did.
    "auto_ack_skipped": "Decision",
    "auto_ack_inherited": "Decision",
    "classification": "Decision",
    "investigation_transcript": "Decision",
    "self_consistency_vote": "Decision",
    "fast_path_escalation": "Decision",
    "approval_decision": "Decision",
    "session_end": "Decision",
    "verdict_floor_rewrite": "Validators",
    "coverage_cap": "Validators",
    "fast_path_evidence_guard": "Validators",
    "fast_path_verdict_cap": "Validators",
    "icmp_solicited_downgrade": "Validators",
    "evidence_gate_downgrade": "Validators",
    "ungrounded_host_anchored_tp_downgrade": "Validators",
    "malware_rule_name_ungrounded_downgrade": "Validators",
    "decisive_value_support_cap": "Validators",
    "unsupported_decisive_value_downgrade": "Validators",
    "recommended_actions_blocked": "Validators",
    "egress_blocked": "Validators",
}
# Write-action tools (ack/escalate/comment): their tool_call rows belong under
# "Decision" too — they act on the verdict rather than investigate.
_WRITE_TOOLS = {"t_ack_alert", "t_escalate_to_case", "t_add_case_comment"}
_TL_SKIP = {
    "usage",
    "done",
    "tool_result",
    "model_response",
    "synth_round1_skipped",
    # Post-run analyst bookkeeping (advisory-action execution receipts) — the
    # applied state on the action card already tells this story; a generic
    # timeline row would just be noise appended after "done".
    "action_executed",
    # An analyst dismissed a recommendation or undid the dismissal. The card
    # shows it, with the actor and the time.
    "action_dismissed",
    "action_restored",
    # The Oracle rule shadow ledger. It changes nothing on the run, and
    # Detection tuning shows the tally.
    "oracle_shadow",
}
_PORT_PROTO = {21: "FTP", 22: "SSH", 53: "DNS", 80: "HTTP", 443: "TLS", 445: "SMB", 3389: "RDP"}
_ACTION_TITLE = {
    "ack_alert": "Acknowledge alert",
    "escalate_to_case": "Escalate to case",
    "add_case_comment": "Add case comment",
}
_ACTION_TAG = {"ack_alert": "ack", "escalate_to_case": "escalate", "add_case_comment": "comment"}
# The type of an action in the operator's words: the word on the button of the
# action card (ACTION_VERB in the console).
ACTION_LABEL = {"ack": "Acknowledge", "escalate": "Escalate to case", "comment": "Add comment"}


def _tl_group(kind: str) -> str:
    if kind.startswith("oracle"):
        return "Oracle"
    # An unknown kind is not a tool call. Filing it under "Tool calls" made the
    # section disagree with the tool-call count (P10).
    return _TL_GROUP.get(kind, "Decision")


def _compact(obj: Any) -> str:
    """``obj`` as one string, whole. The console wraps a long line.

    A cut with an ellipsis hid the rest of the text (owner, 2026-10-07).
    """
    return obj if isinstance(obj, str) else json.dumps(obj, default=str, ensure_ascii=False)


def _ep(ip: Any, port: Any) -> str:
    if not ip:
        return "—"
    return f"{ip}:{port}" if port not in (None, "") else str(ip)


def _proto(alert: dict[str, Any]) -> str:
    p = alert.get("destination_port") or alert.get("source_port")
    try:
        return _PORT_PROTO.get(int(p), "TCP") if p is not None else "—"
    except (TypeError, ValueError):
        return "—"


def _alert_meta(
    alert: dict[str, Any], host_profile: dict[str, int], inv: Investigation
) -> dict[str, Any] | None:
    """The triggering detection's raw facts, from the stored alert context."""
    if not alert:
        return None
    rule = alert.get("rule_name") or inv.rule_name or "—"
    return {
        "id": inv.alert_es_id or "",
        "rule": rule,
        "sid": alert.get("rule_uuid"),
        "classtype": alert.get("classtype"),
        "category": alert.get("event_category"),
        "src": _ep(alert.get("source_ip"), alert.get("source_port")),
        "dst": _ep(alert.get("destination_ip"), alert.get("destination_port")),
        "proto": _proto(alert),
        "action": alert.get("alert_action") or alert.get("event_action") or "—",
        # The alert's own @timestamp (tz-aware ISO, stored with the context) —
        # the detection's real fire time. The old shape surfaced the
        # INVESTIGATION's created_at as "last seen", which never correlated
        # with the alert (an alert triaged hours later showed the triage time).
        "time": alert.get("timestamp"),
        "count": int(host_profile.get(rule, 1) or 1),
        # The account and the machine the alert names, for the drawer's
        # four-line Alert details (dogfood 2026-10-06, first hour W4).
        "user": alert.get("user_name") or None,
        "host": alert.get("host_name") or None,
    }


def _host_signals(host_profile: dict[str, int]) -> list[dict[str, Any]]:
    """The host's other alert activity (rule -> count), ranked by volume. The
    tone reflects relative volume on the host, not absolute rule severity."""
    if not host_profile:
        return []
    items = sorted(host_profile.items(), key=lambda kv: kv[1], reverse=True)[:6]
    mx = max((c for _, c in items), default=1) or 1
    out: list[dict[str, Any]] = []
    for rule, cnt in items:
        ratio = cnt / mx
        if ratio > 0.8:
            tone = "critical"
        elif ratio > 0.5:
            tone = "high"
        elif ratio > 0.25:
            tone = "medium"
        else:
            tone = "low"
        out.append(
            {
                "time": "",
                "label": rule,
                "tone": tone,
                "w": max(6, int(100 * ratio)),
                "sev": f"{cnt}×",  # noqa: RUF001  (count multiplier badge)
            }
        )
    return out


def _peer_sub(enr: dict[str, Any]) -> str | None:
    """The most informative one-line locator enrichment offers for a graph node:
    country + ASN ("US · AS13335 Cloudflare") > cloud provider > "internal"."""
    if enr.get("internal"):
        return "internal"
    geo_raw = enr.get("geoip")
    geo: dict[str, Any] = geo_raw if isinstance(geo_raw, dict) else {}
    asn_raw = enr.get("asn")
    asn: dict[str, Any] = asn_raw if isinstance(asn_raw, dict) else {}
    parts: list[str] = []
    # Stored contexts carry the dataclass shape (country_iso / number / org);
    # tool-result payloads use country_name / asn / asn_org — accept both.
    country = geo.get("country_iso") or geo.get("country_name")
    if country:
        parts.append(str(country))
    org = asn.get("org") or asn.get("asn_org")
    num = asn.get("number") or asn.get("asn")
    if org:
        parts.append(f"AS{num} {org}" if num else str(org))
    if parts:
        return " · ".join(parts)
    if enr.get("cloud_provider"):
        return str(enr["cloud_provider"])
    return None


def _blocklist_unchecked(enrichments: Any) -> bool:
    """True when an enrichment AFFIRMS that no blocklist feed answered it.

    Tri-state on purpose: ``None`` is a record written before the field existed
    and makes no claim, so it renders as it always did. Only an explicit
    ``False`` turns a quiet "nothing flagged" into "nothing was checked".

    Shape-tolerant, like everything else reading a stored payload here: a
    partial enrichment can leave a list or a string where the map belongs, and
    a timeline row must not 500 over it.
    """
    if not isinstance(enrichments, dict):
        return False
    return any(
        isinstance(e, dict) and e.get("blocklist_checked") is False for e in enrichments.values()
    )


def _flag_sources(enr: dict[str, Any]) -> list[str]:
    """Names of the intel sources that flagged the indicator (bounded for a badge)."""
    srcs: list[str] = []
    for h in enr.get("blocklist_hits") or []:
        s = h.get("source") if isinstance(h, dict) else None
        if s and str(s) not in srcs:
            srcs.append(str(s))
    if enr.get("misp_hits") and "MISP" not in srcs:
        srcs.append("MISP")
    return srcs[:3]


def _endpoint_internal(ip: Any, enrichments: dict[str, Any]) -> bool | None:
    """Whether an endpoint is inside the estate. None when nothing says.

    Enrichment's ``internal`` flag answers first: it knows the configured
    internal ranges. An address enrichment did not describe falls back to
    "not globally routable", which is internal on every network.
    """
    if not ip:
        return None
    enr = enrichments.get(str(ip))
    if isinstance(enr, dict) and isinstance(enr.get("internal"), bool):
        return bool(enr["internal"])
    try:
        return not ipaddress.ip_address(str(ip).strip()).is_global
    except ValueError:
        return None


def _graph_scope(
    alert: dict[str, Any], enrichments: dict[str, Any], inv: Investigation
) -> str | None:
    """The direction of the alert's flow: lateral, inbound, outbound or external.

    The page called every true positive "lateral movement" and its source
    "compromised", an external SQL injection source too (dogfood 2026-10-19,
    R2-D10). Lateral movement is internal to internal. None when an end is
    missing or unknown.
    """
    src = alert.get("source_ip") or inv.src_ip
    dst = alert.get("destination_ip") or inv.dest_ip
    src_in = _endpoint_internal(src, enrichments)
    dst_in = _endpoint_internal(dst, enrichments)
    if src_in is None or dst_in is None or not dst or str(dst) == str(src):
        return None
    if src_in and dst_in:
        return "lateral"
    if dst_in:
        return "inbound"
    if src_in:
        return "outbound"
    return "external"


def _entity_graph(
    alert: dict[str, Any], enrichments: dict[str, Any], inv: Investigation
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    """A real (if small) blast-radius graph: the host, the peers it contacted,
    and which of those enrichment flagged as malicious. Nodes carry the facts
    enrichment already established (sub-label + intel flag sources) and edges
    carry the flow's port/proto, so the diagram answers "who, where, why
    flagged" at a glance instead of just drawing dots."""
    src = alert.get("source_ip") or inv.src_ip
    dst = alert.get("destination_ip") or inv.dest_ip
    label = alert.get("host_name") or src
    if not src:
        return [], [], None
    src_enr = enrichments.get(str(src)) or {}
    src_internal = _endpoint_internal(src, enrichments)
    # A true positive marks an INTERNAL source compromised. An external source
    # is the far end of an attack, and nothing here shows it was compromised.
    src_node: dict[str, Any] = {
        "id": str(src),
        "x": 20,
        "y": 50,
        "kind": "compromised" if inv.verdict == "true_positive" and src_internal else "host",
        "label": str(label or src),
        "sub": "source · internal"
        if src_internal
        else "source · external"
        if src_internal is False
        else "source",
    }
    src_flags = _flag_sources(src_enr)
    if src_flags:
        src_node["flagged"] = True
        src_node["flagSources"] = src_flags
    nodes: list[dict[str, Any]] = [src_node]
    peers: list[str] = []
    if dst and dst != src:
        peers.append(str(dst))
    for ind in enrichments:
        if str(ind) != str(src) and str(ind) not in peers:
            peers.append(str(ind))
    peers = peers[:5]
    edges: list[dict[str, Any]] = []
    flagged_names: list[str] = []
    n = len(peers)
    for i, ip in enumerate(peers):
        enr = enrichments.get(ip) or {}
        bad = bool(enr.get("blocklist_hits") or enr.get("misp_hits"))
        internal = bool(enr.get("internal"))
        if bad:
            flagged_names.append(ip)
        y = 50 if n <= 1 else int(18 + 64 * i / (n - 1))
        # "internal" (green square), never "dc" — nothing in enrichment can know
        # a host is a domain controller, and mislabeling one erodes trust fast.
        node_kind = "c2" if bad else "internal" if internal else "host"
        node: dict[str, Any] = {"id": ip, "x": 78, "y": y, "kind": node_kind, "label": ip}
        sub = _peer_sub(enr)
        if sub:
            node["sub"] = sub
        if bad:
            node["flagged"] = True
            node["flagSources"] = _flag_sources(enr)
        nodes.append(node)
        edge: dict[str, Any] = {"from": str(src), "to": ip, "kind": "beacon" if bad else "flow"}
        # The alert's primary flow carries its real port/proto (":443 TLS");
        # peers known only from enrichment carry a neutral "observed".
        if dst and ip == str(dst):
            port = alert.get("destination_port")
            if port not in (None, ""):
                proto = _proto(alert)
                edge["label"] = f":{port} {proto}" if proto != "—" else f":{port}"
        else:
            edge["label"] = "observed"
        edges.append(edge)
    note = f"{label or src} contacted {n} peer{'' if n == 1 else 's'}." + (
        f" Enrichment flagged {len(flagged_names)} of them as malicious: "
        f"{_compact(', '.join(flagged_names))}."
        if flagged_names
        else ""
    )
    # An unflagged node is not a cleared node when no feed was loaded. The node
    # shapes carry no third state, so the graph says it in words.
    if _blocklist_unchecked(enrichments):
        note += " soc-ai loaded no blocklist feed. It checked none of them against intel."
    return nodes, edges, note


# Friendly nouns for the read tools so a timeline step says what was checked.
_TOOL_NOUN = {
    "t_enrich_ip": "IP reputation",
    "t_enrich_domain": "Domain reputation",
    "t_enrich_hash": "File-hash reputation",
    "t_query_events_oql": "Event search",
    "t_query_zeek_logs": "Zeek logs",
    "t_query_cases": "Cases",
    "t_query_detections": "Detections",
    "t_get_playbooks": "Playbooks",
    "t_lookup_runbook": "Runbook",
    "t_get_pcap": "PCAP",
    "t_web_search": "Web search",
    "t_crawl_page": "Page fetch",
    "t_get_alert_context": "Alert context",
    "t_host_summary": "Host summary",
    "t_prevalence": "Indicator prevalence",
    "t_rule_prevalence": "Rule prevalence",
    "t_suggest_rule_tuning": "Rule-tuning suggestion",
    "t_greynoise": "GreyNoise",
    "t_shodan_internetdb": "Shodan InternetDB",
    "t_shodan_host": "Shodan host",
    "t_cve_lookup": "CVE lookup",
    "t_describe_dataset": "Dataset shape",
    "t_field_values": "Field values",
    "t_get_event_raw": "Raw event",
    "t_get_rule_content": "Rule content",
    "t_host_dossier": "Host dossier",
    "t_ack_alert": "Acknowledge",
    "t_escalate_to_case": "Escalate to case",
    "t_add_case_comment": "Case comment",
    "final_result": "Verdict synthesis",
}
# Display labels for decision-template ids (don't presume the verdict in the name).
_TEMPLATE_LABELS = {"clean_internal_traffic": "internal traffic"}


def _humanize_id(s: str | None) -> str:
    return (s or "").removeprefix("t_").replace("_", " ").strip() or "tool"


def _template_label(tid: str | None) -> str:
    return _TEMPLATE_LABELS.get(tid or "", _humanize_id(tid))


# "(first 2026-06-24T11:48:12.684Z, last …)" spans in prevalence summaries.
_FIRST_LAST_PAREN_RE = re.compile(r"\s*\(first\b[^)]*\)")
# A full ISO-8601 timestamp; group 1 is the date part we keep in titles.
_ISO_TS_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


def _trim_summary_label(s: str) -> str:
    """Title-only cleanup of a tool summary: drop "(first …, last …)" spans and
    clip any remaining ISO timestamp to its date. Raw ms-precision timestamps
    truncate mid-value in the collapsed title; the full summary stays available
    in the row expander detail."""
    s = _FIRST_LAST_PAREN_RE.sub("", s)
    return _ISO_TS_RE.sub(r"\1", s).strip()


def _tool_outcome(result: Any) -> str:
    """A short, tool-aware outcome — the point of the step (vs 'total: 0')."""
    if result is None:
        return "running"
    if isinstance(result, list):
        return (
            "no results" if not result else f"{len(result)} result{'' if len(result) == 1 else 's'}"
        )
    if isinstance(result, str):
        return _compact(result)
    if not isinstance(result, dict):
        return _compact(result)
    # An online tool that short-circuited (online enrichment off / no API key):
    # a neutral "skipped" outcome, NOT the multi-line config lecture the tool
    # returns for the model to read (that stays in the expander).
    if result.get("available") is False:
        reason = str(result.get("reason") or "")
        if "not_configured" in reason:
            return "skipped, not configured"
        return "skipped, online enrichment off"
    # A tool error — a short, distinct failure phrase, never a JSON/traceback dump.
    if result.get("error"):
        msg = result.get("message") or result.get("error")
        if not isinstance(msg, str):
            return "failed: error"
        # Query errors often already read as failures ("failed to parse
        # filter…") — prefixing again would stutter "failed: failed to…".
        if msg.lstrip().lower().startswith(("failed", "error", "could not", "cannot", "unable")):
            return _compact(msg)
        return "failed: " + _compact(msg)
    # Host summary: "<ip> — 699 events", not the raw {ip, event_count} dict.
    if "event_count" in result and ("ip" in result or "host" in result):
        who = result.get("ip") or result.get("host")
        if not result.get("observations", True):
            return f"{who}, no observations"
        n = result.get("event_count")
        return f"{who}, {n} events"
    # enrichment result
    if {"blocklist_hits", "misp_hits", "indicator"} & set(result):
        bl = result.get("blocklist_hits") or []
        misp = result.get("misp_hits") or []
        if bl or misp:
            srcs = [str(h["source"]) for h in bl if isinstance(h, dict) and h.get("source")]
            return "flagged malicious" + (f" by {', '.join(srcs)}" if srcs else "")
        # A miss is a COVERAGE statement, not a verdict — say so precisely, and
        # only when there was coverage. `blocklist_checked is False` means a
        # lookup ran against feeds that had never been refreshed, so the miss
        # is an absence of data; `None` means the record predates the field and
        # makes no claim either way, which is the old wording. "Internal" does
        # not excuse it: the curated internal-seed feed is the one that names
        # known-bad internal hosts.
        where = "internal address" if result.get("internal") else ""
        if result.get("blocklist_checked") is False:
            unloaded = "no blocklist loaded. soc-ai checked nothing"
            return f"{where}, {unloaded}" if where else unloaded
        return where or "no blocklist/MISP match"
    # ES query / zeek result
    if result.get("prefetch_already_has_this"):
        return "already in alert context"
    if "total" in result or "hits" in result:
        total = result.get("total_display") or result.get("total", 0)
        return f"{total} match" if str(total) == "1" else f"{total} matches"
    # web_search / list-shaped results carrying a count
    if "result_count" in result:
        n = result.get("result_count", 0)
        return "no results" if n == 0 else f"{n} result" if n == 1 else f"{n} results"
    for k in ("summary", "verdict", "status", "note", "hint"):
        if result.get(k):
            val = result[k]
            if k == "summary" and isinstance(val, str):
                val = _trim_summary_label(val)
            return _compact(val)
    # No known field — a bare, human outcome rather than a JSON dump of the dict
    # (machines read the full JSON in the row expander; humans read this line).
    return "done"


def _dossier_outcome(result: Any) -> str | None:
    """A host dossier answer, as the facts it holds.

    The dossier carries an ``event_count`` beside the ``ip``, so the generic
    host-summary branch titled it "<ip>, 0 events". That reads as an all-clear
    on a host the dossier describes in full (RL10). The point of the step is
    what the host IS: its role and how many facts the record holds.
    """
    if not isinstance(result, dict) or result.get("error") or "found" not in result:
        return None
    who = result.get("ip") or "this host"
    if result.get("found") is False:
        return f"{who}, no record in the sweep"
    raw_fields = result.get("fields")
    fields: dict[str, Any] = raw_fields if isinstance(raw_fields, dict) else {}
    known = [f for f in fields.values() if isinstance(f, dict) and f.get("value") is not None]
    declared = [f for f in known if f.get("source") == "operator"]
    role_field = fields.get("role")
    role = role_field.get("value") if isinstance(role_field, dict) else None
    parts = [f"role {role}" if role else "role unknown"]
    parts.append(f"{len(known)} known fact{'' if len(known) == 1 else 's'}")
    if declared:
        parts.append(f"{len(declared)} declared by an operator")
    return f"{who}, " + ", ".join(parts)


def _n(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _times(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _day(iso: Any) -> str | None:
    m = _ISO_TS_RE.search(str(iso or ""))
    return m.group(1) if m else None


def _prevalence_ste(args: dict[str, Any], r: dict[str, Any]) -> str | None:
    total, days = _n(r.get("total_events")), _n(r.get("distinct_days"))
    if total is None or days is None:
        return None
    ends = [str(args[k]) for k in ("ip", "peer_ip", "domain") if args.get(k)]
    who = f"{' and '.join(ends)}: " if ends else ""
    if not r.get("observed") or total == 0:
        return f"{who}soc-ai found no event in the window. The pair is first-seen."
    out = f"{who}{_times(total, 'event', 'events')} on {_times(days, 'day', 'days')}."
    first, last = _day(r.get("first_seen")), _day(r.get("last_seen"))
    if first and last:
        out += f" The first event is on {first}. The last event is on {last}."
    if r.get("rarity"):
        out += f" Rarity: {r['rarity']}."
    return out


def _rule_prevalence_ste(r: dict[str, Any]) -> str | None:
    total, window = _n(r.get("total_fires")), _n(r.get("lookback_days"))
    if total is None or window is None:
        return None
    if total == 0:
        return f"The rule did not fire in the {window}-day window. The rule is first-seen."
    days = _n(r.get("active_days"))
    on_days = f" on {_times(days, 'day', 'days')}" if days else ""
    out = f"The rule fired {_times(total, 'time', 'times')}{on_days} in the {window}-day window."
    src, dst = _n(r.get("distinct_src_hosts")), _n(r.get("distinct_dest_hosts"))
    if src is not None:
        out += f" Source hosts: {src}."
    if dst is not None:
        out += f" Destination hosts: {dst}."
    rate = r.get("fires_per_day")
    if r.get("is_burst"):
        # A burst has no rate. The stored text gave one and then said so
        # (R2 STE item 10). It also called every burst "one burst", and a prod
        # rule fired in three waves on one day (change D).
        out += _burst_waves_ste(r)
    elif isinstance(rate, int | float) and not isinstance(rate, bool):
        out += f" The rate is {rate:.1f} fires a day."
    if r.get("noisiness"):
        out += f" Type: {r['noisiness']}."
    return out


# The most waves the page step names.
_STEP_WAVES = 6


def _wave_window(start: Any, end: Any) -> tuple[str, str] | None:
    """The start and the end of one wave as page words, or None."""
    first, last = as_utc(start), as_utc(end)
    if first is None:
        return None
    if last is None or last < first:
        last = first
    head = first.strftime("%Y-%m-%d %H:%M:%S")
    if last.replace(microsecond=0) == first.replace(microsecond=0):
        return head, ""
    return head, last.strftime("%H:%M:%S" if last.date() == first.date() else "%Y-%m-%d %H:%M:%S")


def _burst_waves_ste(r: dict[str, Any]) -> str:
    """The wave sentences of a burst step. A ``waves`` field from a newer tool
    names each wave. Without it, a span of one wave gap or less is one wave,
    and a longer span claims no wave count."""
    waves = [
        (w, window)
        for w in (r.get("waves") or [])
        if isinstance(w, dict) and (window := _wave_window(w.get("start"), w.get("end")))
    ]
    count = _n(r.get("wave_count")) or len(waves)
    if waves and count == 1:
        head, tail = waves[0][1]
        if not tail:
            return f" The fires form one wave, at {head} UTC."
        return f" The fires form one wave, from {head} to {tail} UTC."
    if waves:
        out = f" The fires form {count} waves."
        for i, (w, (head, tail)) in enumerate(waves[:_STEP_WAVES], 1):
            fires = _times(_n(w.get("fires")) or 0, "fire", "fires")
            out += (
                f" Wave {i}: {fires} from {head} to {tail} UTC."
                if tail
                else f" Wave {i}: {fires} at {head} UTC."
            )
        if count > _STEP_WAVES:
            out += f" The page shows the first {_STEP_WAVES} waves."
        return out
    span = r.get("observed_span_seconds")
    if isinstance(span, int | float) and not isinstance(span, bool):
        if span <= WAVE_GAP_SECONDS:
            return " The fires form one wave."
        return (
            " The rule has no daily rate. The first and the last fire are "
            f"{gap_words(span)} apart. That span can hold one wave or several waves."
        )
    return " The rule has no daily rate."


def _origin_chain_ste(r: dict[str, Any]) -> str | None:
    minutes, ip = _n(r.get("lookback_minutes")), r.get("ip")
    if minutes is None or not ip:
        return None
    if not r.get("observations"):
        return (
            f"soc-ai found no inbound remote-access session to {ip} in the {minutes} "
            "minutes before the activity."
        )
    sessions = r.get("inbound_sessions")
    n = len(sessions) if isinstance(sessions, list) else 0
    out = (
        f"{_times(n, 'inbound remote-access session', 'inbound remote-access sessions')} "
        f"reached {ip} in the {minutes} minutes before the activity."
    )
    closest = r.get("closest_preceding")
    if isinstance(closest, dict) and closest.get("source_ip"):
        secs = closest.get("seconds_before")
        when = f", {secs:.0f} seconds before" if isinstance(secs, int | float) else ""
        out += f" The closest came from {closest['source_ip']}{when}. Look at that source next."
    return out


def _rule_tuning_ste(r: dict[str, Any]) -> str | None:
    count, window = _n(r.get("alert_count")), _n(r.get("lookback_days"))
    if count is None or not r.get("recommendation"):
        return None
    span = f" in the {window}-day window" if window is not None else ""
    return (
        f"The rule raised {_times(count, 'alert', 'alerts')}{span}. "
        f"The recommendation is {r['recommendation']}."
    )


def _rule_content_ste(r: dict[str, Any]) -> str | None:
    """The rule-content answer. Its note and its miss hint are written for the
    model: "2 detections matched; returning the best-ranked one" (V1-A5)."""
    found = r.get("found")
    if found is False:
        return "no detection matches this rule id or title."
    if found is not True:
        return None
    matches = _n(r.get("matches"))
    if matches is not None and matches > 1:
        return f"{matches} detections match. soc-ai read the best-ranked one."
    return "soc-ai read the rule text."


# The tools whose STE summary also replaces the model-facing ``hint``. The
# hint of a rule-content miss names t_query_detections and carries a dash.
_STE_REPLACES_HINT = frozenset({"t_get_rule_content"})


def _ste_tool_summary(tool_name: str, args: dict[str, Any], result: Any) -> str | None:
    """An operator sentence for a tool whose summary is written for the model.

    These tools write their ``summary`` for the model, and the timeline
    printed it verbatim (dogfood 2026-10-19, R2 STE items 9 to 13). The tool
    output does not change. The timeline restates the result from its fields,
    and stored runs read the same way. None leaves the summary as it is.
    """
    if not isinstance(result, dict) or result.get("error"):
        return None
    # A stored run can carry its arguments as a string, and older runs carry
    # other result shapes. The demo fixtures do both. A summary that cannot
    # read its fields returns None, so the step keeps the stored text. It
    # must never fail the whole detail page (dogfood 2026-10-19 merge gate).
    call_args = args if isinstance(args, dict) else {}
    builders = {
        "t_prevalence": lambda: _prevalence_ste(call_args, result),
        "t_rule_prevalence": lambda: _rule_prevalence_ste(result),
        "t_origin_chain": lambda: _origin_chain_ste(result),
        "t_suggest_rule_tuning": lambda: _rule_tuning_ste(result),
        "t_get_rule_content": lambda: _rule_content_ste(result),
    }
    build = builders.get(tool_name)
    if build is None:
        return None
    try:
        return build()
    except (AttributeError, KeyError, TypeError, ValueError):
        _LOGGER.warning("timeline: no STE summary for %s. The stored text stays.", tool_name)
        return None


def _tool_step(tool_name: str, args: dict[str, Any], result: Any) -> tuple[str, str]:
    """Title carries the point (tool + a short outcome); detail (shown on expand)
    carries the FULL headline result first, then the query and any enrichment chips.

    The collapsed title holds a short outcome, so the expanded row is where the
    analyst reads the whole answer — never just the arguments (the old behaviour).
    """
    noun = _TOOL_NOUN.get(tool_name, _humanize_id(tool_name).capitalize())
    outcome = _dossier_outcome(result) if tool_name == "t_host_dossier" else None
    ste = _ste_tool_summary(tool_name, args, result)
    title = f"{noun}: {outcome or (_compact(ste) if ste else None) or _tool_outcome(result)}"

    lines: list[str] = []
    headline_key: str | None = None
    if isinstance(result, dict) and result.get("error"):
        # A failed call leads with the failure and its reason. The analytic
        # tool answers could_not_run with the analytic's own ``status`` beside
        # the error, so the generic headline below read "result: live" and the
        # operator never saw why the call failed.
        code = result["error"]
        lines.append(f"failed: {_compact(code)}" if isinstance(code, str) else "failed")
        for k in ("detail", "message", "hint"):
            reason = result.get(k)
            if isinstance(reason, str) and reason.strip():
                headline_key = k
                lines.append(f"reason: {_compact(reason)}")
                break
    elif ste is not None:
        headline_key = "hint" if tool_name in _STE_REPLACES_HINT else "summary"
        lines.append(f"result: {ste}")
    elif isinstance(result, dict) and result.get("prefetch_already_has_this"):
        # The hint is an instruction to the model (R2 STE 7). The analyst
        # reads what happened.
        headline_key = "hint"
        lines.append("result: soc-ai already loaded the Zeek events of this flow.")
    elif isinstance(result, dict):
        # The full answer first. The title holds only the short outcome.
        for k in ("summary", "verdict", "status", "note", "hint"):
            if result.get(k):
                headline_key = k
                lines.append(f"result: {_compact(result[k])}")
                break
    lines.append(f"query: {_compact(args)}" if args else "no arguments")
    if isinstance(result, dict):
        extra = []
        geo = result.get("geoip") if isinstance(result.get("geoip"), dict) else None
        asn = result.get("asn") if isinstance(result.get("asn"), dict) else None
        if geo and geo.get("country_name"):
            extra.append(str(geo["country_name"]))
        if asn and asn.get("asn_org"):
            extra.append(str(asn["asn_org"]))
        if result.get("cloud_provider"):
            extra.append(str(result["cloud_provider"]))
        # Don't repeat the hint if it was already the headline line.
        if headline_key != "hint" and result.get("hint"):
            extra.append(_compact(result["hint"]))
        if extra:
            lines.append(" · ".join(extra))
    return title, "\n".join(lines)


_VERDICT_WORDS = {
    "true_positive": "a true positive",
    "false_positive": "a false positive",
    "needs_more_info": "needs more info",
    "inconclusive": "no verdict",
}


def _verdict_words(verdict: Any) -> str:
    """A verdict code as words in a sentence: "a false positive"."""
    return _VERDICT_WORDS.get(str(verdict or ""), str(verdict or "no verdict").replace("_", " "))


# Why the investigation loop ran, as a sentence (R2 STE 5). The codes come from
# the orchestrator's loop_reason and soc_ai.agent.budget.ClassPlan.reason.
_LOOP_REASONS = {
    "deep_rerun": "An analyst asked for a deep run.",
    "analyst_run": "An analyst asked for this run.",
    "hunt_subject": "The run investigates a hunt.",
    "fast_triage_disabled": "Fast triage is off. Every alert gets the full investigation.",
    "session_true_positive_stands": "A true positive stands on the same network session.",
    "round1_cannot_settle": "The first pass cannot settle this alert.",
    "gate_would_change": "An evidence gate can change the first-pass verdict.",
    "verdict_not_evidence_backed": "The first-pass verdict has no evidence behind it.",
    "no_dispositive_template": "No pattern settles this alert.",
    "dispositive_template": "A pattern settles this alert.",
}


# The trigger behind ``definitely_investigate``, from the loop event (V1-A1).
# The code had one sentence, "an exploit or malware signal", for three
# triggers. An NTLMv1 alert sent to the loop by a provisional template read
# as malware. A stored run without the field gets the neutral sentence.
_DI_TRIGGERS = {
    "malware_rule": "The alert has an exploit or malware signal.",
    "host_concurrent_threat": "Another alert on the same host signals a threat.",
    "provisional_template": (
        "A pattern proposed a false positive. The pattern cannot close the alert without evidence."
    ),
}
_DI_NO_TRIGGER = "A soc-ai rule sends this alert to the full investigation."


def _loop_reason(code: Any, trigger: Any = None) -> str:
    text = str(code or "").strip()
    if not text:
        return ""
    if text == "definitely_investigate":
        known = _DI_TRIGGERS.get(trigger) if isinstance(trigger, str) else None
        return known or _DI_NO_TRIGGER
    return _LOOP_REASONS.get(text, text.replace("_", " ").capitalize() + ".")


def _percent(ratio: Any) -> str:
    """A 0..1 ratio as a whole percent: "83%", never 0.8333333333333334."""
    if isinstance(ratio, bool) or not isinstance(ratio, int | float):
        return "unknown"
    return f"{round(float(ratio) * 100)}%"


_AUTO_ACK_SKIP_REASON = {
    "high_stakes": "high stakes",
    "below_threshold": "confidence below the threshold",
    "no_investigation": "the run retrieved nothing",
    "uncited": "no citation resolves",
    "promoted_finding": "a promoted finding has no alert",
    "oracle_dissent": "the Oracle disagreed without evidence",
    "analyst_verdict": "an analyst set a different verdict",
    "analyst_verdict_unknown": "soc-ai could not read the analyst verdict",
}


def _auto_ack_skip_reason(p: dict[str, Any]) -> str:
    reason = str(p.get("reason") or "")
    return _AUTO_ACK_SKIP_REASON.get(reason, reason.replace("_", " ") or "no reason recorded")


def _report_detail(p: dict[str, Any]) -> str:
    """The verdict step: the summary. The title states the verdict.

    The detail opened with the code, "false_positive (0.8)" (V1-A4).
    """
    summary = p.get("summary")
    if isinstance(summary, str) and summary.strip():
        return summary.strip()
    conf = p.get("confidence")
    at = f" at {conf:.2f}" if _is_number(conf) else ""
    return f"soc-ai reached {_verdict_words(p.get('verdict'))}{at}. The report has no summary."


def _downgrade_detail(p: dict[str, Any]) -> str | None:
    """A gate that changed the verdict, in words. The step showed its JSON.

    None on a payload without both verdicts, so the stored text stays.
    """
    before, after = p.get("original_verdict"), p.get("downgraded_verdict")
    if not (isinstance(before, str) and isinstance(after, str)):
        return None
    lines = [
        f"soc-ai changed the verdict from {_verdict_words(before)} to {_verdict_words(after)}."
    ]
    reason = p.get("reason")
    if isinstance(reason, str) and reason.strip():
        lines.append(f"Reason: {reason.strip()}")
    summary = p.get("original_summary")
    if isinstance(summary, str) and summary.strip():
        lines.append(f"The summary before the change: {summary.strip()}")
    return "\n".join(lines)


def _template_rationale(template_id: Any, rationale: Any) -> str:
    """The rationale of the template, as the timeline shows it.

    The model reads the internal-traffic rationale as the grounds of the
    candidate, so the template keeps its text. Its "likely benign east-west
    traffic" is a conclusion with no fact behind it, and the timeline states
    the facts only (V1-A5). Four stored wordings exist. Each states whether
    the blocklist answered.
    """
    text = rationale if isinstance(rationale, str) else ""
    if template_id != "clean_internal_traffic" or "east-west" not in text:
        return text
    if "not loaded" in text:
        return (
            "Both hosts are internal. The blocklist was not loaded. "
            "No indicator reached threat intel."
        )
    return "Both hosts are internal. The blocklist answered with no hit."


_EM_DASH = chr(0x2014)
# "- <ip> (<label>) <em dash> no dossier: ..." and "... <em dash> role: ...",
# the two head lines of the dossier block (soc_ai/dossier/prompt.py). The
# model reads the block, so the timeline maps the lines it shows (V1-A5).
_DOSSIER_NONE_RE = re.compile(rf"^- (?P<head>.+?) {_EM_DASH} no dossier:.*$")
_DOSSIER_ROLE_RE = re.compile(rf"^- (?P<head>.+?) {_EM_DASH} role: (?P<rest>.*)$")


def _dossier_line_words(line: str) -> str:
    """One host head line without the dash and the "not evidence" contrast."""
    if m := _DOSSIER_NONE_RE.match(line):
        return (
            f"- {m.group('head')}: soc-ai has no dossier for this address. "
            "The network sweep has no record of it."
        )
    if m := _DOSSIER_ROLE_RE.match(line):
        return f"- {m.group('head')}: role {m.group('rest')}"
    return line


def _dossier_event_detail(p: dict[str, Any]) -> str:
    """The prompt's dossier block, as text an analyst reads.

    The payload is the audit record: a host-to-role map and the markdown block
    the model saw. The raw JSON put a "## Host dossier" heading inside a code
    box (P11). The hosts come first, then the block without its headings.
    """
    raw_hosts = p.get("hosts")
    hosts: dict[str, Any] = raw_hosts if isinstance(raw_hosts, dict) else {}
    lines: list[str] = []
    if hosts:
        lines.append("Hosts: " + ", ".join(f"{ip} ({role})" for ip, role in hosts.items()))
    omitted = p.get("hosts_omitted")
    if isinstance(omitted, int) and omitted > 0:
        lines.append(f"{omitted} more host(s) not described.")
    block = p.get("block")
    if isinstance(block, str) and block.strip():
        text = "\n".join(_dossier_line_words(ln) for ln in _dossier_host_lines(block)).strip()
        if text:
            lines.append(_compact(text))
    return "\n".join(lines) or "The dossier block was empty."


def _dossier_host_lines(block: str) -> list[str]:
    """The host lines of the dossier block, without the model instructions.

    The block opens with a heading, an intro and the writing-style rule, all
    addressed to the model ("Do not cite these lines", "call
    `t_host_dossier`", "Write for the analyst"). The timeline showed them to
    the analyst (dogfood 2026-10-19, R2-D6). A host line starts with "- " at
    the margin, and its detail lines are indented under it. The trailing
    "omitted" line is an instruction too, and ``hosts_omitted`` states it.
    """
    out: list[str] = []
    in_host = False
    for ln in block.splitlines():
        if ln.startswith("- "):
            in_host = not ln.startswith("- (+")
            if in_host:
                out.append(ln)
        elif in_host and ln.startswith("  ") and ln.strip():
            out.append(ln)
        else:
            in_host = False
    return out


def _citation_detail(p: dict[str, Any]) -> str:
    """The citation check: the count, the coverage as a percent, each citation.

    The step used to say "5/5 citations valid. Coverage is 1.0." and list none
    of them (P3). A ratio printed raw read 0.8333333333333334 (RL13).
    """
    c = p.get("counts") or {}
    valid, total, cov = c.get("valid", "?"), p.get("total", "?"), p.get("coverage_ratio")
    if p.get("vacuous") or total == 0:
        # Coverage over nothing is not a number. Saying "0/0 (coverage 0.0)"
        # implies the report tried to cite and failed; it did not try.
        return "the report offered no citations"
    lines = [f"{valid}/{total} citations valid. Coverage is {_percent(cov)}."]
    per = p.get("per_citation")
    for item in per if isinstance(per, list) else []:
        if isinstance(item, dict) and item.get("citation"):
            mark = "valid" if item.get("resolved") else "not resolved"
            lines.append(f"{mark}: {_citation_words(str(item['citation']))}")
    return "\n".join(lines)


# A tool citation as the model writes it: "tool t_prevalence:result.rarity",
# "(tool t_enrich_ip)" or a bare "t_x:result.y". The step listed the tool id
# and the result key, "prefetch_already_has_this" among them (V1-A4).
_TOOL_CITATION_RE = re.compile(
    r"^\(?\s*(?:tool\s+)?(?P<tool>t_[A-Za-z0-9_]+)\s*(?::\s*(?P<path>[^)]*?))?\s*\)?$"
)
# Result keys that are an instruction to the model, as what they mean.
_CITED_RESULT_WORDS = {"prefetch_already_has_this": "the events soc-ai already loaded"}


def _citation_words(citation: str) -> str:
    """A tool citation in words: "Indicator prevalence: rarity".

    A field path and a document id stay as they are: the analyst opens them.
    """
    m = _TOOL_CITATION_RE.match(citation.strip())
    if m is None:
        return _compact(citation)
    tool = m.group("tool")
    noun = _TOOL_NOUN.get(tool, _humanize_id(tool).capitalize())
    path = (m.group("path") or "").strip()
    path = "" if path == "result" else path.removeprefix("result.")
    if not path:
        return noun
    return f"{noun}: {_CITED_RESULT_WORDS.get(path, path.replace('_', ' '))}"


def _auto_ack_detail(p: dict[str, Any]) -> str:
    """The auto-acknowledge write, in words. The step showed its raw JSON (V1-A4)."""
    es_id = p.get("es_id")
    alert = f"alert {es_id}" if isinstance(es_id, str) and es_id else "the alert"
    if p.get("success") is False:
        return f"soc-ai tried to acknowledge {alert} in Security Onion. The write failed."
    out = f"soc-ai acknowledged {alert} in Security Onion."
    conf, threshold = p.get("confidence"), p.get("threshold")
    if _is_number(conf) and _is_number(threshold):
        out += f" The confidence {conf:.2f} is at or above the threshold {threshold:.2f}."
    return out


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _special_step(kind: str, p: dict[str, Any]) -> tuple[str, str] | None:
    """Title and detail for the kinds whose payload is machine data (P11)."""
    if kind == "auto_ack":
        return timeline_labels.title_for(kind, p), _auto_ack_detail(p)
    if kind.endswith("_downgrade") and (down := _downgrade_detail(p)) is not None:
        return timeline_labels.title_for(kind, p), down
    if kind == "auto_ack_skipped":
        reason = _auto_ack_skip_reason(p)
        return (
            f"Auto-acknowledge skipped: {reason}",
            f"soc-ai did not acknowledge the alert. The reason is {reason}.",
        )
    if kind == "host_dossier":
        raw_hosts = p.get("hosts")
        n = len(raw_hosts) if isinstance(raw_hosts, dict) else 0
        return (
            f"Host dossier: asset context for {n} host{'' if n == 1 else 's'}",
            _dossier_event_detail(p),
        )
    return None


def _detail_for(kind: str, p: dict[str, Any] | None, result: Any = None) -> str:
    """A human-readable details+outcome line per event (vs a raw JSON dump)."""
    p = p or {}
    if kind in ("enriched_alert_context", "alert_context"):
        enr = p.get("enrichments") or {}
        prof = p.get("host_alert_profile") or {}
        n_enr = len(enr) if isinstance(enr, dict) else 0
        if p.get("subject") == "hunt":
            # D2. The step loaded the hunt and the documents its findings
            # cite. The alert profile of the one anchor document says nothing
            # about a hunt that spans several.
            docs = p.get("subject_documents")
            return (
                "soc-ai loaded the hunt's findings and the "
                f"{len(docs) if isinstance(docs, list) else 0} documents they cite. "
                f"soc-ai enriched {_times(n_enr, 'indicator', 'indicators')}."
            )
        # "Enriched N indicators" reads as N reputation checks. Say when it was not.
        gap = (
            " soc-ai loaded no blocklist feed. It checked no indicator against threat intel."
            if isinstance(enr, dict) and _blocklist_unchecked(enr)
            else ""
        )
        # One fact per sentence, and a count with its own plural (V1-A5).
        types = (
            f" The host shows {_times(len(prof), 'alert type', 'alert types')} in the window."
            if isinstance(prof, dict) and prof
            else ""
        )
        return (
            f"soc-ai loaded the alert. soc-ai enriched "
            f"{_times(n_enr, 'indicator', 'indicators')}.{types}{gap}"
        )
    if kind == "decision_template_match":
        if p.get("skipped") == "hunt_subject":
            return "A decision template matches an alert rule class. A hunt has none."
        if p.get("matched"):
            conf = p.get("confidence")
            at = f" at {conf:.2f}" if isinstance(conf, int | float) else ""
            return (
                f"The run matched the {_template_label(p.get('template_id'))} pattern. "
                f"The pattern gives {_verdict_words(p.get('verdict'))}{at}. "
                f"{_template_rationale(p.get('template_id'), p.get('rationale'))}"
            ).strip()
        return "No pattern matched. soc-ai ran a full tool-using investigation."
    if kind == "investigation_loop_entered":
        # The first pass is skipped on most alerts, so there is often no
        # round-1 verdict. Say nothing rather than "Round 1 was None at None".
        why = _loop_reason(p.get("reason"), p.get("trigger"))
        if p.get("round1_verdict") is None:
            return f"{why} soc-ai skipped the first pass.".strip()
        conf = p.get("round1_confidence")
        at = f" at {conf:.2f}" if isinstance(conf, int | float) else ""
        return (
            f"{why} The first pass reached {_verdict_words(p.get('round1_verdict'))}{at}."
        ).strip()
    if kind == "triage_report":
        return _report_detail(p)
    if kind == "template_grounds_adopted":
        cites = p.get("citations") or []
        return f"{p.get('template_id')} grounds recorded as the citations: {', '.join(cites)}"
    if kind == "citation_validation":
        return _citation_detail(p)
    if kind == "citation_cap":
        return (
            f"confidence {p.get('original_confidence')} → {p.get('capped_confidence')} "
            "to respect citation coverage"
        )
    if kind == "investigation_transcript":
        ev = p.get("evidence") or []
        return f"{p.get('tentative_summary', '')}\nevidence gathered: {len(ev)} item(s)".strip()
    if kind == "error":
        return _compact(p.get("message") or p.get("error") or "")
    if kind == "session_start":
        # The pipeline name is an internal label (R2 STE 6). The row says
        # enough without it.
        return ""
    if kind == "context_trimmed":
        return _compact(p.get("detail") or "")
    if kind == "prior_outcomes":
        # E4.2 memory recall: compact verdict/tier chips, framed the way the
        # prompt frames them — context the model saw, never evidence.
        items = p.get("items") or []
        chips = ", ".join(
            f"{it.get('verdict')} ({it.get('matched_on')})" for it in items if isinstance(it, dict)
        )
        return (
            f"Context only. This is never evidence. The synthesizer saw "
            f"{p.get('count')} prior verdict(s) within {p.get('window_days')} days: {chips}"
        )
    if kind == "session_prior":
        # The same conversation, already read. Named rather than tallied: the
        # analyst needs the id to open the other investigation, which is the
        # whole point of telling them the two are related.
        items = p.get("items") or []
        chips = ", ".join(
            f"{_verdict_words(it.get('verdict'))} ({it.get('id')})"
            for it in items
            if isinstance(it, dict)
        )
        minutes = p.get("window_minutes")
        window = (
            f" in the last {minutes // 60} hours"
            if isinstance(minutes, int) and minutes >= 120 and minutes % 60 == 0
            else f" in the last {minutes} minutes"
            if isinstance(minutes, int) and minutes > 0
            else ""
        )
        return f"An earlier run on another alert of this network session reached {chips}{window}."
    if kind == "analyst_verdict":
        who = p.get("analyst") or "An analyst"
        return (
            f"{who} set the verdict of this alert to {_verdict_words(p.get('verdict'))} "
            f"on investigation {p.get('id')}. The run read this verdict as context."
        )
    if kind == "session_verdict_conflict":
        return (
            f"Held at needs_more_info. Investigation {p.get('prior_investigation_id')} "
            "already reached true positive on this same session. A false positive "
            "cannot stand on it."
        )
    if kind == "chat_memory":
        # Chat-transcript recall: source/role chips only — the payload carries
        # no snippet text (it lives in the prompt), and the framing repeats the
        # operator's hard rule so the timeline can't oversell a chat opinion.
        items = p.get("items") or []
        chips = ", ".join(
            f"{it.get('source')} ({it.get('role')})" for it in items if isinstance(it, dict)
        )
        return (
            f"Context only. This is never evidence. The synthesizer saw "
            f"{p.get('count')} past chat excerpt(s) within {p.get('window_days')} days: {chips}"
        )
    return _compact(p)


class RecommendedActionOut(BaseModel):
    id: str
    title: str
    tag: str
    rationale: str
    # Always None/False since the approval gate was removed — kept because the
    # frontend still reads these fields (its removal is a separate task).
    token: str | None = None
    pending: bool = False
    # True when this action was already carried out by the system (e.g. auto-ack
    # fired on a high-confidence FP). The UI renders it as done, NOT actionable —
    # the analyst must not be offered an "Acknowledge" button for an already-acked
    # alert. Durable: derived from the persisted event stream, not client state.
    applied: bool = False
    # Short human label for WHY it reads as done ("Already acknowledged",
    # "Executed · analyst"). None keeps the UI's default auto-ack wording.
    appliedNote: str | None = None
    # Why a PENDING ack is waiting for a human when auto-ack is otherwise armed
    # (severity/exploit-class guard, confidence below the threshold, nothing
    # retrieved, or a report that cites nothing that resolves) — from the
    # persisted auto_ack_skipped event. None when auto-ack simply doesn't
    # apply. Two identical-looking ack cards behaving differently with no
    # explanation was a dogfood trust finding (2026-07-15).
    pendingNote: str | None = None
    # Who or what carried the action out, and when (dogfood 2026-10-06, S3).
    # "auto-ack" for the unattended ack, else the caller the execute route
    # recorded. ``appliedAt`` is ISO UTC. Both stay set on an ack the grid
    # no longer shows acknowledged, so the card can name the earlier write
    # while it offers the ack again.
    appliedBy: str | None = None
    appliedAt: str | None = None
    # What the write did, from the stored receipt ("Acknowledged 9 alerts of
    # this rule from the last 7 days.").
    appliedDetail: str | None = None
    # An analyst dismissed the recommendation (dogfood 2026-10-06, first hour
    # S4). Stored, so a reload and a second analyst see it. An undo clears it.
    dismissed: bool = False
    dismissedBy: str | None = None
    dismissedAt: str | None = None
    # Why the card offers no write for this action. The rule is
    # :func:`soc_ai.api.webui.action_rules.action_block`, the one the row of
    # the pending-action list, the needs-you count and the execute route read.
    # Dismiss stays on. None when the console may execute the action.
    blockedReason: str | None = None


# A verdict code as the words of a sentence: "set the verdict to false positive".
_VERDICT_NAMES = {
    "true_positive": "true positive",
    "false_positive": "false positive",
    "needs_more_info": "needs more info",
    "inconclusive": "no verdict",
    "untriaged": "no verdict",
}


def _verdict_name(verdict: str | None) -> str:
    return _VERDICT_NAMES.get(verdict or "", (verdict or "no verdict").replace("_", " "))


def analyst_verdict_block(
    tag: str,
    run_verdict: str | None,
    analyst_verdict: str | None,
    analyst_by: str | None,
) -> str | None:
    """Why the console offers no write for an action, under the analyst verdict rule.

    The one rule for the action card of the run page and for the row of the
    pending-action list, so the two surfaces cannot drift. A write never acts
    against an analyst verdict. The analyst verdict stands on the alert over
    every run of it (dogfood 2026-10-19, R2-D1). The rule fires in two cases:

    * The analyst verdict differs from the verdict of this run. An override
      of this run makes the actions follow the analyst.
    * The action is an ack, and the analyst verdict is not false positive.
      soc-ai does not acknowledge an alert that an analyst set to true positive.

    ``tag`` is the tag of the action: "ack", "escalate" or "comment". None
    when no analyst verdict stands, or when the action agrees with it.
    """
    if not analyst_verdict:
        return None
    who = analyst_by or "An analyst"
    head = f"{who} set the verdict of this alert to {_verdict_name(analyst_verdict)}."
    if analyst_verdict != run_verdict:
        return (
            f"{head} This run reached {_verdict_name(run_verdict)}. "
            "Override the verdict of this run to act."
        )
    if tag == "ack" and analyst_verdict != "false_positive":
        return f"{head} soc-ai does not acknowledge an alert with that verdict."
    return None


class CaseRefOut(BaseModel):
    """One Security Onion case, and where its console shows it.

    The wire shape of ``routes_alerts.CaseLinkOut``. ``url`` is None when the
    settings name no Security Onion host.
    """

    id: str
    url: str | None = None


class WaitingActionOut(BaseModel):
    """One recommended action that waits for a person, as a list row carries it.

    The Investigations list filtered to the waiting actions offers Execute and
    Dismiss on the row (dogfood 2026-10-19, R1-I1). The analyst opened each run
    to act, and came back: two page changes per run. ``index`` is the position
    in the report, the key of the action routes. ``executable`` is False when
    the row must not offer Execute, and ``reason`` then says why. Dismiss
    writes nothing to Security Onion, and the row offers it for every action.
    """

    id: str
    index: int
    # "ack", "escalate" or "comment": the tag of the action card.
    type: str
    label: str
    # The rule of the alert for an ack or an escalate. The case id for a comment.
    target: str | None = None
    # "alert", "case", "finding" or "lead": what the action acts on. A run
    # that a promotion landed names a finding or a lead (V3-N4).
    targetType: str | None = None
    rationale: str = ""
    executable: bool = True
    reason: str | None = None


class TimelineStepOut(BaseModel):
    id: str
    group: str
    title: str
    time: str = ""
    detail: str = ""


# Assistant-message ``meta["kind"]`` values that render as a CARD with a control
# on it (Apply this verdict / Start this hunt) rather than as prose. The registry
# lives next to the serializer that consumes it so a new proposal-producing chat
# registers its kind here and is on the wire — the first one that didn't
# (hunt_proposal, from the Dashboard chat) serialized with kind/messageId/
# proposal all None and the analyst never saw the control.
PROPOSAL_KINDS = frozenset({"verdict_proposal", "hunt_proposal"})


class ChatMessageOut(BaseModel):
    role: str
    text: str
    tools: str | None = None
    messageId: int | None = None
    kind: str | None = None
    validation: str | None = None
    objection: str | None = None
    token: str | None = None
    applied: bool | None = None
    proposal: dict[str, Any] | None = None


class InvMetaOut(BaseModel):
    model: str
    oracle: str | None = None
    ranBy: str
    ranAt: str
    toolCalls: int
    pivots: int


class OracleOut(BaseModel):
    escalated: bool = True
    reason: str | None = None
    localVerdict: str | None = None
    localConfidence: float | None = None
    oracleVerdict: str | None = None
    oracleConfidence: float | None = None
    model: str | None = None
    redacted: bool = False
    redactionNote: str | None = None
    changed: bool = False  # oracleVerdict differs from localVerdict
    # The Oracle answered another class with no evidence that resolves. Its
    # answer is an opinion on the run; the local verdict stands.
    withheld: bool = False


class FallbackOut(BaseModel):
    """Pipeline-failure provenance surfaced to the drawer (E1.2).

    Built from the report's ``resolution`` marker when it carries
    ``provenance == "pipeline_fallback"``. ``hint`` is the analyst-actionable
    ``_hint_for`` string (e.g. "the model hit its response-token cap …") when the
    error class produced one; ``None`` for unclassified failures.
    """

    provenance: str
    phase: str | None = None
    errorType: str | None = None
    hint: str | None = None


def _fallback_out(report: dict[str, Any]) -> FallbackOut | None:
    """Build the ``fallback`` view-model from a persisted report dict, or None.

    Reads the SAME marker as :func:`is_pipeline_fallback` (the single shared
    predicate) so the drawer's fallback state can never disagree with the row /
    badge flag. Never raises on a malformed marker — a rendering builder must not
    break the page.
    """
    from soc_ai.triage_models import is_pipeline_fallback  # noqa: PLC0415

    if not is_pipeline_fallback(report):
        return None
    marker = report.get("resolution") or {}
    return FallbackOut(
        provenance=str(marker.get("provenance") or "pipeline_fallback"),
        phase=marker.get("phase"),
        errorType=marker.get("error_type"),
        hint=marker.get("hint"),
    )


class CitationOut(BaseModel):
    """One citation of the report, with what it names.

    ``kind`` is ``id`` (a document id), ``path`` (an alert-context field),
    ``tool`` (a tool the run called) or ``unknown``. ``target`` is the id, path
    or tool name. ``resolved`` is the validator's answer, None when the run
    recorded no validation.
    """

    text: str
    kind: str
    target: str | None = None
    resolved: bool | None = None


class FailureOut(BaseModel):
    """Why a failed run failed (RL11, RD13).

    ``permanent`` is True when a re-run cannot change the outcome: the alert is
    gone from the grid. The page then does not advise a re-run.
    """

    cause: str
    hint: str | None = None
    permanent: bool = False


# Markers the pipeline writes into `citations` that name no document.
_NON_DOCUMENT_CITATIONS = frozenset({"synth_first_failure"})


_ULID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")


def _citations_out(report: dict[str, Any], events: list[Any]) -> list[CitationOut]:
    """The report's citations, classified, with the validator's verdict on each.

    The detail used to send no citations at all, so the page could link none
    and the Validators step listed none of the ids it had checked (P3).
    """
    from soc_ai.agent.evidence import _classify_citation  # noqa: PLC0415

    resolved_by_text: dict[str, bool] = {}
    for e in events:
        if e.kind != "citation_validation":
            continue
        per = (e.payload or {}).get("per_citation")
        if not isinstance(per, list):
            continue
        resolved_by_text = {
            str(item.get("citation")): bool(item.get("resolved"))
            for item in per
            if isinstance(item, dict) and item.get("citation")
        }
    raw = report.get("citations")
    out: list[CitationOut] = []
    seen: set[str] = set()
    for c in raw if isinstance(raw, list) else []:
        if not isinstance(c, str) or not c.strip() or c in seen:
            continue
        seen.add(c)
        if c.strip() in _NON_DOCUMENT_CITATIONS:
            continue
        kind, target = _classify_citation(c)
        if kind == "id" and target is not None and _ULID_RE.fullmatch(target):
            # A ULID names an investigation or a hunt, never a grid document.
            # The page would open the document dialog on it and read a 404.
            kind = "run"
        out.append(CitationOut(text=c, kind=kind, target=target, resolved=resolved_by_text.get(c)))
    return out


def _open_questions_out(report: dict[str, Any], events: list[Any]) -> list[str]:
    """The gaps the run could not close.

    ``TriageReport`` has no ``open_questions`` field. The investigator's
    transcript has it, and the run stores the transcript as an
    ``investigation_transcript`` event. The detail read the report alone, so
    every needs_more_info run on prod showed no open questions (P2). An older
    report that carries the key still wins.
    """

    def _clean(raw: Any) -> list[str]:
        if not isinstance(raw, list):
            return []
        return [str(q).strip() for q in raw if isinstance(q, str) and q.strip()]

    from_report = _clean(report.get("open_questions"))
    if from_report:
        return from_report
    for e in reversed(events):
        if e.kind == "investigation_transcript":
            found = _clean((e.payload or {}).get("open_questions"))
            if found:
                return found
    return []


# An error type or message that no re-run can change: the alert itself is gone.
_PERMANENT_ERROR_TYPES = frozenset({"SoNotFoundError"})
_PERMANENT_ERROR_PREFIXES = ("alert not found", "hunt not found")


# The analyst sentence for a failure phase. A stored hint named the setting
# ``investigation_run_timeout_s``, which an analyst cannot act on (dogfood
# 2026-10-06). The stored rows keep their text, and the page reads this.
_FAILURE_HINTS: dict[str, str] = {
    "run_cancelled": (
        "This run stopped before a verdict. A sweep time limit, a restart or a closed "
        "connection stops a run. Re-run it to get a verdict."
    ),
    "whole_run_backstop": (
        "This run hit its time limit before a verdict. A slow model backend is the usual "
        "cause. The operator can check the model gateway."
    ),
}


# A hint an older run stored, as the page states it now (V1-A5). The run
# keeps its text. Both wordings name Elasticsearch, and the console calls it
# the grid.
_ALERT_ID_HINT = "The alert id can be wrong. Check that the alert is in the grid."
_STORED_HINTS: dict[str, str] = {
    "alert id may be wrong; verify it exists in ES.": _ALERT_ID_HINT,
    "The alert id can be wrong. Check that the alert exists in Elasticsearch.": _ALERT_ID_HINT,
}


def _failure_out(status: str | None, events: list[Any]) -> FailureOut | None:
    """The recorded cause of an errored run, from its last ``error`` event."""
    if status != "error":
        return None
    for e in reversed(events):
        if e.kind != "error":
            continue
        p = e.payload or {}
        message = str(p.get("message") or p.get("error") or "").strip()
        if not message:
            continue
        err_type = str(p.get("type") or "")
        permanent = err_type in _PERMANENT_ERROR_TYPES or message.lower().startswith(
            _PERMANENT_ERROR_PREFIXES
        )
        hint = _FAILURE_HINTS.get(str(p.get("phase") or ""), p.get("hint"))
        if isinstance(hint, str):
            hint = _STORED_HINTS.get(hint.strip(), hint)
        return FailureOut(
            cause=_compact(message),
            hint=hint if isinstance(hint, str) and hint.strip() else None,
            permanent=permanent,
        )
    return None


class SupersededRunOut(BaseModel):
    """The newer run of the same alert that replaced a run."""

    id: str
    # The list's status word: complete, running, error, cancelled, interrupted.
    status: str
    # The verdict and confidence of a complete run. None while it runs.
    verdict: str | None = None
    conf: float | None = None


class StandingAnalystVerdictOut(BaseModel):
    """The verdict an analyst set on an alert, and the run it is on."""

    investigationId: str
    verdict: str
    # The person, when the resolution names one.
    by: str | None = None
    # "manual" for an override, "chat" for a chat proposal the analyst applied.
    via: str
    # ISO UTC time of the resolution, when it was stored.
    at: str | None = None


class EntityRefOut(BaseModel):
    """One entity the investigation names, with the page that answers for it.

    The console renders each one as a link. ``type`` says what the value is:
    ``address`` (internal), ``external_address``, ``host`` (a host name),
    ``user`` or ``domain``. ``host_key`` is the machine that holds the value,
    when one does, so the link opens the machine page in one step. ``role``
    says where the investigation names it: ``source``, ``destination``,
    ``reporter`` or ``lead``.
    """

    value: str
    type: str
    role: str
    host_key: str | None = None
    href: str


class InvestigationOut(BaseModel):
    id: str
    groupId: str
    name: str
    kind: str
    # The source address and the destination address of the alert, as display
    # strings ("—" when the alert names none). ``host`` held the alert's host
    # name and ``ip`` fell back to the source address, so a host-reported alert
    # read "source <host> → destination <source address>".
    host: str
    ip: str
    # The same two ends, null when the alert names none, and the host that
    # reported the alert. The page names the reporter "on <host>" and never
    # puts it in a direction slot.
    srcIp: str | None = None
    dstIp: str | None = None
    reportedBy: str | None = None
    verdict: str
    conf: float
    rationale: str
    summary: list[dict[str, Any]]
    status: str
    elapsedLabel: str
    elapsedSec: int = 0
    actions: list[RecommendedActionOut]
    timeline: list[TimelineStepOut]
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seedChat: list[ChatMessageOut] = []
    meta: InvMetaOut | None = None
    oracle: OracleOut | None = None
    sev: str | None = None
    alert: dict[str, Any] | None = None
    hostContext: list[dict[str, Any]] = []
    graphNote: str | None = None
    # The direction of the alert's flow: "lateral" (internal to internal),
    # "inbound", "outbound" or "external". None when an end is unknown. The page
    # names lateral movement only on "lateral" (R2-D10).
    graphScope: str | None = None
    # The host context counts alerts within this many hours each side of the
    # alert (``host_risk_window_hours``). The panel states it (R2-D21).
    hostContextWindowHours: int | None = None
    openQuestions: list[str] = []
    # The report's citations, each with what it names. The page links an `id`
    # citation to its event (P3). Built by `_citations_out`.
    citations: list[CitationOut] = []
    # Why a run that ended in `error` failed, from its last `error` event. None
    # on any other run. Built by `_failure_out`.
    failure: FailureOut | None = None
    resolution: dict[str, Any] | None = None
    validatorNote: str | None = None
    # Pipeline-failure fallback provenance (E1.2). Present ONLY when the run's
    # report is a synth-failure fallback (`is_pipeline_fallback`) — the drawer
    # then renders "this run failed before reaching a verdict: <hint>" + a Re-run
    # button instead of treating it as a genuine needs_more_info. Distinct from
    # `resolution` (manual/chat override) so the two never conflate.
    fallback: FallbackOut | None = None
    # Operator ack of a fallback run (POST /investigations/{id}/dismiss-error) —
    # lets the drawer render the Dismiss button as already-done instead of
    # offering a redundant ack.
    errorDismissed: bool = False
    # Ordered model reasoning traces (the <think> blocks) captured per model turn.
    # Surfaced so an analyst can see WHY a verdict was reached — the "show your
    # work" explainability the timeline (which skips model_response) drops.
    reasoning: list[str] = []
    # Live acked state of the investigation's alert in Security Onion — covers
    # acks performed OUTSIDE this run (group-ack, another run's auto-ack, the SO
    # web UI) so the UI never offers "Acknowledge" for an already-acked alert.
    # False on any ES error (resilient: the page must never break on this).
    alertAcked: bool = False
    # What the run investigated (migration 0050). None for an alert subject:
    # the alert is named by the fields above. For a hunt subject it carries
    # the hunt id, the objective, the finding ordinals and titles, the lead id,
    # the cited document ids and the observation ids, so the page can read
    # "Subject: hunt <objective>" with the findings and the lead.
    subject: dict[str, Any] | None = None
    # Promotion provenance (migration 0031) — set only when kind == "hunt".
    huntId: str | None = None
    # The source hunt's whole objective. The console shows its head line and
    # holds the whole text on a hover. None when the hunt was
    # never set OR has since been deleted — hunt_id carries no FK (a promoted
    # investigation must survive hunt deletion), so this degrades gracefully
    # rather than 404ing the whole drawer.
    huntObjective: str | None = None
    # The finding the analyst promoted, for the page to name first: "Promoted
    # finding: F2, <title>", and attacker to victim from the finding. The
    # page read "Subject: hunt" with six findings and the raw model prompt
    # (dogfood 2026-10-06 C4). None on a run that no finding promoted. When
    # the hunt is gone, the stored subject names the finding. Built by
    # routes_hunts.promoted_finding_out.
    promotedFinding: dict[str, Any] | None = None
    # Migration 0032's synthetic-evaluation marker: this run investigated
    # PLANTED synthetic attack scenarios (directly, or promoted from a marked
    # hunt). The drawer badges it so a planted attack can never be read as
    # real activity.
    isSynthEval: bool = False
    # Per-end host context (dogfood 2026-10-01 RL3). One entry per endpoint IP
    # of the alert: the IP, which end of the alert it is, and its in-window
    # alerts split by side. Empty on runs stored before the split existed;
    # the page then labels ``hostContext`` as pooled over both ends.
    hostContexts: list[dict[str, Any]] = []
    # The id of the newer primary run for the same alert, when a later run
    # superseded this one. None when this run is the primary run.
    supersededBy: str | None = None
    # What that newer run reached, so the page can say it: "A newer run on
    # this alert reached true positive (0.65)." None when no run replaced
    # this one.
    supersededRun: SupersededRunOut | None = None
    # The verdict an analyst set on the alert, on ANY run of it, by the rule
    # the store uses (``analyst_verdicts_for_alerts``). The page read only its
    # own run, so a newer model run hid the analyst verdict that stands, and
    # Re-run asked nothing (dogfood 2026-10-19, V1-A3). None when no person
    # set a verdict on the alert, and on a hunt subject.
    standingAnalystVerdict: StandingAnalystVerdictOut | None = None
    # Why no write from this page can reach Security Onion: a promotion landed
    # the run, or a promotion uses the alert of the run as its anchor. The
    # rule is :func:`soc_ai.api.webui.action_rules.action_block`. The page
    # offers no settled bar and no escalate from the chat on such a run
    # (V3-N2). None when the run has an alert to act on.
    writeBlockedReason: str | None = None
    # The Security Onion cases the alert of this run is on, read when an
    # escalate of the run waits: the escalation ledger first, then the case
    # links of the grid. The escalate card names and links each case, like
    # the Alerts escalate confirm (V3-N2). ``alertCasesComplete`` is False
    # when the grid did not confirm the list.
    alertCases: list[CaseRefOut] = []
    alertCasesComplete: bool = False
    # On a backtest replay only: the live run of the alert, the newest
    # complete run outside the backtest. A new run started from a replay is a
    # live run and replaces that verdict (V1-A2). None on a live run, and on a
    # replay whose alert has no live verdict.
    alertLiveRun: SupersededRunOut | None = None
    # A run in flight: what it does now, and how long runs on this grid take
    # (dogfood 2026-10-06, first hour W11). The display stayed on "Working"
    # for minutes with no estimate. Both None once the run ends.
    currentStep: str | None = None
    # {lowMin, highMin, medianMin, samples}, from the newest finished runs.
    # None while the store holds fewer than three.
    typicalRun: dict[str, Any] | None = None
    # The budget class the run ran in (migration 0058): cheap, standard, deep
    # or rule_prior. None on a run stored before the classes existed. The
    # console shows it as a chip.
    runClass: str | None = None
    # Why the run ended in its class, from the stored report. None when the
    # report does not say.
    runClassReason: str | None = None
    # Every host, address, user and domain the run names, each with the page
    # that answers for it. The console makes each one a link. Empty from an
    # older server.
    entities: list[EntityRefOut] = []
    # The documents of the run in event-time order, with the waves (change
    # D). Built by ``_event_timeline.investigation_event_timeline`` from the
    # stored documents. None while the run runs, and when fewer than two
    # documents have a stored time.
    eventTimeline: EventTimelineOut | None = None


def _host_contexts(profiles: Any) -> list[dict[str, Any]]:
    """Wire shape of the per-end host context: each end named, each side ranked."""
    if not isinstance(profiles, list):
        return []
    out: list[dict[str, Any]] = []
    for p in profiles:
        if not isinstance(p, dict) or not p.get("ip"):
            continue
        as_src = p.get("as_source")
        as_dst = p.get("as_destination")
        out.append(
            {
                "ip": str(p["ip"]),
                "end": str(p.get("end") or ""),
                "asSource": _host_signals(as_src if isinstance(as_src, dict) else {}),
                "asDestination": _host_signals(as_dst if isinstance(as_dst, dict) else {}),
            }
        )
    return out


def _collect_reasoning(events: list[Any]) -> list[str]:
    """Ordered reasoning traces from model_response events.

    ``_walk_message`` attaches the model's ``<think>`` trace to each
    model_response event as ``reasoning_trace``; the analyst timeline skips
    model_response, so those traces are otherwise invisible. Collect the
    non-empty ones in order for the "Model reasoning" panel.
    """
    out: list[str] = []
    for e in events:
        if e.kind != "model_response":
            continue
        trace = (e.payload or {}).get("reasoning_trace")
        if isinstance(trace, str) and trace.strip():
            # The trace quotes tool results verbatim, so it can carry a
            # credential the telemetry held. The store keeps the event as
            # evidence; the console never shows the value.
            out.append(scrub_secrets(trace.strip()))
    return out


# Share of ``webui_grid_timeout_s`` the discardable acked-state probe may spend.
# It is one optional badge on a page built mostly from the DB, and its documented
# failure mode is "return False and offer the action anyway" — so it gets a slice
# of the console budget, not all of it. Floored at 0.5 s so a small
# ``webui_grid_timeout_s`` can never round the probe down to an instant expiry.
# The slice was a quarter, 3 s at the default budget. An id lookup across the
# whole index pattern takes that long on a slow grid, and the detail page
# waited the full 3 s on every open (range smoke, 2026-10-06). The page now
# waits at most 0.75 s at the default and shows the stored state after that.
_ACKED_PROBE_BUDGET = 0.0625


def _acked_probe_timeout_s(settings: Settings) -> float:
    """Wall-clock bound for the acked-state probe, derived from the console budget."""
    return max(0.5, settings.webui_grid_timeout_s * _ACKED_PROBE_BUDGET)


async def _alert_currently_acked(
    elastic: ElasticClient, settings: Settings, alert_es_id: str | None
) -> bool:
    """``True`` when the grid says the alert is acknowledged. See :func:`_alert_ack_state`."""
    return await _alert_ack_state(elastic, settings, alert_es_id) is True


async def _alert_ack_state(
    elastic: ElasticClient, settings: Settings, alert_es_id: str | None
) -> bool | None:
    """Live ``event.acknowledged`` state of one alert in the SO index.

    ``True`` or ``False`` when the grid answered, ``None`` when it did not
    (no id, no hit, an error, the time budget). The investigation page needs
    the third answer: an ack the grid does not show must not read as
    executed, but a grid that did not answer proves nothing either way.

    Same ``ids`` lookup shape as :func:`resolve_alert_for_hunt`, reading the
    same ``event.acknowledged`` field the alerts list aggregates on
    (``soc_ai.webui.alerts_query``). Covers acks performed OUTSIDE this
    investigation (group-ack, another run's auto-ack, the SO web UI).
    Resilient by design: any ES error/miss returns False so the detail page
    falls back to current behavior (offer the action) instead of breaking.

    Bounded TIGHTER than the console-wide grid budget (see
    :data:`_ACKED_PROBE_BUDGET`): the answer is discarded on any failure, so a
    silent grid must not spend the investigation-detail page's whole budget —
    let alone the ES client's ~90 s retry budget — on a signal we are already
    willing to do without. Wrong-direction risk is nil: guessing "not acked"
    only re-offers an idempotent ack.
    """
    if not alert_es_id:
        return None
    try:
        async with asyncio.timeout(_acked_probe_timeout_s(settings)):
            lookup = await elastic.search(
                settings.events_index_pattern,
                {"ids": {"values": [alert_es_id]}},
                size=1,
                source=["event.acknowledged"],
            )
        if not lookup.hits:
            return None
        source = lookup.hits[0].get("_source", {})
        return bool(get_dotted(source, "event.acknowledged"))
    except Exception:  # never break the detail page on an acked-state probe
        return None


def _action_identity(action: dict[str, Any]) -> str:
    """Stable key for a recommended action, independent of its POSITION in
    ``report.recommended_actions``.

    Chat-resolve can REPLACE the whole recommended_actions list, re-indexing every
    action; a position-keyed idempotency marker would then bind to whatever action
    now occupies that slot (F04). Keying on the model-authored content (tool + args
    + rationale) keeps an "executed" marker bound to the action it actually ran, and
    lets a genuinely new recommendation stay actionable.
    """
    return json.dumps(
        {
            "tool_name": action.get("tool_name", ""),
            "tool_args": action.get("tool_args") or {},
            "rationale": action.get("rationale", ""),
        },
        sort_keys=True,
        default=str,
    )


def _executed_actions(events: list[Any]) -> dict[str, dict[str, Any]]:
    """action-identity -> payload of persisted successful advisory-action executions.

    ``POST .../actions/{index}/execute`` writes an ``action_executed`` event on
    success (FR-030); reading it back here means a reload never re-offers an
    already-executed escalate (duplicate SO cases) or ack.

    Keyed by the action's stable identity (``action_key``, see
    :func:`_action_identity`) so the marker survives a chat-resolve that REPLACES
    (and thus re-indexes) recommended_actions (F04). Legacy markers written before
    ``action_key`` existed are keyed by position as ``#idx:<n>`` so a reload still
    reads them as applied.
    """
    out: dict[str, dict[str, Any]] = {}
    for e in events:
        if e.kind != "action_executed":
            continue
        p = e.payload or {}
        if not p.get("success"):
            continue
        key = p.get("action_key")
        if not isinstance(key, str) or not key:
            idx = p.get("index")
            if not isinstance(idx, int):
                continue
            key = f"#idx:{idx}"
        out[key] = p
    return out


def _ack_pending_note(events: list[Any]) -> str | None:
    """Why a pending ack waits for a person while auto-ack is armed, or None."""
    # Auto-ack armed but held back? Explain the pending ack instead of leaving
    # the analyst to guess why THIS one needs a click.
    ack_pending_note: str | None = None
    for e in events:
        if e.kind != "auto_ack_skipped":
            continue
        p = e.payload or {}
        if p.get("reason") == "high_stakes":
            ack_pending_note = (
                "An analyst acknowledges a high or critical alert. An analyst "
                "acknowledges a malware or exploit alert."
            )
        elif p.get("reason") == "analyst_verdict":
            ack_pending_note = (
                f"An analyst set this alert to {_verdict_words(p.get('analyst_verdict'))}. "
                "soc-ai does not acknowledge it."
            )
        elif p.get("reason") == "analyst_verdict_unknown":
            ack_pending_note = (
                "soc-ai could not read the analyst verdict of this alert. "
                "A person must acknowledge it."
            )
        elif p.get("reason") == "below_threshold":
            conf, thr = p.get("confidence"), p.get("threshold")
            if isinstance(conf, int | float) and isinstance(thr, int | float):
                ack_pending_note = (
                    f"Auto-ack is on. Confidence {conf:.2f} is below the "
                    f"{thr:.2f} auto-ack threshold."
                )
        elif p.get("reason") == "no_investigation":
            ack_pending_note = (
                "Auto-ack is on. This run reached its verdict and retrieved "
                "nothing. A person must acknowledge it."
            )
        elif p.get("reason") == "oracle_dissent":
            ack_pending_note = (
                "Auto-ack is on. The Oracle answered another verdict and cited no "
                "evidence that resolves. The local verdict stands. A person must "
                "acknowledge it."
            )
        elif p.get("reason") == "uncited":
            # Both shapes read the same way to an analyst — the verdict names
            # nothing that can be checked — so they get one sentence, with the
            # count telling them which one it was.
            ack_pending_note = (
                "Auto-ack is on. The report cites no evidence that resolves to "
                "anything this run retrieved. A person must acknowledge it."
            )
        break
    return ack_pending_note


# The note on every recommended action of a backtest replay. The console
# renders an action that carries a note as closed, with no Execute button.
REPLAY_ACTION_NOTE = "Not executable. This run is a backtest replay."


# Why an ack the record calls done is offered again: the grid answered and
# shows the alert unacknowledged (dogfood 2026-10-06, S3). The card and the
# record must agree, so the card does not say "Executed".
_ACK_NOT_ON_GRID_GROUP = (
    "An earlier ack covered other alerts of this rule. Security Onion shows "
    "this alert as not acknowledged."
)
_ACK_NOT_ON_GRID = "Security Onion shows this alert as not acknowledged."


def _dismissals(events: list[Any]) -> dict[str, dict[str, Any]]:
    """action-identity -> the payload of its standing dismissal.

    The newest record wins: a dismissal followed by an undo is not dismissed.
    Keyed like :func:`_executed_actions`, with the position key for a record
    that names no identity.
    """
    out: dict[str, dict[str, Any]] = {}
    ordered = sorted(
        (e for e in events if e.kind in ("action_dismissed", "action_restored")),
        key=lambda e: int(getattr(e, "sequence", 0) or 0),
    )
    for e in ordered:
        p = e.payload or {}
        key = p.get("action_key")
        if not isinstance(key, str) or not key:
            idx = p.get("index")
            if not isinstance(idx, int):
                continue
            key = f"#idx:{idx}"
        if e.kind == "action_dismissed":
            out[key] = p
        else:
            out.pop(key, None)
    return out


def action_tool_names(events: Sequence[Any], report: dict[str, Any]) -> list[str]:
    """The tool name of each action :func:`_build_actions` returns, in its order.

    The action rule reads the tool, and the action card carries only its tag.
    A run from the old approval gate names its tools on the approval events.
    """
    approvals = [e for e in events if e.kind in ("approval_request", "approval_required")]
    if approvals:
        return [str((e.payload or {}).get("tool_name") or "") for e in approvals]
    recs = report.get("recommended_actions") or []
    return [str(r.get("tool_name") or "") if isinstance(r, dict) else "" for r in recs]


def _build_actions(
    events: list[Any],
    report: dict[str, Any],
    *,
    alert_acked: bool = False,
    alert_unacked: bool = False,
    ran_at: str | None = None,
    replay: bool = False,
) -> list[RecommendedActionOut]:
    """Recommended actions from historical approval events or report recommendations.

    An ack action already carried out by auto-ack is flagged ``applied`` so the UI
    never offers an "Acknowledge" button for an alert the system already acked.
    ``alert_acked`` (the alert's LIVE acked state in ES) and persisted
    ``action_executed`` events extend the same applied concept to acks performed
    outside this run and to analyst-executed advisory actions (FR-030).

    ``alert_unacked`` is the other answer of the same probe: the grid answered
    and the alert is NOT acknowledged. An ack the record calls done then reads
    as pending again, with the earlier write named. ``ran_at`` is when the run
    finished, the time of an auto-ack, which records no time of its own.

    ``replay`` marks the run as a backtest replay. The page still shows what
    the model recommended, because that is part of what the backtest
    measured. Every action is closed with :data:`REPLAY_ACTION_NOTE`, so the
    console offers no Execute button, and the execute route refuses the write.
    """
    if replay:
        return [
            action.model_copy(
                update={
                    "applied": True,
                    "appliedNote": REPLAY_ACTION_NOTE,
                    "pendingNote": None,
                    "appliedBy": None,
                    "appliedAt": None,
                    "dismissed": False,
                }
            )
            for action in _build_actions(events, report, alert_acked=alert_acked)
        ]
    # Auto-ack fired successfully? Then any ack action is already done.
    auto_acked = any(e.kind == "auto_ack" and (e.payload or {}).get("success") for e in events)
    executed = _executed_actions(events)
    dismissed = _dismissals(events)

    ack_pending_note = _ack_pending_note(events)

    def _ack_note(tn: str) -> str | None:
        # Only the NEW already-acked case gets a note; auto-ack keeps the UI's
        # default "Auto-acknowledged · system · automatic" wording.
        if tn == "ack_alert" and alert_acked and not auto_acked:
            return "Already acknowledged"
        return None

    # Historical approval-gate events (the gate was removed; old DB rows still
    # carry them). Render the recommendation, permanently non-actionable:
    # no token, never pending — there is no /approve endpoint to redeem one.
    approval_events = [e for e in events if e.kind in ("approval_request", "approval_required")]
    out: list[RecommendedActionOut] = []
    if approval_events:
        for i, ev in enumerate(approval_events):
            tok = ev.payload.get("token")
            tn = ev.payload.get("tool_name", "")
            applied = (auto_acked or alert_acked) and tn == "ack_alert"
            out.append(
                RecommendedActionOut(
                    id=tok or f"a{i}",
                    title=_ACTION_TITLE.get(tn, tn or "Action"),
                    tag=_ACTION_TAG.get(tn, "comment"),
                    rationale=ev.payload.get("rationale", ""),
                    token=None,
                    pending=False,
                    applied=applied,
                    appliedNote=_ack_note(tn) if applied else None,
                )
            )
        return out
    for i, a in enumerate(report.get("recommended_actions", []) or []):
        tn = a.get("tool_name", "")
        # Match by stable identity first (survives a chat-resolve re-index, F04),
        # falling back to the legacy position key for pre-action_key markers.
        exec_p = executed.get(_action_identity(a)) or executed.get(f"#idx:{i}")
        applied = exec_p is not None or ((auto_acked or alert_acked) and tn == "ack_alert")
        note: str | None = None
        by: str | None = None
        at: str | None = None
        detail: str | None = None
        if exec_p is not None:
            by = str(exec_p.get("by") or "analyst")
            at = _str_or_none(exec_p.get("at"))
            detail = _str_or_none(exec_p.get("detail"))
            # An "execution" that found the alert pre-acked reads as such, not
            # as if the analyst wrote anything.
            if exec_p.get("note") == "already_acknowledged":
                note = "Already acknowledged"
        elif tn == "ack_alert" and auto_acked:
            by, at = "auto-ack", ran_at
        elif applied:
            note = _ack_note(tn)
        pending_note = ack_pending_note if tn == "ack_alert" and not applied else None
        if tn == "ack_alert" and applied and alert_unacked:
            # The record says done and the grid says not done. The card follows
            # the grid, and names the earlier write so nothing is hidden.
            applied = False
            note = None
            pending_note = (
                _ACK_NOT_ON_GRID_GROUP
                if exec_p is not None and exec_p.get("group")
                else _ACK_NOT_ON_GRID
            )
        dis = (
            None if applied else (dismissed.get(_action_identity(a)) or dismissed.get(f"#idx:{i}"))
        )
        out.append(
            RecommendedActionOut(
                id=f"a{i}",
                title=_ACTION_TITLE.get(tn, tn or "Action"),
                tag=_ACTION_TAG.get(tn, "comment"),
                rationale=a.get("rationale", ""),
                applied=applied,
                appliedNote=note,
                pendingNote=pending_note,
                appliedBy=by,
                appliedAt=at,
                appliedDetail=detail,
                dismissed=dis is not None,
                dismissedBy=_str_or_none(dis.get("by")) if dis else None,
                dismissedAt=_str_or_none(dis.get("at")) if dis else None,
            )
        )
    return out


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


# Sanitizer categories (soc_ai.oracle.sanitize) in the order they are read out,
# singular and plural. Anything unrecognised falls back to the raw key, because a
# new category must not be able to silence the note.
_REDACTION_NOUNS: dict[str, tuple[str, str]] = {
    "IP": ("IP address", "IP addresses"),
    "HOST": ("hostname", "hostnames"),
    "USER": ("username", "usernames"),
    "EMAIL": ("email address", "email addresses"),
    "MAC": ("MAC address", "MAC addresses"),
}


def _join_phrases(parts: list[str]) -> str:
    """``[a]`` -> "a"; ``[a, b]`` -> "a and b"; ``[a, b, c]`` -> "a, b and c"."""
    if len(parts) == 1:
        return parts[0]
    return f"{', '.join(parts[:-1])} and {parts[-1]}"


def _redaction_note(redaction: object) -> str | None:
    """One sentence describing what the egress guard replaced, or None.

    The producer records per-category COUNTS — ``{"IP": 3, "HOST": 1}``, see
    :func:`soc_ai.oracle.sanitize.redaction_summary`, which never carries the
    values themselves. This field is a string on the wire and the console renders
    it as a sentence, so the counts are phrased here.

    Passing that dict through raw is what made every investigation whose Oracle
    run actually redacted something answer 500: pydantic rejected a dict for a
    ``str`` field and took the whole detail page down with it. An empty dict is
    falsy, so the bug only ever appeared once redaction had real work to do.

    Total by construction. This renders payloads written by arbitrarily old
    versions, and a page that cannot be opened is worse than a note that cannot
    be phrased — so every unexpected shape degrades to a usable answer rather
    than raising.
    """
    if not redaction:
        return None
    if isinstance(redaction, str):
        return redaction.strip() or None
    if isinstance(redaction, Mapping):
        parts: list[str] = []
        all_counted = True
        for key, count in redaction.items():
            if not isinstance(count, int) or isinstance(count, bool):
                all_counted = False
                continue
            if count <= 0:
                continue
            singular, plural = _REDACTION_NOUNS.get(
                str(key), (str(key).lower(), f"{str(key).lower()}s")
            )
            parts.append(f"{count} {singular if count == 1 else plural}")
        if parts:
            return f"{_join_phrases(parts)} redacted before the data went to the Oracle"
        # Nothing to name. Which of the two reasons matters: a summary that
        # counted and found zero ({"IP": 0}) means nothing was replaced, and
        # saying otherwise would tell every analyst their data went off-box
        # redacted when it did not. A summary we could not read is the other
        # case, and there silence would be the lie.
        return None if all_counted else "redacted before the data went to the Oracle"
    return "redacted before the data went to the Oracle"


def _build_oracle(events: list[Any]) -> OracleOut | None:
    """Scan event stream for oracle_escalation / oracle_adjudication and build OracleOut.

    Returns None when neither event kind is present (Oracle was not consulted).
    If only oracle_escalation exists (Oracle was called but errored before returning),
    the returned OracleOut has escalated=True but oracleVerdict=None.
    """
    esc_payload: dict[str, Any] | None = None
    adj_payload: dict[str, Any] | None = None
    for e in events:
        if e.kind == "oracle_escalation":
            esc_payload = e.payload or {}
        elif e.kind == "oracle_adjudication":
            adj_payload = e.payload or {}
    if esc_payload is None and adj_payload is None:
        return None

    reason = (esc_payload or {}).get("reason")
    local_verdict = (esc_payload or {}).get("local_verdict")
    local_confidence = (esc_payload or {}).get("local_confidence")
    oracle_verdict = (adj_payload or {}).get("oracle_verdict")
    oracle_confidence = (adj_payload or {}).get("oracle_confidence")
    oracle_model = (adj_payload or {}).get("oracle_model")
    redaction = (adj_payload or {}).get("redaction")
    redaction_note = _redaction_note(redaction)
    redacted = redaction_note is not None
    changed = bool(oracle_verdict and local_verdict and oracle_verdict != local_verdict)
    withheld = bool((adj_payload or {}).get("override_withheld"))
    return OracleOut(
        escalated=True,
        reason=reason,
        localVerdict=local_verdict,
        localConfidence=local_confidence,
        oracleVerdict=oracle_verdict,
        oracleConfidence=oracle_confidence,
        model=oracle_model,
        redacted=redacted,
        redactionNote=redaction_note,
        changed=changed,
        withheld=withheld,
    )


def _build_timeline(events: list[Any]) -> tuple[list[TimelineStepOut], int, int, bool]:
    """Build the analyst timeline (what + details + outcome per step) and the
    tool-call / pivot counts. tool_result events are merged into their tool_call."""
    result_by_call = {
        (e.payload or {}).get("tool_call_id"): (e.payload or {}).get("result")
        for e in events
        if e.kind == "tool_result"
    }
    timeline: list[TimelineStepOut] = []
    pivots = 0
    has_oracle = False
    last_dispatch: int | None = None
    for e in events:
        if e.kind in _TL_SKIP:
            continue
        p = e.payload or {}
        if e.kind == "targeted_tool_result" and last_dispatch is not None:
            # The answer to a follow-up check belongs on the check's own row.
            # A second row counted one tool call twice (P10).
            row = timeline[last_dispatch]
            outcome = timeline_labels.title_for(e.kind, p)
            row.detail = f"{row.detail}\nresult: {outcome}".strip()
            last_dispatch = None
            continue
        if e.kind.startswith("oracle"):
            has_oracle = True
        group = _tl_group(e.kind)
        # Phase-D targeted dispatches run REAL tools (run_targeted_investigation)
        # but are recorded as `targeted_dispatch`, not `tool_call` — count them so a
        # synth-first run that grounded its verdict on t_get_event_raw/t_query_events
        # isn't mis-badged "heuristic · no tools" with toolCalls 0 (F06).
        if e.kind == "targeted_dispatch":
            td_tool = str(p.get("tool_name", ""))
            if "query" in td_tool or "zeek" in td_tool or "pcap" in td_tool:
                pivots += 1
        if e.kind == "tool_call":
            tn = str(p.get("tool_name", ""))
            # `final_result` is pydantic-ai's structured-output pseudo-tool, not an
            # investigative call — it never lands a tool_result (so it read
            # "…: running…" forever) and the verdict it carries is already the
            # hero. Drop it from the analyst timeline (and the tool-call count).
            if tn == "final_result":
                continue
            if "query" in tn or "zeek" in tn or "pcap" in tn:
                pivots += 1
            # Write-actions (ack/escalate/comment) act on the verdict — file
            # them under Decision, not the investigative "Tool calls" section.
            if tn in _WRITE_TOOLS:
                group = "Decision"
            result = result_by_call.get(p.get("tool_call_id"))
            title, detail = _tool_step(tn, p.get("args") or {}, result)
        elif e.kind == "decision_template_match" and not p.get("skipped"):
            # A skipped step falls through to the shared labeler, which says
            # which skip it was. This branch is for a template that RAN.
            title = (
                f"Matched pattern: {_template_label(p.get('template_id'))}"
                if p.get("matched")
                else "No pattern matched: a full investigation ran"
            )
            detail = _detail_for(e.kind, p)
        elif (special := _special_step(e.kind, p)) is not None:
            title, detail = special
        else:
            title = timeline_labels.title_for(e.kind, p)
            detail = _detail_for(e.kind, p)
        if e.kind == "targeted_dispatch":
            last_dispatch = len(timeline)
        timeline.append(
            TimelineStepOut(id=f"e{e.sequence}", group=group, title=title, detail=detail)
        )
    # One count from one source: the rows the "Tool calls" section shows. A
    # separate tally drifted from the section (2 against 3 rows on prod, P10).
    tool_calls = sum(1 for step in timeline if step.group == "Tool calls")
    return timeline, tool_calls, pivots, has_oracle


def _chat_msg_out(m: Any) -> ChatMessageOut:
    """Serialize one chat row for the wire, shared by every chat surface.

    The proposal fields are gated on :data:`PROPOSAL_KINDS` so an ordinary answer
    can never arrive carrying a row id and a card — an analyst offered an
    "Apply this verdict" button on prose the agent never proposed.
    """
    meta = (m.meta or {}) if isinstance(m.meta, dict) else {}
    tools = ", ".join(meta.get("tools", [])) if meta.get("tools") else None
    is_prop = meta.get("kind") in PROPOSAL_KINDS
    return ChatMessageOut(
        role=m.role,
        # Scrubbed on read as well as on store: rows from before the store-side
        # scrub can still quote a credential from telemetry.
        text=scrub_secrets(m.content) if isinstance(m.content, str) else m.content,
        tools=tools,
        messageId=m.id if is_prop else None,
        kind=meta.get("kind") if is_prop else None,
        validation=meta.get("validation") if is_prop else None,
        objection=meta.get("objection") if is_prop else None,
        token=meta.get("token") if (is_prop and meta.get("validation") == "pass") else None,
        applied=bool(meta.get("applied")) if is_prop else None,
        proposal=meta.get("proposal") if is_prop else None,
    )
