"""Investigation detail view-model builders (timeline / actions / oracle) shared across routes."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from pydantic import BaseModel

from soc_ai.config import Settings
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
    "citation_validation": "Validators",
    "citation_cap": "Validators",
    "error": "Validators",
    # A taken action (auto-ack on a high-confidence FP) is a verdict
    # consequence, not an investigative tool call — a "no tools" heuristic run
    # must not grow a "Tool calls" timeline section from its own auto-ack.
    "auto_ack": "Decision",
    # Proactive context budgeting happens during prefetch assembly.
    "context_trimmed": "Prefetch & pivots",
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
}
_PORT_PROTO = {21: "FTP", 22: "SSH", 53: "DNS", 80: "HTTP", 443: "TLS", 445: "SMB", 3389: "RDP"}
_ACTION_TITLE = {
    "ack_alert": "Acknowledge alert",
    "escalate_to_case": "Escalate to case",
    "add_case_comment": "Add case comment",
}
_ACTION_TAG = {"ack_alert": "ack", "escalate_to_case": "escalate", "add_case_comment": "comment"}


def _tl_group(kind: str) -> str:
    if kind.startswith("oracle"):
        return "Oracle"
    return _TL_GROUP.get(kind, "Tool calls")


def _compact(obj: Any, limit: int = 160) -> str:
    s = obj if isinstance(obj, str) else json.dumps(obj, default=str, ensure_ascii=False)
    return s if len(s) <= limit else s[: limit - 1] + "…"


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
    src_node: dict[str, Any] = {
        "id": str(src),
        "x": 20,
        "y": 50,
        "kind": "compromised" if inv.verdict == "true_positive" else "host",
        "label": str(label or src),
        "sub": "source · internal" if src_enr.get("internal") else "source",
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
    note = f"{label or src} contacted {n} peer(s)" + (
        f"; {len(flagged_names)} flagged malicious by enrichment"
        f" ({_compact(', '.join(flagged_names), 60)})"
        if flagged_names
        else ""
    )
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
        return "running…"
    if isinstance(result, list):
        return "no results" if not result else f"{len(result)} result(s)"
    if isinstance(result, str):
        return _compact(result, 80)
    if not isinstance(result, dict):
        return _compact(result, 80)
    # An online tool that short-circuited (online enrichment off / no API key):
    # a neutral "skipped" outcome, NOT the multi-line config lecture the tool
    # returns for the model to read (that stays in the expander).
    if result.get("available") is False:
        reason = str(result.get("reason") or "")
        if "not_configured" in reason:
            return "skipped (not configured)"
        return "skipped (online enrichment off)"
    # A tool error — a short, distinct failure phrase, never a JSON/traceback dump.
    if result.get("error"):
        msg = result.get("message") or result.get("error")
        if not isinstance(msg, str):
            return "failed: error"
        # Query errors often already read as failures ("failed to parse
        # filter…") — prefixing again would stutter "failed: failed to…".
        if msg.lstrip().lower().startswith(("failed", "error", "could not", "cannot", "unable")):
            return _compact(msg, 80)
        return "failed: " + _compact(msg, 60)
    # Host summary: "<ip> — 699 events", not the raw {ip, event_count} dict.
    if "event_count" in result and ("ip" in result or "host" in result):
        who = result.get("ip") or result.get("host")
        if not result.get("observations", True):
            return f"{who} — no observations"
        n = result.get("event_count")
        return f"{who} — {n} events"
    # enrichment result
    if {"blocklist_hits", "misp_hits", "indicator"} & set(result):
        bl = result.get("blocklist_hits") or []
        misp = result.get("misp_hits") or []
        if bl or misp:
            srcs = [str(h["source"]) for h in bl if isinstance(h, dict) and h.get("source")]
            return "flagged malicious" + (f" ({', '.join(srcs)})" if srcs else "")
        # A miss is a COVERAGE statement, not a verdict — say so precisely.
        return "internal address" if result.get("internal") else "no blocklist/MISP match"
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
            return _compact(val, 120)
    # No known field — a bare, human outcome rather than a JSON dump of the dict
    # (machines read the full JSON in the row expander; humans read this line).
    return "done"


def _tool_step(tool_name: str, args: dict[str, Any], result: Any) -> tuple[str, str]:
    """Title carries the point (tool + a short outcome); detail (shown on expand)
    carries the FULL headline result first, then the query and any enrichment chips.

    The collapsed title is necessarily clipped, so the expanded row is where the
    analyst reads the whole answer — never just the arguments (the old behaviour).
    """
    noun = _TOOL_NOUN.get(tool_name, _humanize_id(tool_name).capitalize())
    title = f"{noun}: {_tool_outcome(result)}"

    lines: list[str] = []
    headline_key: str | None = None
    if isinstance(result, dict):
        # The full answer first — generously capped (the title was the clipped one).
        for k in ("summary", "verdict", "status", "note", "hint"):
            if result.get(k):
                headline_key = k
                lines.append(f"result: {_compact(result[k], 600)}")
                break
    lines.append(f"query: {_compact(args, 200)}" if args else "no arguments")
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
            extra.append(_compact(result["hint"], 120))
        if extra:
            lines.append(" · ".join(extra))
    return title, "\n".join(lines)


def _detail_for(kind: str, p: dict[str, Any] | None, result: Any = None) -> str:
    """A human-readable details+outcome line per event (vs a raw JSON dump)."""
    p = p or {}
    if kind in ("enriched_alert_context", "alert_context"):
        enr = p.get("enrichments") or {}
        prof = p.get("host_alert_profile") or {}
        return (
            f"Loaded the alert and enriched {len(enr)} indicator(s); the host shows "
            f"{len(prof)} distinct alert type(s) in the window."
        )
    if kind == "decision_template_match":
        if p.get("matched"):
            return (
                f"Matched the '{_template_label(p.get('template_id'))}' pattern → "
                f"{p.get('verdict')} ({p.get('confidence')}). {p.get('rationale', '')}".strip()
            )
        return "No pattern matched — ran a full tool-using investigation."
    if kind == "investigation_loop_entered":
        return (
            f"{p.get('reason', '')} (round-1 was {p.get('round1_verdict')} @ "
            f"{p.get('round1_confidence')})".strip()
        )
    if kind == "triage_report":
        return f"{p.get('verdict')} ({p.get('confidence')})\n{_compact(p.get('summary', ''), 300)}"
    if kind == "citation_validation":
        c = p.get("counts") or {}
        valid, total, cov = c.get("valid", "?"), p.get("total", "?"), p.get("coverage_ratio")
        return f"{valid}/{total} citations valid (coverage {cov})"
    if kind == "citation_cap":
        return (
            f"confidence {p.get('original_confidence')} → {p.get('capped_confidence')} "
            "to respect citation coverage"
        )
    if kind == "investigation_transcript":
        ev = p.get("evidence") or []
        return f"{p.get('tentative_summary', '')}\nevidence gathered: {len(ev)} item(s)".strip()
    if kind == "error":
        return _compact(p.get("message") or p.get("error") or "", 240)
    if kind == "session_start":
        return f"pipeline: {p.get('pipeline', '?')}"
    if kind == "context_trimmed":
        return _compact(p.get("detail") or "", 300)
    return _compact(p, 220)


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


class TimelineStepOut(BaseModel):
    id: str
    group: str
    title: str
    time: str = ""
    detail: str = ""


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


class InvestigationOut(BaseModel):
    id: str
    groupId: str
    name: str
    kind: str
    host: str
    ip: str
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
    openQuestions: list[str] = []
    resolution: dict[str, Any] | None = None
    validatorNote: str | None = None
    # Pipeline-failure fallback provenance (E1.2). Present ONLY when the run's
    # report is a synth-failure fallback (`is_pipeline_fallback`) — the drawer
    # then renders "this run failed before reaching a verdict: <hint>" + a Re-run
    # button instead of treating it as a genuine needs_more_info. Distinct from
    # `resolution` (manual/chat override) so the two never conflate.
    fallback: FallbackOut | None = None
    # Ordered model reasoning traces (the <think> blocks) captured per model turn.
    # Surfaced so an analyst can see WHY a verdict was reached — the "show your
    # work" explainability the timeline (which skips model_response) drops.
    reasoning: list[str] = []
    # Live acked state of the investigation's alert in Security Onion — covers
    # acks performed OUTSIDE this run (group-ack, another run's auto-ack, the SO
    # web UI) so the UI never offers "Acknowledge" for an already-acked alert.
    # False on any ES error (resilient: the page must never break on this).
    alertAcked: bool = False


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
            out.append(trace.strip())
    return out


async def _alert_currently_acked(
    elastic: ElasticClient, settings: Settings, alert_es_id: str | None
) -> bool:
    """Live ``event.acknowledged`` state of one alert in the SO index.

    Same ``ids`` lookup shape as :func:`resolve_alert_for_hunt`, reading the
    same ``event.acknowledged`` field the alerts list aggregates on
    (``soc_ai.webui.alerts_query``). Covers acks performed OUTSIDE this
    investigation (group-ack, another run's auto-ack, the SO web UI).
    Resilient by design: any ES error/miss returns False so the detail page
    falls back to current behavior (offer the action) instead of breaking.
    """
    if not alert_es_id:
        return False
    try:
        lookup = await elastic.search(
            settings.events_index_pattern,
            {"ids": {"values": [alert_es_id]}},
            size=1,
            source=["event.acknowledged"],
        )
        if not lookup.hits:
            return False
        source = lookup.hits[0].get("_source", {})
        return bool(get_dotted(source, "event.acknowledged"))
    except Exception:  # never break the detail page on an acked-state probe
        return False


def _executed_actions(events: list[Any]) -> dict[int, dict[str, Any]]:
    """index -> payload of persisted successful advisory-action executions.

    ``POST .../actions/{index}/execute`` writes an ``action_executed`` event on
    success (FR-030); reading it back here means a reload never re-offers an
    already-executed escalate (duplicate SO cases) or ack.
    """
    out: dict[int, dict[str, Any]] = {}
    for e in events:
        if e.kind != "action_executed":
            continue
        p = e.payload or {}
        if not p.get("success"):
            continue
        idx = p.get("index")
        if isinstance(idx, int):
            out[idx] = p
    return out


def _build_actions(
    events: list[Any],
    report: dict[str, Any],
    *,
    alert_acked: bool = False,
) -> list[RecommendedActionOut]:
    """Recommended actions from historical approval events or report recommendations.

    An ack action already carried out by auto-ack is flagged ``applied`` so the UI
    never offers an "Acknowledge" button for an alert the system already acked.
    ``alert_acked`` (the alert's LIVE acked state in ES) and persisted
    ``action_executed`` events extend the same applied concept to acks performed
    outside this run and to analyst-executed advisory actions (FR-030).
    """
    # Auto-ack fired successfully? Then any ack action is already done.
    auto_acked = any(e.kind == "auto_ack" and (e.payload or {}).get("success") for e in events)
    executed = _executed_actions(events)

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
        exec_p = executed.get(i)
        applied = exec_p is not None or ((auto_acked or alert_acked) and tn == "ack_alert")
        note: str | None = None
        if exec_p is not None:
            # An "execution" that found the alert pre-acked reads as such, not
            # as if the analyst wrote anything.
            if exec_p.get("note") == "already_acknowledged":
                note = "Already acknowledged"
            else:
                note = f"Executed · {exec_p.get('by') or 'analyst'}"
        elif applied:
            note = _ack_note(tn)
        out.append(
            RecommendedActionOut(
                id=f"a{i}",
                title=_ACTION_TITLE.get(tn, tn or "Action"),
                tag=_ACTION_TAG.get(tn, "comment"),
                rationale=a.get("rationale", ""),
                applied=applied,
                appliedNote=note,
            )
        )
    return out


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
    redacted = bool(redaction)
    redaction_note = redaction if redacted else None
    changed = bool(oracle_verdict and local_verdict and oracle_verdict != local_verdict)
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
    tool_calls = pivots = 0
    has_oracle = False
    for e in events:
        if e.kind in _TL_SKIP:
            continue
        p = e.payload or {}
        if e.kind.startswith("oracle"):
            has_oracle = True
        group = _tl_group(e.kind)
        if e.kind == "tool_call":
            tn = str(p.get("tool_name", ""))
            # `final_result` is pydantic-ai's structured-output pseudo-tool, not an
            # investigative call — it never lands a tool_result (so it read
            # "…: running…" forever) and the verdict it carries is already the
            # hero. Drop it from the analyst timeline (and the tool-call count).
            if tn == "final_result":
                continue
            tool_calls += 1
            if "query" in tn or "zeek" in tn or "pcap" in tn:
                pivots += 1
            # Write-actions (ack/escalate/comment) act on the verdict — file
            # them under Decision, not the investigative "Tool calls" section.
            if tn in _WRITE_TOOLS:
                group = "Decision"
            result = result_by_call.get(p.get("tool_call_id"))
            title, detail = _tool_step(tn, p.get("args") or {}, result)
        elif e.kind == "decision_template_match":
            title = (
                f"Matched pattern: {_template_label(p.get('template_id'))}"
                if p.get("matched")
                else "No pattern matched — ran a full investigation"
            )
            detail = _detail_for(e.kind, p)
        else:
            title = timeline_labels.title_for(e.kind, p)
            detail = _detail_for(e.kind, p)
        timeline.append(
            TimelineStepOut(id=f"e{e.sequence}", group=group, title=title, detail=detail)
        )
    return timeline, tool_calls, pivots, has_oracle


def _chat_msg_out(m: Any) -> ChatMessageOut:
    meta = (m.meta or {}) if isinstance(m.meta, dict) else {}
    tools = ", ".join(meta.get("tools", [])) if meta.get("tools") else None
    is_prop = meta.get("kind") == "verdict_proposal"
    return ChatMessageOut(
        role=m.role,
        text=m.content,
        tools=tools,
        messageId=m.id if is_prop else None,
        kind=meta.get("kind") if is_prop else None,
        validation=meta.get("validation") if is_prop else None,
        objection=meta.get("objection") if is_prop else None,
        token=meta.get("token") if (is_prop and meta.get("validation") == "pass") else None,
        applied=bool(meta.get("applied")) if is_prop else None,
        proposal=meta.get("proposal") if is_prop else None,
    )
