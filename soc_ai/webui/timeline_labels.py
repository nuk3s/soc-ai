"""Human-readable labels for the investigation activity timeline.

Deterministic mapping from an investigation event (kind + payload) to a short
title an operator can read at a glance; the raw JSON stays available behind a
per-row expander. No LLM — labels must be instant and never hallucinate. JSON is
fine for the record (the ``detail`` field), NEVER for the title: humans don't
read JSON, machines do. Titles target ≤ ~80 chars; anything longer belongs in
the expander.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

_TITLE_MAX = 120  # hard ceiling; individual phrases are capped well below this

# What each tool "checks", for "Checking X…" / "Checked X" phrasing. Keys are
# bare tool names (any leading ``t_`` is stripped first). Cover every registered
# tool (soc_ai.tools) so the _humanize fallthrough is rare.
_TOOL_NOUN: dict[str, str] = {
    "get_alert_context": "alert context",
    "query_events": "events",
    "query_events_oql": "events",
    "query_zeek_logs": "Zeek logs",
    "query_cases": "past cases",
    "query_detections": "detection rules",
    "get_playbooks": "playbooks",
    "lookup_runbook": "the runbook",
    "enrich_domain": "domain reputation",
    "enrich_hash": "file-hash reputation",
    "enrich_ip": "IP reputation",
    "get_pcap": "packet capture",
    "web_search": "the web",
    "crawl_page": "the web page",
    "host_summary": "host summary",
    "prevalence": "indicator prevalence",
    "rule_prevalence": "rule prevalence",
    "suggest_rule_tuning": "rule-tuning options",
    "greynoise": "GreyNoise",
    "shodan_internetdb": "Shodan InternetDB",
    "shodan_host": "Shodan host details",
    "cve_lookup": "CVE details",
    "describe_dataset": "dataset fields",
    "field_values": "field values",
    "get_event_raw": "the raw event",
    "ack_alert": "alert acknowledgement",
    "escalate_to_case": "case escalation",
    "add_case_comment": "case comment",
}

# Write tools read badly as "Checking case escalation…" — give them real verbs.
# bare name → (in-progress title, completed title)
_WRITE_TOOL_PHRASES: dict[str, tuple[str, str]] = {
    "ack_alert": (
        "Acknowledging the alert in Security Onion…",
        "Alert acknowledged in Security Onion",
    ),
    "escalate_to_case": (
        "Escalating to a Security Onion case…",
        "Escalated to a Security Onion case",
    ),
    "add_case_comment": ("Adding a case comment…", "Case comment added"),
}

_ICON: dict[str, str] = {
    "session_start": "▶",
    "session_end": "🏁",
    "enriched_alert_context": "📎",
    "alert_context": "📎",
    "classification": "🏷",
    "investigation_loop_entered": "🔎",
    "tool_call": "🔧",
    "tool_result": "📥",
    "targeted_dispatch": "🎯",
    "targeted_tool_result": "📥",
    "model_response": "🧠",
    "decision_template_match": "🧩",
    "prior_outcomes": "📚",
    "chat_memory": "💬",
    "citation_validation": "✅",
    "citation_cap": "📉",
    "coverage_cap": "📉",
    "template_ceiling": "📐",
    "rubric_derivation": "📐",
    "verdict_floor_rewrite": "📉",
    "evidence_gate_downgrade": "📉",
    "ungrounded_host_anchored_tp_downgrade": "📉",
    "malware_rule_name_ungrounded_downgrade": "📉",
    "icmp_solicited_downgrade": "📉",
    "fast_path_escalation": "⚡",
    "fast_path_evidence_guard": "⚡",
    "fast_path_verdict_cap": "⚡",
    "self_consistency_vote": "🗳",
    "recommended_actions_blocked": "🚫",
    "retask": "🎯",
    "retask_skipped_no_closeable_gap": "·",
    "oracle_escalation": "🔮",
    "oracle_adjudication": "🔮",
    "investigation_transcript": "📝",
    "auto_ack": "☑",
    "triage_report": "📋",
    "approval_request": "⏸",
    "approval_required": "⏸",
    "approval_decision": "⏯",
    "done": "🏁",
    "error": "✗",
    "usage": "·",
    "llm_request": "·",
    "llm_response": "·",
}

# Bookkeeping rows the analyst rarely needs — rendered dim.
_DIM_KINDS = frozenset({"usage", "model_response", "llm_request", "llm_response"})

_ACRONYMS = {
    "asn": "ASN",
    "sni": "SNI",
    "c2": "C2",
    "dns": "DNS",
    "ssl": "SSL",
    "http": "HTTP",
    "tls": "TLS",
    "ip": "IP",
    "smb": "SMB",
    "rdp": "RDP",
    "url": "URL",
    "icmp": "ICMP",
    "oql": "OQL",
    "cve": "CVE",
}


def _strip_t(name: str) -> str:
    return name[2:] if name.startswith("t_") else name


def _humanize(token: str | None) -> str:
    if not token:  # None or "" — e.g. a decision_template_match with no match
        return ""
    parts = token.replace("-", "_").split("_")
    return " ".join(_ACRONYMS.get(p.lower(), p) for p in parts if p)


def _tool_noun(name: str) -> str:
    bare = _strip_t(name)
    return _TOOL_NOUN.get(bare, _humanize(bare))


def _tool_label(name: str) -> str:
    """A display label for the tool, for '<Label>: skipped' / '<Label> failed'."""
    noun = _tool_noun(name) or "tool"
    noun = noun.removeprefix("the ")
    return noun if noun[:1].isupper() else noun[:1].upper() + noun[1:]


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _phrase(v: Any, n: int = 60) -> str:
    """Coerce ANY value to a short, single-line, human phrase — never JSON.

    Dicts pick their most message-like field; lists pick their first element;
    strings are whitespace-collapsed (tracebacks become one line) and stripped
    of braces so machine payloads can never leak into a title.
    """
    if v is None:
        return ""
    if isinstance(v, str):
        s = " ".join(v.replace("{", " ").replace("}", " ").split())
        return _clip(s, n)
    if isinstance(v, bool):
        return str(v).lower()
    if isinstance(v, int | float):
        return str(v)
    if isinstance(v, dict):
        for key in ("message", "error", "reason", "detail", "summary", "hint"):
            if v.get(key):
                return _phrase(v[key], n)
        for val in v.values():
            if isinstance(val, str | int | float) and not isinstance(val, bool) and val != "":
                return _phrase(val, n)
        return "see details"
    if isinstance(v, list):
        return _phrase(v[0], n) if v else ""
    return _phrase(str(v), n)


def _call_hint(args: Any) -> str:
    """A short parenthetical describing the key tool arg(s)."""
    if not isinstance(args, dict):
        return ""
    for key in ("log_types", "oql", "query", "domain", "url", "hash", "ip", "sni"):
        val = args.get(key)
        if val:
            if isinstance(val, list):
                val = ", ".join(str(x) for x in val)
            return f" ({_phrase(val, 50)})"
    return ""


def _skip_reason(result: Any) -> str | None:
    """Why an online tool was skipped (opt-in egress off / no key), else None.

    Matches the clean not-available dicts from soc_ai.tools.online — these are
    deliberate zero-egress defaults, NOT errors, and must render as neutral,
    dim rows rather than config lectures or failures.
    """
    if isinstance(result, str) and "enrichment is off" in result:
        return "online enrichment off"
    if not isinstance(result, dict) or result.get("available") is not False:
        return None
    reason = str(result.get("reason") or "")
    if reason == "online_enrichment_disabled":
        return "online enrichment off"
    if reason == "not_configured":
        return "not configured"
    return _humanize(reason) or "unavailable"


def _error_phrase(result: Any) -> str | None:
    """A short failure phrase if the tool result is an actual error, else None."""
    if isinstance(result, dict):
        if result.get("error"):
            return _phrase(result["error"], 60)
        if result.get("success") is False:
            return _phrase(result.get("message") or result.get("reason"), 60) or "unsuccessful"
    return None


# Display units for count-ish result keys ("699 events", "0 matches", …).
_COUNT_LABELS = {
    "packets": "packets",
    "total": "matches",
    "count": "results",
    "result_count": "results",
    "hits": "hits",
    "event_count": "events",
}


def _result_hint(result: Any) -> str:
    """A short suffix summarising a tool result. NEVER raw JSON — unknown dicts
    contribute at most a couple of scalar fields, or nothing at all (the title
    stands alone; the full payload lives in the expander)."""
    if isinstance(result, dict):
        # host_summary: {ip, observations, event_count, …}
        if "observations" in result and result.get("ip"):
            ip = result["ip"]
            if not result.get("observations"):
                return f" — {ip}: no observations"
            n = result.get("event_count")
            return f" — {ip}: {n} events" if isinstance(n, int) else f" — {ip}"
        for key, unit in _COUNT_LABELS.items():
            v = result.get(key)
            if isinstance(v, int) and not isinstance(v, bool):
                return f" — {v} {unit}"
        for key in ("classification", "sni", "summary", "verdict", "status", "note"):
            v = result.get(key)
            if isinstance(v, str) and v:
                return f" — {_phrase(v, 50)}"
        if result.get("error"):
            return f" — failed: {_phrase(result['error'], 50)}"
        # Unknown dict: surface up to two scalar fields, verbatim-but-clipped.
        bits: list[str] = []
        for k, v in result.items():
            if isinstance(v, bool) or k in ("available", "reason", "hint"):
                continue
            if isinstance(v, int | float):
                bits.append(f"{_humanize(k)} {v}")
            elif isinstance(v, str) and 0 < len(v) <= 40 and "{" not in v:
                bits.append(f"{_humanize(k)} {_phrase(v, 40)}")
            if len(bits) == 2:
                break
        return f" — {', '.join(bits)}" if bits else ""
    if isinstance(result, list):
        return " — no results" if not result else f" — {len(result)} result(s)"
    if isinstance(result, str) and result:
        return f" — {_phrase(result, 50)}"
    return ""


# --------------------------------------------------------------------------
# Per-kind title builders
# --------------------------------------------------------------------------


def _tool_call_title(p: dict[str, Any]) -> str:
    name = str(p.get("tool_name") or p.get("name") or "tool")
    bare = _strip_t(name)
    if bare == "final_result":  # pydantic-ai structured-output "tool"
        return "Synthesizing verdict…"
    if bare in _WRITE_TOOL_PHRASES:
        return _WRITE_TOOL_PHRASES[bare][0]
    return f"Checking {_tool_noun(name)}…{_call_hint(p.get('args'))}"


def _tool_result_title(p: dict[str, Any]) -> str:
    name = str(p.get("tool_name") or p.get("name") or "tool")
    bare = _strip_t(name)
    result = p.get("result")
    if bare == "final_result":
        return "Verdict synthesized"
    skip = _skip_reason(result)
    if skip is not None:  # neutral, not an error: "GreyNoise: skipped (…)"
        return f"{_tool_label(name)}: skipped ({skip})"
    err = _error_phrase(result)
    if err is not None:
        return f"{_tool_label(name)} failed: {err}"
    if bare in _WRITE_TOOL_PHRASES:
        return _WRITE_TOOL_PHRASES[bare][1]
    return f"Checked {_tool_noun(name)}{_result_hint(result)}"


def _t_classification(p: dict[str, Any]) -> str:
    cls = _humanize(p.get("alert_class"))
    return f"Classified alert: {cls}" if cls else "Alert classified"


def _t_targeted_dispatch(p: dict[str, Any]) -> str:
    q = p.get("question")
    if q:
        return f"Follow-up check: {_phrase(q, 60)}"
    tool = p.get("tool_name")
    if tool:
        return f"Follow-up check via {_tool_noun(str(tool))}"
    return "Follow-up check dispatched"


def _t_targeted_tool_result(p: dict[str, Any]) -> str:
    base = _tool_result_title(p)
    return f"Follow-up: {base[:1].lower()}{base[1:]}" if base else "Follow-up result"


def _t_retask(p: dict[str, Any]) -> str:
    q = p.get("gap_question")
    return f"Re-tasked: {_phrase(q, 60)}" if q else "Re-tasked the agent to close an evidence gap"


def _t_template_match(p: dict[str, Any]) -> str:
    tid = p.get("template_id")
    return f"Matched pattern: {_humanize(tid)}" if tid else "No decision-template match"


def _t_prior_outcomes(p: dict[str, Any]) -> str:
    """E4.2 memory recall — count plus a compact verdict tally, never JSON."""
    n = p.get("count")
    base = (
        f"Recalled {n} prior outcome(s) for similar alerts"
        if isinstance(n, int)
        else "Recalled prior outcomes for similar alerts"
    )
    items = p.get("items")
    if isinstance(items, list) and items:
        tally: dict[str, int] = {}
        for it in items:
            v = _humanize(it.get("verdict")) if isinstance(it, dict) else ""
            if v:
                tally[v] = tally.get(v, 0) + 1
        if tally:
            chips = ", ".join(
                f"{c}x {v}" for v, c in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))
            )
            return f"{base} — {chips}"
    return base


def _t_chat_memory(p: dict[str, Any]) -> str:
    """Chat-transcript memory recall — count plus a compact source tally.

    Mirrors :func:`_t_prior_outcomes`; the "(context only)" suffix keeps the
    operator's hard rule visible right in the timeline row: nothing recalled
    from a chat can ground the verdict.
    """
    n = p.get("count")
    base = (
        f"Recalled {n} past discussion excerpt(s)"
        if isinstance(n, int)
        else "Recalled past discussion excerpts"
    )
    items = p.get("items")
    if isinstance(items, list) and items:
        tally: dict[str, int] = {}
        for it in items:
            s = _humanize(it.get("source")) if isinstance(it, dict) else ""
            if s:
                tally[s] = tally.get(s, 0) + 1
        if tally:
            chips = ", ".join(
                f"{c}x {s}" for s, c in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))
            )
            return f"{base} ({chips}) — context only"
    return f"{base} — context only"


def _t_citation_validation(p: dict[str, Any]) -> str:
    valid = (p.get("counts") or {}).get("valid")
    return "Validated evidence citations" + (f" — {valid} valid" if valid is not None else "")


def _t_citation_cap(p: dict[str, Any]) -> str:
    return (
        "Adjusted confidence for citation coverage "
        f"({p.get('original_confidence')}→{p.get('capped_confidence')})"
    )


def _t_template_ceiling(p: dict[str, Any]) -> str:
    return f"Capped confidence to pattern ceiling ({p.get('template_confidence')})"


def _t_coverage_cap(p: dict[str, Any]) -> str:
    o, c = p.get("original_confidence"), p.get("capped_confidence")
    span = f" ({o}→{c})" if o is not None and c is not None else ""
    return f"Confidence capped{span}: evidence coverage incomplete"


def _t_verdict_floor(p: dict[str, Any]) -> str:
    cv = _humanize(p.get("capped_verdict"))
    if cv:
        return f"Verdict adjusted to {cv}: confidence below evidence floor"
    return "Verdict adjusted: confidence below evidence floor"


def _t_fast_path_guard(p: dict[str, Any]) -> str:
    cv = _humanize(p.get("capped_verdict"))
    if cv:
        return f"Fast-path verdict held at {cv}: needs corroborating evidence"
    return "Fast-path verdict held: needs corroborating evidence"


def _t_fast_path_cap(p: dict[str, Any]) -> str:
    cv = _humanize(p.get("capped_verdict"))
    return f"Fast-path verdict capped at {cv}" if cv else "Fast-path verdict capped"


def _t_vote(p: dict[str, Any]) -> str:
    chosen = _humanize(p.get("chosen_verdict"))
    samples = p.get("samples")
    if isinstance(samples, list):
        n: int | None = len(samples)
    elif isinstance(samples, int):
        n = samples
    else:
        n = None
    suffix = f" ({n} samples)" if n else ""
    return f"Verdict vote: {chosen}{suffix}" if chosen else f"Verdict consistency vote{suffix}"


def _t_actions_blocked(p: dict[str, Any]) -> str:
    n = p.get("blocked_count")
    if isinstance(n, int):
        return f"Withheld {n} recommended action(s): confidence below floor"
    return "Recommended actions withheld: confidence below floor"


def _t_oracle_adjudication(p: dict[str, Any]) -> str:
    v = _humanize(p.get("oracle_verdict"))
    conf = p.get("oracle_confidence")
    suffix = f" ({conf})" if conf is not None else ""
    return f"Oracle verdict: {v}{suffix}" if v else f"Oracle adjudicated{suffix}"


def _t_auto_ack(p: dict[str, Any]) -> str:
    if p.get("success") is False:
        return "Auto-acknowledge failed"
    return "Auto-acknowledged in Security Onion"


def _t_triage_report(p: dict[str, Any]) -> str:
    c = p.get("confidence")
    return f"Verdict: {_humanize(p.get('verdict') or '?')}" + (f" ({c})" if c is not None else "")


def _t_awaiting_approval(p: dict[str, Any]) -> str:
    return f"Awaiting approval: {p.get('tool_name', 'action')}"


def _t_approval_decision(p: dict[str, Any]) -> str:
    approved = p.get("approved")
    if approved is True:
        return "Approval granted"
    if approved is False:
        return "Approval declined"
    decision = p.get("decision") or p.get("status")
    if decision:
        return f"Approval decision: {_phrase(decision, 40)}"
    return "Approval decision recorded"


def _t_done(p: dict[str, Any]) -> str:
    n = p.get("recommended_count")
    return "Done" + (f" — {n} recommended action(s)" if n else "")


def _t_error(p: dict[str, Any]) -> str:
    return "Error: " + (_phrase(p.get("message") or p.get("error"), 90) or "see details")


def _t_usage(p: dict[str, Any]) -> str:
    return (
        f"Model call · {p.get('phase', '?')} round {p.get('round', '?')} "
        f"· {p.get('tool_calls', 0)} tools"
    )


# Kinds whose title never depends on the payload.
_STATIC_TITLES: dict[str, str] = {
    "session_start": "Investigation started",
    "session_end": "Investigation finished",
    "enriched_alert_context": "Loaded alert context + enrichments",
    "alert_context": "Loaded alert context + enrichments",
    "investigation_loop_entered": "Started a deeper investigation",
    "synth_round1_skipped": "Skipped first-pass synthesis — investigating first",
    "context_trimmed": "Trimmed oldest related events to fit the model's context window",
    "retask_skipped_no_closeable_gap": "No re-task: no closeable evidence gap",
    "rubric_derivation": "Derived the evidence checklist for this alert type",
    "evidence_gate_downgrade": "Confidence lowered: verdict not evidence-backed",
    "ungrounded_host_anchored_tp_downgrade": (
        "Verdict downgraded: host-based claim lacked supporting evidence"
    ),
    "malware_rule_name_ungrounded_downgrade": (
        "Confidence lowered: malware rule name not corroborated by evidence"
    ),
    "icmp_solicited_downgrade": "Verdict downgraded: ICMP replies were solicited (normal ping)",
    "fast_path_escalation": "Fast path escalated to a full investigation",
    "oracle_escalation": "Asked the Oracle for a second opinion",
    "investigation_transcript": "Investigation notes compiled",
    "model_response": "Model reasoning",
    "llm_request": "Model prompt sent",
    "llm_response": "Model response received",
}

# Kinds whose title is built from payload fields.
_DYNAMIC_TITLES: dict[str, Callable[[dict[str, Any]], str]] = {
    "classification": _t_classification,
    "tool_call": _tool_call_title,
    "tool_result": _tool_result_title,
    "targeted_dispatch": _t_targeted_dispatch,
    "targeted_tool_result": _t_targeted_tool_result,
    "retask": _t_retask,
    "decision_template_match": _t_template_match,
    "prior_outcomes": _t_prior_outcomes,
    "chat_memory": _t_chat_memory,
    "citation_validation": _t_citation_validation,
    "citation_cap": _t_citation_cap,
    "template_ceiling": _t_template_ceiling,
    "coverage_cap": _t_coverage_cap,
    "verdict_floor_rewrite": _t_verdict_floor,
    "fast_path_evidence_guard": _t_fast_path_guard,
    "fast_path_verdict_cap": _t_fast_path_cap,
    "self_consistency_vote": _t_vote,
    "recommended_actions_blocked": _t_actions_blocked,
    "oracle_adjudication": _t_oracle_adjudication,
    "auto_ack": _t_auto_ack,
    "triage_report": _t_triage_report,
    "approval_request": _t_awaiting_approval,
    "approval_required": _t_awaiting_approval,
    "approval_decision": _t_approval_decision,
    "done": _t_done,
    "error": _t_error,
    "usage": _t_usage,
}


def title_for(kind: str, p: dict[str, Any]) -> str:
    """The human title for one event. Short (target ≤ ~80 chars), never JSON."""
    static = _STATIC_TITLES.get(kind)
    if static is not None:
        return static
    build = _DYNAMIC_TITLES.get(kind)
    if build is not None:
        return _clip(build(p), _TITLE_MAX)
    return _humanize(kind)


def label_event(kind: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    """Map one event to ``{icon, title, detail(json), dim}`` for the timeline.

    ``dim`` marks rows the analyst can skim past: model/token bookkeeping, and
    online tools that were deliberately skipped (zero-egress default) — those
    are neutral facts, not signal, and must not read like errors.
    """
    p = payload or {}
    dim = kind in _DIM_KINDS or (
        kind in ("tool_result", "targeted_tool_result")
        and _skip_reason(p.get("result")) is not None
    )
    return {
        "icon": _ICON.get(kind, "•"),
        "title": title_for(kind, p),
        "detail": json.dumps(p, default=str, ensure_ascii=False, indent=2),
        "dim": dim,
    }
