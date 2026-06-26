"""Human-readable labels for the investigation activity timeline.

Deterministic mapping from an investigation event (kind + payload) to a short
title an operator can read at a glance; the raw JSON stays available behind a
per-row expander. No LLM — labels must be instant and never hallucinate. JSON is
fine for the record, not for the human reading the UI.
"""

from __future__ import annotations

import json
from typing import Any

# What each tool "checks", for "Checking X…" / "Checked X" phrasing. Keys are
# bare tool names (any leading ``t_`` is stripped first).
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
}

_ICON: dict[str, str] = {
    "session_start": "▶",
    "enriched_alert_context": "📎",
    "alert_context": "📎",
    "investigation_loop_entered": "🔎",
    "tool_call": "🔧",
    "tool_result": "📥",
    "model_response": "🧠",
    "decision_template_match": "🧩",
    "citation_validation": "✅",
    "citation_cap": "📉",
    "template_ceiling": "📐",
    "triage_report": "📋",
    "approval_request": "⏸",
    "approval_required": "⏸",
    "done": "🏁",
    "error": "✗",
    "usage": "·",
}

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


def _short(v: Any, n: int = 60) -> str:
    s = v if isinstance(v, str) else json.dumps(v, default=str, ensure_ascii=False)
    return s if len(s) <= n else s[: n - 1] + "…"


def _call_hint(args: Any) -> str:
    """A short parenthetical describing the key tool arg(s)."""
    if not isinstance(args, dict):
        return ""
    for key in ("log_types", "oql", "query", "domain", "url", "hash", "ip", "sni"):
        val = args.get(key)
        if val:
            if isinstance(val, list):
                val = ", ".join(str(x) for x in val)
            return f" ({_short(val, 50)})"
    return ""


def _result_hint(result: Any) -> str:
    """A short suffix summarising a tool result."""
    if isinstance(result, dict):
        for key in ("packets", "total", "count", "result_count", "hits"):
            if isinstance(result.get(key), int):
                return f" — {result[key]} {key.replace('result_', '').replace('_', ' ')}"
        for key in ("sni", "summary", "verdict", "error"):
            if result.get(key):
                return f" — {_short(result[key], 50)}"
    if isinstance(result, list):
        return f" — {len(result)} result(s)"
    return ""


def title_for(kind: str, p: dict[str, Any]) -> str:
    """The human title for one event."""
    if kind == "session_start":
        return "Investigation started"
    if kind in ("enriched_alert_context", "alert_context"):
        return "Loaded alert context + enrichments"
    if kind == "investigation_loop_entered":
        return "Started a deeper investigation"
    if kind == "tool_call":
        name = p.get("tool_name") or p.get("name") or "tool"
        return f"Checking {_tool_noun(name)}…{_call_hint(p.get('args'))}"
    if kind == "tool_result":
        name = p.get("tool_name") or p.get("name") or "tool"
        return f"Checked {_tool_noun(name)}{_result_hint(p.get('result'))}"
    if kind == "decision_template_match":
        tid = p.get("template_id")
        return f"Matched pattern: {_humanize(tid)}" if tid else "No decision-template match"
    if kind == "citation_validation":
        valid = (p.get("counts") or {}).get("valid")
        return "Validated evidence citations" + (f" — {valid} valid" if valid is not None else "")
    if kind == "citation_cap":
        return (
            "Adjusted confidence for citation coverage "
            f"({p.get('original_confidence')}→{p.get('capped_confidence')})"
        )
    if kind == "template_ceiling":
        return f"Capped confidence to pattern ceiling ({p.get('template_confidence')})"
    if kind == "triage_report":
        c = p.get("confidence")
        return f"Verdict: {_humanize(p.get('verdict') or '?')}" + (
            f" ({c})" if c is not None else ""
        )
    if kind in ("approval_request", "approval_required"):
        return f"Awaiting approval: {p.get('tool_name', 'action')}"
    if kind == "done":
        n = p.get("recommended_count")
        return "Done" + (f" — {n} recommended action(s)" if n else "")
    if kind == "error":
        return "Error: " + _short(p.get("message") or p.get("error") or "", 120)
    if kind == "usage":
        return (
            f"Model call · {p.get('phase', '?')} round {p.get('round', '?')} "
            f"· {p.get('tool_calls', 0)} tools"
        )
    if kind == "model_response":
        return "Model reasoning"
    return _humanize(kind)


def label_event(kind: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    """Map one event to ``{icon, title, detail(json), dim}`` for the timeline."""
    p = payload or {}
    return {
        "icon": _ICON.get(kind, "•"),
        "title": title_for(kind, p),
        "detail": json.dumps(p, default=str, ensure_ascii=False, indent=2),
        "dim": kind in ("usage", "model_response"),
    }
