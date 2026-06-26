"""Unit tests for ``soc_ai.cli`` event rendering.

The CLI is mostly a thin SSE-stream printer. We exercise ``_render_event``
directly with representative payloads to catch breakage when SSE event
shapes evolve (e.g. when ``investigation_transcript`` or ``retask`` were
added during the robustness pass).
"""

from __future__ import annotations

from soc_ai.cli import _render_event


def _strip_ansi(s: str) -> str:
    """Drop ANSI color escape sequences for stable assertions."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def test_render_session_start() -> None:
    out = _strip_ansi(_render_event("session_start", {"alert_id": "abc"}))
    assert "session_start" in out
    assert "abc" in out


def test_render_alert_context_summarizes_pivots() -> None:
    payload = {
        "alert": {
            "id": "abc",
            "rule_name": "ET DNS Query for X",
            "severity_label": "high",
            "network_community_id": "1:foo",
        },
        "pivot_summary": {"community_id": 4, "host": 0, "user": 0, "process": 0, "file": 0},
    }
    out = _strip_ansi(_render_event("alert_context", payload))
    assert "alert_context" in out
    assert "high" in out
    assert "ET DNS Query for X" in out
    assert "community_id:4" in out


def test_render_triage_report_with_actions() -> None:
    payload = {
        "verdict": "false_positive",
        "confidence": 0.85,
        "summary": "Internal DNS lookup; benign.",
        "citations": ["alert-001", "event-002"],
        "recommended_actions": [
            {
                "tool_name": "ack_alert",
                "tool_args": {"alert_id": "alert-001"},
                "rationale": "Alert is benign DHCP traffic; can be acknowledged.",
            }
        ],
    }
    out = _strip_ansi(_render_event("triage_report", payload))
    assert "triage_report" in out
    assert "FALSE_POSITIVE" in out
    assert "0.85" in out
    assert "Internal DNS lookup" in out
    assert "alert-001" in out
    assert "ack_alert" in out
    assert "benign DHCP traffic" in out


def test_render_error_includes_hint_when_present() -> None:
    payload = {
        "phase": "investigator",
        "round": 1,
        "type": "OqlValidationError",
        "message": "unknown or forbidden field: 'dest.ip'",
        "hint": "use destination.ip not dest.ip",
    }
    out = _strip_ansi(_render_event("error", payload))
    assert "error" in out
    assert "investigator" in out
    assert "round=1" in out
    assert "OqlValidationError" in out
    assert "dest.ip" in out
    assert "hint:" in out
    assert "destination.ip" in out


def test_render_error_omits_hint_section_when_absent() -> None:
    payload = {
        "phase": "synthesizer",
        "round": 1,
        "type": "RuntimeError",
        "message": "boom",
    }
    out = _strip_ansi(_render_event("error", payload))
    assert "synthesizer" in out
    assert "RuntimeError" in out
    assert "boom" in out
    assert "hint:" not in out


def test_render_retask_event() -> None:
    payload = {
        "reason": "synthesis_below_floor",
        "confidence": 0.3,
        "floor": 0.6,
        "open_questions": ["unenriched IP"],
    }
    out = _strip_ansi(_render_event("retask", payload))
    assert "retask" in out
    assert "synthesis_below_floor" in out
    assert "0.3" in out
    assert "0.6" in out


def test_render_investigation_transcript() -> None:
    payload = {
        "round": 1,
        "evidence": ["a", "b", "c"],
        "open_questions": ["x"],
        "tentative_summary": "DNS-style lookup, no action.",
    }
    out = _strip_ansi(_render_event("investigation_transcript", payload))
    assert "investigation_transcript" in out
    assert "round=1" in out
    assert "evidence=3" in out
    assert "open_questions=1" in out
    assert "DNS-style lookup" in out


def test_render_unknown_kind_falls_back_to_json_dump() -> None:
    out = _strip_ansi(_render_event("future_kind", {"hello": "world"}))
    assert "future_kind" in out
    assert "world" in out
