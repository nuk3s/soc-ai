"""Tests for the deterministic investigation-timeline label renderer."""

from __future__ import annotations

from soc_ai.webui.timeline_labels import label_event, title_for


def test_session_and_context() -> None:
    assert title_for("session_start", {}) == "Investigation started"
    assert "alert context" in title_for("enriched_alert_context", {})


def test_tool_call_and_result_humanized() -> None:
    t = title_for("tool_call", {"tool_name": "t_query_zeek_logs", "args": {"log_types": ["ssl"]}})
    assert t.startswith("Checking Zeek logs")
    assert "ssl" in t.lower()
    r = title_for("tool_result", {"tool_name": "t_get_pcap", "result": {"packets": 1240}})
    assert "packet capture" in r
    assert "1240" in r


def test_web_search_label() -> None:
    t = title_for(
        "tool_call",
        {"tool_name": "t_web_search", "args": {"query": "pushplanet.azurewebsites.net"}},
    )
    assert "the web" in t
    assert "pushplanet" in t


def test_template_match_and_verdict() -> None:
    tm = title_for("decision_template_match", {"template_id": "informational_external_unknown_asn"})
    assert "informational external" in tm.lower()
    assert "ASN" in tm  # acronym uppercased
    v = title_for("triage_report", {"verdict": "false_positive", "confidence": 0.7})
    assert "false positive" in v
    assert "0.7" in v


def test_label_event_shape() -> None:
    ev = label_event(
        "tool_call", {"tool_name": "query_events", "args": {"oql": "event.dataset:suricata.alert"}}
    )
    assert ev["icon"] == "🔧"
    assert ev["title"].startswith("Checking events")
    assert "oql" in ev["detail"]  # raw JSON retained behind the expander
    assert ev["dim"] is False
    assert label_event("usage", {"phase": "synthesizer", "round": 1})["dim"] is True


def test_unknown_kind_and_bad_payloads_never_raise() -> None:
    assert title_for("some_new_kind", {}) == "some new kind"
    assert label_event("tool_result", {"tool_name": "x", "result": None})["title"]
    assert label_event("error", {"message": "boom"})["title"] == "Error: boom"
    assert label_event("session_start", None)["title"] == "Investigation started"


def test_none_template_id_does_not_crash() -> None:
    """Regression: a decision_template_match with template_id=None (no template
    matched — common for malware rules) must not crash the labeler (it 500'd the
    investigation permalink)."""
    ev = label_event("decision_template_match", {"matched": False, "template_id": None})
    assert ev["title"] == "No decision-template match"
    # a None verdict must not crash either
    assert label_event("triage_report", {"verdict": None, "confidence": 0.9})["title"]
