"""Tests for the deterministic investigation-timeline label renderer.

Dogfood feedback (2026-07-04): tool-call titles must be short, human, and never
raw JSON; deliberate skips (zero-egress online tools) must read neutral + dim,
not like errors; only actual failures may read negative. The raw payload stays
in ``detail`` behind the expander — that's where machine data belongs.
"""

from __future__ import annotations

from typing import Any, get_args

import pytest
from soc_ai.audit.schemas import AuditKind
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


# --------------------------------------------------------------------------
# Dogfood: the observed bad-title classes, table-driven (payload → clean title)
# --------------------------------------------------------------------------

_ENRICHMENT_OFF = {
    "available": False,
    "reason": "online_enrichment_disabled",
    "hint": (
        "online enrichment is off (preserves zero-egress default) — set "
        "ALLOW_ONLINE_ENRICHMENT=true to enable these tools"
    ),
}

OBSERVED_BAD_CASES: list[tuple[str, dict[str, Any], str]] = [
    # 1. Host summary rendered raw JSON in the title.
    (
        "tool_result",
        {
            "tool_name": "t_host_summary",
            "result": {"ip": "198.51.100.24", "observations": True, "event_count": 699},
        },
        "Checked host summary — 198.51.100.24: 699 events",
    ),
    (
        "tool_result",
        {
            "tool_name": "t_host_summary",
            "result": {
                "ip": "198.51.100.9",
                "observations": False,
                "summary": "no observations for 198.51.100.9 in the lookback window",
            },
        },
        "Checked host summary — 198.51.100.9: no observations",
    ),
    # 2. Online tools off rendered the full config lecture like an error.
    (
        "tool_result",
        {"tool_name": "t_greynoise", "result": _ENRICHMENT_OFF},
        "GreyNoise: skipped (online enrichment off)",
    ),
    (
        "tool_result",
        {"tool_name": "t_shodan_internetdb", "result": _ENRICHMENT_OFF},
        "Shodan InternetDB: skipped (online enrichment off)",
    ),
    (
        "tool_result",
        {
            "tool_name": "t_shodan_host",
            "result": {
                "available": False,
                "reason": "not_configured",
                "hint": "set SHODAN_API_KEY in .env to enable this provider",
            },
        },
        "Shodan host details: skipped (not configured)",
    ),
    # 3. auto_ack fell through to the raw humanized kind ("auto ack").
    (
        "auto_ack",
        {"es_id": "abc123", "success": True, "confidence": 0.97, "threshold": 0.95},
        "Auto-acknowledged in Security Onion",
    ),
    (
        "auto_ack",
        {"es_id": "abc123", "success": False, "confidence": 0.97, "threshold": 0.95},
        "Auto-acknowledge failed",
    ),
    # 4. investigation_transcript fell through to the raw kind.
    ("investigation_transcript", {}, "Investigation notes compiled"),
    # 5. "Final synthesis: running…" leftover — final_result is the structured-
    #    output pseudo-tool; give it verdict-synthesis phrasing.
    ("tool_call", {"tool_name": "final_result", "args": {}}, "Synthesizing verdict…"),
    ("tool_result", {"tool_name": "final_result", "result": None}, "Verdict synthesized"),
]


@pytest.mark.parametrize(("kind", "payload", "expected"), OBSERVED_BAD_CASES)
def test_observed_bad_titles_now_clean(kind: str, payload: dict[str, Any], expected: str) -> None:
    title = title_for(kind, payload)
    assert title == expected
    assert "{" not in title and "}" not in title


def test_skipped_online_rows_are_dim_and_neutral() -> None:
    """A deliberate zero-egress skip is a neutral fact: dim row, no error tone."""
    ev = label_event("tool_result", {"tool_name": "t_greynoise", "result": _ENRICHMENT_OFF})
    assert ev["dim"] is True
    assert "skipped" in ev["title"]
    assert "failed" not in ev["title"].lower()
    assert "error" not in ev["title"].lower()
    # the config hint stays available behind the expander
    assert "ALLOW_ONLINE_ENRICHMENT" in ev["detail"]
    # a normal (non-skip) tool result is NOT dim
    ok = label_event("tool_result", {"tool_name": "t_query_events_oql", "result": {"total": 3}})
    assert ok["dim"] is False


def test_bookkeeping_rows_are_dim() -> None:
    for kind in ("usage", "model_response", "llm_request", "llm_response"):
        assert label_event(kind, {})["dim"] is True, kind


def test_error_results_read_negative_but_short() -> None:
    t = title_for(
        "tool_result",
        {"tool_name": "t_query_events_oql", "result": {"error": "timeout after 30s"}},
    )
    assert t == "Events failed: timeout after 30s"
    # nested/dict errors flatten to a phrase, never JSON
    t2 = title_for(
        "tool_result",
        {
            "tool_name": "t_query_events_oql",
            "result": {"error": {"type": "ConnectionError", "message": "boom"}},
        },
    )
    assert t2 == "Events failed: boom"
    assert "{" not in t2
    # multi-line tracebacks collapse to one short line
    trace = "Traceback (most recent call last):\n  File x.py\nTimeoutError: read timed out"
    t3 = title_for("tool_result", {"tool_name": "t_query_zeek_logs", "result": {"error": trace}})
    assert "\n" not in t3
    assert len(t3) <= 90
    assert t3.startswith("Zeek logs failed: ")


def test_zero_matches_is_neutral_not_negative() -> None:
    t = title_for("tool_result", {"tool_name": "t_query_events_oql", "result": {"total": 0}})
    assert t == "Checked events — 0 matches"
    assert "fail" not in t.lower()
    t2 = title_for("tool_result", {"tool_name": "t_web_search", "result": {"result_count": 0}})
    assert "0 results" in t2


def test_write_tool_phrasing() -> None:
    assert (
        title_for("tool_call", {"tool_name": "ack_alert", "args": {}})
        == "Acknowledging the alert in Security Onion…"
    )
    assert (
        title_for("tool_result", {"tool_name": "ack_alert", "result": {"success": True}})
        == "Alert acknowledged in Security Onion"
    )
    failed = title_for(
        "tool_result",
        {"tool_name": "ack_alert", "result": {"success": False, "message": "SO API 400"}},
    )
    assert failed == "Alert acknowledgement failed: SO API 400"
    assert (
        title_for("tool_result", {"tool_name": "escalate_to_case", "result": {"success": True}})
        == "Escalated to a Security Onion case"
    )


def test_unknown_dict_results_never_render_json() -> None:
    # nothing scalar worth surfacing → the title stands alone
    t = title_for(
        "tool_result",
        {"tool_name": "t_query_events_oql", "result": {"weird": {"nested": 1}, "flag": True}},
    )
    assert t == "Checked events"
    # at most a couple of scalar fields, verbatim-but-clipped
    t2 = title_for(
        "tool_result",
        {"tool_name": "t_describe_dataset", "result": {"dataset": "zeek.ssh", "fields": 42}},
    )
    assert "zeek.ssh" in t2
    assert "{" not in t2 and "}" not in t2


def test_titles_target_80_chars_for_common_rows() -> None:
    long_oql = "event.dataset:zeek.conn AND source.ip:198.51.100.24 AND destination.port:445 " * 3
    t = title_for("tool_call", {"tool_name": "t_query_events_oql", "args": {"oql": long_oql}})
    assert len(t) <= 80
    long_err = "read timed out connecting to elasticsearch at 198.51.100.253:9200 " * 4
    t2 = title_for(
        "tool_result", {"tool_name": "t_query_events_oql", "result": {"error": long_err}}
    )
    assert len(t2) <= 80


def test_downgrade_kinds_read_human_not_jargon() -> None:
    assert (
        title_for("evidence_gate_downgrade", {"verdict": "needs_more_info"})
        == "Confidence lowered: verdict not evidence-backed"
    )
    assert "ICMP" in title_for("icmp_solicited_downgrade", {})
    assert "evidence" in title_for("ungrounded_host_anchored_tp_downgrade", {})
    assert "malware rule name" in title_for("malware_rule_name_ungrounded_downgrade", {})
    t = title_for(
        "verdict_floor_rewrite",
        {"original_verdict": "true_positive", "capped_verdict": "needs_more_info"},
    )
    assert "needs more info" in t


def test_targeted_and_retask_kinds() -> None:
    t = title_for(
        "targeted_dispatch",
        {"question": "Was the DNS answer NXDOMAIN?", "tool_name": "t_query_events_oql"},
    )
    assert t == "Follow-up check: Was the DNS answer NXDOMAIN?"
    t2 = title_for(
        "targeted_tool_result", {"tool_name": "t_query_events_oql", "result": {"total": 3}}
    )
    assert t2 == "Follow-up: checked events — 3 matches"
    t3 = title_for("retask", {"gap_question": "Do other hosts resolve this domain?"})
    assert t3 == "Re-tasked: Do other hosts resolve this domain?"
    assert (
        title_for("retask_skipped_no_closeable_gap", {"reason": "x"})
        == "No re-task: no closeable evidence gap"
    )


def test_vote_oracle_and_fast_path_kinds() -> None:
    t = title_for(
        "self_consistency_vote",
        {
            "chosen_verdict": "false_positive",
            "samples": ["false_positive", "false_positive", "true_positive"],
            "tally": {"false_positive": 2, "true_positive": 1},
        },
    )
    assert t == "Verdict vote: false positive (3 samples)"
    assert "Oracle" in title_for("oracle_escalation", {})
    t2 = title_for(
        "oracle_adjudication", {"oracle_verdict": "false_positive", "oracle_confidence": 0.8}
    )
    assert t2 == "Oracle verdict: false positive (0.8)"
    assert "Fast path" in title_for("fast_path_escalation", {"reason": "external_ip"})
    assert "suspicious" in title_for("fast_path_verdict_cap", {"capped_verdict": "suspicious"})


def test_prior_outcomes_kind() -> None:
    """E4.2 memory recall: count plus a compact verdict tally, never JSON;
    count-only and empty payloads still read clean."""
    t = title_for(
        "prior_outcomes",
        {
            "count": 3,
            "window_days": 90,
            "items": [
                {"id": "01A", "verdict": "false_positive", "matched_on": "rule+src+dest"},
                {"id": "01B", "verdict": "false_positive", "matched_on": "rule+endpoint"},
                {"id": "01C", "verdict": "true_positive", "matched_on": "rule"},
            ],
        },
    )
    assert t == (
        "Recalled 3 prior outcome(s) for similar alerts — 2x false positive, 1x true positive"
    )
    assert title_for("prior_outcomes", {"count": 1}) == (
        "Recalled 1 prior outcome(s) for similar alerts"
    )
    assert "{" not in title_for("prior_outcomes", {})


# --------------------------------------------------------------------------
# Catch-all: every audit kind must yield a short, JSON-free, non-empty title
# --------------------------------------------------------------------------

_REPRESENTATIVE_PAYLOADS: dict[str, dict[str, Any]] = {
    "tool_call": {"tool_name": "t_query_events_oql", "args": {"oql": "event.dataset:zeek.conn"}},
    "tool_result": {
        "tool_name": "t_host_summary",
        "result": {"ip": "198.51.100.24", "observations": True, "event_count": 699},
    },
    "targeted_dispatch": {"question": "Was the reply solicited?", "tool_name": "t_get_pcap"},
    "targeted_tool_result": {"tool_name": "t_query_events_oql", "result": {"total": 3}},
    "triage_report": {"verdict": "false_positive", "confidence": 0.85},
    "classification": {"alert_class": "dns_dnssec_housekeeping", "fast_path_eligible": True},
    "decision_template_match": {"template_id": "clean_internal_traffic", "matched": True},
    "citation_cap": {"original_confidence": 0.9, "capped_confidence": 0.7},
    "template_ceiling": {"template_confidence": 0.8},
    "coverage_cap": {"original_confidence": 0.9, "capped_confidence": 0.6},
    "verdict_floor_rewrite": {"original_verdict": "true_positive", "capped_verdict": "suspicious"},
    "self_consistency_vote": {"chosen_verdict": "false_positive", "samples": 3},
    "recommended_actions_blocked": {"blocked_count": 2, "confidence": 0.4, "floor": 0.6},
    "retask": {"gap_question": "Do other hosts resolve this domain?"},
    "oracle_adjudication": {"oracle_verdict": "false_positive", "oracle_confidence": 0.8},
    "auto_ack": {"es_id": "abc", "success": True},
    "approval_request": {"tool_name": "ack_alert"},
    "approval_required": {"tool_name": "ack_alert"},
    "approval_decision": {"approved": True},
    "usage": {"phase": "synth", "round": 1, "tool_calls": 3},
    "prior_outcomes": {
        "count": 2,
        "window_days": 90,
        "items": [{"id": "01A", "verdict": "false_positive", "matched_on": "rule+src+dest"}],
    },
    "error": {"message": "boom"},
    "fast_path_verdict_cap": {"original_verdict": "true_positive", "capped_verdict": "suspicious"},
    "fast_path_evidence_guard": {"capped_verdict": "needs_more_info"},
}


@pytest.mark.parametrize("kind", sorted(get_args(AuditKind)))
def test_every_audit_kind_has_a_clean_title(kind: str) -> None:
    payload = _REPRESENTATIVE_PAYLOADS.get(kind, {})
    title = title_for(kind, payload)
    assert title, f"{kind} produced an empty title"
    assert len(title) <= 120, f"{kind} title too long: {title!r}"
    assert "{" not in title and "}" not in title, f"{kind} leaked JSON: {title!r}"
    # the full labeler must also succeed and keep the raw payload in detail
    ev = label_event(kind, payload)
    assert ev["title"] == title
    assert isinstance(ev["detail"], str)
