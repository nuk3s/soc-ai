"""What the investigation detail sends for the console polish of 2026-11-13.

* K1: a cited field path carries its value and the grid document that holds
  it, so the page opens the document at the field. A tool call step names its
  tool, so a tool citation scrolls to it. The chips were spans that did
  nothing, and the payload that made the verdict was not on the page.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from soc_ai.agent.evidence import _path_exists_in_alert, context_path_value
from soc_ai.api.webui import _timeline


def _ev(seq: int, kind: str, payload: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(sequence=seq, kind=kind, payload=payload)


_CONTEXT: dict[str, Any] = {
    "alert": {
        "id": "AlertDoc0000000000001",
        "payload_printable": "POST /index.php HTTP/1.1",
        "rule_metadata": {"signature_severity": "Informational"},
        "alert_action": "allowed",
    },
    "community_id_events": [
        {"id": "ZeekDoc00000000000001", "zeek_http_status": 200, "zeek_ssl_established": True},
    ],
    "host_alert_profiles": [{"ip": "10.20.30.5", "end": "source", "as_source": {"ET X": 3}}],
}


def _cited(*citations: str) -> list[_timeline.CitationOut]:
    report = {"citations": list(citations)}
    return _timeline._citations_out(report, [_ev(1, "enriched_alert_context", _CONTEXT)])


# ── K1: a cited field carries its document and its value ──────────────────


def test_an_alert_field_names_the_alert_document_and_its_value() -> None:
    (out,) = _cited("alert.payload_printable")
    assert (out.kind, out.documentId, out.value) == (
        "path",
        "AlertDoc0000000000001",
        "POST /index.php HTTP/1.1",
    )


def test_a_nested_alert_field_reads_its_value() -> None:
    (out,) = _cited("alert.rule_metadata.signature_severity")
    assert (out.documentId, out.value) == ("AlertDoc0000000000001", "Informational")


def test_a_session_event_field_names_that_event() -> None:
    status, established = _cited(
        "community_id_events.0.zeek_http_status", "community_id_events.0.zeek_ssl_established"
    )
    assert (status.documentId, status.value) == ("ZeekDoc00000000000001", "200")
    assert established.value == "true"


def test_a_profile_field_has_a_value_and_no_document() -> None:
    (out,) = _cited("host_alert_profiles.0.as_source")
    assert out.documentId is None
    assert out.value == '{"ET X":3}'


def test_control_a_field_the_context_lacks_has_neither() -> None:
    # The model wrote alert.alert.alert_action. The alert holds no "alert"
    # key, so the page must not open the alert at a field it does not hold.
    missing, past_end = _cited("alert.alert.alert_action", "community_id_events.4.zeek_http_status")
    assert (missing.documentId, missing.value) == (None, None)
    assert (past_end.documentId, past_end.value) == (None, None)


def test_control_an_id_citation_carries_no_field_value() -> None:
    (out,) = _cited("AlertDoc0000000000001")
    assert out.kind == "id"
    assert (out.documentId, out.value) == (None, None)


def test_control_a_run_with_no_stored_context_has_no_value() -> None:
    out = _timeline._citations_out({"citations": ["alert.payload_printable"]}, [])
    assert (out[0].documentId, out[0].value) == (None, None)


def test_a_cited_value_is_scrubbed() -> None:
    context = {"alert": {"id": "AlertDoc0000000000001", "message": "password=hunter2secret"}}
    report = {"citations": ["alert.message"]}
    (out,) = _timeline._citations_out(report, [_ev(1, "enriched_alert_context", context)])
    assert "hunter2secret" not in (out.value or "")


def test_a_large_cited_value_is_cut_at_the_cap_with_a_flag() -> None:
    payload = "A" * (_timeline.CITED_VALUE_MAX + 500)
    context = {"alert": {"id": "AlertDoc0000000000001", "payload_printable": payload}}
    report = {"citations": ["alert.payload_printable"]}
    (out,) = _timeline._citations_out(report, [_ev(1, "enriched_alert_context", context)])
    assert out.value == "A" * 2000
    assert out.valueTruncated is True
    assert out.documentId == "AlertDoc0000000000001"
    assert out.model_dump()["valueTruncated"] is True


def test_control_a_value_at_the_cap_is_whole_and_has_no_flag() -> None:
    at_cap = "B" * _timeline.CITED_VALUE_MAX
    context = {"alert": {"id": "AlertDoc0000000000001", "payload_printable": at_cap}}
    report = {"citations": ["alert.payload_printable"]}
    (out,) = _timeline._citations_out(report, [_ev(1, "enriched_alert_context", context)])
    assert out.value == at_cap
    assert out.valueTruncated is False
    # A citation with no value has no flag either.
    (missing,) = _cited("alert.not_held")
    assert (missing.value, missing.valueTruncated) == (None, False)


def test_the_page_walk_and_the_validator_walk_agree() -> None:
    # One walk for both: a key that holds a dot and an embedded JSON message.
    dump = {
        "enrichments": {"10.20.30.5": {"internal": True}},
        "alert": {"message": '{"app_proto": "http"}'},
    }
    assert context_path_value(dump, "enrichments.10.20.30.5.internal") is True
    assert context_path_value(dump, "alert.message.app_proto") == "http"
    assert context_path_value(dump, "alert.message.missing") is None
    ctx = SimpleNamespace(model_dump=lambda mode: dump)
    assert _path_exists_in_alert(ctx, "alert.message.app_proto") is True
    assert _path_exists_in_alert(ctx, "alert.message.missing") is False


# ── K1: a tool step names its tool ─────────────────────────────────────────


def test_a_tool_call_step_names_its_tool() -> None:
    events = [
        _ev(1, "tool_call", {"tool_name": "t_prevalence", "tool_call_id": "c1", "args": {}}),
        _ev(2, "tool_result", {"tool_call_id": "c1", "result": {"count": 3}}),
        _ev(3, "session_start", {}),
    ]
    timeline, _calls, _pivots, _oracle = _timeline._build_timeline(events)
    tools = {step.id: step.tool for step in timeline}
    assert tools["e1"] == "t_prevalence"
    assert all(tool is None for step_id, tool in tools.items() if step_id != "e1")


# ── K2: a failed run names the class of its cause ─────────────────────────


def _failure(payload: dict[str, Any]) -> _timeline.FailureOut:
    out = _timeline._failure_out("error", [_ev(9, "error", payload)])
    assert out is not None
    return out


def test_a_gateway_5xx_is_the_gateway() -> None:
    # The shape of run 01M78JGQXMG95Q240SDG2SWTNV.
    out = _failure(
        {
            "phase": "synth_first_round1",
            "type": "ModelHTTPError",
            "message": "status_code: 500, model_name: glm-5.3-flash, body: {'message': 'Cannot "
            "connect to host REDACTED:8888 ssl:<ssl.SSLContext object at 0x75b7>'}",
        }
    )
    assert out.kind == "gateway"


def test_a_token_limit_is_the_token_limit() -> None:
    out = _failure(
        {
            "phase": "investigation_loop",
            "type": "UnexpectedModelBehavior",
            "message": "Exceeded maximum output token limit",
        }
    )
    assert out.kind == "token_limit"


def test_the_backstop_is_the_time_limit() -> None:
    out = _failure(
        {"phase": "whole_run_backstop", "type": "TimeoutError", "message": "run took too long"}
    )
    assert out.kind == "time_limit"


def test_a_prefetch_error_is_the_grid() -> None:
    out = _failure(
        {"phase": "prefetch", "type": "ConnectionTimeout", "message": "connection timed out"}
    )
    assert out.kind == "grid"


def test_an_unknown_error_is_other() -> None:
    out = _failure({"phase": "investigation_loop", "type": "KeyError", "message": "'verdict'"})
    assert out.kind == "other"


def test_control_a_permanent_cause_is_not_the_grid() -> None:
    # The prefetch raised it, and the alert is gone. No re-run changes it, so
    # the page must not say that the grid did not answer.
    out = _failure(
        {"phase": "prefetch", "type": "SoNotFoundError", "message": "alert not found: abc"}
    )
    assert out.permanent is True
    assert out.kind == "other"


# ── K3: the Oracle card says why the Oracle gave no answer ────────────────

_ESCALATION = {
    "reason": "needs_more_info",
    "local_verdict": "needs_more_info",
    "local_confidence": 0.5,
}


def test_a_failed_oracle_call_names_its_reason() -> None:
    out = _timeline._build_oracle(
        [
            _ev(1, "oracle_escalation", _ESCALATION),
            _ev(2, "oracle_adjudication_failed", {"error_class": "quota", "http_status": 429}),
        ]
    )
    assert out is not None
    assert out.oracleVerdict is None
    assert out.noAnswer == "The Oracle route hit a usage limit."


def test_a_paused_oracle_says_so() -> None:
    out = _timeline._build_oracle(
        [_ev(1, "oracle_escalation", _ESCALATION), _ev(2, "oracle_skipped", {"paused_until": None})]
    )
    assert out is not None
    assert out.noAnswer == "Oracle calls are paused."


def test_an_unknown_failure_class_still_reads_as_a_sentence() -> None:
    out = _timeline._build_oracle(
        [_ev(1, "oracle_escalation", _ESCALATION), _ev(2, "oracle_adjudication_failed", {})]
    )
    assert out is not None
    assert out.noAnswer == "The Oracle call failed."


def test_control_an_oracle_verdict_after_a_retry_has_no_reason() -> None:
    out = _timeline._build_oracle(
        [
            _ev(1, "oracle_escalation", _ESCALATION),
            _ev(2, "oracle_adjudication_failed", {"error_class": "timeout"}),
            _ev(
                3,
                "oracle_adjudication",
                {"oracle_verdict": "true_positive", "oracle_confidence": 0.8},
            ),
        ]
    )
    assert out is not None
    assert out.oracleVerdict == "true_positive"
    assert out.noAnswer is None


def test_control_an_escalation_with_no_record_has_no_reason() -> None:
    out = _timeline._build_oracle([_ev(1, "oracle_escalation", _ESCALATION)])
    assert out is not None
    assert out.noAnswer is None
