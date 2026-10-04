"""The investigation detail tells the page what the run recorded (fleet 2026-10-01).

* P2: a needs_more_info run showed no open questions on prod, all 49 of them.
  ``TriageReport`` has no ``open_questions`` field. The investigator transcript
  has it, and the detail never read the transcript.
* P3: the detail sent no citations, so the page could link none.
* P10: the "Tool calls" section held a dossier row and an auto-ack row, so the
  section disagreed with the tool-call count.
* P11 / RL10: raw JSON and a "0 events" dossier title in the timeline.
* RL11: a failed run did not carry its recorded cause.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui import _timeline
from soc_ai.config import Settings
from soc_ai.main import create_app


def _ev(seq: int, kind: str, payload: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(sequence=seq, kind=kind, payload=payload)


# ── open questions ──────────────────────────────────────────────────────────


def test_open_questions_come_from_the_transcript_when_the_report_has_none() -> None:
    events = [
        _ev(
            1,
            "investigation_transcript",
            {"evidence": [], "tentative_summary": "x", "open_questions": ["Who ran the scan?"]},
        )
    ]
    report = {"verdict": "needs_more_info", "citations": []}
    assert _timeline._open_questions_out(report, events) == ["Who ran the scan?"]


def test_open_questions_stay_empty_when_nothing_recorded_any() -> None:
    # Negative control: no transcript event and no report key. The page must
    # get an empty list, never a made-up question.
    events = [_ev(1, "session_start", {"pipeline": "synth_first"})]
    assert _timeline._open_questions_out({"verdict": "needs_more_info"}, events) == []


def test_a_report_that_carries_open_questions_still_wins() -> None:
    events = [_ev(1, "investigation_transcript", {"open_questions": ["older"]})]
    report = {"open_questions": ["from the report", "  ", 3]}
    assert _timeline._open_questions_out(report, events) == ["from the report"]


# ── citations ───────────────────────────────────────────────────────────────


def test_citations_carry_kind_target_and_the_validator_verdict() -> None:
    report = {
        "citations": [
            "UbhH2KABxYz0123456_q",
            "(path alert.rule_metadata.signature_severity)",
            "UbhH2KABxYz0123456_q",
            "synth_first_failure",
        ]
    }
    events = [
        _ev(
            5,
            "citation_validation",
            {
                "per_citation": [
                    {"citation": "UbhH2KABxYz0123456_q", "kind": "id", "resolved": True},
                    {
                        "citation": "(path alert.rule_metadata.signature_severity)",
                        "kind": "path",
                        "resolved": False,
                    },
                ]
            },
        )
    ]
    out = _timeline._citations_out(report, events)
    assert [(c.kind, c.target, c.resolved) for c in out] == [
        ("id", "UbhH2KABxYz0123456_q", True),
        ("path", "alert.rule_metadata.signature_severity", False),
    ]


# ── failure cause ───────────────────────────────────────────────────────────


def test_failure_names_a_missing_alert_as_permanent() -> None:
    events = [
        _ev(
            2,
            "error",
            {"phase": "prefetch", "type": "SoNotFoundError", "message": "alert not found: abc"},
        )
    ]
    failure = _timeline._failure_out("error", events)
    assert failure is not None
    assert failure.cause == "alert not found: abc"
    assert failure.permanent is True


def test_a_timeout_is_not_permanent() -> None:
    events = [_ev(2, "error", {"type": "TimeoutError", "message": "synth timed out"})]
    failure = _timeline._failure_out("error", events)
    assert failure is not None
    assert failure.permanent is False


def test_a_complete_run_has_no_failure() -> None:
    events = [_ev(2, "error", {"type": "SoNotFoundError", "message": "alert not found: abc"})]
    assert _timeline._failure_out("complete", events) is None


# ── timeline ────────────────────────────────────────────────────────────────


def _prod_shaped_run() -> list[SimpleNamespace]:
    """The P10 run: a dossier block, two tool calls, a skipped auto-ack."""
    return [
        _ev(1, "session_start", {"pipeline": "synth_first"}),
        _ev(
            2,
            "host_dossier",
            {
                "hosts": {"192.0.2.10": "source", "198.51.100.5": "destination"},
                "hosts_omitted": 0,
                "block": "## Host dossier: asset context\n\n- 192.0.2.10 role server",
            },
        ),
        _ev(
            3,
            "tool_call",
            {"tool_name": "t_query_events_oql", "args": {"q": "x"}, "tool_call_id": "a"},
        ),
        _ev(4, "tool_result", {"tool_call_id": "a", "result": {"total": 4}}),
        _ev(
            5,
            "tool_call",
            {"tool_name": "t_host_dossier", "args": {"ip": "192.0.2.10"}, "tool_call_id": "b"},
        ),
        _ev(
            6,
            "tool_result",
            {
                "tool_call_id": "b",
                "result": {
                    "ip": "192.0.2.10",
                    "found": True,
                    "event_count": 0,
                    "fields": {
                        "role": {"value": "server", "source": "operator"},
                        "os": {"value": "linux", "source": "inferred"},
                        "hostname": {"value": "web.example.test", "source": "operator"},
                        "site": {"value": None, "source": "inferred"},
                    },
                },
            },
        ),
        _ev(
            7,
            "citation_validation",
            {
                "counts": {"valid": 5},
                "total": 6,
                "coverage_ratio": 0.8333333333333334,
                "per_citation": [
                    {"citation": "UbhH2KABxYz0123456_q", "resolved": True},
                    {"citation": "made-up-id-000000", "resolved": False},
                ],
            },
        ),
        _ev(8, "auto_ack_skipped", {"es_id": "UbhH2KABxYz0123456_q", "reason": "high_stakes"}),
    ]


def test_tool_call_count_matches_the_tool_calls_section() -> None:
    timeline, tool_calls, _pivots, _oracle = _timeline._build_timeline(_prod_shaped_run())
    tool_rows = [s for s in timeline if s.group == "Tool calls"]
    assert tool_calls == len(tool_rows) == 2
    groups = {s.title.split(":")[0]: s.group for s in timeline}
    assert groups["Auto-acknowledge skipped"] == "Decision"


def test_auto_ack_skip_and_dossier_rows_carry_no_raw_json() -> None:
    timeline, *_ = _timeline._build_timeline(_prod_shaped_run())
    by_title = {s.title: s for s in timeline}
    skip = by_title["Auto-acknowledge skipped: high stakes"]
    assert "{" not in skip.detail
    dossier = next(s for s in timeline if s.title.startswith("Host dossier: asset context"))
    assert dossier.group == "Prefetch & pivots"
    assert "##" not in dossier.detail
    assert "{" not in dossier.detail
    assert "192.0.2.10 (source)" in dossier.detail


def test_dossier_tool_title_names_the_facts_and_not_zero_events() -> None:
    timeline, *_ = _timeline._build_timeline(_prod_shaped_run())
    titles = [s.title for s in timeline]
    expected = "Host dossier: 192.0.2.10, role server, 3 known facts, 2 declared by an operator"
    assert expected in titles
    assert not any("0 events" in t for t in titles)


def test_citation_step_lists_the_ids_and_prints_a_percent() -> None:
    timeline, *_ = _timeline._build_timeline(_prod_shaped_run())
    step = next(s for s in timeline if s.group == "Validators")
    assert "Coverage is 83%." in step.detail
    assert "0.83333" not in step.detail
    assert "valid: UbhH2KABxYz0123456_q" in step.detail
    assert "not resolved: made-up-id-000000" in step.detail
    assert "—" not in step.title


def test_follow_up_result_folds_into_its_dispatch_row() -> None:
    events = [
        _ev(1, "targeted_dispatch", {"question": "SNI?", "tool_name": "t_query_zeek_logs"}),
        _ev(2, "targeted_tool_result", {"tool_name": "t_query_zeek_logs", "result": {"total": 3}}),
    ]
    timeline, tool_calls, *_ = _timeline._build_timeline(events)
    assert len(timeline) == 1
    assert tool_calls == 1
    assert "result:" in timeline[0].detail


# ── the detail endpoint ─────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        TestClient(create_app(), client=("testclient", 50000)) as c,
    ):
        yield c


def _seed(
    client: TestClient,
    *,
    status: str,
    verdict: str | None,
    report: dict[str, Any],
    events: list[dict[str, Any]],
) -> str:
    from soc_ai.store import investigations as inv_svc

    async def _go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(
                db, alert_es_id="ev-truth", started_by="tester", rule_name="ET Probe"
            )
            await inv_svc.append_events(db, inv.id, events)
            await inv_svc.finalize(
                db,
                inv.id,
                status=status,
                verdict=verdict,
                confidence=0.5 if verdict else None,
                rationale="r",
                report=report,
            )
            return inv.id

    return asyncio.run(_go())


def test_detail_serves_open_questions_citations_and_failure(client: TestClient) -> None:
    nmi_id = _seed(
        client,
        status="complete",
        verdict="needs_more_info",
        report={"verdict": "needs_more_info", "citations": ["UbhH2KABxYz0123456_q"]},
        events=[
            {
                "sequence": 1,
                "kind": "investigation_transcript",
                "payload": {"evidence": [], "open_questions": ["Did a session complete?"]},
            }
        ],
    )
    body = client.get(f"/api/v1/investigations/{nmi_id}").json()
    assert body["openQuestions"] == ["Did a session complete?"]
    assert body["citations"][0]["kind"] == "id"
    assert body["citations"][0]["target"] == "UbhH2KABxYz0123456_q"
    assert body["failure"] is None

    err_id = _seed(
        client,
        status="error",
        verdict=None,
        report={},
        events=[
            {
                "sequence": 1,
                "kind": "error",
                "payload": {"type": "SoNotFoundError", "message": "alert not found: ev-truth"},
            }
        ],
    )
    err = client.get(f"/api/v1/investigations/{err_id}").json()
    assert err["failure"] == {
        "cause": "alert not found: ev-truth",
        "hint": None,
        "permanent": True,
    }


def test_a_ulid_citation_is_a_run_and_not_a_document() -> None:
    """A run that cites another investigation by its ULID must not render a
    document chip: the dialog would read a 404 from the grid."""
    report = {"citations": ["01M3VN92PXRDYKX039HJ55C5DJ", "UbhH2KABxYz0123456_q"]}
    out = _timeline._citations_out(report, [])
    assert [(c.kind, c.target) for c in out] == [
        ("run", "01M3VN92PXRDYKX039HJ55C5DJ"),
        ("id", "UbhH2KABxYz0123456_q"),
    ]


def test_the_page_never_shows_a_credential_from_the_trace_or_a_tool_result(
    client: TestClient,
) -> None:
    """Production held an NMI run whose reasoning trace and timeline rows quoted
    a plaintext password from telemetry. The store keeps the events as evidence.
    The detail scrubs the value on read."""
    quoted = 'The file contains "svc-portal password: Zq8vL2mX9pR4tY7w" in the body'
    run_id = _seed(
        client,
        status="complete",
        verdict="needs_more_info",
        report={"verdict": "needs_more_info", "citations": []},
        events=[
            {
                "sequence": 1,
                "kind": "model_response",
                "payload": {"reasoning_trace": quoted, "content": "ok"},
            },
            {
                "sequence": 2,
                "kind": "tool_call",
                "payload": {"tool_call_id": "c1", "tool_name": "t_event_raw", "arguments": {}},
            },
            {
                "sequence": 3,
                "kind": "tool_result",
                "payload": {"tool_call_id": "c1", "result": {"body": quoted}},
            },
        ],
    )
    body = client.get(f"/api/v1/investigations/{run_id}").json()
    text = json.dumps(body)
    assert "Zq8vL2mX9pR4tY7w" not in text
    assert "svc-portal password: [redacted]" in text
    assert any("[redacted]" in r for r in body["reasoning"])
