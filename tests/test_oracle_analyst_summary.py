"""The text of the Oracle for the analyst (H3, 2026-11-13).

On production 27 runs showed the reasoning of the Oracle as the summary: up
to 2,502 characters, with "t_query_events_oql counted 2 documents" and "The
local needs_more_info verdict is wrong". The true positives of the Oracle
carried no recommended action.

- The Oracle answers with two text fields: an analyst summary and the
  reasoning. The summary of the run is the analyst summary. The reasoning has
  its own field on the report, and the page returns it as ``oracleReasoning``.
- An Oracle true positive gets the action a local true positive gets: one
  Escalate to case.
- An answer with no analyst summary keeps the text of the earlier release.
- The request stays one call, and the prompt does not grow.

The data is synthetic: placeholder addresses and rule names.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from soc_ai.agent import budget
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.oracle.client import (
    _ORACLE_BASE_PROMPT,
    ORACLE_SYSTEM_PROMPT,
    ORACLE_TOOL_SYSTEM_PROMPT,
    OracleVerdict,
    _parse_oracle_verdict,
    _verdict_to_report,
)
from soc_ai.store import investigations as inv_svc
from soc_ai.triage_models import RecommendedAction, TriageReport

from tests import test_oracle_override_evidence as ov

ANALYST = (
    "The source host sent one probe to the VPN endpoint and got no answer. "
    "Block the source address at the firewall."
)
REASONING = (
    "t_query_events_oql counted 2 documents total for this pair. "
    "The local needs_more_info verdict is wrong."
)
OLD_SUMMARY = "The source host sent one probe to the VPN endpoint."
CITED = [f"community event {ov.PIVOT_ID}"]


def _answer(verdict: str = "true_positive", **over: Any) -> str:
    body: dict[str, Any] = {
        "verdict": verdict,
        "confidence": 0.82,
        "analyst_summary": ANALYST,
        "reasoning": REASONING,
        "impact": "none",
        "citations": CITED,
    }
    body.update(over)
    return json.dumps({k: v for k, v in body.items() if v is not None})


def _old_answer(verdict: str = "true_positive") -> str:
    """The answer shape of the earlier release: a summary and the reasoning."""
    return _answer(verdict, analyst_summary=None, summary=OLD_SUMMARY)


def _local(verdict: str = "needs_more_info", **over: Any) -> TriageReport:
    fields: dict[str, Any] = {
        "verdict": verdict,
        "confidence": 0.4,
        "summary": "The local run could not decide.",
        "citations": ["alert.rule_name"],
        "recommended_actions": [],
    }
    fields.update(over)
    return TriageReport(**fields)


# ── The answer ─────────────────────────────────────────────────────────────


def test_the_prompt_asks_for_an_analyst_summary_and_the_reasoning() -> None:
    for prompt in (ORACLE_SYSTEM_PROMPT, ORACLE_TOOL_SYSTEM_PROMPT):
        assert '"analyst_summary"' in prompt
        assert '"reasoning"' in prompt
        assert "at most three plain sentences" in prompt
        assert "name no tool" in prompt
        assert "do not refer to the local verdict" in prompt
        # The earlier key is not asked for: one text for the analyst.
        assert '"summary" (' not in prompt


def test_the_request_stays_bounded() -> None:
    """The prompt is static text on every request. The two new fields replace
    the old summary field, so the base prompt is no longer than it was with
    the impact field alone (1,811 characters)."""
    assert len(_ORACLE_BASE_PROMPT) <= 1900


def test_an_answer_with_an_analyst_summary_and_no_summary_parses() -> None:
    verdict = _parse_oracle_verdict(_answer())
    assert verdict is not None
    assert verdict.analyst_summary == ANALYST
    assert verdict.reasoning == REASONING
    assert verdict.summary == ""


def test_an_answer_of_the_earlier_release_still_parses() -> None:
    verdict = _parse_oracle_verdict(_old_answer())
    assert verdict is not None
    assert verdict.analyst_summary is None
    assert verdict.summary == OLD_SUMMARY


@pytest.mark.parametrize(
    "over",
    [
        {"analyst_summary": None},
        {"analyst_summary": "   "},
        {"analyst_summary": None, "summary": ""},
    ],
)
def test_an_answer_with_no_text_for_the_analyst_does_not_parse(over: dict[str, Any]) -> None:
    """Negative control: the reasoning alone is no summary. The answer takes
    the unparseable path, and the local verdict stands."""
    assert _parse_oracle_verdict(_answer(**over)) is None


def test_the_report_summary_is_the_analyst_summary() -> None:
    verdict = OracleVerdict.model_validate(json.loads(_answer()))
    report = _verdict_to_report(verdict, local_report=_local(), backed=True)
    assert report.summary == ANALYST
    assert "Oracle reasoning" not in report.summary
    assert "t_query_events_oql" not in report.summary
    assert "local needs_more_info" not in report.summary


def test_an_answer_with_no_analyst_summary_keeps_the_earlier_text() -> None:
    verdict = OracleVerdict.model_validate(json.loads(_old_answer()))
    report = _verdict_to_report(verdict, local_report=_local(), backed=True)
    assert report.summary == f"{OLD_SUMMARY}\n\nOracle reasoning: {REASONING}"


# ── The action of an Oracle true positive ──────────────────────────────────


def test_an_oracle_true_positive_gets_one_escalate() -> None:
    report = _local("true_positive", summary=ANALYST, confidence=0.82)
    out, added = budget.oracle_true_positive_action(
        report, alert_id="alert-0001", rule_name="ET SCAN Example Probe"
    )
    assert added is True
    assert [a.tool_name for a in out.recommended_actions] == ["escalate_to_case"]
    action = out.recommended_actions[0]
    assert action.tool_args == {
        "alert_id": "alert-0001",
        "case_title": "ET SCAN Example Probe",
        "case_description": ANALYST,
    }
    # The reason is the first sentence of the analyst summary: the row headline.
    assert action.rationale == (
        "The source host sent one probe to the VPN endpoint and got no answer."
    )


def test_an_escalate_of_the_local_report_is_not_doubled() -> None:
    escalate = RecommendedAction(
        tool_name="escalate_to_case",
        tool_args={"alert_id": "alert-0001", "case_title": "x", "case_description": "y"},
        rationale="Open a case.",
    )
    report = _local("true_positive", recommended_actions=[escalate])
    out, added = budget.oracle_true_positive_action(report, alert_id="alert-0001", rule_name="r")
    assert out is report
    assert added is False


@pytest.mark.parametrize("verdict", ["false_positive", "needs_more_info", "inconclusive"])
def test_a_verdict_that_is_no_true_positive_gets_no_escalate(verdict: str) -> None:
    """Negative control: only a true positive gets the action."""
    report = _local(verdict, summary=ANALYST)
    out, added = budget.oracle_true_positive_action(report, alert_id="alert-0001", rule_name="r")
    assert out is report
    assert added is False
    assert out.recommended_actions == []


def test_an_escalate_with_no_rule_name_and_no_summary_still_has_its_text() -> None:
    report = _local("true_positive", summary="")
    out, added = budget.oracle_true_positive_action(report, alert_id="alert-0001", rule_name=None)
    assert added is True
    args = out.recommended_actions[0].tool_args
    assert args["case_title"]
    assert args["case_description"]
    assert out.recommended_actions[0].rationale


# ── The pipeline ───────────────────────────────────────────────────────────


def _counting_gateway(answer: str, calls: list[str]) -> Any:
    real_client = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/chat/completions"):
            calls.append(request.content.decode())
            return httpx.Response(200, json={"choices": [{"message": {"content": answer}}]})
        return httpx.Response(404, json={"error": {"message": "not here"}})

    def _client(**kw: Any) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(_handler), **kw)

    return patch("httpx.AsyncClient", _client)


async def _run(settings: Settings, answer: str) -> tuple[dict[str, Any], list[Any], list[str]]:
    calls: list[str] = []
    with patch.object(ov, "_gateway", lambda a: _counting_gateway(a, calls)):
        events, _write = await ov._run(settings, answer)
    return ov._final(events), events, calls


async def test_the_run_shows_the_analyst_summary_and_stores_the_reasoning(
    settings_kratos: Settings,
) -> None:
    final, events, calls = await _run(settings_kratos, _answer())
    assert final["verdict"] == "true_positive"
    assert final["local_verdict"] == "needs_more_info"
    assert final["summary"] == ANALYST
    assert final["oracle_reasoning"] == REASONING
    for internal in ("Oracle", "t_query_events_oql", "local needs_more_info", "local verdict"):
        assert internal not in final["summary"]
    assert final["impact"] == "none"
    # One request to the Oracle route: no second model call writes the text.
    assert len(calls) == 1
    assert ov._adjudication(events)["oracle_verdict"] == "true_positive"


async def test_an_oracle_true_positive_of_the_run_offers_escalate(
    settings_kratos: Settings,
) -> None:
    final, _events, _calls = await _run(settings_kratos, _answer())
    actions = final["recommended_actions"]
    assert [a["tool_name"] for a in actions] == ["escalate_to_case"]
    assert actions[0]["tool_args"]["alert_id"] == "beacon-001"
    assert actions[0]["tool_args"]["case_title"]
    assert actions[0]["tool_args"]["case_description"] == ANALYST
    assert actions[0]["rationale"] == (
        "The source host sent one probe to the VPN endpoint and got no answer."
    )


async def test_an_oracle_false_positive_of_the_run_offers_no_escalate(
    settings_kratos: Settings,
) -> None:
    """Negative control on the whole path."""
    final, _events, _calls = await _run(settings_kratos, _answer("false_positive", impact=None))
    assert final["verdict"] == "false_positive"
    assert final["summary"] == ANALYST
    assert not any(a["tool_name"] == "escalate_to_case" for a in final["recommended_actions"])


async def test_an_old_answer_of_the_run_keeps_the_text_of_the_earlier_release(
    settings_kratos: Settings,
) -> None:
    final, _events, _calls = await _run(settings_kratos, _old_answer())
    assert final["verdict"] == "true_positive"
    assert final["summary"] == (
        f"[Oracle adjudicated] {OLD_SUMMARY}\n\nOracle reasoning: {REASONING}"
    )
    assert "oracle_reasoning" not in final
    # The true positive still gets its action.
    assert [a["tool_name"] for a in final["recommended_actions"]] == ["escalate_to_case"]


async def test_a_withheld_answer_changes_no_text_and_adds_no_action(
    settings_kratos: Settings,
) -> None:
    """Negative control: the Oracle names no evidence, so its answer is an
    opinion. The local report stands as it was."""
    final, events, _calls = await _run(settings_kratos, _answer(citations=None))
    assert final["verdict"] == "needs_more_info"
    assert ANALYST not in final["summary"]
    assert "oracle_reasoning" not in final
    assert final["recommended_actions"] == []
    adjudication = ov._adjudication(events)
    assert adjudication["override_withheld"] is True
    # The opinion on the record is the text for the analyst.
    assert adjudication["oracle_summary"] == ANALYST


# ── The API ────────────────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _seed(client: TestClient, alert_id: str, summary: str, report: dict[str, Any]) -> str:
    async def work() -> str:
        async with client.app.state.db_sessionmaker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id=alert_id,
                started_by="auto-triage",
                rule_name="ET SCAN Example Probe",
                src_ip="10.40.50.7",
                dest_ip="10.20.30.5",
            )
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="true_positive",
                confidence=0.82,
                summary=summary,
                report={
                    "verdict": "true_positive",
                    "confidence": 0.82,
                    "summary": summary,
                    **report,
                },
            )
            return str(inv.id)

    run_id: str = asyncio.run(work())
    return run_id


def _detail(client: TestClient, run_id: str) -> dict[str, Any]:
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        res = client.get(f"/api/v1/investigations/{run_id}")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_the_page_returns_the_reasoning_in_its_own_field(client: TestClient) -> None:
    run_id = _seed(client, "o-new", ANALYST, {"oracle_reasoning": REASONING})
    detail = _detail(client, run_id)
    assert detail["oracleReasoning"] == REASONING
    assert detail["summary"] == [{"t": "text", "v": ANALYST}]


def test_a_run_of_the_earlier_release_keeps_its_text_on_the_page(client: TestClient) -> None:
    old = f"[Oracle adjudicated] {OLD_SUMMARY}\n\nOracle reasoning: {REASONING}"
    run_id = _seed(client, "o-old", old, {})
    detail = _detail(client, run_id)
    assert detail["oracleReasoning"] is None
    assert detail["summary"] == [{"t": "text", "v": old}]
