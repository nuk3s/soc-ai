"""Each run records the model that served it (B4, 2026-11-13).

Two wrong true positives on production came from the gateway fallback route
``qwen3.6-35b-temp-fallback`` on 2026-11-03. Both overrode a false positive on
the same session, and no gate fired (review 2026-11-12, triage finding 6, ops
finding 5). On that day 42 of 84 verdicts came from the fallback model, and the
analyst could not see that a weaker model wrote them.

The store held the fact, on each ``usage`` event (``served_backend``). No run
carried it:

- The report now has ``served_model``: the model groups that served the run,
  the models that its calls asked for and a fallback mark.
- The investigation API serves it, and the report page shows one line.
- A true positive from a fallback route goes to the Oracle. So does a verdict
  from a fallback route that changes an earlier verdict of the same alert.

A call is a fallback only on the word of the gateway: its fallback count is
above zero, or the model group that served the call is not the model that the
call asked for. The configured ``analyst_model`` is no test. Production runs
two configured names on one backend, ``glm-5.3-flash`` and
``deepseek-v4-flash``, and a rule on ``analyst_model`` marked each call that
asked for the second name.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic_ai.models.test import TestModel
from soc_ai.agent import budget
from soc_ai.agent import orchestrator as orch
from soc_ai.agent._gateway_retry import (
    _record_attribution,
    call_was_fallback,
    capture_backend_attribution,
)
from soc_ai.agent.orchestrator import (
    ORACLE_REASON_FALLBACK_ROUTE,
    fallback_route_reason,
    investigate,
    served_model_record,
)
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.triage_models import PIPELINE_FALLBACK_PROVENANCE

from tests import test_hunt_subject as hs
from tests.test_host_anchored_gate import _capturing_gateway, _oracle_answer
from tests.test_webui_api import _client

CONFIGURED = "analyst-main"
FALLBACK = "analyst-temp-fallback"


def _report(verdict: str = "true_positive", **over: Any) -> TriageReport:
    base: dict[str, Any] = {
        "verdict": verdict,
        "confidence": 0.85,
        "summary": "The payload is shellcode.",
        "citations": [hs.ANCHOR_ID],
        "recommended_actions": [],
    }
    base.update(over)
    return TriageReport(**base)


# ── one call ──────────────────────────────────────────────────────────────────

MAIN = "glm-5.3-flash"
SECOND = "deepseek-v4-flash"
TEMP_FALLBACK = "qwen3.6-35b-temp-fallback"


def _call(group: str | None, asked: str | None, attempted: Any = "0") -> dict[str, Any]:
    """One ``served_backend``, as a usage event stores it. Values are strings."""
    call: dict[str, Any] = {"api_base": "http://10.0.0.9:8888/v1", "attempted_retries": "0"}
    if group is not None:
        call["model_group"] = group
    if asked is not None:
        call["requested_model"] = asked
    if attempted is not None:
        call["attempted_fallbacks"] = attempted
    return call


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        # The gateway served what the call asked for.
        (_call(MAIN, MAIN), False),
        (_call(SECOND, SECOND), False),
        # The gateway says that it fell back. The count arrives as a string.
        (_call(MAIN, MAIN, "1"), True),
        (_call(MAIN, MAIN, 2), True),
        (_call(MAIN, None, "1"), True),
        # Another model group served the call.
        (_call(TEMP_FALLBACK, MAIN), True),
        (_call(TEMP_FALLBACK, MAIN, None), True),
        # Negative controls: no asked model and no fallback count prove nothing.
        (_call(SECOND, None), False),
        (_call(SECOND, None, None), False),
        (_call(MAIN, MAIN, "zero"), False),
        (_call(MAIN, MAIN, ""), False),
        ({}, False),
    ],
)
def test_a_call_is_a_fallback_only_on_the_word_of_the_gateway(
    call: dict[str, Any], expected: bool
) -> None:
    assert call_was_fallback(call) is expected


def _response(asked: str, group: str, attempted: str = "0") -> tuple[httpx.Response, httpx.Request]:
    request = httpx.Request(
        "POST",
        "http://gateway.example.test:4000/v1/chat/completions",
        content=json.dumps({"model": asked, "messages": []}).encode(),
    )
    response = httpx.Response(
        200,
        headers={
            "x-litellm-model-api-base": "http://10.0.0.9:8888/v1",
            "x-litellm-model-group": group,
            "x-litellm-attempted-fallbacks": attempted,
        },
        request=request,
    )
    return response, request


def test_the_transport_records_the_model_that_the_call_asked_for() -> None:
    with capture_backend_attribution() as sink:
        _record_attribution(*_response(SECOND, SECOND))
    assert sink["requested_model"] == SECOND
    assert sink["model_group"] == SECOND
    assert "fallback" not in sink
    assert call_was_fallback(sink) is False


def test_a_fallback_call_marks_the_whole_capture_block() -> None:
    """One sink holds the calls of one phase, and each call writes over the
    headers of the call before it. The mark stays when a later call of the
    same phase is served by the model that it asked for."""
    with capture_backend_attribution() as sink:
        _record_attribution(*_response(MAIN, TEMP_FALLBACK, "1"))
        _record_attribution(*_response(MAIN, MAIN, "0"))
    assert sink["model_group"] == MAIN
    assert sink["fallback"] is True
    assert sink["fallback_model_group"] == TEMP_FALLBACK
    assert call_was_fallback(sink) is True


def test_the_transport_never_raises_on_a_body_that_is_no_json() -> None:
    request = httpx.Request("POST", "http://gateway.example.test:4000/v1/x", content=b"not json")
    response = httpx.Response(200, headers={"x-litellm-model-group": MAIN}, request=request)
    with capture_backend_attribution() as sink:
        _record_attribution(response, request)
    assert sink == {"model_group": MAIN}


# ── the record of a run ───────────────────────────────────────────────────────


def test_two_configured_names_on_one_backend_give_no_mark() -> None:
    """The production shape since 2026-11-06: 384 usage events name
    ``glm-5.3-flash`` and 171 name ``deepseek-v4-flash``, on one backend, each
    with a fallback count of '0'. Neither is a fallback."""
    calls = [_call(MAIN, MAIN), _call(SECOND, SECOND), _call(MAIN, MAIN)]
    assert served_model_record(calls) == {
        "model_groups": [MAIN, SECOND],
        "requested_models": [MAIN, SECOND],
        "fallback": False,
    }


def test_a_fallback_group_for_a_call_that_asked_for_the_main_model_gives_a_mark() -> None:
    record = served_model_record([_call(MAIN, MAIN), _call(TEMP_FALLBACK, MAIN)])
    assert record == {
        "model_groups": [MAIN, TEMP_FALLBACK],
        "requested_models": [MAIN],
        "fallback": True,
    }


def test_a_fallback_inside_one_phase_names_its_model_group() -> None:
    """The loop makes many calls under one sink. The record names the group
    that served the fallback call, also when the last call was normal."""
    sink = {**_call(MAIN, MAIN), "fallback": True, "fallback_model_group": TEMP_FALLBACK}
    record = served_model_record([sink])
    assert record is not None
    assert record["fallback"] is True
    assert record["model_groups"] == [MAIN, TEMP_FALLBACK]


def test_a_run_with_no_attribution_has_no_record() -> None:
    """Negative control: a missing ``served_backend`` proves nothing, so the
    run gets no mark and no Oracle call from this rule."""
    assert served_model_record([]) is None
    assert served_model_record([{}, None]) is None  # type: ignore[list-item]


# ── the Oracle rule ───────────────────────────────────────────────────────────


def _settings(settings: Settings, **over: Any) -> Settings:
    return settings.model_copy(update={"oracle_enabled": True, **over})


def _served(fallback: bool = True) -> dict[str, Any]:
    return {
        "model_groups": [FALLBACK if fallback else CONFIGURED],
        "requested_models": [CONFIGURED],
        "fallback": fallback,
    }


def test_a_true_positive_from_a_fallback_route_goes_to_the_oracle(
    settings_kratos: Settings,
) -> None:
    assert (
        fallback_route_reason(
            _report("true_positive"), _served(), _settings(settings_kratos), earlier_verdicts=[]
        )
        == ORACLE_REASON_FALLBACK_ROUTE
    )


@pytest.mark.parametrize(
    ("verdict", "earlier", "expected"),
    [
        # A verdict that changes an earlier verdict of the same alert.
        ("false_positive", ["true_positive"], ORACLE_REASON_FALLBACK_ROUTE),
        ("needs_more_info", ["false_positive"], ORACLE_REASON_FALLBACK_ROUTE),
        # Negative controls: the same verdict again, and no earlier verdict.
        ("false_positive", ["false_positive"], None),
        ("false_positive", [], None),
        ("needs_more_info", ["needs_more_info", "needs_more_info"], None),
    ],
)
def test_a_changed_verdict_from_a_fallback_route_goes_to_the_oracle(
    settings_kratos: Settings, verdict: str, earlier: list[str], expected: str | None
) -> None:
    assert (
        fallback_route_reason(
            _report(verdict), _served(), _settings(settings_kratos), earlier_verdicts=earlier
        )
        == expected
    )


def test_the_configured_model_adds_no_oracle_call(settings_kratos: Settings) -> None:
    """Negative control on the path the rule must not take: a true positive
    from the configured model keeps the rule that it had."""
    settings = _settings(settings_kratos)
    assert (
        fallback_route_reason(
            _report(), _served(fallback=False), settings, earlier_verdicts=["false_positive"]
        )
        is None
    )
    assert fallback_route_reason(_report(), None, settings, earlier_verdicts=[]) is None


def test_the_rule_keeps_the_limits_of_every_oracle_rule(settings_kratos: Settings) -> None:
    """Negative controls: the Oracle is off, the run is a cheap run, or the
    report is a pipeline error."""
    on = _settings(settings_kratos)
    off = settings_kratos.model_copy(update={"oracle_enabled": False})
    assert fallback_route_reason(_report(), _served(), off, earlier_verdicts=[]) is None
    assert (
        fallback_route_reason(_report(), _served(), on, earlier_verdicts=[], run_class=budget.CHEAP)
        is None
    )
    failed = _report("needs_more_info", resolution={"provenance": PIPELINE_FALLBACK_PROVENANCE})
    assert fallback_route_reason(failed, _served(), on, earlier_verdicts=["false_positive"]) is None


# ── the pipeline ──────────────────────────────────────────────────────────────


async def _run(
    settings: Settings,
    *,
    served: dict[str, Any] | None,
    report: TriageReport,
    oracle_answer: str | None,
) -> tuple[list[Any], list[str]]:
    """One run whose model calls carry ``served`` as their ``served_backend``."""
    settings.investigate_when_unsure = True
    settings.oracle_enabled = oracle_answer is not None
    # The configured model is a third name: the rule must not read it.
    settings.analyst_model = CONFIGURED
    ctx = hs._make_ctx(settings)
    bodies: list[str] = []

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return hs._enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=hs._fake_investigator()),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer", return_value=hs._fake_loop_synth(report)
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            MagicMock(return_value=None),
        ),
        patch("soc_ai.store.investigations.session_verdicts", AsyncMock(return_value=[])),
        patch("soc_ai.agent.orchestrator.maybe_auto_ack_fp", AsyncMock(return_value=None)),
        patch("soc_ai.agent.orchestrator._served_backend", lambda _attr: served),
        patch("soc_ai.oracle.client.asyncio.sleep", AsyncMock()),
        _capturing_gateway(oracle_answer or "", bodies),
    ):
        events = [ev async for ev in investigate(hs.ANCHOR_ID, ctx=ctx)]
    return events, bodies


async def test_the_report_records_the_served_model(settings_kratos: Settings) -> None:
    events, _bodies = await _run(
        settings_kratos,
        served=_call(TEMP_FALLBACK, MAIN, "1"),
        report=_report("false_positive"),
        oracle_answer=None,
    )
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["served_model"] == {
        "model_groups": [TEMP_FALLBACK],
        "requested_models": [MAIN],
        "fallback": True,
    }


async def test_a_run_with_no_attribution_stores_no_served_model(
    settings_kratos: Settings,
) -> None:
    """Negative control: the key is absent, so every other report keeps its
    shape. A true positive with no attribution makes no Oracle call."""
    events, bodies = await _run(
        settings_kratos,
        served=None,
        report=_report("true_positive"),
        oracle_answer=_oracle_answer([hs.ANCHOR_ID]),
    )
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert "served_model" not in final
    assert not any(e.kind == "oracle_escalation" for e in events)
    assert bodies == []


async def test_a_fallback_true_positive_is_escalated(settings_kratos: Settings) -> None:
    """The shape of run 01M6H3DDN9W2RDH50CK37RH6SQ: a confident true positive
    from the fallback route. No rule sent it to the Oracle."""
    events, bodies = await _run(
        settings_kratos,
        served=_call(TEMP_FALLBACK, MAIN, None),
        report=_report("true_positive"),
        oracle_answer=_oracle_answer([hs.ANCHOR_ID]),
    )
    escalation = next(e.payload for e in events if e.kind == "oracle_escalation")
    assert escalation["reason"] == ORACLE_REASON_FALLBACK_ROUTE
    assert escalation["local_verdict"] == "true_positive"
    assert bodies, "the Oracle got no call"


@pytest.mark.parametrize("asked", [MAIN, SECOND])
async def test_a_true_positive_of_a_configured_name_stays_local(
    settings_kratos: Settings, asked: str
) -> None:
    """Negative control on the production shape. The call asked for one of the
    two configured names, the gateway served that name, and its fallback count
    is '0'. Neither name is ``analyst_model`` of this test. The run gets no
    mark, and its true positive makes no Oracle call."""
    events, bodies = await _run(
        settings_kratos,
        served=_call(asked, asked, "0"),
        report=_report("true_positive"),
        oracle_answer=_oracle_answer([hs.ANCHOR_ID]),
    )
    assert not any(e.kind == "oracle_escalation" for e in events)
    assert bodies == []
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["served_model"] == {
        "model_groups": [asked],
        "requested_models": [asked],
        "fallback": False,
    }


# ── the API ───────────────────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _seed(client: TestClient, *, report: dict[str, Any], events: list[dict[str, Any]]) -> str:
    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="es-served-model", started_by="tester")
            if events:
                await inv_svc.append_events(db, inv.id, events)
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="true_positive",
                confidence=0.85,
                rationale="The payload is shellcode.",
                report=report,
            )
            return str(inv.id)

    return asyncio.run(_go())


def test_the_api_serves_the_served_model_and_the_asked_model(client: TestClient) -> None:
    inv_id = _seed(
        client,
        report={
            "verdict": "true_positive",
            "served_model": {
                "model_groups": [TEMP_FALLBACK, MAIN],
                "requested_models": [MAIN],
                "fallback": True,
            },
        },
        events=[],
    )
    meta = client.get(f"/api/v1/investigations/{inv_id}").json()["meta"]
    assert meta["servedModel"] == f"{TEMP_FALLBACK}, {MAIN}"
    assert meta["requestedModel"] == MAIN
    assert meta["servedFallback"] is True
    # The model line names the model that the run asked for.
    assert meta["model"] == MAIN


def test_the_api_reads_the_usage_events_of_an_older_run(client: TestClient) -> None:
    """A run of an older release has no record on its report. The usage events
    name the model group and the fallback count of the gateway."""
    inv_id = _seed(
        client,
        report={"verdict": "true_positive"},
        events=[
            {
                "sequence": 1,
                "kind": "usage",
                "payload": {
                    "round": 1,
                    "served_backend": {"model_group": TEMP_FALLBACK, "attempted_fallbacks": "1"},
                },
            },
            {"sequence": 2, "kind": "usage", "payload": {"round": 2}},
        ],
    )
    meta = client.get(f"/api/v1/investigations/{inv_id}").json()["meta"]
    assert meta["servedModel"] == TEMP_FALLBACK
    assert meta["requestedModel"] is None
    assert meta["servedFallback"] is True


def test_the_production_usage_events_give_no_mark(client: TestClient) -> None:
    """Negative control: the stored shape of production since 2026-11-06. Two
    model groups on one backend, each with a fallback count of '0'."""
    backend = {
        "api_base": "http://10.0.0.9:8888/v1",
        "deployment_id": "d1",
        "attempted_fallbacks": "0",
        "attempted_retries": "0",
    }
    inv_id = _seed(
        client,
        report={"verdict": "true_positive"},
        events=[
            {
                "sequence": 1,
                "kind": "usage",
                "payload": {"served_backend": {**backend, "model_group": SECOND}},
            },
            {
                "sequence": 2,
                "kind": "usage",
                "payload": {"served_backend": {**backend, "model_group": MAIN}},
            },
        ],
    )
    meta = client.get(f"/api/v1/investigations/{inv_id}").json()["meta"]
    assert meta["servedModel"] == f"{SECOND}, {MAIN}"
    assert meta["servedFallback"] is False


def test_a_run_with_no_attribution_serves_no_served_model(client: TestClient) -> None:
    """The page prints "not recorded" for this run, and it has no mark."""
    inv_id = _seed(client, report={"verdict": "true_positive"}, events=[])
    meta = client.get(f"/api/v1/investigations/{inv_id}").json()["meta"]
    assert meta["servedModel"] is None
    assert meta["requestedModel"] is None
    assert meta["servedFallback"] is False


def test_a_record_of_the_first_rule_is_not_trusted(client: TestClient) -> None:
    """Negative control. The first rule of this branch compared the model group
    with ``analyst_model`` and stored a ``configured`` key. A record of that
    shape is read from the usage events, by the rule of the gateway."""
    inv_id = _seed(
        client,
        report={
            "verdict": "true_positive",
            "served_model": {"configured": MAIN, "model_groups": [SECOND], "fallback": True},
        },
        events=[
            {
                "sequence": 1,
                "kind": "usage",
                "payload": {"served_backend": {"model_group": SECOND, "attempted_fallbacks": "0"}},
            }
        ],
    )
    meta = client.get(f"/api/v1/investigations/{inv_id}").json()["meta"]
    assert meta["servedModel"] == SECOND
    assert meta["servedFallback"] is False


def test_the_orchestrator_exports_the_reason() -> None:
    assert orch.ORACLE_REASON_FALLBACK_ROUTE == "fallback_route"
