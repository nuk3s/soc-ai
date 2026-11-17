"""The sweep pauses after two gateway connection errors in sequence (B5).

From 2026-11-01 to 2026-11-12 the gateway could not reach the model engine in
eight windows. 62 runs failed, each in 5 to 12 seconds, and the sweep started
the next alert at once. 33 alerts kept an error and no verdict (review
2026-11-12, triage finding 10, ops finding 4).

The pure rules are in tests/test_autotriage_health.py. This file covers the
worker, the scheduler, the gateway test and the read of the store.
"""

from __future__ import annotations

import asyncio
import json
import types
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from soc_ai.agent.orchestrator import StepEvent
from soc_ai.config import Settings
from soc_ai.webui import autotriage as at

from tests.test_autotriage import (
    EVENTS_ES_RESPONSE,
    _count_investigations,
    _FakeState,
    _health_targets,
    _make_es_side_effect,
    _seed_failed_run,
    _seed_run_events,
    _worker_app,
    at_settings,  # noqa: F401 - a fixture
    fake_es,  # noqa: F401 - a fixture
)

GATEWAY_ERROR: dict[str, Any] = {
    "phase": "investigation_loop",
    "round": 1,
    "type": "ModelHTTPError",
    "message": (
        "status_code: 500, model_name: analyst, body: {'message': "
        "'litellm.InternalServerError: Hosted_vllmException - Cannot connect to host "
        "10.0.0.9:8888'}"
    ),
}
SCHEMA_ERROR: dict[str, Any] = {
    "phase": "investigation_loop",
    "round": 1,
    "type": "ModelHTTPError",
    "message": "status_code: 400, model_name: analyst, body: the schema is refused",
}


def _failing(error: dict[str, Any]) -> Any:
    """An investigate() that stops with one error event and no verdict."""

    async def _investigate(alert_id: str, **_kw: Any) -> AsyncIterator[StepEvent]:
        sid = "gateway-sid"
        yield StepEvent(
            kind="session_start", session_id=sid, sequence=1, payload={"alert_id": alert_id}
        )
        yield StepEvent(kind="error", session_id=sid, sequence=2, payload=dict(error))

    return _investigate


def _sweep(app: Any, n: int, *, stop_on_pause: bool) -> Any:
    status = at.get_status(app.state)
    status.reset(active=True, total=n, skipped=0)
    asyncio.run(
        asyncio.wait_for(
            at.run_auto_triage(
                app.state,
                targets=_health_targets(n),
                started_by="auto-triage:scheduler",
                stop_on_pause=stop_on_pause,
            ),
            timeout=30,
        )
    )
    return status


# ── the worker ────────────────────────────────────────────────────────────────


def test_the_scheduled_sweep_stops_after_two_gateway_connection_errors(
    at_settings: Settings,  # noqa: F811
    fake_es: AsyncMock,  # noqa: F811
) -> None:
    with _worker_app(at_settings, fake_es, _failing(GATEWAY_ERROR)) as (app, _client):
        status = _sweep(app, 8, stop_on_pause=True)
        assert status.failed == 2
        assert status.health.gateway_paused
        assert status.health.blocks_sweep()
        # The rule of five failed runs in a row did not open: two runs failed.
        assert not status.health.is_paused()
    # Six alerts of the sweep kept their run for the time after the outage.
    assert _count_investigations(at_settings) == 2


def test_another_error_keeps_the_rule_of_five_failed_runs(
    at_settings: Settings,  # noqa: F811
    fake_es: AsyncMock,  # noqa: F811
) -> None:
    """Negative control: a gateway that answers and refuses the request is no
    connection error. The sweep stops at five, as before."""
    with _worker_app(at_settings, fake_es, _failing(SCHEMA_ERROR)) as (app, _client):
        status = _sweep(app, 8, stop_on_pause=True)
        assert status.failed == 5
        assert not status.health.gateway_paused
        assert status.health.is_paused()
    assert _count_investigations(at_settings) == 5


def test_a_press_runs_every_alert_during_a_gateway_outage(
    at_settings: Settings,  # noqa: F811
    fake_es: AsyncMock,  # noqa: F811
) -> None:
    """Negative control: the pause stops the scheduled runs only."""
    with _worker_app(at_settings, fake_es, _failing(GATEWAY_ERROR)) as (app, _client):
        status = _sweep(app, 4, stop_on_pause=False)
        assert status.failed == 4
        assert status.health.gateway_paused
    assert _count_investigations(at_settings) == 4


# ── the scheduler ─────────────────────────────────────────────────────────────


def _paused_state() -> Any:
    state = types.SimpleNamespace(settings=types.SimpleNamespace(auto_triage_min_severity="high"))
    health = at.get_status(state).health
    for alert in ("a0", "a1"):
        health.record_failure(
            alert, "investigation_loop", "ModelHTTPError", message=GATEWAY_ERROR["message"]
        )
    assert health.gateway_paused
    return state


async def test_a_gateway_pause_plans_nothing_while_the_test_fails() -> None:
    state = _paused_state()
    planned: list[bool] = []

    async def _plan(*_a: Any, **_k: Any) -> Any:
        planned.append(True)
        return [], 0, []

    with (
        patch.object(at, "plan_targets", _plan),
        patch.object(
            at, "probe_gateway", AsyncMock(return_value=at.GatewayProbe(False, None))
        ) as probe,
    ):
        assert await at.start_config_sweep(state, started_by="auto-triage:scheduler") == 0
        assert await at.start_config_sweep(state, started_by="auto-triage:scheduler") == 0
    assert planned == []
    assert probe.await_count == 2  # one test for each scheduled run
    assert at.get_status(state).health.gateway_paused
    assert at.get_status(state).active is False


async def test_a_gateway_test_that_passes_ends_the_pause_and_the_sweep_runs() -> None:
    state = _paused_state()
    planned: list[bool] = []

    async def _plan(*_a: Any, **_k: Any) -> Any:
        planned.append(True)
        return [], 0, []

    with (
        patch.object(at, "plan_targets", _plan),
        patch.object(at, "probe_gateway", AsyncMock(return_value=at.GatewayProbe(True, 200))),
    ):
        await at.start_config_sweep(state, started_by="auto-triage:scheduler")
    health = at.get_status(state).health
    assert planned == [True]
    assert not health.gateway_paused
    # The two alerts that failed on the gateway have their runs back.
    assert health.heal_since("a0") is not None
    assert health.heal_since("a1") is not None


async def test_a_press_during_the_gateway_test_keeps_the_slot() -> None:
    """The gateway test takes time. A press that starts a batch in that time
    owns the slot, so the scheduler plans nothing beside it."""
    state = _paused_state()
    planned: list[bool] = []

    async def _plan(*_a: Any, **_k: Any) -> Any:
        planned.append(True)
        return [], 0, []

    async def _probe(_settings: Any) -> at.GatewayProbe:
        at.get_status(state).active = True  # the press
        return at.GatewayProbe(True, 200)

    with patch.object(at, "plan_targets", _plan), patch.object(at, "probe_gateway", _probe):
        assert await at.start_config_sweep(state, started_by="auto-triage:scheduler") == 0
    assert planned == []
    assert at.get_status(state).active is True
    assert not at.get_status(state).health.gateway_paused


async def test_no_gateway_test_runs_while_no_gateway_pause_is_open() -> None:
    """Negative control: a sweep with no pause makes no extra model call."""
    state = types.SimpleNamespace(settings=types.SimpleNamespace(auto_triage_min_severity="high"))

    async def _plan(*_a: Any, **_k: Any) -> Any:
        return [], 0, []

    with (
        patch.object(at, "plan_targets", _plan),
        patch.object(
            at, "probe_gateway", AsyncMock(return_value=at.GatewayProbe(True, 200))
        ) as probe,
    ):
        await at.start_config_sweep(state, started_by="auto-triage:scheduler")
    probe.assert_not_awaited()


# ── the alerts run again after the outage ─────────────────────────────────────


def _plan_now(settings: Settings, state: Any) -> list[str]:
    targets, _skipped, _acks = asyncio.run(at.plan_targets(state, time_range="24h", oql=None))
    return [t.alert_es_id for t in targets]


def test_an_alert_that_failed_on_the_gateway_runs_again_after_the_outage(
    at_settings: Settings,  # noqa: F811
) -> None:
    """The alert has three failed runs, so the retry limit holds it for six
    hours. After the recovery those runs no longer count, and the next sweep
    plans the alert. The retry limit itself did not change."""
    for minutes in (40, 30, 20):
        inv_id = _seed_failed_run(at_settings, "ev1", minutes_ago=minutes, kind="error")
        _seed_run_events(
            at_settings, inv_id, [{"sequence": 2, "kind": "error", "payload": GATEWAY_ERROR}]
        )
    es = AsyncMock()
    es.search.side_effect = _make_es_side_effect(events_resp=EVENTS_ES_RESPONSE)
    state = _FakeState(at_settings, es)
    assert _plan_now(at_settings, state) == []
    assert at.get_status(state).skipped_reasons == {"retry_limit": 1}

    # A restart lost the failures of the process. The store names the alert.
    stored = asyncio.run(at._gateway_failed_alerts(state))
    assert stored == ["ev1"]
    at.get_status(state).health.record_gateway_recovered(stored)
    assert _plan_now(at_settings, state) == ["ev1"]


def test_an_alert_that_failed_with_another_error_keeps_its_wait(
    at_settings: Settings,  # noqa: F811
) -> None:
    """Negative control: the recovery of the gateway forgives gateway errors
    only. The retry limit of 2026-10-30 holds every other failed alert."""
    for minutes in (40, 30, 20):
        inv_id = _seed_failed_run(at_settings, "ev1", minutes_ago=minutes, kind="error")
        _seed_run_events(
            at_settings, inv_id, [{"sequence": 2, "kind": "error", "payload": SCHEMA_ERROR}]
        )
    es = AsyncMock()
    es.search.side_effect = _make_es_side_effect(events_resp=EVENTS_ES_RESPONSE)
    state = _FakeState(at_settings, es)
    stored = asyncio.run(at._gateway_failed_alerts(state))
    assert stored == []
    at.get_status(state).health.record_gateway_recovered(stored)
    assert _plan_now(at_settings, state) == []
    assert at.get_status(state).skipped_reasons == {"retry_limit": 1}


def test_a_gateway_failure_older_than_one_day_is_not_read(
    at_settings: Settings,  # noqa: F811
) -> None:
    inv_id = _seed_failed_run(at_settings, "ev-old", minutes_ago=60 * 30, kind="error")
    _seed_run_events(
        at_settings, inv_id, [{"sequence": 2, "kind": "error", "payload": GATEWAY_ERROR}]
    )
    state = _FakeState(at_settings, AsyncMock())
    assert asyncio.run(at._gateway_failed_alerts(state)) == []


# ── the gateway test ──────────────────────────────────────────────────────────


def _probe_with(handler: Any, settings: Settings) -> tuple[at.GatewayProbe, list[httpx.Request]]:
    seen: list[httpx.Request] = []
    real_client = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    def _client(**kw: Any) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(_handler), **kw)

    with patch("httpx.AsyncClient", _client):
        ok = asyncio.run(at.probe_gateway(settings))
    return ok, seen


def test_the_gateway_test_is_one_small_completion(settings_kratos: Settings) -> None:
    ok, seen = _probe_with(lambda _r: httpx.Response(200, json={"choices": []}), settings_kratos)
    assert ok == at.GatewayProbe(True, 200)
    assert len(seen) == 1
    assert seen[0].url.path.endswith("/v1/chat/completions")
    body = json.loads(seen[0].content.decode())
    assert body["model"] == settings_kratos.analyst_model
    assert body["max_tokens"] == 1


CONNECT_BODY = {
    "error": {"message": "litellm.InternalServerError: Cannot connect to host 10.0.0.9:8888"}
}


@pytest.mark.parametrize(
    ("status", "body"),
    [(502, {"error": "bad gateway"}), (503, {"error": "no deployment"}), (500, CONNECT_BODY)],
)
def test_a_connection_failure_of_the_gateway_fails_the_test(
    settings_kratos: Settings, status: int, body: dict[str, Any]
) -> None:
    """The gateway answers and cannot reach the model engine. The pause holds."""
    ok, _seen = _probe_with(lambda _r: httpx.Response(status, json=body), settings_kratos)
    assert ok == at.GatewayProbe(False, status)


@pytest.mark.parametrize("status", [401, 404, 400, 429, 500])
def test_any_other_answer_means_that_the_gateway_is_reachable(
    settings_kratos: Settings, status: int
) -> None:
    """Review defect 5. A test that got 401 or 404 held the pause with no end:
    a changed key or a renamed model is no connection failure. The gateway is
    reachable, and the failure rules of the runs handle that error."""
    ok, _seen = _probe_with(
        lambda _r: httpx.Response(status, json={"error": "model not found"}), settings_kratos
    )
    assert ok == at.GatewayProbe(True, status)


async def test_an_answer_that_is_no_connection_failure_closes_the_pause_and_logs_its_status(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    state = _paused_state()
    probe = AsyncMock(return_value=at.GatewayProbe(True, 404))

    async def _plan(*_a: Any, **_k: Any) -> Any:
        return [], 0, []

    with (
        caplog.at_level(logging.INFO, logger="soc_ai.webui.autotriage"),
        patch.object(at, "plan_targets", _plan),
        patch.object(at, "probe_gateway", probe),
    ):
        await at.start_config_sweep(state, started_by="auto-triage:scheduler")
        await at.start_config_sweep(state, started_by="auto-triage:scheduler")
    assert not at.get_status(state).health.gateway_paused
    assert probe.await_count == 1  # the pause is closed, so the next sweep makes no test
    lines = [r.getMessage() for r in caplog.records if "HTTP 404" in r.getMessage()]
    assert len(lines) == 1, lines
    assert "The gateway answers" in lines[0]


def test_a_connection_error_fails_the_test_and_does_not_raise(settings_kratos: Settings) -> None:
    def _refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("All connection attempts failed", request=request)

    ok, _seen = _probe_with(_refuse, settings_kratos)
    assert ok == at.GatewayProbe(False, None)
