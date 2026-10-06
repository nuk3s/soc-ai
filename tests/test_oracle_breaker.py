"""The Oracle route pause (soc_ai.oracle.breaker).

From 2026-09-10 to 2026-09-14 the gateway answered every Oracle call with HTTP
500 and the message that the subscription behind the route had hit its weekly
limit, with the reset time. The client retried each escalation three times:
69 calls to a route that could not answer, and no surface said why.

Now a quota answer, or three server errors in a row, pauses the route until the
reset time the gateway names, or for one hour. Each skipped escalation is an
``oracle_skipped`` event. The doctor and the preflight gain an "oracle route"
row, and the bell gets one row per pause.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic import SecretStr
from pydantic_ai.models.test import TestModel
from soc_ai import doctor
from soc_ai.agent.orchestrator import investigate
from soc_ai.config import Settings
from soc_ai.oracle import breaker
from soc_ai.oracle.breaker import BREAKER, parse_reset_time, parse_retry_after, route_key
from soc_ai.oracle.client import adjudicate
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation, InvestigationEvent
from soc_ai.triage_models import TriageReport
from sqlalchemy import func, select

from tests.test_agent import _make_ctx, _malware_signal_enriched

T0 = datetime(2026, 9, 10, 20, 47, tzinfo=UTC)
RESET = datetime(2026, 9, 14, 5, 0, tzinfo=UTC)

WEEKLY_LIMIT_BODY = json.dumps(
    {
        "error": {
            "message": (
                "litellm.InternalServerError: AnthropicException - api_error: Claude Code "
                "returned an error result: You've hit your weekly limit · resets Sep 14, "
                "5am (UTC). No fallback model group found for original model_group=oracle"
            ),
            "code": "500",
        }
    }
)

VERDICT = json.dumps(
    {
        "verdict": "false_positive",
        "confidence": 0.8,
        "summary": "Benign.",
        "reasoning": "Known scanner.",
    }
)


class _Clock:
    """A settable clock for the breaker."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Any:
    c = _Clock(T0)
    with patch("soc_ai.oracle.breaker._now", c):
        yield c


def _settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://gateway.example.test:4000",
        "oracle_enabled": True,
        "oracle_model": "claude-sonnet-4-6",
        "oracle_timeout_s": 30.0,
    }
    base.update(kw)
    return Settings(**base)


def _enriched() -> Any:
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(id="alert-001", severity_label="low"),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


def _report() -> TriageReport:
    return TriageReport(
        verdict="false_positive",
        confidence=0.75,
        summary="Local summary.",
        citations=["alert.severity_label"],
        recommended_actions=[],
    )


def _gateway(handler: Callable[[httpx.Request], httpx.Response], seen: list[httpx.Request]) -> Any:
    real_client = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    def _client(**kw: Any) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(_handler), **kw)

    return patch("httpx.AsyncClient", _client)


async def _adjudicate(settings: Settings) -> tuple[Any, dict[str, Any]]:
    ctx = MagicMock()
    ctx.settings = settings
    failure: dict[str, Any] = {}
    with patch("soc_ai.oracle.client.asyncio.sleep", AsyncMock()):
        result = await adjudicate(
            ctx,
            enriched=_enriched(),
            local_report=_report(),
            transcript_text="",
            failure_out=failure,
        )
    return result, failure


# ── The reset time ───────────────────────────────────────────────────────────


def test_the_production_message_names_the_reset() -> None:
    assert parse_reset_time(WEEKLY_LIMIT_BODY, T0) == RESET


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("usage limit, resets at 2026-09-14T05:00:00Z", RESET),
        ("rate limited. Try again in 90 seconds.", T0 + timedelta(seconds=90)),
        ("limit reached. Retry after 5 minutes", T0 + timedelta(minutes=5)),
        ("limit reached, resets at 11pm (UTC)", T0.replace(hour=23, minute=0)),
        ("weekly limit, resets Sep 14, 5:30pm (UTC)", RESET.replace(hour=17, minute=30)),
        # A reset in the past, or a time zone that does not resolve, names nothing.
        ("weekly limit, resets Sep 9, 5am (UTC)", datetime(2027, 9, 9, 5, tzinfo=UTC)),
        ("weekly limit, resets Sep 14, 5am (Nowhere/Land)", None),
        ("rate limit exceeded", None),
    ],
)
def test_the_reset_forms(text: str, expected: datetime | None) -> None:
    assert parse_reset_time(text, T0) == expected


def test_the_retry_after_header() -> None:
    assert parse_retry_after("120", T0) == T0 + timedelta(seconds=120)
    assert parse_retry_after("Mon, 14 Sep 2026 05:00:00 GMT", T0) == RESET
    assert parse_retry_after("soon", T0) is None


# ── The client ───────────────────────────────────────────────────────────────


async def test_three_500s_open_the_breaker_calls_stop_and_a_call_after_the_reset_runs(
    clock: _Clock,
) -> None:
    settings = _settings()
    seen: list[httpx.Request] = []
    answers: list[httpx.Response] = [httpx.Response(500, text="Internal Server Error")] * 3
    answers.append(httpx.Response(200, json={"choices": [{"message": {"content": VERDICT}}]}))
    it = iter(answers)
    with _gateway(lambda _r: next(it), seen):
        result, failure = await _adjudicate(settings)
        assert result is None
        assert len(seen) == 3
        assert (failure["reason"], failure["error_class"]) == ("gateway_error", "5xx")
        assert failure["paused_until"] == "2026-09-10T21:47:00Z"
        assert failure["breaker_opened"] is True

        # Calls stop: the next escalation in the pause makes no call.
        clock.now = T0 + timedelta(minutes=30)
        result2, failure2 = await _adjudicate(settings)
        assert result2 is None
        assert len(seen) == 3
        assert (failure2["reason"], failure2["error_class"]) == ("oracle_paused", "paused")
        assert failure2["paused_until"] == "2026-09-10T21:47:00Z"
        assert "breaker_opened" not in failure2

        # After the reset time a call runs and answers.
        clock.now = T0 + timedelta(hours=1, minutes=1)
        result3, _failure3 = await _adjudicate(settings)
    assert result3 is not None
    assert len(seen) == 4
    assert BREAKER.open_until(route_key(settings)) is None


async def test_a_weekly_limit_opens_the_breaker_at_once_until_the_named_reset(
    clock: _Clock,
) -> None:
    settings = _settings()
    seen: list[httpx.Request] = []
    with _gateway(lambda _r: httpx.Response(500, text=WEEKLY_LIMIT_BODY), seen):
        result, failure = await _adjudicate(settings)
    assert result is None
    # One call, not three: a retry cannot answer a weekly limit.
    assert len(seen) == 1
    assert (failure["reason"], failure["error_class"], failure["http_status"]) == (
        "gateway_error",
        "quota",
        500,
    )
    assert failure["paused_until"] == "2026-09-14T05:00:00Z"
    state = BREAKER.state(route_key(settings))
    assert (state.reason, state.reset_named) == ("quota", True)


async def test_a_new_oracle_model_is_a_new_route(clock: _Clock) -> None:
    """The pause belongs to one route. A switch to another model calls at once."""
    paused = _settings()
    BREAKER.record_failure(route_key(paused), error_class="quota", message="weekly limit")
    other = _settings(oracle_model="other-oracle")
    seen: list[httpx.Request] = []
    ok = httpx.Response(200, json={"choices": [{"message": {"content": VERDICT}}]})
    with _gateway(lambda _r: ok, seen):
        result, _f = await _adjudicate(other)
    assert result is not None
    assert len(seen) == 1


def test_a_transport_error_or_a_4xx_never_pauses(clock: _Clock) -> None:
    route = "r"
    for cls in ("timeout", "transport", "4xx", "4xx", "4xx", "unparseable"):
        assert BREAKER.record_failure(route, error_class=cls) is False
    assert BREAKER.open_until(route) is None


def test_an_answer_between_500s_resets_the_run(clock: _Clock) -> None:
    route = "r"
    BREAKER.record_failure(route, error_class="5xx")
    BREAKER.record_failure(route, error_class="5xx")
    BREAKER.record_answer(route)
    assert BREAKER.record_failure(route, error_class="5xx") is False
    assert BREAKER.open_until(route) is None


# ── The orchestrator ─────────────────────────────────────────────────────────


async def _run_escalating(settings: Settings, seen: list[httpx.Request]) -> list[Any]:
    """A run whose local verdict escalates, with the real Oracle client."""
    ctx = _make_ctx(settings)
    local_fp = TriageReport(
        verdict="false_positive",
        confidence=0.75,
        summary="Local verdict: benign.",
        citations=["alert.severity_label"],
        recommended_actions=[],
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=local_fp),
        ),
        patch("soc_ai.oracle.client.asyncio.sleep", AsyncMock()),
        _gateway(lambda _r: httpx.Response(500, text=WEEKLY_LIMIT_BODY), seen),
    ):
        return [ev async for ev in investigate("beacon-001", ctx=ctx)]


async def test_a_pause_skips_the_escalation_and_notifies_once(
    settings_kratos: Settings, clock: _Clock
) -> None:
    settings_kratos.investigate_when_unsure = False
    settings_kratos.oracle_enabled = True
    seen: list[httpx.Request] = []
    fire = AsyncMock()
    with patch("soc_ai.notify.fire_safe", fire):
        first = await _run_escalating(settings_kratos, seen)
        clock.now = T0 + timedelta(hours=2)
        second = await _run_escalating(settings_kratos, seen)

    # One Oracle call in two escalations. The pipeline's other gateway reads
    # (the model info probe) are not Oracle calls.
    oracle_calls = [r for r in seen if r.url.path.endswith("/chat/completions")]
    assert len(oracle_calls) == 1
    assert json.loads(oracle_calls[0].content)["model"] == settings_kratos.oracle_model
    failed = next(e for e in first if e.kind == "oracle_adjudication_failed")
    assert failed.payload["error_class"] == "quota"
    assert failed.payload["paused_until"] == "2026-09-14T05:00:00Z"

    kinds = [e.kind for e in second]
    assert "oracle_escalation" not in kinds
    assert "oracle_adjudication_failed" not in kinds
    skipped = next(e for e in second if e.kind == "oracle_skipped")
    assert skipped.payload["reason"] == "oracle_paused"
    assert skipped.payload["pause_reason"] == "quota"
    assert skipped.payload["paused_until"] == "2026-09-14T05:00:00Z"
    assert skipped.payload["escalation_reason"] == "needs_more_info"
    assert "weekly limit" in skipped.payload["message"]
    # The local verdict stands.
    report = next(e for e in second if e.kind == "triage_report")
    assert report.payload["verdict"] == skipped.payload["local_verdict"]

    # One webhook message for the pause, from the call that opened it.
    assert fire.await_count == 1
    event = fire.await_args.args[0]
    assert event.kind == "oracle_paused"
    assert event.title == "Oracle calls paused until 2026-09-14 05:00:00 UTC"


# ── The doctor and the preflight ─────────────────────────────────────────────


async def test_the_doctor_row_is_info_when_the_oracle_is_off() -> None:
    rows = await doctor.check_oracle_route(_settings(oracle_enabled=False))
    assert [(r.name, r.status) for r in rows] == [("oracle route", "INFO")]


async def test_the_doctor_row_warns_while_the_breaker_is_open(clock: _Clock) -> None:
    settings = _settings()
    BREAKER.record_failure(
        route_key(settings),
        error_class="quota",
        message="You've hit your weekly limit",
        reset_text=WEEKLY_LIMIT_BODY,
    )
    rows = await doctor.check_oracle_route(settings, now=T0)
    assert [(r.name, r.status) for r in rows] == [("oracle route", "WARN")]
    assert "until 2026-09-14 05:00:00 UTC" in rows[0].detail
    assert "usage limit" in rows[0].detail


async def _seed_event(settings: Settings, kind: str, payload: dict[str, Any]) -> None:
    engine = make_engine(settings)
    await run_migrations(engine)
    try:
        async with make_sessionmaker(engine)() as db:
            n = await db.scalar(select(func.count()).select_from(Investigation))
            inv_id = f"route{int(n or 0):027d}"
            db.add(Investigation(id=inv_id, alert_es_id="a", status="complete"))
            db.add(
                InvestigationEvent(investigation_id=inv_id, sequence=1, kind=kind, payload=payload)
            )
            await db.commit()
    finally:
        await engine.dispose()


async def test_the_doctor_reads_the_store_from_another_process(
    tmp_path: Path, clock: _Clock
) -> None:
    """The CLI doctor has an empty breaker. The stored events still tell."""
    settings = _settings(soc_ai_data_dir=tmp_path)
    engine = make_engine(settings)
    await run_migrations(engine)
    await engine.dispose()
    rows = await doctor.check_oracle_route(settings, now=T0)
    assert (rows[0].status, rows[0].detail) == ("INFO", "no Oracle call is on record yet.")

    await _seed_event(settings, "oracle_adjudication", {"oracle_verdict": "false_positive"})
    rows = await doctor.check_oracle_route(settings, now=T0)
    assert rows[0].status == "PASS"

    await _seed_event(
        settings,
        "oracle_adjudication_failed",
        {
            "reason": "gateway_error",
            "error_class": "quota",
            "http_status": 500,
            "message": "You've hit your weekly limit",
            "paused_until": "2026-09-14T05:00:00Z",
        },
    )
    rows = await doctor.check_oracle_route(settings, now=T0)
    assert rows[0].status == "WARN"
    assert "until 2026-09-14 05:00:00 UTC" in rows[0].detail

    # A refusal made no call: it says nothing about the route.
    await _seed_event(
        settings,
        "oracle_adjudication_failed",
        {"reason": "residue_refusal", "error_class": "refused"},
    )
    rows = await doctor.check_oracle_route(settings, now=T0)
    assert rows[0].status == "WARN"

    # After the reset the pause is over.
    rows = await doctor.check_oracle_route(settings, now=RESET + timedelta(minutes=1))
    assert rows[0].status == "INFO"
    assert "ended" in rows[0].detail


async def test_the_preflight_carries_the_oracle_route_row(
    settings_kratos: Settings, clock: _Clock
) -> None:
    from tests.test_preflight_api import _StubAuth, _StubElastic

    settings_kratos.oracle_enabled = True
    BREAKER.record_failure(route_key(settings_kratos), error_class="quota", message="limit")
    with (
        patch("soc_ai.doctor.make_auth", return_value=_StubAuth()),
        patch("soc_ai.doctor.ElasticClient", return_value=_StubElastic()),
        patch("soc_ai.doctor.list_gateway_models", AsyncMock(return_value=([], None))),
        patch("soc_ai.doctor._classify_endpoint", return_value=("", "resolves and connects")),
    ):
        results = await doctor.run_doctor(settings_kratos, include_fitness=False)
    rows = [r for r in results if r.name == "oracle route"]
    assert len(rows) == 1
    assert rows[0].status == "WARN"


# ── The bell ─────────────────────────────────────────────────────────────────


def test_the_bell_gets_one_row_per_pause(settings_kratos: Settings, clock: _Clock) -> None:
    from tests.test_investigations_query import _client

    settings = settings_kratos.model_copy(update={"oracle_enabled": True})
    route = route_key(settings)
    gen = _client(settings)
    client = next(gen)
    try:
        assert not [
            n for n in client.get("/api/v1/notifications").json() if n["id"].startswith("oracle")
        ]
        assert BREAKER.record_failure(route, error_class="quota", message="weekly limit") is True
        rows = [
            n for n in client.get("/api/v1/notifications").json() if n["id"].startswith("oracle")
        ]
        assert len(rows) == 1
        assert rows[0]["title"].startswith("Oracle calls paused until")
        first_id = rows[0]["id"]
        # A second limit answer in the same pause adds no row and keeps the id.
        assert BREAKER.record_failure(route, error_class="quota", message="weekly limit") is False
        rows = [
            n for n in client.get("/api/v1/notifications").json() if n["id"].startswith("oracle")
        ]
        assert [r["id"] for r in rows] == [first_id]
        # The setting turns the row off.
        client.app.state.settings.notify_on_oracle_failure = False
        assert not [
            n for n in client.get("/api/v1/notifications").json() if n["id"].startswith("oracle")
        ]
    finally:
        gen.close()


def test_the_pause_clock_is_the_breaker_clock(clock: _Clock) -> None:
    assert breaker._now() == T0


def test_the_webhook_event_follows_the_setting() -> None:
    from soc_ai import notify

    on = notify.event_for_oracle_paused(
        pause_reason="quota", until="2026-09-14T05:00:00Z", settings=_settings()
    )
    assert on is not None and on.kind == "oracle_paused"
    assert "usage limit" in on.body
    off = notify.event_for_oracle_paused(
        pause_reason="quota",
        until="2026-09-14T05:00:00Z",
        settings=_settings(notify_on_oracle_failure=False),
    )
    assert off is None
    assert notify._trigger_enabled(_settings(), "oracle_paused") is True
