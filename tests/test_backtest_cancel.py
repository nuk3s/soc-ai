"""Cancel a running backtest (dogfood 2026-10-19, R5-I9).

A backtest runs N full investigations by the model, one after the other, and
had no cancel. An operator who started a 50-alert run by mistake waited for
all 50. ``POST /backtest/{id}/cancel`` now stops the run between alerts: the
alert in flight finishes, no new alert starts, and the run ends ``cancelled``
with the results of the alerts it finished.

The fake runner below stands in for the model. The cancel arrives while the
first alert is in flight, which is the path a cancel takes in practice: the
loop spends almost all of its time inside a replay.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import backtests as bt_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.webui import backtest as backtest_svc
from soc_ai.webui.backtest import HUMAN_FP, HUMAN_TP

from tests.test_backtest import (
    SAMPLING_ES_RESPONSE,
    _fake_investigate,
    bt_settings,  # noqa: F401  (fixture)
)

# ---------------------------------------------------------------------------
# The run loop, with a fake replay
# ---------------------------------------------------------------------------


def _samples(n: int) -> list[backtest_svc.BacktestSample]:
    return [
        backtest_svc.BacktestSample(
            alert_es_id=f"alert-{i}",
            rule_name=f"rule {i}",
            human_disposition=HUMAN_TP if i == 0 else HUMAN_FP,
        )
        for i in range(n)
    ]


async def _run(
    settings: Settings,
    *,
    samples: list[backtest_svc.BacktestSample],
    cancel_on: int | None,
) -> tuple[list[str], Any, backtest_svc.BacktestStatus]:
    """Run the loop with a fake replay. The cancel arrives during replay
    number ``cancel_on`` (1-based), while that alert is in flight."""
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)

    class _State:
        pass

    state = _State()
    state.settings = settings  # type: ignore[attr-defined]
    state.db_sessionmaker = maker  # type: ignore[attr-defined]

    async with maker() as db:
        row = await bt_svc.create(db, params={"window_days": 30}, started_by="admin")
    status = backtest_svc.get_status(state)
    status.reset(active=True, total=len(samples), backtest_id=row.id)

    started: list[str] = []

    async def _fake_replay(
        _state: Any, _ctx: Any, sample: backtest_svc.BacktestSample
    ) -> tuple[str | None, str | None]:
        started.append(sample.alert_es_id)
        if cancel_on is not None and len(started) == cancel_on:
            refusal = backtest_svc.request_cancel(state, row.id, by="admin")
            assert refusal is None
        await asyncio.sleep(0)
        return "false_positive", f"inv-{sample.alert_es_id}"

    with (
        patch.object(backtest_svc, "_replay_one", _fake_replay),
        patch.object(backtest_svc, "ctx_from_state", lambda _s: None),
    ):
        await backtest_svc.run_backtest(
            state, backtest_id=row.id, samples=samples, params={"window_days": 30}
        )
    async with maker() as db:
        got = await bt_svc.get(db, row.id)
    await engine.dispose()
    return started, got, status


class TestTheRunStopsBetweenAlerts:
    async def test_a_cancel_during_an_alert_starts_no_new_alert(
        self,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        started, got, status = await _run(bt_settings, samples=_samples(3), cancel_on=1)

        assert started == ["alert-0"], f"the run started another alert after the cancel: {started}"
        assert got is not None
        assert got.status == "cancelled"
        assert status.active is False

    async def test_the_run_keeps_the_results_it_finished(
        self,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        _started, got, _status = await _run(bt_settings, samples=_samples(4), cancel_on=2)

        assert got.status == "cancelled"
        assert got.sampled == 2
        results = got.results or {}
        assert [row["alert_id"] for row in results["rows"]] == ["alert-0", "alert-1"]
        assert results["cancel"] == {"after": 2, "of": 4, "by": "admin"}
        # The finished replays are scored: alert-0 was escalated and the fake
        # called it a false positive, alert-1 agrees.
        assert results["metrics"]["counts"]["total"] == 2
        assert results["metrics"]["missed_tp"] == 1

    async def test_control_with_no_cancel_every_alert_runs(
        self,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        started, got, _status = await _run(bt_settings, samples=_samples(3), cancel_on=None)

        assert started == ["alert-0", "alert-1", "alert-2"]
        assert got.status == "complete"
        assert "cancel" not in (got.results or {})

    async def test_a_cancel_during_the_last_alert_leaves_a_complete_run(
        self,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        """Nothing was left to skip, so the run measured the whole sample."""
        started, got, _status = await _run(bt_settings, samples=_samples(3), cancel_on=3)

        assert started == ["alert-0", "alert-1", "alert-2"]
        assert got.status == "complete"


class TestTheCancelRequest:
    def test_a_second_request_is_refused(self) -> None:
        class _State:
            pass

        state = _State()
        backtest_svc.get_status(state).reset(active=True, total=3, backtest_id="bt-1")

        assert backtest_svc.request_cancel(state, "bt-1", by="admin") is None
        assert backtest_svc.request_cancel(state, "bt-1", by="admin") == "cancel_requested"

    def test_a_run_that_is_not_live_is_refused(self) -> None:
        class _State:
            pass

        state = _State()
        backtest_svc.get_status(state).reset(active=True, total=3, backtest_id="bt-1")

        assert backtest_svc.request_cancel(state, "bt-other", by="admin") == "not_running"

    def test_a_new_run_clears_the_old_request(self) -> None:
        class _State:
            pass

        state = _State()
        status = backtest_svc.get_status(state)
        status.reset(active=True, total=3, backtest_id="bt-1")
        assert backtest_svc.request_cancel(state, "bt-1", by="admin") is None
        status.reset(active=True, total=3, backtest_id="bt-2")

        assert status.cancel_requested is False
        assert backtest_svc.request_cancel(state, "bt-2", by="admin") is None


# ---------------------------------------------------------------------------
# The route, against a live run with a fake model
# ---------------------------------------------------------------------------


class _Gate:
    """Holds the first replay in flight until the test opens the gate.

    A threading event, because the test thread drives the client and the app
    runs in the client's own loop. The fake waits for it in a worker thread,
    so the loop stays free to serve the cancel request.
    """

    def __init__(self) -> None:
        self.open = threading.Event()
        self.started: list[str] = []

    async def investigate(self, alert_id: str, **kwargs: Any) -> AsyncIterator[Any]:
        self.started.append(alert_id)
        await asyncio.to_thread(self.open.wait)
        async for event in _fake_investigate(alert_id, **kwargs):
            yield event


@pytest.fixture
def gated(bt_settings: Settings) -> Iterator[tuple[TestClient, _Gate]]:  # noqa: F811
    gate = _Gate()
    fake_es = AsyncMock()

    async def _search(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return SAMPLING_ES_RESPONSE

    fake_es.search.side_effect = _search
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=bt_settings),
        patch("soc_ai.api.runner.investigate", gate.investigate),
    ):
        app = create_app()
        with TestClient(app) as client:
            app.state.audit = AsyncMock()
            yield client, gate
            gate.open.set()


def _wait(predicate: Any, *, deadline_s: float = 6.0) -> None:
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("the condition did not hold before the deadline")


def _settled(client: TestClient) -> dict[str, Any]:
    out: dict[str, Any] = {}

    def _done() -> bool:
        nonlocal out
        out = client.get("/api/v1/backtest").json()
        return not out["active"]

    _wait(_done)
    return out


class TestTheCancelRoute:
    def test_a_cancel_stops_the_run_and_keeps_what_finished(
        self, gated: tuple[TestClient, _Gate]
    ) -> None:
        client, gate = gated
        started = client.post("/api/v1/backtest", json={"window_days": 30, "sample_size": 20})
        assert started.status_code == 200
        bid = started.json()["backtest_id"]
        assert started.json()["total"] == 3
        _wait(lambda: len(gate.started) == 1)

        resp = client.post(f"/api/v1/backtest/{bid}/cancel")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["active"] is True
        assert body["cancel_requested"] is True

        # A reload reads the request back from the server.
        reloaded = client.get("/api/v1/backtest").json()
        assert reloaded["active"] is True
        assert reloaded["cancel_requested"] is True

        gate.open.set()
        done = _settled(client)

        assert gate.started == [gate.started[0]], (
            f"the run started a new alert after the cancel: {gate.started}"
        )
        assert done["status"] == "cancelled"
        assert done["sampled"] == 1
        assert done["cancel_requested"] is False
        assert len(done["results"]["rows"]) == 1
        assert done["results"]["cancel"]["after"] == 1
        assert done["results"]["cancel"]["of"] == 3
        assert done["skipped_reason"].endswith(
            "An operator cancelled the backtest after 1 of 3 alerts."
        )

    def test_a_second_cancel_answers_409(self, gated: tuple[TestClient, _Gate]) -> None:
        client, gate = gated
        bid = client.post("/api/v1/backtest", json={"window_days": 30}).json()["backtest_id"]
        _wait(lambda: len(gate.started) == 1)
        assert client.post(f"/api/v1/backtest/{bid}/cancel").status_code == 200

        again = client.post(f"/api/v1/backtest/{bid}/cancel")

        assert again.status_code == 409
        assert again.json()["detail"]["reason"] == "cancel_requested"
        assert again.json()["detail"]["hint"]

    def test_a_cancel_of_a_finished_run_answers_409(self, gated: tuple[TestClient, _Gate]) -> None:
        client, gate = gated
        gate.open.set()
        bid = client.post("/api/v1/backtest", json={"window_days": 30}).json()["backtest_id"]
        assert _settled(client)["status"] == "complete"

        resp = client.post(f"/api/v1/backtest/{bid}/cancel")

        assert resp.status_code == 409
        assert resp.json()["detail"]["reason"] == "not_running"
        assert "complete" in resp.json()["detail"]["hint"]

    def test_a_cancel_of_an_unknown_run_answers_404(self, gated: tuple[TestClient, _Gate]) -> None:
        client, _gate = gated
        resp = client.post("/api/v1/backtest/NOSUCHRUN/cancel")
        assert resp.status_code == 404
        assert resp.json()["detail"]["reason"] == "backtest_not_found"

    def test_the_cancel_is_audited(self, gated: tuple[TestClient, _Gate]) -> None:
        client, gate = gated
        bid = client.post("/api/v1/backtest", json={"window_days": 30}).json()["backtest_id"]
        _wait(lambda: len(gate.started) == 1)

        assert client.post(f"/api/v1/backtest/{bid}/cancel").status_code == 200

        audit = client.app.state.audit  # type: ignore[attr-defined]
        kinds = [call.args[1] for call in audit.log_kind.await_args_list]
        assert kinds == ["backtest_cancelled"]
        payload = audit.log_kind.await_args_list[0].args[2]
        assert payload["backtest_id"] == bid
        assert payload["total"] == 3

    def test_a_refused_cancel_writes_no_audit_record(self, gated: tuple[TestClient, _Gate]) -> None:
        client, gate = gated
        gate.open.set()
        bid = client.post("/api/v1/backtest", json={"window_days": 30}).json()["backtest_id"]
        _settled(client)

        assert client.post(f"/api/v1/backtest/{bid}/cancel").status_code == 409

        audit = client.app.state.audit  # type: ignore[attr-defined]
        assert audit.log_kind.await_args_list == []


def test_the_cancel_route_is_admin_only() -> None:
    from soc_ai.api.webui._shared import require_admin_api, router

    route = next(
        r
        for r in router.routes
        if getattr(r, "path", "").endswith("/backtest/{backtest_id}/cancel")
        and "POST" in getattr(r, "methods", set())
    )
    deps = [d.dependency for d in route.dependencies]  # type: ignore[attr-defined]
    assert require_admin_api in deps


def test_the_audit_kind_is_declared() -> None:
    import typing

    from soc_ai.audit.schemas import AuditKind

    assert "backtest_cancelled" in typing.get_args(AuditKind)


class TestTheStatusReadHasNoTornState:
    def test_a_run_that_ends_during_the_status_read_never_reads_running_and_idle(
        self, gated: tuple[TestClient, _Gate]
    ) -> None:
        """The status route read the stored row, then checked ``live.active``.

        A run that ended between the two reads answered status "running" with
        active false. That failed the release run of v1.6.0 on a loaded runner.
        The route now reads the live status first. This test forces the
        interleaving: the run ends while the route reads the store.
        """
        client, gate = gated
        started = client.post("/api/v1/backtest", json={"window_days": 30, "sample_size": 20})
        assert started.status_code == 200
        _wait(lambda: len(gate.started) == 1)

        live = backtest_svc.get_status(client.app.state)
        real_latest = bt_svc.latest

        async def _latest_then_the_run_ends(db: Any) -> Any:
            row = await real_latest(db)
            live.active = False  # the run ends right after the store read
            return row

        with patch.object(bt_svc, "latest", _latest_then_the_run_ends):
            body = client.get("/api/v1/backtest").json()
        live.active = True  # give the run back its own state
        gate.open.set()
        _settled(client)

        torn = body["active"] is False and body["status"] == "running"
        assert not torn, f"the route read a running row as idle: {body}"
