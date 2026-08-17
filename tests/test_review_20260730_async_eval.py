"""Regression tests for the 2026-07-30 review, bucket B07_async_eval.

Covers four findings in ``soc_ai/main.py`` + ``soc_ai/eval/quality.py``:

* **F44** — the regression-alarm single-flip floor must scale to the agreement
  denominator (``n_classified``), not ``n_ok``: an ``unknown`` critique counts
  toward n_ok but not toward the rate, so ``classified < n_ok`` and one flipped
  verdict moves agreement_rate by 1/classified (> 1/n_ok) — which the old floor
  failed to absorb.
* **F18** — the hunt scheduler must stamp ``last_run_at`` only AFTER a spawn
  succeeds; a spawn rejected at the concurrency ceiling must stay unstamped so
  the schedule retries next wake instead of silently losing a cycle.
* **F33** — the periodic reaper must NOT flip a still-running backtest / long
  hunt to ``error`` at the 30-minute investigation age; each gets a reap age
  derived from its own ceiling.
* **F10** — a pending 'Chat about this hunt' turn cancelled at shutdown (the
  drain the lifespan now performs) resolves its pending row to ``error`` via the
  HuntChatManager done-callback backstop, rather than staying wedged 'pending'.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai import main as main_mod
from soc_ai.config import Settings
from soc_ai.eval.quality import (
    SnapshotMetrics,
    TrendPoint,
    compute_snapshot_metrics,
    detect_regression,
)
from soc_ai.eval.report import aggregate
from soc_ai.main import _hunt_schedule_loop, _reaper_loop
from soc_ai.store import backtests as bt_svc
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Backtest, Hunt, Investigation
from soc_ai.webui.hunt_console_manager import HuntChatManager, _hunt_chat_resolve_if_pending

# ==================================================================== #
# F44 — regression floor scales to n_classified, not n_ok
# ==================================================================== #


def _sm(**overrides: Any) -> SnapshotMetrics:
    base: dict[str, Any] = {
        "mode": "graded",
        "n_ok": 5,
        "n_error": 0,
        "agreement_rate": 0.8,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {"false_positive": 5},
        "latency_p50_ms": 60_000,
        "n_classified": 5,
    }
    base.update(overrides)
    return SnapshotMetrics(**base)


def _hist(agreement: float, n: int = 3) -> list[TrendPoint]:
    return [TrendPoint(agreement_rate=agreement, fallback_rate=0.0) for _ in range(n)]


def test_f44_single_flip_with_unknown_critique_does_not_alarm() -> None:
    """n_ok=5 but one critique parsed 'unknown' -> classified=4. Verdicts 3/4 ->
    2/4 is exactly ONE flip (agreement 0.50). Against a 0.75 median with the
    default alarm_drop=0.15 the floor must be 1/4 = 0.25, absorbing the 0.25
    drop. The old 1/n_ok = 0.20 floor let this single flip page on-call."""
    new = _sm(agreement_rate=0.50, n_ok=5, n_classified=4)
    reasons = detect_regression(new, _hist(0.75), alarm_drop=0.15)
    assert reasons == []


def test_f44_two_flips_still_alarms() -> None:
    """Two flips at classified=4 (3/4 -> 1/4 = 0.25, a real 0.50 drop) is a
    genuine regression and must still fire — the floor only suppresses ONE."""
    new = _sm(agreement_rate=0.25, n_ok=5, n_classified=4)
    reasons = detect_regression(new, _hist(0.75), alarm_drop=0.15)
    assert any("agreement_rate" in r for r in reasons)


def test_f44_falls_back_to_n_ok_when_classified_absent() -> None:
    """An older snapshot with no classified count (default 0) keeps the pre-fix
    n_ok behavior: one flip at n_ok=5 (floor 0.20) does not alarm."""
    new = _sm(agreement_rate=0.6, n_ok=5, n_classified=0)
    assert detect_regression(new, _hist(0.8), alarm_drop=0.15) == []


def _row(alert_id: str, *, agreement: str) -> dict[str, Any]:
    return {
        "alert_id": alert_id,
        "bundle_path": f"evals/x/{alert_id}",
        "verdict": "false_positive",
        "confidence": 0.8,
        "agreement": agreement,
        "retask_count": 0,
        "investigation_ms": 60_000,
        "claude_ms": None,
        "input_tokens": None,
        "output_tokens": None,
        "cache_read_tokens": None,
        "error": None,
        "citations": [],
        "is_fallback": False,
        "is_synth": False,
        "synth_scenario_id": None,
    }


def test_f44_compute_metrics_excludes_unknown_from_n_classified() -> None:
    """compute_snapshot_metrics must populate n_classified from yes/no/partial
    only — an 'unknown' critique counts toward n_ok but not the denominator."""
    rows = [
        _row("a", agreement="yes"),
        _row("b", agreement="no"),
        _row("c", agreement="unknown"),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    assert m.n_ok == 3
    assert m.n_classified == 2
    assert m.agreement_rate == pytest.approx(0.5)  # 1 yes / 2 classified


# ==================================================================== #
# F18 — scheduler stamps last_run_at only after a successful spawn
# ==================================================================== #


class _FakeDbCtx:
    """Minimal async-context-manager stand-in for a DB session."""

    async def __aenter__(self) -> Any:
        return object()

    async def __aexit__(self, *a: Any) -> bool:
        return False


async def _run_hunt_sched_iterations(
    monkeypatch: pytest.MonkeyPatch, app: SimpleNamespace, n: int = 1
) -> None:
    """Bound the otherwise-``while True`` hunt scheduler to ``n`` body iterations
    (same sleep-patch trick as tests/test_main_scheduler.py)."""
    real_sleep = asyncio.sleep
    calls = {"n": 0}

    async def _sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] <= n:
            return None
        raise asyncio.CancelledError()

    monkeypatch.setattr(main_mod.asyncio, "sleep", _sleep)
    try:
        with contextlib.suppress(asyncio.CancelledError):
            await _hunt_schedule_loop(app)
    finally:
        monkeypatch.setattr(main_mod.asyncio, "sleep", real_sleep)


@pytest.mark.asyncio
async def test_f18_rejected_spawn_leaves_schedule_unstamped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two due schedules: the first spawns, the second is rejected at the
    concurrency ceiling (start() -> None). Only the schedule that actually
    spawned may be stamped; the rejected one must stay unstamped so it retries
    next wake. BEFORE the fix, mark_ran ran before start() for BOTH."""
    app = SimpleNamespace(
        state=SimpleNamespace(
            settings=SimpleNamespace(hunt_schedules_enabled=True),
            db_sessionmaker=_FakeDbCtx,
        )
    )
    due = [
        SimpleNamespace(id=1, objective="hunt beacons"),
        SimpleNamespace(id=2, objective="hunt c2"),
    ]
    marked: list[int] = []

    async def _due(_db: Any, _now: Any) -> list[Any]:
        return list(due)

    async def _mark(_db: Any, sched_id: int, _now: Any) -> None:
        marked.append(sched_id)

    class _Manager:
        def __init__(self) -> None:
            self.calls = 0

        async def start(
            self, _state: Any, *, objective: str, started_by: str, kind: str
        ) -> str | None:
            self.calls += 1
            return "H1" if self.calls == 1 else None  # second rejected at ceiling

    mgr = _Manager()
    monkeypatch.setattr("soc_ai.store.hunt_schedules.due_schedules", _due)
    monkeypatch.setattr("soc_ai.store.hunt_schedules.mark_ran", _mark)
    monkeypatch.setattr("soc_ai.webui.hunt_console_manager.get_manager", lambda _s: mgr)

    await _run_hunt_sched_iterations(monkeypatch, app)

    assert mgr.calls == 2  # both schedules were attempted
    assert marked == [1]  # only the successful spawn stamped its clock


# ==================================================================== #
# F33 — reaper spares in-flight backtests / long hunts
# ==================================================================== #


async def _run_reaper_once(monkeypatch: pytest.MonkeyPatch, maker: Any, settings: Settings) -> None:
    real_sleep = asyncio.sleep
    calls = {"n": 0}

    async def _sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] <= 1:
            return None  # first wake -> run the body once
        raise asyncio.CancelledError()  # unwind after one iteration

    monkeypatch.setattr(main_mod.asyncio, "sleep", _sleep)
    try:
        with contextlib.suppress(asyncio.CancelledError):
            await _reaper_loop(maker, settings)
    finally:
        monkeypatch.setattr(main_mod.asyncio, "sleep", real_sleep)


@pytest.mark.asyncio
async def test_f33_reaper_spares_running_backtest_and_hunt(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hunt and a backtest 45 minutes old are still well inside their own
    ceilings (hunt ~60 min, backtest ~13 h at defaults), so the periodic reaper
    must leave them 'running'. An investigation of the same age is past the
    30-min investigation age and IS reaped — proving the sweep still works and
    only the derived ages changed."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)

    backdate = utcnow() - timedelta(minutes=45)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="beacon hunt", started_by="t")
        bt = await bt_svc.create(db, params={"sample_size": 20}, started_by="t")
        inv = await inv_svc.create(db, alert_es_id="ev-f33", started_by="t")
        for row in (hunt, bt, inv):
            row.created_at = backdate
        await db.commit()
        hunt_id, bt_id, inv_id = hunt.id, bt.id, inv.id

    await _run_reaper_once(monkeypatch, maker, settings_kratos)

    async with maker() as db:
        h = await db.get(Hunt, hunt_id)
        b = await db.get(Backtest, bt_id)
        i = await db.get(Investigation, inv_id)
        assert h is not None and h.status == "running"  # spared (< derived hunt age)
        assert b is not None and b.status == "running"  # spared (< derived bt age)
        assert i is not None and i.status == "error"  # reaped (> 30-min inv age)
    await engine.dispose()


# ==================================================================== #
# F10 — a hunt-chat turn cancelled at shutdown resolves its pending row
# ==================================================================== #


@pytest.mark.asyncio
async def test_f10_shutdown_drain_resolves_pending_hunt_chat(
    settings_kratos: Settings,
) -> None:
    """Mirrors the lifespan shutdown drain for the hunt chat manager (the new
    ``_worker_tasks.extend(_hcm.get_chat_manager(...)._tasks.values())`` line):
    an in-flight hunt-chat turn is cancelled, and its HuntChatManager
    done-callback backstop resolves the still-'pending' assistant row to
    'error'. Without the drain the task is abandoned, the callback never fires,
    and the row stays 'pending' forever (the hunt's chat then 409s every POST)."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="q&a hunt", started_by="t")
        ev = await hunt_svc.create_pending_chat_assistant(db, hunt.id)
        event_id = ev.id

    state = SimpleNamespace(db_sessionmaker=maker)
    mgr = HuntChatManager()

    started = asyncio.Event()

    async def _parked() -> None:
        started.set()
        await asyncio.Event().wait()  # parks until cancelled

    # Register the task exactly as HuntChatManager.start() does (we can't call
    # start() directly — it would kick off a real model turn). The manager is now
    # a ChatTaskManager subclass, so the done-callback carries the backstop
    # (resolve-if-pending) rather than the state.
    task: asyncio.Task[None] = asyncio.create_task(_parked())
    mgr._tasks[event_id] = task

    def _backstop() -> Any:
        return _hunt_chat_resolve_if_pending(state, event_id)

    task.add_done_callback(lambda t: mgr._on_task_done(event_id, _backstop, t))
    await asyncio.wait_for(started.wait(), timeout=1.0)

    # The lifespan shutdown drain: collect the manager's tasks, cancel, await.
    tasks = list(mgr._tasks.values())
    for t in tasks:
        if not t.done():
            t.cancel()
    for t in tasks:
        with contextlib.suppress(BaseException):
            await t
    # The done-callback (scheduled via call_soon) spawns the pending-row
    # backstop; let it schedule, then drain the backstop tasks it created.
    await asyncio.sleep(0)
    for bt in list(mgr._backstops):
        with contextlib.suppress(BaseException):
            await bt

    async with maker() as db:
        row = await hunt_svc.get_chat_event(db, event_id)
        assert row is not None
        assert (row.payload or {}).get("status") == "error"
    await engine.dispose()
