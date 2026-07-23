"""Tests for the in-process discovery scheduler in ``soc_ai.main``.

The loop (`_discovery_scheduler_loop`) is driven deterministically: we patch
``soc_ai.main.asyncio.sleep`` so its first call returns and its second raises
``CancelledError``, which bounds the otherwise-``while True`` loop to exactly one
body iteration. The lazily-imported scan-now worker / status accessor are patched
at their source (``soc_ai.api.webui_api``) so no real ES/DB is touched. The pure
``_discovery_due`` helper is tested directly.

Each test maps to a scheduler requirement:
* due-helper edge cases (never-run / elapsed / not-elapsed / unparseable);
* runs when enabled + due, claiming the shared single-flight slot;
* no-op when the schedule (or the master switch) is off;
* no-op when not yet due;
* no overlap with a manual "Scan now" already in flight (single-flight);
* clean cancellation at shutdown;
* a failing iteration is logged and the loop survives.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import stat
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai import main as main_mod
from soc_ai.api.webui_api import _DiscoveryStatus, _get_discovery_status
from soc_ai.config import Settings
from soc_ai.main import (
    _auto_triage_scheduler_loop,
    _discovery_due,
    _discovery_scheduler_loop,
    _init_store,
)
from soc_ai.store import auth as auth_svc
from soc_ai.store import chat as chat_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import ChatMessage


def _make_app(status: _DiscoveryStatus) -> SimpleNamespace:
    """A minimal stub app: the loop only touches ``app.state``.

    ``app.state`` carries the shared ``_DiscoveryStatus`` under the same attr the
    real ``_get_discovery_status`` uses, plus the clients ``_run_discovery_task``
    would reach (unused here because the worker is stubbed)."""
    state = SimpleNamespace(
        _discovery_status=status,
        elastic=object(),
        db_sessionmaker=object(),
        settings=None,
    )
    return SimpleNamespace(state=state)


def _settings(
    *,
    schedule_enabled: bool = True,
    discovery_enabled: bool = True,
    interval_hours: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        discovery_schedule_enabled=schedule_enabled,
        discovery_enabled=discovery_enabled,
        discovery_schedule_interval_hours=interval_hours,
    )


async def _run_iterations(
    monkeypatch: pytest.MonkeyPatch,
    app: SimpleNamespace,
    settings: Any,
    n: int = 1,
) -> None:
    """Run the loop for exactly ``n`` body iterations, then unwind cleanly.

    Patches ``soc_ai.main.asyncio.sleep`` so the first ``n`` wakes return and the
    next raises ``CancelledError``, bounding the otherwise-``while True`` loop.
    The patch is reverted before returning (via the local ``_sleep`` delegating to
    the captured real ``sleep`` once exhausted) so callers can safely await real
    coroutines afterwards. Any worker the loop spawned via ``create_task`` is left
    on ``status._task`` for the caller to await."""
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
            await _discovery_scheduler_loop(app, settings)
    finally:
        monkeypatch.setattr(main_mod.asyncio, "sleep", real_sleep)


async def _drain_worker(status: _DiscoveryStatus) -> None:
    """Await the worker task the loop may have spawned, if any."""
    task = status._task
    if task is not None:
        with contextlib.suppress(Exception):
            await task


# --------------------------------------------------------------------------- #
# 1. pure helper
# --------------------------------------------------------------------------- #


def test_discovery_due_helper() -> None:
    # never run this process → due
    assert _discovery_due(None, 24) is True
    # last scan well past the interval → due
    past = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
    assert _discovery_due(past, 24) is True
    # last scan a minute ago, 24h interval → not due
    recent = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    assert _discovery_due(recent, 24) is False
    # unparseable timestamp → fail toward running (due)
    assert _discovery_due("not-a-timestamp", 24) is True


# --------------------------------------------------------------------------- #
# 2. runs when enabled + due
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_loop_runs_when_enabled_and_due(monkeypatch: pytest.MonkeyPatch) -> None:
    status = _DiscoveryStatus()  # last_scan=None → due immediately
    app = _make_app(status)
    settings = _settings(schedule_enabled=True, discovery_enabled=True, interval_hours=1)

    invoked: list[bool] = []

    async def _stub_worker(state: Any) -> None:
        invoked.append(True)
        # mirror the real worker's finally: reset running + stamp last_scan
        status.running = False
        status.last_scan = datetime.now(UTC).isoformat()

    monkeypatch.setattr("soc_ai.api.webui_api._run_discovery_task", _stub_worker)

    await _run_iterations(monkeypatch, app, settings)
    await _drain_worker(status)  # let the create_task'd worker finish

    assert invoked == [True]
    assert status.last_scan is not None


# --------------------------------------------------------------------------- #
# 3. no-op when schedule (or master switch) disabled
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_loop_skips_when_schedule_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    status = _DiscoveryStatus()
    app = _make_app(status)

    invoked: list[bool] = []

    async def _stub_worker(state: Any) -> None:
        invoked.append(True)

    monkeypatch.setattr("soc_ai.api.webui_api._run_discovery_task", _stub_worker)

    # schedule off
    await _run_iterations(
        monkeypatch, app, _settings(schedule_enabled=False, discovery_enabled=True)
    )
    await _drain_worker(status)
    assert invoked == []
    assert status.running is False

    # master switch off (schedule on)
    await _run_iterations(
        monkeypatch, app, _settings(schedule_enabled=True, discovery_enabled=False)
    )
    await _drain_worker(status)
    assert invoked == []
    assert status.running is False


# --------------------------------------------------------------------------- #
# 4. no-op when not yet due
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_loop_skips_when_not_due(monkeypatch: pytest.MonkeyPatch) -> None:
    status = _DiscoveryStatus()
    status.last_scan = datetime.now(UTC).isoformat()  # just ran
    app = _make_app(status)
    settings = _settings(schedule_enabled=True, discovery_enabled=True, interval_hours=24)

    invoked: list[bool] = []

    async def _stub_worker(state: Any) -> None:
        invoked.append(True)

    monkeypatch.setattr("soc_ai.api.webui_api._run_discovery_task", _stub_worker)

    await _run_iterations(monkeypatch, app, settings)
    await _drain_worker(status)

    assert invoked == []
    assert status.running is False


# --------------------------------------------------------------------------- #
# 5. single-flight shared with manual Scan now
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_loop_respects_single_flight(monkeypatch: pytest.MonkeyPatch) -> None:
    status = _DiscoveryStatus()  # last_scan=None → would be due...
    status.running = True  # ...but a manual "Scan now" is mid-flight
    app = _make_app(status)
    settings = _settings(schedule_enabled=True, discovery_enabled=True, interval_hours=1)

    invoked: list[bool] = []

    async def _stub_worker(state: Any) -> None:
        invoked.append(True)

    monkeypatch.setattr("soc_ai.api.webui_api._run_discovery_task", _stub_worker)

    await _run_iterations(monkeypatch, app, settings)
    await _drain_worker(status)

    # the scheduler must not start a second, overlapping scan
    assert invoked == []
    assert status.running is True  # the in-flight scan still owns the slot


# --------------------------------------------------------------------------- #
# 6. clean cancellation at shutdown (mirrors the lifespan teardown)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_loop_cancels_cleanly_on_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    status = _DiscoveryStatus()
    app = _make_app(status)
    settings = _settings()

    started = asyncio.Event()
    park = asyncio.Event()  # never set → parks until cancelled

    async def _sleep(_seconds: float) -> None:
        started.set()
        await park.wait()  # park on the first wake (no real timer)

    monkeypatch.setattr(main_mod.asyncio, "sleep", _sleep)

    task = asyncio.create_task(_discovery_scheduler_loop(app, settings))
    await asyncio.wait_for(started.wait(), timeout=1.0)

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert task.cancelled() or task.done()


# --------------------------------------------------------------------------- #
# 7. a failing iteration is logged and the loop survives
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_loop_continues_after_iteration_error(monkeypatch: pytest.MonkeyPatch) -> None:
    status = _DiscoveryStatus()  # due
    app = _make_app(status)

    # A settings object whose master-switch read raises a non-Cancel error on the
    # FIRST body iteration, then behaves normally — so the loop must log+swallow
    # and reach a SECOND body that actually runs the scan.
    calls = {"n": 0}

    class _Boom:
        discovery_schedule_enabled = True
        discovery_schedule_interval_hours = 1

        @property
        def discovery_enabled(self) -> bool:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            return True

    invoked: list[bool] = []

    async def _stub_worker(state: Any) -> None:
        invoked.append(True)
        status.running = False
        status.last_scan = datetime.now(UTC).isoformat()

    monkeypatch.setattr("soc_ai.api.webui_api._run_discovery_task", _stub_worker)

    # two body iterations: #1 raises (swallowed), #2 runs the scan.
    await _run_iterations(monkeypatch, app, _Boom(), n=2)
    await _drain_worker(status)

    # first iteration raised (logged + swallowed); the loop survived and the
    # second body ran the scan → proves broad-except resilience.
    assert calls["n"] >= 2
    assert invoked == [True]


# --------------------------------------------------------------------------- #
# 8. an in-flight discovery worker is cancelled + drained at shutdown
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_inflight_worker_cancelled_on_shutdown() -> None:
    """A scan still running at shutdown is cancelled + awaited before teardown.

    Mirrors the lifespan teardown block: the worker task tracked on the shared
    single-flight status (the same object the scan-now endpoint uses) is cancelled
    and drained BEFORE the ES/DB clients it holds are closed — so a shutdown
    racing an in-flight scan doesn't log a spurious "scan failed". Asserts the
    worker actually saw the cancellation (its ``finally`` fired, resetting the
    ``running`` flag) and ended cancelled."""
    status = _DiscoveryStatus()
    app = _make_app(status)

    started = asyncio.Event()
    finally_ran = asyncio.Event()

    async def _slow_worker(_state: Any) -> None:
        # Mirror the real _run_discovery_task: claim → (long scan) → finally reset.
        status.running = True
        started.set()
        try:
            await asyncio.sleep(3600)  # parked mid-scan until cancelled
        finally:
            status.running = False
            finally_ran.set()

    # The scheduler / scan-now path spawns the worker and tracks it on _task.
    status.running = True
    status._task = asyncio.create_task(_slow_worker(app.state))
    await asyncio.wait_for(started.wait(), timeout=1.0)

    # Exactly the lifespan-shutdown sequence (post scheduler-loop cancellation).
    _st = _get_discovery_status(app.state)
    assert _st is status
    if _st._task is not None and not _st._task.done():
        _st._task.cancel()
        with contextlib.suppress(BaseException):
            await _st._task

    assert finally_ran.is_set()  # the worker's finally fired
    assert status.running is False  # …resetting the single-flight flag
    assert status._task is not None
    assert status._task.cancelled()


# --------------------------------------------------------------------------- #
# 9. startup store-init reaps orphaned pending chat turns (mirrors running invs)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_init_store_reaps_pending_chat_turns(settings_kratos: Settings) -> None:
    """A 'pending' assistant chat row that survives a restart is resolved to
    'error' by _init_store at startup (its background task is gone), while a
    done row is left untouched. Mirrors the orphaned-'running'-investigation
    startup reap that runs in the same place."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-startup", started_by="t")
        pend = await chat_svc.create_pending_assistant(db, inv.id)
        done = await chat_svc.create_pending_assistant(db, inv.id)
        await chat_svc.finish_assistant(db, done.id, content="kept", status="done")
    await engine.dispose()

    # Fresh engine on the SAME on-disk DB simulates a process restart, then
    # _init_store runs its startup reaps (migrations are idempotent).
    engine2 = make_engine(settings_kratos)
    maker2 = await _init_store(engine2, settings_kratos)
    async with maker2() as db:
        reaped = await db.get(ChatMessage, pend.id)
        assert reaped is not None
        assert reaped.status == "error"
        assert "interrupted" in reaped.content
        # the completed turn is untouched
        kept = await db.get(ChatMessage, done.id)
        assert kept is not None and kept.status == "done" and kept.content == "kept"


@pytest.mark.asyncio
async def test_init_store_reaps_orphaned_investigation_to_interrupted(
    settings_kratos: Settings,
) -> None:
    """An investigation still 'running' after a restart is resolved to
    'interrupted' (NOT 'error') by _init_store — a clean restart cut it off; it
    didn't fail. The benign state is what keeps a healthy single-node env free of
    spurious 'error'/'cancelled' investigations, and it stays re-huntable."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-orphan", started_by="t")
    await engine.dispose()

    # Restart on the same on-disk DB → startup reap runs.
    engine2 = make_engine(settings_kratos)
    maker2 = await _init_store(engine2, settings_kratos)
    async with maker2() as db:
        from soc_ai.store.models import Investigation

        row = await db.get(Investigation, inv.id)
        assert row is not None
        assert row.status == "interrupted"
        assert inv_svc.blocks_rehunt(row) is False
    await engine2.dispose()


@pytest.mark.asyncio
async def test_init_store_bootstrap_password_written_to_locked_file_not_logged(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """The one-shot bootstrap admin password must land in a 0600 sidecar file
    under the data dir, not in cleartext in the log stream — journald/container
    logs are often readable by the same audience (other analysts, integrations)
    this credential must stay secret from."""
    engine = make_engine(settings_kratos)
    with caplog.at_level(logging.WARNING, logger="soc_ai.main"):
        maker = await _init_store(engine, settings_kratos)

    cred_path = settings_kratos.soc_ai_data_dir / "bootstrap-admin-password.txt"
    assert cred_path.is_file()
    assert stat.S_IMODE(cred_path.stat().st_mode) == 0o600
    written_pw = cred_path.read_text().strip()
    assert written_pw

    # The raw password must never appear in the log stream — only a pointer to
    # the file that holds it.
    assert written_pw not in caplog.text
    assert "BOOTSTRAP CREDENTIAL" in caplog.text
    assert str(cred_path) in caplog.text

    # The file's password is the real, working bootstrap credential.
    async with maker() as db:
        assert await auth_svc.authenticate(db, "admin", written_pw) is not None
    await engine.dispose()


# --------------------------------------------------------------------------- #
# Auto-triage scheduler loop — continuously drains the untriaged backlog.
# Mirrors the discovery-loop harness: deterministic sleep-bounded iterations,
# the lazily-imported autotriage module patched at its source.
# --------------------------------------------------------------------------- #


def _at_app() -> SimpleNamespace:
    """A minimal stub app; the auto-triage loop only touches ``app.state``."""
    return SimpleNamespace(state=SimpleNamespace())


def _at_settings(*, enabled: bool = True, interval_minutes: int = 5) -> SimpleNamespace:
    return SimpleNamespace(
        auto_triage_schedule_enabled=enabled,
        auto_triage_schedule_interval_minutes=interval_minutes,
    )


async def _run_at_iterations(
    monkeypatch: pytest.MonkeyPatch,
    app: SimpleNamespace,
    settings: Any,
    n: int = 1,
) -> None:
    """Run ``_auto_triage_scheduler_loop`` for exactly ``n`` body iterations.

    Same bounding trick as the discovery harness: patch ``main.asyncio.sleep`` so
    the first ``n`` wakes return and the next raises ``CancelledError``."""
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
            await _auto_triage_scheduler_loop(app, settings)
    finally:
        monkeypatch.setattr(main_mod.asyncio, "sleep", real_sleep)


@pytest.mark.asyncio
async def test_at_loop_launches_sweep_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """When scheduled auto-triage is on and idle, a body iteration kicks a sweep."""
    app = _at_app()
    launched: list[str] = []

    async def _stub_sweep(_state: Any, *, started_by: str) -> int:
        launched.append(started_by)
        return 3  # pretend it found 3 targets

    monkeypatch.setattr("soc_ai.webui.autotriage.start_config_sweep", _stub_sweep)
    # idle: no in-flight sweep
    monkeypatch.setattr(
        "soc_ai.webui.autotriage.get_status",
        lambda _s: SimpleNamespace(active=False),
    )

    await _run_at_iterations(monkeypatch, app, _at_settings(enabled=True))
    assert launched == ["auto-triage:scheduler"]


@pytest.mark.asyncio
async def test_at_loop_first_sweep_fires_on_fresh_boot_small_monotonic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: on a freshly-booted host ``time.monotonic()`` is near zero
    (its epoch is arbitrary). The first enabled wake must still sweep. A prior
    ``_last_sweep = 0.0`` sentinel made ``now - _last_sweep`` tiny, which read as
    'just swept' and skipped the first sweep — green on long-uptime dev boxes, red
    on fresh CI runners (and a real fresh-boot delay in production)."""
    app = _at_app()
    launched: list[str] = []

    async def _stub_sweep(_state: Any, *, started_by: str) -> int:
        launched.append(started_by)
        return 3

    monkeypatch.setattr("soc_ai.webui.autotriage.start_config_sweep", _stub_sweep)
    monkeypatch.setattr(
        "soc_ai.webui.autotriage.get_status",
        lambda _s: SimpleNamespace(active=False),
    )
    # Simulate a fresh boot: monotonic returns a small value (seconds since boot),
    # far below the 5-minute interval.
    monkeypatch.setattr(main_mod.time, "monotonic", lambda: 5.0)

    await _run_at_iterations(monkeypatch, app, _at_settings(enabled=True))
    assert launched == ["auto-triage:scheduler"]


@pytest.mark.asyncio
async def test_at_loop_noop_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Master switch off → the loop wakes but never plans or launches a sweep."""
    app = _at_app()
    launched: list[str] = []

    async def _stub_sweep(_state: Any, *, started_by: str) -> int:
        launched.append(started_by)
        return 0

    monkeypatch.setattr("soc_ai.webui.autotriage.start_config_sweep", _stub_sweep)
    monkeypatch.setattr(
        "soc_ai.webui.autotriage.get_status",
        lambda _s: SimpleNamespace(active=False),
    )

    await _run_at_iterations(monkeypatch, app, _at_settings(enabled=False))
    assert launched == []


@pytest.mark.asyncio
async def test_at_loop_respects_single_flight(monkeypatch: pytest.MonkeyPatch) -> None:
    """A sweep already in flight (manual ⚡ or a prior tick) blocks a new launch."""
    app = _at_app()
    launched: list[str] = []

    async def _stub_sweep(_state: Any, *, started_by: str) -> int:
        launched.append(started_by)
        return 0

    monkeypatch.setattr("soc_ai.webui.autotriage.start_config_sweep", _stub_sweep)
    monkeypatch.setattr(
        "soc_ai.webui.autotriage.get_status",
        lambda _s: SimpleNamespace(active=True),  # a sweep owns the slot
    )

    await _run_at_iterations(monkeypatch, app, _at_settings(enabled=True))
    assert launched == []


@pytest.mark.asyncio
async def test_at_loop_survives_iteration_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A sweep that raises is logged and swallowed; the loop reaches the next tick."""
    app = _at_app()
    calls = {"n": 0}

    async def _stub_sweep(_state: Any, *, started_by: str) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("planning boom")
        return 1

    monkeypatch.setattr("soc_ai.webui.autotriage.start_config_sweep", _stub_sweep)
    monkeypatch.setattr(
        "soc_ai.webui.autotriage.get_status",
        lambda _s: SimpleNamespace(active=False),
    )

    # iteration #1 raises (swallowed), #2 runs → proves broad-except resilience.
    await _run_at_iterations(monkeypatch, app, _at_settings(enabled=True), n=2)
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_at_loop_cancels_cleanly_on_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancellation at shutdown unwinds the loop without error (lifespan teardown)."""
    app = _at_app()
    settings = _at_settings()

    started = asyncio.Event()
    park = asyncio.Event()  # never set → parks until cancelled

    async def _sleep(_seconds: float) -> None:
        started.set()
        await park.wait()

    monkeypatch.setattr(main_mod.asyncio, "sleep", _sleep)

    task = asyncio.create_task(_auto_triage_scheduler_loop(app, settings))
    await asyncio.wait_for(started.wait(), timeout=1.0)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert task.cancelled() or task.done()


# --------------------------------------------------------------------------- #
# eval-nightly in-app scheduler (schedulable from the UI, 2026-07-16)
# --------------------------------------------------------------------------- #

from unittest.mock import AsyncMock  # noqa: E402

from soc_ai.api.webui.routes_quality import _QualityEvalStatus  # noqa: E402
from soc_ai.main import _eval_nightly_due, _eval_nightly_loop  # noqa: E402


def test_eval_nightly_due_helper() -> None:
    now = datetime(2026, 7, 16, 4, 30, tzinfo=UTC)
    # hour reached, nothing ran today → due
    assert _eval_nightly_due(now, hour_utc=3, last_scheduled_date=None, latest_snapshot_date=None)
    # before the configured hour → not due
    assert not _eval_nightly_due(
        now, hour_utc=5, last_scheduled_date=None, latest_snapshot_date=None
    )
    # already attempted today (even if it failed) → not due
    assert not _eval_nightly_due(
        now, hour_utc=3, last_scheduled_date="2026-07-16", latest_snapshot_date=None
    )
    # a snapshot already landed today (cron/other process) → not due
    assert not _eval_nightly_due(
        now, hour_utc=3, last_scheduled_date=None, latest_snapshot_date="2026-07-16"
    )
    # yesterday's attempt/snapshot never blocks today
    assert _eval_nightly_due(
        now, hour_utc=3, last_scheduled_date="2026-07-15", latest_snapshot_date="2026-07-15"
    )


def _eval_settings(*, enabled: bool = True, hour: int = 0) -> SimpleNamespace:
    return SimpleNamespace(eval_nightly_enabled=enabled, eval_nightly_hour_utc=hour)


def _eval_app(status: _QualityEvalStatus) -> SimpleNamespace:
    class _FakeDb:
        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

    return SimpleNamespace(
        state=SimpleNamespace(_quality_eval_status=status, db_sessionmaker=_FakeDb)
    )


async def _run_eval_iterations(
    monkeypatch: pytest.MonkeyPatch, app: SimpleNamespace, settings: Any, n: int = 1
) -> None:
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
            await _eval_nightly_loop(app, settings)
    finally:
        monkeypatch.setattr(main_mod.asyncio, "sleep", real_sleep)


@pytest.mark.asyncio
async def test_eval_loop_runs_when_enabled_and_hour_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status = _QualityEvalStatus()
    app = _eval_app(status)

    invoked: list[bool] = []

    async def _stub_worker(state: Any) -> None:
        invoked.append(True)
        status.running = False

    monkeypatch.setattr("soc_ai.api.webui_api._quality_eval_worker", _stub_worker)
    monkeypatch.setattr("soc_ai.store.quality.recent_snapshots", AsyncMock(return_value=[]))

    await _run_eval_iterations(monkeypatch, app, _eval_settings(enabled=True, hour=0))
    if status._task is not None:
        with contextlib.suppress(Exception):
            await status._task

    assert invoked == [True]
    assert status.last_scheduled_date is not None


@pytest.mark.asyncio
async def test_eval_loop_skips_when_disabled_or_early_or_already_ran(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status = _QualityEvalStatus()
    app = _eval_app(status)
    invoked: list[bool] = []

    async def _stub_worker(state: Any) -> None:
        invoked.append(True)

    monkeypatch.setattr("soc_ai.api.webui_api._quality_eval_worker", _stub_worker)
    monkeypatch.setattr("soc_ai.store.quality.recent_snapshots", AsyncMock(return_value=[]))

    # disabled
    await _run_eval_iterations(monkeypatch, app, _eval_settings(enabled=False, hour=0))
    # hour not reached (25 can never be reached)
    await _run_eval_iterations(monkeypatch, app, _eval_settings(enabled=True, hour=24))
    # already attempted today
    status.last_scheduled_date = datetime.now(UTC).date().isoformat()
    await _run_eval_iterations(monkeypatch, app, _eval_settings(enabled=True, hour=0))
    # already running
    status.last_scheduled_date = None
    status.running = True
    await _run_eval_iterations(monkeypatch, app, _eval_settings(enabled=True, hour=0))

    assert invoked == []
