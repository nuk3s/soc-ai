"""Tests for scheduled hunts (E3.1): the store CRUD + due-time query, the
in-process ``_hunt_schedule_loop`` (fires once when due, single-flights, skips
when the master switch is off), and the admin-gated CRUD routes.

Store tests run against a real SQLite file migrated to head (mirrors
tests/test_runbooks.py / tests/test_hunts_store.py). The loop is driven
deterministically by the same sleep-bounding trick as tests/test_main_scheduler.py
(patch ``main.asyncio.sleep`` so the first N wakes return, the next cancels).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterator
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai import main as main_mod
from soc_ai.config import Settings
from soc_ai.main import _hunt_schedule_loop
from soc_ai.store import hunt_schedules as hs_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


# ---------------------------------------------------------------------------
# Migration: 0014 creates the hunt_schedules table (proves it applies)
# ---------------------------------------------------------------------------


async def test_migration_creates_hunt_schedules_table(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = set(await conn.run_sync(lambda sc: inspect(sc).get_table_names()))
    assert "hunt_schedules" in tables
    await engine.dispose()


# ---------------------------------------------------------------------------
# Store CRUD
# ---------------------------------------------------------------------------


async def test_create_list_get_update_delete(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        s = await hs_svc.create(
            db,
            objective="Hunt for beaconing to rare IPs",
            interval_minutes=120,
            created_by="alice",
        )
        assert s.id is not None
        assert s.objective == "Hunt for beaconing to rare IPs"
        assert s.interval_minutes == 120
        assert s.enabled is True
        assert s.last_run_at is None
        assert s.created_by == "alice"

        # list + get
        assert [r.id for r in await hs_svc.list_all(db)] == [s.id]
        got = await hs_svc.get(db, s.id)
        assert got is not None and got.id == s.id

        # patch only given fields
        upd = await hs_svc.update(db, s.id, objective="Renamed", enabled=False)
        assert upd is not None
        assert upd.objective == "Renamed"
        assert upd.enabled is False
        assert upd.interval_minutes == 120  # untouched

        # missing id → None
        assert await hs_svc.update(db, 9999, objective="nope") is None

        # delete
        assert await hs_svc.delete(db, s.id) is True
        assert await hs_svc.get(db, s.id) is None
        assert await hs_svc.delete(db, s.id) is False
    await engine.dispose()


async def test_interval_floored_at_minimum(settings_kratos: Settings) -> None:
    """A sub-minimum interval is clamped up (never below the single-flight floor)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        s = await hs_svc.create(db, objective="x", interval_minutes=5)
        assert s.interval_minutes == hs_svc.MIN_INTERVAL_MINUTES
        upd = await hs_svc.update(db, s.id, interval_minutes=1)
        assert upd is not None and upd.interval_minutes == hs_svc.MIN_INTERVAL_MINUTES
    await engine.dispose()


# ---------------------------------------------------------------------------
# due_schedules + mark_ran
# ---------------------------------------------------------------------------


async def test_due_schedules_and_mark_ran(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        # (a) enabled + never run → due
        never = await hs_svc.create(db, objective="never", interval_minutes=60)
        # (b) enabled + last_run well past interval → due
        overdue = await hs_svc.create(db, objective="overdue", interval_minutes=60)
        overdue.last_run_at = now - timedelta(minutes=120)
        # (c) enabled + last_run recent → NOT due
        recent = await hs_svc.create(db, objective="recent", interval_minutes=60)
        recent.last_run_at = now - timedelta(minutes=5)
        # (d) DISABLED but overdue → NOT due
        disabled = await hs_svc.create(db, objective="disabled", interval_minutes=60)
        disabled.enabled = False
        disabled.last_run_at = now - timedelta(minutes=999)
        await db.commit()

        due = await hs_svc.due_schedules(db, now)
        due_ids = {s.id for s in due}
        assert never.id in due_ids
        assert overdue.id in due_ids
        assert recent.id not in due_ids
        assert disabled.id not in due_ids

        # mark_ran stamps last_run_at → the schedule is no longer due at the same now
        await hs_svc.mark_ran(db, never.id, now)
        due2 = await hs_svc.due_schedules(db, now)
        assert never.id not in {s.id for s in due2}

        # mark_ran on a missing id is a no-op (does not raise)
        await hs_svc.mark_ran(db, 9999, now)
    await engine.dispose()


# ---------------------------------------------------------------------------
# _hunt_schedule_loop — the background firing loop
# ---------------------------------------------------------------------------


def _loop_settings(*, enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(hunt_schedules_enabled=enabled)


def _loop_app(maker: async_sessionmaker[AsyncSession], *, enabled: bool = True) -> SimpleNamespace:
    """A stub app whose ``state`` carries the real sessionmaker + the settings the
    loop reads live each wake."""
    return SimpleNamespace(
        state=SimpleNamespace(db_sessionmaker=maker, settings=_loop_settings(enabled=enabled))
    )


async def _run_loop(
    monkeypatch: pytest.MonkeyPatch,
    app: SimpleNamespace,
    n: int = 1,
) -> None:
    """Run ``_hunt_schedule_loop`` for exactly ``n`` body iterations, then unwind.

    Same bounding trick as tests/test_main_scheduler.py: patch ``main.asyncio.sleep``
    so the first ``n`` wakes return and the next raises ``CancelledError``."""
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
async def test_loop_fires_due_schedule_once(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A due schedule fires exactly once — the manager's start is called with the
    schedule's objective + kind='scheduled', and mark_ran stamps last_run_at."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        sched = await hs_svc.create(db, objective="nightly beacon sweep", interval_minutes=60)
    app = _loop_app(maker, enabled=True)

    calls: list[dict[str, Any]] = []

    async def _start(_state: Any, *, objective: str, started_by: str, kind: str = "chat") -> str:
        calls.append({"objective": objective, "started_by": started_by, "kind": kind})
        return "HUNT123"

    fake_manager = SimpleNamespace(start=_start)
    monkeypatch.setattr("soc_ai.webui.hunt_console_manager.get_manager", lambda _s: fake_manager)

    await _run_loop(monkeypatch, app)

    # fired once, tagged scheduled, started_by the scheduler
    assert len(calls) == 1
    assert calls[0]["objective"] == "nightly beacon sweep"
    assert calls[0]["kind"] == "scheduled"
    assert calls[0]["started_by"] == "scheduler"
    # last_run_at stamped → the interval clock reset
    async with maker() as db:
        got = await hs_svc.get(db, sched.id)
        assert got is not None and got.last_run_at is not None
    await engine.dispose()


@pytest.mark.asyncio
async def test_loop_single_flights_just_ran_schedule(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A schedule that just ran (mark_ran on the first wake) is NOT due again on the
    next wake — so two wakes fire it only once (single-flight per schedule)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await hs_svc.create(db, objective="hourly sweep", interval_minutes=60)
    app = _loop_app(maker, enabled=True)

    calls: list[str] = []

    async def _start(_state: Any, *, objective: str, started_by: str, kind: str = "chat") -> str:
        calls.append(objective)
        return "HUNT-X"

    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager",
        lambda _s: SimpleNamespace(start=_start),
    )

    # two body iterations: the mark_ran on wake #1 makes it not-due on wake #2.
    await _run_loop(monkeypatch, app, n=2)
    assert calls == ["hourly sweep"]
    await engine.dispose()


@pytest.mark.asyncio
async def test_loop_skips_when_master_switch_off(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """With ``hunt_schedules_enabled`` off, the loop wakes but never fires a hunt —
    even with a due schedule sitting in the table."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await hs_svc.create(db, objective="should not fire", interval_minutes=60)
    app = _loop_app(maker, enabled=False)

    calls: list[str] = []

    async def _start(_state: Any, *, objective: str, started_by: str, kind: str = "chat") -> str:
        calls.append(objective)
        return "HUNT-Y"

    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager",
        lambda _s: SimpleNamespace(start=_start),
    )

    await _run_loop(monkeypatch, app)
    assert calls == []
    await engine.dispose()


@pytest.mark.asyncio
async def test_loop_survives_a_bad_schedule(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A schedule whose spawn raises is logged + skipped; a sibling still fires
    (one bad schedule can't kill the loop or the others)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        bad = await hs_svc.create(db, objective="BAD", interval_minutes=60)
        await hs_svc.create(db, objective="GOOD", interval_minutes=60)
    app = _loop_app(maker, enabled=True)

    fired: list[str] = []

    async def _start(_state: Any, *, objective: str, started_by: str, kind: str = "chat") -> str:
        if objective == "BAD":
            raise RuntimeError("spawn boom")
        fired.append(objective)
        return "HUNT-OK"

    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager",
        lambda _s: SimpleNamespace(start=_start),
    )

    await _run_loop(monkeypatch, app)
    # the good one fired despite the bad one raising
    assert fired == ["GOOD"]
    # the bad schedule was still marked ran (interval reset before spawn) so it
    # doesn't hammer every wake
    async with maker() as db:
        got = await hs_svc.get(db, bad.id)
        assert got is not None and got.last_run_at is not None
    await engine.dispose()


@pytest.mark.asyncio
async def test_loop_cancels_cleanly_on_shutdown(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Cancellation at shutdown unwinds the loop without error (lifespan teardown)."""
    _engine, maker = await _db(settings_kratos)
    app = _loop_app(maker, enabled=True)

    started = asyncio.Event()
    park = asyncio.Event()  # never set → parks until cancelled

    async def _sleep(_seconds: float) -> None:
        started.set()
        await park.wait()

    monkeypatch.setattr(main_mod.asyncio, "sleep", _sleep)
    task = asyncio.create_task(_hunt_schedule_loop(app))
    await asyncio.wait_for(started.wait(), timeout=1.0)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert task.cancelled() or task.done()
    await _engine.dispose()


# ---------------------------------------------------------------------------
# CRUD routes: GET/POST/PUT/DELETE /hunt-schedules + admin gate
# ---------------------------------------------------------------------------


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = main_mod.create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def test_schedules_crud_roundtrip(client: TestClient) -> None:
    # empty to start
    assert client.get("/api/v1/hunt-schedules").json() == []

    # create (interval below the floor is clamped up by the store)
    resp = client.post(
        "/api/v1/hunt-schedules",
        json={"objective": "Nightly beacon sweep", "interval_minutes": 30, "enabled": True},
    )
    assert resp.status_code == 422  # ge=60 bound on the In model rejects 30

    resp = client.post(
        "/api/v1/hunt-schedules",
        json={"objective": "Nightly beacon sweep", "interval_minutes": 1440, "enabled": True},
    )
    assert resp.status_code == 200, resp.text
    created = resp.json()
    assert created["objective"] == "Nightly beacon sweep"
    assert created["intervalMinutes"] == 1440
    assert created["enabled"] is True
    assert created["lastRunAt"] is None
    assert created["createdBy"] == "anonymous"  # identify_caller w/o a session
    sid = created["id"]

    # list shows it
    listing = client.get("/api/v1/hunt-schedules").json()
    assert [r["objective"] for r in listing] == ["Nightly beacon sweep"]

    # update (pause it + rename)
    upd = client.put(
        f"/api/v1/hunt-schedules/{sid}",
        json={"objective": "Nightly beacon sweep (v2)", "enabled": False},
    )
    assert upd.status_code == 200
    assert upd.json()["objective"] == "Nightly beacon sweep (v2)"
    assert upd.json()["enabled"] is False
    assert upd.json()["intervalMinutes"] == 1440  # untouched

    # delete
    rm = client.delete(f"/api/v1/hunt-schedules/{sid}")
    assert rm.status_code == 200
    assert rm.json() == {"deleted": True}
    assert client.get("/api/v1/hunt-schedules").json() == []


def test_update_missing_schedule_404(client: TestClient) -> None:
    assert client.put("/api/v1/hunt-schedules/9999", json={"objective": "nope"}).status_code == 404


def test_delete_missing_schedule_404(client: TestClient) -> None:
    assert client.delete("/api/v1/hunt-schedules/9999").status_code == 404


def test_create_schedule_requires_objective(client: TestClient) -> None:
    assert client.post("/api/v1/hunt-schedules", json={"interval_minutes": 60}).status_code == 422


def test_mutate_routes_admin_gated(settings_kratos: Settings) -> None:
    """With API auth ON, an unauthenticated mutate is refused; an admin gets through.

    The list GET is analyst-readable but still auth-gated; the POST is the
    admin-gated mutate — an anonymous caller is rejected (401 at the auth layer,
    or 403 admin_required) before it writes."""
    settings = settings_kratos.model_copy(
        update={
            "api_auth_required": True,
            "bootstrap_admin_password": SecretStr("admin-pw"),
        }
    )
    for c in _client(settings):
        # anonymous mutate refused
        anon = c.post(
            "/api/v1/hunt-schedules",
            json={"objective": "x", "interval_minutes": 60, "enabled": True},
        )
        assert anon.status_code in (401, 403)

        # authenticated admin gets through. A cookie-authenticated write must carry
        # a same-origin Origin (TestClient's base_url) to pass the CSRF guard.
        login = c.post("/api/v1/login", json={"username": "admin", "password": "admin-pw"})
        assert login.status_code == 200, login.text
        ok = c.post(
            "/api/v1/hunt-schedules",
            json={"objective": "admin sweep", "interval_minutes": 60, "enabled": True},
            headers={"Origin": "http://testserver"},
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["objective"] == "admin sweep"
