"""The campaigns are rebuilt after a change of the store, with no page read (S1).

Before this change the campaign engine ran only when a person opened a
campaign page, so no other page could name the campaign of an
investigation. A verdict, an override or a dismissed action now asks the
refresh loop for a rebuild. The loop waits for a request or for its timer,
waits two seconds more to join a burst, and calls ``ensure_fresh``.

The loop is off in the test suite (``tests/conftest.py``). These tests run
it on purpose, with short waits.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import AsyncIterator, Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai import main as main_mod
from soc_ai.campaigns import refresh
from soc_ai.campaigns import service as campaign_svc
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_facts import seed_hosts, seed_run


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


class _Calls:
    """A stand-in for ``ensure_fresh`` that counts its calls."""

    def __init__(self, *, fail: int = 0) -> None:
        self.count = 0
        self.fail = fail
        self.called = asyncio.Event()

    async def __call__(self, db: Any, **_kwargs: Any) -> bool:
        self.count += 1
        self.called.set()
        if self.count <= self.fail:
            raise RuntimeError("the store is gone")
        return True


def _app(maker: Any) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(db_sessionmaker=maker))


async def _start(
    maker: Any, monkeypatch: pytest.MonkeyPatch, calls: _Calls, *, idle: float = 60.0
) -> asyncio.Task[None]:
    monkeypatch.setattr(campaign_svc, "ensure_fresh", calls)
    task = asyncio.create_task(refresh.refresh_loop(_app(maker), idle_s=idle, join_s=0.05))
    for _ in range(100):
        if refresh.is_listening():
            break
        await asyncio.sleep(0.01)
    assert refresh.is_listening()
    return task


async def _stop(task: asyncio.Task[None]) -> None:
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not refresh.is_listening()


def test_a_request_with_no_loop_does_nothing_and_raises_nothing() -> None:
    assert not refresh.is_listening()
    refresh.request_refresh()
    campaign_svc.request_refresh()


async def test_a_burst_of_requests_gives_one_rebuild(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _Calls()
    task = await _start(maker, monkeypatch, calls)
    try:
        for _ in range(5):
            refresh.request_refresh()
        await asyncio.wait_for(calls.called.wait(), timeout=5)
        await asyncio.sleep(0.2)
        assert calls.count == 1
        # A later request gives a second rebuild.
        calls.called.clear()
        refresh.request_refresh()
        await asyncio.wait_for(calls.called.wait(), timeout=5)
        assert calls.count == 2
    finally:
        await _stop(task)


async def test_no_request_gives_no_rebuild_before_the_timer(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _Calls()
    task = await _start(maker, monkeypatch, calls)
    try:
        await asyncio.sleep(0.3)
        assert calls.count == 0
    finally:
        await _stop(task)


async def test_the_timer_rebuilds_with_no_request(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _Calls()
    task = await _start(maker, monkeypatch, calls, idle=0.05)
    try:
        await asyncio.wait_for(calls.called.wait(), timeout=5)
        assert calls.count >= 1
    finally:
        await _stop(task)


async def test_a_failed_wake_keeps_the_loop_alive(
    maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls = _Calls(fail=1)
    task = await _start(maker, monkeypatch, calls)
    try:
        refresh.request_refresh()
        await asyncio.wait_for(calls.called.wait(), timeout=5)
        await asyncio.sleep(0.1)
        assert not task.done()
        calls.called.clear()
        refresh.request_refresh()
        await asyncio.wait_for(calls.called.wait(), timeout=5)
        assert calls.count == 2
    finally:
        await _stop(task)
    assert "campaigns: the refresh loop could not rebuild" in caplog.text


async def test_a_request_from_another_thread_wakes_the_loop(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _Calls()
    task = await _start(maker, monkeypatch, calls)
    try:
        worker = threading.Thread(target=refresh.request_refresh)
        worker.start()
        worker.join()
        await asyncio.wait_for(calls.called.wait(), timeout=5)
        assert calls.count == 1
    finally:
        await _stop(task)


async def test_a_verdict_and_an_override_request_a_refresh(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[str] = []
    monkeypatch.setattr(refresh, "request_refresh", lambda: asked.append("asked"))
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0001")
        assert asked == ["asked"]
        await inv_svc.resolve(
            db,
            run_id,
            verdict="false_positive",
            confidence=0.9,
            rationale="The upload was a scheduled test.",
            recommended_actions=None,
            resolved_by="analyst",
            resolved_via="manual",
        )
        assert asked == ["asked", "asked"]


async def test_an_investigation_that_ends_in_an_error_requests_no_refresh(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[str] = []
    monkeypatch.setattr(refresh, "request_refresh", lambda: asked.append("asked"))
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="alert-0002", started_by="auto-triage")
        await inv_svc.finalize(db, inv.id, status="error")
        running = await inv_svc.create(db, alert_es_id="alert-0003", started_by="auto-triage")
    assert running.status == "running"
    assert asked == []


async def test_a_real_rebuild_runs_from_a_request(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-0001")
    task = asyncio.create_task(refresh.refresh_loop(_app(maker), idle_s=60, join_s=0.01))
    try:
        for _ in range(100):
            if refresh.is_listening():
                break
            await asyncio.sleep(0.01)
        refresh.request_refresh()
        for _ in range(500):
            async with maker() as db:
                if await campaign_svc.list_campaigns(db):
                    break
            await asyncio.sleep(0.02)
        async with maker() as db:
            (row,) = await campaign_svc.list_campaigns(db)
        assert row.members == 1
    finally:
        await _stop(task)


@contextlib.contextmanager
def _client(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
        TestClient(main_mod.create_app()) as client,
    ):
        yield client


def test_the_app_starts_no_refresh_loop_in_a_test_that_does_not_ask(
    settings_kratos: Settings,
) -> None:
    assert main_mod.CAMPAIGN_REFRESH_LOOP is False
    with _client(settings_kratos) as client:
        assert client.get("/healthz").status_code == 200
        assert not refresh.is_listening()


def test_the_app_starts_the_refresh_loop_and_stops_it_at_shutdown(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main_mod, "CAMPAIGN_REFRESH_LOOP", True)
    with _client(settings_kratos) as client:
        assert client.get("/healthz").status_code == 200
        assert refresh.is_listening()
    assert not refresh.is_listening()
