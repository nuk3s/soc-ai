"""One alert count at one time (SD5).

Production, 2026-11-18: a rebuild added six investigations to campaign 2.
Only a GET of the campaign page read the grid, so the Dashboard row and the
Needs you row read the stored count of an older read (1,104) and the page
read the new count (1,118). The refresh loop now reads the grid for each
campaign whose content changed after its last read. When the grid does not
answer, the stored count stays, and each surface that shows it states the
time of the read.

The data is synthetic: placeholder addresses, names and rule names. Each
stored time is relative to now. The grid is a fake.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai.api.webui.routes_campaigns import _events_out
from soc_ai.api.webui.routes_meta import _campaign_items
from soc_ai.campaigns import refresh, service
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_facts import RULE_B, seed_run
from tests.test_campaign_service import _built, _Grid, _grid_answer


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _read(
    maker: async_sessionmaker[AsyncSession], grid: _Grid, settings: Settings, **kw: Any
) -> int:
    async with maker() as db:
        return await service.refresh_behind(db, grid, settings, **kw)  # type: ignore[arg-type]


async def _row(maker: async_sessionmaker[AsyncSession], campaign_id: int) -> service.CampaignRow:
    async with maker() as db:
        (row,) = await service.list_campaigns(db, ids=[campaign_id])
        return row


async def _page_alerts(maker: async_sessionmaker[AsyncSession], campaign_id: int) -> int:
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id)
    assert view is not None
    return view.events.alerts


async def _add_investigation(maker: async_sessionmaker[AsyncSession]) -> None:
    async with maker() as db:
        await seed_run(db, "alert-0009", rule=RULE_B, event_hours_ago=0.5, created_minutes_ago=1)
        await service.rebuild(db)


async def test_a_rebuild_that_adds_an_investigation_refreshes_the_stored_count(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    # The first read of a new campaign.
    assert await _read(maker, _Grid(_grid_answer(40)), settings_kratos) == 1
    row = await _row(maker, campaign_id)
    assert (row.alerts, row.alerts_behind) == (40, False)
    await _add_investigation(maker)
    # The rebuild changed the content: the stored count can be behind.
    row = await _row(maker, campaign_id)
    assert (row.alerts, row.alerts_behind) == (40, True)
    grid = _Grid(_grid_answer(46))
    assert await _read(maker, grid, settings_kratos) == 1
    assert grid.calls == 1
    row = await _row(maker, campaign_id)
    assert (row.alerts, row.alerts_behind) == (46, False)
    # Every surface states the same count: the row and the page.
    assert await _page_alerts(maker, campaign_id) == row.alerts
    # A campaign with a current read is no candidate: no second read.
    assert await _read(maker, grid, settings_kratos) == 0
    assert grid.calls == 1


async def test_with_the_grid_down_the_stored_count_stays_and_states_its_read(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: the grid is down."""
    campaign_id = await _built(maker)
    await _read(maker, _Grid(_grid_answer(40)), settings_kratos)
    async with maker() as db:
        held = await db.get(Campaign, campaign_id)
        assert held is not None
        read_at = held.events_at
    await _add_investigation(maker)
    broken = _Grid()
    assert await _read(maker, broken, settings_kratos) == 1
    assert broken.calls == 1
    row = await _row(maker, campaign_id)
    assert (row.alerts, row.alerts_behind, row.alerts_at) == (40, True, read_at)
    # The page keeps the same stored count after the failed read, and states it.
    assert await _page_alerts(maker, campaign_id) == 40
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id)
    assert view is not None
    assert _events_out(view.events, built_at=view.built_at).behind is True
    # The Needs you row states the time of the read.
    assert read_at is not None
    (item,) = _campaign_items([row])
    assert f"40 alert events at the grid read of {read_at:%Y-%m-%d %H:%M} UTC." in item.detail
    # The next wake tries again, and a grid that answers clears the mark.
    assert await _read(maker, _Grid(_grid_answer(46)), settings_kratos) == 1
    row = await _row(maker, campaign_id)
    assert (row.alerts, row.alerts_behind) == (46, False)
    (item,) = _campaign_items([row])
    assert "grid read" not in item.detail


async def test_an_ended_campaign_with_stored_events_reads_no_more(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """The existing rule holds: the grid forgets old records."""
    campaign_id = await _built(maker)
    await _read(maker, _Grid(_grid_answer(40)), settings_kratos)
    await _add_investigation(maker)
    # The end check reads the horizon after the last activity once (E2). It
    # finds no alert, and it reads no events: the stored count stays.
    grid = _Grid(EsSearchResult(total=0, took_ms=1, aggregations={"last": {"value": None}}))
    later = utcnow() + timedelta(days=30)
    assert await _read(maker, grid, settings_kratos, now=later) == 1
    assert await _read(maker, grid, settings_kratos, now=later + timedelta(hours=1)) == 0
    assert grid.calls == 1
    row = await _row(maker, campaign_id)
    assert (row.alerts, row.alerts_behind) == (40, True)


async def test_the_refresh_loop_step_reads_nothing_in_the_demo_or_with_no_grid(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    await _built(maker)
    grid = _Grid(_grid_answer(40))
    demo = settings_kratos.model_copy(update={"soc_ai_demo": True})
    for state in (
        SimpleNamespace(db_sessionmaker=maker, elastic=None, settings=settings_kratos),
        SimpleNamespace(db_sessionmaker=maker, elastic=grid, settings=demo),
    ):
        await refresh._refresh_counts(SimpleNamespace(state=state), service)
    assert grid.calls == 0
    state = SimpleNamespace(db_sessionmaker=maker, elastic=grid, settings=settings_kratos)
    await refresh._refresh_counts(SimpleNamespace(state=state), service)
    assert grid.calls == 1
