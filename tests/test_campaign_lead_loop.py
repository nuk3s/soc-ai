"""The lead loop and the leads of a campaign (D1, D2, D4).

A lead of a campaign follows its campaign. The loop hunts it when the
campaign had no hunt in the last 24 hours, and the hunt carries the campaign
id. The seed of a campaign forms a lead on each end, and the first of them
takes the one hunt of the day: the second waits. A lead with one observation
of another type keeps its hunt.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.hunting import campaign_hunt, lead_hunt
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign, Hunt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_lead_tags import add_observation, seed_campaign


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


class StoreConsole:
    """A console that writes the hunt row as the real one does, and runs no agent."""

    def __init__(self, maker: async_sessionmaker[AsyncSession]) -> None:
        self.maker = maker
        self.started: list[dict[str, Any]] = []

    async def start(self, _state: Any, **kwargs: Any) -> str:
        self.started.append(kwargs)
        with hunt_svc.campaign_of_start(kwargs.get("campaign_id")):
            async with self.maker() as db:
                hunt = await hunt_svc.create(
                    db,
                    objective=str(kwargs["objective"]),
                    started_by=str(kwargs["started_by"]),
                    kind=str(kwargs.get("kind") or "chat"),
                    starter=str(kwargs.get("starter") or "analyst"),
                    lead_id=kwargs.get("lead_id"),
                )
        return str(hunt.id)


@pytest.fixture
def console(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> StoreConsole:
    fake = StoreConsole(maker)
    monkeypatch.setattr("soc_ai.webui.hunt_console_manager.get_manager", lambda _s: fake)

    async def _no_earlier(_maker: Any, _lead_id: int) -> None:
        return None

    monkeypatch.setattr("soc_ai.hunting.earlier.earlier_for_lead", _no_earlier)
    return fake


def _state(maker: async_sessionmaker[AsyncSession]) -> SimpleNamespace:
    return SimpleNamespace(db_sessionmaker=maker)


async def _awaiting(maker: async_sessionmaker[AsyncSession]) -> list[int]:
    async with maker() as db:
        return [int(lead.id) for lead in await lead_hunt.leads_awaiting_a_hunt(db)]


async def _hunt_rows(maker: async_sessionmaker[AsyncSession]) -> list[Hunt]:
    async with maker() as db:
        return list((await db.scalars(select(Hunt).order_by(Hunt.created_at))).all())


async def test_the_seed_lead_hunt_runs_once_for_the_campaign(
    maker: async_sessionmaker[AsyncSession], console: StoreConsole
) -> None:
    """D2: the first hunt of a campaign is the lead hunt of its seed. The second lead waits."""
    _run, campaign_id, leads = await seed_campaign(maker)
    assert await _awaiting(maker) == leads
    out = await lead_hunt.start_lead_hunt(
        _state(maker), lead_id=leads[0], started_by=lead_hunt.AUTO_HUNT_ACTOR
    )
    (row,) = await _hunt_rows(maker)
    assert row.id == out.hunt_id
    assert (row.lead_id, row.campaign_id, row.starter) == (leads[0], campaign_id, "lead")
    # The other end of the seed formed a lead too. The campaign had its hunt.
    assert leads[1] not in await _awaiting(maker)


async def test_the_loop_hunts_a_lead_of_the_campaign_again_after_24_hours(
    maker: async_sessionmaker[AsyncSession], console: StoreConsole
) -> None:
    _run, campaign_id, leads = await seed_campaign(maker)
    async with maker() as db:
        db.add(
            Hunt(
                id="01HUNTOLD",
                objective="[campaign 1] x",
                starter="campaign",
                kind="campaign",
                campaign_id=campaign_id,
                status="error",
                created_at=utcnow() - timedelta(hours=25),
            )
        )
        await db.commit()
    assert await _awaiting(maker) == leads
    async with maker() as db:
        hunt = await db.get(Hunt, "01HUNTOLD")
        assert hunt is not None
        # A hunt of any status counts: an error is a hunt too.
        hunt.created_at = utcnow() - timedelta(hours=23)
        await db.commit()
    assert await _awaiting(maker) == []


async def test_a_closed_campaign_starts_no_lead_hunt(
    maker: async_sessionmaker[AsyncSession], console: StoreConsole
) -> None:
    """A late true positive joins a closed campaign: the analyst decided on that activity."""
    _run, campaign_id, _leads = await seed_campaign(maker)
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        row.decision = "closed"
        await db.commit()
    assert await _awaiting(maker) == []


async def test_a_lead_with_a_statistics_observation_keeps_its_hunt(
    maker: async_sessionmaker[AsyncSession], console: StoreConsole
) -> None:
    """The negative control: one observation of another type keeps normal handling (L8)."""
    _run, campaign_id, leads = await seed_campaign(maker)
    async with maker() as db:
        db.add(Hunt(id="01HUNTNOW", objective="x", starter="campaign", campaign_id=campaign_id))
        await db.commit()
    await add_observation(maker, leads[0])
    assert await _awaiting(maker) == [leads[0]]
    await lead_hunt.start_lead_hunt(
        _state(maker), lead_id=leads[0], started_by=lead_hunt.AUTO_HUNT_ACTOR
    )
    rows = {h.id: h for h in await _hunt_rows(maker)}
    (mine,) = [h for h in rows.values() if h.lead_id == leads[0]]
    assert mine.campaign_id is None


async def test_the_start_asks_the_limit_again_under_the_lock(
    maker: async_sessionmaker[AsyncSession], console: StoreConsole
) -> None:
    """A hunt for the campaign started between the selection of the loop and its start."""
    _run, campaign_id, leads = await seed_campaign(maker)
    assert leads[0] in await _awaiting(maker)
    async with maker() as db:
        db.add(Hunt(id="01HUNTRACE", objective="x", starter="campaign", campaign_id=campaign_id))
        await db.commit()
    with pytest.raises(lead_hunt.LeadHuntRefused) as refused:
        await lead_hunt.start_lead_hunt(
            _state(maker), lead_id=leads[0], started_by=lead_hunt.AUTO_HUNT_ACTOR
        )
    assert refused.value.reason == campaign_hunt.REFUSED_HUNTED
    # The analyst's Hunt is the analyst's call. It is a hunt for the campaign.
    out = await lead_hunt.start_lead_hunt(_state(maker), lead_id=leads[0], started_by="analyst")
    async with maker() as db:
        hunt = await db.get(Hunt, out.hunt_id)
    assert hunt is not None and hunt.campaign_id == campaign_id


async def test_the_console_writes_the_campaign_on_the_row_and_not_in_the_hunt_task(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row names its campaign from its first commit. The task that runs the hunt does not."""
    import asyncio

    from soc_ai.webui import hunt_console_manager as hcm

    seen: list[int | None] = []
    done = asyncio.Event()

    async def _run(_state: Any, **kwargs: Any) -> Any:
        async with maker() as db:
            hunt = await hunt_svc.create(
                db,
                objective=str(kwargs["objective"]),
                started_by=str(kwargs["started_by"]),
                kind=str(kwargs["kind"]),
                starter=str(kwargs["starter"]),
            )
        yield "hunt_created", {"hunt_id": hunt.id}
        seen.append(hunt_svc._START_CAMPAIGN.get())
        done.set()

    monkeypatch.setattr(hcm, "hunt_recorded_run", _run)
    monkeypatch.setattr(hcm, "ctx_from_state", lambda _s: SimpleNamespace())
    manager = hcm.HuntConsoleManager()
    hunt_id = await manager.start(
        _state(maker),
        objective="[campaign 7] Hunt for new activity of campaign 7.",
        started_by="campaign-hunt",
        kind="campaign",
        starter="campaign",
        campaign_id=7,
    )
    await asyncio.wait_for(done.wait(), timeout=5)
    assert hunt_id is not None
    async with maker() as db:
        row = await db.get(Hunt, hunt_id)
    assert row is not None and row.campaign_id == 7
    assert seen == [None]
    assert hunt_svc._START_CAMPAIGN.get() is None
