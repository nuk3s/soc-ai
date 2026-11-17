"""The changes of a campaign, and a decision that survives a rebuild (D2).

A rebuild compares each campaign with its stored row. A new campaign is
``formed``. A higher stage writes ``stage``, and a new machine writes
``party``. A closed campaign stays closed while nothing new happened. A later
event, a higher stage or a new machine opens it again, and the rebuild writes
one ``reopened`` change with the cause. The rebuild deletes the member and
party rows and plans the ids again, so each case runs a rebuild after a close.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from soc_ai.campaigns import decisions, service
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign, CampaignChange, Investigation
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_facts import (
    ACTOR_2,
    RULE_B,
    TARGET_2,
    alert_doc,
    seed_hosts,
    seed_run,
)


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _three_runs(db: AsyncSession) -> list[str]:
    """Three true positive alert runs of one actor on one target, 3, 2 and 1 hours ago."""
    await seed_hosts(db)
    return [
        await seed_run(db, f"alert-000{n}", event_hours_ago=4 - n, created_minutes_ago=40 - n)
        for n in (1, 2, 3)
    ]


async def _campaigns(db: AsyncSession) -> list[Campaign]:
    return list((await db.scalars(select(Campaign).order_by(Campaign.id))).all())


async def _changes(db: AsyncSession, campaign_id: int | None = None) -> list[tuple[str, Any]]:
    query = select(CampaignChange).order_by(CampaignChange.id)
    if campaign_id is not None:
        query = query.where(CampaignChange.campaign_id == campaign_id)
    return [(c.type, c.detail) for c in (await db.scalars(query)).all()]


async def _close(maker: async_sessionmaker[AsyncSession], campaign_id: int) -> None:
    """Close the campaign as the close route does: the basis of the stored row."""
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        row.decision = decisions.DECISION_CLOSED
        row.close_reason = "test_over"
        row.decided_by = "analyst"
        row.decided_at = utcnow()
        row.decision_basis = await decisions.basis_for(db, row)
        await db.commit()


async def _closed_campaign(maker: async_sessionmaker[AsyncSession]) -> int:
    async with maker() as db:
        await _three_runs(db)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
    await _close(maker, campaign.id)
    return campaign.id


async def _rebuild_with(maker: async_sessionmaker[AsyncSession], **run: Any) -> None:
    async with maker() as db:
        await seed_run(db, **run)
        await service.rebuild(db)


# ── The changes ────────────────────────────────────────────────────────────


async def test_a_new_campaign_is_formed_once_and_a_second_rebuild_writes_no_change(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await _three_runs(db)
        await service.rebuild(db)
    async with maker() as db:
        assert len(await _campaigns(db)) == 1
        assert await _changes(db) == [("formed", {})]
        await service.rebuild(db)
    async with maker() as db:
        assert await _changes(db) == [("formed", {})]


async def test_the_first_rebuild_after_the_upgrade_writes_no_change_for_an_old_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await _three_runs(db)
        await service.rebuild(db)
        # The store as the upgrade leaves it: a campaign and no change row.
        await db.execute(delete(CampaignChange))
        await db.commit()
    async with maker() as db:
        await service.rebuild(db)
    async with maker() as db:
        assert await _changes(db) == []
        # A negative control: a new stage on the old campaign is a change.
        await seed_run(db, "alert-s", event_hours_ago=3.5, report={"stage": "access"})
        await service.rebuild(db)
    async with maker() as db:
        assert await _changes(db) == [("stage", {"from": "attempt", "to": "access"})]


async def test_a_new_machine_writes_one_party_change_with_its_name(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await _three_runs(db)
        await service.rebuild(db)
        await seed_run(db, "alert-p", dst=TARGET_2, event_hours_ago=3.5)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        assert await _changes(db, campaign.id) == [
            ("formed", {}),
            ("party", {"names": ["web-2"]}),
        ]


# ── A close and a rebuild ──────────────────────────────────────────────────


async def test_a_rebuild_with_no_new_activity_keeps_the_close(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _closed_campaign(maker)
    async with maker() as db:
        await service.rebuild(db, refresh_facts=True)
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        assert (row.decision, row.close_reason, row.decided_by) == (
            "closed",
            "test_over",
            "analyst",
        )
        assert [t for t, _d in await _changes(db)] == ["formed"]
        # A close changes no verdict.
        verdicts = (await db.scalars(select(Investigation.verdict))).all()
        assert set(verdicts) == {"true_positive"}


@pytest.mark.parametrize(
    ("run", "cause"),
    [
        ({"alert_id": "alert-n", "event_hours_ago": 0.5}, "activity"),
        (
            {"alert_id": "alert-s", "event_hours_ago": 3.5, "report": {"stage": "access"}},
            "stage",
        ),
        ({"alert_id": "alert-p", "dst": TARGET_2, "event_hours_ago": 3.5}, "party"),
    ],
)
async def test_a_new_event_a_higher_stage_and_a_new_machine_each_open_the_close_once(
    maker: async_sessionmaker[AsyncSession], run: dict[str, Any], cause: str
) -> None:
    campaign_id = await _closed_campaign(maker)
    await _rebuild_with(maker, **run)
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        assert (row.decision, row.close_reason, row.decision_basis) == (None, None, None)
        reopened = [d for t, d in await _changes(db) if t == "reopened"]
        assert reopened == [{"cause": cause}]
        # One more rebuild with nothing new writes no second reopen.
        await service.rebuild(db)
    async with maker() as db:
        assert [d for t, d in await _changes(db) if t == "reopened"] == [{"cause": cause}]


async def test_a_rerun_of_an_old_investigation_with_the_same_event_time_keeps_the_close(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    at = utcnow() - timedelta(hours=1)
    context = {"alert": alert_doc("alert-r", at)}
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-q", event_hours_ago=3, created_minutes_ago=50)
        old = await seed_run(db, "alert-r", context=context, created_minutes_ago=40)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
    await _close(maker, campaign.id)
    await _rebuild_with(maker, alert_id="alert-r", context=context, created_minutes_ago=5)
    async with maker() as db:
        row = await db.get(Campaign, campaign.id)
        assert row is not None
        assert row.decision == "closed"
        members = await service.links_of(db, [old])
        # The Re-run took the place of the old run, and the rebuild rewrote the rows.
        assert old not in members
        assert [t for t, _d in await _changes(db)] == ["formed"]


async def test_the_close_survives_a_withdraw_and_a_revive(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-a")
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
    await _close(maker, campaign.id)
    for verdict, status in (("false_positive", "withdrawn"), ("true_positive", "active")):
        async with maker() as db:
            await inv_svc.resolve(
                db,
                run_id,
                verdict=verdict,
                confidence=0.9,
                rationale="The analyst changed the verdict.",
                recommended_actions=None,
                resolved_by="analyst",
                resolved_via="manual",
            )
            await service.rebuild(db)
        async with maker() as db:
            row = await db.get(Campaign, campaign.id)
            assert row is not None
            assert (row.status, row.decision) == (status, "closed")
    async with maker() as db:
        # The revive is no new campaign and no new machine.
        assert [t for t, _d in await _changes(db)] == ["formed"]


async def _two_campaigns(maker: async_sessionmaker[AsyncSession]) -> tuple[int, int]:
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-a", event_hours_ago=10)
        await seed_run(db, "alert-b", src=ACTOR_2, dst=TARGET_2, rule=RULE_B, event_hours_ago=8)
        await service.rebuild(db)
    async with maker() as db:
        older, newer = await _campaigns(db)
    return older.id, newer.id


async def test_a_merged_campaign_passes_no_decision_on(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    older, newer = await _two_campaigns(maker)
    await _close(maker, newer)
    await _rebuild_with(maker, alert_id="alert-c", dst=TARGET_2, rule=RULE_B, event_hours_ago=9)
    async with maker() as db:
        kept = await db.get(Campaign, older)
        merged = await db.get(Campaign, newer)
        assert kept is not None and merged is not None
        assert (merged.status, merged.merged_into_id) == ("merged", older)
        assert (kept.status, kept.decision) == ("active", None)
        assert ("party", {"names": ["actor-b", "web-2"]}) in await _changes(db, older)


async def test_a_merge_that_adds_machines_to_a_closed_campaign_opens_it_again(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    older, _newer = await _two_campaigns(maker)
    await _close(maker, older)
    await _rebuild_with(maker, alert_id="alert-c", dst=TARGET_2, rule=RULE_B, event_hours_ago=9.5)
    async with maker() as db:
        kept = await db.get(Campaign, older)
        assert kept is not None
        assert (kept.status, kept.decision) == ("active", None)
        assert [d for t, d in await _changes(db, older) if t == "reopened"] == [{"cause": "party"}]


def test_a_basis_that_soc_ai_cannot_read_covers_nothing() -> None:
    now = utcnow()
    assert decisions.reopen_cause(None, now, "attempt", ["ip:t1"]) == "activity"
    assert decisions.reopen_cause({"parties": "x"}, now, None, []) == "activity"
    basis = decisions.basis_of(now, "attempt", ["ip:t1", "agent:a1"])
    # A negative control: the same campaign stays covered.
    assert decisions.reopen_cause(basis, now, "attempt", ["agent:a1", "ip:t1"]) is None
    assert decisions.reopen_cause(basis, now, "reconnaissance", ["ip:t1"]) is None
