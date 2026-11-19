"""The engine reads the end of the activity of an investigation (round 4, E3).

The owner, 2026-11-19: "A later alert of a confirmed rule keeps a campaign
open." The links of the engine measured each horizon from the event time of
an investigation only. An attack from the same actor 10 days after the last
investigation event then started a second campaign, while the first one was
open on later alerts of the same actor.

An investigation now carries an optional end of its activity
(``RunFacts.active_until``). The rebuild sets it for a true positive
investigation of an active campaign from the stored grid read: the last
alert of a confirmed rule between its two machines. Each horizon check
measures the gap between two activities. With no end of activity the engine
gives the result of before: ``tests/test_campaign_engine.py`` holds no edit.

The data is synthetic: placeholder addresses, names and rule names. Each
stored time of the store tests is relative to now.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
from soc_ai.campaigns import events, service
from soc_ai.campaigns.engine import build_campaigns
from soc_ai.campaigns.types import RunFacts, jsonable
from soc_ai.config import Settings
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign, CampaignMember
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_engine import A1, A2, T1, T2, at, member, only, run
from tests.test_campaign_facts import RULE, RULE_B, TARGET_2, seed_hosts, seed_run

HOURS = service.decay_horizon_hours()


# ── The engine ─────────────────────────────────────────────────────────────


def _two_attacks(active_until: datetime | None) -> list[RunFacts]:
    """An attack of actor-a on web-1, and one on web-2 with another rule 10 days later."""
    first = run("r1", 0.0, A1, T1, active_until=active_until)
    later = run("r2", 240.0, A1, T2, label="RULE B", rules=frozenset({"RULE B"}))
    return [first, later]


def test_a_new_attack_of_the_actor_joins_the_campaign_that_later_alerts_keep_open() -> None:
    assert HOURS < 240.0
    # The last alert of the pair is 1 day before the new attack.
    draft = only(build_campaigns(_two_attacks(at(216.0))))
    assert draft.run_ids == ("r1", "r2")
    link = member(draft, "r2").link
    assert (link.type, link.member_run_id, link.machine) == ("actor", "r1", A1)
    # The event times of the investigations give the period, as before.
    assert (draft.first_event, draft.last_event) == (at(0.0), at(240.0))


def test_the_same_attack_with_no_later_alert_starts_its_own_campaign() -> None:
    """NEGATIVE CONTROL: with no end of activity the engine is the engine of before."""
    drafts = build_campaigns(_two_attacks(None))
    assert [d.run_ids for d in drafts] == [("r1",), ("r2",)]
    # An end of activity before the event time, or more than one horizon
    # before the new attack, keeps two campaigns too.
    assert len(build_campaigns(_two_attacks(at(-1.0)))) == 2
    assert len(build_campaigns(_two_attacks(at(240.0 - HOURS - 1.0)))) == 2


def test_a_chain_of_the_actor_reads_the_latest_end_of_its_part() -> None:
    """The Actor chain of one source cuts where a run starts one horizon after the part."""
    runs = [
        run("r1", 0.0, A1, T1, active_until=at(200.0)),
        # Inside the activity of r1, with no later alert of its own.
        run("r2", 10.0, A1, T1),
        # 10 days after r2, 2 days after the end of the activity of r1.
        run("r3", 250.0, A1, T2, label="RULE B", rules=frozenset({"RULE B"})),
    ]
    assert only(build_campaigns(runs)).run_ids == ("r1", "r2", "r3")
    # NEGATIVE CONTROL: the end of r1 alone carries the chain.
    plain = [replace(r, active_until=None) for r in runs]
    assert [d.run_ids for d in build_campaigns(plain)] == [("r1", "r2"), ("r3",)]


def test_a_new_actor_with_the_same_rule_measures_from_the_end_of_the_activity() -> None:
    """The Artifact link of a new source machine needs one horizon: the gap of two activities."""
    first = run("r1", 0.0, A1, T1, active_until=at(216.0))
    other = run("r2", 240.0, A2, T1)
    draft = only(build_campaigns([first, other]))
    assert member(draft, "r2").link.type == "artifact"
    # NEGATIVE CONTROL: with no later alert the new actor is too late.
    assert len(build_campaigns([replace(first, active_until=None), other])) == 2


def test_a_target_that_acts_after_the_later_alerts_of_its_attack_joins() -> None:
    """The link Target as source measures from the end of the activity of the attack."""
    hit = run("r1", 0.0, A1, T1, impact="succeeded", active_until=at(200.0))
    acts = run("r2", 300.0, T1, T2, label="RULE B", rules=frozenset({"RULE B"}))
    draft = only(build_campaigns([hit, acts]))
    assert member(draft, "r2").link.type == "target_source"
    # NEGATIVE CONTROL: with no later alert the target acts too late.
    assert len(build_campaigns([replace(hit, active_until=None), acts])) == 2


def test_the_end_of_activity_is_no_stored_fact_of_the_run() -> None:
    held = run("r1", 0.0, active_until=at(5.0))
    stored = held.to_json()
    assert "active_until" not in stored
    assert RunFacts.from_json(stored) == replace(held, active_until=None)


def test_the_earlier_campaign_ended_before_the_draft_starts_by_its_activity() -> None:
    """``_earlier`` reads the end of the activity of the other campaign."""
    old = only(build_campaigns([run("r1", 0.0, A1, T1, active_until=at(50.0))]))
    new = only(build_campaigns([run("r2", 30.0, A1, T1)]))
    # The alerts of the older campaign go on past the start of the new one.
    assert service._earlier(1, [old, new], [1, 2]) is None
    # NEGATIVE CONTROL: with no later alert the older campaign is earlier.
    plain = only(build_campaigns([run("r1", 0.0, A1, T1)]))
    assert service._earlier(1, [plain, new], [1, 2]) == 1


# ── The rebuild ────────────────────────────────────────────────────────────


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _old_campaign(maker: async_sessionmaker[AsyncSession]) -> int:
    """Three attacks of actor-a on web-1, 10 days ago."""
    async with maker() as db:
        await seed_hosts(db)
        for n, hours in enumerate((241.0, 240.5, 240.0), start=1):
            await seed_run(db, f"alert-000{n}", event_hours_ago=hours, created_minutes_ago=60 - n)
        await service.rebuild(db)
    async with maker() as db:
        (campaign_id,) = (await db.scalars(select(Campaign.id))).all()
        return int(campaign_id)


async def _store_read(
    maker: async_sessionmaker[AsyncSession], campaign_id: int, last: datetime, *, alerts: int
) -> None:
    """The stored grid read of the campaign: ``alerts`` events of RULE, the last at ``last``."""
    rules = (events.RuleEvents(RULE, alerts, last - timedelta(days=9), last, "true_positive"),)
    pair = events.PairEvents(
        "agent:a1",
        "ip:t1",
        alerts=alerts,
        other_alerts=0 if alerts else 7,
        first_at=last - timedelta(days=9) if alerts else None,
        last_at=last if alerts else None,
        rules=rules if alerts else (events.RuleEvents("Example Other Rule", 7, last, last),),
    )
    held = events.CampaignEvents(
        source="grid",
        alerts=alerts,
        pairs=(pair,),
        last_alert_at=last if alerts else None,
        read_to=utcnow(),
    )
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        row.events = jsonable(held)
        row.events_at = utcnow()
        row.events_basis = "a-basis"
        row.last_alert_at = last if alerts else None
        row.events_to = utcnow()
        await db.commit()


async def _new_attack(maker: async_sessionmaker[AsyncSession]) -> dict[int, set[str]]:
    """An attack of actor-a on web-2 with another rule, now.

    Returns the members of each active campaign.
    """
    async with maker() as db:
        await seed_run(
            db, "alert-0009", dst=TARGET_2, rule=RULE_B, event_hours_ago=0.2, created_minutes_ago=1
        )
        await service.rebuild(db)
    async with maker() as db:
        rows = (
            await db.execute(
                select(CampaignMember.campaign_id, CampaignMember.run_id)
                .join(Campaign, Campaign.id == CampaignMember.campaign_id)
                .where(Campaign.status == service.STATUS_ACTIVE)
            )
        ).all()
    out: dict[int, set[str]] = {}
    for cid, run_id in rows:
        out.setdefault(int(cid), set()).add(str(run_id))
    return out


async def test_the_rebuild_joins_a_new_attack_to_the_campaign_that_alerts_keep_open(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _old_campaign(maker)
    await _store_read(maker, campaign_id, utcnow() - timedelta(days=1), alerts=40)
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        assert service.api_status(row, utcnow()) == service.STATUS_OPEN
    held = await _new_attack(maker)
    assert list(held) == [campaign_id]
    assert len(held[campaign_id]) == 4


@pytest.mark.parametrize("alerts", [0, None])
async def test_with_no_later_alert_the_new_attack_starts_its_own_campaign(
    maker: async_sessionmaker[AsyncSession], alerts: int | None
) -> None:
    """NEGATIVE CONTROLS: no grid read, and a read with alerts of another rule only."""
    campaign_id = await _old_campaign(maker)
    if alerts is not None:
        await _store_read(maker, campaign_id, utcnow() - timedelta(days=1), alerts=alerts)
    held = await _new_attack(maker)
    assert len(held) == 2
    assert len(held[campaign_id]) == 3
