"""The leads and the hunts of a campaign: the step after a rebuild (D4, D5).

A lead whose every observation is the alert observation of an investigation
that a campaign holds is a lead of that campaign. The step after each rebuild
sets ``leads.campaign_id`` and removes it, from stored rows. A lead with one
observation of another type keeps normal handling. The same step gives
``hunts.campaign_id`` to the lead hunts of such a lead and to a hunt whose
finding investigations one campaign holds.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from soc_ai.campaigns import lead_tags
from soc_ai.campaigns import service as campaign_svc
from soc_ai.config import Settings
from soc_ai.hunting.sources import ALERT_SPEC_ID
from soc_ai.store import leads as leads_store
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import (
    Campaign,
    CampaignMember,
    CampaignRunOverride,
    EntityObservation,
    HostDossier,
    HostMachine,
    Hunt,
    Investigation,
    Lead,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_facts import seed_run

ACTOR = "10.20.30.5"
TARGET = "10.40.50.7"
THIRD = "10.40.50.9"


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def seed_machines(db: AsyncSession) -> None:
    """Two machines of the network: an agent machine and a network record."""
    actor = HostMachine(
        machine_key="agent:a1",
        agent_name="actor-a",
        agent_id="a1",
        primary_ip=ACTOR,
        address_count=1,
    )
    target = HostMachine(machine_key="ip:t1", name="web-1", primary_ip=TARGET, address_count=1)
    third = HostMachine(machine_key="ip:t3", name="db-1", primary_ip=THIRD, address_count=1)
    db.add_all([actor, target, third])
    await db.flush()
    for address, machine, kind in (
        (ACTOR, actor, "agent"),
        (TARGET, target, "network"),
        (THIRD, third, "network"),
    ):
        db.add(HostDossier(host_key=address, ip=address, machine_id=machine.id, address_kind=kind))
    await db.commit()


async def seed_campaign(
    maker: async_sessionmaker[AsyncSession], alert_id: str = "alert-1", **run: Any
) -> tuple[str, int, list[int]]:
    """One true positive from the actor to the target, its two leads and its campaign.

    The verdict writes one alert observation on each internal end, and each
    forms a lead. The rebuild then forms the campaign.
    """
    async with maker() as db:
        if (await db.scalar(select(HostMachine.id).limit(1))) is None:
            await seed_machines(db)
        run_id = await seed_run(db, alert_id, src=ACTOR, dst=TARGET, **run)
    async with maker() as db:
        await campaign_svc.rebuild(db)
    async with maker() as db:
        campaign_id = await db.scalar(
            select(CampaignMember.campaign_id).where(CampaignMember.run_id == run_id)
        )
        leads = (
            await db.scalars(
                select(EntityObservation.lead_id).where(EntityObservation.fingerprint == alert_id)
            )
        ).all()
    assert campaign_id is not None
    return run_id, int(campaign_id), sorted({int(i) for i in leads if i is not None})


async def add_observation(
    maker: async_sessionmaker[AsyncSession],
    lead_id: int,
    *,
    entity: str = ACTOR,
    spec_id: str = "profile-bytes-out",
    kind: str = "above_baseline",
    fingerprint: str = "fp-stat",
) -> None:
    """A statistics observation on a machine of the campaign, attached to the lead."""
    now = utcnow()
    async with maker() as db:
        db.add(
            EntityObservation(
                entity_kind="host",
                entity_key=entity,
                kind=kind,
                spec_id=spec_id,
                fingerprint=fingerprint,
                birth_weight=0.6,
                born_at=now,
                first_seen_at=now,
                occurrences=1,
                source="profile",
                statistic="bytes_out",
                statistic_value=9.0,
                baseline_value=1.0,
                lead_id=lead_id,
            )
        )
        await db.commit()


async def tags(maker: async_sessionmaker[AsyncSession]) -> dict[int, int | None]:
    async with maker() as db:
        rows = await db.execute(select(Lead.id, Lead.campaign_id))
        return {int(lid): cid for lid, cid in rows.all()}


async def step(maker: async_sessionmaker[AsyncSession]) -> lead_tags.TagResult | None:
    async with maker() as db:
        return await lead_tags.after_rebuild(db, now=utcnow())


async def held(maker: async_sessionmaker[AsyncSession], lead_ids: list[int]) -> dict[int, int]:
    async with maker() as db:
        return await leads_store.campaign_leads(db, lead_ids)


def test_the_store_and_the_hunting_package_name_one_alert_spec() -> None:
    assert leads_store._ALERT_SPEC_ID == ALERT_SPEC_ID


async def test_the_leads_of_held_alerts_take_the_campaign_after_the_rebuild(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    _run, campaign_id, leads = await seed_campaign(maker)
    assert len(leads) == 2
    assert {tags_ for lid, tags_ in (await tags(maker)).items() if lid in leads} == {campaign_id}
    assert await held(maker, leads) == dict.fromkeys(leads, campaign_id)


async def test_the_seed_lead_hunt_takes_the_campaign_id_after_the_rebuild(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """D2: the lead loop hunted the seed lead before the campaign formed."""
    async with maker() as db:
        await seed_machines(db)
        await seed_run(db, "alert-1", src=ACTOR, dst=TARGET)
        lead_id = int(await db.scalar(select(Lead.id).order_by(Lead.id).limit(1)) or 0)
        db.add(Hunt(id="01HUNTSEED", objective="[lead 1] x", lead_id=lead_id, starter="lead"))
        db.add(
            Hunt(
                id="01HUNTEVAL",
                objective="[lead 1] x",
                lead_id=lead_id,
                starter="lead",
                is_synth_eval=True,
            )
        )
        await db.commit()
    async with maker() as db:
        await campaign_svc.rebuild(db)
    async with maker() as db:
        seed = await db.get(Hunt, "01HUNTSEED")
        evaluation = await db.get(Hunt, "01HUNTEVAL")
        campaign_id = await db.scalar(select(Campaign.id))
    assert seed is not None and evaluation is not None
    assert seed.campaign_id == campaign_id
    # The negative control: an evaluation hunt never takes a campaign id.
    assert evaluation.campaign_id is None


async def test_a_lead_with_a_statistics_observation_is_no_lead_of_the_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """The negative control: one observation of another type keeps normal handling."""
    async with maker() as db:
        await seed_machines(db)
        await seed_run(db, "alert-1", src=ACTOR, dst=TARGET)
        first = int(await db.scalar(select(Lead.id).order_by(Lead.id).limit(1)) or 0)
    await add_observation(maker, first)
    async with maker() as db:
        await campaign_svc.rebuild(db)
    found = await tags(maker)
    assert found[first] is None
    assert [cid for lid, cid in found.items() if lid != first] != [None]


async def test_a_lead_loses_the_tag_when_it_gains_another_observation(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    _run, campaign_id, leads = await seed_campaign(maker)
    await add_observation(maker, leads[0])
    # The readers give the lead back at once, before any step runs.
    assert await held(maker, leads) == {leads[1]: campaign_id}
    result = await step(maker)
    assert result is not None and result.untagged == 1
    assert (await tags(maker))[leads[0]] is None
    # The negative control: a dismissed observation counts toward no lead.
    async with maker() as db:
        row = await db.scalar(
            select(EntityObservation).where(EntityObservation.lead_id == leads[1])
        )
        assert row is not None
        db.add(
            EntityObservation(
                entity_kind="host",
                entity_key=TARGET,
                kind="above_baseline",
                spec_id="profile-x",
                fingerprint="fp-x",
                birth_weight=0.6,
                dismissed_at=utcnow(),
                dismissed_reason="benign_repeat",
                lead_id=leads[1],
            )
        )
        await db.commit()
    await step(maker)
    assert (await tags(maker))[leads[1]] == campaign_id


async def test_a_lead_loses_the_tag_when_its_campaign_is_withdrawn(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    run_id, campaign_id, leads = await seed_campaign(maker)
    async with maker() as db:
        db.add(
            CampaignRunOverride(
                run_id=run_id,
                type="excluded",
                campaign_id=campaign_id,
                by="analyst",
                reason="A test of the lab.",
                created_at=utcnow(),
            )
        )
        await db.commit()
    async with maker() as db:
        await campaign_svc.rebuild(db)
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None and row.status == "withdrawn"
    found = await tags(maker)
    assert [found[lid] for lid in leads] == [None, None]
    assert await held(maker, leads) == {}


async def test_a_lead_loses_the_tag_when_its_investigation_is_beyond_an_authorization(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    _run, campaign_id, leads = await seed_campaign(maker)
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        # An authorization whose record the investigation does not match.
        row.decision = "authorized"
        row.authorization_id = 999
        await db.commit()
    await step(maker)
    found = await tags(maker)
    assert [found[lid] for lid in leads] == [None, None]


async def _hand_campaign(db: AsyncSession, *, status: str = "active", **fields: Any) -> Campaign:
    now = utcnow()
    row = Campaign(
        status=status,
        seed_run_id="seed",
        title="actor-a against web-1",
        bottom_line="actor-a acted against web-1.",
        stage="access",
        first_event=now - timedelta(hours=3),
        last_event=now - timedelta(hours=2),
        member_count=1,
        detail={},
        built_at=now,
        **fields,
    )
    db.add(row)
    await db.flush()
    return row


async def test_a_hunt_whose_finding_investigations_one_campaign_holds_takes_its_id(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    run_id, campaign_id, _leads = await seed_campaign(maker)
    async with maker() as db:
        other = await seed_run(
            db, "alert-x", src=THIRD, dst="10.40.50.11", verdict="false_positive"
        )
        db.add(
            Hunt(
                id="01HUNTHELD",
                objective="Hunt the web servers.",
                starter="schedule",
                kind="scheduled",
                finding_investigations={"0": {"investigation_id": run_id, "state": "ended"}},
            )
        )
        db.add(
            Hunt(
                id="01HUNTMIXED",
                objective="Hunt the network.",
                finding_investigations={
                    "0": {"investigation_id": run_id, "state": "ended"},
                    "1": {"investigation_id": other, "state": "ended"},
                },
            )
        )
        db.add(
            Hunt(
                id="01HUNTEVAL2",
                objective="Hunt the web servers.",
                is_synth_eval=True,
                finding_investigations={"0": {"investigation_id": run_id, "state": "ended"}},
            )
        )
        await db.commit()
    await step(maker)
    async with maker() as db:
        found = {
            h.id: h.campaign_id
            for h in (await db.scalars(select(Hunt).where(Hunt.id.like("01HUNT%")))).all()
        }
    assert found["01HUNTHELD"] == campaign_id
    # The negative controls: one finding investigation outside the campaign,
    # and an evaluation hunt.
    assert found["01HUNTMIXED"] is None
    assert found["01HUNTEVAL2"] is None


async def test_a_replay_in_a_campaign_tags_no_lead(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """The negative control: a backtest replay is no investigation of the campaign."""
    _run, campaign_id, _leads = await seed_campaign(maker)
    now = utcnow()
    async with maker() as db:
        replay = Investigation(
            id="01REPLAY",
            alert_es_id="alert-replay",
            started_by="backtest",
            status="complete",
            verdict="true_positive",
        )
        db.add(replay)
        db.add(
            CampaignMember(
                campaign_id=campaign_id,
                run_id="01REPLAY",
                link="session",
                evidence={},
                direction="forward",
                verdict_differs=False,
            )
        )
        lead = Lead(status="open", shadow=False, formed_at=now)
        db.add(lead)
        await db.flush()
        db.add(
            EntityObservation(
                entity_kind="host",
                entity_key=TARGET,
                kind="alert",
                spec_id=ALERT_SPEC_ID,
                fingerprint="alert-replay",
                birth_weight=1.0,
                source="alert",
                lead_id=lead.id,
            )
        )
        await db.commit()
        lead_id = int(lead.id)
    await step(maker)
    assert (await tags(maker))[lead_id] is None


async def test_a_hunt_of_a_merged_campaign_moves_to_the_campaign_that_took_it(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    _run, campaign_id, _leads = await seed_campaign(maker)
    async with maker() as db:
        merged = await _hand_campaign(db, status="merged", merged_into_id=campaign_id)
        db.add(Hunt(id="01HUNTMERGED", objective="x", starter="campaign", campaign_id=merged.id))
        await db.commit()
    await step(maker)
    async with maker() as db:
        hunt = await db.get(Hunt, "01HUNTMERGED")
    assert hunt is not None and hunt.campaign_id == campaign_id
