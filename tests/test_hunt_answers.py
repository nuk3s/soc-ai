"""The answer of a hunt for each campaign and each lead that it read (LH2, migration 0074).

Production, 2026-11-16: the scheduled hunt of 18:41 UTC read campaign 2 and
lead 73 and found no new event, and neither page showed it. A hunt that ends
complete and not degraded now records one answer for each subject that it
read, from stored facts.

This module is a store test: it also runs on PostgreSQL. The data is
synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.hunting import hunt_answers
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign, CampaignParty, Hunt, HuntAnswer, HuntEvent, Lead
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

ACTOR = "10.20.30.5"
TARGET = "10.40.50.7"
OTHER = "10.40.50.9"

_OBSERVATION = {
    "title": "No new traffic to the target",
    "category": "observation",
    "hosts": [TARGET],
}
_THREAT_ON_TARGET = {
    "title": "Web shell command on web-1",
    "category": "threat",
    "severity": "high",
    "hosts": [ACTOR, TARGET],
}
_THREAT_ELSEWHERE = {
    "title": "Scan of db-1",
    "category": "threat",
    "severity": "medium",
    "hosts": [OTHER],
}
_FAILED = {"title": "zeek.conn: could not run", "category": "visibility_gap"}


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def seed_campaign(db: AsyncSession) -> int:
    now = utcnow()
    row = Campaign(
        status="active",
        seed_run_id="seed",
        title="actor-a against web-1",
        bottom_line="actor-a acted against web-1.",
        stage="access",
        first_event=now - timedelta(hours=30),
        last_event=now - timedelta(hours=26),
        member_count=1,
        detail={},
        built_at=now,
        decision="closed",
    )
    db.add(row)
    await db.flush()
    db.add_all(
        [
            CampaignParty(
                campaign_id=row.id,
                machine_key="ip:a1",
                role="actor",
                name="actor-a",
                addresses=[ACTOR],
                member_runs=1,
                beyond=False,
            ),
            CampaignParty(
                campaign_id=row.id,
                machine_key="ip:t1",
                role="target",
                name="web-1",
                addresses=[TARGET],
                member_runs=1,
                beyond=False,
            ),
        ]
    )
    await db.flush()
    return int(row.id)


async def seed_lead(db: AsyncSession, *, status: str = "open", host: str = TARGET) -> int:
    lead = Lead(
        status=status,
        shadow=False,
        formed_at=utcnow() - timedelta(days=3),
        updated_at=utcnow() - timedelta(days=3),
        entities_json=[["host", host]],
    )
    if status == "dismissed":
        lead.dismissed_at = utcnow() - timedelta(days=2)
    db.add(lead)
    await db.flush()
    return int(lead.id)


async def seed_hunt(
    db: AsyncSession,
    hunt_id: str,
    *,
    findings: list[dict[str, Any]],
    campaign_ids: list[int] | None = None,
    leads: list[str] | None = None,
    status: str = "complete",
    done: dict[str, Any] | None = None,
    hours_ago: float = 1.0,
    **fields: Any,
) -> str:
    now = utcnow()
    db.add(
        Hunt(
            id=hunt_id,
            objective="Hunt the network.",
            kind=fields.pop("kind", "scheduled"),
            starter=fields.pop("starter", "schedule"),
            status=status,
            report={"findings": findings, "narrative": "The hunt read the network."},
            findings_count=len(findings),
            created_at=now - timedelta(hours=hours_ago),
            finished_at=now - timedelta(hours=hours_ago) + timedelta(minutes=13),
            **fields,
        )
    )
    await db.flush()
    started: dict[str, Any] = {"objective": "Hunt the network."}
    if campaign_ids is not None:
        started["campaign_ids"] = campaign_ids
    if leads is not None:
        started["earlier_refs"] = {"leads": leads, "hunts": [], "investigations": []}
    db.add(HuntEvent(hunt_id=hunt_id, sequence=0, kind="hunt_started", payload=started))
    db.add(
        HuntEvent(
            hunt_id=hunt_id,
            sequence=9,
            kind="done",
            payload=done or {"partial": False, "degraded": False},
        )
    )
    await db.commit()
    return hunt_id


async def answers(db: AsyncSession) -> dict[tuple[str, str, int], tuple[str, int | None]]:
    rows = (await db.scalars(select(HuntAnswer))).all()
    return {(r.hunt_id, r.subject_type, r.subject_id): (r.outcome, r.finding_ordinal) for r in rows}


# ── the pure rule ───────────────────────────────────────────────────────────


def test_the_subjects_come_from_the_start_record() -> None:
    payload = {"campaign_ids": [2, "x", True], "earlier_refs": {"leads": ["73", "nope", 74]}}
    assert hunt_answers.subjects_of(payload) == hunt_answers.Subjects(
        campaigns=(2,), leads=(73, 74)
    )
    assert hunt_answers.subjects_of(None) == hunt_answers.Subjects()


def test_the_outcome_comes_from_the_findings_and_their_links() -> None:
    names = lambda f: TARGET in (f.get("hosts") or [])  # noqa: E731
    held = {
        1: hunt_svc.FindingLink(ordinal=1, state=hunt_svc.LINK_CAMPAIGN, campaign_id=2),
    }
    rule = hunt_answers.decide
    assert rule([_OBSERVATION], {}, names, family={2}) == ("no_new_event", None)
    assert rule([_OBSERVATION, _THREAT_ON_TARGET], {}, names, family={2}) == ("new_activity", 1)
    assert rule([_OBSERVATION, _THREAT_ON_TARGET], held, names, family={2}) == ("continues", 1)
    # A finding that a campaign holds is known activity: no new activity of a lead.
    assert rule([_OBSERVATION, _THREAT_ON_TARGET], held, names, family=None) == (
        "no_new_event",
        None,
    )
    # The negative controls: a threat on another machine, and a repeat of another campaign.
    assert rule([_THREAT_ELSEWHERE], {}, names, family={2}) == ("no_new_event", None)
    assert rule([_OBSERVATION, _THREAT_ON_TARGET], held, names, family={5}) == (
        "no_new_event",
        None,
    )
    # New activity outranks the repeat.
    both = [_OBSERVATION, _THREAT_ON_TARGET, _THREAT_ON_TARGET]
    assert rule(both, held, names, family={2}) == ("new_activity", 2)


# ── the writes ──────────────────────────────────────────────────────────────


async def test_the_head_is_0076_and_holds_the_answer_table(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        head = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
        await db.execute(select(HuntAnswer.id).limit(1))
    assert head == "0076"


async def test_a_clean_scheduled_hunt_answers_the_campaign_and_the_lead_it_read(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Prod: the hunt read campaign 2 and lead 73 and reported no threat finding."""
    async with maker() as db:
        campaign_id = await seed_campaign(db)
        lead_id = await seed_lead(db)
        await seed_hunt(
            db,
            "01HUNTCLEAN",
            findings=[_OBSERVATION, _FAILED],
            campaign_ids=[campaign_id],
            leads=[str(lead_id)],
        )
        assert await hunt_answers.record(db, "01HUNTCLEAN", now=utcnow()) == 2
        found = await answers(db)
        assert found == {
            ("01HUNTCLEAN", "campaign", campaign_id): ("no_new_event", None),
            ("01HUNTCLEAN", "lead", lead_id): ("no_new_event", None),
        }
        # Written once.
        assert await hunt_answers.record(db, "01HUNTCLEAN", now=utcnow()) == 0
        views = await hunt_answers.answers_of(db, "campaign", [campaign_id])
    assert [(v.hunt_id, v.outcome, v.starter) for v in views] == [
        ("01HUNTCLEAN", "no_new_event", "schedule")
    ]


async def test_a_threat_on_a_machine_of_the_subject_is_new_activity(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        campaign_id = await seed_campaign(db)
        lead_id = await seed_lead(db)
        other_lead = await seed_lead(db, host=ACTOR.replace(".5", ".6"))
        await seed_hunt(
            db,
            "01HUNTNEW",
            findings=[_OBSERVATION, _THREAT_ON_TARGET],
            campaign_ids=[campaign_id],
            leads=[str(lead_id), str(other_lead)],
        )
        await hunt_answers.record(db, "01HUNTNEW", now=utcnow())
        found = await answers(db)
        views = await hunt_answers.answers_of(db, "lead", [lead_id])
    assert found[("01HUNTNEW", "campaign", campaign_id)] == ("new_activity", 1)
    assert found[("01HUNTNEW", "lead", lead_id)] == ("new_activity", 1)
    # The negative control: the finding names no machine of the other lead.
    assert found[("01HUNTNEW", "lead", other_lead)] == ("no_new_event", None)
    assert views[0].finding_title == "Web shell command on web-1"


async def test_a_finding_held_as_a_repeat_continues_the_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        campaign_id = await seed_campaign(db)
        await seed_hunt(
            db,
            "01HUNTREPEAT",
            findings=[_THREAT_ON_TARGET],
            campaign_ids=[campaign_id],
            finding_investigations={
                "0": hunt_svc.plan_entry(hunt_svc.LINK_CAMPAIGN, campaign_id=campaign_id)
            },
        )
        await hunt_answers.record(db, "01HUNTREPEAT", now=utcnow())
        found = await answers(db)
    assert found == {("01HUNTREPEAT", "campaign", campaign_id): ("continues", 0)}


@pytest.mark.parametrize(
    ("label", "fields"),
    [
        ("evaluation", {"is_synth_eval": True}),
        ("catalog run", {"kind": "triggered"}),
        ("error", {"status": "error"}),
        ("investigating", {"status": "investigating"}),
        ("degraded", {"done": {"partial": False, "degraded": True}}),
        ("partial", {"done": {"partial": True, "degraded": False}}),
        ("failed queries", {"findings": [_FAILED]}),
    ],
)
async def test_a_hunt_that_read_too_little_writes_no_answer(
    maker: async_sessionmaker[AsyncSession], label: str, fields: dict[str, Any]
) -> None:
    """The negative controls: each hunt that cannot state that nothing is new."""
    async with maker() as db:
        campaign_id = await seed_campaign(db)
        lead_id = await seed_lead(db)
        findings = fields.pop("findings", [_OBSERVATION])
        await seed_hunt(
            db,
            "01HUNTNONE",
            findings=findings,
            campaign_ids=[campaign_id],
            leads=[str(lead_id)],
            **fields,
        )
        assert await hunt_answers.record(db, "01HUNTNONE", now=utcnow()) == 0, label


async def test_a_lead_hunt_answers_no_own_lead_and_no_lead_closed_before_it(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        own = await seed_lead(db)
        closed = await seed_lead(db, status="dismissed")
        read = await seed_lead(db)
        await seed_hunt(
            db,
            "01HUNTLEAD",
            findings=[_OBSERVATION],
            leads=[str(own), str(closed), str(read)],
            kind="chat",
            starter="lead",
            lead_id=own,
        )
        await hunt_answers.record(db, "01HUNTLEAD", now=utcnow())
        found = await answers(db)
    assert found == {("01HUNTLEAD", "lead", read): ("no_new_event", None)}


async def test_the_start_step_fills_the_hunts_of_the_last_30_days(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        campaign_id = await seed_campaign(db)
        await seed_hunt(
            db, "01HUNTRECENT", findings=[_OBSERVATION], campaign_ids=[campaign_id], hours_ago=30
        )
        await seed_hunt(
            db,
            "01HUNTOLD",
            findings=[_OBSERVATION],
            campaign_ids=[campaign_id],
            hours_ago=24 * 40,
        )
        assert await hunt_answers.fill(db, now=utcnow()) == 1
        assert await hunt_answers.fill(db, now=utcnow()) == 0
        found = await answers(db)
    assert set(found) == {("01HUNTRECENT", "campaign", campaign_id)}


async def test_a_deleted_hunt_takes_its_answers(maker: async_sessionmaker[AsyncSession]) -> None:
    async with maker() as db:
        campaign_id = await seed_campaign(db)
        await seed_hunt(db, "01HUNTGONE", findings=[_OBSERVATION], campaign_ids=[campaign_id])
        await hunt_answers.record(db, "01HUNTGONE", now=utcnow())
        assert await hunt_svc.delete(db, "01HUNTGONE")
        assert await answers(db) == {}


async def test_the_recorder_writes_the_answers_when_the_hunt_ends(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """The one call site of a hunt with no subject finding: the end of the recorder."""
    from soc_ai.api.hunt_recorder import HuntRecorder

    async with maker() as db:
        campaign_id = await seed_campaign(db)
        await db.commit()
    recorder = HuntRecorder(maker, objective="o", started_by="schedule", kind="scheduled")
    hunt_id = await recorder.start()
    assert hunt_id
    await recorder.record("hunt_started", 0, {"objective": "o", "campaign_ids": [campaign_id]})
    await recorder.record("hunt_report", 1, {"findings": [_OBSERVATION], "narrative": "Clean."})
    await recorder.record("done", 2, {"partial": False, "degraded": False})
    await recorder.finish("complete")
    async with maker() as db:
        found = await answers(db)
    assert found == {(hunt_id, "campaign", campaign_id): ("no_new_event", None)}


async def test_a_scheduled_hunt_closes_no_lead_and_writes_its_answer(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """LH5: a clean scheduled hunt that read an open lead leaves the lead open.

    The settle rule moves only the lead that a lead hunt was started on
    (:func:`soc_ai.store.leads.settle_after_hunt`). The scheduled hunt writes
    its answer on the lead. The recorder test of test_leads_store holds the
    other half: a clean lead hunt closes its own lead.
    """
    from soc_ai.api.hunt_recorder import HuntRecorder
    from soc_ai.store import leads as leads_store

    async with maker() as db:
        lead_id = await seed_lead(db)
        await db.commit()
    recorder = HuntRecorder(maker, objective="o", started_by="schedule", kind="scheduled")
    hunt_id = await recorder.start()
    assert hunt_id
    await recorder.record(
        "hunt_started", 0, {"objective": "o", "earlier_refs": {"leads": [str(lead_id)]}}
    )
    await recorder.record("hunt_report", 1, {"findings": [_OBSERVATION], "narrative": "Clean."})
    await recorder.record("done", 2, {"partial": False, "degraded": False})
    await recorder.finish("complete")
    async with maker() as db:
        lead = await db.get(Lead, lead_id)
        hunt = await db.get(Hunt, hunt_id)
        assert hunt is not None and lead is not None
        assert lead.status == "open"
        assert await leads_store.settle_after_hunt(db, hunt) == "none"
        assert await leads_store.settle_finished_hunts(db) == 0
        found = await answers(db)
    assert found == {(hunt_id, "lead", lead_id): ("no_new_event", None)}
