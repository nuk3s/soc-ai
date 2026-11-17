"""The rebuild of an authorized campaign (A4).

A rebuild gives the engine the investigations that an analyst excluded or
included, and the basis of the freshness check changes when an override
changes. After the commit, each campaign record in force marks the inside
investigations of its campaign. An authorized campaign gets one ``beyond``
change for each new outside investigation, and new activity does not open
it again.

The data is synthetic: placeholder addresses and names.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from soc_ai.campaigns import decisions
from soc_ai.campaigns import service as svc
from soc_ai.config import Settings
from soc_ai.store import authorized_activity as aa
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import (
    Campaign,
    CampaignChange,
    CampaignMember,
    CampaignRunOverride,
    Investigation,
)
from sqlalchemy import select

from tests.test_campaign_facts import ACTOR, TARGET, TARGET_2, seed_hosts, seed_run


class _Audit:
    def __init__(self) -> None:
        self.kinds: list[str] = []

    async def log_kind(self, _session: str, kind: str, _payload: Any, **_kw: Any) -> None:
        self.kinds.append(kind)


@pytest.fixture
async def maker(settings_kratos: Settings) -> Any:
    svc.reset_fresh_cache()
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()
        svc.reset_fresh_cache()


async def _campaign(db: Any) -> Campaign:
    (row,) = (await db.scalars(select(Campaign).where(Campaign.status == "active"))).all()
    return row


async def _members(db: Any, campaign_id: int) -> dict[str, str]:
    rows = await db.execute(
        select(CampaignMember.run_id, CampaignMember.link).where(
            CampaignMember.campaign_id == campaign_id
        )
    )
    return {str(r): str(link) for r, link in rows.all()}


async def _authorize(db: Any, row: Campaign, keys: tuple[str, ...]) -> aa.AuthorizedActivity:
    now = utcnow()
    roles = {
        "agent:a1": ("actor", ACTOR),
        "ip:t1": ("target", TARGET),
        "ip:t2": ("target", TARGET_2),
    }
    record = await aa.create_for_campaign(
        db,
        campaign_id=row.id,
        label="Red team test",
        parties=[aa.PartyEntry(k, roles[k][0], None, (roles[k][1],)) for k in keys],
        starts_at=row.first_event,
        expires_at=now + timedelta(days=7),
        created_by="casey",
        now=now,
        commit=False,
    )
    decisions.write_authorize(
        db, row, authorization_id=record.id, label=record.label, by="casey", basis={}, now=now
    )
    await db.commit()
    return record


async def test_an_excluded_investigation_joins_no_campaign_and_an_included_one_joins(
    maker: Any,
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        ids = [
            await seed_run(db, f"alert-000{n}", event_hours_ago=5 - n, created_minutes_ago=50 - n)
            for n in (1, 2, 3)
        ]
        loose = await seed_run(
            db, "alert-0008", verdict="needs_more_info", event_hours_ago=1, created_minutes_ago=5
        )
        await svc.rebuild(db)
        row = await _campaign(db)
        assert set(await _members(db, row.id)) >= set(ids)
        assert loose not in await _members(db, row.id)
        now = utcnow()
        db.add_all(
            [
                CampaignRunOverride(
                    run_id=ids[2],
                    type="excluded",
                    campaign_id=row.id,
                    by="casey",
                    reason="Another test.",
                    created_at=now,
                ),
                CampaignRunOverride(
                    run_id=loose,
                    type="included",
                    campaign_id=row.id,
                    anchor_run_id=ids[0],
                    by="casey",
                    reason="The same upload.",
                    created_at=now,
                ),
            ]
        )
        await db.commit()
        await svc.rebuild(db)
        members = await _members(db, (await _campaign(db)).id)
    assert ids[2] not in members
    assert members.get(loose) == "included"


async def test_an_override_changes_the_basis_of_the_freshness_check(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        ids = [await seed_run(db, f"alert-000{n}", event_hours_ago=4 - n) for n in (1, 2)]
        assert await svc.ensure_fresh(db)
        before = await svc._basis(db, [])
        row = await _campaign(db)
        db.add(
            CampaignRunOverride(
                run_id=ids[1],
                type="excluded",
                campaign_id=row.id,
                by="casey",
                reason="Another test.",
                created_at=utcnow(),
            )
        )
        await db.commit()
        after = await svc._basis(db, [])
        assert before != after
        assert await svc.ensure_fresh(db)
        assert ids[1] not in await _members(db, (await _campaign(db)).id)


async def test_a_rebuild_marks_a_new_inside_member_and_records_a_new_outside_one_once(
    maker: Any,
) -> None:
    audit = _Audit()
    async with maker() as db:
        await seed_hosts(db)
        first = await seed_run(db, "alert-0001", event_hours_ago=3, created_minutes_ago=40)
        await svc.rebuild(db)
        record = await _authorize(db, await _campaign(db), ("agent:a1", "ip:t1"))
        inside = await seed_run(db, "alert-0002", event_hours_ago=2, created_minutes_ago=30)
        outside = await seed_run(
            db, "alert-0003", dst=TARGET_2, event_hours_ago=1, created_minutes_ago=20
        )
        await svc.rebuild(db, audit=audit)
        await svc.rebuild(db, audit=audit)
        runs = {inv.id: inv for inv in (await db.scalars(select(Investigation))).all()}
        row = await _campaign(db)
        beyond = (
            await db.scalars(
                select(CampaignChange.detail).where(
                    CampaignChange.campaign_id == row.id, CampaignChange.type == "beyond"
                )
            )
        ).all()
    assert runs[first].authorization_id == record.id
    assert runs[inside].authorization_id == record.id
    assert runs[inside].report["authorized_activity"]["campaign_id"] == row.id
    # A negative control: the investigation on the unlisted target keeps normal handling.
    assert runs[outside].authorization_id is None
    assert beyond == [{"runId": outside, "why": "target"}]
    assert audit.kinds.count("authorized_activity_matched") == 2
    # New activity does not open an authorized campaign again.
    assert (row.decision, row.authorization_id) == ("authorized", record.id)


async def test_a_revoked_record_marks_nothing_after_a_rebuild(maker: Any) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-0001", event_hours_ago=3, created_minutes_ago=40)
        await svc.rebuild(db)
        record = await _authorize(db, await _campaign(db), ("agent:a1", "ip:t1"))
        await aa.revoke(db, record.id, by="morgan", reason="Ended.")
        later = await seed_run(db, "alert-0002", event_hours_ago=2, created_minutes_ago=30)
        await svc.rebuild(db)
        inv = await db.get(Investigation, later)
    assert inv.authorization_id is None
