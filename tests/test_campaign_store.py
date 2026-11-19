"""Migrations 0068 to 0071: the campaign tables, the events, the decisions, the overrides.

The engine writes a campaign, its members, its parties and the facts of each
run. A run is a member of one campaign at most, so the store refuses a second
member row with the same ``run_id``. Three nullable columns of ``campaigns``
hold the events of the last grid read. Migration 0070 adds the decision
columns of ``campaigns`` and the table of the changes of each campaign.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from alembic import command
from soc_ai.config import Settings
from soc_ai.store.auth import utcnow
from soc_ai.store.db import _migration_config, make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign, CampaignChange, CampaignMember, CampaignRunOverride
from sqlalchemy import Connection, inspect, select, text
from sqlalchemy.exc import IntegrityError

pytestmark = pytest.mark.asyncio

TABLES = {"campaigns", "campaign_members", "campaign_parties", "campaign_run_facts"}
EVENT_COLUMNS = {"events", "events_at", "events_basis"}
DECISION_COLUMNS = {
    "decision",
    "decided_at",
    "decided_by",
    "decision_note",
    "close_reason",
    "decision_basis",
    "authorization_id",
    "case_id",
}


def _upgrade_to(connection: Connection, revision: str) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, revision)


def _downgrade_to(connection: Connection, revision: str) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.downgrade(cfg, revision)


async def test_the_head_is_0076_and_holds_the_campaign_tables(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: set(inspect(sc).get_table_names()))
        members = await conn.run_sync(
            lambda sc: {ix["name"]: ix for ix in inspect(sc).get_indexes("campaign_members")}
        )
        head = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert head.scalar_one() == "0076"
    await engine.dispose()
    assert tables >= TABLES
    assert members["ux_campaign_members_run"]["unique"]


async def test_a_downgrade_removes_the_tables_and_an_upgrade_adds_them_again(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade_to, "0067")
        after_down = await conn.run_sync(lambda sc: set(inspect(sc).get_table_names()))
        await conn.run_sync(_upgrade_to, "head")
        after_up = await conn.run_sync(lambda sc: set(inspect(sc).get_table_names()))
        head = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert head.scalar_one() == "0076"
    await engine.dispose()
    assert after_down.isdisjoint(TABLES)
    # A negative control: the downgrade removes the campaign tables only.
    assert "authorized_activity" in after_down
    assert after_up >= TABLES


async def test_two_members_with_one_run_id_raise(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    now = utcnow()

    def _member(campaign_id: int, run_id: str) -> CampaignMember:
        return CampaignMember(
            campaign_id=campaign_id,
            run_id=run_id,
            link="seed",
            evidence={},
            direction="forward",
            stage=None,
            verdict_differs=False,
        )

    async with maker() as db:
        campaign = Campaign(
            seed_run_id="run-a",
            title="Exploit attempts against web-1",
            bottom_line="One actor sent exploit attempts to web-1.",
            first_event=now - timedelta(hours=2),
            last_event=now,
            member_count=2,
            detail={},
            built_at=now,
        )
        db.add(campaign)
        await db.flush()
        assert campaign.status == "active"
        # A negative control: two different runs are two members.
        db.add_all([_member(campaign.id, "run-a"), _member(campaign.id, "run-b")])
        await db.commit()
        db.add(_member(campaign.id, "run-a"))
        with pytest.raises(IntegrityError):
            await db.commit()
    await engine.dispose()


async def test_0069_adds_the_three_event_columns_and_a_downgrade_drops_them(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)

    def columns(sc: Connection) -> dict[str, dict[str, object]]:
        return {c["name"]: c for c in inspect(sc).get_columns("campaigns")}

    async with engine.begin() as conn:
        at_head = await conn.run_sync(columns)
        await conn.run_sync(_downgrade_to, "0068")
        after_down = await conn.run_sync(columns)
        await conn.run_sync(_upgrade_to, "head")
        after_up = await conn.run_sync(columns)
    await engine.dispose()
    assert set(at_head) >= EVENT_COLUMNS
    assert all(at_head[name]["nullable"] for name in EVENT_COLUMNS)
    assert set(after_down).isdisjoint(EVENT_COLUMNS)
    # A negative control: the downgrade keeps the campaign table and its other columns.
    assert {"detail", "built_at", "title"} <= set(after_down)
    assert set(after_up) >= EVENT_COLUMNS


async def test_a_campaign_row_holds_no_events_until_a_grid_read(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    now = utcnow()
    async with maker() as db:
        campaign = Campaign(
            seed_run_id="run-a",
            title="actor-a against web-1",
            bottom_line="actor-a acted against web-1.",
            first_event=now - timedelta(hours=2),
            last_event=now,
            member_count=1,
            detail={},
            built_at=now,
        )
        db.add(campaign)
        await db.commit()
        assert (campaign.events, campaign.events_at, campaign.events_basis) == (None, None, None)
        campaign.events = {"source": "grid", "alerts": 3}
        campaign.events_at = now
        campaign.events_basis = "a" * 40
        await db.commit()
        held = await db.get(Campaign, campaign.id)
        assert held is not None
        assert held.events == {"source": "grid", "alerts": 3}
    await engine.dispose()


async def test_0070_adds_the_decision_columns_and_the_changes_and_a_downgrade_drops_them(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)

    def shape(sc: Connection) -> tuple[dict[str, dict[str, object]], set[str]]:
        columns = {c["name"]: c for c in inspect(sc).get_columns("campaigns")}
        return columns, set(inspect(sc).get_table_names())

    async with engine.begin() as conn:
        at_head, tables_head = await conn.run_sync(shape)
        await conn.run_sync(_downgrade_to, "0069")
        after_down, tables_down = await conn.run_sync(shape)
        await conn.run_sync(_upgrade_to, "head")
        after_up, tables_up = await conn.run_sync(shape)
    await engine.dispose()
    assert set(at_head) >= DECISION_COLUMNS
    assert all(at_head[name]["nullable"] for name in DECISION_COLUMNS)
    assert "campaign_changes" in tables_head
    assert set(after_down).isdisjoint(DECISION_COLUMNS)
    assert "campaign_changes" not in tables_down
    # A negative control: the downgrade keeps the events of 0069.
    assert set(after_down) >= EVENT_COLUMNS
    assert set(after_up) >= DECISION_COLUMNS
    assert "campaign_changes" in tables_up


async def test_a_campaign_has_no_decision_until_one_is_written(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    now = utcnow()
    async with maker() as db:
        campaign = Campaign(
            seed_run_id="run-a",
            title="actor-a against web-1",
            bottom_line="actor-a acted against web-1.",
            first_event=now - timedelta(hours=2),
            last_event=now,
            member_count=1,
            detail={},
            built_at=now,
        )
        db.add(campaign)
        await db.commit()
        assert (campaign.decision, campaign.decision_basis, campaign.close_reason) == (
            None,
            None,
            None,
        )
        db.add(CampaignChange(campaign_id=campaign.id, type="formed", detail={}, created_at=now))
        campaign.decision = "closed"
        campaign.close_reason = "test_over"
        campaign.decision_basis = {"last_event": now.isoformat(), "stage": None, "parties": []}
        await db.commit()
        held = await db.get(Campaign, campaign.id)
        assert held is not None
        assert (held.decision, held.close_reason) == ("closed", "test_over")
        (change,) = (await db.scalars(select(CampaignChange))).all()
        assert (change.campaign_id, change.type, change.detail) == (campaign.id, "formed", {})
    await engine.dispose()


async def test_0071_adds_the_campaign_record_columns_and_the_overrides_and_a_downgrade_drops_them(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)

    def shape(sc: Connection) -> tuple[set[str], set[str], dict[str, dict[str, object]]]:
        columns = {c["name"] for c in inspect(sc).get_columns("authorized_activity")}
        tables = set(inspect(sc).get_table_names())
        indexes = (
            {ix["name"]: ix for ix in inspect(sc).get_indexes("campaign_run_overrides")}
            if "campaign_run_overrides" in tables
            else {}
        )
        return columns, tables, indexes

    async with engine.begin() as conn:
        at_head, tables_head, indexes = await conn.run_sync(shape)
        await conn.run_sync(_downgrade_to, "0070")
        after_down, tables_down, _ = await conn.run_sync(shape)
        await conn.run_sync(_upgrade_to, "head")
        after_up, tables_up, _ = await conn.run_sync(shape)
    await engine.dispose()
    assert {"campaign_id", "parties"} <= at_head
    assert "campaign_run_overrides" in tables_head
    assert indexes["ux_campaign_run_overrides_run"]["unique"]
    assert {"campaign_id", "parties"}.isdisjoint(after_down)
    assert "campaign_run_overrides" not in tables_down
    # A negative control: the downgrade keeps the decisions of 0070.
    assert "campaign_changes" in tables_down
    assert {"rule_names", "sources", "expires_at"} <= after_down
    assert {"campaign_id", "parties"} <= after_up
    assert "campaign_run_overrides" in tables_up


async def test_one_override_for_each_investigation(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    now = utcnow()

    def _override(run_id: str) -> CampaignRunOverride:
        return CampaignRunOverride(
            run_id=run_id,
            type="excluded",
            campaign_id=1,
            by="analyst",
            reason="Other test.",
            created_at=now,
        )

    async with maker() as db:
        # A negative control: two investigations are two overrides.
        db.add_all([_override("run-a"), _override("run-b")])
        await db.commit()
        db.add(_override("run-a"))
        with pytest.raises(IntegrityError):
            await db.commit()
    await engine.dispose()
