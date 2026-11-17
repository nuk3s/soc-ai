"""The campaign of a lead and of a hunt (migration 0073).

``leads.campaign_id`` and ``hunts.campaign_id`` name the campaign that a lead
or a hunt belongs to. Both are nullable and indexed. A hunt that a campaign
starts has the starter ``campaign``, and every reader of the kind and the
starter of a hunt states it.

The data is synthetic: placeholder addresses and names.
"""

from __future__ import annotations

from datetime import UTC, datetime

from soc_ai.campaigns.facts import _tier
from soc_ai.campaigns.types import TIER_HUNT, TIER_LEAD_HUNT
from soc_ai.config import Settings
from soc_ai.hunting import hunt_words
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import run_usage
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Hunt, Lead
from sqlalchemy import Connection, inspect, select, text

from tests.test_campaign_store import _downgrade_to, _upgrade_to

_NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC).replace(tzinfo=None)


def _indexes(sc: Connection, table: str) -> dict[str, list[str]]:
    return {str(ix["name"]): list(ix["column_names"]) for ix in inspect(sc).get_indexes(table)}


def _columns(sc: Connection, table: str) -> dict[str, bool]:
    return {str(c["name"]): bool(c["nullable"]) for c in inspect(sc).get_columns(table)}


async def test_the_head_is_0073_and_both_tables_hold_an_indexed_campaign_id(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        head = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
        leads = await conn.run_sync(_columns, "leads")
        hunts = await conn.run_sync(_columns, "hunts")
        lead_ix = await conn.run_sync(_indexes, "leads")
        hunt_ix = await conn.run_sync(_indexes, "hunts")
    await engine.dispose()
    assert head == "0073"
    assert leads["campaign_id"] is True
    assert hunts["campaign_id"] is True
    assert lead_ix["ix_leads_campaign_id"] == ["campaign_id"]
    assert hunt_ix["ix_hunts_campaign_id"] == ["campaign_id"]


async def test_a_downgrade_removes_both_columns_and_keeps_the_rows(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        db.add(Lead(status="open", campaign_id=7))
        await db.commit()
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade_to, "0072")
        down = await conn.run_sync(_columns, "leads")
        count = (await conn.execute(text("SELECT count(*) FROM leads"))).scalar_one()
        await conn.run_sync(_upgrade_to, "head")
        up = await conn.run_sync(_columns, "hunts")
    await engine.dispose()
    assert "campaign_id" not in down
    assert count == 1
    assert "campaign_id" in up


async def test_the_store_keeps_the_starter_campaign_and_the_campaign_id(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        hunt = await hunt_svc.create(
            db,
            objective="[campaign 4] Hunt for new activity of campaign 4.",
            started_by="campaign-hunt",
            kind="campaign",
            starter="campaign",
            campaign_id=4,
        )
        row = (await db.scalars(select(Hunt).where(Hunt.id == hunt.id))).one()
    await engine.dispose()
    assert (row.kind, row.starter, row.campaign_id, row.lead_id) == (
        "campaign",
        "campaign",
        4,
        None,
    )


async def test_an_evaluation_hunt_never_takes_a_campaign_id(settings_kratos: Settings) -> None:
    """The negative control: an evaluation hunt describes nothing real."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        hunt = await hunt_svc.create(
            db,
            objective="[campaign 4] Hunt for new activity of campaign 4.",
            started_by="eval",
            kind="campaign",
            starter="campaign",
            campaign_id=4,
            is_synth_eval=True,
        )
    await engine.dispose()
    assert hunt.campaign_id is None


def _hunt(**fields: object) -> Hunt:
    return Hunt(id="01HUNT", objective="x", started_by="campaign-hunt", **fields)


def test_each_reader_of_the_kind_and_the_starter_states_a_campaign_hunt() -> None:
    hunt = _hunt(kind="campaign", starter="campaign", campaign_id=4)
    assert run_usage.hunt_entry(hunt) == "Campaign hunt"
    # A campaign hunt is a hunt of soc-ai on the campaign: no lead names it.
    assert _tier("finding", ("campaign", None)) == TIER_HUNT
    assert _tier("finding", ("lead", 3)) == TIER_LEAD_HUNT
    assert hunt_words.campaign_of("[campaign 4] Hunt for new activity of campaign 4.") == 4
    assert hunt_words.campaign_of("[lead 4] Investigate 10.20.30.5.") is None
    assert hunt_words.hunt_title("[campaign 4] Hunt for new activity of campaign 4.") == (
        "Campaign 4 hunt"
    )


def test_the_starter_of_a_campaign_hunt_reads_campaign_on_the_hunts_page() -> None:
    from soc_ai.api.webui.routes_hunts import _starter_of

    assert _starter_of(_hunt(kind="campaign", starter="campaign")) == "campaign"
    # The negative control: a catalog run keeps its word.
    assert _starter_of(_hunt(kind="triggered", starter="analyst")) == "catalog"
