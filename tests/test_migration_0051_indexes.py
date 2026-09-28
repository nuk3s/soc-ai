"""Migration 0051: the bell's finished_since queries and the unread-hit count are index-served.

Migrates to head and asserts, the way tests/test_migration_0028_indexes.py does
for its two indexes:

- the three indexes come into being with the expected columns, and
- ``EXPLAIN QUERY PLAN`` of the statements the pollers actually run names them:
  the completed-runs half of the bell no longer sorts every completed row on
  each poll, and the unread shadow-hit count is a SEARCH on the covering index
  rather than a SCAN of the observations table.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from soc_ai.api.webui.routes_analytics import unread_shadow_hits_where
from soc_ai.config import Settings
from soc_ai.hunting.catalog_tiers import Catalog
from soc_ai.store.db import make_engine, run_migrations
from soc_ai.store.investigations import _display_status_sql
from soc_ai.store.models import EntityObservation, Hunt, Investigation
from sqlalchemy import Connection, Select, func, inspect, select
from sqlalchemy.dialects import sqlite
from sqlalchemy.ext.asyncio import AsyncEngine

_CUTOFF = datetime(2026, 9, 1, tzinfo=UTC)

# The bell's completed-investigations query: the display-status CASE, the
# redundant raw-column equality it keeps for the index, and the finished_at
# window and order (soc_ai/store/investigations.py::list_recent_notifications).
_COMPLETED_INVESTIGATIONS = (
    select(Investigation.id)
    .where(_display_status_sql() == "complete")
    .where(Investigation.status == "complete")
    .where(Investigation.finished_at >= _CUTOFF)
    .order_by(Investigation.finished_at.desc(), Investigation.id.desc())
    .limit(20)
)
_COMPLETED_HUNTS = (
    select(Hunt.id)
    .where(Hunt.status == "complete")
    .where(Hunt.finished_at >= _CUTOFF)
    .order_by(Hunt.finished_at.desc(), Hunt.id.desc())
    .limit(20)
)
_ONE_RETIRED = Catalog(specs={}, listed={}, tiers={"retired-one": ("shipped", "retired")})
_UNREAD_HITS = (
    select(func.count(EntityObservation.id))
    .select_from(EntityObservation)
    .where(*unread_shadow_hits_where(_ONE_RETIRED))
)


def _plan(connection: Connection, query: Select[Any]) -> list[str]:
    sql = str(query.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
    rows = connection.exec_driver_sql(f"EXPLAIN QUERY PLAN {sql}").all()
    return [str(row[-1]) for row in rows]


def _index_columns(connection: Connection, table: str) -> dict[str, list[str | None]]:
    return {ix["name"]: ix["column_names"] for ix in inspect(connection).get_indexes(table)}


async def _migrated(settings: Settings) -> AsyncEngine:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine


async def test_0051_creates_the_indexes(settings_kratos: Settings) -> None:
    engine = await _migrated(settings_kratos)
    async with engine.connect() as conn:
        investigations = await conn.run_sync(_index_columns, "investigations")
        hunts = await conn.run_sync(_index_columns, "hunts")
        observations = await conn.run_sync(_index_columns, "entity_observations")
    await engine.dispose()
    assert investigations["ix_investigations_status_finished"] == ["status", "finished_at"]
    assert hunts["ix_hunts_status_finished"] == ["status", "finished_at"]
    assert observations["ix_entity_observation_unread"] == ["shadow", "read_at", "spec_id"]


async def test_finished_since_queries_seek_on_finished_at(settings_kratos: Settings) -> None:
    engine = await _migrated(settings_kratos)
    async with engine.connect() as conn:
        investigations = await conn.run_sync(_plan, _COMPLETED_INVESTIGATIONS)
        hunts = await conn.run_sync(_plan, _COMPLETED_HUNTS)
    await engine.dispose()
    for plan, index in (
        (investigations, "ix_investigations_status_finished"),
        (hunts, "ix_hunts_status_finished"),
    ):
        assert any(index in line for line in plan), plan
        # The id tiebreak may still sort the last term; a sort of the whole
        # completed set on every poll is what the index is for.
        assert "USE TEMP B-TREE FOR ORDER BY" not in plan, plan


async def test_unread_hit_count_searches_the_covering_index(settings_kratos: Settings) -> None:
    engine = await _migrated(settings_kratos)
    async with engine.connect() as conn:
        plan = await conn.run_sync(_plan, _UNREAD_HITS)
    await engine.dispose()
    assert any("ix_entity_observation_unread" in line for line in plan), plan
    assert not any(line.startswith("SCAN entity_observations") for line in plan), plan
