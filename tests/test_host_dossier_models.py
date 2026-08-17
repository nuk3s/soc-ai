"""Tests for the host-dossier schema (migration 0024) and its shared types.

Two things are pinned here, both of which other modules are built directly on
top of:

* **The 0024 schema** — the three tables, their indexes, the two uniqueness
  guarantees, the FK cascade, and a real ``downgrade()`` that reverses. The
  column sets are asserted by EQUALITY (not subset) because the store service,
  the resolver and the API all read column names straight off these tables; a
  silent addition or rename should surface here first.
* **``soc_ai.dossier.types``** — ``DOSSIER_FIELDS``, the provenance ladder,
  ``Fact`` and ``HostObservations``. These are the contract between the
  collector, the classifier, the store and the prompt renderer, so their names,
  ordering and defaults are asserted rather than assumed.

Scratch-DB recipe copied from tests/test_hunts_store.py: a real SQLite file
migrated to head, isolated per test by the autouse ``clean_env`` fixture.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from alembic import command
from soc_ai.config import Settings
from soc_ai.dossier.types import (
    DOSSIER_FIELDS,
    PROVENANCE_LADDER,
    STRENGTH_CONFIDENCE,
    Fact,
    HostObservations,
    provenance_rank,
)
from soc_ai.store.db import _migration_config, make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import DossierRun, HostDossier, HostDossierField
from sqlalchemy import Connection, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

HOST_DOSSIER_COLUMNS = {
    "id",
    "host_key",
    "ip",
    "first_seen",
    "last_seen",
    "last_built_at",
    "last_observed_at",
    "event_count",
    "identity_fingerprint",
    "identity_rebound_at",
    "build_error",
    "created_at",
    "updated_at",
}

HOST_DOSSIER_FIELD_COLUMNS = {
    "id",
    "dossier_id",
    "field",
    # inference lane — written ONLY by upsert_inferred()
    "inferred_value",
    "inferred_value_json",
    "inferred_confidence",
    "inferred_source",
    "inferred_evidence",
    "inferred_first_seen",
    "inferred_last_seen",
    "inferred_last_run_at",
    "inferred_retracted_at",
    # operator lane — written ONLY by set_override() / clear_override()
    "operator_value",
    "operator_value_json",
    "operator_set_at",
    "operator_actor",
    "operator_note",
    # conflict / prod state
    "conflict_kind",
    "conflict_first_seen_at",
    "conflict_observations",
    "conflict_last_prompted_at",
    "conflict_prompt_count",
    "conflict_snoozed_until",
}

DOSSIER_RUN_COLUMNS = {
    "id",
    "started_at",
    "finished_at",
    "trigger",
    "hosts_seen",
    "hosts_built",
    "fields_written",
    "conflicts_detected",
    "conflicts_prompted",
    "errors",
    # Advisory notes (truncation / cadence), kept apart from errors — migration
    # 0029 so a healthy-but-capped sweep does not report an error count.
    "notes",
}


async def _db(settings: Settings) -> AsyncEngine:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine


def _downgrade_to_0023(connection: Connection) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.downgrade(cfg, "0023")


async def _table_names(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        return set(await conn.run_sync(lambda sc: inspect(sc).get_table_names()))


async def _columns(engine: AsyncEngine, table: str) -> set[str]:
    async with engine.connect() as conn:
        cols = await conn.run_sync(lambda sc: inspect(sc).get_columns(table))
    return {c["name"] for c in cols}


async def _indexes(engine: AsyncEngine, table: str) -> dict[str, dict[str, Any]]:
    async with engine.connect() as conn:
        rows = await conn.run_sync(lambda sc: inspect(sc).get_indexes(table))
    return {row["name"]: row for row in rows}


# ---------------------------------------------------------------------------
# Migration 0024 — tables, columns, indexes, constraints
# ---------------------------------------------------------------------------


async def test_migration_creates_the_three_dossier_tables(settings_kratos: Settings) -> None:
    engine = await _db(settings_kratos)
    tables = await _table_names(engine)
    assert {"host_dossier", "host_dossier_field", "dossier_run"} <= tables
    await engine.dispose()


async def test_host_dossier_columns(settings_kratos: Settings) -> None:
    engine = await _db(settings_kratos)
    assert await _columns(engine, "host_dossier") == HOST_DOSSIER_COLUMNS
    await engine.dispose()


async def test_host_dossier_field_columns_split_into_two_lanes(
    settings_kratos: Settings,
) -> None:
    """The whole design rests on there being NO ``value`` column.

    An operator override cannot be clobbered by an inference run because nothing
    the builder writes is the effective value — the resolver computes it at read
    time from the two lanes. A stored ``value`` (or ``confidence`` / ``source``
    without a lane prefix) would reintroduce exactly the column a rebuild
    overwrites, so their absence is asserted, not just their siblings' presence.
    """
    engine = await _db(settings_kratos)
    columns = await _columns(engine, "host_dossier_field")
    assert columns == HOST_DOSSIER_FIELD_COLUMNS
    assert "value" not in columns
    assert "confidence" not in columns
    assert "source" not in columns
    await engine.dispose()


async def test_dossier_run_columns(settings_kratos: Settings) -> None:
    engine = await _db(settings_kratos)
    assert await _columns(engine, "dossier_run") == DOSSIER_RUN_COLUMNS
    await engine.dispose()


async def test_migration_creates_the_dossier_indexes(settings_kratos: Settings) -> None:
    engine = await _db(settings_kratos)

    host_indexes = await _indexes(engine, "host_dossier")
    assert "ix_host_dossier_ip" in host_indexes
    # The staleness sort key: the builder selects ORDER BY last_built_at ASC.
    assert "ix_host_dossier_last_built_at" in host_indexes
    assert host_indexes["uq_host_dossier_host_key"]["unique"]
    assert host_indexes["uq_host_dossier_host_key"]["column_names"] == ["host_key"]

    field_indexes = await _indexes(engine, "host_dossier_field")
    assert "ix_host_dossier_field_dossier_id" in field_indexes
    # GET /dossiers/conflicts filters on conflict_first_seen_at IS NOT NULL.
    assert "ix_host_dossier_field_conflict" in field_indexes

    run_indexes = await _indexes(engine, "dossier_run")
    assert "ix_dossier_run_started_at" in run_indexes

    await engine.dispose()


async def test_host_key_is_unique(settings_kratos: Settings) -> None:
    engine = await _db(settings_kratos)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO host_dossier (host_key, ip) "
                "VALUES ('192.168.10.202', '192.168.10.202')"
            )
        )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            # Same host_key, different ip -> still a duplicate host.
            await conn.execute(
                text(
                    "INSERT INTO host_dossier (host_key, ip) "
                    "VALUES ('192.168.10.202', '192.168.10.9')"
                )
            )
    await engine.dispose()


async def test_one_row_per_host_and_field(settings_kratos: Settings) -> None:
    engine = await _db(settings_kratos)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO host_dossier (host_key, ip) "
                "VALUES ('192.168.10.202', '192.168.10.202')"
            )
        )
        await conn.execute(
            text("INSERT INTO host_dossier_field (dossier_id, field) VALUES (1, 'role')")
        )
        # A different field on the same host is fine.
        await conn.execute(
            text("INSERT INTO host_dossier_field (dossier_id, field) VALUES (1, 'hostname')")
        )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO host_dossier_field (dossier_id, field) VALUES (1, 'role')")
            )

    async with engine.connect() as conn:
        constraints = await conn.run_sync(
            lambda sc: inspect(sc).get_unique_constraints("host_dossier_field")
        )
    assert "uq_host_dossier_field" in {c["name"] for c in constraints}
    await engine.dispose()


async def test_deleting_a_host_cascades_to_its_fields(settings_kratos: Settings) -> None:
    # make_engine sets PRAGMA foreign_keys=ON, so the cascade is enforced by
    # SQLite rather than left to the ORM to remember.
    engine = await _db(settings_kratos)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO host_dossier (host_key, ip) "
                "VALUES ('192.168.10.202', '192.168.10.202')"
            )
        )
        await conn.execute(
            text("INSERT INTO host_dossier_field (dossier_id, field) VALUES (1, 'role')")
        )
        await conn.execute(text("DELETE FROM host_dossier WHERE id = 1"))
        remaining = await conn.execute(text("SELECT COUNT(*) FROM host_dossier_field"))
    assert remaining.scalar_one() == 0
    await engine.dispose()


async def test_counter_columns_default_to_zero(settings_kratos: Settings) -> None:
    # The conflict state machine does `conflict_observations += 1` on a row it
    # may have just created; a NULL counter would make that a no-op forever.
    engine = await _db(settings_kratos)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO host_dossier (host_key, ip) "
                "VALUES ('192.168.10.202', '192.168.10.202')"
            )
        )
        await conn.execute(
            text("INSERT INTO host_dossier_field (dossier_id, field) VALUES (1, 'role')")
        )
        await conn.execute(
            text("INSERT INTO dossier_run (started_at, trigger) VALUES ('2026-08-06', 'schedule')")
        )
        counters = await conn.execute(
            text(
                "SELECT event_count, "
                "(SELECT conflict_observations FROM host_dossier_field), "
                "(SELECT conflict_prompt_count FROM host_dossier_field), "
                "(SELECT hosts_seen FROM dossier_run), "
                "(SELECT conflicts_prompted FROM dossier_run) "
                "FROM host_dossier"
            )
        )
    assert counters.one() == (0, 0, 0, 0, 0)
    await engine.dispose()


async def test_downgrade_drops_the_dossier_tables(settings_kratos: Settings) -> None:
    engine = await _db(settings_kratos)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade_to_0023)
    tables = await _table_names(engine)
    assert not ({"host_dossier", "host_dossier_field", "dossier_run"} & tables)
    async with engine.connect() as conn:
        head = await conn.execute(text("SELECT version_num FROM alembic_version"))
    assert head.scalar_one() == "0023"
    await engine.dispose()


async def test_migration_is_replayable_after_downgrade(settings_kratos: Settings) -> None:
    # A downgrade that leaves an index or FK behind fails on the way back up.
    engine = await _db(settings_kratos)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade_to_0023)
    await run_migrations(engine)
    assert {"host_dossier", "host_dossier_field", "dossier_run"} <= await _table_names(engine)
    await engine.dispose()


async def test_orm_models_match_the_migrated_schema(settings_kratos: Settings) -> None:
    """The ORM metadata and the migration must agree, column for column.

    Where they drift, ``alembic revision --autogenerate`` proposes dropping
    whatever it cannot see in the models (the reason ``Investigation`` declares
    its 0003 index in ``__table_args__``).
    """
    engine = await _db(settings_kratos)
    for model in (HostDossier, HostDossierField, DossierRun):
        declared = {c.name for c in model.__table__.columns}
        assert declared == await _columns(engine, model.__tablename__), model.__tablename__
    await engine.dispose()


async def test_sessionmaker_still_builds_after_the_migration(settings_kratos: Settings) -> None:
    engine = await _db(settings_kratos)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        rows = await db.execute(text("SELECT COUNT(*) FROM host_dossier"))
        assert rows.scalar_one() == 0
    await engine.dispose()


# ---------------------------------------------------------------------------
# soc_ai.dossier.types — the cross-module contract
# ---------------------------------------------------------------------------


def test_dossier_fields_are_the_twelve_contract_fields() -> None:
    assert DOSSIER_FIELDS == (
        "hostname",
        "mac",
        "os_family",
        "os_detail",
        "role",
        "services_offered",
        "management_plane",
        "domain_membership",
        "is_static_addressed",
        "activity_profile",
        "criticality",
        "policy_notes",
    )
    assert len(set(DOSSIER_FIELDS)) == 12
    # host_dossier_field.field is String(32).
    assert all(len(name) <= 32 for name in DOSSIER_FIELDS)


def test_provenance_ladder_is_ascending() -> None:
    assert PROVENANCE_LADDER == ("behaviour", "telemetry", "banner", "hostlog", "osquery")
    assert [provenance_rank(source) for source in PROVENANCE_LADDER] == [0, 1, 2, 3, 4]
    # host_dossier_field.inferred_source is String(16).
    assert all(len(source) <= 16 for source in PROVENANCE_LADDER)


def test_an_unknown_source_ranks_below_every_rung() -> None:
    # The merge is "strongest source wins"; an unrecognised string must lose it
    # rather than crash it. "operator" is deliberately NOT a rung — the operator
    # lane is a separate column family the resolver reads, never a merge input.
    assert provenance_rank("nonsense") == -1
    assert provenance_rank("operator") == -1


def test_strength_maps_to_the_stored_confidence() -> None:
    assert STRENGTH_CONFIDENCE == {"strong": 0.9, "weak": 0.5, "none": 0.0}


def test_fact_is_frozen_and_defaults_to_no_signal() -> None:
    fact = Fact(field="role")
    assert fact.value is None
    assert fact.value_json is None
    assert fact.confidence == 0.0
    assert fact.strength == "none"
    assert fact.evidence == []
    assert fact.observed_at is None
    assert fact.conflict is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        fact.value = "server"  # type: ignore[misc]


def test_fact_evidence_is_not_shared_between_instances() -> None:
    first, second = Fact(field="role"), Fact(field="hostname")
    first.evidence.append("responds on tcp/8006 (from behaviour)")
    assert second.evidence == []


def test_host_observations_is_frozen_and_empty_by_default() -> None:
    obs = HostObservations(ip="192.168.10.202")
    assert obs.total_events == 0
    assert obs.resp_ports == [] and obs.orig_ports == []
    assert obs.user_agents == () and obs.dhcp == ()
    assert obs.available_datasets == frozenset()
    assert obs.errors == ()
    assert obs.first_seen is None and obs.ptr_name is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        obs.ip = "192.168.10.9"  # type: ignore[misc]


def test_host_observations_mutable_defaults_are_per_instance() -> None:
    first, second = HostObservations(ip="192.168.10.202"), HostObservations(ip="192.168.10.9")
    first.resp_ports.append({"value": 8006, "count": 41})
    first.hour_of_day[3] = 12
    assert second.resp_ports == []
    assert second.hour_of_day == {}
