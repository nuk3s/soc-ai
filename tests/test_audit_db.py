"""Tests for the migration runner's handling of SQLite foreign-key enforcement."""

from __future__ import annotations

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from soc_ai.config import Settings
from soc_ai.store import db as db_mod
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import HostDossier, HostDossierField
from sqlalchemy import Connection, delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine


async def _seed_host_with_field(engine: AsyncEngine) -> None:
    maker = make_sessionmaker(engine)
    async with maker() as db:
        host = HostDossier(host_key="10.0.0.5", ip="10.0.0.5")
        db.add(host)
        await db.flush()
        db.add(HostDossierField(dossier_id=host.id, field="role"))
        await db.commit()


async def _field_count(engine: AsyncEngine) -> int:
    maker = make_sessionmaker(engine)
    async with maker() as db:
        return await db.scalar(select(func.count()).select_from(HostDossierField)) or 0


async def _foreign_keys_pragma(engine: AsyncEngine) -> int:
    async with engine.connect() as conn:
        row = (await conn.exec_driver_sql("PRAGMA foreign_keys")).one()
        return int(row[0])


def _rebuild_host_dossier(connection: Connection) -> None:
    """Stand-in for an upgrade step that makes batch mode recreate ``host_dossier``.

    No shipped migration alters a column on a table with ON DELETE children yet,
    so the recreate path (copy, drop the original, rename the copy) is driven
    directly here.
    """
    ctx = MigrationContext.configure(connection, opts={"render_as_batch": True})
    with Operations(ctx).batch_alter_table("host_dossier") as batch:
        batch.alter_column("ip", existing_type=sa.String(64), nullable=True)


async def test_run_migrations_batch_rebuild_keeps_cascade_children(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    await _seed_host_with_field(engine)
    assert await _field_count(engine) == 1

    monkeypatch.setattr(db_mod, "_upgrade_to_head", _rebuild_host_dossier)
    await run_migrations(engine)

    # The DROP of the original table must not have cascaded into the child rows.
    assert await _field_count(engine) == 1
    # Enforcement is back on for the connection the app gets from the pool ...
    assert await _foreign_keys_pragma(engine) == 1
    # ... and it really is enforced: deleting the parent still cascades.
    maker = make_sessionmaker(engine)
    async with maker() as db:
        await db.execute(delete(HostDossier))
        await db.commit()
    assert await _field_count(engine) == 0
    await engine.dispose()


def _insert_orphan_field(connection: Connection) -> None:
    connection.exec_driver_sql(
        "INSERT INTO host_dossier_field (dossier_id, field) VALUES (424242, 'role')"
    )


async def test_run_migrations_rejects_upgrade_that_leaves_dangling_references(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    await _seed_host_with_field(engine)

    monkeypatch.setattr(db_mod, "_upgrade_to_head", _insert_orphan_field)
    with pytest.raises(RuntimeError, match="host_dossier_field"):
        await run_migrations(engine)

    # The offending upgrade was rolled back rather than committed ...
    assert await _field_count(engine) == 1
    # ... and the connection did not go back to the pool with enforcement off.
    assert await _foreign_keys_pragma(engine) == 1
    await engine.dispose()
