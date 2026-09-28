"""The startup migration is one transaction: a failing upgrade leaves nothing behind.

pysqlite's legacy transaction mode only opens a transaction ahead of DML, so
without an explicit BEGIN every CREATE / ALTER in the chain autocommits while
the ``alembic_version`` bookkeeping is rolled back. A revision that raises
half-way then leaves a schema that is ahead of its version stamp, and the next
start fails on "table already exists" forever. The stand-in revision here does
exactly that: it adds a column and an index and then raises.
"""

from __future__ import annotations

import pytest
from alembic.script import ScriptDirectory
from soc_ai.config import Settings
from soc_ai.store import db as db_mod
from soc_ai.store.db import _migration_config, make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import User
from sqlalchemy import Connection, func, inspect, select, text
from sqlalchemy.ext.asyncio import AsyncEngine

_REAL_UPGRADE = db_mod._upgrade_to_head


def _upgrade_then_fail(connection: Connection) -> None:
    """A future revision that changes the schema and then raises mid-way."""
    _REAL_UPGRADE(connection)
    connection.exec_driver_sql("ALTER TABLE users ADD COLUMN probe_col INTEGER")
    connection.exec_driver_sql("CREATE INDEX ix_users_probe ON users (probe_col)")
    raise RuntimeError("boom")


async def _table_names(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        return await conn.run_sync(lambda sc: inspect(sc).get_table_names())


async def _user_columns(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        return await conn.run_sync(lambda sc: {c["name"] for c in inspect(sc).get_columns("users")})


async def _db_head(engine: AsyncEngine) -> str:
    async with engine.connect() as conn:
        row = await conn.execute(text("SELECT version_num FROM alembic_version"))
        return str(row.scalar_one())


async def _assert_pooled_connection_is_ordinary(engine: AsyncEngine) -> None:
    """The connection the app gets back must behave as if no migration ran on it."""
    async with engine.connect() as conn:
        assert (await conn.exec_driver_sql("PRAGMA foreign_keys")).scalar_one() == 1
        isolation = await conn.run_sync(lambda sc: sc.connection.dbapi_connection.isolation_level)
        assert isolation == ""
    maker = make_sessionmaker(engine)
    async with maker() as db:
        db.add(User(username="probe", password_hash="x", role="analyst"))
        await db.flush()
        await db.rollback()
    async with maker() as db:
        assert await db.scalar(select(func.count()).select_from(User)) == 0


async def test_failed_upgrade_on_fresh_store_leaves_nothing_and_retries_cleanly(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(settings_kratos)
    monkeypatch.setattr(db_mod, "_upgrade_to_head", _upgrade_then_fail)

    with pytest.raises(RuntimeError, match="boom"):
        await run_migrations(engine)
    assert await _table_names(engine) == []

    # The retry hits the same bug in the revision, not "table users already exists".
    with pytest.raises(RuntimeError, match="boom"):
        await run_migrations(engine)
    assert await _table_names(engine) == []

    monkeypatch.setattr(db_mod, "_upgrade_to_head", _REAL_UPGRADE)
    await run_migrations(engine)
    assert "users" in await _table_names(engine)
    await _assert_pooled_connection_is_ordinary(engine)
    await engine.dispose()


async def test_failed_upgrade_on_migrated_store_keeps_the_previous_head(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    code_head = ScriptDirectory.from_config(_migration_config()).get_current_head()
    assert await _db_head(engine) == code_head

    monkeypatch.setattr(db_mod, "_upgrade_to_head", _upgrade_then_fail)
    with pytest.raises(RuntimeError, match="boom"):
        await run_migrations(engine)

    assert await _db_head(engine) == code_head
    assert "probe_col" not in await _user_columns(engine)
    await _assert_pooled_connection_is_ordinary(engine)
    await engine.dispose()
