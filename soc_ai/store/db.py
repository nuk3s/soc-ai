"""Async engine and session factory for the local store."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from soc_ai.config import Settings

_LOGGER = logging.getLogger(__name__)


def make_engine(settings: Settings) -> AsyncEngine:
    """Create the aiosqlite engine; ensures the data directory exists."""
    settings.soc_ai_data_dir.mkdir(parents=True, exist_ok=True)
    db_path = settings.soc_ai_data_dir / "soc-ai.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    return engine


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


def _migration_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    return cfg


def _upgrade_to_head(connection: Connection) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, "head")


def _current_revision(connection: Connection) -> str | None:
    """The revision the store is stamped at (None for an empty store)."""
    from alembic.runtime.migration import MigrationContext  # noqa: PLC0415 - lazy

    return MigrationContext.configure(connection).get_current_revision()


def _script_head() -> str | None:
    from alembic.script import ScriptDirectory  # noqa: PLC0415 - lazy

    return ScriptDirectory.from_config(_migration_config()).get_current_head()


async def run_migrations(engine: AsyncEngine) -> None:
    """Bring the store schema to head (called from the app lifespan).

    Alembic's batch mode rebuilds a table for anything SQLite cannot ALTER in
    place: copy the rows into a new table, DROP the original, rename the copy.
    With ``PRAGMA foreign_keys=ON`` (which every pooled connection has, see
    :func:`make_engine`) that DROP is an implicit ``DELETE FROM``, so the ON
    DELETE actions fire and the children of the rebuilt table (dossier fields,
    saved views, runbook embeddings, the observation->lead link) are silently
    emptied while the migration reports success. Enforcement is therefore
    switched off for the duration of the upgrade and back on before the
    connection returns to the pool. The pragma is a no-op inside an open SQLite
    transaction and the driver only begins one ahead of DML, so it must be the
    first statement on the connection. ``foreign_key_check`` is what stands in
    for enforcement meanwhile: an upgrade that leaves dangling references is
    rolled back rather than committed.

    The explicit ``BEGIN`` is what makes that rollback mean anything. The
    driver's implicit transaction only starts ahead of DML, so without it every
    CREATE / ALTER in the chain commits the moment it runs while the version
    stamp and the backfills are what ``rollback()`` undoes. A revision that
    raises half-way (or a process killed inside the startup window) then leaves
    a schema ahead of its stamp, and every later start fails on "table already
    exists" until the store is restored. Opened here, the transaction holds the
    whole chain: Alembic sees it as external and commits nothing on its own, so
    a failed upgrade leaves the store exactly as it found it.

    The check is the migration's, not the store's. It runs only when a
    revision is about to run, and it compares the dangling references after
    the chain with those before it: a store that already held an orphan (a
    restore from an older backup, a row written before the pragma existed)
    keeps starting, with a warning, instead of refusing to boot on a start
    that migrated nothing.
    """
    async with engine.connect() as conn:
        await conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        await conn.exec_driver_sql("BEGIN")
        try:
            if await conn.run_sync(_current_revision) == _script_head():
                return
            before = set((await conn.exec_driver_sql("PRAGMA foreign_key_check")).all())
            await conn.run_sync(_upgrade_to_head)
            after = set((await conn.exec_driver_sql("PRAGMA foreign_key_check")).all())
            introduced = after - before
            if introduced:
                await conn.rollback()
                tables = sorted({str(row[0]) for row in introduced})
                raise RuntimeError(
                    "The store migration left rows that reference missing parents in "
                    f"{', '.join(tables)}. soc-ai rolled the upgrade back."
                )
            if after:
                tables = sorted({str(row[0]) for row in after})
                _LOGGER.warning(
                    "store holds %d row(s) that reference missing parents in %s. "
                    "The rows predate this upgrade. The upgrade left them in place",
                    len(after),
                    ", ".join(tables),
                )
            await conn.commit()
        finally:
            await conn.rollback()
            await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
