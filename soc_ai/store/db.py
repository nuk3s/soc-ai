"""Async engine and session factory for the local store."""

from __future__ import annotations

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
    """
    async with engine.connect() as conn:
        await conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        try:
            await conn.run_sync(_upgrade_to_head)
            violations = (await conn.exec_driver_sql("PRAGMA foreign_key_check")).all()
            if violations:
                await conn.rollback()
                tables = sorted({str(row[0]) for row in violations})
                raise RuntimeError(
                    "store migration left rows that reference missing parents in "
                    f"{', '.join(tables)}; the upgrade was rolled back"
                )
            await conn.commit()
        finally:
            await conn.rollback()
            await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
