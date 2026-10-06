"""Alembic environment.

Supports two invocation paths:
- programmatic at app startup (a live Connection is passed via config.attributes)
- ``alembic -c soc_ai/store/alembic.ini`` CLI: the URL comes from that ini, or
  from ``-x db_url=sqlite:////abs/path/soc-ai.db`` to target another store.
  ``-x db_url=postgresql+asyncpg://user:password@host/db`` targets a PostgreSQL
  store; the chain then runs through asyncpg with the session in UTC.
"""

from __future__ import annotations

import asyncio
from typing import Any, Literal

from alembic import context
from soc_ai.store.dialect import UtcDateTime
from soc_ai.store.models import Base
from sqlalchemy import URL, Connection, engine_from_config, make_url, pool

config = context.config
target_metadata = Base.metadata


def _render_item(type_: str, obj: Any, _autogen_context: Any) -> str | Literal[False]:
    # The models import the store's UTC type under the name DateTime; a new
    # revision states the plain column type, which is what the store holds.
    if type_ == "type" and isinstance(obj, UtcDateTime):
        return "sa.DateTime()"
    return False


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite ALTERs need batch mode. On PostgreSQL the same batch blocks
        # run as plain ALTER statements: Alembic rebuilds a table on SQLite only.
        render_as_batch=True,
        render_item=_render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_postgres(url: URL) -> None:
    from soc_ai.store.db import make_postgres_engine  # noqa: PLC0415 - CLI path only

    engine = make_postgres_engine(url, pool_size=1)
    try:
        async with engine.connect() as conn, conn.begin():
            await conn.run_sync(_run)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    connection: Connection | None = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    # The ini URL is relative to the cwd, so a manual upgrade or downgrade run
    # from anywhere else would create and migrate an empty store instead of
    # touching the real one; -x db_url names the store to run against.
    x_args = context.get_x_argument(as_dictionary=True)
    if "db_url" in x_args:
        config.set_main_option("sqlalchemy.url", x_args["db_url"])
    url = make_url(config.get_main_option("sqlalchemy.url") or "")
    if url.get_backend_name() == "postgresql":
        # soc-ai ships asyncpg only, so every PostgreSQL spelling runs through it.
        asyncio.run(_run_postgres(url.set(drivername="postgresql+asyncpg")))
        return
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as conn:
        _run(conn)
        conn.commit()


run_migrations_online()
