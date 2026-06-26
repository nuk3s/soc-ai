"""Alembic environment.

Supports two invocation paths:
- programmatic at app startup (a live Connection is passed via config.attributes)
- ``alembic -c soc_ai/store/alembic.ini`` CLI (URL comes from that ini / -x db_url)
"""

from __future__ import annotations

from alembic import context
from soc_ai.store.models import Base
from sqlalchemy import Connection, engine_from_config, pool

config = context.config
target_metadata = Base.metadata


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,  # SQLite ALTERs need batch mode
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection: Connection | None = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
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
