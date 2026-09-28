"""Alembic environment.

Supports two invocation paths:
- programmatic at app startup (a live Connection is passed via config.attributes)
- ``alembic -c soc_ai/store/alembic.ini`` CLI: the URL comes from that ini, or
  from ``-x db_url=sqlite:////abs/path/soc-ai.db`` to target another store
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
    # The ini URL is relative to the cwd, so a manual upgrade or downgrade run
    # from anywhere else would create and migrate an empty store instead of
    # touching the real one; -x db_url names the store to run against.
    x_args = context.get_x_argument(as_dictionary=True)
    if "db_url" in x_args:
        config.set_main_option("sqlalchemy.url", x_args["db_url"])
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as conn:
        _run(conn)
        conn.commit()


run_migrations_online()
