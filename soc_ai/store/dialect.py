"""The parts of the store that differ between SQLite and PostgreSQL.

The store runs on SQLite by default and on PostgreSQL when
``SOC_AI_DATABASE_URL`` names one. Both dialects hold the same schema through
the same migration chain. This module keeps the few places where the two
dialects disagree in one file, so a reader can see every difference at once.

The datetime contract
---------------------
Every timestamp column stores a naive datetime in UTC, on both dialects.

* SQLite has no timezone type. ``CURRENT_TIMESTAMP`` is UTC to the second.
* PostgreSQL ``now()`` returns a ``timestamptz``. A column without a timezone
  keeps the wall clock of the SESSION timezone, so a server in another zone
  would store local time. :func:`_now_utc_postgresql` renders every
  ``func.now()`` as UTC, in DDL defaults and in queries alike, and the engine
  sets the session timezone to UTC as well (see :mod:`soc_ai.store.db`).
* asyncpg refuses a datetime WITH a timezone for a column without one, and
  SQLite stored the wall clock of such a value. :class:`UtcDateTime` converts
  an aware value to naive UTC before either driver sees it.

``func.now()`` on PostgreSQL uses ``statement_timestamp()``. SQLite fixes
``CURRENT_TIMESTAMP`` once per statement, and PostgreSQL ``now()`` is fixed
once per transaction, so ``statement_timestamp()`` is the closer match.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import functions
from sqlalchemy.types import TypeDecorator

SQLITE = "sqlite"
POSTGRESQL = "postgresql"


@compiles(functions.now, POSTGRESQL)
def _now_utc_postgresql(_element: Any, _compiler: Any, **_kw: Any) -> str:
    return "timezone('utc', statement_timestamp())"


class UtcDateTime(TypeDecorator[datetime]):
    """``DateTime`` without a timezone that stores an aware value as naive UTC.

    The column type is a plain ``DateTime`` on both dialects, so the migration
    chain and the parity test see no change. Only the bind value changes: a
    value with a timezone becomes the same instant in UTC, without the zone.
    A naive value passes through. The store already treats a naive value as
    UTC (``soc_ai.store.auth.utcnow``).
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if isinstance(value, datetime) and value.tzinfo is not None:
            return value.astimezone(UTC).replace(tzinfo=None)
        return value

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        return value


def dialect_name(bind: Any) -> str:
    """The dialect name of an engine, a connection or a session.

    Takes an ``AsyncSession``, an ``AsyncConnection``, an ``AsyncEngine`` or
    their sync forms. A session answers through the engine it is bound to.
    """
    get_bind = getattr(bind, "get_bind", None)
    if callable(get_bind):
        bind = get_bind()
    return str(bind.dialect.name)


def is_sqlite(bind: Any) -> bool:
    return dialect_name(bind) == SQLITE
