"""An absent JSON value has to be an absence in SQL, not the text ``null``.

SQLAlchemy's ``JSON`` type defaults to ``none_as_null=False``, so a Python
``None`` is serialised by ``json.dumps`` and stored as the two-byte string
``null`` — a JSON value. It deserialises back to ``None``, which is why this
survived so long: every assertion anywhere in this suite reads
``row.col is None`` through the ORM, and every one of them passes either way.
The ORM cannot see the difference. SQL can, and it says the opposite of the
truth: ``WHERE col IS NOT NULL`` matched every row in ten tables and
``WHERE col IS NULL`` matched none.

So these tests do the one thing the existing ones do not: they go around the
mapper and ask the database. Every storage assertion here is raw SQL, because an
assertion made through the ORM is exactly the assertion that already passed
while the bug was live.

The dossier lane was the one place this had already cost behaviour, and it grew
a per-statement workaround (``soc_ai.store.host_dossier._JSON_COLUMNS``) that
covered three columns and missed the two beside them in the same subsystem. The
fix now lives on the column type, so the last test holds the whole set at once
rather than the columns someone remembered to list.
"""

from __future__ import annotations

from typing import Any

import pytest
from alembic import command
from soc_ai.config import Settings
from soc_ai.store import quality as quality_svc
from soc_ai.store.db import _migration_config, make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Base
from sqlalchemy import text
from sqlalchemy.engine import Connection

# Every (table, column) the 0040 migration repairs. Duplicated from the
# migration on purpose: a test that imported the list would agree with the
# migration by construction and could never catch a column dropped from it.
NULLABLE_JSON_COLUMNS = [
    ("investigations", "report"),
    ("hunts", "report"),
    ("backtests", "results"),
    ("chat_messages", "meta"),
    ("internal_identifier", "evidence"),
    ("quality_snapshots", "alarm_reasons"),
    ("model_battery_results", "fitness_result"),
    ("host_dossier_field", "inferred_value_json"),
    ("host_dossier_field", "inferred_evidence"),
    ("host_dossier_field", "operator_value_json"),
    ("dossier_run", "errors"),
    ("dossier_run", "notes"),
    ("general_chat_messages", "meta"),
]


async def _db(settings: Settings) -> Any:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _downgrade_to_0039(connection: Connection) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.downgrade(cfg, "0039")


def _snapshot(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "mode": "local",
        "n_ok": 5,
        "n_error": 0,
        "agreement_rate": None,
        "fallback_rate": None,
        "error_rate": 0.0,
        "verdict_counts": {},
        "latency_p50_ms": None,
        "batch_dir": None,
        "alarmed": False,
        "alarm_reasons": None,
    }
    base.update(overrides)
    return base


async def test_a_none_lands_as_sql_null_not_as_the_text_null(
    settings_kratos: Settings,
) -> None:
    """The canonical case, asked in SQL rather than through the mapper."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await quality_svc.insert_snapshot(db, **_snapshot())
        raw = await db.scalar(text("SELECT alarm_reasons FROM quality_snapshots"))
        assert raw is None, f"stored {raw!r} — the text 'null' is a value, not an absence"

        # The predicate the next person will write. Before the fix this returned
        # the row and ``IS NULL`` returned nothing, which is the trap itself.
        held = (
            await db.execute(
                text("SELECT id FROM quality_snapshots WHERE alarm_reasons IS NOT NULL")
            )
        ).all()
        assert held == []
        absent = (
            await db.execute(text("SELECT id FROM quality_snapshots WHERE alarm_reasons IS NULL"))
        ).all()
        assert len(absent) == 1
    await engine.dispose()


async def test_a_real_value_still_round_trips(settings_kratos: Settings) -> None:
    """The fix must not turn a stored list into an absence."""
    reasons = ["agreement 0.40 against a median of 1.00"]
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await quality_svc.insert_snapshot(db, **_snapshot(alarmed=True, alarm_reasons=reasons))
        raw = await db.scalar(text("SELECT alarm_reasons FROM quality_snapshots"))
        assert raw == '["agreement 0.40 against a median of 1.00"]'
        assert (await quality_svc.recent_snapshots(db))[0].alarm_reasons == reasons
    await engine.dispose()


async def test_the_string_null_is_still_storable_as_a_value(
    settings_kratos: Settings,
) -> None:
    """The migration's repair predicate must not be able to eat a real value.

    ``WHERE col = 'null'`` is exact: a Python string ``"null"`` serialises with
    its quotes, so only a ``None`` bound under the old default produces the bare
    four-byte literal the migration clears.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await quality_svc.insert_snapshot(db, **_snapshot(alarmed=True, alarm_reasons=["null"]))
        raw = await db.scalar(text("SELECT alarm_reasons FROM quality_snapshots"))
        assert raw == '["null"]'
        assert raw != "null"
    await engine.dispose()


async def test_the_migration_repairs_rows_written_before_the_fix(
    settings_kratos: Settings,
) -> None:
    """Legacy rows are normalised, so one query cannot answer two ways.

    Planted as the old code wrote it — the bare text ``null`` — with the schema
    stepped back to 0039, then 0040 is replayed over it. Half a normalised table
    is a worse trap than a uniformly wrong one: the query that motivated this
    would work on this month's rows and silently skip everything older.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await quality_svc.insert_snapshot(db, **_snapshot())

    async with engine.begin() as conn:
        await conn.run_sync(_downgrade_to_0039)
        await conn.execute(text("UPDATE quality_snapshots SET alarm_reasons = 'null'"))

    async with maker() as db:
        assert await db.scalar(text("SELECT alarm_reasons FROM quality_snapshots")) == "null"

    await run_migrations(engine)

    async with maker() as db:
        assert await db.scalar(text("SELECT alarm_reasons FROM quality_snapshots")) is None
        left = (
            await db.execute(
                text("SELECT id FROM quality_snapshots WHERE alarm_reasons IS NOT NULL")
            )
        ).all()
        assert left == []
    await engine.dispose()


@pytest.mark.parametrize(("table", "column"), NULLABLE_JSON_COLUMNS)
def test_every_nullable_json_column_carries_the_absence_preserving_type(
    table: str, column: str
) -> None:
    """The whole set, held at the type rather than at the call sites.

    The dossier workaround protected the three columns someone listed and missed
    ``dossier_run.errors``/``notes`` sitting in the same subsystem. Checking the
    mapped metadata per column is what stops the next optional JSON column from
    being declared with the plain type and nobody noticing for a year.
    """
    col = Base.metadata.tables[table].columns[column]
    assert col.nullable, (
        f"{table}.{column} is not nullable — this test is aimed at the wrong column"
    )
    assert getattr(col.type, "none_as_null", False) is True, (
        f"{table}.{column} would store a Python None as the JSON text 'null'"
    )
