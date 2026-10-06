"""Store behaviour that only a live PostgreSQL can show.

Every test here skips unless SOC_AI_TEST_DATABASE_URL names a PostgreSQL
server (see the ``postgres_store`` fixture in tests/conftest.py). The CI job
``store-postgres`` runs them, with the store test modules, as ``-m postgres``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta, timezone

import pytest
from soc_ai.config import Settings
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Hunt
from sqlalchemy import select, text

from tests.conftest import POSTGRES_TEST_URL

pytestmark = pytest.mark.skipif(
    not POSTGRES_TEST_URL, reason="SOC_AI_TEST_DATABASE_URL names no PostgreSQL server"
)


async def test_the_run_points_the_store_at_postgres(
    settings_kratos: Settings, postgres_store: str | None
) -> None:
    """The guard on the harness: a green PostgreSQL run must have used PostgreSQL."""
    assert postgres_store is not None
    engine = make_engine(settings_kratos)
    try:
        assert engine.dialect.name == "postgresql"
        assert engine.url.database == postgres_store.rsplit("/", 1)[1]
        assert not (settings_kratos.soc_ai_data_dir / "soc-ai.db").exists()
    finally:
        await engine.dispose()


async def test_the_session_runs_in_utc(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    try:
        async with engine.connect() as conn:
            zone = (await conn.execute(text("SHOW timezone"))).scalar_one()
    finally:
        await engine.dispose()
    assert zone == "UTC"


async def test_a_server_default_is_utc_under_another_session_zone(
    settings_kratos: Settings,
) -> None:
    """The DDL default is UTC by itself; it does not lean on the session zone.

    The negative control is the zone: a session in UTC-10 that inserted with a
    plain ``now()`` default stores a stamp ten hours behind the UTC clock.
    """
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SET LOCAL timezone = 'Pacific/Honolulu'"))
            await conn.execute(
                text(
                    "INSERT INTO hunts (id, objective, kind, status, started_by) "
                    "VALUES ('01HUNTZONE0000000000000000', 'x', 'chat', 'running', 'a')"
                )
            )
        async with make_sessionmaker(engine)() as db:
            created = await db.scalar(
                select(Hunt.created_at).where(Hunt.id == "01HUNTZONE0000000000000000")
            )
    finally:
        await engine.dispose()
    now = datetime.now(UTC).replace(tzinfo=None)
    assert created is not None and created.tzinfo is None
    assert abs(created - now) < timedelta(minutes=5)


async def test_an_aware_value_reaches_asyncpg_as_naive_utc(settings_kratos: Settings) -> None:
    """asyncpg refuses an aware value for a column without a timezone."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    aware = datetime(2026, 10, 4, 12, 0, tzinfo=timezone(timedelta(hours=-5)))
    try:
        async with make_sessionmaker(engine)() as db:
            db.add(Hunt(id="01HUNTAWAREPG0000000000000", objective="x", finished_at=aware))
            await db.commit()
            stored = await db.scalar(
                select(Hunt.finished_at).where(Hunt.id == "01HUNTAWAREPG0000000000000")
            )
    finally:
        await engine.dispose()
    assert stored == datetime(2026, 10, 4, 17, 0)


async def test_two_starts_at_once_migrate_the_store_once(settings_kratos: Settings) -> None:
    """The advisory lock serialises the chain: both starts succeed, one runs it."""
    first, second = make_engine(settings_kratos), make_engine(settings_kratos)
    try:
        await asyncio.gather(run_migrations(first), run_migrations(second))
        async with first.connect() as conn:
            rows = (await conn.execute(text("SELECT version_num FROM alembic_version"))).all()
    finally:
        await first.dispose()
        await second.dispose()
    assert len(rows) == 1


async def test_doctor_reads_a_postgres_store_without_showing_the_password(
    settings_kratos: Settings,
) -> None:
    from soc_ai.doctor import check_store

    fresh = await check_store(settings_kratos)
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    await engine.dispose()
    at_head = await check_store(settings_kratos)
    url = settings_kratos.soc_ai_database_url
    assert url is not None
    # The userinfo as it sits in the URL: ":password@". A leak has that shape.
    userinfo = (
        ":" + url.get_secret_value().split("://", 1)[1].split("@", 1)[0].split(":", 1)[1] + "@"
    )
    lines = [f"{r.name} {r.status} {r.detail} {r.hint}" for r in fresh + at_head]
    assert all(userinfo not in line for line in lines)
    assert [(r.name, r.status) for r in fresh] == [("store", "PASS"), ("store fts5", "INFO")]
    assert "is fresh" in fresh[0].detail
    assert [(r.name, r.status) for r in at_head] == [("store", "PASS"), ("store fts5", "INFO")]
    assert "at migration head" in at_head[0].detail
    assert at_head[0].detail.startswith("PostgreSQL ")
