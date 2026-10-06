"""The store URL, the engine factory and the datetime contract on both dialects.

These tests run on SQLite in every run. tests/conftest.py marks the module
``postgres``, so the ``-m postgres`` run with SOC_AI_TEST_DATABASE_URL set
runs the same tests against PostgreSQL. A test that pins a URL of its own
uses that URL on both runs. The tests that need a live PostgreSQL and mean
nothing on SQLite are in tests/test_store_postgres.py.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.store.db import (
    POSTGRES_DRIVER,
    StoreUrlError,
    describe_store,
    make_engine,
    make_sessionmaker,
    parse_store_url,
    run_migrations,
    store_url,
)
from soc_ai.store.dialect import UtcDateTime, dialect_name
from soc_ai.store.models import Hunt, Investigation
from sqlalchemy import func, select, text
from sqlalchemy.dialects import postgresql, sqlite

_PASSWORD = "s3cret-pw-for-the-test"


def _with_url(settings: Settings, url: str | None) -> Settings:
    return settings.model_copy(
        update={"soc_ai_database_url": SecretStr(url) if url is not None else None}
    )


def test_default_store_is_the_sqlite_file_in_the_data_dir(settings_kratos: Settings) -> None:
    settings = _with_url(settings_kratos, None)
    url = store_url(settings)
    assert url.drivername == "sqlite+aiosqlite"
    assert url.database == str(settings.soc_ai_data_dir / "soc-ai.db")
    # An empty value is the same as an absent one: the line ships bare in .env.example.
    assert store_url(_with_url(settings_kratos, "  ")) == url


@pytest.mark.parametrize("scheme", ["postgresql", "postgres", "postgresql+asyncpg"])
def test_every_postgres_spelling_runs_through_asyncpg(scheme: str) -> None:
    url = parse_store_url(f"{scheme}://soc:{_PASSWORD}@db.example.test:5432/soc_ai")
    assert url.drivername == POSTGRES_DRIVER
    assert url.password == _PASSWORD
    assert url.database == "soc_ai"


@pytest.mark.parametrize(
    "raw",
    [
        f"mysql+aiomysql://soc:{_PASSWORD}@db.example.test/soc_ai",
        f"postgresql+psycopg2://soc:{_PASSWORD}@db.example.test/soc_ai",
        "sqlite+aiosqlite:////var/lib/soc-ai/other.db",
    ],
)
def test_an_unsupported_driver_is_refused_without_the_password(raw: str) -> None:
    with pytest.raises(StoreUrlError) as err:
        parse_store_url(raw)
    assert _PASSWORD not in str(err.value)
    assert "postgresql+asyncpg" in str(err.value)


def test_an_unparseable_url_is_refused_without_echoing_it() -> None:
    raw = f"not a url {_PASSWORD}"
    with pytest.raises(StoreUrlError) as err:
        parse_store_url(raw)
    assert _PASSWORD not in str(err.value)


def test_a_copy_target_may_name_a_sqlite_file() -> None:
    url = parse_store_url("sqlite:////var/lib/soc-ai/copy.db", allow_sqlite=True)
    assert url.drivername == "sqlite+aiosqlite"
    assert url.database == "/var/lib/soc-ai/copy.db"
    with pytest.raises(StoreUrlError):
        parse_store_url("sqlite://", allow_sqlite=True)


def test_describe_store_never_shows_the_password(settings_kratos: Settings) -> None:
    pg = _with_url(settings_kratos, f"postgresql://soc:{_PASSWORD}@db.example.test/soc_ai")
    label = describe_store(pg)
    assert _PASSWORD not in label
    assert label.startswith("PostgreSQL ")
    assert "db.example.test" in label
    bad = _with_url(settings_kratos, f"oracle://soc:{_PASSWORD}@db.example.test/x")
    assert _PASSWORD not in describe_store(bad)
    sqlite_label = describe_store(_with_url(settings_kratos, None))
    assert sqlite_label.endswith("soc-ai.db")


async def test_make_engine_picks_the_dialect_from_the_url(settings_kratos: Settings) -> None:
    pg = make_engine(_with_url(settings_kratos, "postgresql://soc:pw@db.example.test/soc_ai"))
    try:
        assert pg.dialect.name == "postgresql"
        assert pg.dialect.driver == "asyncpg"
        # The data dir holds more than the SQLite file, so PostgreSQL makes it too.
        assert settings_kratos.soc_ai_data_dir.is_dir()
    finally:
        await pg.dispose()
    lite = make_engine(_with_url(settings_kratos, None))
    try:
        assert dialect_name(lite) == "sqlite"
    finally:
        await lite.dispose()


def test_func_now_is_utc_on_postgresql_and_unchanged_on_sqlite() -> None:
    """A server default and an ``onupdate`` stamp naive UTC on both dialects.

    The PostgreSQL rendering must not depend on the session timezone: ``now()``
    alone returns a ``timestamptz`` that a column without a timezone stores in
    the session zone.
    """
    pg = str(select(func.now()).compile(dialect=postgresql.dialect()))
    assert "timezone('utc', statement_timestamp())" in pg
    assert "now()" not in pg
    lite = str(select(func.now()).compile(dialect=sqlite.dialect()))
    assert "CURRENT_TIMESTAMP" in lite


def test_utc_datetime_converts_an_aware_value_to_naive_utc() -> None:
    kind = UtcDateTime()
    plus_two = timezone(timedelta(hours=2))
    aware = datetime(2026, 10, 4, 12, 0, tzinfo=plus_two)
    assert kind.process_bind_param(aware, sqlite.dialect()) == datetime(2026, 10, 4, 10, 0)
    naive = datetime(2026, 10, 4, 12, 0)
    assert kind.process_bind_param(naive, sqlite.dialect()) is naive
    assert kind.process_bind_param(None, sqlite.dialect()) is None


async def test_an_aware_stamp_is_stored_as_its_utc_instant(settings_kratos: Settings) -> None:
    """The negative control for the type: SQLite stored the wall clock.

    Before the store had its own DateTime, a value of 12:00 at UTC+2 went into
    SQLite as 12:00, two hours off the instant, and asyncpg refused it outright.
    The row must read back as 10:00, a naive UTC value.
    """
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    aware = datetime(2026, 10, 4, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    try:
        async with maker() as db:
            db.add(Hunt(id="01HUNTAWARESTAMP0000000000", objective="x", finished_at=aware))
            await db.commit()
        async with maker() as db:
            stored = await db.scalar(
                select(Hunt.finished_at).where(Hunt.id == "01HUNTAWARESTAMP0000000000")
            )
            raw = await db.scalar(
                text("SELECT finished_at FROM hunts WHERE id = '01HUNTAWARESTAMP0000000000'")
            )
    finally:
        await engine.dispose()
    assert stored == datetime(2026, 10, 4, 10, 0)
    assert stored is not None and stored.tzinfo is None
    assert str(raw).startswith("2026-10-04 10:00")


async def test_a_server_default_stamp_is_naive_utc(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    before = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    try:
        async with maker() as db:
            db.add(Hunt(id="01HUNTSERVERDEFAULT0000000", objective="x"))
            await db.commit()
        async with maker() as db:
            created = await db.scalar(
                select(Hunt.created_at).where(Hunt.id == "01HUNTSERVERDEFAULT0000000")
            )
    finally:
        await engine.dispose()
    after = datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=1)
    assert created is not None and created.tzinfo is None
    assert before <= created <= after


async def test_json_reads_work_on_the_store_dialect(settings_kratos: Settings) -> None:
    """The JSON reads in the investigation store run on SQLite and PostgreSQL.

    ``json_extract`` exists on SQLite only. The PostgreSQL run of this test
    failed on each of the three reads before they used the JSON index.
    """
    from soc_ai.so_client.fields import detection_kind_of_alert_payload
    from soc_ai.store import investigations as inv_svc

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    alert = {"event_dataset": "x.y", "event_module": "z", "raw": {"sigma_level": "high"}}
    derived = detection_kind_of_alert_payload(alert)
    assert derived is not None and derived != "suricata"
    ack = inv_svc.INHERITED_ACK_EVENT_KIND
    try:
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="a-1", started_by="t", kind="suricata")
            hunt_run = await inv_svc.create(
                db, alert_es_id="a-1", started_by="t", subject={"type": "hunt", "hunt_id": "h"}
            )
            await inv_svc.append_events(
                db, inv.id, [{"sequence": 1, "kind": "alert_context", "payload": {"alert": alert}}]
            )
            await inv_svc.append_events(
                db,
                inv.id,
                [
                    {"sequence": 2, "kind": ack, "payload": {"acked": 2}},
                    {"sequence": 3, "kind": ack, "payload": {"acked": 3}},
                ],
            )
            await inv_svc.heal_detection_kinds(db, [inv])
            await db.commit()
            total = await inv_svc.inherited_ack_total(db)
            other = await inv_svc.inherited_ack_total(db, source_id=hunt_run.id)
            alert_runs = (
                await db.scalars(select(Investigation.id).where(inv_svc.not_hunt_subject()))
            ).all()
        async with maker() as db:
            stored = await db.get(Investigation, inv.id)
    finally:
        await engine.dispose()
    assert (total, other) == (5, 0)
    assert stored is not None and stored.kind == derived
    assert set(alert_runs) == {inv.id}


async def test_runbook_search_finds_by_text_and_keeps_the_session(
    settings_kratos: Settings,
) -> None:
    """Runbook search answers on both dialects, and the session stays usable.

    On PostgreSQL the FTS5 probe raised a ProgrammingError, which the
    OperationalError guard did not catch, and a failed statement there aborts
    the transaction. The write after the search proves the session survived.
    """
    from soc_ai.store import runbooks as rb_svc

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        async with make_sessionmaker(engine)() as db:
            await rb_svc.create(db, title="Beacon triage", content="Check the beacon interval.")
            await rb_svc.create(db, title="Phishing", content="Pull the headers.")
            hits = await rb_svc.search(db, "beacon interval", k=5)
            await rb_svc.create(db, title="After the search", content="x")
            titles = [rb.title for rb in await rb_svc.list_all(db)]
    finally:
        await engine.dispose()
    assert [h["title"] for h in hits] == ["Beacon triage"]
    assert "After the search" in titles


async def test_chat_memory_finds_an_ip_phrase_on_both_dialects(settings_kratos: Settings) -> None:
    """A dotted IP matches as the phrase of its octets, and only as that phrase.

    The second message holds the same octets in another order. A ranker that
    OR'd the octets, or dropped the phrase, would return it too.
    """
    from soc_ai.store import chat_memory

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        async with make_sessionmaker(engine)() as db:
            for thread, content in (
                ("01THREADA00000000000000000", "We know 192.0.2.10, it is the vuln scanner."),
                ("01THREADB00000000000000000", "Counted 10 hosts, 2 of 192 on 0 days."),
                ("01THREADC00000000000000000", "Nothing to see."),
            ):
                chat_memory.record_message(
                    db, source="investigation", thread_id=thread, role="user", content=content
                )
            await db.commit()
            hits = await chat_memory.relevant_chat_snippets(
                db, query_terms=["192.0.2.10"], exclude_thread=None, window_days=30, limit=5
            )
            excluded = await chat_memory.relevant_chat_snippets(
                db,
                query_terms=["192.0.2.10"],
                exclude_thread="01THREADA00000000000000000",
                window_days=30,
                limit=5,
            )
    finally:
        await engine.dispose()
    assert [h["thread_id"] for h in hits] == ["01THREADA00000000000000000"]
    assert hits[0]["score"] > 0
    assert excluded == []


async def test_dossier_search_ignores_case_on_both_dialects(settings_kratos: Settings) -> None:
    """The host search matches across case on both dialects.

    SQLite LIKE ignores ASCII case and PostgreSQL LIKE does not. The store keys
    an IPv6 address in lower case, and an analyst may paste it in upper case.
    """
    from soc_ai.store import host_dossier as store

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        async with make_sessionmaker(engine)() as db:
            await store.upsert_host(db, "2001:db8::10")
            await store.upsert_host(db, "192.0.2.10")
            await db.commit()
            rows, total = await store.list_dossiers(db, q="2001:DB8")
    finally:
        await engine.dispose()
    assert (total, [r.ip for r, _fields in rows]) == (1, ["2001:db8::10"])


async def test_a_postgres_start_waits_for_the_server_then_gives_up(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A refused connection is retried inside the budget, then raised.

    The compose profile starts PostgreSQL and soc-ai together. Without the
    wait, the first start failed on a refused connection and logged a corrupt
    store. Port 1 on loopback refuses, so no server is needed.
    """
    import logging

    from soc_ai.store import db as store_db

    monkeypatch.setattr(store_db, "READY_BUDGET_S", 2.0)
    engine = store_db.make_postgres_engine(
        parse_store_url("postgresql://u:pw@127.0.0.1:1/soc_ai"), pool_size=1
    )
    caplog.set_level(logging.WARNING, logger="soc_ai.store.db")
    try:
        with pytest.raises(OSError):
            await run_migrations(engine)
    finally:
        await engine.dispose()
    waits = [r for r in caplog.records if "does not accept connections yet" in r.getMessage()]
    assert len(waits) >= 2
