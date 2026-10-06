"""``soc-ai store migrate``: copy every table of a store into an empty store.

The source is always a SQLite file. The target is a second SQLite file in a
normal run. In the ``-m postgres`` run with SOC_AI_TEST_DATABASE_URL set, the
target is the fresh PostgreSQL database of the ``postgres_store`` fixture, so
the same assertions prove the SQLite to PostgreSQL copy.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

import pytest
from pydantic import SecretStr
from soc_ai import cli
from soc_ai.config import Settings
from soc_ai.store import auth as auth_svc
from soc_ai.store import chat_memory
from soc_ai.store import host_dossier as dossier_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store import runbooks as rb_svc
from soc_ai.store.copy import StoreCopyRefused, _source_problems, copy_store
from soc_ai.store.db import (
    engine_for_url,
    make_sessionmaker,
    parse_store_url,
    run_migrations,
)
from soc_ai.store.models import Hunt, HuntTemplate, Investigation, User
from sqlalchemy import URL, inspect, select, text
from sqlalchemy.ext.asyncio import AsyncEngine


def _sqlite_url(path: Path) -> URL:
    return parse_store_url(f"sqlite:///{path}", allow_sqlite=True)


def _target_url(tmp_path: Path, postgres_store: str | None) -> URL:
    if postgres_store is not None:
        return parse_store_url(postgres_store)
    return _sqlite_url(tmp_path / "target" / "soc-ai.db")


async def _seed(engine: AsyncEngine) -> dict[str, str]:
    """A source store with a row in the tables the copy has to get right."""
    await run_migrations(engine)
    async with make_sessionmaker(engine)() as db:
        admin = await auth_svc.create_user(db, "admin", "pw-for-the-copy-test", role="admin")
        inv = await inv_svc.create(db, alert_es_id="a-1", started_by=admin.username)
        await inv_svc.append_events(
            db,
            inv.id,
            [{"sequence": 1, "kind": "alert_context", "payload": {"alert": {"x": [1, None]}}}],
        )
        db.add(Hunt(id="01HUNTCOPY0000000000000000", objective="copy", report=None))
        # A plain JSON column stores None as the JSON text null; NULLABLE_JSON
        # stores SQL NULL. The copy must keep the two apart. The "legacy" row
        # holds SQL NULL in the plain column, as a row from before the column
        # was added does: a Python round trip would write the JSON text there.
        db.add(HuntTemplate(name="tpl", analytics_json=None))
        db.add(HuntTemplate(name="legacy", analytics_json=None))
        await db.commit()
        await db.execute(
            text("UPDATE hunt_templates SET analytics_json = NULL WHERE name = 'legacy'")
        )
        await db.commit()
        await rb_svc.create(db, title="Beacon triage", content="Check the beacon interval.")
        chat_memory.record_message(
            db, source="investigation", thread_id=inv.id, role="user", content="the scanner"
        )
        host = await dossier_svc.upsert_host(db, "192.0.2.10")
        await db.commit()
    return {"investigation": inv.id, "host": host.ip}


async def _count(engine: AsyncEngine, table: str) -> int:
    async with engine.connect() as conn:
        return int(await conn.scalar(text(f"SELECT count(*) FROM {table}")) or 0)


async def test_a_copy_moves_every_row_and_keeps_json_null_apart_from_sql_null(
    tmp_path: Path, postgres_store: str | None
) -> None:
    source = engine_for_url(_sqlite_url(tmp_path / "source" / "soc-ai.db"))
    (tmp_path / "source").mkdir()
    (tmp_path / "target").mkdir()
    target = engine_for_url(_target_url(tmp_path, postgres_store))
    try:
        seeded = await _seed(source)
        result = await copy_store(source, target, batch_size=2)
        assert not result.dry_run
        assert result.problems == []
        assert result.source_rows > 0
        assert all(t.target_rows == t.source_rows for t in result.tables)
        assert result.target_rows == result.source_rows
        for table in ("users", "investigations", "investigation_events", "runbook", "host_dossier"):
            assert await _count(target, table) == await _count(source, table), table

        async with target.connect() as conn:
            plain = dict(
                (
                    await conn.execute(
                        select(HuntTemplate.name, HuntTemplate.analytics_json.is_(None))
                    )
                ).all()
            )
            nullable = await conn.scalar(select(Hunt.report.is_(None)))
        assert plain == {"tpl": False, "legacy": True}
        assert nullable is True

        async with make_sessionmaker(target)() as db:
            event = await db.scalar(
                select(inv_svc.InvestigationEvent).where(
                    inv_svc.InvestigationEvent.investigation_id == seeded["investigation"]
                )
            )
            assert event is not None and event.payload == {"alert": {"x": [1, None]}}
            admin = await db.scalar(select(User).where(User.username == "admin"))
            assert admin is not None
            assert await auth_svc.authenticate(db, "admin", "pw-for-the-copy-test") is not None
            # A new row after the copy takes a key past the copied ones.
            fresh = await auth_svc.create_user(db, "second", "pw-two-for-the-test")
            assert fresh.id > admin.id
            hits = await rb_svc.search(db, "beacon", k=3)
            assert [h["title"] for h in hits] == ["Beacon triage"]
            inv = await db.get(Investigation, seeded["investigation"])
            assert inv is not None and inv.created_at.tzinfo is None
    finally:
        await source.dispose()
        await target.dispose()


async def test_a_dry_run_writes_nothing(tmp_path: Path, postgres_store: str | None) -> None:
    (tmp_path / "source").mkdir()
    (tmp_path / "target").mkdir()
    source = engine_for_url(_sqlite_url(tmp_path / "source" / "soc-ai.db"))
    target_url = _target_url(tmp_path, postgres_store)
    target = engine_for_url(target_url)
    try:
        await _seed(source)
        result = await copy_store(source, target, dry_run=True)
        async with target.connect() as conn:
            tables = await conn.run_sync(lambda c: inspect(c).get_table_names())
    finally:
        await source.dispose()
        await target.dispose()
    assert result.dry_run and result.target_head is None
    assert all(t.target_rows is None for t in result.tables)
    assert result.source_rows > 0
    assert tables == []


async def test_a_target_with_rows_is_refused(tmp_path: Path, postgres_store: str | None) -> None:
    (tmp_path / "source").mkdir()
    (tmp_path / "target").mkdir()
    source = engine_for_url(_sqlite_url(tmp_path / "source" / "soc-ai.db"))
    target = engine_for_url(_target_url(tmp_path, postgres_store))
    try:
        await _seed(source)
        await run_migrations(target)
        async with make_sessionmaker(target)() as db:
            await auth_svc.create_user(db, "already-here", "pw-for-the-test")
        with pytest.raises(StoreCopyRefused, match="holds rows in users"):
            await copy_store(source, target)
        assert await _count(target, "users") == 1
    finally:
        await source.dispose()
        await target.dispose()


async def test_a_source_behind_the_head_is_refused(
    tmp_path: Path, postgres_store: str | None
) -> None:
    (tmp_path / "source").mkdir()
    (tmp_path / "target").mkdir()
    source = engine_for_url(_sqlite_url(tmp_path / "source" / "soc-ai.db"))
    target = engine_for_url(_target_url(tmp_path, postgres_store))
    try:
        await run_migrations(source)
        async with source.begin() as conn:
            await conn.execute(text("UPDATE alembic_version SET version_num = '0055'"))
        with pytest.raises(StoreCopyRefused, match="migration 0055"):
            await copy_store(source, target)
    finally:
        await source.dispose()
        await target.dispose()


async def test_the_source_check_counts_what_postgresql_refuses(tmp_path: Path) -> None:
    """Each value class that SQLite holds and a PostgreSQL column refuses.

    The plants sit on the paths a check could miss: a NUL in the middle of a
    value, a string one character over its limit, an integer one past 32 bits,
    and an orphan written while SQLite did not enforce foreign keys.
    """
    (tmp_path / "source").mkdir()
    source = engine_for_url(_sqlite_url(tmp_path / "source" / "soc-ai.db"))
    try:
        await run_migrations(source)
        async with make_sessionmaker(source)() as db:
            db.add(Hunt(id="01HUNTNUL00000000000000000", objective="before\x00after"))
            db.add(Hunt(id="01HUNTLONG0000000000000000", objective="x", kind="k" * 17))
            db.add(HuntTemplate(name="big", default_window_minutes=2_147_483_648))
            db.add(HuntTemplate(name="fits", default_window_minutes=2_147_483_647))
            await db.commit()
        async with source.connect() as conn:
            await conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
            await conn.execute(
                text(
                    "INSERT INTO investigation_events (investigation_id, sequence, kind, payload) "
                    "VALUES ('01MISSINGPARENT00000000000', 1, 'x', '{}')"
                )
            )
            await conn.commit()
            await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        async with source.connect() as conn:
            problems = await _source_problems(conn)
    finally:
        await source.dispose()
    found = {(p.table, p.column, p.problem, p.rows) for p in problems}
    assert found == {
        ("hunts", "objective", "a NUL character", 1),
        ("hunts", "kind", "text longer than 16 characters", 1),
        ("hunt_templates", "default_window_minutes", "an integer outside 32 bits", 1),
        ("investigation_events", "", "a reference to a missing parent row", 1),
    }


def _cli_args(**kwargs: object) -> argparse.Namespace:
    base: dict[str, object] = {"from_url": None, "dry_run": False, "batch_size": 1000}
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_the_cli_copies_and_reports(
    tmp_path: Path, postgres_store: str | None, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "source").mkdir()
    (tmp_path / "target").mkdir()
    source_path = tmp_path / "source" / "soc-ai.db"
    source = engine_for_url(_sqlite_url(source_path))

    async def _prepare() -> None:
        try:
            await _seed(source)
        finally:
            await source.dispose()

    asyncio.run(_prepare())
    target = _target_url(tmp_path, postgres_store).render_as_string(hide_password=False)
    source_arg = f"sqlite:///{source_path}"

    assert cli._store_migrate(_cli_args(to=target, from_url=source_arg, dry_run=True)) == 0
    out = capsys.readouterr().out
    assert "dry run" in out and "Nothing stops the copy" in out

    assert cli._store_migrate(_cli_args(to=target, from_url=source_arg)) == 0
    out = capsys.readouterr().out
    assert "The target holds the source count in every table" in out
    assert "pw-for-the-copy-test" not in out

    # A second copy finds rows in the target and refuses.
    assert cli._store_migrate(_cli_args(to=target, from_url=source_arg)) == 2
    err = capsys.readouterr().err
    assert "holds rows" in err


def test_the_cli_refuses_a_bad_target_without_echoing_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source_path = tmp_path / "soc-ai.db"
    source_path.touch()
    secret = "do-not-echo-this-pw"
    rc = cli._store_migrate(
        _cli_args(to=f"mysql://u:{secret}@db.example.test/x", from_url=f"sqlite:///{source_path}")
    )
    assert rc == 2
    captured = capsys.readouterr()
    assert secret not in captured.err + captured.out
    missing = cli._store_migrate(
        _cli_args(to=f"sqlite:///{tmp_path / 't.db'}", from_url=f"sqlite:///{tmp_path / 'no.db'}")
    )
    assert missing == 2
    assert not (tmp_path / "no.db").exists()


def test_backup_refuses_a_postgresql_store(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    settings_kratos: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A backup of the SQLite file would report success for data the app no longer writes.

    The negative control is the stale file: the data dir still holds a SQLite
    store, so a backup without the guard would succeed.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    settings = settings_kratos.model_copy(
        update={
            "soc_ai_data_dir": data_dir,
            "soc_ai_database_url": SecretStr("postgresql://u:pw@db.example.test/soc_ai"),
        }
    )
    stale = engine_for_url(_sqlite_url(data_dir / "soc-ai.db"))

    async def _make_stale() -> None:
        try:
            await run_migrations(stale)
        finally:
            await stale.dispose()

    asyncio.run(_make_stale())
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    archive = tmp_path / "b.tar.gz"
    rc = cli._backup(argparse.Namespace(out=str(archive), full=False, data_dir=None))
    assert rc == 2
    assert "pg_dump" in capsys.readouterr().err
    assert not archive.exists()
    rc = cli._restore(argparse.Namespace(archive=str(archive), yes=True, data_dir=None))
    assert rc == 2
    # --data-dir names the SQLite file on purpose, and the backup runs.
    rc = cli._backup(argparse.Namespace(out=str(archive), full=False, data_dir=str(data_dir)))
    assert rc == 0 and archive.exists()


def test_the_store_command_is_registered() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli._register_store(sub)
    args = parser.parse_args(["store", "migrate", "--to", "postgresql://h/d", "--dry-run"])
    assert args.func is cli._store_migrate
    assert args.dry_run is True and args.from_url is None
