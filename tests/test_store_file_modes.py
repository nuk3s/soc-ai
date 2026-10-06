"""The modes of the SQLite store and its data directory.

Range dogfood 2026-10-05: ``data/soc-ai.db`` was mode 0644 in a 0755 directory,
and it holds ``users.password_hash``, the investigations and the host table.
The store now makes the file and its WAL siblings 0600 and the data directory
0700, and tightens an older file when it opens it.

Each test sets the umask to 022 first, the umask the range ran with, so a test
fails on the old code whatever umask the runner has.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.store import db as store_db
from soc_ai.store.db import (
    SQLITE_FILENAME,
    engine_for_url,
    make_engine,
    make_private_dir,
    restrict_file,
    restrict_sqlite_files,
    run_migrations,
    sqlite_store_file,
    store_url,
)
from sqlalchemy import make_url, text

from tests.conftest import _base_settings_kwargs


@pytest.fixture(autouse=True)
def _umask_022() -> Iterator[None]:
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


@pytest.fixture(autouse=True)
def _fresh_warnings() -> Iterator[None]:
    store_db._MODE_WARNED.clear()
    yield
    store_db._MODE_WARNED.clear()


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _settings(data_dir: Path, **over: Any) -> Settings:
    kwargs = _base_settings_kwargs()
    kwargs["soc_ai_data_dir"] = data_dir
    kwargs.update(over)
    return Settings(**kwargs)


def _siblings(store: Path) -> list[Path]:
    return [store.with_name(store.name + s) for s in ("-wal", "-shm", "-journal")]


async def test_a_fresh_store_is_0600_in_a_0700_directory(tmp_path: Path) -> None:
    data = tmp_path / "data"
    settings = _settings(data)
    engine = make_engine(settings)
    try:
        await run_migrations(engine)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            store = data / SQLITE_FILENAME
            assert _mode(data) == 0o700
            assert _mode(store) == 0o600
            # While a connection is open the WAL siblings exist. They are 0600 too.
            live = [p for p in _siblings(store) if p.exists()]
            assert live, "expected WAL siblings while a connection is open"
            assert {_mode(p) for p in live} == {0o600}
    finally:
        await engine.dispose()


async def test_an_old_0644_store_and_its_siblings_are_tightened_on_open(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o755)
    store = data / SQLITE_FILENAME
    # An older install: sqlite3 under umask 022 makes the store and its WAL
    # siblings 0644. The held connection keeps the siblings on disk.
    holder = sqlite3.connect(store)
    holder.execute("PRAGMA journal_mode=WAL")
    holder.execute("CREATE TABLE t (x INTEGER)")
    holder.execute("INSERT INTO t VALUES (1)")
    holder.commit()
    try:
        before = [p for p in [store, *_siblings(store)] if p.exists()]
        assert len(before) >= 3
        assert {_mode(p) for p in before} == {0o644}
        assert _mode(data) == 0o755

        engine = make_engine(_settings(data))
        try:
            async with engine.connect() as conn:
                assert (await conn.execute(text("SELECT x FROM t"))).scalar_one() == 1
        finally:
            await engine.dispose()
        assert _mode(data) == 0o700
        assert {_mode(p) for p in before if p.exists()} == {0o600}
    finally:
        holder.close()


async def test_a_postgresql_url_skips_the_chmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: a PostgreSQL store has no file, and its data directory keeps its mode.

    A PostgreSQL URL names a database, not a path. A chmod of ``url.database``
    would act on a relative path in the working directory.
    """
    data = tmp_path / "pg-data"
    data.mkdir(mode=0o755)
    calls: list[str] = []
    real_chmod = Path.chmod

    def _spy(self: Path, mode: int, **kw: Any) -> None:
        calls.append(str(self))
        real_chmod(self, mode, **kw)

    monkeypatch.setattr(Path, "chmod", _spy)
    monkeypatch.setattr(os, "chmod", lambda *a, **kw: calls.append(str(a[0])))
    settings = _settings(
        data,
        soc_ai_database_url=SecretStr("postgresql+asyncpg://soc_ai:pw@127.0.0.1:1/soc_ai"),
    )
    assert sqlite_store_file(store_url(settings)) is None
    engine = make_engine(settings)
    await engine.dispose()
    assert calls == []
    assert _mode(data) == 0o755


async def test_a_memory_store_is_not_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: ``:memory:`` and a ``file:`` URI name no file to tighten."""
    monkeypatch.chdir(tmp_path)
    assert sqlite_store_file(make_url("sqlite+aiosqlite:///:memory:")) is None
    assert sqlite_store_file(make_url("sqlite+aiosqlite:///file:x.db?mode=ro&uri=true")) is None
    engine = engine_for_url(make_url("sqlite+aiosqlite:///:memory:"))
    try:
        async with engine.connect() as conn:
            assert (await conn.execute(text("SELECT 1"))).scalar_one() == 1
    finally:
        await engine.dispose()
    assert not (tmp_path / ":memory:").exists()


async def test_a_scratch_store_through_engine_for_url_is_0600(tmp_path: Path) -> None:
    """The replay scratch store and a copy target open through engine_for_url."""
    scratch = tmp_path / "replay" / "store.db"
    scratch.parent.mkdir()
    engine = engine_for_url(make_url(f"sqlite+aiosqlite:///{scratch}"))
    try:
        async with engine.connect() as conn:
            await conn.execute(text("CREATE TABLE t (x INTEGER)"))
            await conn.commit()
    finally:
        await engine.dispose()
    assert _mode(scratch) == 0o600


def test_make_private_dir_tightens_an_old_directory(tmp_path: Path) -> None:
    old = tmp_path / "reports"
    old.mkdir(mode=0o755)
    assert make_private_dir(old) == old
    assert _mode(old) == 0o700
    fresh = make_private_dir(tmp_path / "a" / "b")
    assert _mode(fresh) == 0o700


def test_restrict_file_and_siblings_fail_soft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = tmp_path / "x.db"
    store.write_text("")
    store.chmod(0o644)
    assert restrict_file(tmp_path / "missing.db") is True

    def _denied(self: Path, mode: int, **_kw: Any) -> None:
        raise PermissionError(1, "Operation not permitted", str(self))

    monkeypatch.setattr(Path, "chmod", _denied)
    with caplog.at_level(logging.WARNING, logger="soc_ai.store.db"):
        assert restrict_sqlite_files(store) == [str(store)]
        assert restrict_sqlite_files(store) == [str(store)]
    lines = [r.getMessage() for r in caplog.records]
    assert len(lines) == 1, lines
    assert "cannot remove group and other access from the file" in lines[0]
    assert "—" not in lines[0] and "–" not in lines[0]
    assert _mode(store) == 0o644
