"""Round-trip tests for ``soc-ai backup`` / ``restore`` (soc_ai/backup.py).

Builds a real store via the actual Alembic migrations, inserts rows through
the store services (investigation + runbook), backs it up, mutates the
original, restores to a fresh directory, and asserts the restored rows are
byte-faithful to the pre-mutation state with the correct ``alembic_version``.
Also covers the refusal gates: an archive from a NEWER soc-ai (downgrade),
the ``--yes`` overwrite gate, and the live-WAL "app looks running" gate.
"""

from __future__ import annotations

import argparse
import io
import json
import sqlite3
import tarfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from soc_ai.backup import (
    DB_FILENAME,
    BackupError,
    Manifest,
    RestoreRefused,
    code_migration_head,
    create_backup,
    default_backup_name,
    read_manifest,
    restore_backup,
)
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store import runbooks as rb_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

KEY_BYTES = b"\x01" * 32
KNOWN_HOSTS = "sensor ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n"


def _settings(data_dir: Path) -> Settings:
    """Minimal valid Settings pointed at *data_dir* (mirrors conftest's base)."""
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        api_auth_required=False,
        soc_ai_data_dir=data_dir,
    )


async def _seed_store(settings: Settings) -> None:
    """Migrate to head and insert one investigation + one runbook via the store fns."""
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        await inv_svc.create(
            db,
            alert_es_id="es-round-trip",
            started_by="admin",
            rule_name="ET TEST Round Trip",
            src_ip="10.0.0.5",
            dest_ip="203.0.113.9",
        )
        await rb_svc.create(
            db,
            title="Beaconing triage",
            content="1. Check destination rarity\n2. Pull the PCAP",
            tags=["c2", "beaconing"],
            created_by="admin",
        )
    await engine.dispose()


def _write_sidecars(data_dir: Path) -> None:
    key = data_dir / "decision_signing_ed25519.key"
    key.write_bytes(KEY_BYTES)
    key.chmod(0o600)
    (data_dir / "known_hosts").write_text(KNOWN_HOSTS)


def _rows(db_path: Path, table: str) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
    finally:
        conn.close()


def _db_head(db_path: Path) -> str:
    conn = sqlite3.connect(db_path)
    try:
        return str(conn.execute("SELECT version_num FROM alembic_version").fetchone()[0])
    finally:
        conn.close()


def _rewrite_manifest(archive: Path, out: Path, **overrides: Any) -> None:
    """Copy *archive* to *out* with manifest.json fields replaced (tamper helper)."""
    with tarfile.open(archive, "r:gz") as src, tarfile.open(out, "w:gz") as dst:
        for member in src.getmembers():
            fobj = src.extractfile(member)
            data = fobj.read() if fobj else b""
            if member.name == "manifest.json":
                doc = json.loads(data)
                doc.update(overrides)
                data = json.dumps(doc).encode()
                member.size = len(data)
            dst.addfile(member, io.BytesIO(data))


# ── Round trip ───────────────────────────────────────────────────────────────


async def test_backup_restore_round_trip(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    settings = _settings(src_dir)
    await _seed_store(settings)
    _write_sidecars(src_dir)
    src_db = src_dir / DB_FILENAME

    inv_before = _rows(src_db, "investigations")
    rb_before = _rows(src_db, "runbook")
    assert len(inv_before) == 1
    assert len(rb_before) == 1
    head = code_migration_head()
    assert head is not None

    archive = tmp_path / "backup.tar.gz"
    result = create_backup(src_dir, archive)
    assert result.archive == archive
    assert archive.is_file()
    assert result.db_bytes > 0

    manifest = read_manifest(archive)
    assert isinstance(manifest, Manifest)
    assert manifest.alembic_head == head
    assert manifest.code_head == head
    assert manifest.sidecars == ["decision_signing_ed25519.key", "known_hosts"]
    assert manifest.full is False
    assert manifest.caches == []

    # Mutate the ORIGINAL after the backup — the restore must return the
    # point-in-time snapshot, not the mutated present.
    engine = make_engine(settings)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        await rb_svc.create(db, title="post-backup noise", created_by="admin")
    await engine.dispose()
    assert _rows(src_db, "runbook") != rb_before

    dst_dir = tmp_path / "dst"
    restored = restore_backup(archive, dst_dir)  # fresh dir — no --yes needed
    dst_db = dst_dir / DB_FILENAME
    assert restored.db_path == dst_db
    assert restored.warnings == []
    assert restored.sidecars == ["decision_signing_ed25519.key", "known_hosts"]

    # Byte-faithful rows + correct migration head.
    assert _rows(dst_db, "investigations") == inv_before
    assert _rows(dst_db, "runbook") == rb_before
    assert _db_head(dst_db) == head

    # Sidecars byte-faithful; the signing key stays private (0600).
    restored_key = dst_dir / "decision_signing_ed25519.key"
    assert restored_key.read_bytes() == KEY_BYTES
    assert restored_key.stat().st_mode & 0o777 == 0o600
    assert (dst_dir / "known_hosts").read_text() == KNOWN_HOSTS


async def test_backup_is_safe_while_wal_journal_is_hot(tmp_path: Path) -> None:
    """Snapshot a store with a live WAL connection holding uncommitted state."""
    src_dir = tmp_path / "src"
    await _seed_store(_settings(src_dir))
    src_db = src_dir / DB_FILENAME
    rb_before = _rows(src_db, "runbook")

    # An open writer with an uncommitted row — the snapshot must contain only
    # committed state (this is exactly what a hot file-copy gets wrong).
    writer = sqlite3.connect(src_db)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("BEGIN")
        writer.execute(
            "INSERT INTO runbook (title, content, tags, linked_rules, created_by,"
            " created_at, updated_at) VALUES ('uncommitted', '', '[]', '[]', 'x',"
            " CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
        archive = tmp_path / "hot.tar.gz"
        create_backup(src_dir, archive)
    finally:
        writer.rollback()
        writer.close()

    restored = restore_backup(archive, tmp_path / "dst")
    assert _rows(restored.db_path, "runbook") == rb_before


# ── Refusal gates ────────────────────────────────────────────────────────────


async def test_restore_refuses_archive_from_newer_soc_ai(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    await _seed_store(_settings(src_dir))
    archive = tmp_path / "backup.tar.gz"
    create_backup(src_dir, archive)

    tampered = tmp_path / "newer.tar.gz"
    _rewrite_manifest(archive, tampered, alembic_head="9999_from_the_future")

    with pytest.raises(RestoreRefused, match="NEWER"):
        restore_backup(tampered, tmp_path / "dst")
    # A refused restore must not have touched the target.
    assert not (tmp_path / "dst" / DB_FILENAME).exists()


async def test_restore_refuses_existing_store_without_yes(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    settings = _settings(src_dir)
    await _seed_store(settings)
    inv_before = _rows(src_dir / DB_FILENAME, "investigations")
    archive = tmp_path / "backup.tar.gz"
    create_backup(src_dir, archive)

    # Restoring over the SAME dir: the db exists → refuse, naming the file.
    with pytest.raises(RestoreRefused, match="--yes") as excinfo:
        restore_backup(archive, src_dir)
    assert DB_FILENAME in str(excinfo.value)

    # With assume_yes it proceeds and the content round-trips.
    restored = restore_backup(archive, src_dir, assume_yes=True)
    assert _rows(restored.db_path, "investigations") == inv_before


async def test_restore_gates_on_live_wal_and_clears_stale_journals(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    await _seed_store(_settings(src_dir))
    archive = tmp_path / "backup.tar.gz"
    create_backup(src_dir, archive)

    # A fresh -wal next to the target db ⇒ "the app looks RUNNING".
    wal = src_dir / f"{DB_FILENAME}-wal"
    wal.write_bytes(b"\x00" * 32)
    with pytest.raises(RestoreRefused, match="RUNNING"):
        restore_backup(archive, src_dir)

    # --yes proceeds, carries a hard warning, and removes the stale journal.
    restored = restore_backup(archive, src_dir, assume_yes=True)
    assert any("RUNNING" in w for w in restored.warnings)
    assert not wal.exists()


def test_restore_rejects_a_non_backup_archive(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.tar.gz"
    with tarfile.open(bogus, "w:gz") as tar:
        info = tarfile.TarInfo("random.txt")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"hello"))
    with pytest.raises(BackupError, match="manifest"):
        restore_backup(bogus, tmp_path / "dst")


def test_backup_without_a_store_fails_honestly(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="nothing to back up"):
        create_backup(tmp_path / "empty", tmp_path / "out.tar.gz")


# ── Cache include/exclude (--full) ───────────────────────────────────────────


async def test_full_includes_caches_default_excludes(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    await _seed_store(_settings(src_dir))
    bl_dir = tmp_path / "blocklists"
    bl_dir.mkdir()
    (bl_dir / "urlhaus.csv").write_text("http://malware.example/,c2\n")
    cache_dirs = {"blocklists": bl_dir, "maxmind": tmp_path / "absent"}

    default_archive = tmp_path / "default.tar.gz"
    create_backup(src_dir, default_archive, cache_dirs=cache_dirs)
    assert read_manifest(default_archive).caches == []

    full_archive = tmp_path / "full.tar.gz"
    create_backup(src_dir, full_archive, full=True, cache_dirs=cache_dirs)
    manifest = read_manifest(full_archive)
    assert manifest.full is True
    assert manifest.caches == ["blocklists"]  # absent/empty dirs are skipped

    bl_restore = tmp_path / "bl_restore"
    restored = restore_backup(full_archive, tmp_path / "dst", cache_dirs={"blocklists": bl_restore})
    assert restored.caches == ["blocklists"]
    assert (bl_restore / "urlhaus.csv").read_text() == "http://malware.example/,c2\n"


async def test_backup_excludes_db_journals_and_parked_archives(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    await _seed_store(_settings(src_dir))
    (src_dir / f"{DB_FILENAME}-wal").write_bytes(b"\x00")
    (src_dir / f"{DB_FILENAME}-shm").write_bytes(b"\x00")
    (src_dir / "old-backup.tar.gz").write_bytes(b"\x1f\x8b")
    out = src_dir / "in-data-dir.tar.gz"  # the archive itself lands in the data dir
    create_backup(src_dir, out)
    assert read_manifest(out).sidecars == []


# ── CLI wiring ───────────────────────────────────────────────────────────────


def test_backup_and_restore_parsers_are_registered() -> None:
    """`soc-ai backup/restore` flags parse via the real registration helper."""
    from soc_ai import cli

    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    cli._register_backup(sub)

    args = p.parse_args(["backup", "--out", "/tmp/x.tar.gz", "--full", "--data-dir", "/d"])
    assert args.func is cli._backup
    assert args.out == "/tmp/x.tar.gz"
    assert args.full is True
    assert args.data_dir == "/d"

    args = p.parse_args(["restore", "/tmp/x.tar.gz", "--yes"])
    assert args.func is cli._restore
    assert args.archive == "/tmp/x.tar.gz"
    assert args.yes is True


async def test_cli_backup_and_restore_handlers_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The argparse handlers work end-to-end with --data-dir (no .env needed)."""
    from soc_ai import cli

    src_dir = tmp_path / "src"
    await _seed_store(_settings(src_dir))
    inv_before = _rows(src_dir / DB_FILENAME, "investigations")
    archive = tmp_path / "cli.tar.gz"

    rc = cli._backup(argparse.Namespace(out=str(archive), full=False, data_dir=str(src_dir)))
    assert rc == 0
    out = capsys.readouterr().out
    assert "archive:" in out
    assert "excluded" in out  # the cache-exclusion note is printed

    dst_dir = tmp_path / "dst"
    rc = cli._restore(argparse.Namespace(archive=str(archive), yes=False, data_dir=str(dst_dir)))
    assert rc == 0
    assert "restart the app" in capsys.readouterr().out
    assert _rows(dst_dir / DB_FILENAME, "investigations") == inv_before

    # Second restore without --yes → refused with exit code 2.
    rc = cli._restore(argparse.Namespace(archive=str(archive), yes=False, data_dir=str(dst_dir)))
    assert rc == 2
    assert "--yes" in capsys.readouterr().err


def test_default_backup_name_shape() -> None:
    from datetime import UTC, datetime

    name = default_backup_name(datetime(2026, 7, 10, 12, 34, 56, tzinfo=UTC))
    assert name == "soc-ai-backup-20260710T123456Z.tar.gz"
