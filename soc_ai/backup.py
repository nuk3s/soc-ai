"""Safe backup/restore for the soc-ai local store (``soc-ai backup`` / ``restore``).

The operator's store is months of investigations, audit history, runbooks, and
config overrides in one SQLite file — with WAL journaling, so a naive ``cp`` of
a live database can capture a torn page set. This module snapshots it SAFELY:
the stdlib :meth:`sqlite3.Connection.backup` API copies a consistent,
committed view through a second connection and honors WAL, so **backups are
safe while the app is running**.

Archive layout (``soc-ai-backup-<UTC-stamp>.tar.gz``)::

    manifest.json               # schema head, app version, created_at, source dir
    data/soc-ai.db              # the consistent DB snapshot
    data/<sidecar files>        # app-owned files next to the DB (see below)
    caches/<label>/...          # only with --full (re-downloadable enrichment data)

Sidecars are every regular file directly under ``soc_ai_data_dir`` except the
DB itself and its ``-wal``/``-shm`` journals (the snapshot already contains
their committed state) and ``*.tar.gz`` (a previous backup parked in the data
dir is not app state). Today that means the Ed25519 decision-record signing
key (``decision_signing_ed25519.key`` — losing it breaks signature
verification for previously exported records) and the pinned sensor
``known_hosts`` (the SSH trust anchor for PCAP fetch).

The enrichment caches (blocklists, MaxMind, cloud prefixes) live in separate
directories and are EXCLUDED by default: they are re-downloadable with
``soc-ai blocklists refresh`` and dwarf the DB. ``--full`` includes them for
air-gapped hosts where re-downloading is not an option.

Restore semantics (see :func:`restore_backup`):

- Refuses when the target DB (or a sidecar) already exists, unless
  ``assume_yes`` — and prints exactly what it would overwrite.
- Refuses when the archive's migration head is UNKNOWN to this code's
  migration scripts — that means the backup came from a NEWER soc-ai and
  restoring it would be a schema downgrade (unsupported). An OLDER head is
  fine: the app migrates to head at startup.
- Detects a live-looking store (a ``-wal``/``-shm`` journal touched within
  :data:`RUNNING_WAL_WINDOW_S`) and refuses without ``assume_yes``; with it,
  the restore proceeds but carries a hard warning. Stale journals are always
  removed so old WAL frames can't graft onto the restored file.

Pure logic lives here; ``soc_ai.cli`` owns argparse and the printing (the
same split as ``soc_ai.doctor``).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from alembic.script import ScriptDirectory

from soc_ai import __version__
from soc_ai.store.db import _migration_config

MANIFEST_VERSION = 1
DB_FILENAME = "soc-ai.db"
_MANIFEST_ARCNAME = "manifest.json"
_DB_ARCNAME = f"data/{DB_FILENAME}"
_SIGNING_KEY_FILENAME = "decision_signing_ed25519.key"

#: A ``-wal``/``-shm`` journal younger than this (seconds) means the app looks
#: RUNNING for restore purposes. Generous on purpose: WAL mtime only advances
#: on writes, so a quiet-but-live app can lag real activity by minutes.
RUNNING_WAL_WINDOW_S = 300.0

#: Cache labels a ``--full`` backup may carry (archive dir under ``caches/``).
CACHE_LABELS = ("blocklists", "maxmind", "cloud_prefixes")


class BackupError(RuntimeError):
    """A backup/restore failed outright (bad archive, missing store, I/O)."""


class RestoreRefused(BackupError):
    """The restore was refused: needs ``--yes``, or is an unsupported downgrade."""


@dataclass
class Manifest:
    """The ``manifest.json`` written into (and read back from) every archive."""

    manifest_version: int
    app_version: str
    created_at: str
    source_data_dir: str
    alembic_head: str | None
    code_head: str | None
    sidecars: list[str] = field(default_factory=list)
    full: bool = False
    caches: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Manifest:
        try:
            return cls(
                manifest_version=int(raw["manifest_version"]),
                app_version=str(raw["app_version"]),
                created_at=str(raw["created_at"]),
                source_data_dir=str(raw["source_data_dir"]),
                alembic_head=None if raw.get("alembic_head") is None else str(raw["alembic_head"]),
                code_head=None if raw.get("code_head") is None else str(raw["code_head"]),
                sidecars=[str(s) for s in raw.get("sidecars") or []],
                full=bool(raw.get("full", False)),
                caches=[str(c) for c in raw.get("caches") or []],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BackupError(f"malformed manifest.json in the archive: {exc}") from exc


@dataclass
class BackupResult:
    """What :func:`create_backup` produced (the CLI prints this)."""

    archive: Path
    manifest: Manifest
    db_bytes: int


@dataclass
class RestoreResult:
    """What :func:`restore_backup` restored (the CLI prints this)."""

    data_dir: Path
    db_path: Path
    archive_head: str | None
    code_head: str | None
    sidecars: list[str] = field(default_factory=list)
    caches: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def default_backup_name(now: datetime | None = None) -> str:
    """``soc-ai-backup-<UTC-stamp>.tar.gz`` — the default ``--out`` filename."""
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return f"soc-ai-backup-{stamp}.tar.gz"


def code_migration_head() -> str | None:
    """This checkout's Alembic head (same derivation as ``soc-ai doctor``)."""
    return ScriptDirectory.from_config(_migration_config()).get_current_head()


# ── Backup ───────────────────────────────────────────────────────────────────


def _snapshot_db(db_path: Path, dest: Path) -> None:
    """Copy a consistent, committed view of *db_path* to *dest*.

    Uses the SQLite Online Backup API via a second connection — the documented
    safe way to copy a live WAL database (a plain file copy can tear pages
    that only exist in the ``-wal`` journal).
    """
    src = sqlite3.connect(db_path, timeout=30.0)
    try:
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def _db_migration_head(db_path: Path) -> str | None:
    """``alembic_version.version_num`` of a (snapshot) DB file, or None if fresh."""
    conn = sqlite3.connect(db_path)
    try:
        try:
            row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        except sqlite3.OperationalError:
            return None  # fresh store — no migrations applied yet
        return None if row is None else str(row[0])
    finally:
        conn.close()


def _sidecar_files(data_dir: Path) -> list[Path]:
    """App-owned flat files next to the DB (see the module docstring)."""
    picked: list[Path] = []
    for p in sorted(data_dir.iterdir()):
        if not p.is_file():
            continue
        if p.name == DB_FILENAME or p.name.startswith(DB_FILENAME + "-"):
            continue  # snapshot covers the DB; -wal/-shm are journal state
        if p.name.endswith(".tar.gz"):
            continue  # a parked backup archive is not app state
        picked.append(p)
    return picked


def create_backup(
    data_dir: Path,
    out_path: Path,
    *,
    full: bool = False,
    cache_dirs: dict[str, Path] | None = None,
) -> BackupResult:
    """Snapshot the store at *data_dir* into a tar.gz at *out_path*.

    Safe while the app is running (see :func:`_snapshot_db`). With *full*,
    also packs each non-empty directory in *cache_dirs* under ``caches/``.
    The archive is written to a temp file and atomically renamed into place.
    """
    data_dir = Path(data_dir).resolve()
    db_path = data_dir / DB_FILENAME
    if not db_path.is_file():
        raise BackupError(f"no store found at {db_path} — nothing to back up")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="soc-ai-backup-") as td:
        snap = Path(td) / DB_FILENAME
        _snapshot_db(db_path, snap)

        out_resolved = out_path.resolve()
        sidecars = [p for p in _sidecar_files(data_dir) if p.resolve() != out_resolved]

        cache_sets: list[tuple[str, Path, list[Path]]] = []
        if full:
            for label, cdir in sorted((cache_dirs or {}).items()):
                if not cdir.is_dir():
                    continue
                files = sorted(f for f in cdir.rglob("*") if f.is_file())
                if files:
                    cache_sets.append((label, cdir, files))

        manifest = Manifest(
            manifest_version=MANIFEST_VERSION,
            app_version=__version__,
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
            source_data_dir=str(data_dir),
            alembic_head=_db_migration_head(snap),
            code_head=code_migration_head(),
            sidecars=[p.name for p in sidecars],
            full=full,
            caches=[label for label, _dir, _files in cache_sets],
        )

        tmp_archive = out_path.parent / f".{out_path.name}.tmp-{os.getpid()}"
        try:
            with tarfile.open(tmp_archive, "w:gz") as tar:
                manifest_bytes = json.dumps(manifest.as_dict(), indent=2).encode()
                info = tarfile.TarInfo(_MANIFEST_ARCNAME)
                info.size = len(manifest_bytes)
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(manifest_bytes))
                tar.add(snap, arcname=_DB_ARCNAME)
                for p in sidecars:
                    tar.add(p, arcname=f"data/{p.name}")
                for label, cdir, files in cache_sets:
                    for f in files:
                        tar.add(f, arcname=f"caches/{label}/{f.relative_to(cdir)}")
            tmp_archive.replace(out_path)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp_archive.unlink()
            raise

        return BackupResult(archive=out_path, manifest=manifest, db_bytes=snap.stat().st_size)


# ── Restore ──────────────────────────────────────────────────────────────────


def read_manifest(archive: Path) -> Manifest:
    """Read + validate ``manifest.json`` out of a backup archive."""
    try:
        with tarfile.open(archive, "r:gz") as tar:
            try:
                fobj = tar.extractfile(_MANIFEST_ARCNAME)
            except KeyError:
                fobj = None
            if fobj is None:
                raise BackupError(f"{archive} has no manifest.json — not a soc-ai backup archive")
            with fobj:
                raw = json.load(fobj)
    except (tarfile.TarError, OSError, json.JSONDecodeError) as exc:
        raise BackupError(f"cannot read backup archive {archive}: {exc}") from exc
    if not isinstance(raw, dict):
        raise BackupError(f"malformed manifest.json in {archive} (not an object)")
    return Manifest.from_dict(raw)


def check_archive_head(archive_head: str | None) -> None:
    """Refuse an archive whose migration head this code doesn't know.

    An unknown revision id means the backup was made by a NEWER soc-ai;
    restoring it would be a schema downgrade, which Alembic (and the app)
    doesn't support. ``None`` (a fresh, never-migrated store) and any revision
    in this checkout's migration scripts are fine — the app migrates an older
    store to head at startup.
    """
    if archive_head is None:
        return
    script = ScriptDirectory.from_config(_migration_config())
    try:
        script.get_revision(archive_head)
    except Exception as exc:
        raise RestoreRefused(
            f"the archive's migration head {archive_head!r} is unknown to this code "
            f"(code head: {script.get_current_head()!r}) — the backup was made by a "
            "NEWER soc-ai, and restoring it here would be a schema downgrade "
            "(unsupported). Upgrade soc-ai to at least the version that wrote the "
            "backup, then restore."
        ) from exc


def _live_wal_age_s(db_path: Path) -> float | None:
    """Age (s) of the freshest ``-wal``/``-shm`` journal, or None when absent."""
    ages: list[float] = []
    for suffix in ("-wal", "-shm"):
        journal = db_path.with_name(db_path.name + suffix)
        try:
            ages.append(time.time() - journal.stat().st_mtime)
        except OSError:
            continue
    return min(ages) if ages else None


def _install_file(src: Path, target: Path) -> None:
    """Copy *src* over *target* atomically (temp file + rename, mode preserved)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(fd, "wb") as out, src.open("rb") as inp:
            shutil.copyfileobj(inp, out)
        shutil.copymode(src, tmp_name)
        os.replace(tmp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def _restore_caches(
    caches_root: Path, cache_dirs: dict[str, Path], warnings: list[str]
) -> list[str]:
    """Best-effort restore of ``caches/<label>/`` trees — they are re-downloadable,
    so a failure lands a warning (with the re-seed command), never an abort."""
    restored: list[str] = []
    if not caches_root.is_dir():
        return restored
    for cache_src in sorted(d for d in caches_root.iterdir() if d.is_dir()):
        label = cache_src.name
        target_dir = cache_dirs.get(label)
        if target_dir is None:
            warnings.append(
                f"archive carries the {label!r} cache but no target directory is "
                "configured — skipped (re-seed with `soc-ai blocklists refresh`)"
            )
            continue
        try:
            shutil.copytree(cache_src, target_dir, dirs_exist_ok=True)
            restored.append(label)
        except OSError as exc:
            warnings.append(
                f"could not restore the {label!r} cache to {target_dir}: {exc} "
                "(re-seed with `soc-ai blocklists refresh`)"
            )
    return restored


def restore_backup(
    archive: Path,
    data_dir: Path,
    *,
    assume_yes: bool = False,
    cache_dirs: dict[str, Path] | None = None,
) -> RestoreResult:
    """Restore a backup archive into *data_dir* (see module docstring semantics).

    Raises :class:`RestoreRefused` when a gate needs ``--yes`` or the archive
    is from a newer soc-ai; :class:`BackupError` on a bad archive. Stop the
    app before restoring — a live app keeps its open file handles and will
    diverge from (or clobber) the restored store.
    """
    archive = Path(archive)
    if not archive.is_file():
        raise BackupError(f"no such archive: {archive}")
    manifest = read_manifest(archive)
    check_archive_head(manifest.alembic_head)

    data_dir = Path(data_dir).resolve()
    db_path = data_dir / DB_FILENAME
    warnings: list[str] = []

    # Refusal gates, evaluated together so one refusal names every problem:
    #   1. existing state — never overwrite silently;
    #   2. the store looks LIVE (recent WAL activity) — never restore under a
    #      running app silently. Without --yes both refuse; with --yes the
    #      restore proceeds but the live-store case carries a hard warning.
    targets = (db_path, *(data_dir / s for s in manifest.sidecars))
    would_overwrite = [p for p in targets if p.exists()]
    wal_age = _live_wal_age_s(db_path)
    live_msg: str | None = None
    if wal_age is not None and wal_age < RUNNING_WAL_WINDOW_S:
        live_msg = (
            f"the store at {db_path} has a write-ahead log touched {wal_age:.0f}s ago — "
            "the app looks RUNNING; restoring under a live app loses writes and can "
            "corrupt the restored store. Stop the app first (docker compose stop "
            "soc-ai / systemctl stop soc-ai)"
        )
    if not assume_yes:
        reasons: list[str] = []
        if would_overwrite:
            listing = "\n".join(f"  {p}" for p in would_overwrite)
            reasons.append(f"refusing to overwrite existing state under {data_dir}:\n{listing}")
        if live_msg:
            reasons.append(live_msg)
        if reasons:
            raise RestoreRefused("\n".join(reasons) + "\nrerun with --yes to restore anyway")
    elif live_msg:
        warnings.append(f"{live_msg} (--yes given — restoring anyway)")

    data_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="soc-ai-restore-") as td:
        try:
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(td, filter="data")  # blocks traversal/symlinks/devices
        except (tarfile.TarError, OSError) as exc:
            raise BackupError(f"cannot extract backup archive {archive}: {exc}") from exc
        extracted = Path(td)

        src_db = extracted / "data" / DB_FILENAME
        if not src_db.is_file():
            raise BackupError(f"{archive} has no {_DB_ARCNAME} — not a soc-ai backup archive")

        # Old journals belong to the OLD database file; left in place they would
        # graft stale WAL frames onto the restored one. Always remove them.
        for suffix in ("-wal", "-shm"):
            db_path.with_name(db_path.name + suffix).unlink(missing_ok=True)
        _install_file(src_db, db_path)

        restored_sidecars: list[str] = []
        for p in sorted((extracted / "data").iterdir()):
            if p.name == DB_FILENAME or not p.is_file():
                continue
            target = data_dir / p.name
            _install_file(p, target)
            if p.name == _SIGNING_KEY_FILENAME:
                # Belt-and-suspenders: the signing key must stay private
                # (mirrors soc_ai.store.signing.DecisionSigner.load_or_create).
                with contextlib.suppress(OSError):
                    target.chmod(0o600)
            restored_sidecars.append(p.name)

        restored_caches = _restore_caches(extracted / "caches", cache_dirs or {}, warnings)

    return RestoreResult(
        data_dir=data_dir,
        db_path=db_path,
        archive_head=manifest.alembic_head,
        code_head=code_migration_head(),
        sidecars=restored_sidecars,
        caches=restored_caches,
        warnings=warnings,
    )
