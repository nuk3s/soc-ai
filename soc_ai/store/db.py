"""Async engine and session factory for the local store.

The store is the SQLite file ``soc-ai.db`` in ``SOC_AI_DATA_DIR`` by default.
``SOC_AI_DATABASE_URL`` moves it to PostgreSQL through asyncpg. The datetime
contract and the other dialect differences are in :mod:`soc_ai.store.dialect`.

**File modes.** A SQLite store holds the password hashes, the investigations
and the host table. Only the service user may read it: the store file and its
WAL siblings are mode 0600, and the data directory is 0700. The range found
the file at 0644 in a 0755 directory (dogfood 2026-10-05). The engine sets the
modes when it opens a SQLite file, so an old 0644 file is tightened on the next
start. :func:`make_private_dir` and :func:`restrict_file` are the helpers for
other files soc-ai writes under the data directory.
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import URL, Connection, event, make_url, text
from sqlalchemy.exc import ArgumentError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from soc_ai.config import Settings

_LOGGER = logging.getLogger(__name__)

SQLITE_FILENAME = "soc-ai.db"
SQLITE_DRIVER = "sqlite+aiosqlite"
POSTGRES_DRIVER = "postgresql+asyncpg"
# The spellings an operator may write for the one PostgreSQL driver soc-ai ships.
_POSTGRES_SCHEMES = frozenset({"postgresql", "postgres", POSTGRES_DRIVER})

# Two processes that start against one PostgreSQL store at the same moment must
# not run the chain twice. The first takes this transaction-scoped advisory lock,
# and the second waits for it, then finds the store at head. The number is
# arbitrary and only has to be stable: it spells "socai" in ASCII.
_MIGRATION_LOCK_KEY = 0x736F636169

# The modes of what only the service user may read. The helpers below take the
# group and other bits away and leave the owner bits as they are.
PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
# SQLite writes these beside a store file. They hold the same rows.
SQLITE_SIBLING_SUFFIXES: tuple[str, ...] = ("-wal", "-shm", "-journal")

# One warning per path: the in-app preflight opens the store every few minutes.
_MODE_WARNED: set[str] = set()


def _strip_group_and_other(path: Path, *, kind: str) -> bool:
    """Take the group and other bits off *path*. True when none are left. Never raises."""
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            path.chmod(mode & 0o700)
        return True
    except FileNotFoundError:
        return True
    except OSError as exc:
        key = str(path)
        if key not in _MODE_WARNED:
            _MODE_WARNED.add(key)
            _LOGGER.warning(
                "soc-ai cannot remove group and other access from the %s %s: %s. "
                "Run soc-ai as the owner of the %s.",
                kind,
                path,
                exc.strerror or type(exc).__name__,
                kind,
            )
        return False


def restrict_dir(path: str | os.PathLike[str]) -> bool:
    """Remove group and other access from a directory, so it reads 0700. Fails soft."""
    return _strip_group_and_other(Path(path), kind="directory")


def restrict_file(path: str | os.PathLike[str]) -> bool:
    """Remove group and other access from a file, so it reads 0600. Fails soft.

    A missing file is not an error. Call it after a write of a file that only
    the service user may read, for example a report or a scratch store.
    """
    return _strip_group_and_other(Path(path), kind="file")


def make_private_dir(path: str | os.PathLike[str]) -> Path:
    """Create *path* with its parents, and make the leaf mode 0700. Returns the path.

    The mkdir mode covers a new directory. The chmod covers an old one that a
    looser umask made. A chmod failure is logged and the directory stays usable.
    """
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    restrict_dir(target)
    return target


def restrict_sqlite_files(database: str | os.PathLike[str]) -> list[str]:
    """Make a SQLite store file and its WAL siblings mode 0600. Returns the paths it could not.

    The replay scratch store and a store copy target are SQLite files outside the
    engine of the app. Their writers can call this after the first write.
    """
    base = Path(database)
    paths = [base, *(base.with_name(base.name + suffix) for suffix in SQLITE_SIBLING_SUFFIXES)]
    return [str(p) for p in paths if not restrict_file(p)]


def sqlite_store_file(url: URL) -> Path | None:
    """The file a SQLite URL names, or None: PostgreSQL, memory, or a URI form."""
    if url.get_backend_name() != "sqlite":
        return None
    database = str(url.database or "")
    if not database or database == ":memory:" or database.startswith("file:"):
        return None
    if url.query.get("uri") or url.query.get("mode") == "memory":
        return None
    return Path(database)


class StoreUrlError(ValueError):
    """The store URL names a driver soc-ai does not support, or does not parse.

    The message never repeats the URL: it holds the database password.
    """


def parse_store_url(raw: str, *, allow_sqlite: bool = False) -> URL:
    """Parse a store URL and normalise the PostgreSQL scheme to asyncpg.

    ``allow_sqlite`` admits a ``sqlite+aiosqlite:///path`` URL, which a copy
    target may name. The ``SOC_AI_DATABASE_URL`` setting admits PostgreSQL only:
    the default store already is SQLite.
    """
    try:
        url = make_url(raw.strip())
    except (ArgumentError, ValueError):
        raise StoreUrlError(
            "The store URL does not parse. Write it as "
            "postgresql+asyncpg://user:password@host:5432/database."
        ) from None
    if url.drivername in _POSTGRES_SCHEMES:
        return url.set(drivername=POSTGRES_DRIVER)
    if allow_sqlite and url.drivername in {"sqlite", SQLITE_DRIVER}:
        if not url.database:
            raise StoreUrlError("A SQLite store URL must name a file.")
        return url.set(drivername=SQLITE_DRIVER)
    supported = POSTGRES_DRIVER + (f" or {SQLITE_DRIVER}" if allow_sqlite else "")
    raise StoreUrlError(
        f"The store URL uses the driver {url.drivername}. soc-ai supports {supported}."
    )


def store_url(settings: Settings) -> URL:
    """The URL of the store this configuration names."""
    secret = settings.soc_ai_database_url
    raw = secret.get_secret_value().strip() if secret is not None else ""
    if raw:
        return parse_store_url(raw)
    return make_url(f"{SQLITE_DRIVER}:///{settings.soc_ai_data_dir / SQLITE_FILENAME}")


def is_postgres_url(url: URL) -> bool:
    return url.get_backend_name() == "postgresql"


def describe_url(url: URL) -> str:
    """A store URL for a log line or a doctor row. Never the password."""
    if is_postgres_url(url):
        return f"PostgreSQL {url.render_as_string(hide_password=True)}"
    return str(url.database)


def describe_store(settings: Settings) -> str:
    """Where the configured store is. Never the password."""
    try:
        url = store_url(settings)
    except StoreUrlError:
        return "SOC_AI_DATABASE_URL, which does not parse"
    return describe_url(url)


def make_engine(settings: Settings) -> AsyncEngine:
    """Create the store engine; ensures the data directory exists.

    The data directory holds more than the SQLite file (the bootstrap
    credential, the signing key, known_hosts), so it is created on both
    dialects. With a SQLite store the directory holds the store too, so it is
    made mode 0700. A PostgreSQL URL leaves the mode as it is.
    """
    url = store_url(settings)
    if sqlite_store_file(url) is not None:
        make_private_dir(settings.soc_ai_data_dir)
    else:
        settings.soc_ai_data_dir.mkdir(parents=True, exist_ok=True)
    return engine_for_url(url, pool_size=settings.soc_ai_database_pool_size)


def engine_for_url(url: URL, *, pool_size: int = 10) -> AsyncEngine:
    """The engine for a parsed store URL, with the settings of its dialect."""
    if is_postgres_url(url):
        return make_postgres_engine(url, pool_size=pool_size)
    return _make_sqlite_engine(url)


def make_postgres_engine(url: URL, *, pool_size: int = 10) -> AsyncEngine:
    """An asyncpg engine whose sessions run in UTC.

    The session timezone is the second half of the datetime contract: a
    ``timestamptz`` value that reaches a column without a timezone keeps its
    wall clock in the session zone. ``pool_pre_ping`` drops a connection the
    server closed while it sat in the pool, for example after a restart.
    """
    return create_async_engine(
        url,
        pool_size=pool_size,
        max_overflow=pool_size,
        pool_pre_ping=True,
        connect_args={"server_settings": {"timezone": "UTC", "application_name": "soc-ai"}},
    )


def _make_sqlite_engine(url: URL) -> AsyncEngine:
    engine = create_async_engine(url)
    store_file = sqlite_store_file(url)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
        # The connect made the file if it was new. Tighten it before WAL mode
        # makes the siblings: SQLite gives them the mode of the store file.
        if store_file is not None:
            restrict_file(store_file)
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()
        # Siblings an older start left at 0644 keep that mode until changed here.
        if store_file is not None:
            restrict_sqlite_files(store_file)

    return engine


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


def _migration_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    return cfg


def _upgrade_to_head(connection: Connection) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, "head")


def _current_revision(connection: Connection) -> str | None:
    """The revision the store is stamped at (None for an empty store)."""
    from alembic.runtime.migration import MigrationContext  # noqa: PLC0415 - lazy

    return MigrationContext.configure(connection).get_current_revision()


def _script_head() -> str | None:
    from alembic.script import ScriptDirectory  # noqa: PLC0415 - lazy

    return ScriptDirectory.from_config(_migration_config()).get_current_head()


async def run_migrations(engine: AsyncEngine) -> None:
    """Bring the store schema to head (called from the app lifespan)."""
    if engine.dialect.name == "sqlite":
        await _run_sqlite_migrations(engine)
    else:
        await _run_postgres_migrations(engine)


# How long a start waits for a PostgreSQL server that is still coming up.
READY_BUDGET_S = 60.0


async def _wait_for_postgres(engine: AsyncEngine) -> None:
    """Wait until the PostgreSQL server accepts a connection.

    The compose profile starts the server and soc-ai together, and a first
    start of the server initialises its data directory before it listens. A
    refused connection, a name that does not resolve yet, and "the database
    system is starting up" are each retried until ``READY_BUDGET_S`` runs out.
    Any other error, a wrong password for example, raises at once.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + READY_BUDGET_S
    delay = 0.5
    while True:
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return
        except Exception as exc:
            starting = isinstance(exc, OSError) or type(exc).__name__ == "CannotConnectNowError"
            if not starting or loop.time() + delay > deadline:
                raise
            _LOGGER.warning(
                "The PostgreSQL store does not accept connections yet (%s). "
                "soc-ai tries again in %.1f s.",
                type(exc).__name__,
                delay,
            )
            await asyncio.sleep(delay)
            delay = min(delay * 2, 5.0)


async def _run_postgres_migrations(engine: AsyncEngine) -> None:
    """Run the chain on PostgreSQL in one transaction, under an advisory lock.

    PostgreSQL DDL is transactional, so a revision that fails rolls back the
    whole chain with its version stamp. PostgreSQL always enforces foreign
    keys, and batch mode alters a table in place there, so the SQLite
    ``foreign_key_check`` has no counterpart here: a dangling reference fails
    the statement that makes it.
    """
    await _wait_for_postgres(engine)
    async with engine.connect() as conn, conn.begin():
        await conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _MIGRATION_LOCK_KEY})
        if await conn.run_sync(_current_revision) == _script_head():
            return
        await conn.run_sync(_upgrade_to_head)


async def _run_sqlite_migrations(engine: AsyncEngine) -> None:
    """Bring a SQLite store to head, with foreign keys checked by hand.

    Alembic's batch mode rebuilds a table for anything SQLite cannot ALTER in
    place: copy the rows into a new table, DROP the original, rename the copy.
    With ``PRAGMA foreign_keys=ON`` (which every pooled connection has, see
    :func:`make_engine`) that DROP is an implicit ``DELETE FROM``, so the ON
    DELETE actions fire and the children of the rebuilt table (dossier fields,
    saved views, runbook embeddings, the observation->lead link) are silently
    emptied while the migration reports success. Enforcement is therefore
    switched off for the duration of the upgrade and back on before the
    connection returns to the pool. The pragma is a no-op inside an open SQLite
    transaction and the driver only begins one ahead of DML, so it must be the
    first statement on the connection. ``foreign_key_check`` is what stands in
    for enforcement meanwhile: an upgrade that leaves dangling references is
    rolled back rather than committed.

    The explicit ``BEGIN`` is what makes that rollback mean anything. The
    driver's implicit transaction only starts ahead of DML, so without it every
    CREATE / ALTER in the chain commits the moment it runs while the version
    stamp and the backfills are what ``rollback()`` undoes. A revision that
    raises half-way (or a process killed inside the startup window) then leaves
    a schema ahead of its stamp, and every later start fails on "table already
    exists" until the store is restored. Opened here, the transaction holds the
    whole chain: Alembic sees it as external and commits nothing on its own, so
    a failed upgrade leaves the store exactly as it found it.

    The check is the migration's, not the store's. It runs only when a
    revision is about to run, and it compares the dangling references after
    the chain with those before it: a store that already held an orphan (a
    restore from an older backup, a row written before the pragma existed)
    keeps starting, with a warning, instead of refusing to boot on a start
    that migrated nothing.
    """
    async with engine.connect() as conn:
        await conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        await conn.exec_driver_sql("BEGIN")
        try:
            if await conn.run_sync(_current_revision) == _script_head():
                return
            before = set((await conn.exec_driver_sql("PRAGMA foreign_key_check")).all())
            await conn.run_sync(_upgrade_to_head)
            after = set((await conn.exec_driver_sql("PRAGMA foreign_key_check")).all())
            introduced = after - before
            if introduced:
                await conn.rollback()
                tables = sorted({str(row[0]) for row in introduced})
                raise RuntimeError(
                    "The store migration left rows that reference missing parents in "
                    f"{', '.join(tables)}. soc-ai rolled the upgrade back."
                )
            if after:
                tables = sorted({str(row[0]) for row in after})
                _LOGGER.warning(
                    "store holds %d row(s) that reference missing parents in %s. "
                    "The rows predate this upgrade. The upgrade left them in place",
                    len(after),
                    ", ".join(tables),
                )
            await conn.commit()
        finally:
            await conn.rollback()
            await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
