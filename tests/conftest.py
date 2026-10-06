"""Shared pytest fixtures for soc-ai tests.

The ``clean_env`` autouse fixture strips soc-ai-related env vars before each
test so leakage from the host shell or CI runner can't bleed into config-loading
tests. Tests that need specific env values use ``monkeypatch.setenv`` themselves
or construct :class:`Settings` directly.

:class:`Settings` has no ``env_prefix``, so every field is readable from a
bare, case-insensitive env var — ``GENERAL_CHAT_ENABLED=false`` in a dev shell
silently flips a default under every test that constructs ``Settings()``, and
the failure surfaces as an unrelated assertion in an unrelated file. The scrub
set is therefore *derived* from ``Settings.model_fields`` rather than
hand-listed: a knob added to config.py is isolated the moment it is declared,
with nothing here to keep in step.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import bcrypt
import pytest
from pydantic import SecretStr

# Cheap bcrypt for the whole suite. Every app startup hashes a bootstrap-admin
# password and the security harness hashes two more per test; at the library
# default (cost 12, ~0.16 s each on the CI runner) that was minutes of the run.
# Cost 4 is the bcrypt minimum; the hashes still round-trip through the real
# checkpw path. Patched before any soc_ai import so auth.py's import-time
# dummy hash picks it up too.
_real_gensalt = bcrypt.gensalt
bcrypt.gensalt = lambda rounds=4, prefix=b"2b": _real_gensalt(rounds, prefix)  # type: ignore[assignment]

from soc_ai import main as soc_ai_main  # noqa: E402
from soc_ai.config import Settings, get_settings  # noqa: E402
from soc_ai.store import db as store_db  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncEngine  # noqa: E402

# Security-audit harness fixtures (auth ON, two real roles, hostile-doc
# factory). Imported by name so pytest registers them here: pytest 9 rejects
# `pytest_plugins` in a non-rootdir conftest, and the repo has no root conftest.
from tests.conftest_security import (  # noqa: E402, F401
    admin_client,
    analyst_client,
    audit_client,
    audit_settings,
    hostile_doc,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Family sweeps, for env vars that are NOT :class:`Settings` fields but still
# steer soc-ai: ``SOC_AI_API_TOKEN`` (cli.py reads it straight from os.environ),
# and whatever else an operator's .env carries in one of these families. Exact
# field names are covered by ``_SETTINGS_ENV_NAMES`` below, so this tuple no
# longer has to track config.py. tests/test_config.py imports it.
_PREFIXES = (
    "SO_",
    "ES_",
    "LITELLM_",
    "AUDIT_",
    "QDRANT_",
    "MISP_",
    "INTERNAL_",
    "ORACLE_",
    "SOC_AI_",
    "HEAVY_",
    "FAST_",
    "MEMORY_",
    "EMBED_",
    "LOG_",
    "DOSSIER_",
    "API_AUTH_REQUIRED",
    "SESSION_TTL_HOURS",
    "BOOTSTRAP_ADMIN_PASSWORD",
    "WEBUI_",
)


def _settings_env_names() -> frozenset[str]:
    """Every env var name pydantic-settings would read into :class:`Settings`.

    Field names and their validation aliases (``ANALYST_MODEL`` / ``HEAVY_MODEL``),
    upper-cased for comparison because ``case_sensitive=False`` means the shell
    can spell them either way. No soc-ai field is a single bare word, so this
    never collides with PATH/HOME-style host variables.
    """
    names: set[str] = set()
    for name, field in Settings.model_fields.items():
        names.add(name.upper())
        alias = field.validation_alias
        if isinstance(alias, str):
            names.add(alias.upper())
        else:
            names.update(c.upper() for c in getattr(alias, "choices", ()) if isinstance(c, str))
    return frozenset(names)


_SETTINGS_ENV_NAMES = _settings_env_names()


def _scrub_soc_ai_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop every env var :class:`Settings` would read (see the module docstring)."""
    for key in list(os.environ):
        upper = key.upper()  # Settings reads env case-insensitively; so do we.
        if upper.startswith(_PREFIXES) or upper in _SETTINGS_ENV_NAMES:
            monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Strip soc-ai env vars and isolate tests from any .env in the project root."""
    _scrub_soc_ai_env(monkeypatch)
    # pydantic-settings reads `.env` from cwd; chdir to a clean tmp dir so the
    # repo's runtime .env doesn't bleed into tests.
    monkeypatch.chdir(tmp_path)
    # The enrichment data dirs default to absolute /var/lib/soc-ai paths, so on
    # a host with a real install every app startup parsed ~7 MB of AWS/Azure
    # prefix JSON (~1.8 s per test) and tests saw live data CI never has.
    # Point them at empty dirs; tests that need data pass the kwarg.
    for name in ("blocklist", "maxmind", "cloud_prefix"):
        monkeypatch.setenv(f"{name.upper()}_DATA_DIR", str(tmp_path / "no-host-data" / name))
    get_settings.cache_clear()
    # Reset the in-process credential throttles so failed-attempt tests don't
    # leak lockout state into later tests (the per-IP spray throttle aggregates
    # all failures from the shared "testclient" IP).
    from soc_ai.store import auth as _auth

    _auth.login_throttle.reset()
    _auth.login_ip_throttle.reset()
    _auth.password_change_throttle.reset()
    yield
    get_settings.cache_clear()


@pytest.fixture(scope="session")
def migrated_store_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A store file already at alembic head, migrated once per session.

    Every app boot runs the whole migration chain against an empty SQLite file,
    about a quarter of a second, and well over a thousand tests boot the app.
    The chain is deterministic, so it runs once here and each boot starts from
    a copy (see :func:`fast_app_boot`). The Settings it needs are built under
    the same env scrub as :func:`clean_env`, from a cwd of its own, so a dev
    shell cannot steer them. ``dispose()`` closes the last connection, which
    checkpoints and removes the WAL sidecar: the one file is the whole store.
    """
    template_dir = tmp_path_factory.mktemp("store-template")
    with pytest.MonkeyPatch.context() as mp:
        _scrub_soc_ai_env(mp)
        mp.chdir(template_dir)
        settings = Settings(**_base_settings_kwargs(), soc_ai_data_dir=template_dir / "data")

    async def _migrate_fresh_store() -> None:
        engine = store_db.make_engine(settings)
        try:
            await store_db.run_migrations(engine)
        finally:
            await engine.dispose()

    asyncio.run(_migrate_fresh_store())
    return settings.soc_ai_data_dir / "soc-ai.db"


@pytest.fixture(autouse=True)
def reset_oracle_breaker() -> Iterator[None]:
    """Each test starts with every Oracle route closed.

    The route breaker (soc_ai.oracle.breaker) is process state. A test that
    feeds a fake gateway three server errors pauses the route, and the next
    test in the same worker would otherwise make no Oracle call at all.
    """
    from soc_ai.oracle.breaker import BREAKER

    BREAKER.reset()
    yield
    BREAKER.reset()


@pytest.fixture(autouse=True)
def fast_app_boot(monkeypatch: pytest.MonkeyPatch, migrated_store_template: Path) -> None:
    """Take the migration chain out of an app boot.

    Only the lifespan's call (``soc_ai.main.run_migrations``) is redirected, and
    only when the store file does not exist yet: it then starts as a copy of
    the migrated template. A store that already exists, because the test
    migrated it first or is restarting the app, still goes through
    ``soc_ai.store.db.run_migrations``, which stays untouched for the migration
    tests and every direct caller.

    The other fixed cost of a boot, the bootstrap admin's bcrypt hash, is paid
    at the minimum cost through the module-level ``bcrypt.gensalt`` patch at the
    top of this file (it has to precede the first soc_ai import to reach
    auth.py's import-time dummy hash), so nothing is patched per test here.
    """

    async def _migrate_or_copy(engine: AsyncEngine) -> None:
        database = engine.url.database
        sqlite_file = engine.dialect.name == "sqlite" and database and database != ":memory:"
        store = Path(database) if sqlite_file and database else None
        if store is None or store.exists():
            await store_db.run_migrations(engine)
            return
        store.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(migrated_store_template, store)

    monkeypatch.setattr(soc_ai_main, "run_migrations", _migrate_or_copy)


# ── The PostgreSQL store run ──────────────────────────────────────────────────
#
# The store test modules below carry the ``postgres`` marker. In a normal run
# they use SQLite, like every other test. When SOC_AI_TEST_DATABASE_URL names a
# PostgreSQL server, each marked test gets a fresh, empty database on that
# server, and SOC_AI_DATABASE_URL points the test's Settings at it. The run then
# proves the same assertions on the second dialect:
#
#   SOC_AI_TEST_DATABASE_URL=postgresql+asyncpg://postgres:pw@127.0.0.1:5432/postgres \
#       pytest -m postgres
#
# The URL names a maintenance database. The role must be allowed to create
# databases. Read here, at import, because clean_env strips every SOC_AI_ name.
POSTGRES_TEST_URL = os.environ.get("SOC_AI_TEST_DATABASE_URL", "").strip()

POSTGRES_MODULES = frozenset(
    {
        "test_store.py",
        "test_store_investigations.py",
        "test_leads_store.py",
        "test_host_dossier_store.py",
        "test_host_machines_store.py",
        "test_hunts_store.py",
        "test_entity_profiles_store.py",
        "test_migrations_parity.py",
        # The other head canaries.
        "test_escalations_store.py",
        "test_quality_snapshot_provenance.py",
        "test_store_dialect.py",
        "test_store_postgres.py",
        "test_store_copy.py",
        # The saved-view cap leaned on SQLite's writer lock under concurrent saves.
        "test_saved_views.py",
    }
)


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    # tryfirst: the marker has to be on the item before `-m postgres` selects.
    for item in items:
        if item.path.name in POSTGRES_MODULES:
            item.add_marker(pytest.mark.postgres)


def _postgres_admin_url() -> Any:
    return store_db.parse_store_url(POSTGRES_TEST_URL)


async def _postgres_admin(statement: str) -> None:
    import asyncpg  # only the PostgreSQL run needs the driver

    url = _postgres_admin_url()
    conn = await asyncpg.connect(
        host=url.host,
        port=url.port or 5432,
        user=url.username,
        password=url.password,
        database=url.database,
    )
    try:
        await conn.execute(statement)
    finally:
        await conn.close()


@pytest.fixture(autouse=True)
def postgres_store(
    request: pytest.FixtureRequest, clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> Iterator[str | None]:
    """A fresh PostgreSQL database for a ``postgres`` test, when the run has a server.

    Yields the database URL, or ``None`` on a SQLite run. A test marked
    ``sqlite_only`` reads SQLite internals (the file, a pragma, the FTS5
    tables) and skips on the PostgreSQL run.
    """
    if not POSTGRES_TEST_URL or request.node.get_closest_marker("postgres") is None:
        yield None
        return
    if request.node.get_closest_marker("sqlite_only") is not None:
        pytest.skip("The test reads SQLite internals. The PostgreSQL run skips it.")
    name = f"socai_test_{uuid.uuid4().hex[:16]}"
    asyncio.run(_postgres_admin(f'CREATE DATABASE "{name}"'))
    url = _postgres_admin_url().set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("SOC_AI_DATABASE_URL", url)
    get_settings.cache_clear()
    try:
        yield url
    finally:
        asyncio.run(_postgres_admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@pytest.fixture
def fixture_loader() -> Callable[[str], dict[str, Any]]:
    """Returns a function that loads a JSON fixture by stem name."""

    def _load(name: str) -> dict[str, Any]:
        path = FIXTURES_DIR / f"{name}.json"
        with path.open() as f:
            return json.load(f)  # type: ignore[no-any-return]

    return _load


@pytest.fixture
def sample_alert(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("sample_alert")


@pytest.fixture
def sample_case(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("sample_case")


@pytest.fixture
def sample_detection(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("sample_detection")


@pytest.fixture
def sample_playbook(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("sample_playbook")


@pytest.fixture
def kratos_init(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("kratos_login_init")


@pytest.fixture
def oauth_token(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("oauth_token")


def _base_settings_kwargs() -> dict[str, Any]:
    """Common kwargs for constructing Settings without env loading."""
    return {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        # Tests opt into dev-open mode explicitly; the production default
        # (soc_ai.config.Settings) is True (secure-by-default).
        "api_auth_required": False,
        # The product default is True (the investigator writes the report). The
        # shared fixture pins the round-2 path so the tests that mock the
        # synthesizer keep their meaning. A test of the report-writing path sets
        # this True itself. The default itself is pinned in test_config.py.
        "investigator_emits_report": False,
    }


@pytest.fixture
def settings_kratos() -> Settings:
    """Settings configured for Kratos session-cookie auth (no Connect API)."""
    return Settings(**_base_settings_kwargs())


@pytest.fixture
def settings_connect() -> Settings:
    """Settings with Connect API client credentials configured (Pro path)."""
    kwargs = _base_settings_kwargs()
    kwargs.update(
        so_client_id="client-abc",
        so_client_secret=SecretStr("client-secret-xyz"),
    )
    return Settings(**kwargs)


@pytest.fixture
def settings_with_misp() -> Settings:
    """Settings with MISP enrichment configured."""
    kwargs = _base_settings_kwargs()
    kwargs.update(
        misp_url="https://misp.example.com",
        misp_api_key=SecretStr("misp-api-key-xyz"),
    )
    return Settings(**kwargs)
