"""Dependency and test-harness hygiene gates.

The major caps in pyproject.toml are policy, not accident: each one carries a
comment naming the breaking change the next major brings (pydantic-ai 2.x, the
Elasticsearch 9.x client refusing an 8.x grid, mcp 2.x removing
``mcp.server.fastmcp``). A cap that goes missing surfaces as an import error
after a routine ``uv lock --upgrade``, with no pyproject diff to flag it, so the
policy is pinned here where a lockfile refresh cannot bypass it.

The harness gates hold tests/conftest.py to its own promise: an app booted under
the suite starts from a store at alembic head, a store that already exists is
migrated in place rather than replaced, and the throwaway credentials the suite
hashes do not pay production bcrypt cost.

Hermetic by design: reads the repo's own pyproject.toml and boots the app
against a scratch data dir; no network.
"""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store.auth import hash_password
from soc_ai.store.db import _migration_config

REPO_ROOT = Path(__file__).resolve().parents[1]


def _runtime_requirements() -> dict[str, Requirement]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        data = tomllib.load(f)
    reqs = [Requirement(spec) for spec in data["project"]["dependencies"]]
    return {canonicalize_name(req.name): req for req in reqs}


@pytest.mark.parametrize(
    ("name", "next_major"),
    [("pydantic-ai-slim", 2), ("elasticsearch", 9), ("mcp", 2)],
)
def test_runtime_dependency_majors_are_capped(name: str, next_major: int) -> None:
    """Every dependency whose next major is a known break stays capped below it.

    ``mcp.server.fastmcp`` is a stub in mcp 2.x that raises ``ModuleNotFoundError``
    (FastMCP became ``mcp.server.mcpserver.MCPServer``), so an uncapped floor lets
    ``uv lock --upgrade`` take the MCP server module down with no diff in
    pyproject.toml to review.
    """
    reqs = _runtime_requirements()
    assert name in reqs, f"{name} is no longer a declared runtime dependency; update this test"
    spec = reqs[name].specifier
    assert not spec.contains(f"{next_major}.0", prereleases=True), (
        f"pyproject.toml declares {reqs[name]!s}, which admits {name} {next_major}.0: cap the "
        f"major (`<{next_major}`) the way the neighbouring pins do, so a lockfile refresh "
        "cannot cross a breaking release silently."
    )


@contextlib.contextmanager
def _booted(settings: Settings) -> Iterator[TestClient]:
    """The suite's usual app boot: mocked grid and SO auth, the real store lifespan."""
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def _query_one(store: Path, sql: str) -> tuple[Any, ...] | None:
    conn = sqlite3.connect(store)
    try:
        return conn.execute(sql).fetchone()  # type: ignore[no-any-return]
    finally:
        conn.close()


def _stamped_revision(store: Path) -> str:
    row = _query_one(store, "SELECT version_num FROM alembic_version")
    assert row is not None, "the store carries no alembic_version stamp"
    return str(row[0])


def _alembic_head() -> str:
    head = ScriptDirectory.from_config(_migration_config()).get_current_head()
    assert head is not None
    return head


def test_app_boot_starts_from_a_store_at_alembic_head(settings_kratos: Settings) -> None:
    """A fresh boot under the suite serves the schema production migrates to.

    The harness copies a once-migrated template instead of running the chain per
    test; this is what catches that template falling behind a new migration.
    """
    store = settings_kratos.soc_ai_data_dir / "soc-ai.db"
    assert not store.exists()
    with _booted(settings_kratos):
        pass
    assert _stamped_revision(store) == _alembic_head()


def test_app_boot_migrates_an_existing_store_in_place(settings_kratos: Settings) -> None:
    """A store that already exists is upgraded in place, never replaced."""
    store = settings_kratos.soc_ai_data_dir / "soc-ai.db"
    store.parent.mkdir(parents=True)
    conn = sqlite3.connect(store)
    try:
        conn.execute("CREATE TABLE operator_note (body TEXT)")
        conn.execute("INSERT INTO operator_note VALUES ('kept')")
        conn.commit()
    finally:
        conn.close()
    with _booted(settings_kratos):
        pass
    assert _stamped_revision(store) == _alembic_head()
    assert _query_one(store, "SELECT body FROM operator_note") == ("kept",)


def test_suite_hashes_throwaway_passwords_at_the_minimum_bcrypt_cost() -> None:
    """Under the suite a bcrypt hash costs 4 rounds, not the production 12.

    The bootstrap admin and every seeded test user is a throwaway credential; at
    cost 12 each hash is ~0.3 s, paid once per app boot and again per login. The
    stored hash carries its own cost, so a verify against it is cheap as well.
    """
    digest = asyncio.run(hash_password("throwaway"))
    assert digest.startswith("$2b$04$"), f"hash cost prefix {digest[:7]!r}"
