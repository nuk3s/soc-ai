"""Per-user tour state: ``GET/PUT /api/v1/me/tours`` and migration 0065.

The console's tutorial mode keeps one small object per user: the global
opt-out and, per tour id, the version the operator saw. It lives on the user
row, so "first sign-in" holds across browsers. The contracts that matter:

- isolation: a user reads and writes their own state and nobody else's; a
  bearer token reads and writes the state of the user who created it;
- shape: a write that is not ``{"off": bool, "seen": {id: version}}``, or that
  is too large, is refused; a stored value the store cannot read reads as the
  default and never as a 500;
- authentication off: no user row stands behind the request, so the route
  answers the house 401 and the console keeps the state in the browser.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from alembic import command
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import auth as auth_svc
from soc_ai.store import user_tours as tours_svc
from soc_ai.store.db import _migration_config, make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import User
from sqlalchemy import Connection, inspect, select, text, update

ADMIN_PW = "test-admin-pw"
ANALYST_PW = "test-analyst-pw"
ORIGIN = {"Origin": "http://testserver"}
URL = "/api/v1/me/tours"


def _client(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


_client_ctx = contextlib.contextmanager(_client)


@pytest.fixture
def auth_settings(settings_kratos: Settings, tmp_path: Path) -> Settings:
    return settings_kratos.model_copy(
        update={
            "api_auth_required": True,
            "bootstrap_admin_password": SecretStr(ADMIN_PW),
            "soc_ai_data_dir": tmp_path / "data",
        }
    )


@pytest.fixture
def auth_client(auth_settings: Settings) -> Iterator[TestClient]:
    yield from _client(auth_settings)


@pytest.fixture
def open_client(settings_kratos: Settings) -> Iterator[TestClient]:
    """Authentication OFF, the way the range and the demo run."""
    yield from _client(settings_kratos)


def _login(client: TestClient, username: str = "admin", password: str = ADMIN_PW) -> None:
    resp = client.post("/api/v1/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text


def _db_call(settings: Settings, fn: Any) -> Any:
    async def _go() -> Any:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            out = await fn(db)
        await engine.dispose()
        return out

    return asyncio.run(_go())


def _make_analyst(settings: Settings, username: str) -> None:
    async def _fn(db: Any) -> None:
        await auth_svc.create_user(db, username, ANALYST_PW, role="analyst")

    _db_call(settings, _fn)


def _put(client: TestClient, body: Any, headers: dict[str, str] | None = None) -> Any:
    return client.put(URL, json=body, headers={**ORIGIN, **(headers or {})})


STATE_A = {"off": False, "seen": {"welcome": 1, "alerts": 2}}
STATE_B = {"off": True, "seen": {"hosts": 1}}
DEFAULT = {"off": False, "seen": {}}


# ── migration 0065 ────────────────────────────────────────────────────────────


def _upgrade_to(connection: Connection, revision: str) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, revision)


def _downgrade_to(connection: Connection, revision: str) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.downgrade(cfg, revision)


async def test_a_fresh_store_has_the_column_with_an_empty_default(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        cols = await conn.run_sync(
            lambda sc: {c["name"]: c for c in inspect(sc).get_columns("users")}
        )
        head = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert head.scalar_one() == "0065"
    assert "tours_state" in cols
    assert cols["tours_state"]["nullable"] is False
    maker = make_sessionmaker(engine)
    async with maker() as db:
        user = await auth_svc.create_user(db, "casey", ANALYST_PW)
        raw = await db.scalar(select(User.tours_state).where(User.id == user.id))
    await engine.dispose()
    assert raw == "{}"


async def test_the_upgrade_gives_an_existing_user_the_empty_state(
    settings_kratos: Settings,
) -> None:
    """A user row from before 0065 reads as a user who saw no tour."""
    engine = make_engine(settings_kratos)
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0064")
        await conn.execute(
            text(
                "INSERT INTO users (id, username, password_hash, role, disabled, status) "
                "VALUES (7, 'dana', 'x', 'analyst', false, '')"
            )
        )
        await conn.run_sync(_upgrade_to, "0065")
        raw = (await conn.execute(text("SELECT tours_state FROM users WHERE id = 7"))).scalar_one()
    assert raw == "{}"
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade_to, "0064")
        cols = await conn.run_sync(lambda sc: {c["name"] for c in inspect(sc).get_columns("users")})
        await conn.run_sync(_upgrade_to, "head")
    await engine.dispose()
    assert "tours_state" not in cols


# ── round trip and isolation ──────────────────────────────────────────────────


def test_a_new_user_has_seen_no_tour(auth_client: TestClient) -> None:
    _login(auth_client)
    resp = auth_client.get(URL)
    assert resp.status_code == 200, resp.text
    assert resp.json() == DEFAULT


def test_put_then_get_round_trips(auth_client: TestClient) -> None:
    _login(auth_client)
    resp = _put(auth_client, STATE_A)
    assert resp.status_code == 200, resp.text
    assert resp.json() == STATE_A
    assert auth_client.get(URL).json() == STATE_A
    # A second write replaces the first one whole.
    assert _put(auth_client, STATE_B).json() == STATE_B
    assert auth_client.get(URL).json() == STATE_B


def test_a_user_reads_and_writes_only_their_own_state(
    auth_settings: Settings, auth_client: TestClient
) -> None:
    _login(auth_client)
    _put(auth_client, STATE_A)

    _make_analyst(auth_settings, "jordan")
    with _client_ctx(auth_settings) as other:
        _login(other, "jordan", ANALYST_PW)
        assert other.get(URL).json() == DEFAULT
        assert _put(other, STATE_B).status_code == 200
        assert other.get(URL).json() == STATE_B

    # Negative control: jordan's write did not touch the admin's row.
    assert auth_client.get(URL).json() == STATE_A


def test_a_token_reads_and_writes_the_state_of_its_user(
    auth_settings: Settings, auth_client: TestClient
) -> None:
    _login(auth_client)
    _put(auth_client, STATE_A)

    async def _token(db: Any) -> str:
        admin = await db.scalar(select(User).where(User.username == "admin"))
        return await auth_svc.create_api_token(db, "automation", admin.id)

    raw = _db_call(auth_settings, _token)
    with _client_ctx(auth_settings) as bot:
        bearer = {"Authorization": f"Bearer {raw}"}
        assert bot.get(URL, headers=bearer).json() == STATE_A
        resp = bot.put(URL, json=STATE_B, headers=bearer)
        assert resp.status_code == 200, resp.text
        # A token that soc-ai does not know reads nothing.
        bad = {"Authorization": "Bearer scai_not-a-token"}
        assert bot.get(URL, headers=bad).status_code == 401
    assert auth_client.get(URL).json() == STATE_B


def test_an_unauthenticated_call_fails_when_auth_is_on(auth_client: TestClient) -> None:
    assert auth_client.get(URL).status_code == 401
    assert _put(auth_client, STATE_A).status_code == 401
    # Negative control: the same client, signed in, gets through.
    _login(auth_client)
    assert auth_client.get(URL).status_code == 200


def test_with_auth_off_the_route_refuses_and_names_the_browser(open_client: TestClient) -> None:
    """With authentication off no user row owns the state.

    The console reads ``signed_in`` from /me and keeps the state in the
    browser. A direct call gets the house 401 with a hint that says so.
    """
    assert open_client.get("/api/v1/me").json()["signed_in"] is False
    resp = open_client.get(URL)
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "no_session"
    assert "browser" in resp.json()["detail"]["hint"]
    assert _put(open_client, STATE_A).status_code == 401


# ── shape ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "body",
    [
        {"off": "yes", "seen": {}},
        {"off": 1, "seen": {}},
        {"off": False, "seen": {"welcome": "1"}},
        {"off": False, "seen": {"welcome": 1.5}},
        {"off": False, "seen": {"welcome": True}},
        {"off": False, "seen": []},
        {"off": False},
        {"seen": {}},
        {"off": False, "seen": {}, "extra": 1},
        [],
    ],
)
def test_put_refuses_a_body_of_the_wrong_shape(auth_client: TestClient, body: Any) -> None:
    _login(auth_client)
    assert _put(auth_client, body).status_code == 422
    # Nothing was stored.
    assert auth_client.get(URL).json() == DEFAULT


@pytest.mark.parametrize(
    "seen",
    [
        {"Welcome": 1},
        {"": 1},
        {"a b": 1},
        {"x" * 49: 1},
        {"welcome": -1},
        {"welcome": tours_svc.MAX_VERSION + 1},
    ],
)
def test_put_refuses_a_tour_id_or_version_out_of_range(
    auth_client: TestClient, seen: dict[str, int]
) -> None:
    _login(auth_client)
    resp = _put(auth_client, {"off": False, "seen": seen})
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["reason"] == "invalid_tours_state"
    assert resp.json()["detail"]["hint"]
    assert auth_client.get(URL).json() == DEFAULT


def test_put_caps_the_number_of_tours(auth_client: TestClient) -> None:
    _login(auth_client)
    full = {f"tour-{i}": 1 for i in range(tours_svc.MAX_TOURS)}
    assert _put(auth_client, {"off": False, "seen": full}).status_code == 200
    over = {**full, "one-more": 1}
    resp = _put(auth_client, {"off": False, "seen": over})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "invalid_tours_state"
    # The state before the refused write stays.
    assert auth_client.get(URL).json()["seen"] == full


def test_put_caps_the_size_of_the_body(auth_client: TestClient) -> None:
    """A large body is refused before it is parsed into the model."""
    _login(auth_client)
    padded = json.dumps({"off": False, "seen": {}}) + " " * (tours_svc.MAX_BYTES + 1)
    resp = auth_client.put(
        URL, content=padded, headers={**ORIGIN, "Content-Type": "application/json"}
    )
    assert resp.status_code == 413
    assert resp.json()["detail"]["reason"] == "payload_too_large"


def test_get_reads_a_damaged_value_as_the_default(
    auth_settings: Settings, auth_client: TestClient
) -> None:
    _login(auth_client)

    async def _damage(db: Any) -> None:
        await db.execute(
            update(User).where(User.username == "admin").values(tours_state="{not json")
        )
        await db.commit()

    _db_call(auth_settings, _damage)
    resp = auth_client.get(URL)
    assert resp.status_code == 200
    assert resp.json() == DEFAULT
    # The next write repairs the row.
    assert _put(auth_client, STATE_A).status_code == 200
    assert auth_client.get(URL).json() == STATE_A


# ── store functions ───────────────────────────────────────────────────────────


def test_sanitize_reads_anything_without_raising() -> None:
    assert tours_svc.sanitize_state(None) == DEFAULT
    assert tours_svc.sanitize_state("") == DEFAULT
    assert tours_svc.sanitize_state("[]") == DEFAULT
    assert tours_svc.sanitize_state('{"off": "x", "seen": 3}') == DEFAULT
    # Good entries stay. A bad entry goes on its own.
    mixed = json.dumps({"off": True, "seen": {"welcome": 2, "Bad Id": 1, "hosts": "1", "lead": -3}})
    assert tours_svc.sanitize_state(mixed) == {"off": True, "seen": {"welcome": 2}}


def test_validate_refuses_and_names_the_fault() -> None:
    with pytest.raises(tours_svc.ToursStateInvalidError) as exc:
        tours_svc.validate_state({"off": False, "seen": {"BAD": 1}})
    assert "BAD" in exc.value.hint
    assert tours_svc.validate_state(STATE_A) == STATE_A
