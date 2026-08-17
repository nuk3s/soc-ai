"""Per-user saved list views: ``GET/POST/DELETE /api/v1/me/views``.

A saved view is one analyst's named filter set for one list screen. The owner
chose server-side storage over localStorage explicitly, so the views follow the
analyst between workstations — which makes the isolation contract the load-
bearing one: a view is readable and deletable by exactly the user who made it,
and by nobody else. Everything below exists to pin that.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import auth as auth_svc
from soc_ai.store import saved_views as views_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect, select

ADMIN_PW = "test-admin-pw"
ANALYST_PW = "test-analyst-pw"
ORIGIN = {"Origin": "http://testserver"}


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


# A second signed-in browser, so two users can hold sessions at once.
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


def _make_analyst(settings: Settings, username: str, password: str = ANALYST_PW) -> None:
    async def _fn(db: Any) -> None:
        await auth_svc.create_user(db, username, password, role="analyst")

    _db_call(settings, _fn)


def _create(
    client: TestClient,
    *,
    screen: str = "investigations",
    name: str = "Beacons",
    query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resp = client.post(
        "/api/v1/me/views",
        json={
            "screen": screen,
            "name": name,
            "query": query if query is not None else {"verdict": ["true_positive"]},
        },
        headers=ORIGIN,
    )
    assert resp.status_code == 200, resp.text
    out: dict[str, Any] = resp.json()
    return out


# ── schema ────────────────────────────────────────────────────────────────────


async def test_migration_creates_saved_view_table(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "saved_view" in tables
        cols = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("saved_view")}
        )
        assert {"id", "user_id", "screen", "name", "query_json", "created_at"} <= cols
        indexes = await conn.run_sync(lambda sc: inspect(sc).get_indexes("saved_view"))
        assert "ix_saved_view_user_screen" in {ix["name"] for ix in indexes}
    await engine.dispose()


# ── CRUD ──────────────────────────────────────────────────────────────────────


def test_create_then_list_own_views(auth_client: TestClient) -> None:
    _login(auth_client)
    created = _create(auth_client, screen="hosts", name="Crown jewels", query={"role": "server"})
    assert created["screen"] == "hosts"
    assert created["name"] == "Crown jewels"
    assert created["query"] == {"role": "server"}
    assert isinstance(created["id"], int)

    resp = auth_client.get("/api/v1/me/views")
    assert resp.status_code == 200, resp.text
    rows = resp.json()["rows"]
    assert [r["name"] for r in rows] == ["Crown jewels"]
    assert rows[0]["query"] == {"role": "server"}


def test_list_filters_by_screen(auth_client: TestClient) -> None:
    _login(auth_client)
    _create(auth_client, screen="hosts", name="Crown jewels")
    _create(auth_client, screen="investigations", name="Beacons")

    rows = auth_client.get("/api/v1/me/views", params={"screen": "hosts"}).json()["rows"]
    assert [r["name"] for r in rows] == ["Crown jewels"]
    rows = auth_client.get("/api/v1/me/views", params={"screen": "investigations"}).json()["rows"]
    assert [r["name"] for r in rows] == ["Beacons"]
    assert len(auth_client.get("/api/v1/me/views").json()["rows"]) == 2


def test_views_are_listed_oldest_first(auth_client: TestClient) -> None:
    # Chip order must be stable across loads, so the operator's muscle memory
    # holds; creation order is the only order that never reshuffles itself.
    _login(auth_client)
    for name in ("one", "two", "three"):
        _create(auth_client, name=name)
    rows = auth_client.get("/api/v1/me/views").json()["rows"]
    assert [r["name"] for r in rows] == ["one", "two", "three"]


def test_resaving_a_name_replaces_the_view(auth_client: TestClient) -> None:
    # One name per screen per user: saving "Beacons" twice updates the filters
    # rather than growing a second identical chip.
    _login(auth_client)
    first = _create(auth_client, name="Beacons", query={"verdict": ["true_positive"]})
    again = _create(auth_client, name="Beacons", query={"verdict": ["false_positive"]})
    assert again["id"] == first["id"]
    rows = auth_client.get("/api/v1/me/views").json()["rows"]
    assert len(rows) == 1
    assert rows[0]["query"] == {"verdict": ["false_positive"]}


def test_same_name_on_a_different_screen_is_a_different_view(auth_client: TestClient) -> None:
    _login(auth_client)
    _create(auth_client, screen="hosts", name="Mine")
    _create(auth_client, screen="hunts", name="Mine")
    assert len(auth_client.get("/api/v1/me/views").json()["rows"]) == 2


def test_delete_own_view(auth_client: TestClient) -> None:
    _login(auth_client)
    created = _create(auth_client)
    resp = auth_client.delete(f"/api/v1/me/views/{created['id']}", headers=ORIGIN)
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    assert auth_client.get("/api/v1/me/views").json()["rows"] == []


def test_delete_unknown_view_is_404(auth_client: TestClient) -> None:
    _login(auth_client)
    resp = auth_client.delete("/api/v1/me/views/9999", headers=ORIGIN)
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"


# ── validation ────────────────────────────────────────────────────────────────


def test_unknown_screen_is_refused(auth_client: TestClient) -> None:
    _login(auth_client)
    resp = auth_client.post(
        "/api/v1/me/views",
        json={"screen": "spaceships", "name": "nope", "query": {}},
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "unknown_screen"


def test_blank_name_is_refused(auth_client: TestClient) -> None:
    _login(auth_client)
    resp = auth_client.post(
        "/api/v1/me/views",
        json={"screen": "hosts", "name": "   ", "query": {}},
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "empty_name"


def test_an_oversized_query_is_refused(auth_client: TestClient) -> None:
    """`query_json` had no bound at all: a 4 MiB blob returned 200 and round-
    tripped byte-for-byte, so any signed-in analyst could script 30 rows of
    arbitrary size into the appliance's SQLite. The real payloads are 95-485
    bytes."""
    _login(auth_client)
    resp = auth_client.post(
        "/api/v1/me/views",
        json={"screen": "hosts", "name": "fat", "query": {"q": "x" * 8000}},
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "query_too_large"
    assert auth_client.get("/api/v1/me/views").json()["rows"] == []


def test_a_deeply_nested_query_is_refused(auth_client: TestClient) -> None:
    """Length alone does not cover nesting: ~2,000 nested arrays fit inside the
    size cap and exhaust the recursion limit when the value is walked."""
    _login(auth_client)
    deep: Any = "leaf"
    for _ in range(500):
        deep = [deep]
    resp = auth_client.post(
        "/api/v1/me/views",
        json={"screen": "hosts", "name": "deep", "query": {"nest": deep}},
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "query_too_deep"


def test_a_realistic_query_fits_the_bound_with_room(auth_client: TestClient) -> None:
    """The bound has to clear what the screens actually save, with headroom for
    facets not built yet — otherwise it is a bug waiting for a feature."""
    _login(auth_client)
    realistic = {
        "verdict": ["true_positive", "false_positive", "needs_more_info", "inconclusive"],
        "status": ["complete", "running", "error", "interrupted", "cancelled"],
        "range": "custom",
        "custom": {"from": "2026-08-01T00:00:00.000Z", "to": "2026-08-12T23:59:59.000Z"},
        "q": "x" * 200,
        "groupBy": "detection",
    }
    resp = auth_client.post(
        "/api/v1/me/views",
        json={"screen": "investigations", "name": "everything", "query": realistic},
        headers=ORIGIN,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["query"] == realistic


def test_the_cap_still_lets_you_edit_the_views_that_filled_it(auth_client: TestClient) -> None:
    """Re-saving is an UPDATE, so it must work at the cap — otherwise hitting the
    limit locks the operator out of the very views that hit it."""
    _login(auth_client)
    for i in range(30):
        _create(auth_client, name=f"view-{i}")
    resp = auth_client.post(
        "/api/v1/me/views",
        json={"screen": "investigations", "name": "view-0", "query": {"verdict": ["inconclusive"]}},
        headers=ORIGIN,
    )
    assert resp.status_code == 200, resp.text
    rows = auth_client.get("/api/v1/me/views").json()["rows"]
    assert len(rows) == 30
    assert rows[0]["query"] == {"verdict": ["inconclusive"]}


def test_concurrent_saves_cannot_exceed_the_cap(auth_settings: Settings) -> None:
    """The cap used to be check-then-act: count, then insert. Eight concurrent
    saves against 29 existing rows landed 31. The count now happens while the
    writer holds SQLite's write lock, so the losers are refused rather than
    squeezed in."""

    async def _fn(db: Any) -> None:
        user = await auth_svc.create_user(db, "race", "race-pw-123456", role="analyst")
        for i in range(29):
            await views_svc.upsert_view(
                db, user.id, screen="hosts", name=f"seed-{i}", query={"n": i}
            )

    _db_call(auth_settings, _fn)

    async def _go() -> list[Any]:
        engine = make_engine(auth_settings)
        maker = make_sessionmaker(engine)
        user_id = await _lookup_user_id(maker, "race")

        async def one(n: int) -> Any:
            async with maker() as db:
                try:
                    await views_svc.upsert_view(
                        db, user_id, screen="hunts", name=f"race-{n}", query={"n": n}
                    )
                    return "ok"
                except views_svc.TooManyViewsError:
                    return "refused"

        out = await asyncio.gather(*(one(n) for n in range(8)))
        await engine.dispose()
        return list(out)

    results = asyncio.run(_go())
    assert results.count("ok") == 1, results

    async def _count(db: Any) -> int:
        rows = await views_svc.list_views(db, await _uid(db, "race"))
        return len(rows)

    assert _db_call(auth_settings, _count) == 30


async def _lookup_user_id(maker: Any, username: str) -> int:
    async with maker() as db:
        return await _uid(db, username)


async def _uid(db: Any, username: str) -> int:
    from soc_ai.store.models import User

    user = await db.scalar(select(User).where(User.username == username))
    assert user is not None
    return int(user.id)


def test_a_view_hoard_is_capped(auth_client: TestClient) -> None:
    # An unbounded per-user table behind a one-click button is a growth path
    # with no ceiling; the chip row stops being readable long before it hurts.
    _login(auth_client)
    for i in range(30):
        _create(auth_client, name=f"view-{i}")
    resp = auth_client.post(
        "/api/v1/me/views",
        json={"screen": "investigations", "name": "one too many", "query": {}},
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "too_many_views"


# ── isolation: the contract the owner asked for ───────────────────────────────


def test_another_users_views_are_invisible(
    auth_settings: Settings, auth_client: TestClient
) -> None:
    _login(auth_client)
    _create(auth_client, name="admin's view")

    _make_analyst(auth_settings, "jordan")
    with _client_ctx(auth_settings) as other:
        _login(other, "jordan", ANALYST_PW)
        assert other.get("/api/v1/me/views").json()["rows"] == []
        _create(other, name="jordan's view")
        assert [r["name"] for r in other.get("/api/v1/me/views").json()["rows"]] == [
            "jordan's view"
        ]

    # The admin still sees only their own.
    assert [r["name"] for r in auth_client.get("/api/v1/me/views").json()["rows"]] == [
        "admin's view"
    ]


def test_another_users_view_cannot_be_deleted(
    auth_settings: Settings, auth_client: TestClient
) -> None:
    _login(auth_client)
    mine = _create(auth_client, name="admin's view")

    _make_analyst(auth_settings, "jordan")
    with _client_ctx(auth_settings) as other:
        _login(other, "jordan", ANALYST_PW)
        # Not 403 — an id that is not yours simply does not exist for you, so a
        # probe cannot map the other user's ids either.
        resp = other.delete(f"/api/v1/me/views/{mine['id']}", headers=ORIGIN)
        assert resp.status_code == 404

    assert [r["name"] for r in auth_client.get("/api/v1/me/views").json()["rows"]] == [
        "admin's view"
    ]


def test_no_session_no_views(auth_client: TestClient) -> None:
    resp = auth_client.get("/api/v1/me/views")
    assert resp.status_code == 401
