"""Per-user Dashboard layout: ``GET/PUT/DELETE /api/v1/me/dashboard-layout``.

A layout is one operator's arrangement of the Dashboard panels. It belongs to a
user row, the way a saved view does, so the isolation contract is the one that
matters: a layout is readable, replaceable and resettable by the user who made
it and by nobody else. The shape contract comes second: a write that names a
panel the console does not have, or a slot outside the grid, is refused, and a
stored slot the console cannot place is dropped on read.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
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
from soc_ai.store import dashboard_layout as layout_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import DashboardLayout, User
from sqlalchemy import delete, inspect, select

ADMIN_PW = "test-admin-pw"
ANALYST_PW = "test-analyst-pw"
ORIGIN = {"Origin": "http://testserver"}
URL = "/api/v1/me/dashboard-layout"
REPO_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_LAYOUT = REPO_ROOT / "frontend" / "src" / "lib" / "dashboardLayout.ts"


def _client(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
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


def _slot(pid: str, x: int = 0, y: int = 0, w: int = 3, h: int = 1) -> dict[str, Any]:
    return {"id": pid, "x": x, "y": y, "w": w, "h": h}


LAYOUT_A = [_slot("recent", 0, 0, 12, 1), _slot("outcomes", 0, 1, 8, 1)]
LAYOUT_B = [_slot("setup-health", 0, 0, 6, 1), _slot("enrichment", 6, 0, 6, 1)]


def _put(client: TestClient, panels: list[dict[str, Any]]) -> Any:
    return client.put(URL, json={"panels": panels}, headers=ORIGIN)


def _panels(client: TestClient) -> Any:
    resp = client.get(URL)
    assert resp.status_code == 200, resp.text
    return resp.json()["panels"]


# ── schema ────────────────────────────────────────────────────────────────────


async def test_migration_creates_the_table(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "dashboard_layout" in tables
        cols = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("dashboard_layout")}
        )
        assert cols == {"user_id", "panels_json", "updated_at"}
        pk = await conn.run_sync(lambda sc: inspect(sc).get_pk_constraint("dashboard_layout"))
        assert pk["constrained_columns"] == ["user_id"]
    await engine.dispose()


async def test_a_layout_dies_with_its_user(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        user = await auth_svc.create_user(db, "casey", ANALYST_PW, role="analyst")
        await layout_svc.put_layout(db, user.id, [{"id": "recent", "x": 0, "y": 0, "w": 8, "h": 1}])
        assert await layout_svc.get_layout(db, user.id) is not None
        await db.execute(delete(User).where(User.id == user.id))
        await db.commit()
        left = (await db.scalars(select(DashboardLayout))).all()
    await engine.dispose()
    assert left == []


# ── the panel ids are one list in two languages ──────────────────────────────


def test_the_panel_ids_match_the_console() -> None:
    """The console's grid and this store must agree on every panel id.

    A panel added to the console only would be refused on every save, so no
    operator could keep a layout. A panel added here only would be accepted and
    then dropped by the console. Parse the TypeScript list and compare.
    """
    src = FRONTEND_LAYOUT.read_text(encoding="utf-8")
    block = re.search(r"export const PANEL_IDS = \[(.*?)\] as const;", src, re.S)
    assert block is not None, "PANEL_IDS not found in dashboardLayout.ts"
    console_ids = tuple(re.findall(r"'([a-z0-9-]+)'", block.group(1)))
    assert console_ids == layout_svc.PANEL_IDS


# ── round trip ────────────────────────────────────────────────────────────────


def test_a_new_user_keeps_the_shipped_layout(auth_client: TestClient) -> None:
    _login(auth_client)
    body = auth_client.get(URL).json()
    assert body["panels"] is None


def test_put_then_get_round_trips(auth_client: TestClient) -> None:
    _login(auth_client)
    resp = _put(auth_client, LAYOUT_A)
    assert resp.status_code == 200, resp.text
    assert resp.json()["panels"] == LAYOUT_A
    assert resp.json()["updated_at"]
    assert _panels(auth_client) == LAYOUT_A


def test_put_replaces_the_layout_before(auth_client: TestClient) -> None:
    _login(auth_client)
    assert _put(auth_client, LAYOUT_A).status_code == 200
    assert _put(auth_client, LAYOUT_B).status_code == 200
    assert _panels(auth_client) == LAYOUT_B


def test_an_empty_layout_is_kept(auth_client: TestClient) -> None:
    """An empty list is a layout: the console places every panel in its shipped slot."""
    _login(auth_client)
    assert _put(auth_client, []).status_code == 200
    assert _panels(auth_client) == []


def test_delete_resets_to_the_shipped_layout(auth_client: TestClient) -> None:
    _login(auth_client)
    _put(auth_client, LAYOUT_A)
    resp = auth_client.delete(URL, headers=ORIGIN)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True, "removed": True}
    assert _panels(auth_client) is None
    # A second reset is not an error: the user already has the shipped layout.
    again = auth_client.delete(URL, headers=ORIGIN)
    assert again.status_code == 200
    assert again.json() == {"ok": True, "removed": False}


# ── isolation ─────────────────────────────────────────────────────────────────


def test_a_user_sees_only_their_own_layout(
    auth_settings: Settings, auth_client: TestClient
) -> None:
    _login(auth_client)
    _put(auth_client, LAYOUT_A)

    _make_analyst(auth_settings, "jordan")
    with _client_ctx(auth_settings) as other:
        _login(other, "jordan", ANALYST_PW)
        # The admin's layout is not there for jordan.
        assert _panels(other) is None
        _put(other, LAYOUT_B)
        assert _panels(other) == LAYOUT_B

    # Negative control: jordan's save did not touch the admin's row.
    assert _panels(auth_client) == LAYOUT_A


def test_a_reset_touches_only_your_own_layout(
    auth_settings: Settings, auth_client: TestClient
) -> None:
    _login(auth_client)
    _put(auth_client, LAYOUT_A)

    _make_analyst(auth_settings, "jordan")
    with _client_ctx(auth_settings) as other:
        _login(other, "jordan", ANALYST_PW)
        resp = other.delete(URL, headers=ORIGIN)
        assert resp.status_code == 200
        assert resp.json()["removed"] is False

    assert _panels(auth_client) == LAYOUT_A


# ── shape validation ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("panels", "reason"),
    [
        ([_slot("no-such-panel")], "unknown_panel"),
        ([_slot("recent"), _slot("recent", y=5)], "duplicate_panel"),
        ([_slot("recent", x=10, w=3)], "outside_grid"),
        ([_slot("recent", x=-1)], "outside_grid"),
        ([_slot("recent", w=0)], "outside_grid"),
        ([_slot("recent", y=-1)], "outside_grid"),
        ([_slot("recent", y=layout_svc.MAX_Y + 1)], "outside_grid"),
        ([_slot("recent", h=0)], "outside_grid"),
        ([_slot("recent", h=layout_svc.MAX_H + 1)], "outside_grid"),
        ([_slot("recent", y=n) for n in range(15)], "too_many_panels"),
    ],
)
def test_put_refuses_a_layout_the_grid_cannot_place(
    auth_client: TestClient, panels: list[dict[str, Any]], reason: str
) -> None:
    _login(auth_client)
    _put(auth_client, LAYOUT_A)
    resp = _put(auth_client, panels)
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["reason"] == reason
    assert resp.json()["detail"]["hint"]
    # The refused write left the saved layout alone.
    assert _panels(auth_client) == LAYOUT_A


@pytest.mark.parametrize(
    "bad",
    [
        {"id": "recent", "x": 1.5, "y": 0, "w": 3, "h": 1},
        {"id": "recent", "x": True, "y": 0, "w": 3, "h": 1},
        {"id": "recent", "x": "0", "y": 0, "w": 3, "h": 1},
        {"id": "recent", "x": 0, "y": 0, "w": 3},
        {"id": "recent", "x": 0, "y": 0, "w": 3, "h": 1, "static": True},
    ],
)
def test_put_refuses_a_slot_that_is_not_integers(
    auth_client: TestClient, bad: dict[str, Any]
) -> None:
    _login(auth_client)
    resp = _put(auth_client, [bad])
    assert resp.status_code == 422, resp.text
    assert _panels(auth_client) is None


def test_put_accepts_every_edge_of_the_grid(auth_client: TestClient) -> None:
    """Negative control for the refusals above: the bounds are inclusive."""
    _login(auth_client)
    edges = [
        _slot("recent", x=0, w=12),
        _slot("outcomes", x=11, w=1),
        _slot("setup-health", y=layout_svc.MAX_Y),
        _slot("enrichment", h=layout_svc.MAX_H),
    ]
    resp = _put(auth_client, edges)
    assert resp.status_code == 200, resp.text
    assert _panels(auth_client) == edges


def test_put_accepts_every_known_panel(auth_client: TestClient) -> None:
    _login(auth_client)
    full = [_slot(pid, y=n) for n, pid in enumerate(layout_svc.PANEL_IDS)]
    resp = _put(auth_client, full)
    assert resp.status_code == 200, resp.text
    assert [p["id"] for p in _panels(auth_client)] == list(layout_svc.PANEL_IDS)


def test_get_drops_what_the_console_cannot_place(
    auth_settings: Settings, auth_client: TestClient
) -> None:
    """A row written before a panel was removed must still load.

    The unknown panel, the malformed slot and the second slot for one panel are
    dropped. The rest of the layout survives.
    """
    _login(auth_client)
    _put(auth_client, LAYOUT_A)

    async def _corrupt(db: Any) -> None:
        row = (await db.scalars(select(DashboardLayout))).one()
        row.panels_json = [
            _slot("retired-panel"),
            _slot("recent", 0, 0, 12, 1),
            {"id": "outcomes", "x": "zero"},
            _slot("recent", 0, 9, 12, 1),
            _slot("enrichment", 4, 2, 4, 1),
            "not a slot",
        ]
        await db.commit()

    _db_call(auth_settings, _corrupt)
    assert _panels(auth_client) == [_slot("recent", 0, 0, 12, 1), _slot("enrichment", 4, 2, 4, 1)]


# ── authentication ────────────────────────────────────────────────────────────


def test_an_unauthenticated_call_fails_when_auth_is_on(auth_client: TestClient) -> None:
    assert auth_client.get(URL).status_code == 401
    assert _put(auth_client, LAYOUT_A).status_code == 401
    assert auth_client.delete(URL, headers=ORIGIN).status_code == 401
    # Negative control: the same client, signed in, gets through.
    _login(auth_client)
    assert auth_client.get(URL).status_code == 200


def test_with_auth_off_the_route_refuses_and_says_why(open_client: TestClient) -> None:
    """With authentication off there is no user row to own a layout.

    The console reads ``signed_in`` from /me and keeps the layout in the
    browser. A direct call gets the house 401 with a hint that says so.
    """
    assert open_client.get("/api/v1/me").json()["signed_in"] is False
    resp = open_client.get(URL)
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "no_session"
    assert "browser" in resp.json()["detail"]["hint"]
    assert _put(open_client, LAYOUT_A).status_code == 401


# ── store functions ───────────────────────────────────────────────────────────


def test_validate_refuses_a_bool_where_a_column_goes() -> None:
    slot: layout_svc.PanelSlot = {"id": "recent", "x": True, "y": 0, "w": 3, "h": 1}
    with pytest.raises(layout_svc.LayoutInvalidError) as err:
        layout_svc.validate_panels([slot])
    assert err.value.reason == "outside_grid"


def test_sanitize_reads_anything_without_raising() -> None:
    for raw in (None, "text", 7, {"panels": []}, [None, 3, [], {}]):
        assert layout_svc.sanitize_panels(raw) == []
