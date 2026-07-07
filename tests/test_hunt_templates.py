"""Tests for the hunt template library (E3.2): the store CRUD + idempotent builtin
seed, and the availability-annotated CRUD routes.

Store tests run against a real SQLite file migrated to head (mirrors
tests/test_runbooks.py / tests/test_hunt_schedules.py). The route tests drive the
real app via TestClient and MOCK ``discover_datasets`` (patched where it's used,
in ``routes_hunts``) so availability annotation is deterministic without an ES.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai import main as main_mod
from soc_ai.config import Settings
from soc_ai.so_client.inventory import DatasetInfo, GridInventory
from soc_ai.store import hunt_templates as ht_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _inventory(*dataset_names: str) -> GridInventory:
    """A GridInventory whose ``dataset_names()`` returns exactly the given names."""
    return GridInventory(
        datasets=tuple(
            DatasetInfo(dataset=name, count=1000, last_seen_ms=_now_ms(), categories=("network",))
            for name in dataset_names
        ),
        window_minutes=1440,
        total_events=len(dataset_names) * 1000,
    )


# ---------------------------------------------------------------------------
# Migration: 0016 creates the hunt_templates table (proves it applies)
# ---------------------------------------------------------------------------


async def test_migration_creates_hunt_templates_table(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = set(await conn.run_sync(lambda sc: inspect(sc).get_table_names()))
    assert "hunt_templates" in tables
    await engine.dispose()


# ---------------------------------------------------------------------------
# Store CRUD
# ---------------------------------------------------------------------------


async def test_create_list_get_update_delete(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        t = await ht_svc.create(
            db,
            name="RDP lateral movement",
            objective_template="Hunt for RDP between internal hosts.",
            required_datasets=["zeek.rdp", "zeek.rdp", " "],  # dedup + drop blanks
            default_window_minutes=720,
            created_by="alice",
        )
        assert t.id is not None
        assert t.name == "RDP lateral movement"
        assert t.required_datasets == ["zeek.rdp"]  # de-duplicated, blank dropped
        assert t.default_window_minutes == 720
        assert t.builtin is False
        assert t.created_by == "alice"

        # list + get
        assert [r.id for r in await ht_svc.list_all(db)] == [t.id]
        got = await ht_svc.get(db, t.id)
        assert got is not None and got.id == t.id
        assert await ht_svc.get_by_name(db, "RDP lateral movement") is not None

        # patch only given fields
        upd = await ht_svc.update(
            db, t.id, name="RDP hunt", required_datasets=["zeek.rdp", "endpoint"]
        )
        assert upd is not None
        assert upd.name == "RDP hunt"
        assert upd.required_datasets == ["zeek.rdp", "endpoint"]
        assert upd.default_window_minutes == 720  # untouched

        # missing id → None
        assert await ht_svc.update(db, 9999, name="nope") is None

        # delete
        assert await ht_svc.delete(db, t.id) is True
        assert await ht_svc.get(db, t.id) is None
        assert await ht_svc.delete(db, t.id) is False
    await engine.dispose()


# ---------------------------------------------------------------------------
# seed_builtins — idempotent upsert-by-name
# ---------------------------------------------------------------------------


async def test_seed_builtins_seeds_the_pill_set(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        n = await ht_svc.seed_builtins(db)
        assert n == len(ht_svc._BUILTINS)  # every builtin seeded
        rows = await ht_svc.list_all(db)
        names = {r.name for r in rows}
        # the six canned pills are present, all flagged builtin
        assert "Beaconing to rare IPs" in names
        assert "Lateral movement" in names
        assert "Suspicious PowerShell / LOLBins" in names
        assert all(r.builtin for r in rows)
        # the lateral-movement builtin carries the RDP telemetry requirement
        lat = next(r for r in rows if r.name == "Lateral movement")
        assert "zeek.rdp" in lat.required_datasets
    await engine.dispose()


async def test_seed_builtins_is_idempotent(settings_kratos: Settings) -> None:
    """Calling seed twice does NOT duplicate — the same six rows, keyed by name."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ht_svc.seed_builtins(db)
        first = await ht_svc.list_all(db)
        await ht_svc.seed_builtins(db)  # second startup
        second = await ht_svc.list_all(db)
    assert len(first) == len(second) == len(ht_svc._BUILTINS)
    assert {r.name for r in first} == {r.name for r in second}
    await engine.dispose()


async def test_seed_builtins_refreshes_content_but_not_customs(settings_kratos: Settings) -> None:
    """A re-seed refreshes a builtin's objective in place; a custom (builtin=False)
    template is never touched, even one that happens to share a name."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ht_svc.seed_builtins(db)
        # corrupt a builtin's objective, then re-seed → it's refreshed back
        lat = await ht_svc.get_by_name(db, "Lateral movement")
        assert lat is not None
        lat.objective_template = "TAMPERED"
        await db.commit()
        await ht_svc.seed_builtins(db)
        lat2 = await ht_svc.get_by_name(db, "Lateral movement")
        assert lat2 is not None and lat2.objective_template != "TAMPERED"

        # a custom template is left alone by a re-seed
        custom = await ht_svc.create(
            db, name="My grid recon", objective_template="custom obj", builtin=False
        )
        await ht_svc.seed_builtins(db)
        again = await ht_svc.get(db, custom.id)
        assert again is not None and again.objective_template == "custom obj"
    await engine.dispose()


# ---------------------------------------------------------------------------
# CRUD routes + availability annotation
# ---------------------------------------------------------------------------


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = main_mod.create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _templates_by_name(payload: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {t["name"]: t for t in payload}


def test_list_annotates_availability_missing_rdp(client: TestClient) -> None:
    """On a grid WITHOUT zeek.rdp, the lateral-movement template is available=False
    with zeek.rdp in missingDatasets; a template whose datasets are all present is
    available=True. Builtins are seeded at app startup (lifespan)."""
    # grid has conn/kerberos/smb_files/dns/endpoint but NOT zeek.rdp
    inv = _inventory("zeek.conn", "zeek.kerberos", "zeek.smb_files", "zeek.dns", "endpoint")
    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(return_value=inv),
    ):
        resp = client.get("/api/v1/hunt-templates")
    assert resp.status_code == 200, resp.text
    by_name = _templates_by_name(resp.json())

    # lateral movement needs zeek.rdp (absent) → FLAGGED, not hidden
    lat = by_name["Lateral movement"]
    assert lat["available"] is False
    assert lat["missingDatasets"] == ["zeek.rdp"]
    assert lat["builtin"] is True

    # beaconing needs only zeek.conn (present) → available
    beacon = by_name["Beaconing to rare IPs"]
    assert beacon["available"] is True
    assert beacon["missingDatasets"] == []

    # DNS/C2 needs zeek.dns (present) → available
    assert by_name["DNS / C2 exfiltration"]["available"] is True


def test_list_best_effort_when_inventory_fails(client: TestClient) -> None:
    """If inventory discovery raises, templates are returned available=True /
    missing=[] — an inventory error never HIDES or falsely flags a template."""
    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(side_effect=RuntimeError("es down")),
    ):
        resp = client.get("/api/v1/hunt-templates")
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload  # builtins seeded
    assert all(t["available"] is True and t["missingDatasets"] == [] for t in payload)


def test_custom_template_create_and_delete(client: TestClient) -> None:
    """A custom template round-trips (create → list → delete). builtin=False."""
    empty_inv = _inventory()  # no datasets → everything flagged, but shape is fine
    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(return_value=empty_inv),
    ):
        created = client.post(
            "/api/v1/hunt-templates",
            json={
                "name": "Custom SSH brute force",
                "objective_template": "Hunt for SSH brute-force against internal hosts.",
                "required_datasets": ["zeek.ssh"],
                "default_window_minutes": 720,
            },
        )
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["name"] == "Custom SSH brute force"
        assert body["builtin"] is False
        assert body["requiredDatasets"] == ["zeek.ssh"]
        # zeek.ssh not in the empty inventory → flagged
        assert body["available"] is False
        assert body["missingDatasets"] == ["zeek.ssh"]
        tid = body["id"]

        # it appears in the list
        listing = client.get("/api/v1/hunt-templates").json()
        assert "Custom SSH brute force" in _templates_by_name(listing)

        # delete the custom template
        rm = client.delete(f"/api/v1/hunt-templates/{tid}")
        assert rm.status_code == 200
        assert rm.json() == {"deleted": True}
        listing2 = client.get("/api/v1/hunt-templates").json()
        assert "Custom SSH brute force" not in _templates_by_name(listing2)


def test_delete_builtin_refused_409(client: TestClient) -> None:
    """A builtin template cannot be deleted (409) — it's code-owned + re-seeded."""
    inv = _inventory("zeek.conn")
    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(return_value=inv),
    ):
        listing = client.get("/api/v1/hunt-templates").json()
        beacon = _templates_by_name(listing)["Beaconing to rare IPs"]
        assert beacon["builtin"] is True
        rm = client.delete(f"/api/v1/hunt-templates/{beacon['id']}")
    assert rm.status_code == 409
    assert rm.json()["detail"]["reason"] == "builtin_undeletable"


def test_update_builtin_refused_409(client: TestClient) -> None:
    """A builtin template cannot be edited (409) — its content is code-owned."""
    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(return_value=_inventory("zeek.conn")),
    ):
        listing = client.get("/api/v1/hunt-templates").json()
        beacon = _templates_by_name(listing)["Beaconing to rare IPs"]
        upd = client.put(
            f"/api/v1/hunt-templates/{beacon['id']}",
            json={"name": "hijack attempt"},
        )
    assert upd.status_code == 409
    assert upd.json()["detail"]["reason"] == "builtin_immutable"


def test_delete_missing_template_404(client: TestClient) -> None:
    assert client.delete("/api/v1/hunt-templates/9999").status_code == 404


def test_create_template_requires_name_and_objective(client: TestClient) -> None:
    assert client.post("/api/v1/hunt-templates", json={"name": "x"}).status_code == 422
    assert (
        client.post("/api/v1/hunt-templates", json={"objective_template": "y"}).status_code == 422
    )


def test_mutate_routes_admin_gated(settings_kratos: Settings) -> None:
    """With API auth ON, an anonymous custom-template create is refused; an admin
    gets through (mirrors the schedule/runbook admin gate)."""
    settings = settings_kratos.model_copy(
        update={
            "api_auth_required": True,
            "bootstrap_admin_password": SecretStr("admin-pw"),
        }
    )
    inv = _inventory("zeek.conn")
    for c in _client(settings):
        with patch(
            "soc_ai.api.webui.routes_hunts.discover_datasets",
            AsyncMock(return_value=inv),
        ):
            anon = c.post(
                "/api/v1/hunt-templates",
                json={"name": "x", "objective_template": "hunt x", "required_datasets": []},
            )
            assert anon.status_code in (401, 403)

            login = c.post("/api/v1/login", json={"username": "admin", "password": "admin-pw"})
            assert login.status_code == 200, login.text
            ok = c.post(
                "/api/v1/hunt-templates",
                json={
                    "name": "admin tmpl",
                    "objective_template": "hunt it",
                    "required_datasets": [],
                },
                headers={"Origin": "http://testserver"},
            )
            assert ok.status_code == 200, ok.text
            assert ok.json()["name"] == "admin tmpl"
            assert ok.json()["builtin"] is False
