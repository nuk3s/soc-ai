"""Tests for the hunt template library (E3.2): the store CRUD + idempotent builtin
seed, and the availability-annotated CRUD routes.

Store tests run against a real SQLite file migrated to head (mirrors
tests/test_runbooks.py / tests/test_hunt_schedules.py). The route tests drive the
real app via TestClient and MOCK ``discover_datasets`` (patched where it's used,
in ``routes_hunts``) so availability annotation is deterministic without an ES.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import ConnectionError as EsConnectionError
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai import main as main_mod
from soc_ai.config import Settings
from soc_ai.dossier.types import Fact
from soc_ai.so_client.inventory import DatasetInfo, GridInventory
from soc_ai.so_client.inventory import _clear_cache as _clear_inventory_cache
from soc_ai.store import host_dossier as dossier_store
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
            DatasetInfo(
                dataset=name, live_count=1000, last_seen_ms=_now_ms(), categories=("network",)
            )
            for name in dataset_names
        ),
        window_minutes=1440,
        live_events=len(dataset_names) * 1000,
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
            db, t.id, name="RDP hunt", required_datasets=["zeek.rdp", "endpoint.events.process"]
        )
        assert upd is not None
        assert upd.name == "RDP hunt"
        assert upd.required_datasets == ["zeek.rdp", "endpoint.events.process"]
        assert upd.default_window_minutes == 720  # untouched

        # missing id → None
        assert await ht_svc.update(db, 9999, name="nope") is None

        # delete
        assert await ht_svc.delete(db, t.id) is True
        assert await ht_svc.get(db, t.id) is None
        assert await ht_svc.delete(db, t.id) is False
    await engine.dispose()


# ---------------------------------------------------------------------------
# Declared dataset names have to be names something actually emits
# ---------------------------------------------------------------------------

# The vocabulary a template may draw a `required_datasets` entry from.
#
# Sourced, not invented. The `zeek.*` and `suricata.*` entries are Security
# Onion 2.4's own ingest pipeline names, which are the `event.dataset` values it
# writes (`salt/elasticsearch/files/ingest/` in Security-Onion-Solutions/
# securityonion); SO ships 130-odd Zeek pipelines and the ones below are the
# subset this product reads. The `endpoint.events.*` and `endpoint.alerts`
# entries are Elastic Defend's data streams, which land as `logs-endpoint.*`
# (Elastic Defend integration reference, "Data collected"). The `system.*` and
# `network_traffic.*` entries are the Elastic System and Packetbeat integrations.
#
# This is deliberately wider than what the builtins use. It is a vocabulary to
# check names against, not a copy of the answer: a second list of exactly the
# seven builtins' datasets would agree with a wrong name as readily as a right
# one.
_REAL_DATASET_NAMES: frozenset[str] = frozenset(
    {
        # Zeek, as Security Onion names it
        "zeek.conn",
        "zeek.dce_rpc",
        "zeek.dhcp",
        "zeek.dns",
        "zeek.files",
        "zeek.ftp",
        "zeek.http",
        "zeek.intel",
        "zeek.kerberos",
        "zeek.ldap",
        "zeek.notice",
        "zeek.ntlm",
        "zeek.rdp",
        "zeek.smb_files",
        "zeek.smb_mapping",
        "zeek.smtp",
        "zeek.software",
        "zeek.ssh",
        "zeek.ssl",
        "zeek.x509",
        # Suricata, as Security Onion names it
        "suricata.alert",
        "suricata.dns",
        "suricata.http",
        "suricata.tls",
        # Elastic Defend. There is no bare `endpoint` data stream in any of it.
        "endpoint.alerts",
        # Elastic Agent's network sensor, which on a stock Security Onion is the
        # only plane carrying flow, DNS and TLS for the range VLANs.
        "network_traffic.flow",
        "network_traffic.dns",
        "network_traffic.tls",
        "network_traffic.http",
        "endpoint.events.api",
        "endpoint.events.file",
        "endpoint.events.library",
        "endpoint.events.network",
        "endpoint.events.process",
        "endpoint.events.registry",
        "endpoint.events.security",
        # Windows and Linux host logs, and the network-metadata plane
        "system.auth",
        "system.security",
        "system.syslog",
    }
)


def test_every_builtin_requires_a_dataset_that_can_exist() -> None:
    """A template that names a dataset nothing emits is unavailable everywhere.

    "Suspicious PowerShell / LOLBins" required a dataset called `endpoint`.
    Elastic Defend has no such data stream: process execution lands in
    `endpoint.events.process`, loaded modules in `endpoint.events.library`, and
    so on. The availability check compares exact strings against the grid
    census, so the template reported missing telemetry on every Elastic Defend
    deployment there has ever been, including a grid carrying 20,760 process
    documents and 13,719 PowerShell documents in a day.
    """
    # Per alternative: a plane nothing emits is just as unavailable inside an
    # "a|b" requirement as outside one.
    declared = {
        alt
        for b in ht_svc._BUILTINS
        for ds in b.required_datasets
        for alt in ht_svc.alternatives(ds)
    }
    assert declared <= _REAL_DATASET_NAMES, sorted(declared - _REAL_DATASET_NAMES)


def test_the_powershell_builtin_is_available_on_an_elastic_defend_grid() -> None:
    """The audit above is about spelling; this is about what an analyst sees.

    A grid running Elastic Defend reports `endpoint.events.process` in its
    census, and the hunt this template starts is process execution.
    """
    powershell = next(b for b in ht_svc._BUILTINS if b.name == "Suspicious PowerShell / LOLBins")
    assert "endpoint.events.process" in powershell.required_datasets
    inv = _inventory("zeek.conn", "endpoint.events.process")
    missing = [d for d in powershell.required_datasets if d not in set(inv.dataset_names())]
    assert missing == []


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
        # the seven canned pills are present, all flagged builtin
        assert "Beaconing to rare IPs" in names
        assert "Lateral movement" in names
        assert "Suspicious PowerShell / LOLBins" in names
        assert "DCE-RPC abuse / DC attacks" in names
        assert all(r.builtin for r in rows)
        # the lateral-movement builtin carries the RDP telemetry requirement
        lat = next(r for r in rows if r.name == "Lateral movement")
        assert "zeek.rdp|system.security" in lat.required_datasets
        # the DCE-RPC builtin carries its telemetry requirement, no env gate
        dcerpc = next(r for r in rows if r.name == "DCE-RPC abuse / DC attacks")
        assert "zeek.dce_rpc" in dcerpc.required_datasets
    await engine.dispose()


async def test_seed_builtins_is_idempotent(settings_kratos: Settings) -> None:
    """Calling seed twice does NOT duplicate — the same seven rows, keyed by name."""
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
    inv = _inventory(
        "zeek.conn", "zeek.kerberos", "zeek.smb_files", "zeek.dns", "endpoint.events.process"
    )
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
    # The RDP requirement now names its Windows alternative too; this grid has
    # neither, so the whole requirement is what is missing.
    assert lat["missingDatasets"] == ["zeek.rdp|system.security"]
    assert lat["builtin"] is True

    # beaconing needs only zeek.conn (present) → available
    beacon = by_name["Beaconing to rare IPs"]
    assert beacon["available"] is True
    assert beacon["missingDatasets"] == []

    # DNS/C2 needs zeek.dns (present) → available
    assert by_name["DNS / C2 exfiltration"]["available"] is True


def test_list_annotates_availability_missing_dcerpc(client: TestClient) -> None:
    """On a grid WITHOUT zeek.dce_rpc, the DCE-RPC builtin is flagged (amber), not
    hidden or demoted — flag-not-demote: a dataset gap is fixable collection, not
    an environment mismatch, so `applicable` stays True while `available` flips."""
    inv = _inventory(
        "zeek.conn", "zeek.kerberos", "zeek.smb_files", "zeek.dns", "endpoint.events.process"
    )
    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(return_value=inv),
    ):
        resp = client.get("/api/v1/hunt-templates")
    assert resp.status_code == 200, resp.text
    by_name = _templates_by_name(resp.json())

    dcerpc = by_name["DCE-RPC abuse / DC attacks"]
    assert dcerpc["available"] is False
    assert dcerpc["missingDatasets"] == ["zeek.dce_rpc"]
    assert dcerpc["applicable"] is True  # flag, not demote — no env requirement
    assert dcerpc["missingEnvironment"] == []
    assert dcerpc["builtin"] is True


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


def test_list_available_when_the_grid_is_down(client: TestClient) -> None:
    """G7: a DOWN grid must not be reported as a grid with no telemetry.

    Unlike the test above this does NOT patch ``discover_datasets`` — it fails
    the real ES search underneath it, which is the path that shipped the bug:
    discovery swallowed the error and handed the route a real-looking EMPTY
    inventory, so the fail-open branch never ran and every starter was dimmed
    with "your grid carries no DNS/endpoint/network telemetry".
    """
    _clear_inventory_cache()
    es = client.app.state.elastic._client  # type: ignore[attr-defined]
    es.search = AsyncMock(side_effect=EsConnectionError("connection refused"))
    try:
        resp = client.get("/api/v1/hunt-templates")
    finally:
        _clear_inventory_cache()

    assert resp.status_code == 200, resp.text
    payload = resp.json()
    with_datasets = [t for t in payload if t["requiredDatasets"]]
    assert with_datasets, "expected builtins that require datasets"
    for template in with_datasets:
        assert template["available"] is True, template["name"]
        assert template["missingDatasets"] == [], template["name"]


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


# ---------------------------------------------------------------------------
# Environment fit — the SECOND annotation axis (dataset presence ≠ relevance).
# A builtin whose target machinery the network has never shown (Kerberoasting
# with no domain-joined host) is applicable=False + missingEnvironment — and
# STILL in the list: not-applicable is a demotion, never a hiding. Fail-open on
# a profile error and on a never-built table, and one qualifying host suffices.
# ---------------------------------------------------------------------------

# The three environment-gated builtins, and the four network-generic ones.
ENV_GATED = ("Credential abuse / lockouts", "Lateral movement", "Suspicious PowerShell / LOLBins")
NETWORK_GENERIC = (
    "Beaconing to rare IPs",
    "DNS / C2 exfiltration",
    "New external services",
    "DCE-RPC abuse / DC attacks",
)

# A full inventory so availability is all-green and the tests below isolate the
# environment axis from the telemetry axis.
_FULL_INV = (
    "zeek.conn",
    "zeek.kerberos",
    "zeek.smb_files",
    "zeek.rdp",
    "zeek.dns",
    "endpoint.events.process",
    "zeek.dce_rpc",
)


def _seed_dossier_host(
    client: TestClient,
    ip: str,
    *,
    os_family: str | None = None,
    domain: str | None = None,
    built: bool = True,
) -> None:
    """One host through the builder's own write path (fresh, strong facts)."""
    now = datetime.now(UTC).replace(tzinfo=None)

    async def _run() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            host = await dossier_store.upsert_host(
                db, ip, last_built_at=now if built else None, now=now
            )
            facts = []
            if os_family is not None:
                facts.append(("os_family", os_family))
            if domain is not None:
                facts.append(("domain_membership", domain))
            for field, value in facts:
                await dossier_store.upsert_inferred(
                    db,
                    host,
                    Fact(
                        field=field,
                        value=value,
                        confidence=0.9,
                        strength="strong",
                        source="hostlog",
                        evidence=[f"{value} (from hostlog)"],
                        observed_at=now,
                    ),
                    now=now,
                )
            await db.commit()

    asyncio.run(_run())


def _list_templates(client: TestClient) -> dict[str, dict[str, Any]]:
    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(return_value=_inventory(*_FULL_INV)),
    ):
        resp = client.get("/api/v1/hunt-templates")
    assert resp.status_code == 200, resp.text
    return _templates_by_name(resp.json())


def test_environment_fit_demotes_on_an_owner_shaped_network(client: TestClient) -> None:
    """A few linux hosts, zero Windows, zero domain: the domain/Windows hunts
    are applicable=False with the human phrase, still listed (never hidden),
    while the network-generic three stay applicable. Telemetry availability is
    all-green here — the two axes are independent."""
    for ip in ("10.0.0.11", "10.0.0.12", "10.0.0.13"):
        _seed_dossier_host(client, ip, os_family="linux")
    by_name = _list_templates(client)

    assert set(by_name) >= set(ENV_GATED)  # demoted, NOT hidden
    cred = by_name["Credential abuse / lockouts"]
    assert cred["applicable"] is False
    assert cred["missingEnvironment"] == ["a domain-joined host"]
    for name in ("Lateral movement", "Suspicious PowerShell / LOLBins"):
        assert by_name[name]["applicable"] is False
        assert by_name[name]["missingEnvironment"] == ["a Windows host"]
        assert by_name[name]["available"] is True  # the axes are independent
    for name in NETWORK_GENERIC:
        assert by_name[name]["applicable"] is True
        assert by_name[name]["missingEnvironment"] == []


def test_environment_fit_fail_open_when_nothing_ever_built(client: TestClient) -> None:
    """An unknown network is not an empty network: census rows with no build
    (and an empty table before them) must not demote anything."""
    by_name = _list_templates(client)  # empty table
    assert all(t["applicable"] is True for t in by_name.values())

    _seed_dossier_host(client, "10.0.0.14", built=False)  # census-only row
    by_name = _list_templates(client)
    assert all(t["applicable"] is True for t in by_name.values())
    assert all(t["missingEnvironment"] == [] for t in by_name.values())


def test_environment_fit_fail_open_when_profile_query_raises(client: TestClient) -> None:
    """A broken profile query must never demote a hunt (mirrors the inventory
    fail-open one field over)."""
    with patch(
        "soc_ai.api.webui.routes_hunts.dossier_store.environment_profile",
        AsyncMock(side_effect=RuntimeError("db broke")),
    ):
        by_name = _list_templates(client)
    assert by_name  # builtins seeded
    assert all(t["applicable"] is True for t in by_name.values())


def test_environment_fit_one_qualifying_host_reopens_the_hunts(client: TestClient) -> None:
    """The moment ONE Windows domain-joined host resolves, every demotion lifts
    — computed per request from the store, so no cache to wait out."""
    for ip in ("10.0.0.11", "10.0.0.12", "10.0.0.13"):
        _seed_dossier_host(client, ip, os_family="linux")
    assert _list_templates(client)["Lateral movement"]["applicable"] is False

    _seed_dossier_host(client, "10.0.0.20", os_family="windows", domain="CORP.EXAMPLE.COM")
    by_name = _list_templates(client)
    for name in (*ENV_GATED, *NETWORK_GENERIC):
        assert by_name[name]["applicable"] is True, name
        assert by_name[name]["missingEnvironment"] == []


def test_environment_fit_custom_templates_are_always_applicable(client: TestClient) -> None:
    """An operator template is never demoted — the operator knows their network
    — even one that shares a builtin's name on a network that demotes that
    builtin."""
    for ip in ("10.0.0.11", "10.0.0.12"):
        _seed_dossier_host(client, ip, os_family="linux")
    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(return_value=_inventory(*_FULL_INV)),
    ):
        created = client.post(
            "/api/v1/hunt-templates",
            json={
                "name": "Lateral movement",  # deliberate collision with the builtin
                "objective_template": "My own lateral-movement sweep.",
                "required_datasets": [],
            },
        )
        assert created.status_code == 200, created.text
        assert created.json()["applicable"] is True
        listing = client.get("/api/v1/hunt-templates").json()
    rows = [t for t in listing if t["name"] == "Lateral movement"]
    assert len(rows) == 2
    by_kind = {t["builtin"]: t for t in rows}
    assert by_kind[True]["applicable"] is False  # the builtin stays demoted
    assert by_kind[False]["applicable"] is True  # the operator's is untouched


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


# ---------------------------------------------------------------------------
# "Any of": one requirement, several planes that satisfy it
# ---------------------------------------------------------------------------


def test_alternatives_splits_and_normalises() -> None:
    assert ht_svc.alternatives("zeek.rdp|system.security") == ("zeek.rdp", "system.security")
    assert ht_svc.alternatives(" zeek.rdp | system.security |") == ("zeek.rdp", "system.security")
    assert ht_svc.alternatives("zeek.conn") == ("zeek.conn",)


def test_norm_datasets_canonicalises_alternatives() -> None:
    """Whitespace and empties inside an element go, and an element that
    collapses to one plane is stored as that plane, so ``a|`` and ``a`` are
    the same requirement and compare equal on the wire."""
    assert ht_svc._norm_datasets([" zeek.rdp | system.security ", "zeek.conn|", "zeek.conn"]) == [
        "zeek.rdp|system.security",
        "zeek.conn",
    ]


def test_lateral_movement_is_available_when_windows_logs_stand_in_for_zeek_rdp(
    client: TestClient,
) -> None:
    """The range: 30k live SMB records, 184 Kerberos, zero zeek.rdp anywhere, and
    RDP sessions plainly visible as Windows logon type 10 in system.security.
    The template reported unavailable on that grid."""
    inv = _inventory("zeek.conn", "zeek.smb_files", "system.security", "endpoint.events.process")
    with patch("soc_ai.api.webui.routes_hunts.discover_datasets", AsyncMock(return_value=inv)):
        resp = client.get("/api/v1/hunt-templates")
    lat = _templates_by_name(resp.json())["Lateral movement"]
    assert lat["available"] is True
    assert lat["missingDatasets"] == []


def test_a_requirement_no_alternative_satisfies_is_listed_verbatim(client: TestClient) -> None:
    """NEGATIVE CONTROL. Neither plane present: the whole requirement is what is
    missing, and the operator sees every plane that would have satisfied it."""
    inv = _inventory("zeek.conn", "zeek.smb_files", "endpoint.events.process")
    with patch("soc_ai.api.webui.routes_hunts.discover_datasets", AsyncMock(return_value=inv)):
        resp = client.get("/api/v1/hunt-templates")
    lat = _templates_by_name(resp.json())["Lateral movement"]
    assert lat["available"] is False
    assert lat["missingDatasets"] == ["zeek.rdp|system.security", "zeek.kerberos|system.security"]


# ---------------------------------------------------------------------------
# Backfill-only planes are present, queryable, and said so
# ---------------------------------------------------------------------------


def _inventory_with_backfill(
    live: tuple[str, ...], backfill_only: tuple[str, ...]
) -> GridInventory:
    rows = [
        DatasetInfo(dataset=n, live_count=1000, last_seen_ms=_now_ms(), categories=("network",))
        for n in live
    ] + [
        DatasetInfo(
            dataset=n,
            live_count=0,
            last_seen_ms=None,
            categories=("network",),
            imported_count=40000,
        )
        for n in backfill_only
    ]
    return GridInventory(
        datasets=tuple(rows),
        window_minutes=1440,
        live_events=len(live) * 1000,
        imported_events=len(backfill_only) * 40000,
    )


def test_a_backfill_only_plane_keeps_the_template_available_and_says_so(
    client: TestClient,
) -> None:
    """Hunting history is legitimate, so the template stays available. But on the
    range zeek.dns was 88% imports and system.security 98%, and 'available'
    on its own reads as 'this grid is seeing it'. The label carries the truth."""
    inv = _inventory_with_backfill(live=("zeek.conn",), backfill_only=("zeek.dns",))
    with patch("soc_ai.api.webui.routes_hunts.discover_datasets", AsyncMock(return_value=inv)):
        resp = client.get("/api/v1/hunt-templates")
    by_name = _templates_by_name(resp.json())
    dns = by_name["DNS / C2 exfiltration"]
    assert dns["available"] is True
    assert dns["missingDatasets"] == []
    # The label names the REQUIREMENT, alternatives and all -- the same rule
    # the next test pins for "zeek.rdp|system.security".
    assert dns["backfillOnlyDatasets"] == ["zeek.dns|network_traffic.dns"]
    # NEGATIVE CONTROL in the same response: a live plane is not labelled.
    assert by_name["Beaconing to rare IPs"]["backfillOnlyDatasets"] == []


def test_an_alternative_met_only_by_backfill_is_labelled_by_its_requirement(
    client: TestClient,
) -> None:
    """Alternatives and backfill compose: if the only alternative present is an
    import, the requirement is met and the label names the requirement."""
    inv = _inventory_with_backfill(
        live=("zeek.smb_files", "zeek.kerberos"), backfill_only=("system.security",)
    )
    with patch("soc_ai.api.webui.routes_hunts.discover_datasets", AsyncMock(return_value=inv)):
        resp = client.get("/api/v1/hunt-templates")
    lat = _templates_by_name(resp.json())["Lateral movement"]
    assert lat["available"] is True
    assert lat["backfillOnlyDatasets"] == ["zeek.rdp|system.security"]


def test_backfill_labels_are_absent_when_the_inventory_could_not_be_read(
    client: TestClient,
) -> None:
    """Fail-open must not invent a label either way."""
    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(side_effect=RuntimeError("down")),
    ):
        resp = client.get("/api/v1/hunt-templates")
    for t in resp.json():
        assert t["backfillOnlyDatasets"] == []
        assert t["availabilityKnown"] is False


# ---------------------------------------------------------------------------
# Merge 5: a template names the analytics to run first
# ---------------------------------------------------------------------------


async def test_migration_0049_adds_the_analytics_column(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        cols = {
            c["name"]
            for c in await conn.run_sync(lambda sc: inspect(sc).get_columns("hunt_templates"))
        }
    assert "analytics_json" in cols
    await engine.dispose()


async def test_a_template_stores_and_updates_its_analytics(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        t = await ht_svc.create(
            db,
            name="Kerberos sweep",
            objective_template="Hunt for service ticket abuse.",
            analytics=["identity-4769-rc4-service-ticket", " ", "identity-4769-rc4-service-ticket"],
        )
        # Blanks are dropped and duplicates are removed.
        assert t.analytics == ["identity-4769-rc4-service-ticket"]

        patched = await ht_svc.update(db, t.id, analytics=["identity-4768-preauth-disabled"])
        assert patched is not None and patched.analytics == ["identity-4768-preauth-disabled"]

        # None leaves the list alone.
        again = await ht_svc.update(db, t.id, name="Kerberos sweep 2")
        assert again is not None and again.analytics == ["identity-4768-preauth-disabled"]

        # A template that names none reads as an empty list, never as None.
        plain = await ht_svc.create(db, name="Plain", objective_template="Hunt.")
        assert plain.analytics == []
    await engine.dispose()
