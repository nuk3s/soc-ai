"""Preflight-as-API: the Wave-1 doctor checks feeding the Dashboard setup-health card."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai import doctor
from soc_ai.config import Settings
from soc_ai.doctor import CheckResult
from soc_ai.main import create_app
from soc_ai.so_client.elastic import EsSearchResult

FAKE_ROWS = [
    CheckResult("upstream reachability", "PASS", "all good"),
    CheckResult("audit write grant", "FAIL", "missing write", hint="run the script"),
    CheckResult("index pattern coverage", "WARN", "no auth events", hint="widen it"),
    CheckResult("egress posture", "INFO", "local-only"),
]


# ── doctor-level stubs for the ONE full run_doctor() test below — replicated
# (not imported) from tests/test_doctor.py's _StubSecurity/_StubElastic/_StubAuth,
# per that file's own module-local convention (see its docstring: patches go
# where the callee looks the name up, doubles live beside the tests that use
# them rather than in a shared module). ──────────────────────────────────────


class _StubSecurity:
    def __init__(self, has_all_requested: bool) -> None:
        self._has_all_requested = has_all_requested

    async def has_privileges(self, **kwargs: Any) -> dict[str, Any]:
        index_req = kwargs.get("index") or [{}]
        names = index_req[0].get("names", [])
        privileges = index_req[0].get("privileges", [])
        index_name = names[0] if names else ""
        return {
            "has_all_requested": self._has_all_requested,
            "index": {index_name: dict.fromkeys(privileges, self._has_all_requested)},
        }


class _StubElastic:
    def __init__(self, *, total: int = 42) -> None:
        self._total = total
        self.closed = False
        self._client = SimpleNamespace(security=_StubSecurity(True))

    async def ping(self) -> dict[str, Any]:
        return {"cluster": "so-grid", "version": "8.14.3"}

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        return EsSearchResult(total=self._total, took_ms=1)

    async def aclose(self) -> None:
        self.closed = True


class _StubAuth:
    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        return SimpleNamespace(status_code=200)

    async def aclose(self) -> None:
        pass


# ── module-local `_client`/`client` fixture: same shape as
# tests/test_webui_api.py (plain client, settings_kratos, api_auth_required
# unset so require_admin_api / require_api_auth both no-op) — that file
# defines it module-local rather than sharing it via conftest, so this
# replicates the same pattern here (tests/test_config_day1_tier.py does too).


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


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


# ── the authed-non-admin shape, mirrored from
# tests/test_webui_api.py::_auth_client / _seed_user_session (module-local
# there too — see e.g. test_sweep_health_readable_by_an_analyst_while_the_full_
# status_stays_admin, the DossierSweepHealthOut precedent's own admin-gate test).

_ADMIN_PW = "test-preflight-admin-pw"


def _auth_client(settings_kratos: Settings) -> Iterator[TestClient]:
    auth_settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr(_ADMIN_PW)}
    )
    yield from _client(auth_settings)


async def _seed_user_session(client: TestClient, *, username: str, role: str) -> str:
    from soc_ai.store import auth as auth_svc

    maker = client.app.state.db_sessionmaker
    async with maker() as db:
        user = await auth_svc.create_user(db, username, "longpassword1", role=role)
        return await auth_svc.create_session(db, user, ttl_hours=24)


# ── fake run_doctor, patched at the seam routes_meta.py imports it into ─────


def _install_fake_run_doctor(monkeypatch: pytest.MonkeyPatch, calls: list[int]) -> None:
    async def _fake_run_doctor(
        settings: Settings, *, include_fitness: bool = True
    ) -> list[CheckResult]:
        calls.append(1)
        return FAKE_ROWS

    monkeypatch.setattr("soc_ai.api.webui.routes_meta.run_doctor", _fake_run_doctor)


@pytest.fixture
def _preflight_calls() -> list[int]:
    return []


@pytest.fixture
def run_counter(_preflight_calls: list[int]) -> Callable[[], int]:
    """Closure over the patched fake's call count — how many times the fake
    run_doctor actually ran, vs. being served from the TTL cache."""

    def _count() -> int:
        return len(_preflight_calls)

    return _count


@pytest.fixture
def client_with_fake_preflight(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, _preflight_calls: list[int]
) -> TestClient:
    _install_fake_run_doctor(monkeypatch, _preflight_calls)
    return client


@pytest.fixture
def admin_client_with_fake_preflight(client_with_fake_preflight: TestClient) -> TestClient:
    """Same client as above: with api_auth_required off, require_admin_api
    no-ops (see soc_ai/api/webui/_shared.py), so the plain client already
    reaches the admin-gated detail route — mirrors how
    tests/test_config_day1_tier.py's plain `client` reaches the admin-gated
    GET /api/v1/config with no login at all."""
    return client_with_fake_preflight


@pytest.fixture
def client_nonadmin_with_fake_preflight(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch, _preflight_calls: list[int]
) -> Iterator[TestClient]:
    _install_fake_run_doctor(monkeypatch, _preflight_calls)
    from soc_ai.store.auth import SESSION_COOKIE

    for authed in _auth_client(settings_kratos):
        token = asyncio.run(_seed_user_session(authed, username="analyst1", role="analyst"))
        authed.cookies.set(SESSION_COOKIE, token)
        yield authed


@pytest.fixture
def demo_client_with_fake_preflight(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch, _preflight_calls: list[int]
) -> Iterator[TestClient]:
    """The public Render demo: replayed fixtures, no live grid/gateway.

    Mirrors tests/test_host_chat_api.py's ``demo_client`` fixture shape:
    ``soc_ai_demo=True`` plus a loopback ``es_hosts`` override — required for
    app STARTUP to succeed at all, since ``ElasticClient.__init__`` itself
    refuses a non-loopback host under the demo egress guard regardless of any
    HTTP-layer route (see tests/test_demo_mode.py::test_elastic_loopback_only_in_demo).
    """
    _install_fake_run_doctor(monkeypatch, _preflight_calls)
    yield from _client(
        settings_kratos.model_copy(
            update={"soc_ai_demo": True, "es_hosts": ["http://127.0.0.1:9200"]}
        )
    )


# ── run_doctor(include_fitness=False) ────────────────────────────────────────


async def test_run_doctor_include_fitness_false_skips_fitness(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Pins the kwarg: the card must never pay the ~130s fitness probe."""
    called: list[str] = []

    async def _fake_fitness(settings: Any) -> CheckResult:
        called.append("fitness")
        return CheckResult("model fitness", "PASS", "")

    monkeypatch.setattr(doctor, "check_model_fitness", _fake_fitness)
    # Stub the network-shaped checks the same way tests/test_doctor.py's
    # test_run_doctor_all_green does, so this stays hermetic/fast instead of
    # actually dialing so.example.com / localhost:4000.
    with (
        patch("soc_ai.doctor.make_auth", return_value=_StubAuth()),
        patch("soc_ai.doctor.ElasticClient", return_value=_StubElastic()),
        patch("soc_ai.doctor.list_gateway_models", AsyncMock(return_value=([], None))),
        patch("soc_ai.doctor._classify_endpoint", return_value=("", "resolves and connects")),
    ):
        results = await doctor.run_doctor(settings_kratos, include_fitness=False)
    assert called == []
    assert all(r.name != "model fitness" for r in results)


# ── GET /api/v1/health/preflight — closed non-admin projection ──────────────


def test_preflight_projection_shape_and_status(client_with_fake_preflight: TestClient) -> None:
    resp = client_with_fake_preflight.get("/api/v1/health/preflight")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"status", "failing", "warned", "checked_at"}
    assert body["status"] == "degraded"  # one FAIL in FAKE_ROWS
    assert body["failing"] == 1
    assert body["warned"] == 1  # INFO not counted


def test_preflight_detail_requires_admin(client_nonadmin_with_fake_preflight: TestClient) -> None:
    resp = client_nonadmin_with_fake_preflight.get("/api/v1/health/preflight/detail")
    assert resp.status_code == 403


def test_preflight_detail_rows_for_admin(admin_client_with_fake_preflight: TestClient) -> None:
    resp = admin_client_with_fake_preflight.get("/api/v1/health/preflight/detail")
    assert resp.status_code == 200
    rows = resp.json()["rows"]
    assert {"name", "status", "detail", "hint"} <= set(rows[0])
    assert any(r["hint"] == "run the script" for r in rows)


def test_preflight_is_cached_and_refresh_bypasses(
    admin_client_with_fake_preflight: TestClient, run_counter: Callable[[], int]
) -> None:
    c = admin_client_with_fake_preflight
    c.get("/api/v1/health/preflight")
    c.get("/api/v1/health/preflight")
    assert run_counter() == 1  # second hit served from cache
    c.get("/api/v1/health/preflight/detail?refresh=true")
    assert run_counter() == 2


# ── demo mode: never run the real doctor, never report degraded ─────────────
#
# Third instance of the demo false-alarm class already hotfixed for probe_llm
# (soc_ai/webui/probes.py:221-233) and probe_model_fitness
# (soc_ai/webui/probes.py:808-841): every doctor check that reaches an
# upstream (gateway, SO, ES) would hit the demo egress guard
# (assert_egress_allowed -> DemoEgressBlocked) and FAIL unconditionally,
# lighting up a false "setup broken" card on a demo that is working exactly
# as designed.


def test_preflight_demo_mode_reports_green_and_never_runs_the_doctor(
    demo_client_with_fake_preflight: TestClient, run_counter: Callable[[], int]
) -> None:
    """The summary must read green with zero counts, and the patched
    run_doctor must NEVER be called — pins that the demo never probes its own
    mock every 10 minutes.

    The already-admin-gated detail route keeps 403ing exactly as every other
    admin read does in demo mode (require_admin_api's unconditional demo
    lock — see tests/test_demo_mode.py::test_demo_refuses_admin_reads); a
    demo visitor never reaches ``_cached_preflight``'s body over HTTP at all,
    admin or not. The next test checks that function's own empty-rows
    contract directly, since no HTTP caller can observe it here by design.
    """
    c = demo_client_with_fake_preflight
    resp = c.get("/api/v1/health/preflight")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"status", "failing", "warned", "checked_at"}
    assert body["status"] == "green"
    assert body["failing"] == 0
    assert body["warned"] == 0

    detail = c.get("/api/v1/health/preflight/detail")
    assert detail.status_code == 403
    assert detail.json()["detail"]["reason"] == "demo_mode"

    assert run_counter() == 0


def test_preflight_demo_mode_cached_preflight_yields_empty_rows(
    demo_client_with_fake_preflight: TestClient,
) -> None:
    """``_cached_preflight``'s own contract for demo settings: empty rows and
    a ``checked_at``, no doctor call — checked directly, since the previous
    test shows no HTTP caller (not even an admin) can reach the detail
    route's body in demo mode. The empty-rows shape is real; it is just never
    observable over the wire there, by the pre-existing demo admin lock."""
    from soc_ai.api.webui.routes_meta import _cached_preflight

    state = demo_client_with_fake_preflight.app.state
    fake_request = SimpleNamespace(app=SimpleNamespace(state=state))
    rows, checked_at = asyncio.run(_cached_preflight(fake_request, refresh=False))  # type: ignore[arg-type]
    assert rows == []
    assert checked_at
