"""Regression tests for the B06_api_security review batch (2026-07-30).

Covers:
- F03  client_ip / _request_is_https use the right-most UNtrusted hop, not the
       client-forgeable left-most X-Forwarded-* entry.
- F54  the CSRF origin normaliser returns None (→ 403) on a malformed port
       instead of raising ValueError (→ 500).
- F53  GET /me / POST /me/status report the token identity (not the dev admin)
       to bearer callers when API auth is required.
- F20  demo POST /investigate 409s while an investigation for the alert runs.
- F34  recorded_run shields its terminal write so a client disconnect lands the
       row terminal ('error'), not stuck 'running'.
- F55  the agent-tools catalogue lists describe_dataset + field_values.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import auth as auth_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

from tests.conftest import _base_settings_kwargs


def _fake_request(
    *, headers: dict[str, str] | None = None, peer: str = "1.1.1.1", scheme: str = "http"
) -> Any:
    return SimpleNamespace(
        headers=headers or {},
        client=SimpleNamespace(host=peer),
        url=SimpleNamespace(scheme=scheme),
    )


# ---------------------------------------------------------------------------
# F03 — X-Forwarded-For / X-Forwarded-Proto trust the right-most untrusted hop
# ---------------------------------------------------------------------------


def test_client_ip_uses_rightmost_untrusted_hop_not_forged_leftmost() -> None:
    from soc_ai.api.webui._shared import client_ip

    settings = SimpleNamespace(proxy_trusted_ips=("10.0.0.1",))
    # Append-style proxy: header arrives as "<client-forged>, <real client>".
    req = _fake_request(headers={"x-forwarded-for": "6.6.6.6, 203.0.113.9"}, peer="10.0.0.1")
    assert client_ip(req, settings) == "203.0.113.9"
    # The forged left-most entry must never become the throttling key.
    assert client_ip(req, settings) != "6.6.6.6"


def test_client_ip_skips_trusted_hops_multi_proxy() -> None:
    from soc_ai.api.webui._shared import client_ip

    settings = SimpleNamespace(proxy_trusted_ips=("10.0.0.1", "10.0.0.2"))
    req = _fake_request(
        headers={"x-forwarded-for": "6.6.6.6, 203.0.113.9, 10.0.0.2"}, peer="10.0.0.1"
    )
    assert client_ip(req, settings) == "203.0.113.9"


def test_client_ip_ignores_xff_from_untrusted_peer() -> None:
    from soc_ai.api.webui._shared import client_ip

    settings = SimpleNamespace(proxy_trusted_ips=("10.0.0.1",))
    req = _fake_request(headers={"x-forwarded-for": "6.6.6.6"}, peer="8.8.8.8")
    assert client_ip(req, settings) == "8.8.8.8"


def test_request_is_https_honors_edge_proto_and_ignores_untrusted_peer() -> None:
    from soc_ai.api.webui._shared import _request_is_https

    settings = SimpleNamespace(proxy_trusted_ips=("10.0.0.1",))
    # X-Forwarded-Proto's left-most value is the client's protocol at the edge
    # proxy — honored from a trusted peer (distinct from X-Forwarded-For, where
    # the left-most hop is the forgeable client IP).
    legit = _fake_request(headers={"x-forwarded-proto": "https"}, peer="10.0.0.1", scheme="http")
    assert _request_is_https(legit, settings) is True
    # Forgery is blocked by the trusted-peer guard, not by hop position: an
    # untrusted peer's forwarded header is ignored entirely, so it can't flip the
    # Secure flag over plain HTTP.
    forged = _fake_request(
        headers={"x-forwarded-proto": "https"}, peer="203.0.113.9", scheme="http"
    )
    assert _request_is_https(forged, settings) is False
    # A direct TLS connection is always HTTPS regardless of headers.
    direct = _fake_request(peer="8.8.8.8", scheme="https")
    assert _request_is_https(direct, settings) is True


# ---------------------------------------------------------------------------
# F54 — malformed Origin/Referer port → None (403), never a 500
# ---------------------------------------------------------------------------


def test_normalize_origin_bad_port_returns_none() -> None:
    from soc_ai.api.security import _normalize_origin

    assert _normalize_origin("http://h:abc") is None
    assert _normalize_origin("http://h:99999") is None
    # Well-formed origins still normalise as before.
    assert _normalize_origin("https://h:443") == "https://h"
    assert _normalize_origin("http://h") == "http://h"


async def test_csrf_malformed_port_is_403_not_500() -> None:
    from soc_ai.api.security import require_csrf_safe

    settings = Settings(**_base_settings_kwargs())
    req = SimpleNamespace(
        method="POST",
        headers={"origin": "http://soc-ai.lan:99999"},
        cookies={auth_svc.SESSION_COOKIE: "sess"},
        base_url="http://testserver/",
        app=SimpleNamespace(state=SimpleNamespace(settings=settings)),
    )
    with pytest.raises(HTTPException) as ei:
        await require_csrf_safe(req)
    assert ei.value.status_code == 403
    assert ei.value.detail["reason"] == "bad_origin"


# ---------------------------------------------------------------------------
# F53 — /me identity for bearer-token callers under required auth
# ---------------------------------------------------------------------------

_ADMIN_PW = "review-admin-pw"


def _auth_settings() -> Settings:
    return Settings(**_base_settings_kwargs()).model_copy(
        update={
            "api_auth_required": True,
            "bootstrap_admin_password": SecretStr(_ADMIN_PW),
        }
    )


@contextmanager
def _app(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def _mint_token(settings: Settings, name: str) -> str:
    async def _go() -> str:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            user = await auth_svc.create_user(db, "svc", "pw")
            raw = await auth_svc.create_api_token(db, name, user.id)
        await engine.dispose()
        return raw

    return asyncio.run(_go())


def test_me_reports_token_identity_not_dev_admin() -> None:
    settings = _auth_settings()
    with _app(settings) as client:
        raw = _mint_token(settings, "autobot")
        resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {raw}"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["role"] == "token"
        assert body["role"] != "admin"
        assert body["username"] == "token:autobot"


# ---------------------------------------------------------------------------
# F20 — demo /investigate 409 while an investigation for the alert is running
# ---------------------------------------------------------------------------


def _seed_running_investigation(settings: Settings, alert_id: str) -> str:
    async def _go() -> str:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id=alert_id, started_by="seed")
        await engine.dispose()
        return inv.id

    return asyncio.run(_go())


def test_demo_investigate_409_while_investigation_running(monkeypatch, tmp_path) -> None:
    from tests.test_demo_mode import REPLAY_FIXTURE, _demo_app_settings, _replay_app

    alert = REPLAY_FIXTURE["replays"][0]["alert_es_id"]
    with _replay_app(monkeypatch, tmp_path) as client:
        running_id = _seed_running_investigation(_demo_app_settings(), alert)
        resp = client.post("/investigate", json={"alert_id": alert})
        assert resp.status_code == 409
        detail = resp.json()["detail"]
        assert detail["reason"] == "investigation_in_progress"
        assert detail["running_inv_id"] == running_id


# ---------------------------------------------------------------------------
# F34 — recorded_run shields its terminal write on client disconnect
# ---------------------------------------------------------------------------


async def test_recorded_run_client_disconnect_lands_terminal_state(monkeypatch, tmp_path) -> None:
    """A consumer cancelled mid-stream (SSE client disconnect) must leave the
    investigation row terminal ('error'), not orphaned in 'running'. Faithful to
    production, the consumer runs inside an anyio cancel scope, which re-delivers
    the cancellation on every await until the scope exits — a bare cleanup await is
    cancelled mid-commit; only the shielded write lands the row."""
    import anyio
    from soc_ai.agent.orchestrator import StepEvent
    from soc_ai.api.runner import recorded_run

    settings = Settings(**_base_settings_kwargs())  # DB under the clean_env tmp cwd
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    state = SimpleNamespace(db_sessionmaker=maker, settings=settings)

    async def slow_stream():
        seq = 0
        while True:
            seq += 1
            yield StepEvent(kind="step", session_id="sid", sequence=seq, payload={})
            await asyncio.sleep(0.02)

    holder: dict[str, str] = {}
    seen: list[str] = []

    async def consume(scope: anyio.CancelScope) -> None:
        async for name, data in recorded_run(
            state, alert_id="a-disc", started_by="visitor", event_stream=slow_stream()
        ):
            if name == "investigation_created":
                holder["id"] = data["investigation_id"]
            seen.append(name)
            if len(seen) >= 3:  # disconnect mid-stream, before any terminal event
                scope.cancel()

    async with anyio.create_task_group() as tg:
        tg.start_soon(consume, tg.cancel_scope)

    inv_id = holder["id"]
    # The disconnect cleanup lands the terminal row through asyncio.shield: under
    # cancellation the shield re-raises in the consumer immediately and finishes
    # the write on a detached task, so the row goes terminal a beat AFTER the task
    # group unwinds. Wait for that write rather than racing it (fast enough to win
    # locally, not under CI load). A real regression — the row never leaving
    # 'running' — still fails, at the timeout.
    inv = None
    for _ in range(300):  # up to ~3s
        async with maker() as db:
            got = await inv_svc.get_with_events(db, inv_id)
        assert got is not None
        inv, _events = got
        if inv.status != "running":
            break
        await asyncio.sleep(0.01)
    await engine.dispose()

    assert "done" not in seen
    assert inv is not None
    assert inv.status == "error"


# ---------------------------------------------------------------------------
# F55 — the agent-tools catalogue lists the dataset-discovery tools
# ---------------------------------------------------------------------------


def test_catalog_includes_dataset_discovery_tools() -> None:
    from soc_ai.api.agent_tools import catalog_tool_names, collect_agent_tools

    names = catalog_tool_names()
    assert "describe_dataset" in names
    assert "field_values" in names

    settings = SimpleNamespace(es_hosts=["https://es:9200"])
    tools = {t.name: t for t in collect_agent_tools(settings)}
    for n in ("describe_dataset", "field_values"):
        assert tools[n].read_only is True
        assert tools[n].category == "Query"
        assert tools[n].requires == ["Elasticsearch"]
        assert tools[n].available is True
