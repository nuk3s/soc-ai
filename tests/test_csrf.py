"""CSRF Origin/Referer guard for cookie-authenticated mutating /api/v1 requests.

The guard (``soc_ai.api.security.require_csrf_safe``) protects the gated
``/api/v1`` router. We exercise it against ``POST /api/v1/me/status`` (a simple
mutating endpoint that needs no SO/ES mocking) and ``POST /api/v1/login`` (open
router → exempt).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import auth as auth_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

ADMIN_PW = "test-admin-pw"
# TestClient's default base_url → its own (same) origin.
SAME_ORIGIN = "http://testserver"
CROSS_ORIGIN = "https://evil.example.com"


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
def auth_settings(settings_kratos: Settings) -> Settings:
    return settings_kratos.model_copy(
        update={
            "api_auth_required": True,
            "bootstrap_admin_password": SecretStr(ADMIN_PW),
        }
    )


@pytest.fixture
def auth_client(auth_settings: Settings) -> Iterator[TestClient]:
    yield from _client(auth_settings)


@pytest.fixture
def open_client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _login(client: TestClient) -> None:
    """Authenticate so the session cookie is set on the client's jar.

    Login is on the open router (exempt) and needs no Origin header.
    """
    resp = client.post("/api/v1/login", json={"username": "admin", "password": ADMIN_PW})
    assert resp.status_code == 200, resp.text


def _mint_token(settings: Settings) -> str:
    async def _go() -> str:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            user = await auth_svc.create_user(db, "svc", "pw")
            raw = await auth_svc.create_api_token(db, "test", user.id)
        await engine.dispose()
        return raw

    return asyncio.run(_go())


# ── cookie-auth mutating POSTs ──────────────────────────────────────────────


def test_cookie_post_no_origin_is_rejected(auth_client: TestClient) -> None:
    _login(auth_client)
    resp = auth_client.post("/api/v1/me/status", json={"status": "busy"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "bad_origin"


def test_cookie_post_cross_origin_is_rejected(auth_client: TestClient) -> None:
    _login(auth_client)
    resp = auth_client.post(
        "/api/v1/me/status",
        json={"status": "busy"},
        headers={"Origin": CROSS_ORIGIN},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "bad_origin"


def test_cookie_post_same_origin_is_allowed(auth_client: TestClient) -> None:
    _login(auth_client)
    resp = auth_client.post(
        "/api/v1/me/status",
        json={"status": "busy"},
        headers={"Origin": SAME_ORIGIN},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_cookie_post_referer_fallback_is_allowed(auth_client: TestClient) -> None:
    """No Origin but a same-origin Referer → allowed."""
    _login(auth_client)
    resp = auth_client.post(
        "/api/v1/me/status",
        json={"status": "busy"},
        headers={"Referer": f"{SAME_ORIGIN}/app/me"},
    )
    assert resp.status_code == 200


# ── bearer-token requests are exempt ────────────────────────────────────────


def test_bearer_post_cross_origin_is_allowed(
    auth_client: TestClient, auth_settings: Settings
) -> None:
    raw = _mint_token(auth_settings)
    resp = auth_client.post(
        "/api/v1/me/status",
        json={"status": "busy"},
        headers={"Authorization": f"Bearer {raw}", "Origin": CROSS_ORIGIN},
    )
    assert resp.status_code == 200, resp.text


# ── GET / login exemptions ──────────────────────────────────────────────────


def test_get_with_any_origin_is_allowed(auth_client: TestClient) -> None:
    _login(auth_client)
    # /hunts is a dependency-free GET ([]); the CSRF guard never engages on GET.
    resp = auth_client.get("/api/v1/hunts", headers={"Origin": CROSS_ORIGIN})
    assert resp.status_code == 200


def test_login_is_exempt_from_csrf(auth_client: TestClient) -> None:
    """POST /api/v1/login carries no Origin and must not be CSRF-rejected."""
    resp = auth_client.post("/api/v1/login", json={"username": "admin", "password": ADMIN_PW})
    assert resp.status_code == 200
    # logout is also on the open router → exempt.
    out = auth_client.post("/api/v1/logout")
    assert out.status_code != 403


# ── dev mode (api_auth_required=False) ──────────────────────────────────────


def test_dev_mode_no_cookie_is_exempt(open_client: TestClient) -> None:
    """No auth required + no cookie → CSRF guard skipped (no ambient credential)."""
    resp = open_client.post(
        "/api/v1/me/status",
        json={"status": "busy"},
        headers={"Origin": CROSS_ORIGIN},
    )
    assert resp.status_code == 200


def test_dev_mode_with_cookie_still_enforced(open_client: TestClient) -> None:
    """Even with api_auth_required=False, a present session cookie is enforced."""
    open_client.cookies.set(auth_svc.SESSION_COOKIE, "some-session-value")
    resp = open_client.post(
        "/api/v1/me/status",
        json={"status": "busy"},
        headers={"Origin": CROSS_ORIGIN},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "bad_origin"
