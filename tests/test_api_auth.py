"""Tests for flag-gated session/bearer auth on the JSON API."""

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
def open_client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


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


def _mint_token(settings: Settings) -> str:
    """Create an API token directly in the same SQLite file the app uses."""

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


def test_flag_off_keeps_api_open(open_client: TestClient) -> None:
    assert open_client.get("/sessions/any").status_code == 200


def test_flag_on_rejects_anonymous(auth_client: TestClient) -> None:
    resp = auth_client.get("/sessions/any")
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "no_session"


def test_flag_on_rejects_bad_token(auth_client: TestClient) -> None:
    resp = auth_client.get("/sessions/any", headers={"Authorization": "Bearer scai_bogus"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "invalid_token"


def test_flag_on_accepts_api_token(auth_client: TestClient, auth_settings: Settings) -> None:
    raw = _mint_token(auth_settings)
    resp = auth_client.get("/sessions/any", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200


def test_flag_on_accepts_session_cookie(auth_client: TestClient) -> None:
    login = auth_client.post(
        "/api/v1/login",
        json={"username": "admin", "password": ADMIN_PW},
    )
    assert login.status_code == 200
    assert auth_client.get("/sessions/any").status_code == 200


def test_healthz_stays_open(auth_client: TestClient) -> None:
    assert auth_client.get("/healthz").status_code == 200


def test_flag_on_rejects_anonymous_post(auth_client: TestClient) -> None:
    resp = auth_client.post("/find-alert", json={})
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "no_session"
