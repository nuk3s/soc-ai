"""Self-service password change: ``POST /api/v1/me/password``.

Closes the ``no-self-service-password-change`` gap — the startup log tells the
operator to change the bootstrap admin password and delete the sidecar file,
and until this endpoint there was no way to do either from the product.

The contract that matters here is the *session scoping*: unlike the admin
``reset_user_password`` (which revokes everything), changing your own password
must keep the tab you typed it in signed in and evict only the other sessions.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.bootstrap_credential import bootstrap_credential_path
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import auth as auth_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import User, UserSession
from sqlalchemy import func, select

ADMIN_PW = "test-admin-pw"
NEW_PW = "a-much-better-pw"
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
    """Run ``fn(db)`` against the same SQLite file the app uses."""

    async def _go() -> Any:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            out = await fn(db)
        await engine.dispose()
        return out

    return asyncio.run(_go())


def _password_hash(settings: Settings, username: str) -> str:
    async def _fn(db: Any) -> str:
        user = await db.scalar(select(User).where(User.username == username))
        assert user is not None
        return str(user.password_hash)

    return str(_db_call(settings, _fn))


def _session_count(settings: Settings) -> int:
    async def _fn(db: Any) -> int:
        return int(await db.scalar(select(func.count()).select_from(UserSession)) or 0)

    return int(_db_call(settings, _fn))


def _extra_sessions(settings: Settings, username: str, n: int) -> None:
    """Mint ``n`` additional sessions for ``username`` (other tabs / devices)."""

    async def _fn(db: Any) -> None:
        user = await db.scalar(select(User).where(User.username == username))
        assert user is not None
        for _ in range(n):
            await auth_svc.create_session(db, user, 24)

    _db_call(settings, _fn)


def _user_id(settings: Settings, username: str) -> int:
    async def _fn(db: Any) -> int:
        user = await db.scalar(select(User).where(User.username == username))
        assert user is not None
        return int(user.id)

    return int(_db_call(settings, _fn))


def _make_analyst(settings: Settings, username: str, password: str) -> None:
    async def _fn(db: Any) -> None:
        await auth_svc.create_user(db, username, password, role="analyst")

    _db_call(settings, _fn)


# ── happy path ────────────────────────────────────────────────────────────────


def test_change_password_rehashes_and_keeps_current_session(
    auth_client: TestClient, auth_settings: Settings
) -> None:
    _login(auth_client)
    before = _password_hash(auth_settings, "admin")
    _extra_sessions(auth_settings, "admin", 2)
    assert _session_count(auth_settings) == 3  # this tab + two others

    resp = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": ADMIN_PW, "new_password": NEW_PW},
        headers=ORIGIN,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True

    # Hash rotated, and the new credential is the one that authenticates.
    after = _password_hash(auth_settings, "admin")
    assert after != before
    assert asyncio.run(auth_svc.verify_password(NEW_PW, after)) is True

    # The caller's own session survives — /me still answers on the same cookie.
    me = auth_client.get("/api/v1/me")
    assert me.status_code == 200, me.text
    assert me.json()["username"] == "admin"

    # …and only the caller's own session survives.
    assert _session_count(auth_settings) == 1


def test_non_admin_can_change_own_password(
    auth_client: TestClient, auth_settings: Settings
) -> None:
    """Role-independent: the endpoint is session-auth, not admin-gated."""
    _make_analyst(auth_settings, "jordan", "analyst-pw-1")
    _login(auth_client, "jordan", "analyst-pw-1")
    before = _password_hash(auth_settings, "jordan")

    resp = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": "analyst-pw-1", "new_password": "analyst-pw-2"},
        headers=ORIGIN,
    )
    assert resp.status_code == 200, resp.text
    assert _password_hash(auth_settings, "jordan") != before
    # The admin's password is untouched — the change is scoped to the caller.
    assert asyncio.run(auth_svc.verify_password(ADMIN_PW, _password_hash(auth_settings, "admin")))


# ── rejections ────────────────────────────────────────────────────────────────


def test_wrong_current_password_is_400(auth_client: TestClient, auth_settings: Settings) -> None:
    _login(auth_client)
    before = _password_hash(auth_settings, "admin")

    resp = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": "not-the-password", "new_password": NEW_PW},
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "bad_credentials"
    assert _password_hash(auth_settings, "admin") == before


def _wrong_attempt(client: TestClient) -> int:
    return client.post(
        "/api/v1/me/password",
        json={"current_password": "not-the-password", "new_password": NEW_PW},
        headers=ORIGIN,
    ).status_code


def test_repeated_wrong_current_password_is_throttled(auth_client: TestClient) -> None:
    """The endpoint is a "prove you know this password" oracle — throttle it.

    Without this, a stolen session cookie (app access, but NOT the plaintext)
    could be turned into the plaintext credential at the global rate limiter's
    ~1200/min, where login allows five attempts per 15 minutes.
    """
    _login(auth_client)
    limit = auth_svc.password_change_throttle.max_failures

    codes = [_wrong_attempt(auth_client) for _ in range(limit)]
    assert codes == [400] * limit, codes

    # The next attempt is refused before any bcrypt work happens.
    resp = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": "not-the-password", "new_password": NEW_PW},
        headers=ORIGIN,
    )
    assert resp.status_code == 429
    assert resp.json()["detail"]["reason"] == "too_many_attempts"

    # …and the lockout holds even for the CORRECT password (fail closed).
    locked = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": ADMIN_PW, "new_password": NEW_PW},
        headers=ORIGIN,
    )
    assert locked.status_code == 429


def test_password_change_throttle_does_not_lock_the_user_out_of_login(
    auth_client: TestClient,
) -> None:
    """Separate throttle instance, so a fat-fingered modal can't bar the door.

    Both throttles key on (ip, username); sharing login's instance would mean
    mistyping your current password five times also locks you out of the login
    page — punishing the legitimate analyst on a screen they reached BY being
    signed in.
    """
    _login(auth_client)
    for _ in range(auth_svc.password_change_throttle.max_failures + 3):
        _wrong_attempt(auth_client)
    assert _wrong_attempt(auth_client) == 429  # change-password is locked

    # Login for the SAME user from the SAME client is untouched.
    assert auth_svc.login_throttle.is_locked("testclient", "admin") is False
    fresh = auth_client.post("/api/v1/login", json={"username": "admin", "password": ADMIN_PW})
    assert fresh.status_code == 200, fresh.text


def test_successful_change_clears_the_throttle(auth_client: TestClient) -> None:
    _login(auth_client)
    for _ in range(auth_svc.password_change_throttle.max_failures - 1):
        assert _wrong_attempt(auth_client) == 400

    ok = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": ADMIN_PW, "new_password": NEW_PW},
        headers=ORIGIN,
    )
    assert ok.status_code == 200, ok.text
    # Counter reset: a fresh run of wrong guesses starts from zero.
    assert _wrong_attempt(auth_client) == 400


# ── the 422 must not echo the submitted plaintext ─────────────────────────────


def test_over_long_password_does_not_echo_the_plaintext(auth_client: TestClient) -> None:
    """A value past the Field bound 422s — with the plaintext scrubbed.

    FastAPI's default validation handler serialises the rejected ``input``, so
    an over-long new password used to come straight back in the response body
    and into every reverse-proxy body-capture log downstream.
    """
    _login(auth_client)
    secret = "S3CRET-PLAINTEXT-" + ("x" * 2000)

    resp = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": ADMIN_PW, "new_password": secret},
        headers=ORIGIN,
    )
    assert resp.status_code == 422
    assert "S3CRET-PLAINTEXT" not in resp.text
    assert secret[:40] not in resp.text
    assert "input" not in resp.json()["detail"][0]


def test_over_long_login_password_does_not_echo_either(auth_client: TestClient) -> None:
    """The scrub is app-wide: the PRE-AUTH login field leaked the same way."""
    resp = auth_client.post(
        "/api/v1/login",
        json={"username": "admin", "password": "L0GIN-PLAINTEXT-" + ("y" * 2000)},
    )
    assert resp.status_code == 422
    assert "L0GIN-PLAINTEXT" not in resp.text


def test_long_but_bcrypt_rejectable_password_keeps_the_house_error(
    auth_client: TestClient,
) -> None:
    """Inside the Field bound, over bcrypt's 72 bytes → the clean 400, not a 422."""
    _login(auth_client)
    resp = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": ADMIN_PW, "new_password": "z" * 200},
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "password_too_long"
    assert "z" * 40 not in resp.text


def test_short_new_password_rejected_at_the_shared_minimum(
    auth_client: TestClient, auth_settings: Settings
) -> None:
    """Same floor the admin create-user path enforces — one constant, not two."""
    _login(auth_client)
    before = _password_hash(auth_settings, "admin")
    too_short = "x" * (auth_svc.MIN_PASSWORD_LENGTH - 1)

    resp = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": ADMIN_PW, "new_password": too_short},
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "password_too_short"
    assert str(auth_svc.MIN_PASSWORD_LENGTH) in resp.json()["detail"]["hint"]
    assert _password_hash(auth_settings, "admin") == before

    # …and the boundary itself is accepted.
    ok = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": ADMIN_PW, "new_password": "y" * auth_svc.MIN_PASSWORD_LENGTH},
        headers=ORIGIN,
    )
    assert ok.status_code == 200, ok.text


def test_create_user_shares_the_same_minimum(auth_client: TestClient) -> None:
    """The admin create-user path reads the same constant (no second rule)."""
    _login(auth_client)
    resp = auth_client.post(
        "/api/v1/config/users",
        json={
            "username": "shorty",
            "password": "x" * (auth_svc.MIN_PASSWORD_LENGTH - 1),
            "role": "analyst",
        },
        headers=ORIGIN,
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "password_too_short"


def test_anonymous_caller_is_rejected(auth_client: TestClient) -> None:
    resp = auth_client.post(
        "/api/v1/me/password",
        json={"current_password": ADMIN_PW, "new_password": NEW_PW},
        headers=ORIGIN,
    )
    assert resp.status_code == 401


# ── bootstrap-credential sidecar ──────────────────────────────────────────────


def test_bootstrap_sidecar_deleted_on_successful_change(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """No BOOTSTRAP_ADMIN_PASSWORD → startup invents one and writes the sidecar.

    The admin's first successful self-service change is what retires that file.
    """
    settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "soc_ai_data_dir": tmp_path / "data"}
    )
    cred = bootstrap_credential_path(settings)
    for client in _client(settings):
        assert cred.exists(), "startup should have written the bootstrap sidecar"
        generated = cred.read_text().strip()

        # A failed attempt must NOT retire the file.
        _login(client, "admin", generated)
        bad = client.post(
            "/api/v1/me/password",
            json={"current_password": "wrong", "new_password": NEW_PW},
            headers=ORIGIN,
        )
        assert bad.status_code == 400
        assert cred.exists(), "a rejected change must leave the sidecar in place"

        ok = client.post(
            "/api/v1/me/password",
            json={"current_password": generated, "new_password": NEW_PW},
            headers=ORIGIN,
        )
        assert ok.status_code == 200, ok.text
        assert not cred.exists()

        # Changing again with the file already gone is harmless.
        again = client.post(
            "/api/v1/me/password",
            json={"current_password": NEW_PW, "new_password": "third-password-ok"},
            headers=ORIGIN,
        )
        assert again.status_code == 200, again.text


def test_admin_reset_of_the_bootstrap_admin_also_retires_the_sidecar(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """The admin reset path invalidates the file's contents too — so delete it."""
    settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "soc_ai_data_dir": tmp_path / "data"}
    )
    cred = bootstrap_credential_path(settings)
    for client in _client(settings):
        assert cred.exists()
        generated = cred.read_text().strip()
        _login(client, "admin", generated)
        admin_id = _user_id(settings, "admin")

        resp = client.post(f"/api/v1/config/users/{admin_id}/reset-password", headers=ORIGIN)
        assert resp.status_code == 200, resp.text
        assert not cred.exists()


def test_admin_reset_of_another_user_leaves_the_sidecar(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "soc_ai_data_dir": tmp_path / "data"}
    )
    cred = bootstrap_credential_path(settings)
    for client in _client(settings):
        generated = cred.read_text().strip()
        _login(client, "admin", generated)
        _make_analyst(settings, "jordan", "analyst-pw-1")

        resp = client.post(
            f"/api/v1/config/users/{_user_id(settings, 'jordan')}/reset-password",
            headers=ORIGIN,
        )
        assert resp.status_code == 200, resp.text
        assert cred.exists()


def test_non_bootstrap_user_change_leaves_the_sidecar(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """Only the bootstrap admin's own change retires the file."""
    settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "soc_ai_data_dir": tmp_path / "data"}
    )
    cred = bootstrap_credential_path(settings)
    for client in _client(settings):
        assert cred.exists()
        _make_analyst(settings, "jordan", "analyst-pw-1")
        _login(client, "jordan", "analyst-pw-1")
        ok = client.post(
            "/api/v1/me/password",
            json={"current_password": "analyst-pw-1", "new_password": "analyst-pw-2"},
            headers=ORIGIN,
        )
        assert ok.status_code == 200, ok.text
        assert cred.exists()
