"""Fixtures for the 2026-08-25 adversarial security audit suite.

The repo's hermetic harnesses boot with ``api_auth_required=False``; an auth
audit needs the opposite. This plugin boots the real ``create_app()`` with auth
genuinely ON, seeds two users of different roles through the app's own
user-creation path (real bcrypt hashing), and logs each one in through the real
``POST /api/v1/login`` route — session cookies are never fabricated. The grid
is the packaged mock-ES fixture responder, so the whole surface (including the
sigma-authoring bridge and the analyst-cloud redaction guard) is reachable with
no lab dependency.

Registered from ``tests/conftest.py`` by explicit fixture imports (pytest 9
rejects ``pytest_plugins`` in a non-rootdir conftest, and this repo has no
rootdir conftest).
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from scripts.demo.mock_es import DETECTION_FIXTURE_DOCS, _search_response_from_docs
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import auth as auth_svc

# Seeded audit identities. The passwords are harness-local test credentials —
# they exist only inside a scratch tmp_path SQLite file, hashed with bcrypt.
ANALYST_CREDS = ("audit-analyst", "audit-analyst-pw-9f2c")
ADMIN_CREDS = ("audit-admin", "audit-admin-pw-4b7e")

_HOSTILE_IDS = itertools.count(1)


@pytest.fixture
def audit_settings(tmp_path: Path) -> Settings:
    """Auth ON, full surface enabled, scratch data dir, unreachable backends.

    ``.invalid`` hosts (RFC 2606) guarantee any code path that slips past the
    mock and tries a real network call fails fast instead of touching the lab.
    """
    return Settings(
        so_host="https://so.invalid",
        so_username="analyst",
        so_password=SecretStr("audit-harness-so-pw"),
        so_verify_ssl=False,
        es_hosts=["https://es.invalid:9200"],
        litellm_base_url="http://litellm.invalid:4000",
        api_auth_required=True,
        soc_ai_data_dir=tmp_path / "audit-data",
        analyst_cloud_redaction=True,
        sigma_authoring_enabled=True,
        soc_ai_demo=False,
    )


def _mock_grid_search(**kwargs: Any) -> dict[str, Any]:
    """Route an ElasticClient search to the mock ES fixture-response builder."""
    return _search_response_from_docs(kwargs.get("body") or {}, DETECTION_FIXTURE_DOCS)


@pytest.fixture
def audit_client(audit_settings: Settings) -> Iterator[TestClient]:
    """A real ``create_app()`` under ``audit_settings``, grid = mock fixture."""
    fake_es = AsyncMock()
    fake_es.search = AsyncMock(side_effect=_mock_grid_search)
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=audit_settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            _seed_audit_users(client)
            yield client


def _seed_audit_users(client: TestClient) -> None:
    """Create the two audit users through the app's own user-creation path.

    Real bcrypt hashing via ``auth_svc.create_user`` against the app's own
    sessionmaker (the same code the admin create-user route calls). Startup's
    bootstrap also created an ``admin`` user with a random password; the audit
    identities use distinct usernames so the two never collide.
    """

    async def _go() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            await auth_svc.create_user(db, ANALYST_CREDS[0], ANALYST_CREDS[1], role="analyst")
            await auth_svc.create_user(db, ADMIN_CREDS[0], ADMIN_CREDS[1], role="admin")

    asyncio.run(_go())


def _login_session(client: TestClient, username: str, password: str) -> dict[str, str]:
    """Log in through the REAL login route and return the session cookie dict.

    The cookie is then cleared from the client's jar so the shared
    ``audit_client`` stays anonymous — tests attach a role per request via
    ``cookies=...``, and an un-cookied request genuinely has no session.
    """
    resp = client.post("/api/v1/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"harness login failed for {username!r}: {resp.text}"
    raw = resp.cookies.get(auth_svc.SESSION_COOKIE)
    assert raw, "login response did not set the session cookie"
    client.cookies.clear()
    return {auth_svc.SESSION_COOKIE: raw}


@pytest.fixture
def analyst_session(audit_client: TestClient) -> dict[str, str]:
    """Session cookie dict for a real, logged-in ``analyst``-role user."""
    return _login_session(audit_client, *ANALYST_CREDS)


@pytest.fixture
def admin_session(audit_client: TestClient) -> dict[str, str]:
    """Session cookie dict for a real, logged-in ``admin``-role user."""
    return _login_session(audit_client, *ADMIN_CREDS)


@pytest.fixture
def hostile_doc() -> Callable[..., dict[str, Any]]:
    """Factory for an ES document carrying attacker-controlled text.

    ``hostile_doc(field, payload, *, dataset="suricata.alert")`` returns a doc
    shaped like ``DETECTION_FIXTURE_DOCS`` entries (``_index``/``_id``/
    ``_source``) with ``payload`` placed at the dotted ``field`` path inside
    ``_source``. Addressing stays in RFC 5737 space; only ``payload`` is
    attacker-chosen.
    """

    def _build(field: str, payload: str, *, dataset: str = "suricata.alert") -> dict[str, Any]:
        seq = next(_HOSTILE_IDS)
        source: dict[str, Any] = {
            "@timestamp": "2026-08-25T09:00:00.000Z",
            "event": {"dataset": dataset},
            "source": {"ip": "203.0.113.66", "port": 40000 + seq},
            "destination": {"ip": "192.0.2.10", "port": 443},
            "host": {"name": "victim.example.test"},
        }
        node = source
        parts = field.split(".")
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        node[parts[-1]] = payload
        return {"_index": "logs-hostile", "_id": f"hostile-{seq:06d}", "_source": source}

    return _build
