"""About endpoint + opt-in GitHub update check.

The update check is an OUTBOUND call, so it must be off by default, fail closed,
never raise, and never leak. These tests pin that contract:

- disabled (the default) makes NO network call at all;
- demo mode makes no live call either;
- a reachable GitHub reports the latest release and whether it is newer;
- an unreachable GitHub degrades to a clean, secret-free result, never a raise;
- the running version is compared LOCALLY (semver-aware, tolerant of a ``v`` tag).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from soc_ai import __version__
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import config_overrides as cfg
from soc_ai.webui import updates

from tests.conftest import _base_settings_kwargs


# --------------------------------------------------------------------------- #
# Fakes: a mock GitHub releases endpoint, and a tripwire client that fails the
# test if the code reaches for the network when it must not.
# --------------------------------------------------------------------------- #
def _mock_release_client(payload: dict[str, Any], status: int = 200) -> httpx.AsyncClient:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class _NetworkReached(BaseException):
    """Raised if the code reaches for the network when it must not. Deliberately a
    BaseException so check_for_update's broad ``except Exception`` cannot swallow it
    and let a real egress breach masquerade as a clean error-fallback result."""


def _tripwire_client(_settings: Any) -> httpx.AsyncClient:
    raise _NetworkReached("check_for_update must not touch the network here")


def _settings(**over: Any) -> Settings:
    base = _base_settings_kwargs()
    base.update(over)
    return Settings(**base)


# --------------------------------------------------------------------------- #
# check_for_update — the core logic (unit-tested directly, like probes.py)
# --------------------------------------------------------------------------- #
async def test_disabled_makes_no_network_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates, "online_client", _tripwire_client)
    result = await updates.check_for_update(_settings(update_check_enabled=False))
    assert result["enabled"] is False
    assert result["current_version"] == __version__
    assert result["update_available"] is False


async def test_demo_mode_makes_no_live_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(updates, "online_client", _tripwire_client)
    result = await updates.check_for_update(_settings(update_check_enabled=True, soc_ai_demo=True))
    # Enabled but demo → the demo branch's clean answer, NOT the swallowed-error
    # fallback (which would be ok=False with no latest_version). Assert the fields
    # only the demo branch produces so this actually pins "no live call".
    assert result["enabled"] is True
    assert result["ok"] is True
    assert result["latest_version"] == __version__
    assert result["update_available"] is False
    assert "demo" in result["detail"].lower()


async def test_enabled_newer_release_reports_update_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        updates, "online_client", lambda _s: _mock_release_client({"tag_name": "v999.0.0"})
    )
    result = await updates.check_for_update(_settings(update_check_enabled=True))
    assert result["enabled"] is True
    assert result["ok"] is True
    assert result["current_version"] == __version__
    assert result["latest_version"] == "999.0.0"
    assert result["update_available"] is True


async def test_enabled_same_version_is_up_to_date(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        updates,
        "online_client",
        lambda _s: _mock_release_client({"tag_name": f"v{__version__}"}),
    )
    result = await updates.check_for_update(_settings(update_check_enabled=True))
    assert result["ok"] is True
    assert result["update_available"] is False


async def test_semver_compare_is_numeric_not_lexical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A lexical compare would call 1.9.0 newer than 1.10.0; semver must not.
    monkeypatch.setattr(
        updates, "online_client", lambda _s: _mock_release_client({"tag_name": "v1.9.0"})
    )
    with patch.object(updates, "__version__", "1.10.0"):
        result = await updates.check_for_update(_settings(update_check_enabled=True))
    assert result["update_available"] is False


async def test_network_error_degrades_cleanly_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(_s: Any) -> httpx.AsyncClient:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused to secret-host:443")

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(updates, "online_client", _boom)
    result = await updates.check_for_update(_settings(update_check_enabled=True))
    assert result["enabled"] is True
    assert result["ok"] is False
    assert result["update_available"] is False
    # The failure detail must not echo the raw exception text (host/URL).
    assert "secret-host" not in result["detail"]


async def test_http_error_degrades_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-200 makes raise_for_status() throw → the generic error path (not the
    # tag-parsing path exercised below).
    monkeypatch.setattr(
        updates, "online_client", lambda _s: _mock_release_client({"message": "Not Found"}, 404)
    )
    result = await updates.check_for_update(_settings(update_check_enabled=True))
    assert result["ok"] is False
    assert result["update_available"] is False


async def test_empty_or_null_tag_reports_no_release(monkeypatch: pytest.MonkeyPatch) -> None:
    # A 200 whose body carries no usable tag_name — GitHub does this for a repo
    # with no releases. Exercises the `if not latest:` branch specifically.
    for payload in ({}, {"tag_name": None}, {"tag_name": ""}):
        monkeypatch.setattr(updates, "online_client", lambda _s, p=payload: _mock_release_client(p))
        result = await updates.check_for_update(_settings(update_check_enabled=True))
        assert result["ok"] is False
        assert result["update_available"] is False
        assert result["detail"] == "GitHub returned no release tag"


async def test_unrecognized_tag_is_inconclusive_not_up_to_date(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A non-semver tag can't be compared: report it inconclusive (ok=False), never
    # a false "up to date" that skipped the comparison entirely.
    monkeypatch.setattr(
        updates, "online_client", lambda _s: _mock_release_client({"tag_name": "nightly"})
    )
    result = await updates.check_for_update(_settings(update_check_enabled=True))
    assert result["ok"] is False
    assert result["update_available"] is False
    assert "nightly" in result["detail"]
    assert "up to date" not in result["detail"]


# --------------------------------------------------------------------------- #
# Config registration: the toggle is a live (hot) admin setting, off by default.
# --------------------------------------------------------------------------- #
def test_update_check_enabled_default_off() -> None:
    assert _settings().update_check_enabled is False


def test_update_check_enabled_is_a_hot_egress_setting() -> None:
    spec = cfg.WHITELIST_BY_KEY["update_check_enabled"]
    assert spec.type == "bool"
    assert spec.hot is True
    assert spec.danger is False
    assert spec.secret is False
    # It lives under the egress-facing parent so a privacy-minded admin finds it.
    assert cfg.SECTION_PARENTS[spec.section] == "Privacy & Egress"


# --------------------------------------------------------------------------- #
# Routes: GET /api/v1/about (any authed user) and POST /api/v1/updates/check.
# --------------------------------------------------------------------------- #
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


def test_about_endpoint_exposes_version_repo_license() -> None:
    for c in _client(_settings()):
        body = c.get("/api/v1/about").json()
        assert body["version"] == __version__
        assert "github.com/nuk3s/soc-ai" in body["repo_url"]
        assert body["license"] == "Apache-2.0"
        assert body["update_check_enabled"] is False


def test_about_reflects_update_check_toggle() -> None:
    for c in _client(_settings(update_check_enabled=True)):
        assert c.get("/api/v1/about").json()["update_check_enabled"] is True


def test_updates_check_route_disabled_makes_no_call() -> None:
    for c in _client(_settings(update_check_enabled=False)):
        body = c.post("/api/v1/updates/check").json()
        assert body["enabled"] is False
        assert body["update_available"] is False


def test_updates_check_route_reports_latest_when_enabled() -> None:
    with patch.object(
        updates, "online_client", lambda _s: _mock_release_client({"tag_name": "v999.0.0"})
    ):
        for c in _client(_settings(update_check_enabled=True)):
            body = c.post("/api/v1/updates/check").json()
            assert body["enabled"] is True
            assert body["ok"] is True
            assert body["latest_version"] == "999.0.0"
            assert body["update_available"] is True
