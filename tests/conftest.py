"""Shared pytest fixtures for soc-ai tests.

The ``clean_env`` autouse fixture strips soc-ai-related env vars before each
test so leakage from the host shell or CI runner can't bleed into config-loading
tests. Tests that need specific env values use ``monkeypatch.setenv`` themselves
or construct :class:`Settings` directly.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from soc_ai.config import Settings, get_settings

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_PREFIXES = (
    "SO_",
    "ES_",
    "LITELLM_",
    "AUDIT_",
    "QDRANT_",
    "MISP_",
    "INTERNAL_",
    "ORACLE_",
    "SOC_AI_",
    "HEAVY_",
    "FAST_",
    "EMBED_",
    "LOG_",
    "API_AUTH_REQUIRED",
    "SESSION_TTL_HOURS",
    "BOOTSTRAP_ADMIN_PASSWORD",
    "WEBUI_",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Strip soc-ai env vars and isolate tests from any .env in the project root."""
    for key in list(os.environ):
        if key.startswith(_PREFIXES):
            monkeypatch.delenv(key, raising=False)
    # pydantic-settings reads `.env` from cwd; chdir to a clean tmp dir so the
    # repo's runtime .env doesn't bleed into tests.
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    # Reset the in-process login throttles so failed-login tests don't leak
    # lockout state into later tests (the per-IP spray throttle aggregates all
    # failures from the shared "testclient" IP).
    from soc_ai.store import auth as _auth

    _auth.login_throttle.reset()
    _auth.login_ip_throttle.reset()
    yield
    get_settings.cache_clear()


@pytest.fixture
def fixture_loader() -> Callable[[str], dict[str, Any]]:
    """Returns a function that loads a JSON fixture by stem name."""

    def _load(name: str) -> dict[str, Any]:
        path = FIXTURES_DIR / f"{name}.json"
        with path.open() as f:
            return json.load(f)  # type: ignore[no-any-return]

    return _load


@pytest.fixture
def sample_alert(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("sample_alert")


@pytest.fixture
def sample_case(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("sample_case")


@pytest.fixture
def sample_detection(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("sample_detection")


@pytest.fixture
def sample_playbook(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("sample_playbook")


@pytest.fixture
def kratos_init(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("kratos_login_init")


@pytest.fixture
def kratos_success(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("kratos_login_success")


@pytest.fixture
def oauth_token(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("oauth_token")


def _base_settings_kwargs() -> dict[str, Any]:
    """Common kwargs for constructing Settings without env loading.

    Test default keeps ``synth_first_pipeline=False`` so legacy
    ``investigate()`` tests continue to exercise the two-stage path
    without per-test opt-out. The production default (set in
    ``soc_ai.config.Settings``) is ``True`` once the evidence-aware
    validators cleared cross-validation. Synth-first integration tests
    opt in explicitly with ``settings_kratos.synth_first_pipeline = True``.
    """
    return {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "synth_first_pipeline": False,
        # Tests opt into dev-open mode explicitly; the production default
        # (soc_ai.config.Settings) is True (secure-by-default).
        "api_auth_required": False,
    }


@pytest.fixture
def settings_kratos() -> Settings:
    """Settings configured for Kratos session-cookie auth (no Connect API)."""
    return Settings(**_base_settings_kwargs())


@pytest.fixture
def settings_connect() -> Settings:
    """Settings with Connect API client credentials configured (Pro path)."""
    kwargs = _base_settings_kwargs()
    kwargs.update(
        so_client_id="client-abc",
        so_client_secret=SecretStr("client-secret-xyz"),
    )
    return Settings(**kwargs)


@pytest.fixture
def settings_with_misp() -> Settings:
    """Settings with MISP enrichment configured."""
    kwargs = _base_settings_kwargs()
    kwargs.update(
        misp_url="https://misp.example.com",
        misp_api_key=SecretStr("misp-api-key-xyz"),
    )
    return Settings(**kwargs)
