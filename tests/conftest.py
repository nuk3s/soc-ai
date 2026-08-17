"""Shared pytest fixtures for soc-ai tests.

The ``clean_env`` autouse fixture strips soc-ai-related env vars before each
test so leakage from the host shell or CI runner can't bleed into config-loading
tests. Tests that need specific env values use ``monkeypatch.setenv`` themselves
or construct :class:`Settings` directly.

:class:`Settings` has no ``env_prefix``, so every field is readable from a
bare, case-insensitive env var — ``GENERAL_CHAT_ENABLED=false`` in a dev shell
silently flips a default under every test that constructs ``Settings()``, and
the failure surfaces as an unrelated assertion in an unrelated file. The scrub
set is therefore *derived* from ``Settings.model_fields`` rather than
hand-listed: a knob added to config.py is isolated the moment it is declared,
with nothing here to keep in step.
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

# Family sweeps, for env vars that are NOT :class:`Settings` fields but still
# steer soc-ai: ``SOC_AI_API_TOKEN`` (cli.py reads it straight from os.environ),
# and whatever else an operator's .env carries in one of these families. Exact
# field names are covered by ``_SETTINGS_ENV_NAMES`` below, so this tuple no
# longer has to track config.py. tests/test_config.py imports it.
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
    "MEMORY_",
    "EMBED_",
    "LOG_",
    "DOSSIER_",
    "API_AUTH_REQUIRED",
    "SESSION_TTL_HOURS",
    "BOOTSTRAP_ADMIN_PASSWORD",
    "WEBUI_",
)


def _settings_env_names() -> frozenset[str]:
    """Every env var name pydantic-settings would read into :class:`Settings`.

    Field names and their validation aliases (``ANALYST_MODEL`` / ``HEAVY_MODEL``),
    upper-cased for comparison because ``case_sensitive=False`` means the shell
    can spell them either way. No soc-ai field is a single bare word, so this
    never collides with PATH/HOME-style host variables.
    """
    names: set[str] = set()
    for name, field in Settings.model_fields.items():
        names.add(name.upper())
        alias = field.validation_alias
        if isinstance(alias, str):
            names.add(alias.upper())
        else:
            names.update(c.upper() for c in getattr(alias, "choices", ()) if isinstance(c, str))
    return frozenset(names)


_SETTINGS_ENV_NAMES = _settings_env_names()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Strip soc-ai env vars and isolate tests from any .env in the project root."""
    for key in list(os.environ):
        upper = key.upper()  # Settings reads env case-insensitively; so do we.
        if upper.startswith(_PREFIXES) or upper in _SETTINGS_ENV_NAMES:
            monkeypatch.delenv(key, raising=False)
    # pydantic-settings reads `.env` from cwd; chdir to a clean tmp dir so the
    # repo's runtime .env doesn't bleed into tests.
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    # Reset the in-process credential throttles so failed-attempt tests don't
    # leak lockout state into later tests (the per-IP spray throttle aggregates
    # all failures from the shared "testclient" IP).
    from soc_ai.store import auth as _auth

    _auth.login_throttle.reset()
    _auth.login_ip_throttle.reset()
    _auth.password_change_throttle.reset()
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
def oauth_token(fixture_loader: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    return fixture_loader("oauth_token")


def _base_settings_kwargs() -> dict[str, Any]:
    """Common kwargs for constructing Settings without env loading."""
    return {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
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
