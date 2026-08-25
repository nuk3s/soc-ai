"""Tests for the ``sigma_authoring_enabled`` config flag (Task 4 of the
detection-engineering bridge plan): default off, admin-editable, and surfaced
on ``/about`` so the SPA can hide the draft-detection affordance when the
flag is off. Mirrors the ``crawl4ai_enabled`` precedent
(``tests/test_config.py``'s crawl4ai/general_chat_enabled tests).
"""

from __future__ import annotations

import pytest
from soc_ai.config import Settings


def _setenv_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SO_HOST", "https://so.example.com")
    monkeypatch.setenv("SO_USERNAME", "analyst")
    monkeypatch.setenv("SO_PASSWORD", "password123")
    monkeypatch.setenv("ES_HOSTS", "https://so.example.com:9200")
    monkeypatch.setenv("LITELLM_BASE_URL", "http://localhost:4000")


def test_sigma_authoring_enabled_defaults_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """The detection-bridge feature ships dark until an admin opts in."""
    _setenv_required(monkeypatch)
    assert Settings().sigma_authoring_enabled is False


def test_sigma_authoring_enabled_is_whitelisted_hot_not_danger_or_secret() -> None:
    """Admin-editable in the config console, applies live, and — since it only
    gates a read+draft feature with no secret/connection material — is neither
    a Danger Zone nor a write-only secret setting."""
    from soc_ai.store.config_overrides import SECTION_ORDER, WHITELIST_BY_KEY

    spec = WHITELIST_BY_KEY["sigma_authoring_enabled"]
    assert spec.attr == "sigma_authoring_enabled"
    assert spec.type == "bool"
    assert spec.hot is True
    assert spec.danger is False
    assert spec.secret is False
    assert spec.section in SECTION_ORDER


def test_sigma_authoring_enabled_attr_exists_on_settings() -> None:
    """The whitelisted attr must map to a real Settings field (belt to the
    repo-wide test_whitelist_attrs_all_exist_on_settings in test_config.py)."""
    from soc_ai.store.config_overrides import WHITELIST_BY_KEY

    spec = WHITELIST_BY_KEY["sigma_authoring_enabled"]
    assert spec.attr in Settings.model_fields


async def test_about_reports_sigma_authoring_enabled(settings_kratos: Settings) -> None:
    """GET /api/v1/about carries the flag so the SPA can hide the
    draft-detection affordance when the feature is off (mirrors
    test_about_reports_general_chat_enabled in test_config.py)."""
    from soc_ai.api.webui.routes_meta import about

    settings_kratos.sigma_authoring_enabled = False
    assert (await about(settings=settings_kratos)).sigma_authoring_enabled is False

    settings_kratos.sigma_authoring_enabled = True
    assert (await about(settings=settings_kratos)).sigma_authoring_enabled is True
