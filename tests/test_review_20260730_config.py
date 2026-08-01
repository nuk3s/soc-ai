"""Regression tests for the 2026-07-30 config-console review (bucket B04_config).

Covers:
  F25 — a rejected hot-apply must NOT delete the operator's previously-saved
        override (POST /config/setting and POST /config/danger/setting).
  F26 — a csv URL setting (es_hosts) must enforce the http(s) scheme, so a bare
        host:port is rejected at save time instead of stored-then-dropped.
  F29 — misp_api_key is restart-required (hot=False), and its help surfaces the
        restart warning via GET /config/api-keys.
  F45 — GET /config renders the STAGED override for a hot=False setting, not the
        pre-restart live value, so a just-saved value doesn't appear to vanish.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import config_overrides as cfg


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


def _config_item(client: TestClient, key: str) -> dict[str, Any]:
    body = client.get("/api/v1/config").json()
    items = {i["key"]: i for g in body["groups"] for i in g["items"]}
    return items[key]


def _load_overrides(client: TestClient) -> dict[str, Any]:
    async def _read() -> dict[str, Any]:
        async with client.app.state.db_sessionmaker() as db:
            return await cfg.load_overrides(db)

    return asyncio.run(_read())


# ---------------------------------------------------------------------------
# F26 — es_hosts (csv URL) http(s)-scheme enforcement
# ---------------------------------------------------------------------------


def test_coerce_es_hosts_rejects_bare_host_port() -> None:
    """F26: coerce() must enforce the http(s) scheme on the csv-typed es_hosts —
    a bare host:port (the classic ES spelling) is rejected up front, not stored
    then silently dropped by AnyHttpUrl at every restart."""
    with pytest.raises(ValueError):
        cfg.coerce("es_hosts", "es1:9200,es2:9200")
    with pytest.raises(ValueError):
        cfg.coerce("es_hosts", "https://es1:9200, es2:9200")  # one good, one bad
    # A well-formed csv of URLs still coerces to the trimmed list.
    assert cfg.coerce("es_hosts", "https://es1:9200, https://es2:9200") == [
        "https://es1:9200",
        "https://es2:9200",
    ]
    assert cfg.coerce("es_hosts", "") == []  # unset is fine


def test_validate_typed_es_hosts_rejects_bare_host_port() -> None:
    """F26: the persist/apply path (_validate_typed) enforces the same scheme check
    inside the csv branch, so a poisoned list can't slip through set_override."""
    spec = cfg.WHITELIST_BY_KEY["es_hosts"]
    with pytest.raises(ValueError):
        cfg._validate_typed(spec, ["es1:9200"])
    assert cfg._validate_typed(spec, ["https://es1:9200"]) == ["https://es1:9200"]


# ---------------------------------------------------------------------------
# F29 — misp_api_key is restart-required, and the help says so
# ---------------------------------------------------------------------------


def test_misp_api_key_is_restart_required_not_hot() -> None:
    """F29: misp_api_key is baked into the MispClient built at startup, so it is
    hot=False (like misp_url) and its help states restart is required — but it
    still lives in the API-keys panel."""
    spec = cfg.WHITELIST_BY_KEY["misp_api_key"]
    assert spec.hot is False
    assert spec.secret is True
    assert "restart" in spec.help.lower()
    assert spec.key in {s.key for s in cfg.api_key_specs()}
    # The sibling per-call keys remain hot.
    assert cfg.WHITELIST_BY_KEY["shodan_api_key"].hot is True
    assert cfg.WHITELIST_BY_KEY["crawl4ai_token"].hot is True


def test_api_keys_panel_surfaces_misp_restart_warning(client: TestClient) -> None:
    """F29: GET /config/api-keys carries the misp_api_key restart warning to the
    operator — the signal that was missing entirely before."""
    rows = {r["key"]: r for r in client.get("/api/v1/config/api-keys").json()}
    assert "misp_api_key" in rows
    assert "restart" in rows["misp_api_key"]["help"].lower()


# ---------------------------------------------------------------------------
# F25 — a rejected hot-apply must not destroy the prior saved override
# ---------------------------------------------------------------------------


def test_setting_reject_keeps_prior_override(client: TestClient) -> None:
    """F25 (POST /config/setting): save a valid value, then a value that coerce()
    accepts but the Settings field validator rejects. The bad save must 400 AND
    leave the previously-saved override intact — not delete it (which would
    revert to the env default on the next restart)."""
    ok = client.post(
        "/api/v1/config/setting",
        json={"key": "auto_triage_min_severity", "value": "medium"},
    )
    assert ok.status_code == 200
    assert client.app.state.settings.auto_triage_min_severity == "medium"
    assert _load_overrides(client).get("auto_triage_min_severity") == "medium"

    bad = client.post(
        "/api/v1/config/setting",
        json={"key": "auto_triage_min_severity", "value": "med"},  # fat-finger
    )
    assert bad.status_code == 400
    assert bad.json()["detail"]["reason"] == "invalid_value"

    # The prior override + live value survive the rejected save.
    assert _load_overrides(client).get("auto_triage_min_severity") == "medium"
    assert client.app.state.settings.auto_triage_min_severity == "medium"
    item = _config_item(client, "auto_triage_min_severity")
    assert item["source"] == "db"
    assert item["value"] == "medium"


def test_danger_setting_reject_keeps_prior_override(client: TestClient) -> None:
    """F25 (POST /config/danger/setting): the hot danger path has the same bug —
    a rejected internal_cidrs value must not delete the operator's prior CIDR
    override."""
    ok = client.post(
        "/api/v1/config/danger/setting",
        json={"key": "internal_cidrs", "value": "10.0.0.0/8", "confirm": "internal_cidrs"},
    )
    assert ok.status_code == 200
    assert ok.json() == {"ok": True, "restart_required": False}
    assert _load_overrides(client).get("internal_cidrs") == ["10.0.0.0/8"]
    assert [str(n) for n in client.app.state.settings.internal_cidrs] == ["10.0.0.0/8"]

    bad = client.post(
        "/api/v1/config/danger/setting",
        json={"key": "internal_cidrs", "value": "not-a-cidr", "confirm": "internal_cidrs"},
    )
    assert bad.status_code == 400
    assert bad.json()["detail"]["reason"] == "invalid_value"

    # The prior override + live value survive the rejected save.
    assert _load_overrides(client).get("internal_cidrs") == ["10.0.0.0/8"]
    assert [str(n) for n in client.app.state.settings.internal_cidrs] == ["10.0.0.0/8"]


# ---------------------------------------------------------------------------
# F45 — GET /config renders the staged override for a hot=False setting
# ---------------------------------------------------------------------------


def test_config_renders_staged_value_for_non_hot_override(client: TestClient) -> None:
    """F45: misp_url is hot=False — its DB override is not applied to live Settings
    until restart. GET /config must render the STAGED override value (matching the
    'db' badge), not the empty pre-restart live value that made a just-saved URL
    look like it vanished."""
    before = _config_item(client, "misp_url")
    assert before["source"] == "env"
    assert before["value"] == ""

    save = client.post(
        "/api/v1/config/setting",
        json={"key": "misp_url", "value": "https://misp.newhost.example"},
    )
    assert save.status_code == 200
    assert save.json() == {"ok": True, "restart_required": True}
    # hot=False → live attribute is unchanged until restart …
    assert client.app.state.settings.misp_url is None
    # … but GET /config now shows the staged value, consistent with source=db.
    after = _config_item(client, "misp_url")
    assert after["source"] == "db"
    assert after["value"] == "https://misp.newhost.example"
