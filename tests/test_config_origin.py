"""Setting origin, "Use the default" and the restart marker (dogfood 2026-10-19).

R5-D7: the source badge read ENV for a code default, so a value set in .env
and a default looked the same. R5-D8: the console could not return a setting
to its .env or default value. R5-D22: a restart setting showed no marker after
Apply.
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

ORIGIN = {"Origin": "http://testserver"}


def _client(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _item(client: TestClient, key: str) -> dict[str, Any]:
    groups = client.get("/api/v1/config").json()["groups"]
    for g in groups:
        for it in g["items"]:
            if it["key"] == key:
                return dict(it)
    raise AssertionError(f"no setting {key}")


def _overrides(client: TestClient) -> dict[str, Any]:
    async def _read() -> dict[str, Any]:
        async with client.app.state.db_sessionmaker() as db:
            return await cfg.load_overrides(db)

    return asyncio.run(_read())


def test_three_origins(client: TestClient) -> None:
    # The fixture passes investigator_emits_report explicitly: that is the
    # .env origin. host_risk_window_hours is not passed: a code default.
    env = _item(client, "investigator_emits_report")
    assert env["source"] == "env"
    default = _item(client, "host_risk_window_hours")
    assert default["source"] == "default"
    assert default["default"] == default["value"]

    r = client.post("/api/v1/config/setting", json={"key": "host_risk_window_hours", "value": "48"})
    assert r.status_code == 200, r.text
    db = _item(client, "host_risk_window_hours")
    assert db["source"] == "db"
    assert db["value"] == 48
    # The value under the override, so the console can say what it overrides.
    assert db["base_value"] == default["value"]
    assert db["base_source"] == "default"


def test_use_the_default_removes_the_override_and_applies_it_live(client: TestClient) -> None:
    before = _item(client, "host_risk_window_hours")["value"]
    client.post("/api/v1/config/setting", json={"key": "host_risk_window_hours", "value": "48"})
    assert client.app.state.settings.host_risk_window_hours == 48

    r = client.delete("/api/v1/config/setting/host_risk_window_hours", headers=ORIGIN)
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "restart_required": False, "removed": True}
    assert "host_risk_window_hours" not in _overrides(client)
    # A hot setting takes the default at once.
    assert client.app.state.settings.host_risk_window_hours == before
    after = _item(client, "host_risk_window_hours")
    assert after["source"] == "default"
    assert after["value"] == before


def test_use_the_env_value_restores_the_env_value(client: TestClient) -> None:
    env_value = client.app.state.settings.investigator_emits_report
    client.post(
        "/api/v1/config/setting",
        json={"key": "investigator_emits_report", "value": str(not env_value).lower()},
    )
    assert client.app.state.settings.investigator_emits_report is (not env_value)
    r = client.delete("/api/v1/config/setting/investigator_emits_report", headers=ORIGIN)
    assert r.status_code == 200, r.text
    assert client.app.state.settings.investigator_emits_report is env_value
    assert _item(client, "investigator_emits_report")["source"] == "env"


def test_use_the_default_with_no_override_is_a_no_op(client: TestClient) -> None:
    r = client.delete("/api/v1/config/setting/host_risk_window_hours", headers=ORIGIN)
    assert r.status_code == 200
    assert r.json() == {"ok": True, "restart_required": False, "removed": False}


@pytest.mark.parametrize(
    ("key", "reason"),
    [
        ("no_such_key", "unknown_setting"),
        ("so_host", "danger_zone"),
        ("shodan_api_key", "secret_setting"),
    ],
)
def test_use_the_default_refuses_keys_outside_the_settings_list(
    client: TestClient, key: str, reason: str
) -> None:
    r = client.delete(f"/api/v1/config/setting/{key}", headers=ORIGIN)
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == reason


def test_a_restart_setting_reports_that_it_waits_for_a_restart(client: TestClient) -> None:
    item = _item(client, "so_login_flow")
    assert item["pending_restart"] is False
    other = next(o for o in item["options"] if o != item["value"])
    r = client.post("/api/v1/config/setting", json={"key": "so_login_flow", "value": other})
    assert r.status_code == 200, r.text
    assert r.json()["restart_required"] is True
    saved = _item(client, "so_login_flow")
    assert saved["value"] == other
    assert saved["pending_restart"] is True

    # Back to the default: the live value never changed, so nothing waits.
    r = client.delete("/api/v1/config/setting/so_login_flow", headers=ORIGIN)
    assert r.json()["restart_required"] is False
    assert _item(client, "so_login_flow")["pending_restart"] is False


# ── Connections (the old Danger Zone), dogfood 2026-10-19 H1-D15 / H1-I2 ──────


def _danger_row(client: TestClient, key: str) -> dict[str, Any]:
    rows = client.get("/api/v1/config/danger").json()
    return dict(next(r for r in rows if r["key"] == key))


def test_connection_rows_show_the_value_of_a_non_secret_setting(client: TestClient) -> None:
    host = _danger_row(client, "so_host")
    assert host["value"] == str(client.app.state.settings.so_host)
    assert host["required"] is True
    hosts = _danger_row(client, "es_hosts")
    assert hosts["value"].rstrip("/") == "https://so.example.com:9200"


def test_connection_rows_never_carry_a_secret(client: TestClient) -> None:
    for key in ("so_password", "es_password", "litellm_api_key"):
        row = _danger_row(client, key)
        assert row["type"] == "secret"
        assert "value" not in row
    assert _danger_row(client, "so_password")["required"] is True
    # An unset optional secret is no fault: the console shows it in a neutral tone.
    assert _danger_row(client, "es_password")["required"] is False


def test_test_connection_probes_the_edited_value(client: TestClient) -> None:
    """Test ran on the saved value only. A fix needed a save, a restart and a
    test, and a wrong value cost a second restart."""
    seen: list[str] = []

    async def _probe(settings: Any) -> dict[str, Any]:
        seen.append(str(settings.litellm_base_url))
        return {"ok": True, "detail": "3 models"}

    with patch("soc_ai.api.webui.routes_config.probes.probe_llm", _probe):
        r = client.post(
            "/api/v1/config/danger/test/llm",
            json={"key": "litellm_base_url", "value": "http://gw.example.test:4000"},
            headers=ORIGIN,
        )
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is True
        plain = client.post("/api/v1/config/danger/test/llm", headers=ORIGIN)
        assert plain.status_code == 200, plain.text
    assert seen[0].startswith("http://gw.example.test:4000")
    assert seen[1].startswith("http://localhost:4000")
    # The trial value never reaches the live settings.
    assert str(client.app.state.settings.litellm_base_url).startswith("http://localhost:4000")


def test_test_connection_refuses_a_key_of_another_target(client: TestClient) -> None:
    r = client.post(
        "/api/v1/config/danger/test/llm",
        json={"key": "es_hosts", "value": "https://es.example.test:9200"},
        headers=ORIGIN,
    )
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "key_not_for_target"


def test_test_connection_reports_an_invalid_value(client: TestClient) -> None:
    r = client.post(
        "/api/v1/config/danger/test/llm",
        json={"key": "litellm_base_url", "value": "ftp://gw.example.test"},
        headers=ORIGIN,
    )
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is False
    assert "http" in r.json()["detail"]
