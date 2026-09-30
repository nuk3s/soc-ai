"""GET /config/tls reads the files on disk and says whether a restart is due."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app

from tests.test_tls_status import _cert, _key, _write
from tests.test_webui_api import _client

TLS_ROUTE = "/api/v1/config/tls"


def _settings_with_cert(tmp_path: Path, base: Settings, days: int = 90) -> Settings:
    key = _key()
    cert = _cert(
        subject="soc-ai.example.test",
        issuer_name="soc-ai.example.test",
        issuer_key=key,
        key=key,
        days=days,
        sans=("soc-ai.example.test",),
    )
    cert_path, key_path = _write(tmp_path, [cert], key)
    return base.model_copy(update={"soc_ai_tls_cert": cert_path, "soc_ai_tls_key": key_path})


def test_tls_route_reports_the_certificate_and_no_restart_when_unchanged(
    tmp_path: Path, settings_kratos: Settings
) -> None:
    s = _settings_with_cert(tmp_path, settings_kratos)
    for c in _client(s):
        body = c.get(TLS_ROUTE).json()
        assert body["mode"] == "direct"
        assert body["subject"] == "CN=soc-ai.example.test"
        assert body["self_signed"] is True
        assert body["restart_required"] is False
        assert body["loaded_at"]


def test_tls_route_says_restart_required_after_the_files_change(
    tmp_path: Path, settings_kratos: Settings
) -> None:
    s = _settings_with_cert(tmp_path, settings_kratos)
    for c in _client(s):
        assert c.get(TLS_ROUTE).json()["restart_required"] is False
        key = _key()
        cert = _cert(
            subject="renewed.example.test",
            issuer_name="renewed.example.test",
            issuer_key=key,
            key=key,
            days=365,
        )
        _write(tmp_path, [cert], key)
        body = c.get(TLS_ROUTE).json()
        assert body["subject"] == "CN=renewed.example.test"
        assert body["restart_required"] is True


def test_tls_route_reports_errors_as_sentences_for_a_missing_file(
    tmp_path: Path, settings_kratos: Settings
) -> None:
    missing = settings_kratos.model_copy(
        update={
            "soc_ai_tls_cert": tmp_path / "none.pem",
            "soc_ai_tls_key": tmp_path / "none-key.pem",
        }
    )
    for c in _client(missing):
        body = c.get(TLS_ROUTE).json()
        assert body["mode"] == "direct"
        assert body["restart_required"] is False
        assert body["errors"]
        for line in body["errors"]:
            assert line[0].isupper() and line.endswith("."), line


def test_a_surprise_in_the_inspector_does_not_stop_the_start(
    tmp_path: Path, settings_kratos: Settings
) -> None:
    s = _settings_with_cert(tmp_path, settings_kratos)
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=s),
        patch("soc_ai.tls_status.inspect_tls", side_effect=RuntimeError("the inspector fell over")),
    ):
        app = create_app()
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200
            status = app.state.tls_at_start
            assert status.mode == "direct"
            assert status.errors == ["Cannot inspect the certificate: the inspector fell over."]


def test_tls_route_reads_off_when_tls_is_off(settings_kratos: Settings) -> None:
    off = settings_kratos.model_copy(update={"soc_ai_tls_cert": None, "soc_ai_tls_key": None})
    for c in _client(off):
        body = c.get(TLS_ROUTE).json()
        assert body["mode"] == "off"
        assert body["restart_required"] is False


def test_tls_route_is_admin_only(analyst: TestClient) -> None:
    resp = analyst.get(TLS_ROUTE)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "admin_required"
