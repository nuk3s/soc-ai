"""One document from the grid, by id, for the evidence chips."""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def test_a_document_comes_back_with_its_dataset_and_timestamp(client: TestClient) -> None:
    doc = {
        "@timestamp": "2026-09-18T10:00:00Z",
        "event": {"dataset": "system.security", "code": "4662"},
    }
    with patch("soc_ai.api.webui.routes_events.get_event_raw", AsyncMock(return_value=doc)):
        res = client.get("/api/v1/events/abc123")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["id"] == "abc123" and body["dataset"] == "system.security"
    assert body["timestamp"] == "2026-09-18T10:00:00Z"
    assert body["source"]["event"]["code"] == "4662"


def test_a_missing_document_is_a_404_with_a_hint(client: TestClient) -> None:
    with patch(
        "soc_ai.api.webui.routes_events.get_event_raw",
        AsyncMock(return_value={"error": "event not found", "event_id": "nope"}),
    ):
        res = client.get("/api/v1/events/nope")
    assert res.status_code == 404
    assert res.json()["detail"]["reason"] == "event_not_found"
    assert "aged out" in res.json()["detail"]["hint"]
