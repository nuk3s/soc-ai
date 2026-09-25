"""One document from the grid, by id, for the evidence chips."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import ApiResponseMeta, HttpHeaders, TransportError
from elasticsearch import BadRequestError
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


def _es_meta(status: int) -> ApiResponseMeta:
    return ApiResponseMeta(
        status=status,
        http_version="1.1",
        headers=HttpHeaders({}),
        duration=0.0,
        node=None,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    "grid_failure",
    [TransportError("connection refused"), TimeoutError()],
    ids=["transport_error", "timeout"],
)
def test_an_unreachable_grid_is_a_retryable_503(
    client: TestClient, grid_failure: BaseException
) -> None:
    # The evidence chip must get the same retryable card every other grid read
    # answers with, not an unhandled 500.
    with patch("soc_ai.api.webui.routes_events.get_event_raw", AsyncMock(side_effect=grid_failure)):
        res = client.get("/api/v1/events/abc123")
    assert res.status_code == 503, res.text
    assert res.json()["detail"]["reason"] == "grid_unavailable"


def test_a_query_the_grid_rejects_is_a_400_not_a_500(client: TestClient) -> None:
    rejected = BadRequestError("failed to parse", meta=_es_meta(400), body={})
    with patch("soc_ai.api.webui.routes_events.get_event_raw", AsyncMock(side_effect=rejected)):
        res = client.get("/api/v1/events/abc123")
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["reason"] == "bad_query"


def test_a_slow_grid_read_is_cut_at_the_console_timeout(
    client: TestClient, settings_kratos: Settings
) -> None:
    # The route, not the ES client's retry budget, decides how long the chip
    # request may block the browser.
    settings_kratos.webui_grid_timeout_s = 1

    async def never_answers(*_args: object, **_kwargs: object) -> dict[str, object]:
        await asyncio.sleep(5)
        return {}

    with patch("soc_ai.api.webui.routes_events.get_event_raw", never_answers):
        res = client.get("/api/v1/events/abc123")
    assert res.status_code == 503, res.text
    assert res.json()["detail"]["reason"] == "grid_unavailable"
