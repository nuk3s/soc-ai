"""Unit tests for soc_ai.tools.get_event_raw."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.get_event_raw import get_event_raw

# ---------------------------------------------------------------------------
# Helpers (mirrors the pattern in test_tools_misc.py)
# ---------------------------------------------------------------------------


def _hits(docs: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "took": 1,
        "hits": {"total": {"value": len(docs)}, "hits": docs},
    }


def _doc(source: dict[str, Any], doc_id: str = "x") -> dict[str, Any]:
    return {"_id": doc_id, "_source": source}


def _make_elastic(
    settings: Settings, responses: list[dict[str, Any]]
) -> tuple[ElasticClient, AsyncMock]:
    fake_es = AsyncMock()
    fake_es.search.side_effect = responses
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        return ElasticClient(settings), fake_es


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_event_raw_returns_source(settings_kratos: Settings) -> None:
    """When the event exists, get_event_raw returns its _source dict."""
    source = {
        "@timestamp": "2026-06-22T10:00:00.000Z",
        "event.dataset": "zeek.conn",
        "source.ip": "10.20.30.204",
        "destination.ip": "10.20.30.1",
        "host.name": "lab-gateway",
        "network.bytes": 512,
    }
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([_doc(source, doc_id="ev1")])])

    result = await get_event_raw("ev1", elastic=elastic, settings=settings_kratos)

    assert result == source
    # Confirm the query used the ids DSL and the correct index
    body = fake_es.search.call_args.kwargs["body"]
    assert body["query"] == {"ids": {"values": ["ev1"]}}
    assert fake_es.search.call_args.kwargs["index"] == settings_kratos.events_index_pattern


@pytest.mark.asyncio
async def test_get_event_raw_not_found(settings_kratos: Settings) -> None:
    """When no document matches, get_event_raw returns the standard error dict."""
    elastic, _ = _make_elastic(settings_kratos, [_hits([])])

    result = await get_event_raw("missing-id", elastic=elastic, settings=settings_kratos)

    assert result == {"error": "event not found", "event_id": "missing-id"}


@pytest.mark.asyncio
async def test_get_event_raw_empty_source(settings_kratos: Settings) -> None:
    """A hit with an empty _source returns an empty dict (not an error)."""
    elastic, _ = _make_elastic(settings_kratos, [_hits([_doc({}, doc_id="ev2")])])

    result = await get_event_raw("ev2", elastic=elastic, settings=settings_kratos)

    assert result == {}
