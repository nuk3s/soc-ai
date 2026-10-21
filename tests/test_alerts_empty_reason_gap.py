"""An empty alert window over a grid gap is blind, and it never reads "The grid is quiet."

After the range outage of 2026-10-15 to 2026-10-19 the Alerts page and the
Dashboard said "The grid is quiet." for a week the grid was dark for four
days (dogfood 2026-10-19, R1-D2, R2-D2).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client import inventory as inventory_svc
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import grid_gaps
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

from tests.test_alerts_empty_reason import _LabelCounts

_NOW = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
_GAP = (_NOW - timedelta(days=4), _NOW - timedelta(hours=2))


def _seed(settings: Settings) -> None:
    async def go() -> None:
        engine = make_engine(settings)
        await run_migrations(engine)
        async with make_sessionmaker(engine)() as db:
            await grid_gaps.open_probe_gap(db, started_at=_GAP[0], detail="refused")
            await grid_gaps.close_probe_gaps(db, ended_at=_GAP[1])
        await engine.dispose()

    asyncio.run(go())


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    inventory_svc._clear_cache()
    _seed(settings_kratos)
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _reason(client: TestClient, query: str, counts: dict[str, int] | None = None) -> Any:
    with patch.object(ElasticClient, "search", _LabelCounts(counts or {})):
        resp = client.get(f"/api/v1/alerts/empty-reason?{query}")
    assert resp.status_code == 200
    return resp.json()


def test_an_empty_window_over_a_gap_names_the_gap_hours(client: TestClient) -> None:
    body = _reason(client, "range=7d")
    assert body["reason"] == "gap"
    assert "The grid is quiet." not in body["hint"]
    start, end = grid_gaps.stamp(_GAP[0]), grid_gaps.stamp(_GAP[1])
    assert f"The grid was unreadable from {start} to {end}." in body["hint"]
    assert body["hint"].endswith("The alert count over those hours is unknown.")


def test_an_empty_window_after_the_gap_is_quiet(client: TestClient) -> None:
    """The negative control: the last hour does not overlap the gap."""
    body = _reason(client, "range=1h")
    assert body["reason"] == "quiet"


def test_a_custom_window_over_the_gap_is_a_gap(client: TestClient) -> None:
    start = (_GAP[0] + timedelta(hours=1)).isoformat() + "Z"
    end = (_GAP[0] + timedelta(hours=5)).isoformat() + "Z"
    body = _reason(client, f"range=custom&from={start}&to={end}")
    assert body["reason"] == "gap"


def test_a_filter_mismatch_over_a_gap_still_names_the_label(client: TestClient) -> None:
    """The mismatch is the actionable answer. The gap does not hide it."""
    body = _reason(client, "range=7d", {"event.kind:alert": 25})
    assert body["reason"] == "filter_mismatch"
