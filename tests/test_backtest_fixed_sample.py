"""A backtest replays a fixed list of alerts.

The swarm triage experiment replays one sample of closed production alerts
through each arm (docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md,
"Datasets and metrics"). The sampler picks the newest dispositioned alert of
each rule, so two runs a day apart replay two different sets. ``alert_ids``
replays exactly the listed alerts, in the listed order, and reads each
analyst label from the grid as the sampler does. Every run names the ids it
replayed, so a reader copies the list of arm A into the request of arm B.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.agent.orchestrator import StepEvent
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui import backtest as backtest_svc

from tests.test_backtest import (
    SAMPLING_ES_RESPONSE,
    _fake_investigate,
    _poll_backtest,
    bt_settings,  # noqa: F401 - the fixture the client below reads
)

_HITS: dict[str, dict[str, Any]] = {hit["_id"]: hit for hit in SAMPLING_ES_RESPONSE["hits"]["hits"]}
_HITS["a4"] = {
    "_id": "a4",
    "_source": {
        "@timestamp": "2026-06-30T06:44:00.000Z",
        "rule": {"name": "ET INFO no call"},
        "event": {"severity_label": "low"},
    },
}


def _ids_of(query: dict[str, Any]) -> list[str] | None:
    for clause in (query.get("bool") or {}).get("filter") or []:
        if isinstance(clause, dict) and "ids" in clause:
            return list(clause["ids"]["values"])
    return None


class _Grid:
    """A fake grid that answers the sampler and the listed read, and records both."""

    def __init__(self) -> None:
        self.queries: list[dict[str, Any]] = []
        self.replayed: list[str] = []

    async def search(self, *_args: Any, **kwargs: Any) -> dict[str, Any]:
        query = (kwargs.get("body") or {}).get("query") or {}
        self.queries.append(query)
        ids = _ids_of(query)
        if ids is None:
            return SAMPLING_ES_RESPONSE
        # The grid answers in its own order, never the listed one.
        hits = [_HITS[i] for i in sorted(ids) if i in _HITS]
        return {"took": 1, "hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits}}

    async def investigate(self, alert_id: str, **kwargs: Any) -> AsyncIterator[StepEvent]:
        self.replayed.append(alert_id)
        async for ev in _fake_investigate(alert_id, **kwargs):
            yield ev


@pytest.fixture
def grid() -> _Grid:
    return _Grid()


@pytest.fixture
def client(bt_settings: Settings, grid: _Grid) -> Iterator[TestClient]:  # noqa: F811
    fake_es = AsyncMock()
    fake_es.search.side_effect = grid.search
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=bt_settings),
        patch("soc_ai.api.runner.investigate", grid.investigate),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def test_an_explicit_list_replays_those_alerts_only_in_order(
    client: TestClient, grid: _Grid
) -> None:
    resp = client.post("/api/v1/backtest", json={"alert_ids": ["a3", "a1"]})
    assert resp.status_code == 200
    started = resp.json()
    assert started["total"] == 2
    assert started["alert_ids"] == ["a3", "a1"]

    data = _poll_backtest(client)
    assert data["status"] == "complete"
    assert grid.replayed == ["a3", "a1"]
    assert [row["alert_id"] for row in data["results"]["rows"]] == ["a3", "a1"]
    # The labels come from the grid, as the sampler reads them.
    assert [row["human_disposition"] for row in data["results"]["rows"]] == [
        "true_positive",
        "false_positive",
    ]
    # One read by id: no window, no severity floor, no sampling.
    assert grid.queries == [{"bool": {"filter": [{"ids": {"values": ["a3", "a1"]}}]}}]
    assert data["params"]["mode"] == "listed"
    assert data["requested"] == 2
    assert data["skipped_reason"] is None


def test_the_result_names_the_ids_so_the_next_arm_replays_the_same_alerts(
    client: TestClient, grid: _Grid
) -> None:
    assert client.post("/api/v1/backtest", json={"sample_size": 20}).status_code == 200
    arm_a = _poll_backtest(client)
    assert arm_a["status"] == "complete"
    assert arm_a["alert_ids"] == ["a1", "a2", "a3"]
    assert arm_a["results"]["alert_ids"] == ["a1", "a2", "a3"]

    grid.replayed.clear()
    resp = client.post("/api/v1/backtest", json={"alert_ids": arm_a["alert_ids"]})
    assert resp.status_code == 200
    arm_b = _poll_backtest(client)
    assert arm_b["backtest_id"] != arm_a["backtest_id"]
    assert grid.replayed == ["a1", "a2", "a3"]
    assert arm_b["alert_ids"] == arm_a["alert_ids"]
    by_id = client.get(f"/api/v1/backtest/{arm_b['backtest_id']}").json()
    assert by_id["alert_ids"] == ["a1", "a2", "a3"]


def test_a_list_over_the_cap_is_refused(client: TestClient, grid: _Grid) -> None:
    ids = [f"alert-{n:04d}" for n in range(backtest_svc.MAX_LISTED_ALERTS + 1)]
    resp = client.post("/api/v1/backtest", json={"alert_ids": ids})
    assert resp.status_code == 422
    assert "alert_ids must hold at most 200 items." in resp.json()["detail"]["hint"]
    assert client.get("/api/v1/backtest").json()["active"] is False
    assert grid.queries == []


def test_a_list_at_the_cap_is_accepted(client: TestClient) -> None:
    ids = [f"alert-{n:04d}" for n in range(backtest_svc.MAX_LISTED_ALERTS)]
    resp = client.post("/api/v1/backtest", json={"alert_ids": ids})
    assert resp.status_code == 200
    # None of them is on the grid, so the attempt starts no run and says so.
    assert resp.json()["refused"]["reason"] == "no_dispositioned_alerts"


def test_an_empty_list_is_refused(client: TestClient) -> None:
    resp = client.post("/api/v1/backtest", json={"alert_ids": []})
    assert resp.status_code == 422
    assert "alert_ids is empty. Send at least one item." in resp.json()["detail"]["hint"]


def test_a_missing_or_unlabelled_alert_is_left_out_and_named(
    client: TestClient, grid: _Grid
) -> None:
    resp = client.post(
        "/api/v1/backtest", json={"alert_ids": ["a2", "gone-0001", "a4", "a2", " a1 "]}
    )
    assert resp.status_code == 200
    data = _poll_backtest(client)
    # Repeats and blanks collapse. The listed order holds.
    assert data["params"]["listed_alert_ids"] == ["a2", "gone-0001", "a4", "a1"]
    assert grid.replayed == ["a2", "a1"]
    assert data["alert_ids"] == ["a2", "a1"]
    plan = data["params"]["plan"]
    assert plan["not_found"] == ["gone-0001"]
    assert plan["no_disposition"] == ["a4"]
    assert data["skipped_reason"] == (
        "1 listed alert is not on the grid. 1 listed alert carries no analyst disposition."
    )


def test_the_list_ignores_the_sample_cap(bt_settings: Settings) -> None:  # noqa: F811
    """The list is the operator's own sample. backtest_max_sample cuts a sampled run only."""
    params, requested, capped = backtest_svc._start_params(
        bt_settings.model_copy(update={"backtest_max_sample": 2}),
        window_days=30,
        sample_size=20,
        min_severity=None,
        listed=["a1", "a2", "a3"],
    )
    assert (requested, capped) == (3, 3)
    assert params["listed_alert_ids"] == ["a1", "a2", "a3"]
