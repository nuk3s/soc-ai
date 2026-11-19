"""A route that runs an analyst's query answers 400 for a query the grid rejected.

The grid answered and rejected the query for the type of a field
(:class:`GridQueryRejectedError`). The 503 of today told the analyst to check
the shard allocation of a healthy cluster. A route that runs the analyst's
query now answers 400 ``query_rejected`` with the reason of Elasticsearch and
a hint, in the ``{reason, hint}`` shape of every refused filter.

Negative controls: the same route with no analyst query keeps the 503, a route
that runs a fixed query of soc-ai keeps the 503, and a real partial read keeps
the 503 with an analyst query too.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client import inventory as inventory_svc
from soc_ai.so_client.elastic import (
    ElasticClient,
    GridPartialResultsError,
    GridQueryRejectedError,
)

_RULE = "ET DOC TEST Suspicious Beacon"
_Q = "destination.ip:192.0.2.*"
_REASON = (
    "query_shard_exception: Can only use prefix queries on keyword, text and wildcard "
    "fields - not on [destination.ip] which is of type [ip]"
)


def _rejected() -> GridQueryRejectedError:
    return GridQueryRejectedError(
        f"partial search results from logs-*: 97 of 612 shards failed ({_REASON}).",
        shards_failed=97,
        shards_total=612,
        reason=_REASON,
    )


def _partial_read() -> GridPartialResultsError:
    return GridPartialResultsError(
        "partial search results from logs-*: 2 of 612 shards failed",
        shards_failed=2,
        shards_total=612,
        reason="no_shard_available_action_exception: recovering",
    )


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    inventory_svc._clear_cache()  # the inventory TTL cache outlives a test
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


def _grid_raising(exc: BaseException) -> Any:
    return patch.object(ElasticClient, "search", AsyncMock(side_effect=exc))


def _assert_rejected(resp: Any) -> None:
    assert resp.status_code == 400, resp.text
    detail = resp.json()["detail"]
    assert detail["reason"] == "query_rejected"
    hint = detail["hint"]
    # The correction leads, and the reason text of Elasticsearch follows it.
    assert hint.startswith("The field destination.ip is an IP field.")
    assert _REASON in hint
    assert "CIDR" in hint
    assert "unknown" in hint
    # The shard count is for the model and the log.
    assert "shards" not in hint
    # The shard story of the 503 is not the remedy here.
    assert "shard allocation" not in hint


def _assert_grid_unavailable(resp: Any) -> None:
    assert resp.status_code == 503, resp.text
    assert resp.json()["detail"]["reason"] == "grid_unavailable"


# (path, query parameters without the analyst query)
_GET_ROUTES: dict[str, tuple[str, dict[str, str]]] = {
    "alerts": ("/api/v1/alerts", {"range": "24h"}),
    "group_events": ("/api/v1/alerts/events", {"rule_name": _RULE, "range": "24h"}),
    "representative": ("/api/v1/alerts/representative", {"rule_name": _RULE, "range": "24h"}),
}


@pytest.mark.parametrize("route", sorted(_GET_ROUTES))
def test_an_analyst_query_that_the_grid_rejected_is_a_400(client: TestClient, route: str) -> None:
    with _grid_raising(_rejected()):
        path, params = _GET_ROUTES[route]
        resp = client.get(path, params={**params, "q": _Q})
    _assert_rejected(resp)


@pytest.mark.parametrize("route", sorted(_GET_ROUTES))
def test_the_same_route_with_no_analyst_query_keeps_the_503(client: TestClient, route: str) -> None:
    """Negative control: soc-ai wrote the query, so the analyst has nothing to correct."""
    with _grid_raising(_rejected()):
        path, params = _GET_ROUTES[route]
        resp = client.get(path, params=params)
    _assert_grid_unavailable(resp)


@pytest.mark.parametrize("route", sorted(_GET_ROUTES))
def test_a_real_partial_read_with_an_analyst_query_keeps_the_503(
    client: TestClient, route: str
) -> None:
    with _grid_raising(_partial_read()):
        path, params = _GET_ROUTES[route]
        resp = client.get(path, params={**params, "q": _Q})
    _assert_grid_unavailable(resp)


@pytest.mark.parametrize("path", ["/api/v1/alerts/ack-group", "/api/v1/alerts/escalate-group"])
def test_a_group_action_with_a_rejected_filter_is_a_400_and_writes_nothing(
    client: TestClient, path: str
) -> None:
    writes = AsyncMock(return_value=(None, None))
    with (
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", writes),
        _grid_raising(_rejected()),
    ):
        resp = client.post(path, json={"rule_name": _RULE, "q": _Q})
    _assert_rejected(resp)
    assert writes.await_count == 0


@pytest.mark.parametrize("path", ["/api/v1/alerts/ack-group", "/api/v1/alerts/escalate-group"])
def test_a_group_action_with_no_filter_keeps_the_503(client: TestClient, path: str) -> None:
    with _grid_raising(_rejected()):
        resp = client.post(path, json={"rule_name": _RULE})
    _assert_grid_unavailable(resp)


def test_starting_a_hunt_runs_a_fixed_query_and_keeps_the_503(client: TestClient) -> None:
    """The alert lookup is soc-ai's own query: no analyst query to correct."""
    with _grid_raising(_rejected()):
        resp = client.post("/api/v1/hunt", json={"alert_id": "ev-rejected-1"})
    _assert_grid_unavailable(resp)


def test_bulk_investigate_with_a_rejected_filter_is_a_400_with_no_outage_mark(
    client: TestClient,
) -> None:
    with _grid_raising(_rejected()):
        resp = client.post("/api/v1/auto-triage", json={"range": "24h", "q": _Q})
        after = client.get("/api/v1/auto-triage").json()
    _assert_rejected(resp)
    assert after["active"] is False
    # The grid was up: the dashboard must not report an outage over a filter.
    assert after["grid_errors"] == []


def test_bulk_investigate_with_no_filter_keeps_the_503_and_the_outage_mark(
    client: TestClient,
) -> None:
    with _grid_raising(_rejected()):
        resp = client.post("/api/v1/auto-triage", json={"range": "24h"})
        after = client.get("/api/v1/auto-triage").json()
    _assert_grid_unavailable(resp)
    assert after["active"] is False
    assert after["grid_errors"]
