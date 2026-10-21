"""A grid double for the anchor rule: alerts, telemetry, or no answer.

The anchor rule asks the grid whether the alert feed holds the anchor
document of a promotion (soc_ai.webui.anchor_check). The double holds two
sets of document ids. A query by id alone finds both sets, the way the grid
finds any document by id. A query that also carries the alert filter of the
Alerts page finds the alerts only. A check that forgets the filter then calls
a telemetry document an alert, and the test that plants one fails.

:func:`install` puts the double behind the ElasticClient of a test app, so
the code under test builds its own request.
"""

from __future__ import annotations

import json
from typing import Any

from elastic_transport import ConnectionError as EsConnectionError
from fastapi.testclient import TestClient
from soc_ai.config import Settings


def ids_of(node: Any) -> list[str] | None:
    """The ids of an ``ids`` clause anywhere in the query, or None."""
    if isinstance(node, dict):
        ids = node.get("ids")
        if isinstance(ids, dict) and isinstance(ids.get("values"), list):
            return [str(v) for v in ids["values"]]
        nodes: list[Any] = list(node.values())
    elif isinstance(node, list):
        nodes = node
    else:
        return None
    for value in nodes:
        found = ids_of(value)
        if found is not None:
            return found
    return None


class AnchorGrid:
    """The double. ``feed_reads`` counts the anchor checks it answered.

    An anchor check is a query with ids and the alert filter. ``down`` makes
    every search fail the way a refused connection does.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        alerts: set[str] | None = None,
        telemetry: set[str] | None = None,
        down: bool = False,
    ) -> None:
        from soc_ai.webui.alerts_query import _oql_filter_dsl

        self.alerts = set(alerts or ())
        self.telemetry = set(telemetry or ())
        self.down = down
        self.feed_reads = 0
        self._feed = json.dumps(_oql_filter_dsl(settings.webui_alerts_query), sort_keys=True)

    async def search(self, **kwargs: Any) -> dict[str, Any]:
        body = kwargs.get("body") or {}
        ids = ids_of(body.get("query"))
        feed = self._feed in json.dumps(body, sort_keys=True)
        if feed and ids is not None:
            self.feed_reads += 1
        if self.down:
            raise EsConnectionError("the grid is down")
        if ids is None:
            return {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}
        held = self.alerts if feed else self.alerts | self.telemetry
        hits = [{"_id": i, "_index": "logs-test", "_source": {}} for i in ids if i in held]
        return {"hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits}}


def install(client: TestClient, **kwargs: Any) -> AnchorGrid:
    """Answer every grid search of the test app from a new double."""
    grid = AnchorGrid(client.app.state.settings, **kwargs)
    client.app.state.elastic._client.search = grid.search
    return grid
