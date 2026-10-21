"""The check of the anchor rule: does the alert feed hold a document.

:func:`soc_ai.webui.anchor_check.alert_status` answers a batch of document ids
with one grid search. The query is the alert filter of the Alerts page with
no time window. The answers stay in a bounded cache per app, and a grid
failure answers "unknown" for a short hold.

The negative controls plant each case on the path a loose check would miss:

* The grid holds a Zeek conn record and a CaptureLoss notice. A check by id
  alone calls them alerts. The alert filter leaves them out.
* The alert is 30 days old. A check with the time window of a page calls it
  telemetry.
* A planted synthetic alert is no alert, as in the feed.
* A grid failure and a partial read are not a "no".
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from elastic_transport import ConnectionError as EsConnectionError
from soc_ai.config import Settings

from tests.anchor_grid import ids_of
from tests.conftest import _base_settings_kwargs
from tests.doc_grid import DocGrid


class _Elastic:
    """An ElasticClient double for the check: answers from a set of alert ids."""

    def __init__(self, alerts: set[str], *, fail: BaseException | None = None) -> None:
        self.alerts = alerts
        self.fail = fail
        self.queries: list[dict[str, Any]] = []
        self.kwargs: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> Any:
        from soc_ai.so_client.elastic import EsSearchResult

        self.queries.append(query)
        self.kwargs.append(kwargs)
        if self.fail is not None:
            raise self.fail
        ids = ids_of(query) or []
        hits = [{"_id": i} for i in ids if i in self.alerts]
        return EsSearchResult(total=len(hits), took_ms=1, hits=hits)


def _state(elastic: _Elastic, **settings: Any) -> SimpleNamespace:
    return SimpleNamespace(
        elastic=elastic, settings=Settings(**_base_settings_kwargs(), **settings)
    )


def _feed_docs() -> list[dict[str, Any]]:
    """Documents as the grid holds them: alerts of each feed source, and telemetry."""
    now = datetime.now(UTC)
    recent = (now - timedelta(minutes=5)).isoformat()
    old = (now - timedelta(days=30)).isoformat()
    return [
        {"_id": "es-suricata", "tags": ["alert"], "event.dataset": "suricata.alert"},
        {"_id": "es-endpoint", "event.kind": "alert", "event.dataset": "endpoint.alerts"},
        {"_id": "es-sigma", "event.dataset": "sigma.alert"},
        {"_id": "es-notice", "event.dataset": "zeek.notice", "notice.note": "ATTACK::Discovery"},
        {"_id": "es-old", "tags": ["alert"], "@timestamp": old},
        {"_id": "es-zeek-conn", "event.dataset": "zeek.conn", "@timestamp": recent},
        {
            "_id": "es-capture-loss",
            "event.dataset": "zeek.notice",
            "notice.note": "CaptureLoss::Too_Much_Loss",
        },
        {"_id": "es-synth", "tags": ["alert"], "synth.scenario_id": "dcsync-1"},
    ]


@pytest.mark.parametrize(
    ("extra", "alerts"),
    [
        (True, {"es-suricata", "es-endpoint", "es-sigma", "es-notice", "es-old"}),
        (False, {"es-suricata", "es-endpoint", "es-old"}),
    ],
)
def test_the_check_reads_the_feed_of_the_alerts_page(extra: bool, alerts: set[str]) -> None:
    """The grid evaluates the query against documents.

    NEGATIVE CONTROLS: the 30-day-old alert is an alert, because the check has
    no time window. The Zeek conn record and the CaptureLoss notice are on the
    grid, and the feed leaves them out. A planted synthetic alert is no alert.
    """
    from soc_ai.webui import anchor_check

    grid = DocGrid(_feed_docs())
    ids = [str(d["_id"]) for d in _feed_docs()]
    state = SimpleNamespace(
        elastic=grid,
        settings=Settings(**_base_settings_kwargs(), webui_extra_detections=extra),
    )
    got = asyncio.run(anchor_check.alert_status(state, ids))
    assert {i for i, status in got.items() if status == anchor_check.ALERT} == alerts
    assert {i for i, status in got.items() if status == anchor_check.NOT_ALERT} == set(ids) - alerts
    assert len(grid.searches) == 1


def test_the_check_asks_for_a_complete_read_of_each_id() -> None:
    from soc_ai.webui import anchor_check

    elastic = _Elastic({"es-old"})
    got = asyncio.run(anchor_check.alert_status(_state(elastic), ["es-old", "es-zeek"]))
    assert got == {"es-old": anchor_check.ALERT, "es-zeek": anchor_check.NOT_ALERT}
    assert "@timestamp" not in json.dumps(elastic.queries[0])
    assert elastic.kwargs[0]["size"] == 2
    assert elastic.kwargs[0]["source"] is False
    assert elastic.kwargs[0]["require_complete"] is True


def test_the_feed_sources_are_the_sources_of_the_alerts_page() -> None:
    from soc_ai.webui import alerts_query

    on = Settings(**_base_settings_kwargs(), webui_extra_detections=True)
    off = Settings(**_base_settings_kwargs(), webui_extra_detections=False)
    assert alerts_query.feed_sources(on) == [
        on.webui_alerts_query,
        alerts_query.SIGMA_SOURCE_OQL,
        alerts_query.NOTICE_SOURCE_OQL,
    ]
    assert alerts_query.feed_sources(off) == [off.webui_alerts_query]


def test_the_cache_answers_the_second_call_with_no_search() -> None:
    from soc_ai.webui import anchor_check

    elastic = _Elastic({f"es-{n}" for n in range(15)})
    state = _state(elastic)
    ids = [f"es-{n}" for n in range(30)]
    first = asyncio.run(anchor_check.alert_status(state, ids))
    second = asyncio.run(anchor_check.alert_status(state, ids))
    assert first == second
    assert sum(1 for v in first.values() if v == anchor_check.ALERT) == 15
    assert len(elastic.queries) == 1


def test_the_cache_asks_again_after_its_ttl_and_holds_a_bounded_count() -> None:
    from soc_ai.webui import anchor_check

    now = [1000.0]
    cache = anchor_check.AnchorAlertCache(size=3, clock=lambda: now[0])
    assert anchor_check.ANSWER_TTL_S >= 3600
    for n in range(4):
        cache.put(("k", f"es-{n}"), anchor_check.ALERT)
    assert cache.get(("k", "es-0")) is None
    assert cache.get(("k", "es-3")) == anchor_check.ALERT
    now[0] += anchor_check.ANSWER_TTL_S + 1
    assert cache.get(("k", "es-3")) is None


@pytest.mark.parametrize(
    "fail",
    [
        EsConnectionError("down"),
        TimeoutError(),
        RuntimeError("partial search results"),
    ],
)
def test_a_grid_failure_answers_unknown_and_the_next_read_asks_again(
    fail: BaseException,
) -> None:
    from soc_ai.webui import anchor_check

    now = [1000.0]
    elastic = _Elastic({"es-wmi"}, fail=fail)
    state = _state(elastic)
    state.anchor_alert_cache = anchor_check.AnchorAlertCache(clock=lambda: now[0])
    got = asyncio.run(anchor_check.alert_status(state, ["es-wmi"]))
    assert got == {"es-wmi": anchor_check.UNKNOWN}
    # A failure stands for a short hold, so a poll does not ask a sick grid.
    asyncio.run(anchor_check.alert_status(state, ["es-wmi"]))
    assert len(elastic.queries) == 1
    now[0] += anchor_check.FAILURE_HOLD_S + 1
    elastic.fail = None
    assert asyncio.run(anchor_check.alert_status(state, ["es-wmi"])) == {
        "es-wmi": anchor_check.ALERT
    }
    assert len(elastic.queries) == 2


def test_a_partial_read_answers_unknown() -> None:
    """A shard that failed can hide the alert. That is "could not see"."""
    from soc_ai.so_client.elastic import GridPartialResultsError
    from soc_ai.webui import anchor_check

    elastic = _Elastic({"es-wmi"}, fail=GridPartialResultsError("1 of 3 shards failed"))
    got = asyncio.run(anchor_check.alert_status(_state(elastic), ["es-wmi", "es-other"]))
    assert got == {"es-wmi": anchor_check.UNKNOWN, "es-other": anchor_check.UNKNOWN}


def test_no_ids_ask_nothing() -> None:
    from soc_ai.webui import anchor_check

    elastic = _Elastic(set())
    assert asyncio.run(anchor_check.alert_status(_state(elastic), ["", ""])) == {}
    assert elastic.queries == []
