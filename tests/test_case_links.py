"""Reading Security Onion's own record of which alerts are on a case.

Attaching an alert writes a ``related`` document on the case index carrying the
alert's ES ``_id`` as ``so_related.fields.soc_id``. That document is written on
every attach by every producer, so it sees cases this instance never opened.
Shape confirmed against a live SO 3.2.0 grid on 2026-09-06.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.webui.case_links import MAX_LOOKUP_IDS, case_ids_for_alerts

pytestmark = pytest.mark.asyncio


def _bucket(alert_id: str, *case_ids: str) -> dict[str, Any]:
    return {
        "key": alert_id,
        "first_case": {
            "hits": {
                "hits": [{"_source": {"so_related": {"caseId": case_id}}} for case_id in case_ids]
            }
        },
    }


def _elastic(buckets: list[dict[str, Any]]) -> AsyncMock:
    es = AsyncMock()
    es.search.return_value = EsSearchResult(
        total=0, took_ms=1, aggregations={"by_alert": {"buckets": buckets}}
    )
    return es


@pytest.fixture
def settings() -> Settings:
    return Settings.model_construct(cases_index_pattern="so-case*")  # type: ignore[arg-type]


async def test_alerts_on_a_case_come_back_keyed_by_alert_id(settings: Settings) -> None:
    es = _elastic([_bucket("ev-1", "case-a"), _bucket("ev-3", "case-b")])

    links = await case_ids_for_alerts(es, settings, ["ev-1", "ev-2", "ev-3"])

    assert links == {"ev-1": "case-a", "ev-3": "case-b"}
    query = es.search.call_args.args[1]
    assert {"term": {"so_kind": "related"}} in query["bool"]["filter"]
    assert {"terms": {"so_related.fields.soc_id": ["ev-1", "ev-2", "ev-3"]}} in query["bool"][
        "filter"
    ]


async def test_an_alert_with_several_cases_reports_the_earliest(settings: Settings) -> None:
    """The bucket is sorted oldest-first, so the answer does not move when a
    duplicate lands after it."""
    es = _elastic([_bucket("ev-1", "case-first")])

    assert await case_ids_for_alerts(es, settings, ["ev-1"]) == {"ev-1": "case-first"}
    sub_aggs = es.search.call_args.kwargs["aggs"]["by_alert"]["aggs"]
    assert sub_aggs["first_case"]["top_hits"]["sort"] == [
        {"so_related.createTime": {"order": "asc"}}
    ]
    assert sub_aggs["first_case"]["top_hits"]["size"] == 1


async def test_a_degraded_read_raises_rather_than_reporting_no_case(
    settings: Settings,
) -> None:
    """Negative control, and the reason this lookup exists at all. The caller
    uses absence to decide it may open a case, so a search that could only see
    some shards must not answer "nothing found". ``require_complete`` is what
    turns that into a raise."""
    es = _elastic([])

    await case_ids_for_alerts(es, settings, ["ev-1"])

    assert es.search.call_args.kwargs["require_complete"] is True


async def test_no_ids_asks_the_grid_nothing(settings: Settings) -> None:
    es = _elastic([])
    assert await case_ids_for_alerts(es, settings, []) == {}
    assert await case_ids_for_alerts(es, settings, ["", ""]) == {}
    es.search.assert_not_awaited()


async def test_duplicate_ids_are_asked_about_once(settings: Settings) -> None:
    es = _elastic([_bucket("ev-1", "case-a")])
    await case_ids_for_alerts(es, settings, ["ev-1", "ev-1", "ev-2"])
    terms = es.search.call_args.args[1]["bool"]["filter"][1]["terms"]
    assert terms["so_related.fields.soc_id"] == ["ev-1", "ev-2"]


async def test_the_terms_clause_is_bounded(settings: Settings) -> None:
    es = _elastic([])
    await case_ids_for_alerts(es, settings, [f"ev-{i}" for i in range(MAX_LOOKUP_IDS + 50)])
    terms = es.search.call_args.args[1]["bool"]["filter"][1]["terms"]
    assert len(terms["so_related.fields.soc_id"]) == MAX_LOOKUP_IDS


async def test_a_bucket_with_no_case_id_is_not_a_link(settings: Settings) -> None:
    """A related document that came back without a caseId says nothing about
    whether a case exists, so it must not be reported as one."""
    es = _elastic([_bucket("ev-1", ""), {"key": "ev-2", "first_case": {"hits": {"hits": []}}}])
    assert await case_ids_for_alerts(es, settings, ["ev-1", "ev-2"]) == {}
