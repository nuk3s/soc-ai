"""The composite pager: every key of an estate-wide read, up to a disclosed ceiling.

A terms read of 500 held the busiest 500 entities and nothing past them. The
pager reads every key in key order, one page per search, and says when the
ceiling stopped it.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.dossier import observe
from soc_ai.hunting import prior_sweep
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.so_client.paging import MIN_PAGE_SIZE, read_pages, too_many_buckets

from tests.es_doubles import composite_page


class _BucketLimit(Exception):
    """The body Elasticsearch sends for a response past ``search.max_buckets``."""

    def __init__(self) -> None:
        super().__init__("too many buckets")
        self.body = {
            "error": {
                "type": "search_phase_execution_exception",
                "reason": "",
                "root_cause": [{"type": "too_many_buckets_exception", "reason": "x"}],
            }
        }


class _PagedES:
    """Answers one composite aggregation over ``count`` keys, one page per search.

    ``limit`` refuses a page larger than it with the bucket limit. ``sizes``
    holds the size every search asked for, a refused one too.
    """

    def __init__(self, count: int, *, limit: int | None = None) -> None:
        self.buckets = [{"key": f"host-{n:06d}", "doc_count": 1} for n in range(count)]
        self.limit = limit
        self.sizes: list[int] = []

    async def search(self, index: str, query: Any, **kwargs: Any) -> EsSearchResult:
        body = kwargs["aggs"]["entities"]
        size = int(body["composite"]["size"])
        self.sizes.append(size)
        if self.limit is not None and size > self.limit:
            raise _BucketLimit()
        page = composite_page(body, self.buckets)
        return EsSearchResult(total=0, took_ms=1, aggregations={"entities": page})


async def _read(es: Any, *, page_size: int = 1000, ceiling: int = 20_000) -> Any:
    return await read_pages(
        es,
        "logs-*",
        {"match_all": {}},
        name="entities",
        field="source.ip",
        aggs={"hours": {"date_histogram": {"field": "@timestamp", "calendar_interval": "hour"}}},
        page_size=page_size,
        ceiling=ceiling,
    )


def test_the_shipped_reads_page_1000_up_to_20000() -> None:
    assert prior_sweep.RECENT_PAGE_SIZE == 1000
    assert prior_sweep.RECENT_MAX_ENTITIES == 20_000
    assert observe._AGENT_HOST_PAGE == 1000
    assert observe._AGENT_HOST_CEILING == 20_000


async def test_an_estate_past_the_ceiling_stops_at_it_and_says_so() -> None:
    """20,500 keys: twenty pages, the last one asking for one key past the ceiling."""
    es = _PagedES(20_500)

    pages = await _read(es)

    assert pages.capped is True
    assert len(pages.buckets) == 20_000
    assert pages.searches == 20
    assert es.sizes == [1000] * 19 + [1001]
    # The keys are unwrapped to the shape a terms bucket carries.
    assert pages.buckets[0]["key"] == "host-000000"
    assert pages.buckets[-1]["key"] == "host-019999"


async def test_an_estate_of_exactly_the_ceiling_reads_as_complete() -> None:
    """Negative control: a full last page is not proof of more keys."""
    es = _PagedES(20_000)

    pages = await _read(es)

    assert pages.capped is False
    assert len(pages.buckets) == 20_000
    assert pages.searches == 20


async def test_a_short_page_ends_the_read() -> None:
    es = _PagedES(2500)

    pages = await _read(es)

    assert pages.capped is False
    assert es.sizes == [1000, 1000, 1000]
    assert [b["key"] for b in pages.buckets] == [b["key"] for b in es.buckets]


async def test_a_page_past_the_bucket_limit_is_asked_again_at_half_the_size() -> None:
    es = _PagedES(1200, limit=500)

    pages = await _read(es)

    assert pages.capped is False
    assert len(pages.buckets) == 1200
    assert es.sizes == [1000, 500, 500, 500]
    assert pages.searches == 4


async def test_a_refusal_at_the_smallest_page_raises() -> None:
    es = _PagedES(1200, limit=MIN_PAGE_SIZE - 1)

    with pytest.raises(_BucketLimit):
        await _read(es)


async def test_any_other_failure_raises_with_no_partial_answer() -> None:
    class _Broken(_PagedES):
        async def search(self, index: str, query: Any, **kwargs: Any) -> EsSearchResult:
            if len(self.sizes) == 1:
                raise RuntimeError("the grid is gone")
            return await super().search(index, query, **kwargs)

    with pytest.raises(RuntimeError, match="the grid is gone"):
        await _read(_Broken(2500))


def test_the_bucket_limit_is_read_from_the_error_body() -> None:
    assert too_many_buckets(_BucketLimit()) is True
    assert too_many_buckets(RuntimeError("too_many_buckets_exception")) is False
