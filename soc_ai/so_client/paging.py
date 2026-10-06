"""Read an estate-wide aggregation in composite pages, up to a ceiling.

A ``terms`` aggregation returns the ``size`` busiest keys and nothing past
them. On an estate larger than ``size`` the rest are absent from the answer,
and an absent host reads as a silent one. A ``composite`` aggregation returns
every key in key order, one page per search. Each page starts after the last
key of the page before it.

The reader stops at a ceiling, and it says when it did, so the caller can
disclose it. The last page asks for one key past the ceiling: a page that
returns it proves the plane holds more, at no extra search. An estate of
exactly the ceiling reads as complete.

A page the grid refuses with the bucket limit is asked again at half the
size, down to :data:`MIN_PAGE_SIZE`. Any other failure raises, and so does a
refusal at the floor: a partial read handed back as a whole one is the false
all-clear the ceiling exists to prevent.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_LOGGER = logging.getLogger(__name__)

# The smallest page the bucket-limit retry halves down to.
MIN_PAGE_SIZE = 50
# The name of the one composite source. Each bucket key is ``{_SOURCE: value}``.
_SOURCE = "key"
_TOO_MANY_BUCKETS = "too_many_buckets_exception"


@dataclass(frozen=True)
class Pages:
    """Every bucket the pages returned, and whether the ceiling stopped the read.

    Each bucket's ``key`` is the source value, as a terms bucket carries it, so
    a reader written for a terms answer reads these unchanged. ``searches``
    counts every search sent, a refused one too.
    """

    buckets: tuple[dict[str, Any], ...] = ()
    capped: bool = False
    searches: int = 0


def too_many_buckets(exc: BaseException) -> bool:
    """Whether an Elasticsearch error is the bucket limit, read from its body.

    The top-level ``reason`` of a search_phase_execution_exception is an empty
    string. The cause sits under ``caused_by`` or ``root_cause``.
    """
    body = getattr(exc, "body", None)
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return False
    if (error.get("caused_by") or {}).get("type") == _TOO_MANY_BUCKETS:
        return True
    return any((rc or {}).get("type") == _TOO_MANY_BUCKETS for rc in error.get("root_cause") or [])


def _terms_shaped(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Composite buckets with the source value as ``key``. A key that is no mapping reads None."""
    out: list[dict[str, Any]] = []
    for row in rows:
        key = row.get("key")
        out.append({**row, "key": key.get(_SOURCE) if isinstance(key, Mapping) else None})
    return out


class CompositeRead:
    """One paged read of a composite aggregation over ``field``.

    Iterate :meth:`pages` for the buckets of each page, then read
    :attr:`capped`. A caller that parses each page as it arrives holds one
    page of raw buckets at a time. ``name`` is the aggregation's name in the
    request and in the answer. ``aggs`` are the sub-aggregations of every key,
    the same ones a terms read would carry.
    """

    def __init__(
        self,
        elastic: Any,
        index: str,
        query: dict[str, Any],
        *,
        name: str,
        field: str,
        aggs: Mapping[str, Any] | None = None,
        page_size: int,
        ceiling: int,
    ) -> None:
        self._elastic = elastic
        self._index = index
        self._query = query
        self._name = name
        self._field = field
        self._aggs = dict(aggs or {})
        self._page_size = max(1, page_size)
        self._ceiling = max(0, ceiling)
        self.capped = False
        self.searches = 0

    async def pages(self) -> AsyncIterator[list[dict[str, Any]]]:
        """The buckets of each page, until the keys run out or the ceiling holds.

        A short page ends the read: Elasticsearch fills a composite page
        unless the keys ran out.
        """
        read = 0
        after: Mapping[str, Any] | None = None
        size = self._page_size
        while True:
            remaining = self._ceiling - read
            want = remaining + 1 if remaining <= size else size
            composite: dict[str, Any] = {
                "size": want,
                "sources": [{_SOURCE: {"terms": {"field": self._field}}}],
            }
            if after is not None:
                composite["after"] = dict(after)
            body: dict[str, Any] = {"composite": composite}
            if self._aggs:
                body["aggs"] = self._aggs
            self.searches += 1
            try:
                result = await self._elastic.search(
                    self._index, self._query, size=0, aggs={self._name: body}
                )
            except Exception as exc:
                if too_many_buckets(exc) and size > MIN_PAGE_SIZE:
                    size = max(MIN_PAGE_SIZE, size // 2)
                    _LOGGER.info(
                        "%s: a page passed search.max_buckets; asking again with %d keys",
                        self._name,
                        size,
                    )
                    continue
                raise
            page = (result.aggregations or {}).get(self._name) or {}
            rows = list(page.get("buckets") or [])
            if len(rows) > remaining:
                self.capped = True
                yield _terms_shaped(rows[:remaining])
                return
            read += len(rows)
            yield _terms_shaped(rows)
            after = page.get("after_key")
            if len(rows) < want or not after:
                return


async def read_pages(
    elastic: Any,
    index: str,
    query: dict[str, Any],
    *,
    name: str,
    field: str,
    aggs: Mapping[str, Any] | None = None,
    page_size: int,
    ceiling: int,
) -> Pages:
    """Every bucket of a :class:`CompositeRead`, collected, and whether it was capped."""
    reader = CompositeRead(
        elastic,
        index,
        query,
        name=name,
        field=field,
        aggs=aggs,
        page_size=page_size,
        ceiling=ceiling,
    )
    buckets: list[dict[str, Any]] = []
    async for page in reader.pages():
        buckets.extend(page)
    return Pages(buckets=tuple(buckets), capped=reader.capped, searches=reader.searches)
