"""Fetch-and-verify the audit hash chain against the live ES audit index.

The tamper-evident chain itself lives in :mod:`soc_ai.audit.chain`
(:func:`verify_chain` recomputes every record's hash and checks linkage). This
module is the *operator-facing* half: it pulls the stored records back out of
the date-stamped audit indices (``{audit_index_alias}-*``) and runs them through
:func:`verify_chain`, so a ``soc-ai audit verify`` CLI run and the admin
``GET /config/audit/verify-chain`` endpoint share one ES-fetch path.

Paging: the chain can be large (one record per LLM I/O + tool call), so a single
``size`` search would hit ES's 10 000-hit ``from``+``size`` ceiling. We page with
``search_after`` on ``seq`` ascending, which has no window limit, and stop when a
page returns fewer than the page size. A ``max_records`` safety cap bounds a
pathological run; if it is hit we set ``capped=True`` and the caller MUST surface
it (a capped scan cannot claim the whole chain was verified). We never silently
truncate.

Time window: ``days=N`` bounds the scan to records with ``timestamp >= now-Nd``
(the audit field is ``timestamp``; ``verify_chain`` still checks that ``seq`` is
contiguous *within* the returned window, but a windowed scan cannot verify
linkage across the window boundary — the record before the window is not fetched,
so its ``hash`` can't be confirmed against the first in-window ``prev_hash``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.audit.chain import verify_chain
from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)

# Per-page hit count for the search_after scan. 1000 keeps each round trip small
# while paging a large chain in few requests.
_PAGE_SIZE = 1000

# Absolute safety cap on records pulled in one verification. A real audit chain
# can be long, but an unbounded pull on a misconfigured index shouldn't be able
# to OOM the process. 500k records ≈ a very active deployment's multi-week trail;
# beyond that, bound with days=. Hitting it sets capped=True (never silent).
_MAX_RECORDS = 500_000


@dataclass(frozen=True)
class ChainVerifyResult:
    """Outcome of a fetch-and-verify pass over the audit chain.

    - ``ok`` — True iff the chain (over the fetched records) is intact.
    - ``records_verified`` — number of chained records checked.
    - ``first_broken_seq`` — the ``seq`` where linkage first failed, else None.
    - ``first_seq`` / ``last_seq`` — the seq span actually covered (None on an
      empty/legacy-only result).
    - ``capped`` — True iff the ``max_records`` cap was hit, so the scan did NOT
      reach the end of the chain (``ok`` then covers only the fetched prefix).
    """

    ok: bool
    records_verified: int
    first_broken_seq: int | None
    first_seq: int | None
    last_seq: int | None
    capped: bool


async def _search_page(
    elastic: ElasticClient,
    index: str,
    query: dict[str, Any],
    *,
    size: int,
    sort: list[dict[str, Any]],
    search_after: list[Any] | None,
) -> list[dict[str, Any]]:
    """Run one ``search_after`` page directly on the low-level ES client.

    :class:`ElasticClient.search` does not expose ``search_after``, so drop to the
    underlying client (mirroring the tolerant ``ignore_unavailable`` /
    ``allow_no_indices`` flags the wrapper sets) and return the raw hit dicts —
    each carries ``_source`` (the stored record) and ``sort`` (the next cursor).
    """
    body: dict[str, Any] = {
        "query": query,
        "size": size,
        "sort": sort,
        # Accurate total isn't needed (we page to exhaustion), but asking keeps the
        # semantics obvious and cheap for the small pages we pull.
        "track_total_hits": False,
    }
    if search_after is not None:
        body["search_after"] = search_after
    response = await elastic._client.search(
        index=index,
        body=body,
        ignore_unavailable=True,
        allow_no_indices=True,
    )
    return list(response.get("hits", {}).get("hits", []))


async def _fetch_audit_records(
    elastic: ElasticClient,
    audit_index_alias: str,
    *,
    days: int | None,
    max_records: int,
) -> tuple[list[dict[str, Any]], bool]:
    """Pull audit ``_source`` bodies from ``{alias}-*`` sorted ascending by seq.

    Pages with ``search_after`` on ``seq`` (no 10k window limit). Returns
    ``(records, capped)`` where ``capped`` is True iff ``max_records`` was reached
    before the scan exhausted the index (so the caller must not claim the whole
    chain was verified).
    """
    index = f"{audit_index_alias}-*"
    # Only records that carry a seq — legacy pre-chain docs have none and
    # verify_chain would ignore them anyway; excluding them here keeps paging tight.
    filters: list[dict[str, Any]] = [{"exists": {"field": "seq"}}]
    if days is not None:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        filters.append({"range": {"timestamp": {"gte": since}}})
    query: dict[str, Any] = {"bool": {"filter": filters}}
    # Tie-break on _id so the sort is a total order even if two docs somehow share
    # a seq (a tamper we still want to page past deterministically, not loop on).
    sort: list[dict[str, Any]] = [{"seq": {"order": "asc"}}, {"_id": {"order": "asc"}}]

    records: list[dict[str, Any]] = []
    search_after: list[Any] | None = None
    while True:
        remaining = max_records - len(records)
        if remaining <= 0:
            return records, True  # cap reached — scan did NOT exhaust the index
        page_size = min(_PAGE_SIZE, remaining)
        hits = await _search_page(
            elastic, index, query, size=page_size, sort=sort, search_after=search_after
        )
        if not hits:
            break
        for hit in hits:
            src = hit.get("_source")
            if isinstance(src, dict):
                records.append(src)
        if len(hits) < page_size:
            break  # last (partial) page — index exhausted
        cursor = hits[-1].get("sort")
        if not isinstance(cursor, list) or not cursor:
            # ES echoes `sort` on every hit when a sort is set; if it didn't, stop
            # rather than risk an infinite loop re-fetching the same page.
            _LOGGER.warning("audit verify: page missing sort cursor, stopping scan early")
            break
        search_after = cursor

    return records, False


async def verify_audit_chain(
    elastic: ElasticClient,
    audit_index_alias: str,
    *,
    days: int | None = None,
    max_records: int = _MAX_RECORDS,
) -> ChainVerifyResult:
    """Fetch every audit record from ES and verify the tamper-evident chain.

    Queries ``{audit_index_alias}-*`` for all chained records (optionally the last
    ``days`` days), sorted ascending by ``seq``, and runs :func:`verify_chain`
    over them. An empty index (no chained records) is intact by definition.

    Shared by the ``soc-ai audit verify`` CLI and the admin verify-chain endpoint.
    Raises on a transport/ES error (the caller maps that to exit-2 / a 5xx) — this
    is a *verification*, so an unreachable index is "could not run", NOT "intact".
    """
    records, capped = await _fetch_audit_records(
        elastic, audit_index_alias, days=days, max_records=max_records
    )
    ok, first_broken = verify_chain(records)

    # Seq span actually covered (over the chained records verify_chain considered).
    seqs = [r["seq"] for r in records if isinstance(r.get("seq"), int)]
    first_seq = min(seqs) if seqs else None
    last_seq = max(seqs) if seqs else None

    return ChainVerifyResult(
        ok=ok,
        records_verified=len(seqs),
        first_broken_seq=first_broken,
        first_seq=first_seq,
        last_seq=last_seq,
        capped=capped,
    )
