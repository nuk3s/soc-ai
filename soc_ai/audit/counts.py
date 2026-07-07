"""Best-effort audit-count aggregation over the date-stamped audit indices.

The audit log is written by :class:`soc_ai.audit.logger.AuditLogger` into daily
indices named ``{audit_index_alias}-YYYY.MM.dd`` (see that module). This helper
reads them back: a single ES ``terms`` aggregation on ``kind`` over the last N
days, so a caller (the egress-policy read-model, E5.3) can show "how many times
did each egress destination actually fire" without a per-kind round trip.

Contract: this is a DIAGNOSTIC, not a load-bearing read. EVERY failure path
(no ES, a search error, a malformed aggregation response) returns ``None`` for
every requested kind — never raises. A caller renders the policy table with the
counters blank when the count can't be obtained, so a down/unreachable audit
index never turns an inspectable config page into a 500.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)


async def audit_counts_by_kind(
    elastic: ElasticClient | None,
    audit_index_alias: str,
    kinds: list[str],
    *,
    days: int = 7,
) -> dict[str, int | None]:
    """Count audit events per ``kind`` over the last ``days`` days.

    Runs ONE ``terms`` aggregation on the ``kind`` keyword, filtered to the
    ``{alias}-*`` daily indices and a ``timestamp >= now-Nd`` range. Returns a
    dict mapping every requested kind to its count, or ``None`` for that kind
    when the count couldn't be obtained.

    Best-effort by construction: a missing/None client, an ES error, or a
    response without the expected aggregation buckets all yield an all-``None``
    result. The caller must treat ``None`` as "unknown", not "zero".
    """
    if elastic is None or not kinds:
        return {k: None for k in kinds}

    since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    index = f"{audit_index_alias}-*"
    query = {
        "bool": {
            "filter": [
                {"terms": {"kind": kinds}},
                {"range": {"timestamp": {"gte": since}}},
            ]
        }
    }
    # A `terms` agg sized to the number of kinds we asked for — the domain is a
    # fixed, tiny set (the egress kinds), so this never paginates.
    aggs = {"by_kind": {"terms": {"field": "kind", "size": max(len(kinds), 1)}}}

    try:
        result = await elastic.search(index, query, size=0, aggs=aggs)
    except Exception as exc:  # any transport/auth/index error → all-unknown
        _LOGGER.info("audit count aggregation failed (returning unknown counts): %s", exc)
        return {k: None for k in kinds}

    aggregations = result.aggregations
    if not isinstance(aggregations, dict):
        return {k: None for k in kinds}
    by_kind = aggregations.get("by_kind")
    if not isinstance(by_kind, dict):
        return {k: None for k in kinds}
    buckets = by_kind.get("buckets")
    if not isinstance(buckets, list):
        return {k: None for k in kinds}

    # A kind absent from the buckets genuinely had zero events in the window —
    # start every requested kind at 0 (a successful aggregation), then fill in
    # the observed counts. (Contrast with the error paths above, which return
    # None = "unknown".)
    counts: dict[str, int | None] = {k: 0 for k in kinds}
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        key = bucket.get("key")
        doc_count = bucket.get("doc_count")
        if isinstance(key, str) and key in counts and isinstance(doc_count, int):
            counts[key] = doc_count
    return counts
