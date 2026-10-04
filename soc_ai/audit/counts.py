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
index never turns an inspectable config page into a 500. The failure now
travels with its reason (:class:`AuditCounts`), so the page can say WHY a count
is blank.

Mapping drift: an old audit index can map ``kind`` as ``text`` (an index made
before the template, or by a dynamic mapping). A ``terms`` aggregation over
``{alias}-*`` then fails on every shard of that one index with "Fielddata is
disabled on [kind]", and every count on the page went blank with no reason.
The field-caps read below finds those indices first: each one is counted on
``kind.keyword`` when it has that sub-field, and left out (and named in the
reason) when it does not.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditCounts:
    """Per-kind counts plus the reason a count is unknown or partial.

    ``counts`` maps every requested kind to its count, or ``None`` when the
    count could not be obtained. ``reason`` is one operator sentence: why the
    counts are ``None``, or which indices a numeric count leaves out. ``None``
    when the counts are complete.
    """

    counts: dict[str, int | None]
    reason: str | None = None


@dataclass(frozen=True)
class _Leg:
    index: str
    field: str


def _unknown(kinds: list[str], reason: str) -> AuditCounts:
    return AuditCounts(counts={k: None for k in kinds}, reason=reason)


def _caps_body(resp: Any) -> dict[str, Any] | None:
    body = getattr(resp, "body", resp)
    return body if isinstance(body, dict) else None


def _non_aggregatable(field_caps: dict[str, Any]) -> tuple[set[str], bool]:
    """Indices where the field is not aggregatable, and whether that is every index.

    Field caps list ``indices`` on a type entry only when the field has more
    than one type across the pattern; an entry without the list covers every
    index that has the field.
    """
    bad: set[str] = set()
    everywhere = False
    for info in field_caps.values():
        if not isinstance(info, dict) or info.get("aggregatable", False):
            continue
        indices = info.get("indices")
        if isinstance(indices, list) and indices:
            bad.update(str(i) for i in indices)
        else:
            # Absent or empty: the client serialises the missing list as
            # ``[]``, and both mean every index that has the field.
            everywhere = True
    return bad, everywhere


async def _plan(elastic: ElasticClient, index: str) -> tuple[list[_Leg], list[str]]:
    """The aggregation legs that avoid a ``kind`` mapped as text, and the indices left out.

    One field-caps read. When it fails, or reports nothing odd, the plan is the
    single ``kind`` aggregation over the whole pattern (the behaviour before
    this read existed).
    """
    try:
        resp = await elastic._client.field_caps(
            index=index,
            fields=["kind", "kind.keyword"],
            ignore_unavailable=True,
            allow_no_indices=True,
        )
    except Exception as exc:
        _LOGGER.info("audit count field-caps read failed (aggregating on kind): %s", exc)
        return [_Leg(index, "kind")], []
    body = _caps_body(resp)
    fields = body.get("fields") if body else None
    if not isinstance(fields, dict):
        return [_Leg(index, "kind")], []
    kind_caps = fields.get("kind")
    if not isinstance(kind_caps, dict):
        return [_Leg(index, "kind")], []
    bad, everywhere = _non_aggregatable(kind_caps)
    if not bad and not everywhere:
        return [_Leg(index, "kind")], []

    keyword_caps = fields.get("kind.keyword")
    keyword_ok: set[str] = set()
    keyword_everywhere = False
    if isinstance(keyword_caps, dict):
        for info in keyword_caps.values():
            if isinstance(info, dict) and info.get("aggregatable", False):
                indices = info.get("indices")
                if isinstance(indices, list) and indices:
                    keyword_ok.update(str(i) for i in indices)
                else:
                    keyword_everywhere = True

    if everywhere:
        # Every index maps kind as text: the keyword sub-field is the only way.
        if keyword_everywhere:
            return [_Leg(index, "kind.keyword")], []
        return [], [index]

    legs = [_Leg(",".join([index, *(f"-{b}" for b in sorted(bad))]), "kind")]
    rescued = sorted(b for b in bad if keyword_everywhere or b in keyword_ok)
    if rescued:
        legs.append(_Leg(",".join(rescued), "kind.keyword"))
    left_out = sorted(b for b in bad if b not in rescued)
    return legs, left_out


def _bucket_counts(result: Any, kinds: list[str]) -> dict[str, int] | None:
    aggregations = getattr(result, "aggregations", None)
    if not isinstance(aggregations, dict):
        return None
    by_kind = aggregations.get("by_kind")
    if not isinstance(by_kind, dict):
        return None
    buckets = by_kind.get("buckets")
    if not isinstance(buckets, list):
        return None
    counts: dict[str, int] = {}
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        key = bucket.get("key")
        doc_count = bucket.get("doc_count")
        if isinstance(key, str) and key in kinds and isinstance(doc_count, int):
            counts[key] = counts.get(key, 0) + doc_count
    return counts


def _short(exc: BaseException) -> str:
    text = " ".join(str(exc).split())
    if len(text) > 200:
        text = text[:197] + "..."
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


async def audit_counts_with_reason(
    elastic: ElasticClient | None,
    audit_index_alias: str,
    kinds: list[str],
    *,
    days: int = 7,
) -> AuditCounts:
    """Count audit events per ``kind`` over the last ``days`` days, with a reason.

    Every failure returns ``None`` counts and a reason, never raises. A
    successful aggregation starts every requested kind at 0, so a kind with no
    bucket had zero events in the window.
    """
    if not kinds:
        return AuditCounts(counts={})
    if elastic is None:
        return _unknown(kinds, "soc-ai has no grid connection, so it cannot count audit records.")

    since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    pattern = f"{audit_index_alias}-*"
    legs, left_out = await _plan(elastic, pattern)
    if not legs:
        reason = (
            "Every audit index maps the type field as text with no keyword form, "
            "so the grid cannot count it."
        )
        _LOGGER.warning("audit count aggregation impossible: %s", reason)
        return _unknown(kinds, reason)

    totals: dict[str, int | None] = {k: 0 for k in kinds}
    for leg in legs:
        query = {
            "bool": {
                "filter": [
                    {"terms": {leg.field: kinds}},
                    {"range": {"timestamp": {"gte": since}}},
                ]
            }
        }
        # A `terms` agg sized to the number of kinds we asked for — the domain
        # is a fixed, tiny set (the egress kinds), so this never paginates.
        aggs = {"by_kind": {"terms": {"field": leg.field, "size": max(len(kinds), 1)}}}
        try:
            result = await elastic.search(leg.index, query, size=0, aggs=aggs)
        except Exception as exc:  # any transport/auth/index error → all-unknown
            _LOGGER.warning(
                "audit count aggregation failed on %s (returning unknown counts): %s",
                leg.index,
                exc,
            )
            return _unknown(kinds, f"The grid refused the audit count. {_short(exc)}")
        found = _bucket_counts(result, kinds)
        if found is None:
            _LOGGER.warning("audit count aggregation returned no buckets on %s", leg.index)
            return _unknown(kinds, "The grid answered the audit count with no buckets.")
        for key, value in found.items():
            totals[key] = (totals[key] or 0) + value

    note: str | None = None
    if left_out:
        note = (
            f"The count leaves out {len(left_out)} audit index(es) that map the type field "
            f"as text: {', '.join(left_out)}."
        )
        _LOGGER.warning("audit count %s", note)
    return AuditCounts(counts=totals, reason=note)


async def audit_counts_by_kind(
    elastic: ElasticClient | None,
    audit_index_alias: str,
    kinds: list[str],
    *,
    days: int = 7,
) -> dict[str, int | None]:
    """The counts of :func:`audit_counts_with_reason`, without the reason.

    The caller must treat ``None`` as "unknown", not "zero".
    """
    return (await audit_counts_with_reason(elastic, audit_index_alias, kinds, days=days)).counts
