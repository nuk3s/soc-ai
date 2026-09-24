"""Which alerts Security Onion already has on a case.

Attaching an alert to a case writes a ``related`` document on Security Onion's
own case index carrying the alert's ES ``_id`` as ``so_related.fields.soc_id``.
That document is the grid's record of the link, and unlike ``event.escalated``
it is written on every attach, on every index, by every producer: soc-ai, the
Security Onion console, and any other instance pointed at the same grid.

Measured on a live SO 3.2.0 grid on 2026-09-06: a term query on
``so_related.fields.soc_id`` over ``so-case`` returned the four cases an
endpoint alert had accumulated, keyed by the alert id, in a few milliseconds.

It is the broadest answer available but not the fastest one, and it is a read,
so it lags: a case opened a second earlier may not be visible yet. It belongs
BEHIND soc-ai's own escalation ledger, which is written in the same transaction
that claims the alert and therefore cannot lag at all. This module answers
"has anyone put this alert on a case", not "may I open one".
"""

from __future__ import annotations

from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient

# Security Onion's case index holds several document shapes under ``so_kind``;
# ``related`` is the alert-to-case link. ``artifact`` and ``comment`` live
# alongside it and would otherwise be scanned for nothing.
_RELATED_KIND = "related"
_SOC_ID_FIELD = "so_related.fields.soc_id"
_CASE_ID_FIELD = "so_related.caseId"
_CREATE_TIME_FIELD = "so_related.createTime"

# One lookup asks about at most a group escalate's worth of alerts. Larger
# callers should page; a terms clause is not a scan target.
MAX_LOOKUP_IDS = 200


async def case_ids_for_alerts(
    elastic: ElasticClient,
    settings: Settings,
    alert_ids: list[str],
) -> dict[str, str]:
    """Map each of ``alert_ids`` that is already on a case to that case's id.

    An alert absent from the result has no link document the grid could show.
    When an alert is on several cases the earliest is returned, so the answer
    does not change under a later duplicate.

    ``require_complete`` is deliberate. The caller uses absence to decide it may
    open a case, and a degraded search returning no hits from the surviving
    shards is "could not see", never "no case exists". A partial read raises
    rather than answering, and the caller treats the failure as unknown.
    """
    ids = [i for i in dict.fromkeys(alert_ids) if i][:MAX_LOOKUP_IDS]
    if not ids:
        return {}
    query: dict[str, Any] = {
        "bool": {
            "filter": [
                {"term": {"so_kind": _RELATED_KIND}},
                {"terms": {_SOC_ID_FIELD: ids}},
            ]
        }
    }
    # One bucket per alert with its earliest link, rather than a flat hit list:
    # an alert that already collected several cases would otherwise fill the
    # page and hide the answer for the alerts after it.
    aggs: dict[str, Any] = {
        "by_alert": {
            "terms": {"field": _SOC_ID_FIELD, "size": len(ids)},
            "aggs": {
                "first_case": {
                    "top_hits": {
                        "size": 1,
                        "_source": [_CASE_ID_FIELD],
                        "sort": [{_CREATE_TIME_FIELD: {"order": "asc"}}],
                    }
                }
            },
        }
    }
    result = await elastic.search(
        settings.cases_index_pattern,
        query,
        size=0,
        aggs=aggs,
        require_complete=True,
    )
    buckets = ((result.aggregations or {}).get("by_alert") or {}).get("buckets") or []
    links: dict[str, str] = {}
    for bucket in buckets:
        alert_id = str(bucket.get("key") or "")
        hits = (((bucket.get("first_case") or {}).get("hits") or {}).get("hits")) or []
        if not alert_id or not hits:
            continue
        related = (hits[0].get("_source") or {}).get("so_related") or {}
        case_id = str(related.get("caseId") or "")
        if case_id:
            links[alert_id] = case_id
    return links
