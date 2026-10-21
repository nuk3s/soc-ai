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

import asyncio
import logging
from typing import Any
from urllib.parse import quote

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)

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


# The most cases one alert lists. An alert on more cases than this is a case
# queue problem, and the card names the first ones.
MAX_CASES_PER_ALERT = 20


async def all_case_ids_for_alert(
    elastic: ElasticClient,
    settings: Settings,
    alert_id: str,
    *,
    limit: int = MAX_CASES_PER_ALERT,
) -> list[str]:
    """Every case Security Onion has ``alert_id`` on, earliest first.

    :func:`case_ids_for_alerts` answers with the earliest case of each alert,
    because a press decides on the first link. The action card names every
    case of one alert: the alert of the range was on two cases, and the card
    must link both (dogfood 2026-10-20, V3-N2). A second attach to the same
    case is one case.

    ``require_complete`` as above: a partial read raises, and the caller
    treats the failure as unknown.
    """
    if not alert_id:
        return []
    query: dict[str, Any] = {
        "bool": {
            "filter": [
                {"term": {"so_kind": _RELATED_KIND}},
                {"term": {_SOC_ID_FIELD: alert_id}},
            ]
        }
    }
    result = await elastic.search(
        settings.cases_index_pattern,
        query,
        size=limit,
        sort=[{_CREATE_TIME_FIELD: {"order": "asc"}}],
        source=[_CASE_ID_FIELD],
        require_complete=True,
    )
    out: list[str] = []
    for hit in result.hits:
        related = (hit.get("_source") or {}).get("so_related") or {}
        case_id = str(related.get("caseId") or "")
        if case_id and case_id not in out:
            out.append(case_id)
    return out


async def cases_of_alert(
    db_sessionmaker: Any,
    elastic: ElasticClient,
    settings: Settings,
    alert_id: str,
) -> tuple[list[str], bool]:
    """The cases ``alert_id`` is on, and whether Security Onion confirmed the list.

    The two sources of the duplicate-case guard of the execute route, in its
    order: soc-ai's escalation ledger, then the case links of Security Onion.
    The ledger is a store read and cannot lag. The grid read is bounded by
    ``webui_grid_timeout_s``. A failed grid read leaves the ledger case alone,
    and the list is then not confirmed. Best-effort: a failure of both reads
    answers an empty list, and the console then names no case.
    """
    from soc_ai.store import escalations as esc_svc  # noqa: PLC0415 - light import

    if not alert_id:
        return [], False
    ledger: str | None = None
    try:
        async with db_sessionmaker() as db:
            ledger = (await esc_svc.cases_for_alerts(db, [alert_id])).get(alert_id)
    except Exception:
        _LOGGER.warning("case links: the escalation ledger could not be read", exc_info=True)
    ids: list[str] = []
    complete = False
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            ids = await all_case_ids_for_alert(elastic, settings, alert_id)
        complete = len(ids) < MAX_CASES_PER_ALERT
    except Exception as exc:
        _LOGGER.info("case links: the grid was not read (%s)", type(exc).__name__)
    if ledger and ledger not in ids:
        ids = [ledger, *ids]
    return ids, complete


def case_url(settings: Settings, case_id: str) -> str | None:
    """The case in Security Onion's console, built from ``so_host``.

    ``None`` when the settings name no host to build it from. The same form
    the escalate answer carries.
    """
    host = str(settings.so_host or "").rstrip("/")
    if not host or not case_id:
        return None
    return f"{host}/#/case/{quote(case_id, safe='')}"
