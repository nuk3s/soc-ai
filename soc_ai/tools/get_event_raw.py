"""``get_event_raw`` — fetch a single event's full ``_source`` by ES ``_id``.

Useful when the agent needs detail that was omitted from a summary pivot
(e.g. full payload bytes, all zeek fields, raw suricata metadata).
"""

from __future__ import annotations

from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools._registry import tool
from soc_ai.tools._synth_scope import SynthScope, synth_scope_must_not


@tool(
    read_only=True,
    description="Fetch a single event's full raw _source document by ES _id.",
)
async def get_event_raw(
    event_id: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    include_synth: SynthScope = False,
) -> dict[str, Any]:
    """Return the full ``_source`` of the ES document with ``_id == event_id``.

    Use this when a pivot summary omitted a field you need (e.g. raw bytes,
    full zeek fields, suricata metadata).  For host characterisation prefer
    OQL queries; use this for single-event deep-dives.

    Args:
        event_id: The Elasticsearch ``_id`` of the event to fetch.
        elastic:  Injected ES client.
        settings: Injected app settings (provides ``events_index_pattern``).
        include_synth: synth-doc visibility (:data:`~soc_ai.tools._synth_scope.SynthScope`).
            False (the prod default): the fetch excludes every ``synth.scenario_id``
            doc, so a planted eval fixture can never be pulled by ``_id`` in
            production. A scenario id (batch eval): that scenario's plants are
            fetchable, siblings' are not. Threaded because ``logs-*`` ⊇
            ``logs-synth-*`` — a bare ``ids`` query would otherwise read a planted
            doc in prod, the gap the other ES readers already close.

    Returns:
        The document's ``_source`` dict, or
        ``{"error": "event not found", "event_id": event_id}`` when no
        document with that ``_id`` exists (or when it is out of synth scope).
    """
    query: dict[str, Any] = {"bool": {"must": [{"ids": {"values": [event_id]}}]}}
    if synth_must_not := synth_scope_must_not(include_synth):
        query["bool"]["must_not"] = synth_must_not
    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=1,
    )
    if not result.hits:
        return {"error": "event not found", "event_id": event_id}
    hit = result.hits[0]
    source: dict[str, Any] = hit.get("_source", {})
    return source
