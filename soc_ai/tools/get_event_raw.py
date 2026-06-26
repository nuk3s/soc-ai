"""``get_event_raw`` — fetch a single event's full ``_source`` by ES ``_id``.

Useful when the agent needs detail that was omitted from a summary pivot
(e.g. full payload bytes, all zeek fields, raw suricata metadata).
"""

from __future__ import annotations

from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools._registry import tool


@tool(
    read_only=True,
    description="Fetch a single event's full raw _source document by ES _id.",
)
async def get_event_raw(
    event_id: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
) -> dict[str, Any]:
    """Return the full ``_source`` of the ES document with ``_id == event_id``.

    Use this when a pivot summary omitted a field you need (e.g. raw bytes,
    full zeek fields, suricata metadata).  For host characterisation prefer
    OQL queries; use this for single-event deep-dives.

    Args:
        event_id: The Elasticsearch ``_id`` of the event to fetch.
        elastic:  Injected ES client.
        settings: Injected app settings (provides ``events_index_pattern``).

    Returns:
        The document's ``_source`` dict, or
        ``{"error": "event not found", "event_id": event_id}`` when no
        document with that ``_id`` exists.
    """
    result = await elastic.search(
        settings.events_index_pattern,
        {"ids": {"values": [event_id]}},
        size=1,
    )
    if not result.hits:
        return {"error": "event not found", "event_id": event_id}
    hit = result.hits[0]
    source: dict[str, Any] = hit.get("_source", {})
    return source
