"""One document from the grid, by id.

An evidence id on a lead, a shadow hit or a hunt finding opens here. The route
reads the document the same way the agent's ``get_event_raw`` tool does.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, Request
from pydantic import BaseModel

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import router
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.get_event_raw import get_event_raw


class EventDocumentOut(BaseModel):
    id: str
    dataset: str | None = None
    timestamp: str | None = None
    source: dict[str, Any]


def _get(source: dict[str, Any], *path: str) -> Any:
    node: Any = source
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


@router.get("/events/{event_id}", response_model=EventDocumentOut)
async def get_event(
    request: Request,
    event_id: str,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> EventDocumentOut:
    """The full source of one document. 404 if the grid does not hold it."""
    source = await get_event_raw(event_id, elastic=elastic, settings=settings)
    if not isinstance(source, dict) or source.get("error") == "event not found":
        raise api_error(
            404,
            "event_not_found",
            f"The grid holds no document with id {event_id}. It may have aged out.",
        )
    dataset = _get(source, "event", "dataset") or _get(source, "data_stream", "dataset")
    return EventDocumentOut(
        id=event_id,
        dataset=str(dataset) if dataset else None,
        timestamp=str(source.get("@timestamp")) if source.get("@timestamp") else None,
        source=source,
    )
