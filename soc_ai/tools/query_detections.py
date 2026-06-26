"""``query_detections`` tool - search SOC detection rules."""

from __future__ import annotations

from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoDetection
from soc_ai.tools._registry import tool


@tool(read_only=True, description="Search SOC detection rules by free-text query.")
async def query_detections(
    query: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    max_results: int = 25,
) -> list[SoDetection]:
    """Full-text search across detection titles, public IDs, authors, and tags.

    Args:
        query: free-text search. ``"*"`` matches every detection.
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``detections_index_pattern``).
        max_results: hard cap on returned detections.
    """
    if max_results <= 0:
        raise ValueError(f"max_results must be positive, got {max_results}")

    if query and query.strip() and query.strip() != "*":
        es_query: dict[str, Any] = {
            "multi_match": {
                "query": query,
                "fields": ["title", "publicId", "author", "tags"],
            }
        }
    else:
        es_query = {"match_all": {}}

    result = await elastic.search(
        settings.detections_index_pattern,
        es_query,
        size=max_results,
    )
    return [SoDetection.from_so_doc(h.get("_source", {})) for h in result.hits]
