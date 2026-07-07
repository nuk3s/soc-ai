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
        # Both doc shapes. Live SO 3.x nests fields under `so_detection.*` and
        # maps the metadata as KEYWORD (exact-value only — a multi_match never
        # hits a substring), so those need case-insensitive wildcards; the rule
        # body `so_detection.content` is text-mapped and full-text searchable.
        # Flat paths keep older docs (and the SO /connect API shape) working.
        q = query.strip()
        es_query: dict[str, Any] = {
            "bool": {
                "should": [
                    {
                        "multi_match": {
                            "query": q,
                            "fields": [
                                "title",
                                "publicId",
                                "author",
                                "tags",
                                "so_detection.content",
                            ],
                        }
                    },
                    {
                        "wildcard": {
                            "so_detection.title": {"value": f"*{q}*", "case_insensitive": True}
                        }
                    },
                    {"term": {"so_detection.publicId": q}},
                    {
                        "wildcard": {
                            "so_detection.author": {"value": f"*{q}*", "case_insensitive": True}
                        }
                    },
                ],
                "minimum_should_match": 1,
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
