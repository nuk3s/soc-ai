"""``query_cases`` tool - search SOC cases."""

from __future__ import annotations

from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoCase
from soc_ai.tools._registry import tool


@tool(read_only=True, description="Search SOC cases by free-text query.")
async def query_cases(
    query: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    status: str | None = None,
    max_results: int = 25,
) -> list[SoCase]:
    """Full-text search across case titles, descriptions, and tags.

    Args:
        query: free-text search. Pass ``"*"`` to match everything (then optionally
            constrain by ``status``).
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``cases_index_pattern``).
        status: optional exact-match status filter (e.g. ``"new"``, ``"in progress"``,
            ``"closed"``).
        max_results: hard cap on returned cases.
    """
    if max_results <= 0:
        raise ValueError(f"max_results must be positive, got {max_results}")

    must: list[dict[str, Any]] = []
    if query and query.strip() and query.strip() != "*":
        must.append(
            {
                "multi_match": {
                    "query": query,
                    "fields": ["title", "description", "tags"],
                }
            }
        )
    if status:
        must.append({"term": {"status": status}})

    es_query: dict[str, Any] = {"bool": {"must": must}} if must else {"match_all": {}}

    # SO 3.0.0's `so-case-*` mapping only carries `@timestamp` for case docs;
    # earlier code used `updateTime` which doesn't exist on this grid and
    # caused a search_phase_execution_exception that crashed the agent run.
    # Use `@timestamp` and tolerate docs without it via unmapped_type.
    result = await elastic.search(
        settings.cases_index_pattern,
        es_query,
        size=max_results,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    )
    return [SoCase.from_so_doc(h.get("_source", {})) for h in result.hits]
