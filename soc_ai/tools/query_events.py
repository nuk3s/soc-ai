"""``query_events_oql`` tool: validated OQL search against the SO events index.

This is the lowest-friction way for the agent to read events. It parses the OQL
string, validates against the field whitelist, translates to Elasticsearch DSL,
wraps with the requested time-range filter, and dispatches via
:class:`ElasticClient`.

The tool decorator + registration happen in step 5 of the v1 roadmap; this
module exposes a plain ``async def`` so step 5 can wrap it without restructuring.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.so_client.oql import (
    Count,
    GroupBy,
    Head,
    ast_to_es_dsl,
    parse_oql,
    validate_oql,
)
from soc_ai.tools._registry import tool


def _build_time_filter(
    time_range_minutes: int,
    time_anchor: datetime | None,
) -> dict[str, Any]:
    """Build an ES range filter on @timestamp.

    Two modes:

    - **Anchored** (preferred for batch eval): when ``time_anchor`` is the
      alert's ``@timestamp``, the window is centered on it as
      ``[anchor - half, anchor + half]`` where ``half = time_range_minutes / 2``.
      Most batch-eval alerts are minutes-to-days old; "last N minutes
      from now" returns empty and burns retask rounds.
    - **Now-relative** (legacy): when ``time_anchor`` is None, falls back
      to the original ``[now - time_range_minutes, now]``. Live-monitoring
      callers (CLI / WebUI) should keep this default; the orchestrator's
      tool wrappers anchor on the alert.
    """
    if time_anchor is not None:
        half = timedelta(minutes=time_range_minutes / 2)
        gte = (time_anchor - half).isoformat()
        lte = (time_anchor + half).isoformat()
        return {"range": {"@timestamp": {"gte": gte, "lte": lte}}}
    return {
        "range": {
            "@timestamp": {
                "gte": f"now-{time_range_minutes}m",
                "lte": "now",
            }
        }
    }


@tool(
    read_only=True,
    description="Run a validated OQL query against the SO events index.",
)
async def query_events_oql(
    query: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    time_range_minutes: int = 1440,
    max_results: int = 100,
    time_anchor: datetime | None = None,
    include_synth: bool = False,
) -> EsSearchResult:
    """Run a validated OQL query against ``settings.events_index_pattern``.

    Args:
        query: The OQL query string. May include pipe stages (``groupby``,
            ``sortby``, ``head``, ``count``).
        elastic: An :class:`ElasticClient` for dispatching to the SO ES cluster.
        settings: The application :class:`Settings` (used for the index pattern).
        time_range_minutes: Window size in minutes. Default 1440 = 24h.
        max_results: Hard cap on returned hits (or ``head N`` limit). The
            validator rejects ``head`` stages that exceed this value.
        time_anchor: When set, center the window on this timestamp
            (``[anchor - rng/2, anchor + rng/2]``) instead of the now-relative
            default. The orchestrator passes ``alert.timestamp`` here so
            batch-eval queries actually find evidence; CLI/WebUI callers
            usually leave it ``None`` for live monitoring.

    Returns:
        An :class:`EsSearchResult`. For ``groupby`` queries the response holds
        the bucketed aggregation under :attr:`EsSearchResult.aggregations` and
        :attr:`hits` is empty; for plain queries, ``hits`` carries the
        documents and ``aggregations`` is ``None``.
    """
    if time_range_minutes <= 0:
        raise ValueError(f"time_range_minutes must be positive, got {time_range_minutes}")

    ast = parse_oql(query)
    validate_oql(ast, max_results=max_results)
    body = ast_to_es_dsl(ast, default_size=max_results)

    time_filter = _build_time_filter(time_range_minutes, time_anchor)
    wrapped_bool: dict[str, Any] = {
        "must": [body["query"]],
        "filter": [time_filter],
    }
    # Synthetic-eval kill-switch: by default, every OQL query excludes docs
    # tagged with synth.scenario_id, so synth-TP fixtures cannot leak
    # into prod responses or the eval sampler's view of "real" alerts.
    # Callers triaging a synth alert can opt in with include_synth=True.
    if not include_synth:
        wrapped_bool["must_not"] = [{"exists": {"field": "synth.scenario_id"}}]
    wrapped_query = {"bool": wrapped_bool}

    # Groupby/Count queries set size=0; preserve that.
    has_aggregating_stage = any(isinstance(s, GroupBy | Count) for s in ast.pipes)
    has_head = any(isinstance(s, Head) for s in ast.pipes)
    effective_size = body.get("size", max_results)
    if not has_aggregating_stage and not has_head:
        effective_size = min(effective_size, max_results)

    return await elastic.search(
        settings.events_index_pattern,
        wrapped_query,
        size=effective_size,
        sort=body.get("sort"),
        aggs=body.get("aggs"),
        track_total_hits=body.get("track_total_hits"),
    )
