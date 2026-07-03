"""On-demand grid-discovery tools for the agent.

Complements the ambient dataset inventory (:mod:`soc_ai.so_client.inventory`) with
drill-down the agent calls when it needs it — dataset-agnostic, so they work for
host logs (endpoint/windows/sysmon) exactly as they do for zeek/suricata:

- :func:`describe_dataset` — sample recent docs of ANY dataset and report the
  fields actually POPULATED on it (+ an example value + coverage). This is how the
  agent learns "what fields does zeek.ssh / endpoint / windows.security have"
  without a static schema.
- :func:`field_values` — a terms aggregation: the top values a field takes
  (optionally within one dataset). "Which rule.names fire", "which host.names exist".

Both are read-only metadata over ``settings.events_index_pattern`` and best-effort
(an ES error returns a structured ``error`` result, never raises into the agent).
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)

_SAMPLE_SIZE = 40
_MAX_FIELDS = 100
_EXAMPLE_CLIP = 120


def _clip(value: Any) -> Any:
    """Truncate a long scalar example so a describe result stays compact."""
    if isinstance(value, str) and len(value) > _EXAMPLE_CLIP:
        return value[:_EXAMPLE_CLIP] + "…"
    return value


def _flatten(obj: Any, prefix: str = "") -> Any:
    """Yield ``(dotted_path, scalar)`` leaves of a doc ``_source``.

    Handles both nested (``{"event": {"dataset": …}}``) and flat-dotted
    (``{"event.dataset": …}``) layouts — a flat-dotted key is already a path, a
    nested dict is descended. Lists contribute their first scalar (or the first
    dict element is flattened) so an example value is available without exploding.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            yield from _flatten(v, path)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, dict):
                yield from _flatten(v, prefix)
                break
            if v not in (None, ""):
                yield (prefix, v)
                break
    elif prefix and obj not in (None, ""):
        yield (prefix, obj)


async def describe_dataset(
    dataset: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    sample_size: int = _SAMPLE_SIZE,
) -> dict[str, Any]:
    """Sample recent docs of ``dataset`` and report its POPULATED fields.

    Returns ``{dataset, sampled, fields:[{field, coverage, example}]}`` sorted by
    how many of the sampled docs carry each field (most-common first)."""
    ds = str(dataset).strip()
    if not ds:
        return {"error": True, "reason": "empty dataset name"}
    query: dict[str, Any] = {"bool": {"filter": [{"term": {"event.dataset": ds}}]}}
    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=max(1, min(sample_size, 100)),
            sort=[{"@timestamp": {"order": "desc"}}],
        )
    except Exception as exc:
        _LOGGER.warning("describe_dataset(%s) failed: %s", ds, exc)
        return {"error": True, "type": type(exc).__name__, "message": str(exc)}

    if not result.hits:
        return {
            "dataset": ds,
            "sampled": 0,
            "fields": [],
            "note": (
                f"no documents for event.dataset:{ds} — check the exact name against "
                "the auto-discovered grid inventory (a dataset that isn't listed there "
                "has no data on this grid)."
            ),
        }

    prevalence: Counter[str] = Counter()
    example: dict[str, Any] = {}
    for h in result.hits:
        src = h.get("_source", {}) or {}
        seen: set[str] = set()
        for path, val in _flatten(src):
            if path in seen:
                continue
            seen.add(path)
            prevalence[path] += 1
            example.setdefault(path, val)

    n = len(result.hits)
    ranked = sorted(prevalence.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_FIELDS]
    return {
        "dataset": ds,
        "sampled": n,
        "fields": [
            {"field": p, "coverage": f"{cnt}/{n}", "example": _clip(example[p])}
            for p, cnt in ranked
        ],
    }


async def field_values(
    field: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    dataset: str | None = None,
    size: int = 25,
    window_minutes: int = 1440,
) -> dict[str, Any]:
    """Top values of ``field`` (a terms aggregation), optionally within ``dataset``.

    Returns ``{field, dataset, values:[{value, count}]}`` newest-window, most-common
    first. Use this to learn what actually populates a field before querying on it."""
    f = str(field).strip()
    if not f:
        return {"error": True, "reason": "empty field name"}
    filters: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}}]
    if dataset:
        filters.append({"term": {"event.dataset": str(dataset).strip()}})
    query: dict[str, Any] = {"bool": {"filter": filters}}
    aggs: dict[str, Any] = {"vals": {"terms": {"field": f, "size": max(1, min(size, 100))}}}
    try:
        result = await elastic.search(settings.events_index_pattern, query, size=0, aggs=aggs)
    except Exception as exc:
        _LOGGER.warning("field_values(%s) failed: %s", f, exc)
        return {
            "error": True,
            "type": type(exc).__name__,
            "message": str(exc),
            "hint": (
                "the field may be text (not aggregatable) or unknown — run "
                "t_describe_dataset first to see the exact populated field names."
            ),
        }
    buckets = ((result.aggregations or {}).get("vals") or {}).get("buckets") or []
    return {
        "field": f,
        "dataset": dataset,
        "values": [{"value": b.get("key"), "count": b.get("doc_count")} for b in buckets],
    }


__all__ = ["describe_dataset", "field_values"]
