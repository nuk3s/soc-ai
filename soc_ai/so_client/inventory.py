"""Runtime discovery of what's actually in the SO events index.

The agent should DISCOVER the grid's contents, never work from a hardcoded list —
that's exactly what blinded a hunt to ``zeek.ssh``. A terms aggregation over
``event.dataset`` finds whatever is present: a network-only deployment shows
``suricata.alert`` / ``zeek.*``; the moment host logging lands (``endpoint`` /
``windows.*`` / ``sysmon`` / ``osquery`` / ``system.auth`` …) those datasets appear
here too, with ZERO code changes. ``event.category`` is rolled up alongside so the
agent can see network-vs-host-vs-process-vs-authentication data at a glance.

Cheap (one ``size=0`` metadata query), TTL-cached per index pattern, and rendered
into an ambient prompt block so every OQL-running agent starts knowing the terrain.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)

# Datasets/fields don't change minute-to-minute; cache the inventory per index
# pattern so we don't re-aggregate on every hunt/investigation/chat turn.
_TTL_SECONDS = 300.0
_MAX_DATASETS = 120  # generous cap — a busy grid has dozens of datasets, not hundreds


@dataclass(frozen=True)
class DatasetInfo:
    """One ``event.dataset`` present in the grid + how much / how recent."""

    dataset: str
    count: int
    last_seen_ms: int | None
    categories: tuple[str, ...]  # event.category values seen (network/host/process/…)


@dataclass(frozen=True)
class GridInventory:
    """The datasets discovered in the events index, most-populated first."""

    datasets: tuple[DatasetInfo, ...]
    window_minutes: int
    total_events: int

    def dataset_names(self) -> tuple[str, ...]:
        return tuple(d.dataset for d in self.datasets)


# (index, window) -> (monotonic_deadline, inventory)
_CACHE: dict[tuple[str, int], tuple[float, GridInventory]] = {}


def _clear_cache() -> None:
    """Test hook."""
    _CACHE.clear()


async def discover_datasets(
    elastic: ElasticClient,
    settings: Settings,
    *,
    window_minutes: int = 1440,
    ttl_seconds: float = _TTL_SECONDS,
) -> GridInventory:
    """Aggregate ``event.dataset`` (+ count, newest event, ``event.category``) over
    the events index for the last ``window_minutes``. TTL-cached.

    Best-effort: any ES error returns an EMPTY inventory rather than raising — the
    ambient block is additive, and a discovery failure must never break triage.
    """
    index = settings.events_index_pattern
    key = (index, window_minutes)
    now = time.monotonic()
    cached = _CACHE.get(key)
    if cached is not None and now < cached[0]:
        return cached[1]

    query: dict[str, Any] = {
        "bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}}]}
    }
    aggs: dict[str, Any] = {
        "datasets": {
            "terms": {"field": "event.dataset", "size": _MAX_DATASETS, "order": {"_count": "desc"}},
            "aggs": {
                "last_seen": {"max": {"field": "@timestamp"}},
                "categories": {"terms": {"field": "event.category", "size": 6}},
            },
        }
    }
    try:
        result = await elastic.search(index, query, size=0, aggs=aggs, track_total_hits=True)
    except Exception as exc:
        _LOGGER.warning("dataset discovery failed on %s: %s", index, exc)
        return GridInventory(datasets=(), window_minutes=window_minutes, total_events=0)

    buckets = ((result.aggregations or {}).get("datasets") or {}).get("buckets") or []
    infos: list[DatasetInfo] = []
    for b in buckets:
        ds = b.get("key")
        if not isinstance(ds, str) or not ds:
            continue
        cats = tuple(
            str(c.get("key"))
            for c in (((b.get("categories") or {}).get("buckets")) or [])
            if c.get("key")
        )
        last = (b.get("last_seen") or {}).get("value")
        infos.append(
            DatasetInfo(
                dataset=ds,
                count=int(b.get("doc_count") or 0),
                last_seen_ms=int(last) if isinstance(last, (int, float)) else None,
                categories=cats,
            )
        )

    inv = GridInventory(
        datasets=tuple(infos),
        window_minutes=window_minutes,
        total_events=result.total,
    )
    _CACHE[key] = (now + ttl_seconds, inv)
    return inv


def _humanize_count(n: int) -> str:
    """1234567 -> '1.2M', 9400 -> '9.4k', 42 -> '42'."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M".replace(".0M", "M")
    if n >= 1_000:
        return f"{n / 1_000:.1f}k".replace(".0k", "k")
    return str(n)


def _ago_from_ms(ms: int | None) -> str:
    """Epoch-millis -> short relative label ('now', '3m', '2h', '5d')."""
    if ms is None:
        return "?"
    secs = datetime.now(UTC).timestamp() - ms / 1000.0
    if secs < 60:
        return "now"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


def format_inventory_block(inv: GridInventory) -> str:
    """Render the discovered datasets as an ambient prompt block. Empty string when
    nothing was discovered (so callers can append unconditionally)."""
    if not inv.datasets:
        return ""
    hrs = inv.window_minutes // 60
    window = f"{hrs}h" if hrs else f"{inv.window_minutes}m"
    lines = [
        "## Data available on this grid (auto-discovered)",
        f"The events index currently holds these datasets (count · newest event, "
        f"last {window}). This is the GROUND TRUTH for what data exists here — a "
        f"network-only grid shows suricata/zeek, a host-logging grid also shows "
        f"endpoint/windows/sysmon/etc. Query any of them with `event.dataset:<name>`, "
        f"and NEVER conclude a data type is absent without querying its dataset:",
    ]
    for d in inv.datasets:
        cat = f"  [{'/'.join(d.categories)}]" if d.categories else ""
        lines.append(
            f"- `{d.dataset}` — {_humanize_count(d.count)} · {_ago_from_ms(d.last_seen_ms)}{cat}"
        )
    return "\n".join(lines)


async def inventory_prompt_block(
    elastic: ElasticClient, settings: Settings, *, window_minutes: int = 1440
) -> str:
    """Discover + format in one call, returning '' on any failure. The block is
    prefixed with a blank line so it appends cleanly to a system/user prompt."""
    try:
        inv = await discover_datasets(elastic, settings, window_minutes=window_minutes)
    except Exception as exc:
        _LOGGER.warning("inventory_prompt_block failed: %s", exc)
        return ""
    block = format_inventory_block(inv)
    return f"\n\n{block}" if block else ""


__all__ = [
    "DatasetInfo",
    "GridInventory",
    "discover_datasets",
    "format_inventory_block",
    "inventory_prompt_block",
]
