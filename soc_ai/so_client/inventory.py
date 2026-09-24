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

**Live telemetry and imports are counted apart.** A grid holds what its sensors
saw and, separately, whatever ``so-import-pcap`` / ``so-import-evtx`` or a
replayed corpus put there. Both are real; only one of them tells you a sensor is
alive. Counting them together made the census report a network intrusion sensor
as five hours stale when it had been dead for three days, because the newest
document under ``suricata.alert`` was an imported one. Every recency and volume
figure here is measured over live telemetry alone (see
:mod:`soc_ai.tools._provenance`), and imported documents are reported beside it
as a labelled plane rather than dropped: a grid that genuinely holds imported
evidence is a real situation, and hiding it is its own kind of lie.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import DATASET_NAME_FIELDS
from soc_ai.tools._provenance import LIVE, provenance_must_not
from soc_ai.tools._synth_scope import synth_scope_must_not

_LOGGER = logging.getLogger(__name__)

# Datasets/fields don't change minute-to-minute; cache the inventory per index
# pattern so we don't re-aggregate on every hunt/investigation/chat turn.
_TTL_SECONDS = 300.0
_MAX_DATASETS = 120  # generous cap — a busy grid has dozens of datasets, not hundreds


@dataclass(frozen=True)
class DatasetInfo:
    """One dataset present in the grid + how much of it is live, and how recent.

    ``live_count`` and ``last_seen_ms`` describe this grid's own sensors.
    ``imported_count`` is the same dataset's backfill: documents carrying an
    import identifier or a replay tag. A dataset with ``live_count == 0`` and a
    non-zero ``imported_count`` is present on the grid and queryable, and no
    sensor here is producing it.

    ``last_seen_ms`` is the newest LIVE document, so it is ``None`` for an
    import-only plane. It deliberately cannot be satisfied by an import, which
    is the whole reason the split exists.

    ``identity_field`` is the field the census found this dataset under, and it
    is carried rather than inferred because only the census knows: the two
    terms aggregations partition the index, and by the time a row reaches a
    renderer or a tool the evidence is gone. Guessing it downstream produces
    the same predicate for every row, which is wrong for whichever shape the
    guess does not assume.
    """

    dataset: str
    live_count: int
    last_seen_ms: int | None
    categories: tuple[str, ...]  # event.category values seen (network/host/process/…)
    imported_count: int = 0
    identity_field: str = DATASET_NAME_FIELDS[0]

    @property
    def predicate(self) -> str:
        """The query that selects this dataset, e.g. ``event.dataset:zeek.conn``.

        Built in one place so the ambient prompt block and any tool taking a
        dataset name cannot drift apart on which field names a given plane.
        """
        return f"{self.identity_field}:{self.dataset}"


@dataclass(frozen=True)
class GridInventory:
    """The datasets discovered in the events index, most-populated first.

    "Most populated" means most LIVE documents. Ranking on the grand total would
    let one imported file outrank every sensor on the grid, which on the
    measured grid was 18.8 million documents of somebody else's Windows event
    log sitting above every live plane.
    """

    datasets: tuple[DatasetInfo, ...]
    window_minutes: int
    live_events: int
    imported_events: int = 0

    @property
    def total_events(self) -> int:
        """Every document the census counted in the window, imports included."""
        return self.live_events + self.imported_events

    def dataset_names(self) -> tuple[str, ...]:
        """Every dataset on the grid, backfill included. Presence, not liveness."""
        return tuple(d.dataset for d in self.datasets)

    def live_dataset_names(self) -> tuple[str, ...]:
        """Only the datasets a sensor here is still producing.

        For anything that reasons over a POPULATION rather than about one
        document an analyst is already holding. A host dossier built over an
        import-only plane resolves that host against whatever the import
        contains, which is somebody else's network.
        """
        return tuple(d.dataset for d in self.datasets if d.live_count)


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

    RAISES on an ES failure — it does not return an empty inventory. An empty
    ``GridInventory`` is a claim about the estate ("this grid carries no DNS,
    endpoint or network telemetry"); an outage is a claim about the read. They
    are not the same sentence, and swallowing the error made the console tell
    analysts the first one whenever the second was true.

    Every caller fails soft on its own terms and needs the error to do it: the
    hunt-template route returns ``None`` so every template reports available,
    the dossier reads an empty frozenset as "unknown, not nothing", and
    :func:`inventory_prompt_block` drops the ambient block rather than telling
    the model the grid is empty.
    """
    index = settings.events_index_pattern
    key = (index, window_minutes)
    now = time.monotonic()
    cached = _CACHE.get(key)
    if cached is not None and now < cached[0]:
        return cached[1]

    query: dict[str, Any] = {
        "bool": {
            "filter": [{"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}}],
            # Synthetic-eval kill-switch, UNCONDITIONAL here: the inventory
            # feeds only analyst surfaces (hunt-template availability, ambient
            # prompt blocks, dossiers), and this TTL cache is shared across all
            # of them — an opt-in would let one caller's synth-inclusive read
            # be served to the rest for ttl_seconds. A live eval batch must
            # never inflate the dataset list or its counts; eval-mode reads of
            # planted docs go through the per-call ``include_synth`` opt-ins on
            # the query tools instead.
            "must_not": list(synth_scope_must_not(False)),
        }
    }
    # The live/imported split lives in the AGGREGATIONS, not on the query above.
    # On the query it would delete imports from the census, and the grid would
    # lose the ability to say it holds them at all: an analyst looking at a
    # dataset that is 100% backfill would see nothing where there is something.
    # Here the bucket totals keep counting every document while every liveness
    # figure is measured over sensor telemetry alone.
    _live_filter: dict[str, Any] = {"bool": {"must_not": provenance_must_not(LIVE)}}
    _sub_aggs: dict[str, Any] = {
        "categories": {"terms": {"field": "event.category", "size": 6}},
        # ``last_seen`` sits INSIDE the live filter on purpose. A bucket-level
        # max over @timestamp is what reported a three-day-dead Suricata sensor
        # as five hours stale: the newest document under that dataset had an
        # import marker and a file path under an import directory.
        "live": {
            "filter": _live_filter,
            "aggs": {"last_seen": {"max": {"field": "@timestamp"}}},
        },
    }
    aggs: dict[str, Any] = {
        # The window's live total, for the same reason the per-dataset one
        # exists: at 48h on the measured grid 91.3% of every document was
        # backfill, and a "total events" that counts it describes a corpus.
        "live_events": {"filter": _live_filter},
        "datasets": {
            "terms": {"field": "event.dataset", "size": _MAX_DATASETS, "order": {"_count": "desc"}},
            "aggs": _sub_aggs,
        },
        # A second census over documents that carry NO ``event.dataset``.
        # Elastic Agent integrations shipping through a data stream may put the
        # plane only in ``data_stream.dataset``: on the development grid 632,523
        # documents are in that shape and every one of them has it, including
        # the flow, DNS, TLS and HTTP telemetry from the only sensor watching
        # the live range VLANs.
        #
        # Without this the agent was handed a "data available on this grid"
        # block that omitted them — told the planes do not exist while being
        # able to query them.
        #
        # Scoped by ``must_not exists event.dataset`` rather than merged after
        # the fact, so a document counted in one census can never be counted in
        # the other and the totals stay exact.
        "datasets_by_stream": {
            "filter": {"bool": {"must_not": [{"exists": {"field": "event.dataset"}}]}},
            "aggs": {
                "datasets": {
                    "terms": {
                        "field": "data_stream.dataset",
                        "size": _MAX_DATASETS,
                        "order": {"_count": "desc"},
                    },
                    "aggs": _sub_aggs,
                }
            },
        },
    }
    try:
        result = await elastic.search(index, query, size=0, aggs=aggs, track_total_hits=True)
    except Exception as exc:
        # Logged here (the index pattern is only known here), then re-raised so
        # the caller can tell an outage from an empty grid. Nothing is cached:
        # the next call re-reads rather than serving a phantom empty inventory.
        _LOGGER.warning("dataset discovery failed on %s: %s", index, exc)
        raise

    aggregations = result.aggregations or {}
    event_field, stream_field = DATASET_NAME_FIELDS
    # Each bucket is tagged with the field whose aggregation produced it, here
    # and nowhere else. This is the only point in the program that still knows,
    # because the two censuses are merged into one ranked list on the next
    # statement and a merged row carries no trace of which one it came from.
    buckets: list[tuple[str, dict[str, Any]]] = [
        (event_field, b) for b in ((aggregations.get("datasets") or {}).get("buckets") or [])
    ]
    buckets += [
        (stream_field, b)
        for b in (
            (((aggregations.get("datasets_by_stream") or {}).get("datasets")) or {}).get("buckets")
            or []
        )
    ]
    infos: list[DatasetInfo] = []
    for identity_field, b in buckets:
        ds = b.get("key")
        if not isinstance(ds, str) or not ds:
            continue
        cats = tuple(
            str(c.get("key"))
            for c in (((b.get("categories") or {}).get("buckets")) or [])
            if c.get("key")
        )
        # A missing ``live`` sub-aggregation means the read could not tell live
        # telemetry from backfill, and the honest reading of that is "no live
        # telemetry measured here", not "all of it is live". The wrong direction
        # is the one that reports a dead sensor as healthy.
        live_bucket = b.get("live") or {}
        live_count = int(live_bucket.get("doc_count") or 0)
        total = int(b.get("doc_count") or 0)
        last = (live_bucket.get("last_seen") or {}).get("value")
        infos.append(
            DatasetInfo(
                dataset=ds,
                live_count=live_count,
                last_seen_ms=int(last) if isinstance(last, (int, float)) else None,
                categories=cats,
                imported_count=max(0, total - live_count),
                identity_field=identity_field,
            )
        )

    # Rank across BOTH censuses. The terms aggregations each come back ordered
    # by count, but they are two separate orderings: appending the
    # ``data_stream.dataset`` fallback to the end of the ``event.dataset``
    # census put the largest plane on the measured grid at position 32, below a
    # dataset holding two documents. That plane was 39% of every document there
    # and the only surviving network-metadata sensor. ``GridInventory`` documents itself
    # as most-populated-first and the prompt block renders it as a ranked list,
    # so the rank has to be one list, not two concatenated. Ties break on the
    # imported volume and then on the name, so the order is stable between reads
    # of an unchanged grid and an import-only plane sinks below every sensor.
    infos.sort(key=lambda d: (-d.live_count, -d.imported_count, d.dataset))

    live_events = int(((aggregations.get("live_events") or {}).get("doc_count")) or 0)
    inv = GridInventory(
        datasets=tuple(infos),
        window_minutes=window_minutes,
        live_events=live_events,
        imported_events=max(0, result.total - live_events),
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
        f"last {window}). This is the GROUND TRUTH for what data exists here: a "
        f"network-only grid shows suricata/zeek, a host-logging grid also shows "
        f"endpoint/windows/sysmon/etc. Each line BEGINS with the predicate that "
        f"selects that dataset, and the two are not interchangeable. Most planes "
        f"are named by `event.dataset`, but an integration shipping through a data "
        f"stream may carry its name only in `data_stream.dataset`, and on such a "
        f"plane `event.dataset:<name>` matches nothing at all. Use each line's "
        f"predicate exactly as written, and NEVER conclude a data type is absent "
        f"without querying it:",
    ]
    if inv.imported_events:
        # Said once, in the header, so the per-dataset lines stay short. Only a
        # grid that actually holds backfill pays for this sentence.
        lines.append(
            f"Counts and recency describe LIVE telemetry: what this grid's own sensors "
            f"recorded. {_humanize_count(inv.imported_events)} of the "
            f"{_humanize_count(inv.total_events)} documents in this window are backfill "
            f"instead (loaded by so-import-pcap / so-import-evtx, or replayed from a "
            f"corpus) and are reported separately below as `imported`. Imported "
            f"documents are real and you can query them, but they are not evidence "
            f"that a sensor is alive, and a plane with no live events has no sensor "
            f"producing it here."
        )
    for d in inv.datasets:
        cat = f"  [{'/'.join(d.categories)}]" if d.categories else ""
        if d.live_count:
            body = f"{_humanize_count(d.live_count)} · {_ago_from_ms(d.last_seen_ms)}"
        else:
            body = "no live events"
        if d.imported_count:
            body += f" · {_humanize_count(d.imported_count)} imported"
        lines.append(f"- `{d.predicate}` — {body}{cat}")
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
