"""Tests for runtime dataset discovery (soc_ai.so_client.inventory)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from elastic_transport import ConnectionError as EsConnectionError
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.so_client.inventory import (
    _clear_cache,
    discover_datasets,
    format_inventory_block,
    inventory_prompt_block,
)


class _FakeES:
    def __init__(
        self, aggregations: dict[str, Any] | None, total: int = 0, raise_exc: bool = False
    ):
        self._aggs = aggregations
        self._total = total
        self._raise = raise_exc
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"index": index, "query": query, **kwargs})
        if self._raise:
            raise EsConnectionError("connection refused")
        return EsSearchResult(
            total=self._total,
            took_ms=1,
            hits=[],
            aggregations=self._aggs,
            total_is_lower_bound=False,
        )


def _settings() -> Any:
    class S:
        events_index_pattern = "logs-*"

    return S()


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


# A grid with no backfill at all: every bucket is entirely live.
_AGG = {
    "datasets": {
        "buckets": [
            {
                "key": "zeek.conn",
                "doc_count": 11_000_000,
                "categories": {"buckets": [{"key": "network"}]},
                "live": {"doc_count": 11_000_000, "last_seen": {"value": _now_ms()}},
            },
            {
                "key": "zeek.ssh",
                "doc_count": 9400,
                "categories": {"buckets": [{"key": "network"}]},
                "live": {"doc_count": 9400, "last_seen": {"value": _now_ms() - 120_000}},
            },
            # A HOST dataset — proves discovery is not zeek/network-only.
            {
                "key": "endpoint",
                "doc_count": 1_200_000,
                "categories": {"buckets": [{"key": "host"}, {"key": "process"}]},
                "live": {"doc_count": 1_200_000, "last_seen": {"value": _now_ms()}},
            },
        ]
    },
    "live_events": {"doc_count": 12_209_400},
}


@pytest.mark.asyncio
async def test_discover_datasets_is_dataset_agnostic() -> None:
    _clear_cache()
    es = _FakeES(_AGG, total=12_209_400)
    inv = await discover_datasets(es, _settings())
    names = inv.dataset_names()
    assert "zeek.ssh" in names  # the dataset a hunt missed before
    assert "endpoint" in names  # host logging surfaces automatically, no code change
    assert inv.total_events == 12_209_400
    endpoint = next(d for d in inv.datasets if d.dataset == "endpoint")
    assert "host" in endpoint.categories and "process" in endpoint.categories


# Two censuses, deliberately unbalanced. The `data_stream.dataset` fallback
# holds the biggest plane on the grid AND the smallest, so an order that simply
# appends the fallback to the end is wrong in one direction and an order that
# puts it first is wrong in the other. Only a rank by size gets both right.
_AGG_TWO_CENSUSES = {
    "datasets": {
        "buckets": [
            {
                "key": "zeek.conn",
                "doc_count": 900_000,
                "categories": {"buckets": [{"key": "network"}]},
                "live": {"doc_count": 900_000, "last_seen": {"value": _now_ms()}},
            },
            {
                "key": "zeek.notice",
                "doc_count": 2,
                "categories": {"buckets": [{"key": "network"}]},
                "live": {"doc_count": 2, "last_seen": {"value": _now_ms()}},
            },
        ]
    },
    "datasets_by_stream": {
        "datasets": {
            "buckets": [
                {
                    "key": "network_traffic.flow",
                    "doc_count": 8_000_000,
                    "categories": {"buckets": [{"key": "network"}]},
                    "live": {"doc_count": 8_000_000, "last_seen": {"value": _now_ms()}},
                },
                {
                    "key": "network_traffic.tls",
                    "doc_count": 1,
                    "categories": {"buckets": [{"key": "network"}]},
                    "live": {"doc_count": 1, "last_seen": {"value": _now_ms()}},
                },
            ]
        }
    },
    "live_events": {"doc_count": 8_900_003},
}


@pytest.mark.asyncio
async def test_discover_datasets_ranks_both_censuses_together() -> None:
    """`GridInventory` says most-populated-first and the prompt block renders it
    as a ranked list, so the rank has to hold across both censuses.

    Concatenating the `data_stream.dataset` fallback after the `event.dataset`
    census left the largest plane on the measured grid sitting below a dataset
    holding two documents. That plane was 39% of every document there and the
    only surviving network-metadata sensor.
    """
    _clear_cache()
    es = _FakeES(_AGG_TWO_CENSUSES, total=8_900_003)
    inv = await discover_datasets(es, _settings())
    assert inv.dataset_names() == (
        "network_traffic.flow",
        "zeek.conn",
        "zeek.notice",
        "network_traffic.tls",
    )
    counts = [d.live_count for d in inv.datasets]
    assert counts == sorted(counts, reverse=True)


@pytest.mark.asyncio
async def test_discover_datasets_records_which_field_identified_each_dataset() -> None:
    """The census runs two aggregations and only it knows which one produced a
    row. Losing that at the census means every consumer has to guess the
    predicate at render or query time, and the guess is wrong for whichever
    shape it does not assume."""
    _clear_cache()
    es = _FakeES(_AGG_TWO_CENSUSES, total=8_900_003)
    inv = await discover_datasets(es, _settings())
    by_name = {d.dataset: d.identity_field for d in inv.datasets}
    assert by_name["zeek.conn"] == "event.dataset"
    assert by_name["zeek.notice"] == "event.dataset"
    assert by_name["network_traffic.flow"] == "data_stream.dataset"
    assert by_name["network_traffic.tls"] == "data_stream.dataset"


@pytest.mark.asyncio
async def test_dataset_info_predicate_is_the_query_that_matches_it() -> None:
    """One place builds the predicate, so the prompt block and any tool that
    takes a dataset name cannot drift apart."""
    _clear_cache()
    es = _FakeES(_AGG_TWO_CENSUSES, total=8_900_003)
    inv = await discover_datasets(es, _settings())
    by_name = {d.dataset: d.predicate for d in inv.datasets}
    assert by_name["zeek.conn"] == "event.dataset:zeek.conn"
    assert by_name["network_traffic.flow"] == "data_stream.dataset:network_traffic.flow"


@pytest.mark.asyncio
async def test_discover_datasets_body_excludes_synth_unconditionally() -> None:
    """The inventory feeds ONLY analyst surfaces (hunt-template availability,
    ambient prompt blocks, dossiers) and its TTL cache is shared across all of
    them — so the issued body excludes planted eval docs (synth.scenario_id)
    with no opt-in at all. A live eval batch must never inflate the dataset
    list or its counts."""
    _clear_cache()
    es = _FakeES(_AGG)
    await discover_datasets(es, _settings())
    must_not = es.calls[0]["query"]["bool"]["must_not"]
    assert {"exists": {"field": "synth.scenario_id"}} in must_not


@pytest.mark.asyncio
async def test_discover_datasets_caches() -> None:
    _clear_cache()
    es = _FakeES(_AGG)
    await discover_datasets(es, _settings())
    await discover_datasets(es, _settings())
    assert len(es.calls) == 1  # second call served from cache


@pytest.mark.asyncio
async def test_discover_datasets_propagates_grid_errors() -> None:
    """G7: an outage must NOT return an empty-looking inventory.

    A returned empty `GridInventory` is indistinguishable from a grid that
    genuinely carries no datasets, which is how a hiccup told analysts their
    network has no DNS or endpoint telemetry. Callers fail soft on their own
    terms (the hunt-template route reports every template available, the
    dossier reads an empty set as "unknown"); they can only do that if the
    error reaches them.
    """
    _clear_cache()
    es = _FakeES(None, raise_exc=True)
    with pytest.raises(EsConnectionError):
        await discover_datasets(es, _settings())


@pytest.mark.asyncio
async def test_discover_datasets_does_not_cache_a_failure() -> None:
    """A failed discovery leaves the cache empty, so the next call re-reads."""
    _clear_cache()
    es = _FakeES(_AGG, total=1, raise_exc=True)
    with pytest.raises(EsConnectionError):
        await discover_datasets(es, _settings())
    es._raise = False
    inv = await discover_datasets(es, _settings())
    assert "zeek.ssh" in inv.dataset_names()


def test_format_inventory_block_lists_all_datasets() -> None:
    _clear_cache()
    from soc_ai.so_client.inventory import DatasetInfo, GridInventory

    inv = GridInventory(
        datasets=(
            DatasetInfo("suricata.alert", 2_100_000, _now_ms(), ("network", "intrusion_detection")),
            DatasetInfo("endpoint", 1_200_000, _now_ms(), ("host",)),
        ),
        window_minutes=1440,
        live_events=3_300_000,
    )
    block = format_inventory_block(inv)
    assert "suricata.alert" in block and "endpoint" in block
    assert "2.1M" in block and "1.2M" in block


def test_format_inventory_block_renders_the_predicate_that_matches_each_row() -> None:
    """The block is rendered into the model's prompt as ground truth and the
    model queries what it says. A plane whose documents carry no
    `event.dataset` at all is selected only by `data_stream.dataset`, so a row
    that implies the other predicate hands the model a query returning nothing
    for the largest plane on the grid.

    41% of the documents on the measured range are in exactly that shape.
    """
    from soc_ai.so_client.inventory import DatasetInfo, GridInventory

    inv = GridInventory(
        datasets=(
            DatasetInfo(
                "network_traffic.flow",
                354_269,
                _now_ms(),
                ("network",),
                identity_field="data_stream.dataset",
            ),
        ),
        window_minutes=1440,
        live_events=354_269,
    )
    block = format_inventory_block(inv)
    assert "`data_stream.dataset:network_traffic.flow`" in block
    assert "`event.dataset:network_traffic.flow`" not in block


def test_format_inventory_block_keeps_event_dataset_for_a_plane_that_has_it() -> None:
    """Negative control. A dataset genuinely identified by `event.dataset` must
    still render with that predicate: a fix that renamed every row to the
    data-stream field would break the 59% of the grid that was working."""
    from soc_ai.so_client.inventory import DatasetInfo, GridInventory

    inv = GridInventory(
        datasets=(DatasetInfo("zeek.conn", 800_000, _now_ms(), ("network",)),),
        window_minutes=1440,
        live_events=800_000,
    )
    block = format_inventory_block(inv)
    assert "`event.dataset:zeek.conn`" in block
    assert "data_stream.dataset:zeek.conn" not in block


def test_format_inventory_block_mixed_grid_gives_each_row_its_own_predicate() -> None:
    """Both shapes on one grid, which is the shape of the measured range: the
    two predicates must not be applied uniformly in either direction."""
    from soc_ai.so_client.inventory import DatasetInfo, GridInventory

    inv = GridInventory(
        datasets=(
            DatasetInfo(
                "network_traffic.flow",
                354_269,
                _now_ms(),
                ("network",),
                identity_field="data_stream.dataset",
            ),
            DatasetInfo("suricata.alert", 40_000, _now_ms(), ("network",)),
        ),
        window_minutes=1440,
        live_events=394_269,
    )
    block = format_inventory_block(inv)
    assert "`data_stream.dataset:network_traffic.flow`" in block
    assert "`event.dataset:suricata.alert`" in block


def test_format_inventory_block_empty() -> None:
    from soc_ai.so_client.inventory import GridInventory

    assert format_inventory_block(GridInventory((), 1440, 0)) == ""


@pytest.mark.asyncio
async def test_inventory_prompt_block_prefixes_blank_line() -> None:
    _clear_cache()
    es = _FakeES(_AGG)
    block = await inventory_prompt_block(es, _settings())
    assert block.startswith("\n\n## Data available on this grid")


@pytest.mark.asyncio
async def test_inventory_prompt_block_empty_on_error() -> None:
    _clear_cache()
    es = _FakeES(None, raise_exc=True)
    assert await inventory_prompt_block(es, _settings()) == ""


# ---------------------------------------------------------------------------
# Provenance: imports are counted, labelled, and never mistaken for a sensor
# ---------------------------------------------------------------------------


def _three_days_ago_ms() -> int:
    return _now_ms() - 3 * 86_400_000


# Frozen once, at import: the fixture below and the assertions that read it back
# have to name the same instant, and the suite takes long enough that recomputing
# it drifts.
_DEAD_SENSOR_LAST_SEEN_MS = _three_days_ago_ms()


# A census in the shape the measured grid produced. Every bucket deliberately
# still carries the contaminated bucket-level `last_seen` the old reader used,
# set to NOW, so a reader that goes on using it fails these tests rather than
# passing them by accident.
_AGG_WITH_IMPORTS = {
    "datasets": {
        "buckets": [
            {
                # A dead sensor with a fresh import sitting on top of it. The
                # document the old census called the newest Suricata alert had
                # an import marker and a file path under an import directory.
                "key": "suricata.alert",
                "doc_count": 40_000,
                "last_seen": {"value": _now_ms()},
                "categories": {"buckets": [{"key": "network"}]},
                "live": {
                    "doc_count": 12,
                    "last_seen": {"value": _DEAD_SENSOR_LAST_SEEN_MS},
                },
            },
            {
                # The single Windows event-log import: 18.8M documents, not one
                # of them from a sensor on this grid.
                "key": "windows.security",
                "doc_count": 18_823_251,
                "last_seen": {"value": _now_ms()},
                "categories": {"buckets": [{"key": "host"}]},
                "live": {"doc_count": 0, "last_seen": {"value": None}},
            },
            {
                "key": "zeek.conn",
                "doc_count": 800_000,
                "last_seen": {"value": _now_ms()},
                "categories": {"buckets": [{"key": "network"}]},
                "live": {"doc_count": 800_000, "last_seen": {"value": _now_ms()}},
            },
        ]
    },
    "live_events": {"doc_count": 800_012},
}


@pytest.mark.asyncio
async def test_last_seen_describes_live_telemetry_not_the_newest_import() -> None:
    """The census called a network intrusion sensor five hours stale when it had
    been dead for three days, because the newest document under its dataset was
    an imported one. `last_seen` is now read from the live-only sub-aggregation.
    """
    _clear_cache()
    es = _FakeES(_AGG_WITH_IMPORTS, total=19_663_251)
    inv = await discover_datasets(es, _settings())
    suricata = next(d for d in inv.datasets if d.dataset == "suricata.alert")
    assert suricata.last_seen_ms == _DEAD_SENSOR_LAST_SEEN_MS
    assert suricata.live_count == 12
    assert suricata.imported_count == 39_988


@pytest.mark.asyncio
async def test_an_import_only_plane_stays_visible_and_says_it_is_an_import() -> None:
    """Hiding the import is its own kind of lie: a grid that genuinely holds
    imported evidence is a real situation and an analyst has to be able to see
    it. It is reported as a labelled plane with no live telemetry, never as
    live telemetry.
    """
    _clear_cache()
    es = _FakeES(_AGG_WITH_IMPORTS, total=19_663_251)
    inv = await discover_datasets(es, _settings())
    assert "windows.security" in inv.dataset_names()
    imported = next(d for d in inv.datasets if d.dataset == "windows.security")
    assert imported.live_count == 0
    assert imported.imported_count == 18_823_251
    assert imported.last_seen_ms is None
    # Ranked by LIVE volume, so the largest thing on disk cannot outrank the
    # sensors just by being an import.
    assert inv.dataset_names()[0] == "zeek.conn"


@pytest.mark.asyncio
async def test_the_census_totals_split_live_from_imported() -> None:
    _clear_cache()
    es = _FakeES(_AGG_WITH_IMPORTS, total=19_663_251)
    inv = await discover_datasets(es, _settings())
    assert inv.live_events == 800_012
    assert inv.imported_events == 18_863_239
    assert inv.total_events == 19_663_251


@pytest.mark.asyncio
async def test_the_census_query_counts_imports_and_isolates_them_in_the_aggs() -> None:
    """The import filter belongs in the sub-aggregations, not on the query.

    On the query it would make imports vanish from the census entirely, and the
    grid would stop being able to say it holds them. In the sub-aggregations the
    totals keep counting every document while every liveness figure is measured
    over sensor telemetry alone.
    """
    _clear_cache()
    es = _FakeES(_AGG_WITH_IMPORTS)
    await discover_datasets(es, _settings())
    call = es.calls[0]
    assert {"exists": {"field": "import.id"}} not in call["query"]["bool"]["must_not"]
    for path in (
        call["aggs"]["datasets"]["aggs"],
        call["aggs"]["datasets_by_stream"]["aggs"]["datasets"]["aggs"],
    ):
        must_not = path["live"]["filter"]["bool"]["must_not"]
        assert {"exists": {"field": "import.id"}} in must_not
        assert {"term": {"tags": "replayed-corpus"}} in must_not
    live_total = call["aggs"]["live_events"]["filter"]["bool"]["must_not"]
    assert {"exists": {"field": "import.id"}} in live_total


def test_format_inventory_block_labels_imported_documents() -> None:
    from soc_ai.so_client.inventory import DatasetInfo, GridInventory

    inv = GridInventory(
        datasets=(
            DatasetInfo("zeek.conn", 800_000, _now_ms(), ("network",), 0),
            DatasetInfo("suricata.alert", 12, _DEAD_SENSOR_LAST_SEEN_MS, ("network",), 39_988),
            DatasetInfo("windows.security", 0, None, ("host",), 18_823_251),
        ),
        window_minutes=1440,
        live_events=800_012,
        imported_events=18_863_239,
    )
    block = format_inventory_block(inv)
    assert "40k imported" in block
    assert "18.8M imported" in block
    assert "no live events" in block
    # The clean sensor's line stays a plain live line.
    assert "`event.dataset:zeek.conn` — 800k · " in block
    assert "imported" not in block.split("`event.dataset:zeek.conn`")[1].split("\n")[0]


def test_format_inventory_block_says_nothing_about_imports_on_a_clean_grid() -> None:
    """Negative control. A grid that holds no imported documents must read
    exactly as it did before this split existed, or the fix has invented a
    caveat on every deployment that never imported anything."""
    from soc_ai.so_client.inventory import DatasetInfo, GridInventory

    inv = GridInventory(
        datasets=(DatasetInfo("zeek.conn", 800_000, _now_ms(), ("network",), 0),),
        window_minutes=1440,
        live_events=800_000,
        imported_events=0,
    )
    block = format_inventory_block(inv)
    assert "imported" not in block
    assert "no live events" not in block
