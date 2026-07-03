"""Tests for runtime dataset discovery (soc_ai.so_client.inventory)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
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
            raise RuntimeError("es down")
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


_AGG = {
    "datasets": {
        "buckets": [
            {
                "key": "zeek.conn",
                "doc_count": 11_000_000,
                "last_seen": {"value": _now_ms()},
                "categories": {"buckets": [{"key": "network"}]},
            },
            {
                "key": "zeek.ssh",
                "doc_count": 9400,
                "last_seen": {"value": _now_ms() - 120_000},
                "categories": {"buckets": [{"key": "network"}]},
            },
            # A HOST dataset — proves discovery is not zeek/network-only.
            {
                "key": "endpoint",
                "doc_count": 1_200_000,
                "last_seen": {"value": _now_ms()},
                "categories": {"buckets": [{"key": "host"}, {"key": "process"}]},
            },
        ]
    }
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


@pytest.mark.asyncio
async def test_discover_datasets_caches() -> None:
    _clear_cache()
    es = _FakeES(_AGG)
    await discover_datasets(es, _settings())
    await discover_datasets(es, _settings())
    assert len(es.calls) == 1  # second call served from cache


@pytest.mark.asyncio
async def test_discover_datasets_best_effort_on_error() -> None:
    _clear_cache()
    es = _FakeES(None, raise_exc=True)
    inv = await discover_datasets(es, _settings())
    assert inv.datasets == ()  # never raises; empty inventory


def test_format_inventory_block_lists_all_datasets() -> None:
    _clear_cache()
    from soc_ai.so_client.inventory import DatasetInfo, GridInventory

    inv = GridInventory(
        datasets=(
            DatasetInfo("suricata.alert", 2_100_000, _now_ms(), ("network", "intrusion_detection")),
            DatasetInfo("endpoint", 1_200_000, _now_ms(), ("host",)),
        ),
        window_minutes=1440,
        total_events=3_300_000,
    )
    block = format_inventory_block(inv)
    assert "suricata.alert" in block and "endpoint" in block
    assert "2.1M" in block and "1.2M" in block
    assert "event.dataset:<name>" in block


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
