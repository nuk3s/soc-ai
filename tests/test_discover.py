"""Tests for the on-demand discovery tools (soc_ai.tools.discover)."""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.tools.discover import _flatten, describe_dataset, field_values


class _FakeES:
    def __init__(self, *, hits=None, aggs=None, raise_exc=False):
        self._hits = hits or []
        self._aggs = aggs
        self._raise = raise_exc
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"index": index, "query": query, **kwargs})
        if self._raise:
            raise RuntimeError("es down")
        return EsSearchResult(
            total=len(self._hits),
            took_ms=1,
            hits=self._hits,
            aggregations=self._aggs,
            total_is_lower_bound=False,
        )


def _settings() -> Any:
    class S:
        events_index_pattern = "logs-*"

    return S()


def test_flatten_handles_nested_and_flat_dotted() -> None:
    src = {
        "event": {"dataset": "zeek.ssh"},  # nested
        "source.ip": "203.0.113.5",  # flat-dotted
        "ssh": {"auth_success": True, "client": "OpenSSH_9.0"},
        "tags": ["a", "b"],
    }
    out = dict(_flatten(src))
    assert out["event.dataset"] == "zeek.ssh"
    assert out["source.ip"] == "203.0.113.5"
    assert out["ssh.auth_success"] is True
    assert out["ssh.client"] == "OpenSSH_9.0"
    assert out["tags"] == "a"  # first scalar of the list


@pytest.mark.asyncio
async def test_describe_dataset_reports_populated_fields() -> None:
    hits = [
        {
            "_source": {
                "event": {"dataset": "zeek.ssh"},
                "ssh.auth_success": True,
                "ssh.client": "X",
            }
        },
        {"_source": {"event": {"dataset": "zeek.ssh"}, "ssh.auth_success": False}},
    ]
    es = _FakeES(hits=hits)
    out = await describe_dataset("zeek.ssh", elastic=es, settings=_settings())
    assert out["dataset"] == "zeek.ssh"
    assert out["sampled"] == 2
    field_names = {f["field"] for f in out["fields"]}
    assert "ssh.auth_success" in field_names and "ssh.client" in field_names
    auth = next(f for f in out["fields"] if f["field"] == "ssh.auth_success")
    assert auth["coverage"] == "2/2"  # present in both sampled docs


@pytest.mark.asyncio
async def test_describe_dataset_empty_gives_helpful_note() -> None:
    es = _FakeES(hits=[])
    out = await describe_dataset("zeek.nope", elastic=es, settings=_settings())
    assert out["sampled"] == 0 and out["fields"] == []
    assert "inventory" in out["note"].lower()


@pytest.mark.asyncio
async def test_describe_dataset_best_effort_on_error() -> None:
    es = _FakeES(raise_exc=True)
    out = await describe_dataset("zeek.ssh", elastic=es, settings=_settings())
    assert out["error"] is True


@pytest.mark.asyncio
async def test_field_values_returns_terms() -> None:
    aggs = {
        "vals": {
            "buckets": [{"key": "ET SCAN", "doc_count": 42}, {"key": "ET DNS", "doc_count": 7}]
        }
    }
    es = _FakeES(aggs=aggs)
    out = await field_values(
        "rule.name", elastic=es, settings=_settings(), dataset="suricata.alert"
    )
    assert out["field"] == "rule.name" and out["dataset"] == "suricata.alert"
    assert out["values"][0] == {"value": "ET SCAN", "count": 42}


@pytest.mark.asyncio
async def test_field_values_error_carries_hint() -> None:
    es = _FakeES(raise_exc=True)
    out = await field_values("some.text.field", elastic=es, settings=_settings())
    assert out["error"] is True and "describe_dataset" in out["hint"]


# ---------------------------------------------------------------------------
# Synthetic-eval kill-switch: both discovery tools read the same events index
# the planted eval scenarios are written to, so the ISSUED body must exclude
# synth.scenario_id docs by default — a live eval batch must never inflate a
# dataset's described fields or a field's top values on an analyst surface.
# The eval harness opts in per call, like every other events reader.
# ---------------------------------------------------------------------------

_SYNTH_CLAUSE = {"exists": {"field": "synth.scenario_id"}}


@pytest.mark.asyncio
async def test_describe_dataset_body_excludes_synth_by_default() -> None:
    es = _FakeES(hits=[{"_source": {"event": {"dataset": "zeek.ssh"}}}])
    await describe_dataset("zeek.ssh", elastic=es, settings=_settings())
    must_not = es.calls[0]["query"]["bool"]["must_not"]
    assert _SYNTH_CLAUSE in must_not


@pytest.mark.asyncio
async def test_describe_dataset_body_admits_synth_when_opted_in() -> None:
    es = _FakeES(hits=[{"_source": {"event": {"dataset": "zeek.ssh"}}}])
    await describe_dataset("zeek.ssh", elastic=es, settings=_settings(), include_synth=True)
    must_not = es.calls[0]["query"]["bool"].get("must_not", [])
    assert _SYNTH_CLAUSE not in must_not


@pytest.mark.asyncio
async def test_field_values_body_excludes_synth_by_default() -> None:
    es = _FakeES(aggs={"vals": {"buckets": []}})
    await field_values("rule.name", elastic=es, settings=_settings(), dataset="suricata.alert")
    must_not = es.calls[0]["query"]["bool"]["must_not"]
    assert _SYNTH_CLAUSE in must_not


@pytest.mark.asyncio
async def test_field_values_body_admits_synth_when_opted_in() -> None:
    es = _FakeES(aggs={"vals": {"buckets": []}})
    await field_values("rule.name", elastic=es, settings=_settings(), include_synth=True)
    must_not = es.calls[0]["query"]["bool"].get("must_not", [])
    assert _SYNTH_CLAUSE not in must_not
