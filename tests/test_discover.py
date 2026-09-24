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


def _dataset_terms(query: dict) -> set[str]:
    """Every ES field the query's FILTER matches the dataset name against.

    Scoped to ``filter`` rather than the whole query: the dataset predicate is
    a filter, while ``must_not`` carries the visibility scopes (synth markers,
    import markers, a replay tag on ``tags``). Walking everything made the
    negative control below fail on a ``term`` that has nothing to do with a
    dataset name, which is the assertion answering a different question than
    the one it asks.
    """
    fields: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "term" and isinstance(v, dict):
                    fields.update(v)
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(query.get("bool", {}).get("filter", []))
    return fields


@pytest.mark.asyncio
async def test_describe_dataset_matches_either_dataset_field() -> None:
    """A model that learns `data_stream.dataset:network_traffic.flow` from the
    ambient inventory then calls this tool with that dataset name. Scoping the
    sample to `event.dataset` alone answers "no documents" for a plane holding
    41% of the grid."""
    es = _FakeES(hits=[{"_source": {"data_stream": {"dataset": "network_traffic.flow"}}}])
    await describe_dataset("network_traffic.flow", elastic=es, settings=_settings())
    assert _dataset_terms(es.calls[0]["query"]) >= {"event.dataset", "data_stream.dataset"}


@pytest.mark.asyncio
async def test_field_values_matches_either_dataset_field() -> None:
    es = _FakeES(aggs={"vals": {"buckets": []}})
    await field_values(
        "source.ip", elastic=es, settings=_settings(), dataset="network_traffic.flow"
    )
    assert _dataset_terms(es.calls[0]["query"]) >= {"event.dataset", "data_stream.dataset"}


@pytest.mark.asyncio
async def test_field_values_without_a_dataset_adds_no_dataset_term() -> None:
    """Negative control: the widened filter must only appear when a dataset was
    asked for, or every unscoped aggregation silently gains a clause."""
    es = _FakeES(aggs={"vals": {"buckets": []}})
    await field_values("source.ip", elastic=es, settings=_settings())
    assert _dataset_terms(es.calls[0]["query"]) == set()


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
    """An ES failure points the agent at describe_dataset.

    Uses a WHITELISTED field on purpose: an unwhitelisted one is now refused
    before any round-trip, which is a different path with a different message,
    and this test is about the grid-error hint.
    """
    es = _FakeES(raise_exc=True)
    out = await field_values("event.dataset", elastic=es, settings=_settings())
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


# ---------------------------------------------------------------------------
# Provenance: the two tools answer different kinds of question, so they get
# different defaults. Getting this backwards either way is worse than the bug —
# a filtered schema read blinds the agent to a plane the grid inventory has
# already told it exists, and an unfiltered value ranking hands it an imported
# corpus's hostnames as the terrain.
# ---------------------------------------------------------------------------

_IMPORT_CLAUSE = {"exists": {"field": "import.id"}}


@pytest.mark.asyncio
async def test_a_value_ranking_is_a_ranking_of_this_grid() -> None:
    es = _FakeES(aggs={"vals": {"buckets": []}})
    out = await field_values("host.name", elastic=es, settings=_settings())
    must_not = es.calls[0]["query"]["bool"]["must_not"]
    assert _IMPORT_CLAUSE in must_not
    assert {"term": {"tags": "replayed-corpus"}} in must_not
    assert out["provenance"] == "live"
    assert "live telemetry only" in out["counted_over"]


@pytest.mark.asyncio
async def test_enumerating_an_imports_values_is_an_explicit_ask() -> None:
    es = _FakeES(aggs={"vals": {"buckets": []}})
    out = await field_values("host.name", elastic=es, settings=_settings(), provenance="any")
    assert _IMPORT_CLAUSE not in es.calls[0]["query"]["bool"].get("must_not", [])
    assert out["provenance"] == "any"


@pytest.mark.asyncio
async def test_a_schema_read_still_reaches_an_import_only_plane() -> None:
    """describe_dataset must NOT be filtered, and this is why.

    The grid inventory reports an import-only plane as present and queryable.
    A schema read that came back "no documents named X" for that plane would
    contradict the inventory and leave the agent unable to write a query for
    documents it has just been told exist — a filter blinding the product,
    which is the failure mode this whole change has to avoid in both directions.
    """
    es = _FakeES(hits=[{"_source": {"event": {"dataset": "windows.sysmon_operational"}}}])
    out = await describe_dataset("windows.sysmon_operational", elastic=es, settings=_settings())
    must_not = es.calls[0]["query"]["bool"].get("must_not", [])
    assert _IMPORT_CLAUSE not in must_not
    assert out["sampled"] == 1


@pytest.mark.asyncio
async def test_the_marker_guard_answers_in_the_same_shape_as_a_real_empty() -> None:
    """The refusal must not become a tell by having fewer keys than an answer.

    `field_values("synth.scenario_id")` returns an empty list without querying,
    so that probing for the eval marker looks exactly like probing for a field
    that does not exist. Every key the answered path gained has to appear on
    the refusal too, or the shapes diverge and the difference is the disclosure.
    """
    es = _FakeES(aggs={"vals": {"buckets": []}})
    answered = await field_values("host.name", elastic=es, settings=_settings())
    refused = await field_values("synth.scenario_id", elastic=es, settings=_settings())

    assert refused.keys() == answered.keys()
    assert refused["values"] == answered["values"] == []
    assert len(es.calls) == 1, "the guard must not issue a query"
