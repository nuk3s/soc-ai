"""Tests for soc_ai.eval.synth_ingest — OpenSearch ingestion (#45)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.eval.synth_loader import EventTemplate, GroundTruth, Scenario
from soc_ai.so_client.elastic import ElasticClient

RUN_TIME = datetime(2026, 5, 13, 22, 30, 0, tzinfo=UTC)


def _make_elastic(
    settings: Settings, index_responses: list[dict[str, Any]] | None = None
) -> tuple[ElasticClient, AsyncMock]:
    """ElasticClient backed by a mocked AsyncElasticsearch that records calls."""
    fake_es = AsyncMock()
    fake_es.index = AsyncMock(
        side_effect=index_responses
        or [{"_id": f"synth-{i}", "result": "created"} for i in range(100)]
    )
    fake_es.indices = AsyncMock()
    fake_es.indices.refresh = AsyncMock(return_value={"acknowledged": True})
    # The containment pre-check (assert_no_synth_in_production) reads before
    # any write; default to a clean grid so ingest proceeds. Contamination
    # tests override this per-test (see tests/test_quality_spine.py).
    fake_es.search = AsyncMock(
        return_value={
            "took": 1,
            "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        }
    )
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    return client, fake_es


def _scenario(events: list[EventTemplate]) -> Scenario:
    return Scenario(
        id="test-ingest",
        name="ingest test",
        version=1,
        tier="easy",
        story="test",
        attack=["T1071.001"],
        sigma_refs=[],
        ground_truth=GroundTruth(
            verdict="true_positive",
            confidence_min=0.7,
            required_citation_kinds=[],
            expected_actions=[],
            expected_field_reconciliation=False,
        ),
        events=events,
        rubric_notes="",
    )


@pytest.mark.asyncio
async def test_cleanup_synth_docs_deletes_only_synth_tagged(settings_kratos: Settings) -> None:
    from soc_ai.eval.synth_ingest import cleanup_synth_docs

    client, fake_es = _make_elastic(settings_kratos)
    fake_es.delete_by_query = AsyncMock(return_value={"deleted": 7})

    deleted = await cleanup_synth_docs(client)

    assert deleted == 7
    call = fake_es.delete_by_query.call_args
    assert call.kwargs["index"] == "logs-synth-*"
    must = call.kwargs["body"]["query"]["bool"]["must"]
    assert {"exists": {"field": "synth.scenario_id"}} in must
    # No older_than filter when not requested.
    assert all("range" not in clause for clause in must)


@pytest.mark.asyncio
async def test_cleanup_synth_docs_honors_older_than(settings_kratos: Settings) -> None:
    from soc_ai.eval.synth_ingest import cleanup_synth_docs

    client, fake_es = _make_elastic(settings_kratos)
    fake_es.delete_by_query = AsyncMock(return_value={"deleted": 2})

    cutoff = datetime(2026, 5, 1, tzinfo=UTC)
    deleted = await cleanup_synth_docs(client, older_than=cutoff)

    assert deleted == 2
    must = fake_es.delete_by_query.call_args.kwargs["body"]["query"]["bool"]["must"]
    range_clauses = [c for c in must if "range" in c]
    assert range_clauses == [{"range": {"@timestamp": {"lt": cutoff.isoformat()}}}]


@pytest.mark.asyncio
async def test_cleanup_synth_docs_missing_index_returns_zero(settings_kratos: Settings) -> None:
    from elasticsearch import NotFoundError
    from soc_ai.eval.synth_ingest import cleanup_synth_docs

    client, fake_es = _make_elastic(settings_kratos)
    fake_es.delete_by_query = AsyncMock(side_effect=NotFoundError("missing", meta=None, body=None))

    assert await cleanup_synth_docs(client) == 0


@pytest.mark.asyncio
async def test_ingest_writes_docs_to_authored_indices(settings_kratos: Settings) -> None:
    from soc_ai.eval.synth_ingest import ingest_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                    "event.dataset": "suricata.alert",
                },
            ),
            EventTemplate(
                index="logs-synth-zeek-conn",
                time_offset_seconds=-1,
                is_triage_target=False,
                fields={
                    "@timestamp": "{{ run_time | offset_seconds(-1) }}",
                    "event.dataset": "zeek.conn",
                },
            ),
        ]
    )
    elastic, fake_es = _make_elastic(settings_kratos)

    await ingest_scenario(scenario, elastic=elastic, run_time=RUN_TIME)

    assert fake_es.index.call_count == 2
    indices_called = [c.kwargs["index"] for c in fake_es.index.call_args_list]
    assert indices_called == ["logs-synth-suricata-alert", "logs-synth-zeek-conn"]


@pytest.mark.asyncio
async def test_ingest_returns_triage_doc_id_and_index(settings_kratos: Settings) -> None:
    from soc_ai.eval.synth_ingest import ingest_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-zeek-conn",
                time_offset_seconds=-1,
                is_triage_target=False,
                fields={"@timestamp": "{{ run_time | offset_seconds(-1) }}"},
            ),
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            ),
        ]
    )
    elastic, _ = _make_elastic(
        settings_kratos,
        index_responses=[
            {"_id": "supporting-doc-id", "result": "created"},
            {"_id": "the-triage-target", "result": "created"},
        ],
    )

    result = await ingest_scenario(scenario, elastic=elastic, run_time=RUN_TIME)

    assert result.scenario_id == "test-ingest"
    assert result.triage_doc_id == "the-triage-target"
    assert result.triage_index == "logs-synth-suricata-alert"
    assert result.doc_count == 2


@pytest.mark.asyncio
async def test_ingest_stamps_synth_metadata_on_body(settings_kratos: Settings) -> None:
    from soc_ai.eval.synth_ingest import ingest_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            )
        ]
    )
    elastic, fake_es = _make_elastic(settings_kratos)

    await ingest_scenario(scenario, elastic=elastic, run_time=RUN_TIME)

    body = fake_es.index.call_args_list[0].kwargs["body"]
    assert body["synth.scenario_id"] == "test-ingest"
    assert body["synth.scenario_version"] == 1
    # synth.expected_verdict must NOT be stamped — it is the answer key
    # and the agent under test can read ingested docs via OpenSearch.
    assert "synth.expected_verdict" not in body


@pytest.mark.asyncio
async def test_ingest_calls_refresh_after_writes(settings_kratos: Settings) -> None:
    """Refresh so the docs are queryable by the harness immediately after ingest."""
    from soc_ai.eval.synth_ingest import ingest_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            ),
            EventTemplate(
                index="logs-synth-zeek-conn",
                time_offset_seconds=-1,
                is_triage_target=False,
                fields={"@timestamp": "{{ run_time | offset_seconds(-1) }}"},
            ),
        ]
    )
    elastic, fake_es = _make_elastic(settings_kratos)

    await ingest_scenario(scenario, elastic=elastic, run_time=RUN_TIME)

    fake_es.indices.refresh.assert_awaited_once()
    refreshed_indices = (
        fake_es.indices.refresh.call_args.kwargs.get("index")
        or fake_es.indices.refresh.call_args.args[0]
    )
    # Both target indices included so the harness's subsequent search hits both.
    assert "logs-synth-suricata-alert" in refreshed_indices
    assert "logs-synth-zeek-conn" in refreshed_indices


@pytest.mark.asyncio
async def test_ingest_set_processes_multiple_scenarios(settings_kratos: Settings) -> None:
    from soc_ai.eval.synth_ingest import ingest_scenarios

    scenarios = [
        _scenario(
            [
                EventTemplate(
                    index="logs-synth-suricata-alert",
                    time_offset_seconds=0,
                    is_triage_target=True,
                    fields={
                        "@timestamp": "{{ run_time }}",
                        "source.ip": "10.0.0.42",
                        "source.port": 49321,
                        "destination.ip": "185.220.101.7",
                        "destination.port": 443,
                        "network.transport": "tcp",
                    },
                )
            ]
        ),
    ]
    scenarios[0] = scenarios[0].model_copy(update={"id": "scen-a"})
    scenarios.append(scenarios[0].model_copy(update={"id": "scen-b"}))
    elastic, _ = _make_elastic(
        settings_kratos,
        index_responses=[
            {"_id": "a-target", "result": "created"},
            {"_id": "b-target", "result": "created"},
        ],
    )

    results = await ingest_scenarios(scenarios, elastic=elastic, run_time=RUN_TIME)

    assert len(results) == 2
    assert {r.scenario_id for r in results} == {"scen-a", "scen-b"}


@pytest.mark.asyncio
async def test_ingest_refresh_retries_on_datastream_alias_race(
    settings_kratos: Settings,
) -> None:
    """SO routes logs-synth-* writes into managed datastreams; the first
    refresh after datastream creation can race the alias registration
    and return 404. The ingester retries once after a short sleep, then
    swallows the second 404 (default ES refresh interval picks up the
    docs within 1s anyway).
    """
    from elasticsearch import NotFoundError
    from soc_ai.eval.synth_ingest import ingest_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            )
        ]
    )

    fake_es = AsyncMock()
    fake_es.index = AsyncMock(return_value={"_id": "doc-1", "result": "created"})
    fake_es.indices = AsyncMock()
    # First refresh: 404 (datastream alias not yet registered).
    # Second refresh: success.
    fake_es.indices.refresh = AsyncMock(
        side_effect=[
            NotFoundError(
                meta=None,
                body={"error": {"type": "index_not_found_exception"}},
                message="no such index",
            ),
            {"acknowledged": True},
        ]
    )
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)

    result = await ingest_scenario(scenario, elastic=elastic, run_time=RUN_TIME)
    assert result.scenario_id == "test-ingest"
    # Refresh was attempted twice (one 404 retry, then success).
    assert fake_es.indices.refresh.call_count == 2


@pytest.mark.asyncio
async def test_ingest_refresh_swallows_persistent_404(
    settings_kratos: Settings,
) -> None:
    """If refresh 404s twice (alias still not registered), swallow + log,
    don't fail the whole batch — ES's default refresh interval picks up
    the docs within 1s anyway."""
    from elasticsearch import NotFoundError
    from soc_ai.eval.synth_ingest import ingest_scenario

    scenario = _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            )
        ]
    )

    fake_es = AsyncMock()
    fake_es.index = AsyncMock(return_value={"_id": "doc-1", "result": "created"})
    fake_es.indices = AsyncMock()
    fake_es.indices.refresh = AsyncMock(
        side_effect=NotFoundError(
            meta=None,
            body={"error": {"type": "index_not_found_exception"}},
            message="no such index",
        )
    )
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)

    # Does NOT raise — swallows the second 404.
    result = await ingest_scenario(scenario, elastic=elastic, run_time=RUN_TIME)
    assert result.scenario_id == "test-ingest"
    assert fake_es.indices.refresh.call_count == 2


@pytest.mark.asyncio
async def test_ingest_captures_the_event_index_to_doc_id_bridge_for_m1(
    settings_kratos: Settings,
) -> None:
    """The journey scorer's citation bridge is captured AT INGEST TIME.

    ``score_journey`` resolves a finding's citations against the ES ``_id``s
    ingest assigned, keyed by event ``index`` — and refuses to score when the
    bridge misses an expected event. ``triage_doc_id`` alone covers ZERO of
    m1's two ``expected_cited_event_ids`` (the triage target is the suricata
    alert, the expected citations are the two Zeek events), so without this
    field the flagship journey can never be scored end to end.
    """
    from pathlib import Path

    from soc_ai.eval.synth_ingest import ingest_scenario
    from soc_ai.eval.synth_loader import load_scenario_file

    m1 = load_scenario_file(
        Path(__file__).parent.parent
        / "soc_ai"
        / "eval"
        / "synth_scenarios"
        / "m1-cobalt-strike-beacon.yaml"
    )
    responses = [{"_id": f"real-es-id-{i}", "result": "created"} for i in range(len(m1.events))]
    elastic, fake_es = _make_elastic(settings_kratos, index_responses=responses)

    result = await ingest_scenario(m1, elastic=elastic, run_time=RUN_TIME)

    # Rebuild index → ids from the transport calls themselves, so the assertion
    # holds whatever order the docs were written in.
    expected: dict[str, list[str]] = {}
    for call, resp in zip(fake_es.index.call_args_list, responses, strict=True):
        expected.setdefault(call.kwargs["index"], []).append(str(resp["_id"]))
    assert result.doc_ids_by_event == expected
    # Every event is bridged — in particular BOTH journey-expected events,
    # which the triage locator alone covers none of.
    assert set(result.doc_ids_by_event) == {e.index for e in m1.events}
    assert m1.hunt_journey is not None
    for event_id in m1.hunt_journey.expected_cited_event_ids:
        assert result.doc_ids_by_event[event_id], f"no ingested _ids bridged for {event_id!r}"
    # The pre-existing locator fields are untouched (batch.py reads them).
    assert result.triage_index == "logs-synth-suricata-alert"
    assert result.doc_ids_by_event[result.triage_index] == [result.triage_doc_id]


@pytest.mark.asyncio
async def test_ingest_refuses_non_synth_index_prefix(settings_kratos: Settings) -> None:
    """The synth pollution kill-switch: refuse to write to a non-synth index.

    The Scenario schema already enforces the prefix at load time, but a
    runtime guard catches programmatic construction (test fixtures, ad-hoc
    repl use) that bypasses the loader.
    """
    from soc_ai.eval.synth_ingest import ingest_scenario

    # Bypass schema validation by constructing the event with a hand-crafted index.
    scenario = _scenario(
        [
            EventTemplate.model_construct(
                index="logs-prod-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "source.ip": "10.0.0.42",
                    "source.port": 49321,
                    "destination.ip": "185.220.101.7",
                    "destination.port": 443,
                    "network.transport": "tcp",
                },
            )
        ]
    )
    elastic, _ = _make_elastic(settings_kratos)

    with pytest.raises(ValueError, match="logs-synth-"):
        await ingest_scenario(scenario, elastic=elastic, run_time=RUN_TIME)


# --------------------------------------------------------------------
# Repeated plants (--repeats): each repeat gets its own scope key.
# --------------------------------------------------------------------


def _two_event_scenario() -> Scenario:
    return _scenario(
        [
            EventTemplate(
                index="logs-synth-suricata-alert",
                time_offset_seconds=0,
                is_triage_target=True,
                fields={"@timestamp": "{{ run_time }}", "event.dataset": "suricata.alert"},
            ),
            EventTemplate(
                index="logs-synth-zeek-conn",
                time_offset_seconds=-1,
                is_triage_target=False,
                fields={"@timestamp": "{{ run_time | offset_seconds(-1) }}"},
            ),
        ]
    )


@pytest.mark.asyncio
async def test_ingest_scenarios_repeats_plants_isolated_copies(
    settings_kratos: Settings,
) -> None:
    """repeats=3 plants the scenario three times, each copy stamped with a
    DISTINCT synth.scenario_id (the SynthScope term key), so one repeat's
    queries exclude its siblings' documents — same mechanism that already
    isolates sibling scenarios. Repeat 0 keeps the bare id."""
    from soc_ai.eval.synth_ingest import ingest_scenarios

    scenario = _two_event_scenario()
    elastic, fake_es = _make_elastic(settings_kratos)

    results = await ingest_scenarios([scenario], elastic=elastic, run_time=RUN_TIME, repeats=3)

    assert len(results) == 3
    assert fake_es.index.call_count == 6  # 2 events × 3 plants

    plant_ids = [r.plant_id for r in results]
    assert plant_ids == ["test-ingest", "test-ingest::r1", "test-ingest::r2"]
    assert len(set(plant_ids)) == 3  # pairwise distinct — no shared scope key
    assert [r.repeat for r in results] == [0, 1, 2]
    # Scoring joins on the BASE id; every repeat keeps it.
    assert all(r.scenario_id == "test-ingest" for r in results)
    # Distinct triage targets per plant (the batch runner triages each).
    assert len({r.triage_doc_id for r in results}) == 3

    stamped = [c.kwargs["body"]["synth.scenario_id"] for c in fake_es.index.call_args_list]
    # Every doc carries synth.scenario_id (synth-clean deletes by exists on
    # this field, so all repeats stay removable), valued with its plant's key.
    assert sorted(set(stamped)) == sorted(plant_ids)
    assert all(stamped.count(pid) == 2 for pid in plant_ids)


@pytest.mark.asyncio
async def test_ingest_scenarios_default_repeats_is_one_bare_plant(
    settings_kratos: Settings,
) -> None:
    """Omitting repeats keeps today's behavior byte-identical: one plant,
    stamped with the bare scenario id."""
    from soc_ai.eval.synth_ingest import ingest_scenarios

    scenario = _two_event_scenario()
    elastic, fake_es = _make_elastic(settings_kratos)

    results = await ingest_scenarios([scenario], elastic=elastic, run_time=RUN_TIME)

    assert len(results) == 1
    assert results[0].plant_id == "test-ingest"
    assert results[0].repeat == 0
    stamped = {c.kwargs["body"]["synth.scenario_id"] for c in fake_es.index.call_args_list}
    assert stamped == {"test-ingest"}


@pytest.mark.asyncio
async def test_ingest_scenarios_rejects_nonpositive_repeats(
    settings_kratos: Settings,
) -> None:
    from soc_ai.eval.synth_ingest import ingest_scenarios

    elastic, _ = _make_elastic(settings_kratos)
    with pytest.raises(ValueError, match="repeats"):
        await ingest_scenarios(
            [_two_event_scenario()], elastic=elastic, run_time=RUN_TIME, repeats=0
        )


def test_synth_scope_of_one_repeat_excludes_sibling_plants() -> None:
    """The scope clause built from a repeat's plant id term-matches ONLY that
    plant id; docs stamped with the bare id or another repeat's id carry
    synth.scenario_id (the exists arm) without matching the term — so a
    repeat's queries exclude every sibling plant's documents."""
    from soc_ai.tools._synth_scope import synth_scope_must_not

    clauses = synth_scope_must_not("test-ingest::r1")
    assert len(clauses) == 1
    inner = clauses[0]["bool"]
    assert inner["must"] == [{"exists": {"field": "synth.scenario_id"}}]
    assert {"term": {"synth.scenario_id": "test-ingest::r1"}} in inner["must_not"]
    assert {"term": {"synth.scenario_id.keyword": "test-ingest::r1"}} in inner["must_not"]
    # Neither the bare id nor another repeat's id is exempted.
    for other in ("test-ingest", "test-ingest::r2"):
        assert {"term": {"synth.scenario_id": other}} not in inner["must_not"]
