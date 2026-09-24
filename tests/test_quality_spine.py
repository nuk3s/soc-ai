"""Regression suite for the quality spine (trust release, slice 2).

Step 1 makes synthetic scenarios visible to an eval-mode hunt. These tests pin
the DEFAULT (synth excluded) as hard as the opt-in, because the default is what
protects a real analyst from seeing planted attacks.
"""

from __future__ import annotations

import asyncio
import json
import textwrap
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import TransportError
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from soc_ai.agent.orchestrator import StepEvent, _path_exists_in_alert
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.api.runner import recorded_run, run_recorded
from soc_ai.config import Settings
from soc_ai.eval.synth_ingest import ingest_scenarios
from soc_ai.eval.synth_loader import (
    EventTemplate,
    Scenario,
    load_all_scenarios,
    load_scenario_file,
    triage_scenarios,
)
from soc_ai.eval.synth_render import render_scenario
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult, GridPartialResultsError
from soc_ai.so_client.models import SoAlert
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Hunt, Investigation
from soc_ai.tools._synth_scope import synth_scope_must_not
from soc_ai.tools.analytics import (
    _hunt_must_not,
    beacon_profile,
    dcerpc_histogram,
    dns_entropy_scan,
    first_seen,
)
from soc_ai.tools.get_alert_context import AlertContext

# Reuse the analytics suite's typed EsSearchResult fakes — same harness, no
# parallel one (precedent: tests/test_toolset.py importing test_tool_surface).
from tests.test_analytics_tools import _make_elastic, _result

# Reuse the promotion suite's store/app harness for the synth-eval marker tests
# below (Task 4) — it covers migration 0031 on the same two tables, so its
# `_db`/`_client` fixtures and empty event stream are the closest precedent.
from tests.test_finding_promotion import (
    _LONG_OBJECTIVE,
    _MGR_TARGET,
    _client,
    _db,
    _empty_stream,
)

# Reuse the synth-ingest suite's transport-level fake and scenario builder for
# the containment tests below — same harness, no parallel one.
from tests.test_synth_ingest import RUN_TIME, _scenario
from tests.test_synth_ingest import _make_elastic as _make_ingest_elastic

# Reuse the toolset suite's agent/context builder for the closure-threading
# tests below — same reason.
from tests.test_toolset import _agent_with


def test_hunt_must_not_excludes_synth_by_default(settings_kratos: Settings) -> None:
    clauses = _hunt_must_not(settings_kratos, exclude_internal_dest=False)
    assert {"exists": {"field": "synth.scenario_id"}} in clauses


def test_hunt_must_not_admits_synth_when_opted_in(settings_kratos: Settings) -> None:
    clauses = _hunt_must_not(settings_kratos, exclude_internal_dest=False, include_synth=True)
    assert {"exists": {"field": "synth.scenario_id"}} not in clauses


# ---------------------------------------------------------------------------
# Per-tool coverage: the ISSUED Elasticsearch body carries the synth-exclusion
# clause by default and omits it only under the explicit opt-in.
# ---------------------------------------------------------------------------

_SYNTH_CLAUSE = {"exists": {"field": "synth.scenario_id"}}
# The whole prod exclusion, every marker position.
_SYNTH_MUST_NOT = synth_scope_must_not(False)


def _cidr_clauses(must_not: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [c for c in must_not if "terms" in c and "destination.ip" in c["terms"]]


# The claim these tests make about the three DNS/DCE-RPC sweeps is narrow: no
# internal-destination exclusion may ride along, because their traffic IS
# internal. It used to be spelled as equality with the synth clause list, which
# asserted something much wider — that the query carries no other scope at all —
# and so broke the day a second scope was threaded through the same helper,
# while the thing it was written to protect had not changed. Spelled as itself
# now, so it fails for its own reason or not at all.


@pytest.mark.asyncio
async def test_beacon_profile_body_excludes_synth_by_default(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    await beacon_profile(elastic=elastic, settings=settings_kratos)

    # resolve_agg_field may probe elastic.search first; call_args is the LAST
    # call, i.e. the actual aggregation query (the test_analytics_tools
    # convention).
    must_not = elastic.search.call_args.args[1]["bool"]["must_not"]  # type: ignore[attr-defined]
    assert _SYNTH_CLAUSE in must_not


@pytest.mark.asyncio
async def test_beacon_profile_body_admits_synth_when_opted_in(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    await beacon_profile(elastic=elastic, settings=settings_kratos, include_synth=True)

    must_not = elastic.search.call_args.args[1]["bool"]["must_not"]  # type: ignore[attr-defined]
    assert _SYNTH_CLAUSE not in must_not
    # The opt-in touches ONLY the synth clause — the default server-side
    # internal-destination exclusion must survive it.
    assert len(_cidr_clauses(must_not)) == 1


@pytest.mark.asyncio
async def test_dns_entropy_scan_body_excludes_synth_by_default(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    await dns_entropy_scan(elastic=elastic, settings=settings_kratos)

    # No internal-destination exclusion may be smuggled in by _hunt_must_not:
    # DNS resolvers ARE internal destinations, so excluding them would drop the
    # traffic this sweep measures.
    must_not = elastic.search.call_args.args[1]["bool"]["must_not"]  # type: ignore[attr-defined]
    assert all(clause in must_not for clause in _SYNTH_MUST_NOT)
    assert _cidr_clauses(must_not) == []


@pytest.mark.asyncio
async def test_dns_entropy_scan_body_admits_synth_when_opted_in(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    await dns_entropy_scan(elastic=elastic, settings=settings_kratos, include_synth=True)

    must_not = elastic.search.call_args.args[1]["bool"]["must_not"]  # type: ignore[attr-defined]
    # The opt-in touches ONLY the synth clause, and it still brings no
    # internal-destination exclusion with it.
    assert _SYNTH_CLAUSE not in must_not
    assert _cidr_clauses(must_not) == []


@pytest.mark.asyncio
async def test_dcerpc_histogram_body_excludes_synth_by_default(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    await dcerpc_histogram(elastic=elastic, settings=settings_kratos)

    # No internal-destination exclusion may ride along — DCE-RPC is lateral
    # movement between INTERNAL hosts.
    must_not = elastic.search.call_args.args[1]["bool"]["must_not"]  # type: ignore[attr-defined]
    assert all(clause in must_not for clause in _SYNTH_MUST_NOT)
    assert _cidr_clauses(must_not) == []


@pytest.mark.asyncio
async def test_dcerpc_histogram_body_admits_synth_when_opted_in(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    await dcerpc_histogram(elastic=elastic, settings=settings_kratos, include_synth=True)

    must_not = elastic.search.call_args.args[1]["bool"]["must_not"]  # type: ignore[attr-defined]
    # The opt-in touches ONLY the synth clause, and it still brings no
    # internal-destination exclusion with it.
    assert _SYNTH_CLAUSE not in must_not
    assert _cidr_clauses(must_not) == []


@pytest.mark.asyncio
async def test_first_seen_body_excludes_synth_by_default_on_both_queries(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    await first_seen(elastic=elastic, settings=settings_kratos)

    assert elastic.search.call_count == 2  # type: ignore[attr-defined]
    for call in elastic.search.call_args_list:  # type: ignore[attr-defined]
        assert _SYNTH_CLAUSE in call.args[1]["bool"]["must_not"]


@pytest.mark.asyncio
async def test_first_seen_body_admits_synth_when_opted_in_on_both_queries(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    await first_seen(elastic=elastic, settings=settings_kratos, include_synth=True)

    assert elastic.search.call_count == 2  # type: ignore[attr-defined]
    for call in elastic.search.call_args_list:  # type: ignore[attr-defined]
        must_not = call.args[1]["bool"]["must_not"]
        assert _SYNTH_CLAUSE not in must_not
        # Recent AND baseline keep the server-side internal-destination
        # exclusion — the opt-in touches only the synth clause.
        assert len(_cidr_clauses(must_not)) == 1


# ---------------------------------------------------------------------------
# Step 2: the agent's OWN tool closures thread ctx.include_synth through.
# Without this an eval-mode run's Phase-A prefetch sees the planted scenario
# but every query the agent loop itself issues silently excludes it — the
# flagship hunt journey can never reach the ground truth it is graded on.
# Both directions are pinned: True must arrive, and the default context must
# arrive as an EXPLICIT False (absence would mean the closure isn't wired).
# ---------------------------------------------------------------------------


class _StubOqlResult:
    """Shape-only stand-in for the query_events_oql result model."""

    def model_dump(self, mode: str = "python") -> dict[str, Any]:
        return {}


@pytest.mark.asyncio
@pytest.mark.parametrize("opted_in", [True, False])
async def test_oql_closure_threads_context_synth_flag(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch, opted_in: bool
) -> None:
    captured: dict[str, Any] = {}

    async def _fake_query_events_oql(query: str, **kwargs: Any) -> _StubOqlResult:
        captured.update(kwargs)
        return _StubOqlResult()

    monkeypatch.setattr("soc_ai.agent.toolset.query_events_oql", _fake_query_events_oql)
    agent = _agent_with("hunt", settings_kratos, include_synth=opted_in)

    await agent._function_toolset.tools["t_query_events_oql"].function("event.dataset:zeek.conn")

    assert captured["include_synth"] is opted_in


@pytest.mark.asyncio
@pytest.mark.parametrize("opted_in", [True, False])
@pytest.mark.parametrize(
    "tool_name",
    ["t_beacon_profile", "t_dns_entropy_scan", "t_dcerpc_histogram", "t_first_seen"],
)
async def test_analytics_closures_thread_context_synth_flag(
    settings_kratos: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    opted_in: bool,
) -> None:
    captured: dict[str, Any] = {}

    async def _fake_analytics(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {}

    # The closures call the module-level names imported into the toolset
    # namespace (t_beacon_profile → beacon_profile, etc.).
    monkeypatch.setattr(f"soc_ai.agent.toolset.{tool_name.removeprefix('t_')}", _fake_analytics)
    agent = _agent_with("hunt", settings_kratos, include_synth=opted_in)

    await agent._function_toolset.tools[tool_name].function()

    assert captured["include_synth"] is opted_in


@pytest.mark.asyncio
@pytest.mark.parametrize("opted_in", [True, False])
@pytest.mark.parametrize(
    ("tool_name", "call_args"),
    [("t_describe_dataset", ("zeek.conn",)), ("t_field_values", ("event.dataset",))],
)
async def test_discovery_closures_thread_context_synth_flag(
    settings_kratos: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    call_args: tuple[str, ...],
    opted_in: bool,
) -> None:
    """The on-demand discovery tools read the same events index the scenarios
    are planted into — an eval-mode hunt describing a dataset (or listing a
    field's values) must see the planted docs, and a prod context must arrive
    as an EXPLICIT False."""
    captured: dict[str, Any] = {}

    async def _fake_discover(*args: Any, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(f"soc_ai.agent.toolset.{tool_name.removeprefix('t_')}", _fake_discover)
    agent = _agent_with("hunt", settings_kratos, include_synth=opted_in)

    await agent._function_toolset.tools[tool_name].function(*call_args)

    assert captured["include_synth"] is opted_in


# ---------------------------------------------------------------------------
# Task 3: synth containment — ingest refuses when a synthetic document has
# reached a PRODUCTION index. A planted scenario outside logs-synth-* would be
# shown to a real analyst as genuine, and would contaminate every measurement
# taken after it. The synth catalogue README has mandated this check since the
# catalogue landed (soc_ai/eval/synth_scenarios/README.md, "Synth pollution
# kill-switch"); it is the read-side twin of _check_synth_prefix.
# ---------------------------------------------------------------------------

_LEAKED_INDEX = ".ds-logs-suricata.alerts-so-2026.08.26-000042"


def _es_search_response(hits: list[dict[str, Any]]) -> dict[str, Any]:
    """A raw (transport-level) ES search response with healthy shard metadata."""
    return {
        "took": 2,
        "timed_out": False,
        "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits},
    }


def _ingestable_scenario() -> Scenario:
    """A minimal valid scenario (one triage-target event, synth-prefixed index)."""
    return _scenario(
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
            )
        ]
    )


@pytest.mark.asyncio
async def test_ingest_refuses_when_synth_doc_reached_a_production_index(
    settings_kratos: Settings,
) -> None:
    """A synth-tagged doc outside logs-synth-* must abort ingest — and the
    error must name the offending index so an operator can go clean it."""
    elastic, fake_es = _make_ingest_elastic(settings_kratos)
    fake_es.search = AsyncMock(
        return_value=_es_search_response(
            [
                {
                    "_index": _LEAKED_INDEX,
                    "_id": "leaked-0001",
                    "_source": {"synth.scenario_id": "c2-beacon-tls"},
                }
            ]
        )
    )

    with pytest.raises(RuntimeError, match=_LEAKED_INDEX):
        await ingest_scenarios([_ingestable_scenario()], elastic=elastic, run_time=RUN_TIME)

    # Refused BEFORE any write — nothing was ingested on the contaminated grid.
    fake_es.index.assert_not_called()


@pytest.mark.asyncio
async def test_containment_check_queries_prod_pattern_excluding_synth_indices(
    settings_kratos: Settings,
) -> None:
    """The check searches the PRODUCTION pattern minus logs-synth-*: the prod
    pattern (default logs-*) legitimately matches the synth datastreams, so
    without the exclusion every batch with stale-but-legal synth docs would
    refuse. size=1 — one escaped doc is already a refusal."""
    elastic, fake_es = _make_ingest_elastic(settings_kratos)
    fake_es.search = AsyncMock(return_value=_es_search_response([]))

    await ingest_scenarios([_ingestable_scenario()], elastic=elastic, run_time=RUN_TIME)

    containment_call = fake_es.search.call_args_list[0]
    assert containment_call.kwargs["index"] == "logs-*,-logs-synth-*"
    assert containment_call.kwargs["body"]["query"] == {"exists": {"field": "synth.scenario_id"}}
    assert containment_call.kwargs["body"]["size"] == 1


@pytest.mark.asyncio
async def test_ingest_proceeds_normally_on_a_clean_grid(settings_kratos: Settings) -> None:
    """Negative control: no synth docs in production → ingest runs to completion."""
    elastic, fake_es = _make_ingest_elastic(settings_kratos)
    fake_es.search = AsyncMock(return_value=_es_search_response([]))

    results = await ingest_scenarios([_ingestable_scenario()], elastic=elastic, run_time=RUN_TIME)

    assert len(results) == 1
    assert results[0].scenario_id == "test-ingest"
    fake_es.index.assert_called()  # the writes actually happened


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("shards", "timed_out"),
    [
        # A dead data node: two of three shards never answered.
        ({"total": 3, "successful": 1, "skipped": 0, "failed": 2}, False),
        # All shards nominally answered, but the search timed out first.
        ({"total": 3, "successful": 3, "skipped": 0, "failed": 0}, True),
    ],
)
async def test_containment_refuses_a_partial_read_even_under_the_partial_opt_out(
    settings_kratos: Settings, shards: dict[str, Any], timed_out: bool
) -> None:
    """A degraded search that reads only the surviving shards and returns 0 hits
    is NOT an all-clear — the check could not actually SEE the whole grid. The
    grid-wide ``es_fail_on_partial_results=False`` opt-out (a chronically red
    shard an operator has accepted for ordinary reads) must not soften this
    check: a false all-clear outranks any error, so a partial/timed-out read
    refuses exactly like a transport error, with the partial-read error chained
    as the cause."""
    settings = settings_kratos.model_copy(update={"es_fail_on_partial_results": False})
    elastic, fake_es = _make_ingest_elastic(settings)
    fake_es.search = AsyncMock(
        return_value={
            "took": 2,
            "timed_out": timed_out,
            "_shards": shards,
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        }
    )

    with pytest.raises(RuntimeError, match="could not be performed") as exc_info:
        await ingest_scenarios([_ingestable_scenario()], elastic=elastic, run_time=RUN_TIME)

    assert isinstance(exc_info.value.__cause__, GridPartialResultsError)
    fake_es.index.assert_not_called()


@pytest.mark.asyncio
async def test_ingest_refuses_when_containment_check_cannot_run(
    settings_kratos: Settings,
) -> None:
    """Fail loud, not soft: a transport error during the check is itself a
    refusal — an unverifiable grid must not be treated as clean."""
    elastic, fake_es = _make_ingest_elastic(settings_kratos)
    cause = TransportError("connection reset by peer")
    fake_es.search = AsyncMock(side_effect=cause)

    with pytest.raises(RuntimeError, match="could not be performed") as exc_info:
        await ingest_scenarios([_ingestable_scenario()], elastic=elastic, run_time=RUN_TIME)

    # The original transport error is chained, not swallowed.
    assert exc_info.value.__cause__ is cause
    fake_es.index.assert_not_called()


# ---------------------------------------------------------------------------
# Task 4: the synth-eval marker — a hunt run against synthetic data, and any
# investigation promoted from it, is permanently marked in the store. Without
# the marker a planted attack could later be read back as a real finding (in
# the UI, in a report, or by a future measurement). The marker is reachable
# ONLY from an explicit eval context (ctx.include_synth) or inherited from a
# marked hunt — never from an API request body.
# ---------------------------------------------------------------------------


async def _no_events_run_hunt(ctx: Any, **_kw: Any) -> AsyncIterator[Any]:
    """Stand-in for the hunt agent loop: no events, no model. The recorder
    still creates + finalizes the hunt row, which is all these tests read."""
    return
    yield  # pragma: no cover


@pytest.mark.parametrize("opted_in", [True, False])
async def test_hunt_recorded_run_marks_synth_eval_from_the_eval_context(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch, opted_in: bool
) -> None:
    """The Hunt row's marker comes from the CONTEXT the run was recorded with:
    an eval context (include_synth=True) marks the row; the ordinary context
    (the default every API/scheduler path builds) leaves it False."""
    engine, maker = await _db(settings_kratos)
    monkeypatch.setattr("soc_ai.api.hunt_runner.run_hunt", _no_events_run_hunt)
    state = type("S", (), {"db_sessionmaker": maker})()
    ctx = type("Ctx", (), {"include_synth": opted_in})()

    events = [
        ev
        async for ev in hunt_recorded_run(
            state, ctx=ctx, objective="sweep for the planted beacon", started_by="eval"
        )
    ]
    hunt_id = dict(events)["hunt_created"]["hunt_id"]
    async with maker() as db:
        hunt = await db.get(Hunt, hunt_id)
    assert hunt is not None
    assert hunt.is_synth_eval is opted_in
    await engine.dispose()


@pytest.mark.parametrize("marked", [True, False])
async def test_recorded_run_threads_synth_eval_marker_to_the_row(
    settings_kratos: Settings, marked: bool
) -> None:
    """The promotion chain's bottom hop (recorded_run -> recorder ->
    inv_svc.create) carries the marker to the Investigation row — mirrors
    test_finding_promotion's provenance-threading test."""
    engine, maker = await _db(settings_kratos)
    state = type("S", (), {"db_sessionmaker": maker})()
    events = [
        ev
        async for ev in recorded_run(
            state,
            alert_id="anchor-1",
            started_by="eval",
            event_stream=_empty_stream(),
            is_synth_eval=marked,
        )
    ]
    created = dict(events)["investigation_created"]
    async with maker() as db:
        inv = await db.get(Investigation, created["investigation_id"])
    assert inv is not None
    assert inv.is_synth_eval is marked
    await engine.dispose()


@pytest.mark.parametrize("opted_in", [True, False])
async def test_run_recorded_derives_marker_from_eval_context(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch, opted_in: bool
) -> None:
    """An investigation recorded FROM an eval context is marked even when no
    caller passes the kwarg — same invariant as the hunt side: a run whose
    tools were allowed to see planted scenarios must never persist unmarked."""
    engine, maker = await _db(settings_kratos)

    def _fake_investigate(alert_id: str, **_kw: Any) -> AsyncIterator[Any]:
        return _empty_stream()

    monkeypatch.setattr("soc_ai.api.runner.investigate", _fake_investigate)
    state = type("S", (), {"db_sessionmaker": maker})()
    ctx = type("Ctx", (), {"include_synth": opted_in})()

    events = [
        ev
        async for ev in run_recorded(state, ctx=ctx, alert_id="anchor-synth-1", started_by="eval")
    ]
    created = dict(events)["investigation_created"]
    async with maker() as db:
        inv = await db.get(Investigation, created["investigation_id"])
    assert inv is not None
    assert inv.is_synth_eval is opted_in
    await engine.dispose()


def test_hunt_manager_threads_synth_eval_marker_into_run_recorded() -> None:
    """The middle hop: HuntManager.start passes the marker through to
    run_recorded (and defaults it OFF for every caller that omits it) —
    mirrors test_finding_promotion's allow_so_writes force test."""
    from soc_ai.webui import hunt_manager as hm

    captured: dict[str, Any] = {}

    async def fake_run_recorded(state: Any, **kwargs: Any) -> AsyncIterator[Any]:
        captured.update(kwargs)
        yield "investigation_created", {"investigation_id": "INV-SYNTH"}

    async def run(**start_kwargs: Any) -> str | None:
        with (
            patch.object(hm, "run_recorded", fake_run_recorded),
            patch.object(hm, "ctx_from_state", lambda _s: object()),
        ):
            mgr = hm.HuntManager()
            inv_id = await mgr.start(
                object(), alert_id="tel-doc-000001", started_by="eval", **start_kwargs
            )
            await asyncio.sleep(0)  # let the drain task settle
            return inv_id

    assert asyncio.run(run(is_synth_eval=True)) == "INV-SYNTH"
    assert captured["is_synth_eval"] is True
    captured.clear()
    assert asyncio.run(run()) == "INV-SYNTH"
    assert captured["is_synth_eval"] is False


# ── The promotion route inherits the marker from the source hunt ─────────────


@pytest.fixture
def spine_client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _seed_marked_hunt(client: TestClient, *, is_synth_eval: bool) -> str:
    """Seed a COMPLETE hunt (optionally synth-eval-marked) with one promotable
    finding; returns its id."""

    async def _go() -> str:
        async with client.app.state.db_sessionmaker() as db:
            hunt = await hunt_svc.create(
                db,
                objective=_LONG_OBJECTIVE,
                started_by="eval",
                is_synth_eval=is_synth_eval,
            )
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                report={
                    "findings": [
                        {
                            "title": "Planted C2 beacon",
                            "detail": "10.0.0.5 -> 185.220.101.7 on a fixed cadence.",
                            "hosts": ["10.0.0.5"],
                            "citations": ["tel-doc-000001"],
                        }
                    ]
                },
            )
            return hunt.id

    return asyncio.run(_go())


async def _fake_start_records_marker(
    state: Any,
    *,
    alert_id: str,
    started_by: str,
    rule_name: str | None = None,
    is_synth_eval: bool = False,
    **_kw: Any,
) -> str:
    """HuntManager.start stand-in that persists a real Investigation row with
    exactly the marker the route passed (the lower hops are pinned above)."""
    async with state.db_sessionmaker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_id,
            started_by=started_by,
            rule_name=rule_name,
            is_synth_eval=is_synth_eval,
        )
        return inv.id


@pytest.mark.parametrize("marked", [True, False])
def test_promote_finding_inherits_synth_eval_marker_from_its_hunt(
    spine_client: TestClient, marked: bool
) -> None:
    hunt_id = _seed_marked_hunt(spine_client, is_synth_eval=marked)
    fake_mgr = AsyncMock()
    fake_mgr.start = _fake_start_records_marker
    search_result = EsSearchResult(
        total=1,
        took_ms=1,
        hits=[{"_id": "tel-doc-000001", "_source": {"event": {"dataset": "zeek.conn"}}}],
    )
    with (
        patch(_MGR_TARGET, return_value=fake_mgr),
        patch.object(ElasticClient, "search", AsyncMock(return_value=search_result)),
    ):
        resp = spine_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")

    assert resp.status_code == 200
    inv_id = resp.json()["investigation_id"]

    async def _fetch() -> Investigation | None:
        async with spine_client.app.state.db_sessionmaker() as db:
            return await db.get(Investigation, inv_id)

    inv = asyncio.run(_fetch())
    assert inv is not None
    assert inv.is_synth_eval is marked


# ── The marker is carried out to the wire wherever the row is displayed ──────
# The whole purpose of is_synth_eval is that a hunt run against planted attacks
# (and any investigation promoted from it) can never be mistaken for real
# activity — which requires the flag to REACH the UI, on the list row and the
# opened detail alike. A marker that is persisted but never serialized protects
# nobody.


def _seed_marked_investigation(client: TestClient, *, is_synth_eval: bool) -> str:
    """Seed one investigation row (optionally synth-eval-marked); returns its id."""

    async def _go() -> str:
        async with client.app.state.db_sessionmaker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="synth-anchor-wire-1",
                started_by="eval",
                rule_name="Planted C2 beacon",
                is_synth_eval=is_synth_eval,
            )
            return inv.id

    return asyncio.run(_go())


@pytest.mark.parametrize("marked", [True, False])
def test_hunt_list_and_detail_carry_the_synth_eval_marker_on_the_wire(
    spine_client: TestClient, marked: bool
) -> None:
    hunt_id = _seed_marked_hunt(spine_client, is_synth_eval=marked)

    rows = spine_client.get("/api/v1/hunts").json()
    row = next(r for r in rows if r["id"] == hunt_id)
    assert row["isSynthEval"] is marked

    detail = spine_client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["isSynthEval"] is marked


@pytest.mark.parametrize("marked", [True, False])
def test_investigation_list_and_detail_carry_the_synth_eval_marker_on_the_wire(
    spine_client: TestClient, marked: bool
) -> None:
    inv_id = _seed_marked_investigation(spine_client, is_synth_eval=marked)

    rows = spine_client.get("/api/v1/investigations").json()["rows"]
    row = next(r for r in rows if r["id"] == inv_id)
    assert row["isSynthEval"] is marked

    # The detail route probes live acked state on the grid — stub the ES read
    # (empty, healthy) so this stays a store-serialization test.
    empty = EsSearchResult(total=0, took_ms=1, hits=[])
    with patch.object(ElasticClient, "search", AsyncMock(return_value=empty)):
        detail = spine_client.get(f"/api/v1/investigations/{inv_id}").json()
    assert detail["isSynthEval"] is marked


@pytest.mark.parametrize("marked", [True, False])
def test_notifications_carry_the_synth_eval_marker_on_the_wire(
    spine_client: TestClient, marked: bool
) -> None:
    """The bell and the Notifications screen render investigation and hunt rows
    too — "Verdict true_positive: <planted rule>" with no marker is exactly the
    mistaken-for-real failure the flag exists to prevent. All three entry kinds
    the bell mints from marked rows must carry it: an in-flight investigation,
    a completed one, and a completed hunt."""

    async def _seed() -> tuple[str, str, str]:
        async with spine_client.app.state.db_sessionmaker() as db:
            running = await inv_svc.create(
                db,
                alert_es_id="synth-bell-running",
                started_by="eval",
                rule_name="Planted C2 beacon",
                is_synth_eval=marked,
            )
            done = await inv_svc.create(
                db,
                alert_es_id="synth-bell-done",
                started_by="eval",
                rule_name="Planted C2 beacon",
                is_synth_eval=marked,
            )
            await inv_svc.finalize(
                db, done.id, status="complete", verdict="true_positive", confidence=0.9
            )
            hunt = await hunt_svc.create(
                db,
                objective="sweep for planted beacons",
                started_by="eval",
                is_synth_eval=marked,
            )
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                report={"findings": [{"title": "Planted C2 beacon"}]},
            )
            return running.id, done.id, hunt.id

    running_id, done_id, hunt_id = asyncio.run(_seed())
    by_id = {n["id"]: n for n in spine_client.get("/api/v1/notifications").json()}
    assert by_id[f"inv:{running_id}"]["isSynthEval"] is marked
    assert by_id[f"inv-done:{done_id}"]["isSynthEval"] is marked
    assert by_id[f"hunt-done:{hunt_id}"]["isSynthEval"] is marked


def test_entity_timeline_excludes_synth_eval_rows(spine_client: TestClient) -> None:
    """DESIGN CHOICE (badge-coverage review, surface 2): synth-eval rows are
    EXCLUDED from the entity read-model rather than threaded-and-badged.

    The entity page answers "what do we know about this box", and a planted
    scenario describes nothing that happened on the box — worse, the newest
    run's verdict becomes the page's "latest verdict" (the host's current
    disposition), where a planted true_positive is fiction even with a badge
    beside it. Excluding at the query fixes the timeline, both summary counts
    and latestVerdict in one move; the runs themselves stay fully visible
    (badged) on the Hunts/Investigations lists and their detail pages."""

    async def _seed() -> tuple[str, str]:
        async with spine_client.app.state.db_sessionmaker() as db:
            real = await inv_svc.create(
                db,
                alert_es_id="ent-real",
                started_by="analyst",
                rule_name="ET real detection",
                src_ip="10.0.0.5",
                dest_ip="203.0.113.9",
            )
            await inv_svc.finalize(db, real.id, status="complete", verdict="false_positive")
            synth = await inv_svc.create(
                db,
                alert_es_id="ent-synth",
                started_by="eval",
                rule_name="Planted C2 beacon",
                src_ip="10.0.0.5",
                dest_ip="203.0.113.9",
                is_synth_eval=True,
            )
            await inv_svc.finalize(
                db, synth.id, status="complete", verdict="true_positive", confidence=0.9
            )
            return real.id, synth.id

    real_id, synth_id = asyncio.run(_seed())
    # One marked and one unmarked COMPLETE hunt, each with a finding naming
    # 10.0.0.5 (the host _seed_marked_hunt plants).
    synth_hunt_id = _seed_marked_hunt(spine_client, is_synth_eval=True)
    real_hunt_id = _seed_marked_hunt(spine_client, is_synth_eval=False)

    data = spine_client.get("/api/v1/entity/10.0.0.5").json()
    links = [item["link"] for item in data["timeline"]]
    assert f"/app/investigation/{real_id}" in links
    assert f"/app/investigation/{synth_id}" not in links
    assert f"/app/hunts/{real_hunt_id}" in links
    assert f"/app/hunts/{synth_hunt_id}" not in links
    # The summary strip describes only real history: the planted true_positive
    # (the newer row) must not become this host's "latest verdict".
    assert data["summary"]["investigationCount"] == 1
    assert data["summary"]["huntFindingCount"] == 1
    assert data["summary"]["latestVerdict"] == "false_positive"


# ── The API path can never set the marker ────────────────────────────────────


def test_hunts_chat_request_body_cannot_set_the_synth_eval_marker(
    spine_client: TestClient,
) -> None:
    """A client that smuggles is_synth_eval into the POST /hunts/chat body gets
    an ordinary UNMARKED hunt: the request model doesn't carry the field and
    the route builds its context via ctx_from_state (include_synth=False), so
    the eval opt-in is unreachable from the wire."""
    with patch("soc_ai.api.hunt_runner.run_hunt", _no_events_run_hunt):
        resp = spine_client.post(
            "/api/v1/hunts/chat",
            json={"objective": "hunt for beaconing", "is_synth_eval": True},
        )
        assert resp.status_code == 200
        hunt_id = resp.json()["hunt_id"]

        # Wait for the background drainer to finish INSIDE the patch (the fake
        # loop is resolved lazily when the drain task first iterates it).
        for _ in range(50):  # up to ~5s
            status = spine_client.get(f"/api/v1/hunts/{hunt_id}").json()["status"]
            if status != "running":
                break
            time.sleep(0.1)

    async def _fetch() -> Hunt | None:
        async with spine_client.app.state.db_sessionmaker() as db:
            return await db.get(Hunt, hunt_id)

    hunt = asyncio.run(_fetch())
    assert hunt is not None
    assert hunt.is_synth_eval is False


# ---------------------------------------------------------------------------
# Task 5: the hunt-journey vocabulary — a scenario may declare what a correct
# hunt JOURNEY looks like (the objective to run, the events a correct finding
# cites, the verdict the promoted investigation reaches). The block is
# optional and MUST stay optional: the shipped catalogue predates it, and
# Scenario's extra="forbid" means any schema slip breaks every eval run.
# Loader symbols are imported inside each test (the test_synth_loader.py
# precedent) so a red schema shows up as failing tests, not a module-level
# collection error that takes the Task 1-4 pins down with it.
# ---------------------------------------------------------------------------

SCENARIOS_DIR = Path(__file__).parent.parent / "soc_ai" / "eval" / "synth_scenarios"

_JOURNEY_SCENARIO_YAML = """\
id: {stem}
name: journey-schema probe
version: 1
tier: medium
story: minimal scenario for hunt_journey schema tests
attack: [T1071.001]
ground_truth:
  verdict: true_positive
  confidence_min: 0.7
events:
  - index: logs-synth-suricata-alert
    is_triage_target: true
    fields: {{}}
  - index: logs-synth-zeek-ssl
    fields: {{}}
"""


def _write_journey_scenario(tmp_path: Path, stem: str, journey_block: str = "") -> Path:
    """Write a minimal valid scenario YAML, optionally with a journey block."""
    path = tmp_path / f"{stem}.yaml"
    body = _JOURNEY_SCENARIO_YAML.format(stem=stem)
    if journey_block:
        body += textwrap.dedent(journey_block).strip() + "\n"
    path.write_text(body, encoding="utf-8")
    return path


def test_scenario_without_hunt_journey_loads_as_single_alert_only(tmp_path: Path) -> None:
    """Optional is load-bearing: a journey-free scenario (all 12 as shipped
    before m1 gained one) loads with hunt_journey None, not an error."""
    from soc_ai.eval.synth_loader import load_scenario_file

    scenario = load_scenario_file(_write_journey_scenario(tmp_path, "journey-absent"))

    assert scenario.hunt_journey is None


def test_scenario_with_hunt_journey_loads_the_typed_block(tmp_path: Path) -> None:
    from soc_ai.eval.synth_loader import HuntJourney, load_scenario_file

    path = _write_journey_scenario(
        tmp_path,
        "journey-present",
        """
        hunt_journey:
          objective: Hunt for regular-cadence beaconing to external services.
          expected_cited_event_ids: [logs-synth-zeek-ssl]
          expected_promoted_verdict: true_positive
        """,
    )

    scenario = load_scenario_file(path)

    assert isinstance(scenario.hunt_journey, HuntJourney)
    assert scenario.hunt_journey.objective == (
        "Hunt for regular-cadence beaconing to external services."
    )
    assert scenario.hunt_journey.expected_cited_event_ids == ["logs-synth-zeek-ssl"]
    assert scenario.hunt_journey.expected_promoted_verdict == "true_positive"


def test_hunt_journey_rejects_a_cited_event_id_no_event_has(tmp_path: Path) -> None:
    """Cross-reference guard: a typo'd id would ship a journey the scorer can
    never satisfy — it would look for an event that does not exist and report
    a false failure. Ids are event ``index`` values (events have no id field)."""
    from soc_ai.eval.synth_loader import load_scenario_file

    path = _write_journey_scenario(
        tmp_path,
        "journey-typo",
        """
        hunt_journey:
          objective: Hunt for regular-cadence beaconing to external services.
          expected_cited_event_ids: [logs-synth-zeek-sssl]
          expected_promoted_verdict: true_positive
        """,
    )

    with pytest.raises(ValidationError, match="unknown event id"):
        load_scenario_file(path)


def test_hunt_journey_rejects_unknown_fields(tmp_path: Path) -> None:
    """extra='forbid' on the block itself: a misspelled rubric key must fail
    loud at load time, not silently drop an expectation from the rubric."""
    from soc_ai.eval.synth_loader import load_scenario_file

    path = _write_journey_scenario(
        tmp_path,
        "journey-extra",
        """
        hunt_journey:
          objective: Hunt for regular-cadence beaconing to external services.
          expected_promoted_verdict: true_positive
          expected_promoted_verdicts: true_positive
        """,
    )

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        load_scenario_file(path)


def test_all_shipped_scenario_files_still_load() -> None:
    """Regression guard for Scenario's extra='forbid': every YAML in the
    catalogue must parse through the REAL loader after any schema change."""
    from soc_ai.eval.synth_loader import load_scenario_file

    paths = sorted(SCENARIOS_DIR.glob("*.yaml"))
    assert len(paths) >= 12  # an empty glob must not green this guard
    for path in paths:
        load_scenario_file(path)  # raises on any parse or validation failure


def test_m1_ships_a_hunt_journey_that_does_not_leak_the_answer() -> None:
    """m1 carries the first journey rubric BECAUSE it has a benign twin (b1
    CDN-update beacon): the journey measures discrimination. The objective
    must describe the behaviour to hunt for — naming the scenario, the tool,
    or the fingerprints would measure obedience, not hunting."""
    from soc_ai.eval.synth_loader import load_scenario_file

    m1 = load_scenario_file(SCENARIOS_DIR / "m1-cobalt-strike-beacon.yaml")

    journey = m1.hunt_journey
    assert journey is not None
    assert journey.expected_promoted_verdict == "true_positive"
    assert journey.expected_cited_event_ids  # at least one decisive citation
    lowered = journey.objective.lower()
    for giveaway in ("cobalt", "malleable", "ja3", "104.18.42.69", "10.0.0.115", "m1"):
        assert giveaway not in lowered, f"objective leaks the answer: {giveaway!r}"


# ---------------------------------------------------------------------------
# Scenario/tool fidelity: the planted beacon must be VISIBLE to the cadence
# tool the journey's objective steers the hunt toward. The first end-to-end
# journey run scored FINDING_NOT_PROMOTABLE because m1 encoded its cadence as
# ONE pre-aggregated zeek.conn_summary doc plus a single raw zeek.conn row —
# but t_beacon_profile measures cadence by aggregating RAW event.dataset:
# zeek.conn rows (>= min_events of them, default 8) and computing the
# inter-arrival cv. A "beacon" represented by one connection has no
# inter-arrival profile: the fixture under-specified the attack it claims to
# represent. These tests drive the REAL tool over the REAL rendered scenario
# through the mock-ES aggregation engine (the tests/test_detection_bridge_e2e
# harness), so the pin is on the pair (scenario data-shape, tool contract).
# ---------------------------------------------------------------------------


def _scenario_rendered_elastic(
    settings: Settings, scenario_stem: str, *, id_prefix: str
) -> ElasticClient:
    """A real ``ElasticClient`` whose transport answers from a shipped
    scenario's RENDERED docs via the mock-ES query/aggregation engine —
    the whole tool path (query build, nested terms/top_hits agg, cv math)
    stays real; only the transport is the mock."""
    from datetime import UTC, datetime

    from scripts.demo.mock_es import _search_response_from_docs
    from soc_ai.eval.synth_loader import load_scenario_file
    from soc_ai.eval.synth_render import render_scenario

    scenario = load_scenario_file(SCENARIOS_DIR / f"{scenario_stem}.yaml")
    rendered = render_scenario(scenario, run_time=datetime.now(UTC))
    es_docs = [
        {"_index": doc.index, "_id": f"{id_prefix}-{i:04d}", "_source": dict(doc.body)}
        for i, doc in enumerate(rendered)
    ]
    fake_es = AsyncMock()
    fake_es.search = AsyncMock(
        side_effect=lambda **kw: _search_response_from_docs(kw.get("body") or {}, es_docs)
    )
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        return ElasticClient(settings)


@pytest.mark.asyncio
async def test_m1_rendered_beacon_pair_flags_periodic_in_beacon_profile(
    settings_kratos: Settings,
) -> None:
    """The finding, reproduced: m1's planted beacon must actually LOOK like a
    beacon to the cadence tool the journey steers the hunt toward — enough raw
    zeek.conn rows (>= the tool's min_events=8) at a jittered ~60s cadence
    whose measured inter-arrival cv clears the "periodic" bar (cv <= 0.15,
    _CV_PERIODIC), not just the candidacy bar (cv <= 0.4, _CV_MAX)."""
    elastic = _scenario_rendered_elastic(settings_kratos, "m1-cobalt-strike-beacon", id_prefix="m1")

    out = await beacon_profile(elastic=elastic, settings=settings_kratos, include_synth=True)

    assert out.get("error") is not True
    pairs = {(item["src"], item["dst"]): item for item in out["items"]}
    item = pairs.get(("10.0.0.115", "104.18.42.69"))
    assert item is not None, (
        f"m1's beacon pair is invisible to t_beacon_profile — the flagship "
        f"journey dies at FINDING_NOT_PROMOTABLE (items: {out['items']}, "
        f"summary: {out.get('summary')!r})"
    )
    assert item["events"] >= 8  # the tool's default min_events floor
    assert item["mean_interval_s"] == pytest.approx(60.0, abs=5.0)
    assert item["cv"] <= 0.15, "the story promises ~60s +/- ~6s jitter: periodic, not semi-regular"
    assert item["verdict_hint"] == "periodic"
    # The pair's citable evidence resolves to planted docs, so a hunt finding
    # built on this measurement can cite its way through the journey scorer.
    assert item["sample_ids"], "sample_ids must be non-empty so findings are citable"


@pytest.mark.asyncio
async def test_b1_benign_twin_does_not_flag_in_beacon_profile(
    settings_kratos: Settings,
) -> None:
    """The discrimination guard: b1 (the benign updater twin) must NOT flag —
    its single raw zeek.conn row stays under the tool's min_events floor, so
    the cadence sweep surfaces m1 alone and the TLS/JA3 pivot (stock WinHTTP
    fingerprint + real vendor SNI vs the Cobalt Strike JA3/JA3S pair) remains
    the evidence that separates the twins' verdicts. If this ever starts
    flagging, re-check that m1 vs b1 still turns on evidence, not shape."""
    elastic = _scenario_rendered_elastic(settings_kratos, "b1-cdn-update-beacon", id_prefix="b1")

    out = await beacon_profile(elastic=elastic, settings=settings_kratos, include_synth=True)

    assert out.get("error") is not True
    assert out["items"] == [], (
        f"b1's benign updater must stay under the cadence tool's evidence "
        f"floor (one raw conn row < min_events); got items: {out['items']}"
    )


# ---------------------------------------------------------------------------
# Task 6: the journey scorer — hunt → finding → promote → verdict, scored
# stage by stage. Per-stage attribution is the diagnostic value: a single
# pass/fail would tell an operator nothing about WHERE the journey broke.
# Citations resolve against ingested doc _ids by EXACT membership (the
# hunt_gates 2026-08-25 audit convention — substring matching over
# attacker-influencable strings is forgeable), via a caller-supplied
# event-index → ingested-_ids bridge captured at ingest time.
# Journey symbols are imported inside each test (the Task 5 precedent) so a
# missing/red module fails these tests without taking down the Task 1-5 pins.
# ---------------------------------------------------------------------------

# The ingest-time bridge: event ``index`` → the ES ``_id``s ingest assigned to
# that scenario's docs. Expectations are index-granular (events carry no id
# field), so this loses nothing.
_JOURNEY_DOC_IDS: dict[str, list[str]] = {
    "logs-synth-suricata-alert": ["es-alert-0001"],
    "logs-synth-zeek-ssl": ["es-ssl-0001"],
    "logs-synth-zeek-conn-beacon-summary": ["es-beacon-0001"],
}


def _journey_score_scenario() -> Scenario:
    return Scenario(
        id="journey-score",
        name="journey scorer probe",
        version=1,
        tier="medium",
        story="minimal scenario for journey scoring tests",
        attack=["T1071.001"],
        ground_truth={"verdict": "true_positive", "confidence_min": 0.7},
        events=[
            EventTemplate(index="logs-synth-suricata-alert", is_triage_target=True, fields={}),
            EventTemplate(index="logs-synth-zeek-ssl", fields={}),
            EventTemplate(index="logs-synth-zeek-conn-beacon-summary", fields={}),
        ],
        hunt_journey={
            "objective": "Hunt for regular-cadence beaconing to external services.",
            "expected_cited_event_ids": [
                "logs-synth-zeek-conn-beacon-summary",
                "logs-synth-zeek-ssl",
            ],
            "expected_promoted_verdict": "true_positive",
        },
    )


def _journey_finding(citations: list[str]) -> dict[str, Any]:
    return {
        "title": "Regular-cadence TLS beacon",
        "detail": "10.0.0.115 -> 104.18.42.69 every 60s with near-constant sizes.",
        "severity": "high",
        "category": "threat",
        "hosts": ["10.0.0.115"],
        "citations": citations,
    }


def _journey_hunt(findings: list[dict[str, Any]], *, status: str = "complete") -> Hunt:
    return Hunt(
        id="HJRNY001",
        objective="Hunt for regular-cadence beaconing to external services.",
        status=status,
        is_synth_eval=True,
        report={"findings": findings, "narrative": "probe"},
    )


def _journey_promoted(hunt: Hunt, *, ordinal: int = 0, verdict: str | None) -> Investigation:
    return Investigation(
        id="IJRNY001",
        alert_es_id="es-beacon-0001",
        kind="hunt",
        hunt_id=hunt.id,
        finding_ordinal=ordinal,
        verdict=verdict,
        status="complete" if verdict is not None else "running",
        is_synth_eval=True,
    )


def test_journey_attributes_hunt_found_nothing() -> None:
    from soc_ai.eval.journey import JourneyStage, score_journey

    result = score_journey(
        _journey_score_scenario(),
        hunt=_journey_hunt([]),
        investigation=None,
        doc_ids_by_event=_JOURNEY_DOC_IDS,
    )

    assert result.reached is JourneyStage.HUNT_FOUND_NOTHING
    assert result.scenario_id == "journey-score"
    assert result.expected_verdict == "true_positive"
    assert result.actual_verdict is None
    assert result.cited_expected_events == []
    assert "no findings" in result.detail


def test_journey_attributes_finding_not_promotable() -> None:
    """A finding that cites only the alert doc (ingested, but not an expected
    event) is not promotable to the RIGHT evidence — exact _id membership, so
    a tool marker or an unrelated doc id can never fuzzily count."""
    from soc_ai.eval.journey import JourneyStage, score_journey

    hunt = _journey_hunt([_journey_finding(["es-alert-0001", "tool:t_beacon_profile#1"])])

    result = score_journey(
        _journey_score_scenario(),
        hunt=hunt,
        investigation=None,
        doc_ids_by_event=_JOURNEY_DOC_IDS,
    )

    assert result.reached is JourneyStage.FINDING_NOT_PROMOTABLE
    assert result.actual_verdict is None
    assert result.cited_expected_events == []
    # The detail names what was missing, so an operator knows what to look at.
    assert "logs-synth-zeek-conn-beacon-summary" in result.detail
    assert "logs-synth-zeek-ssl" in result.detail


def test_journey_attributes_verdict_mismatch_with_partial_credit() -> None:
    """The investigation landed the WRONG verdict — and the result still lists
    which expected events WERE cited, so the operator sees how close it got."""
    from soc_ai.eval.journey import JourneyStage, score_journey

    hunt = _journey_hunt([_journey_finding(["es-ssl-0001"])])
    inv = _journey_promoted(hunt, verdict="false_positive")

    result = score_journey(
        _journey_score_scenario(),
        hunt=hunt,
        investigation=inv,
        doc_ids_by_event=_JOURNEY_DOC_IDS,
    )

    assert result.reached is JourneyStage.VERDICT_MISMATCH
    assert result.actual_verdict == "false_positive"
    assert result.expected_verdict == "true_positive"
    assert result.cited_expected_events == ["logs-synth-zeek-ssl"]  # partial credit survives
    assert "false_positive" in result.detail
    assert "true_positive" in result.detail


def test_journey_complete() -> None:
    from soc_ai.eval.journey import JourneyStage, score_journey

    hunt = _journey_hunt([_journey_finding(["es-beacon-0001", "es-ssl-0001"])])
    inv = _journey_promoted(hunt, verdict="true_positive")

    result = score_journey(
        _journey_score_scenario(),
        hunt=hunt,
        investigation=inv,
        doc_ids_by_event=_JOURNEY_DOC_IDS,
    )

    assert result.reached is JourneyStage.COMPLETE
    assert result.actual_verdict == "true_positive"
    # Journey-declaration order, both credited.
    assert result.cited_expected_events == [
        "logs-synth-zeek-conn-beacon-summary",
        "logs-synth-zeek-ssl",
    ]


def test_journey_stalled_promotion_is_attributed_to_the_promotion_boundary() -> None:
    """A right-evidence finding that was never promoted fails at the
    finding→investigation boundary — and the detail says the PROMOTION is what
    is missing, not the citations (which earn partial credit)."""
    from soc_ai.eval.journey import JourneyStage, score_journey

    hunt = _journey_hunt([_journey_finding(["es-beacon-0001"])])

    result = score_journey(
        _journey_score_scenario(),
        hunt=hunt,
        investigation=None,
        doc_ids_by_event=_JOURNEY_DOC_IDS,
    )

    assert result.reached is JourneyStage.FINDING_NOT_PROMOTABLE
    assert result.cited_expected_events == ["logs-synth-zeek-conn-beacon-summary"]
    assert "never promoted" in result.detail


def test_journey_promotion_anchored_on_the_wrong_finding_does_not_reach_verdict() -> None:
    """An investigation promoted from a finding that cited NONE of the expected
    events must not score the verdict stage — even a matching verdict there
    would reward anchoring on the wrong evidence. The verdict is still
    REPORTED (actual_verdict) so the operator sees the near-miss."""
    from soc_ai.eval.journey import JourneyStage, score_journey

    hunt = _journey_hunt(
        [
            _journey_finding(["es-alert-0001"]),  # promoted: cited only the alert
            _journey_finding(["es-ssl-0001"]),  # the right-evidence finding, not promoted
        ]
    )
    inv = _journey_promoted(hunt, ordinal=0, verdict="true_positive")

    result = score_journey(
        _journey_score_scenario(),
        hunt=hunt,
        investigation=inv,
        doc_ids_by_event=_JOURNEY_DOC_IDS,
    )

    assert result.reached is JourneyStage.FINDING_NOT_PROMOTABLE
    assert result.actual_verdict == "true_positive"  # reported, not credited
    assert result.cited_expected_events == ["logs-synth-zeek-ssl"]  # union partial credit


def test_journey_refuses_when_the_bridge_lacks_an_expected_event() -> None:
    """No ingested _ids for an expected event would make that event silently
    uncitable and every run a false FINDING_NOT_PROMOTABLE — the scorer
    refuses (naming the gap) instead of scoring a rigged journey."""
    from soc_ai.eval.journey import score_journey

    hunt = _journey_hunt([_journey_finding(["es-beacon-0001"])])

    with pytest.raises(ValueError, match="logs-synth-zeek-ssl"):
        score_journey(
            _journey_score_scenario(),
            hunt=hunt,
            investigation=None,
            doc_ids_by_event={"logs-synth-zeek-conn-beacon-summary": ["es-beacon-0001"]},
        )


def test_journey_refuses_an_investigation_from_another_hunt() -> None:
    """The join keys (Investigation.hunt_id / finding_ordinal) must match the
    hunt being scored — silently scoring a stray row would attribute another
    journey's verdict to this scenario."""
    from soc_ai.eval.journey import score_journey

    hunt = _journey_hunt([_journey_finding(["es-beacon-0001"])])
    stray = Investigation(
        id="ISTRAY01",
        alert_es_id="es-beacon-0001",
        kind="hunt",
        hunt_id="HOTHER01",
        finding_ordinal=0,
        verdict="true_positive",
        is_synth_eval=True,
    )

    with pytest.raises(ValueError, match="HOTHER01"):
        score_journey(
            _journey_score_scenario(),
            hunt=hunt,
            investigation=stray,
            doc_ids_by_event=_JOURNEY_DOC_IDS,
        )


def test_journey_refuses_an_unmarked_hunt() -> None:
    """A hunt without the Task 4 synth-eval marker could never legitimately
    have seen the planted docs (the kill-switches exclude them) — scoring it
    would only ever produce a false failure, so the scorer refuses."""
    from soc_ai.eval.journey import score_journey

    hunt = _journey_hunt([_journey_finding(["es-beacon-0001"])])
    hunt.is_synth_eval = False

    with pytest.raises(ValueError, match="is_synth_eval"):
        score_journey(
            _journey_score_scenario(),
            hunt=hunt,
            investigation=None,
            doc_ids_by_event=_JOURNEY_DOC_IDS,
        )


def test_journey_refuses_a_scenario_without_a_journey() -> None:
    """Scoring a single-alert-only scenario as a journey is a caller error,
    not a journey outcome."""
    from soc_ai.eval.journey import score_journey

    scenario = _journey_score_scenario()
    scenario.hunt_journey = None

    with pytest.raises(ValueError, match="hunt_journey"):
        score_journey(
            scenario,
            hunt=_journey_hunt([]),
            investigation=None,
            doc_ids_by_event=_JOURNEY_DOC_IDS,
        )


# ---------------------------------------------------------------------------
# Task 7: expected_actions scoring — the rubric's "which write actions should
# a correct triage recommend?" finally scores instead of the standing
# unscoreable give-up. Matching is by write-tool name: each rubric kind maps
# to the ONE write tool that expresses it (escalate → escalate_to_case,
# close_benign → ack_alert); an unrelated recommendation never satisfies a
# kind, and kinds outside the v1 write-tool vocabulary are reported as such
# rather than silently dropped. Like required_citation_kinds, an action
# mismatch is a MISS REASON ONLY — it must never flip `correct` (graders,
# not gatekeepers), or the recall baseline this slice measures against
# silently changes meaning. Scorer symbols are imported inside each test
# (the Task 5/6 precedent).
# ---------------------------------------------------------------------------


def _action_scenario(expected_actions: list[dict[str, Any]], *, verdict: str) -> Scenario:
    """Minimal scenario with the given expected_actions — the
    test_synth_score.py inline-Scenario pattern."""
    return Scenario.model_validate(
        {
            "id": "test-action-score",
            "name": "test",
            "version": 1,
            "tier": "easy",
            "story": "x",
            "attack": ["T1071.001"],
            "ground_truth": {
                "verdict": verdict,
                "confidence_min": 0.7,
                "required_citation_kinds": [],
                "expected_actions": expected_actions,
            },
            "events": [
                {
                    "index": "logs-synth-suricata-alert",
                    "is_triage_target": True,
                    "fields": {"@timestamp": "2026-01-01T00:00:00Z"},
                }
            ],
        }
    )


def test_recommending_the_expected_action_scores_without_action_miss_reason() -> None:
    """A report that recommends the expected escalation carries NO
    expected-action miss reason (and no unscoreable give-up either)."""
    from soc_ai.eval.synth_score import SynthRow, _score_one

    scenario = _action_scenario([{"kind": "escalate"}], verdict="true_positive")
    row = SynthRow(
        scenario_id="test-action-score",
        verdict="true_positive",
        confidence=0.9,
        citations=["blocklist_hit"],
        recommended_actions=["escalate_to_case"],
    )

    detail = _score_one(row, scenario)

    assert detail.correct is True
    # Neither the old give-up ("expected_actions unscoreable") nor a
    # not-recommended reason — the expectation was met.
    assert not any("expected_action" in r for r in detail.miss_reasons), (
        f"expected no action miss reason, got: {detail.miss_reasons}"
    )


def test_recommending_nothing_scores_with_the_action_miss_reason() -> None:
    """A report that recommends NO actions gains a miss reason naming the
    unmet kind — and `correct` is untouched (graders, not gatekeepers)."""
    from soc_ai.eval.synth_score import SynthRow, _score_one, score_synth_stratum

    scenario = _action_scenario([{"kind": "escalate"}], verdict="true_positive")
    row = SynthRow(
        scenario_id="test-action-score",
        verdict="true_positive",
        confidence=0.9,
        citations=["blocklist_hit"],
        recommended_actions=[],
    )

    detail = _score_one(row, scenario)

    assert any(
        "expected action not recommended" in r and "escalate" in r for r in detail.miss_reasons
    ), f"expected a not-recommended miss reason, got: {detail.miss_reasons}"
    # CRITICAL: the action miss never flips correct — verdict + confidence
    # still decide it, so the recall baseline keeps its meaning.
    assert detail.correct is True
    score = score_synth_stratum([row], scenarios=[scenario])
    assert score.true_positive_count == 1
    assert score.escalation_recall == 1.0


def test_recommending_an_unrelated_action_scores_with_the_action_miss_reason() -> None:
    """An unrelated acknowledge must NOT satisfy an expected escalation."""
    from soc_ai.eval.synth_score import SynthRow, _score_one

    scenario = _action_scenario([{"kind": "escalate"}], verdict="true_positive")
    row = SynthRow(
        scenario_id="test-action-score",
        verdict="true_positive",
        confidence=0.9,
        citations=["blocklist_hit"],
        recommended_actions=["ack_alert", "add_case_comment"],
    )

    detail = _score_one(row, scenario)

    assert any(
        "expected action not recommended" in r and "escalate" in r for r in detail.miss_reasons
    )
    assert detail.correct is True


@pytest.mark.parametrize(
    ("recommended", "satisfied"),
    [(["ack_alert"], True), (["escalate_to_case"], False)],
)
def test_close_benign_is_satisfied_by_ack_alert_only(
    recommended: list[str], satisfied: bool
) -> None:
    """The benign direction of the mapping: close_benign ↔ ack_alert (the
    product's close-as-benign write action); escalating instead is a miss."""
    from soc_ai.eval.synth_score import SynthRow, _score_one

    scenario = _action_scenario([{"kind": "close_benign"}], verdict="false_positive")
    row = SynthRow(
        scenario_id="test-action-score",
        verdict="false_positive",
        confidence=0.9,
        citations=["prefetch_pivot"],
        recommended_actions=recommended,
    )

    detail = _score_one(row, scenario)

    assert detail.correct is True
    has_miss = any("expected action not recommended" in r for r in detail.miss_reasons)
    assert has_miss is (not satisfied)


def test_unmappable_action_kind_is_reported_not_silently_dropped() -> None:
    """Kinds outside the v1 write-tool vocabulary (isolate, block_indicator,
    disable_account) can never be recommended through recommended_actions.
    The scorer says so explicitly — naming the kind and its target — instead
    of silently dropping the rubric field or blaming the model."""
    from soc_ai.eval.synth_score import SynthRow, _score_one

    scenario = _action_scenario(
        [{"kind": "isolate", "target_field": "source.ip"}], verdict="true_positive"
    )
    # Even a report recommending every v1 write tool cannot satisfy it.
    row = SynthRow(
        scenario_id="test-action-score",
        verdict="true_positive",
        confidence=0.9,
        citations=["blocklist_hit"],
        recommended_actions=["ack_alert", "escalate_to_case", "add_case_comment"],
    )

    detail = _score_one(row, scenario)

    assert detail.correct is True
    reason = next(r for r in detail.miss_reasons if "no write-tool equivalent" in r)
    assert "isolate" in reason
    assert "source.ip" in reason


def test_action_kind_map_targets_only_real_write_tools() -> None:
    """The kind→tool map must stay inside triage_models.WriteToolName — a
    write-tool rename would otherwise silently turn every expectation into a
    permanent miss."""
    from typing import get_args

    from soc_ai.eval.synth_score import _ACTION_KIND_TO_TOOL
    from soc_ai.triage_models import WriteToolName

    assert set(_ACTION_KIND_TO_TOOL.values()) <= set(get_args(WriteToolName))


@pytest.mark.asyncio
async def test_recommended_actions_from_report_land_on_index_row(tmp_path: Path) -> None:
    """The batch runner captures the report's recommended-action tool names on
    the IndexRow — same site and shape discipline as `citations` (mirrors
    test_eval_batch.test_citations_from_report_land_on_index_row)."""
    import json

    from soc_ai.eval.batch import BatchConfig, run_batch
    from soc_ai.eval.harness import EvalResult
    from soc_ai.eval.oracle_client import OracleResponse
    from soc_ai.eval.sanitize import Mapping

    from tests.test_eval_batch import _make_sampler, _settings

    async def _runner_with_actions(
        alert_id: str, *, settings: Any, out_dir: Path, **_kw: Any
    ) -> EvalResult:
        bundle = out_dir / f"2026-01-01T000000Z-{alert_id}"
        bundle.mkdir(parents=True, exist_ok=True)
        md = "## 1. Verdict\n\nAGREEMENT: yes\n"
        (bundle / "response.md").write_text(md, encoding="utf-8")
        (bundle / "events.jsonl").write_text(
            json.dumps({"kind": "session_start", "sequence": 1, "payload": {}}) + "\n",
            encoding="utf-8",
        )
        return EvalResult(
            bundle_dir=bundle,
            response_md=md,
            sanitized_events=[],
            sanitized_report={
                "verdict": "true_positive",
                "confidence": 0.9,
                "citations": ["blocklist_hit:ip=1.2.3.4"],
                "recommended_actions": [
                    {
                        "tool_name": "escalate_to_case",
                        "tool_args": {"title": "C2 escalation"},
                        "rationale": "confirmed C2",
                    },
                    {
                        "tool_name": "add_case_comment",
                        "tool_args": {},
                        "rationale": "context for the analyst",
                    },
                ],
            },
            mapping=Mapping(),
            oracle_response=OracleResponse(
                text=md,
                model="test",
                usage={
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                },
                elapsed_ms=100,
            ),
            investigation_elapsed_ms=1000,
        )

    summary = await run_batch(
        BatchConfig(oql="x", n=1, out_dir=tmp_path),
        settings=_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=_make_sampler(["a1"]),
        runner=_runner_with_actions,
    )

    rows = [
        json.loads(line)
        for line in (summary.batch_dir / "index.jsonl").read_text().splitlines()
        if line
    ]
    assert len(rows) == 1
    assert rows[0]["recommended_actions"] == ["escalate_to_case", "add_case_comment"]


def test_report_synth_stratum_scores_recommended_actions_from_the_index(
    tmp_path: Path,
) -> None:
    """End-to-end through report.build_report: the index row's captured
    actions reach the scorer, so a satisfied expectation adds no
    not-recommended reason while the catalogue's unmappable kinds (e1 also
    expects isolate) surface explicitly. Without the report.py SynthRow
    bridge this feature would be dead code — every batch would score as
    'recommended nothing'."""
    import json

    from soc_ai.eval.report import build_report

    from tests.test_eval_report import _row

    synth = _row("synth-doc-e1", verdict="true_positive", confidence=0.92)
    synth["is_synth"] = True
    synth["synth_scenario_id"] = "e1-emotet-feodo-c2"
    synth["citations"] = ["blocklist_hit", "typed_path"]
    synth["recommended_actions"] = ["escalate_to_case"]
    (tmp_path / "index.jsonl").write_text(json.dumps(synth) + "\n", encoding="utf-8")

    json_path, _, _ = build_report(tmp_path)
    saved = json.loads(json_path.read_text())

    detail = saved["synth_stratum"]["per_scenario"]["e1-emotet-feodo-c2"]
    assert detail["correct"] is True
    # The recommended escalation satisfied `kind: escalate`.
    assert not any("expected action not recommended" in r for r in detail["miss_reasons"])
    # e1 also expects `kind: isolate` (target source.ip) — outside the v1
    # write-tool vocabulary, reported as such.
    assert any("no write-tool equivalent" in r and "isolate" in r for r in detail["miss_reasons"])


# ---------------------------------------------------------------------------
# Task 8: the decisive-value support gate (H1, 2026-08-25 audit — the deferred
# half). The trust gates checked that evidence was GATHERED, never that it
# SUPPORTS the verdict: one successful tool call let an attacker-dictated
# true_positive @0.95 persist verbatim, escalate action and all. The new gate
# asks the deterministic half of "does the conclusion follow?": a decisive
# indicator VALUE the verdict asserts (a globally-routable IP, a file hash)
# must appear in a document the run actually retrieved — the prefetched
# bundle or a real tool result. Doctrine (the floor-rewrite lessons): band,
# never zero; coerce only when the asserted evidence is genuinely absent;
# stay SILENT when no decisive value is asserted at all. Gate symbols are
# imported inside each test (the Task 5-7 precedent).
# ---------------------------------------------------------------------------

# The two IPs of the support-gate fixture: one genuinely in the prefetched
# bundle (the alert's own destination), one appearing in NO retrieved document.
_RETRIEVED_BAD_IP = "185.220.101.7"
_FABRICATED_BAD_IP = "185.220.101.66"


def _support_ctx(*, with_ioc_hit: bool = False) -> Any:
    """A real EnrichedAlertContext (the test_recall_fix pattern) whose bundle
    contains _RETRIEVED_BAD_IP and nothing resembling _FABRICATED_BAD_IP. The
    rule name is deliberately non-malware-signalling so GATE A stays out of
    these tests."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    alert = SoAlert.from_es_hit(
        {
            "_id": "alert-h1-support",
            "_source": {
                "event.dataset": "suricata.alert",
                "rule.name": "ET POLICY Observed External IP Lookup",
                "source.ip": "10.0.0.115",
                "destination.ip": _RETRIEVED_BAD_IP,
            },
        }
    )
    enrichments = {}
    if with_ioc_hit:
        from soc_ai.enrichment.blocklists import BlocklistHit
        from soc_ai.tools.enrichment import IndicatorEnrichment

        enrichments = {
            _RETRIEVED_BAD_IP: IndicatorEnrichment(
                indicator=_RETRIEVED_BAD_IP,
                indicator_type="ip",
                blocklist_hits=[
                    BlocklistHit(
                        indicator=_RETRIEVED_BAD_IP,
                        indicator_type="ip",
                        source="abuse.ch Feodo Tracker",
                        tags=("c2",),
                    )
                ],
            )
        }
    return EnrichedAlertContext(alert=alert, enrichments=enrichments)


def _support_tp(summary: str, citations: list[str]) -> Any:
    """A confident TP with an escalate action — the exact H1 repro shape."""
    from soc_ai.agent.triage import RecommendedAction, TriageReport

    return TriageReport(
        verdict="true_positive",
        confidence=0.95,
        summary=summary,
        citations=citations,
        recommended_actions=[
            RecommendedAction(
                tool_name="escalate_to_case",
                tool_args={"title": "C2 escalation"},
                rationale="confirmed C2",
            )
        ],
    )


def _support_validate(report: Any, ctx: Any, messages: list[Any] | None = None) -> Any:
    """Run the post-validate chain WITH tool evidence — the H1 precondition
    (one successful tool call already exempts the hard evidence gate)."""
    from soc_ai.agent.gates import _synth_first_post_validate

    from tests.test_recall_fix import _tool_evidence

    return _synth_first_post_validate(
        report,
        ctx,
        candidate=None,
        targeted_messages=messages if messages is not None else _tool_evidence(),
        targeted_tool_called=None,
    )


def test_tp_asserting_a_retrieved_decisive_value_is_unaffected() -> None:
    """Case 1: the asserted decisive value IS in a retrieved document (the
    alert's own destination IP in the prefetched bundle) → the gate has
    nothing to say; verdict, confidence and actions all survive."""
    report = _support_tp(
        f"Beaconing to {_RETRIEVED_BAD_IP} on a fixed cadence; the flow records confirm it.",
        ["alert.destination_ip", _RETRIEVED_BAD_IP],
    )
    out, audit = _support_validate(report, _support_ctx())

    assert out.verdict == "true_positive"
    assert out.confidence == pytest.approx(0.95)
    assert out.recommended_actions == report.recommended_actions
    assert "unsupported_decisive_value_downgrade" not in audit
    assert "decisive_value_support_cap" not in audit


def test_tp_asserting_a_decisive_value_retrieved_nowhere_is_coerced() -> None:
    """Case 2 — the H1 repro: with one successful tool call, a TP whose
    asserted decisive value appears in NO retrieved document currently
    persists verbatim (escalate action and all). The gate must coerce it to
    needs_more_info in the 0.4 band, clear the actions, and record the
    decision in the audit dict."""
    report = _support_tp(
        f"Beaconing to known-bad {_FABRICATED_BAD_IP} confirmed; escalate immediately.",
        ["alert.rule_name"],  # resolves as a strict path → full citation coverage
    )
    out, audit = _support_validate(report, _support_ctx())

    assert out.verdict == "needs_more_info"
    assert out.confidence <= 0.4
    assert out.recommended_actions == []
    entry = audit["unsupported_decisive_value_downgrade"]
    assert entry["original_verdict"] == "true_positive"
    assert _FABRICATED_BAD_IP in entry["unsupported_values"]


def test_verdict_asserting_no_decisive_value_is_left_alone() -> None:
    """Case 3 — the silence condition: a verdict that asserts no decisive
    value at all (no global IP, no hash — just prose and path citations) is
    NONE of this gate's business, whatever its other qualities."""
    report = _support_tp(
        "External IP lookup judged malicious from the rule context and flow shape.",
        ["alert.rule_name"],
    )
    out, audit = _support_validate(report, _support_ctx())

    assert out.verdict == "true_positive"
    assert out.confidence == pytest.approx(0.95)
    assert out.recommended_actions == report.recommended_actions
    assert "unsupported_decisive_value_downgrade" not in audit
    assert "decisive_value_support_cap" not in audit


def test_value_retrieved_by_a_tool_call_supports_the_verdict() -> None:
    """A decisive value that entered the run through a REAL tool result (not
    the prefetch bundle) is retrieved evidence — a verdict resting on it must
    not be punished. This is the model-variance guard: investigation-loop
    finds are as citable as prefetched ones."""
    from tests.test_recall_fix import _Msg, _RetPart

    tool_found_ip = "45.155.205.233"  # in no bundle field — only the tool doc
    messages = [
        _Msg(
            [
                _RetPart(
                    {
                        "total": 1,
                        "hits": [
                            {
                                "_id": "loop-doc-000001",
                                "_source": {"destination": {"ip": tool_found_ip}},
                            }
                        ],
                    }
                )
            ]
        )
    ]
    report = _support_tp(
        f"Related flows to {tool_found_ip} found during the investigation confirm the C2 channel.",
        ["alert.rule_name", "loop-doc-000001"],
    )
    out, audit = _support_validate(report, _support_ctx(), messages=messages)

    assert out.verdict == "true_positive"
    assert out.confidence == pytest.approx(0.95)
    assert "unsupported_decisive_value_downgrade" not in audit
    assert "decisive_value_support_cap" not in audit


def test_partial_support_bands_confidence_and_preserves_the_verdict() -> None:
    """One asserted value retrieved, one not → the verdict LABEL survives
    (evidence is not genuinely absent) and confidence takes the banded shave —
    never a zero-out, never an erased verdict."""
    report = _support_tp(
        f"Beaconing to {_RETRIEVED_BAD_IP}, with secondary C2 at {_FABRICATED_BAD_IP}.",
        ["alert.destination_ip"],
    )
    out, audit = _support_validate(report, _support_ctx())

    assert out.verdict == "true_positive"
    # support_ratio 0.5 → the ≥0.5 band → 0.9x of 0.95.
    assert out.confidence == pytest.approx(0.95 * 0.9)
    cap = audit["decisive_value_support_cap"]
    assert cap["support_ratio"] == pytest.approx(0.5)
    assert cap["unsupported_values"] == [_FABRICATED_BAD_IP]
    assert "unsupported_decisive_value_downgrade" not in audit


def test_a_real_ioc_hit_exempts_the_coercion_but_not_the_band() -> None:
    """A genuine blocklist IOC hit grounds the escalation, so even a fully
    unsupported asserted value (e.g. the model fat-fingered the IP in its
    narrative) must not ERASE the verdict — it bands confidence instead. An
    attacker cannot manufacture this exemption: it requires the indicator to
    actually be on a blocklist."""
    report = _support_tp(
        f"Beaconing to Feodo-listed {_FABRICATED_BAD_IP} confirmed.",
        ["alert.rule_name"],
    )
    out, audit = _support_validate(report, _support_ctx(with_ioc_hit=True))

    assert out.verdict == "true_positive"
    # support_ratio 0.0 → the <0.25 band → 0.5x of 0.95 (above the 0.4 floor).
    assert out.confidence == pytest.approx(0.95 * 0.5)
    assert "unsupported_decisive_value_downgrade" not in audit
    assert "decisive_value_support_cap" in audit


# ---------------------------------------------------------------------------
# Holdout benign twin (b4) — authored blind to the decisive-value gate
# ---------------------------------------------------------------------------


def test_b4_holdout_benign_twin_loads_through_the_real_loader() -> None:
    """b4-av-dns-reputation is the fourth benign twin: AV cloud
    file-reputation DNS lookups, the tunnel-shaped twin of m2. It was
    authored as a HOLDOUT — designed without reading the gate it will
    measure — so escalation precision on it reflects generalization,
    not tuning to the three benign twins the gate grew up with."""
    from soc_ai.eval.synth_loader import load_all_scenarios

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    b4 = next(s for s in scenarios if s.id == "b4-av-dns-reputation")

    assert b4.ground_truth.verdict == "false_positive"
    assert b4.tier == "medium"
    assert b4.attack == []
    assert [a.kind for a in b4.ground_truth.expected_actions] == ["close_benign"]

    # The catalogue's benign stratum is now eight scenarios.
    benign = {s.id for s in scenarios if s.ground_truth.verdict == "false_positive"}
    assert len(benign) == 8
    assert "b4-av-dns-reputation" in benign

    # Synth pollution kill-switch invariant: every event in the whole
    # catalogue (b4 included) must live under the logs-synth- prefix.
    for scenario in scenarios:
        for event in scenario.events:
            assert event.index.startswith("logs-synth-"), (
                f"{scenario.id}/{event.index}: outside the logs-synth- prefix"
            )


# ---------------------------------------------------------------------------
# Task 7: the journey runner — `soc-ai eval-journey` orchestrates ingest →
# hunt → promote → investigate → score for ONE scenario. These tests drive the
# REAL chain (ingest_scenarios' containment check, hunt_recorded_run + the hunt
# agent + the post-hunt gates, the promotion anchor pick, run_recorded + the
# investigation recorder, score_journey) with only the MODEL scripted (a
# FunctionModel, so the hunt's grid read and its report are honest inputs to
# the gates — nothing is stubbed away) and the GRID mocked at the transport
# level, the tests/test_detection_bridge_e2e.py pattern. Runner symbols are
# imported inside each test (the Task 5/6 precedent) so a red/missing module
# fails these tests without taking down the earlier pins.
# ---------------------------------------------------------------------------


def _runner_scenario() -> Scenario:
    """A minimal journey scenario: a triage-target alert + the decisive zeek.ssl
    doc a correct finding must cite. RFC1918/RFC5737 addressing only."""
    return Scenario(
        id="journey-runner-probe",
        name="journey runner probe",
        version=1,
        tier="medium",
        story="minimal scenario for journey-runner orchestration tests",
        attack=["T1071.001"],
        ground_truth={"verdict": "true_positive", "confidence_min": 0.7},
        events=[
            EventTemplate(
                index="logs-synth-suricata-alert",
                is_triage_target=True,
                fields={
                    "@timestamp": "{{ run_time }}",
                    "event.dataset": "suricata.alert",
                    "source.ip": "10.0.0.42",
                    "destination.ip": "198.51.100.7",
                },
            ),
            EventTemplate(
                index="logs-synth-zeek-ssl",
                fields={
                    "@timestamp": "{{ run_time }}",
                    "event.dataset": "zeek.ssl",
                    "source.ip": "10.0.0.42",
                    "destination.ip": "198.51.100.7",
                },
            ),
        ],
        hunt_journey={
            "objective": "Hunt for regular-cadence beaconing to external services.",
            "expected_cited_event_ids": ["logs-synth-zeek-ssl"],
            "expected_promoted_verdict": "true_positive",
        },
    )


def _journey_grid(settings: Settings) -> tuple[ElasticClient, AsyncMock]:
    """A transport-level mock grid that records ingested docs and serves them back.

    Ingest writes land in ``docs`` with long (id-shaped, ≥12-char) ``_id``s;
    searches answer from that store: the containment pre-check (prod pattern
    minus logs-synth-*) sees a clean grid, aggregation probes (the dataset
    inventory) see nothing, an ``ids`` lookup (the promotion anchor pick)
    resolves exactly the requested docs, and any other query (the hunt's OQL
    read) returns everything planted — so the hunt's citations and the anchor
    both resolve against what ingest actually wrote.
    """
    docs: list[dict[str, Any]] = []
    fake_es = AsyncMock()

    async def _index(**kwargs: Any) -> dict[str, Any]:
        doc_id = f"jr-es-doc-{len(docs):06d}"
        docs.append(
            {
                "_index": str(kwargs.get("index") or ""),
                "_id": doc_id,
                "_source": kwargs.get("body") or {},
            }
        )
        return {"_id": doc_id, "result": "created"}

    async def _search(**kwargs: Any) -> dict[str, Any]:
        index = str(kwargs.get("index") or "")
        body = kwargs.get("body") or {}
        if "-logs-synth-*" in index:
            return _es_search_response([])  # containment: nothing escaped
        # A probe asks for aggregates and no hits. "Has aggs" alone stopped
        # discriminating once every OQL read began carrying a reserved
        # composition agg (so a count can say what it counted) — routing the
        # hunt's own grid read here as though it were the inventory probe, and
        # failing the journey with an empty read rather than a real defect.
        if "aggs" in body and not body.get("size"):
            return _es_search_response([])  # dataset-inventory probe
        ids = body.get("query", {}).get("ids", {}).get("values")
        if ids is not None:
            wanted = {str(i) for i in ids}
            return _es_search_response([d for d in docs if d["_id"] in wanted])
        return _es_search_response(list(docs))

    fake_es.index = AsyncMock(side_effect=_index)
    fake_es.search = AsyncMock(side_effect=_search)
    fake_es.indices = AsyncMock()
    fake_es.indices.refresh = AsyncMock(return_value={"acknowledged": True})
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    return client, fake_es


def _scripted_hunt_model(report_args: Callable[[list[str]], dict[str, Any]]) -> FunctionModel:
    """The scripted hunt agent: ONE real grid read, then the final HuntReport.

    The first call issues ``t_query_events_oql`` (a genuinely-executed
    grid-backed read, so the evidence-count gate sees a hunt that looked); the
    second builds the report from the ``_id``s that read actually returned, so
    the citation gate resolves them by structural membership — the honest path
    through every post-hunt gate, with nothing stubbed away.
    """

    def _fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        returns = [
            part
            for msg in messages
            if isinstance(msg, ModelRequest)
            for part in msg.parts
            if isinstance(part, ToolReturnPart)
        ]
        if not returns:
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        tool_name="t_query_events_oql",
                        args={"query": "event.dataset:zeek.ssl"},
                    )
                ]
            )
        content = returns[-1].content
        hits = content.get("hits", []) if isinstance(content, dict) else []
        hit_ids = [str(h["_id"]) for h in hits if isinstance(h, dict) and h.get("_id")]
        assert info.output_tools, "hunt agent advertises no output tool"
        return ModelResponse(
            parts=[ToolCallPart(tool_name=info.output_tools[0].name, args=report_args(hit_ids))]
        )

    return FunctionModel(_fn)


def _scripted_investigate(verdict: str) -> Callable[..., AsyncIterator[StepEvent]]:
    """A stand-in for the promoted investigation's inner loop (the established
    ``soc_ai.api.runner.investigate`` patch point): the recorder chain above it
    stays real, and the row lands this verdict."""

    def _fake(alert_id: str, **_kw: Any) -> AsyncIterator[StepEvent]:
        async def _stream() -> AsyncIterator[StepEvent]:
            yield StepEvent(
                kind="triage_report",
                session_id="jr",
                sequence=1,
                payload={
                    "verdict": verdict,
                    "confidence": 0.8,
                    "summary": "planted beacon confirmed",
                },
            )

        return _stream()

    return _fake


@pytest.mark.asyncio
async def test_journey_runner_complete_journey_exits_zero(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The full arc lands COMPLETE and exit 0 — and the promoted row proves the
    REAL chain ran (kind='hunt', joined to the hunt, synth-eval-marked)."""
    from soc_ai.eval.journey import JourneyStage
    from soc_ai.eval.journey_runner import run_journey
    from soc_ai.store.db import make_engine, make_sessionmaker

    elastic, _fake_es = _journey_grid(settings_kratos)
    scenario = _runner_scenario()

    def _report(hit_ids: list[str]) -> dict[str, Any]:
        return {
            "narrative": (
                "Suspicious: one internal host beacons on a regular cadence, "
                "corroborated by the zeek.ssl records cited below."
            ),
            "findings": [
                {
                    "title": "Regular-cadence TLS beacon",
                    "detail": "10.0.0.42 -> 198.51.100.7 on a fixed cadence with TLS metadata.",
                    "severity": "medium",
                    "category": "threat",
                    "hosts": ["10.0.0.42"],
                    "citations": hit_ids,
                }
            ],
            "affected_hosts": ["10.0.0.42"],
            "confidence": 0.7,
        }

    monkeypatch.setattr(
        "soc_ai.api.hunt_runner.build_investigator_model",
        lambda _settings: _scripted_hunt_model(_report),
    )
    monkeypatch.setattr("soc_ai.api.runner.investigate", _scripted_investigate("true_positive"))

    outcome = await run_journey(settings_kratos, scenario, elastic=elastic)

    assert outcome.exit_code == 0
    assert outcome.result is not None
    assert outcome.result.reached is JourneyStage.COMPLETE
    assert outcome.result.expected_verdict == "true_positive"
    assert outcome.result.actual_verdict == "true_positive"
    assert outcome.result.cited_expected_events == ["logs-synth-zeek-ssl"]
    assert outcome.hunt_id is not None
    assert outcome.investigation_id is not None

    # The investigation came through the real promotion chain, not a
    # hand-crafted row: hunt-kind, joined to this hunt's finding 0, marked.
    engine = make_engine(settings_kratos)
    try:
        maker = make_sessionmaker(engine)
        async with maker() as db:
            inv = await db.get(Investigation, outcome.investigation_id)
    finally:
        await engine.dispose()
    assert inv is not None
    assert inv.kind == "hunt"
    assert inv.hunt_id == outcome.hunt_id
    assert inv.finding_ordinal == 0
    assert inv.is_synth_eval is True
    assert inv.status == "complete"


@pytest.mark.asyncio
async def test_journey_runner_hunt_found_nothing_exits_nonzero(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hunt that reads the grid but surfaces NO findings scores
    HUNT_FOUND_NOTHING, promotes nothing (no GPU spent on a doomed
    investigation), and exits non-zero so a CI gate can fail on it."""
    from soc_ai.eval.journey import JourneyStage
    from soc_ai.eval.journey_runner import run_journey

    elastic, _fake_es = _journey_grid(settings_kratos)
    scenario = _runner_scenario()

    def _report(_hit_ids: list[str]) -> dict[str, Any]:
        return {
            "narrative": "No malicious indication: nothing on this grid matched the objective.",
            "findings": [],
            "confidence": 0.4,
        }

    monkeypatch.setattr(
        "soc_ai.api.hunt_runner.build_investigator_model",
        lambda _settings: _scripted_hunt_model(_report),
    )

    def _unexpected_investigate(alert_id: str, **_kw: Any) -> AsyncIterator[StepEvent]:
        raise AssertionError("nothing was promotable — investigate() must not run")

    monkeypatch.setattr("soc_ai.api.runner.investigate", _unexpected_investigate)

    outcome = await run_journey(settings_kratos, scenario, elastic=elastic)

    assert outcome.exit_code != 0
    assert outcome.result is not None
    assert outcome.result.reached is JourneyStage.HUNT_FOUND_NOTHING
    assert outcome.result.actual_verdict is None
    assert outcome.result.cited_expected_events == []
    assert outcome.investigation_id is None


# ---------------------------------------------------------------------------
# Fixture-shape fidelity (batch 2026-08-26T133449Z finding): synthetic alerts
# must parse like real Security Onion documents. 8 of 9 TP scenarios scored
# below 1.0 citation coverage, every one with an unresolved citation naming
# the alert's severity metadata. Root cause: the scenario YAMLs wrote
# signature_severity / classtype flattened at the top level of the event
# source, while a real SO document carries them under rule.metadata
# (single-element-list values) and inside the EVE message JSON as
# alert.category — which is where SoAlert reads them. Every synthetic alert
# therefore parsed with rule_metadata=None, so the citation could never
# resolve, while the identical citation resolved on the batch's one real
# alert. Coverage < 1.0 caps confidence, turning correct detections into
# recorded misses — an instrument defect, not a product bug.
# ---------------------------------------------------------------------------

_SCENARIOS_DIR = Path(__file__).resolve().parents[1] / "soc_ai" / "eval" / "synth_scenarios"


def test_rendered_triage_alert_carries_severity_metadata_where_soalert_reads_it() -> None:
    """A rendered triage doc, parsed through SoAlert exactly as the harness
    parses a live hit, must yield a populated rule_metadata — and the very
    citation path the model kept writing must resolve against the context."""
    scenario = load_scenario_file(_SCENARIOS_DIR / "e1-emotet-feodo-c2.yaml")
    docs = render_scenario(scenario, run_time=RUN_TIME)
    triage = next(d for d in docs if d.is_triage_target)

    alert = SoAlert.from_es_hit({"_id": "synth-e1", "_source": triage.body})

    assert alert.rule_metadata is not None, (
        "rule_metadata parsed as None — the severity metadata is not where "
        "SoAlert reads it (rule.metadata, single-element-list values)"
    )
    assert alert.rule_metadata.signature_severity == "Major"
    assert alert.classtype == "trojan-activity"

    ctx = AlertContext(alert=alert)
    assert _path_exists_in_alert(ctx, "alert.rule_metadata.signature_severity") is True
    assert _path_exists_in_alert(ctx, "alert.classtype") is True


def test_every_scenario_parses_its_severity_metadata_through_soalert() -> None:
    """Catalogue-wide pin: severity/classification metadata visible anywhere
    in a rendered triage document must be reachable through the typed parse.
    Visible-but-unresolvable is exactly what produced the unresolved-citation
    cluster (the model can see the value in raw and tries every spelling)."""
    # Scoped to the triage population: this asserts a property of the rendered
    # ALERT, and a spec_journey scenario deliberately has none.
    scenarios = triage_scenarios(load_all_scenarios(_SCENARIOS_DIR))
    assert scenarios, "scenario catalogue is empty"
    for scenario in scenarios:
        docs = render_scenario(scenario, run_time=RUN_TIME)
        triage = next(d for d in docs if d.is_triage_target)
        body_text = json.dumps(triage.body)
        alert = SoAlert.from_es_hit({"_id": f"synth-{scenario.id}", "_source": triage.body})
        if "signature_severity" in body_text:
            assert alert.rule_metadata is not None, (
                f"{scenario.id}: signature_severity present in the rendered "
                "doc but rule_metadata parsed as None"
            )
            assert alert.rule_metadata.signature_severity, scenario.id
        if "classtype" in body_text or '"category"' in body_text:
            assert alert.classtype, (
                f"{scenario.id}: classtype visible in the rendered doc but "
                "SoAlert.classtype is None (it reads message JSON alert.category)"
            )
        # The flattened top-level spellings must not come back: they are the
        # unparseable shape this finding is about.
        assert "signature_severity" not in triage.body, scenario.id
        assert "classtype" not in triage.body, scenario.id


# ---------------------------------------------------------------------------
# Answer-key leak: the synth marker must never reach the MODEL. Every planted
# document carries `synth.scenario_id` / `synth.scenario_version` (the
# harness's join key) and lives in a `logs-synth-*` index — and both were
# arriving verbatim in the model's tool results (batch 2026-08-26, the
# m1-cobalt-strike-beacon trace literally reads the scenario id off the
# evidence). The markers must STAY in Elasticsearch — the exclusion filters,
# the containment check, `synth-clean` and the journey scorer's `_id` joins
# all depend on them — but the model-visible copy of a document must not
# carry the answer key. The strip is the MARKER ONLY: everything else under
# `synth.*` is the scenario's planted evidence and must flow (2026-08-27: a
# namespace-wide strip amputated it and the eval measured the strip, not
# the model). These tests pin all three: marker stripped at the model
# boundary, evidence preserved through it, everything intact where the
# harness reads.
# ---------------------------------------------------------------------------


def _planted_hit() -> dict[str, Any]:
    """A raw ES hit shaped like the m1 triage doc that leaked (dotted synth
    keys, a nested `synth` object for the mapped-object spelling, and the
    `.ds-logs-synth-*` backing-index name)."""
    return {
        "_index": ".ds-logs-synth-suricata-alert-2026.08.12-000004",
        "_id": "xeZ3QKABZjR0vNGrpz7u",
        "_score": 1.0,
        "_source": {
            "@timestamp": "2026-08-26T23:46:17.876008+00:00",
            "rule.name": "ET HUNTING Possible Cobalt Strike Extra Whitespace HTTP Response",
            "event.dataset": "suricata.alert",
            "source.ip": "10.0.0.115",
            "destination.ip": "104.18.42.69",
            "network.community_id": "1:QCj4k0TN76IUQUu4NyvzbTSNRjQ=",
            "synth.scenario_id": "m1-cobalt-strike-beacon",
            "synth.scenario_version": 1,
            "synth": {"scenario_id": "m1-cobalt-strike-beacon"},
        },
    }


def _leak_probe_agent(settings: Settings, elastic: Any, role: str = "hunt") -> Any:
    """A real registered toolset over a caller-controlled elastic, in the
    eval-mode context (include_synth=True) — the exact configuration that
    leaked."""
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import InvestigationContext
    from soc_ai.agent.toolset import register_read_tools

    agent: Agent[Any, str] = Agent(TestModel(call_tools=[]), output_type=str, system_prompt="x")
    ctx = InvestigationContext(
        settings=settings, auth=AsyncMock(), elastic=elastic, include_synth=True
    )
    register_read_tools(agent, ctx, role=role)  # type: ignore[arg-type]
    return agent


def _es_returning(hits: list[dict[str, Any]]) -> AsyncMock:
    elastic = AsyncMock()
    elastic.search = AsyncMock(return_value=EsSearchResult(total=len(hits), took_ms=3, hits=hits))
    return elastic


@pytest.mark.asyncio
async def test_marker_only_query_hit_reaches_the_model_with_no_synth_residue(
    settings_kratos: Settings,
) -> None:
    """The exact leak from the 2026-08-26 batch: a t_query_events_oql result
    handed the model `_source["synth.scenario_id"]` AND the `logs-synth-*`
    backing-index name. Neither may appear in the model-bound payload.

    Scope: `_planted_hit()` is MARKER-ONLY (no evidence subkeys in the
    `synth.*` namespace), so its stripped copy must carry no trace of the
    namespace at all — not even a leftover empty `synth` key. That is a
    property of marker-only docs, NOT a global one: evidence-bearing docs
    legitimately spell `synth.` after the narrowed strip (see
    test_marker_keys_are_stripped_even_when_evidence_flows for the global
    marker-key property on an evidence-bearing fixture)."""
    agent = _leak_probe_agent(settings_kratos, _es_returning([_planted_hit()]))

    out = await agent._function_toolset.tools["t_query_events_oql"].function(
        "event.dataset:suricata.alert"
    )

    text = json.dumps(out)
    assert "synth" not in text, f"synth residue reached the model: {text[:400]}"
    assert "logs-synth" not in text
    assert "m1-cobalt-strike-beacon" not in text
    hit = out["hits"][0]
    assert "_index" not in hit, "the physical index name alone says 'planted'"


@pytest.mark.asyncio
async def test_stripped_hit_keeps_its_evidence_and_its_citation_key(
    settings_kratos: Settings,
) -> None:
    """One namespace was stripped, not the payload: the real evidence fields
    and the ES `_id` (the citation / scorer join key) must survive intact."""
    agent = _leak_probe_agent(settings_kratos, _es_returning([_planted_hit()]))

    out = await agent._function_toolset.tools["t_query_events_oql"].function(
        "event.dataset:suricata.alert"
    )

    hit = out["hits"][0]
    assert hit["_id"] == "xeZ3QKABZjR0vNGrpz7u"
    src = hit["_source"]
    assert src["rule.name"] == ("ET HUNTING Possible Cobalt Strike Extra Whitespace HTTP Response")
    assert src["@timestamp"] == "2026-08-26T23:46:17.876008+00:00"
    assert src["source.ip"] == "10.0.0.115"
    assert src["destination.ip"] == "104.18.42.69"
    assert src["network.community_id"] == "1:QCj4k0TN76IUQUu4NyvzbTSNRjQ="
    assert src["event.dataset"] == "suricata.alert"


def _planted_evidence_hit() -> dict[str, Any]:
    """The h1 kerberos-summary doc: the MARKER and the DISCRIMINATING
    EVIDENCE live in the same ``synth.*`` namespace. Dotted spelling (what
    ES ``_source`` returns for the ingested doc) plus the mapped-object
    spelling carrying both a marker subkey and an evidence subkey."""
    return {
        "_index": ".ds-logs-synth-zeek-kerberos-summary-2026.08.12-000002",
        "_id": "h1-kerb-summary-0001",
        "_score": 1.0,
        "_source": {
            "@timestamp": "2026-08-27T11:58:30.000000+00:00",
            "event.dataset": "zeek.kerberos_summary",
            "event.module": "zeek",
            "source.ip": "10.0.0.55",
            "destination.ip": "10.0.0.250",
            "user.name": "jdoe",
            "synth.kerberos_profile": {
                "window_seconds": 90,
                "request_type": "TGS",
                "success_count": 14,
                "unique_spns": 14,
                "ciphers_observed": {"rc4-hmac": 14, "aes256-cts-hmac-sha1-96": 0},
                "sample_spns": ["MSSQLSvc/sql01.corp.lan:1433", "HTTP/owa.corp.lan"],
            },
            "synth.scenario_id": "h1-kerberoasting",
            "synth.scenario_version": 1,
            "synth": {
                "scenario_id": "h1-kerberoasting",
                "scenario_version": 1,
                "ntlm_profile": {"window_seconds": 90, "servers_authenticated": 8},
            },
        },
    }


@pytest.mark.asyncio
async def test_planted_evidence_in_the_synth_namespace_reaches_the_model(
    settings_kratos: Settings,
) -> None:
    """The 2026-08-27 finding: stripping the whole ``synth.*`` namespace
    amputated every scenario's discriminating evidence (h1's Kerberos
    profile, b3's signer, b5/h6's WMI class/method, e4's auth profile) —
    the eval was measuring the strip, not the model. Only the MARKER is the
    answer key; the rest of the namespace must reach the model intact."""
    agent = _leak_probe_agent(settings_kratos, _es_returning([_planted_evidence_hit()]))

    out = await agent._function_toolset.tools["t_query_events_oql"].function(
        "event.dataset:zeek.kerberos_summary"
    )

    src = out["hits"][0]["_source"]
    profile = src["synth.kerberos_profile"]
    assert profile["unique_spns"] == 14
    assert profile["ciphers_observed"]["rc4-hmac"] == 14
    assert profile["ciphers_observed"]["aes256-cts-hmac-sha1-96"] == 0
    assert "MSSQLSvc/sql01.corp.lan:1433" in profile["sample_spns"]
    # The mapped-object spelling keeps its evidence subkey too.
    assert src["synth"]["ntlm_profile"]["servers_authenticated"] == 8


@pytest.mark.asyncio
async def test_marker_keys_are_stripped_even_when_evidence_flows(
    settings_kratos: Settings,
) -> None:
    """The security property of 8e17d3d3, re-pinned against the narrowed
    strip: with evidence now flowing, the marker keys — both spellings —
    and the synth index name must STILL never reach the model."""
    agent = _leak_probe_agent(settings_kratos, _es_returning([_planted_evidence_hit()]))

    out = await agent._function_toolset.tools["t_query_events_oql"].function(
        "event.dataset:zeek.kerberos_summary"
    )

    text = json.dumps(out)
    assert "scenario_id" not in text, f"marker key reached the model: {text[:400]}"
    assert "scenario_version" not in text
    assert "h1-kerberoasting" not in text
    assert "logs-synth" not in text
    assert "_index" not in out["hits"][0]


@pytest.mark.asyncio
async def test_event_raw_keeps_planted_evidence_and_drops_the_marker(
    settings_kratos: Settings,
) -> None:
    """The measured h1 failure verbatim: the model pivoted to its planted
    Kerberos summary, called t_get_event_raw, and got 8 generic fields with
    the profile gone. The deep-dive tool must return the evidence and only
    withhold the marker."""
    agent = _leak_probe_agent(
        settings_kratos, _es_returning([_planted_evidence_hit()]), role="investigator"
    )

    out = await agent._function_toolset.tools["t_get_event_raw"].function(
        event_id="h1-kerb-summary-0001"
    )

    assert out["synth.kerberos_profile"]["unique_spns"] == 14
    assert out["synth.kerberos_profile"]["ciphers_observed"]["rc4-hmac"] == 14
    text = json.dumps(out)
    assert "scenario_id" not in text, f"marker key reached the model: {text[:400]}"
    assert "scenario_version" not in text
    assert "h1-kerberoasting" not in text


@pytest.mark.asyncio
async def test_phase_d_dispatch_keeps_planted_evidence(
    settings_kratos: Settings,
) -> None:
    """Phase-D targeted dispatch crosses the same model boundary
    (_clamp_tool_result) — the narrowed strip must hold there identically:
    evidence through, marker withheld."""
    from types import SimpleNamespace

    from soc_ai.agent.targeted_investigator import run_targeted_investigation
    from soc_ai.triage_models import TargetedGap

    ctx = SimpleNamespace(
        settings=settings_kratos, elastic=_es_returning([_planted_evidence_hit()])
    )
    gap = TargetedGap(
        question="fetch the kerberos summary doc",
        tool_name="t_get_event_raw",
        tool_args={"event_id": "h1-kerb-summary-0001"},
        why_this_matters="probe",
    )

    out = await run_targeted_investigation(gap, ctx=ctx)

    text = json.dumps(out)
    assert "kerberos_profile" in text, f"evidence lost on the Phase-D path: {text[:400]}"
    assert "rc4-hmac" in text
    assert "scenario_id" not in text
    assert "h1-kerberoasting" not in text


# --- Phase-D dispatch must be ABLE to retrieve planted evidence. The test
# --- above proves the marker strip lets evidence through the funnel; these
# --- prove the emitted QUERY can select it at all. The dispatch never
# --- threaded include_synth, so query_events_oql / query_zeek_logs fell to
# --- their prod default and injected `must_not exists synth.scenario_id` —
# --- an eval-mode Phase-D query structurally could not return the scenario's
# --- planted documents. That survived because the prior test's AsyncMock
# --- ignored the query body: a mock that ignores the body cannot catch a bug
# --- in the body. These assert on the body itself, and on retrieval through
# --- a fake ES that actually evaluates it.

# The blanket prod exclusion clause (synth_scope_must_not(False)[0]).
_SYNTH_EXCLUSION = {"exists": {"field": "synth.scenario_id"}}


async def _phase_d_query_body(
    settings: Settings,
    tool_name: str,
    tool_args: dict[str, Any],
    **ctx_extra: Any,
) -> dict[str, Any]:
    """Dispatch one Phase-D query tool against a recording mock and return the
    ES query body it emitted."""
    from types import SimpleNamespace

    from soc_ai.agent.targeted_investigator import run_targeted_investigation
    from soc_ai.triage_models import TargetedGap

    elastic = _es_returning([])
    ctx = SimpleNamespace(settings=settings, elastic=elastic, **ctx_extra)
    gap = TargetedGap(
        question="probe", tool_name=tool_name, tool_args=tool_args, why_this_matters="probe"
    )
    out = await run_targeted_investigation(gap, ctx=ctx)
    assert not (isinstance(out, str) and out.startswith("targeted dispatch error")), out
    body = elastic.search.await_args.args[1]
    assert isinstance(body, dict)
    return body


_PHASE_D_QUERY_CALLS = [
    ("t_query_events_oql", {"query": "event.dataset:zeek.kerberos_summary"}),
    ("t_query_zeek_logs", {"community_id": "1:QCj4k0TN76IUQUu4NyvzbTSNRjQ="}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool_name", "tool_args"), _PHASE_D_QUERY_CALLS)
async def test_phase_d_eval_dispatch_emits_a_query_that_admits_planted_docs(
    settings_kratos: Settings, tool_name: str, tool_args: dict[str, Any]
) -> None:
    """In eval mode (include_synth=True) the Phase-D query body must NOT carry
    the synth exclusion — otherwise the targeted investigator cannot see the
    scenario it is grading."""
    body = await _phase_d_query_body(settings_kratos, tool_name, tool_args, include_synth=True)

    must_not = body["bool"].get("must_not", [])
    assert _SYNTH_EXCLUSION not in must_not, (
        f"eval-mode Phase-D query still excludes planted docs: {must_not}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool_name", "tool_args"), _PHASE_D_QUERY_CALLS)
async def test_phase_d_scenario_scoped_dispatch_admits_only_that_scenario(
    settings_kratos: Settings, tool_name: str, tool_args: dict[str, Any]
) -> None:
    """The batch-eval scope (include_synth=<scenario id>) must reach the query
    body as the scoped clause — sibling scenarios excluded, this scenario's own
    plants admitted — never as the blanket exclusion."""
    from soc_ai.tools._synth_scope import synth_scope_must_not

    body = await _phase_d_query_body(
        settings_kratos, tool_name, tool_args, include_synth="h1-kerberoasting"
    )

    must_not = body["bool"].get("must_not", [])
    assert _SYNTH_EXCLUSION not in must_not
    assert must_not == synth_scope_must_not("h1-kerberoasting")


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool_name", "tool_args"), _PHASE_D_QUERY_CALLS)
@pytest.mark.parametrize("prod_ctx", [{}, {"include_synth": False}])
async def test_phase_d_production_dispatch_still_excludes_planted_docs(
    settings_kratos: Settings,
    tool_name: str,
    tool_args: dict[str, Any],
    prod_ctx: dict[str, Any],
) -> None:
    """The prod kill-switch is unchanged: a context without an include_synth
    opt-in (absent or explicit False) must keep the synth exclusion in the
    body, so planted fixtures can never join a real investigation."""
    body = await _phase_d_query_body(settings_kratos, tool_name, tool_args, **prod_ctx)

    assert _SYNTH_EXCLUSION in body["bool"].get("must_not", [])


def _es_clause_matches(clause: dict[str, Any], src: dict[str, Any]) -> bool:
    """Evaluate an ES bool-query clause against a flat dotted ``_source``.

    Covers exactly the clause kinds the query tools emit (bool / term / terms
    / exists / wildcard / range / match_all) and RAISES on anything else —
    a fake that silently ignores part of the query body is how the Phase-D
    defect survived its own regression test."""
    from datetime import datetime
    from fnmatch import fnmatchcase

    if "bool" in clause:
        b = clause["bool"]
        if not all(_es_clause_matches(c, src) for c in b.get("must", [])):
            return False
        if not all(_es_clause_matches(c, src) for c in b.get("filter", [])):
            return False
        if any(_es_clause_matches(c, src) for c in b.get("must_not", [])):
            return False
        should = b.get("should", [])
        if should and b.get("minimum_should_match", 1) >= 1:
            return any(_es_clause_matches(c, src) for c in should)
        return True
    if "term" in clause:
        ((field, spec),) = clause["term"].items()
        want = spec["value"] if isinstance(spec, dict) else spec
        return src.get(field) == want
    if "terms" in clause:
        ((field, values),) = clause["terms"].items()
        return src.get(field) in values
    if "exists" in clause:
        return clause["exists"]["field"] in src
    if "wildcard" in clause:
        ((field, spec),) = clause["wildcard"].items()
        pattern = spec["value"] if isinstance(spec, dict) else spec
        return fnmatchcase(str(src.get(field, "")), pattern)
    if "range" in clause:
        ((field, bounds),) = clause["range"].items()
        raw = src.get(field)
        if raw is None:
            return False
        val = datetime.fromisoformat(str(raw))
        # `now`-relative bounds would need clock math this fake refuses to
        # fake — the tests below pass an explicit time anchor instead.
        for op, bound in bounds.items():
            edge = datetime.fromisoformat(str(bound))
            if op == "gte" and val < edge:
                return False
            if op == "lte" and val > edge:
                return False
        return True
    if "match_all" in clause:
        return True
    raise AssertionError(f"query-honoring fake ES cannot evaluate clause: {clause}")


class _QueryHonoringEs:
    """A fake ElasticClient whose ``search`` actually EVALUATES the query body
    against its corpus — retrieval proof, not funnel proof."""

    def __init__(self, corpus: list[dict[str, Any]]) -> None:
        self._corpus = corpus

    async def search(self, index: str, query: dict[str, Any], **_kw: Any) -> EsSearchResult:
        matched = [h for h in self._corpus if _es_clause_matches(query, h["_source"])]
        return EsSearchResult(total=len(matched), took_ms=1, hits=matched)


def _phase_d_retrieval_fixture() -> tuple[Any, Any]:
    """(ctx kwargs, gap) for a Phase-D OQL query whose corpus holds h1's
    planted kerberos-summary doc, time-anchored on the doc itself."""
    from datetime import datetime

    from soc_ai.triage_models import TargetedGap

    anchor = datetime.fromisoformat(_planted_evidence_hit()["_source"]["@timestamp"])
    gap = TargetedGap(
        question="pull the kerberos summary for 10.0.0.55",
        tool_name="t_query_events_oql",
        tool_args={"query": "event.dataset:zeek.kerberos_summary"},
        why_this_matters="probe",
    )
    return anchor, gap


@pytest.mark.asyncio
async def test_phase_d_eval_dispatch_retrieves_the_planted_document(
    settings_kratos: Settings,
) -> None:
    """End to end through the real dispatch and a query-honoring ES: in the
    batch-eval scope the planted document COMES BACK (evidence intact, marker
    stripped). This is the retrievability control the eval depends on — without
    it the evaluation measures the harness, not the model."""
    from types import SimpleNamespace

    from soc_ai.agent.targeted_investigator import run_targeted_investigation

    anchor, gap = _phase_d_retrieval_fixture()
    ctx = SimpleNamespace(
        settings=settings_kratos,
        elastic=_QueryHonoringEs([_planted_evidence_hit()]),
        include_synth="h1-kerberoasting",
        default_time_anchor=anchor,
    )

    out = await run_targeted_investigation(gap, ctx=ctx)

    assert isinstance(out, dict), out
    assert out["total"] == 1
    assert out["hits"][0]["_id"] == "h1-kerb-summary-0001"
    text = json.dumps(out)
    assert "kerberos_profile" in text  # the evidence arrives
    assert "scenario_id" not in text  # the marker still does not


@pytest.mark.asyncio
async def test_phase_d_production_dispatch_cannot_retrieve_the_planted_document(
    settings_kratos: Settings,
) -> None:
    """Negative control, through the same query-honoring ES: a production
    context's Phase-D query returns zero hits over a corpus of planted docs —
    proving both the kill-switch and that the fake honors ``must_not``."""
    from types import SimpleNamespace

    from soc_ai.agent.targeted_investigator import run_targeted_investigation

    anchor, gap = _phase_d_retrieval_fixture()
    ctx = SimpleNamespace(
        settings=settings_kratos,
        elastic=_QueryHonoringEs([_planted_evidence_hit()]),
        default_time_anchor=anchor,
    )

    out = await run_targeted_investigation(gap, ctx=ctx)

    assert isinstance(out, dict), out
    assert out["total"] == 0
    assert out["hits"] == []


def test_real_document_payload_is_untouched_except_index() -> None:
    """A real hit (no synth keys) crosses the boundary byte-identical apart
    from the `_index` drop — the strip may not perturb honest telemetry."""
    from soc_ai.agent.toolset import strip_synth_markers

    source = {
        "@timestamp": "2026-08-27T09:00:00.000000+00:00",
        "event.dataset": "zeek.conn",
        "source.ip": "10.0.0.77",
        "destination.ip": "142.250.72.14",
        "network.bytes": 0,
        "zeek.conn.history": "ShADadFf",
        "nested": {"list": [{"deep": True}, "s"], "empty": [], "none": None},
    }
    hit = {"_index": ".ds-logs-zeek-conn-2026.08.27-000001", "_id": "real-1", "_source": source}

    out = strip_synth_markers(hit)

    assert out["_id"] == "real-1"
    assert out["_source"] == source
    assert "_index" not in out


def test_marker_only_nested_synth_object_is_dropped_not_left_empty() -> None:
    """If the mapped-object spelling holds ONLY marker subkeys, the whole
    `synth` key goes — a leftover `"synth": {}` on a document would itself
    say 'planted' (real docs never carry the key at all)."""
    from soc_ai.agent.toolset import strip_synth_markers

    out = strip_synth_markers({"a": 1, "synth": {"scenario_id": "x", "scenario_version": 1}})

    assert out == {"a": 1}


@pytest.mark.asyncio
async def test_event_raw_reaching_the_model_carries_no_synth_marker(
    settings_kratos: Settings,
) -> None:
    """t_get_event_raw returns the full `_source` — the deep-dive tool must
    strip the marker namespace exactly as the query tools do."""
    agent = _leak_probe_agent(settings_kratos, _es_returning([_planted_hit()]), role="investigator")

    out = await agent._function_toolset.tools["t_get_event_raw"].function(
        event_id="xeZ3QKABZjR0vNGrpz7u"
    )

    text = json.dumps(out)
    assert "synth" not in text, f"synth marker reached the model: {text[:400]}"
    assert "m1-cobalt-strike-beacon" not in text
    assert out["rule.name"].startswith("ET HUNTING")  # evidence intact


@pytest.mark.asyncio
async def test_phase_d_dispatch_strips_the_synth_marker_too(
    settings_kratos: Settings,
) -> None:
    """Phase-D targeted dispatch calls the tool functions directly (bypassing
    the interactive wrappers) and embeds the result verbatim in the round-2
    synth prompt — it must pass the same model boundary."""
    from types import SimpleNamespace

    from soc_ai.agent.targeted_investigator import run_targeted_investigation
    from soc_ai.triage_models import TargetedGap

    ctx = SimpleNamespace(settings=settings_kratos, elastic=_es_returning([_planted_hit()]))
    gap = TargetedGap(
        question="fetch the raw alert doc",
        tool_name="t_get_event_raw",
        tool_args={"event_id": "xeZ3QKABZjR0vNGrpz7u"},
        why_this_matters="probe",
    )

    out = await run_targeted_investigation(gap, ctx=ctx)

    text = json.dumps(out)
    assert "synth" not in text, f"synth marker reached round-2 synthesis: {text[:400]}"
    assert "m1-cobalt-strike-beacon" not in text


@pytest.mark.asyncio
async def test_oql_cannot_select_documents_by_physical_index_name(
    settings_kratos: Settings,
) -> None:
    """`_index` used to be OQL-whitelisted, and `_index:logs-synth*` compiled
    to a working wildcard query: the hits came back marker-stripped, but the
    SELECTION itself — plus the total count — told the model exactly which
    documents are planted (and the narrowed strip leaves the `synth.`
    namespace visible on evidence-bearing docs, handing the model the token it
    needs to guess the index spelling). Every `_index` spelling, filter or
    groupby, must be refused AT VALIDATION with a correctable message —
    a silent empty result is indistinguishable from "no data" — and must
    never touch Elasticsearch."""
    for query in ("_index:logs-synth*", "event.kind:event | groupby _index"):
        elastic = AsyncMock()
        agent = _leak_probe_agent(settings_kratos, elastic)

        out = await agent._function_toolset.tools["t_query_events_oql"].function(query)

        assert out["error"] is True, out
        assert "_index" in out["message"]
        assert "synth" not in json.dumps(out), f"the refusal itself is a tell: {out}"
        elastic.search.assert_not_awaited()


@pytest.mark.asyncio
async def test_grid_error_text_cannot_spell_the_synth_index_name(
    settings_kratos: Settings,
) -> None:
    """A 4xx ES error keeps its own message (that text is how the model fixes
    its query) — but ES error messages name indices, so the synth index
    spelling must be rewritten out of the error path as well."""
    from types import SimpleNamespace

    from elasticsearch import ApiError

    elastic = AsyncMock()
    elastic.search = AsyncMock(
        side_effect=ApiError(
            message=(
                "no mapping found for field [zeek.conn.histry] in index "
                "[.ds-logs-synth-zeek-conn-2026.08.12-000004]"
            ),
            meta=SimpleNamespace(status=400),  # type: ignore[arg-type]
            body={},
        )
    )
    agent = _leak_probe_agent(settings_kratos, elastic)

    out = await agent._function_toolset.tools["t_query_events_oql"].function(
        "event.dataset:zeek.conn"
    )

    assert out["error"] is True
    assert "logs-synth" not in json.dumps(out)


@pytest.mark.asyncio
async def test_describe_dataset_never_reports_the_synth_namespace_as_a_field(
    settings_kratos: Settings,
) -> None:
    """describe_dataset reports field NAMES as values — a key-level strip
    cannot catch `{"field": "synth.scenario_id", "example": "m1-..."}`. The
    eval-mode sample (include_synth=True) must still describe the dataset
    without teaching the model the marker field exists."""
    from soc_ai.tools.discover import describe_dataset

    elastic = _es_returning([_planted_hit()])

    out = await describe_dataset(
        "suricata.alert", elastic=elastic, settings=settings_kratos, include_synth=True
    )

    names = {f["field"] for f in out["fields"]}
    assert not any(n == "synth" or n.startswith("synth.") for n in names), names
    assert "rule.name" in names  # the real schema is still described
    assert "m1-cobalt-strike-beacon" not in json.dumps(out)


@pytest.mark.asyncio
async def test_field_values_refuses_to_enumerate_the_marker_namespace(
    settings_kratos: Settings,
) -> None:
    """An active probe: field_values("synth.scenario_id") would list every
    planted scenario id, and field_values("_index") every `logs-synth-*`
    index. Both must answer exactly as a nonexistent field does — an empty
    values list — without touching Elasticsearch, so the refusal itself is
    not a tell. Unconditional: the same answer in prod and eval mode."""
    from soc_ai.tools.discover import field_values

    for probe in ("synth.scenario_id", "synth", "_index"):
        for opted_in in (True, False):
            elastic = AsyncMock()
            out = await field_values(
                probe, elastic=elastic, settings=settings_kratos, include_synth=opted_in
            )
            assert out["values"] == [], (probe, opted_in, out)
            elastic.search.assert_not_awaited()


def test_oql_rejects_probing_the_synth_marker_field() -> None:
    """The remaining active probe: an OQL query naming the marker field. The
    whitelist has never admitted `synth.*`; pin that so a future whitelist
    expansion cannot silently open the channel."""
    from soc_ai.so_client.oql import OqlValidationError, parse_oql, validate_oql

    with pytest.raises(OqlValidationError):
        validate_oql(parse_oql("synth.scenario_id:*"))


# --- The harness half: everything the scorer / containment / teardown reads
# --- still carries the marker. The strip lives at the MODEL boundary only.


def test_rendered_docs_still_stamp_the_marker_for_ingest() -> None:
    """Ingest-side invariant: every rendered doc still carries the synth
    stamp — the exclusion filters, the containment probe and `synth-clean`
    all key on it in Elasticsearch."""
    docs = render_scenario(_ingestable_scenario(), run_time=RUN_TIME)
    assert docs
    for doc in docs:
        assert doc.body["synth.scenario_id"]
        assert doc.body["synth.scenario_version"] == 1
        assert doc.index.startswith("logs-synth-")


@pytest.mark.asyncio
async def test_direct_es_reads_keep_the_marker_for_the_harness(
    settings_kratos: Settings,
) -> None:
    """The strip must NOT live in the shared ES client or the tool function:
    harness code (ingest containment, the scorer, synth-clean preflight) reads
    through the same query path and needs the marker intact. Calling
    query_events_oql directly — as harness code does — must return the hit
    unstripped, `_index` included."""
    from soc_ai.tools.query_events import query_events_oql

    elastic = _es_returning([_planted_hit()])

    res = await query_events_oql(
        "event.dataset:suricata.alert",
        elastic=elastic,
        settings=settings_kratos,
        include_synth=True,
    )

    hit = res.hits[0]
    assert hit["_source"]["synth.scenario_id"] == "m1-cobalt-strike-beacon"
    assert hit["_index"].startswith(".ds-logs-synth-")


def test_prefetch_alert_context_dump_carries_no_synth_marker() -> None:
    """The Phase-A prefetch reaches the model via AlertContext.model_dump —
    SoAlert's typed view must keep excluding the raw `_source` (where the
    marker lives), even as fields are added to it."""
    alert = SoAlert.from_es_hit(_planted_hit())
    ctx = AlertContext(alert=alert, community_id_events=[alert])

    dump = json.dumps(ctx.model_dump(mode="json"), default=str)

    assert "synth" not in dump, f"synth marker in the prefetch dump: {dump[:400]}"
    assert "m1-cobalt-strike-beacon" not in dump


# ---------------------------------------------------------------------------
# Confidence floor-raise: credit decisive evidence the investigator found
# ITSELF. The 2026-08-26 batch recorded correct true_positives (m1 @0.65,
# h1 @0.60) as recall misses because the raise's decisive-value check
# (`_verdict_cites_decisive_pivot_value`) only reads the prefetch pivots'
# typed attrs against the CITATIONS text — evidence retrieved by the run's
# own tool calls, and values the model asserts in its summary, were both
# invisible. The new retrieved path credits only value classes an attacker
# cannot mint through free-form wire content (sensor-computed digests and
# fingerprints, fixed-vocabulary cipher enums), harvested from the real
# STRUCTURE of retrieved payloads — never by scanning dumped text (the M2
# discipline: a text match may only ever SILENCE a downgrade, because this
# check RAISES).
# ---------------------------------------------------------------------------

# A JA3 the investigation loop retrieves (Cobalt Strike's classic fingerprint
# shape): 32 hex chars, computed by the sensor over the observed ClientHello.
_TOOL_FOUND_JA3 = "72a589da586844d7f0818ce684948eea"


def _raise_ctx(rule_name: str = "ET POLICY Suspicious Periodic TLS Flow") -> Any:
    """EnrichedAlertContext whose prefetch carries NO decisive typed value —
    one plain zeek.conn pivot only — so the legacy prefetch path cannot fire
    and any raise must come from what the run retrieved."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    alert = SoAlert.from_es_hit(
        {
            "_id": "alert-raise-1",
            "_source": {
                "event.dataset": "suricata.alert",
                "rule.name": rule_name,
                "source.ip": "10.0.0.115",
                "destination.ip": "104.18.42.69",
            },
        }
    )
    conn = SoAlert.from_es_hit({"_id": "piv-conn-1", "_source": {"event.dataset": "zeek.conn"}})
    return EnrichedAlertContext(alert=alert, community_id_events=[conn])


def _raise_tp(confidence: float, summary: str, citations: list[str]) -> Any:
    from soc_ai.agent.triage import TriageReport

    return TriageReport(
        verdict="true_positive",
        confidence=confidence,
        summary=summary,
        citations=citations,
    )


def _raise_validate(report: Any, ctx: Any, messages: list[Any] | None) -> Any:
    from soc_ai.agent.gates import _synth_first_post_validate

    return _synth_first_post_validate(
        report, ctx, candidate=None, targeted_messages=messages, targeted_tool_called=None
    )


def test_floor_raise_credits_decisive_value_retrieved_by_a_tool_call() -> None:
    """THE REPRODUCTION (m1/h1 blindness): a true_positive below the escalation
    floor whose decisive value (a sensor-computed JA3) entered the run through
    the investigator's OWN tool call — not the prefetch bundle — must receive
    the confidence floor-raise, with the audit entry recording the retrieved
    grounding."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR

    from tests.test_recall_fix import _Msg, _RetPart

    messages = [
        _Msg(
            [
                _RetPart(
                    {
                        "total": 1,
                        "hits": [
                            {
                                "_id": "loop-ssl-0001",
                                "_source": {
                                    "event": {"dataset": "zeek.ssl"},
                                    "hash": {"ja3": _TOOL_FOUND_JA3},
                                },
                            }
                        ],
                    }
                )
            ]
        )
    ]
    report = _raise_tp(
        0.65,
        f"Periodic TLS beacon whose JA3 {_TOOL_FOUND_JA3} matches a Cobalt "
        "Strike client profile; the loop query confirmed the flow.",
        [_TOOL_FOUND_JA3, "loop-ssl-0001"],
    )
    out, audit = _raise_validate(report, _raise_ctx(), messages)

    assert out.verdict == "true_positive"
    assert out.confidence == pytest.approx(_ESCALATION_CONF_FLOOR)
    entry = audit["confidence_floor_raise"]
    assert entry["grounded_by"] == "retrieved_decisive_value"
    assert entry["original_confidence"] == pytest.approx(0.65)
    assert entry["floored_confidence"] == pytest.approx(_ESCALATION_CONF_FLOOR)
    assert entry["reason"]


def test_floor_raise_credits_a_cipher_enum_asserted_in_the_summary() -> None:
    """The h1 shape: the verdict cites retrieved documents by ID and asserts
    the decisive value (the rc4-hmac Kerberos cipher, a fixed-vocabulary enum
    the sensor parsed from the ticket) in its SUMMARY. The value rode in on
    the run's own OQL result in ES fields-form — it must earn the raise."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR

    from tests.test_recall_fix import _Msg, _RetPart

    messages = [
        _Msg(
            [
                _RetPart(
                    {
                        "total": 1,
                        "hits": [
                            {
                                "_id": "loop-krb-0001",
                                "_source": {
                                    "event.dataset": "zeek.kerberos",
                                    "zeek.kerberos.request_type": "TGS",
                                    "zeek.kerberos.cipher": "rc4-hmac",
                                },
                            }
                        ],
                    }
                )
            ]
        )
    ]
    report = _raise_tp(
        0.60,
        "TGS request for a service account using the weak RC4-HMAC cipher — "
        "the classic Kerberoasting signature; the Zeek kerberos record "
        "confirms the rc4-hmac etype.",
        ["loop-krb-0001"],
    )
    out, audit = _raise_validate(report, _raise_ctx(), messages)

    assert out.verdict == "true_positive"
    assert out.confidence == pytest.approx(_ESCALATION_CONF_FLOOR)
    assert audit["confidence_floor_raise"]["grounded_by"] == "retrieved_decisive_value"


def test_floor_raise_prefetch_pivot_value_path_is_unchanged() -> None:
    """The existing prefetch-based raise still fires exactly as before: a TP
    citing a decisive typed value carried by a prefetched pivot (the JA3S) is
    floored, grounded_by the legacy decisive_pivot_value reason."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    from tests.test_recall_fix import _alert, _zeek

    ctx = EnrichedAlertContext(
        alert=_alert(),
        community_id_events=[
            _zeek("piv-ssl-1", "zeek.ssl", {"zeek.ssl.ja3": "a0e9f5", "zeek.ssl.ja3s": "b742b4"})
        ],
    )
    report = _raise_tp(
        0.65,
        "C2 beacon over TLS.",
        ["JA3S b742b4 matches a Cobalt Strike team server", "community_id pivot id piv-ssl-1"],
    )
    out, audit = _raise_validate(report, ctx, None)

    assert out.verdict == "true_positive"
    assert out.confidence == pytest.approx(_ESCALATION_CONF_FLOOR)
    assert audit["confidence_floor_raise"]["grounded_by"] == "decisive_pivot_value"


def test_no_floor_raise_when_the_cited_value_was_never_retrieved() -> None:
    """A verdict citing a decisive-SHAPED value (a well-formed 32-hex JA3)
    that appears in NOTHING the run retrieved — not the prefetch, not any
    tool return — earns no raise. (The decisive-value support gate then
    coerces the unsupported assertion, unchanged.)"""
    from tests.test_recall_fix import _Msg, _RetPart

    fabricated = "9f" * 16  # hash-shaped, retrieved nowhere
    messages = [
        _Msg(
            [
                _RetPart(
                    {
                        "total": 1,
                        "hits": [
                            {
                                "_id": "loop-conn-0001",
                                "_source": {"event": {"dataset": "zeek.conn"}},
                            }
                        ],
                    }
                )
            ]
        )
    ]
    report = _raise_tp(
        0.65,
        f"Beacon confirmed via JA3 {fabricated}.",
        [fabricated, "loop-conn-0001"],
    )
    out, audit = _raise_validate(report, _raise_ctx(), messages)

    assert "confidence_floor_raise" not in audit
    # The unsupported assertion is the support gate's business, and it still is.
    assert out.verdict == "needs_more_info"
    assert out.confidence <= 0.4


def test_forged_value_planted_in_free_form_telemetry_earns_no_raise() -> None:
    """FORGERY GUARD: an attacker who composes a decisive-shaped token into
    free-form wire content (a DNS query label, an SMB file name) that the run
    then genuinely retrieves must NOT be able to lift a verdict citing that
    token to escalation confidence. The raise credits values only from
    sensor-computed / fixed-vocabulary STRUCTURAL slots, never from content
    leaves an attacker can write through traffic."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR

    from tests.test_recall_fix import _Msg, _RetPart

    forged = "deadbeef" * 4  # 32-hex, but attacker-composed content
    messages = [
        _Msg(
            [
                _RetPart(
                    {
                        "total": 2,
                        "hits": [
                            {
                                "_id": "loop-dns-0001",
                                "_source": {
                                    "event": {"dataset": "zeek.dns"},
                                    "dns": {"question": {"name": f"{forged}.evil.example"}},
                                },
                            },
                            {
                                "_id": "loop-smb-0001",
                                "_source": {
                                    "event.dataset": "zeek.smb_files",
                                    "zeek.smb_files.name": forged,
                                },
                            },
                        ],
                    }
                )
            ]
        )
    ]
    report = _raise_tp(
        0.65,
        f"Malware hash {forged} observed on the wire; escalate.",
        [forged, "loop-dns-0001"],
    )
    out, audit = _raise_validate(report, _raise_ctx(), messages)

    assert "confidence_floor_raise" not in audit
    assert out.confidence < _ESCALATION_CONF_FLOOR


# ---------------------------------------------------------------------------
# Confidence floor-raise, beacon-profile ground (defect 1, 2026-08-26 batch).
# m1-cobalt-strike-beacon could not be rescued by the retrieved-value paths
# because its report never ASSERTS a decisive string: it cites the beacon
# aggregate and the TLS row by ES id and describes the cadence statistically
# ("~60s interval, low jitter"). A beacon profile is a decisive RECORD with no
# citable string value — its evidence is the measured statistics. Crediting the
# cited doc ids instead is forbidden (bare-id doctrine, tests/test_recall_fix),
# so the raise gains a deterministic profile check: a genuinely-RETRIEVED
# profile at or below the beacon tool's own "periodic" bar (analytics._CV_PERIODIC)
# with at least its default min_events sample floor is decisive; a marginal one
# (semi-regular cadence, or too few events — b1's benign updater profile) is not.
# ---------------------------------------------------------------------------

# The recorded m1 pivot's profile, verbatim (batch-2026-08-26T234616Z):
# cv = 5.8 / 60.1 ≈ 0.0965 <= _CV_PERIODIC (0.15); 240 events >= min_events (8).
_M1_BEACON_PROFILE: dict[str, Any] = {
    "connection_count": 240,
    "window_seconds": 14400,
    "mean_interval_seconds": 60.1,
    "interval_stddev_seconds": 5.8,
    "interval_similarity": 0.95,
    "mean_orig_bytes": 442,
    "mean_resp_bytes": 1188,
    "orig_bytes_cv": 0.04,
    "resp_bytes_cv": 0.06,
}


def _beacon_pivot_ctx(profile: dict[str, Any] | None) -> Any:
    """m1's prefetch shape: alert 10.0.0.115 → 104.18.42.69, one conn_summary
    community-id pivot for the same pair carrying (or not) the beacon-profile
    dict. Deliberately NO decisive string value anywhere (no ja3/hash/cipher),
    so only the profile itself can ground a raise."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    alert = SoAlert.from_es_hit(
        {
            "_id": "alert-beacon-1",
            "_source": {
                "event.dataset": "suricata.alert",
                "rule.name": "ET HUNTING Suspicious Extra Whitespace HTTP Response",
                "source.ip": "10.0.0.115",
                "destination.ip": "104.18.42.69",
            },
        }
    )
    src: dict[str, Any] = {
        "event.dataset": "zeek.conn_summary",
        "source.ip": "10.0.0.115",
        "destination.ip": "104.18.42.69",
    }
    if profile is not None:
        src["synth.beacon_profile"] = profile
    pivot = SoAlert.from_es_hit({"_id": "piv-beacon-summary-1", "_source": src})
    return EnrichedAlertContext(alert=alert, community_id_events=[pivot])


def _m1_shaped_report(confidence: float = 0.65) -> Any:
    """The m1 report shape: bare-id citations + statistical prose, no decisive
    string value asserted anywhere."""
    return _raise_tp(
        confidence,
        "Internal host connects to 104.18.42.69 on a highly regular ~60s "
        "cadence with low jitter and near-constant payload sizes — consistent "
        "with automated C2 beaconing; escalation warranted.",
        ["piv-beacon-summary-1", "alert-beacon-1"],
    )


def test_floor_raise_credits_a_retrieved_periodic_beacon_profile() -> None:
    """THE REPRODUCTION (m1): a true_positive below the escalation floor whose
    decisive evidence is a genuinely-retrieved, clearly-periodic beacon profile
    — cited by ES id, described statistically, no decisive string asserted —
    must receive the confidence floor-raise."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR

    out, audit = _raise_validate(_m1_shaped_report(), _beacon_pivot_ctx(_M1_BEACON_PROFILE), None)

    assert out.verdict == "true_positive"
    assert out.confidence == pytest.approx(_ESCALATION_CONF_FLOOR)
    assert audit["confidence_floor_raise"]["grounded_by"] == "retrieved_beacon_profile"


def test_floor_raise_credits_a_periodic_beacon_profile_from_the_beacon_tool() -> None:
    """Same ground through the run's own t_beacon_profile call: a candidate
    item the tool itself scored "periodic" (cv <= _CV_PERIODIC, events >=
    min_events) for THIS alert's src→dst pair earns the raise."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR

    from tests.test_recall_fix import _Msg, _RetPart

    messages = [
        _Msg(
            [
                _RetPart(
                    {
                        "window_minutes": 1440,
                        "pairs_scanned": 3,
                        "internal_excluded": 0,
                        "truncated": False,
                        "items": [
                            {
                                "src": "10.0.0.115",
                                "dst": "104.18.42.69",
                                "events": 31,
                                "mean_interval_s": 60.3,
                                "stdev_s": 5.61,
                                "cv": 0.093,
                                "bytes_out_avg": 441.0,
                                "sample_ids": ["conn-a", "conn-b"],
                                "verdict_hint": "periodic",
                            }
                        ],
                        "thresholds": {"min_events": 8, "cv_max": 0.4},
                    }
                )
            ]
        )
    ]
    out, audit = _raise_validate(_m1_shaped_report(), _beacon_pivot_ctx(None), messages)

    assert out.verdict == "true_positive"
    assert out.confidence == pytest.approx(_ESCALATION_CONF_FLOOR)
    assert audit["confidence_floor_raise"]["grounded_by"] == "retrieved_beacon_profile"


def test_no_floor_raise_for_a_marginal_beacon_profile() -> None:
    """A profile OUTSIDE the tool's own periodic bar earns nothing — in either
    direction of marginality: semi-regular cadence (cv > _CV_PERIODIC), or too
    few events (b1's benign updater profile: ultra-regular but only 6
    connections, below the tool's min_events floor of 8)."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR

    semi_regular = dict(_M1_BEACON_PROFILE, interval_stddev_seconds=12.0)  # cv ≈ 0.20
    out, audit = _raise_validate(_m1_shaped_report(), _beacon_pivot_ctx(semi_regular), None)
    assert "confidence_floor_raise" not in audit
    assert out.confidence < _ESCALATION_CONF_FLOOR

    # b1-cdn-update-beacon's own numbers: cv ≈ 0.0037 but connection_count 6.
    b1_profile = {
        "connection_count": 6,
        "mean_interval_seconds": 300.2,
        "interval_stddev_seconds": 1.1,
        "interval_similarity": 0.99,
    }
    out, audit = _raise_validate(_m1_shaped_report(), _beacon_pivot_ctx(b1_profile), None)
    assert "confidence_floor_raise" not in audit
    assert out.confidence < _ESCALATION_CONF_FLOOR


def test_no_floor_raise_when_no_beacon_profile_was_retrieved() -> None:
    """A verdict DESCRIBING a periodic beacon whose profile appears in nothing
    the run retrieved — not the prefetch, not any tool return — earns no raise.
    Prose statistics are not retrieval, and bare cited ids stay bare."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR

    out, audit = _raise_validate(_m1_shaped_report(), _beacon_pivot_ctx(None), None)

    assert "confidence_floor_raise" not in audit
    assert out.confidence < _ESCALATION_CONF_FLOOR


def test_beacon_profile_of_an_unrelated_pair_earns_no_raise() -> None:
    """Endpoint binding: a periodic profile the sweep flagged for SOMEONE
    ELSE'S src→dst pair grounds nothing about this alert's flow."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR

    from tests.test_recall_fix import _Msg, _RetPart

    messages = [
        _Msg(
            [
                _RetPart(
                    {
                        "items": [
                            {
                                "src": "10.0.0.77",
                                "dst": "203.0.113.9",
                                "events": 31,
                                "mean_interval_s": 60.3,
                                "stdev_s": 5.61,
                                "cv": 0.093,
                                "verdict_hint": "periodic",
                            }
                        ],
                    }
                )
            ]
        )
    ]
    out, audit = _raise_validate(_m1_shaped_report(), _beacon_pivot_ctx(None), messages)

    assert "confidence_floor_raise" not in audit
    assert out.confidence < _ESCALATION_CONF_FLOOR


def test_beacon_profile_raise_is_recorded_in_the_audit() -> None:
    """The audit entry names the distinct ground and carries the measured
    statistics AND the thresholds they were judged against — the reasoning
    trace must show WHY the profile counted as decisive."""
    from soc_ai.agent.gates import _ESCALATION_CONF_FLOOR
    from soc_ai.tools.analytics import _CV_PERIODIC, _MIN_EVENTS_DEFAULT

    _, audit = _raise_validate(_m1_shaped_report(), _beacon_pivot_ctx(_M1_BEACON_PROFILE), None)

    entry = audit["confidence_floor_raise"]
    assert entry["grounded_by"] == "retrieved_beacon_profile"
    assert entry["original_confidence"] == pytest.approx(0.65)
    assert entry["floored_confidence"] == pytest.approx(_ESCALATION_CONF_FLOOR)
    detail = entry["beacon_profile"]
    assert detail["cv"] == pytest.approx(5.8 / 60.1)
    assert detail["events"] == 240
    # Thresholds are the beacon tool's own constants, not invented numbers.
    assert detail["cv_periodic_max"] == _CV_PERIODIC
    assert detail["min_events"] == _MIN_EVENTS_DEFAULT
    assert entry["reason"]


# ---------------------------------------------------------------------------
# Template classtype coverage (defect 2, 2026-08-26 batch). h1-kerberoasting —
# an unambiguous true positive — matched the benign clean_internal_traffic
# template in both measured runs: its Sigma-on-Zeek alert carries classtype
# attempted-recon, which was absent from _ATTACK_CLASSTYPES, so an
# internal→internal Kerberoasting alert fell through to the benign default.
# (Invisible until now because synthetic alerts used to parse with
# classtype=None and the classtype routing never fired on them at all.)
# ---------------------------------------------------------------------------


def test_kerberoasting_classtype_no_longer_matches_the_benign_template() -> None:
    """The real rendered h1 triage alert (classtype attempted-recon, both
    endpoints internal, no blocklist hit) must not receive the benign
    clean_internal_traffic anchor — no template should match at all, so the
    synth reasons from the evidence."""
    from soc_ai.agent.classifier import normalize_classtype
    from soc_ai.agent.decision_templates import _ATTACK_CLASSTYPES, match_decision_template
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    scenario = load_scenario_file(_SCENARIOS_DIR / "h1-kerberoasting.yaml")
    docs = render_scenario(scenario, run_time=RUN_TIME)
    triage = next(d for d in docs if d.is_triage_target)
    alert = SoAlert.from_es_hit({"_id": "synth-h1", "_source": triage.body})

    assert alert.classtype == "attempted-recon"
    # Through the normalizer, like every classtype comparison in the product:
    # the scenarios render shortnames and a sensor sends descriptions, and a
    # raw comparison here would pass on the fixture while the code it stands
    # for could never match live data.
    assert normalize_classtype(alert.classtype) in _ATTACK_CLASSTYPES, (
        "attempted-recon missing from _ATTACK_CLASSTYPES — an internal "
        "Kerberoasting alert falls through to the benign default"
    )

    cv = match_decision_template(EnrichedAlertContext(alert=alert))
    assert cv is None, f"h1's triage alert matched template {cv.template_id!r}"


def test_benign_internal_traffic_still_matches_clean_internal() -> None:
    """Regression guard for the other direction: the benign twins must not
    start escalating. Routine internal east-west traffic (the b5/b6 shape:
    misc-activity, no malware-signal rule name) still gets the benign anchor,
    and no benign scenario in the catalogue carries a classtype this fix
    widened the attack set with."""
    from soc_ai.agent.classifier import normalize_classtype
    from soc_ai.agent.decision_templates import match_decision_template
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    benign = SoAlert.from_es_hit(
        {
            "_id": "alert-benign-int",
            "_source": {
                "event.dataset": "suricata.alert",
                "rule.name": "ET INFO Windows Update Delivery Optimization",
                "source.ip": "10.0.0.40",
                "destination.ip": "10.0.0.41",
                "message": '{"alert": {"category": "misc-activity"}}',
            },
        }
    )
    cv = match_decision_template(EnrichedAlertContext(alert=benign))
    assert cv is not None
    assert cv.template_id == "clean_internal_traffic"
    assert cv.verdict == "false_positive"

    # The classtypes this fix added. None of the benign twins may carry one —
    # widening further past this set needs a benign-twin check first.
    added = {
        "attempted-recon",
        "successful-recon-limited",
        "successful-recon-largescale",
        "credential-theft",
    }
    for scenario in load_all_scenarios(_SCENARIOS_DIR):
        if not scenario.id.startswith("b"):
            continue
        docs = render_scenario(scenario, run_time=RUN_TIME)
        triage = next(d for d in docs if d.is_triage_target)
        alert = SoAlert.from_es_hit({"_id": f"synth-{scenario.id}", "_source": triage.body})
        assert normalize_classtype(alert.classtype) not in added, (
            f"{scenario.id} carries newly-widened attack classtype {alert.classtype!r}"
        )
