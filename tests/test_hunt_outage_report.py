"""G6 — a hunt whose grid queries ALL failed is not a clean sweep.

The false all-clear this file exists to stop: the Security Onion grid is down,
every query tool a hunt calls returns a connection error, the model writes "the
network is quiet" anyway, and the Hunts list shows a fresh COMPLETE hunt with
zero findings. The analyst reads a finished hunt that found nothing and concludes
the network is clean, when the hunt never managed to look.

Two layers, both tested here:

1. **The tool boundary** (``soc_ai.agent.toolset._tool_error``) — a grid failure
   reaches the model as a structured ``reason: "grid_unavailable"`` result that
   says the answer is UNKNOWN, not absent, instead of a raw exception string it
   can paraphrase into a finding.
2. **The deterministic gate** (``soc_ai.api.hunt_runner``) — the runner COUNTS
   grid-backed tool outcomes. A hunt may only persist as a clean ``complete``
   if at least ONE grid read SUCCEEDED (a genuine zero-hit answer included:
   the grid answered, quiet is a real result). Zero successes marks the
   PERSISTED hunt degraded (``status="error"``, confidence floored, an explicit
   visibility-gap finding), regardless of what the model wrote — whether every
   grid call failed (a transport outage), every query was rejected (ES 4xx:
   the QUERIES' fault, not the grid's — the wording tells them apart), or no
   grid call ever ran (the zero-tool hunt). Mirrors the triage path's hard
   evidence gate, which already excludes errored tool results from
   ``count_successful_tool_calls``.
"""

from __future__ import annotations

import asyncio
import itertools
import json
from contextlib import ExitStack
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import elasticsearch as es
import pytest
from elastic_transport import ApiResponseMeta
from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.test import TestModel
from soc_ai.agent.hunt import HUNT_SYSTEM_PROMPT, HuntFinding, HuntReport, build_hunt_agent
from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.agent.toolset import (
    GRID_BACKED_TOOLS,
    GRID_UNAVAILABLE_REASON,
    OFF_GRID_TOOLS,
    _tool_error,
)
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.config import Settings
from soc_ai.store import hunts as hunt_svc

# The write-up a weak model produces when every query it made errored: zero
# findings, an all-clear narrative, high confidence. This is the input the
# deterministic gate has to override.
QUIET_REPORT = HuntReport(
    findings=[],
    narrative="The network is quiet — nothing matched the objective in the window.",
    affected_hosts=[],
    confidence=0.85,
)


def _ctx(settings: Settings) -> InvestigationContext:
    return InvestigationContext(settings=settings, auth=AsyncMock(), elastic=AsyncMock())


# ── Layer 1: the tool boundary ───────────────────────────────────────────────


def test_failed_grid_tool_call_returns_structured_error_not_raw_exception(
    settings_kratos: Settings,
) -> None:
    """A grid query that raises a transport error reaches the MODEL as a
    structured ``{error, reason: "grid_unavailable"}`` result whose message says
    the answer is unknown — not the raw exception text it could reason around.

    Driven through the real registered tool on the real hunt agent, so this
    covers the wrapping (dedup / guard / clamp) as well as ``_tool_error``.
    """
    boom = es.ConnectionTimeout("Connection timed out by 10.0.0.9:9200 CAUSED BY: TimeoutError()")

    async def _go() -> Any:
        agent = build_hunt_agent(
            TestModel(call_tools=["t_query_events_oql"], custom_output_args=QUIET_REPORT),
            _ctx(settings_kratos),
            system_prompt=HUNT_SYSTEM_PROMPT.format(objective="hunt for beaconing"),
        )
        with patch("soc_ai.agent.toolset.query_events_oql", side_effect=boom):
            return await agent.run("hunt for beaconing")

    result = asyncio.run(_go())
    returns = [
        p
        for m in result.all_messages()
        for p in getattr(m, "parts", [])
        if getattr(p, "part_kind", None) == "tool-return"
        and getattr(p, "tool_name", "") == "t_query_events_oql"
    ]
    assert returns, "the tool never ran"
    content = returns[0].content
    assert isinstance(content, dict)
    assert content["error"] is True
    assert content["reason"] == GRID_UNAVAILABLE_REASON
    # The model is told the result is UNKNOWABLE, not empty.
    assert "unknown" in content["message"].lower()
    # ...and it never sees the raw exception string / its chained cause.
    encoded = json.dumps(content)
    assert "CAUSED BY" not in encoded
    assert "10.0.0.9:9200" not in encoded


def test_tool_error_leaves_a_malformed_query_alone() -> None:
    """Only GRID failures are relabeled. A bad-query error keeps its own message
    (the model needs it to fix the query) and carries no grid reason — otherwise
    every typo would read as an outage and degrade the hunt."""
    err = _tool_error(ValueError("OQL parse error at column 7: unbalanced parenthesis"))
    assert err["error"] is True
    assert "reason" not in err
    assert "column 7" in err["message"]


def test_tool_error_classifies_es_api_errors_by_status() -> None:
    """An ES 400 is the analyst's query to fix; a 503/429 is the grid failing.
    Mirrors ``routes_alerts._es_api_error_http``'s 4xx/else split, with 408/429
    (queue full, circuit breaker) counted as the grid, not the query."""

    def _api_error(status: int) -> es.ApiError:
        meta = ApiResponseMeta(
            status=status, http_version="1.1", headers={}, duration=0.0, node=None
        )
        return es.ApiError("boom", meta=meta, body={})

    assert "reason" not in _tool_error(_api_error(400))
    assert _tool_error(_api_error(503))["reason"] == GRID_UNAVAILABLE_REASON
    assert _tool_error(_api_error(429))["reason"] == GRID_UNAVAILABLE_REASON


def test_every_registered_tool_is_classified_grid_or_off_grid(settings_kratos: Settings) -> None:
    """The runner's outage arithmetic counts SUCCESSES by tool name, so a new
    grid tool that nobody classified would silently stop counting as a look at
    the network. Force the decision: the two sets must partition the whole
    registered surface of every role."""
    from soc_ai.agent.chat_agent import build_chat_agent
    from soc_ai.agent.orchestrator import build_investigator

    all_on = settings_kratos.model_copy(
        update={
            "allow_online_enrichment": True,
            "pcap_enabled": True,
            "so_ssh_host": "sensor.example.internal",
            "web_search_enabled": True,
            "searxng_url": "https://searx.example.internal",
            "crawl4ai_enabled": True,
            "crawl4ai_url": "https://crawl.example.internal",
        }
    )
    model = TestModel(call_tools=[])
    registered: set[str] = set()
    for agent in (
        build_investigator(model, _ctx(all_on)),
        build_chat_agent(model, _ctx(all_on), system_prompt="chat"),
        build_hunt_agent(model, _ctx(all_on), system_prompt="hunt"),
    ):
        registered |= set(agent._function_toolset.tools.keys())  # type: ignore[attr-defined]

    assert not (GRID_BACKED_TOOLS & OFF_GRID_TOOLS), sorted(GRID_BACKED_TOOLS & OFF_GRID_TOOLS)
    unclassified = registered - GRID_BACKED_TOOLS - OFF_GRID_TOOLS - {"propose_verdict"}
    assert not unclassified, f"classify these in soc_ai.agent.toolset: {sorted(unclassified)}"
    assert "t_query_events_oql" in GRID_BACKED_TOOLS
    assert "t_web_search" in OFF_GRID_TOOLS


# ── Layer 2: the deterministic gate on the persisted hunt ────────────────────


def _stub_agent(nodes: list[Any], output: HuntReport) -> Any:
    """An agent whose ``iter()`` replays ``nodes`` and lands ``output``."""

    class _Run:
        def __init__(self) -> None:
            self._nodes = iter(nodes)
            self.result = SimpleNamespace(output=output)

        async def __aenter__(self) -> _Run:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        def __aiter__(self) -> _Run:
            return self

        async def __anext__(self) -> Any:
            try:
                return next(self._nodes)
            except StopIteration:
                raise StopAsyncIteration from None

    class _Agent:
        def iter(self, *a: Any, **k: Any) -> _Run:
            return _Run()

    return _Agent()


def _call_and_return(tool_name: str, call_id: str, content: Any) -> list[Any]:
    """The two nodes one tool round-trip streams: the call, then its result."""
    return [
        SimpleNamespace(
            model_response=ModelResponse(
                parts=[ToolCallPart(tool_name=tool_name, args={}, tool_call_id=call_id)]
            ),
            request=None,
        ),
        SimpleNamespace(
            model_response=None,
            request=SimpleNamespace(
                parts=[ToolReturnPart(tool_name=tool_name, content=content, tool_call_id=call_id)]
            ),
        ),
    ]


def _persist_hunt(
    settings: Settings, ctx: InvestigationContext, patches: list[Any]
) -> tuple[Any, list[Any]]:
    """Drive ``hunt_recorded_run`` against a real store under ``patches``; return
    the persisted ``(hunt, events)`` read back, not the in-memory objects."""

    async def _go() -> tuple[Any, list[Any]]:
        from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

        engine = make_engine(settings)
        try:
            await run_migrations(engine)
            maker = make_sessionmaker(engine)
            state = SimpleNamespace(db_sessionmaker=maker, settings=settings, audit=None)
            hunt_id = ""
            with ExitStack() as stack:
                for p in patches:
                    stack.enter_context(p)
                async for name, data in hunt_recorded_run(
                    state,
                    ctx=ctx,
                    objective="hunt for beaconing to rare external IPs",
                    started_by="admin",
                ):
                    if name == "hunt_created":
                        hunt_id = data["hunt_id"]
            async with maker() as db:
                got = await hunt_svc.get_with_events(db, hunt_id)
            assert got is not None
            return got[0], list(got[1])
        finally:
            await engine.dispose()

    return asyncio.run(_go())


def _run_recorded(settings: Settings, nodes: list[Any], output: HuntReport) -> Any:
    """Drive ``hunt_recorded_run`` with a STUBBED agent replaying ``nodes``.

    Fast and precise for the gate's arithmetic edge cases. It does NOT exercise
    the tool boundary — see :func:`_run_recorded_real` for the tests that carry
    the end-to-end guarantee.
    """
    hunt, _events = _persist_hunt(
        settings,
        _ctx(settings),
        [
            patch(
                "soc_ai.api.hunt_runner.build_hunt_agent",
                return_value=_stub_agent(nodes, output),
            ),
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=TestModel(call_tools=[]),
            ),
        ],
    )
    return hunt


def _scripted_model(calls: list[tuple[str, dict[str, Any]]], output: HuntReport) -> Any:
    """A FunctionModel that makes ``calls`` in order, one per turn, then emits
    ``output`` through the agent's real output tool."""
    from pydantic_ai.models.function import AgentInfo, FunctionModel

    turn = itertools.count()

    def _fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
        i = next(turn)
        if i < len(calls):
            name, args = calls[i]
            return ModelResponse(
                parts=[ToolCallPart(tool_name=name, args=args, tool_call_id=f"call-{i}")]
            )
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name=info.output_tools[0].name,
                    args=output.model_dump(mode="json"),
                    tool_call_id=f"call-{i}",
                )
            ]
        )

    return FunctionModel(_fn)


def _run_recorded_real(
    settings: Settings,
    calls: list[tuple[str, dict[str, Any]]],
    output: HuntReport,
    *,
    grid_raises: BaseException | None = None,
    grid_returns: Any = None,
) -> tuple[Any, list[Any]]:
    """Drive the REAL pipeline to persistence: real ``build_hunt_agent``, real
    registered toolset (dedup, egress and clamp wrappers included), real recorder,
    real sqlite store. Only the LLM and the ES call underneath the query tool are
    substituted.

    The stub-node tests above compose the two layers in the reader's head; this
    one composes them in code, so a change to a tool wrapper's short-circuit
    shape (a duplicate hit, a prefetch hit, a new early return) is caught instead
    of quietly changing what the gate sees in production.
    """
    from soc_ai.so_client.elastic import EsSearchResult

    elastic = AsyncMock()
    # Whatever the grid does to the hunt's own queries, it does to the prompt's
    # dataset-inventory probe too — that probe is fail-soft either way.
    elastic.search.side_effect = grid_raises
    elastic.search.return_value = EsSearchResult(total=0, took_ms=0)
    ctx = InvestigationContext(settings=settings, auth=AsyncMock(), elastic=elastic)
    patches = [
        patch(
            "soc_ai.api.hunt_runner.build_investigator_model",
            return_value=_scripted_model(calls, output),
        )
    ]
    if grid_raises is not None:
        patches.append(patch("soc_ai.agent.toolset.query_events_oql", side_effect=grid_raises))
    elif grid_returns is not None:
        patches.append(
            patch("soc_ai.agent.toolset.query_events_oql", AsyncMock(return_value=grid_returns))
        )
    return _persist_hunt(settings, ctx, patches)


@pytest.fixture
def grid_error() -> dict[str, Any]:
    """The tool result a down grid actually produces — built by the REAL
    classifier, so this test breaks if the two layers drift apart."""
    return _tool_error(es.ConnectionTimeout("Connection timed out"))


def test_hunt_with_every_grid_query_failed_is_not_persisted_as_a_clean_complete_hunt(
    settings_kratos: Settings, grid_error: dict[str, Any]
) -> None:
    """THE defect: three grid queries, all failed, model writes "the network is
    quiet" at 0.85 confidence — the PERSISTED hunt must not read as a completed
    clean sweep.

    Asserted on what the recorder wrote, not on the streamed event: the streamed
    report is the model's output, and the whole point is that the deterministic
    layer overrides it.
    """
    nodes = (
        _call_and_return("t_query_events_oql", "c1", grid_error)
        + _call_and_return("t_query_zeek_logs", "c2", grid_error)
        + _call_and_return("t_host_summary", "c3", grid_error)
    )

    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)

    assert hunt.status == "error", "an outage hunt must not be a completed hunt"
    report = hunt.report or {}
    assert report, "the report is still persisted — the analyst sees what happened"
    assert report["confidence"] <= 0.5
    # The report SAYS so, in the two places the analyst reads.
    assert "grid" in (hunt.narrative or "").lower()
    gaps = [f for f in report["findings"] if f["category"] == "visibility_gap"]
    assert gaps, "no visibility-gap finding recorded for the outage"
    assert gaps[0]["validator_note"], "the deterministic note is missing"
    assert GRID_UNAVAILABLE_REASON.replace("_", " ") in gaps[0]["validator_note"].lower()


def test_hunt_whose_queries_succeeded_stays_complete_with_zero_findings(
    settings_kratos: Settings,
) -> None:
    """The control: a genuinely quiet network. Queries answered, the model found
    nothing — that IS a valid clean hunt and must stay ``complete`` with its
    confidence untouched, so the fix can never be "always degrade"."""
    nodes = _call_and_return(
        "t_query_events_oql", "c1", {"total": 0, "hits": []}
    ) + _call_and_return("t_query_zeek_logs", "c2", {"total": 0, "hits": []})

    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)

    assert hunt.status == "complete"
    report = hunt.report or {}
    assert report["confidence"] == 0.85
    assert report["findings"] == []


def test_hunt_with_one_surviving_grid_query_stays_complete(
    settings_kratos: Settings, grid_error: dict[str, Any]
) -> None:
    """A flaky grid is not a blind one: one query failed, another answered, so
    the hunt DID look. Stays complete — this is the assertion that stops the fix
    from being "degrade on any error"."""
    nodes = _call_and_return("t_query_events_oql", "c1", grid_error) + _call_and_return(
        "t_query_zeek_logs", "c2", {"total": 3, "hits": [{"_id": "e1"}]}
    )

    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)

    assert hunt.status == "complete"
    assert (hunt.report or {})["confidence"] == 0.85


def test_off_grid_tool_success_does_not_rescue_a_blind_hunt(
    settings_kratos: Settings, grid_error: dict[str, Any]
) -> None:
    """A web search that worked says nothing about whether the SENSOR could be
    read. Only grid-backed successes count, so this hunt is still degraded."""
    nodes = _call_and_return("t_query_events_oql", "c1", grid_error) + _call_and_return(
        "t_web_search", "c2", {"results": [{"title": "APT-X uses port 4444"}]}
    )

    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)

    assert hunt.status == "error"


def test_prefetch_short_circuit_is_not_a_grid_read(
    settings_kratos: Settings, grid_error: dict[str, Any]
) -> None:
    """The other short-circuit that never touches the grid: a community_id the
    orchestrator already prefetched. Like a duplicate hit it comes back as a
    non-error dict from a grid-backed tool, and like a duplicate hit it is not
    evidence the sensor could be read."""
    nodes = _call_and_return("t_query_events_oql", "c1", grid_error) + _call_and_return(
        "t_query_zeek_logs",
        "c2",
        {"prefetch_already_has_this": True, "community_id": "1:abc=", "hint": "read those"},
    )

    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)

    assert hunt.status == "error"


def test_hunt_that_called_no_tools_at_all_is_not_a_clean_complete_hunt(
    settings_kratos: Settings,
) -> None:
    """FLIPPED (was ``..._is_untouched``): the zero-tool hunt. The transport-only
    outage gate had no failures to count here and let the model's quiet report
    land ``complete`` off an empty transcript — a report that looked at nothing
    reading as "the network is clean". The evidence-count gate keys off the
    ABSENCE of successful reads, not the presence of failures, so a hunt that
    never asked the grid anything persists degraded, saying so."""
    hunt = _run_recorded(settings_kratos, [], QUIET_REPORT)

    assert hunt.status == "error", "a hunt that never queried the grid must not complete"
    report = hunt.report or {}
    assert report["confidence"] <= 0.5
    gaps = [f for f in report["findings"] if f["category"] == "visibility_gap"]
    assert gaps, "no visibility-gap finding recorded for the blind hunt"
    assert "no grid reads" in (gaps[0]["validator_note"] or "").lower()
    assert "grid" in (hunt.narrative or "").lower()


def test_hunt_that_only_used_off_grid_tools_is_not_a_clean_complete_hunt(
    settings_kratos: Settings,
) -> None:
    """The zero-GRID-tool variant: a hunt that answered entirely from web search
    / enrichment never looked at the network — off-grid successes are context
    about the network, not a look at it. Same arm of the gate as the zero-tool
    hunt."""
    nodes = _call_and_return("t_web_search", "c1", {"results": [{"title": "APT-X uses port 4444"}]})

    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)

    assert hunt.status == "error"
    report = hunt.report or {}
    assert report["confidence"] <= 0.5
    assert [f for f in report["findings"] if f["category"] == "visibility_gap"]


def test_hunt_whose_queries_were_all_rejected_is_not_a_clean_complete_hunt(
    settings_kratos: Settings,
) -> None:
    """FLIPPED from the pinned KNOWN GAP (``..._all_malformed_is_untouched``):
    every query came back a BAD QUERY (ES 4xx) rather than a transport failure,
    and the transport-only gate counted 0 successes / 0 failures and stayed
    silent — the hunt landed complete with zero grid reads behind it (a mapping
    change that 400s every OQL query, say). Same false all-clear, different
    cause. The evidence-count gate requires >=1 successful grid read, so this
    now persists degraded — and the wording points at the QUERIES (the model
    wrote queries ES rejected), not at grid health: the grid answered every
    call, it just said no.
    """
    meta = ApiResponseMeta(status=400, http_version="1.1", headers={}, duration=0.0, node=None)
    bad_query = _tool_error(es.ApiError("parse_exception", meta=meta, body={}))
    nodes = _call_and_return("t_query_events_oql", "c1", bad_query) + _call_and_return(
        "t_query_events_oql", "c2", bad_query
    )

    hunt = _run_recorded(settings_kratos, nodes, QUIET_REPORT)

    assert hunt.status == "error", "an all-rejected hunt read nothing and must not complete"
    report = hunt.report or {}
    assert report, "the report is still persisted — the analyst sees what happened"
    assert report["confidence"] <= 0.5
    gaps = [f for f in report["findings"] if f["category"] == "visibility_gap"]
    assert gaps, "no visibility-gap finding recorded for the blind hunt"
    note = (gaps[0]["validator_note"] or "").lower()
    assert "rejected" in note
    # The refused/rejected distinction must survive into what the analyst reads:
    # this arm blames the queries, never grid availability.
    assert GRID_UNAVAILABLE_REASON.replace("_", " ") not in note
    assert "rejected" in (hunt.narrative or "").lower()


def test_grid_outage_does_not_page_on_call_about_a_threat(
    settings_kratos: Settings, grid_error: dict[str, Any]
) -> None:
    """A "threat" a blind hunt asserts is not evidence of anything. The E2.4
    hunt-threat notification must not fire off a hunt that could not read the
    grid."""
    claimed = HuntReport(
        findings=[
            HuntFinding(
                title="C2 beaconing from 192.0.2.15",
                detail="Asserted with no data behind it.",
                severity="critical",
                category="threat",
                hosts=["192.0.2.15"],
                citations=[],
            )
        ],
        narrative="Found beaconing.",
        confidence=0.9,
    )
    nodes = _call_and_return("t_query_events_oql", "c1", grid_error)

    with patch("soc_ai.notify.event_for_hunt") as ev:
        hunt = _run_recorded(
            settings_kratos.model_copy(update={"notify_on_hunt_threat": True}), nodes, claimed
        )

    assert hunt.status == "error"
    ev.assert_not_called()


# ── Layers 1 and 2 composed: the real pipeline, end to end ───────────────────
#
# The stub-node tests above hand the gate pre-built error dicts. These drive the
# REAL toolset, so the seam between "the ES call raised" and "the gate counted
# it" is covered in code rather than in the reader's head — that seam is where a
# short-circuiting tool wrapper can hand the gate a non-error dict for a call
# that never reached the grid.

_OQL_CALL = (
    "t_query_events_oql",
    {"query": "event.dataset:conn | groupby destination.ip", "time_range_minutes": 1440},
)


def test_real_pipeline_hunt_whose_every_grid_query_raised_is_not_a_clean_complete_hunt(
    settings_kratos: Settings,
) -> None:
    """The brief's mandated shape, with nothing hand-assembled in the middle: the
    ES call RAISES, the real tool wrapper renders it, the real gate counts it,
    and the PERSISTED hunt is an outage rather than a completed clean sweep."""
    hunt, events = _run_recorded_real(
        settings_kratos,
        [_OQL_CALL],
        QUIET_REPORT,
        grid_raises=es.ConnectionTimeout("Connection timed out by 10.0.0.9:9200"),
    )

    assert hunt.status == "error", "an outage hunt must not be a completed hunt"
    report = hunt.report or {}
    assert report["confidence"] <= 0.5
    assert "grid" in (hunt.narrative or "").lower()
    gaps = [f for f in report["findings"] if f["category"] == "visibility_gap"]
    assert gaps, "no visibility-gap finding recorded for the outage"
    # The tool DID fail the way this test claims, and the failure reached the
    # model as the structured shape rather than transport text.
    results = [e for e in events if e.kind == "tool_result"]
    assert results, "the real tool never ran"
    assert results[0].payload["result"]["reason"] == GRID_UNAVAILABLE_REASON
    assert "10.0.0.9:9200" not in json.dumps([e.payload for e in events])


def test_real_pipeline_failed_query_retried_verbatim_does_not_rescue_a_blind_hunt(
    settings_kratos: Settings,
) -> None:
    """A DEDUP HIT is not a grid read.

    The failing call registers its key with the dedup tracker before it runs, so
    an identical retry — the documented top failure mode of a weak model under
    errors — short-circuits to ``{"duplicate_call": True}`` without touching the
    grid. Counting that as a success would let a blind hunt certify itself as
    having looked: the exact G6 false all-clear, reached by retrying.
    """
    hunt, events = _run_recorded_real(
        settings_kratos,
        [_OQL_CALL, _OQL_CALL],
        QUIET_REPORT,
        grid_raises=es.ConnectionTimeout("Connection timed out by 10.0.0.9:9200"),
    )

    # The retry really was short-circuited — otherwise this proves nothing.
    results = [e.payload["result"] for e in events if e.kind == "tool_result"]
    assert len(results) == 2, results
    assert results[0]["reason"] == GRID_UNAVAILABLE_REASON
    assert results[1].get("duplicate_call") is True, results[1]

    assert hunt.status == "error", "a duplicate-call short-circuit is not a grid read"
    assert (hunt.report or {})["confidence"] <= 0.5


def test_real_pipeline_healthy_grid_with_zero_hits_stays_complete(
    settings_kratos: Settings,
) -> None:
    """The composed control. Same model, same report, same code path — but the ES
    call ANSWERS (with nothing). A genuinely quiet network is a valid clean hunt
    and keeps its confidence, so nothing here can be satisfied by degrading
    every hunt."""
    from soc_ai.so_client.elastic import EsSearchResult

    hunt, events = _run_recorded_real(
        settings_kratos,
        [_OQL_CALL],
        QUIET_REPORT,
        grid_returns=EsSearchResult(total=0, hits=[], took_ms=7),
    )

    # The query really ANSWERED (with nothing) — without this the test would
    # pass just as well on a tool that failed in some other, uncounted way.
    results = [e.payload["result"] for e in events if e.kind == "tool_result"]
    assert results and results[0].get("total") == 0 and not results[0].get("error"), results

    assert hunt.status == "complete"
    assert (hunt.report or {})["confidence"] == 0.85
    assert (hunt.report or {})["findings"] == []


def test_real_pipeline_hunt_whose_every_query_was_rejected_is_not_a_clean_complete_hunt(
    settings_kratos: Settings,
) -> None:
    """The rejected arm with nothing hand-assembled in the middle: the ES call
    raises a 400, the real tool wrapper renders it as a bad-query error (its own
    message kept, no grid reason — the model needs the text to fix the query),
    the real gate counts zero successful reads, and the PERSISTED hunt is
    degraded — with the done event's reason naming the queries, not grid
    health."""
    meta = ApiResponseMeta(status=400, http_version="1.1", headers={}, duration=0.0, node=None)
    hunt, events = _run_recorded_real(
        settings_kratos,
        [_OQL_CALL],
        QUIET_REPORT,
        grid_raises=es.ApiError("parse_exception", meta=meta, body={}),
    )

    # The tool really failed as a BAD QUERY (kept its own message, no grid
    # reason) — otherwise this test collapses into the transport-outage one.
    results = [e.payload["result"] for e in events if e.kind == "tool_result"]
    assert results, "the real tool never ran"
    assert results[0].get("error") is True
    assert results[0].get("reason") is None, results[0]

    assert hunt.status == "error", "an all-rejected hunt read nothing and must not complete"
    assert (hunt.report or {})["confidence"] <= 0.5
    done = [e for e in events if e.kind == "done"]
    assert done and done[0].payload.get("degraded") is True
    assert done[0].payload.get("degraded_reason") == "grid_queries_rejected"


# ── The prompt half (belt to the gate's braces) ──────────────────────────────


def test_hunt_prompt_separates_a_grid_outage_from_an_empty_result() -> None:
    """The model is told the two apart explicitly: a grid_unavailable result is
    unknowable, not empty, and never grounds an all-clear."""
    p = HUNT_SYSTEM_PROMPT
    assert GRID_UNAVAILABLE_REASON in p
    assert "UNKNOWABLE, not absent" in p
    assert "the network is quiet" in p
    # ...and it is not told to do something the toolset cannot honor: an
    # identical re-send short-circuits on the dedup tracker instead of
    # re-querying, so the instruction is to VARY the retry, not repeat it.
    assert "duplicate_call" in p
    assert "Retry the query once" not in p
