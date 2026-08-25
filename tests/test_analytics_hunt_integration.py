"""Task 8 (behavioral-analytics, 1.3 slice 2) — hunt-agent integration.

Tasks 1-7 landed the four analytics tools (:mod:`soc_ai.tools.analytics`),
registered them hunt-only (:data:`soc_ai.agent.toolset.HUNT_ONLY`), wired
their prompt guidance, and named them in the hunt templates. What is not yet
proven end-to-end: that the REAL hunt agent actually calls them, and that a
finding citing their output survives the deterministic post-hunt citation
gate (:mod:`soc_ai.agent.hunt_gates`) the same way a finding built from
``t_query_events_oql`` evidence does — while a finding citing an id the hunt
never pulled still gets caught.

Harness copied from ``tests/test_hunt_outage_report.py``: ``_scripted_model``
(a ``FunctionModel`` that makes ordered tool calls, then emits a
``HuntReport`` through the agent's real output tool) and ``_persist_hunt``
(drives ``hunt_recorded_run`` against a real sqlite store under patches,
returning the PERSISTED ``(hunt, events)`` read back — not the in-memory
objects — mirroring that file's ``_run_recorded_real``: real
``build_hunt_agent``, real registered toolset (dedup/clamp wrappers
included), real recorder; only the LLM and the raw ``ElasticClient.search``
call are substituted). The ES fake here is new: ``beacon_profile`` and
``dcerpc_histogram`` call ``elastic.search`` directly (not through a single
patched query function), so the fake dispatches by the ``aggs`` key the tool
asked for — the ``tests/test_discover.py`` / ``tests/test_host_activity.py``
duck-typed-fake convention, extended to route on agg NAME rather than just
returning one fixed payload.
"""

from __future__ import annotations

import asyncio
import itertools
import json
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from pydantic_ai.messages import ModelResponse, ToolCallPart
from pydantic_ai.models.test import TestModel
from soc_ai.agent.hunt import HUNT_SYSTEM_PROMPT, HuntFinding, HuntReport, build_hunt_agent
from soc_ai.agent.orchestrator import InvestigationContext, build_investigator
from soc_ai.agent.toolset import HUNT_ONLY
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult

# ── Harness (copied from tests/test_hunt_outage_report.py) ──────────────────


def _ctx(settings: Settings, elastic: Any) -> InvestigationContext:
    return InvestigationContext(settings=settings, auth=AsyncMock(), elastic=elastic)


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


def _persist_hunt(
    settings: Settings, ctx: InvestigationContext, patches: list[Any]
) -> tuple[Any, list[Any]]:
    """Drive ``hunt_recorded_run`` against a real store under ``patches``; return
    the persisted ``(hunt, events)`` read back, not the in-memory objects."""

    async def _go() -> tuple[Any, list[Any]]:
        from soc_ai.api.hunt_runner import hunt_recorded_run
        from soc_ai.store import hunts as hunt_svc
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
                    objective="hunt for beaconing and DCE-RPC abuse",
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


# ── ES fixture: dispatch-by-agg-name fake ────────────────────────────────────
#
# beacon_profile's terms agg is keyed "pairs"; dcerpc_histogram's is keyed
# "ops" (see soc_ai/tools/analytics.py). resolve_agg_field issues its own
# exists-probe search first (aggs=None) and the hunt prompt's dataset-
# inventory block issues further unrelated searches — both are fail-soft (an
# all-zero probe just falls back to resolve_agg_field's first, ECS-first,
# candidate; inventory_prompt_block swallows everything into ""), so a single
# benign zero-hit response covers every call this fake doesn't specifically
# recognize.

_BASE_TS = datetime(2026, 8, 23, 0, 0, 0, tzinfo=UTC)


def _beacon_timestamps(n: int, step_s: float) -> list[str]:
    return [
        (_BASE_TS + timedelta(seconds=i * step_s)).isoformat().replace("+00:00", "Z")
        for i in range(n)
    ]


# A realistic ES `_id` shape (base64-ish, mixed case, no separators but one
# hyphen) — the happy-path fixture's other hit ids are all-lowercase tokens,
# which never exercise the gate's case-folding or its >= 8 char substring-
# match path against a REAL id shape. This one rides as the earliest (and
# thus cited) beacon hit so the happy-path test proves a realistic ES `_id`
# resolves, not just a lowercase test token.
_MIXED_CASE_SAMPLE_ID = "AY72kQBiPCqcmx1Iu-Gz"


def _beacon_aggregations() -> dict[str, Any]:
    """A periodic pair: 10.0.0.5 -> 8.8.8.8 every 60s, 20 events -> cv ~ 0."""
    timestamps = _beacon_timestamps(20, 60.0)
    hits = [
        {"_id": f"beaconhit{i:06d}", "_source": {"@timestamp": ts}}
        for i, ts in enumerate(timestamps, start=1)
    ]
    hits[0]["_id"] = _MIXED_CASE_SAMPLE_ID
    dst_bucket = {
        "key": "8.8.8.8",
        "doc_count": len(timestamps),
        "ts": {
            "hits": {
                "total": {"value": len(timestamps), "relation": "eq"},
                "hits": hits,
            }
        },
        "bytes_out_avg": {"value": 512.0},
    }
    return {
        "pairs": {
            "sum_other_doc_count": 0,
            "buckets": [
                {
                    "key": "10.0.0.5",
                    "doc_count": len(timestamps),
                    "dsts": {"buckets": [dst_bucket]},
                }
            ],
        }
    }


def _dcerpc_aggregations() -> dict[str, Any]:
    """A Zerologon-shaped histogram: busy svcctl noise plus a rare
    NetrServerAuthenticate3 burst from one source -> both flagged and rare."""
    busy_bucket = {
        "key": "svcctl",
        "doc_count": 5000,
        "sample": {
            "hits": {
                "total": {"value": 5000, "relation": "gte"},
                "hits": [
                    {
                        "_id": f"dcerpcbusy{i}",
                        "_source": {
                            "source.ip": "10.0.0.1",
                            "destination.ip": "10.0.0.9",
                            "dce_rpc.operation": "svcctl",
                        },
                    }
                    for i in range(2)
                ],
            }
        },
        "sources": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [{"key": "10.0.0.1", "doc_count": 5000}],
        },
    }
    zerologon_bucket = {
        "key": "NetrServerAuthenticate3",
        "doc_count": 4,
        "sample": {
            "hits": {
                "total": {"value": 4, "relation": "eq"},
                "hits": [
                    {
                        "_id": f"dcerpchit0000{i}",
                        "_source": {
                            "source.ip": "10.0.0.50",
                            "destination.ip": "10.0.0.9",
                            "dce_rpc.operation": "NetrServerAuthenticate3",
                        },
                    }
                    for i in range(1, 3)
                ],
            }
        },
        "sources": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [{"key": "10.0.0.50", "doc_count": 4}],
        },
    }
    return {
        "ops": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [busy_bucket, zerologon_bucket],
        }
    }


class _AnalyticsFakeElastic:
    """Routes ``ElasticClient.search`` calls by the top-level ``aggs`` key the
    tool asked for. Anything unrecognized (the ``resolve_agg_field`` exists-
    probe, the hunt prompt's dataset-inventory search) gets a benign
    zero-hit, no-aggregations response — both callers are fail-soft on that
    shape (see module docstring)."""

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        aggs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> EsSearchResult:
        if aggs and "pairs" in aggs:
            return EsSearchResult(total=20, took_ms=2, aggregations=_beacon_aggregations())
        if aggs and "ops" in aggs:
            return EsSearchResult(total=5004, took_ms=2, aggregations=_dcerpc_aggregations())
        return EsSearchResult(total=0, took_ms=1)


def _fake_elastic() -> AsyncMock:
    fake = _AnalyticsFakeElastic()
    elastic = AsyncMock()
    elastic.search = AsyncMock(side_effect=fake.search)
    return elastic


_BEACON_CALL = ("t_beacon_profile", {})
_DCERPC_CALL = ("t_dcerpc_histogram", {})


def _analytics_report(citation: str) -> HuntReport:
    """A HuntReport whose one finding cites ``citation`` — a real sample id
    from the beacon fixture in the happy-path test, a fabricated one in the
    gate test."""
    return HuntReport(
        findings=[
            HuntFinding(
                title="Periodic beacon plus Zerologon-shaped DCE-RPC burst",
                detail=(
                    "10.0.0.5 shows a periodic connection cadence to 8.8.8.8 (cv ~0, "
                    "measured by t_beacon_profile) alongside a NetrServerAuthenticate3 "
                    "burst t_dcerpc_histogram flagged as both dangerous and rare against "
                    "the busy svcctl baseline -- consistent with Zerologon staging."
                ),
                severity="critical",
                category="threat",
                hosts=["10.0.0.5"],
                citations=[citation],
            )
        ],
        narrative=(
            "Critical: periodic external beaconing corroborated by a Zerologon-shaped "
            "DCE-RPC authentication burst."
        ),
        affected_hosts=["10.0.0.5"],
        confidence=0.8,
    )


# ── Registration sanity ──────────────────────────────────────────────────────


def test_analytics_tools_registered_hunt_only(settings_kratos: Settings) -> None:
    """The four analytics tools are on the hunt agent's real registered
    surface, and NOT on the investigator's -- HUNT_ONLY (soc_ai.agent.toolset)
    is a hunt-exclusive delta, not a widened role."""
    model = TestModel(call_tools=[])

    async def _go() -> tuple[Any, Any]:
        hunt_agent = build_hunt_agent(
            model,
            _ctx(settings_kratos, AsyncMock()),
            system_prompt=HUNT_SYSTEM_PROMPT.format(objective="hunt for beaconing"),
        )
        investigator = build_investigator(model, _ctx(settings_kratos, AsyncMock()))
        return hunt_agent, investigator

    hunt_agent, investigator = asyncio.run(_go())
    hunt_tools = set(hunt_agent._function_toolset.tools.keys())  # type: ignore[attr-defined]
    investigator_tools = set(
        investigator._function_toolset.tools.keys()  # type: ignore[attr-defined]
    )

    assert hunt_tools >= HUNT_ONLY, f"missing from hunt surface: {HUNT_ONLY - hunt_tools}"
    assert not (HUNT_ONLY & investigator_tools), (
        f"leaked onto investigator: {HUNT_ONLY & investigator_tools}"
    )


# ── Happy path: both tools run, evidence is citable ──────────────────────────


def test_hunt_agent_calls_analytics_tools_and_evidence_resolves(
    settings_kratos: Settings,
) -> None:
    """Script the model to call t_beacon_profile then t_dcerpc_histogram over
    a REAL hunt agent + real toolset + real store (only the LLM and the raw ES
    call are substituted), then emit a HuntReport whose finding cites a real
    beacon sample id. Both tools must actually have run, and the citation must
    SURVIVE the post-hunt gate: no validator_note, severity uncapped."""
    ctx = _ctx(settings_kratos, _fake_elastic())
    report = _analytics_report(_MIXED_CASE_SAMPLE_ID)

    hunt, events = _persist_hunt(
        settings_kratos,
        ctx,
        [
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=_scripted_model([_BEACON_CALL, _DCERPC_CALL], report),
            )
        ],
    )

    # The persisted read-back of run_hunt's gathered_tool_results (hunt_runner
    # ._stream_node appends {tool_name, result} for every tool_result event,
    # and the recorder persists each event's payload verbatim) -- both tools
    # actually ran, and neither errored.
    tool_results = [e.payload for e in events if e.kind == "tool_result"]
    names = {r.get("tool_name") for r in tool_results}
    assert {"t_beacon_profile", "t_dcerpc_histogram"} <= names, names
    for r in tool_results:
        if r.get("tool_name") in {"t_beacon_profile", "t_dcerpc_histogram"}:
            assert r["result"].get("error") is not True, r["result"]

    # The beacon result really does carry the sample id the finding cites --
    # otherwise this test would prove nothing about resolution. It's the
    # mixed-case, ES-`_id`-shaped id, not a lowercase test token.
    beacon_result = next(r["result"] for r in tool_results if r["tool_name"] == "t_beacon_profile")
    assert _MIXED_CASE_SAMPLE_ID in beacon_result["items"][0]["sample_ids"]

    assert hunt.status == "complete", "grid-backed successes must not degrade the hunt"
    findings = (hunt.report or {}).get("findings") or []
    assert len(findings) == 1
    finding = findings[0]
    assert finding["citations"] == [_MIXED_CASE_SAMPLE_ID], (
        "a resolving mixed-case citation must survive intact"
    )
    assert finding["validator_note"] is None
    assert finding["severity"] == "critical", "a resolved, corroborated threat keeps its severity"


# ── The gate still bites on an analytics-only hunt ───────────────────────────


def test_hunt_agent_fabricated_citation_is_stripped_and_capped(settings_kratos: Settings) -> None:
    """Same setup, but the finding cites an id present in NEITHER tool result.
    The deterministic citation gate must still strip it and cap severity --
    proving the gate holds when the hunt's whole evidence base is analytics
    tools, not just t_query_events_oql."""
    ctx = _ctx(settings_kratos, _fake_elastic())
    report = _analytics_report("fabricated0000000001")

    hunt, events = _persist_hunt(
        settings_kratos,
        ctx,
        [
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=_scripted_model([_BEACON_CALL, _DCERPC_CALL], report),
            )
        ],
    )

    # The fabricated id genuinely never appears in what the hunt gathered --
    # otherwise a "gate held" result would be an accident of a real match.
    tool_results = [e.payload for e in events if e.kind == "tool_result"]
    dump = json.dumps([r.get("result") for r in tool_results], default=str).lower()
    assert "fabricated0000000001" not in dump

    assert hunt.status == "complete", "the tools DID run and answer; only the citation is bogus"
    findings = (hunt.report or {}).get("findings") or []
    assert len(findings) == 1
    finding = findings[0]
    assert finding["citations"] == [], "the fabricated citation must be stripped"
    assert finding["validator_note"], "the gate must leave a note explaining the cap"
    assert "did not resolve" in finding["validator_note"].lower()
    assert finding["severity"] == "low", "an unresolved citation caps severity to low"
