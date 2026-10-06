"""Every run records what it cost: requests, tokens, tool calls, searches, wall time.

Stage 1, item 1 of the four-tier plan (docs/dev/specs/
2026-10-04-four-tier-detection-methodology.md, "Measurement"). The counters
are the "before" measurement, so they must say what the run did and never more.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.agent.context import StepEvent
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.api.runner import recorded_run
from soc_ai.config import Settings
from soc_ai.run_meter import RunMeter, SearchMeter, count_search, start_search_meter
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Hunt, Investigation


def test_meter_counts_model_usage_tool_calls_and_code_dispatches() -> None:
    meter = RunMeter()
    meter.observe("session_start", {"run_class": "standard"})
    meter.observe("usage", {"requests": 2, "input_tokens": 30_000, "output_tokens": 900})
    meter.observe("usage", {"requests": 1, "input_tokens": 8_000, "output_tokens": 300})
    meter.observe("tool_call", {"tool_name": "t_rule_prevalence"})
    # The output tool is the model handing back its answer, not a tool it ran.
    meter.observe("tool_call", {"tool_name": "final_result"})
    # A tool the pipeline called in code still costs a tool call.
    meter.observe("targeted_dispatch", {"tool_name": "t_web_search"})
    meter.observe("triage_report", {"verdict": "false_positive", "run_class": "deep"})
    c = meter.finish()
    assert c.model_requests == 3
    assert c.input_tokens == 38_000
    assert c.output_tokens == 1_200
    assert c.tool_calls == 2
    # The report states the final class, and the last statement wins.
    assert c.run_class == "deep"
    # No search meter was attached: the count is unknown, not zero.
    assert c.es_searches is None
    assert c.wall_ms >= 0


def test_a_meter_with_no_usage_event_reports_zero_requests() -> None:
    """A run that never reached the model really made zero requests."""
    c = RunMeter().finish()
    assert (c.model_requests, c.input_tokens, c.output_tokens, c.tool_calls) == (0, 0, 0, 0)


async def test_the_search_meter_follows_the_run_into_child_tasks() -> None:
    """A tool call runs in a child task. Its search must land on the run's meter."""
    seen: list[SearchMeter] = []

    async def run_one() -> None:
        meter = start_search_meter()
        seen.append(meter)
        count_search()

        async def child() -> None:
            count_search()
            count_search()

        await asyncio.gather(child(), child())

    # Two runs in two tasks at once: each meter sees only its own reads.
    await asyncio.gather(asyncio.create_task(run_one()), asyncio.create_task(run_one()))
    assert [m.searches for m in seen] == [5, 5]


async def test_a_search_outside_a_run_counts_nowhere() -> None:
    async def outside() -> int:
        count_search()  # no meter in this task: a no-op, never an error
        meter = start_search_meter()
        return meter.searches

    assert await asyncio.create_task(outside()) == 0


async def test_the_elastic_client_counts_its_searches_and_gets(settings_kratos: Settings) -> None:
    fake = AsyncMock()
    fake.search = AsyncMock(return_value={"hits": {"total": {"value": 0}, "hits": []}})
    fake.get = AsyncMock(return_value={"_id": "doc-1", "_source": {}})
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake):
        client = ElasticClient(settings_kratos)

    async def run() -> int:
        meter = start_search_meter()
        await client.search("logs-*", {"match_all": {}})
        await client.search("logs-*", {"match_all": {}})
        await client.get("logs-x", "doc-1")
        return meter.searches

    assert await asyncio.create_task(run()) == 3


def _state(settings: Settings) -> Any:
    engine = make_engine(settings)
    return engine, SimpleNamespace(db_sessionmaker=make_sessionmaker(engine), settings=settings)


async def test_a_triage_run_lands_its_counters_on_the_row(settings_kratos: Settings) -> None:
    engine, state = _state(settings_kratos)
    await run_migrations(engine)
    fake = AsyncMock()
    fake.search = AsyncMock(return_value={"hits": {"total": {"value": 0}, "hits": []}})
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake):
        client = ElasticClient(settings_kratos)

    async def stream() -> AsyncIterator[StepEvent]:
        def ev(seq: int, kind: str, payload: dict[str, Any]) -> StepEvent:
            return StepEvent(kind=kind, session_id="s", sequence=seq, payload=payload)

        yield ev(1, "session_start", {"alert_id": "a-1", "run_class": "standard"})
        # The prefetch reads the grid twice before the model runs.
        await client.search("logs-*", {"match_all": {}})
        await client.search("logs-*", {"match_all": {}})
        yield ev(2, "tool_call", {"tool_name": "t_rule_prevalence", "args": {}})
        await client.search("logs-*", {"match_all": {}})
        yield ev(3, "tool_call", {"tool_name": "final_result", "args": {}})
        yield ev(4, "usage", {"requests": 2, "input_tokens": 50_000, "output_tokens": 800})
        yield ev(
            5,
            "triage_report",
            {"verdict": "false_positive", "confidence": 0.9, "summary": "Benign."},
        )
        yield ev(6, "done", {})

    async def drive() -> str:
        inv_id = ""
        async for name, data in recorded_run(
            state, alert_id="a-1", started_by="analyst", event_stream=stream()
        ):
            if name == "investigation_created":
                inv_id = data["investigation_id"]
        return inv_id

    # The run is drained in its own task, as the hunt manager and the sweep do.
    inv_id = await asyncio.create_task(drive())
    async with state.db_sessionmaker() as db:
        row = await db.get(Investigation, inv_id)
    await engine.dispose()
    assert row is not None
    assert row.status == "complete"
    assert row.run_class == "standard"
    assert row.model_requests == 2
    assert row.input_tokens == 50_000
    assert row.output_tokens == 800
    assert row.tool_calls == 1
    assert row.es_searches == 3
    assert row.wall_ms is not None and row.wall_ms >= 0


async def test_a_hunt_lands_its_counters_on_the_row(settings_kratos: Settings) -> None:
    """A hunt stored no model usage before the counters. Now it does."""
    engine, state = _state(settings_kratos)
    await run_migrations(engine)

    async def fake_run_hunt(_ctx: Any, **_kw: Any) -> AsyncIterator[StepEvent]:
        def ev(seq: int, kind: str, payload: dict[str, Any]) -> StepEvent:
            return StepEvent(kind=kind, session_id="h", sequence=seq, payload=payload)

        yield ev(1, "hunt_started", {"objective": "look"})
        yield ev(2, "tool_call", {"tool_name": "t_query_events_oql", "args": {}})
        yield ev(3, "tool_call", {"tool_name": "t_host_dossier", "args": {}})
        yield ev(4, "usage", {"requests": 7, "input_tokens": 120_000, "output_tokens": 4_000})
        yield ev(5, "hunt_report", {"narrative": "Quiet.", "findings": []})
        yield ev(6, "done", {"finding_count": 0, "degraded": False})

    ctx = SimpleNamespace(include_synth=False)

    async def drive() -> str:
        hunt_id = ""
        with patch("soc_ai.api.hunt_runner.run_hunt", fake_run_hunt):
            async for name, data in hunt_recorded_run(
                state, ctx=ctx, objective="look", started_by="analyst"
            ):
                if name == "hunt_created":
                    hunt_id = data["hunt_id"]
        return hunt_id

    hunt_id = await asyncio.create_task(drive())
    async with state.db_sessionmaker() as db:
        row = await db.get(Hunt, hunt_id)
    await engine.dispose()
    assert row is not None
    assert row.run_class == "standard"
    assert row.model_requests == 7
    assert row.input_tokens == 120_000
    assert row.output_tokens == 4_000
    assert row.tool_calls == 2
    assert row.es_searches == 0
    assert row.wall_ms is not None


def test_run_hunt_emits_a_usage_event_from_the_agent_run() -> None:
    """The hunt runner reads the agent run's usage, property or method."""
    from pydantic_ai.usage import RunUsage
    from soc_ai.api.hunt_runner import _hunt_usage_event

    def factory(kind: str, payload: dict[str, Any]) -> StepEvent:
        return StepEvent(kind=kind, session_id="h", sequence=1, payload=payload)

    run = SimpleNamespace(
        usage=RunUsage(requests=4, input_tokens=9_000, output_tokens=500, tool_calls=3)
    )
    ev = _hunt_usage_event(factory, run, phase="hunt")
    assert ev is not None
    assert ev.kind == "usage"
    assert ev.payload["requests"] == 4
    assert ev.payload["input_tokens"] == 9_000
    # No run object: nothing to report, and no fake zero.
    assert _hunt_usage_event(factory, None, phase="hunt") is None


@pytest.mark.parametrize("kind", ["usage", "tool_call"])
def test_a_non_dict_payload_never_breaks_the_meter(kind: str) -> None:
    meter = RunMeter()
    meter.observe(kind, None)
    meter.observe(kind, "garbage")
    assert meter.finish().model_requests == 0
