"""The model gets one fact line per grid gap: a zero over those hours means unknown.

The general chat called a host "simply inactive" over four days the grid held
no data, and a hunt over the same hours reported zero counts as facts
(dogfood 2026-10-19, R1-D5, R3-D3). The tools give the model no coverage fact
for its window, so the seed states it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient
from soc_ai.agent.chat_agent import build_general_context_block
from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.config import Settings
from soc_ai.store import general_chat as gc_svc
from soc_ai.store import grid_gaps
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

from tests.test_general_chat_api import _run, _state, client  # noqa: F401 - the fixture
from tests.test_hunts_api import _planner_system_prompt

_LINE_END = "A zero count over these hours means unknown."


def _gap_times() -> tuple[datetime, datetime]:
    now = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    return now - timedelta(days=4), now - timedelta(hours=3)


async def _record(maker: Any) -> tuple[datetime, datetime]:
    start, end = _gap_times()
    async with maker() as db:
        await grid_gaps.open_probe_gap(db, started_at=start, detail="refused")
        await grid_gaps.close_probe_gaps(db, ended_at=end)
    return start, end


def test_the_seed_block_carries_each_gap_line_after_the_inventory() -> None:
    line = "The grid held no data from 2026-10-15 13:36 UTC to 2026-10-19 10:15 UTC. " + _LINE_END
    block = build_general_context_block(inventory_block="## Data available", gap_lines=[line])
    assert line in block
    assert block.index("## Data available") < block.index(line) < block.index("Recent posture")
    assert _LINE_END not in build_general_context_block(inventory_block="## Data available")


def test_the_general_chat_seed_names_a_recorded_gap(client: TestClient) -> None:  # noqa: F811
    from soc_ai.webui.general_chat_manager import _general_spec

    state = _state(client)

    async def _go() -> tuple[str, tuple[datetime, datetime]]:
        span = await _record(state.db_sessionmaker)
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, "t9", "what happened on the host last week?")
            row = await gc_svc.create_pending_assistant(db, "t9")
        inputs = await _general_spec(state, "t9", row.id).prepare()
        assert inputs is not None
        return inputs.seed_context, span

    seed, (start, end) = _run(_go())
    assert (
        f"The grid held no data from {grid_gaps.stamp(start)} to {grid_gaps.stamp(end)}. "
        + _LINE_END
    ) in seed


def test_the_general_chat_seed_has_no_gap_line_without_a_gap(client: TestClient) -> None:  # noqa: F811
    from soc_ai.webui.general_chat_manager import _general_spec

    state = _state(client)

    async def _go() -> str:
        async with state.db_sessionmaker() as db:
            await gc_svc.add_user_message(db, "t8", "anything new?")
            row = await gc_svc.create_pending_assistant(db, "t8")
        inputs = await _general_spec(state, "t8", row.id).prepare()
        assert inputs is not None
        return inputs.seed_context

    assert _LINE_END not in _run(_go())


async def test_the_hunt_prompt_names_a_recorded_gap(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    start, end = await _record(maker)
    ctx = InvestigationContext(
        settings=settings_kratos, auth=AsyncMock(), elastic=AsyncMock(), db_sessionmaker=maker
    )
    prompt = await _planner_system_prompt(ctx, "did the domain controller see a ticket attack?")
    await engine.dispose()
    assert (
        f"The grid held no data from {grid_gaps.stamp(start)} to {grid_gaps.stamp(end)}. "
        + _LINE_END
    ) in prompt
