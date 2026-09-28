"""hunt_recorded_run must land a terminal row when its SSE consumer goes away.

Starlette/sse-starlette run POST /api/v1/hunts/chat/stream inside an anyio
cancel scope that re-delivers the cancellation on every await until the scope
exits. A bare cleanup ``await recorder.finish(...)`` is therefore itself
cancelled mid-commit and the hunt row is orphaned in 'running' until the
reaper. The sibling /investigate runner shields the terminal write; the hunt
path must do the same.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import anyio
from soc_ai.agent.orchestrator import InvestigationContext, StepEvent
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.config import Settings
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations


async def _slow_hunt(*_args: Any, **_kwargs: Any) -> AsyncIterator[StepEvent]:
    """A hunt that keeps streaming steps and never reaches its terminal event."""
    for i in range(50):
        yield StepEvent(kind="step", session_id="s", sequence=i, payload={"i": i})
        await anyio.sleep(0.02)


async def test_hunt_stream_client_disconnect_lands_terminal_state(
    settings_kratos: Settings,
) -> None:
    """A client disconnect mid-hunt (anyio cancel scope, as in production) must
    finalize the row to 'error' straight away — NOT leave it 'running' for the
    reaper. A bare asyncio ``task.cancel()`` does not reproduce this: only the
    anyio scope keeps the cancellation pending across the cleanup awaits."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    state = SimpleNamespace(db_sessionmaker=maker)
    ctx = InvestigationContext(settings=settings_kratos, auth=AsyncMock(), elastic=AsyncMock())

    holder: dict[str, str] = {}
    seen: list[str] = []

    async def consume(scope: anyio.CancelScope) -> None:
        async for name, data in hunt_recorded_run(
            state, ctx=ctx, objective="hunt for beaconing to rare external hosts", started_by="t"
        ):
            if name == "hunt_created":
                holder["id"] = data["hunt_id"]
            seen.append(name)
            if len(seen) >= 3:
                scope.cancel()

    with patch("soc_ai.api.hunt_runner.run_hunt", _slow_hunt):
        async with anyio.create_task_group() as tg:
            tg.start_soon(consume, tg.cancel_scope)

    hunt_id = holder["id"]
    # The shielded finalize lands on a detached task a beat after the task group
    # unwinds; poll for it rather than race it. A genuine orphan still fails at
    # the timeout.
    hunt = None
    for _ in range(300):  # up to ~3s
        async with maker() as db:
            got = await hunt_svc.get_with_events(db, hunt_id)
        assert got is not None
        hunt, _events = got
        if hunt.status != "running":
            break
        await anyio.sleep(0.01)
    await engine.dispose()

    assert "done" not in seen
    assert hunt is not None
    assert hunt.status == "error"
