"""recorded_run cancellation semantics: only an EXPLICIT operator cancel lands
'cancelled'; a shutdown / client-disconnect cancellation lands 'error'."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from soc_ai.api.runner import CancelToken, recorded_run
from soc_ai.webui.hunt_manager import HuntManager


class _FakeRecorder:
    """Stands in for InvestigationRecorder; records the first finish() (the real
    recorder is first-wins idempotent)."""

    def __init__(self, *a: Any, **k: Any) -> None:
        self.finishes: list[str] = []

    async def start(self) -> str:
        return "INV-1"

    async def record(self, *a: Any, **k: Any) -> None:
        return None

    async def finish(self, status: str) -> None:
        if not self.finishes:  # first-wins, like the real recorder
            self.finishes.append(status)


async def _blocking_stream() -> Any:
    """Emit one event, then block forever (an in-flight investigation)."""
    yield SimpleNamespace(kind="step", sequence=1, payload={}, session_id="s")
    await asyncio.Event().wait()


async def _run_until_cancel(token: CancelToken | None) -> _FakeRecorder:
    rec = _FakeRecorder()
    with patch("soc_ai.api.runner.InvestigationRecorder", return_value=rec):

        async def consume() -> None:
            async for _name, _data in recorded_run(
                SimpleNamespace(db_sessionmaker=None),
                alert_id="a",
                started_by="u",
                event_stream=_blocking_stream(),
                cancel_token=token,
            ):
                pass

        task = asyncio.create_task(consume())
        await asyncio.sleep(0.05)  # let it start + block inside the stream
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    return rec


@pytest.mark.asyncio
async def test_unmarked_cancellation_lands_error() -> None:
    """A disconnect / shutdown cancel (no token, or token not requested) → error."""
    rec = await _run_until_cancel(None)
    assert rec.finishes == ["error"]

    rec2 = await _run_until_cancel(CancelToken())  # token present but not requested
    assert rec2.finishes == ["error"]


@pytest.mark.asyncio
async def test_explicit_cancel_lands_cancelled() -> None:
    """An operator cancel marks the token requested → 'cancelled'."""
    token = CancelToken()
    token.requested = True
    rec = await _run_until_cancel(token)
    assert rec.finishes == ["cancelled"]


def test_hunt_manager_cancel_marks_token_before_cancelling() -> None:
    """HuntManager.cancel sets the token requested BEFORE cancelling the task, so
    the recorded run can distinguish it from an infrastructural cancellation."""

    class _FakeTask:
        def __init__(self) -> None:
            self.cancelled = False

        def done(self) -> bool:
            return False

        def cancel(self) -> None:
            self.cancelled = True

    mgr = HuntManager()
    token = CancelToken()
    task = _FakeTask()
    mgr._tasks["INV-1"] = task  # type: ignore[assignment]
    mgr._tokens["INV-1"] = token

    assert mgr.cancel("INV-1") is True
    assert token.requested is True
    assert task.cancelled is True

    # Unknown id → False, nothing touched.
    assert mgr.cancel("nope") is False
