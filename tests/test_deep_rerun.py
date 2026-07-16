"""The per-run deep flag must survive the whole chain:
POST /hunt {deep} → hunt_manager.start → run_recorded → investigate →
_run_synth_first_pipeline(force loop). Route→manager is covered in
test_webui_api.py; these pin the inner links."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch


def test_investigate_threads_deep_to_pipeline() -> None:
    from soc_ai.agent import orchestrator

    captured: dict[str, Any] = {}

    async def fake_pipeline(*, alert_id: str, ctx: Any, focus_hint: Any = None, deep: bool = False):
        captured["deep"] = deep
        return
        yield  # pragma: no cover - makes this an async generator

    async def run() -> None:
        with patch.object(orchestrator, "_run_synth_first_pipeline", fake_pipeline):
            async for _ in orchestrator.investigate("a1", ctx=SimpleNamespace(), deep=True):
                pass

    asyncio.run(run())
    assert captured["deep"] is True


def test_run_recorded_threads_deep_to_investigate() -> None:
    from soc_ai.api import runner

    captured: dict[str, Any] = {}

    def fake_investigate(alert_id: str, *, ctx: Any, focus_hint: Any = None, deep: bool = False):
        captured["deep"] = deep

        async def gen():
            return
            yield  # pragma: no cover

        return gen()

    async def fake_recorded_run(state: Any, **kwargs: Any):
        # drain the supplied event stream like the real recorder would
        async for item in kwargs["event_stream"]:
            yield item

    async def run() -> None:
        with (
            patch.object(runner, "investigate", fake_investigate),
            patch.object(runner, "recorded_run", fake_recorded_run),
        ):
            async for _ in runner.run_recorded(
                SimpleNamespace(),
                ctx=SimpleNamespace(),
                alert_id="a1",
                started_by="tester",
                deep=True,
            ):
                pass

    asyncio.run(run())
    assert captured["deep"] is True


def test_hunt_manager_threads_deep_to_run_recorded() -> None:
    from soc_ai.webui import hunt_manager as hm

    captured: dict[str, Any] = {}

    async def fake_run_recorded(state: Any, **kwargs: Any):
        captured["deep"] = kwargs.get("deep")
        yield "investigation_created", {"investigation_id": "INV-1"}

    async def run() -> None:
        with (
            patch.object(hm, "run_recorded", fake_run_recorded),
            patch.object(hm, "ctx_from_state", lambda _s: SimpleNamespace()),
        ):
            mgr = hm.HuntManager()
            inv_id = await mgr.start(
                SimpleNamespace(), alert_id="a1", started_by="tester", deep=True
            )
            assert inv_id == "INV-1"
            # let the drain task settle so no warning leaks between tests
            await asyncio.sleep(0)

    asyncio.run(run())
    assert captured["deep"] is True
