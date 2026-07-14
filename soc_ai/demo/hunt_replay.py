"""Demo hunt-start replay — stream a recorded canned hunt through HuntRecorder.

Mirrors :mod:`soc_ai.demo.replay` (investigations) for the Hunt Console
"start hunt" path (``POST /api/v1/hunts/chat``). In demo mode the live path
would build the hunt agent and the Task-2 egress guard would raise
``DemoEgressBlocked``; instead we replay ONE canned hunt's recorded events
through the same :class:`~soc_ai.api.hunt_recorder.HuntRecorder` the live runner
uses, so the SPA's poll of ``GET /api/v1/hunts/{id}`` sees an ordinary completed
hunt — timeline, narrative, and report all rendered.

How the report/narrative lands: the recorded ``events[]`` carry a ``hunt_report``
event whose payload IS the HuntReport dump (exactly what ``run_hunt`` emits). The
recorder tees that payload into ``self._report`` on ``record``, and
``finish("complete")`` finalizes the row with ``narrative=report["narrative"]``
and ``report=report`` — so the replayed hunt ends ``status=complete`` WITH its
narrative + report, not an empty completed hunt. Zero egress: the recorder writes
the store only; no model/gateway is ever constructed.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, cast

from soc_ai.api.hunt_recorder import HuntRecorder

_LOGGER = logging.getLogger(__name__)

TOTAL_REPLAY_S = 30.0  # spec: paced, capped well under a minute
MAX_STEP_S = 1.0


def pick_canned_hunt(fixtures: dict[str, Any] | None) -> dict[str, Any] | None:
    """The first seeded hunt whose events include a ``hunt_report`` — the replay
    target.

    *fixtures* is the cached fixture document (``app.state.demo_fixtures``) —
    ``None`` when the fixture file was missing/invalid at startup (fail-soft
    boot). A ``hunt_report`` event is REQUIRED, not merely any event: the
    recorder tees that event's payload into the row's report, and
    ``finish("complete")`` downgrades a reportless stream to ``error`` — so a
    hunt with events but no ``hunt_report`` (e.g. a chat-only row) would replay
    straight to a broken ``error`` hunt. Skipping it here means the replay only
    ever targets a hunt that will actually land ``complete`` with a narrative +
    report.
    """
    for hunt in (fixtures or {}).get("hunts") or []:
        if not isinstance(hunt, dict):
            continue
        events = hunt.get("events") or []
        if any(isinstance(e, dict) and e.get("kind") == "hunt_report" for e in events):
            return cast("dict[str, Any]", hunt)
    return None


def _step_delay(n: int) -> float:
    """Per-step pause: spread the run across :data:`TOTAL_REPLAY_S`, capped per step."""
    return min(MAX_STEP_S, TOTAL_REPLAY_S / max(n, 1))


async def start_background_hunt_replay(
    state: Any, objective: str, started_by: str, hunt: dict[str, Any]
) -> str | None:
    """Create a Hunt via HuntRecorder, background-drain its recorded events, and
    return the new hunt id immediately.

    Mirrors ``HuntConsoleManager.start`` / ``start_background_replay``: the row is
    created up front (so the route can return the id and the SPA can start
    polling), then the recorded events are teed into the store from a background
    ``asyncio.Task`` that runs to completion regardless of client state. Task refs
    ride on ``state.demo_replay_tasks`` so they can't be GC'd mid-run and so the
    app-shutdown drain can cancel them cleanly. Returns ``None`` if the row could
    not be created (route answers 503).
    """
    recorder = HuntRecorder(
        state.db_sessionmaker, objective=objective, started_by=started_by, kind="chat"
    )
    hunt_id = await recorder.start()
    if hunt_id is None:
        return None

    events = list(hunt.get("events") or [])
    delay = _step_delay(len(events))

    async def _drain() -> None:
        try:
            for i, ev in enumerate(events):
                if i:  # pace BETWEEN steps — no dead air after the terminal event
                    await asyncio.sleep(delay)
                await recorder.record(
                    str(ev.get("kind", "")),
                    int(ev.get("sequence", 0)),
                    ev.get("payload") or {},
                )
            # The recorded hunt_report event already teed into recorder._report, so
            # finish("complete") lands the row complete WITH narrative + report.
            await recorder.finish("complete")
        except asyncio.CancelledError:
            # This drain is a bare asyncio.Task, and app shutdown cancels it:
            # main.py's lifespan extends its worker-drain list with
            # state.demo_replay_tasks and calls task.cancel() on each BEFORE
            # db_engine.dispose(). Shield the terminal write so it commits before
            # the unwind — a bare `await recorder.finish(...)` here races the
            # engine dispose (or is re-cancelled) and orphans the row in
            # 'running'. asyncio.shield runs the finalize where the cancellation
            # can't reach it, so the row lands terminal, not stuck.
            await asyncio.shield(recorder.finish("error"))
            raise
        except Exception:
            _LOGGER.exception("demo hunt replay background drain failed")
            await asyncio.shield(recorder.finish("error"))
        finally:
            # No-op if already finished; lands a drain abandoned mid-stream as
            # 'error'. Shielded for the same reason as the cancel path above.
            await asyncio.shield(recorder.finish("error"))

    task: asyncio.Task[None] = asyncio.create_task(_drain())
    if not hasattr(state, "demo_replay_tasks"):
        state.demo_replay_tasks = set()
    tasks: set[asyncio.Task[None]] = state.demo_replay_tasks
    tasks.add(task)
    task.add_done_callback(tasks.discard)
    return hunt_id
