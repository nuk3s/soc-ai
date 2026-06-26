"""HuntManager — interactive investigations as decoupled background tasks.

POST /api/v1/hunt creates the investigation row via run_recorded's first
``investigation_created`` event, then drains the REST of the stream in a
background asyncio.Task that runs to completion regardless of client state.

This mirrors the auto-triage pattern in autotriage.py but for single,
on-demand hunts initiated from the React app (/app).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from soc_ai.api.deps import ctx_from_state
from soc_ai.api.runner import run_recorded

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_hunt_manager"


class HuntManager:
    """Tracks in-flight background hunt tasks to prevent GC collection."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[None]] = {}

    async def start(
        self,
        state: Any,
        *,
        alert_id: str,
        started_by: str,
    ) -> str | None:
        """Create the investigation row and spawn a background drainer task.

        Consumes ``run_recorded`` until the first ``investigation_created``
        event to capture the investigation id, then hands the remaining
        generator to a background task that runs it to completion.

        Returns the investigation id, or None if the generator ended or
        errored before emitting ``investigation_created``.
        """
        ctx = ctx_from_state(state)
        gen = run_recorded(state, ctx=ctx, alert_id=alert_id, started_by=started_by)

        # Consume until the first event — must be "investigation_created".
        inv_id: str | None = None
        try:
            async for name, data in gen:
                if name == "investigation_created":
                    inv_id = data.get("investigation_id")
                    break
                # Any other event before investigation_created means something
                # unexpected; keep consuming to find it or give up.
        except Exception:
            _LOGGER.exception(
                "hunt_manager: failed to start investigation for alert_id=%s", alert_id
            )
            return None

        if inv_id is None:
            return None

        # Spawn a background task to drain the rest of the generator.
        task: asyncio.Task[None] = asyncio.create_task(
            _drain(gen, alert_id=alert_id, inv_id=inv_id)
        )
        self._tasks[inv_id] = task
        task.add_done_callback(lambda t: self._tasks.pop(inv_id, None))
        return inv_id


async def _drain(
    gen: Any,
    *,
    alert_id: str,
    inv_id: str,
) -> None:
    """Exhaust the remaining events in *gen*.

    The recorder inside run_recorded persists everything; _drain just
    exhausts the generator so the recorder can call finish().  Any
    exception is logged and swallowed so a failure never escapes the task.
    """
    try:
        async for _name, _data in gen:
            pass
    except Exception:
        _LOGGER.exception(
            "hunt_manager: background drain failed for inv_id=%s alert_id=%s",
            inv_id,
            alert_id,
        )


def get_manager(state: Any) -> HuntManager:
    """Lazily attach a :class:`HuntManager` to *app.state* and return it."""
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, HuntManager())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]
