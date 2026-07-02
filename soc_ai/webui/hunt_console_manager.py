"""HuntConsoleManager — chat-driven hunts as decoupled background tasks.

POST /api/v1/hunts/chat creates the hunt row via ``hunt_recorded_run``'s first
``hunt_created`` event, then drains the REST of the stream in a background
asyncio.Task that runs to completion regardless of client state — so a hunt
survives an SSE-client disconnect and lands its report.

Mirrors :mod:`soc_ai.webui.hunt_manager` (the interactive-investigation drainer)
but for free-form Hunt Console objectives.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from soc_ai.api.deps import ctx_from_state
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.api.runner import CancelToken

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_hunt_console_manager"


class HuntConsoleManager:
    """Tracks in-flight background hunt tasks to prevent GC collection."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._tokens: dict[str, CancelToken] = {}

    async def start(
        self,
        state: Any,
        *,
        objective: str,
        started_by: str,
        prior: str | None = None,
    ) -> str | None:
        """Create the hunt row and spawn a background drainer task.

        Consumes ``hunt_recorded_run`` until the first ``hunt_created`` event to
        capture the hunt id, then hands the remaining generator to a background
        task that runs it to completion. Returns the hunt id, or None if the
        generator ended/errored before emitting ``hunt_created``.
        """
        ctx = ctx_from_state(state)
        token = CancelToken()
        gen = hunt_recorded_run(
            state,
            ctx=ctx,
            objective=objective,
            started_by=started_by,
            prior=prior,
            cancel_token=token,
        )

        hunt_id: str | None = None
        try:
            async for name, data in gen:
                if name == "hunt_created":
                    hunt_id = data.get("hunt_id")
                    break
        except Exception:
            _LOGGER.exception("hunt_console_manager: failed to start hunt")
            return None

        if hunt_id is None:
            return None

        task: asyncio.Task[None] = asyncio.create_task(_drain(gen, hunt_id=hunt_id))
        self._tasks[hunt_id] = task
        self._tokens[hunt_id] = token

        def _cleanup(_t: asyncio.Task[None]) -> None:
            self._tasks.pop(hunt_id, None)
            self._tokens.pop(hunt_id, None)

        task.add_done_callback(_cleanup)
        return hunt_id

    def cancel(self, hunt_id: str) -> bool:
        """Cancel an in-flight hunt — an EXPLICIT operator cancel.

        Marks the cancel token requested FIRST so ``hunt_recorded_run`` records
        the run as ``cancelled`` (an unmarked cancellation lands as ``error``).
        Returns True if a live task was found and cancelled.
        """
        task = self._tasks.get(hunt_id)
        if task is None or task.done():
            return False
        token = self._tokens.get(hunt_id)
        if token is not None:
            token.requested = True
        task.cancel()
        return True


async def _drain(gen: Any, *, hunt_id: str) -> None:
    """Exhaust the remaining events in *gen* (the recorder persists everything)."""
    try:
        async for _name, _data in gen:
            pass
    except Exception:
        _LOGGER.exception("hunt_console_manager: background drain failed for hunt_id=%s", hunt_id)


def get_manager(state: Any) -> HuntConsoleManager:
    """Lazily attach a :class:`HuntConsoleManager` to *app.state* and return it."""
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, HuntConsoleManager())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]
