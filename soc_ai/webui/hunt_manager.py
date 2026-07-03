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
from soc_ai.api.runner import CancelToken, run_recorded

# Fallback whole-investigation wall-clock backstop (seconds) when the setting is
# unavailable on state.settings. Mirrors config.investigation_run_timeout_s.
_DEFAULT_INVESTIGATION_RUN_TIMEOUT_S = 900

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_hunt_manager"


class HuntManager:
    """Tracks in-flight background hunt tasks to prevent GC collection."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[None]] = {}
        # Per-hunt cancel tokens — set requested=True on an EXPLICIT cancel so the
        # recorded run lands 'cancelled' (vs 'error' for a shutdown/disconnect).
        self._tokens: dict[str, CancelToken] = {}

    async def start(
        self,
        state: Any,
        *,
        alert_id: str,
        started_by: str,
        rule_name: str | None = None,
        focus_hint: str | None = None,
    ) -> str | None:
        """Create the investigation row and spawn a background drainer task.

        Consumes ``run_recorded`` until the first ``investigation_created``
        event to capture the investigation id, then hands the remaining
        generator to a background task that runs it to completion.

        ``rule_name`` seeds the row's display name at creation so it is never
        anonymous even if the run dies before the first alert_context event.

        ``focus_hint`` (optional): prior open questions from a re-launched
        ``needs_more_info`` investigation ("request more info") — threaded into
        the run so the fresh investigation targets those gaps.

        Returns the investigation id, or None if the generator ended or
        errored before emitting ``investigation_created``.
        """
        ctx = ctx_from_state(state)
        token = CancelToken()
        gen = run_recorded(
            state,
            ctx=ctx,
            alert_id=alert_id,
            started_by=started_by,
            cancel_token=token,
            rule_name=rule_name,
            focus_hint=focus_hint,
        )

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
            _drain(gen, state=state, alert_id=alert_id, inv_id=inv_id)
        )
        self._tasks[inv_id] = task
        self._tokens[inv_id] = token

        def _cleanup(_t: asyncio.Task[None]) -> None:
            self._tasks.pop(inv_id, None)
            self._tokens.pop(inv_id, None)

        task.add_done_callback(_cleanup)
        return inv_id

    def cancel(self, inv_id: str) -> bool:
        """Cancel an in-flight hunt's background task — an EXPLICIT operator cancel.

        Marks the cancel token requested FIRST so ``recorded_run`` records the
        run as ``cancelled`` (an unmarked cancellation — shutdown / client
        disconnect — lands as ``error`` instead). Returns True if a live task was
        found and cancelled; False if no live task is tracked (already finished,
        or never started here).
        """
        task = self._tasks.get(inv_id)
        if task is None or task.done():
            return False
        token = self._tokens.get(inv_id)
        if token is not None:
            token.requested = True
        task.cancel()
        return True


async def _drain(
    gen: Any,
    *,
    state: Any,
    alert_id: str,
    inv_id: str,
) -> None:
    """Exhaust the remaining events in *gen*.

    The recorder inside run_recorded persists everything; _drain just
    exhausts the generator so the recorder can call finish().  Any
    exception is logged and swallowed so a failure never escapes the task.

    The whole drain is bounded by an ``asyncio.timeout`` wall-clock backstop:
    a wedged LLM stream has no budget-based stopping point and would otherwise
    leave the background task (and the investigation row) ``running`` forever.
    On expiry the timeout cancels the awaited ``run_recorded`` step — which the
    recorder's ``except asyncio.CancelledError`` handler lands as
    ``status='error'`` (the interrupted-run path) since no operator cancel was
    requested — and ``asyncio.timeout`` re-raises the expiry as ``TimeoutError``
    here, which we log and swallow like any other drain failure.
    """
    run_timeout = getattr(
        state.settings, "investigation_run_timeout_s", _DEFAULT_INVESTIGATION_RUN_TIMEOUT_S
    )
    try:
        # Hold the generator so it can be closed if the wall-clock backstop fires
        # mid-stream — a hung LLM read would otherwise leak the coroutine (mirrors
        # the auto-triage worker's stream handling).
        try:
            async with asyncio.timeout(run_timeout):
                async for _name, _data in gen:
                    pass
        finally:
            await gen.aclose()
    except TimeoutError:
        _LOGGER.warning(
            "hunt_manager: investigation exceeded %ss wall-clock backstop for "
            "inv_id=%s alert_id=%s — recorder lands status=error",
            run_timeout,
            inv_id,
            alert_id,
        )
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
