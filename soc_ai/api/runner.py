"""Shared recorded-investigation runner (SSE route + auto-triage worker).

The core primitive is ``recorded_run``: given an already-created async
iterator of StepEvents, it wraps them with the investigation recorder tee and
yields ``(event_name, data_dict)`` pairs ready for SSE encoding or draining.

``run_recorded`` is the higher-level convenience that calls ``investigate()``
itself.  Routes keep their own patchable ``investigate`` binding (needed by
existing tests); the auto-triage worker calls this module's ``investigate``
directly.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from soc_ai.agent.orchestrator import (
    InvestigationContext,
    StepEvent,
    investigate,
)
from soc_ai.api.recorder import InvestigationRecorder

_LOGGER = logging.getLogger(__name__)

# Fallback whole-run wall-clock backstop when the setting is absent (older config
# overlays / test doubles). Mirrors ``Settings.investigation_run_timeout_s``.
_DEFAULT_INVESTIGATION_RUN_TIMEOUT_S = 900


@dataclass
class CancelToken:
    """Marks an EXPLICIT operator cancel so a recorded run can tell it apart from
    an infrastructural cancellation.

    A bare ``asyncio.CancelledError`` reaches :func:`recorded_run` for several
    reasons that are NOT an operator cancel — the SSE client disconnects, or the
    app/container is shutting down (every deploy). Only when the operator hits
    Cancel does the hunt manager set ``requested = True`` before cancelling the
    task; everything else is an interrupted run (→ ``error``), never ``cancelled``.
    """

    requested: bool = False


async def recorded_run(
    state: Any,
    *,
    alert_id: str,
    started_by: str,
    event_stream: AsyncIterator[StepEvent],
    cancel_token: CancelToken | None = None,
    rule_name: str | None = None,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Wrap *event_stream* with the investigation recorder tee.

    Yields ``(event_name, data_dict)`` pairs.  The leading
    ``investigation_created`` event is always first.  The caller is
    responsible for building the event stream (so the route can keep its
    own patchable ``investigate`` binding without circular imports).
    """
    recorder = InvestigationRecorder(
        state.db_sessionmaker,
        alert_id=alert_id,
        started_by=started_by,
        rule_name=rule_name,
    )
    inv_id = await recorder.start()

    yield "investigation_created", {"investigation_id": inv_id}

    # Whole-run wall-clock backstop. The per-turn timeouts inside the orchestrator
    # bound each model turn, but a slow-but-progressing multi-turn run (or a wedged
    # stream that keeps resetting the per-turn clock) has no whole-run stop. This
    # wraps the event-stream consumption for EVERY caller — the interactive SSE
    # route consumes recorded_run directly, and the background hunt path reaches it
    # via run_recorded — so the backstop is applied in exactly one place instead of
    # per call site.
    run_timeout = getattr(
        getattr(state, "settings", None),
        "investigation_run_timeout_s",
        _DEFAULT_INVESTIGATION_RUN_TIMEOUT_S,
    )
    # Highest sequence seen, so a terminal error event appends after the run's
    # own events instead of colliding with sequence 0 in the timeline.
    last_seq = 0

    async def _record_terminal_error(payload: dict[str, Any]) -> None:
        """Persist a terminal-failure event so the row is never silently 'error'.

        ``recorder.record`` is otherwise only reached from inside the streaming
        loop, so a run that dies at a TIMEOUT, a CANCEL or an escaped exception
        finalized as ``status='error'`` with NO error event at all — nothing for
        the pipeline-error drilldown to show and no hint about the cause. In the
        14 days to 2026-08-03 that produced 49 of 64 error rows, every one of them
        undiagnosable; 41 landed on a single day when the model backend was down.

        Fail-soft: a persistence problem here must not mask the original failure,
        and this runs on the cancellation unwind where the DB write may itself be
        cancelled.
        """
        nonlocal last_seq
        try:
            last_seq += 1
            await recorder.record("error", last_seq, payload)
        except Exception:
            _LOGGER.exception("failed to record terminal error event")

    try:
        async with asyncio.timeout(run_timeout):
            async for ev in event_stream:
                last_seq = max(last_seq, ev.sequence)
                await recorder.record(ev.kind, ev.sequence, ev.payload)
                # Frame contract (kind, {session_id, sequence, payload}) is
                # mirrored by soc_ai/demo/replay.py — change both together
                # (pinned by tests/test_demo_mode.py's frame-contract test).
                yield (
                    ev.kind,
                    {
                        "session_id": ev.session_id,
                        "sequence": ev.sequence,
                        "payload": ev.payload,
                    },
                )
        await recorder.finish("complete")
        # E2.4 notification trigger — a completed investigation with a
        # high-confidence true-positive verdict pings on-call. THIN + fail-soft:
        # build a NotifyEvent from the recorder's captured report and fire it
        # (notify.fire is a hard no-op unless notifications are enabled + a webhook
        # is configured, so this is zero-egress by default). Wrapped so a webhook
        # can never break the finalized investigation.
        await _maybe_notify_investigation(state, recorder)
    except TimeoutError:
        # Whole-run backstop tripped: land the partial run as error and tell the
        # client, rather than propagating (mirrors the generic-crash handler below).
        # asyncio.timeout converts its own expiry to TimeoutError at the `async with`
        # boundary, so an EXTERNAL cancel (operator/ shutdown) still surfaces as
        # CancelledError to the handler below — only a real deadline lands here.
        _LOGGER.warning(
            "investigation exceeded %ss wall-clock backstop for inv_id=%s alert_id=%s",
            run_timeout,
            inv_id,
            alert_id,
        )
        timeout_payload = {
            "message": f"investigation exceeded {run_timeout}s wall-clock limit",
            "type": "TimeoutError",
            "phase": "whole_run_backstop",
            "hint": (
                "the run was still streaming when the whole-run wall clock "
                "expired — usually a hung or very slow model backend. Check the "
                "LLM gateway and its serving engine before raising "
                "investigation_run_timeout_s."
            ),
        }
        await _record_terminal_error(timeout_payload)
        await recorder.finish("error")
        yield ("error", timeout_payload)
    except asyncio.CancelledError:
        # Land a clean terminal state, then let the cancellation propagate so the
        # task actually stops. Only an EXPLICIT operator cancel is 'cancelled';
        # any other cancellation (SSE client disconnect, app/container shutdown)
        # is an interrupted run that never reached a verdict → 'error'. finish()
        # is idempotent, so the finally below is a no-op.
        # Shield the terminal write: Starlette/sse-starlette run this generator
        # inside an anyio cancel scope that RE-DELIVERS the cancellation on every
        # await until the scope exits, so a bare ``await recorder.finish(...)`` is
        # itself cancelled mid-commit and the row is orphaned in ``running`` until
        # the reaper. asyncio.shield runs the finalize where the cancellation can't
        # reach it (same fix as soc_ai/demo/replay.py's replay_recorded_run).
        operator_cancel = cancel_token is not None and cancel_token.requested
        if not operator_cancel:
            # NOT an operator cancel, so this lands as 'error' — record why, or the
            # row is another silent failure. This is the branch the auto-triage
            # per-target cap trips (it cancels the consumer, which closes this
            # generator), so it is exactly where the prod silent rows came from.
            # Shielded like the finalize below: the cancellation is re-delivered on
            # every await during the unwind.
            await asyncio.shield(
                _record_terminal_error(
                    {
                        "message": (
                            "investigation cancelled before reaching a verdict "
                            "(client disconnect, shutdown, or an outer wall-clock cap)"
                        ),
                        "type": "CancelledError",
                        "phase": "run_cancelled",
                        "hint": (
                            "if this was an auto-triage sweep, the per-target cap "
                            "fired; it is floored above investigation_run_timeout_s "
                            "so the whole-run backstop reports the real cause first."
                        ),
                    }
                )
            )
        await asyncio.shield(recorder.finish("cancelled" if operator_cancel else "error"))
        raise
    except Exception as exc:
        _LOGGER.exception("investigation stream crashed")
        await _record_terminal_error(
            {
                "message": str(exc),
                "type": type(exc).__name__,
                "phase": "stream_crashed",
            }
        )
        await recorder.finish("error")
        yield "error", {"message": str(exc), "type": type(exc).__name__}
    finally:
        # no-op if already finished; lands rows abandoned by client disconnect.
        # Shielded for the same reason as the cancel branch above: the finally runs
        # during the cancellation unwind, where a bare await would be cancelled
        # before the finalize commits.
        await asyncio.shield(recorder.finish("error"))


async def run_recorded(
    state: Any,
    *,
    ctx: InvestigationContext,
    alert_id: str,
    started_by: str,
    cancel_token: CancelToken | None = None,
    rule_name: str | None = None,
    focus_hint: str | None = None,
    deep: bool = False,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Call investigate() and tee it through the recorder.

    Used by the auto-triage worker.  The SSE route has its own ``stream()``
    that calls ``recorded_run`` directly so that unittest patches on
    ``soc_ai.api.routes.investigate`` continue to work.

    ``focus_hint`` (optional): prior open questions from a re-launched
    ``needs_more_info`` investigation ("request more info") — threaded into
    ``investigate()`` so the fresh run targets those gaps.

    ``deep`` (optional): force the full tool-driven loop for this run
    (the analyst's "deep re-run" of a heuristic verdict).
    """
    event_gen = investigate(
        alert_id,
        ctx=ctx,
        focus_hint=focus_hint,
        deep=deep,
    )

    async for name, data in recorded_run(
        state,
        alert_id=alert_id,
        started_by=started_by,
        event_stream=event_gen,
        cancel_token=cancel_token,
        rule_name=rule_name,
    ):
        yield name, data


async def _maybe_notify_investigation(state: Any, recorder: InvestigationRecorder) -> None:
    """Fire the E2.4 TP notification for a finalized investigation (fail-soft).

    Reads the recorder's captured triage report + investigation id, builds a
    NotifyEvent iff it's a high-confidence true-positive (per settings), and fires
    it. Every failure mode is swallowed — a notification must NEVER break the
    just-finalized investigation. Zero egress unless notifications are enabled +
    a webhook is configured (enforced inside ``notify.fire``).
    """
    try:
        from soc_ai import notify  # noqa: PLC0415 - local, keeps import graph light

        inv_id = recorder.investigation_id
        report = recorder._report  # the captured triage_report payload (or None)
        if inv_id is None or not report:
            return
        event = notify.event_for_investigation(
            investigation_id=inv_id,
            report=report,
            settings=state.settings,
        )
        if event is not None:
            await notify.fire_safe(event, state.settings, getattr(state, "audit", None))
    except Exception:  # a notification trigger must never break the primary flow
        _LOGGER.warning("investigation notify trigger failed (continuing)", exc_info=True)


def sse_encode(name: str, data: dict[str, Any]) -> dict[str, Any]:
    """Encode a (name, data) pair into the SSE dict format used by EventSourceResponse."""
    return {"event": name, "data": json.dumps(data, default=str)}
