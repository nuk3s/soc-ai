"""Recorded hunt runner (SSE route + background drainer).

Mirrors :mod:`soc_ai.api.runner`. ``run_hunt`` streams the chat-driven hunt
agent NODE-BY-NODE (via ``agent.iter()`` + the orchestrator's ``_walk_message``
projector, exactly like the investigation loop) so each tool_call / tool_result
/ model_response lands the moment it happens; it emits a leading ``hunt_started``
event and a trailing ``hunt_report`` event carrying the final
:class:`~soc_ai.agent.hunt.HuntReport`.

``hunt_recorded_run`` wraps that stream with :class:`HuntRecorder` so every run
is persisted (leading ``hunt_created`` event carries the new row's id), whether
consumed by the SSE route or drained in the background.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator
from typing import Any

from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import UsageLimits

from soc_ai.agent.hunt import (
    HUNT_SYSTEM_PROMPT,
    build_hunt_agent,
    build_hunt_prompt,
    build_hunt_synthesizer,
)
from soc_ai.agent.models import build_investigator_model
from soc_ai.agent.orchestrator import InvestigationContext, StepEvent, _walk_message
from soc_ai.api.hunt_recorder import HuntRecorder
from soc_ai.api.runner import CancelToken

_LOGGER = logging.getLogger(__name__)


async def _synthesize_partial_hunt(
    ctx: InvestigationContext, *, objective: str, gathered: list[Any]
) -> Any:
    """Force a :class:`HuntReport` from an already-gathered transcript (no tools).

    Called when a hunt exhausts its budget before emitting a report: replays the
    accumulated message history through the no-tools hunt synthesizer so the
    analyst still gets a grounded partial report instead of a bare error.
    """
    synth = build_hunt_synthesizer(build_investigator_model(ctx.settings), objective=objective)
    return await synth.run(
        "Write the HuntReport now from the evidence already gathered above.",
        message_history=gathered,
        usage_limits=UsageLimits(request_limit=3, tool_calls_limit=0),
    )


async def run_hunt(
    ctx: InvestigationContext,
    *,
    objective: str,
    prior: str | None = None,
    session_id: str | None = None,
) -> AsyncIterator[StepEvent]:
    """Stream a chat-driven hunt as StepEvents.

    Builds the hunt agent (reusing the investigator's read tools) with the
    hunt-oriented system prompt, runs it node-by-node, and yields:

    - ``hunt_started`` — the objective, first;
    - ``tool_call`` / ``tool_result`` / ``model_response`` — the live trace;
    - ``hunt_report`` — the final HuntReport (or an ``error`` event on failure);
    - ``done`` — a small terminal marker with the finding count.
    """
    sid = session_id or uuid.uuid4().hex[:12]
    sequence = 0

    def _ev(kind: str, payload: dict[str, Any]) -> StepEvent:
        nonlocal sequence
        sequence += 1
        return StepEvent(kind=kind, session_id=sid, sequence=sequence, payload=payload)

    yield _ev("hunt_started", {"objective": objective})

    system_prompt = HUNT_SYSTEM_PROMPT.format(objective=objective)
    agent = build_hunt_agent(
        build_investigator_model(ctx.settings), ctx, system_prompt=system_prompt
    )
    # Hunts get a bigger budget than a single-alert investigation — they explore
    # broadly (many hosts/queries) before synthesizing, and the investigation-sized
    # request_limit ran out mid-hunt, erroring before the findings report.
    usage_limits = UsageLimits(
        request_limit=ctx.settings.hunt_request_limit,
        tool_calls_limit=ctx.settings.hunt_tool_calls_limit,
    )

    user_msg = build_hunt_prompt(objective, prior=prior)
    result: Any = None
    # Accumulate the streamed node messages so that, if the hunt exhausts its budget
    # before emitting a report, we can synthesize a partial report from what it
    # actually gathered instead of erroring with nothing.
    gathered: list[Any] = []
    budget_exhausted = False
    try:
        node_msg: Any = None
        async with agent.iter(user_msg, usage_limits=usage_limits) as run:
            async for node in run:
                node_msg = getattr(node, "model_response", None)
                if node_msg is None:
                    node_msg = getattr(node, "request", None)
                if node_msg is not None:
                    gathered.append(node_msg)
                    async for ev in _walk_message(node_msg, _ev, phase="hunt", round_num=1):
                        yield ev
        result = run.result
    except asyncio.CancelledError:
        raise  # cooperative cancel — propagate, never swallow
    except UsageLimitExceeded as e:
        # Budget exhaustion is an EXPECTED outcome of a broad hunt on a slow model,
        # not an infra failure. The queries + results already streamed live — don't
        # discard them with status=error and no report. Fall through to synthesize a
        # PARTIAL report from what was gathered.
        _LOGGER.warning("hunt hit budget limit; synthesizing partial report: %s", e)
        budget_exhausted = True
    except BaseException as e:
        _LOGGER.exception("hunt agent run failed")
        yield _ev("error", {"message": str(e), "type": type(e).__name__})
        return

    if result is None and budget_exhausted and gathered:
        # Replay the accumulated transcript through a no-tools synthesizer to land a
        # grounded partial HuntReport rather than an empty error.
        yield _ev(
            "model_response",
            {
                "text": (
                    "Reached the hunt's exploration budget — synthesizing a partial "
                    "report from the evidence gathered so far."
                )
            },
        )
        try:
            result = await _synthesize_partial_hunt(ctx, objective=objective, gathered=gathered)
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            _LOGGER.exception("hunt partial synthesis failed")
            yield _ev(
                "error",
                {
                    "message": f"hunt hit its budget and partial synthesis failed: {e}",
                    "type": type(e).__name__,
                },
            )
            return

    if result is None:
        yield _ev("error", {"message": "hunt produced no report", "type": "EmptyResult"})
        return

    report = result.output
    report_payload = report.model_dump(mode="json")
    yield _ev("hunt_report", report_payload)
    yield _ev("done", {"finding_count": len(report.findings)})


async def hunt_recorded_run(
    state: Any,
    *,
    ctx: InvestigationContext,
    objective: str,
    started_by: str,
    prior: str | None = None,
    kind: str = "chat",
    cancel_token: CancelToken | None = None,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Wrap :func:`run_hunt` with the hunt recorder tee.

    Yields ``(event_name, data_dict)`` pairs. The leading ``hunt_created`` event
    (carrying the new row id) is always first. Mirrors
    :func:`soc_ai.api.runner.recorded_run`.
    """
    recorder = HuntRecorder(
        state.db_sessionmaker,
        objective=objective,
        started_by=started_by,
        kind=kind,
    )
    hunt_id = await recorder.start()

    yield "hunt_created", {"hunt_id": hunt_id}

    try:
        async for ev in run_hunt(ctx, objective=objective, prior=prior):
            await recorder.record(ev.kind, ev.sequence, ev.payload)
            yield (
                ev.kind,
                {
                    "session_id": ev.session_id,
                    "sequence": ev.sequence,
                    "payload": ev.payload,
                },
            )
        await recorder.finish("complete")
    except asyncio.CancelledError:
        # Only an EXPLICIT operator cancel is 'cancelled'; any other cancellation
        # (SSE client disconnect, app/container shutdown) is an interrupted run
        # that never reached a report → 'error'. finish() is idempotent.
        await recorder.finish(
            "cancelled" if (cancel_token is not None and cancel_token.requested) else "error"
        )
        raise
    except Exception as exc:
        _LOGGER.exception("hunt stream crashed")
        await recorder.finish("error")
        yield "error", {"message": str(exc), "type": type(exc).__name__}
    finally:
        # no-op if already finished; lands rows abandoned by client disconnect
        await recorder.finish("error")


def sse_encode(name: str, data: dict[str, Any]) -> dict[str, Any]:
    """Encode a (name, data) pair into the SSE dict format used by EventSourceResponse."""
    return {"event": name, "data": json.dumps(data, default=str)}
