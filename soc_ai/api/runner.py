"""Shared recorded-investigation runner (SSE route + auto-triage worker).

The core primitive is ``recorded_run``: given an already-created async
iterator of StepEvents, it wraps them with the investigation recorder tee and
yields ``(event_name, data_dict)`` pairs ready for SSE encoding or draining.

``run_recorded`` is the higher-level convenience that also builds the
investigator/synthesizer and calls ``investigate()``.  Routes keep their own
patchable bindings for ``investigate`` etc. (needed by existing tests); the
auto-triage worker calls this module's ``investigate`` directly.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import Any

from soc_ai.agent.orchestrator import (
    InvestigationContext,
    StepEvent,
    build_investigator,
    build_investigator_model,
    build_synthesizer,
    build_synthesizer_model,
    investigate,
)
from soc_ai.api.recorder import InvestigationRecorder

_LOGGER = logging.getLogger(__name__)


async def recorded_run(
    state: Any,
    *,
    alert_id: str,
    started_by: str,
    event_stream: AsyncIterator[StepEvent],
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Wrap *event_stream* with the investigation recorder tee.

    Yields ``(event_name, data_dict)`` pairs.  The leading
    ``investigation_created`` event is always first.  The caller is
    responsible for building the event stream (so the route can keep its
    own patchable bindings for ``investigate``, ``build_investigator_model``
    etc. without circular imports).
    """
    recorder = InvestigationRecorder(
        state.db_sessionmaker,
        alert_id=alert_id,
        started_by=started_by,
    )
    inv_id = await recorder.start()

    yield "investigation_created", {"investigation_id": inv_id}

    try:
        async for ev in event_stream:
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
    except Exception as exc:
        _LOGGER.exception("investigation stream crashed")
        await recorder.finish("error")
        yield "error", {"message": str(exc), "type": type(exc).__name__}
    finally:
        # no-op if already finished; lands rows abandoned by client disconnect
        await recorder.finish("error")


async def run_recorded(
    state: Any,
    *,
    ctx: InvestigationContext,
    alert_id: str,
    started_by: str,
    session_id: str | None = None,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Build investigator/synthesizer, call investigate(), and tee through the recorder.

    Used by the auto-triage worker.  The SSE route has its own ``stream()``
    that calls ``recorded_run`` directly so that unittest patches on
    ``soc_ai.api.routes.investigate`` continue to work.
    """
    investigator = build_investigator(build_investigator_model(ctx.settings), ctx)
    synthesizer = build_synthesizer(build_synthesizer_model(ctx.settings))

    event_gen = investigate(
        alert_id,
        ctx=ctx,
        investigator=investigator,
        synthesizer=synthesizer,
        session_id=session_id,
    )

    async for name, data in recorded_run(
        state,
        alert_id=alert_id,
        started_by=started_by,
        event_stream=event_gen,
    ):
        yield name, data


def sse_encode(name: str, data: dict[str, Any]) -> dict[str, Any]:
    """Encode a (name, data) pair into the SSE dict format used by EventSourceResponse."""
    return {"event": name, "data": json.dumps(data, default=str)}
