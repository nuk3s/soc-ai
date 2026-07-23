"""Replay a recorded event stream through the live recorder path.

The UI renders replays with ZERO changes: events land via the same
:class:`~soc_ai.api.recorder.InvestigationRecorder` that live runs use, so the
``/investigate`` SSE stream and every polled GET endpoint see an ordinary run.
Pacing keeps the playback feeling live — the whole run is spread across
:data:`TOTAL_REPLAY_S` with at most :data:`MAX_STEP_S` between steps, so a
2-event recording stays snappy and a 200-event one still lands inside the cap.

Both demo-allowlisted POSTs converge here (note: ``POST /api/v1/hunt`` is the
alert-row "hunt" — a background *investigation* returning ``investigation_id``,
NOT a Hunt-Console row):

- ``POST /investigate`` wraps :func:`replay_recorded_run` in its existing SSE
  encoder (the demo twin of ``soc_ai.api.runner.recorded_run``).
- ``POST /api/v1/hunt`` runs the same generator to completion in a background
  task via :func:`start_background_replay` (the demo twin of
  ``HuntManager.start``).

A missing recording replays the live pipeline's unknown-alert stream —
``session_start`` then a prefetch-phase ``error`` event with the same payload
keys as ``soc_ai.agent.orchestrator._error_payload``. Unlike a live run, NO
row is created for it: an unrecorded alert_id has nothing to persist, and
creating one anyway would let an unauthenticated demo visitor flood the DB
by looping bogus alert_ids (F37).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncGenerator
from typing import Any

from soc_ai.api.recorder import InvestigationRecorder

_LOGGER = logging.getLogger(__name__)

TOTAL_REPLAY_S = 45.0  # spec: paced, capped around a minute
MAX_STEP_S = 1.2


def find_replay(data: dict[str, Any] | None, alert_es_id: str) -> dict[str, Any] | None:
    """The ``replays[]`` entry recorded for *alert_es_id* (``None`` = no recording).

    *data* is the cached fixture document (``app.state.demo_fixtures``) — ``None``
    when the fixture file was missing/invalid at startup (fail-soft boot).
    """
    if not data:
        return None
    return next(
        (r for r in data.get("replays") or [] if r.get("alert_es_id") == alert_es_id),
        None,
    )


def step_delay(n_events: int) -> float:
    """Per-step pause: spread the run across :data:`TOTAL_REPLAY_S`, capped per step."""
    return min(MAX_STEP_S, TOTAL_REPLAY_S / max(n_events, 1))


def _unknown_alert_replay(alert_es_id: str) -> dict[str, Any]:
    """The events for a synthetic replay mirroring the live pipeline's
    unknown-alert stream — the caller (:func:`replay_recorded_run`) streams
    ``events`` directly and skips the recorder, so no row is created.

    Live, an unknown alert 200s the SSE stream and fails in prefetch:
    ``session_start`` then ``error`` (``_error_payload`` keys — phase/round/
    type/message/hint). The demo mirrors that same error shape without the
    row a live run would land, since the alert was never recorded.
    """
    return {
        "alert_es_id": alert_es_id,
        "investigation": {},
        "events": [
            {"kind": "session_start", "sequence": 1, "payload": {"alert_id": alert_es_id}},
            {
                "kind": "error",
                "sequence": 2,
                "payload": {
                    "phase": "prefetch",
                    "round": 0,
                    "type": "ReplayNotFound",
                    "message": f"no recorded demo replay for alert {alert_es_id}",
                    "hint": (
                        "the public demo replays its recorded alerts only — "
                        "pick an alert from the demo's alerts list"
                    ),
                },
            },
        ],
    }


async def replay_recorded_run(
    state: Any,
    *,
    alert_id: str,
    started_by: str,
    replay: dict[str, Any] | None,
) -> AsyncGenerator[tuple[str, dict[str, Any]], None]:
    """Feed a recorded event stream through a live :class:`InvestigationRecorder`.

    Yields ``(event_name, data_dict)`` pairs with EXACTLY ``recorded_run``'s
    contract: a leading ``investigation_created`` carrying the new row's id,
    then each recorded event as ``{session_id, sequence, payload}``. Because
    the recorder is the same tee live runs use, the GET endpoints render the
    replay identically to a real run. Each replay creates a NEW row (live
    parity: re-clicking re-runs the recording).

    *replay* ``None`` (no recording for *alert_id*) is the ONE case that never
    touches the recorder: there is nothing to persist for an alert the demo
    never recorded, and ``/investigate`` is an unauthenticated, allow-listed
    write on a public demo — starting a row per bogus alert_id would let a
    visitor flood the DB just by looping garbage ids (F37). The unknown-alert
    error stream is emitted directly, with no leading ``investigation_created``.
    """
    if replay is None:
        session_id = uuid.uuid4().hex[:12]
        for ev in _unknown_alert_replay(alert_id)["events"]:
            kind = str(ev.get("kind", ""))
            sequence = int(ev.get("sequence", 0))
            payload = ev.get("payload") or {}
            yield kind, {"session_id": session_id, "sequence": sequence, "payload": payload}
        return
    inv_meta = replay.get("investigation") or {}
    recorder = InvestigationRecorder(
        state.db_sessionmaker,
        alert_id=alert_id,
        started_by=started_by,
        rule_name=inv_meta.get("rule_name"),
    )
    inv_id = await recorder.start()
    yield "investigation_created", {"investigation_id": inv_id}

    session_id = uuid.uuid4().hex[:12]
    events = replay.get("events") or []
    delay = step_delay(len(events))
    try:
        for i, ev in enumerate(events):
            if i:  # pace BETWEEN steps — no dead air after the terminal event
                await asyncio.sleep(delay)
            kind = str(ev.get("kind", ""))
            sequence = int(ev.get("sequence", 0))
            payload = ev.get("payload") or {}
            await recorder.record(kind, sequence, payload)
            yield kind, {"session_id": session_id, "sequence": sequence, "payload": payload}
        await recorder.finish("complete")
    except asyncio.CancelledError:
        # Client disconnect / shutdown cancels the task consuming this stream — the
        # common case on a PUBLIC demo (visitors navigate away mid-replay). Land a
        # terminal state, then propagate (same discipline as recorded_run; finish()
        # is idempotent).
        #
        # The write MUST be shielded. Under anyio's cancel-scope semantics
        # (Starlette/FastAPI re-deliver the cancellation on every await until the
        # scope exits), a bare `await recorder.finish("error")` here is itself
        # cancelled mid-commit — the SQLAlchemy async pool tears the connection down
        # ("no active connection") and the row is orphaned in 'running' until the
        # 30-min reaper. asyncio.shield runs the finalize in a task the cancellation
        # can't reach, so the terminal write commits before the unwind completes.
        await asyncio.shield(recorder.finish("error"))
        raise
    except Exception as exc:
        _LOGGER.exception("demo replay stream crashed")
        await recorder.finish("error")
        yield "error", {"message": str(exc), "type": type(exc).__name__}
    finally:
        # no-op if already finished; lands rows abandoned mid-stream as 'error'.
        # Shielded for the same reason as the cancel path above: the finally runs
        # during the cancellation unwind, where a bare await would be cancelled
        # before the finalize commits.
        await asyncio.shield(recorder.finish("error"))


async def start_background_replay(
    state: Any, *, replay: dict[str, Any], started_by: str
) -> str | None:
    """Run a replay to completion in a background task; return the new row id.

    Mirrors ``HuntManager.start``'s shape for ``POST /api/v1/hunt``: consume
    the generator until the leading ``investigation_created`` event (so the
    route can return the id immediately), then hand the rest to an
    ``asyncio.Task`` that drains it regardless of client state. Task refs ride
    on ``state.demo_replay_tasks`` so they can't be garbage-collected mid-run.
    Returns ``None`` if the row could not be created (route answers 503).
    """
    gen = replay_recorded_run(
        state,
        alert_id=str(replay.get("alert_es_id", "")),
        started_by=started_by,
        replay=replay,
    )
    inv_id: str | None = None
    try:
        async for name, data in gen:
            if name == "investigation_created":
                inv_id = data.get("investigation_id")
                break
    except Exception:
        _LOGGER.exception("demo replay failed to start for alert_id=%s", replay.get("alert_es_id"))
        return None

    if inv_id is None:
        await gen.aclose()
        return None

    task: asyncio.Task[None] = asyncio.create_task(_drain(gen))
    if not hasattr(state, "demo_replay_tasks"):
        state.demo_replay_tasks = set()
    tasks: set[asyncio.Task[None]] = state.demo_replay_tasks
    tasks.add(task)
    task.add_done_callback(tasks.discard)
    return inv_id


async def _drain(gen: AsyncGenerator[tuple[str, dict[str, Any]], None]) -> None:
    """Exhaust the remaining replay events (the recorder inside persists them)."""
    try:
        try:
            async for _name, _data in gen:
                pass
        finally:
            await gen.aclose()
    except Exception:
        _LOGGER.exception("demo replay background drain failed")
