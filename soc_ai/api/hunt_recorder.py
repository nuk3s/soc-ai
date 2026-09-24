"""Tees a hunt's agent stream into the hunts store.

Mirrors :mod:`soc_ai.api.recorder` (the investigation tee): events are buffered
and flushed per-event so the running hunt's timeline populates LIVE, and the
final :class:`~soc_ai.agent.hunt.HuntReport` lands on ``finish``.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai.hunting.findings import plain_error
from soc_ai.store import hunts as hunt_svc

_LOGGER = logging.getLogger(__name__)

# How much of a raw exception message the narrative keeps. Enough to name the
# index, the host or the field that broke. Short enough that a stack trace
# pasted into a message does not become the hunt's whole write-up.
_ERROR_MESSAGE_CHARS = 200


def error_narrative(message: str | None, exc_type: str | None) -> str:
    """One sentence that says why a hunt failed.

    A hunt that ended 'error' with an empty narrative was the second dogfood's
    most repeated complaint. The page said the hunt failed and no surface said
    what failed, so every one of them cost a server-log read.

    A known exception shape gets the plain sentence
    :func:`soc_ai.hunting.findings.plain_error` writes for the catalog path.
    Anything else names the exception and keeps the start of its message.
    """
    raw = (message or "").strip()
    plain = plain_error(raw)
    if plain and plain != raw:
        return plain
    name = (exc_type or "").strip() or "Error"
    if not raw:
        return f"The hunt failed: {name}."
    return f"The hunt failed: {name}. {raw[:_ERROR_MESSAGE_CHARS]}"


# Flush after every event so the running hunt's activity timeline populates LIVE
# (the detail view polls the persisted events). Hunts emit tens of events at low
# frequency, so per-event commits are cheap and the operator latency win is worth
# it — same rationale as the investigation recorder.
FLUSH_EVERY = 1


class HuntRecorder:
    """Buffers a hunt's StepEvents and lands them + the final HuntReport."""

    def __init__(
        self,
        maker: async_sessionmaker[AsyncSession],
        *,
        objective: str,
        started_by: str,
        kind: str = "chat",
        is_synth_eval: bool = False,
        starter: str = "analyst",
        lead_id: int | None = None,
    ) -> None:
        self._maker = maker
        self._objective = objective
        self._started_by = started_by
        self._kind = kind
        # The class that started the hunt, and the lead it came from. The
        # hunt row records both. started_by keeps the actor name.
        self._starter = starter
        self._lead_id = lead_id
        # Synthetic-evaluation marker: the run's context opted in to planted
        # synth scenarios, so the row must never read as real activity.
        # Derived from ctx.include_synth by hunt_recorded_run — no API caller
        # can supply it.
        self._is_synth_eval = is_synth_eval
        self._buffer: list[dict[str, Any]] = []
        self._report: dict[str, Any] | None = None
        # The last failure this run reported, from an ``error`` event or from
        # the caller's own exception handler. It becomes the narrative of a run
        # that finalizes 'error' with no report.
        self._error: dict[str, Any] | None = None
        self._finished = False
        self.hunt_id: str | None = None

    async def start(self) -> str | None:
        try:
            async with self._maker() as db:
                hunt = await hunt_svc.create(
                    db,
                    objective=self._objective,
                    started_by=self._started_by,
                    kind=self._kind,
                    is_synth_eval=self._is_synth_eval,
                    starter=self._starter,
                    lead_id=self._lead_id,
                )
        except Exception:
            _LOGGER.exception(
                "hunt recorder could not create row — persistence disabled for this run"
            )
            return None
        self.hunt_id = hunt.id
        return hunt.id

    async def record(self, kind: str, sequence: int, payload: dict[str, Any]) -> None:
        if self.hunt_id is None:
            return
        self._buffer.append({"kind": kind, "sequence": sequence, "payload": payload})
        if kind == "hunt_report":
            self._report = payload
        if kind == "error":
            self._error = payload
        if len(self._buffer) >= FLUSH_EVERY:
            await self._flush()

    def note_failure(self, exc: BaseException) -> None:
        """Record why the run is about to be finalized as an error.

        The stream raises before it can emit an ``error`` event when the
        failure is in the runner rather than in the agent. The caller's except
        block calls this so the narrative still says what happened.
        """
        self._error = {"message": str(exc), "type": type(exc).__name__}

    async def _flush(self) -> None:
        if not self._buffer or self.hunt_id is None:
            return
        batch, self._buffer = self._buffer, []
        try:
            async with self._maker() as db:
                await hunt_svc.append_events(db, self.hunt_id, batch)
        except Exception:
            _LOGGER.exception("hunt recorder flush failed")

    async def finish(self, status: str) -> None:
        if self._finished or self.hunt_id is None:
            return
        self._finished = True
        await self._flush()
        report = self._report or {}
        # A stream that finishes without a hunt_report is an error, even if the
        # caller asks for "complete".
        final_status = status
        if status == "complete" and not report:
            final_status = "error"
        narrative = report.get("narrative")
        if final_status == "error" and not narrative:
            # A hunt that says only "error" makes the analyst read the server
            # log. The failure sentence belongs on the row.
            if self._error is None:
                # No event and no exception: the client went away mid-run, or
                # the process stopped. Say that, rather than name a cause.
                narrative = "The hunt did not finish. The result is unknown."
            else:
                narrative = error_narrative(self._error.get("message"), self._error.get("type"))
        try:
            async with self._maker() as db:
                await hunt_svc.finalize(
                    db,
                    self.hunt_id,
                    status=final_status,
                    narrative=narrative,
                    report=report or None,
                )
        except Exception:
            _LOGGER.exception("hunt recorder finalize failed")
