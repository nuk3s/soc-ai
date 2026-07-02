"""Tees a hunt's agent stream into the hunts store.

Mirrors :mod:`soc_ai.api.recorder` (the investigation tee): events are buffered
and flushed per-event so the running hunt's timeline populates LIVE, and the
final :class:`~soc_ai.agent.hunt.HuntReport` lands on ``finish``.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai.store import hunts as hunt_svc

_LOGGER = logging.getLogger(__name__)

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
    ) -> None:
        self._maker = maker
        self._objective = objective
        self._started_by = started_by
        self._kind = kind
        self._buffer: list[dict[str, Any]] = []
        self._report: dict[str, Any] | None = None
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
        if len(self._buffer) >= FLUSH_EVERY:
            await self._flush()

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
        try:
            async with self._maker() as db:
                await hunt_svc.finalize(
                    db,
                    self.hunt_id,
                    status=final_status,
                    narrative=report.get("narrative"),
                    report=report or None,
                )
        except Exception:
            _LOGGER.exception("hunt recorder finalize failed")
