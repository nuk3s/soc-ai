"""Tees /investigate SSE streams into the investigations store.

Lives at the route level so EVERY caller's runs are persisted (web UI,
userscript, automation). Events are buffered and flushed in batches to
keep per-event write amplification off the SQLite WAL.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai.store import investigations as inv_svc

_LOGGER = logging.getLogger(__name__)

# Flush after every event so the running investigation's activity timeline
# populates LIVE (the drawer polls the persisted events every 2s). Investigations
# emit only tens of events at low frequency, so per-event commits are cheap and
# the latency win for the operator is worth it. Was 10, which left short runs
# showing nothing until they finished.
FLUSH_EVERY = 1


def _first_rationale(report: dict[str, Any]) -> str | None:
    actions = report.get("recommended_actions") or []
    if actions and actions[0].get("rationale"):
        return str(actions[0]["rationale"])
    summary = str(report.get("summary") or "")
    if summary:
        return summary.split(". ", maxsplit=1)[0][:300]
    return None


def _dig(payload: dict[str, Any], *paths: str) -> Any:
    """Return the first dotted path that resolves in payload."""
    for path in paths:
        cur: Any = payload
        ok = True
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                ok = False
                break
            cur = cur[part]
        if ok and cur is not None:
            return cur
    return None


class InvestigationRecorder:
    """Buffers StepEvents and lands them + the final verdict in the store."""

    def __init__(
        self,
        maker: async_sessionmaker[AsyncSession],
        *,
        alert_id: str,
        started_by: str,
    ) -> None:
        self._maker = maker
        self._alert_id = alert_id
        self._started_by = started_by
        self._buffer: list[dict[str, Any]] = []
        self._report: dict[str, Any] | None = None
        self._rule_name: str | None = None
        self._src_ip: str | None = None
        self._dest_ip: str | None = None
        self._finished = False
        self.investigation_id: str | None = None

    async def start(self) -> str | None:
        try:
            async with self._maker() as db:
                inv = await inv_svc.create(
                    db, alert_es_id=self._alert_id, started_by=self._started_by
                )
        except Exception:
            _LOGGER.exception(
                "investigation recorder could not create row — persistence disabled for this run"
            )
            return None
        self.investigation_id = inv.id
        return inv.id

    async def record(self, kind: str, sequence: int, payload: dict[str, Any]) -> None:
        if self.investigation_id is None:
            return
        self._buffer.append({"kind": kind, "sequence": sequence, "payload": payload})
        if kind in ("alert_context", "enriched_alert_context"):
            if self._rule_name is None:
                # AlertContext.model_dump() shape: {"alert": {"rule_name": ...}, ...}
                # Also handle nested rule.name variants for forward-compat.
                rule = _dig(
                    payload,
                    "alert.rule_name",
                    "rule.name",
                    "alert.rule.name",
                    "alert_rule_name",
                )
                if rule:
                    self._rule_name = str(rule)
            if self._src_ip is None:
                self._src_ip = _dig(payload, "alert.source_ip")
                self._dest_ip = _dig(payload, "alert.destination_ip")
        if kind == "triage_report":
            self._report = payload
        if len(self._buffer) >= FLUSH_EVERY:
            await self._flush()

    async def _flush(self) -> None:
        if not self._buffer or self.investigation_id is None:
            return
        batch, self._buffer = self._buffer, []
        try:
            async with self._maker() as db:
                await inv_svc.append_events(db, self.investigation_id, batch)
                if self._rule_name or self._src_ip or self._dest_ip:
                    await inv_svc.set_alert_fields(
                        db,
                        self.investigation_id,
                        rule_name=self._rule_name,
                        src_ip=self._src_ip,
                        dest_ip=self._dest_ip,
                    )
        except Exception:
            _LOGGER.exception("investigation recorder flush failed")

    async def finish(self, status: str) -> None:
        if self._finished or self.investigation_id is None:
            return
        self._finished = True
        await self._flush()
        report = self._report or {}
        # A stream that finishes without a triage_report is always an error,
        # even if the route calls finish("complete").
        final_status = status
        if status == "complete" and not report:
            final_status = "error"
        try:
            async with self._maker() as db:
                await inv_svc.finalize(
                    db,
                    self.investigation_id,
                    status=final_status,
                    verdict=report.get("verdict"),
                    confidence=report.get("confidence"),
                    rationale=_first_rationale(report) if report else None,
                    summary=report.get("summary"),
                    report=report or None,
                )
        except Exception:
            _LOGGER.exception("investigation recorder finalize failed")
