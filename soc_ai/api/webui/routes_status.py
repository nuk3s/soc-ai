"""Read-only state of the unattended jobs that had no route of their own.

The Status page lists every job that runs with no operator: continuous
Auto-Investigate, the dossier sweep, the discovery scan, the audit-chain check,
the nightly eval and the backup. Each of those reads an existing route, except
the scheduled audit-chain check. That loop (``soc_ai.main._audit_verify_loop``)
keeps its state in an in-memory slot on ``app.state``, and the only reader was
the bell, which shows a break and nothing else. "When did the check last run"
had no answer anywhere in the console.

This route reads that slot and the live settings. It runs no check, reads no
index and writes nothing, including the slot itself: it reads the slot with
``getattr`` so a page view cannot create it.

``last_outcome`` says what the last run found: "intact", "broken", or
"not_checked" when it could not read the audit index. A process that has not
run the check yet has none.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, Request
from pydantic import BaseModel, ConfigDict

from soc_ai.api.deps import get_settings_dep
from soc_ai.api.webui._shared import router
from soc_ai.config import Settings


class AuditVerifyScheduleOut(BaseModel):
    """The scheduled audit-chain check: its schedule, its last run, its alarm.

    Analyst-readable. The bell already shows a standing break, with its size,
    to any signed-in caller, and this projection adds only the schedule and the
    time of the last run. ``extra="forbid"`` so a refactor cannot widen it past
    those facts without a test noticing.
    """

    model_config = ConfigDict(extra="forbid")

    # The live settings: ``audit_verify_schedule_enabled``,
    # ``audit_verify_schedule_interval_hours`` and ``audit_verify_days``.
    enabled: bool
    interval_hours: int
    window_days: int
    # When the loop last ran the check, clean or not, ISO-8601. Null until the
    # first scheduled check of this process: the slot is in memory.
    last_run: str | None = None
    # True while the loop holds an alarm: the newest check that read the index
    # found a break. A clean check clears it. A check that could not read the
    # index leaves it as it was.
    broken: bool = False
    # When the current break was first seen, and the census sentence the bell
    # shows. Both null with no alarm.
    broken_since: str | None = None
    detail: str | None = None
    # What the last run found: "intact", "broken" or "not_checked". Null
    # before the first run of this process.
    last_outcome: str | None = None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


@router.get("/audit/verify-schedule", response_model=AuditVerifyScheduleOut)
async def audit_verify_schedule(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> AuditVerifyScheduleOut:
    """The scheduled audit-chain check, as the loop last left it."""
    slot = getattr(request.app.state, "_audit_verify_status", None)
    alarm = getattr(slot, "alarm", None)
    alarm = alarm if isinstance(alarm, dict) else None
    return AuditVerifyScheduleOut(
        enabled=bool(settings.audit_verify_schedule_enabled),
        interval_hours=int(settings.audit_verify_schedule_interval_hours),
        window_days=int(settings.audit_verify_days),
        last_run=_text(getattr(slot, "last_run", None)),
        last_outcome=_text(getattr(slot, "last_outcome", None)),
        broken=alarm is not None,
        broken_since=_text(alarm.get("alarm_since")) if alarm else None,
        detail=(_text(alarm.get("blast_radius")) or _text(alarm.get("break_detail")))
        if alarm
        else None,
    )
