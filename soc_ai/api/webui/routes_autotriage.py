"""Auto-triage (bulk) start/status/stop endpoints."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    router,
)
from soc_ai.webui import alerts_query as aq
from soc_ai.webui import autotriage as at

_LOGGER = logging.getLogger(__name__)

# ── Auto-triage (bulk) ─────────────────────────────────────────────────────


class AutoTriageStatusOut(BaseModel):
    active: bool
    total: int
    hunted: int
    skipped: int
    failed: int
    finished_at: str | None = None
    severities: list[str] = []
    note: str | None = None
    current: str | None = None
    tool_calls: int = 0
    # Inherited-verdict FP alerts this run acknowledged in SO (no LLM involved).
    inherited_acked: int = 0
    # Per-reason breakdown of ``skipped`` (reason code -> count); sums to skipped.
    skipped_reasons: dict[str, int] = {}


def _at_status(status: Any, note: str | None = None) -> AutoTriageStatusOut:
    return AutoTriageStatusOut(
        active=status.active,
        total=status.total,
        hunted=status.hunted,
        skipped=status.skipped,
        failed=status.failed,
        finished_at=status.finished_at,
        severities=list(status.severities),
        note=note,
        current=status.current,
        tool_calls=status.tool_calls,
        inherited_acked=getattr(status, "inherited_acked", 0),
        skipped_reasons=dict(getattr(status, "skipped_reasons", {}) or {}),
    )


_ALERT_IDS_CAP = 50
# plan_targets_for_ids() intentionally applies no max-targets cap to an explicit
# selection (the operator picked these on purpose) — so without an input-boundary
# cap here, an uncapped alert_ids list would hold the single-flight slot for one
# sequential LLM investigation (up to auto_triage_per_target_timeout_s each) per
# id, starving the scheduled sweep. Cap at the boundary, mirroring the
# investigations/hunts rehunt endpoints' ``_REHUNT_CAP``.


class AutoTriageIn(BaseModel):
    range: str = aq.DEFAULT_RANGE
    q: str | None = None
    severities: list[str] = []
    # Explicit operator selection (alert ES ids). When present, auto-triage
    # honours the selection — bypassing severity/range planning and the
    # max-targets cap — and only skips ids that already carry a verdict. Capped
    # at the input boundary so an oversized payload is rejected (422) before
    # the dedup/planning loop iterates it.
    alert_ids: list[str] = Field(default_factory=list, max_length=_ALERT_IDS_CAP)


@router.post("/auto-triage", response_model=AutoTriageStatusOut)
async def start_auto_triage(request: Request, body: AutoTriageIn) -> AutoTriageStatusOut:
    """Plan + launch a background auto-triage batch (single-flight). Poll
    GET /auto-triage for progress. With ``alert_ids`` it triages exactly that
    selection (already-verdicted ids skipped); otherwise it sweeps the
    critical+high detections in range."""
    state = request.app.state
    status = at.get_status(state)
    if status.active:
        return _at_status(status, note="already running")

    selected = [a for a in body.alert_ids if a]
    # Derive the config-default severity band: everything at or above the floor.
    _ladder = list(aq.SEVERITIES)  # ("critical", "high", "medium", "low")
    _settings = state.settings
    _floor = getattr(_settings, "auto_triage_min_severity", "high")
    _idx = _ladder.index(_floor) if _floor in _ladder else _ladder.index("high")
    _config_band: tuple[str, ...] = tuple(_ladder[: _idx + 1])
    chosen: tuple[str, ...] = _config_band
    status.active = True  # claim the slot before any await
    inherited_acks: list[at.InheritedAck] = []
    try:
        if selected:
            targets, skipped = await at.plan_targets_for_ids(state, alert_ids=selected)
        else:
            # Explicit severities from the caller take precedence over the config floor.
            chosen = tuple(s for s in body.severities if s in aq.SEVERITIES) or _config_band
            time_range = body.range if body.range in aq.TIME_RANGES else aq.DEFAULT_RANGE
            oql = (body.q or "").strip() or None
            targets, skipped, inherited_acks = await at.plan_targets(
                state, time_range=time_range, oql=oql, severities=chosen
            )
    except Exception:
        status.active = False
        # Log the real cause — `from None` + a bare 500 body left a planning
        # failure (bad OQL, ES down, coercion bug) completely undiagnosable.
        _LOGGER.exception("auto-triage planning failed")
        raise HTTPException(status_code=500, detail={"reason": "planning_failed"}) from None

    if not targets and not inherited_acks:
        status.reset(active=False, total=0, skipped=skipped, severities=chosen)
        status.finished_at = datetime.now(UTC).isoformat()
        if selected:
            empty_note = (
                f"all {skipped} selected already triaged" if skipped else "nothing to triage"
            )
        else:
            empty_note = "nothing to hunt"
        return _at_status(status, note=empty_note)

    # 0 targets + N inherited acks still runs the worker: the ack pass is how a
    # standing inherited-FP backlog drains (no LLM calls involved).
    status.reset(active=True, total=len(targets), skipped=skipped, severities=chosen)
    started_by = f"auto-triage:{await identify_caller(request)}"
    status._task = asyncio.create_task(
        at.run_auto_triage(
            state, targets=targets, started_by=started_by, inherited_acks=inherited_acks
        )
    )
    note: str | None = None
    if selected:
        note = f"triaging {len(targets)} selected"
        if skipped:
            note += f" ({skipped} already triaged)"
    return _at_status(status, note=note)


@router.get("/auto-triage", response_model=AutoTriageStatusOut)
async def auto_triage_status(request: Request) -> AutoTriageStatusOut:
    return _at_status(at.get_status(request.app.state))


@router.post("/auto-triage/stop", response_model=AutoTriageStatusOut)
async def stop_auto_triage(request: Request) -> AutoTriageStatusOut:
    """Request an in-flight auto-triage run to stop after its current target.

    The current investigation is allowed to finish cleanly; no further targets
    are started. Returns the (now winding-down) status; a no-op if idle.
    """
    state = request.app.state
    at.request_stop(state)
    return _at_status(at.get_status(state))
