"""Detection tuning: noisy-rule nominations + soft-mute overrides."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    require_admin_api,
    router,
)
from soc_ai.store import detection_overrides as override_svc

_LOGGER = logging.getLogger(__name__)

# ── Detection tuning (noisy-rule nomination + soft mutes) ──────────────────────


class DetectionNominationOut(BaseModel):
    """One nominated noisy rule from the detection-tuning analysis."""

    rule_name: str
    alert_count: int
    investigations: int
    fp: int
    tp: int
    nmi: int
    recommendation: str  # 'mute' | 'monitor' | 'none'
    reason: str
    already_muted: bool


class DetectionOverrideOut(BaseModel):
    """One active operator override (a soft mute)."""

    id: int
    rule_name: str
    action: str  # 'mute'
    reason: str | None = None
    created_by: str
    created_at: str
    active: bool


class DetectionTuningOut(BaseModel):
    nominations: list[DetectionNominationOut]
    overrides: list[DetectionOverrideOut]


class DetectionOverrideIn(BaseModel):
    # Detection-rule / signature name. The value is whatever rule.name carries —
    # bounded length, no pattern restriction (rule names contain spaces/punct).
    rule_name: str = Field(min_length=1, max_length=512)
    action: str = "mute"
    reason: str | None = Field(default=None, max_length=512)


def _override_out(row: Any) -> DetectionOverrideOut:
    return DetectionOverrideOut(
        id=row.id,
        rule_name=row.rule_name,
        action=row.action,
        reason=row.reason,
        created_by=row.created_by,
        created_at=row.created_at.isoformat() if row.created_at else "",
        active=row.active,
    )


@router.get(
    "/detection-tuning",
    response_model=DetectionTuningOut,
    dependencies=[Depends(require_admin_api)],
)
async def get_detection_tuning(request: Request) -> DetectionTuningOut:
    """Nominated noisy rules + the active soft-mute overrides (detection tuning).

    Nominations join the live alert volume with each rule's completed-investigation
    verdict trend (see :mod:`soc_ai.webui.detection_tuning`); the overrides are the
    operator's active soft mutes. A mute hides a rule from the default alerts feed
    — it never touches Security Onion.
    """
    from soc_ai.webui import detection_tuning as dt  # noqa: PLC0415 - lazy

    nominations = await dt.nominate(request.app.state)
    async with request.app.state.db_sessionmaker() as db:
        overrides = await override_svc.list_active(db)
    return DetectionTuningOut(
        nominations=[DetectionNominationOut(**n) for n in nominations],
        overrides=[_override_out(o) for o in overrides],
    )


@router.post(
    "/detection-tuning/override",
    response_model=DetectionOverrideOut,
    dependencies=[Depends(require_admin_api)],
)
async def create_detection_override(
    request: Request, body: DetectionOverrideIn
) -> DetectionOverrideOut:
    """Mute a noisy rule — create a soft, reversible suppression. SO is untouched."""
    if body.action != "mute":
        raise HTTPException(
            status_code=400,
            detail={"reason": "invalid_action", "hint": "only 'mute' is supported"},
        )
    created_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        row = await override_svc.create(
            db,
            rule_name=body.rule_name,
            action=body.action,
            reason=body.reason,
            created_by=created_by,
        )
    return _override_out(row)


@router.post(
    "/detection-tuning/override/{override_id}/remove",
    dependencies=[Depends(require_admin_api)],
)
async def remove_detection_override(request: Request, override_id: int) -> dict[str, bool]:
    """Un-mute: deactivate an override (kept for audit). 404 if not active."""
    async with request.app.state.db_sessionmaker() as db:
        ok = await override_svc.deactivate(db, override_id)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found", "hint": "no active override with that id"},
        )
    return {"removed": True}
