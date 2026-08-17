"""Detection tuning: noisy-rule nominations + soft-mute overrides."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.deps import get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    require_admin_api,
    router,
)
from soc_ai.api.webui.routes_alerts import _es_api_error_http, _grid_unavailable
from soc_ai.config import Settings
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
    # Analyst-feedback signal (E4.3): how the analyst has corrected this rule —
    # verdict overrides TO false-positive + the chat/manual resolution split.
    override_fp: int = 0
    chat_resolved: int = 0
    manual_resolved: int = 0


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


async def _nominate(request: Request, settings: Settings) -> list[dict[str, Any]]:
    """Nominate noisy rules, answering a degraded grid instead of crashing on it.

    Nominating reads the grid, so it carries the alert routes' failure modes and
    owes their answers: a slow or unreachable Security Onion is a 503, an ES 4xx
    is a 400. Without that the Config panel and the Dashboard's nudge returned an
    unhandled 500 with an ASGI traceback whenever the grid was down — the moment a
    SOC console most needs to stay composed, and the state the public demo runs in.

    Both callers go through here for one reason: MR !70 fixed the summary route by
    hand and left the identical call in the list route bare, so the deep-link the
    nudge points AT still 500'd. A shared helper makes that divergence impossible
    rather than merely unlikely.

    ``ApiError`` gets its own arm because it is not an ``elastic_transport``
    ``TransportError`` — separate hierarchies, so the two-tuple alone still lets
    every ES 4xx through as a 500.

    The ``asyncio.timeout`` bounds the wait at the console's budget instead of the
    ES client's retry budget (~90 s at shipped defaults). A grid that accepts the
    connection and never answers raises nothing for the arms below to catch; it
    just hangs the panel until the SPA gives up first.

    ``_grid_unavailable(exc)`` rather than the flat constant because THIS panel is
    where the mismatch showed: the muted-rules header learned to print "(—)" for a
    count it never read, while the error card directly above it kept advising
    "retry shortly" — one screen giving an honest unknown and a remedy that cannot
    produce it. The hint now follows the failure class the header follows.
    """
    from soc_ai.webui import detection_tuning as dt  # noqa: PLC0415 - lazy

    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            return await dt.nominate(request.app.state)
    except (TimeoutError, TransportError) as exc:
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        raise _es_api_error_http(exc) from exc


@router.get(
    "/detection-tuning",
    response_model=DetectionTuningOut,
    dependencies=[Depends(require_admin_api)],
)
async def get_detection_tuning(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> DetectionTuningOut:
    """Nominated noisy rules + the active soft-mute overrides (detection tuning).

    Nominations join the live alert volume with each rule's completed-investigation
    verdict trend (see :mod:`soc_ai.webui.detection_tuning`); the overrides are the
    operator's active soft mutes. A mute hides a rule from the default alerts feed
    — it never touches Security Onion.
    """
    nominations = await _nominate(request, settings)
    async with request.app.state.db_sessionmaker() as db:
        overrides = await override_svc.list_active(db)
    return DetectionTuningOut(
        nominations=[DetectionNominationOut(**n) for n in nominations],
        overrides=[_override_out(o) for o in overrides],
    )


class DetectionTuningSummaryOut(BaseModel):
    # Actionable mute recommendations: recommendation == 'mute' and not already
    # muted. Feeds the Dashboard nudge so the suggestions stop living unseen in
    # Config while auto-investigate keeps paying for runs on the same rules.
    pending: int


@router.get(
    "/detection-tuning/summary",
    response_model=DetectionTuningSummaryOut,
    dependencies=[Depends(require_admin_api)],
)
async def get_detection_tuning_summary(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> DetectionTuningSummaryOut:
    """Count of pending (not-yet-applied) mute recommendations — the Dashboard nudge.

    Degraded-grid behaviour lives in :func:`_nominate`, shared with the list route.
    """
    nominations = await _nominate(request, settings)
    pending = sum(
        1 for n in nominations if n.get("recommendation") == "mute" and not n.get("already_muted")
    )
    return DetectionTuningSummaryOut(pending=pending)


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
