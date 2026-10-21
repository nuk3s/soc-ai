"""Grid-gap writes: an operator gap, and the review of the hits a gap wrote.

``GET /grid/gaps`` lives in :mod:`soc_ai.api.webui.routes_meta` with the other
page-wide reads. This module holds the three routes an operator uses after an
outage (dogfood 2026-10-19, R1-I5, R3-I1, R3-I2, R4-I3):

* ``POST /grid/gaps`` records a gap soc-ai did not see. Admin only, and
  audited, because every reader then treats the hours as unknown.
* ``GET /grid/gaps/{id}/hits`` lists the hits the gap wrote and the holds
  they caused. It reads the store only.
* ``POST /grid/gaps/{id}/hits/benign`` marks the hits the operator selected
  benign in one write. Each mark goes through the per-hit path. It detaches
  nothing, and it moves no analytic: Return to live stays the operator's click
  on the approve route.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Request, Response
from pydantic import BaseModel, Field

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import require_admin_api, router
from soc_ai.api.webui.kind_labels import kind_label
from soc_ai.api.webui.routes_analytics import GridGapHoldOut, gap_hold_out
from soc_ai.api.webui.routes_meta import GridGapOut, _gap_moment, _gap_out, _z
from soc_ai.hunting import gap_recovery
from soc_ai.hunting.catalog_tiers import effective_catalog
from soc_ai.hunting.wording import reword_legacy_summary
from soc_ai.store import grid_gaps as gaps_svc

_LOGGER = logging.getLogger(__name__)

# The audit session the grid-gap writes share.
_AUDIT_SESSION = "grid-gaps"

# The most hits one review lists. The count stays exact past it.
_MAX_LISTED = 500


class GridGapIn(BaseModel):
    """A gap an operator records. The edges take ISO-8601. A naive time is UTC."""

    started_at: str = Field(min_length=1, max_length=64)
    ended_at: str = Field(min_length=1, max_length=64)
    detail: str | None = Field(default=None, max_length=2000)


class GridGapHitOut(BaseModel):
    """One hit a gap wrote, with the event window the rule read."""

    id: int
    analytic_id: str
    analytic_title: str
    entity_kind: str
    entity_key: str
    kind: str
    kind_label: str
    summary: str | None = None
    recorded_in_shadow: bool = False
    lead_id: int | None = None
    event_start: str
    event_end: str
    born_at: str | None = None
    # The event window lies inside the gap plus the settle margin.
    inside_gap: bool = True
    # The review selects the hit for the mark. A spike and a hit that only
    # overlaps the gap stay unselected, and ``reasons`` says why.
    selected_by_default: bool = True
    reasons: list[str] = Field(default_factory=list)


class GridGapHitsOut(BaseModel):
    """The review of one gap: the hits it wrote and the holds they caused."""

    gap: GridGapOut
    # The hours the review reads: the gap, plus the settle margin after it.
    review_start: str
    review_end: str
    settle_minutes: int
    # The note each mark carries.
    note: str
    # The hits nobody marked benign yet. ``hits`` stops at 500 rows.
    count: int
    hits: list[GridGapHitOut]
    # The hits of ``count`` that the review selects by default.
    selected_count: int = 0
    # The leads that hold one of the hits. A mark detaches no hit from its lead.
    leads: list[int]
    # The holds of the daily hit limit that hits of this gap are part of.
    held: list[GridGapHoldOut]


class GridGapBenignIn(BaseModel):
    """The hits the operator selected, and the count the confirm step showed.

    ``ids`` is required. A body without it marked every listed hit before
    (dogfood round 2, G-1), and the list holds hits the gap does not explain.
    """

    ids: list[int] | None = Field(default=None, max_length=_MAX_LISTED)
    expected: int | None = Field(default=None, ge=0)


class GridGapBenignOut(BaseModel):
    marked: int
    ids: list[int]
    leads: list[int]
    note: str
    held: list[GridGapHoldOut]


def _not_found(gap_id: int) -> Any:
    return api_error(
        404,
        "gap_not_found",
        f"No grid gap has the id {gap_id}. GET /api/v1/grid/gaps lists the gaps.",
    )


async def _audit(request: Request, kind: str, payload: dict[str, Any]) -> None:
    """One audit record. Best-effort: the write is already committed."""
    try:
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(_AUDIT_SESSION, kind, payload, user=await identify_caller(request))
    except Exception:
        _LOGGER.warning("%s audit write failed (continuing)", kind, exc_info=True)


@router.post(
    "/grid/gaps",
    status_code=201,
    response_model=GridGapOut,
    dependencies=[Depends(require_admin_api)],
)
async def record_grid_gap(request: Request, body: GridGapIn, response: Response) -> GridGapOut:
    """Record a grid gap that soc-ai did not see. Admin only.

    soc-ai can be down itself during an outage, and an outage can predate the
    ledger. The route refuses an end at or before the start, a span over 30
    days, a start in the future and an end in the future. A gap with the same
    edges as an operator gap on record answers 200 with that gap.
    """
    now = datetime.now(UTC)
    start = _gap_moment(body.started_at, name="started_at")
    end = _gap_moment(body.ended_at, name="ended_at")
    if start is None or end is None:
        raise api_error(400, "bad_time", "Give started_at and ended_at as ISO 8601 timestamps.")
    settle = gaps_svc.settle_of(request.app.state.settings)
    async with request.app.state.db_sessionmaker() as db:
        try:
            row, created = await gaps_svc.record_operator_gap(
                db, started_at=start, ended_at=end, detail=body.detail, now=now
            )
        except gaps_svc.GapRefused as exc:
            raise api_error(422, exc.code, str(exc)) from exc
        # The same count the ledger route states, so the console can offer
        # the review at once.
        to_review = len(await gap_recovery.hits_in_gap(db, row, settle=settle, now=now))
    if not created:
        response.status_code = 200
    out = _gap_out(row, now=now, hits_to_review=to_review)
    await _audit(
        request,
        "grid_gap_recorded",
        {
            "gap_id": out.id,
            "started_at": out.started_at,
            "ended_at": out.ended_at,
            "detail": out.detail,
            "created": created,
        },
    )
    return out


@router.get("/grid/gaps/{gap_id}/hits", response_model=GridGapHitsOut)
async def review_grid_gap_hits(request: Request, gap_id: int) -> GridGapHitsOut:
    """The hits one gap wrote, and the holds of the daily hit limit they caused.

    A hit of the gap comes from an analytic, measures a count or a silence,
    and has an event window that overlaps the gap plus the settle margin.
    The review selects a hit whose event window lies inside that window and
    that is not a spike. The rule is in :mod:`soc_ai.hunting.gap_recovery`. A hit
    somebody marked benign already is not listed.
    """
    now = datetime.now(UTC)
    settle = gaps_svc.settle_of(request.app.state.settings)
    async with request.app.state.db_sessionmaker() as db:
        gap = await gaps_svc.get(db, gap_id)
        if gap is None:
            raise _not_found(gap_id)
        hits = await gap_recovery.hits_in_gap(db, gap, settle=settle, now=now)
        holds = await gap_recovery.gap_holds(db, settle=settle, now=now, gap=gap)
        catalog = await effective_catalog(db)
        to_review = len(hits) if gap.ended_at is not None else 0
        window = gap_recovery.review_window(gap, settle=settle, now=now)
        listed = [
            GridGapHitOut(
                id=int(hit.row.id),
                analytic_id=str(hit.row.spec_id),
                analytic_title=(
                    catalog.listed[hit.row.spec_id].title
                    if hit.row.spec_id in catalog.listed
                    else str(hit.row.spec_id)
                ),
                entity_kind=str(hit.row.entity_kind),
                entity_key=str(hit.row.entity_key),
                kind=str(hit.row.kind),
                kind_label=kind_label(hit.row.kind),
                summary=reword_legacy_summary(hit.row.summary),
                recorded_in_shadow=bool(hit.row.shadow),
                lead_id=hit.row.lead_id,
                event_start=_z(hit.start),
                event_end=_z(hit.end),
                born_at=_z(hit.row.born_at) if hit.row.born_at is not None else None,
                inside_gap=hit.inside,
                selected_by_default=hit.selected,
                reasons=list(hit.reasons),
            )
            for hit in hits[:_MAX_LISTED]
        ]
        return GridGapHitsOut(
            gap=_gap_out(gap, now=now, hits_to_review=to_review),
            review_start=_z(window.start),
            review_end=_z(window.end),
            settle_minutes=int(settle.total_seconds() // 60),
            note=gap_recovery.gap_note(gap),
            count=len(hits),
            hits=listed,
            selected_count=sum(1 for hit in hits if hit.selected),
            leads=sorted({int(h.row.lead_id) for h in hits if h.row.lead_id is not None}),
            held=[gap_hold_out(h) for h in holds],
        )


@router.post("/grid/gaps/{gap_id}/hits/benign", response_model=GridGapBenignOut)
async def mark_grid_gap_hits_benign(
    request: Request, gap_id: int, body: GridGapBenignIn
) -> GridGapBenignOut:
    """Mark the selected hits of a closed gap benign, with one reason and the gap as the note.

    The reason is ``grid_gap``. Each mark goes through the per-hit path of
    ``POST /hunts/observations/{id}/benign``. A hit keeps its lead. No
    analytic moves. ``ids`` names the hits and is required: a body without
    it answers 422 ``gap_ids_required``. ``expected`` is the count the confirm
    step showed. A count that differs from the ids answers 422
    ``gap_selection_mismatch``. A selected id that is no longer in the gap
    list answers 409 ``gap_hits_changed``. Both write nothing.
    """
    now = datetime.now(UTC)
    settle = gaps_svc.settle_of(request.app.state.settings)
    by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        gap = await gaps_svc.get(db, gap_id)
        if gap is None:
            raise _not_found(gap_id)
        if gap.ended_at is not None:
            if not body.ids:
                raise api_error(
                    422,
                    "gap_ids_required",
                    "Name the hits to mark in ids. "
                    f"GET /api/v1/grid/gaps/{gap_id}/hits lists the hits of the gap.",
                )
            selected = len(set(body.ids))
            if body.expected is not None and body.expected != selected:
                raise api_error(
                    422,
                    "gap_selection_mismatch",
                    f"The confirm named {body.expected} hits. The request selects {selected}.",
                )
        try:
            result = await gap_recovery.mark_benign(
                db, gap, ids=body.ids or [], by=by, settle=settle, now=now
            )
        except gap_recovery.GapOpen as exc:
            raise api_error(409, "gap_open", str(exc)) from exc
        except gap_recovery.HitsChanged as exc:
            raise api_error(
                409,
                "gap_hits_changed",
                f"{exc} Open the review again and select the hits again.",
            ) from exc
        holds = await gap_recovery.gap_holds(db, settle=settle, now=now, gap=gap)
    await _audit(
        request,
        "grid_gap_hits_benign",
        {
            "gap_id": int(gap_id),
            "marked": len(result.ids),
            "ids": result.ids[:_MAX_LISTED],
            "leads": result.leads,
            "note": result.note,
        },
    )
    return GridGapBenignOut(
        marked=len(result.ids),
        ids=result.ids,
        leads=result.leads,
        note=result.note,
        held=[gap_hold_out(h) for h in holds],
    )
