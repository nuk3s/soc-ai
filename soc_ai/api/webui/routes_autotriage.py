"""Auto-triage (bulk) start/status/stop endpoints."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Annotated, Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    router,
)
from soc_ai.api.webui.routes_alerts import _GRID_UNAVAILABLE, _es_api_error_http
from soc_ai.errors import OqlValidationError
from soc_ai.webui import alerts_query as aq
from soc_ai.webui import autotriage as at

_LOGGER = logging.getLogger(__name__)

# Same 2048-char cap as the alert-action / GET-alert q params: bound the OQL
# body BEFORE it reaches the synchronous lark parse, so a 30k-term q can't burn
# ~1s of event loop here — this endpoint is the other door into parse_oql.
_OQL_Q = Annotated[str, Field(max_length=2048)]

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
    # True when this run could not read part (or all) of the grid. Without it a
    # blind sweep is indistinguishable on the wire from a drained queue: both are
    # total=0, hunted=0, failed=0. ``grid_errors`` names the queries that failed
    # (never the exception text — that carries the grid's host:port).
    degraded: bool = False
    grid_errors: list[str] = []


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
        degraded=bool(getattr(status, "degraded", False)),
        grid_errors=list(getattr(status, "grid_errors", []) or []),
    )


def _mark_grid_outage(status: Any, severities: tuple[str, ...]) -> None:
    """Land a failed sweep as a FINISHED, degraded run.

    Releases the single-flight slot and replaces the previous run's counters, so
    the last thing the console knows about auto-triage is "this sweep could not
    read the grid" rather than a stale "0 investigated" that reads as calm. The
    planner already stashed ``grid_errors`` on the status; ``reset()`` leaves
    that field alone by design.
    """
    status.reset(active=False, total=0, skipped=0, severities=severities)
    status.finished_at = datetime.now(UTC).isoformat()


def _planning_budget_spent(status: Any, budget: int) -> HTTPException:
    """Release the slot and build the 503 for planning that outran the grid budget.

    Deliberately NOT :func:`_mark_grid_outage`. That function publishes a
    finished, degraded run off ``grid_errors``, and the planner is that field's
    sole writer — a planner cancelled mid-read wrote nothing, so what is still
    sitting there belongs to the PREVIOUS run. On a fresh process that is an
    empty list, which lands this blind, never-started sweep on the dashboard as
    ``total: 0, degraded: false``: a swept, clean backlog. The last completed
    run's status is a true statement about a run that did happen, so it is left
    alone, and this attempt is reported to the caller that made it.
    """
    status.active = False
    _LOGGER.warning("auto-triage planning exceeded the grid budget (%ss)", budget)
    return HTTPException(
        status_code=503,
        detail={
            "reason": "grid_unavailable",
            "hint": (
                f"Security Onion did not finish answering within {budget}s, so no sweep "
                "was started. Retry, or narrow the range or severities."
            ),
        },
    )


def _finished_empty(
    status: Any, *, selected: bool, skipped: int, severities: tuple[str, ...]
) -> AutoTriageStatusOut:
    """Land a run that planned successfully and found nothing to do."""
    status.reset(active=False, total=0, skipped=skipped, severities=severities)
    status.finished_at = datetime.now(UTC).isoformat()
    if selected:
        note = f"all {skipped} selected already triaged" if skipped else "nothing to triage"
    else:
        note = "nothing to hunt"
    return _at_status(status, note=note)


def _launched_note(*, selected: bool, launched: int, skipped: int) -> str | None:
    """The toast for a sweep that just started. Only an explicit SELECTION gets
    one: the analyst picked those alerts and is owed the count that survived the
    already-triaged filter. A config-band sweep's numbers are on the tile."""
    if not selected:
        return None
    note = f"triaging {launched} selected"
    return f"{note} ({skipped} already triaged)" if skipped else note


_ALERT_IDS_CAP = 50
# plan_targets_for_ids() intentionally applies no max-targets cap to an explicit
# selection (the operator picked these on purpose) — so without an input-boundary
# cap here, an uncapped alert_ids list would hold the single-flight slot for one
# sequential LLM investigation (up to auto_triage_per_target_timeout_s each) per
# id, starving the scheduled sweep. Cap at the boundary, mirroring the
# investigations/hunts rehunt endpoints' ``_REHUNT_CAP``.


class AutoTriageIn(BaseModel):
    range: str = aq.DEFAULT_RANGE
    q: _OQL_Q | None = None
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
    # The config-default severity band: everything at or above the floor. Shared
    # with the scheduler's config sweep so the two paths cannot drift apart.
    _config_band: tuple[str, ...] = at.config_severity_band(state.settings)
    chosen: tuple[str, ...] = _config_band
    status.active = True  # claim the slot before any await
    inherited_acks: list[at.InheritedAck] = []
    budget = state.settings.webui_grid_timeout_s
    try:
        # PLANNING is bounded, the sweep is not. Everything below the planner runs
        # in a background task on its own per-target budget; what the analyst waits
        # on here is the grid reads that decide what to sweep, and those had no
        # bound at all — so against a grid that accepts the connection and never
        # answers, this POST rode the ES client's retry budget while the browser
        # gave up at 20 s. That abandoned request is what makes the bulk-investigate
        # toast unable to say whether the sweep started: the client cannot know.
        # Now the server decides, inside the console budget and well before the
        # browser has cause to abandon anything.
        #
        # KNOWN COARSE: this is one budget over a fan-out. plan_targets reads
        # groups per severity and then events per group (up to alerts_query's
        # MAX_GROUPS of them, in series), so a genuinely large backlog on a
        # working-but-busy grid can exceed the budget for a working reason and be
        # reported as an outage. The right shape is a per-read bound inside
        # ``soc_ai/webui/autotriage.py``, next to the loop that knows how many
        # reads it is making; ``webui_grid_timeout_s`` is documented as the bound
        # for ONE interactive read, and that is the knob to raise until then.
        async with asyncio.timeout(budget) as planning_budget:
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
    except OqlValidationError as exc:
        # The filter never reached the grid — this is operator error, matching
        # the alerts routes' arm. Release the slot and accuse nobody: planting
        # the degraded mark here would leave the dashboard reporting an outage
        # over a typo, on a grid that is perfectly healthy.
        status.active = False
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc
    except (TimeoutError, TransportError) as exc:
        # The budget above firing is NOT the same event as the grid raising a
        # timeout at us: the planner was cancelled mid-read and never got to stash
        # what it could and could not see. See _planning_budget_spent.
        if isinstance(exc, TimeoutError) and planning_budget.expired():
            raise _planning_budget_spent(status, budget) from exc
        # Nothing could be READ, so there is no claim to make about the backlog.
        # This used to fall through to the "nothing to hunt" 200 below: the queue
        # showed as drained for the whole blind window, which is the worst thing
        # this product can tell an analyst. Mark the run degraded and finished so
        # the dashboard tile keeps saying so after the toast is gone.
        _mark_grid_outage(status, chosen)
        raise HTTPException(status_code=503, detail=_GRID_UNAVAILABLE) from exc
    except ApiError as exc:
        # An ES ApiError is NOT a TransportError — without this arm a 4xx from
        # the grid leaks as an unhandled 500. Split it the way the alerts routes
        # do: a 4xx is the grid REJECTING a query (it answered, so it is up and
        # earns no outage mark), a 5xx is the grid failing to answer one.
        http = _es_api_error_http(exc)
        if http.status_code >= 500:
            _mark_grid_outage(status, chosen)
        else:
            status.active = False
        raise http from exc
    except asyncio.CancelledError:
        # The caller went away mid-planning: a closed tab, the SPA unmounting its
        # abort controller, or a shutdown. CancelledError is a BaseException, so
        # it sails past every arm above and used to leave the single-flight claim
        # outliving the request that made it — from then on every Bulk
        # Investigate answered "already running", the scheduler's backlog-drain
        # sweep no-opped at its own ``if status.active`` gate, and GET
        # /auto-triage reported a sweep that did not exist, until a restart. The
        # bounded planning wait above is exactly the window a navigate-away lands
        # in. Same mechanism, same arm, in soc_ai/webui/backtest.py.
        status.active = False
        raise
    except Exception:
        status.active = False
        # Log the real cause — `from None` + a bare 500 body left a planning
        # failure (bad OQL, ES down, coercion bug) completely undiagnosable.
        _LOGGER.exception("auto-triage planning failed")
        raise HTTPException(status_code=500, detail={"reason": "planning_failed"}) from None

    if not targets and not inherited_acks:
        return _finished_empty(status, selected=bool(selected), skipped=skipped, severities=chosen)

    # 0 targets + N inherited acks still runs the worker: the ack pass is how a
    # standing inherited-FP backlog drains (no LLM calls involved).
    status.reset(active=True, total=len(targets), skipped=skipped, severities=chosen)
    started_by = f"auto-triage:{await identify_caller(request)}"
    status._task = asyncio.create_task(
        at.run_auto_triage(
            state, targets=targets, started_by=started_by, inherited_acks=inherited_acks
        )
    )
    return _at_status(
        status,
        note=_launched_note(selected=bool(selected), launched=len(targets), skipped=skipped),
    )


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
