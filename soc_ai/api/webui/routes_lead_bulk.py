"""Bulk decisions on leads: dismiss, reopen, hunt, and the Undo of each.

The owner asked for bulk management of leads like the alerts and the
investigations have (2026-10-20). Every lead decision was one lead at a time:
ten noise leads on one host cost about thirty clicks on the Hunts page.

One route per action, like the alert writes in ``routes_alert_actions.py``.
Each route takes the lead ids and ``expected``, the count the confirm step
named. A count that differs from the ids answers 409 and writes nothing.

Each lead goes through the store function its single route uses
(:func:`soc_ai.store.leads.dismiss`, :func:`~soc_ai.store.leads.reopen` and
:func:`soc_ai.hunting.lead_hunt.start_lead_hunt`). So a bulk decision writes
the same history row a single decision writes, under the same rules. A lead
the press cannot take is skipped with a reason and never forced: a shadow
lead, a lead in a state the action does not accept, and a lead that changed
after the page loaded.

There is no bulk promotion. An investigation is one decision per case.
There is no bulk Keep open either. Keep open answers the verdict of one
investigation on one lead, and no two leads share that question.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import Request
from pydantic import BaseModel, Field

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import router
from soc_ai.api.webui.routes_hunts import (
    _COULD_NOT_START_HINT,
    HuntRunTimeOut,
    _iso,
    _typical_run,
)
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import leads as leads_store
from soc_ai.store.models import Hunt, Lead

_LOGGER = logging.getLogger(__name__)

# The most leads one press takes. The leads list shows at most 200 rows, and
# a press acts on the rows on screen.
LEAD_BULK_MAX = 200

# The most hunts one bulk Hunt press starts. Each hunt is a model run. The
# bulk re-hunt of the hunt and investigation lists starts 3, because seven
# hunts at once on the one model route all hit the wall clock and wrote
# garbage. The auto-hunt loop runs up to 2 hunts of its own beside these.
LEAD_BULK_HUNT_CAP = 3

# The audit record of one press. A string literal at the call: the docs gate
# scans for it, and AuditKind declares it.
_AUDIT_SESSION = "leads-bulk"

# The sentence for each skip and each failure. The console shows it beside
# the lead id.
_HINTS: dict[str, str] = {
    "not_found": "No lead has this id. Read the list again.",
    "changed": "The lead changed after the page loaded. Read the lead and decide again.",
    "shadow": "This is a shadow lead. Decide on a shadow lead from its own row.",
    "already_closed": "The lead is closed. Reopen it before you decide again.",
    "hunt_running": "A hunt runs on this lead. Wait for the hunt to end.",
    "over_cap": (
        f"One press starts at most {LEAD_BULK_HUNT_CAP} hunts. Press Hunt again for this lead."
    ),
    "not_closed": "The lead is open. Only a closed lead can reopen.",
    "promoted": "An investigation closed this lead. Reopen it from its own row.",
    "no_dismissal": ("No analyst dismissal comes before the last reopen. The lead stays open."),
    "write_failed": "The write failed. Select the lead and try again.",
    "could_not_start": _COULD_NOT_START_HINT,
}

_LeadId = Annotated[int, Field(ge=1)]


class LeadBulkIn(BaseModel):
    """The leads of one press, and the count the confirm step named.

    ``seen`` holds the ``updated_at`` of each lead as the page read it. A lead
    whose value differs now changed after the page loaded, and the press
    skips it. A lead the map does not name is not checked.
    """

    ids: list[_LeadId] = Field(min_length=1, max_length=LEAD_BULK_MAX)
    expected: int = Field(ge=1, le=LEAD_BULK_MAX)
    seen: dict[int, str | None] | None = None


class LeadBulkDismissIn(LeadBulkIn):
    """One reason and one optional note for every lead of the press."""

    reason: str
    note: str | None = None


class LeadBulkDoneOut(BaseModel):
    id: int
    # The lead's change token after the write. Undo sends it back as ``seen``,
    # so Undo leaves a lead that changed after this press.
    updated_at: str | None = None
    # The hunt the press started on the lead.
    hunt_id: str | None = None
    # The dismissal reason the write cleared or restored.
    previous_reason: str | None = None


class LeadBulkSkipOut(BaseModel):
    id: int
    reason: str
    hint: str


class LeadBulkOut(BaseModel):
    """What one press did, lead by lead."""

    action: str
    done: list[LeadBulkDoneOut] = Field(default_factory=list)
    skipped: list[LeadBulkSkipOut] = Field(default_factory=list)
    failed: list[LeadBulkSkipOut] = Field(default_factory=list)
    # The hunt cap of a Hunt press. None on the other actions.
    cap: int | None = None


class LeadBulkHuntPlanOut(BaseModel):
    """What the Hunt confirm states before the press."""

    cap: int
    # How long agent hunts on this grid take, from the store. None while the
    # store holds too few finished hunts to say.
    typical_run: HuntRunTimeOut | None = None


class _Failed(Exception):
    """A lead the press tried and could not write."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# The answer for one lead: the done row, or the code of the skip.
_Outcome = LeadBulkDoneOut | str


def _unique(ids: list[int]) -> list[int]:
    seen: set[int] = set()
    out: list[int] = []
    for lead_id in ids:
        if lead_id not in seen:
            seen.add(lead_id)
            out.append(lead_id)
    return out


def _check_expected(ids: list[int], expected: int) -> None:
    """409 when the request does not name the leads the confirm counted."""
    if expected != len(ids):
        raise api_error(
            409,
            "lead_selection_changed",
            f"The confirm named {expected} leads. The request names {len(ids)}. "
            "Select the leads again and confirm the new count.",
        )


def _common_skip(lead: Lead | None, lead_id: int, seen: dict[int, str | None] | None) -> str | None:
    """The skips every action shares: no lead, a changed lead, a shadow lead."""
    if lead is None:
        return "not_found"
    if seen is not None and lead_id in seen and seen[lead_id] != _iso(lead.updated_at):
        return "changed"
    if lead.shadow:
        return "shadow"
    return None


async def _hunt_runs(db: Any, lead: Lead) -> bool:
    """Whether the hunt the lead names still runs."""
    if not lead.hunt_id:
        return False
    hunt = await db.get(Hunt, str(lead.hunt_id))
    return hunt is not None and hunt.status in leads_store.HUNT_RUNNING_STATUSES


def _dismissal_before_reopen(lead: Lead) -> dict[str, Any] | None:
    """The analyst dismissal the lead's last reopen cleared, or None.

    The reopen must be the last decision on the lead. The decision before it
    must be an analyst dismissal with a reason from the list. A close by the
    settle rule carries the rule's own reason, and no analyst can write it.
    """
    annotations = {leads_store.BACKTEST_DECISION, leads_store.KEPT_OPEN}
    history = [d for d in leads_store.decisions_of(lead) if d.get("action") not in annotations]
    if len(history) < 2 or history[-1].get("action") != "reopened":
        return None
    prior = history[-2]
    if prior.get("action") != "dismissed" or prior.get("reason") not in leads_store.DISMISS_REASONS:
        return None
    return prior


async def _audit(
    request: Request,
    by: str,
    out: LeadBulkOut,
    *,
    expected: int,
    reason: str | None = None,
) -> None:
    """One audit record per press. Best-effort: the writes are committed.

    Each lead's history holds its own row, as a single decision writes. This
    record holds the press: who, which leads, and what each one got.
    """
    try:
        audit = getattr(request.app.state, "audit", None)
        if audit is None:
            return
        payload: dict[str, Any] = {
            "action": out.action,
            "expected": expected,
            "done": [d.id for d in out.done],
            "skipped": [{"id": s.id, "reason": s.reason} for s in out.skipped],
            "failed": [{"id": f.id, "reason": f.reason} for f in out.failed],
        }
        if reason is not None:
            payload["reason"] = reason
        await audit.log_kind(_AUDIT_SESSION, "leads_bulk_decision", payload, user=by)
    except Exception:
        _LOGGER.warning("lead bulk audit write failed (continuing)", exc_info=True)


async def _press(
    request: Request,
    body: LeadBulkIn,
    action: str,
    decide: Callable[[int, str], Awaitable[_Outcome]],
    *,
    reason: str | None = None,
    cap: int | None = None,
) -> LeadBulkOut:
    """Run ``decide`` on each lead in order and collect the outcomes."""
    ids = _unique(list(body.ids))
    _check_expected(ids, body.expected)
    by = await identify_caller(request)
    out = LeadBulkOut(action=action, cap=cap)
    for lead_id in ids:
        try:
            outcome = await decide(lead_id, by)
        except _Failed as exc:
            out.failed.append(
                LeadBulkSkipOut(id=lead_id, reason=exc.reason, hint=_HINTS[exc.reason])
            )
            continue
        except Exception:
            # One lead must not sink the press. Its session rolled back on
            # close, so the lead is as it was.
            _LOGGER.warning("lead bulk %s failed on lead %s", action, lead_id, exc_info=True)
            out.failed.append(
                LeadBulkSkipOut(id=lead_id, reason="write_failed", hint=_HINTS["write_failed"])
            )
            continue
        if isinstance(outcome, str):
            out.skipped.append(LeadBulkSkipOut(id=lead_id, reason=outcome, hint=_HINTS[outcome]))
        else:
            out.done.append(outcome)
    await _audit(request, by, out, expected=body.expected, reason=reason)
    return out


@router.post("/hunts/leads/bulk-dismiss", response_model=LeadBulkOut)
async def bulk_dismiss_leads(request: Request, body: LeadBulkDismissIn) -> LeadBulkOut:
    """Dismiss each lead with one reason and one optional note.

    The history of each lead records one row, with the same hand, reason and
    note. A closed lead, a lead under a running hunt, a shadow lead and a
    changed lead are skipped.
    """
    if body.reason not in leads_store.DISMISS_REASONS:
        raise api_error(
            422,
            "unknown_dismiss_reason",
            f"'{body.reason}' is not a dismissal reason. "
            f"Use one of: {', '.join(leads_store.DISMISS_REASONS)}.",
        )

    async def decide(lead_id: int, by: str) -> _Outcome:
        async with request.app.state.db_sessionmaker() as db:
            lead = await leads_store.get(db, lead_id)
            skip = _common_skip(lead, lead_id, body.seen)
            if skip is not None:
                return skip
            assert lead is not None  # _common_skip answers not_found for None
            if lead.status in leads_store.CLOSED_STATUSES:
                return "already_closed"
            if await _hunt_runs(db, lead):
                return "hunt_running"
            done = await leads_store.dismiss(db, lead_id, reason=body.reason, note=body.note, by=by)
            return LeadBulkDoneOut(id=lead_id, updated_at=_iso(done.updated_at))

    return await _press(request, body, "dismiss", decide, reason=body.reason)


@router.post("/hunts/leads/bulk-reopen", response_model=LeadBulkOut)
async def bulk_reopen_leads(request: Request, body: LeadBulkIn) -> LeadBulkOut:
    """Reopen each dismissed lead. The dismissal moves to the lead's history.

    A promoted lead is skipped: an investigation closed it, and its reopen is
    one decision on its own row. The Undo of a bulk dismiss sends this route
    with the change tokens of the dismiss, so it reopens only the leads that
    did not change after it.
    """

    async def decide(lead_id: int, by: str) -> _Outcome:
        async with request.app.state.db_sessionmaker() as db:
            lead = await leads_store.get(db, lead_id)
            skip = _common_skip(lead, lead_id, body.seen)
            if skip is not None:
                return skip
            assert lead is not None
            if lead.status not in leads_store.CLOSED_STATUSES:
                return "not_closed"
            if lead.status == "promoted":
                return "promoted"
            previous = lead.dismissed_reason
            done = await leads_store.reopen(db, lead_id, by)
            return LeadBulkDoneOut(
                id=lead_id, updated_at=_iso(done.updated_at), previous_reason=previous
            )

    return await _press(request, body, "reopen", decide)


@router.post("/hunts/leads/bulk-dismiss-again", response_model=LeadBulkOut)
async def bulk_dismiss_leads_again(request: Request, body: LeadBulkIn) -> LeadBulkOut:
    """Dismiss each lead again with the reason and the note its last reopen cleared.

    The Undo of a bulk Reopen sends this route. A lead whose close before the
    reopen was not an analyst dismissal stays open: soc-ai closed it after a
    clean hunt, and an analyst cannot write the rule's reason.
    """

    async def decide(lead_id: int, by: str) -> _Outcome:
        async with request.app.state.db_sessionmaker() as db:
            lead = await leads_store.get(db, lead_id)
            skip = _common_skip(lead, lead_id, body.seen)
            if skip is not None:
                return skip
            assert lead is not None
            if lead.status in leads_store.CLOSED_STATUSES:
                return "already_closed"
            if await _hunt_runs(db, lead):
                return "hunt_running"
            prior = _dismissal_before_reopen(lead)
            if prior is None:
                return "no_dismissal"
            reason = str(prior["reason"])
            done = await leads_store.dismiss(
                db, lead_id, reason=reason, note=prior.get("note"), by=by
            )
            return LeadBulkDoneOut(
                id=lead_id, updated_at=_iso(done.updated_at), previous_reason=reason
            )

    return await _press(request, body, "dismiss_again", decide)


@router.post("/hunts/leads/bulk-hunt", response_model=LeadBulkOut)
async def bulk_hunt_leads(request: Request, body: LeadBulkIn) -> LeadBulkOut:
    """Start one hunt per lead, at most ``LEAD_BULK_HUNT_CAP`` per press.

    Each start goes through :func:`soc_ai.hunting.lead_hunt.start_lead_hunt`,
    the path of the single Hunt button and of the auto-hunt loop. A lead with
    a hunt in flight is skipped, and so is a lead past the cap: the console
    states the cap, and a second press takes the rest.
    """
    from soc_ai.hunting import lead_hunt  # noqa: PLC0415 - lazy, as the single route

    state = request.app.state
    started: list[int] = []

    async def decide(lead_id: int, by: str) -> _Outcome:
        # The read closes before the start: the start writes the hunt row and
        # the mark in sessions of its own.
        async with state.db_sessionmaker() as db:
            lead = await leads_store.get(db, lead_id)
            skip = _common_skip(lead, lead_id, body.seen)
            if skip is not None:
                return skip
            assert lead is not None
            if lead.status in leads_store.CLOSED_STATUSES:
                return "already_closed"
            if await _hunt_runs(db, lead):
                return "hunt_running"
        if len(started) >= LEAD_BULK_HUNT_CAP:
            return "over_cap"
        try:
            out = await lead_hunt.start_lead_hunt(state, lead_id=lead_id, started_by=by)
        except lead_hunt.LeadHuntRefused as exc:
            if exc.reason == "lead_not_found":
                return "not_found"
            if exc.reason == "lead_is_closed":
                return "already_closed"
            raise _Failed("could_not_start") from exc
        if out.existing:
            return "hunt_running"
        started.append(lead_id)
        return LeadBulkDoneOut(id=lead_id, hunt_id=out.hunt_id)

    return await _press(request, body, "hunt", decide, cap=LEAD_BULK_HUNT_CAP)


@router.get("/leads/bulk-hunt-plan", response_model=LeadBulkHuntPlanOut)
async def lead_bulk_hunt_plan(request: Request) -> LeadBulkHuntPlanOut:
    """The cap of a bulk Hunt press, and how long hunts on this grid take.

    The Hunt confirm states both before the press. The time is the middle
    half of the recent finished agent hunts, the figure a running hunt page
    states.
    """
    async with request.app.state.db_sessionmaker() as db:
        typical = _typical_run(await hunt_svc.recent_run_seconds(db))
    return LeadBulkHuntPlanOut(cap=LEAD_BULK_HUNT_CAP, typical_run=typical)
