"""The hunt a lead starts, and the leads that still wait for one.

A lead is hunted. Two callers start that hunt: the route
``POST /hunts/leads/{id}/hunt``, which an analyst clicks, and the auto-hunt
loop in :mod:`soc_ai.main`, which wakes every 60 seconds. Both call
:func:`start_lead_hunt`, so a hunt the analyst started and a hunt the loop
started carry the same objective, the same evidence block and the same tags.
Two copies of that body would drift, and the drift would only show on the
range, where a lead hunt reads a different prompt depending on who began it.

The loop's own rules live here too, because they are queries and not schedule
discipline: :func:`leads_awaiting_a_hunt` names the leads the loop may take,
and :func:`running_auto_hunts` counts the hunts it already has in flight.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.leads import HUNT_RUNNING_STATUSES
from soc_ai.store.models import Hunt, Lead

__all__ = [
    "AUTO_HUNT_ACTOR",
    "LeadHuntRefused",
    "LeadHuntStart",
    "leads_awaiting_a_hunt",
    "running_auto_hunts",
    "start_lead_hunt",
]

# The hand the loop signs its hunts with. ``started_by`` names the actor, so a
# hunt the loop began reads as the loop's on every surface, and the cap below
# can tell its own hunts from an analyst's.
AUTO_HUNT_ACTOR = "auto-hunt"


@dataclass(frozen=True)
class LeadHuntStart:
    """The hunt the lead now has.

    ``existing`` is true when the lead already had one that has not finished.
    A second click and a loop wake that races it both land here rather than
    running a second agent. A finished hunt is not in the way: the start after
    it is a second hunt, which the lead page offers as Hunt again.
    """

    hunt_id: str
    existing: bool = False


class LeadHuntRefused(Exception):
    """The lead cannot take a hunt now.

    ``reason`` is one of ``lead_not_found``, ``lead_is_closed`` or
    ``could_not_start``. The route turns it into a 404, a 409 or a 503. The
    loop logs it and takes the next lead. ``lead`` carries the row when there
    is one, because the 409 names the dismissal that closed it.
    """

    def __init__(self, reason: str, lead_id: int, *, lead: Lead | None = None) -> None:
        super().__init__(f"lead {lead_id}: {reason}")
        self.reason = reason
        self.lead_id = int(lead_id)
        self.lead = lead


async def start_lead_hunt(state: Any, *, lead_id: int, started_by: str) -> LeadHuntStart:
    """Start the lead's hunt and attach it to the lead.

    ``state`` is ``app.state``: the hunt console manager and the session maker
    both hang off it. The objective is the lead's own sentence plus the
    evidence block, so the agent reads the documents that formed the lead
    before it queries anything.

    The lead is marked hunting only after the console reports a hunt id. A
    lead marked hunting on a hunt that never began sits in In progress for
    ever and appears on no tab the analyst reads.

    A lead that names a hunt is read against the hunt row. While that hunt
    runs, the start lands on it: a second click and a loop wake that races it
    must not run a second agent. Once it has finished the start is a second
    hunt, the one the page offers after a visibility gap or a failed run; the
    finished hunt stays as history and the lead moves to the new one. A hunt
    id with no row is treated as running: the console writes the row before
    it reports the id, so the id is the record that a start is under way.
    """
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - lazy
    from soc_ai.webui import hunt_console_manager as hcm  # noqa: PLC0415 - lazy

    lead_id = int(lead_id)
    async with state.db_sessionmaker() as db:
        lead = await leads_store.get(db, lead_id)
        if lead is None:
            raise LeadHuntRefused("lead_not_found", lead_id)
        if lead.hunt_id:
            hunt = await db.get(Hunt, str(lead.hunt_id))
            if hunt is None or hunt.status in HUNT_RUNNING_STATUSES:
                return LeadHuntStart(hunt_id=str(lead.hunt_id), existing=True)
        if lead.status in leads_store.CLOSED_STATUSES:
            raise LeadHuntRefused("lead_is_closed", lead_id, lead=lead)
        rows = await leads_store.timeline(db, lead_id)
        related = await leads_store.related_leads(db, lead)
        objective = (
            leads_store.objective_for(lead, rows, related=related)
            + "\n\n"
            + leads_store.evidence_block_for(rows)
        )

    hunt_id = await hcm.get_manager(state).start(
        state,
        objective=objective,
        started_by=started_by,
        kind="lead",
        starter="lead",
        lead_id=lead_id,
    )
    if hunt_id is None:
        raise LeadHuntRefused("could_not_start", lead_id)

    async with state.db_sessionmaker() as db:
        try:
            await leads_store.mark_hunting(db, lead_id, hunt_id=hunt_id)
        except ValueError as exc:
            # The lead closed while the console was starting the hunt. The hunt
            # exists and keeps running. The lead does not take it.
            lead = await leads_store.get(db, lead_id)
            raise LeadHuntRefused("lead_is_closed", lead_id, lead=lead) from exc
    return LeadHuntStart(hunt_id=str(hunt_id), existing=False)


async def leads_awaiting_a_hunt(db: AsyncSession, *, limit: int = 50) -> list[Lead]:
    """The open leads the loop may hunt, oldest first.

    Four conditions, and each one is a decision the loop must not overrule:

    - ``open``: a dismissed or promoted lead is answered.
    - no ``hunt_id``: the lead already has its hunt.
    - no ``dismissed_at``: a reopened lead carries its dismissal as history.
      The analyst reopened it to decide again, and Hunt again is their call.
    - no hunt row naming the lead: the console can start a hunt and the mark
      can still fail. The row is the record that the lead has had its hunt.

    Oldest first, because the oldest lead has waited longest.
    """
    rows = await db.scalars(
        select(Lead)
        .where(
            Lead.status == "open",
            Lead.hunt_id.is_(None),
            Lead.dismissed_at.is_(None),
            # A shadow lead came from an analytic in shadow. Shadow records and
            # never acts, so its hunt waits for the analyst.
            Lead.shadow.is_(False),
            ~select(Hunt.id).where(Hunt.lead_id == Lead.id).exists(),
        )
        .order_by(Lead.formed_at.asc(), Lead.id.asc())
        .limit(max(1, int(limit)))
    )
    return list(rows.all())


async def running_auto_hunts(db: AsyncSession) -> int:
    """How many lead hunts the loop has in flight.

    Only the loop's own hunts count. A hunt an analyst started by hand must
    never block the loop, and the loop must never block the analyst.
    """
    return int(
        (
            await db.scalar(
                select(func.count(Hunt.id)).where(
                    Hunt.starter == "lead",
                    Hunt.started_by == AUTO_HUNT_ACTOR,
                    Hunt.status.in_(HUNT_RUNNING_STATUSES),
                )
            )
        )
        or 0
    )
