"""The outcome ledger of one analytic, computed on read. Never stored.

An analytic earns its place if it contributes to confirmed leads at a cost the
grid can afford. The ledger is the evidence for that judgement: what it
observed, which leads it fed, what became of them, what it spent, and how much
of the estate it could see.

Computed on read, for the reason the observation weights are: a stored figure
is correct on the night the job ran and wrong every night the job is missed,
and a retirement decision taken on a stale number retires the wrong analytic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import EntityObservation, HuntSpecSweep, Lead, PriorSpecRun

__all__ = ["Ledger", "analytic_ledger", "analytic_ledgers"]


@dataclass(frozen=True)
class Ledger:
    """What one analytic did over one window, and what it cost."""

    analytic_id: str
    since: datetime
    observations: int = 0
    entities: int = 0
    shadow_hits: int = 0
    unread_shadow_hits: int = 0
    leads: int = 0
    hunted: int = 0
    promoted: int = 0
    dismissed: dict[str, int] = field(default_factory=dict)
    docs_scanned: int = 0
    runtime_ms: int = 0
    sweeps: int = 0
    coverage: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "analytic_id": self.analytic_id,
            "since": self.since.isoformat(),
            "observations": self.observations,
            "entities": self.entities,
            "shadow_hits": self.shadow_hits,
            "unread_shadow_hits": self.unread_shadow_hits,
            "leads": self.leads,
            "hunted": self.hunted,
            "promoted": self.promoted,
            "dismissed": dict(self.dismissed),
            "docs_scanned": self.docs_scanned,
            "runtime_ms": self.runtime_ms,
            "sweeps": self.sweeps,
            "coverage": dict(self.coverage),
        }


async def analytic_ledger(
    db: AsyncSession, analytic_id: str, *, since: datetime, now: datetime | None = None
) -> Ledger:
    """The ledger of one analytic over one window.

    An analytic with no rows at all reads as zeros rather than as an error: a
    candidate that has never run is the normal first state, and the detail view
    must be able to open on it.
    """
    ledgers = await analytic_ledgers(db, [analytic_id], since=since, now=now)
    return ledgers[analytic_id]


async def analytic_ledgers(
    db: AsyncSession,
    analytic_ids: Sequence[str],
    *,
    since: datetime,
    now: datetime | None = None,
) -> dict[str, Ledger]:
    """The same numbers for many analytics, in one query per counter.

    The analytics list shows a ledger per row. Computed one analytic at a time
    that is four queries per analytic, and the catalog is sixteen analytics
    before an analyst writes one. Every id asked for comes back, with zeros if
    it has no rows.
    """
    since_naive = since.replace(tzinfo=None)
    wanted = list(dict.fromkeys(str(i) for i in analytic_ids))
    if not wanted:
        return {}

    rows = (
        await db.scalars(
            select(EntityObservation).where(
                EntityObservation.spec_id.in_(wanted),
                EntityObservation.first_seen_at >= since_naive,
            )
        )
    ).all()
    by_spec: dict[str, list[Any]] = {spec: [] for spec in wanted}
    lead_ids: set[int] = set()
    for row in rows:
        by_spec.setdefault(str(row.spec_id), []).append(row)
        if row.lead_id:
            lead_ids.add(int(row.lead_id))

    leads = (
        {
            lead.id: lead
            for lead in (await db.scalars(select(Lead).where(Lead.id.in_(sorted(lead_ids))))).all()
        }
        if lead_ids
        else {}
    )

    cost = (
        await db.execute(
            select(
                HuntSpecSweep.spec_id,
                func.count(HuntSpecSweep.id),
                func.coalesce(func.sum(HuntSpecSweep.precondition_docs), 0),
                func.coalesce(func.sum(HuntSpecSweep.duration_ms), 0),
            )
            .where(
                HuntSpecSweep.spec_id.in_(wanted),
                HuntSpecSweep.created_at >= since_naive,
            )
            .group_by(HuntSpecSweep.spec_id)
        )
    ).all()
    by_cost = {str(spec): (int(n), int(docs or 0), int(ms or 0)) for spec, n, docs, ms in cost}

    # Coverage is the NEWEST prior run, not a sum over the window. The question
    # is how much of the estate this analytic can score now; a sum would keep
    # the number of a fortnight ago on a spec that has since gone blind.
    #
    # Newest by id. The table is append-only with one writer, so the key IS the
    # order, and a run written with a back-dated ``created_at`` cannot present
    # itself as the current state of the grid.
    newest = (
        select(PriorSpecRun.spec_id, func.max(PriorSpecRun.id).label("id"))
        .where(PriorSpecRun.spec_id.in_(wanted))
        .group_by(PriorSpecRun.spec_id)
        .subquery()
    )
    priors = (
        await db.scalars(select(PriorSpecRun).join(newest, PriorSpecRun.id == newest.c.id))
    ).all()
    by_coverage = {
        str(run.spec_id): {
            "measured": int(run.measured or 0),
            "learning": int(run.learning or 0),
            "blind": int(run.blind or 0),
        }
        for run in priors
    }

    out: dict[str, Ledger] = {}
    for spec in wanted:
        observations = by_spec.get(spec, [])
        attached = sorted({int(o.lead_id) for o in observations if o.lead_id})
        dismissed: dict[str, int] = {}
        hunted = promoted = 0
        for lead_id in attached:
            lead = leads.get(lead_id)
            if lead is None:
                continue
            if lead.status == "hunting" or lead.hunt_id:
                hunted += 1
            if lead.status == "promoted":
                promoted += 1
            if lead.status == "dismissed":
                key = lead.dismissed_reason or "other"
                dismissed[key] = dismissed.get(key, 0) + 1
        sweeps, docs, runtime = by_cost.get(spec, (0, 0, 0))
        out[spec] = Ledger(
            analytic_id=spec,
            since=since_naive,
            observations=len(observations),
            entities=len({(o.entity_kind, o.entity_key) for o in observations}),
            shadow_hits=sum(1 for o in observations if o.shadow),
            unread_shadow_hits=sum(1 for o in observations if o.shadow and o.read_at is None),
            leads=len([i for i in attached if i in leads]),
            hunted=hunted,
            promoted=promoted,
            dismissed=dismissed,
            docs_scanned=docs,
            runtime_ms=runtime,
            sweeps=sweeps,
            coverage=by_coverage.get(spec, {}),
        )
    return out
