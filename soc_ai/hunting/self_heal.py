"""The self-healing hold: a live analytic that breaches its own budget goes back to shadow.

The four-tier methodology (docs/dev/specs/2026-10-04-four-tier-detection-
methodology.md, "Self-adapting and self-healing") asks for it: a live
detector moves back to shadow when it breaches its fire budget or its
precision floor on hunted leads, and the ledger records why. Approval to live,
positive labels and weight changes stay human.

Two budgets, both declared on the spec and both off by default:

- ``fire_budget_per_day``: the hits the analytic may write in 24 hours. A hit
  is an observation the analytic wrote or refreshed live in the window, the
  unit the Analytic hits section counts.
- ``precision_floor``: the share of its hunted leads over 30 days that reached
  a promoted finding or an investigation. The other side of the share is the
  leads a hunt closed clean. A lead an analyst dismissed counts on neither
  side: its reason says why, and the reason is the analyst's word. The floor
  is read only once ``PRECISION_MIN_LEADS`` leads are decided, because a share
  of one or two is the noise band and not a precision.

The check reads the store only: no grid query and no model call. It never
moves an analytic in shadow, and it never moves one twice for one window. The
window of a breach starts at the later of its own edge and the analytic's
latest approval to live, so the hits and the leads that earned a demotion
cannot earn a second one after an analyst approves the analytic again.

The demotion goes through :func:`soc_ai.store.analytics.demote_to_shadow`,
which writes the version row with the numbers as evidence. The bell reads the
hold from the store (``soc_ai.api.webui.routes_meta``).
"""

from __future__ import annotations

import logging
import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.catalog_tiers import Catalog, effective_catalog
from soc_ai.hunting.spec import HuntSpec
from soc_ai.store import analytics as analytics_store
from soc_ai.store.leads import HUNT_CLEAN_REASON
from soc_ai.store.models import EntityObservation, Hunt, Investigation, Lead

__all__ = [
    "FIRE_WINDOW",
    "PRECISION_MIN_LEADS",
    "PRECISION_WINDOW",
    "RULE_FIRE_BUDGET",
    "RULE_PRECISION_FLOOR",
    "Breach",
    "Demotion",
    "LeadOutcomes",
    "SelfHealResult",
    "count_hits",
    "find_breaches",
    "lead_outcomes",
    "run_self_heal",
]

_LOGGER = logging.getLogger(__name__)

FIRE_WINDOW = timedelta(hours=24)
PRECISION_WINDOW = timedelta(days=30)
# Decided leads before the floor is read. Five of five is a Wilson lower bound
# of 0.57; one of one reads 1.0 or 0.0 and says nothing about the analytic.
PRECISION_MIN_LEADS = 5
# Lead ids a precision breach names on its version row. The count is exact;
# the list is for the analyst to open, and a month of leads is not a list.
_MAX_LEAD_IDS = 20

RULE_FIRE_BUDGET = "fire_budget"
RULE_PRECISION_FLOOR = "precision_floor"


@dataclass(frozen=True)
class Breach:
    """One budget or floor one analytic breached, with the numbers it read."""

    rule: str
    sentence: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class Demotion:
    """One analytic the check moves to shadow, and why."""

    analytic_id: str
    title: str
    breaches: tuple[Breach, ...]

    @property
    def reason(self) -> str:
        return " ".join(b.sentence for b in self.breaches)

    @property
    def evidence(self) -> dict[str, Any]:
        return {"breaches": [dict(b.evidence) for b in self.breaches]}


@dataclass(frozen=True)
class LeadOutcomes:
    """The hunted leads of one analytic in one window, by outcome."""

    reached: tuple[int, ...] = ()
    closed_clean: tuple[int, ...] = ()

    @property
    def decided(self) -> int:
        return len(self.reached) + len(self.closed_clean)

    @property
    def precision(self) -> float | None:
        return len(self.reached) / self.decided if self.decided else None


@dataclass
class SelfHealResult:
    """What one run of the check did."""

    # The live analytics that declare a budget or a floor.
    checked: list[str] = field(default_factory=list)
    demoted: list[Demotion] = field(default_factory=list)
    # A breach the check did not act on, and why.
    skipped: dict[str, str] = field(default_factory=dict)


def _naive(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def _iso(value: datetime) -> str:
    return _naive(value).isoformat() + "Z"


def _window_start(now: datetime, width: timedelta, live_since: datetime | None) -> datetime:
    """The later of the window's own edge and the analytic's latest approval to live."""
    edge = now - width
    if live_since is None:
        return edge
    return max(edge, _naive(live_since))


async def count_hits(
    db: AsyncSession, analytic_id: str, *, since: datetime, until: datetime
) -> int:
    """The live observations one analytic wrote or refreshed in the window."""
    found = await db.scalar(
        select(func.count(EntityObservation.id)).where(
            EntityObservation.spec_id == analytic_id,
            EntityObservation.shadow.is_(False),
            EntityObservation.born_at >= _naive(since),
            EntityObservation.born_at <= _naive(until),
        )
    )
    return int(found or 0)


async def lead_outcomes(
    db: AsyncSession, analytic_id: str, *, since: datetime, until: datetime
) -> LeadOutcomes:
    """The leads one analytic fed that formed in the window, by outcome.

    ``reached``: the lead was promoted to an investigation, or a finding of a
    hunt on the lead was promoted to one. ``closed_clean``: a hunt closed the
    lead with no threat, and nothing reached an investigation. A planted
    synthetic investigation does not count: it is evidence of the eval and not
    of the analytic.
    """
    fed = (
        select(EntityObservation.lead_id)
        .where(
            EntityObservation.spec_id == analytic_id,
            EntityObservation.lead_id.is_not(None),
        )
        .distinct()
    )
    leads = (
        await db.scalars(
            select(Lead).where(
                Lead.id.in_(fed),
                Lead.formed_at >= _naive(since),
                Lead.formed_at <= _naive(until),
            )
        )
    ).all()
    if not leads:
        return LeadOutcomes()

    lead_ids = [int(lead.id) for lead in leads]
    hunts_of: dict[int, set[str]] = {lead_id: set() for lead_id in lead_ids}
    for lead in leads:
        if lead.hunt_id:
            hunts_of[int(lead.id)].add(str(lead.hunt_id))
    for hunt_id, lead_id in (
        await db.execute(select(Hunt.id, Hunt.lead_id).where(Hunt.lead_id.in_(lead_ids)))
    ).all():
        if lead_id is not None:
            hunts_of.setdefault(int(lead_id), set()).add(str(hunt_id))

    all_hunts = sorted({h for hunts in hunts_of.values() for h in hunts})
    promoted_hunts: set[str] = set()
    if all_hunts:
        promoted_hunts = {
            str(h)
            for h in (
                await db.scalars(
                    select(Investigation.hunt_id)
                    .where(
                        Investigation.hunt_id.in_(all_hunts),
                        Investigation.is_synth_eval.is_(False),
                    )
                    .distinct()
                )
            ).all()
            if h
        }

    reached: list[int] = []
    clean: list[int] = []
    for lead in sorted(leads, key=lambda row: int(row.id)):
        lead_id = int(lead.id)
        if lead.status == "promoted" or hunts_of.get(lead_id, set()) & promoted_hunts:
            reached.append(lead_id)
        elif lead.status == "dismissed" and lead.dismissed_reason == HUNT_CLEAN_REASON:
            clean.append(lead_id)
    return LeadOutcomes(reached=tuple(reached), closed_clean=tuple(clean))


def _fire_breach(hits: int, budget: int, *, start: datetime, now: datetime) -> Breach | None:
    if hits <= budget:
        return None
    hours = max(1, min(24, math.ceil((now - start).total_seconds() / 3600)))
    span = "24 hours" if hours == 24 else f"{hours} hours since its approval to live"
    return Breach(
        rule=RULE_FIRE_BUDGET,
        sentence=(f"The analytic wrote {hits} hits in {span}. Its fire budget is {budget} a day."),
        evidence={
            "rule": RULE_FIRE_BUDGET,
            "hits": hits,
            "budget": budget,
            "window_hours": hours,
            "window_start": _iso(start),
            "window_end": _iso(now),
        },
    )


def _precision_breach(
    outcomes: LeadOutcomes, floor: float, *, start: datetime, now: datetime
) -> Breach | None:
    precision = outcomes.precision
    if precision is None or outcomes.decided < PRECISION_MIN_LEADS or precision >= floor:
        return None
    reached = len(outcomes.reached)
    named = sorted((*outcomes.reached, *outcomes.closed_clean))[:_MAX_LEAD_IDS]
    return Breach(
        rule=RULE_PRECISION_FLOOR,
        sentence=(
            f"{reached} of {outcomes.decided} hunted leads reached a finding or an "
            f"investigation. The precision is {precision:.2f}. Its floor is {floor:.2f}."
        ),
        evidence={
            "rule": RULE_PRECISION_FLOOR,
            "precision": round(precision, 3),
            "floor": floor,
            "reached": reached,
            "closed_clean": len(outcomes.closed_clean),
            "decided": outcomes.decided,
            "min_decided": PRECISION_MIN_LEADS,
            "window_days": PRECISION_WINDOW.days,
            "window_start": _iso(start),
            "window_end": _iso(now),
            "lead_ids": named,
        },
    )


def _live_with_a_budget(catalog: Catalog) -> list[tuple[str, HuntSpec]]:
    """The live analytics that declare a fire budget or a precision floor."""
    out: list[tuple[str, HuntSpec]] = []
    for analytic_id, spec in catalog.specs.items():
        if analytic_id in catalog.shadow_ids:
            continue
        if catalog.status_of(analytic_id)[1] != "live":
            continue
        if spec.fire_budget_per_day is None and spec.precision_floor is None:
            continue
        out.append((analytic_id, spec))
    return out


async def find_breaches(
    db: AsyncSession, catalog: Catalog, *, now: datetime
) -> tuple[list[Demotion], list[str], dict[str, str]]:
    """The demotions the store calls for now. Reads only.

    Returns the demotions, the ids it checked, and the breaches it does not act
    on with the reason. A breach whose window already holds a system demotion
    of the same analytic is one of those: the hold was written once.
    """
    now = _naive(now)
    candidates = _live_with_a_budget(catalog)
    ids: Sequence[str] = [analytic_id for analytic_id, _spec in candidates]
    if not ids:
        return [], [], {}
    live_since = await analytics_store.latest_live_at(db, ids)
    demoted_at = {
        analytic_id: row.at
        for analytic_id, row in (await analytics_store.latest_system_demotion(db, ids)).items()
    }

    demotions: list[Demotion] = []
    skipped: dict[str, str] = {}
    for analytic_id, spec in candidates:
        since = live_since.get(analytic_id)
        breaches: list[Breach] = []
        starts: list[datetime] = []
        if spec.fire_budget_per_day is not None:
            start = _window_start(now, FIRE_WINDOW, since)
            hits = await count_hits(db, analytic_id, since=start, until=now)
            found = _fire_breach(hits, spec.fire_budget_per_day, start=start, now=now)
            if found is not None:
                breaches.append(found)
                starts.append(start)
        if spec.precision_floor is not None:
            start = _window_start(now, PRECISION_WINDOW, since)
            outcomes = await lead_outcomes(db, analytic_id, since=start, until=now)
            found = _precision_breach(outcomes, spec.precision_floor, start=start, now=now)
            if found is not None:
                breaches.append(found)
                starts.append(start)
        if not breaches:
            continue
        last = demoted_at.get(analytic_id)
        if last is not None and _naive(last) >= min(starts):
            # The analytic was demoted inside this window and is live again
            # without an approval on record. The breach is the same one.
            skipped[analytic_id] = "already demoted in this window"
            continue
        demotions.append(
            Demotion(analytic_id=analytic_id, title=spec.title, breaches=tuple(breaches))
        )
    return demotions, list(ids), skipped


async def run_self_heal(
    db: AsyncSession, *, now: datetime | None = None, catalog: Catalog | None = None
) -> SelfHealResult:
    """Check every live analytic that declares a budget, and demote each one in breach.

    The check reads the store. Each demotion writes one version row through
    the store, in the system hand, with the numbers as evidence.
    """
    at = _naive(now or datetime.now(UTC))
    cat = catalog if catalog is not None else await effective_catalog(db)
    demotions, checked, skipped = await find_breaches(db, cat, now=at)
    result = SelfHealResult(checked=checked, skipped=skipped)
    for demotion in demotions:
        try:
            await analytics_store.demote_to_shadow(
                db,
                demotion.analytic_id,
                reason=demotion.reason,
                evidence=demotion.evidence,
                actor=analytics_store.SYSTEM_ACTOR,
                now=at,
            )
        except (LookupError, ValueError) as exc:
            # The analytic moved between the read and the write. The store
            # refuses a demotion of anything that is not live, so the hold
            # is skipped and said, never forced.
            await db.rollback()
            result.skipped[demotion.analytic_id] = f"not demoted: {exc}"
            continue
        result.demoted.append(demotion)
        _LOGGER.warning(
            "self-healing hold: %s moved to shadow. %s", demotion.analytic_id, demotion.reason
        )
    return result
