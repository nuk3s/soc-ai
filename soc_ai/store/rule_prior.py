"""The rule prior's store: the history it reads and the decisions it records.

The rung itself lives in :mod:`soc_ai.agent.rule_prior`. This module holds
the SQL: a rule's model-backed runs, its analyst overrides, the leads and the
observations on a host, and the ``rule_prior_decisions`` rows (migration
0058) with the suspension they carry.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import load_only

from soc_ai.store.auth import utcnow
from soc_ai.store.investigations import PROMOTED_KINDS, not_hunt_subject
from soc_ai.store.leads import CLOSED_STATUSES
from soc_ai.store.models import EntityObservation, Investigation, Lead, RulePriorDecision

# The class a rule-prior run records. Kept as a string here so the store does
# not import the agent package (soc_ai.agent.budget.RULE_PRIOR).
RULE_PRIOR_CLASS = "rule_prior"

_ANALYST_RESOLUTIONS = ("chat", "manual")


async def model_backed_runs(
    db: AsyncSession, rule_name: str, *, since: datetime
) -> list[Investigation]:
    """The rule's completed model-backed runs since ``since``, newest first.

    Model-backed means a model wrote the verdict. A rule-prior run did not,
    so it never feeds the prior that produced it. A pipeline fallback is a
    failure, not a verdict. A promotion and a synthetic evaluation are not
    runs of the rule at all.
    """
    rows = await db.scalars(
        select(Investigation)
        .options(
            load_only(
                Investigation.id,
                Investigation.verdict,
                Investigation.confidence,
                Investigation.created_at,
                Investigation.run_class,
                raiseload=True,
            )
        )
        .where(
            Investigation.rule_name == rule_name,
            Investigation.status == "complete",
            Investigation.verdict.is_not(None),
            Investigation.created_at >= since,
            Investigation.is_fallback.isnot(True),
            func.coalesce(Investigation.run_class, "") != RULE_PRIOR_CLASS,
            Investigation.kind.not_in(PROMOTED_KINDS),
            Investigation.is_synth_eval.isnot(True),
            not_hunt_subject(),
        )
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
    )
    return list(rows.all())


async def rule_has_analyst_override(db: AsyncSession, rule_name: str) -> bool:
    """Whether an analyst ever overrode a verdict of this rule, at any age.

    An override is a chat or a manual resolution (``investigations.resolve``).
    The whole history counts, not a recent window: one old correction says the
    model got this rule wrong once, and the prior must never paper over it.
    """
    # The JSON index renders json_extract on SQLite and ->> on PostgreSQL.
    resolved_via = Investigation.report["resolution"]["resolved_via"].as_string()
    hit = await db.scalar(
        select(Investigation.id)
        .where(Investigation.rule_name == rule_name, resolved_via.in_(_ANALYST_RESOLUTIONS))
        .limit(1)
    )
    return hit is not None


async def hosts_have_tier2_signal(
    db: AsyncSession, hosts: Iterable[str], *, now: datetime, fresh_hours: int
) -> bool:
    """Whether any of ``hosts`` carries an open lead or a fresh observation.

    Fresh means the observed event time, else the record time, falls inside
    the last ``fresh_hours``. A shadow observation counts too: a detector in
    shadow that fired on the host is still a reason to look.
    """
    keys = sorted({h for h in hosts if h})
    if not keys:
        return False
    cutoff = now - timedelta(hours=fresh_hours)
    fresh = await db.scalar(
        select(EntityObservation.id)
        .where(
            EntityObservation.entity_key.in_(keys),
            func.coalesce(EntityObservation.observed_at, EntityObservation.born_at) >= cutoff,
        )
        .limit(1)
    )
    if fresh is not None:
        return True
    via_observation = await db.scalar(
        select(Lead.id)
        .join(EntityObservation, EntityObservation.lead_id == Lead.id)
        .where(
            EntityObservation.entity_key.in_(keys),
            Lead.status.not_in(tuple(CLOSED_STATUSES)),
        )
        .limit(1)
    )
    if via_observation is not None:
        return True
    open_entities = await db.scalars(
        select(Lead.entities_json).where(Lead.status.not_in(tuple(CLOSED_STATUSES)))
    )
    wanted = set(keys)
    for entities in open_entities.all():
        for entity in entities or []:
            if isinstance(entity, (list, tuple)) and len(entity) == 2 and str(entity[1]) in wanted:
                return True
    return False


async def rule_is_suspended(db: AsyncSession, rule_name: str) -> bool:
    """A disagreement on a covered alert stands with no analyst clearance."""
    hit = await db.scalar(
        select(RulePriorDecision.id)
        .where(
            RulePriorDecision.rule_name == rule_name,
            RulePriorDecision.agree.is_(False),
            RulePriorDecision.cleared_at.is_(None),
        )
        .limit(1)
    )
    return hit is not None


async def record_decision(db: AsyncSession, **fields: Any) -> RulePriorDecision:
    row = RulePriorDecision(**fields)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def settle_decision(
    db: AsyncSession,
    decision_id: int,
    *,
    investigation_id: str | None,
    real_verdict: str | None,
) -> RulePriorDecision | None:
    """Put the real verdict beside the decision, and say whether they agree.

    ``real_verdict`` None means the real run reached no verdict (an error, a
    pipeline fallback). There is then nothing to compare, and the decision
    neither agrees nor disagrees.
    """
    row = await db.get(RulePriorDecision, decision_id)
    if row is None:
        return None
    row.investigation_id = investigation_id
    row.real_verdict = real_verdict
    if row.applies and real_verdict is not None and row.would_verdict is not None:
        row.agree = real_verdict == row.would_verdict
    await db.commit()
    return row


async def clear_suspension(db: AsyncSession, rule_name: str, *, by: str) -> int:
    """An analyst clears the suspension of a rule. Returns the rows cleared."""
    result = await db.execute(
        update(RulePriorDecision)
        .where(
            RulePriorDecision.rule_name == rule_name,
            RulePriorDecision.agree.is_(False),
            RulePriorDecision.cleared_at.is_(None),
        )
        .values(cleared_at=utcnow(), cleared_by=by[:80])
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return int(getattr(result, "rowcount", 0) or 0)


@dataclass(frozen=True)
class RulePriorStats:
    """One rule's rule-prior record, for the Detection tuning panel."""

    covered: int = 0
    agreements: int = 0
    disagreements: int = 0
    suspended: bool = False
    # Covered alerts that got no real run (live mode, not sampled).
    unchecked: int = 0
    # Why the prior held back on the newest alert it did not cover.
    last_reason: str | None = None


async def stats_by_rule(
    db: AsyncSession, rule_names: Sequence[str], *, days: int = 30
) -> dict[str, RulePriorStats]:
    """Covered alerts, agreements, disagreements and the suspension, per rule."""
    names = [r for r in dict.fromkeys(rule_names) if r]
    if not names:
        return {}
    since = utcnow() - timedelta(days=days)

    def _count(condition: Any) -> Any:
        return func.sum(case((condition, 1), else_=0))

    counts = await db.execute(
        select(
            RulePriorDecision.rule_name,
            _count(RulePriorDecision.applies.is_(True)),
            _count(RulePriorDecision.agree.is_(True)),
            _count(RulePriorDecision.agree.is_(False)),
            _count(and_(RulePriorDecision.applies.is_(True), RulePriorDecision.agree.is_(None))),
        )
        .where(RulePriorDecision.rule_name.in_(names), RulePriorDecision.created_at >= since)
        .group_by(RulePriorDecision.rule_name)
    )
    suspended = set(
        (
            await db.scalars(
                select(RulePriorDecision.rule_name).where(
                    RulePriorDecision.rule_name.in_(names),
                    RulePriorDecision.agree.is_(False),
                    RulePriorDecision.cleared_at.is_(None),
                )
            )
        ).all()
    )
    last_reason: dict[str, str] = {}
    ranked = (
        select(
            RulePriorDecision.rule_name,
            RulePriorDecision.reason,
            func.row_number()
            .over(
                partition_by=RulePriorDecision.rule_name,
                order_by=(RulePriorDecision.created_at.desc(), RulePriorDecision.id.desc()),
            )
            .label("rn"),
        )
        .where(
            RulePriorDecision.rule_name.in_(names),
            or_(RulePriorDecision.applies.is_(False), RulePriorDecision.applies.is_(None)),
        )
        .subquery()
    )
    for rule, reason in (
        await db.execute(select(ranked.c.rule_name, ranked.c.reason).where(ranked.c.rn == 1))
    ).all():
        last_reason[str(rule)] = str(reason)
    out: dict[str, RulePriorStats] = {}
    for rule, covered, agreements, disagreements, unchecked in counts.all():
        out[str(rule)] = RulePriorStats(
            covered=int(covered or 0),
            agreements=int(agreements or 0),
            disagreements=int(disagreements or 0),
            suspended=rule in suspended,
            unchecked=int(unchecked or 0),
            last_reason=last_reason.get(str(rule)),
        )
    for rule in suspended:
        if rule not in out:
            out[rule] = RulePriorStats(suspended=True)
    return out


__all__ = [
    "RULE_PRIOR_CLASS",
    "RulePriorStats",
    "clear_suspension",
    "hosts_have_tier2_signal",
    "model_backed_runs",
    "record_decision",
    "rule_has_analyst_override",
    "rule_is_suspended",
    "settle_decision",
    "stats_by_rule",
]
