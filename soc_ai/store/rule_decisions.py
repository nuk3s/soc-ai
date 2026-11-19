"""The store of the rule decisions (migration 0075).

``rule_decisions`` holds each decision of the analyst on the open false
positives of a rule: ``acknowledge`` once, or ``standing``, which also lets
soc-ai acknowledge each later false positive of the rule for a term.

The store cannot tell if the alert of an open false positive is still open:
an acknowledge from another investigation, from the inherited fan-out or from
Security Onion leaves no row. ``rule_alert_states`` holds what the grid stated
for each alert, and when (:mod:`soc_ai.webui.rule_decisions`).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, not_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns.facts import chunked
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Investigation, RuleAlertState, RuleDecision

# The states that the grid can state for an alert.
STATE_OPEN = "open"
STATE_ACKNOWLEDGED = "acknowledged"
STATE_GONE = "gone"
STATES: tuple[str, ...] = (STATE_OPEN, STATE_ACKNOWLEDGED, STATE_GONE)
# The states that take an alert out of the selection.
CLOSED_STATES: tuple[str, ...] = (STATE_ACKNOWLEDGED, STATE_GONE)


def closed_state_sql(model: Any = Investigation) -> Any:
    """The SQL for a run whose alert the grid states as acknowledged or gone."""
    return (
        select(RuleAlertState.alert_es_id)
        .where(
            RuleAlertState.alert_es_id == model.alert_es_id,
            RuleAlertState.state.in_(CLOSED_STATES),
        )
        .exists()
    )


async def states_for(db: AsyncSession, alert_ids: Iterable[str]) -> dict[str, tuple[str, datetime]]:
    """The stored ``(state, read_at)`` of each alert. An alert with no read has no entry."""
    out: dict[str, tuple[str, datetime]] = {}
    for ids in chunked(sorted({a for a in alert_ids if a})):
        rows = await db.execute(
            select(RuleAlertState.alert_es_id, RuleAlertState.state, RuleAlertState.read_at).where(
                RuleAlertState.alert_es_id.in_(ids)
            )
        )
        for alert_id, state, read_at in rows.all():
            out[str(alert_id)] = (str(state), read_at)
    return out


async def record_states(db: AsyncSession, answers: Mapping[str, str], *, at: datetime) -> None:
    """Store the state that the grid stated for each alert, read at ``at``. Commits.

    A state outside :data:`STATES` is not stored.
    """
    wanted = {a: s for a, s in answers.items() if a and s in STATES}
    if not wanted:
        return
    for ids in chunked(sorted(wanted)):
        held = {
            row.alert_es_id: row
            for row in (
                await db.scalars(select(RuleAlertState).where(RuleAlertState.alert_es_id.in_(ids)))
            ).all()
        }
        for alert_id in ids:
            row = held.get(alert_id)
            if row is None:
                db.add(RuleAlertState(alert_es_id=alert_id, state=wanted[alert_id], read_at=at))
            else:
                row.state = wanted[alert_id]
                row.read_at = at
    await db.commit()


# ── The decisions ──────────────────────────────────────────────────────────

DECISION_ACKNOWLEDGE = "acknowledge"
DECISION_STANDING = "standing"
DECISIONS: tuple[str, ...] = (DECISION_ACKNOWLEDGE, DECISION_STANDING)

# The states of the background work of a decision.
STATE_ACKNOWLEDGING = "acknowledging"
STATE_DONE = "done"
STATE_FAILED = "failed"

# The causes of the end of a standing decision.
CAUSE_EXPIRED = "expired"
CAUSE_ANALYST = "analyst"
CAUSE_TRUE_POSITIVE = "true_positive"

# The most decisions that the history of one rule lists.
HISTORY_MAX = 20

# The key in ``detail`` of a decision that also acknowledges the open false
# positives on the machine pair of a true positive of the rule (F4). The
# table has no column for it, and ``detail`` holds the rest of a decision.
DETAIL_TP_PAIRS = "include_true_positive_pairs"


def includes_true_positive_pairs(row: RuleDecision) -> bool:
    """Whether the decision also takes the false positives on the machines of a true positive."""
    detail = row.detail if isinstance(row.detail, dict) else {}
    return detail.get(DETAIL_TP_PAIRS) is True


def new_decision(
    *,
    rule_name: str,
    decision: str,
    include_weak: bool,
    note: str,
    by: str,
    at: datetime,
    ends_at: datetime | None,
    include_true_positive_pairs: bool = False,
) -> RuleDecision:
    """A new decision in the state ``acknowledging``. The caller adds and commits it."""
    return RuleDecision(
        detail={DETAIL_TP_PAIRS: True} if include_true_positive_pairs else None,
        rule_name=rule_name,
        decision=decision,
        include_weak=include_weak,
        note=note,
        decided_by=by,
        decided_at=at,
        state=STATE_ACKNOWLEDGING,
        alerts=0,
        failed=0,
        investigations=0,
        acknowledged=0,
        ends_at=ends_at if decision == DECISION_STANDING else None,
    )


async def history(
    db: AsyncSession, rule_name: str, *, limit: int = HISTORY_MAX
) -> list[RuleDecision]:
    """The decisions of one rule, the newest first."""
    return list(
        (
            await db.scalars(
                select(RuleDecision)
                .where(RuleDecision.rule_name == rule_name)
                .order_by(RuleDecision.decided_at.desc(), RuleDecision.id.desc())
                .limit(max(1, limit))
            )
        ).all()
    )


async def running(db: AsyncSession, rule_name: str, *, since: datetime) -> RuleDecision | None:
    """A decision of the rule whose background work runs, decided after ``since``.

    An older row in the state ``acknowledging`` lost its work to a restart,
    and it blocks no new decision.
    """
    found: RuleDecision | None = await db.scalar(
        select(RuleDecision)
        .where(
            RuleDecision.rule_name == rule_name,
            RuleDecision.state == STATE_ACKNOWLEDGING,
            RuleDecision.decided_at >= since,
        )
        .limit(1)
    )
    return found


async def finish(
    db: AsyncSession,
    decision_id: int,
    *,
    state: str,
    alerts: int,
    failed: int,
    investigations: int,
    detail: dict[str, Any],
    at: datetime,
) -> None:
    """Store the result of the background work of a decision. Commits."""
    await db.execute(
        update(RuleDecision)
        .where(RuleDecision.id == decision_id)
        .values(
            state=state,
            alerts=alerts,
            failed=failed,
            investigations=investigations,
            detail=detail,
            finished_at=at,
        )
    )
    await db.commit()


def standing_true_positive_conds(rule_name: str) -> list[Any]:
    """The SQL of a true positive of the rule that stands (``standing_true_positives``)."""
    return [*inv_svc._standing_conds(), Investigation.rule_name == rule_name]


async def standing_true_positives(
    db: AsyncSession, rule_name: str, *, limit: int = HISTORY_MAX
) -> list[Investigation]:
    """The true positives of the rule that stand, the newest event first."""
    rows = list(
        (
            await db.scalars(
                select(Investigation)
                .where(*standing_true_positive_conds(rule_name))
                .order_by(Investigation.event_at.desc(), Investigation.id.desc())
                .limit(max(1, limit))
            )
        ).all()
    )
    answered = await inv_svc.answered_ids(db, rows)
    return [inv for inv in rows if inv.id not in answered]


def _in_force_conds(now: datetime) -> list[Any]:
    return [
        RuleDecision.decision == DECISION_STANDING,
        RuleDecision.ended_at.is_(None),
        RuleDecision.ends_at.is_not(None),
        RuleDecision.ends_at > now,
    ]


def _true_positive_since_sql(rule_name: str, since: datetime) -> Any:
    """The SQL for a true positive of the rule that came at or after ``since``.

    A new investigation that ended with a true positive, an analyst who set a
    true positive, or a true positive of the rule that stands. A synthetic
    run, a backtest replay and a pipeline error say nothing about the rule.
    """
    resolved_at = Investigation.report["resolution"]["resolved_at"].as_string()
    return (
        select(Investigation.id)
        .where(
            Investigation.rule_name == rule_name,
            Investigation.status == "complete",
            Investigation.verdict == "true_positive",
            Investigation.is_fallback.isnot(True),
            Investigation.is_synth_eval.isnot(True),
            inv_svc.not_backtest(),
            or_(
                func.coalesce(Investigation.finished_at, Investigation.created_at) >= since,
                and_(resolved_at.is_not(None), resolved_at >= since.isoformat()),
                not_(inv_svc.superseded_sql()),
            ),
        )
        .exists()
    )


def end_decision(row: RuleDecision, *, cause: str, at: datetime, by: str | None = None) -> None:
    """End a standing decision with its cause. The caller commits."""
    row.ended_at = at
    row.end_cause = cause
    row.ended_by = by


async def _end_cause(db: AsyncSession, row: RuleDecision, *, now: datetime) -> str | None:
    """The cause that ends the row now, or None while it is in force."""
    if row.ends_at is None or row.ends_at <= now:
        return CAUSE_EXPIRED
    if await db.scalar(select(_true_positive_since_sql(row.rule_name, row.decided_at))):
        return CAUSE_TRUE_POSITIVE
    return None


async def in_force(db: AsyncSession, rule_name: str, *, now: datetime) -> RuleDecision | None:
    """The standing decision in force for the rule, or None.

    A standing decision ends after its term, and at once when an
    investigation of the rule gets a true positive verdict. This read leaves
    out such a row before :func:`settle` states its end, so no write waits on
    the settle step.
    """
    rows = (
        await db.scalars(
            select(RuleDecision)
            .where(
                RuleDecision.rule_name == rule_name,
                RuleDecision.decision == DECISION_STANDING,
                RuleDecision.ended_at.is_(None),
            )
            .order_by(RuleDecision.decided_at.desc(), RuleDecision.id.desc())
        )
    ).all()
    for row in rows:
        if await _end_cause(db, row, now=now) is None:
            found: RuleDecision = row
            return found
    return None


async def settle(db: AsyncSession, *, now: datetime) -> list[RuleDecision]:
    """End each standing decision whose term is over or whose rule got a true positive.

    The end of an expired decision is the end of its term. Commits. The rows
    that ended, for the audit records of the caller.
    """
    rows = list(
        (
            await db.scalars(
                select(RuleDecision).where(
                    RuleDecision.decision == DECISION_STANDING, RuleDecision.ended_at.is_(None)
                )
            )
        ).all()
    )
    ended: list[RuleDecision] = []
    for row in rows:
        cause = await _end_cause(db, row, now=now)
        if cause is None:
            continue
        at = row.ends_at if cause == CAUSE_EXPIRED and row.ends_at is not None else now
        end_decision(row, cause=cause, at=at)
        ended.append(row)
    if ended:
        await db.commit()
    return ended


async def count_acknowledged(db: AsyncSession, decision_id: int, count: int) -> None:
    """Add ``count`` acknowledges under a standing decision. Commits."""
    if count <= 0:
        return
    await db.execute(
        update(RuleDecision)
        .where(RuleDecision.id == decision_id)
        .values(acknowledged=RuleDecision.acknowledged + count)
    )
    await db.commit()


async def last_ended(db: AsyncSession, rule_names: Iterable[str]) -> dict[str, RuleDecision]:
    """The newest standing decision that ended, for each rule that has one."""
    out: dict[str, RuleDecision] = {}
    for names in chunked(sorted({r for r in rule_names if r})):
        rows = await db.scalars(
            select(RuleDecision)
            .where(
                RuleDecision.rule_name.in_(names),
                RuleDecision.decision == DECISION_STANDING,
                RuleDecision.ended_at.is_not(None),
            )
            .order_by(RuleDecision.ended_at.desc(), RuleDecision.id.desc())
        )
        for row in rows.all():
            out.setdefault(row.rule_name, row)
    return out


async def standing_rows(db: AsyncSession, *, now: datetime) -> list[RuleDecision]:
    """Every standing decision in force, the newest first."""
    return list(
        (
            await db.scalars(
                select(RuleDecision)
                .where(*_in_force_conds(now))
                .order_by(RuleDecision.decided_at.desc(), RuleDecision.id.desc())
            )
        ).all()
    )


async def ended_rows(db: AsyncSession, *, limit: int = HISTORY_MAX) -> list[RuleDecision]:
    """The standing decisions that ended, the newest end first."""
    return list(
        (
            await db.scalars(
                select(RuleDecision)
                .where(
                    RuleDecision.decision == DECISION_STANDING,
                    RuleDecision.ended_at.is_not(None),
                )
                .order_by(RuleDecision.ended_at.desc(), RuleDecision.id.desc())
                .limit(max(1, limit))
            )
        ).all()
    )


__all__ = [
    "CAUSE_ANALYST",
    "CAUSE_EXPIRED",
    "CAUSE_TRUE_POSITIVE",
    "CLOSED_STATES",
    "DECISIONS",
    "DECISION_ACKNOWLEDGE",
    "DECISION_STANDING",
    "DETAIL_TP_PAIRS",
    "HISTORY_MAX",
    "STATES",
    "STATE_ACKNOWLEDGED",
    "STATE_ACKNOWLEDGING",
    "STATE_DONE",
    "STATE_FAILED",
    "STATE_GONE",
    "STATE_OPEN",
    "closed_state_sql",
    "count_acknowledged",
    "end_decision",
    "ended_rows",
    "finish",
    "history",
    "in_force",
    "includes_true_positive_pairs",
    "last_ended",
    "new_decision",
    "record_states",
    "running",
    "settle",
    "standing_rows",
    "standing_true_positive_conds",
    "standing_true_positives",
    "states_for",
]
