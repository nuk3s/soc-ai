"""The prior sweep's trail: one row per profile spec per run.

Mirrors :mod:`soc_ai.store.hunt_spec_sweeps` deliberately — insert-then-prune
in one commit, pruned per spec by id — so the two loops leave the same shape
of evidence and the Operate panel can read either without a second vocabulary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import PriorSpecRun

if TYPE_CHECKING:  # pragma: no cover
    from soc_ai.hunting.prior_sweep import PriorSweep, ProfileState

__all__ = ["KEEP_LAST_PER_SPEC", "PriorStatus", "catalog_status", "newest", "record_sweep"]

KEEP_LAST_PER_SPEC = 500


async def record_sweep(
    db: AsyncSession,
    sweep: PriorSweep,
    *,
    shadow_ids: frozenset[str],
    now: datetime | None = None,
    keep_last: int = KEEP_LAST_PER_SPEC,
    profiles: ProfileState | None = None,
) -> int:
    """Write one row per spec that was evaluated. Returns how many.

    A spec with no evaluations at all (nothing recent on its dimension) still
    gets a row of zeros: that is a fact about this run — "there was nothing to
    score" — and omitting it would make the spec look never-run.

    ``shadow_ids`` is the set of specs the sweep ran in shadow, the same set
    the observations were written under. It has no default. A default of
    ``True`` marked every row of a live prior as shadow, so the catalog
    reported live priors as shadow for weeks.

    Each row carries the blind reason of its spec, when the sweep has one.
    See :func:`soc_ai.hunting.prior_sweep.blind_reasons`.
    """
    from soc_ai.hunting.prior_sweep import clip_reason  # noqa: PLC0415 - lazy, avoids a cycle

    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    reasons = sweep.blind_reasons()
    per_spec: dict[str, dict[str, int]] = {}
    for r in sweep.results:
        bucket = per_spec.setdefault(
            r.spec_id, {"measured": 0, "learning": 0, "blind": 0, "not_applicable": 0, "fired": 0}
        )
        # A detector state outside the four columns folds into one of them.
        # Counted under its own name, it was written to no column at all.
        bucket[r.trail_state] = bucket.get(r.trail_state, 0) + 1
        if r.fired:
            bucket["fired"] += 1
    for spec_id in sweep.evaluated_specs:
        per_spec.setdefault(
            spec_id, {"measured": 0, "learning": 0, "blind": 0, "not_applicable": 0, "fired": 0}
        )

    written = 0
    for spec_id, c in per_spec.items():
        db.add(
            PriorSpecRun(
                created_at=at,
                spec_id=spec_id,
                shadow=spec_id in shadow_ids,
                measured=c["measured"],
                learning=c["learning"],
                blind=c["blind"],
                not_applicable=c["not_applicable"],
                fired=c["fired"],
                profiles_built_at=profiles.built_at if profiles else None,
                profiles_stale=bool(profiles.stale) if profiles else False,
                profiles_reason=(profiles.reason or None) if profiles else None,
                blind_reason=clip_reason(reasons.get(spec_id)),
            )
        )
        written += 1
    await db.flush()
    for spec_id in per_spec:
        keep = (
            select(PriorSpecRun.id)
            .where(PriorSpecRun.spec_id == spec_id)
            .order_by(PriorSpecRun.id.desc())
            .limit(keep_last)
            .scalar_subquery()
        )
        await db.execute(
            delete(PriorSpecRun).where(
                PriorSpecRun.spec_id == spec_id, PriorSpecRun.id.not_in(keep)
            )
        )
    await db.commit()
    return written


async def newest(db: AsyncSession) -> dict[str, PriorSpecRun]:
    """The newest row per spec. A never-run spec is ABSENT, not zeroed."""
    ids = select(func.max(PriorSpecRun.id)).group_by(PriorSpecRun.spec_id)
    rows = (await db.scalars(select(PriorSpecRun).where(PriorSpecRun.id.in_(ids)))).all()
    return {r.spec_id: r for r in rows}


# The same rate window the catalog sweep's trail reports over.
STATUS_WINDOW = timedelta(hours=24)


@dataclass(frozen=True)
class PriorStatus:
    """What the prior sweep's trail says about one profile spec.

    The catalog page read a profile spec's ``last_swept_at`` and ``last_error``
    from the catalog sweep's table. That loop stopped running profile specs on
    2026-09-15, so every prior showed the last error of that loop, dated that
    day, under an hourly sweep that was running fine. This is the trail of the
    loop that does run them. It records no error column: a prior sweep that
    fails part-way records its errors in the log, and the rows it does write
    are runs that completed.
    """

    last_run_at: datetime
    last_fired_at: datetime | None
    runs_24h: int
    fired_24h: int
    shadow_24h: int


async def catalog_status(db: AsyncSession, *, now: datetime) -> dict[str, PriorStatus]:
    """Per-spec status for every profile spec with at least one run.

    A never-run spec is ABSENT, for the reason :func:`newest` gives.
    """
    last = {
        spec_id: at
        for spec_id, at in (
            await db.execute(
                select(PriorSpecRun.spec_id, func.max(PriorSpecRun.created_at)).group_by(
                    PriorSpecRun.spec_id
                )
            )
        ).all()
    }
    if not last:
        return {}
    fired_at = {
        spec_id: at
        for spec_id, at in (
            await db.execute(
                select(PriorSpecRun.spec_id, func.max(PriorSpecRun.created_at))
                .where(PriorSpecRun.fired > 0)
                .group_by(PriorSpecRun.spec_id)
            )
        ).all()
    }
    cutoff = now - STATUS_WINDOW
    windowed = {
        spec_id: (int(runs or 0), int(fired or 0), int(shadow or 0))
        for spec_id, runs, fired, shadow in (
            await db.execute(
                select(
                    PriorSpecRun.spec_id,
                    func.count(),
                    func.sum(case((PriorSpecRun.fired > 0, 1), else_=0)),
                    func.sum(case((PriorSpecRun.shadow.is_(True), 1), else_=0)),
                )
                .where(PriorSpecRun.created_at >= cutoff)
                .group_by(PriorSpecRun.spec_id)
            )
        ).all()
    }
    out: dict[str, PriorStatus] = {}
    for spec_id, at in last.items():
        runs, fired, shadow = windowed.get(spec_id, (0, 0, 0))
        out[str(spec_id)] = PriorStatus(
            last_run_at=at,
            last_fired_at=fired_at.get(spec_id),
            runs_24h=runs,
            fired_24h=fired,
            shadow_24h=shadow,
        )
    return out
