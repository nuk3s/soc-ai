"""The prior sweep's trail: one row per profile spec per run.

Mirrors :mod:`soc_ai.store.hunt_spec_sweeps` deliberately — insert-then-prune
in one commit, pruned per spec by id — so the two loops leave the same shape
of evidence and the Operate panel can read either without a second vocabulary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import PriorSpecRun

if TYPE_CHECKING:  # pragma: no cover
    from soc_ai.hunting.prior_sweep import PriorSweep

__all__ = ["KEEP_LAST_PER_SPEC", "newest", "record_sweep"]

KEEP_LAST_PER_SPEC = 500


async def record_sweep(
    db: AsyncSession,
    sweep: PriorSweep,
    *,
    shadow: bool = True,
    now: datetime | None = None,
    keep_last: int = KEEP_LAST_PER_SPEC,
) -> int:
    """Write one row per spec that was evaluated. Returns how many.

    A spec with no evaluations at all (nothing recent on its dimension) still
    gets a row of zeros: that is a fact about this run — "there was nothing to
    score" — and omitting it would make the spec look never-run.
    """
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    per_spec: dict[str, dict[str, int]] = {}
    for r in sweep.results:
        bucket = per_spec.setdefault(
            r.spec_id, {"measured": 0, "learning": 0, "blind": 0, "not_applicable": 0, "fired": 0}
        )
        bucket[r.coverage] = bucket.get(r.coverage, 0) + 1
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
                shadow=shadow,
                measured=c["measured"],
                learning=c["learning"],
                blind=c["blind"],
                not_applicable=c["not_applicable"],
                fired=c["fired"],
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
