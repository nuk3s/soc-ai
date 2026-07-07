"""Persistence + due-time query for recurring hunt schedules (E3.1).

A :class:`~soc_ai.store.models.HuntSchedule` row is one recurring hunt: an
``objective`` re-run every ``interval_minutes``. The in-process
``_hunt_schedule_loop`` (see :mod:`soc_ai.main`) polls :func:`due_schedules` each
wake and, when the master switch is on, spawns a normal hunt tagged
``kind="scheduled"`` for each, then calls :func:`mark_ran` to reset the interval
clock (the loop's single-flight guard).

Small-table CRUD in the runbooks/store mould (create / list_all / get / update /
delete), plus the two loop helpers (:func:`due_schedules`, :func:`mark_ran`). All
timestamps are naive UTC (SQLite has no tz type); :func:`soc_ai.store.auth.utcnow`
is the one producer of comparison values.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.auth import utcnow
from soc_ai.store.models import HuntSchedule

# A schedule fires by re-spawning a full hunt; spawning stamps ``last_run_at``
# immediately, so the interval doubles as the single-flight window. It MUST be
# ≥ a hunt's own runtime or a schedule could re-fire while its prior run is still
# going. 60 minutes is the sane floor (matches the nightly/hourly cadence the
# feature is for); shorter intervals are clamped up here, not rejected.
MIN_INTERVAL_MINUTES = 60


def _clamp_interval(minutes: int) -> int:
    """Floor the interval at :data:`MIN_INTERVAL_MINUTES` (never below)."""
    return max(int(minutes), MIN_INTERVAL_MINUTES)


# ── CRUD ─────────────────────────────────────────────────────────────────────


async def create(
    db: AsyncSession,
    *,
    objective: str,
    interval_minutes: int = MIN_INTERVAL_MINUTES,
    enabled: bool = True,
    created_by: str = "anonymous",
) -> HuntSchedule:
    """Create a schedule. ``interval_minutes`` is floored at the sane minimum."""
    schedule = HuntSchedule(
        objective=objective,
        interval_minutes=_clamp_interval(interval_minutes),
        enabled=enabled,
        created_by=created_by[:128],
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return schedule


async def get(db: AsyncSession, schedule_id: int) -> HuntSchedule | None:
    return await db.get(HuntSchedule, schedule_id)


async def list_all(db: AsyncSession, *, limit: int = 500) -> list[HuntSchedule]:
    """All schedules, most-recently-created first."""
    rows = await db.scalars(
        select(HuntSchedule)
        .order_by(HuntSchedule.created_at.desc(), HuntSchedule.id.desc())
        .limit(limit)
    )
    return list(rows.all())


async def update(
    db: AsyncSession,
    schedule_id: int,
    *,
    objective: str | None = None,
    interval_minutes: int | None = None,
    enabled: bool | None = None,
) -> HuntSchedule | None:
    """Patch the given fields (``None`` = leave unchanged). Returns the row or None."""
    schedule = await db.get(HuntSchedule, schedule_id)
    if schedule is None:
        return None
    if objective is not None:
        schedule.objective = objective
    if interval_minutes is not None:
        schedule.interval_minutes = _clamp_interval(interval_minutes)
    if enabled is not None:
        schedule.enabled = enabled
    await db.commit()
    await db.refresh(schedule)
    return schedule


async def delete(db: AsyncSession, schedule_id: int) -> bool:
    """Hard-delete a schedule. Returns True if it existed."""
    schedule = await db.get(HuntSchedule, schedule_id)
    if schedule is None:
        return False
    await db.delete(schedule)
    await db.commit()
    return True


# ── Loop helpers ─────────────────────────────────────────────────────────────


async def due_schedules(db: AsyncSession, now: datetime | None = None) -> list[HuntSchedule]:
    """Enabled schedules whose interval has elapsed (or that never ran).

    A schedule is DUE when ``enabled`` AND (``last_run_at is None`` OR
    ``last_run_at + interval_minutes <= now``). ``now`` defaults to
    :func:`utcnow` (naive UTC); pass it explicitly in tests for determinism.
    Ordered oldest-first so a backlog fires in a stable order.
    """
    now = now or utcnow()
    rows = (
        await db.scalars(
            select(HuntSchedule).where(HuntSchedule.enabled.is_(True)).order_by(HuntSchedule.id)
        )
    ).all()
    out: list[HuntSchedule] = []
    for s in rows:
        if s.last_run_at is None:
            out.append(s)
            continue
        if s.last_run_at + timedelta(minutes=s.interval_minutes) <= now:
            out.append(s)
    return out


async def mark_ran(db: AsyncSession, schedule_id: int, now: datetime | None = None) -> None:
    """Stamp ``last_run_at`` — the interval clock reset + single-flight guard.

    Called the moment the loop SPAWNS a hunt for this schedule (not on hunt
    completion), so the same schedule can't re-fire on the next wake until the
    interval elapses again. No-op if the row vanished (deleted mid-loop).
    """
    schedule = await db.get(HuntSchedule, schedule_id)
    if schedule is None:
        return
    schedule.last_run_at = now or utcnow()
    await db.commit()
