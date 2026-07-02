"""Persistence service for threat hunts (Hunt Console).

A hunt row is created when a chat-driven hunt starts; events append as the
agent's trace streams; :func:`finalize` lands the narrative + the HuntReport.
Mirrors :mod:`soc_ai.store.investigations` — the hunt is broader (findings +
narrative across hosts/time) but the lifecycle + tee/finalize shape is the same.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from soc_ai.store.auth import utcnow
from soc_ai.store.models import Hunt, HuntEvent

STATUS_RUNNING = "running"


async def create(
    db: AsyncSession,
    *,
    objective: str,
    started_by: str,
    kind: str = "chat",
) -> Hunt:
    hunt = Hunt(
        id=str(ULID()),
        objective=objective,
        started_by=started_by,
        kind=kind[:16],
    )
    db.add(hunt)
    await db.commit()
    await db.refresh(hunt)
    return hunt


async def append_events(db: AsyncSession, hunt_id: str, events: list[dict[str, Any]]) -> None:
    for ev in events:
        db.add(
            HuntEvent(
                hunt_id=hunt_id,
                sequence=int(ev.get("sequence", 0)),
                kind=str(ev.get("kind", ""))[:40],
                payload=ev.get("payload") or {},
            )
        )
    await db.commit()


async def finalize(
    db: AsyncSession,
    hunt_id: str,
    *,
    status: str,
    narrative: str | None = None,
    report: dict[str, Any] | None = None,
) -> None:
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return
    hunt.status = status
    if narrative is not None:
        hunt.narrative = narrative
    if report is not None:
        hunt.report = report
    hunt.finished_at = utcnow()
    await db.commit()


async def get_with_events(
    db: AsyncSession, hunt_id: str
) -> tuple[Hunt, list[HuntEvent]] | None:
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return None
    events = (
        await db.scalars(
            select(HuntEvent)
            .where(HuntEvent.hunt_id == hunt_id)
            .order_by(HuntEvent.sequence, HuntEvent.id)
        )
    ).all()
    return hunt, list(events)


async def list_recent(
    db: AsyncSession,
    *,
    status: str | None = None,
    limit: int = 100,
) -> list[Hunt]:
    """Return hunts ordered by created_at desc, with optional status filter."""
    q = select(Hunt).order_by(Hunt.created_at.desc(), Hunt.id.desc())
    if status is not None:
        q = q.where(Hunt.status == status)
    q = q.limit(limit)
    return list((await db.scalars(q)).all())


async def reap_stale_running(
    db: AsyncSession, *, older_than_minutes: int | None, status: str = "error"
) -> int:
    """Mark orphaned ``running`` hunts terminal. Returns the count.

    ``older_than_minutes=None`` reaps EVERY running row (startup: any row still
    ``running`` was orphaned by the restart); a positive int reaps only rows
    older than that many minutes (periodic sweep). Mirrors the investigation
    reaper: startup uses ``interrupted`` (a clean restart cut the run off, not a
    failure), the periodic sweep uses ``error``.
    """
    q = select(Hunt).where(Hunt.status == STATUS_RUNNING)
    if older_than_minutes is not None:
        cutoff = utcnow() - timedelta(minutes=older_than_minutes)
        q = q.where(Hunt.created_at < cutoff)
    rows = list((await db.scalars(q)).all())
    now = utcnow()
    interrupted = status == "interrupted"
    for hunt in rows:
        hunt.status = status
        hunt.finished_at = now
        if not hunt.narrative:
            hunt.narrative = (
                "Hunt was interrupted by a service restart before it finished — re-run it."
                if interrupted
                else "Hunt did not finish (interrupted by a restart or timed out)."
            )
    if rows:
        await db.commit()
    return len(rows)


async def delete(db: AsyncSession, hunt_id: str) -> bool:
    """Delete a hunt and its events in one transaction.

    Returns True if the hunt existed (and was removed), False otherwise.
    """
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return False
    await db.execute(sa_delete(HuntEvent).where(HuntEvent.hunt_id == hunt_id))
    await db.delete(hunt)
    await db.commit()
    return True
