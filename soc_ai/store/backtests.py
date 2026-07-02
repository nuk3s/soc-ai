"""Persistence service for backtests ("prove it on my last N days").

A backtest row is created when a replay starts; :func:`finalize` lands the
aggregated metrics + per-alert rows and the terminal status. Mirrors
:mod:`soc_ai.store.hunts` / :mod:`soc_ai.store.investigations` — the lifecycle
(running → complete/error) and the finalize/reap shape are the same; a backtest
just carries ``params`` + ``results`` instead of a verdict or a narrative.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from soc_ai.store.auth import utcnow
from soc_ai.store.models import Backtest

STATUS_RUNNING = "running"


async def create(
    db: AsyncSession,
    *,
    params: dict[str, Any],
    started_by: str,
) -> Backtest:
    bt = Backtest(
        id=str(ULID()),
        params=params,
        started_by=started_by,
    )
    db.add(bt)
    await db.commit()
    await db.refresh(bt)
    return bt


async def finalize(
    db: AsyncSession,
    backtest_id: str,
    *,
    status: str,
    sampled: int | None = None,
    results: dict[str, Any] | None = None,
) -> None:
    bt = await db.get(Backtest, backtest_id)
    if bt is None:
        return
    bt.status = status
    if sampled is not None:
        bt.sampled = sampled
    if results is not None:
        bt.results = results
    bt.finished_at = utcnow()
    await db.commit()


async def get(db: AsyncSession, backtest_id: str) -> Backtest | None:
    return await db.get(Backtest, backtest_id)


async def latest(db: AsyncSession) -> Backtest | None:
    """The most recent backtest (running or terminal) — what the console shows by default."""
    rows = (
        await db.scalars(
            select(Backtest).order_by(Backtest.created_at.desc(), Backtest.id.desc()).limit(1)
        )
    ).all()
    return rows[0] if rows else None


async def list_recent(
    db: AsyncSession,
    *,
    status: str | None = None,
    limit: int = 100,
) -> list[Backtest]:
    """Return backtests ordered by created_at desc, with optional status filter."""
    q = select(Backtest).order_by(Backtest.created_at.desc(), Backtest.id.desc())
    if status is not None:
        q = q.where(Backtest.status == status)
    q = q.limit(limit)
    return list((await db.scalars(q)).all())


async def reap_stale_running(
    db: AsyncSession, *, older_than_minutes: int | None, status: str = "error"
) -> int:
    """Mark orphaned ``running`` backtests terminal. Returns the count.

    ``older_than_minutes=None`` reaps EVERY running row (startup: any row still
    ``running`` was orphaned by the restart); a positive int reaps only rows
    older than that many minutes (periodic sweep). Mirrors the investigation /
    hunt reapers.
    """
    q = select(Backtest).where(Backtest.status == STATUS_RUNNING)
    if older_than_minutes is not None:
        cutoff = utcnow() - timedelta(minutes=older_than_minutes)
        q = q.where(Backtest.created_at < cutoff)
    rows = list((await db.scalars(q)).all())
    now = utcnow()
    for bt in rows:
        bt.status = status
        bt.finished_at = now
    if rows:
        await db.commit()
    return len(rows)
