"""Store service for ``quality_snapshots`` — the nightly micro-eval trend (I4).

Tiny, deliberately boring CRUD in the hunt_schedules mould: the CLI writes one
row per ``soc-ai eval-nightly`` run (pruning history in the same transaction),
and the ``GET /api/v1/quality/trend`` read-model lists the newest rows for the
dashboard's Quality card. Everything analytical (metric computation, the
regression rule) lives in :mod:`soc_ai.eval.quality` — this module only moves
rows.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import QualitySnapshot

# How many snapshots survive pruning — ~3 months of nightlies. The table is a
# TREND, not an archive: the full per-run artifacts (bundles, index.jsonl,
# report.md) stay on disk at each row's ``batch_dir``, so pruning a row loses
# only its point on the sparkline.
KEEP_LAST = 90


async def insert_snapshot(
    db: AsyncSession,
    *,
    mode: str,
    n_ok: int,
    n_error: int,
    agreement_rate: float | None,
    fallback_rate: float | None,
    error_rate: float,
    verdict_counts: dict[str, Any],
    latency_p50_ms: int | None,
    batch_dir: str | None,
    alarmed: bool,
    alarm_reasons: list[str] | None,
    keep_last: int = KEEP_LAST,
) -> QualitySnapshot:
    """Insert one nightly snapshot and prune history in the SAME transaction.

    Insert-then-prune in one commit means the table can never be observed
    over-capacity, and a crash between the two statements can't lose the new
    point while keeping stale ones. The prune keeps the newest ``keep_last``
    rows BY ID (the integer PK is insertion-ordered on SQLite, and
    ``created_at`` has only second precision — two same-second inserts would
    tie). ``keep_last`` is parameterized so tests can exercise the prune
    without inserting 90+ rows.
    """
    row = QualitySnapshot(
        mode=mode,
        n_ok=n_ok,
        n_error=n_error,
        agreement_rate=agreement_rate,
        fallback_rate=fallback_rate,
        error_rate=error_rate,
        verdict_counts=verdict_counts,
        latency_p50_ms=latency_p50_ms,
        batch_dir=batch_dir,
        alarmed=alarmed,
        alarm_reasons=alarm_reasons,
    )
    db.add(row)
    # Flush so the new row has its id and is visible to the prune subquery —
    # otherwise a full table could prune everything EXCEPT the newest point.
    await db.flush()
    keep_ids = (
        select(QualitySnapshot.id)
        .order_by(QualitySnapshot.id.desc())
        .limit(keep_last)
        .scalar_subquery()
    )
    await db.execute(delete(QualitySnapshot).where(QualitySnapshot.id.not_in(keep_ids)))
    await db.commit()
    return row


async def recent_snapshots(
    db: AsyncSession,
    *,
    limit: int = 30,
    mode: str | None = None,
) -> list[QualitySnapshot]:
    """Newest-first snapshots, optionally filtered to one measurement mode.

    ``mode`` matters to callers that must not blend the two measurement
    regimes: the regression detector compares a new point ONLY against
    same-mode history (an oracle-graded 0.8 agreement and a local NULL are
    different instruments, not a trend). The dashboard trend passes no mode —
    it renders every point and labels each with its badge.
    """
    stmt = select(QualitySnapshot)
    if mode is not None:
        stmt = stmt.where(QualitySnapshot.mode == mode)
    stmt = stmt.order_by(QualitySnapshot.id.desc()).limit(limit)
    return list((await db.scalars(stmt)).all())
