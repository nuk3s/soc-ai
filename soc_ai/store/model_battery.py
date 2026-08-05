"""Persistence for the model fitness battery (one row per model, newest wins).

See the design spec (docs/superpowers/specs/2026-08-05-model-battery-design.md)
and migration 0022 for the shape rationale.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import ModelBatteryResult


async def upsert(db: AsyncSession, *, model: str, result: dict[str, Any]) -> None:
    """Replace the stored battery result for *model* (insert if first run).

    ``created_at`` is stamped explicitly on replace — the column's
    server_default only fires on INSERT, and the age shown in the UI must be
    the age of THIS measurement, not the first one ever.
    """
    row = await db.get(ModelBatteryResult, model)
    if row is None:
        db.add(ModelBatteryResult(model=model, result=result))
    else:
        row.result = result
        row.created_at = datetime.now(UTC).replace(tzinfo=None)
    await db.commit()


async def get(db: AsyncSession, *, model: str) -> dict[str, Any] | None:
    """The stored battery report for *model*, or None if never probed.

    Returns ``{"result": …, "created_at": ISO-8601}`` — the shape the API
    serves for a persisted (non-live) battery.
    """
    row = (
        await db.execute(select(ModelBatteryResult).where(ModelBatteryResult.model == model))
    ).scalar_one_or_none()
    if row is None:
        return None
    return {"result": row.result, "created_at": row.created_at.isoformat()}


async def upsert_fitness(db: AsyncSession, *, model: str, result: dict[str, Any]) -> None:
    """Cache a quick-fitness result for *model* (row created if first touch).

    The battery's ``result`` column is left alone — independent cadences (see
    migration 0023). NULL-safe on rows created by the battery path.
    """
    row = await db.get(ModelBatteryResult, model)
    now = datetime.now(UTC).replace(tzinfo=None)
    if row is None:
        # `result` is non-nullable; an empty dict marks "no battery run yet"
        # (rendered as absent — the API checks for the configs key).
        db.add(ModelBatteryResult(model=model, result={}, fitness_result=result, fitness_at=now))
    else:
        row.fitness_result = result
        row.fitness_at = now
    await db.commit()


async def get_fitness(db: AsyncSession, *, model: str) -> dict[str, Any] | None:
    """The cached quick-fitness result for *model*, or None if never checked."""
    row = await db.get(ModelBatteryResult, model)
    if row is None or row.fitness_result is None or row.fitness_at is None:
        return None
    return {"result": row.fitness_result, "checked_at": row.fitness_at.isoformat()}
