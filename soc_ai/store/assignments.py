"""Store helpers for alert ownership assignments.

Each assignment ties a ``rule_name`` to an ``owner`` string
(username or ``token:<name>``).  One row per rule — upserted on assign,
deleted on unassign.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import AlertAssignment


async def set_assignment(db: AsyncSession, rule_name: str, owner: str) -> None:
    """Upsert: set *owner* for *rule_name*, creating the row if absent."""
    row = await db.scalar(select(AlertAssignment).where(AlertAssignment.rule_name == rule_name))
    if row is None:
        db.add(AlertAssignment(rule_name=rule_name, owner=owner))
    else:
        row.owner = owner
        row.assigned_at = datetime.now(UTC).replace(tzinfo=None)
    await db.commit()


async def clear_assignment(db: AsyncSession, rule_name: str) -> None:
    """Remove the assignment for *rule_name* (no-op if none exists)."""
    row = await db.scalar(select(AlertAssignment).where(AlertAssignment.rule_name == rule_name))
    if row is not None:
        await db.delete(row)
        await db.commit()


async def owners_for_rules(db: AsyncSession, rule_names: list[str]) -> dict[str, str]:
    """Return a mapping of rule_name → owner for any assigned rules in *rule_names*."""
    if not rule_names:
        return {}
    rows = (
        await db.scalars(select(AlertAssignment).where(AlertAssignment.rule_name.in_(rule_names)))
    ).all()
    return {row.rule_name: row.owner for row in rows}
