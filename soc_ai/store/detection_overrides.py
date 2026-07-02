"""Persistence service for detection overrides (detection tuning).

A :class:`~soc_ai.store.models.DetectionOverride` row is an operator's soft,
reversible suppression of a noisy detection rule — a soc-ai-side ``mute`` that
hides the rule's alerts from the default alerts feed. Nothing here ever touches
Security Onion / Elasticsearch: the override lives only in the local store.

``active`` is the live flag: :func:`list_active` / :func:`muted_rule_names`
return only active rows, and :func:`deactivate` flips it (the row is kept for
audit, never deleted). Mutes are global (no per-host scope) in this MVP.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import DetectionOverride


async def create(
    db: AsyncSession,
    *,
    rule_name: str,
    action: str = "mute",
    reason: str | None = None,
    created_by: str = "anonymous",
) -> DetectionOverride:
    """Create an active override (a soft mute) for ``rule_name``.

    A rule may carry more than one historical override row (each mute/un-mute
    leaves its trail), but only the active rows drive the feed suppression.
    """
    override = DetectionOverride(
        rule_name=rule_name[:512],
        action=action[:16],
        reason=reason[:512] if reason else None,
        created_by=created_by[:128],
        active=True,
    )
    db.add(override)
    await db.commit()
    await db.refresh(override)
    return override


async def list_active(db: AsyncSession) -> list[DetectionOverride]:
    """All currently-active overrides, newest first."""
    rows = await db.scalars(
        select(DetectionOverride)
        .where(DetectionOverride.active.is_(True))
        .order_by(DetectionOverride.created_at.desc(), DetectionOverride.id.desc())
    )
    return list(rows.all())


async def muted_rule_names(db: AsyncSession) -> set[str]:
    """Set of rule names with an active ``mute`` override — the feed suppression list."""
    rows = await db.scalars(
        select(DetectionOverride.rule_name).where(
            DetectionOverride.active.is_(True),
            DetectionOverride.action == "mute",
        )
    )
    return set(rows.all())


async def deactivate(db: AsyncSession, override_id: int) -> bool:
    """Un-mute: flip an override's ``active`` flag to False (kept for audit).

    Returns ``True`` if an active row was deactivated, ``False`` if the id is
    missing or already inactive (idempotent un-mute).
    """
    override = await db.get(DetectionOverride, override_id)
    if override is None or not override.active:
        return False
    override.active = False
    await db.commit()
    return True
