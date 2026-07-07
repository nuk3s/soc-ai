"""Store helpers for alert ownership assignments.

Each assignment ties a ``rule_name`` to an ``owner`` string
(username or ``token:<name>``) and a human triage ``state``.  One row per rule
— upserted on assign, deleted on unassign.

Triage states: ``owned`` (the default on assign) → ``in_review`` → ``done``.
The fourth conceptual state, ``unassigned``, is the ABSENCE of a row — so a
persisted ``state`` is always one of the three above.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import AlertAssignment

# The persisted triage states (``unassigned`` is the absence of a row, so it is
# never stored). Kept here as the single source of truth for validation.
ASSIGNMENT_STATES: frozenset[str] = frozenset({"owned", "in_review", "done"})


async def set_assignment(db: AsyncSession, rule_name: str, owner: str) -> None:
    """Upsert: set *owner* for *rule_name*, creating the row if absent.

    Assigning (re)sets the triage state to ``owned`` — a fresh owner starts at
    the beginning of the triage flow, and re-assigning an in-review/done rule to
    a new owner resets it too (the new owner hasn't reviewed it yet).
    """
    row = await db.scalar(select(AlertAssignment).where(AlertAssignment.rule_name == rule_name))
    if row is None:
        db.add(AlertAssignment(rule_name=rule_name, owner=owner, state="owned"))
    else:
        row.owner = owner
        row.state = "owned"
        row.assigned_at = datetime.now(UTC).replace(tzinfo=None)
    await db.commit()


async def set_state(db: AsyncSession, rule_name: str, state: str) -> bool:
    """Set the triage *state* on an existing assignment for *rule_name*.

    Returns ``True`` when the state was applied, ``False`` when there is no
    assignment to update (state requires an owner — ``unassigned`` is the
    absence of a row, so there is nothing to set). Raises ``ValueError`` on an
    unknown state.
    """
    if state not in ASSIGNMENT_STATES:
        raise ValueError(f"unknown assignment state: {state!r}")
    row = await db.scalar(select(AlertAssignment).where(AlertAssignment.rule_name == rule_name))
    if row is None:
        return False
    row.state = state
    row.assigned_at = datetime.now(UTC).replace(tzinfo=None)
    await db.commit()
    return True


async def clear_assignment(db: AsyncSession, rule_name: str) -> None:
    """Remove the assignment for *rule_name* (no-op if none exists).

    Removing the row drops the owner AND the state together — the rule returns
    to the ``unassigned`` (no-row) state.
    """
    row = await db.scalar(select(AlertAssignment).where(AlertAssignment.rule_name == rule_name))
    if row is not None:
        await db.delete(row)
        await db.commit()


async def assignments_for_rules(
    db: AsyncSession, rule_names: list[str]
) -> dict[str, dict[str, str]]:
    """Return ``rule_name → {"owner": ..., "state": ...}`` for assigned rules.

    Only rules with an assignment row appear in the mapping; an absent rule is
    ``unassigned`` (the caller treats a missing key as no owner / no state).
    """
    if not rule_names:
        return {}
    rows = (
        await db.scalars(select(AlertAssignment).where(AlertAssignment.rule_name.in_(rule_names)))
    ).all()
    return {row.rule_name: {"owner": row.owner, "state": row.state} for row in rows}


async def owners_for_rules(db: AsyncSession, rule_names: list[str]) -> dict[str, str]:
    """Return a mapping of rule_name → owner for any assigned rules in *rule_names*.

    Thin back-compat wrapper over :func:`assignments_for_rules` for callers that
    only need the owner (the state-aware callers use the richer helper directly).
    """
    return {
        rule: rec["owner"] for rule, rec in (await assignments_for_rules(db, rule_names)).items()
    }
