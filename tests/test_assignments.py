"""Tests for the alert-assignment store service (E2.3 triage state).

Exercises set_assignment / set_state / assignments_for_rules / owners_for_rules /
clear_assignment against a real SQLite file migrated to head (which proves the
0015 assignment_state migration applies). Uses the ``settings_kratos`` fixture,
isolated per-test by the autouse ``clean_env`` fixture.
"""

from __future__ import annotations

import pytest
from soc_ai.config import Settings
from soc_ai.store import assignments as assign_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_set_assignment_defaults_to_owned(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await assign_svc.set_assignment(db, "ET RULE A", "alice")
    async with maker() as db:
        recs = await assign_svc.assignments_for_rules(db, ["ET RULE A"])
    assert recs["ET RULE A"] == {"owner": "alice", "state": "owned"}
    await engine.dispose()


async def test_set_state_persists(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await assign_svc.set_assignment(db, "ET RULE B", "bob")
        applied = await assign_svc.set_state(db, "ET RULE B", "in_review")
    assert applied is True
    async with maker() as db:
        recs = await assign_svc.assignments_for_rules(db, ["ET RULE B"])
    assert recs["ET RULE B"] == {"owner": "bob", "state": "in_review"}
    await engine.dispose()


async def test_set_state_no_row_returns_false(settings_kratos: Settings) -> None:
    """State requires an owner: setting state on an unassigned rule is a no-op."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        applied = await assign_svc.set_state(db, "ET NEVER ASSIGNED", "done")
    assert applied is False
    await engine.dispose()


async def test_set_state_rejects_unknown_state(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await assign_svc.set_assignment(db, "ET RULE C", "carol")
        with pytest.raises(ValueError):
            await assign_svc.set_state(db, "ET RULE C", "unassigned")
        with pytest.raises(ValueError):
            await assign_svc.set_state(db, "ET RULE C", "bogus")
    await engine.dispose()


async def test_reassign_resets_state_to_owned(settings_kratos: Settings) -> None:
    """Re-assigning an in-review rule to a new owner resets the triage state."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await assign_svc.set_assignment(db, "ET RULE D", "dan")
        await assign_svc.set_state(db, "ET RULE D", "in_review")
        await assign_svc.set_assignment(db, "ET RULE D", "erin")
    async with maker() as db:
        recs = await assign_svc.assignments_for_rules(db, ["ET RULE D"])
    assert recs["ET RULE D"] == {"owner": "erin", "state": "owned"}
    await engine.dispose()


async def test_clear_removes_owner_and_state(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await assign_svc.set_assignment(db, "ET RULE E", "frank")
        await assign_svc.set_state(db, "ET RULE E", "done")
        await assign_svc.clear_assignment(db, "ET RULE E")
    async with maker() as db:
        recs = await assign_svc.assignments_for_rules(db, ["ET RULE E"])
    assert "ET RULE E" not in recs  # absence of a row == unassigned
    await engine.dispose()


async def test_owners_for_rules_backcompat(settings_kratos: Settings) -> None:
    """owners_for_rules stays a thin owner-only wrapper over the state-aware lookup."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await assign_svc.set_assignment(db, "ET RULE F", "gina")
        await assign_svc.set_state(db, "ET RULE F", "in_review")
    async with maker() as db:
        owners = await assign_svc.owners_for_rules(db, ["ET RULE F", "ET UNSEEN"])
    assert owners == {"ET RULE F": "gina"}
    await engine.dispose()


async def test_assignments_for_rules_empty_input(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await assign_svc.assignments_for_rules(db, []) == {}
    await engine.dispose()
