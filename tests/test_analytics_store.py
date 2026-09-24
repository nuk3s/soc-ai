"""The local analytics tier: create, transition, retire, and the version trail."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from soc_ai.config import Settings
from soc_ai.store import analytics as analytics_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)

SPEC_TEXT = """
id: local-svc-ticket-from-workstation
title: A Kerberos ticket request names a service account from a workstation
description: For the tier tests.
level: high
scope_field: source.ip
scope_kind: host
precondition:
  all:
    - field: event.code
      value: "4769"
detection:
  all:
    - field: event.code
      value: "4769"
"""


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_create_local_starts_as_a_candidate_with_one_version_row(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        state = await analytics_store.create_local(db, spec_text=SPEC_TEXT, by="analyst", now=_NOW)
        versions = await analytics_store.versions(db, state.analytic_id)
    await engine.dispose()
    assert state.analytic_id == "local-svc-ticket-from-workstation"
    assert state.tier == "local" and state.status == "candidate"
    assert [v.to_status for v in versions] == ["candidate"]
    assert versions[0].spec_after == SPEC_TEXT.strip() + "\n"


async def test_a_candidate_cannot_go_straight_to_live(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        state = await analytics_store.create_local(db, spec_text=SPEC_TEXT, by="analyst", now=_NOW)
        with pytest.raises(ValueError):
            await analytics_store.transition(
                db, state.analytic_id, to_status="live", by="analyst", why=None
            )
        state = await analytics_store.transition(
            db, state.analytic_id, to_status="shadow", by="analyst", why="try it"
        )
        state = await analytics_store.transition(
            db,
            state.analytic_id,
            to_status="live",
            by="analyst",
            why="two true hits",
            receipts={"matched_ids": ["d1"]},
        )
        versions = await analytics_store.versions(db, state.analytic_id)
    await engine.dispose()
    assert state.status == "live"
    assert [v.to_status for v in versions] == ["candidate", "shadow", "live"]
    assert versions[-1].receipts_json == {"matched_ids": ["d1"]}


async def test_empty_receipts_are_stored_as_nothing(settings_kratos: Settings) -> None:
    """An empty list is not a receipt. It read as one on the version row.

    The approval reason is the receipts packet. Stored as [], the detail view
    showed an approval that brought evidence and then showed none of it.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        state = await analytics_store.create_local(db, spec_text=SPEC_TEXT, by="analyst", now=_NOW)
        await analytics_store.transition(
            db, state.analytic_id, to_status="shadow", by="analyst", why="try it"
        )
        await analytics_store.transition(
            db,
            state.analytic_id,
            to_status="live",
            by="analyst",
            why="approved",
            receipts=[],
        )
        versions = await analytics_store.versions(db, state.analytic_id)
    await engine.dispose()
    assert versions[-1].receipts_json is None


async def test_the_version_trail_reads_in_the_order_it_was_written(
    settings_kratos: Settings,
) -> None:
    # By id, not by ``at``. A back-dated transition must not reorder the trail
    # an append-only log with one writer already has in order.
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        state = await analytics_store.create_local(db, spec_text=SPEC_TEXT, by="analyst", now=_NOW)
        await analytics_store.transition(
            db, state.analytic_id, to_status="shadow", by="analyst", why="try it", now=_NOW
        )
        await analytics_store.transition(
            db,
            state.analytic_id,
            to_status="live",
            by="analyst",
            why="approved",
            now=_NOW - timedelta(days=2),
        )
        versions = await analytics_store.versions(db, state.analytic_id)
    await engine.dispose()
    assert [v.to_status for v in versions] == ["candidate", "shadow", "live"]
    assert [v.id for v in versions] == sorted(v.id for v in versions)


async def test_retire_shipped_keeps_the_file_and_records_the_reason(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        state = await analytics_store.retire_shipped(
            db,
            "identity-4662-dcsync-nonmachine",
            shipped_text="id: x\n",
            by="analyst",
            why="no domain controller on this grid",
            now=_NOW,
        )
        again = await analytics_store.retire_shipped(
            db,
            "identity-4662-dcsync-nonmachine",
            shipped_text="id: x\n",
            by="analyst",
            why="again",
        )
        versions = await analytics_store.versions(db, state.analytic_id)
    await engine.dispose()
    assert state.tier == "shipped" and state.status == "retired"
    assert again.reason == "no domain controller on this grid"
    assert len(versions) == 1


async def test_a_bad_spec_text_is_refused(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        with pytest.raises(ValueError):
            await analytics_store.create_local(db, spec_text="- not a mapping\n", by="analyst")
    await engine.dispose()


async def test_a_shipped_id_cannot_be_taken_by_a_local_analytic(
    settings_kratos: Settings,
) -> None:
    """A local analytic that wears a shipped id replaced it silently.

    The local row then inherited the shipped analytic's sweep trail, so the
    ledger of the shipped analytic counted runs of the local one.
    """
    engine, maker = await _db(settings_kratos)
    text = SPEC_TEXT.replace(
        "id: local-svc-ticket-from-workstation", "id: identity-4662-dcsync-nonmachine"
    )
    async with maker() as db:
        with pytest.raises(ValueError, match="shipped analytic"):
            await analytics_store.create_local(db, spec_text=text, by="analyst", now=_NOW)
        states = await analytics_store.states(db)
    await engine.dispose()
    assert states == {}
