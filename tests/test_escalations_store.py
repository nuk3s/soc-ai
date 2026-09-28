"""The escalation ledger: soc-ai's own record of which alerts are on a case.

The point of the table is that the claim and the guard are the same write. A
read-then-write check has a window, and two operators escalating overlapping
groups land in it; the unique index does not.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from soc_ai.config import Settings
from soc_ai.store import escalations as esc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect, text

pytestmark = pytest.mark.asyncio


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_migration_creates_the_ledger(settings_kratos: Settings) -> None:
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "alert_escalations" in tables
        indexes = await conn.run_sync(lambda sc: inspect(sc).get_indexes("alert_escalations"))
        by_name = {ix["name"]: ix for ix in indexes}
        assert by_name["ix_alert_escalations_alert_id"]["unique"], (
            "without the unique index the claim is a suggestion, not a guard"
        )
        # A SECOND head canary, despite the note in tests/test_hunts_store.py
        # claiming the repo keeps exactly one. Bump both when a migration lands.
        row = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert row.scalar_one() == "0051"
    await engine.dispose()


async def test_a_second_claim_on_the_same_alert_is_refused(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        claimed, already = await esc.claim(db, ["a-1", "a-2"], actor="analyst")
        assert claimed == ["a-1", "a-2"]
        assert already == []

        claimed, already = await esc.claim(db, ["a-2", "a-3"], actor="other")
        assert claimed == ["a-3"], "a-2 was already held"
        assert already == ["a-2"]


async def test_a_collision_does_not_roll_back_the_claims_beside_it(
    settings_kratos: Settings,
) -> None:
    """One taken alert in a group must not cost the operator the rest of it."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await esc.claim(db, ["held"], actor="first")
        claimed, already = await esc.claim(db, ["new-1", "held", "new-2"], actor="second")
        assert claimed == ["new-1", "new-2"]
        assert already == ["held"]
        assert set(await esc.cases_for_alerts(db, ["new-1", "new-2", "held"])) == {
            "new-1",
            "new-2",
            "held",
        }


async def test_two_concurrent_claims_split_the_alerts_between_them(
    settings_kratos: Settings,
) -> None:
    """Two operators escalating overlapping groups at once. Every alert goes to
    exactly one of them, so the overlap opens one case, not two."""
    _engine, maker = await _db(settings_kratos)
    overlap = [f"ev-{i}" for i in range(6)]

    async def press(actor: str) -> list[str]:
        async with maker() as db:
            claimed, _already = await esc.claim(db, overlap, actor=actor)
            return claimed

    first, second = await asyncio.gather(press("analyst-a"), press("analyst-b"))

    assert sorted(first + second) == overlap
    assert not set(first) & set(second), "the same alert was claimed twice"


async def test_the_case_id_is_written_onto_the_claim(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await esc.claim(db, ["a-1"], actor="analyst")
        assert await esc.cases_for_alerts(db, ["a-1"]) == {"a-1": None}
        assert esc.unresolved({"a-1": None}) == ["a-1"]

        await esc.record_case(db, "a-1", "case-7")
        assert await esc.cases_for_alerts(db, ["a-1"]) == {"a-1": "case-7"}
        assert esc.unresolved({"a-1": "case-7"}) == []


async def test_the_first_case_an_alert_reached_is_the_one_kept(
    settings_kratos: Settings,
) -> None:
    """A skip is justified by a case that exists. Letting a later write move the
    answer would make the ledger point at whichever duplicate landed last."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await esc.claim(db, ["a-1"], actor="analyst")
        await esc.record_case(db, "a-1", "case-first")
        await esc.record_case(db, "a-1", "case-second")
        assert await esc.cases_for_alerts(db, ["a-1"]) == {"a-1": "case-first"}


async def test_recording_a_case_for_an_unclaimed_alert_does_nothing(
    settings_kratos: Settings,
) -> None:
    """Negative control. ``record_case`` resolves a claim; it must never be a
    back door that inserts one, or a caller could mark an alert escalated
    without ever having reserved it."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await esc.record_case(db, "never-claimed", "case-9")
        assert await esc.cases_for_alerts(db, ["never-claimed"]) == {}


async def test_the_ledger_offers_no_way_to_record_a_case_without_claiming_it(
    settings_kratos: Settings,
) -> None:
    """The single-alert escalate used to record its case here after the fact,
    which is a report rather than a reservation: it could not collide with a
    group escalate opening a case for the same alert in the same instant. Both
    paths claim first now, and the helper that let one of them skip that is
    gone, so the next escalate path cannot quietly be written the old way."""
    assert not hasattr(esc, "remember")


async def test_releasing_a_claim_frees_the_alert_to_be_escalated(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await esc.claim(db, ["a-1", "a-2"], actor="analyst")
        await esc.release(db, ["a-1"])
        assert await esc.cases_for_alerts(db, ["a-1", "a-2"]) == {"a-2": None}
        claimed, already = await esc.claim(db, ["a-1"], actor="analyst")
        assert claimed == ["a-1"]
        assert already == []


# ---------------------------------------------------------------------------
# stranded(): the only reader here that is not keyed by a list of alert ids.
#
# Every other reader takes the ids the caller already has, which is what the
# press path needs and no use at all for "what is this table holding". So a
# claim that never got its answer could only be found by opening the database,
# while it went on refusing every escalate of its alert.


async def _age(maker, alert_id: str, *, minutes: int) -> None:  # type: ignore[no-untyped-def]
    """Backdate a claim, since ``claim`` always stamps it now."""
    async with maker() as db:
        await db.execute(
            text(
                "UPDATE alert_escalations "
                "SET created_at = datetime('now', :delta) WHERE alert_id = :a"
            ),
            {"delta": f"-{minutes} minutes", "a": alert_id},
        )
        await db.commit()


async def test_a_claim_that_never_got_an_answer_can_be_found(settings_kratos: Settings) -> None:
    """The whole defect. Reconciliation is lazy and press-scoped, so a claim
    whose alert has left the queue is permanent — and it was invisible."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await esc.claim(db, ["a-stuck"], actor="analyst")
    await _age(maker, "a-stuck", minutes=90)

    async with maker() as db:
        rows, total = await esc.stranded(db, now=datetime.now(UTC).replace(tzinfo=None))
    assert [r.alert_id for r in rows] == ["a-stuck"]
    assert (total, rows[0].escalated_by) == (1, "analyst")


async def test_a_settled_or_fresh_claim_is_not_stranded(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL, and it is two controls, not one.

    A claim that reached a case is a working escalate. A claim taken seconds
    ago is a request in flight — the ledger is deliberately claim-first, so
    reporting those would call the healthy path broken on every press, which is
    the fastest way to make the panel ignorable.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await esc.claim(db, ["a-settled", "a-fresh"], actor="analyst")
        await esc.record_case(db, "a-settled", "case-1")
    # Old enough to be stranded if it were still open. It is not.
    await _age(maker, "a-settled", minutes=90)

    async with maker() as db:
        rows, total = await esc.stranded(db, now=datetime.now(UTC).replace(tzinfo=None))
    assert (rows, total) == ([], 0)


async def test_the_oldest_stranded_claims_come_first(settings_kratos: Settings) -> None:
    """Oldest first, because a stranded claim does not improve with age.

    Newest-first would put the claims most likely to still resolve on their own
    at the top of a capped list, and push the alert that has been unescalatable
    longest off the bottom.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await esc.claim(db, ["a-recent", "a-ancient", "a-middle"], actor="analyst")
    await _age(maker, "a-recent", minutes=30)
    await _age(maker, "a-middle", minutes=600)
    await _age(maker, "a-ancient", minutes=6000)

    async with maker() as db:
        rows, _total = await esc.stranded(db, now=datetime.now(UTC).replace(tzinfo=None))
    assert [r.alert_id for r in rows] == ["a-ancient", "a-middle", "a-recent"]


async def test_the_stranded_count_is_the_whole_set_not_the_page(
    settings_kratos: Settings,
) -> None:
    """The cap is silent unless the total is counted separately.

    ``len(rows)`` as the total is the same under-report the surface exists to
    end: a ledger holding two hundred stuck claims would report the size of the
    list that fitted on screen and read as a small, manageable problem.
    """
    _engine, maker = await _db(settings_kratos)
    ids = [f"a-{i:03d}" for i in range(12)]
    async with maker() as db:
        await esc.claim(db, ids, actor="analyst")
    for alert_id in ids:
        await _age(maker, alert_id, minutes=90)

    async with maker() as db:
        rows, total = await esc.stranded(db, now=datetime.now(UTC).replace(tzinfo=None), limit=5)
    assert len(rows) == 5
    assert total == 12, "the total must count the whole set, not the page"


async def test_empty_input_touches_nothing(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await esc.claim(db, [], actor="analyst") == ([], [])
        assert await esc.claim(db, ["", ""], actor="analyst") == ([], [])
        assert await esc.cases_for_alerts(db, []) == {}
        await esc.release(db, [])
