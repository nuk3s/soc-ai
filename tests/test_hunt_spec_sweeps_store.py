"""The sweep trail: one row per spec per sweep, including the sweeps that saw nothing.

Before this table a clean sweep left no trace, so "did spec X run and see
nothing" had no answer — the same hole ``dossier_run`` closed for the network
sweep. The tests here hold three things: the row is written for a CLEAN run
(the whole point), the prune keeps the table bounded in the same transaction as
the insert, and ``catalog_status`` derives the per-spec facts an operator reads
without conflating a visibility-gap hunt with a firing or a shadow run with a
live one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from soc_ai.config import Settings
from soc_ai.hunting.execute import Candidate, SpecRun
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.hunt_spec_sweeps import KEEP_LAST_PER_SPEC, catalog_status, recent, record
from soc_ai.store.models import HuntSpecSweep
from sqlalchemy import inspect, select

pytestmark = pytest.mark.asyncio

NOW = datetime(2026, 9, 4, 17, 0, tzinfo=UTC).replace(tzinfo=None)
SPEC = "identity-4662-dcsync-nonmachine"
OTHER = "decoy-opencanary-interaction"


@pytest_asyncio.fixture
async def engine(settings_kratos: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def session(engine):  # type: ignore[no-untyped-def]
    async with make_sessionmaker(engine)() as s:
        yield s


def _candidate(scope: str) -> Candidate:
    return Candidate(
        spec_id=SPEC,
        scope_key=scope,
        scope_kind="user",
        doc_count=1,
        sample_ids=("idA",),
        anchor_id="idA",
        anchor_index=".ds-a",
        first_seen=None,
        last_seen=None,
    )


def _run(spec_id: str = SPEC, **over: Any) -> SpecRun:
    base: dict[str, Any] = {
        "spec_id": spec_id,
        "since": "now-1440m",
        "until": "now",
        "blind": False,
        "precondition_docs": 47,
        "matched_docs": 0,
    }
    base.update(over)
    return SpecRun(**base)


async def _record(
    session: Any,
    *,
    spec_id: str = SPEC,
    now: datetime = NOW,
    hunt_id: str | None = None,
    shadow: bool = False,
    keep_last: int = KEEP_LAST_PER_SPEC,
    **over: Any,
) -> HuntSpecSweep:
    return await record(
        session,
        spec_id=spec_id,
        run=_run(spec_id, **over),
        hunt_id=hunt_id,
        shadow=shadow,
        since="now-1440m",
        until="now",
        now=now,
        keep_last=keep_last,
    )


async def _rows(session: Any) -> list[HuntSpecSweep]:
    return list((await session.execute(select(HuntSpecSweep).order_by(HuntSpecSweep.id))).scalars())


# ---------------------------------------------------------------------------
# Migration 0034 + the ORM model
# ---------------------------------------------------------------------------


async def test_migration_creates_the_table_and_its_index(engine) -> None:  # type: ignore[no-untyped-def]
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "hunt_spec_sweeps" in tables
        indexes = await conn.run_sync(lambda sc: inspect(sc).get_indexes("hunt_spec_sweeps"))
    by_name = {ix["name"]: ix["column_names"] for ix in indexes}
    assert by_name["ix_hunt_spec_sweeps_spec_created"] == ["spec_id", "created_at"]


async def test_orm_model_matches_the_migrated_schema(engine) -> None:  # type: ignore[no-untyped-def]
    """Where they drift, autogenerate proposes dropping what it cannot see."""
    async with engine.connect() as conn:
        cols = await conn.run_sync(lambda sc: inspect(sc).get_columns("hunt_spec_sweeps"))
    assert {c["name"] for c in cols} == {c.name for c in HuntSpecSweep.__table__.columns}


async def test_every_counter_defaults_to_zero_at_the_database(engine) -> None:  # type: ignore[no-untyped-def]
    """A raw insert naming only the identity columns must not fail on a NOT NULL.

    That is what makes the migration clean against any writer that predates a
    counter — the ``DossierRun`` columns were added the same way.
    """
    async with make_sessionmaker(engine)() as s:
        s.add(HuntSpecSweep(spec_id=SPEC, window_since="a", window_until="b"))
        await s.commit()
        (row,) = await _rows(s)
    assert row.shadow is False
    assert row.blind is False
    assert row.error is None
    assert row.hunt_id is None
    assert (
        row.precondition_docs,
        row.matched_docs,
        row.fresh_candidates,
        row.already_handled,
        row.over_budget,
        row.truncated_docs,
        row.unattributed_docs,
        row.undecided_docs,
    ) == (0, 0, 0, 0, 0, 0, 0, 0)
    assert row.created_at is not None


# ---------------------------------------------------------------------------
# record(): insert + prune, one transaction
# ---------------------------------------------------------------------------


async def test_a_clean_sweep_leaves_a_row(session) -> None:  # type: ignore[no-untyped-def]
    """The entire point. A spec that ran and saw nothing must be distinguishable
    from a spec that never ran."""
    await _record(session)
    (row,) = await _rows(session)
    assert row.spec_id == SPEC
    assert row.blind is False
    assert row.error is None
    assert row.shadow is False
    assert row.hunt_id is None
    assert row.fresh_candidates == 0
    assert row.precondition_docs == 47
    assert row.matched_docs == 0
    assert row.created_at == NOW
    assert (row.window_since, row.window_until) == ("now-1440m", "now")


async def test_the_row_carries_every_counter_the_run_computed(session) -> None:  # type: ignore[no-untyped-def]
    await _record(
        session,
        hunt_id="01HUNT",
        matched_docs=9,
        candidates=[_candidate("a"), _candidate("b")],
        truncated_docs=3,
        unattributed_docs=4,
        undecided_docs=7,
        gate_already_handled=5,
        gate_over_budget=6,
    )
    (row,) = await _rows(session)
    assert row.hunt_id == "01HUNT"
    assert row.matched_docs == 9
    assert row.fresh_candidates == 2, "fresh is the candidate list that SURVIVED the gate"
    assert row.truncated_docs == 3
    assert row.unattributed_docs == 4
    assert row.undecided_docs == 7, (
        "a run that could not evaluate its exclusions leaves a row that reads clean"
    )
    assert row.already_handled == 5
    assert row.over_budget == 6


async def test_a_blind_or_errored_run_is_recorded_as_such(session) -> None:  # type: ignore[no-untyped-def]
    await _record(session, blind=True, precondition_docs=0, hunt_id="01GAP")
    await _record(session, spec_id=OTHER, error="ConnectionError: grid down")
    blind, errored = await _rows(session)
    assert blind.blind is True
    assert blind.hunt_id == "01GAP", "the visibility-gap hunt is linked like any other"
    assert errored.error == "ConnectionError: grid down"
    assert errored.blind is False


async def test_insert_and_prune_keep_the_newest_rows_of_that_spec(session) -> None:  # type: ignore[no-untyped-def]
    """Insert-then-prune in one commit: the table can never be observed over
    capacity, and a crash between the two cannot lose the new point while
    keeping stale ones."""
    for i in range(5):
        await _record(session, now=NOW + timedelta(hours=i), keep_last=3)
    rows = await _rows(session)
    assert [r.created_at for r in rows] == [NOW + timedelta(hours=i) for i in (2, 3, 4)]


async def test_another_specs_rows_cannot_evict_this_specs_last_firing(session) -> None:  # type: ignore[no-untyped-def]
    """The prune is PER SPEC, so retention does not depend on catalog size.

    A global "newest N across the table" cap let a spec that fired once and
    then swept clean lose its firing to OTHER specs' clean rows — and the more
    specs in the catalog, the sooner. ``last_fired_at`` going null is exactly
    what the status docstring promises will not happen a day later.
    """
    await _record(session, now=NOW, hunt_id="01FIRED", candidates=[_candidate("a")], keep_last=3)
    for i in range(1, 6):
        await _record(session, spec_id=OTHER, now=NOW + timedelta(hours=i), keep_last=3)
    rows = await _rows(session)
    assert [r.spec_id for r in rows] == [SPEC, OTHER, OTHER, OTHER], (
        "the other spec is pruned to its own newest three; this spec keeps its one row"
    )
    status = await catalog_status(session, now=NOW + timedelta(hours=5))
    assert status[SPEC].last_fired_at == NOW


async def test_the_default_retention_is_about_three_weeks_for_every_spec() -> None:
    """One spec hourly is 24 rows a day; 500 rows is ~21 days of trail, and the
    arithmetic holds no matter how many specs share the table."""
    assert KEEP_LAST_PER_SPEC == 500
    assert 14 <= KEEP_LAST_PER_SPEC / 24 <= 30


# ---------------------------------------------------------------------------
# recent()
# ---------------------------------------------------------------------------


async def test_recent_is_newest_first_and_filters_by_spec(session) -> None:  # type: ignore[no-untyped-def]
    await _record(session, spec_id=SPEC, now=NOW)
    await _record(session, spec_id=OTHER, now=NOW + timedelta(hours=1))
    await _record(session, spec_id=SPEC, now=NOW + timedelta(hours=2))
    rows = await recent(session)
    assert [(r.spec_id, r.created_at) for r in rows] == [
        (SPEC, NOW + timedelta(hours=2)),
        (OTHER, NOW + timedelta(hours=1)),
        (SPEC, NOW),
    ]
    assert [r.spec_id for r in await recent(session, spec_id=OTHER)] == [OTHER]
    assert len(await recent(session, limit=1)) == 1


# ---------------------------------------------------------------------------
# catalog_status()
# ---------------------------------------------------------------------------


async def test_a_never_swept_spec_is_absent_from_status(session) -> None:  # type: ignore[no-untyped-def]
    """Absent, not zeroed: the route joins the catalog and renders nulls, and a
    fabricated zero row here would read as 'swept, saw nothing'."""
    await _record(session, spec_id=SPEC)
    status = await catalog_status(session, now=NOW)
    assert set(status) == {SPEC}


async def test_status_reads_the_live_facts_off_the_newest_row(session) -> None:  # type: ignore[no-untyped-def]
    await _record(
        session, now=NOW - timedelta(hours=3), hunt_id="01FIRED", candidates=[_candidate("a")]
    )
    await _record(session, now=NOW - timedelta(hours=2), blind=True, precondition_docs=0)
    await _record(session, now=NOW - timedelta(hours=1), gate_already_handled=1)
    await _record(session, now=NOW, error="boom")
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert s.last_swept_at == NOW
    assert s.last_fired_at == NOW - timedelta(hours=3)
    assert s.blind is False, "blind is the NEWEST row's fact, not 'was ever blind'"
    assert s.last_error == "boom"
    assert s.sweeps_24h == 4
    assert s.fired_24h == 1
    assert s.fresh_24h == 1
    assert s.already_handled_24h == 1


async def test_a_blind_spec_reads_blind_until_it_sees_again(session) -> None:  # type: ignore[no-untyped-def]
    await _record(session, now=NOW - timedelta(hours=1), blind=True, precondition_docs=0)
    assert (await catalog_status(session, now=NOW))[SPEC].blind is True
    await _record(session, now=NOW)
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert s.blind is False
    assert s.last_error is None, "a clean newest row clears the last error"


async def test_a_visibility_gap_hunt_is_not_a_firing(session) -> None:  # type: ignore[no-untyped-def]
    """A blind spec records a hunt too (the gap finding). That is a hunt about
    the spec's own eyesight, not the detection firing, and reporting it as
    'fired' would tell an operator a blind spec is working."""
    await _record(session, blind=True, precondition_docs=0, hunt_id="01GAP")
    await _record(session, spec_id=OTHER, error="boom", hunt_id="01GAP2")
    status = await catalog_status(session, now=NOW)
    assert status[SPEC].last_fired_at is None
    assert status[SPEC].fired_24h == 0
    assert status[OTHER].last_fired_at is None
    assert status[OTHER].fired_24h == 0


async def test_shadow_rows_are_swept_but_never_fired(session) -> None:  # type: ignore[no-untyped-def]
    """Shadow counts what a spec WOULD surface. It is a sweep — the loop ran —
    and its would-be count is the number the shadow week exists to read, but it
    fired nothing, and a shadow row must not be able to claim otherwise even if
    a hunt id somehow reaches it."""
    await _record(session, shadow=True, candidates=[_candidate("a"), _candidate("b")])
    await _record(
        session,
        now=NOW + timedelta(minutes=1),
        shadow=True,
        hunt_id="01SHOULD-NOT-COUNT",
        candidates=[_candidate("c")],
    )
    s = (await catalog_status(session, now=NOW + timedelta(minutes=1)))[SPEC]
    assert s.sweeps_24h == 2
    assert s.fired_24h == 0
    assert s.last_fired_at is None
    assert s.fresh_24h == 3


async def test_status_counts_the_windows_shadow_sweeps(session) -> None:  # type: ignore[no-untyped-def]
    """The panel's own hint tells a new operator to run ``spec-sweep --shadow``
    first, after which the row read "fired 0 · fresh 2" with nothing to say
    why. ``shadow_24h`` is the why. It is windowed like the other rates and
    reads the ``shadow`` column only: a live row cannot reach it, and a shadow
    row older than the window cannot either. The same condition seen by a
    shadow sweep and then by a live one is fresh TWICE by design (the shadow
    seed leaves the budget unspent), so ``fresh_24h`` is 2 here, not 1."""
    # A shadow row outside the window: swept, but not a fact about today.
    await _record(session, now=NOW - timedelta(days=2), shadow=True, candidates=[_candidate("old")])
    await _record(session, shadow=True, candidates=[_candidate("a")])
    await _record(
        session, now=NOW + timedelta(minutes=1), hunt_id="01LIVE", candidates=[_candidate("a")]
    )
    s = (await catalog_status(session, now=NOW + timedelta(minutes=1)))[SPEC]
    assert s.shadow_24h == 1, "one shadow row in the window; the live row must not count"
    assert s.sweeps_24h == 2
    assert s.fresh_24h == 2, "the same condition, seen by a shadow sweep then a live one"
    assert s.fired_24h == 1


async def test_the_24h_window_bounds_the_counters_not_the_facts(session) -> None:  # type: ignore[no-untyped-def]
    """'When did this last fire' must not go null a day later. The counters are
    a rate; the last-* fields are a memory, and the memory is the table's
    whole retention."""
    old = NOW - timedelta(hours=25)
    await _record(session, now=old, hunt_id="01OLD", candidates=[_candidate("a")])
    await _record(session, now=NOW - timedelta(hours=24), gate_already_handled=2)
    await _record(session, now=NOW - timedelta(hours=1))
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert s.last_swept_at == NOW - timedelta(hours=1)
    assert s.last_fired_at == old, "the last firing is older than the window and still known"
    assert s.sweeps_24h == 2, "exactly 24h ago is inside the window; 25h is not"
    assert s.fired_24h == 0
    assert s.fresh_24h == 0
    assert s.already_handled_24h == 2


async def test_status_keeps_specs_apart(session) -> None:  # type: ignore[no-untyped-def]
    await _record(session, spec_id=SPEC, hunt_id="01A", candidates=[_candidate("a")])
    await _record(session, spec_id=OTHER, now=NOW + timedelta(minutes=1), error="boom")
    status = await catalog_status(session, now=NOW + timedelta(minutes=1))
    assert status[SPEC].fired_24h == 1
    assert status[SPEC].last_error is None
    assert status[OTHER].fired_24h == 0
    assert status[OTHER].last_error == "boom"


async def test_status_carries_the_newest_sweeps_undecided_count(session) -> None:  # type: ignore[no-untyped-def]
    """A spec discarding documents reads exactly like a quiet one without this.

    ``undecided_docs`` is the newest row's fact, the same way ``blind`` is: the
    question the operator asks of the catalog panel is "is this spec throwing
    documents away NOW", not "did it ever". A run that discarded 5,240
    documents and bucketed none of them writes zeros into every counter on the
    row, so nothing else on it can carry the number.
    """
    await _record(session, undecided_docs=5240)
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert s.undecided_docs == 5240
    assert s.fresh_24h == 0, "the counters this row already had cannot say it"


async def test_a_cleared_undecided_count_clears_on_the_row(session) -> None:  # type: ignore[no-untyped-def]
    """The newest row clears it, like an error. A spec whose grid started
    carrying the field again is not still discarding documents, and a marker
    that never goes away is one an operator learns to ignore."""
    await _record(session, now=NOW - timedelta(hours=1), undecided_docs=5240)
    await _record(session, now=NOW)
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert s.undecided_docs == 0


async def test_a_healthy_spec_reports_no_undecided_documents(session) -> None:  # type: ignore[no-untyped-def]
    """The negative control for the panel's marker: a clean sweep and a firing
    sweep both read zero, so nothing on a working spec can grow the chip."""
    await _record(session, now=NOW - timedelta(hours=1))
    await _record(session, hunt_id="01FIRED", candidates=[_candidate("a")])
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert s.undecided_docs == 0
    assert s.fired_24h == 1


async def test_status_carries_the_newest_sweeps_unattributed_count(session) -> None:  # type: ignore[no-untyped-def]
    """Undecided's sibling failure, and it reads the same on the row.

    These documents MATCHED and grouped into no scope, so they are inside
    ``matched_docs`` and inside no candidate. ``matched_docs`` is not on the
    read model at all, and the counters that are — fresh, fired, handled — are
    computed from the candidate list, which is empty. So a spec whose scope
    field is missing on every hit renders a row of zeros over documents the
    detection genuinely fired on.
    """
    await _record(session, matched_docs=12, unattributed_docs=12)
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert s.unattributed_docs == 12
    assert (s.fresh_24h, s.fired_24h, s.already_handled_24h) == (0, 0, 0), (
        "no counter on the row could carry it"
    )


async def test_status_carries_the_newest_sweeps_truncated_count(session) -> None:  # type: ignore[no-untyped-def]
    """The one of the three where the counters are NOT zero.

    The grid stopped returning scope buckets at the executor's ceiling and
    reported the remainder as a lump sum. So the row shows a real fired count
    and a real fresh count that are both smaller than the truth, and an
    under-report is indistinguishable from a total. That is why this cannot be
    inferred: it is the only unclean state whose row looks like a working spec
    finding things.
    """
    await _record(
        session,
        hunt_id="01FIRED",
        matched_docs=500,
        candidates=[_candidate("a")],
        truncated_docs=460,
    )
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert s.truncated_docs == 460
    assert (s.fired_24h, s.fresh_24h) == (1, 1), (
        "the row reads like a healthy firing spec, which is exactly the problem"
    )


async def test_a_cleared_unattributed_or_truncated_count_clears_on_the_row(session) -> None:  # type: ignore[no-untyped-def]
    """Newest-row semantics for both, the same as undecided and ``blind``.

    A narrowed detection that now fits under the bucket ceiling, or a dataset
    that started carrying the scope field, is not still losing documents. A
    marker that outlives its condition is one an operator learns to ignore.
    """
    await _record(
        session,
        now=NOW - timedelta(hours=1),
        matched_docs=500,
        unattributed_docs=12,
        truncated_docs=460,
    )
    await _record(session, now=NOW)
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert (s.unattributed_docs, s.truncated_docs) == (0, 0)


async def test_a_healthy_spec_reports_neither_unattributed_nor_truncated(session) -> None:  # type: ignore[no-untyped-def]
    """The negative control for both new markers, on the same rows the
    undecided control uses: a clean sweep and a firing sweep."""
    await _record(session, now=NOW - timedelta(hours=1))
    await _record(session, hunt_id="01FIRED", candidates=[_candidate("a")])
    s = (await catalog_status(session, now=NOW))[SPEC]
    assert (s.unattributed_docs, s.truncated_docs) == (0, 0)
    assert s.fired_24h == 1
