"""The fire-once gate, and the backfill trap it has to avoid.

A spec runs on a loop, so a condition that persists would fire on every sweep.
On a one-analyst SOC the problem is never the first notification, it is the
ninetieth.

The trap is what makes this worth testing hard. The naive gate — record every
condition you see, suppress anything recorded — is ACTIVELY WORSE than no gate,
because the first thing an operator does with a new spec is sweep history to see
what is already there. That sweep would mark every historical occurrence as
handled, and the one finding they care about would be suppressed forever, before
anybody was watching. It fails silently and in the direction of missing things.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from soc_ai.config import Settings
from soc_ai.hunting.execute import Candidate
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.hunt_spec_state import (
    BACKFILL_SEED,
    DISMISSED,
    FIRED,
    GAP_CLEAR_HOLD,
    GAP_SCOPE,
    STATE_RETENTION,
    SUPPRESSED,
    apply_gate,
    fingerprint,
    link_hunt,
)
from soc_ai.store.models import HuntSpecState
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

NOW = datetime(2026, 9, 4, 17, 0, tzinfo=UTC).replace(tzinfo=None)
LATER = datetime(2026, 9, 5, 17, 0, tzinfo=UTC).replace(tzinfo=None)
# How long a spec has to stay sighted before going dark again is news.
HOLD = GAP_CLEAR_HOLD


def _candidate(scope: str = "localuser", *, count: int = 2, index: str = ".ds-a") -> Candidate:
    return Candidate(
        spec_id="identity-4662-dcsync-nonmachine",
        scope_key=scope,
        scope_kind="user",
        doc_count=count,
        sample_ids=("idA",),
        anchor_id="idA",
        anchor_index=index,
        first_seen=None,
        last_seen=None,
    )


@pytest_asyncio.fixture
async def db_session(settings_kratos: Settings):  # type: ignore[no-untyped-def]
    """A migrated scratch DB. Real migrations, so 0033 is exercised every run."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as session:
        yield session
        await session.commit()
    await engine.dispose()


async def _rows(session) -> list[HuntSpecState]:
    return list((await session.execute(select(HuntSpecState))).scalars())


async def _fire(session, spec: str, candidates, *, now, **kw):
    """Gate, then LINK — the complete firing, as the sweep performs it.

    A `fired` row with no `hunt_id` is deliberately not treated as handled: the
    row is staged before the Hunt exists and the two land in separate commits,
    so a crash between them would otherwise suppress the condition forever
    while never having shown it to anybody.
    """
    decision = await apply_gate(session, spec, candidates, now=now, **kw)
    if decision.fresh and not kw.get("seed_only"):
        await link_hunt(session, spec, decision.fresh, f"hunt-{now.isoformat()}")
    return decision


async def test_a_condition_fires_once_and_then_stays_quiet(db_session) -> None:
    spec = "identity-4662-dcsync-nonmachine"
    first = await _fire(db_session, spec, [_candidate()], now=NOW)
    assert len(first.fresh) == 1

    second = await apply_gate(db_session, spec, [_candidate()], now=LATER)
    assert second.fresh == []
    assert len(second.already_handled) == 1
    assert second.over_budget == []


async def test_a_backfill_seeds_memory_without_firing_anything(db_session) -> None:
    """A historical sweep is for seeding and one digest, never N findings."""
    spec = "identity-4662-dcsync-nonmachine"
    result = await apply_gate(db_session, spec, [_candidate()], now=NOW, seed_only=True)

    # ``fresh`` is still populated so a shadow run can COUNT what a spec would
    # surface; the caller decides whether to act on it. Only the recorded
    # disposition changes.
    assert len(result.seeded) == 1
    rows = await _rows(db_session)
    assert [r.disposition for r in rows] == [BACKFILL_SEED]


async def test_a_seeded_condition_can_still_fire_once_live(db_session) -> None:
    """THE trap. Without this the gate silently suppresses the finding that matters.

    An operator adds the DCSync spec on Monday, sweeps history so they can see
    what is already there, and a naive gate would mark every historical
    occurrence handled — including the live one that arrives Tuesday.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await apply_gate(db_session, spec, [_candidate()], now=NOW, seed_only=True)

    live = await apply_gate(db_session, spec, [_candidate()], now=LATER)

    assert len(live.fresh) == 1, (
        "a backfill-seeded condition was suppressed on its first LIVE appearance; "
        "this is the failure that makes the gate worse than no gate"
    )
    dispositions = sorted(r.disposition for r in await _rows(db_session))
    assert dispositions == [BACKFILL_SEED, FIRED]


async def test_it_fires_again_on_a_genuinely_different_telemetry_plane(db_session) -> None:
    """Same account, different plane, is a different thing worth seeing."""
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_candidate(index="logs-system.security-default")], now=NOW)
    again = await apply_gate(
        db_session, spec, [_candidate(index="logs-windows.sysmon-default")], now=LATER
    )
    assert len(again.fresh) == 1


async def test_an_ilm_rollover_is_not_a_different_condition(db_session) -> None:
    """A backing index is a GENERATION, not a plane.

    On Security Onion the anchor is
    ``.ds-logs-system.security-default-2026.09.03-000001``, and because the
    top_hits sort is newest-first, every standing condition's anchor sits in the
    current write index. Fingerprinting on the raw name therefore flipped every
    fingerprint in lockstep at each rollover and re-fired the whole catalog —
    contradicting `identity-4768-preauth-disabled`'s promise to fire once per
    account, whose entire safety story is this gate.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(
        db_session,
        spec,
        [_candidate(index=".ds-logs-system.security-default-2026.09.03-000001")],
        now=NOW,
    )
    after_rollover = await apply_gate(
        db_session,
        spec,
        [_candidate(index=".ds-logs-system.security-default-2026.10.01-000013")],
        now=LATER,
    )
    assert after_rollover.fresh == [], "an ILM rollover re-fired a standing condition"


async def test_a_changed_document_count_is_the_same_condition(db_session) -> None:
    """A beacon seen 40 times today and 41 tomorrow must not fire twice.

    Folding the count into the fingerprint would make every persistent condition
    fire daily, which is the exact behaviour the gate exists to stop.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_candidate(count=40)], now=NOW)
    again = await apply_gate(db_session, spec, [_candidate(count=41)], now=LATER)
    assert again.fresh == []


async def test_over_budget_candidates_are_recorded_not_dropped(db_session) -> None:
    """Silent truncation reads as "I surfaced everything"."""
    spec = "identity-4662-dcsync-nonmachine"
    candidates = [_candidate(f"user{i}") for i in range(5)]
    result = await apply_gate(db_session, spec, candidates, now=NOW, top_k=2)

    assert len(result.fresh) == 2
    # Separate from already_handled: these have never been seen and will
    # surface on a later sweep, which is the opposite of "you dealt with this".
    assert len(result.over_budget) == 3
    assert result.already_handled == []
    by_disposition = sorted(r.disposition for r in await _rows(db_session))
    assert by_disposition == [FIRED, FIRED, SUPPRESSED, SUPPRESSED, SUPPRESSED]


async def test_a_suppressed_condition_is_not_treated_as_handled(db_session) -> None:
    """Budget is not a verdict. Something held back today should surface tomorrow."""
    spec = "identity-4662-dcsync-nonmachine"
    await apply_gate(db_session, spec, [_candidate("a"), _candidate("b")], now=NOW, top_k=1)

    tomorrow = await apply_gate(db_session, spec, [_candidate("b")], now=LATER)
    assert len(tomorrow.fresh) == 1, (
        "a candidate ranked out by budget was later treated as already handled; "
        "budget pressure would silently become permanent suppression"
    )


async def test_recording_the_same_condition_twice_makes_one_row(db_session) -> None:
    """Idempotent by the unique constraint, not by a hopeful read-then-write."""
    spec = "identity-4662-dcsync-nonmachine"
    await apply_gate(db_session, spec, [_candidate()], now=NOW)
    await apply_gate(db_session, spec, [_candidate()], now=LATER)
    rows = await _rows(db_session)
    assert len(rows) == 1
    assert rows[0].last_seen == LATER


async def test_the_scope_kind_is_persisted(db_session) -> None:
    """A candidate's entity is not always a host, and the column proves it."""
    await apply_gate(
        db_session,
        "decoy-opencanary-interaction",
        [
            Candidate(
                "decoy-opencanary-interaction", "10.0.0.66", "ip", 2, ("i",), "i", ".ds", None, None
            )
        ],
        now=NOW,
    )
    rows = await _rows(db_session)
    assert rows[0].scope_kind == "ip"


@pytest.mark.asyncio(loop_scope="function")
async def test_the_fingerprint_ignores_volume_and_time() -> None:
    a = _candidate(count=1)
    b = _candidate(count=999)
    assert fingerprint(a) == fingerprint(b)


@pytest.mark.asyncio(loop_scope="function")
async def test_the_fingerprint_separates_scopes_and_planes() -> None:
    assert fingerprint(_candidate("a")) != fingerprint(_candidate("b"))
    assert fingerprint(_candidate(index="logs-a")) != fingerprint(_candidate(index="logs-b"))


@pytest.mark.asyncio(loop_scope="function")
async def test_the_fingerprint_ignores_the_backing_index_generation() -> None:
    a = _candidate(index=".ds-logs-system.security-default-2026.09.03-000001")
    b = _candidate(index=".ds-logs-system.security-default-2026.10.01-000013")
    assert fingerprint(a) == fingerprint(b)


async def test_a_fired_row_with_no_hunt_is_not_treated_as_handled(db_session) -> None:
    """The half-written-sweep case, and why it must self-heal.

    The state row is staged before the Hunt is created and the two land in
    separate commits. A crash in between leaves a terminal row pointing at
    nothing, and the condition it describes would be suppressed forever while
    never having been shown to anybody. `finished_at` is not the check —
    `hunt_id` is, because a row whose hunt does not exist has nothing an
    operator could have read.
    """
    spec = "identity-4662-dcsync-nonmachine"
    crashed = await apply_gate(db_session, spec, [_candidate()], now=NOW)
    assert len(crashed.fresh) == 1  # gated, but link_hunt never ran

    retry = await apply_gate(db_session, spec, [_candidate()], now=LATER)
    assert len(retry.fresh) == 1, "a fired row with no hunt suppressed the condition permanently"


async def test_linking_the_hunt_is_what_makes_a_firing_stick(db_session) -> None:
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_candidate()], now=NOW)
    again = await apply_gate(db_session, spec, [_candidate()], now=LATER)
    assert again.fresh == []
    rows = await _rows(db_session)
    assert rows[0].hunt_id is not None


# ---------------------------------------------------------------------------
# The visibility gap, and why it must be able to close.
#
# The fifth instance of this codebase's recurring bug: a terminal row that
# nothing ever clears. `sweep.py` documents the gap path as re-reporting on
# transition, blind then seeing then blind again being a second thing to say,
# and the gate never retired the row, so the first gap a spec ever recorded was
# the last one it could record.


def _gap(
    spec: str = "identity-4662-dcsync-nonmachine",
    *,
    reason: str = "precondition matched nothing",
) -> Candidate:
    """The synthetic candidate the sweep builds for a blind or errored run."""
    return Candidate(
        spec_id=spec,
        scope_key=GAP_SCOPE,
        scope_kind="dataset",
        doc_count=0,
        sample_ids=(),
        anchor_id=None,
        anchor_index=reason[:120],
        first_seen=None,
        last_seen=None,
    )


async def test_a_gap_that_cleared_and_returned_is_news_again(db_session) -> None:
    """Blind, seeing, blind is a transition, and the docstring always said so.

    A deployment that recorded a gap once could never be told about the next
    one. The case that forced this: a spec was fixed so a quiet honeypot reads
    clean instead of blind, and every deployment carrying the old false gap
    would have spent its one report on the bug rather than on the day the
    honeypot actually died.
    """
    spec = "identity-4662-dcsync-nonmachine"
    first = await _fire(db_session, spec, [_gap()], now=NOW)
    assert len(first.fresh) == 1

    # The spec sees its plane again. A clean sweep carries no candidates at all,
    # which is exactly the sweep that proves the plane is alive.
    await apply_gate(db_session, spec, [], now=NOW + HOLD)

    returned = await apply_gate(db_session, spec, [_gap()], now=NOW + HOLD + HOLD)
    assert len(returned.fresh) == 1, (
        "a spec that went dark a second time said nothing; the first gap it ever "
        "recorded was the last one it could record"
    )


async def test_a_continuously_blind_spec_still_reports_exactly_once(db_session) -> None:
    """NEGATIVE CONTROL. The failure the terminal row was protecting against.

    A deployment without OpenCanary is blind on that spec forever by
    construction. Twenty-four sweeps of it once produced twenty-four hunts and
    twenty-four bell entries, evicting the real ones. Making the gap retirable
    must not bring that back.
    """
    spec = "identity-4662-dcsync-nonmachine"
    fired = 0
    for hour in range(48):
        decision = await _fire(db_session, spec, [_gap()], now=NOW + timedelta(hours=hour))
        fired += len(decision.fresh)
    assert fired == 1, f"a permanently blind spec reported {fired} times over 48 sweeps"


async def test_the_gate_says_how_many_gaps_it_closed(db_session) -> None:
    """The retirement was a column write returned to nobody.

    ``_retire_gaps`` set ``retired_at`` and the function it was called from
    returned a decision about candidates. A caller therefore had no way to tell
    a call that ended an outage from an ordinary clean one, and every surface
    downstream inherited that: the sweep report, the CLI's JSON and the
    scheduler's log line all said the same thing on both.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap()], now=NOW)

    recovered = await apply_gate(db_session, spec, [], now=NOW + HOLD)
    assert recovered.gaps_retired == 1
    # The decision is otherwise empty, which is the point: nothing else on this
    # object distinguishes the sweep that ended the outage.
    assert (recovered.fresh, recovered.already_handled, recovered.over_budget) == ([], [], [])


async def test_a_gate_call_that_closed_nothing_says_zero(db_session) -> None:
    """NEGATIVE CONTROL. A number that is 1 on every clean sweep says nothing.

    Three ways of closing nothing, all of which must read the same: a spec that
    was never blind, the second clean call after a recovery, and a call that
    carries a gap of its own.
    """
    spec = "identity-4662-dcsync-nonmachine"
    never_blind = await apply_gate(db_session, spec, [_candidate()], now=NOW)
    assert never_blind.gaps_retired == 0

    await _fire(db_session, spec, [_gap()], now=NOW + HOLD)
    first = await apply_gate(db_session, spec, [], now=NOW + HOLD + HOLD)
    second = await apply_gate(db_session, spec, [], now=NOW + HOLD + HOLD + HOLD)
    assert (first.gaps_retired, second.gaps_retired) == (1, 0), (
        "a recovery announced on every sweep after it is not a recovery report"
    )

    still_dark = await apply_gate(db_session, spec, [_gap()], now=NOW + HOLD * 4)
    assert still_dark.gaps_retired == 0, "a call carrying a gap cannot close one"


async def test_a_shadow_sweep_reports_no_retirement(db_session) -> None:
    """NEGATIVE CONTROL, paired with the one below it.

    Shadow retires nothing, so it must claim nothing. A shadow sweep reporting
    a closed gap while the gap is still open would be a false all-clear told by
    the mode whose entire promise is that it changes nothing.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap()], now=NOW)

    shadow = await apply_gate(db_session, spec, [], now=NOW + HOLD, seed_only=True)
    assert shadow.gaps_retired == 0

    # And the gap really is still open, so the live call is the one that says
    # so — the claim and the state cannot drift apart.
    live = await apply_gate(db_session, spec, [], now=NOW + HOLD + HOLD)
    assert live.gaps_retired == 1


async def test_a_shadow_sweep_retires_nothing(db_session) -> None:
    """NEGATIVE CONTROL. Shadow must not touch the gate in either direction.

    A shadow evaluation that spent the fire-once budget would silence the spec
    it was assessing. Handing the budget BACK is the same violation read the
    other way: a shadow run that cleared the gap would make the next live sweep
    re-report a gap the operator has already been shown.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap()], now=NOW)

    # A shadow sweep sees the plane. It must leave the gap row alone.
    await apply_gate(db_session, spec, [], now=NOW + HOLD, seed_only=True)

    still_open = await apply_gate(db_session, spec, [_gap()], now=NOW + HOLD + HOLD)
    assert still_open.fresh == [], "a shadow sweep retired a live gap and re-armed the report"
    assert len(still_open.already_handled) == 1


async def test_a_backfill_retires_nothing(db_session) -> None:
    """A backfill sweeps history, where the plane was alive even if it is dead now.

    Same flag, and the sharper case: seeing telemetry in retention says nothing
    about whether the spec can see today, so a backfill that retired the gap
    would erase a CURRENT coverage hole on the strength of an old document.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap()], now=NOW)

    await apply_gate(db_session, spec, [_candidate()], now=NOW + HOLD, seed_only=True)

    still_open = await apply_gate(db_session, spec, [_gap()], now=NOW + HOLD + HOLD)
    assert still_open.fresh == [], "a backfill erased a live coverage gap"


async def test_a_gap_that_flaps_within_the_hold_is_not_reported_again(db_session) -> None:
    """A plane that recovers for an hour and dies again is one gap, not two.

    Without this the fix trades a gap that can never re-report for one that
    re-reports on every other sweep, which is the same bell-eviction failure
    reached by the opposite route. The recovery has to last before going dark
    again counts as new.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap()], now=NOW)

    reports = 0
    for hour in range(1, 25):
        # Alternating: sees on the odd hour, blind on the even one.
        at = NOW + timedelta(hours=hour)
        if hour % 2:
            await apply_gate(db_session, spec, [], now=at)
        else:
            decision = await _fire(db_session, spec, [_gap()], now=at)
            reports += len(decision.fresh)
    assert reports == 0, f"a flapping plane re-reported {reports} times in a day"


async def test_a_gap_reported_late_is_still_reported(db_session) -> None:
    """The hold delays a report; it must never cancel one.

    A spec that recovers and goes dark again inside the hold stays dark. The
    next sweep past the hold has to say so, or the hold has quietly become the
    bug it was added to prevent.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap()], now=NOW)
    await apply_gate(db_session, spec, [], now=NOW + timedelta(hours=1))

    too_soon = await apply_gate(db_session, spec, [_gap()], now=NOW + timedelta(hours=2))
    assert too_soon.fresh == []

    later = await apply_gate(db_session, spec, [_gap()], now=NOW + timedelta(hours=1) + HOLD)
    assert len(later.fresh) == 1, "the hold swallowed the report instead of delaying it"


async def test_a_gap_with_a_new_reason_does_not_reopen_a_gap_already_open(db_session) -> None:
    """The reason string is not stable, so it must not drive the gate.

    An errored run's reason is `f"precondition: {exc}"`, and the exception text
    carries a shard-failure count on a partial result and a rolled-over backing
    index name on an Elasticsearch API error. Both change between sweeps while
    the outage does not. Keyed on the fingerprint, which carries the reason, a
    grid failing two shards and then three would report twice. The gap is keyed
    on the SCOPE instead: while a spec's gap is open, a change of reason is a
    change of detail, not a second gap.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap(reason="precondition: 2 of 5 shards failed")], now=NOW)

    churned = 0
    for shard in range(3, 6):
        decision = await _fire(
            db_session,
            spec,
            [_gap(reason=f"precondition: {shard} of 5 shards failed")],
            now=NOW + timedelta(hours=shard),
        )
        churned += len(decision.fresh)
    assert churned == 0, f"an unstable reason string re-fired the gap {churned} times"


async def test_a_reopened_gap_needs_its_own_hunt_before_it_counts_as_handled(db_session) -> None:
    """The fourth instance of this bug, reachable again through the fifth.

    Reopening reuses the row, and a row still pointing at the PREVIOUS gap's
    hunt would read as handled the moment it was staged. A crash before the new
    hunt existed would then suppress the new gap forever while never having
    shown it to anybody, which is exactly what `hunt_id` was made to prevent.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap()], now=NOW)
    await apply_gate(db_session, spec, [], now=NOW + HOLD)

    # Reopened, then the process dies before the hunt is created.
    crashed = await apply_gate(db_session, spec, [_gap()], now=NOW + HOLD + HOLD)
    assert len(crashed.fresh) == 1
    row = next(r for r in await _rows(db_session) if r.scope_key == GAP_SCOPE)
    assert row.hunt_id is None, "the reopened gap still pointed at the previous gap's hunt"
    assert row.first_seen == NOW + HOLD + HOLD, "a new episode kept the old episode's start"

    retry = await apply_gate(db_session, spec, [_gap()], now=NOW + HOLD + HOLD + HOLD)
    assert len(retry.fresh) == 1, "the reopened gap was suppressed permanently by a crash"


async def test_seeing_again_does_not_retire_an_ordinary_finding(db_session) -> None:
    """Retirement is deliberately gap-only, and this is the fence.

    For a gap, absence from a sweep means the plane is alive: a real state
    change. For an ordinary finding it means the evidence aged out of the
    rolling window, which happens to every condition on a fixed schedule and
    says nothing at all. Retiring findings on absence would turn fire-once into
    fire-every-window-length.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_candidate()], now=NOW)

    # Several sweeps in which the account does not appear.
    for hour in range(1, 5):
        await apply_gate(db_session, spec, [], now=NOW + timedelta(hours=hour))

    back = await apply_gate(db_session, spec, [_candidate()], now=NOW + HOLD + HOLD)
    assert back.fresh == [], "an ordinary finding retired on absence and re-fired"
    assert len(back.already_handled) == 1


# ---------------------------------------------------------------------------
# A dismissed gap
#
# Nothing writes `dismissed` yet, so this is a shape fixed before it can cost
# anything. A dismissal is a standing instruction rather than a report, which is
# why an ordinary dismissed finding is terminal forever — but the gap scope is
# the one place that reasoning stops holding, for the reason the whole module is
# about: a spec that goes dark for a NEW reason is a new thing to say, and the
# dismissal was about the gap that was open when the operator dismissed it.
# ---------------------------------------------------------------------------


async def _dismiss_the_open_gap(session, spec: str) -> None:
    """What a dismiss action would do: flip the spec's open gap row.

    Written against the row rather than through an action because no action
    exists. If one is added, this is the state it has to produce.
    """
    row = next(r for r in await _rows(session) if r.scope_key == GAP_SCOPE)
    row.disposition = DISMISSED
    row.hunt_id = None  # a dismissal has no hunt by construction
    await session.flush()


async def test_a_dismissed_gap_does_not_silence_the_spec_forever(db_session) -> None:
    """The defect. The dismissal was about a gap that has since cleared, and the
    spec going dark again is a new fact about coverage."""
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap()], now=NOW)
    await _dismiss_the_open_gap(db_session, spec)

    # The spec sees its plane again — a live sweep carrying no gap candidate.
    await apply_gate(db_session, spec, [], now=NOW + HOLD)

    returned = await apply_gate(db_session, spec, [_gap()], now=NOW + HOLD + HOLD)
    assert len(returned.fresh) == 1, (
        "a gap dismissed for a passing reason silenced this spec's coverage for "
        "the life of the database"
    )


async def test_a_dismissed_gap_on_a_spec_that_never_sees_again_stays_quiet(db_session) -> None:
    """NEGATIVE CONTROL, and the reason the fix costs nothing.

    Retirement is not a timer: it only happens on a live sweep that produced NO
    gap candidate, which is the spec demonstrating it can see. A deployment that
    genuinely lacks the plane never has such a sweep, so the dismissal holds
    forever by construction rather than by rule — which is exactly what the
    operator asked for when they dismissed it.
    """
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_gap()], now=NOW)
    await _dismiss_the_open_gap(db_session, spec)

    fired = 0
    for hour in range(1, 96):
        decision = await apply_gate(db_session, spec, [_gap()], now=NOW + timedelta(hours=hour))
        fired += len(decision.fresh)
    assert fired == 0, f"a dismissed standing gap reported {fired} times over 95 blind sweeps"


async def test_an_ordinary_dismissed_finding_is_still_terminal_forever(db_session) -> None:
    """NEGATIVE CONTROL. Retirement stays gap-only. Absence of an ordinary
    condition means the evidence aged out of the rolling window, which happens
    to everything on a schedule, so a dismissal there is permanent."""
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_candidate()], now=NOW)
    row = next(r for r in await _rows(db_session) if r.scope_key != GAP_SCOPE)
    row.disposition = DISMISSED
    row.hunt_id = None
    await db_session.flush()

    for hour in range(1, 5):
        await apply_gate(db_session, spec, [], now=NOW + timedelta(hours=hour))

    back = await apply_gate(db_session, spec, [_candidate()], now=NOW + HOLD + HOLD)
    assert back.fresh == [], "a dismissed finding came back after the operator dismissed it"


# ---------------------------------------------------------------------------
# Retention
#
# The table had none. It is bounded in practice, so this is a decision nobody
# made rather than a disk filling up — but the SHAPE of the rule is the part
# that matters. By age of last sighting, never by row count: evicting a row in a
# fire-once memory re-fires the condition it was holding, so a newest-N cap
# would make one spec's new condition evict its own oldest standing one.
# ---------------------------------------------------------------------------


async def test_a_condition_unseen_past_the_retention_is_forgotten(db_session) -> None:
    """The decision. A condition absent from every sweep for a quarter has
    stopped, and one notification if it comes back is the right answer."""
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_candidate()], now=NOW)

    long_after = NOW + STATE_RETENTION + timedelta(days=1)
    await apply_gate(db_session, spec, [], now=long_after)
    assert await _rows(db_session) == []

    back = await _fire(db_session, spec, [_candidate()], now=long_after)
    assert len(back.fresh) == 1


async def test_a_standing_condition_is_never_aged_out(db_session) -> None:
    """NEGATIVE CONTROL, and the whole risk of the feature. ``last_seen`` is
    refreshed on every sweep the condition is still true, so an old row means an
    absent condition, not an old one. A retention that read ``first_seen`` would
    re-fire every standing condition on a fixed cycle — fire-once turned into
    fire-once-a-quarter."""
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_candidate()], now=NOW)

    fired = 0
    for day in range(1, 200):
        decision = await _fire(db_session, spec, [_candidate()], now=NOW + timedelta(days=day))
        fired += len(decision.fresh)
    assert fired == 0, f"a condition true every day re-fired {fired} times"
    assert len(await _rows(db_session)) == 1


async def test_a_shadow_sweep_forgets_nothing(db_session) -> None:
    """NEGATIVE CONTROL. Shadow must leave the gate exactly as it found it in
    both directions, and dropping a row is a decision to let its condition fire
    again — the fire-once budget handed back rather than spent."""
    spec = "identity-4662-dcsync-nonmachine"
    await _fire(db_session, spec, [_candidate()], now=NOW)

    long_after = NOW + STATE_RETENTION + timedelta(days=1)
    await apply_gate(db_session, spec, [_candidate("other")], now=long_after, seed_only=True)
    assert any(r.scope_key == "localuser" for r in await _rows(db_session)), (
        "a shadow run spent the gate's memory of a condition it was not assessing"
    )


async def test_one_spec_ageing_out_does_not_touch_another(db_session) -> None:
    """NEGATIVE CONTROL. Retention is per spec, like the sweep trail's, so
    adding a spec cannot change how long every other spec remembers."""
    import dataclasses

    for spec in ("spec-a", "spec-b"):
        await _fire(db_session, spec, [dataclasses.replace(_candidate(), spec_id=spec)], now=NOW)

    long_after = NOW + STATE_RETENTION + timedelta(days=1)
    await apply_gate(db_session, "spec-a", [], now=long_after)

    remaining = {r.spec_id for r in await _rows(db_session)}
    assert remaining == {"spec-b"}
