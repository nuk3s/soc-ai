"""The fire-once gate: has this condition already been handled?

A spec runs on a loop over a rolling window. Without memory, a condition that
persists fires on every sweep — and on a one-analyst SOC the problem is never
the first notification, it is the ninetieth. This module is the memory.

**The backfill trap, and why ``disposition`` exists.** When an operator adds a
spec, the natural first move is to sweep history so they can see what is already
there. If that sweep recorded every historical occurrence the same way a live
firing is recorded, the gate would then suppress all of them forever — including
the one that matters, before anybody was watching. So a backfill records
``backfill_seed``, which still permits exactly one live firing afterwards. The
naive version of this feature is actively worse than no gate at all, because it
fails silently and in the direction of missing things.

**Terminal is not the same as permanent, and ``retired_at`` is the difference.**
The gate deliberately has no exit for an ordinary finding: a condition that
persists is one item ever, which is the whole false-positive argument. A
visibility gap is not that. ``sweep.py`` records a blind or errored run on the
``visibility-gap`` scope and its own comment promises the gap re-reports on
transition, blind then seeing then blind again, because a spec that goes dark
for a new reason is a new thing to say. Nothing retired the row, so the first
coverage gap a spec ever recorded was the last one it could record. That is the
fifth time this module has suppressed a real finding forever, and like the four
before it the repair belongs here rather than in a caller.

A DISMISSED gap retires on the same rule, which is the one place a dismissal is
not a standing instruction. See :func:`_retire_gaps`.

**Retention is by age of last sighting, and only on a live sweep.** See
:data:`STATE_RETENTION` for why a row-count cap would be the wrong shape for a
memory whose eviction re-fires a condition.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.execute import Candidate
from soc_ai.store.models import HuntSpecState

if TYPE_CHECKING:
    from sqlalchemy import CursorResult

# A condition seen during a historical sweep. Recorded so the operator can be
# shown what is already there, but NOT treated as "already handled".
BACKFILL_SEED = "backfill_seed"
# A condition that was actually surfaced to a human.
FIRED = "fired"
# Ranked out by the per-sweep budget. Recorded rather than dropped so the count
# can be reported: silent truncation reads as "I surfaced everything".
SUPPRESSED = "suppressed"
# An operator said this is not interesting.
DISMISSED = "dismissed"

# Dispositions that mean "do not surface this again". ``backfill_seed`` is
# deliberately absent: that is the entire point of the distinction.
_TERMINAL = frozenset({FIRED, DISMISSED})

# The scope a blind or errored run is gated on. One per spec: a spec is either
# able to see its plane or it is not, and a gap is a fact about the spec rather
# than about any entity in the data.
#
# It lives here rather than in the sweep because the gate treats it specially,
# and the four previous versions of this module's recurring bug were all a rule
# that lived in a caller. `soc_ai.hunting.sweep` imports it from here.
GAP_SCOPE = "visibility-gap"

# How long a spec has to keep seeing before going dark again counts as news.
#
# Retirement without this is the old failure reached from the other side. A
# grid that answers on one sweep and times out on the next would retire and
# reopen the gap every hour, and each reopening is another hunt and another
# notification-bell entry, evicting the real ones. The hold asks the recovery
# to be real before it re-arms the report.
#
# It delays a report, it never cancels one: a spec that recovers briefly and
# stays dark is still dark on the sweep after the hold expires, and that sweep
# reports it.
GAP_CLEAR_HOLD = timedelta(hours=24)

# How long a condition may go unseen before the gate forgets it.
#
# This table had no retention at all. It is bounded in practice — roughly one
# row per spec per condition, and a standing condition refreshes its existing
# row rather than adding one — so nothing was going to fill a disk. Unbounded
# growth with no stated rule is still a decision nobody made, and the shape of
# the answer matters more than the number.
#
# By AGE OF LAST SIGHTING, never by row count. The sweep trail next door caps at
# a newest-N per spec, which is right for a trail and would be wrong here: this
# is the fire-once memory, so evicting a row RE-FIRES the condition it was
# holding, and under a count cap a spec with many scopes would evict its oldest
# standing condition every time a new one appeared. Age does not have that
# property. A row's ``last_seen`` is refreshed on every sweep the condition is
# still true (see :func:`_touch`), so an old ``last_seen`` means the condition
# has been absent from every sweep for that long — not that it is old.
#
# Ninety days, because forgetting is the same act as re-notifying and the
# question is when a recurrence stops being the same standing thing. A
# pre-authentication-disabled account authenticates most days and a
# DCSync-capable service account replicates constantly, so a condition that has
# been absent for a quarter has stopped; if it comes back, one notification is
# the right answer and silence is not. The cost of the number being too small is
# one duplicate notification, and of it being too large is a real recurrence
# suppressed — so it is set where a wrong guess errs toward saying something.
STATE_RETENTION = timedelta(days=90)


# `.ds-logs-system.security-default-2026.09.03-000001` -> `logs-system.security-default`.
# A backing index is a GENERATION, not a plane, and every standing condition's
# anchor sits in the current write index (top_hits sorts newest first), so
# fingerprinting on the raw name flipped every fingerprint in lockstep at each
# ILM rollover and re-fired the whole catalog.
_BACKING_INDEX_RE = re.compile(r"^\.ds-(?P<stream>.+?)-\d{4}\.\d{2}\.\d{2}-\d{6}$")


def data_stream_of(index: str | None) -> str:
    """The logical data stream behind a concrete index name.

    Returns the input unchanged when it does not look like an ILM backing
    index, so a plain index or an already-logical name passes through.
    """
    if not index:
        return ""
    match = _BACKING_INDEX_RE.match(index)
    return match.group("stream") if match else index


def fingerprint(candidate: Candidate) -> str:
    """What was true about this condition, not merely that the scope appeared.

    Deliberately excludes ``doc_count`` and the timestamps: a beacon seen 40
    times today and 41 times tomorrow is the SAME condition, and folding the
    count in would make the gate fire daily.

    It includes the telemetry PLANE, because the same account acting on a
    different plane is a different thing worth seeing — but the plane, not the
    backing index. Those are not the same on a Security Onion grid: the anchor
    is `.ds-logs-system.security-default-2026.09.03-000001`, whose trailing
    generation changes at every ILM rollover while the condition does not. An
    earlier version hashed the raw name, so every standing condition re-fired in
    lockstep on rollover day, contradicting both this module's purpose and
    `identity-4768-preauth-disabled`'s promise to fire once per account.
    """
    parts = [
        candidate.spec_id,
        candidate.scope_kind,
        candidate.scope_key,
        data_stream_of(candidate.anchor_index),
    ]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:64]


@dataclass(frozen=True)
class GateDecision:
    """Which candidates survive the gate, and what was held back, and WHY.

    ``already_handled`` and ``over_budget`` are separate because they mean
    opposite things to an operator: the first was surfaced before and needs no
    action, the second has never been seen and will surface on a later sweep.
    They were once summed into one number reported as "held back by the budget",
    which made a run that held back nothing report several.

    ``gaps_retired`` is the one field that is not about ``candidates`` at all:
    it counts the visibility gaps this call CLOSED, because the call carried
    none. Going dark is loud (the gap fires a hunt and a notification); coming
    back was a timestamp written inside this function and returned to nobody,
    so a caller could not tell a spec that had just recovered from one that had
    been fine all week. Zero on every ordinary call, which is what keeps the
    recovery a report rather than a running total.
    """

    fresh: list[Candidate]
    already_handled: list[Candidate]
    over_budget: list[Candidate]
    seeded: list[Candidate]
    gaps_retired: int = 0


async def _handled_keys(
    session: AsyncSession, spec_id: str, fingerprints: Sequence[str]
) -> set[str]:
    """Fingerprints already handled, treating a hunt-less ``fired`` row as NOT handled.

    ``fired`` is only meaningful if something exists for an operator to read.
    The state row is staged before the Hunt is created, and the two land in
    separate commits, so a crash in between leaves a terminal row pointing at
    nothing — and the condition it describes would then be suppressed forever
    while never having been shown to anybody. Requiring ``hunt_id`` makes that
    half-written state self-heal on the next sweep instead of losing the finding
    permanently.

    ``dismissed`` has no hunt by construction (an operator said "not
    interesting"), so it stays terminal regardless.
    """
    if not fingerprints:
        return set()
    rows = await session.execute(
        select(HuntSpecState.fingerprint)
        .where(HuntSpecState.spec_id == spec_id)
        .where(HuntSpecState.fingerprint.in_(list(fingerprints)))
        .where(
            or_(
                HuntSpecState.disposition == DISMISSED,
                and_(
                    HuntSpecState.disposition == FIRED,
                    HuntSpecState.hunt_id.isnot(None),
                ),
            )
        )
    )
    return {r[0] for r in rows}


def _is_gap(candidate: Candidate) -> bool:
    return candidate.scope_key == GAP_SCOPE


async def _open_gap(session: AsyncSession, spec_id: str, now: datetime) -> HuntSpecState | None:
    """The spec's visibility gap that has already been reported, if it has one.

    Keyed on the SCOPE, not on the fingerprint, and that is the point. The gap
    fingerprint carries the reason string, and the reason is not stable: an
    errored run reports ``f"precondition: {exc}"``, and the exception text
    carries a shard-failure count on a partial result and a rolled-over backing
    index name on an Elasticsearch API error. Both change between sweeps while
    the outage does not. Keyed on the fingerprint, a grid failing two shards and
    then three would report two gaps for one outage. While a spec's gap is open,
    a change of reason is a change of detail on the same gap.

    Stabilising the reason strings instead was the alternative, and it is the
    weaker fix: it holds only until the next contributor adds an error message
    with a request id in it, and there is no test that could notice.
    """
    rows = await session.execute(
        select(HuntSpecState)
        .where(HuntSpecState.spec_id == spec_id)
        .where(HuntSpecState.scope_key == GAP_SCOPE)
        # The same terminal test :func:`_handled_keys` applies, so a gap row
        # whose hunt was never created does not block the retry.
        .where(
            or_(
                HuntSpecState.disposition == DISMISSED,
                and_(
                    HuntSpecState.disposition == FIRED,
                    HuntSpecState.hunt_id.isnot(None),
                ),
            )
        )
        # Plus the retirement: a gap cleared longer ago than the hold no longer
        # speaks for anything, which is what lets the next one be reported.
        .where(
            or_(
                HuntSpecState.retired_at.is_(None),
                HuntSpecState.retired_at > now - GAP_CLEAR_HOLD,
            )
        )
        .order_by(HuntSpecState.id)
    )
    return rows.scalars().first()


async def _retire_gaps(session: AsyncSession, spec_id: str, now: datetime) -> int:
    """The spec can see its plane again, so its recorded gap is spent.

    Both terminal dispositions, and the ``dismissed`` half is the correction.
    A dismissal is a standing instruction rather than a report, which is why
    :func:`_handled_keys` keeps an ordinary dismissed finding terminal forever —
    but on the gap scope that reasoning stops holding, for the reason this
    module's whole header is about: a spec that goes dark for a new reason is a
    new thing to say, and the dismissal was about the gap that was open when the
    operator dismissed it.

    Nothing writes ``dismissed`` today, so this is a shape being fixed before it
    can cost anything. The two ways to fix it were to make the gap dismissal
    non-terminal or to make it unreachable by construction, and this is the
    first. The second would delete a legitimate operator action — "I know this
    spec cannot see, stop telling me" — and leave nothing in its place.

    Making it non-terminal costs nothing in the case the dismissal exists for.
    Retirement is not a timer: it only happens on a live sweep that produced NO
    gap candidate, which is the spec demonstrating it can see its plane again,
    and :data:`GAP_CLEAR_HOLD` then asks that recovery to last a day before the
    gap can be reported afresh. A deployment that genuinely does not have the
    plane never retires anything, so a dismissal there holds forever by
    construction rather than by rule. What it closes is the other case: a gap
    dismissed for a passing reason — a maintenance window the operator already
    knew about — silencing that spec's coverage for the life of the database,
    which is the fifth-time-lucky failure the header names.

    Returns how many rows it retired, which is what makes the recovery
    reportable. Going dark has always been news — the gap fires a hunt and a
    bell entry — and coming back was a column update nobody was told about, so
    the only evidence a spec had recovered was a marker quietly not being
    there. Almost always 0 or 1; more than one only where a gap was recorded
    before the scope key made a second one impossible.
    """
    rows = await session.execute(
        select(HuntSpecState)
        .where(HuntSpecState.spec_id == spec_id)
        .where(HuntSpecState.scope_key == GAP_SCOPE)
        .where(HuntSpecState.disposition.in_([FIRED, DISMISSED]))
        .where(HuntSpecState.retired_at.is_(None))
    )
    retired = 0
    for row in rows.scalars():
        row.retired_at = now
        retired += 1
    return retired


async def link_handled(
    session: AsyncSession, spec_id: str, candidates: Iterable[Candidate], ref: str
) -> None:
    """Point the ``fired`` rows for these candidates at what reports them.

    Until this runs the rows are deliberately not treated as handled — see
    :func:`_handled_keys`. Calling it is what makes a firing durable.

    ``ref`` is a hunt id, or ``obs:<id>`` for an observation. The column is a
    reference, not a foreign key.
    """
    for candidate in candidates:
        rows = await session.execute(
            select(HuntSpecState)
            .where(HuntSpecState.spec_id == spec_id)
            .where(HuntSpecState.fingerprint == fingerprint(candidate))
            .where(HuntSpecState.disposition == FIRED)
        )
        for row in rows.scalars():
            row.hunt_id = ref


async def link_hunt(
    session: AsyncSession, spec_id: str, candidates: Iterable[Candidate], hunt_id: str
) -> None:
    """Point the ``fired`` rows for these candidates at the hunt that reports them."""
    await link_handled(session, spec_id, candidates, hunt_id)


async def apply_gate(
    session: AsyncSession,
    spec_id: str,
    candidates: Iterable[Candidate],
    *,
    now: datetime,
    seed_only: bool = False,
    top_k: int | None = None,
) -> GateDecision:
    """Filter ``candidates`` to the ones not already handled, and record them.

    ``seed_only=True`` records everything as ``backfill_seed`` rather than
    ``fired``, while still returning what WOULD have been fresh so a caller can
    count it. Two callers need exactly that, for the same reason:

    - a historical backfill, which seeds memory and produces one digest instead
      of firing N findings at somebody who was not watching;
    - shadow mode, which counts what a spec would surface over a week before it
      is allowed to spend anything.

    Both must leave the fire-once budget UNSPENT. A shadow evaluation recording
    ``fired`` would silence the very spec it was assessing, so the day it went
    live it would already be quiet. That is the backfill trap wearing a
    different hat, and it was in the first version of this function.

    ``top_k`` caps how many fresh candidates are returned. The remainder are
    recorded ``suppressed`` so the count is reportable. The cap lives HERE
    rather than downstream because this is the first place an unbounded number
    of candidates can turn into an unbounded number of findings.

    **Visibility gaps retire; ordinary findings do not.** A candidate on
    :data:`GAP_SCOPE` says the spec could not see, and the caller passes one
    only on a blind or errored run. So a live call carrying no gap candidate IS
    the spec reporting that it can see again, and that retires the gap it
    recorded before. Inferred from the candidates rather than taken as a flag
    because every previous version of this bug was a rule a caller had to
    remember: there is nothing here for a caller to get wrong.

    A ``seed_only`` call retires nothing, for the same reason it fires nothing.
    Shadow must leave the gate exactly as it found it in both directions, and a
    backfill reads history, where the plane was alive even if it is dead now.
    """
    items = list(candidates)
    fps = [fingerprint(c) for c in items]

    gaps = [c for c in items if _is_gap(c)]
    gaps_retired = 0
    if not gaps and not seed_only:
        gaps_retired = await _retire_gaps(session, spec_id, now)
    # Read once: a second gap candidate in the same call must be held by the
    # first rather than firing beside it.
    open_gap = await _open_gap(session, spec_id, now) if gaps else None

    handled = await _handled_keys(
        session, spec_id, [fp for c, fp in zip(items, fps, strict=True) if not _is_gap(c)]
    )
    fresh: list[Candidate] = []
    already: list[Candidate] = []
    gap_fired_here = False
    for candidate, fp in zip(items, fps, strict=True):
        if _is_gap(candidate):
            if open_gap is not None:
                already.append(candidate)
                open_gap.last_seen = now
            elif gap_fired_here:
                # A second gap in one call is a repeat of the first, whatever
                # its reason. One spec, one plane, one gap.
                already.append(candidate)
            else:
                fresh.append(candidate)
                gap_fired_here = True
        elif fp in handled:
            already.append(candidate)
            # Refresh the existing row rather than skipping it. The condition
            # is not being surfaced again, but "still true as of now" is worth
            # knowing: without it a persistent condition looks like it stopped
            # on the day it was first handled.
            await _touch(session, candidate, fp, now)
        else:
            fresh.append(candidate)

    over_budget: list[Candidate] = []
    if top_k is not None and len(fresh) > top_k:
        fresh, over_budget = fresh[:top_k], fresh[top_k:]

    disposition = BACKFILL_SEED if seed_only else FIRED
    for candidate in fresh:
        await _record(session, candidate, fingerprint(candidate), disposition, now)
    for candidate in over_budget:
        await _record(session, candidate, fingerprint(candidate), SUPPRESSED, now)

    if not seed_only:
        # Forgetting is a live-sweep act, for the same reason retiring is: a
        # shadow run must leave the gate exactly as it found it, and dropping a
        # row is a decision to let its condition fire again. Runs AFTER the
        # records above so a condition seen on this very sweep cannot be aged
        # out by the same call that recorded it.
        await prune(session, spec_id, now=now)

    return GateDecision(
        fresh=fresh,
        already_handled=already,
        over_budget=over_budget,
        seeded=list(fresh) if seed_only else [],
        gaps_retired=gaps_retired,
    )


async def prune(
    session: AsyncSession,
    spec_id: str,
    *,
    now: datetime,
    retention: timedelta = STATE_RETENTION,
) -> int:
    """Forget this spec's conditions unseen for ``retention``. Returns the count.

    Scoped to ONE spec, like the sweep trail's prune and for the same reason:
    retention must not depend on how large the catalog is, or adding a spec
    changes how long every other spec remembers.

    Rows whose ``last_seen`` was never written fall back to ``created_at``,
    which is not nullable. A row with neither would be immortal, and an
    immortal row in a fire-once memory is a permanently suppressed condition.

    Does not commit: the caller owns the transaction, so the forgetting lands
    with the sweep that decided it rather than in a window of its own.
    """
    cutoff = now - retention
    result = await session.execute(
        delete(HuntSpecState)
        .where(HuntSpecState.spec_id == spec_id)
        .where(
            or_(
                HuntSpecState.last_seen < cutoff,
                and_(HuntSpecState.last_seen.is_(None), HuntSpecState.created_at < cutoff),
            )
        )
        .execution_options(synchronize_session=False)
    )
    # A DELETE always returns a CursorResult, whose rowcount is how many rows
    # went; the static type is the wider Result, which has no such attribute.
    return int(cast("CursorResult[Any]", result).rowcount or 0)


async def _touch(session: AsyncSession, candidate: Candidate, fp: str, now: datetime) -> None:
    """Mark an already-handled condition as still true, without re-firing it."""
    rows = await session.execute(
        select(HuntSpecState)
        .where(HuntSpecState.spec_id == candidate.spec_id)
        .where(HuntSpecState.fingerprint == fp)
        .where(HuntSpecState.disposition.in_(list(_TERMINAL)))
    )
    for row in rows.scalars():
        row.last_seen = now
        row.doc_count = candidate.doc_count


async def _record(
    session: AsyncSession, candidate: Candidate, fp: str, disposition: str, now: datetime
) -> None:
    """Insert a state row, or leave the existing one alone.

    Idempotent by the unique constraint rather than by a read-then-write: two
    sweeps racing on the same condition must not produce two rows, and the
    scheduler is single-worker today but the constraint is what makes that an
    invariant rather than a hope.
    """
    existing = await session.execute(
        select(HuntSpecState)
        .where(HuntSpecState.spec_id == candidate.spec_id)
        .where(HuntSpecState.scope_key == candidate.scope_key)
        .where(HuntSpecState.fingerprint == fp)
        .where(HuntSpecState.disposition == disposition)
    )
    row = existing.scalar_one_or_none()
    if row is not None:
        row.last_seen = now
        row.doc_count = candidate.doc_count
        if row.retired_at is not None:
            # A retired row being recorded again is a NEW episode, so it starts
            # over. ``hunt_id`` has to go with it: a row still pointing at the
            # previous episode's hunt reads as handled the moment it is staged,
            # and a crash before this episode's hunt exists would suppress it
            # forever while never having shown it to anybody. That is the
            # crash-permanence bug, reachable again through retirement.
            row.retired_at = None
            row.hunt_id = None
            row.first_seen = now
        return
    session.add(
        HuntSpecState(
            spec_id=candidate.spec_id,
            scope_key=candidate.scope_key,
            scope_kind=candidate.scope_kind,
            fingerprint=fp,
            disposition=disposition,
            doc_count=candidate.doc_count,
            anchor_id=candidate.anchor_id,
            anchor_index=candidate.anchor_index,
            first_seen=now,
            last_seen=now,
        )
    )


__all__ = [
    "BACKFILL_SEED",
    "DISMISSED",
    "FIRED",
    "GAP_CLEAR_HOLD",
    "GAP_SCOPE",
    "STATE_RETENTION",
    "SUPPRESSED",
    "GateDecision",
    "apply_gate",
    "data_stream_of",
    "fingerprint",
    "link_handled",
    "link_hunt",
    "prune",
]
