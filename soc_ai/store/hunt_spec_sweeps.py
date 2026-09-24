"""Store service for ``hunt_spec_sweeps`` — the per-spec sweep trail.

The catalog sweep computes, per spec, everything worth knowing — blind or
seeing, what the precondition and detection matched, what the gate held back —
and before this table persisted none of it. A clean sweep left no trace, so a
spec that had quietly gone blind or stopped firing looked exactly like one that
had never run. This module moves those rows; the :mod:`quality` store is the
mould: insert + prune in ONE transaction, a newest-first reader, and a small
read-model the route joins against the catalog.

"Fired" has one definition here and the route inherits it: a row whose
``hunt_id`` is set, that is NOT blind, has NO error, and is NOT a shadow run. A
blind spec records a hunt too (the visibility-gap finding), and counting that
as a firing would tell an operator a blind spec is working.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import ColumnElement, case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.execute import SpecRun
from soc_ai.store.models import HuntSpecSweep

# How many rows survive pruning, PER SPEC. The cap is per spec and not per
# table so that retention does not depend on the size of the catalog: under a
# global "newest N" cap, a spec that fired once and then swept clean had its
# firing evicted by every other spec's clean rows — four hourly specs forgot a
# firing after ~21 days, twenty specs after ~4 — and ``last_fired_at`` went
# null in exactly the way :class:`SpecStatus` promises it will not. One spec on
# the default hourly cadence writes 24 rows a day, so 500 is about three weeks
# of trail for every spec however many share the table (a twenty-spec catalog
# is 10 000 rows): long enough to see a spec stop firing across a fortnight,
# short enough that the table never needs thinking about. An operations trail,
# not an archive: the hunts a sweep recorded live in ``hunts`` and are not
# pruned with the row that made them.
KEEP_LAST_PER_SPEC = 500

# The rate counters' window.
STATUS_WINDOW = timedelta(hours=24)


@dataclass(frozen=True)
class SpecStatus:
    """What the trail says about one spec, as the catalog page reads it.

    The ``last_*`` fields are a memory and read the whole retention: "when did
    this last fire" must not go null a day later. The ``*_24h`` fields are a
    rate over :data:`STATUS_WINDOW`. Shadow rows count as sweeps (the loop ran)
    and contribute their would-have-surfaced count to ``fresh_24h`` — that is
    the number a shadow week exists to read — but never to ``fired_24h``.

    ``undecided_docs``, ``unattributed_docs`` and ``truncated_docs`` are the
    newest row's, and they are the three numbers here that a row of zeros
    cannot imply. They are the executor's three separate answers to "what did
    this sweep fail to account for", and the row renders identically without
    any of them:

    * undecided — an exclusion read a field the documents do not carry, so
      they were neither matched nor ruled out. The run matched nothing,
      bucketed nothing and handled nothing, so every counter reads zero on the
      sweep that threw thousands of documents away.
    * unattributed — documents that DID match and produced no scope bucket, so
      they are in ``matched_docs`` and in no candidate. The gate then removes
      the candidates that did surface and the row reads zero fresh.
    * truncated — scopes Elasticsearch never returned because the bucket
      ceiling was hit, counted from the aggregation's own
      ``sum_other_doc_count``. Here the counters are not zero, which is worse:
      they are a real number that is too small, with nothing saying so.

    All three are the newest row's fact rather than a 24h rate, for the reason
    ``blind`` is: the question is whether the spec is discarding documents
    NOW, and a window would keep the number on the row for a day after the
    grid started carrying the field, or after the catalog dropped the ceiling.

    ``shadow_24h`` says how many of the window's sweeps were shadow, because
    without it "fired 0 · fresh 2" is what a new install reads after the very
    ``--shadow`` run the console tells it to make, and it looks like a spec
    that finds things and refuses to report them. The shadow seed leaves the
    fire-once budget unspent, so a condition a shadow sweep saw is fresh AGAIN
    to the live sweep that follows; ``fresh_24h`` counts it both times by
    design, and this field is what lets the row explain that.
    """

    last_swept_at: datetime
    # Newest row that FIRED (see the module docstring); None if it never has.
    last_fired_at: datetime | None
    # The newest row's fact — "is it blind now", not "was it ever".
    blind: bool
    # The newest row's error, or None: a clean newest row clears it.
    last_error: str | None
    # The newest sweep's three unaccounted-for counts. Zero for every run that
    # accounted for everything it looked at, which is what keeps the markers
    # off a healthy spec. See the class docstring for what each one means and
    # why none of them can be inferred from the counters below.
    undecided_docs: int
    unattributed_docs: int
    truncated_docs: int
    sweeps_24h: int
    fired_24h: int
    fresh_24h: int
    already_handled_24h: int
    shadow_24h: int


def _fired() -> ColumnElement[bool]:
    """The one place "fired" is spelled out, as a SQL predicate."""
    return (
        HuntSpecSweep.hunt_id.is_not(None)
        & HuntSpecSweep.blind.is_(False)
        & HuntSpecSweep.error.is_(None)
        & HuntSpecSweep.shadow.is_(False)
    )


def sweep_row(
    *,
    spec_id: str,
    run: SpecRun,
    hunt_id: str | None,
    shadow: bool,
    since: str,
    until: str,
    now: datetime,
) -> HuntSpecSweep:
    """One spec's outcome as the row :func:`record` writes, not yet added.

    The single place a :class:`SpecRun` becomes a trail row. :func:`record`
    is the writer for a live sweep; the demo seed builds a week of these and
    commits them with the hunt they link to, and it must produce the same
    columns from the same run or the catalog page would be reading a shape no
    sweep writes.

    ``run.candidates`` is the list that SURVIVED the gate (the sweep rebuilds
    the run after gating), so its length is the fresh count — in shadow mode,
    the would-have-surfaced count.
    """
    return HuntSpecSweep(
        created_at=now,
        spec_id=spec_id,
        shadow=shadow,
        blind=run.blind,
        error=run.error,
        precondition_docs=run.precondition_docs,
        matched_docs=run.matched_docs,
        fresh_candidates=len(run.candidates),
        already_handled=run.gate_already_handled,
        over_budget=run.gate_over_budget,
        truncated_docs=run.truncated_docs,
        unattributed_docs=run.unattributed_docs,
        undecided_docs=run.undecided_docs,
        hunt_id=hunt_id,
        window_since=since,
        window_until=until,
        duration_ms=int(run.duration_ms or 0),
    )


async def record(
    session: AsyncSession,
    *,
    spec_id: str,
    run: SpecRun,
    hunt_id: str | None,
    shadow: bool,
    since: str,
    until: str,
    now: datetime,
    keep_last: int = KEEP_LAST_PER_SPEC,
) -> HuntSpecSweep:
    """Write one spec's outcome and prune history in the SAME transaction.

    Insert-then-prune in one commit means the table can never be observed
    over capacity, and a crash between the two cannot lose the new row while
    keeping stale ones. The prune keeps THIS spec's newest ``keep_last`` rows
    BY ID — the integer key is insertion-ordered on SQLite, and ``created_at``
    carries the sweep's ``now``, which every spec in a sweep shares — and
    touches no other spec's rows, so one spec's clean sweeps can never evict
    another's last firing.
    """
    row = sweep_row(
        spec_id=spec_id,
        run=run,
        hunt_id=hunt_id,
        shadow=shadow,
        since=since,
        until=until,
        now=now,
    )
    session.add(row)
    # Flush so the new row has its id and is visible to the prune subquery —
    # otherwise a full table could prune everything EXCEPT the newest row.
    await session.flush()
    keep_ids = (
        select(HuntSpecSweep.id)
        .where(HuntSpecSweep.spec_id == spec_id)
        .order_by(HuntSpecSweep.id.desc())
        .limit(keep_last)
        .scalar_subquery()
    )
    await session.execute(
        delete(HuntSpecSweep).where(
            HuntSpecSweep.spec_id == spec_id, HuntSpecSweep.id.not_in(keep_ids)
        )
    )
    await session.commit()
    return row


async def recent(
    session: AsyncSession,
    *,
    limit: int = 200,
    spec_id: str | None = None,
) -> list[HuntSpecSweep]:
    """Newest-first rows, optionally for one spec."""
    stmt = select(HuntSpecSweep)
    if spec_id is not None:
        stmt = stmt.where(HuntSpecSweep.spec_id == spec_id)
    stmt = stmt.order_by(HuntSpecSweep.id.desc()).limit(limit)
    return list((await session.scalars(stmt)).all())


async def catalog_status(session: AsyncSession, *, now: datetime) -> dict[str, SpecStatus]:
    """Per-spec status for every spec that has at least one row.

    A never-swept spec is ABSENT rather than zeroed: the route joins the
    catalog and renders nulls for it, and a fabricated zero row here would read
    as "swept, saw nothing" — the exact confusion the table exists to end.

    Three queries rather than one: the newest row per spec, the newest firing
    per spec, and the windowed aggregates. Each is a GROUP BY over an indexed
    column on a table capped at :data:`KEEP_LAST_PER_SPEC` rows per spec.
    """
    # Newest row per spec — by id, the same tie-break the prune uses. The
    # newest row carries the live facts: blind, last error, last swept.
    newest_ids = select(func.max(HuntSpecSweep.id)).group_by(HuntSpecSweep.spec_id)
    newest = {
        row.spec_id: row
        for row in (
            await session.scalars(select(HuntSpecSweep).where(HuntSpecSweep.id.in_(newest_ids)))
        ).all()
    }
    if not newest:
        return {}

    fired_at: dict[str, datetime] = {
        spec_id: fired
        for spec_id, fired in (
            await session.execute(
                select(HuntSpecSweep.spec_id, func.max(HuntSpecSweep.created_at))
                .where(_fired())
                .group_by(HuntSpecSweep.spec_id)
            )
        ).all()
    }

    cutoff = now - STATUS_WINDOW
    windowed = {
        spec_id: (sweeps, fired, fresh, handled, shadow)
        for spec_id, sweeps, fired, fresh, handled, shadow in (
            await session.execute(
                select(
                    HuntSpecSweep.spec_id,
                    func.count(),
                    func.sum(case((_fired(), 1), else_=0)),
                    func.sum(HuntSpecSweep.fresh_candidates),
                    func.sum(HuntSpecSweep.already_handled),
                    func.sum(case((HuntSpecSweep.shadow.is_(True), 1), else_=0)),
                )
                .where(HuntSpecSweep.created_at >= cutoff)
                .group_by(HuntSpecSweep.spec_id)
            )
        ).all()
    }

    status: dict[str, SpecStatus] = {}
    for spec_id, row in newest.items():
        sweeps, fired, fresh, handled, shadow = windowed.get(spec_id, (0, 0, 0, 0, 0))
        status[spec_id] = SpecStatus(
            last_swept_at=row.created_at,
            last_fired_at=fired_at.get(spec_id),
            blind=row.blind,
            last_error=row.error,
            undecided_docs=row.undecided_docs or 0,
            unattributed_docs=row.unattributed_docs or 0,
            truncated_docs=row.truncated_docs or 0,
            sweeps_24h=int(sweeps or 0),
            fired_24h=int(fired or 0),
            fresh_24h=int(fresh or 0),
            already_handled_24h=int(handled or 0),
            shadow_24h=int(shadow or 0),
        )
    return status


__all__ = [
    "KEEP_LAST_PER_SPEC",
    "STATUS_WINDOW",
    "SpecStatus",
    "catalog_status",
    "recent",
    "record",
    "sweep_row",
]
