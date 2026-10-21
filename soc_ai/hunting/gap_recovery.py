"""Recovery after a grid gap: the hits the gap wrote, and the holds those hits caused.

The range sensor was down from 2026-10-15 13:36Z to 2026-10-19 10:15Z. The
first sweep after the recovery wrote five "connection rate collapsed" hits and
three "plane falls silent" hits for hours inside the outage. One joined a lead,
and the daily hit limit moved a live analytic to shadow. The operator cleaned
up by hand: every hit opened and marked benign, 24 actions, and the cause of
the hold found alone (dogfood 2026-10-19, R1-I5, R3-I1, R3-I2, R4-I3).

This module answers three questions for one recorded gap. The store is the
only source. No grid query and no model call.

* Which hits did the gap write, and which of them does the review select?
  :func:`hits_in_gap`.
* Mark the selected hits benign with one reason. :func:`mark_benign` writes each mark
  through :func:`soc_ai.store.leads.dismiss_observation`, the path of the
  per-hit "Mark benign". It detaches nothing: a hit keeps its lead, and the
  lead reads its weight from the observations that remain.
* Which holds did the gap hits cause? :func:`gap_holds`. The console offers
  "Return to live" for a hold that the gap hits alone explain. The approval
  stays the operator's click.

The rule for "a hit of the gap":

1. The hit comes from an analytic (``ledger.HIT_SOURCES``).
2. Its type measures a count or a silence (:data:`GAP_KINDS`). A gap reads as
   zero documents, so these types depart on it. A hit on matched documents
   stays: the documents exist, and the gap does not explain them.
3. Its event window overlaps the gap plus the settle margin. The event window
   is :func:`hit_window`. A moment counts when it falls inside.

The review lists every such hit, and it selects some of them for the mark
(dogfood round 2, G-1). The range review listed 12 hits, and one confirm
marked them all: two rate spikes and a collapse that ran on after the
recovery among them. A hit is selected when its event window lies inside the
gap plus the settle margin and it is not a spike. A spike stays unselected: the
gap gives no documents, so it cannot make more of them. Only a back-fill burst
can, and that needs a look. A hit that only overlaps stays unselected too.
The operator reads the reason and selects it by hand. The mark writes only
the ids the operator selected.

The self-healing hold uses the same inside rule for its count. That hold acts
with no operator.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting import self_heal
from soc_ai.hunting.catalog_tiers import effective_catalog
from soc_ai.hunting.ledger import HIT_SOURCES
from soc_ai.hunting.weight import Kind
from soc_ai.store import analytics as analytics_store
from soc_ai.store import grid_gaps as gap_store
from soc_ai.store import leads as leads_store
from soc_ai.store.models import EntityObservation, GridGap

__all__ = [
    "EDGE_REASON",
    "GAP_KINDS",
    "SPIKE_REASON",
    "GapHit",
    "GapHold",
    "GapOpen",
    "HitsChanged",
    "MarkResult",
    "gap_holds",
    "gap_note",
    "hit_window",
    "hits_in_gap",
    "in_gap",
    "mark_benign",
    "review_window",
]

# The hit types that measure a count or a silence. Each one departs when the
# grid holds no documents. A novelty, a catalog match, a spread or a logon
# chain needs a document to exist, so a gap cannot write one.
GAP_KINDS: frozenset[str] = frozenset(
    {
        Kind.BELOW_BASELINE.value,
        Kind.ABOVE_BASELINE.value,
        Kind.TELEMETRY_SILENCE.value,
        Kind.ESTATE_OUTLIER.value,
    }
)

# Why the review leaves a hit unselected. The console shows the sentence
# under the hit.
SPIKE_REASON = "A gap does not explain a spike. Check for a back-fill burst."
EDGE_REASON = "Part of this window is outside the gap."

# A rate run ends at most one hour after the sweep that wrote it, because the
# run ends at the close of its last hour. A hit recorded more than this before
# the gap starts cannot describe hours inside it.
_RUN_TAIL = timedelta(hours=1)

# How far back a hold looks for the gaps that can explain its hits. The hits
# of a 24-hour window describe events up to a day or so older, and a silence
# can run for weeks. The model fact lines read the same 30 days.
_HOLD_LOOKBACK = gap_store.FACT_LOOKBACK


class GapOpen(ValueError):
    """The gap has no end yet. Its hours and its settle margin are not known."""


class HitsChanged(ValueError):
    """A selected hit is no longer in the list of the gap.

    Another hand marked it, or the hit moved out of the gap. Nothing is
    written, so the operator reads the list again before the mark.
    """

    def __init__(self, *, gone: list[int]) -> None:
        verb = "is" if len(gone) == 1 else "are"
        super().__init__(f"{len(gone)} of the selected hits {verb} no longer in the gap list.")
        self.gone = gone


@dataclass(frozen=True)
class GapHit:
    """One hit of the gap with its event window as aware UTC."""

    row: EntityObservation
    start: datetime
    end: datetime
    # The event window lies inside the gap plus the settle margin.
    inside: bool = True
    # Why the review leaves the hit unselected. Empty: the review selects it.
    reasons: tuple[str, ...] = ()

    @property
    def selected(self) -> bool:
        """The review selects this hit for the mark by default."""
        return not self.reasons


@dataclass(frozen=True)
class MarkResult:
    """What one mark of a gap wrote."""

    ids: list[int]
    leads: list[int]
    note: str


@dataclass(frozen=True)
class GapHold:
    """One analytic soc-ai held in shadow, and the gap hits in the window that broke its limit."""

    analytic_id: str
    title: str
    # The live hits of the analytic in the window of the hold.
    hits: int
    # The hits of those that a gap wrote.
    gap_hits: int
    # The gap hits that are spikes. A gap does not explain a spike, so these
    # never earn Return to live.
    spike_hits: int
    # The daily hit limit the hold read.
    budget: int
    # The gap hits alone broke the limit: the other hits stay inside it, and
    # the hold names no other breach. The console then offers Return to live.
    return_offered: bool
    # The gaps that hold one or more of the gap hits, oldest first.
    gap_ids: tuple[int, ...]
    held_at: datetime


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _naive(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def _moment(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        at = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return _aware(at)


def hit_window(row: EntityObservation) -> tuple[datetime, datetime]:
    """The event window of one hit, as aware UTC.

    The rule of the self-healing hold first (:func:`soc_ai.hunting.self_heal.
    event_window`), with the query of an older rate row. A row with no
    document time at all reads its record span: the first sighting to the
    newest.
    """
    span = self_heal.event_window(row.observed_at, row.evidence_json, row.rerun_query)
    if span is not None:
        return span
    first = row.first_seen_at or row.born_at
    return _aware(min(first, row.born_at)), _aware(row.born_at)


def _touches(window: gap_store.GapWindow, start: datetime, end: datetime) -> bool:
    if start >= end:
        return window.holds(start)
    return window.overlaps(start, end)


def in_gap(row: EntityObservation, windows: Sequence[gap_store.GapWindow]) -> list[int]:
    """The positions of the windows this hit falls in. Empty for a hit no gap wrote."""
    if str(row.source or "") not in HIT_SOURCES or str(row.kind) not in GAP_KINDS:
        return []
    span = hit_window(row)
    return [i for i, window in enumerate(windows) if _touches(window, *span)]


def review_window(
    gap: GridGap, *, settle: timedelta, now: datetime | None = None
) -> gap_store.GapWindow:
    """The hours the review reads: the gap, plus the settle margin after it."""
    return gap_store.windows_of([gap], settle=settle, now=now)[0]


def gap_note(gap: GridGap) -> str:
    """The note on each hit the review marks: the gap and its hours."""
    if gap.ended_at is None:
        return f"Grid gap from {gap_store.stamp(gap.started_at)}"
    return f"Grid gap from {gap_store.stamp(gap.started_at)} to {gap_store.stamp(gap.ended_at)}"


async def hits_in_gap(
    db: AsyncSession,
    gap: GridGap,
    *,
    settle: timedelta,
    now: datetime | None = None,
) -> list[GapHit]:
    """The hits of the gap that nobody marked benign yet, oldest event first."""
    window = review_window(gap, settle=settle, now=now)
    rows = (
        await db.scalars(
            select(EntityObservation).where(
                EntityObservation.source.in_(HIT_SOURCES),
                EntityObservation.kind.in_(sorted(GAP_KINDS)),
                EntityObservation.dismissed_at.is_(None),
                EntityObservation.born_at >= _naive(gap.started_at) - _RUN_TAIL,
            )
        )
    ).all()
    out: list[GapHit] = []
    for row in rows:
        if not in_gap(row, [window]):
            continue
        start, end = hit_window(row)
        inside = window.holds_span(start, end)
        reasons: list[str] = []
        if str(row.kind) == Kind.ABOVE_BASELINE.value:
            reasons.append(SPIKE_REASON)
        if not inside:
            reasons.append(EDGE_REASON)
        out.append(GapHit(row=row, start=start, end=end, inside=inside, reasons=tuple(reasons)))
    return sorted(out, key=lambda hit: (hit.start, hit.row.id))


async def mark_benign(
    db: AsyncSession,
    gap: GridGap,
    *,
    ids: Sequence[int],
    by: str,
    settle: timedelta,
    now: datetime | None = None,
) -> MarkResult:
    """Mark the selected hits of a closed gap benign, with the gap as the note.

    ``ids`` are the hits the operator selected. Each one must still be in the
    list of the gap. One that is not is :class:`HitsChanged`, and nothing is
    written. Each mark goes through the per-hit path.
    """
    if gap.ended_at is None:
        raise GapOpen("The gap is open. Review its hits after the grid comes back.")
    wanted = list(dict.fromkeys(int(i) for i in ids))
    listed = {int(hit.row.id) for hit in await hits_in_gap(db, gap, settle=settle, now=now)}
    gone = [i for i in wanted if i not in listed]
    if gone:
        raise HitsChanged(gone=gone)
    note = gap_note(gap)
    marked: list[int] = []
    leads: set[int] = set()
    for observation_id in wanted:
        row = await leads_store.dismiss_observation(
            db,
            observation_id,
            reason=leads_store.GRID_GAP_REASON,
            note=note,
            by=by,
            now=now,
        )
        marked.append(int(row.id))
        if row.lead_id is not None:
            leads.add(int(row.lead_id))
    return MarkResult(ids=marked, leads=sorted(leads), note=note)


def _fire_breach(version: Any) -> tuple[dict[str, Any] | None, int]:
    """The fire-budget breach of a hold, and how many breaches the hold names."""
    evidence = analytics_store.evidence_of(version) or {}
    breaches = [b for b in evidence.get("breaches") or [] if isinstance(b, dict)]
    fire = next((b for b in breaches if b.get("rule") == self_heal.RULE_FIRE_BUDGET), None)
    return fire, len(breaches)


async def gap_holds(
    db: AsyncSession,
    *,
    settle: timedelta,
    now: datetime | None = None,
    gap: GridGap | None = None,
    analytic_id: str | None = None,
) -> list[GapHold]:
    """The holds of the daily hit limit that a gap hit is part of, by analytic id.

    A hold is the newest version row of an analytic in shadow, when soc-ai
    wrote it (:func:`soc_ai.store.analytics.system_holds`). Its hits are the
    hits of the analytic in the window of the breach that existed at the hold.
    A hit refreshed after the window still counts, so the count of the other
    hits never falls below what the hold read. ``gap`` keeps the holds that
    gap explains. ``analytic_id`` keeps one analytic.

    The read does not filter on the shadow flag of a row. A sighting sets the
    flag to the status of the analytic at that sweep. The first sweep after
    the hold sees the same hits again in shadow, and a filter on the flag then
    found none of the hits that broke the limit (dogfood round 2, G-1). The
    analytic was live for the whole window, because the window of a breach
    starts at the latest approval to live.
    """
    present = _aware(now or datetime.now(UTC))
    holds = await analytics_store.system_holds(db)
    if analytic_id is not None:
        holds = {key: row for key, row in holds.items() if key == analytic_id}
    out: list[GapHold] = []
    titles: dict[str, str] | None = None
    for held_id, version in sorted(holds.items()):
        fire, breach_count = _fire_breach(version)
        if fire is None:
            continue
        try:
            budget = int(fire.get("budget"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        end = _moment(fire.get("window_end")) or _aware(version.at)
        start = _moment(fire.get("window_start")) or end - self_heal.FIRE_WINDOW
        gap_rows = (
            [gap]
            if gap is not None
            else await gap_store.overlapping(db, since=start - _HOLD_LOOKBACK, until=end)
        )
        if not gap_rows:
            continue
        windows = gap_store.windows_of(gap_rows, settle=settle, now=present)
        rows = (
            await db.scalars(
                select(EntityObservation).where(
                    EntityObservation.spec_id == held_id,
                    EntityObservation.first_seen_at <= _naive(end),
                    EntityObservation.born_at >= _naive(start),
                )
            )
        ).all()
        hit_gaps = [in_gap(row, windows) for row in rows]
        gap_hits = sum(1 for found in hit_gaps if found)
        if gap_hits == 0:
            continue
        # The review does not select a spike: a gap does not explain one. The
        # offer leans on the same rule, so a spike inside a gap still counts
        # against the limit (dogfood 2026-10-19, round 2 on the range).
        spike_hits = sum(
            1
            for row, found in zip(rows, hit_gaps, strict=True)
            if found and str(row.kind) == Kind.ABOVE_BASELINE.value
        )
        explained = gap_hits - spike_hits
        named = sorted({int(gap_rows[i].id) for found in hit_gaps for i in found})
        if titles is None:
            catalog = await effective_catalog(db)
            titles = {key: spec.title for key, spec in catalog.listed.items()}
        out.append(
            GapHold(
                analytic_id=held_id,
                title=titles.get(held_id, held_id),
                hits=len(rows),
                gap_hits=gap_hits,
                spike_hits=spike_hits,
                budget=budget,
                return_offered=(
                    breach_count == 1 and explained > 0 and len(rows) - explained <= budget
                ),
                gap_ids=tuple(named),
                held_at=_aware(version.at),
            )
        )
    return out
