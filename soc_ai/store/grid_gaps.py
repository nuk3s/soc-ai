"""The grid-gap ledger: the hours soc-ai could not read the grid.

The range sensor was down from 2026-10-15 13:36Z to 2026-10-19 10:15Z. soc-ai
saw Elasticsearch fail, kept the fact in process memory, and dropped it at the
recovery. Every windowed surface then read the hole as a quiet grid, the
profile sweep wrote "connection rate collapsed" departures for hours the grid
held nothing for, and the baseline learned 90 hours of zeros.

This table keeps the fact. Two sources write it:

* ``probe``: the health probe found the grid unreadable. The row opens at
  the first failed probe and closes at the first good probe. An open row
  survives a restart. See :mod:`soc_ai.webui.grid_gap_probe`.
* ``sweep``: the grid answered, and the profile sweep found the documents of
  one plane stopped on most hosts at once. A sensor that dies while
  Elasticsearch stays up looks like that. See
  :mod:`soc_ai.hunting.prior_sweep`.
* ``operator``: an operator recorded a gap soc-ai did not see. soc-ai can be
  down itself during an outage, and an outage can predate the ledger. See
  ``soc-ai grid-gaps add`` and ``POST /api/v1/grid/gaps``.

The readers treat an hour inside a gap as unknown. A reader that scores hours
also waits a settle margin after a gap ends, because the agents back-fill the
hole after a restart and the hours right after the recovery are not final.

Every timestamp is naive UTC, as everywhere in the store. The helpers here
accept aware or naive values and return aware UTC windows for the readers that
compare against grid time.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import GridGap

__all__ = [
    "DEFAULT_SETTLE_MINUTES",
    "FACT_LOOKBACK",
    "MAX_OPERATOR_SPAN",
    "SOURCE_OPERATOR",
    "SOURCE_PROBE",
    "SOURCE_SWEEP",
    "GapRefused",
    "GapWindow",
    "check_operator_span",
    "close_probe_gaps",
    "closed_since",
    "covered",
    "describe",
    "fact_lines",
    "gap_hours",
    "get",
    "open_probe_gap",
    "open_probe_gaps",
    "overlapping",
    "plane_words",
    "recent_fact_lines",
    "record_operator_gap",
    "record_sweep_gap",
    "settle_of",
    "stamp",
    "windows_of",
]

SOURCE_PROBE = "probe"
SOURCE_SWEEP = "sweep"
SOURCE_OPERATOR = "operator"

# The longest gap an operator can record in one row. A longer span is most
# often a mistyped date, and a gap of months would blind every reader.
MAX_OPERATOR_SPAN = timedelta(days=30)

# The clock skew an operator gap may carry at its end. The operator types the
# end from another clock, and a minute ahead of the server is no future gap.
_END_SKEW = timedelta(minutes=5)

# How long a scoring reader waits after a gap ends. The setting
# ``grid_gap_settle_minutes`` overrides it.
DEFAULT_SETTLE_MINUTES = 60

# The most gaps one model prompt names. A flapping grid can write many short
# gaps, and the prompt carries every line on every turn.
_MAX_FACT_LINES = 5


def _naive(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def settle_of(settings: Any) -> timedelta:
    """The settle margin from the settings. A bad value reads as the default."""
    raw = getattr(settings, "grid_gap_settle_minutes", DEFAULT_SETTLE_MINUTES)
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        minutes = DEFAULT_SETTLE_MINUTES
    return timedelta(minutes=max(0, minutes))


async def open_probe_gaps(db: AsyncSession) -> list[GridGap]:
    """The probe gaps with no end yet, oldest first."""
    rows = await db.scalars(
        select(GridGap)
        .where(GridGap.source == SOURCE_PROBE, GridGap.ended_at.is_(None))
        .order_by(GridGap.started_at, GridGap.id)
    )
    return list(rows.all())


async def open_probe_gap(db: AsyncSession, *, started_at: datetime, detail: str) -> GridGap:
    """Open a probe gap. An open probe gap already on record is returned as it is.

    One outage is one row. A restart in the middle of an outage finds the open
    row and keeps it.
    """
    existing = await open_probe_gaps(db)
    if existing:
        return existing[0]
    row = GridGap(
        source=SOURCE_PROBE,
        plane=None,
        started_at=_naive(started_at),
        ended_at=None,
        detail=detail[:2000],
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def close_probe_gaps(db: AsyncSession, *, ended_at: datetime) -> int:
    """Close every open probe gap at ``ended_at``. Returns how many closed."""
    rows = await open_probe_gaps(db)
    end = _naive(ended_at)
    for row in rows:
        # A clock that moved back must not write an end before the start.
        row.ended_at = max(end, row.started_at)
    if rows:
        await db.commit()
    return len(rows)


async def record_sweep_gap(
    db: AsyncSession,
    *,
    plane: str,
    started_at: datetime,
    ended_at: datetime,
    detail: str,
    join_within: timedelta = timedelta(0),
) -> GridGap:
    """Record the dark hours one sweep found on one plane.

    A sweep gap on the same plane that overlaps the new hours, or ends at most
    ``join_within`` before they start, grows to hold them. An ingest gap that
    lasts several sweeps stays one row. The sweep passes its settle margin
    here, because it does not score the hours of that margin.
    """
    start, end = _naive(started_at), _naive(ended_at)
    near = (
        await db.scalars(
            select(GridGap)
            .where(
                GridGap.source == SOURCE_SWEEP,
                GridGap.plane == plane,
                GridGap.started_at <= end + join_within,
                or_(GridGap.ended_at.is_(None), GridGap.ended_at >= start - join_within),
            )
            .order_by(GridGap.started_at, GridGap.id)
        )
    ).first()
    if near is not None:
        near.started_at = min(near.started_at, start)
        if near.ended_at is not None:
            near.ended_at = max(near.ended_at, end)
        near.detail = detail[:2000]
        await db.commit()
        return near
    row = GridGap(
        source=SOURCE_SWEEP,
        plane=plane,
        started_at=start,
        ended_at=end,
        detail=detail[:2000],
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


class GapRefused(ValueError):
    """An operator gap the ledger refuses. ``code`` names the rule it broke."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def check_operator_span(
    started_at: datetime, ended_at: datetime, *, now: datetime | None = None
) -> tuple[datetime, datetime]:
    """The edges of an operator gap as naive UTC, or :class:`GapRefused`.

    The ledger refuses an end at or before the start, a span over 30 days, a
    start in the future and an end in the future. Each of them states hours the
    grid did not miss. Every reader would then call those hours unknown.
    """
    start, end = _naive(started_at), _naive(ended_at)
    present = _naive(now or datetime.now(UTC))
    if end <= start:
        raise GapRefused("gap_end_before_start", "The end must be later than the start.")
    if start > present:
        raise GapRefused(
            "gap_start_in_future",
            "The start is in the future. Record a gap after the grid stops.",
        )
    if end > present + _END_SKEW:
        raise GapRefused(
            "gap_end_in_future",
            "The end is in the future. Record the gap after the grid comes back.",
        )
    if end - start > MAX_OPERATOR_SPAN:
        raise GapRefused(
            "gap_too_long",
            f"A gap can span {MAX_OPERATOR_SPAN.days} days at most. Check the start and the end.",
        )
    return start, end


async def record_operator_gap(
    db: AsyncSession,
    *,
    started_at: datetime,
    ended_at: datetime,
    detail: str | None,
    now: datetime | None = None,
) -> tuple[GridGap, bool]:
    """Record a gap that soc-ai did not see. Returns the row and whether it is new.

    The edges pass :func:`check_operator_span` first. An operator gap with the
    same edges is returned as it is, so a repeat of the command records nothing
    new. Any other operator gap is a new row, also when it overlaps an older one.
    """
    start, end = check_operator_span(started_at, ended_at, now=now)
    same = (
        await db.scalars(
            select(GridGap).where(
                GridGap.source == SOURCE_OPERATOR,
                GridGap.started_at == start,
                GridGap.ended_at == end,
            )
        )
    ).first()
    if same is not None:
        return same, False
    row = GridGap(
        source=SOURCE_OPERATOR,
        plane=None,
        started_at=start,
        ended_at=end,
        detail=(detail or "").strip()[:2000] or None,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row, True


async def get(db: AsyncSession, gap_id: int) -> GridGap | None:
    """One gap by its id, or None."""
    return await db.get(GridGap, int(gap_id))


async def overlapping(db: AsyncSession, *, since: datetime, until: datetime) -> list[GridGap]:
    """The gaps that overlap ``[since, until)``, oldest first. An open gap runs to now."""
    lo, hi = _naive(since), _naive(until)
    rows = await db.scalars(
        select(GridGap)
        .where(
            GridGap.started_at < hi,
            or_(GridGap.ended_at.is_(None), GridGap.ended_at > lo),
        )
        .order_by(GridGap.started_at, GridGap.id)
    )
    return list(rows.all())


async def closed_since(db: AsyncSession, *, since: datetime) -> list[GridGap]:
    """The gaps that closed at or after ``since``, newest end first."""
    rows = await db.scalars(
        select(GridGap)
        .where(GridGap.ended_at.is_not(None), GridGap.ended_at >= _naive(since))
        .order_by(GridGap.ended_at.desc(), GridGap.id.desc())
    )
    return list(rows.all())


@dataclass(frozen=True)
class GapWindow:
    """One gap as a reader compares it: aware UTC edges, the settle margin included."""

    start: datetime
    end: datetime

    def holds(self, at: datetime) -> bool:
        moment = _aware(at)
        return self.start <= moment < self.end

    def holds_span(self, start: datetime, end: datetime) -> bool:
        """Whether ``[start, end)`` lies inside this window."""
        return self.start <= _aware(start) and _aware(end) <= self.end

    def overlaps(self, start: datetime, end: datetime) -> bool:
        return self.start < _aware(end) and _aware(start) < self.end


def windows_of(
    gaps: Sequence[GridGap], *, settle: timedelta, now: datetime | None = None
) -> list[GapWindow]:
    """The windows a scoring reader leaves out: each gap, plus the settle margin.

    An open gap runs to ``now``. The margin follows the end, because the agents
    back-fill the hole after a restart.
    """
    present = _aware(now or datetime.now(UTC))
    out: list[GapWindow] = []
    for gap in gaps:
        end = _aware(gap.ended_at) if gap.ended_at is not None else present
        out.append(GapWindow(start=_aware(gap.started_at), end=end + settle))
    return out


def covered(at: datetime, windows: Sequence[GapWindow]) -> bool:
    """Whether a moment falls inside any of the windows."""
    return any(w.holds(at) for w in windows)


def gap_hours(gap: GridGap, *, now: datetime | None = None) -> float:
    """The length of a gap in hours. An open gap runs to ``now``."""
    end = _aware(gap.ended_at) if gap.ended_at is not None else _aware(now or datetime.now(UTC))
    return max(0.0, (end - _aware(gap.started_at)).total_seconds() / 3600.0)


def stamp(value: datetime) -> str:
    """A gap edge as the hints and the prompt write it: 2026-10-15 13:36 UTC."""
    return _aware(value).astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def fact_lines(gaps: Sequence[GridGap]) -> list[str]:
    """One line per gap for the model: the hours the grid held no data.

    The model read a zero count over a dead grid as a quiet host. Each line
    tells it that a zero over these hours is unknown. The newest gaps win
    when there are more than the prompt carries.
    """
    lines: list[str] = []
    for gap in sorted(gaps, key=lambda g: g.started_at)[-_MAX_FACT_LINES:]:
        if gap.ended_at is None:
            lines.append(
                f"The grid has held no data since {stamp(gap.started_at)}. "
                "A zero count over these hours means unknown."
            )
        else:
            lines.append(
                f"The grid held no data from {stamp(gap.started_at)} to "
                f"{stamp(gap.ended_at)}. A zero count over these hours means unknown."
            )
    return lines


# The words for the plane of a sweep gap. The sweep records the dimension it
# read, and the operator reads the plane that carries it.
_PLANE_WORDS = {"connection_rate": "network flow"}


def plane_words(plane: str | None) -> str:
    """The plane of a sweep gap as the console writes it."""
    if not plane:
        return "grid"
    return _PLANE_WORDS.get(plane, plane.replace("_", " "))


def describe(gap: GridGap) -> str:
    """One sentence that names the gap and its hours, for the bell and the hints."""
    if gap.source == SOURCE_OPERATOR and gap.ended_at is not None:
        return (
            f"An operator recorded a grid gap from {stamp(gap.started_at)} "
            f"to {stamp(gap.ended_at)}."
        )
    if gap.source == SOURCE_SWEEP:
        words = plane_words(gap.plane)
        if gap.ended_at is None:
            return f"Most hosts send no {words} documents since {stamp(gap.started_at)}."
        return (
            f"Most hosts sent no {words} documents from {stamp(gap.started_at)} "
            f"to {stamp(gap.ended_at)}."
        )
    if gap.ended_at is None:
        return f"The grid is unreadable since {stamp(gap.started_at)}."
    return f"The grid was unreadable from {stamp(gap.started_at)} to {stamp(gap.ended_at)}."


# How far back the model's fact lines reach. The console's widest preset window
# is 30 days, and a chat or a hunt asks about any window up to it.
FACT_LOOKBACK = timedelta(days=30)


async def recent_fact_lines(sessionmaker: Any, *, now: datetime | None = None) -> list[str]:
    """The fact lines for the gaps of the last 30 days. Never raises.

    A store that cannot be read gives no line. The prompt then says what it
    said before the ledger existed.
    """
    end = now or datetime.now(UTC)
    try:
        async with sessionmaker() as db:
            gaps = await overlapping(db, since=end - FACT_LOOKBACK, until=end)
    except Exception:
        return []
    return fact_lines(gaps)
