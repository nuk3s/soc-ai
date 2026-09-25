"""The arithmetic behind a behavioural profile. Pure — no I/O, no grid.

Three cells, not 168 bins. A 30-day window over hour-of-week bins gives four
or five samples per bin and a MAD of zero in most of them, and a MAD of zero
is not a dispersion — it is a division by zero wearing a number's clothes.
Work hours, off hours and weekend give dozens of samples each.

Median and MAD rather than mean and standard deviation, because the thing a
baseline most needs to survive is the event it is meant to catch. One spike
moves a mean enough that the second spike looks ordinary; it does not move a
median at all.

Everything here is bucketed in the deployment's LOCAL time. Bucketing in UTC
mislabels an entire timezone's working day as off hours, and "activity outside
business hours" is one of the loudest dimensions in the profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

__all__ = [
    "GUARDED_PORT_DIMENSIONS",
    "LINUX_EPHEMERAL_START",
    "Cell",
    "TimeCell",
    "cell_for",
    "mad",
    "median",
    "robust_z",
    "served_port_counts",
    "summarise_cells",
]

# Makes MAD comparable to a standard deviation for normally distributed data,
# so a threshold expressed in "sigmas" means roughly what a reader expects.
_MAD_TO_SIGMA = 0.6745

_WORK_START_HOUR = 8
_WORK_END_HOUR = 18


class TimeCell(Enum):
    """The three cells a numeric dimension is measured in."""

    WORK = "work"
    OFF = "off"
    WEEKEND = "weekend"


@dataclass(frozen=True)
class Cell:
    """One cell's summary.

    ``support_days`` is distinct LOCAL days, not samples. Ten samples in one
    afternoon is one day of support; counting samples instead would let a
    single busy afternoon clear a seven-day minimum-support bar.
    """

    median: float | None = None
    dispersion: float | None = None
    support_days: int = 0
    samples: int = 0


def median(values: list[float]) -> float | None:
    """The middle value, or None for an empty list."""
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def mad(values: list[float]) -> float | None:
    """Median absolute deviation from the median."""
    med = median(values)
    if med is None:
        return None
    return median([abs(v - med) for v in values])


def robust_z(*, value: float, med: float | None, dispersion: float | None) -> float | None:
    """How far ``value`` sits from ``med`` in MAD-derived sigmas.

    Signed on purpose: a backup that stops is as interesting as one that
    doubles, and ``below`` is a departure kind in its own right. Taking an
    absolute value here would erase the distinction before anything could
    read it.

    Returns None when there is no dispersion to measure against. A cell whose
    samples are all identical cannot say how surprising anything is, and the
    infinity a naive division produces sorts above every real departure.
    """
    if med is None or dispersion is None or dispersion <= 0.0:
        return None
    return _MAD_TO_SIGMA * (value - med) / dispersion


def _zone(tz: str) -> ZoneInfo:
    """The named zone, falling back to UTC rather than raising.

    A misconfigured ``so_timezone`` must not take the whole dossier sweep down.
    """
    try:
        return ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def cell_for(at: datetime, *, tz: str) -> TimeCell:
    """Which cell a moment falls in, in the deployment's local time."""
    local = at.astimezone(_zone(tz))
    if local.weekday() >= 5:
        return TimeCell.WEEKEND
    if _WORK_START_HOUR <= local.hour < _WORK_END_HOUR:
        return TimeCell.WORK
    return TimeCell.OFF


def summarise_cells(samples: list[tuple[datetime, float]], *, tz: str) -> dict[TimeCell, Cell]:
    """Bucket (moment, value) samples into the three cells and summarise each.

    Every cell is present in the result even when empty, so a profile can say
    "no weekend activity observed" — which is a fact — rather than omitting the
    cell, which is indistinguishable from never having measured it.
    """
    grouped: dict[TimeCell, list[float]] = {cell: [] for cell in TimeCell}
    days: dict[TimeCell, set[str]] = {cell: set() for cell in TimeCell}
    zone = _zone(tz)

    for at, value in samples:
        cell = cell_for(at, tz=tz)
        grouped[cell].append(float(value))
        # Local date, matching the cell boundary. Counting distinct days in
        # UTC reports two days of support for one local evening that happens
        # to straddle midnight UTC.
        days[cell].add(at.astimezone(zone).date().isoformat())

    return {
        cell: Cell(
            median=median(values),
            dispersion=mad(values),
            support_days=len(days[cell]),
            samples=len(values),
        )
        for cell, values in grouped.items()
    }


# The port range Linux hands out per connection. The IANA dynamic floor
# (49152, so_client.fields.EPHEMERAL_PORT_FLOOR) stays where it is. The range
# read a listener at 47908 once, and a numeric floor high enough to catch it
# would hide a real listener parked on a high port. A port in this range has
# to earn its place with peers AND days.
LINUX_EPHEMERAL_START = 32768

# The dimensions the peers-or-days guard applies to: sets of ports the ENTITY
# answers on, keyed by destination.ip.
GUARDED_PORT_DIMENSIONS = frozenset({"served_ports"})


def served_port_counts(member: Any, *, count: int, peers: int, days: int) -> bool:
    """Whether a port earned a place in a served-port set.

    Telemetry-independent. A served port is one several machines reach, or
    one reached again on another day. One peer on one day is what an
    ephemeral source port looks like when a sensor writes the reply as a
    flow. The production sweep read 73 of them as new services on two
    hypervisors. Every one was a Postfix DNS lookup seen by the endpoint
    sensor.

    ``count`` below one never counts. A member that is not a port number
    never counts. The dimension is a set of ports, and a word in it is a
    mapping defect, not a service.
    """
    if count < 1:
        return False
    try:
        port = int(str(member))
    except (TypeError, ValueError):
        return False
    if port >= LINUX_EPHEMERAL_START:
        return peers >= 2 and days >= 2
    return peers >= 2 or days >= 2
