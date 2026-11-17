"""The time of the event that an investigation judges (migration 0072).

The owner, 2026-11-15: "The 'when' in investigations is causing events from
several days ago to show up as recent TPs." A hunt and a Re-run judged events
of 3 and 17 days ago, and the list, the Dashboard tile and the Confirmed
threats panel dated them by the time soc-ai investigated them.

For the analyst, the time of an investigation is the time of the event that
it judges. ``investigations.event_at`` holds it, and :func:`decide` is the one
rule that fills it:

1. the settled event time of the run (``report["event_time"]``, written by
   the orchestrator from the alert of the run),
2. else the time of the stored alert (the ``alert.timestamp`` of the first
   context event, :func:`soc_ai.store.investigations.alert_event_times`),
3. else ``created_at``.

An event time later than ``created_at`` is clamped to ``created_at``: the
event happened before soc-ai investigated it, and a sensor clock that runs
ahead must not sort a row above every newer one. A malformed time counts as
no time.

Every writer calls the rule: the insert hook of the model (with no alert
time), ``finalize`` and the reaper of the store (with the alert time), the
demo seed, and migration 0072 for the rows stored before it. This module
imports nothing from the store, so the model and the migration can import it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

# The key of the stored report that holds the settled event time.
EVENT_TIME_KEY = "event_time"


def parse_time(raw: Any) -> datetime | None:
    """An ISO time as naive UTC, or None. A value with no offset is UTC."""
    if isinstance(raw, datetime):
        value = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            value = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if value.tzinfo is None:
        return value
    try:
        return value.astimezone(UTC).replace(tzinfo=None)
    except OverflowError:
        # A time at the edge of the calendar with an offset has no UTC value.
        return None


def first_time(raws: Iterable[Any]) -> datetime | None:
    """The first value of *raws* that parses as a time, as naive UTC, or None.

    The time of the stored alert of a run: the ``alert.timestamp`` of its
    context events, in the order of the events.
    """
    for raw in raws:
        at = parse_time(raw) if isinstance(raw, str) else None
        if at is not None:
            return at
    return None


def stored_event_time(report: Any) -> datetime | None:
    """The settled event time of a stored report as naive UTC, or None."""
    raw = report.get(EVENT_TIME_KEY) if isinstance(report, Mapping) else None
    return parse_time(raw)


def decide(*, report: Any, alert_at: datetime | None, created_at: datetime) -> datetime:
    """The event time of one investigation: the one rule of ``event_at``.

    ``report`` is the stored report (or None), ``alert_at`` the time of the
    stored alert as naive UTC (or None), ``created_at`` the time when soc-ai
    started the investigation. An aware value of either time counts as the
    same instant in UTC.
    """
    created = parse_time(created_at) or created_at
    at = stored_event_time(report) or parse_time(alert_at)
    if at is None or at > created:
        return created
    return at


__all__ = ["EVENT_TIME_KEY", "decide", "first_time", "parse_time", "stored_event_time"]
