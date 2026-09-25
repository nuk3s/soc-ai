"""The window one catalog sweep covers, computed in one place for every caller.

Three paths need the same two numbers and used to compute them separately.
The scheduler in :mod:`soc_ai.main` floors the interval at five minutes and
widens a look-back that is not wider than the interval, saying so in the log;
``soc-ai spec-sweep`` with no ``--since`` widened but did not floor and said
nothing, so the two could disagree about what one sweep covers and only one of
them would tell you; and the catalog route reported the setting as typed, so
the Operate panel could say "looks back 60m" over trail rows that recorded 61.

This module lives in :mod:`soc_ai.hunting` beside the sweep it describes, and
apart from :mod:`soc_ai.hunting.sweep` on purpose: the sweep module imports the
Elasticsearch client and the store, and a route that only wants to report a
number should not pay for those. It imports nothing of soc-ai's own.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

# The interval floor. Far below the hour scheduled hunts need, because a sweep
# runs no model; not zero, because each sweep is a real query against the
# analyst's grid. The config console enforces the same floor on its own
# control; this is for the value that arrives by environment instead.
MIN_INTERVAL_MINUTES = 5

# How far back the prior sweep reads for "what did this entity do lately".
# Lives here, beside the other window numbers and away from the sweep, so the
# wording module can state the window in a sentence without importing the
# sweep that calls the evaluator that calls the wording.
DEFAULT_RECENT_HOURS = 24


class SweepSettings(Protocol):
    """The two settings the window is computed from."""

    hunt_spec_sweep_interval_minutes: int
    hunt_spec_sweep_window_minutes: int


@dataclass(frozen=True)
class SweepWindow:
    """What one sweep covers, after the floor and the clamp.

    ``interval_minutes`` and ``window_minutes`` are the EFFECTIVE values, the
    ones a sweep runs with and the trail rows record. ``configured_window_minutes``
    is the setting as typed, kept so the widening can be said out loud with
    both numbers in it.
    """

    interval_minutes: int
    window_minutes: int
    configured_window_minutes: int

    @property
    def widened(self) -> bool:
        return self.window_minutes != self.configured_window_minutes

    @property
    def since(self) -> str:
        """The window start as Elasticsearch date math, the form the sweep takes."""
        return f"now-{self.window_minutes}m"

    def say_if_widened(self, log: logging.Logger) -> None:
        """Log the widening, from a path that is about to sweep.

        Called once per sweep rather than inside :func:`sweep_window` because
        not every reader is a sweep: the catalog route computes the window to
        report it, on a panel that polls every five minutes, and a warning per
        poll would bury the one per sweep that matters.
        """
        if self.widened:
            log.warning(
                "spec sweep: look-back window (%dm) is not wider than the interval "
                "(%dm), which would leave an unexamined gap between sweeps; "
                "widening the window to %dm for this run",
                self.configured_window_minutes,
                self.interval_minutes,
                self.window_minutes,
            )


def sweep_window(settings: SweepSettings) -> SweepWindow:
    """The window a sweep under ``settings`` covers.

    The window MUST exceed the interval or the sweep leaves a blind gap between
    runs: window=5 with interval=60 examines five minutes in every sixty and
    reports the other fifty-five as clean. The two console settings are
    validated independently, so nothing else enforces the relationship, and it
    is clamped here rather than trusted. The interval is floored first, so a
    window narrower than the floor is widened past the floor and not past the
    number that was typed.
    """
    interval = max(MIN_INTERVAL_MINUTES, int(settings.hunt_spec_sweep_interval_minutes))
    configured = int(settings.hunt_spec_sweep_window_minutes)
    window = configured if configured > interval else interval + 1
    return SweepWindow(
        interval_minutes=interval,
        window_minutes=window,
        configured_window_minutes=configured,
    )


__all__ = ["MIN_INTERVAL_MINUTES", "SweepSettings", "SweepWindow", "sweep_window"]
