"""Per-run counters: model requests, tokens, tool calls, grid searches, wall time.

Every recorded run (an alert triage, a hunt, a lead hunt) lands these numbers
on its row, so the cost of a run is a column and not a reconstruction. Before
this module the store held the model ``usage`` events of a triage run and
nothing for a hunt, and no store held how many Elasticsearch searches a run
made. The 2026-10-04 survey had to compute every cost table by hand, and the
hunt and search columns stayed empty.

Two halves:

* :class:`SearchMeter` counts the Elasticsearch reads one run makes. The
  client cannot know which run called it, so the meter rides a context
  variable. :func:`start_search_meter` sets a fresh meter in the task that
  drives the run, and every child task the run spawns (a pydantic-ai tool
  call, a prefetch fan-out) copies the context, so it increments the same
  object. Never reset: a run that ends leaves a stale meter on its task, and
  the next run on that task replaces it before its first read.
* :class:`RunMeter` reads the run's own event stream. The recorder feeds it
  every event it persists, so the counters and the trail cannot disagree.

Dependency-free on purpose: :mod:`soc_ai.so_client.elastic` imports it, and
the agent package imports the client.
"""

from __future__ import annotations

import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

# The pydantic-ai output tool. A ``tool_call`` event with this name is the model
# handing back its structured answer, not a tool the run executed.
OUTPUT_TOOL_NAME = "final_result"


@dataclass
class SearchMeter:
    """Elasticsearch reads made by one run."""

    searches: int = 0


_SEARCH_METER: ContextVar[SearchMeter | None] = ContextVar("soc_ai_search_meter", default=None)


def count_search() -> None:
    """Count one Elasticsearch read against the current run, if one is metered."""
    meter = _SEARCH_METER.get()
    if meter is not None:
        meter.searches += 1


def start_search_meter() -> SearchMeter:
    """Start metering the Elasticsearch reads of the run this task drives.

    Call it in the task that iterates the run's event stream, before the first
    event is pulled. The returned meter is the one the recorder reads at finish.
    """
    meter = SearchMeter()
    _SEARCH_METER.set(meter)
    return meter


@dataclass
class RunCounters:
    """What one run cost. ``None`` on a field means the run did not report it."""

    model_requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    es_searches: int | None = None
    wall_ms: int = 0
    run_class: str | None = None

    def as_columns(self) -> dict[str, Any]:
        """The counters as the column values a run row stores."""
        return {
            "model_requests": self.model_requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "tool_calls": self.tool_calls,
            "es_searches": self.es_searches,
            "wall_ms": self.wall_ms,
            "run_class": self.run_class,
        }


# The run-row columns the counters land in (migration 0058). Investigations and
# hunts carry the same set.
COUNTER_COLUMNS: tuple[str, ...] = (
    "run_class",
    "model_requests",
    "input_tokens",
    "output_tokens",
    "tool_calls",
    "es_searches",
    "wall_ms",
)


def apply_counters(row: Any, counters: RunCounters | None) -> None:
    """Stamp ``counters`` onto a run row. ``None`` leaves the row untouched."""
    if counters is None:
        return
    for column, value in counters.as_columns().items():
        setattr(row, column, value)


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


class RunMeter:
    """Accumulate one run's counters from the events the recorder persists.

    * ``usage`` events carry the model requests and the tokens of one model
      run (round 1, the loop, a synthesis, a hunt agent run).
    * ``tool_call`` events are tools the model called. The output tool is not
      one of them.
    * ``targeted_dispatch`` events are tools the pipeline called in code, with
      no model turn: a Phase D dispatch, or the web search the pipeline makes
      before the loop. They count as tool calls, so moving a call from the
      model to the code does not make the run look cheaper than it is.
    * ``run_class`` rides the ``session_start``, ``triage_report`` and
      ``hunt_started`` payloads. The last one seen wins, because a cheap run
      that escalates states its final class on the report.
    """

    def __init__(self) -> None:
        self._started = time.monotonic()
        self._search: SearchMeter | None = None
        self._counters = RunCounters()

    def attach_search_meter(self, meter: SearchMeter) -> None:
        self._search = meter

    def observe(self, kind: str, payload: Any) -> None:
        p = payload if isinstance(payload, dict) else {}
        c = self._counters
        if kind == "usage":
            c.model_requests += _as_int(p.get("requests"))
            c.input_tokens += _as_int(p.get("input_tokens"))
            c.output_tokens += _as_int(p.get("output_tokens"))
        elif kind == "tool_call":
            if p.get("tool_name") != OUTPUT_TOOL_NAME:
                c.tool_calls += 1
        elif kind == "targeted_dispatch":
            c.tool_calls += 1
        run_class = p.get("run_class")
        if isinstance(run_class, str) and run_class:
            c.run_class = run_class

    def finish(self) -> RunCounters:
        """The counters as of now. Safe to call more than once."""
        c = self._counters
        c.wall_ms = int((time.monotonic() - self._started) * 1000)
        c.es_searches = self._search.searches if self._search is not None else None
        return c


__all__ = [
    "COUNTER_COLUMNS",
    "OUTPUT_TOOL_NAME",
    "RunCounters",
    "RunMeter",
    "SearchMeter",
    "apply_counters",
    "count_search",
    "start_search_meter",
]
