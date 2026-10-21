"""What an unattended sweep loop did on its recent wakes, and the words for it.

The catalog sweep writes one trail row per analytic per run, a failed run
included, so the trail answers "did the last sweep fail" for that loop
(:func:`soc_ai.store.hunt_spec_sweeps.loop_status`). The profile sweep did
not. Its trail (``prior_spec_runs``) records the runs that completed, and a
wake that found the grid down recorded nothing at all. While the grid was down
for four days the Status page read the profile rows as live and quiet
(dogfood 2026-10-19, R5-D5 and H1-D2).

:class:`LoopHealth` is that missing record for the profile sweep. It lives on
``app.state`` and holds the last day of attempts: a run that completed, a run
that failed and a wake that skipped the run because the grid was down. It is
in memory, so a restart starts it again. ``counted_since`` says from when it
counts, and the console states that window.

:func:`error_sentence` turns a stored exception text into one sentence for the
console. The raw text stays in the trail and in the log. An analyst reading
the Analytics tab gets the sentence and not the exception class.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

__all__ = [
    "OUTCOME_FAILED",
    "OUTCOME_OK",
    "OUTCOME_SKIPPED",
    "SKIP_GRID_DOWN",
    "LoopHealth",
    "LoopSnapshot",
    "error_sentence",
    "prior_health",
]

OUTCOME_OK = "ok"
OUTCOME_FAILED = "failed"
OUTCOME_SKIPPED = "skipped"

# The window the counts cover. The same 24 h the trail counters use.
WINDOW = timedelta(hours=24)

# The reason a profile sweep wake did not run the sweep.
SKIP_GRID_DOWN = "The grid did not answer the health check. soc-ai skipped the sweep."

_STE_DEFAULT = "The sweep stopped on an error. The application log holds the details."

# Needle, then sentence. The first needle found decides. The order puts the
# connection failure first: a connection error text also names a timeout or
# a status code in its chain.
_SENTENCES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(needle, re.IGNORECASE), sentence)
    for needle, sentence in (
        (
            r"cannot connect to host|connection refused|connectionerror|connection error"
            r"|connect call failed|name or service not known|nodename nor servname"
            r"|did not accept a connection",
            "soc-ai could not connect to the grid.",
        ),
        (r"timeout|timed out|did not answer in time", "The grid did not answer in time."),
        (
            r"authenticationexception|\b401\b|unauthori[sz]ed|rejected the credentials",
            "The grid refused the credentials of soc-ai.",
        ),
        (
            r"partial search results|shards? failed|of \d+ shards",
            "The grid answered from a part of its shards. The result is incomplete.",
        ),
        (r"index_not_found|no such index", "The grid has no index that the analytic reads."),
        (
            r"authorizationexception|security_exception|\b403\b|forbidden|refused the query"
            r"|search_phase_execution|parsing_exception|query_shard_exception"
            r"|illegal_argument|rejected the query",
            "The grid refused the query.",
        ),
    )
)


def error_sentence(text: str | None) -> str | None:
    """One console sentence for a stored error text. None for no error.

    The sentence names what the grid did. It never quotes the exception, so
    no class name and no address reaches the console.
    """
    raw = (text or "").strip()
    if not raw:
        return None
    for pattern, sentence in _SENTENCES:
        if pattern.search(raw):
            return sentence
    return _STE_DEFAULT


@dataclass(frozen=True)
class LoopSnapshot:
    """The state of one loop at one moment, as the hunt-catalog route reads it."""

    last_at: datetime
    last_outcome: str
    last_error: str | None
    last_error_text: str | None
    runs_24h: int
    failed_24h: int
    failing_since: datetime | None
    counted_since: datetime
    spec_errors: dict[str, str]


@dataclass
class LoopHealth:
    """The last day of attempts of one loop. One per process, on ``app.state``."""

    attempts: list[tuple[datetime, str]] = field(default_factory=list)
    last_at: datetime | None = None
    last_outcome: str | None = None
    last_error: str | None = None
    failing_since: datetime | None = None
    counted_since: datetime | None = None
    # The raw error of each analytic the last attempt named, keyed by its id.
    spec_errors: dict[str, str] = field(default_factory=dict)

    def note(
        self,
        at: datetime,
        outcome: str,
        error: str | None = None,
        *,
        spec_errors: dict[str, str] | None = None,
    ) -> None:
        """Record one attempt. ``error`` is the raw text, kept for the trail."""
        if self.counted_since is None:
            self.counted_since = at
        self.attempts = [(t, o) for t, o in self.attempts if t >= at - WINDOW]
        self.attempts.append((at, outcome))
        if outcome == OUTCOME_OK:
            self.failing_since = None
        elif self.last_outcome in (None, OUTCOME_OK) or self.failing_since is None:
            self.failing_since = at
        self.last_at = at
        self.last_outcome = outcome
        self.last_error = error if outcome != OUTCOME_OK else None
        self.spec_errors = dict(spec_errors or {})

    def note_skip(self, at: datetime, reason: str, every: timedelta) -> bool:
        """Record a wake that did not run a due sweep, once per interval.

        The loop wakes every minute and the grid check runs on each wake, so
        a skip is counted once for each interval it covers. Returns whether
        it was counted.
        """
        if (
            self.last_outcome == OUTCOME_SKIPPED
            and self.last_at is not None
            and at - self.last_at < every
        ):
            return False
        self.note(at, OUTCOME_SKIPPED, reason)
        return True

    def note_sweep(self, at: datetime, sweep: Any) -> None:
        """Record a profile sweep that returned.

        It failed when it reported errors and scored no entity: the grid gave
        it nothing to measure. It completed when it scored at least one, and
        the analytics its errors name keep their own error.
        """
        errors = [str(e) for e in (getattr(sweep, "errors", ()) or ())]
        results = getattr(sweep, "results", ()) or ()
        evaluated = [str(s) for s in (getattr(sweep, "evaluated_specs", ()) or ())]
        per_spec: dict[str, str] = {}
        for err in errors:
            spec_id = next(
                (s for s in evaluated if err.startswith((f"{s}:", f"{s}/"))),
                None,
            )
            if spec_id is not None and spec_id not in per_spec:
                per_spec[spec_id] = err
        if errors and not results:
            self.note(at, OUTCOME_FAILED, errors[0], spec_errors=per_spec)
        else:
            self.note(at, OUTCOME_OK, spec_errors=per_spec)

    def snapshot(self, now: datetime) -> LoopSnapshot | None:
        """The state now. None before the first attempt."""
        if self.last_at is None or self.last_outcome is None or self.counted_since is None:
            return None
        window = [o for t, o in self.attempts if t >= now - WINDOW]
        return LoopSnapshot(
            last_at=self.last_at,
            last_outcome=self.last_outcome,
            last_error=self.last_error,
            last_error_text=(
                self.last_error
                if self.last_outcome == OUTCOME_SKIPPED
                else error_sentence(self.last_error)
            ),
            runs_24h=len(window),
            failed_24h=sum(1 for o in window if o != OUTCOME_OK),
            failing_since=self.failing_since,
            counted_since=max(self.counted_since, now - WINDOW),
            spec_errors=dict(self.spec_errors),
        )


def prior_health(state: Any) -> LoopHealth:
    """The profile sweep's record on ``app.state``. Created on the first read."""
    health = getattr(state, "prior_sweep_health", None)
    if not isinstance(health, LoopHealth):
        health = LoopHealth()
        state.prior_sweep_health = health
    return health
