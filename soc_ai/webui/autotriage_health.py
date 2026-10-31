"""Auto-Investigate health: the retry wait, the alarm and the pause.

On 2026-10-27 the model gateway refused the triage schema from 00:16 to 11:25
UTC. Every cheap-class run failed in about 0.3 s with ModelHTTPError in
synth_first_round1. A pipeline fallback does not count as triaged, so the
scheduler planned the same two alerts on every 5-minute cycle and ran each of
them 109 times: 226 fallbacks in 11 hours. 42 standard-class false positives
landed between the failures, so a rule of "five failures in a row" never
fired. The bell showed each fallback as a needs_more_info verdict, and no
surface named the fault.

On 2026-10-28 one alert failed 6 times before it reached a verdict: 2 whole-run
timeouts, 3 run_cancelled stops at about 600 s and 1 ModelHTTPError in
investigation_loop.

This module holds three guards. The state lives in the process, the same way
the Oracle route breaker holds its state (:mod:`soc_ai.oracle.breaker`).

- The retry wait. A failed alert waits 15 minutes before its first retry, and
  each next retry waits twice as long. After ``auto_triage_retry_limit``
  retries it runs once each 6 hours. The count comes from the store
  (:func:`soc_ai.store.investigations.failed_runs_for_alerts`).
- The alarm. Five failed runs with the same error in two hours open one bell
  alarm, also when verdicts land between them. While it is open, one failed
  alert runs each hour as a probe. A verdict on an alert that failed with that
  error closes the alarm and gives the other alerts with that error their
  retries back.
- The pause. Five failed runs in a row with no verdict between them stop the
  scheduled runs for 15 minutes. Each failure after that doubles the pause, up
  to one hour. A verdict ends the pause.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.oracle import breaker
from soc_ai.store.investigations import FailedRuns

_LOGGER = logging.getLogger(__name__)

RETRY_FIRST_WAIT = timedelta(minutes=15)
"""The wait before the first retry of a failed alert. Each next wait doubles."""
RETRY_SLOW_WAIT = timedelta(hours=6)
"""The wait of an alert past its retry limit, and the longest wait of all."""
ALARM_AFTER = 5
"""Failed runs with one error in ALARM_WINDOW that open the alarm."""
ALARM_WINDOW = timedelta(hours=2)
# One alert alone puts at most 4 failures in any 2 h window at any limit up to
# 10: its waits are 15, 30, 60 and 120 minutes. So only two or more alerts can
# open the alarm.
ALARM_STALE = timedelta(hours=2)
"""An alarm with no failure for this long closes on the next verdict."""
PROBE_EVERY = timedelta(hours=1)
"""While an alarm is open, one failed alert runs again this often."""
PAUSE_AFTER = 5
"""Failed runs in a row, with no verdict between them, that pause the scheduler."""
PAUSE_FIRST = timedelta(minutes=15)
PAUSE_MAX = timedelta(hours=1)
MEMORY = timedelta(hours=24)
"""How long the failed error of an alert and its heal stay in memory."""

TIMEOUT_KEY = "timeout"
# Every shape a run that ran out of time takes. One timeout that recovers says
# the backend answers again, so they share one key.
_TIMEOUT_PHASES = frozenset(
    {"whole_run_backstop", "run_cancelled", "per_target_cap", "investigation_loop_timeout"}
)
_TIMEOUT_TYPES = frozenset({"TimeoutError", "CancelledError"})

RETRY_WAIT = "retry_wait"
RETRY_LIMIT = "retry_limit"


def _now() -> datetime:
    """The clock, aware UTC. Tests patch this."""
    return datetime.now(UTC)


def error_key(phase: str, error_type: str) -> str:
    """The error class of a failed run. All timeout shapes share one key."""
    if phase in _TIMEOUT_PHASES or error_type in _TIMEOUT_TYPES:
        return TIMEOUT_KEY
    return f"{error_type} in {phase}"


def describe(phase: str, error_type: str) -> str:
    """The error name the operator reads: "ModelHTTPError in synth_first_round1"."""
    return f"{error_type} in {phase}" if phase else error_type


def _doubled(times: int) -> int:
    """2 to the power ``times``, held at 2**8. The waits it scales stop at 6 hours.

    A pause that a long outage extends hundreds of times would otherwise
    multiply a timedelta past its range.
    """
    factor: int = 2 ** min(max(times, 0), 8)
    return factor


def retry_wait(count: int, limit: int) -> timedelta:
    """The wait after the ``count``-th failed run of one alert."""
    if count > limit:
        return RETRY_SLOW_WAIT
    return min(RETRY_FIRST_WAIT * _doubled(count - 1), RETRY_SLOW_WAIT)


def retry_hold(limit: int, failed: FailedRuns | None, *, now: datetime) -> str | None:
    """Why the sweep holds a failed alert back, or None when it may run.

    ``now`` is naive UTC, the clock of ``failed.last_at``. The answer is a skip
    reason: ``retry_limit`` past the limit, else ``retry_wait``.
    """
    if failed is None or now - failed.last_at >= retry_wait(failed.count, limit):
        return None
    return RETRY_LIMIT if failed.count > limit else RETRY_WAIT


def _stamp(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def pause_text(until: datetime, streak: int, error: str) -> str:
    """The bell title while the pause is open."""
    return (
        f"Continuous Auto-Investigate is paused until {_stamp(until)} UTC. The last "
        f"{streak} runs failed, and no run reached a verdict. The last error is {error}. "
        "A run that reaches a verdict ends the pause."
    )


def alarm_text(failures: int, error: str) -> str:
    """The bell title while an alarm is open."""
    return (
        f"{failures} Auto-Investigate runs failed with the same error: {error}. A failed "
        "alert waits longer before each retry. A verdict on one of these alerts closes "
        "this alarm."
    )


@dataclass
class ErrorAlarm:
    """One open alarm: runs keep failing with one error class."""

    key: str
    phase: str
    error_type: str
    since: datetime
    failures: int
    last_at: datetime
    last_probe_at: datetime | None = None

    def describe(self) -> str:
        return describe(self.phase, self.error_type)


@dataclass
class TriageHealth:
    """The alarms, the pause, the probes and the heals of this process.

    Every time is aware UTC.
    """

    # Failure times per error class in the last ALARM_WINDOW.
    recent: dict[str, list[datetime]] = field(default_factory=dict)
    alarms: dict[str, ErrorAlarm] = field(default_factory=dict)
    # alert id -> (error class, time) of its last failure.
    failed_class: dict[str, tuple[str, datetime]] = field(default_factory=dict)
    # alert id -> the verdict that healed its error class.
    forgiven: dict[str, datetime] = field(default_factory=dict)
    # Failed runs since the last verdict.
    streak: int = 0
    last_error: tuple[str, str] | None = None
    paused_until: datetime | None = None
    pause_since: datetime | None = None
    pause_count: int = 0

    def _prune(self, at: datetime) -> None:
        for key in list(self.recent):
            kept = [t for t in self.recent[key] if at - t < ALARM_WINDOW]
            if kept:
                self.recent[key] = kept
            else:
                del self.recent[key]
        self.failed_class = {
            a: (k, t) for a, (k, t) in self.failed_class.items() if at - t < MEMORY
        }
        self.forgiven = {a: t for a, t in self.forgiven.items() if at - t < MEMORY}

    def record_failure(
        self, alert_id: str, phase: str, error_type: str, *, at: datetime | None = None
    ) -> tuple[bool, bool]:
        """Record one failed run. Returns (the alarm opened, the pause opened).

        Only a transition returns True, so a caller can log once per outage.
        """
        at = at or _now()
        self._prune(at)
        key = error_key(phase, error_type)
        self.recent.setdefault(key, []).append(at)
        self.failed_class[alert_id] = (key, at)
        self.last_error = (phase, error_type)
        self.streak += 1

        alarm_opened = False
        alarm = self.alarms.get(key)
        if alarm is not None:
            alarm.failures += 1
            alarm.last_at = at
            alarm.phase = phase
            alarm.error_type = error_type
        elif len(self.recent[key]) >= ALARM_AFTER:
            alarm = ErrorAlarm(
                key=key,
                phase=phase,
                error_type=error_type,
                since=at,
                failures=len(self.recent[key]),
                last_at=at,
            )
            self.alarms[key] = alarm
            alarm_opened = True
            _LOGGER.warning(
                "auto-triage: %d runs failed with the same error in two hours: %s. "
                "The bell shows an alarm.",
                alarm.failures,
                alarm.describe(),
            )

        pause_opened = False
        if self.streak >= PAUSE_AFTER:
            self.paused_until = at + min(PAUSE_FIRST * _doubled(self.pause_count), PAUSE_MAX)
            self.pause_count += 1
            if self.pause_since is None:
                self.pause_since = at
                pause_opened = True
                _LOGGER.warning(
                    "auto-triage: %d runs failed in a row, and no run reached a verdict. "
                    "Continuous Auto-Investigate is paused until %s.",
                    self.streak,
                    breaker.iso(self.paused_until),
                )
        return alarm_opened, pause_opened

    def record_verdict(self, alert_id: str, *, at: datetime | None = None) -> None:
        """Record a run that reached a real verdict. Idempotent.

        The verdict ends the pause and gives no retries back. A verdict on an
        alert that failed with error class K closes alarm K and heals every
        alert that failed with K. Any other alarm with no failure for
        ALARM_STALE closes too, and heals nothing.
        """
        at = at or _now()
        self.streak = 0
        if self.pause_since is not None:
            self.paused_until = None
            self.pause_since = None
            self.pause_count = 0
            _LOGGER.info("auto-triage: a run reached a verdict. The pause is closed.")
        entry = self.failed_class.get(alert_id)
        if entry is not None:
            key = entry[0]
            for other, (other_key, _t) in self.failed_class.items():
                if other_key == key:
                    self.forgiven[other] = at
            self.recent.pop(key, None)
            alarm = self.alarms.pop(key, None)
            if alarm is not None:
                _LOGGER.info(
                    "auto-triage: a run of a failed alert reached a verdict. "
                    "The alarm for %s is closed.",
                    alarm.describe(),
                )
            self.failed_class.pop(alert_id, None)
        for key, alarm in list(self.alarms.items()):
            if at - alarm.last_at >= ALARM_STALE:
                del self.alarms[key]
                _LOGGER.info(
                    "auto-triage: no run failed with %s in two hours. The alarm is closed.",
                    alarm.describe(),
                )

    def is_paused(self, at: datetime | None = None) -> bool:
        """True while the scheduled runs wait."""
        at = at or _now()
        return self.paused_until is not None and self.paused_until > at

    def take_probe(self, alert_id: str, *, at: datetime | None = None) -> bool:
        """Admit a held alert as the probe of its open alarm, once an hour."""
        at = at or _now()
        entry = self.failed_class.get(alert_id)
        if entry is None:
            return False
        alarm = self.alarms.get(entry[0])
        if alarm is None:
            return False
        last = alarm.last_at
        if alarm.last_probe_at is not None and alarm.last_probe_at > last:
            last = alarm.last_probe_at
        if at - last < PROBE_EVERY:
            return False
        alarm.last_probe_at = at
        _LOGGER.info(
            "auto-triage: alert_id=%s runs again as a test of the alarm for %s.",
            alert_id,
            alarm.describe(),
        )
        return True

    def heal_since(self, alert_id: str) -> datetime | None:
        """The verdict that healed the error class of this alert, or None."""
        return self.forgiven.get(alert_id)

    def newest_alarm(self) -> ErrorAlarm | None:
        if not self.alarms:
            return None
        return max(self.alarms.values(), key=lambda a: a.since)

    def bell_row(self, at: datetime | None = None) -> tuple[str, str, datetime] | None:
        """(id, title, since) of the one bell row, or None when all is well.

        The id carries the start of the outage: the newest alarm, else the
        pause. One id holds for one outage, and a new error class gets a new id.
        """
        at = at or _now()
        alarm = self.newest_alarm()
        paused = self.is_paused(at)
        if alarm is None and not paused:
            return None
        since = alarm.since if alarm is not None else (self.pause_since or at)
        row_id = f"auto-triage-failing:{breaker.iso(since)}"
        if alarm is not None and not paused:
            return row_id, alarm_text(alarm.failures, alarm.describe()), since
        if self.last_error is not None:
            error = describe(*self.last_error)
        elif alarm is not None:
            error = alarm.describe()
        else:
            error = "an unknown error"
        until = self.paused_until or at
        return row_id, pause_text(until, self.streak, error), since

    def status_fields(self, at: datetime | None = None) -> dict[str, Any]:
        """The fields GET /auto-triage adds for the Status page."""
        at = at or _now()
        paused = self.is_paused(at)
        alarm = self.newest_alarm()
        if alarm is not None:
            alarm_error: str | None = alarm.describe()
        elif paused and self.last_error is not None:
            alarm_error = describe(*self.last_error)
        else:
            alarm_error = None
        # The end of the last pause holds until a verdict closes the pause.
        # The next scheduled run comes up to one interval after it, so the
        # Status page measures an overdue run from this moment.
        open_pause = self.pause_since is not None and self.paused_until is not None
        return {
            "paused_until": breaker.iso(self.paused_until) if paused else None,
            "pause_ends": breaker.iso(self.paused_until) if open_pause else None,
            "failed_in_a_row": self.streak if paused else 0,
            "alarm_error": alarm_error,
            "alarm_failures": alarm.failures if alarm is not None else 0,
        }


__all__ = [
    "ALARM_AFTER",
    "ALARM_STALE",
    "ALARM_WINDOW",
    "MEMORY",
    "PAUSE_AFTER",
    "PAUSE_FIRST",
    "PAUSE_MAX",
    "PROBE_EVERY",
    "RETRY_FIRST_WAIT",
    "RETRY_LIMIT",
    "RETRY_SLOW_WAIT",
    "RETRY_WAIT",
    "ErrorAlarm",
    "TriageHealth",
    "alarm_text",
    "describe",
    "error_key",
    "pause_text",
    "retry_hold",
    "retry_wait",
]
