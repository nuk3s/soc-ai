"""The profile sweep's record of its own attempts, and the console words for an error.

Dogfood 2026-10-19 (R5-D5, H1-D2): while the grid was down for four days the
profile sweep skipped every wake and recorded nothing, so the Status page read
its rows as live and quiet. A sweep against a dead grid recorded rows of zeros
and no reason. The record here is what the console reads instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from soc_ai.hunting.loop_health import (
    OUTCOME_FAILED,
    OUTCOME_OK,
    OUTCOME_SKIPPED,
    SKIP_GRID_DOWN,
    LoopHealth,
    error_sentence,
    prior_health,
)

HOUR = timedelta(hours=1)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


@dataclass
class _Sweep:
    results: tuple[object, ...] = ()
    errors: tuple[str, ...] = ()
    evaluated_specs: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)


@pytest.mark.parametrize(
    ("raw", "sentence"),
    [
        (
            "precondition: Connection error caused by: ConnectionError(Connection error caused "
            "by: ClientConnectorError(Cannot connect to host 192.0.2.10:9200 ssl:default))",
            "soc-ai could not connect to the grid.",
        ),
        ("precondition: ConnectionTimeout caused by ...", "The grid did not answer in time."),
        ("detection: AuthenticationException(401, 'security_exception')", None),
        ("precondition: partial search results: 45 of 289 shards", None),
        ("detection: search_phase_execution_exception", "The grid refused the query."),
        ("something nobody planned for", None),
    ],
)
def test_an_error_reads_as_one_sentence_with_no_class_name(raw: str, sentence: str | None) -> None:
    text = error_sentence(raw)
    assert text is not None
    if sentence is not None:
        assert text == sentence
    for leak in ("Error(", "Exception", "192.0.2.10", "_exception", "caused by"):
        assert leak not in text


def test_no_error_has_no_sentence() -> None:
    assert error_sentence(None) is None
    assert error_sentence("  ") is None


def test_a_sweep_that_scored_nothing_and_reported_errors_failed() -> None:
    now = _now()
    health = LoopHealth()
    sweep = _Sweep(
        errors=("profile-a: recent read for conn failed: ConnectionError(x)",),
        evaluated_specs=("profile-a", "profile-b"),
    )
    health.note_sweep(now, sweep)
    snap = health.snapshot(now)
    assert snap is not None
    assert snap.last_outcome == OUTCOME_FAILED
    assert snap.last_error_text == "soc-ai could not connect to the grid."
    assert snap.failing_since == now
    assert snap.spec_errors == {"profile-a": sweep.errors[0]}


def test_a_sweep_that_scored_one_entity_completed() -> None:
    now = _now()
    health = LoopHealth()
    health.note_sweep(now, _Sweep(results=(object(),), errors=("profile-b: oops",)))
    snap = health.snapshot(now)
    assert snap is not None
    assert snap.last_outcome == OUTCOME_OK
    assert snap.failed_24h == 0
    assert snap.failing_since is None


def test_a_skip_counts_once_per_interval() -> None:
    """The loop wakes every minute. A skip is one run that did not happen, not sixty."""
    start = _now() - 3 * HOUR
    health = LoopHealth()
    counted = [
        health.note_skip(start + timedelta(minutes=m), SKIP_GRID_DOWN, HOUR) for m in range(0, 180)
    ]
    assert sum(counted) == 3
    snap = health.snapshot(start + 3 * HOUR)
    assert snap is not None
    assert snap.last_outcome == OUTCOME_SKIPPED
    assert snap.last_error_text == SKIP_GRID_DOWN
    assert (snap.runs_24h, snap.failed_24h) == (3, 3)
    assert snap.failing_since == start


def test_the_streak_ends_on_a_good_run_and_the_window_keeps_the_outage() -> None:
    now = _now()
    health = LoopHealth()
    health.note(now - 3 * HOUR, OUTCOME_FAILED, "boom")
    health.note(now - 2 * HOUR, OUTCOME_FAILED, "boom")
    health.note(now - HOUR, OUTCOME_OK)
    snap = health.snapshot(now)
    assert snap is not None
    assert snap.failing_since is None
    assert snap.last_error is None
    assert (snap.runs_24h, snap.failed_24h) == (3, 2), "one good run does not erase the outage"


def test_the_window_drops_attempts_older_than_a_day() -> None:
    now = _now()
    health = LoopHealth()
    health.note(now - 30 * HOUR, OUTCOME_FAILED, "boom")
    health.note(now - HOUR, OUTCOME_FAILED, "boom")
    snap = health.snapshot(now)
    assert snap is not None
    assert (snap.runs_24h, snap.failed_24h) == (1, 1)
    assert snap.failing_since == now - 30 * HOUR, "the streak is older than the window"
    assert snap.counted_since == now - 24 * HOUR


def test_no_attempt_has_no_snapshot() -> None:
    assert LoopHealth().snapshot(_now()) is None


def test_the_record_lives_on_the_app_state() -> None:
    state = SimpleNamespace()
    first = prior_health(state)
    assert prior_health(state) is first
