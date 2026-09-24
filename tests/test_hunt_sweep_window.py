"""The one window computation the scheduler, the CLI and the catalog route share.

Before this helper the scheduler floored the interval and widened the window
with a warning, and the CLI widened without flooring and without a word, so
the two could disagree about what one sweep covers and only one of them said
so. These tests pin the arithmetic once; the callers' tests pin that each of
them uses it.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from soc_ai.hunting.window import MIN_INTERVAL_MINUTES, sweep_window


def _settings(window: int, interval: int) -> SimpleNamespace:
    return SimpleNamespace(
        hunt_spec_sweep_window_minutes=window, hunt_spec_sweep_interval_minutes=interval
    )


def test_a_window_wider_than_the_interval_passes_through() -> None:
    w = sweep_window(_settings(1440, 60))
    assert (w.interval_minutes, w.window_minutes) == (60, 1440)
    assert w.since == "now-1440m"
    assert w.widened is False


def test_a_window_not_wider_than_the_interval_is_widened_past_it() -> None:
    """window=5 with interval=60 examines five minutes in every sixty."""
    w = sweep_window(_settings(5, 60))
    assert w.window_minutes == 61
    assert w.since == "now-61m"
    assert w.widened is True
    assert w.configured_window_minutes == 5, "the number that was typed is kept for the log"
    # Equal is not wider either: back-to-back sweeps would touch, not overlap.
    assert sweep_window(_settings(60, 60)).window_minutes == 61


def test_the_interval_is_floored_before_the_window_is_clamped() -> None:
    """The case the CLI got wrong. With interval=0 in the environment the
    scheduler floored it to five and widened a 3-minute window to six; the
    CLI compared 3 against 0, found it wider, and swept three minutes."""
    w = sweep_window(_settings(3, 0))
    assert w.interval_minutes == MIN_INTERVAL_MINUTES
    assert w.window_minutes == MIN_INTERVAL_MINUTES + 1
    assert w.since == "now-6m"


def test_the_widening_is_said_with_both_numbers_and_only_when_it_happened(
    caplog: pytest.LogCaptureFixture,
) -> None:
    log = logging.getLogger("test.sweep.window")
    with caplog.at_level(logging.WARNING, logger=log.name):
        sweep_window(_settings(1440, 60)).say_if_widened(log)
        assert caplog.records == [], "nothing to say about a window that was not widened"
        sweep_window(_settings(5, 60)).say_if_widened(log)
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert "(5m)" in record.getMessage() and "(60m)" in record.getMessage()
    assert "61m" in record.getMessage()
