"""Tests for the shared burstiness test used by the two rule-level tools.

The question this module answers is "are these fires a rate, or an episode?".
Getting it wrong in one direction fabricates a background rate out of a burst
(the 1531-fires-in-59-seconds defect); getting it wrong in the other calls a
genuine steady baseline an episode. Both directions are covered here.
"""

from __future__ import annotations

from soc_ai.tools import _burstiness as burst

DAY = burst.SECONDS_PER_DAY


def test_the_measured_defect_is_a_burst() -> None:
    """1531 fires inside 59 seconds of a 30-day window: an episode, no rate."""
    shape = burst.measure(total=1531, span_seconds=58.877, active_days=1, lookback_days=30)

    assert shape.is_burst is True
    assert shape.rate_is_meaningful is False
    assert shape.span_fraction is not None
    assert shape.span_fraction < 0.0001


def test_negative_control_the_same_volume_spread_out_is_a_rate() -> None:
    """Identical count and window, fires spread across it: still a steady rate."""
    shape = burst.measure(total=1531, span_seconds=30 * DAY, active_days=30, lookback_days=30)

    assert shape.is_burst is False
    assert shape.rate_is_meaningful is True
    assert shape.span_fraction == 1.0


def test_two_episodes_far_apart_are_not_a_rate() -> None:
    """A wide span does not make a rate honest when the days are clumped."""
    shape = burst.measure(total=1500, span_seconds=28 * DAY, active_days=2, lookback_days=30)

    assert shape.is_burst is True
    assert shape.rate_is_meaningful is False
    # The span is 28 days of which 26 are silent, so it is not the episode and
    # no density over it means anything.
    assert shape.fires_fill_span is False


def test_one_short_episode_fills_its_own_span() -> None:
    """1531 fires inside 59s occupy that span, so a density over it is real."""
    shape = burst.measure(total=1531, span_seconds=58.877, active_days=1, lookback_days=30)

    assert shape.is_burst is True
    assert shape.fires_fill_span is True


def test_a_span_with_unknown_active_days_is_taken_at_face_value() -> None:
    """No day histogram means no evidence of clumping, and unknown is not clumped."""
    shape = burst.measure(total=900, span_seconds=120.0, active_days=None, lookback_days=30)

    assert shape.fires_fill_span is True


def test_an_unmeasurable_span_fills_nothing() -> None:
    shape = burst.measure(total=900, span_seconds=None, active_days=None, lookback_days=30)

    assert shape.fires_fill_span is False


def test_a_sparse_weekly_pattern_is_not_a_burst() -> None:
    """Four fires over three weeks are rare, not an episode, and keep their rate.

    Below the volume floor the choice of denominator cannot mislead by much, and
    calling a handful of sightings a burst would overstate them.
    """
    shape = burst.measure(total=4, span_seconds=21 * DAY, active_days=4, lookback_days=30)

    assert shape.is_burst is False
    assert shape.rate_is_meaningful is True


def test_a_lone_fire_has_no_rate_and_is_not_a_burst() -> None:
    shape = burst.measure(total=1, span_seconds=0.0, active_days=1, lookback_days=30)

    assert shape.is_burst is False
    assert shape.rate_is_meaningful is False


def test_an_unmeasurable_span_is_unknown_not_bursty() -> None:
    """Missing timestamps mean no rate, but they are not evidence of a burst."""
    shape = burst.measure(total=900, span_seconds=None, active_days=None, lookback_days=30)

    assert shape.is_burst is False
    assert shape.rate_is_meaningful is False
    assert shape.span_fraction is None


def test_span_alone_carries_the_test_when_day_buckets_are_missing() -> None:
    shape = burst.measure(total=900, span_seconds=120.0, active_days=None, lookback_days=30)

    assert shape.is_burst is True
    assert shape.rate_is_meaningful is False


def test_span_phrase_reads_at_the_right_scale() -> None:
    assert burst.span_phrase(58.877) == "59s"
    assert burst.span_phrase(600) == "10m"
    assert burst.span_phrase(6 * 3600) == "6.0h"
    assert burst.span_phrase(26 * DAY) == "26.0 days"


def test_plural_agrees_with_its_count() -> None:
    assert burst.plural(1, "source port") == "1 source port"
    assert burst.plural(3, "source port") == "3 source ports"


def test_active_days_tolerates_a_missing_or_malformed_aggregation() -> None:
    assert burst.active_days_from(None) is None
    assert burst.active_days_from({"no_buckets": 1}) is None
    assert burst.active_days_from({"buckets": [{}, {}, {}]}) == 3


def test_epoch_reader_prefers_the_numeric_value_and_parses_the_string() -> None:
    assert burst.agg_epoch_seconds({"value": 1788223098475.0}) == 1788223098475.0 / 1000.0
    parsed = burst.agg_epoch_seconds({"value_as_string": "2026-09-01T00:38:18.475Z"})
    assert parsed is not None
    assert abs(parsed - 1788223098.475) < 0.001
    assert burst.agg_epoch_seconds({"value_as_string": "not a date"}) is None
    assert burst.agg_epoch_seconds(None) is None
