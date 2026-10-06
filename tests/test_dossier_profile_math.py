"""Tests for profile arithmetic (soc_ai.dossier.profile_math)."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

from soc_ai.dossier.profile_math import (
    HOURS_PER_WEEK,
    Cell,
    TimeCell,
    cell_for,
    hour_of_week,
    mad,
    median,
    robust_z,
    seasonal_baseline,
    seasonal_from_samples,
    summarise_cells,
    zero_filled,
)


def test_median_of_even_and_odd_length() -> None:
    assert median([3.0, 1.0, 2.0]) == 2.0
    assert median([4.0, 1.0, 3.0, 2.0]) == 2.5
    assert median([]) is None


def test_mad_is_the_median_absolute_deviation_not_the_mean() -> None:
    # 1,1,1,1,100: the mean absolute deviation is dragged to 19.8 by the
    # outlier, the median absolute deviation is not moved at all. Using the
    # mean here is what lets one spike raise the bar so the next looks normal.
    assert mad([1.0, 1.0, 1.0, 1.0, 100.0]) == 0.0


def test_mad_of_a_real_spread() -> None:
    assert mad([1.0, 2.0, 3.0, 4.0, 5.0]) == 1.0


def test_robust_z_uses_the_consistency_constant() -> None:
    # 0.6745 makes MAD comparable to a standard deviation for normal data.
    assert robust_z(value=5.0, med=1.0, dispersion=1.0) == 0.6745 * 4.0


def test_robust_z_of_zero_dispersion_is_not_infinite() -> None:
    # A cell where every sample is identical has no dispersion. Dividing by it
    # produces inf, and inf outranks every real departure on the page.
    assert robust_z(value=5.0, med=1.0, dispersion=0.0) is None


def test_robust_z_at_the_median_is_zero() -> None:
    assert robust_z(value=1.0, med=1.0, dispersion=2.0) == 0.0


def test_robust_z_is_signed_so_a_drop_is_distinguishable_from_a_spike() -> None:
    # "below" is a departure kind in its own right: a backup that stops is as
    # interesting as one that doubles. An absolute value would erase it.
    assert robust_z(value=0.0, med=10.0, dispersion=1.0) < 0


def test_work_hours_weekday_is_the_work_cell() -> None:
    # Tuesday 2026-09-15, 10:00 local
    at = datetime(2026, 9, 15, 10, 0, tzinfo=UTC)
    assert cell_for(at, tz="UTC") is TimeCell.WORK


def test_evening_weekday_is_the_off_hours_cell() -> None:
    at = datetime(2026, 9, 15, 22, 0, tzinfo=UTC)
    assert cell_for(at, tz="UTC") is TimeCell.OFF


def test_saturday_is_the_weekend_cell_whatever_the_hour() -> None:
    # 2026-09-19 is a Saturday.
    assert cell_for(datetime(2026, 9, 19, 10, 0, tzinfo=UTC), tz="UTC") is TimeCell.WEEKEND
    assert cell_for(datetime(2026, 9, 19, 22, 0, tzinfo=UTC), tz="UTC") is TimeCell.WEEKEND


def test_the_cell_is_computed_in_local_time_not_utc() -> None:
    # 2026-09-15 13:00 UTC is 09:00 in New York, which is work, and 22:00 in
    # Tokyo, which is not. Bucketing in UTC mislabels a whole timezone's
    # working day as off hours, and "activity outside business hours" is one
    # of the loudest dimensions in the profile.
    at = datetime(2026, 9, 15, 13, 0, tzinfo=UTC)
    assert cell_for(at, tz="America/New_York") is TimeCell.WORK
    assert cell_for(at, tz="Asia/Tokyo") is TimeCell.OFF


def test_an_unknown_timezone_falls_back_to_utc_rather_than_raising() -> None:
    # A misconfigured so_timezone must not take the whole sweep down.
    assert cell_for(datetime(2026, 9, 15, 10, tzinfo=UTC), tz="Not/AZone") is TimeCell.WORK


def test_summarise_cells_reports_support_days_per_cell() -> None:
    # Two distinct days in the work cell, one in off hours.
    samples = [
        (datetime(2026, 9, 15, 10, tzinfo=UTC), 5.0),
        (datetime(2026, 9, 16, 11, tzinfo=UTC), 7.0),
        (datetime(2026, 9, 16, 22, tzinfo=UTC), 1.0),
    ]
    cells = summarise_cells(samples, tz="UTC")
    assert cells[TimeCell.WORK] == Cell(median=6.0, dispersion=1.0, support_days=2, samples=2)
    assert cells[TimeCell.OFF].support_days == 1
    assert cells[TimeCell.WEEKEND].samples == 0


def test_support_days_counts_distinct_days_not_samples() -> None:
    # Ten samples in one day is one day of support. Counting samples lets a
    # single busy afternoon clear a seven-day minimum-support bar.
    samples = [(datetime(2026, 9, 15, 9 + i, tzinfo=UTC), 1.0) for i in range(8)]
    cells = summarise_cells(samples, tz="UTC")
    assert cells[TimeCell.WORK].samples == 8
    assert cells[TimeCell.WORK].support_days == 1


def test_a_cell_with_no_samples_is_present_and_empty_not_absent() -> None:
    # An absent cell is indistinguishable from a cell that was never measured.
    # The profile must be able to say "no weekend activity observed".
    cells = summarise_cells([], tz="UTC")
    assert set(cells) == set(TimeCell)
    assert all(c.samples == 0 and c.median is None for c in cells.values())


def test_support_days_are_counted_in_local_time_too() -> None:
    # 2026-09-15 23:30 and 2026-09-16 00:30 UTC are the same local day in
    # New York (19:30 and 20:30 on the 15th). Counting days in UTC would
    # report two days of support where the entity was seen on one.
    samples = [
        (datetime(2026, 9, 15, 23, 30, tzinfo=UTC), 1.0),
        (datetime(2026, 9, 16, 0, 30, tzinfo=UTC), 1.0),
    ]
    cells = summarise_cells(samples, tz="America/New_York")
    assert cells[TimeCell.OFF].support_days == 1


# ---------------------------------------------------------------------------
# The hour-of-week expectation
# ---------------------------------------------------------------------------

_MONDAY = datetime(2026, 8, 3, tzinfo=UTC)


def test_the_hour_of_the_week_counts_from_monday_midnight_local() -> None:
    assert hour_of_week(_MONDAY, tz="UTC") == 0
    assert hour_of_week(_MONDAY + timedelta(days=6, hours=23), tz="UTC") == 167
    # 00:00 UTC on a Monday is 20:00 on the Sunday in New York.
    assert hour_of_week(_MONDAY, tz="America/New_York") == 6 * 24 + 20


def test_zero_filled_fills_the_quiet_hours_between_the_first_and_the_last() -> None:
    start, series = zero_filled({_MONDAY + timedelta(hours=1): 5, _MONDAY + timedelta(hours=4): 2})
    assert start == _MONDAY + timedelta(hours=1)
    assert series == [5.0, 0.0, 0.0, 2.0]
    assert zero_filled({}) == (None, [])


def test_the_expected_count_is_the_median_of_its_own_hour_of_the_week() -> None:
    counts = [100.0 if n % HOURS_PER_WEEK != 9 else 1000.0 for n in range(4 * HOURS_PER_WEEK)]
    seasonal = seasonal_baseline(_MONDAY, counts, tz="UTC")
    assert seasonal.expected[9] == 1000.0
    assert seasonal.expected[10] == 100.0
    assert seasonal.samples[9] == 4
    assert seasonal.support_days == 28
    # Every sample sits on its own median: the pooled MAD is zero, and the
    # floor is the square root of the expected count.
    assert seasonal.mad == 0.0
    assert seasonal.sigma(10) == 10.0


def test_a_zero_expectation_with_no_spread_is_unmeasurable() -> None:
    """Negative control: an hour that never held a document, on a host whose
    hours never vary, has no dispersion to read. It is None, never zero."""
    counts = [0.0 if n % 24 < 8 else 50.0 for n in range(2 * HOURS_PER_WEEK)]
    seasonal = seasonal_baseline(_MONDAY, counts, tz="UTC")
    assert seasonal.expected[3] == 0.0
    assert seasonal.sigma(3) is None
    assert seasonal.sigma(12) == math.sqrt(50.0)


def test_the_pooled_spread_reads_every_hour_against_its_own_median() -> None:
    counts = [100.0 + (n // HOURS_PER_WEEK) * 10.0 for n in range(4 * HOURS_PER_WEEK)]
    seasonal = seasonal_baseline(_MONDAY, counts, tz="UTC")
    # Each hour holds 100, 110, 120, 130: a median of 115 and residuals of 5 and 15.
    assert seasonal.expected[0] == 115.0
    assert seasonal.mad == 10.0
    assert seasonal.sigma(0) == 10.0 / 0.6745


def test_sparse_samples_give_the_same_expectation_as_the_series() -> None:
    """The tier 3 silence detector reads the same hours in earlier weeks only.
    The helper it calls is the arithmetic of the series, not a second copy."""
    counts = [100.0 + (n // HOURS_PER_WEEK) * 10.0 for n in range(4 * HOURS_PER_WEEK)]
    whole = seasonal_baseline(_MONDAY, counts, tz="UTC")
    # Hours 9 and 10 of each Monday, out of order.
    hours = [w * HOURS_PER_WEEK + h for w in (3, 0, 2, 1) for h in (10, 9)]
    sparse = seasonal_from_samples(
        ((_MONDAY + timedelta(hours=n), counts[n]) for n in hours), tz="UTC"
    )
    assert sparse.expected[9] == whole.expected[9] == 115.0
    assert sparse.expected[10] == whole.expected[10]
    assert sparse.expected[11] is None
    assert sparse.samples[9] == 4
    assert sparse.mad == whole.mad == 10.0


def test_an_excluded_window_is_left_out_of_the_expectation() -> None:
    counts = [100.0] * (4 * HOURS_PER_WEEK)
    counts[HOURS_PER_WEEK + 9] = 5000.0
    window = (_MONDAY + timedelta(weeks=1, hours=8), _MONDAY + timedelta(weeks=1, hours=11))
    learnt = seasonal_baseline(_MONDAY, counts, tz="UTC")
    clean = seasonal_baseline(_MONDAY, counts, tz="UTC", exclude=[window])
    assert learnt.samples[9] == 4 and clean.samples[9] == 3
    assert clean.expected[9] == 100.0
