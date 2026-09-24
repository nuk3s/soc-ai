"""Tests for profile arithmetic (soc_ai.dossier.profile_math)."""

from __future__ import annotations

from datetime import UTC, datetime

from soc_ai.dossier.profile_math import (
    Cell,
    TimeCell,
    cell_for,
    mad,
    median,
    robust_z,
    summarise_cells,
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
