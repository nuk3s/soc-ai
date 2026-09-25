"""Observation weight: decay, sub-linear stacking, and the floor.

Live weight is computed on READ from the half-life. There is no decay job,
because a decay job that misses a night leaves every weight in the system
overstated and nothing says so.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest
from soc_ai.hunting.weight import (
    DEFAULT_FLOOR,
    DEFAULT_HALF_LIFE_HOURS,
    DEFAULT_LEAD_THRESHOLD,
    KIND_WEIGHT_CAP,
    Kind,
    birth_weight,
    lead_total,
    live_weight,
    stacked,
    weight_by_kind,
)

_NOW = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)


def test_a_fresh_single_observation_is_worth_its_birth_weight() -> None:
    assert live_weight(0.5, born_at=_NOW, count=1, now=_NOW) == 0.5


def test_weight_halves_over_one_half_life() -> None:
    born = _NOW - timedelta(hours=DEFAULT_HALF_LIFE_HOURS)
    assert live_weight(0.5, born_at=born, count=1, now=_NOW) == 0.25


def test_weight_quarters_over_two_half_lives() -> None:
    born = _NOW - timedelta(hours=DEFAULT_HALF_LIFE_HOURS * 2)
    assert live_weight(0.5, born_at=born, count=1, now=_NOW) == 0.125


def test_below_the_floor_an_observation_is_history_not_weight() -> None:
    # Kept for the dossier timeline, never summed. Returning a tiny number
    # instead lets ten thousand dead observations quietly add up to a lead.
    born = _NOW - timedelta(days=60)
    assert live_weight(0.5, born_at=born, count=1, now=_NOW) == 0.0


def test_the_floor_is_a_cliff_not_a_clamp() -> None:
    # Just above the floor keeps its real value; just below is zero. A clamp to
    # the floor would make every ancient observation worth exactly the floor.
    w = DEFAULT_FLOOR * 2
    assert live_weight(w, born_at=_NOW, count=1, now=_NOW) == w


def test_repeats_stack_sub_linearly() -> None:
    # w * (1 + ln n). Ten identical steps are louder than one, not ten times.
    assert stacked(0.5, count=1) == 0.5
    assert stacked(0.5, count=math.e) == 1.0
    assert 0.5 < stacked(0.5, count=2) < 1.0


def test_the_cap_bites_early_for_the_strongest_kind() -> None:
    # Worth knowing before tuning in shadow: at a birth weight of 0.5 the
    # ceiling is reached at n = e, about 2.7. Stacking therefore separates
    # "once" from "more than twice" for the strongest kind and nothing finer.
    # If shadow wants a campaign to outrank a pair, the birth weight has to
    # come down or the cap has to go up -- the log cannot do it alone.
    assert stacked(0.5, count=3) == 1.0
    assert stacked(0.3, count=3) < 1.0


def test_stacking_is_capped_at_one() -> None:
    # A campaign of identical steps must be louder without becoming unbounded:
    # uncapped, one repeated observation alone clears any threshold.
    assert stacked(0.5, count=10_000) == 1.0
    assert stacked(1.0, count=10_000) == 1.0


def test_a_count_below_one_does_not_reduce_the_weight() -> None:
    # ln(0) is -inf and ln(0.5) is negative; either would turn an observation
    # into a negative weight that SUBTRACTS from a lead.
    assert stacked(0.5, count=0) == 0.5
    assert stacked(0.5, count=-3) == 0.5


def test_decay_and_stacking_compose() -> None:
    born = _NOW - timedelta(hours=DEFAULT_HALF_LIFE_HOURS)
    # stacked first, then halved.
    assert live_weight(0.5, born_at=born, count=math.e, now=_NOW) == 0.5


def test_a_naive_timestamp_is_read_as_utc_not_local() -> None:
    # The store hands back naive datetimes. Treating them as local time shifts
    # every weight by the timezone offset, which on this deployment is up to
    # five hours of decay applied or skipped.
    born = (_NOW - timedelta(hours=DEFAULT_HALF_LIFE_HOURS)).replace(tzinfo=None)
    assert live_weight(0.5, born_at=born, count=1, now=_NOW) == 0.25


def test_an_observation_born_in_the_future_does_not_gain_weight() -> None:
    # Clock skew between the grid and this host is routine, and a negative age
    # would multiply the weight up rather than down.
    born = _NOW + timedelta(hours=12)
    assert live_weight(0.5, born_at=born, count=1, now=_NOW) == 0.5


def test_the_no_baseline_prior_is_born_a_finding() -> None:
    # The design: a prior with no benign population is 1.0 and IS a finding,
    # not a contribution toward one.
    assert birth_weight(Kind.PRIOR_NO_BASELINE) == 1.0


def test_a_novel_member_outweighs_an_off_hours_observation() -> None:
    # Inverted from the first draft. A novel destination or process is the
    # strongest single statistical signal; off-hours is the clause most exposed
    # to clock changes and shift patterns, so it is the weakest.
    assert birth_weight(Kind.NOVEL_DESTINATION) > birth_weight(Kind.OFF_HOURS)


def test_every_kind_has_a_birth_weight() -> None:
    # A kind with no weight silently contributes nothing, which is
    # indistinguishable from a kind that never fired.
    for kind in Kind:
        assert 0.0 < birth_weight(kind) <= 1.0, kind


# ---------------------------------------------------------------------------
# The per-type cap on a lead's total
# ---------------------------------------------------------------------------


def test_one_kind_saturates_at_twice_the_lead_threshold() -> None:
    # Production formed a lead at 25 from 45 novel served ports. Forty-five
    # rows of one kind are one story told forty-five times.
    assert pytest.approx(2 * DEFAULT_LEAD_THRESHOLD) == KIND_WEIGHT_CAP
    assert lead_total([(Kind.NOVEL_SERVED_PORT, 0.5)] * 45) == pytest.approx(KIND_WEIGHT_CAP)


def test_two_kinds_saturate_at_twice_the_cap() -> None:
    pairs = [(Kind.NOVEL_SERVED_PORT, 1.0)] * 30 + [(Kind.OFF_HOURS, 0.3)] * 30
    assert lead_total(pairs) == pytest.approx(2 * KIND_WEIGHT_CAP)


def test_below_the_cap_the_total_is_the_plain_sum() -> None:
    assert lead_total([(Kind.NOVEL_DESTINATION, 0.5), (Kind.OFF_HOURS, 0.3)]) == pytest.approx(0.8)


def test_the_breakdown_names_each_kind_once_with_its_cap() -> None:
    rows = weight_by_kind(
        [(Kind.OFF_HOURS, 0.3), ("novel_served_port", 1.0), (Kind.NOVEL_SERVED_PORT, 1.0)]
    )
    assert [r.kind for r in rows] == ["novel_served_port", "off_hours"]
    served, off = rows
    assert served.weight == pytest.approx(KIND_WEIGHT_CAP)
    assert served.saturated is True
    assert off.weight == pytest.approx(0.3)
    assert off.saturated is False
    assert off.cap == pytest.approx(KIND_WEIGHT_CAP)


def test_a_negative_weight_never_subtracts_from_a_kind() -> None:
    assert lead_total([(Kind.OFF_HOURS, -0.3), (Kind.OFF_HOURS, 0.3)]) == pytest.approx(0.3)


def test_an_empty_lead_weighs_nothing() -> None:
    assert lead_total([]) == 0.0
    assert weight_by_kind([]) == []
