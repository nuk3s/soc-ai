"""The kinds and weights that let every source feed one lead."""

from __future__ import annotations

from soc_ai.hunting.weight import (
    ALERT_WEIGHT_BY_VERDICT,
    ESTATE_RARE_WEIGHT,
    Kind,
    alert_weight,
    birth_weight,
    is_finding_grade,
    novelty_weight,
)


def test_catalog_and_hunt_finding_kinds_exist_at_0_7() -> None:
    assert birth_weight(Kind.CATALOG_MATCH) == 0.7
    assert birth_weight(Kind.HUNT_FINDING) == 0.7


def test_alert_weight_follows_the_verdict() -> None:
    assert alert_weight("true_positive") == 1.0
    assert alert_weight("needs_more_info") == 0.5
    assert alert_weight("false_positive") is None
    assert alert_weight("garbage") is None
    assert set(ALERT_WEIGHT_BY_VERDICT) == {"true_positive", "needs_more_info"}


def test_finding_grade_is_a_no_baseline_prior_or_a_true_positive_alert() -> None:
    assert is_finding_grade(Kind.PRIOR_NO_BASELINE, 1.0)
    assert is_finding_grade(Kind.ALERT, 1.0)
    assert not is_finding_grade(Kind.ALERT, 0.5)
    assert not is_finding_grade(Kind.CATALOG_MATCH, 0.7)
    assert not is_finding_grade(Kind.NOVEL_DESTINATION, 0.5)


def test_an_estate_rare_novelty_is_born_heavier_and_nothing_else_moves() -> None:
    assert novelty_weight(Kind.NOVEL_SERVED_PORT, estate_rare=True) == ESTATE_RARE_WEIGHT == 0.6
    assert novelty_weight(Kind.NOVEL_SERVED_PORT, estate_rare=False) == 0.5
    # Negative controls: a rare mark on a kind that is not a novelty changes
    # nothing. A finding stays a finding. A rate stays a rate.
    assert novelty_weight(Kind.PRIOR_NO_BASELINE, estate_rare=True) == 1.0
    assert novelty_weight(Kind.ABOVE_BASELINE, estate_rare=True) == 0.35
    assert novelty_weight(Kind.SCOPE_COUNT, estate_rare=True) == 0.4
