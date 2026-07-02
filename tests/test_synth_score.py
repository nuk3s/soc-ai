"""Tests for soc_ai.eval.synth_score — escalation P/R + Wilson CI (#45)."""

from __future__ import annotations

from pathlib import Path

import pytest
from soc_ai.eval.synth_loader import load_all_scenarios

SCENARIOS_DIR = Path(__file__).parent.parent / "soc_ai" / "eval" / "synth_scenarios"


def test_wilson_ci_zero_count_returns_zero_floor_one_ceiling() -> None:
    from soc_ai.eval.synth_score import wilson_ci

    # 0/0: undefined proportion, return (0.0, 1.0) as uninformative interval.
    lo, hi = wilson_ci(0, 0)
    assert lo == 0.0
    assert hi == 1.0


def test_wilson_ci_perfect_recall_has_lower_bound_above_chance() -> None:
    from soc_ai.eval.synth_score import wilson_ci

    # 10/10 → 100% recall; 95% Wilson lower bound for n=10 is ~0.72.
    lo, hi = wilson_ci(10, 10)
    assert lo == pytest.approx(0.722, abs=0.01)
    assert hi == 1.0


def test_wilson_ci_half_passing_centers_at_half() -> None:
    from soc_ai.eval.synth_score import wilson_ci

    # 5/10 → 50%; 95% Wilson CI ≈ (0.237, 0.763).
    lo, hi = wilson_ci(5, 10)
    assert lo == pytest.approx(0.237, abs=0.01)
    assert hi == pytest.approx(0.763, abs=0.01)


def test_score_all_correct_yields_recall_one() -> None:
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    rows = [
        SynthRow(
            scenario_id=s.id,
            verdict=s.ground_truth.verdict,  # always TP in current catalogue
            confidence=max(s.ground_truth.confidence_min, 0.9),
            citations=["alert.severity_label"],
        )
        for s in scenarios
    ]

    score = score_synth_stratum(rows, scenarios=scenarios)

    assert score.true_positive_count == 9
    assert score.false_negative_count == 0
    assert score.escalation_recall == 1.0
    # 9/9 → Wilson 95% lower bound ≈ 0.701
    assert score.escalation_recall_ci[0] == pytest.approx(0.701, abs=0.01)
    assert score.escalation_recall_ci[1] == 1.0


def test_score_all_missed_yields_recall_zero() -> None:
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    rows = [
        SynthRow(
            scenario_id=s.id,
            verdict="false_positive",  # wrong verdict for TP-tagged scenarios
            confidence=0.95,
            citations=[],
        )
        for s in scenarios
    ]

    score = score_synth_stratum(rows, scenarios=scenarios)

    assert score.true_positive_count == 0
    assert score.false_negative_count == 9
    assert score.escalation_recall == 0.0


def test_score_low_confidence_below_floor_fails_verdict_match() -> None:
    """Right verdict label but confidence below the rubric floor = miss."""
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    e1 = next(s for s in scenarios if s.id == "e1-emotet-feodo-c2")
    # e1 wants confidence_min=0.75.
    rows = [
        SynthRow(
            scenario_id=e1.id,
            verdict="true_positive",
            confidence=0.60,  # below floor of 0.75
            citations=["alert.severity_label"],
        )
    ]

    score = score_synth_stratum(rows, scenarios=[e1])

    assert score.true_positive_count == 0
    assert score.false_negative_count == 1
    assert score.escalation_recall == 0.0
    # The per-scenario detail records WHY it missed.
    detail = score.per_scenario["e1-emotet-feodo-c2"]
    assert detail.correct is False
    assert "confidence" in detail.miss_reasons[0]


def test_missing_required_citation_kind_adds_miss_reason_without_flipping_correct() -> None:
    """A scenario with required_citation_kinds — when the row has no citation
    string matching that kind, miss_reasons gains an entry but correct is
    unchanged (#49: graders, not gatekeepers)."""
    from soc_ai.eval.synth_loader import Scenario
    from soc_ai.eval.synth_score import SynthRow, _score_one

    scenario = Scenario.model_validate(
        {
            "id": "test-cite-kind",
            "name": "test",
            "version": 1,
            "tier": "easy",
            "story": "x",
            "attack": ["T1071.001"],
            "ground_truth": {
                "verdict": "true_positive",
                "confidence_min": 0.7,
                "required_citation_kinds": ["zeek_conn"],
                "expected_actions": [],
            },
            "events": [
                {
                    "index": "logs-synth-suricata-alert",
                    "is_triage_target": True,
                    "fields": {"@timestamp": "2026-01-01T00:00:00Z"},
                }
            ],
        }
    )

    # Row with correct verdict + confidence but no zeek_conn citation.
    row = SynthRow(
        scenario_id="test-cite-kind",
        verdict="true_positive",
        confidence=0.9,
        citations=["alert.severity_label", "blocklist_hit"],
    )
    detail = _score_one(row, scenario)

    # Verdict + confidence correct → still correct overall.
    assert detail.correct is True
    # But miss_reasons records the gap.
    assert any("zeek_conn" in r for r in detail.miss_reasons)
    assert any("missing required citation kind" in r for r in detail.miss_reasons)


def test_present_required_citation_kind_does_not_add_miss_reason() -> None:
    """If the row's citations contain the required kind, no miss reason added."""
    from soc_ai.eval.synth_loader import Scenario
    from soc_ai.eval.synth_score import SynthRow, _score_one

    scenario = Scenario.model_validate(
        {
            "id": "test-cite-kind2",
            "name": "test",
            "version": 1,
            "tier": "easy",
            "story": "x",
            "attack": ["T1071.001"],
            "ground_truth": {
                "verdict": "true_positive",
                "confidence_min": 0.7,
                "required_citation_kinds": ["zeek_conn"],
                "expected_actions": [],
            },
            "events": [
                {
                    "index": "logs-synth-suricata-alert",
                    "is_triage_target": True,
                    "fields": {"@timestamp": "2026-01-01T00:00:00Z"},
                }
            ],
        }
    )

    row = SynthRow(
        scenario_id="test-cite-kind2",
        verdict="true_positive",
        confidence=0.9,
        citations=["zeek_conn:uid=CX12", "alert.severity_label"],
    )
    detail = _score_one(row, scenario)
    assert detail.correct is True
    assert not any("missing required citation kind" in r for r in detail.miss_reasons)


def test_score_returns_per_scenario_detail() -> None:
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    e1 = next(s for s in scenarios if s.id == "e1-emotet-feodo-c2")
    e2 = next(s for s in scenarios if s.id == "e2-urlhaus-pe-delivery")

    rows = [
        SynthRow(
            scenario_id="e1-emotet-feodo-c2",
            verdict="true_positive",
            confidence=0.9,
            citations=["alert.severity_label"],
        ),
        SynthRow(
            scenario_id="e2-urlhaus-pe-delivery",
            verdict="needs_more_info",
            confidence=0.8,
            citations=[],
        ),
    ]

    score = score_synth_stratum(rows, scenarios=[e1, e2])

    assert score.per_scenario["e1-emotet-feodo-c2"].correct is True
    assert score.per_scenario["e2-urlhaus-pe-delivery"].correct is False


def test_score_skips_rows_without_matching_scenario() -> None:
    """A row tagged with an unknown scenario_id is reported, not scored.

    ``scenarios`` is the ATTEMPTED set — here it's empty, isolating the
    unmatched-row path (no attempted scenario ⇒ no expected FN)."""
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    rows = [
        SynthRow(
            scenario_id="unknown-scenario-id",
            verdict="true_positive",
            confidence=0.9,
            citations=[],
        )
    ]

    score = score_synth_stratum(rows, scenarios=[])

    # Unknown rows don't count toward TP/FN.
    assert score.true_positive_count == 0
    assert score.false_negative_count == 0
    # But they are surfaced as a separate stratum so the operator can find them.
    assert "unknown-scenario-id" in score.unmatched_scenario_ids


def test_score_counts_attempted_scenario_with_no_row_as_fn() -> None:
    """An expected-TP scenario that was attempted but produced no result row
    (run errored / timed out) counts as a false negative, so recall's
    denominator reflects all attempted scenarios — not just successful runs."""
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)  # all expected-TP
    # Only the first scenario produced a (correct) result row; the rest errored.
    first = scenarios[0]
    rows = [
        SynthRow(
            scenario_id=first.id,
            verdict="true_positive",
            confidence=max(first.ground_truth.confidence_min, 0.9),
            citations=[],
        )
    ]

    score = score_synth_stratum(rows, scenarios=scenarios)

    assert score.true_positive_count == 1
    # every other attempted scenario is a miss
    assert score.false_negative_count == len(scenarios) - 1
    # recall denominator = all attempted scenarios (not just the 1 that ran)
    expected_recall = 1 / len(scenarios)
    assert abs(score.escalation_recall - expected_recall) < 1e-9
    # the errored scenarios are recorded with an explicit reason
    missed = [d for d in score.per_scenario.values() if d.actual_verdict == "error"]
    assert len(missed) == len(scenarios) - 1
    assert all("errored or timed out" in " ".join(d.miss_reasons) for d in missed)


def test_score_to_dict_round_trips_with_floats() -> None:
    """The aggregate is JSON-serializable for report.py to merge in."""
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    rows = [
        SynthRow(
            scenario_id=s.id,
            verdict=s.ground_truth.verdict,
            confidence=0.9,
            citations=["alert.severity_label"],
        )
        for s in scenarios
    ]
    score = score_synth_stratum(rows, scenarios=scenarios)

    d = score.to_dict()
    assert d["true_positive_count"] == 9
    assert d["false_negative_count"] == 0
    assert d["escalation_recall"] == 1.0
    assert isinstance(d["escalation_recall_ci"], list)
    assert len(d["escalation_recall_ci"]) == 2
    assert d["per_scenario"]["e1-emotet-feodo-c2"]["correct"] is True


def test_nonempty_expected_actions_adds_unscoreable_miss_reason_without_flipping_correct() -> None:
    """When a scenario has expected_actions and the row carries no action data,
    miss_reasons must record an unscoreable-miss entry — never silently drop it.
    correct must NOT be affected (#49: graders, not gatekeepers)."""
    from soc_ai.eval.synth_loader import Scenario
    from soc_ai.eval.synth_score import SynthRow, _score_one

    scenario = Scenario.model_validate(
        {
            "id": "test-actions",
            "name": "test",
            "version": 1,
            "tier": "easy",
            "story": "x",
            "attack": ["T1071.001"],
            "ground_truth": {
                "verdict": "true_positive",
                "confidence_min": 0.7,
                "required_citation_kinds": [],
                "expected_actions": [
                    {"kind": "escalate"},
                    {"kind": "isolate", "target_field": "source.ip"},
                ],
            },
            "events": [
                {
                    "index": "logs-synth-suricata-alert",
                    "is_triage_target": True,
                    "fields": {"@timestamp": "2026-01-01T00:00:00Z"},
                }
            ],
        }
    )

    # Row has correct verdict + confidence; no action data (SynthRow has no
    # actions field — actions are not captured in the indexed row).
    row = SynthRow(
        scenario_id="test-actions",
        verdict="true_positive",
        confidence=0.9,
        citations=["alert.severity_label"],
    )
    detail = _score_one(row, scenario)

    # Verdict + confidence correct → still correct overall.
    assert detail.correct is True
    # But miss_reasons must record that expected_actions could not be scored.
    assert any("expected_actions unscoreable" in r for r in detail.miss_reasons), (
        f"expected an 'expected_actions unscoreable' miss reason, got: {detail.miss_reasons}"
    )


def test_empty_expected_actions_does_not_add_unscoreable_miss_reason() -> None:
    """When expected_actions is empty, no unscoreable-miss entry is added."""
    from soc_ai.eval.synth_loader import Scenario
    from soc_ai.eval.synth_score import SynthRow, _score_one

    scenario = Scenario.model_validate(
        {
            "id": "test-actions-empty",
            "name": "test",
            "version": 1,
            "tier": "easy",
            "story": "x",
            "attack": ["T1071.001"],
            "ground_truth": {
                "verdict": "true_positive",
                "confidence_min": 0.7,
                "required_citation_kinds": [],
                "expected_actions": [],
            },
            "events": [
                {
                    "index": "logs-synth-suricata-alert",
                    "is_triage_target": True,
                    "fields": {"@timestamp": "2026-01-01T00:00:00Z"},
                }
            ],
        }
    )

    row = SynthRow(
        scenario_id="test-actions-empty",
        verdict="true_positive",
        confidence=0.9,
        citations=["alert.severity_label"],
    )
    detail = _score_one(row, scenario)

    assert detail.correct is True
    assert not any("expected_actions" in r for r in detail.miss_reasons), (
        f"expected no 'expected_actions' entry in miss_reasons, got: {detail.miss_reasons}"
    )


def test_score_per_tier_breakdown() -> None:
    """Per-tier breakdown lets the operator see whether Hard tier is the gap."""
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    rows = []
    # Easy + Medium correct; Hard all wrong (3 false negatives).
    for s in scenarios:
        verdict = s.ground_truth.verdict if s.tier != "hard" else "false_positive"
        rows.append(
            SynthRow(
                scenario_id=s.id,
                verdict=verdict,
                confidence=0.9,
                citations=["alert.severity_label"],
            )
        )

    score = score_synth_stratum(rows, scenarios=scenarios)

    assert score.per_tier["easy"].recall == 1.0
    assert score.per_tier["medium"].recall == 1.0
    assert score.per_tier["hard"].recall == 0.0
    assert score.per_tier["hard"].false_negative_count == 3
