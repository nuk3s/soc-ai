"""Tests for soc_ai.eval.synth_score — escalation P/R + Wilson CI (#45)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

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

    assert score.true_positive_count == 17
    assert score.false_negative_count == 0
    assert score.escalation_recall == 1.0
    # 17/17 → Wilson 95% lower bound ≈ 0.816. The catalogue widening from 9 to
    # 17 attacks is visible right here: perfect recall on 9 could only claim
    # 0.70 with 95% confidence, on 17 it claims 0.82 — the same result, said
    # with more of the noise squeezed out.
    assert score.escalation_recall_ci[0] == pytest.approx(0.816, abs=0.01)
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
    assert score.false_negative_count == 17
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

    # Scope to expected-TP scenarios only — the errored-as-FN backfill is a
    # positive-class (recall) concern; benign scenarios must not be dragged in.
    scenarios = [
        s for s in load_all_scenarios(SCENARIOS_DIR) if s.ground_truth.verdict == "true_positive"
    ]
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
    assert d["true_positive_count"] == 17
    assert d["false_negative_count"] == 0
    assert d["escalation_recall"] == 1.0
    assert isinstance(d["escalation_recall_ci"], list)
    assert len(d["escalation_recall_ci"]) == 2
    assert d["per_scenario"]["e1-emotet-feodo-c2"]["correct"] is True


def test_nonempty_expected_actions_adds_miss_reasons_without_flipping_correct() -> None:
    """When a scenario has expected_actions and the row recommends nothing,
    miss_reasons must record each unmet expectation — never silently drop it.
    A mappable kind (escalate) reads as not-recommended; a kind outside the
    v1 write-tool vocabulary (isolate) reads as unmappable. correct must NOT
    be affected either way (#49: graders, not gatekeepers)."""
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

    # Row has correct verdict + confidence; recommends no actions.
    row = SynthRow(
        scenario_id="test-actions",
        verdict="true_positive",
        confidence=0.9,
        citations=["alert.severity_label"],
    )
    detail = _score_one(row, scenario)

    # Verdict + confidence correct → still correct overall.
    assert detail.correct is True
    # The unmet escalation is a not-recommended miss...
    assert any(
        "expected action not recommended" in r and "escalate" in r for r in detail.miss_reasons
    ), f"expected a not-recommended miss reason for 'escalate', got: {detail.miss_reasons}"
    # ...while isolate is reported as unmappable (no v1 write tool), not
    # blamed on the model.
    assert any("no write-tool equivalent" in r and "isolate" in r for r in detail.miss_reasons), (
        f"expected an unmappable-kind reason for 'isolate', got: {detail.miss_reasons}"
    )


def test_empty_expected_actions_does_not_add_action_miss_reason() -> None:
    """When expected_actions is empty, no action-related entry is added."""
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
    assert not any("expected action" in r for r in detail.miss_reasons), (
        f"expected no action entry in miss_reasons, got: {detail.miss_reasons}"
    )


def test_benign_scenarios_load_and_are_false_positive() -> None:
    """The b* benign scenarios parse via the real loader and carry
    ground_truth.verdict == 'false_positive' (the negative class that makes
    escalation precision meaningful)."""
    scenarios = load_all_scenarios(SCENARIOS_DIR)
    benign = [s for s in scenarios if s.ground_truth.verdict == "false_positive"]
    benign_ids = sorted(s.id for s in benign)
    assert benign_ids == [
        "b1-cdn-update-beacon",
        "b2-authorized-vuln-scanner",
        "b3-rmm-admin-lateral",
        "b4-av-dns-reputation",
        "b5-sanctioned-wmi-inventory",
        "b6-backup-scheduled-transfer",
        "b7-browser-doh",
        "b8-dc-replication-partner",
    ]
    # The stratum spans all three difficulty tiers, weighted toward medium and
    # hard — the easy shapes were never where over-escalation lives.
    assert sorted(s.tier for s in benign) == [
        "easy",
        "hard",
        "hard",
        "hard",
        "medium",
        "medium",
        "medium",
        "medium",
    ]


def test_benign_not_escalated_scores_as_true_negative() -> None:
    """A benign scenario the system correctly does NOT escalate is a true
    negative: it neither adds a false positive (precision unaffected) nor a
    false negative (recall unaffected)."""
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    e1 = next(s for s in scenarios if s.id == "e1-emotet-feodo-c2")
    b1 = next(s for s in scenarios if s.id == "b1-cdn-update-beacon")

    rows = [
        # Seeded TP escalated correctly.
        SynthRow(
            scenario_id=e1.id,
            verdict="true_positive",
            confidence=max(e1.ground_truth.confidence_min, 0.9),
            citations=["blocklist_hit", "typed_path", "prefetch_pivot"],
        ),
        # Benign correctly dispositioned as false_positive → true negative.
        SynthRow(
            scenario_id=b1.id,
            verdict="false_positive",
            confidence=0.8,
            citations=["prefetch_pivot", "typed_path"],
        ),
    ]

    score = score_synth_stratum(rows, scenarios=[e1, b1])

    assert score.true_positive_count == 1
    assert score.true_negative_count == 1
    assert score.false_positive_count == 0
    assert score.false_negative_count == 0
    # Precision and recall both perfect: no benign was escalated, the TP caught.
    assert score.escalation_precision == 1.0
    assert score.escalation_recall == 1.0


def test_benign_wrongly_escalated_scores_as_false_positive_and_drops_precision() -> None:
    """A benign scenario the system WRONGLY escalates to true_positive is a
    false positive: precision drops, recall is unaffected."""
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    e1 = next(s for s in scenarios if s.id == "e1-emotet-feodo-c2")
    b1 = next(s for s in scenarios if s.id == "b1-cdn-update-beacon")

    rows = [
        # Seeded TP caught → true positive.
        SynthRow(
            scenario_id=e1.id,
            verdict="true_positive",
            confidence=max(e1.ground_truth.confidence_min, 0.9),
            citations=["blocklist_hit", "typed_path", "prefetch_pivot"],
        ),
        # Benign WRONGLY escalated → false positive.
        SynthRow(
            scenario_id=b1.id,
            verdict="true_positive",
            confidence=0.85,
            citations=["typed_path"],
        ),
    ]

    score = score_synth_stratum(rows, scenarios=[e1, b1])

    assert score.true_positive_count == 1
    assert score.false_positive_count == 1
    assert score.true_negative_count == 0
    # 1 TP + 1 FP → precision 0.5.
    assert score.escalation_precision == pytest.approx(0.5)
    # No seeded TP was missed → recall stays perfect (precision/recall decouple).
    assert score.false_negative_count == 0
    assert score.escalation_recall == 1.0


def test_benign_escalation_at_low_confidence_still_counts_as_false_positive() -> None:
    """Escalating benign traffic is a false positive regardless of the emitted
    confidence — the FP classification keys off the true_positive verdict, not
    whether the confidence cleared the benign scenario's floor."""
    from soc_ai.eval.synth_score import SynthRow, score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    b2 = next(s for s in scenarios if s.id == "b2-authorized-vuln-scanner")

    rows = [
        SynthRow(
            scenario_id=b2.id,
            verdict="true_positive",
            confidence=0.30,  # low confidence, but still an escalation of benign
            citations=[],
        )
    ]

    score = score_synth_stratum(rows, scenarios=[b2])

    assert score.false_positive_count == 1
    assert score.true_negative_count == 0
    assert score.true_positive_count == 0
    # 0 TP + 1 FP → precision 0.0.
    assert score.escalation_precision == 0.0


def test_benign_scenario_with_no_row_is_not_counted_as_fn() -> None:
    """The errored-scenario-as-FN backfill only fires for expected-TP
    scenarios. An attempted benign scenario that produced no row must NOT be
    silently turned into a false negative (it isn't a positive-class miss)."""
    from soc_ai.eval.synth_score import score_synth_stratum

    scenarios = load_all_scenarios(SCENARIOS_DIR)
    b3 = next(s for s in scenarios if s.id == "b3-rmm-admin-lateral")

    # No rows at all — b3 attempted but produced nothing.
    score = score_synth_stratum([], scenarios=[b3])

    assert score.false_negative_count == 0
    assert score.false_positive_count == 0
    assert score.true_negative_count == 0
    assert score.true_positive_count == 0
    # b3 is not backfilled as an error row (that path is TP-only).
    assert b3.id not in score.per_scenario


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
    assert score.per_tier["hard"].false_negative_count == 6


# --------------------------------------------------------------------
# Repeated runs per scenario (--repeats): per-scenario stability,
# majority-vote headline metrics, all-runs sub-aggregate, flip rate.
# --------------------------------------------------------------------


def _tp_scenario(scenario_id: str, *, tier: str = "easy", conf_min: float = 0.7) -> Any:
    from soc_ai.eval.synth_loader import Scenario

    return Scenario.model_validate(
        {
            "id": scenario_id,
            "name": "test",
            "version": 1,
            "tier": tier,
            "story": "x",
            "attack": ["T1071.001"],
            "ground_truth": {
                "verdict": "true_positive",
                "confidence_min": conf_min,
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


def _tp_row(scenario_id: str, *, verdict: str = "true_positive", confidence: float = 0.9) -> Any:
    from soc_ai.eval.synth_score import SynthRow

    return SynthRow(scenario_id=scenario_id, verdict=verdict, confidence=confidence, citations=[])


def test_repeats_stability_block_reports_distribution() -> None:
    """5 repeats of one scenario (3 strict passes, 2 misses) must surface as a
    distribution — repeats/strict_passes/pass_rate + every confidence seen —
    not as 5 rows silently double-counted into the headline."""
    from soc_ai.eval.synth_score import score_synth_stratum

    scen = _tp_scenario("rep-a")
    rows = [
        _tp_row("rep-a", confidence=0.72),
        _tp_row("rep-a", confidence=0.70),
        _tp_row("rep-a", confidence=0.75),
        _tp_row("rep-a", confidence=0.60),  # below floor → strict miss
        _tp_row("rep-a", verdict="false_positive", confidence=0.80),  # wrong verdict
    ]

    score = score_synth_stratum(rows, scenarios=[scen])

    stab = score.per_scenario_stability["rep-a"]
    assert stab.repeats == 5
    assert stab.strict_passes == 3
    assert stab.pass_rate == pytest.approx(0.6)
    assert sorted(stab.confidences) == [0.60, 0.70, 0.72, 0.75, 0.80]
    assert stab.errored_runs == 0
    # Non-unanimous repeats → the scenario flips; it is the only multi-run one.
    assert score.flip_rate == pytest.approx(1.0)


def test_repeats_headline_is_per_scenario_majority_all_runs_kept() -> None:
    """Headline recall aggregates per-scenario MAJORITY (one unlucky repeat
    can't swing it); the per-run numbers stay available under all_runs. Each
    tier's Wilson CI uses its own denominator: scenarios for the headline,
    runs for all_runs."""
    from soc_ai.eval.synth_score import score_synth_stratum, wilson_ci

    scen_a = _tp_scenario("rep-a")
    scen_b = _tp_scenario("rep-b", tier="hard")
    rows = [
        # A: 2/3 strict passes → majority pass.
        _tp_row("rep-a"),
        _tp_row("rep-a"),
        _tp_row("rep-a", verdict="needs_more_info"),
        # B: 0/3 → majority fail.
        _tp_row("rep-b", verdict="false_positive"),
        _tp_row("rep-b", verdict="false_positive"),
        _tp_row("rep-b", verdict="false_positive"),
    ]

    score = score_synth_stratum(rows, scenarios=[scen_a, scen_b])

    # Headline: scenario-denominated (2 scenarios, 1 majority-pass).
    assert score.true_positive_count == 1
    assert score.false_negative_count == 1
    assert score.escalation_recall == pytest.approx(0.5)
    assert score.escalation_recall_ci == pytest.approx(wilson_ci(1, 2))
    # Per-tier stays scenario-denominated too.
    assert score.per_tier["easy"].true_positive_count == 1
    assert score.per_tier["hard"].false_negative_count == 1
    # All-runs: run-denominated (6 runs, 2 strict passes).
    assert score.all_runs is not None
    assert score.all_runs.true_positive_count == 2
    assert score.all_runs.false_negative_count == 4
    assert score.all_runs.escalation_recall == pytest.approx(2 / 6)
    assert score.all_runs.escalation_recall_ci == pytest.approx(wilson_ci(2, 6))
    # Flip rate: A non-unanimous, B unanimous → 1 of 2 multi-run scenarios.
    assert score.flip_rate == pytest.approx(0.5)


def test_repeats_tie_is_not_a_majority() -> None:
    """An even split (1/2) is NOT a majority pass — strict metrics stay
    conservative under ties."""
    from soc_ai.eval.synth_score import score_synth_stratum

    scen = _tp_scenario("rep-tie")
    rows = [
        _tp_row("rep-tie"),
        _tp_row("rep-tie", verdict="needs_more_info"),
    ]

    score = score_synth_stratum(rows, scenarios=[scen])

    assert score.true_positive_count == 0
    assert score.false_negative_count == 1
    assert score.false_negative_breakdown["missed"] == 1
    assert score.per_scenario["rep-tie"].correct is False


def test_repeats_errored_runs_count_against_the_scenario() -> None:
    """attempted_repeats carries the PLANNED run count, so an errored repeat
    (no scored row) still lands in the denominator — both in the stability
    block and in the majority vote — instead of silently shrinking it."""
    from soc_ai.eval.synth_score import score_synth_stratum

    scen_a = _tp_scenario("rep-a")
    scen_b = _tp_scenario("rep-b")
    rows = [
        # A: 2 scored passes of 3 attempted → majority pass (2*2 > 3).
        _tp_row("rep-a"),
        _tp_row("rep-a"),
        # B: 1 scored pass of 3 attempted → no majority (1*2 <= 3) → FN.
        _tp_row("rep-b"),
    ]

    score = score_synth_stratum(
        rows,
        scenarios=[scen_a, scen_b],
        attempted_repeats={"rep-a": 3, "rep-b": 3},
    )

    stab_a = score.per_scenario_stability["rep-a"]
    assert stab_a.repeats == 3
    assert stab_a.strict_passes == 2
    assert stab_a.errored_runs == 1
    assert score.true_positive_count == 1
    assert score.false_negative_count == 1
    # B's majority-fail is dominated by errored runs (2 errored vs 0 scored misses).
    assert score.false_negative_breakdown["errored"] == 1
    # All-runs: 6 attempted expected-TP runs, 3 strict passes, 3 errored.
    assert score.all_runs is not None
    assert score.all_runs.true_positive_count == 3
    assert score.all_runs.false_negative_count == 3
    assert score.all_runs.false_negative_breakdown["errored"] == 3


def test_repeats_verdict_only_majority_shares_scenario_denominator() -> None:
    """Verdict-only recall under repeats is also a per-scenario majority over
    correct-verdict escalations (any confidence)."""
    from soc_ai.eval.synth_score import score_synth_stratum, wilson_ci

    scen_a = _tp_scenario("rep-a", conf_min=0.75)
    scen_b = _tp_scenario("rep-b")
    rows = [
        # A: escalates correctly 3/3 but always under the floor → strict fail,
        # verdict-only pass.
        _tp_row("rep-a", confidence=0.60),
        _tp_row("rep-a", confidence=0.62),
        _tp_row("rep-a", confidence=0.65),
        # B: never escalates.
        _tp_row("rep-b", verdict="needs_more_info"),
        _tp_row("rep-b", verdict="needs_more_info"),
        _tp_row("rep-b", verdict="needs_more_info"),
    ]

    score = score_synth_stratum(rows, scenarios=[scen_a, scen_b])

    assert score.escalation_recall == 0.0
    assert score.escalation_recall_verdict_only == pytest.approx(0.5)
    assert score.escalation_recall_verdict_only_ci == pytest.approx(wilson_ci(1, 2))
    assert score.false_negative_breakdown == {"missed": 1, "low_confidence": 1, "errored": 0}


def test_single_run_flip_rate_is_none_and_stability_still_reported() -> None:
    """With one run per scenario the flip rate is UNDEFINED (None, not 0.0 —
    a single sample can't demonstrate stability), but the stability block is
    still emitted so consumers have one shape."""
    from soc_ai.eval.synth_score import score_synth_stratum

    scen = _tp_scenario("rep-a")
    score = score_synth_stratum([_tp_row("rep-a", confidence=0.8)], scenarios=[scen])

    assert score.flip_rate is None
    stab = score.per_scenario_stability["rep-a"]
    assert stab.repeats == 1
    assert stab.strict_passes == 1
    assert stab.confidences == [0.8]


def test_repeats_to_dict_carries_stability_flip_rate_and_all_runs() -> None:
    from soc_ai.eval.synth_score import score_synth_stratum

    scen = _tp_scenario("rep-a")
    rows = [_tp_row("rep-a"), _tp_row("rep-a", verdict="needs_more_info")]
    d = score_synth_stratum(rows, scenarios=[scen]).to_dict()

    assert d["flip_rate"] == pytest.approx(1.0)
    stab = d["per_scenario_stability"]["rep-a"]
    assert stab["repeats"] == 2
    assert stab["strict_passes"] == 1
    assert stab["pass_rate"] == pytest.approx(0.5)
    assert stab["confidences"] == [0.9, 0.9]
    all_runs = d["all_runs"]
    assert all_runs["true_positive_count"] == 1
    assert all_runs["false_negative_count"] == 1
    assert isinstance(all_runs["escalation_recall_ci"], list)
