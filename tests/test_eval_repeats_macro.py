"""Macro-averaged repeat statistics (``--repeats``) over the synth stratum.

The repeats machinery (75fa9b5e) reports per-scenario stability and a
majority-vote headline. What the noise-floor work also needs is the
structure-respecting summary statistic: strict + verdict-only recall as the
MACRO-AVERAGE of per-scenario pass rates (scenarios weighted equally, so a
3/5 scenario contributes 0.6 — not a coin flip and not a rounded majority),
with a bootstrap CI that resamples SCENARIOS, never runs (repeated runs of
one scenario are not independent samples of the catalogue). These tests pin:

- the macro block: hand-computed macro means for strict, verdict-only and
  the benign-twin precision analogues (incl. the false-escalation rate);
- errored repeats staying in each scenario's denominator;
- bootstrap determinism (seeded from scenario ids — same batch, same CI);
- ``macro is None`` when nothing ran more than once (single-sample batches
  cannot claim a variance-aware statistic);
- report rendering: the macro table, the unanimous-vs-split stability
  counts, and the per-scenario verdict-only k/N + distribution + coin-flip
  columns.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.eval.synth_loader import GroundTruth, Scenario
from soc_ai.eval.synth_score import SynthRow, score_synth_stratum


def _scenario(
    sid: str,
    *,
    verdict: str = "true_positive",
    floor: float = 0.7,
    tier: str = "easy",
) -> Scenario:
    return Scenario.model_construct(
        id=sid,
        name=sid,
        version=1,
        tier=tier,
        story="",
        attack=[],
        sigma_refs=[],
        ground_truth=GroundTruth(verdict=verdict, confidence_min=floor),  # type: ignore[arg-type]
        events=[],
        rubric_notes="",
        hunt_journey=None,
    )


def _srow(sid: str, verdict: str, conf: float) -> SynthRow:
    return SynthRow(scenario_id=sid, verdict=verdict, confidence=conf, citations=[])


def _three_scenario_fixture() -> tuple[list[Scenario], list[SynthRow], dict[str, int]]:
    """a-solid 3/3 strict; b-flaky strict 1/3 (one NMI, one below-floor TP);
    c-benign correct-close 2/3 with one false escalation."""
    scenarios = [
        _scenario("a-solid"),
        _scenario("b-flaky"),
        _scenario("c-benign", verdict="false_positive", floor=0.6),
    ]
    rows = [
        _srow("a-solid", "true_positive", 0.9),
        _srow("a-solid", "true_positive", 0.9),
        _srow("a-solid", "true_positive", 0.9),
        _srow("b-flaky", "true_positive", 0.9),
        _srow("b-flaky", "needs_more_info", 0.5),
        _srow("b-flaky", "true_positive", 0.6),  # right verdict, below floor
        _srow("c-benign", "false_positive", 0.8),
        _srow("c-benign", "false_positive", 0.8),
        _srow("c-benign", "true_positive", 0.9),  # a false escalation
    ]
    attempted = {"a-solid": 3, "b-flaky": 3, "c-benign": 3}
    return scenarios, rows, attempted


def test_macro_block_matches_hand_computed_rates() -> None:
    scenarios, rows, attempted = _three_scenario_fixture()

    score = score_synth_stratum(rows, scenarios=scenarios, attempted_repeats=attempted)
    macro = score.macro

    assert macro is not None
    # Strict: a=3/3, b=1/3 → (1.0 + 1/3) / 2.
    assert macro["strict_recall_macro"] == pytest.approx((1.0 + 1 / 3) / 2)
    # Verdict-only: a=3/3, b=2/3 → (1.0 + 2/3) / 2.
    assert macro["verdict_only_recall_macro"] == pytest.approx((1.0 + 2 / 3) / 2)
    # Benign twin (precision analogue): c passes 2/3 both ways; 1/3 escalated.
    assert macro["benign_strict_macro"] == pytest.approx(2 / 3)
    assert macro["benign_verdict_only_macro"] == pytest.approx(2 / 3)
    assert macro["false_escalation_rate_macro"] == pytest.approx(1 / 3)
    assert macro["bootstrap_iterations"] == 10_000

    # CIs bracket their point estimates.
    for name in ("strict_recall_macro", "verdict_only_recall_macro"):
        lo, hi = macro[f"{name}_ci"]
        assert lo <= macro[name] <= hi

    # The macro block rides along in the serialized stratum.
    assert score.to_dict()["macro"] == macro


def test_macro_counts_errored_repeats_in_the_denominator() -> None:
    """attempted=3 with only 2 scored rows → the errored repeat fails the
    scenario's rate (2/3), never shrinks it to 2/2."""
    scenarios = [_scenario("a-solid"), _scenario("b-flaky")]
    rows = [
        _srow("a-solid", "true_positive", 0.9),
        _srow("a-solid", "true_positive", 0.9),
        _srow("b-flaky", "true_positive", 0.9),
        _srow("b-flaky", "true_positive", 0.9),
        _srow("b-flaky", "true_positive", 0.9),
    ]

    score = score_synth_stratum(
        rows, scenarios=scenarios, attempted_repeats={"a-solid": 3, "b-flaky": 3}
    )

    assert score.macro is not None
    assert score.macro["strict_recall_macro"] == pytest.approx((2 / 3 + 1.0) / 2)


def test_macro_bootstrap_ci_is_deterministic() -> None:
    """Same batch content → same CI (RNG seeded from scenario ids, not the
    wall clock)."""
    scenarios, rows, attempted = _three_scenario_fixture()

    first = score_synth_stratum(rows, scenarios=scenarios, attempted_repeats=attempted).macro
    second = score_synth_stratum(rows, scenarios=scenarios, attempted_repeats=attempted).macro

    assert first is not None
    assert first == second
    lo, hi = first["strict_recall_macro_ci"]
    assert 0.0 <= lo <= hi <= 1.0


def test_macro_is_none_when_no_scenario_ran_more_than_once() -> None:
    """A single-sample batch cannot claim a variance-aware statistic —
    macro stays None (mirroring flip_rate), values-comparable with history."""
    scenarios = [_scenario("a-solid"), _scenario("b-flaky")]
    rows = [
        _srow("a-solid", "true_positive", 0.9),
        _srow("b-flaky", "true_positive", 0.9),
    ]

    score = score_synth_stratum(rows, scenarios=scenarios)

    assert score.macro is None
    assert score.to_dict()["macro"] is None


def test_report_renders_macro_table_stability_counts_and_kn_columns() -> None:
    """The repeats section of report.md gains the macro table, the
    unanimous-vs-split counts, and per-scenario verdict-only k/N +
    verdict-distribution + coin-flip columns."""
    from soc_ai.eval.report import _render_synth_stratum

    scenarios, rows, attempted = _three_scenario_fixture()
    stratum: dict[str, Any] = score_synth_stratum(
        rows, scenarios=scenarios, attempted_repeats=attempted
    ).to_dict()

    md = _render_synth_stratum(stratum)

    # Macro table with bootstrap CIs.
    assert "macro" in md.lower()
    assert "bootstrap" in md.lower()
    # Stability counts, not just the flip rate.
    assert "unanimous" in md
    assert "split" in md
    # Per-scenario table: verdict-only k/N, distribution, coin-flip flag.
    assert "verdict-only k/N" in md
    assert "×3" in md  # a-solid's TP×3
    assert "coin-flip" in md
    assert "a-solid" in md
    assert "b-flaky" in md
