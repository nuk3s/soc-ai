"""Escalation precision/recall + Wilson 95% CI for the synth stratum.

Reads synth-tagged eval rows (one per ingested triage-target alert),
joins them against the scenario catalogue's ground truth, and emits a
two-tier aggregate the operator can compare across pipeline versions.

The headline metrics are deliberately separated from the real-stratum
``agreement_rate``: the synth stratum tests whether the system *can*
escalate, the real stratum tests how often it agrees with the oracle on
benign-lab data. Never blend.
"""

from __future__ import annotations

import math
import random
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from soc_ai.eval.synth_loader import Scenario, Tier

_Z_95 = 1.959963984540054  # quantile of standard normal at 0.975


def wilson_ci(successes: int, n: int) -> tuple[float, float]:
    """Wilson-score 95% CI for a binomial proportion.

    Returns ``(0.0, 1.0)`` for ``n == 0`` (proportion undefined →
    fully uninformative interval).
    """
    if n == 0:
        return (0.0, 1.0)
    p_hat = successes / n
    # Float math drifts the saturated tails (e.g. 1.0 - eps for perfect
    # recall). Pin them so callers can compare against 1.0 / 0.0 exactly.
    if successes == n:
        lo_special, hi_special = None, 1.0
    elif successes == 0:
        lo_special, hi_special = 0.0, None
    else:
        lo_special = hi_special = None
    z = _Z_95
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    margin = (z / denom) * math.sqrt(p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n))
    lo = lo_special if lo_special is not None else max(0.0, center - margin)
    hi = hi_special if hi_special is not None else min(1.0, center + margin)
    return (lo, hi)


@dataclass(frozen=True)
class SynthRow:
    """One synth-tagged eval result, ready for scoring."""

    scenario_id: str
    verdict: str
    confidence: float
    citations: list[str]
    # Tool names of the report's recommended_actions (e.g. "escalate_to_case"),
    # as captured on the IndexRow. Defaulted so pre-capture index files (which
    # lack the field) score as "recommended nothing" rather than erroring.
    recommended_actions: list[str] = field(default_factory=list)


@dataclass
class ScenarioDetail:
    """Per-scenario score detail — what happened on this single TP injection."""

    scenario_id: str
    expected_verdict: str
    expected_confidence_min: float
    actual_verdict: str
    actual_confidence: float
    correct: bool
    miss_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "expected_verdict": self.expected_verdict,
            "expected_confidence_min": self.expected_confidence_min,
            "actual_verdict": self.actual_verdict,
            "actual_confidence": self.actual_confidence,
            "correct": self.correct,
            "miss_reasons": list(self.miss_reasons),
        }


@dataclass
class ScenarioStability:
    """Across-repeat distribution for one scenario (``--repeats``).

    ``repeats`` is the ATTEMPTED run count (scored rows + errored runs that
    produced no row), so an errored repeat can't silently shrink the
    denominator. ``strict_passes`` counts runs whose verdict AND confidence
    met the rubric; errored runs count as fails. ``confidences`` / ``verdicts``
    list the scored runs in row order so a reader sees the spread ("0.65 ±
    0.04, 3/5 passed"), not one coin flip.
    """

    scenario_id: str
    repeats: int
    strict_passes: int
    errored_runs: int
    confidences: list[float] = field(default_factory=list)
    verdicts: list[str] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        return self.strict_passes / self.repeats if self.repeats else 0.0

    @property
    def unanimous(self) -> bool:
        """True when every attempted run agreed (all passed or all failed)."""
        return self.strict_passes in (0, self.repeats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "repeats": self.repeats,
            "strict_passes": self.strict_passes,
            "pass_rate": self.pass_rate,
            "errored_runs": self.errored_runs,
            "confidences": list(self.confidences),
            "verdicts": list(self.verdicts),
            "unanimous": self.unanimous,
        }


@dataclass
class AllRunsAggregate:
    """Per-run (n_scenarios x repeats) escalation aggregate.

    The HEADLINE metrics on :class:`SynthStratumScore` aggregate per-scenario
    majorities; this block keeps the raw per-run numbers available (its Wilson
    CIs use the RUN count as denominator). With one run per scenario the two
    coincide exactly.
    """

    n_runs: int
    true_positive_count: int
    false_positive_count: int
    false_negative_count: int
    true_negative_count: int
    escalation_precision: float
    escalation_recall: float
    escalation_precision_ci: tuple[float, float]
    escalation_recall_ci: tuple[float, float]
    escalation_recall_verdict_only: float
    escalation_recall_verdict_only_ci: tuple[float, float]
    false_negative_breakdown: dict[str, int] = field(
        default_factory=lambda: {"missed": 0, "low_confidence": 0, "errored": 0}
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "n_runs": self.n_runs,
            "true_positive_count": self.true_positive_count,
            "false_positive_count": self.false_positive_count,
            "false_negative_count": self.false_negative_count,
            "true_negative_count": self.true_negative_count,
            "escalation_precision": self.escalation_precision,
            "escalation_recall": self.escalation_recall,
            "escalation_precision_ci": list(self.escalation_precision_ci),
            "escalation_recall_ci": list(self.escalation_recall_ci),
            "escalation_recall_verdict_only": self.escalation_recall_verdict_only,
            "escalation_recall_verdict_only_ci": list(self.escalation_recall_verdict_only_ci),
            "false_negative_breakdown": dict(self.false_negative_breakdown),
        }


@dataclass
class TierAggregate:
    """Per-tier (easy/medium/hard) TP+FN summary."""

    tier: Tier
    true_positive_count: int
    false_negative_count: int

    @property
    def recall(self) -> float:
        n = self.true_positive_count + self.false_negative_count
        return self.true_positive_count / n if n else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "true_positive_count": self.true_positive_count,
            "false_negative_count": self.false_negative_count,
            "recall": self.recall,
        }


@dataclass
class SynthStratumScore:
    """Aggregate result for the whole synth stratum."""

    true_positive_count: int
    false_positive_count: int
    false_negative_count: int
    true_negative_count: int
    escalation_precision: float
    escalation_recall: float
    escalation_precision_ci: tuple[float, float]
    escalation_recall_ci: tuple[float, float]
    per_scenario: dict[str, ScenarioDetail]
    per_tier: dict[Tier, TierAggregate]
    unmatched_scenario_ids: list[str]
    # Verdict-only recall: a correct-verdict escalation counts as detected
    # REGARDLESS of confidence (the strict ``escalation_recall`` additionally
    # requires confidence >= floor). Reported alongside so a well-reasoned but
    # under-confident escalation isn't indistinguishable from a total miss, and
    # the headline recall doesn't track the model's calibration verbosity.
    escalation_recall_verdict_only: float = 0.0
    escalation_recall_verdict_only_ci: tuple[float, float] = (0.0, 1.0)
    # FN split so calibration + infra loss don't masquerade as detection misses:
    #   missed         — wrong verdict on an expected-TP scenario (a real miss)
    #   low_confidence — correct escalation, but below the confidence floor
    #   errored        — no result row (run errored / triage doc deleted mid-run)
    # Under --repeats > 1 each majority-FN scenario contributes ONE count — its
    # dominant per-run failure mode — so the split still sums to
    # ``false_negative_count``; the per-run split lives on ``all_runs``.
    false_negative_breakdown: dict[str, int] = field(
        default_factory=lambda: {"missed": 0, "low_confidence": 0, "errored": 0}
    )
    # --repeats support. ``per_scenario_stability`` always carries the
    # across-repeat distribution (repeats == 1 gives single-sample entries).
    # ``flip_rate`` is the fraction of multi-run (>= 2 attempts) scenarios
    # whose repeats were NOT unanimous — a direct readout of the noise floor;
    # ``None`` when no scenario ran more than once (a single sample cannot
    # demonstrate stability, so 0.0 would overclaim). ``all_runs`` keeps the
    # run-denominated aggregate beside the majority-denominated headline.
    per_scenario_stability: dict[str, ScenarioStability] = field(default_factory=dict)
    flip_rate: float | None = None
    all_runs: AllRunsAggregate | None = None
    # Macro-averaged repeat statistics: strict + verdict-only recall as the
    # MEAN of per-scenario pass rates (scenarios weighted equally — a 3/5
    # scenario contributes 0.6, not a rounded majority), with a percentile
    # bootstrap 95% CI that resamples SCENARIOS, never runs (repeated runs
    # of one scenario are not independent samples of the catalogue). Benign
    # twins carry the precision analogues: their own macro pass rates and
    # the macro false-escalation rate. ``None`` when no scenario ran more
    # than once — same gating as ``flip_rate``: a single sample cannot
    # claim a variance-aware statistic, and single-run strata stay
    # values-comparable with history.
    macro: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positive_count": self.true_positive_count,
            "false_positive_count": self.false_positive_count,
            "false_negative_count": self.false_negative_count,
            "true_negative_count": self.true_negative_count,
            "escalation_precision": self.escalation_precision,
            "escalation_recall": self.escalation_recall,
            "escalation_precision_ci": list(self.escalation_precision_ci),
            "escalation_recall_ci": list(self.escalation_recall_ci),
            "escalation_recall_verdict_only": self.escalation_recall_verdict_only,
            "escalation_recall_verdict_only_ci": list(self.escalation_recall_verdict_only_ci),
            "false_negative_breakdown": dict(self.false_negative_breakdown),
            "per_scenario": {k: v.to_dict() for k, v in self.per_scenario.items()},
            "per_tier": {k: v.to_dict() for k, v in self.per_tier.items()},
            "unmatched_scenario_ids": list(self.unmatched_scenario_ids),
            "per_scenario_stability": {
                k: v.to_dict() for k, v in self.per_scenario_stability.items()
            },
            "flip_rate": self.flip_rate,
            "all_runs": self.all_runs.to_dict() if self.all_runs is not None else None,
            "macro": self.macro,
        }


# Maps a rubric action kind (synth_scenarios YAML vocabulary) to the ONE v1
# write tool that expresses it. Values must stay inside
# soc_ai.triage_models.WriteToolName (pinned by test_quality_spine).
# Kinds with no entry — isolate, block_indicator, disable_account — name
# containment actions the product has no write tool for; they are reported as
# unmappable rather than silently dropped or blamed on the model.
_ACTION_KIND_TO_TOOL: dict[str, str] = {
    "escalate": "escalate_to_case",
    "close_benign": "ack_alert",
}


def _citation_kind_present(kind: str, citations: list[str]) -> bool:
    """Return True if any citation string contains ``kind`` as a case-insensitive
    substring. Intentionally loose — kinds are coarse tags like ``zeek_conn``,
    ``payload``, ``blocklist`` that typically appear as a prefix token in the
    citation string but may appear anywhere (e.g. ``(tool t_zeek_conn:uid=...)``)."""
    kind_lower = kind.lower()
    return any(kind_lower in c.lower() for c in citations)


def _score_one(row: SynthRow, scenario: Scenario) -> ScenarioDetail:
    miss_reasons: list[str] = []
    if row.verdict != scenario.ground_truth.verdict:
        miss_reasons.append(
            f"verdict mismatch: actual={row.verdict!r}, expected={scenario.ground_truth.verdict!r}"
        )
    if row.confidence < scenario.ground_truth.confidence_min:
        miss_reasons.append(
            f"confidence {row.confidence:.2f} below floor "
            f"{scenario.ground_truth.confidence_min:.2f}"
        )

    # Citation-kind coverage — miss_reasons only, never flips `correct`
    # (evidence-aware graders, not gatekeepers).
    for kind in scenario.ground_truth.required_citation_kinds:
        if not _citation_kind_present(kind, row.citations):
            miss_reasons.append(f"missing required citation kind: {kind}")

    # expected_actions coverage — miss_reasons only, never flips `correct`
    # (graders, not gatekeepers). Matching is by write-tool name: a kind is
    # satisfied iff its mapped tool appears among the recommended tool names.
    # Tool name only, no arg matching — the write tools' args are case/alert
    # ids the scenario cannot know a priori, and the catalogue's target_field
    # appears only on unmappable kinds (it is echoed for context).
    # ExpectedAction.reason_contains_any is not scored: rationales are not
    # captured on the index row, and no shipped scenario declares it.
    for expected in scenario.ground_truth.expected_actions:
        tool = _ACTION_KIND_TO_TOOL.get(expected.kind)
        target = f" targeting {expected.target_field}" if expected.target_field else ""
        if tool is None:
            miss_reasons.append(
                f"expected action kind {expected.kind!r}{target} has "
                f"no write-tool equivalent in v1 (product gap, not a model miss)"
            )
        elif tool not in row.recommended_actions:
            miss_reasons.append(
                f"expected action not recommended: {expected.kind}{target} (write tool {tool})"
            )

    return ScenarioDetail(
        scenario_id=scenario.id,
        expected_verdict=scenario.ground_truth.verdict,
        expected_confidence_min=scenario.ground_truth.confidence_min,
        actual_verdict=row.verdict,
        actual_confidence=row.confidence,
        # correct is determined only by verdict + confidence, not citation
        # coverage (graders, not gatekeepers).
        correct=(
            row.verdict == scenario.ground_truth.verdict
            and row.confidence >= scenario.ground_truth.confidence_min
        ),
        miss_reasons=miss_reasons,
    )


_BOOTSTRAP_ITERATIONS = 10_000


def _macro_mean(rates: list[float]) -> float | None:
    return sum(rates) / len(rates) if rates else None


def _bootstrap_macro_ci(
    rates: list[float], *, seed: str, iterations: int = _BOOTSTRAP_ITERATIONS
) -> tuple[float, float]:
    """Percentile-bootstrap 95% CI for the MEAN of per-scenario pass rates.

    Resamples SCENARIOS (their pass rates) with replacement — never
    individual runs, which are repeated draws of the same scenario, not of
    the catalogue. Deterministic: the RNG is seeded from the metric name +
    the sorted scenario ids, so rebuilding a report reproduces the same
    interval and tests can pin it (no wall-clock nondeterminism).
    """
    if not rates:
        return (0.0, 1.0)
    if len(rates) == 1:
        return (rates[0], rates[0])
    rng = random.Random(seed)  # noqa: S311 - statistical resampling, not crypto
    n = len(rates)
    means = sorted(sum(rng.choices(rates, k=n)) / n for _ in range(iterations))
    lo_idx = int(0.025 * (iterations - 1))
    hi_idx = int(0.975 * (iterations - 1))
    return (means[lo_idx], means[hi_idx])


def _macro_block(
    *,
    tp_strict_rates: list[float],
    tp_vo_rates: list[float],
    benign_strict_rates: list[float],
    benign_vo_rates: list[float],
    benign_escalation_rates: list[float],
    seed_base: str,
) -> dict[str, Any]:
    """Assemble the macro dict (see ``SynthStratumScore.macro``)."""

    def _ci(rates: list[float], metric: str) -> list[float] | None:
        if not rates:
            return None
        lo, hi = _bootstrap_macro_ci(rates, seed=f"{metric}:{seed_base}")
        return [lo, hi]

    return {
        "strict_recall_macro": _macro_mean(tp_strict_rates),
        "strict_recall_macro_ci": _ci(tp_strict_rates, "strict_recall"),
        "verdict_only_recall_macro": _macro_mean(tp_vo_rates),
        "verdict_only_recall_macro_ci": _ci(tp_vo_rates, "verdict_only_recall"),
        "benign_strict_macro": _macro_mean(benign_strict_rates),
        "benign_strict_macro_ci": _ci(benign_strict_rates, "benign_strict"),
        "benign_verdict_only_macro": _macro_mean(benign_vo_rates),
        "benign_verdict_only_macro_ci": _ci(benign_vo_rates, "benign_verdict_only"),
        "false_escalation_rate_macro": _macro_mean(benign_escalation_rates),
        "bootstrap_iterations": _BOOTSTRAP_ITERATIONS,
    }


def score_synth_stratum(  # noqa: PLR0912, PLR0915 - one linear pass filling both aggregation levels
    rows: list[SynthRow],
    *,
    scenarios: list[Scenario],
    attempted_repeats: Mapping[str, int] | None = None,
) -> SynthStratumScore:
    """Compute escalation P/R + Wilson CIs across the synth stratum.

    "Positive class" = the system emitted ``true_positive`` (escalated).
    True positive = expected TP AND emitted TP (with correct confidence).
    False negative = expected TP, system emitted something else.
    False positive = expected ≠TP (e.g. benign synth), system emitted TP.
    True negative = expected ≠TP, system did not emit TP.

    Repeats (``--repeats N``) semantics:

    - The HEADLINE metrics aggregate per-scenario MAJORITY outcomes — an
      expected-TP scenario counts as detected iff its strict passes are a
      strict majority of its attempted runs (a tie is a fail) — so one
      unlucky repeat cannot swing the batch metric. Their Wilson CIs use
      the SCENARIO count as denominator.
    - The per-run numbers stay available under ``all_runs`` (denominator =
      runs; its Wilson CIs use the RUN count). ``per_scenario_stability``
      carries each scenario's k/N distribution and ``flip_rate`` the
      fraction of multi-run scenarios whose repeats were not unanimous.
    - With one run per scenario, majority-of-one is that run: every metric
      reduces exactly to the historical single-sample behavior.

    ``attempted_repeats`` maps scenario id → PLANNED run count so an errored
    repeat (no scored row) still lands in every denominator; omitted, each
    attempted scenario defaults to max(scored rows, 1) — preserving the
    historical errored-run-as-FN backfill. ``scenarios`` is scoped by the
    caller to the ATTEMPTED set, so a subset --synth-set is never penalised
    for scenarios it did not inject.
    """
    by_id = {s.id: s for s in scenarios}

    rows_by_scenario: defaultdict[str, list[SynthRow]] = defaultdict(list)
    unmatched: list[str] = []
    for row in rows:
        if row.scenario_id in by_id:
            rows_by_scenario[row.scenario_id].append(row)
        else:
            unmatched.append(row.scenario_id)

    per_scenario: dict[str, ScenarioDetail] = {}
    stability: dict[str, ScenarioStability] = {}
    per_tier_tp: defaultdict[Tier, int] = defaultdict(int)
    per_tier_fn: defaultdict[Tier, int] = defaultdict(int)

    # Scenario-level (majority) tallies — the headline.
    tp = fp = fn = tn = 0
    vo_pass = 0
    fn_missed = fn_low_conf = fn_errored = 0
    # Run-level tallies — the all_runs block.
    run_tp = run_fp = run_fn = run_tn = 0
    run_vo = 0
    run_fn_missed = run_fn_low = run_fn_err = 0
    # Flip rate inputs: scenarios with >= 2 attempted runs.
    multi_run = flips = 0
    # Per-scenario pass rates feeding the macro block.
    tp_strict_rates: list[float] = []
    tp_vo_rates: list[float] = []
    benign_strict_rates: list[float] = []
    benign_vo_rates: list[float] = []
    benign_escalation_rates: list[float] = []

    error_reason = "run errored or timed out — no result row"

    for scenario in scenarios:
        scored = rows_by_scenario.get(scenario.id, [])
        expected_tp = scenario.ground_truth.verdict == "true_positive"
        if not scored and not expected_tp:
            # Historical behavior: a benign scenario with no scored row is
            # not counted at all (the errored-as-FN backfill is a positive-
            # class recall concern; benign must not be dragged in).
            continue

        attempted = max(
            attempted_repeats.get(scenario.id, 0) if attempted_repeats is not None else 0,
            len(scored),
            1,
        )
        errored = attempted - len(scored)
        details = [_score_one(r, scenario) for r in scored]
        strict_passes = sum(1 for d in details if d.correct)
        escalations = sum(1 for r in scored if r.verdict == "true_positive")
        # Scored strict misses, split by cause (calibration vs plain miss).
        n_low = sum(
            1
            for r, d in zip(scored, details, strict=True)
            if not d.correct and r.verdict == "true_positive"
        )
        n_missed = len(scored) - strict_passes - n_low

        stability[scenario.id] = ScenarioStability(
            scenario_id=scenario.id,
            repeats=attempted,
            strict_passes=strict_passes,
            errored_runs=errored,
            confidences=[r.confidence for r in scored],
            verdicts=[r.verdict for r in scored],
        )
        if attempted >= 2:
            multi_run += 1
            if strict_passes not in (0, attempted):
                flips += 1

        # Per-scenario pass RATES for the macro block. Denominator =
        # attempted, so an errored repeat drags the rate down instead of
        # vanishing. Verdict-only pass = the expected verdict at any
        # confidence; for a benign twin that is the correct close.
        vo_run_passes = sum(1 for r in scored if r.verdict == scenario.ground_truth.verdict)
        if expected_tp:
            tp_strict_rates.append(strict_passes / attempted)
            tp_vo_rates.append(vo_run_passes / attempted)
        else:
            benign_strict_rates.append(strict_passes / attempted)
            benign_vo_rates.append(vo_run_passes / attempted)
            benign_escalation_rates.append(escalations / attempted)

        # ---- Run-level (all_runs) tallies.
        if expected_tp:
            run_tp += strict_passes
            run_fn += (len(scored) - strict_passes) + errored
            run_fn_low += n_low
            run_fn_missed += n_missed
            run_fn_err += errored
            run_vo += escalations
        else:
            run_fp += escalations
            run_tn += len(scored) - escalations

        # ---- Scenario-level majority.
        if expected_tp:
            majority_pass = strict_passes * 2 > attempted
            if escalations * 2 > attempted:
                vo_pass += 1
            if majority_pass:
                tp += 1
                per_tier_tp[scenario.tier] += 1
            else:
                fn += 1
                per_tier_fn[scenario.tier] += 1
                # Dominant failure mode among this scenario's failing runs;
                # ties break missed > low_confidence > errored (max() keeps
                # the first maximum). With one run this is that run's cause.
                counts = {
                    "missed": n_missed,
                    "low_confidence": n_low,
                    "errored": errored,
                }
                dominant = max(counts, key=lambda k: counts[k])
                if dominant == "missed":
                    fn_missed += 1
                elif dominant == "low_confidence":
                    fn_low_conf += 1
                else:
                    fn_errored += 1
            # Representative detail: the first scored run matching the
            # majority outcome, so per_scenario reconciles with the headline
            # TP/FN. All-errored (or errored-dominated) majorities fall back
            # to the synthesized error detail — same shape as the historical
            # attempted-but-no-row backfill.
            rep = next((d for d in details if d.correct == majority_pass), None)
        else:
            majority_escalated = escalations * 2 > attempted
            if majority_escalated:
                fp += 1
            else:
                tn += 1
            rep = next(
                (
                    d
                    for r, d in zip(scored, details, strict=True)
                    if (r.verdict == "true_positive") == majority_escalated
                ),
                None,
            )

        if rep is None:
            rep = ScenarioDetail(
                scenario_id=scenario.id,
                expected_verdict=scenario.ground_truth.verdict,
                expected_confidence_min=scenario.ground_truth.confidence_min,
                actual_verdict="error",
                actual_confidence=0.0,
                correct=False,
                miss_reasons=[error_reason],
            )
        per_scenario[scenario.id] = rep

    # ---- Headline metrics: scenario-denominated (majority outcomes).
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision_ci = wilson_ci(tp, tp + fp)
    recall_ci = wilson_ci(tp, tp + fn)
    # Verdict-only recall shares the strict recall's denominator (all
    # expected-TP scenarios) but a scenario passes on a majority of correct-
    # verdict escalations at ANY confidence, so it is unaffected by the floor.
    expected_tp_total = tp + fn
    recall_verdict_only = vo_pass / expected_tp_total if expected_tp_total else 0.0
    recall_verdict_only_ci = wilson_ci(vo_pass, expected_tp_total)

    # ---- All-runs metrics: run-denominated.
    run_precision = run_tp / (run_tp + run_fp) if (run_tp + run_fp) else 0.0
    run_recall = run_tp / (run_tp + run_fn) if (run_tp + run_fn) else 0.0
    run_expected_tp = run_tp + run_fn
    run_recall_vo = run_vo / run_expected_tp if run_expected_tp else 0.0
    all_runs = AllRunsAggregate(
        n_runs=run_tp + run_fp + run_fn + run_tn,
        true_positive_count=run_tp,
        false_positive_count=run_fp,
        false_negative_count=run_fn,
        true_negative_count=run_tn,
        escalation_precision=run_precision,
        escalation_recall=run_recall,
        escalation_precision_ci=wilson_ci(run_tp, run_tp + run_fp),
        escalation_recall_ci=wilson_ci(run_tp, run_tp + run_fn),
        escalation_recall_verdict_only=run_recall_vo,
        escalation_recall_verdict_only_ci=wilson_ci(run_vo, run_expected_tp),
        false_negative_breakdown={
            "missed": run_fn_missed,
            "low_confidence": run_fn_low,
            "errored": run_fn_err,
        },
    )

    per_tier: dict[Tier, TierAggregate] = {}
    for tier in ("easy", "medium", "hard"):
        per_tier[tier] = TierAggregate(
            tier=tier,
            true_positive_count=per_tier_tp.get(tier, 0),
            false_negative_count=per_tier_fn.get(tier, 0),
        )

    macro: dict[str, Any] | None = None
    if multi_run:
        macro = _macro_block(
            tp_strict_rates=tp_strict_rates,
            tp_vo_rates=tp_vo_rates,
            benign_strict_rates=benign_strict_rates,
            benign_vo_rates=benign_vo_rates,
            benign_escalation_rates=benign_escalation_rates,
            seed_base=",".join(sorted(stability)),
        )

    return SynthStratumScore(
        true_positive_count=tp,
        false_positive_count=fp,
        false_negative_count=fn,
        true_negative_count=tn,
        escalation_precision=precision,
        escalation_recall=recall,
        escalation_precision_ci=precision_ci,
        escalation_recall_ci=recall_ci,
        escalation_recall_verdict_only=recall_verdict_only,
        escalation_recall_verdict_only_ci=recall_verdict_only_ci,
        false_negative_breakdown={
            "missed": fn_missed,
            "low_confidence": fn_low_conf,
            "errored": fn_errored,
        },
        per_scenario=per_scenario,
        per_tier=per_tier,
        unmatched_scenario_ids=unmatched,
        per_scenario_stability=stability,
        flip_rate=(flips / multi_run) if multi_run else None,
        all_runs=all_runs,
        macro=macro,
    )
