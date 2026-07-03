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
from collections import defaultdict
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
    false_negative_breakdown: dict[str, int] = field(
        default_factory=lambda: {"missed": 0, "low_confidence": 0, "errored": 0}
    )

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

    # expected_actions coverage. NOTE: expected_actions are not scored —
    # action data is not captured on the indexed eval row, so we record an
    # explicit unscoreable-miss rather than silently ignoring the rubric field.
    # Never flips `correct` (graders, not gatekeepers).
    if scenario.ground_truth.expected_actions:
        miss_reasons.append("expected_actions unscoreable: action not captured in row")

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


def score_synth_stratum(rows: list[SynthRow], *, scenarios: list[Scenario]) -> SynthStratumScore:
    """Compute escalation P/R + Wilson CIs across the synth stratum.

    "Positive class" = the system emitted ``true_positive`` (escalated).
    True positive = expected TP AND emitted TP (with correct confidence).
    False negative = expected TP, system emitted something else.
    False positive = expected ≠TP (e.g. benign synth), system emitted TP.
    True negative = expected ≠TP, system did not emit TP.

    The current catalogue (v1) ships only ``expected_verdict=true_positive``
    scenarios, so ``false_positive_count`` and ``true_negative_count``
    will be 0 in practice — they're computed structurally for when
    benign-synth (TN/FP coverage) lands in a future round.
    """
    by_id = {s.id: s for s in scenarios}

    per_scenario: dict[str, ScenarioDetail] = {}
    per_tier_tp: defaultdict[Tier, int] = defaultdict(int)
    per_tier_fn: defaultdict[Tier, int] = defaultdict(int)
    unmatched: list[str] = []
    tp = fp = fn = tn = 0
    # Verdict-only escalations (correct verdict, ANY confidence) + FN split.
    escalated_correct = 0
    fn_missed = fn_low_conf = fn_errored = 0

    for row in rows:
        scenario = by_id.get(row.scenario_id)
        if scenario is None:
            unmatched.append(row.scenario_id)
            continue
        detail = _score_one(row, scenario)
        per_scenario[scenario.id] = detail

        expected_tp = scenario.ground_truth.verdict == "true_positive"
        # verdict-only escalation ignores the confidence floor; strict TP adds it.
        escalated = row.verdict == "true_positive"
        emitted_tp = escalated and detail.correct
        if expected_tp and escalated:
            escalated_correct += 1
        if expected_tp and emitted_tp:
            tp += 1
            per_tier_tp[scenario.tier] += 1
        elif expected_tp and not emitted_tp:
            fn += 1
            per_tier_fn[scenario.tier] += 1
            # A correct escalation below the floor is a calibration FN, not a miss.
            if escalated:
                fn_low_conf += 1
            else:
                fn_missed += 1
        elif not expected_tp and escalated:
            fp += 1
        else:
            tn += 1

    # Scenarios that were attempted this batch but produced no scored row (the
    # harness run errored or timed out before a verdict) still count as false
    # negatives for an expected-TP scenario. Without this, recall's denominator
    # silently shrinks to successful runs only and inflates escalation_recall.
    # ``scenarios`` is scoped by the caller to the ATTEMPTED set, so this never
    # penalises a subset --synth-set for scenarios it did not inject.
    for scenario in scenarios:
        if scenario.id in per_scenario:
            continue
        if scenario.ground_truth.verdict == "true_positive":
            fn += 1
            fn_errored += 1
            per_tier_fn[scenario.tier] += 1
            per_scenario[scenario.id] = ScenarioDetail(
                scenario_id=scenario.id,
                expected_verdict=scenario.ground_truth.verdict,
                expected_confidence_min=scenario.ground_truth.confidence_min,
                actual_verdict="error",
                actual_confidence=0.0,
                correct=False,
                miss_reasons=["run errored or timed out — no result row"],
            )

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision_ci = wilson_ci(tp, tp + fp)
    recall_ci = wilson_ci(tp, tp + fn)
    # Verdict-only recall shares the strict recall's denominator (all expected-TP
    # scenarios = tp + fn) but credits every correct-verdict escalation, so it is
    # unaffected by the confidence floor. Numerator = strict TP + low-confidence
    # (correct-verdict) escalations = escalated_correct.
    expected_tp_total = tp + fn
    recall_verdict_only = escalated_correct / expected_tp_total if expected_tp_total else 0.0
    recall_verdict_only_ci = wilson_ci(escalated_correct, expected_tp_total)

    per_tier: dict[Tier, TierAggregate] = {}
    for tier in ("easy", "medium", "hard"):
        per_tier[tier] = TierAggregate(
            tier=tier,
            true_positive_count=per_tier_tp.get(tier, 0),
            false_negative_count=per_tier_fn.get(tier, 0),
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
    )
