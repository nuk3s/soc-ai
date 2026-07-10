"""Nightly quality micro-eval analytics: snapshot metrics + the regression rule.

``soc-ai eval-nightly`` reuses the batch machinery (:mod:`soc_ai.eval.batch` /
:mod:`soc_ai.eval.report`) to RUN the investigations; this module is the pure
layer on top that turns one batch's rows into a trendable point and decides
whether that point is a regression against its own history.

Everything here is side-effect-free by design — no store, no network, no
settings object — so the regression rule (the thing that wakes an operator)
is exhaustively unit-testable with plain values.

Two measurement modes, never blended:

* ``"graded"`` — the cloud oracle critiqued each run, so ``agreement_rate``
  (the fraction of classified critiques that said "yes") is the headline.
* ``"local"`` — zero-egress: no oracle, ``agreement_rate`` is ``None``, and
  the trend leans on local proxies (fallback rate, error rate, verdict
  distribution, latency p50) that need no cloud call.

The detector compares a new point ONLY against same-mode history (the caller
guarantees that): a graded 0.8 and a local ``None`` are different instruments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from soc_ai.eval.report import Aggregates

# The detector needs a real median to compare against — fewer than 3 history
# points and a single noisy night IS the median. Below this, skip (no alarm).
MIN_HISTORY = 3

# Absolute error-rate ceiling. Independent of history on purpose: >30% of the
# nightly's runs erroring means the pipeline itself is sick (gateway down,
# engine wedged) regardless of what last week looked like.
ERROR_RATE_CEILING = 0.3

# Absolute fallback-rate jump over the trailing median that alarms. Fallback
# verdicts are the pipeline's "the model call failed, I'm guessing
# needs_more_info" path — a jump here is the classic silent-engine-swap
# symptom (verdicts keep flowing, but they're no longer reasoned).
FALLBACK_JUMP = 0.3


@dataclass(frozen=True)
class SnapshotMetrics:
    """One nightly run reduced to the numbers the trend stores.

    The same shape whether the run was graded or local — ``agreement_rate``
    simply stays ``None`` in local mode. ``fallback_rate`` is ``None`` when no
    run succeeded (no denominator), never a fake 0.0.
    """

    mode: str  # "local" | "graded"
    n_ok: int
    n_error: int
    agreement_rate: float | None
    fallback_rate: float | None
    error_rate: float
    verdict_counts: dict[str, int]
    latency_p50_ms: int | None


@dataclass(frozen=True)
class TrendPoint:
    """The slice of a historical snapshot the regression rule consumes.

    A deliberate seam: the detector takes these instead of ORM rows so its
    tests (and any future caller) never need a database.
    """

    agreement_rate: float | None
    fallback_rate: float | None


def compute_snapshot_metrics(
    rows: list[dict[str, Any]],
    agg: Aggregates,
    *,
    mode: str,
) -> SnapshotMetrics:
    """Reduce one batch's ``index.jsonl`` rows + aggregates to a snapshot point.

    Most numbers come straight from the already-computed
    :class:`~soc_ai.eval.report.Aggregates` (single source of truth for
    agreement/verdicts/latency). ``fallback_rate`` is derived here from the
    per-row ``is_fallback`` flag the batch runner stamps
    (:class:`soc_ai.eval.batch.IndexRow`) — the aggregator predates that flag
    and the nightly is its only consumer so far. Rows written by older batch
    runs lack the key entirely; ``.get`` treats them as non-fallback, which is
    the pre-flag behavior (honest for old data, exact for new).

    ``agreement_rate`` is forced to ``None`` in local mode even though the
    aggregator technically computed one — with no oracle every row's agreement
    is "unknown", the classified denominator is 0, and surfacing anything but
    NULL would let a local point masquerade as a graded one on the trend.
    """
    ok_rows = [r for r in rows if not r.get("error")]
    fallback_rate: float | None = None
    if ok_rows:
        n_fallback = sum(1 for r in ok_rows if r.get("is_fallback"))
        fallback_rate = n_fallback / len(ok_rows)

    n_total = agg.n_ok + agg.n_error
    error_rate = (agg.n_error / n_total) if n_total > 0 else 0.0

    # .get (not indexing): the aggregator always emits the key today, but a
    # missing histogram must degrade to "no latency point", not a KeyError in
    # an unattended 02:17 cron run.
    latency_p50_ms: int | None = None
    hist = agg.histograms.get("investigation_ms")
    if hist is not None and hist.p50 is not None:
        latency_p50_ms = int(hist.p50)

    return SnapshotMetrics(
        mode=mode,
        n_ok=agg.n_ok,
        n_error=agg.n_error,
        agreement_rate=agg.agreement_rate if mode == "graded" else None,
        fallback_rate=fallback_rate,
        error_rate=error_rate,
        verdict_counts=dict(agg.verdict_counts),
        latency_p50_ms=latency_p50_ms,
    )


def _median(values: list[float]) -> float:
    """Plain median (mean of the middle pair on even n). Caller ensures non-empty."""
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def detect_regression(
    new: SnapshotMetrics,
    history: list[TrendPoint],
    *,
    alarm_drop: float,
) -> list[str]:
    """Decide whether *new* regresses against its trailing same-mode *history*.

    Returns the list of human-readable reasons (empty = no alarm). The caller
    passes the trailing (up to 7) SAME-MODE points; with fewer than
    :data:`MIN_HISTORY` the whole check is skipped — a median of one or two
    nights is noise, and a young install must not page anyone.

    Three rules, deliberately simple (a nightly n≈5 sample can't support
    anything statistical — medians resist the single-outlier night that a
    mean would chase):

    * **Agreement drop** — ``new.agreement_rate`` more than *alarm_drop*
      below the median of the history points that HAVE an agreement rate.
      Skipped when either side lacks the signal (local mode, or graded runs
      where the oracle classified nothing).
    * **Error-rate ceiling** — ``new.error_rate`` > 0.3, absolute. History
      independent: a third of the nightly erroring is sick, full stop.
    * **Fallback jump** — ``new.fallback_rate`` more than 0.3 above the
      history median. The silent-engine-swap tripwire: the pipeline still
      "works" but verdicts are fabricated fallbacks.
    """
    if len(history) < MIN_HISTORY:
        return []

    reasons: list[str] = []

    hist_agreement = [p.agreement_rate for p in history if p.agreement_rate is not None]
    if new.agreement_rate is not None and hist_agreement:
        med = _median(hist_agreement)
        if med - new.agreement_rate > alarm_drop:
            reasons.append(
                f"agreement_rate {new.agreement_rate:.2f} is more than "
                f"{alarm_drop:.2f} below the trailing median {med:.2f}"
            )

    if new.error_rate > ERROR_RATE_CEILING:
        reasons.append(
            f"error_rate {new.error_rate:.2f} exceeds the {ERROR_RATE_CEILING:.2f} ceiling"
        )

    hist_fallback = [p.fallback_rate for p in history if p.fallback_rate is not None]
    if new.fallback_rate is not None and hist_fallback:
        med_fb = _median(hist_fallback)
        if new.fallback_rate - med_fb > FALLBACK_JUMP:
            reasons.append(
                f"fallback_rate {new.fallback_rate:.2f} jumped more than "
                f"{FALLBACK_JUMP:.2f} above the trailing median {med_fb:.2f}"
            )

    return reasons


__all__ = [
    "ERROR_RATE_CEILING",
    "FALLBACK_JUMP",
    "MIN_HISTORY",
    "SnapshotMetrics",
    "TrendPoint",
    "compute_snapshot_metrics",
    "detect_regression",
]
