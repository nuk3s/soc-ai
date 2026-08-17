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

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from soc_ai.eval.report import Aggregates

# The detector needs a real baseline to compare against — fewer than 3 history
# points and a single noisy night IS the baseline. Below this, skip (no alarm).
MIN_HISTORY = 3

# How many trailing same-mode points the agreement baseline POOLS. Deliberately
# much wider than the median window below: pooling only 7 nights of 5 grades
# lets a lucky week (35 of 35) claim a baseline of 1.0, under which any miss at
# all looks impossible and the next ordinary night pages. 30 points is a month
# of nightlies — enough grades that the pooled rate is a rate, not an anecdote.
BASELINE_WINDOW = 30

# How many trailing points the MEDIAN-based rules (fallback jump, and the
# pre-0026 agreement fallback) look at. Unchanged from the original design: a
# median wants recency, not sample size — it is a "what did last week look
# like" reference, and a month-long median would smooth away a real shift.
MEDIAN_WINDOW = 7

# False-alarm budget for the agreement test: fire only when a night this bad
# would occur with probability <= 2% under the pooled baseline. At the install's
# own historical rate that is ~1 spurious alarm per 50 graded nights, against
# ~1 in 11 under the median-of-rates rule it replaces.
ALARM_P = 0.02

# Add-one (Laplace) smoothing on the pooled baseline. A flawless trailing month
# is NOT evidence that the true agreement rate is exactly 1.0, and an unsmoothed
# p=1.0 makes ANY disagreement infinitely improbable — the very first flipped
# grade would page. Smoothing also buys a hard invariant: with at most
# BASELINE_WINDOW * 5 grades pooled, the smoothed baseline can never exceed
# 151/152, and P(4 or fewer of 5 | 0.9934) = 0.033 > ALARM_P. So a single
# flipped verdict can never alarm on its own — the guarantee the removed
# 1/denom floor used to provide (dogfood fix, 2026-07-24).
BASELINE_PSEUDO_COUNT = 1.0

# Absolute error-rate ceiling. Independent of history on purpose: >30% of the
# nightly's runs erroring means the pipeline itself is sick (gateway down,
# engine wedged) regardless of what last week looked like.
ERROR_RATE_CEILING = 0.3

# Absolute fallback-rate jump over the trailing median that alarms. Fallback
# verdicts are the pipeline's "the model call failed, I'm guessing
# needs_more_info" path — a jump here is the classic silent-engine-swap
# symptom (verdicts keep flowing, but they're no longer reasoned).
FALLBACK_JUMP = 0.3

# Binary floats can't represent most n_ok fractions exactly (0.8 - 0.6 is
# 0.20000000000000007, not 0.2), so a drop that lands EXACTLY on a threshold
# must not out-round it and fire by float dust alone.
_FLOAT_SLOP = 1e-9

# The three conditions the detector can report, one per rule. These are the
# stable half of a reason — see :class:`AlarmReason`.
CODE_AGREEMENT_DROP = "agreement_drop"
CODE_ERROR_CEILING = "error_ceiling"
CODE_FALLBACK_JUMP = "fallback_jump"

# Joins the sorted codes into one alarm_key. "+" cannot occur inside a code, so
# the key splits back losslessly for the wire.
ALARM_KEY_SEP = "+"


class AlarmReason(str):
    """One detector finding: the operator-facing message, carrying its CODE.

    The message alone cannot identify a CONDITION. Every one of them embeds the
    live numbers behind it ("agreement_rate 0.80 ... below the trailing median
    1.00"), so the same unchanged condition re-observed tomorrow produces a
    different string — which is why the caller comparing reason strings could
    never tell "still bad" from "newly bad", and prod alarmed three times in 27
    hours for one condition (rows 9/10/11, 2026-08-06). The code is what the
    transition gate keys on.

    A ``str`` subclass rather than a tuple or a dataclass, because the message
    is ALREADY a wire artifact in three places — the ``alarm_reasons`` JSON
    column, the ``quality_regression`` audit payload, and the notification
    webhook body. Carrying the code alongside instead of wrapping the message
    keeps all three byte-identical: this type is a (code, message) pair that
    every existing consumer can still treat as the message.
    """

    # An instance attribute, declared here for type checkers. NOT __slots__:
    # variable-length builtins (str, int, tuple) reject a non-empty one.
    code: str

    def __new__(cls, code: str, message: str) -> AlarmReason:
        reason = super().__new__(cls, message)
        reason.code = code
        return reason

    @property
    def message(self) -> str:
        """The human half, for call sites that want to say which half they mean."""
        return str(self)

    def __repr__(self) -> str:
        return f"AlarmReason({self.code!r}, {str(self)!r})"


def alarm_key_for(reasons: Sequence[AlarmReason]) -> str | None:
    """The identity of an alarm CONDITION: its sorted codes, joined. None = clean.

    Sorted and de-duplicated so the key depends only on WHICH rules fired, never
    on the order the detector appended them — otherwise an
    agreement+error night and an error+agreement night would look like two
    different conditions and alarm twice for one problem.
    """
    codes = sorted({r.code for r in reasons})
    return ALARM_KEY_SEP.join(codes) if codes else None


def alarm_codes_from_key(key: str | None) -> list[str]:
    """Split a stored ``alarm_key`` back into codes ([] for clean AND pre-0027).

    Rows written before migration 0027 have a NULL key even when ``alarmed`` is
    true; they degrade to "no codes", so a consumer renders their prose reasons
    rather than inventing a condition they never recorded.
    """
    return key.split(ALARM_KEY_SEP) if key else []


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
    # The grade counts BEHIND agreement_rate, which is n_yes / n_classified.
    # The detector tests these, not the rate: a rate cannot be pooled with
    # other rates or significance-tested, and at n=5 it is quantised to 0.2
    # steps, so rate-vs-rate comparisons fire on ordinary sampling noise.
    #
    # `partial` ("right verdict, thin reasoning") is counted in n_classified
    # but not n_yes — it costs exactly as much as a flat disagreement — so it
    # is recorded separately: the card can then say "3 agree, 2 partial"
    # instead of a bare 0.60 that hides which it was. `unknown` critiques
    # count toward n_ok but enter neither, which is why n_classified (not
    # n_ok) is the honest denominator.
    #
    # All default to 0 for callers that predate them; the detector treats a
    # zero denominator as "no counts" and falls back to the median rule.
    n_yes: int = 0
    n_partial: int = 0
    n_no: int = 0
    n_classified: int = 0


@dataclass(frozen=True)
class TrendPoint:
    """The slice of a historical snapshot the regression rule consumes.

    A deliberate seam: the detector takes these instead of ORM rows so its
    tests (and any future caller) never need a database.

    Callers pass points NEWEST FIRST (the order the store's ``recent_snapshots``
    returns) — the detector pools a wide window for the agreement baseline but
    slices the newest :data:`MEDIAN_WINDOW` for its median rules.
    """

    agreement_rate: float | None
    fallback_rate: float | None
    # Grade counts for this historical point, or None for rows written before
    # migration 0026. None is load-bearing: it is what makes the detector fall
    # back to the median rule instead of silently pooling absent evidence.
    n_yes: int | None = None
    n_classified: int | None = None


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

    # The grade counts behind agreement_rate, taken straight from the
    # aggregator (never recomputed — one source of truth for what the oracle
    # said). Zeroed in local mode for the same reason agreement_rate is NULLed:
    # with no oracle there are no critiques, and counts that disagreed with the
    # rate would let a local point arm a graded baseline.
    graded = mode == "graded"
    counts = {
        k: (agg.agreement_counts.get(k, 0) if graded else 0) for k in ("yes", "no", "partial")
    }
    # `unknown` critiques count toward n_ok but enter neither the numerator nor
    # the denominator — this, not n_ok, is agreement_rate's true denominator.
    n_classified = sum(counts.values())

    return SnapshotMetrics(
        mode=mode,
        n_ok=agg.n_ok,
        n_error=agg.n_error,
        agreement_rate=agg.agreement_rate if graded else None,
        fallback_rate=fallback_rate,
        error_rate=error_rate,
        verdict_counts=dict(agg.verdict_counts),
        latency_p50_ms=latency_p50_ms,
        n_yes=counts["yes"],
        n_partial=counts["partial"],
        n_no=counts["no"],
        n_classified=n_classified,
    )


def _median(values: list[float]) -> float:
    """Plain median (mean of the middle pair on even n). Caller ensures non-empty."""
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _binomial_tail_at_most(k: int, n: int, p: float) -> float:
    """Exact P(X <= k) for X ~ Binomial(n, p) — the lower tail, summed.

    Exact and stdlib-only (``math.comb``): n is the nightly's classified-grade
    count, 5 by default and capped at 10 by ``quality_nightly_n``, so the sum
    is at most eleven terms. A normal approximation would be wrong at exactly
    this sample size, and pulling in scipy to get one CDF would add a compiled
    numerical dependency to an app whose whole install story is "pip and go".
    """
    if n <= 0:
        return 1.0
    p = min(max(p, 0.0), 1.0)
    return sum(math.comb(n, i) * (p**i) * ((1.0 - p) ** (n - i)) for i in range(k + 1))


@dataclass(frozen=True)
class _PooledBaseline:
    """The trailing history reduced to one rate the new night can be tested against."""

    n_yes: int
    n_classified: int
    n_points: int

    @property
    def rate(self) -> float:
        """The point estimate an operator reads (unsmoothed — it is a fact)."""
        return self.n_yes / self.n_classified

    @property
    def smoothed_rate(self) -> float:
        """The rate the binomial test uses. See :data:`BASELINE_PSEUDO_COUNT`."""
        return (self.n_yes + BASELINE_PSEUDO_COUNT) / (
            self.n_classified + 2 * BASELINE_PSEUDO_COUNT
        )


def _pool_baseline(history: list[TrendPoint]) -> _PooledBaseline | None:
    """Pool the trailing counted points, or None if there aren't enough.

    A point with a NULL count is a pre-0026 row and a point with zero
    classified critiques is a night the oracle graded nothing; neither is
    evidence, so neither contributes to the pool OR to the history quorum —
    otherwise three empty nights and two real ones would look like a baseline.
    """
    counted = [
        (p.n_yes, p.n_classified)
        for p in history[:BASELINE_WINDOW]
        if p.n_yes is not None and p.n_classified
    ]
    if len(counted) < MIN_HISTORY:
        return None
    return _PooledBaseline(
        n_yes=sum(yes for yes, _ in counted),
        n_classified=sum(n for _, n in counted),
        n_points=len(counted),
    )


def _agreement_drop_by_counts(
    new: SnapshotMetrics, baseline: _PooledBaseline, *, alarm_drop: float
) -> AlarmReason | None:
    """The counts-driven agreement test: the reason it fired, or None.

    Asks the exact binomial question against the pooled baseline: under that
    rate, how often would a night grade this badly by chance? Two independent
    gates must BOTH pass — statistical significance (<= :data:`ALARM_P`) and
    operational significance (a point-estimate drop past the operator's
    ``quality_alarm_drop``) — so neither a hair-trigger p-value on a large
    sample nor a big-looking drop on a tiny one can page anyone alone.
    """
    tail = _binomial_tail_at_most(new.n_yes, new.n_classified, baseline.smoothed_rate)
    rate = new.n_yes / new.n_classified
    if tail > ALARM_P or baseline.rate - rate <= alarm_drop + _FLOAT_SLOP:
        return None

    return AlarmReason(
        CODE_AGREEMENT_DROP,
        f"agreement_rate {rate:.2f} ({new.n_yes}/{new.n_classified} grades agreed) "
        f"is a real drop from the pooled baseline {baseline.rate:.2f} "
        f"({baseline.n_yes}/{baseline.n_classified} over {baseline.n_points} runs) — "
        f"a night this bad happens by chance {tail * 100:.1f}% of the time",
    )


def _agreement_drop_by_median(
    new: SnapshotMetrics, history: list[TrendPoint], *, alarm_drop: float
) -> AlarmReason | None:
    """Pre-0026 fallback: the median-of-rates rule, kept verbatim.

    Rows written before the grade counts existed carry only a rate, and their
    batch artifacts are long gone — there is nothing to recover the counts
    from. Without this path the detector would go SILENT for the days it takes
    counted history to accumulate after an upgrade, which is the worst possible
    failure: a quiet detector looks exactly like a healthy pipeline.

    So this is the old rule unchanged, floor included. That floor
    (``max(alarm_drop, 1/denom)``) is what keeps a single flipped verdict from
    paging when all you have is a quantised rate; it is also why the rule
    cannot tell noise from a regression, which is precisely what the counts
    path fixes. It expires on its own as counted rows push the old ones out.
    """
    rate = new.agreement_rate
    hist_agreement = [
        p.agreement_rate for p in history[:MEDIAN_WINDOW] if p.agreement_rate is not None
    ]
    if rate is None or not hist_agreement or new.n_ok <= 0:
        return None

    med = _median(hist_agreement)
    denom = new.n_classified if new.n_classified > 0 else new.n_ok
    min_drop = max(alarm_drop, 1.0 / denom)
    if med - rate <= min_drop + _FLOAT_SLOP:
        return None
    # Same CODE as the counts path: these are two ways of observing ONE
    # condition, and an install crossing from legacy to counted history must not
    # read the crossover as a brand-new alarm.
    return AlarmReason(
        CODE_AGREEMENT_DROP,
        f"agreement_rate {rate:.2f} is more than {min_drop:.2f} "
        f"below the trailing median {med:.2f}",
    )


def detect_regression(
    new: SnapshotMetrics,
    history: list[TrendPoint],
    *,
    alarm_drop: float,
) -> list[AlarmReason]:
    """Decide whether *new* regresses against its trailing same-mode *history*.

    Returns :class:`AlarmReason` findings — a code and a human message each,
    empty = no alarm. The caller passes the trailing (up to
    :data:`BASELINE_WINDOW`) SAME-MODE points, NEWEST FIRST; with fewer than
    :data:`MIN_HISTORY` the whole check is skipped — a young install must not
    page anyone off two nights of data.

    **This function answers "is this point bad", never "should anyone be told".**
    It re-decides from scratch every run and has no memory, so a condition that
    PERSISTS is re-reported every night it persists — correctly: the row is a
    measurement, and a measurement of a still-broken pipeline is still bad. The
    caller (:func:`soc_ai.eval.nightly._record_trend_point`) is what turns that
    into notifications, and it fires only on a change of
    :func:`alarm_key_for` — the transition into a condition, not each
    re-observation of it. Do not push suppression down here: the trend would
    then record "clean" for nights that were not.

    Corollary, so nobody "fixes" it later: the median fallback below can fire on
    consecutive nights while an install crosses over from pre-0026 history
    (the counts baseline needs :data:`MIN_HISTORY` counted rows, which arrives
    within three nightlies of the upgrade). That needs no special case — the
    transition gate makes a repeated same-code night quiet anyway, and a
    window-shaped exception would be dead code by the time it was reviewed.

    Three rules:

    * **Agreement drop** — the counts test. ``agreement_rate`` is
      ``n_yes / n_classified`` over ~5 graded alerts, so as a *rate* it moves
      in 0.2 steps and comparing it to a median of other such rates fires on
      ordinary sampling noise: at this install's own historical agreement
      (107 of 120 = 0.892) that rule alarmed with probability 0.094 per night,
      about one false alarm every eleven nightlies — 95% odds of at least one
      per month, which is what it actually delivered. So the baseline is the
      trailing counts POOLED (:func:`_agreement_drop_by_counts`), the test is
      the exact binomial tail against it, and the alarm needs both statistical
      significance (P <= :data:`ALARM_P`, ~1 false alarm per 50 nights) and a
      drop past the operator's ``alarm_drop``. History without counts (pre-0026
      rows) falls back to the old median rule — see
      :func:`_agreement_drop_by_median`.

      The old ``max(alarm_drop, 1/denom)`` floor is gone from the counts path:
      with a real significance test it no longer protects anything, and at n=5
      it pinned the operator-facing ``quality_alarm_drop`` knob at 0.20,
      silently ignoring every setting at or below that. The single-flip
      guarantee it existed for now comes from the smoothed baseline (see
      :data:`BASELINE_PSEUDO_COUNT`).
    * **Error-rate ceiling** — ``new.error_rate`` > 0.3, absolute. History
      independent: a third of the nightly erroring is sick, full stop.
    * **Fallback jump** — ``new.fallback_rate`` more than 0.3 above the
      trailing median. The silent-engine-swap tripwire: the pipeline still
      "works" but verdicts are fabricated fallbacks.
    """
    if len(history) < MIN_HISTORY:
        return []

    reasons: list[AlarmReason] = []

    if new.agreement_rate is not None:
        # Which test runs is decided ONCE, up front, by whether the evidence
        # for the counts test exists. Never "try the counts test and fall back
        # if it stays silent" — that would let the noisy rule it replaces
        # re-fire every alarm the counts test just cleared.
        baseline = _pool_baseline(history) if new.n_classified > 0 else None
        agreement = (
            _agreement_drop_by_median(new, history, alarm_drop=alarm_drop)
            if baseline is None
            else _agreement_drop_by_counts(new, baseline, alarm_drop=alarm_drop)
        )
        if agreement is not None:
            reasons.append(agreement)

    if new.error_rate > ERROR_RATE_CEILING:
        reasons.append(
            AlarmReason(
                CODE_ERROR_CEILING,
                f"error_rate {new.error_rate:.2f} exceeds the {ERROR_RATE_CEILING:.2f} ceiling",
            )
        )

    hist_fallback = [
        p.fallback_rate for p in history[:MEDIAN_WINDOW] if p.fallback_rate is not None
    ]
    if new.fallback_rate is not None and hist_fallback:
        med_fb = _median(hist_fallback)
        if new.fallback_rate - med_fb > FALLBACK_JUMP:
            reasons.append(
                AlarmReason(
                    CODE_FALLBACK_JUMP,
                    f"fallback_rate {new.fallback_rate:.2f} jumped more than "
                    f"{FALLBACK_JUMP:.2f} above the trailing median {med_fb:.2f}",
                )
            )

    return reasons


__all__ = [
    "ALARM_KEY_SEP",
    "ALARM_P",
    "BASELINE_WINDOW",
    "CODE_AGREEMENT_DROP",
    "CODE_ERROR_CEILING",
    "CODE_FALLBACK_JUMP",
    "ERROR_RATE_CEILING",
    "FALLBACK_JUMP",
    "MEDIAN_WINDOW",
    "MIN_HISTORY",
    "AlarmReason",
    "SnapshotMetrics",
    "TrendPoint",
    "alarm_codes_from_key",
    "alarm_key_for",
    "compute_snapshot_metrics",
    "detect_regression",
]
