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

Two strata, never blended either. Every number above describes the REAL alerts
of the batch. A planted scenario (``is_synth``) is scored against its own
ground truth and lands in :attr:`SnapshotMetrics.synth`, so the one known
positive of a batch cannot enter the verdict distribution of the real alerts.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from soc_ai.eval.report import Aggregates, aggregate

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

# The absolute level below which VERDICT agreement is low.
#
# Verdict agreement is the share of real alerts for which the Oracle reaches
# the same verdict class as the model (see :func:`verdict_class`). It is not
# ``agreement_rate``. That rate grades the verdict, the confidence and the
# reasoning as one, so a correct verdict under a loose report scores as
# ``partial`` and counts against it. An earlier review judged it a measure of
# the Oracle's taste in prose and not a gate, and production bears that out:
# over the last 7 graded runs before this rule the rate read 6 of 35, while
# the Oracle named the model's own verdict in 26 of the 26 critiques of a run
# that had a verdict. The other 9 critiques were of runs that died with no
# report. An alarm on the rate would have reported a regression that the
# verdicts did not have.
#
# This is the one number the 2026-11-13 production review added. The code had
# no absolute level for agreement of any type. One half is the majority line:
# below it, the Oracle reaches a different verdict than the model more often
# than the same one. It is a constant and reads no history, so no run of bad
# nights can move it. It is never tested against ONE night: see
# :func:`_agreement_low_over_window`.
AGREEMENT_FLOOR = 0.5

# Binary floats can't represent most n_ok fractions exactly (0.8 - 0.6 is
# 0.20000000000000007, not 0.2), so a drop that lands EXACTLY on a threshold
# must not out-round it and fire by float dust alone.
_FLOAT_SLOP = 1e-9

# The conditions the detector can report, one per rule. These are the
# stable half of a reason — see :class:`AlarmReason`.
CODE_AGREEMENT_DROP = "agreement_drop"
CODE_ERROR_CEILING = "error_ceiling"
CODE_FALLBACK_JUMP = "fallback_jump"
# Two more (production review 2026-11-13). ``agreement_low`` is the VERDICT
# agreement of a window of nights against :data:`AGREEMENT_FLOOR`. It does not
# read ``agreement_rate``; ``agreement_drop`` above still does. ``synth_miss``
# is a planted true positive that the run did not call a positive.
CODE_AGREEMENT_LOW = "agreement_low"
CODE_SYNTH_MISS = "synth_miss"

# Verdicts that mean the run called something a threat. A batch with none of
# these observed no positive at all, whatever its agreement rate says.
_POSITIVE_VERDICTS = ("true_positive", "escalate")

# The class of each verdict, for verdict agreement. Two verdicts agree when
# their classes are equal. ``needs_more_info`` and ``inconclusive`` share a
# class: both say that the run did not settle the alert. So one of them against
# a settled verdict is a disagreement, and one against the other is not.
_VERDICT_CLASS = {
    "true_positive": "positive",
    "escalate": "positive",
    "false_positive": "negative",
    "needs_more_info": "unsettled",
    "inconclusive": "unsettled",
}

# The row a batch writes for a run that never started, because the failure
# budget stopped the batch first. Such a run did not end, so it is neither an
# error nor a completed run. The batch runner imports this constant.
NOT_RUN_ERROR = "aborted by failure budget"

# How a run ended. See :func:`run_outcome`.
RUN_COMPLETED = "completed"
RUN_ERROR = "error"
RUN_UNFINISHED = "unfinished"

# The classes of a run that ended with no result, and how each is printed.
ERROR_GATEWAY = "gateway"
ERROR_TOKEN_LIMIT = "token_limit"  # noqa: S105 - the name of an error class, not a secret
ERROR_TIME_LIMIT = "time_limit"
ERROR_OTHER = "other"
_ERROR_LABEL = {
    ERROR_GATEWAY: "gateway",
    ERROR_TOKEN_LIMIT: "token limit",
    ERROR_TIME_LIMIT: "time limit",
    ERROR_OTHER: "other",
}

# Exception classes that mean the model gateway did not serve the call.
_GATEWAY_TYPES = frozenset(
    {
        "modelhttperror",
        "connecterror",
        "connecttimeout",
        "readtimeout",
        "readerror",
        "remoteprotocolerror",
        "apiconnectionerror",
        "apitimeouterror",
        "modelapierror",
    }
)
_TOKEN_LIMIT_MARKERS = ("token limit", "max_tokens", "context length", "context window")
_TIME_LIMIT_MARKERS = ("timeout after", "timed out", "time limit", "wall clock")
_TIME_LIMIT_TYPES = frozenset({"timeouterror", "cancellederror"})
_GATEWAY_MARKERS = ("status_code: 5", "status_code: 429", "cannot connect", "connection refused")

# Separates the two verdicts of a disagreement in a stored pair key:
# ``<local verdict>><Oracle verdict>``. No verdict holds the character.
PAIR_SEP = ">"

# The three outcomes of one planted true positive.
SYNTH_CAUGHT = "caught"
SYNTH_MISSED = "missed"
SYNTH_NOT_MEASURED = "not_measured"

# The ground truth a planted row must carry to count here. A benign twin
# (``false_positive``) has no positive to miss.
_SYNTH_POSITIVE = "true_positive"

# One sentence for each way a grade request fails. The keys are the harness
# GRADER_* constants, spelled out here so this module keeps importing nothing
# that touches the network.
_NOT_GRADED_SENTENCE = {
    "quota": "The Oracle quota is used up.",
    "gateway": "The Oracle gateway returned an error.",
    "refusal": "The sanitizer check stopped the send to the Oracle.",
}
_NOT_GRADED_UNKNOWN = "The grade request failed."

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


def alarm_conditions(key: str | None) -> frozenset[str]:
    """The CONDITIONS behind a stored ``alarm_key``, for the notification gate.

    Each code is one condition. The gate notifies when a condition appears that
    the previous point did not hold, and stays quiet when one clears beside
    another that stands. Comparing whole keys cannot do the second: "low
    agreement and a missed plant" followed by "low agreement" is a changed key
    and nothing new.

    ``agreement_drop`` and ``agreement_low`` are two conditions and not one.
    They read different measures: the first reads ``agreement_rate`` and the
    second reads verdict agreement.
    """
    return frozenset(alarm_codes_from_key(key))


def classify_run_error(error_type: str | None, text: str | None) -> str:
    """The class of a run that ended with no result, from what the run recorded.

    ``gateway``, ``token_limit``, ``time_limit`` or ``other``. The order
    matters. A token limit is tested first: it arrives as a model-behaviour
    error and its text is the only mark. A gateway exception class is tested
    before the time limit: a read timeout on the gateway is the gateway that
    did not answer, not the run that took too long.
    """
    kind = (error_type or "").strip().lower()
    body = f"{error_type or ''} {text or ''}".lower()
    if any(marker in body for marker in _TOKEN_LIMIT_MARKERS):
        return ERROR_TOKEN_LIMIT
    if kind in _GATEWAY_TYPES:
        return ERROR_GATEWAY
    if kind in _TIME_LIMIT_TYPES or any(marker in body for marker in _TIME_LIMIT_MARKERS):
        return ERROR_TIME_LIMIT
    if any(marker in body for marker in _GATEWAY_MARKERS):
        return ERROR_GATEWAY
    return ERROR_OTHER


def run_outcome(row: dict[str, Any]) -> str:
    """How one run of the batch ended: completed, error or unfinished.

    **Completed** is a run that left a report with a verdict of its own. Any
    verdict counts: ``needs_more_info`` is a completed run.

    **Error** is every other run that ended:

    - the harness raised or timed out (``error`` on the row);
    - the run left no report, or a report with no verdict. On production the
      runs of 2026-11-07 died on a gateway error after the harness had started
      them. The harness returned, so the row carried no ``error``, and the
      snapshot recorded ``error_rate 0.00`` for 5 dead runs of 5;
    - the report is a pipeline fallback. The model call failed and the pipeline
      wrote a placeholder ``needs_more_info``. That is a failed run that carries
      a verdict, the same defect one layer up.

    **Unfinished** is a run that never ended: the failure budget stopped the
    batch before it started. It is not counted on either side.

    A run that the Oracle did not grade is a completed run when it has a
    verdict. A lost grade says nothing about the triage.
    """
    error = row.get("error")
    if error == NOT_RUN_ERROR:
        return RUN_UNFINISHED
    if error or row.get("is_fallback") or verdict_class(row.get("verdict")) is None:
        return RUN_ERROR
    return RUN_COMPLETED


def _error_class_of(row: dict[str, Any]) -> str:
    """The class of an error run, from the row's own record of the failure."""
    error = row.get("error")
    if error:
        text = str(error)
        head, sep, _rest = text.partition(":")
        return classify_run_error(head if sep and " " not in head else None, text)
    return classify_run_error(row.get("run_error_type"), row.get("run_error"))


def verdict_class(verdict: Any) -> str | None:
    """The class of a verdict for verdict agreement, or None for no verdict.

    ``positive``, ``negative`` or ``unsettled``. None covers a run that
    produced no report and a critique that named no verdict: neither can be
    compared, and neither is counted as an agreement or as a disagreement.
    """
    return _VERDICT_CLASS.get(verdict) if isinstance(verdict, str) else None


@dataclass(frozen=True)
class SynthOutcome:
    """What happened to one planted true positive.

    ``caught`` and ``missed`` are measurements. ``not_measured`` is the absence
    of one, with its ``cause``: the plant was refused, the run errored, or the
    model call failed and left a fallback verdict. Only ``missed`` alarms. A run
    that produced no verdict of its own says nothing about what the model would
    have decided, and a verdict alarm for a timeout would send its reader to the
    wrong place.
    """

    scenario_id: str
    outcome: str
    verdict: str | None = None
    confidence: float | None = None
    cause: str | None = None


@dataclass(frozen=True)
class ServedModel:
    """One (model, backend) pair and how many runs of the batch it served."""

    model: str
    backend: str | None
    runs: int


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
    # The planted true positives of this batch, one entry each. Empty when the
    # batch planned none. Scored against ground truth, never by the Oracle.
    synth: tuple[SynthOutcome, ...] = ()
    # Why the batch planted nothing, when it was asked to and could not.
    synth_note: str | None = None
    # The scenarios the deployment could not detect tonight, as (id, reason).
    # They were not planted, so they have no outcome above and raise no alarm.
    synth_ineligible: tuple[tuple[str, str], ...] = ()
    # Runs whose investigation completed and whose grade request failed, with
    # the count of each cause. These are NOT errors: ``n_error`` and
    # ``error_rate`` count failed investigations only. Always 0 in local mode.
    n_not_graded: int = 0
    not_graded_kinds: dict[str, int] = field(default_factory=dict)
    # Which model served the completed runs, and how many completed runs
    # recorded nothing. See :func:`snapshot_detail` for the fallback.
    served: tuple[ServedModel, ...] = ()
    n_served_unrecorded: int = 0
    # VERDICT agreement over the real alerts: of the runs where the model and
    # the Oracle each stated a verdict, how many are the same class
    # (:func:`verdict_class`). ``verdict_pairs`` counts each disagreement under
    # ``<local verdict>><Oracle verdict>``. ``n_no_oracle_verdict`` counts the
    # completed runs left out because the critique named no verdict. A run with
    # no verdict of its own is an error and is not here. Planted rows never
    # enter. All zero in local mode.
    verdict_agree: int = 0
    verdict_compared: int = 0
    verdict_pairs: dict[str, int] = field(default_factory=dict)
    n_no_oracle_verdict: int = 0
    # The class of each run counted in ``n_error`` (:func:`classify_run_error`),
    # and the runs that never ended. ``n_ok`` counts completed runs only: a run
    # with a report and a verdict of its own. See :func:`run_outcome`.
    error_classes: dict[str, int] = field(default_factory=dict)
    n_unfinished: int = 0


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
    # Whether THIS point already alarmed for agreement. See _pool_baseline: a
    # night the detector called a regression is not evidence of the normal rate,
    # and pooling it teaches the baseline to accept it.
    agreement_alarmed: bool = False
    # Verdict agreement of this historical point, for the window rule. None on
    # a row that never recorded it, which is every row written before the
    # Oracle was asked for its own verdict. Such a row is not evidence either
    # way and the rule does not count it.
    verdict_agree: int | None = None
    verdict_compared: int | None = None
    verdict_pairs: dict[str, int] | None = None


def _confidence_of(row: dict[str, Any]) -> float | None:
    value = row.get("confidence")
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _synth_outcomes(
    synth_rows: list[dict[str, Any]], *, planned: Sequence[str], note: str | None
) -> tuple[SynthOutcome, ...]:
    """Score the planted true positives of one batch against their ground truth.

    Verdict only, never the confidence floor of the scenario rubric. The
    benchmark's strict recall moved 0.235 between two batches of identical code
    because ten scenarios sit within 0.05 of their floor, so a floor here would
    alarm on that noise. The question a nightly can answer is the plain one:
    did the run call a known intrusion a positive.

    A row whose ground truth is not ``true_positive`` is skipped, and so is a
    row that predates the field: neither holds a positive that could be missed.
    A planned scenario with no row at all is reported as not measured, with the
    reason the plant failed, so a refused plant cannot pass as a quiet night.
    """
    outcomes: list[SynthOutcome] = []
    seen: set[str] = set()
    for row in synth_rows:
        scenario_id = str(row.get("synth_scenario_id") or "")
        if not scenario_id or row.get("synth_expected_verdict") != _SYNTH_POSITIVE:
            continue
        seen.add(scenario_id)
        verdict = row.get("verdict")
        if row.get("error"):
            outcomes.append(
                SynthOutcome(scenario_id, SYNTH_NOT_MEASURED, cause=str(row["error"])[:200])
            )
        elif row.get("is_fallback"):
            # The model call died and the pipeline wrote a placeholder
            # needs_more_info. That is a failed run wearing a verdict.
            outcomes.append(
                SynthOutcome(
                    scenario_id,
                    SYNTH_NOT_MEASURED,
                    cause="The model call failed and the run holds a fallback verdict.",
                )
            )
        elif verdict_class(verdict) is None:
            # The run died and left no verdict. That is no answer, so it is not
            # a miss: a verdict alarm for a gateway outage names the wrong fault.
            outcomes.append(
                SynthOutcome(
                    scenario_id,
                    SYNTH_NOT_MEASURED,
                    cause=str(row.get("run_error") or "The run ended with no verdict.")[:200],
                )
            )
        elif verdict in _POSITIVE_VERDICTS:
            outcomes.append(
                SynthOutcome(
                    scenario_id, SYNTH_CAUGHT, verdict=str(verdict), confidence=_confidence_of(row)
                )
            )
        else:
            outcomes.append(
                SynthOutcome(
                    scenario_id,
                    SYNTH_MISSED,
                    verdict=str(verdict or "unknown"),
                    confidence=_confidence_of(row),
                )
            )
    for scenario_id in planned:
        if scenario_id not in seen:
            seen.add(scenario_id)
            outcomes.append(
                SynthOutcome(
                    scenario_id,
                    SYNTH_NOT_MEASURED,
                    cause=note or "The batch holds no run for this scenario.",
                )
            )
    return tuple(outcomes)


def _served_models(rows: list[dict[str, Any]]) -> tuple[tuple[ServedModel, ...], int]:
    """Count the completed runs of each served (model, backend) pair.

    Returns the pairs, most runs first, and the number of completed runs that
    recorded nothing. A run that changed route counts once under each pair, so
    the counts can sum to more than the runs. An errored run is left out: it
    has no result to read a record from.
    """
    counts: dict[tuple[str, str | None], int] = {}
    unrecorded = 0
    for row in rows:
        if row.get("error"):
            continue
        pairs: set[tuple[str, str | None]] = set()
        for entry in row.get("served") or []:
            if not isinstance(entry, dict):
                continue
            model = entry.get("model")
            if not isinstance(model, str) or not model:
                continue
            backend = entry.get("backend")
            pairs.add((model, backend if isinstance(backend, str) and backend else None))
        if not pairs:
            unrecorded += 1
            continue
        for pair in pairs:
            counts[pair] = counts.get(pair, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1] or ""))
    return (
        tuple(ServedModel(model=model, backend=backend, runs=n) for (model, backend), n in ordered),
        unrecorded,
    )


def _verdict_agreement(ok_rows: list[dict[str, Any]]) -> tuple[int, int, dict[str, int], int]:
    """``(agree, compared, pairs, no Oracle verdict)`` over the completed real runs.

    A run the grader did not answer for is left out. So is a critique with no
    verdict line, which is counted apart and compared with nothing.
    """
    agree = compared = no_oracle_verdict = 0
    pairs: dict[str, int] = {}
    for r in ok_rows:
        if r.get("grader_error") or r.get("grader_error_kind"):
            continue
        local, oracle = r.get("verdict"), r.get("oracle_verdict")
        local_class, oracle_class = verdict_class(local), verdict_class(oracle)
        if oracle_class is None:
            no_oracle_verdict += 1
            continue
        compared += 1
        if local_class == oracle_class:
            agree += 1
        else:
            pair = f"{local}{PAIR_SEP}{oracle}"
            pairs[pair] = pairs.get(pair, 0) + 1
    return agree, compared, pairs, no_oracle_verdict


def compute_snapshot_metrics(
    rows: list[dict[str, Any]],
    agg: Aggregates,
    *,
    mode: str,
    synth_planned: Sequence[str] = (),
    synth_note: str | None = None,
    synth_ineligible: Sequence[tuple[str, str]] = (),
    n_planned: int | None = None,
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

    **Planted rows are a stratum of their own.** When the batch holds any, the
    aggregates are recomputed over the real rows alone, so every number above
    keeps the meaning it has on every earlier point of the trend. The planted
    rows are scored by :func:`_synth_outcomes`. ``synth_planned`` names the
    scenarios the caller asked the batch to plant, and ``synth_note`` the reason
    a plant failed, so a scenario that never produced a row is still reported.

    **A lost grade is not an error.** A row with ``grader_error`` completed its
    investigation: it counts in ``n_ok`` and in the verdict distribution, its
    agreement is ``unknown``, and it is counted in ``n_not_graded``. Only a
    failed investigation counts in ``n_error``.

    **A run with no result is an error.** ``n_ok`` counts completed runs: a
    report with a verdict of its own (:func:`run_outcome`). A run that left no
    report, a run with no verdict and a pipeline fallback count in ``n_error``
    and in ``error_rate``, each under its class in ``error_classes``. The
    agreement counts, the verdict distribution and the latency are over the
    completed runs alone: a grade the Oracle gave a dead run is not a grade of
    a verdict. ``fallback_rate`` keeps its meaning, the share of the runs with
    a report that are fallbacks, so its own rule still reads it.

    ``n_planned`` is the number of runs the batch planned. With it, the runs
    that never ended are counted in ``n_unfinished`` and in neither rate.
    """
    all_rows = rows
    synth_rows = [r for r in rows if r.get("is_synth")]
    rows = [r for r in rows if not r.get("is_synth")]
    outcomes = [run_outcome(r) for r in rows]
    ok_rows = [r for r, outcome in zip(rows, outcomes, strict=True) if outcome == RUN_COMPLETED]
    error_rows = [r for r, outcome in zip(rows, outcomes, strict=True) if outcome == RUN_ERROR]
    if len(ok_rows) != len(all_rows):
        # One source of truth for the numbers of the completed real runs: the
        # same aggregator, over those rows. Never a second copy of its
        # arithmetic here.
        agg = aggregate(ok_rows)

    error_classes: dict[str, int] = {}
    for r in error_rows:
        name = _error_class_of(r)
        error_classes[name] = error_classes.get(name, 0) + 1
    n_unfinished = sum(1 for r in all_rows if run_outcome(r) == RUN_UNFINISHED)
    if n_planned is not None:
        n_unfinished += max(0, n_planned - len(all_rows))

    n_fallback = sum(1 for r in rows if not r.get("error") and r.get("is_fallback"))
    fallback_rate: float | None = None
    if ok_rows or n_fallback:
        fallback_rate = n_fallback / (len(ok_rows) + n_fallback)

    n_ok, n_error = len(ok_rows), len(error_rows)
    n_total = n_ok + n_error
    error_rate = (n_error / n_total) if n_total > 0 else 0.0

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

    # Runs the grader never answered for. Only a graded run asks, so a stray
    # key on a local row cannot invent a lost grade.
    not_graded_kinds: dict[str, int] = {}
    if graded:
        for r in ok_rows:
            if r.get("grader_error") or r.get("grader_error_kind"):
                kind = str(r.get("grader_error_kind") or "unknown")
                not_graded_kinds[kind] = not_graded_kinds.get(kind, 0) + 1

    verdict_agree, verdict_compared, verdict_pairs, n_no_oracle_verdict = (
        _verdict_agreement(ok_rows) if graded else (0, 0, {}, 0)
    )

    served, n_served_unrecorded = _served_models([*rows, *synth_rows])

    return SnapshotMetrics(
        mode=mode,
        n_ok=n_ok,
        n_error=n_error,
        agreement_rate=agg.agreement_rate if graded else None,
        fallback_rate=fallback_rate,
        error_rate=error_rate,
        verdict_counts=dict(agg.verdict_counts),
        latency_p50_ms=latency_p50_ms,
        n_yes=counts["yes"],
        n_partial=counts["partial"],
        n_no=counts["no"],
        n_classified=n_classified,
        synth=_synth_outcomes(synth_rows, planned=synth_planned, note=synth_note),
        synth_note=synth_note,
        synth_ineligible=tuple((str(sid), str(reason)) for sid, reason in synth_ineligible),
        n_not_graded=sum(not_graded_kinds.values()),
        not_graded_kinds=not_graded_kinds,
        served=served,
        n_served_unrecorded=n_served_unrecorded,
        verdict_agree=verdict_agree,
        verdict_compared=verdict_compared,
        verdict_pairs=verdict_pairs,
        n_no_oracle_verdict=n_no_oracle_verdict,
        error_classes=error_classes,
        n_unfinished=n_unfinished,
    )


def error_classes_text(classes: dict[str, int]) -> str:
    """The error classes as one clause, most frequent first: ``gateway 4, time limit 1``."""
    ordered = sorted(classes.items(), key=lambda item: (-item[1], item[0]))
    return ", ".join(f"{_ERROR_LABEL.get(name, name)} {n}" for name, n in ordered)


def run_errors_text(metrics: SnapshotMetrics) -> str | None:
    """One sentence for the runs that ended with no result, or None when all completed."""
    if metrics.n_error <= 0:
        return None
    total = metrics.n_ok + metrics.n_error
    sentence = f"{metrics.n_error} of {total} runs ended with no result"
    if metrics.error_classes:
        sentence += f": {error_classes_text(metrics.error_classes)}"
    return f"{sentence}."


def not_measured_text(metrics: SnapshotMetrics) -> str | None:
    """The sentence for a night that lost grades to the grader, or None.

    Opens with "Agreement is not measured." when no run was graded at all, and
    names each cause. A night with some grades keeps its agreement rate and
    states only the loss, so the reader knows the rate rests on fewer runs.

    None in local mode and on a night that lost nothing. This is a statement
    about the GRADER. It is never an alarm reason: a used-up quota is not a
    regression of the verdicts, and reporting it as one is the defect this
    function replaces.
    """
    if metrics.mode != "graded" or metrics.n_not_graded <= 0:
        return None
    graded = max(0, metrics.n_ok - metrics.n_not_graded)
    parts = [f"The Oracle graded {graded} of {metrics.n_ok} runs."]
    if metrics.n_classified == 0:
        parts.insert(0, "Agreement is not measured.")
    ordered = sorted(metrics.not_graded_kinds.items(), key=lambda item: (-item[1], item[0]))
    for kind, _n in ordered:
        sentence = _NOT_GRADED_SENTENCE.get(kind, _NOT_GRADED_UNKNOWN)
        if sentence not in parts:
            parts.append(sentence)
    return " ".join(parts)


def _with_stop(text: str) -> str:
    """End ``text`` with a full stop, so a cause can be followed by a sentence."""
    text = text.strip()
    return text if text.endswith((".", "!", "?")) else f"{text}."


def ineligible_text(metrics: SnapshotMetrics) -> str | None:
    """One line that names each scenario that was not eligible, and why. Or None."""
    if not metrics.synth_ineligible:
        return None
    return " ".join(
        _with_stop(f"{scenario_id} is not eligible: {reason}")
        for scenario_id, reason in metrics.synth_ineligible
    )


def synth_text(metrics: SnapshotMetrics) -> list[str]:
    """One or two sentences for each planted true positive, for the run's detail.

    The last line names the scenarios that were not eligible, when there are
    any, so a night that planted nothing for that reason says which input is
    missing.
    """
    lines: list[str] = []
    if metrics.synth_note:
        lines.append(
            _with_stop(f"The batch planted no synthetic true positive. Cause: {metrics.synth_note}")
        )
    for outcome in metrics.synth:
        if outcome.outcome == SYNTH_CAUGHT:
            lines.append(f"The model caught the synthetic true positive {outcome.scenario_id}.")
        elif outcome.outcome == SYNTH_MISSED:
            lines.append(
                f"The model missed the synthetic true positive {outcome.scenario_id}. "
                f"{_missed_clause(outcome)}."
            )
        elif not metrics.synth_note:
            # With a plant failure the note above already gave the cause.
            lines.append(
                _with_stop(
                    f"The synthetic true positive {outcome.scenario_id} is not measured. "
                    f"Cause: {outcome.cause or 'unknown'}"
                )
            )
    if (line := ineligible_text(metrics)) is not None:
        lines.append(line)
    return lines


def snapshot_detail(metrics: SnapshotMetrics, *, configured_model: str | None) -> dict[str, Any]:
    """The JSON the snapshot row keeps beside its numbers (migration 0066).

    ``served`` lists each (model, backend) pair with its run count and a
    ``recorded`` mark. A completed run that recorded nothing is listed under the
    CONFIGURED model with ``recorded: false``: the best available name, and
    marked so that it is never read as the served one. ``served_recorded`` is
    True only when every completed run carried a record, and None when no run
    completed.
    """
    served: list[dict[str, Any]] = [
        {"model": s.model, "backend": s.backend, "runs": s.runs, "recorded": True}
        for s in metrics.served
    ]
    if metrics.n_served_unrecorded:
        served.append(
            {
                "model": configured_model,
                "backend": None,
                "runs": metrics.n_served_unrecorded,
                "recorded": False,
            }
        )
    served_recorded: bool | None = None
    if served:
        served_recorded = metrics.n_served_unrecorded == 0
    return {
        "served": served,
        "served_recorded": served_recorded,
        "synth": [
            {
                "scenario_id": o.scenario_id,
                "outcome": o.outcome,
                "verdict": o.verdict,
                "confidence": o.confidence,
                "cause": o.cause,
            }
            for o in metrics.synth
        ],
        "synth_note": metrics.synth_note,
        # Scenarios the deployment could not detect, so the nightly did not
        # plant them: the structured list, and the same fact as one line.
        "synth_ineligible": [
            {"scenario_id": scenario_id, "reason": reason}
            for scenario_id, reason in metrics.synth_ineligible
        ],
        "synth_ineligible_note": ineligible_text(metrics),
        "not_graded": {"n": metrics.n_not_graded, "kinds": dict(metrics.not_graded_kinds)},
        "not_measured": not_measured_text(metrics),
        # What the low agreement rule pools from history. ``pairs`` holds the
        # disagreements only, under ``<local verdict>><Oracle verdict>``.
        "verdict_agreement": {
            "agree": metrics.verdict_agree,
            "compared": metrics.verdict_compared,
            "pairs": dict(metrics.verdict_pairs),
            "no_oracle_verdict": metrics.n_no_oracle_verdict,
        },
        # How the runs of the real alerts ended. ``errors`` is ``n_error`` and
        # ``error_classes`` splits it by cause. ``unfinished`` runs never ended
        # and are in neither rate.
        "runs": {
            "completed": metrics.n_ok,
            "errors": metrics.n_error,
            "unfinished": metrics.n_unfinished,
        },
        "error_classes": dict(metrics.error_classes),
    }


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
    is at most eleven terms for one night and 71 for the window rule's seven
    nights. A normal approximation would be wrong at exactly
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
    window = [p for p in history[:BASELINE_WINDOW] if p.n_yes is not None and p.n_classified]
    # Nights this detector already called a regression are not evidence of the
    # normal rate. Pooling them is how a sustained decline becomes the new
    # baseline and the alarm goes quiet without anything improving: on the home
    # deployment the baseline slid 0.75 → 0.73 → 0.70 → 0.68 → 0.61 across the
    # bad nights, and two identical 1-of-5 measurements five days apart got
    # opposite answers — the first paged, the second was unremarkable against a
    # baseline the first had helped lower.
    #
    # Deliberately conservative: if dropping them leaves too little history the
    # old pool is used unchanged, so this can only ever make the detector harder
    # to erode, never blinder than it was.
    clean = [p for p in window if not p.agreement_alarmed]
    counted = [(p.n_yes, p.n_classified) for p in (clean if len(clean) >= MIN_HISTORY else window)]
    if len(counted) < MIN_HISTORY:
        return None
    return _PooledBaseline(
        n_yes=sum(yes for yes, _ in counted if yes is not None),
        n_classified=sum(n for _, n in counted if n),
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
        f"agreement_rate {rate:.2f} ({_grade_split(new)}) "
        f"is a real drop from the pooled baseline {baseline.rate:.2f} "
        f"({baseline.n_yes}/{baseline.n_classified} over {baseline.n_points} runs). "
        f"A night this bad happens by chance {tail * 100:.1f}% of the time"
        f"{_what_kind_of_bad(new)}{_what_this_cannot_tell_you(new)}",
    )


def _what_this_cannot_tell_you(new: SnapshotMetrics) -> str:
    """Bound the claim when the batch contained no positive verdict.

    The real alerts of a nightly batch come from the live queue and carry no
    ground truth. On a quiet grid every one of them is benign, so the rate
    measures the grader's opinion of benign traffic. That is worth watching and
    it is not what the label "quality" is read as.

    The bound ends when the batch MEASURED a planted true positive, caught or
    missed: that batch did test the direction that matters, and its result is
    reported on its own. A plant that was refused or whose run failed measured
    nothing, so the bound stays.

    It matters most in the direction nobody checks: if the analyst model started
    calling real intrusions benign, the grader would agree that benign things
    are benign and this number would go UP. An alarm that cannot move on the
    failure that matters should say so rather than let its silence imply cover.
    """
    counts = new.verdict_counts or {}
    if any(counts.get(v) for v in _POSITIVE_VERDICTS):
        return ""
    if any(o.outcome != SYNTH_NOT_MEASURED for o in new.synth):
        return ""
    return (
        ". Every verdict in this batch was benign and the batch measured no synthetic "
        "true positive, so this measures agreement on benign traffic only. It gives no "
        "evidence either way about whether a real detection would be caught"
    )


def _grade_split(new: SnapshotMetrics) -> str:
    """The three counts behind the rate, never just the numerator.

    "0/5 grades agreed" is false when all five were partial: the oracle agreed
    with every verdict and declined to fully stand behind the reasoning. Five
    partials and five flat contradictions produce the identical rate and call
    for opposite responses, and the operator was reading the first as the
    second. `partial` sits in the denominator but not the numerator by design
    (see soc_ai/eval/report.py) — that is defensible arithmetic and indefensible
    prose, so the prose now carries the split the dataclass already holds.
    """
    whole = f"{new.n_yes} of {new.n_classified} fully agreed"
    # Only break it down when the three parts actually account for the
    # denominator. They always do in real snapshots (report.py derives
    # n_classified as their sum), but a caller that supplied only n_yes would
    # otherwise be shown a fabricated "0 partial, 0 disagreed".
    if new.n_yes + new.n_partial + new.n_no != new.n_classified:
        return whole
    return f"{whole}: {new.n_partial} partial, {new.n_no} disagreed"


def _what_kind_of_bad(new: SnapshotMetrics) -> str:
    """Name the shape of the drop when it is unambiguous, else say nothing.

    The two shapes want different work — thin reasoning is prompt and citation
    work, wrong verdicts are model and logic work — so an alarm that cannot
    distinguish them sends its reader looking in the wrong place.
    """
    if not new.n_classified:
        return ""
    if new.n_no == 0 and new.n_partial:
        return (
            ". Every grade was partial. The Oracle contradicted no verdict. It did not "
            "fully accept the reasoning, which points at thin grounds or missing "
            "citations"
        )
    if new.n_partial == 0 and new.n_no:
        return ". Every grade was a flat disagreement. The Oracle rejected the verdicts themselves"
    return ""


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


# Below this share the tail is stated as a bound. It is a print width, not a
# rule: "0.0%" would read as "never".
_SMALLEST_PRINTED_TAIL = 0.001


def _tail_share(tail: float) -> str:
    """A tail probability as a share of the time."""
    return "less than 0.1%" if tail < _SMALLEST_PRINTED_TAIL else f"{tail * 100:.1f}%"


def _missed_clause(outcome: SynthOutcome) -> str:
    """The clause ``It returned <verdict> at confidence <c>``, with no final stop."""
    at = f" at confidence {outcome.confidence:.2f}" if outcome.confidence is not None else ""
    return f"It returned {outcome.verdict or 'unknown'}{at}"


def _synth_miss(new: SnapshotMetrics) -> AlarmReason | None:
    """A planted true positive that the run did not call a positive.

    The one rule with ground truth. Every other number on the trend is an
    opinion about benign traffic, and the failure that matters most is the one
    those numbers cannot see: a model that starts to call real intrusions benign
    is agreed with, and its agreement rate goes UP. A planted intrusion that
    comes back benign is that failure, observed.

    The message names each missed scenario and the verdict it got, because the
    scenario is the first thing the reader needs: its file states what the run
    had to find.
    """
    missed = [o for o in new.synth if o.outcome == SYNTH_MISSED]
    if not missed:
        return None
    if len(missed) == 1:
        only = missed[0]
        message = (
            f"The model missed the synthetic true positive {only.scenario_id}. "
            f"{_missed_clause(only)}"
        )
    else:
        each = ". ".join(
            f"{o.scenario_id} returned {o.verdict or 'unknown'}"
            + (f" at confidence {o.confidence:.2f}" if o.confidence is not None else "")
            for o in missed
        )
        message = f"The model missed {len(missed)} synthetic true positives. {each}"
    return AlarmReason(CODE_SYNTH_MISS, message)


def _pairs_text(pairs: dict[str, int]) -> str:
    """The disagreement pairs as one clause, most frequent first.

    ``local false_positive against Oracle needs_more_info: 12, local ...``. The
    pairs are what the alarm MEANS. A rate of 0.30 does not say whether the
    model closes alerts the Oracle would escalate or escalates alerts the
    Oracle would close, and those two want opposite work.
    """
    ordered = sorted(pairs.items(), key=lambda item: (-item[1], item[0]))
    parts = []
    for pair, n in ordered:
        local, _sep, oracle = pair.partition(PAIR_SEP)
        parts.append(f"local {local} against Oracle {oracle}: {n}")
    return ", ".join(parts)


def _agreement_low_over_window(
    new: SnapshotMetrics, history: list[TrendPoint]
) -> AlarmReason | None:
    """VERDICT agreement across a WINDOW of nights is below :data:`AGREEMENT_FLOOR`.

    **What it counts.** Real alerts only, and only those where the model and
    the Oracle each stated a verdict. A run counts as an agreement when the two
    verdicts are the same class (:func:`verdict_class`): ``true_positive``
    against ``true_positive``, ``false_positive`` against ``false_positive``,
    or two unsettled verdicts. ``needs_more_info`` against a settled verdict is
    a disagreement in either direction. ``inconclusive`` is the same class as
    ``needs_more_info``. A planted run is never in the pool: the nightly does
    not send it to the Oracle, and :func:`compute_snapshot_metrics` counts the
    real rows alone.

    **What it does not read.** ``agreement_rate`` and the yes, partial and no
    counts behind it. Those grade the confidence and the reasoning with the
    verdict, and a ``partial`` there is most often a correct verdict under a
    report the Oracle would have written better.

    **A window, never one batch.** One batch of five grades has a noise band of
    0.20 to 0.25, so one bad night proves nothing. The window is tonight and the
    newest ``MEDIAN_WINDOW - 1`` points before it, the same "what did last week
    look like" reach the median rules use. Its counted nights are pooled, and it
    needs at least :data:`MIN_HISTORY` of them. A night counts when it compared
    at least one verdict.

    **The same false-alarm budget.** The pooled count is tested with the exact
    binomial tail against the floor, at :data:`ALARM_P`: it fires only when a
    true rate AT the floor would produce a count this low 2% of the time or
    less. At 35 compared verdicts that is 10 agreements or fewer.

    **A fixed floor.** The rule reads no baseline, so a long run of bad nights
    cannot teach it to accept them.

    **Tonight need not be graded.** A night with nothing compared adds no count
    and removes none. If the rule needed a grade from tonight, every night lost
    to the Oracle quota would read as a recovery and the next graded night would
    raise the same alarm again as news.

    The message states the disagreement pairs with their counts, because the
    pairs are what an operator acts on. Graded mode only.
    """
    if new.mode != "graded":
        return None
    window: list[tuple[int | None, int | None, dict[str, int] | None]] = [
        (new.verdict_agree, new.verdict_compared, new.verdict_pairs),
        *(
            (p.verdict_agree, p.verdict_compared, p.verdict_pairs)
            for p in history[: MEDIAN_WINDOW - 1]
        ),
    ]
    counted = [(agree, n, pairs) for agree, n, pairs in window if agree is not None and n]
    if len(counted) < MIN_HISTORY:
        return None
    n_agree = sum(agree for agree, _n, _pairs in counted)
    n_compared = sum(n for _agree, n, _pairs in counted)
    tail = _binomial_tail_at_most(n_agree, n_compared, AGREEMENT_FLOOR)
    if tail > ALARM_P:
        return None

    pooled: dict[str, int] = {}
    for _agree, _n, pairs in counted:
        for pair, n in (pairs or {}).items():
            pooled[pair] = pooled.get(pair, 0) + int(n)
    message = (
        f"Verdict agreement is low across the last {len(counted)} graded nights. "
        f"The Oracle reached the verdict of the model for {n_agree} of {n_compared} "
        f"real alerts, a rate of {n_agree / n_compared:.2f}. "
        f"The floor is {AGREEMENT_FLOOR:.2f}. "
        f"A rate at the floor gives a count this low {_tail_share(tail)} of the time"
    )
    if pooled:
        message += f". The disagreements: {_pairs_text(pooled)}"
    return AlarmReason(CODE_AGREEMENT_LOW, message + _what_this_cannot_tell_you(new))


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
    :data:`MIN_HISTORY` every rule that needs a baseline is skipped — a young
    install must not page anyone off two nights of data.

    **This function answers "is this point bad", never "should anyone be told".**
    It re-decides from scratch every run and has no memory, so a condition that
    PERSISTS is re-reported every night it persists — correctly: the row is a
    measurement, and a measurement of a still-broken pipeline is still bad. The
    caller (:func:`soc_ai.eval.nightly._record_trend_point`) is what turns that
    into notifications, and it fires only when a condition appears that the
    previous point did not hold (:func:`alarm_conditions`) — the transition
    into a condition, not each re-observation of it. Do not push suppression
    down here: the trend would then record "clean" for nights that were not.

    Corollary, so nobody "fixes" it later: the median fallback below can fire on
    consecutive nights while an install crosses over from pre-0026 history
    (the counts baseline needs :data:`MIN_HISTORY` counted rows, which arrives
    within three nightlies of the upgrade). That needs no special case — the
    transition gate makes a repeated same-code night quiet anyway, and a
    window-shaped exception would be dead code by the time it was reviewed.

    Five rules. The first needs no history and runs on a new install too: a
    planted true positive has ground truth, so one miss is a miss without a
    baseline. The other four wait for :data:`MIN_HISTORY` points.

    * **Synthetic miss** — a planted true positive that the run did not call a
      positive. See :func:`_synth_miss`.
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
    * **Low verdict agreement** — the Oracle reaches the model's verdict class
      for too few real alerts across a window of nights
      (:data:`AGREEMENT_FLOOR`). See :func:`_agreement_low_over_window`. It
      does not read ``agreement_rate``. The rule above does, and that rate also
      falls for a correct verdict with a loose report.
    * **Error-rate ceiling** — ``new.error_rate`` > 0.3, absolute. History
      independent: a third of the nightly erroring is sick, full stop. A run
      whose grade request failed is not an error and is not counted here.
    * **Fallback jump** — ``new.fallback_rate`` more than 0.3 above the
      trailing median. The silent-engine-swap tripwire: the pipeline still
      "works" but verdicts are fabricated fallbacks.
    """
    reasons: list[AlarmReason] = []

    # First in the list on purpose: the bell and the webhook lead with the
    # first reason, and a missed known positive is the one to lead with.
    miss = _synth_miss(new)
    if miss is not None:
        reasons.append(miss)

    if len(history) < MIN_HISTORY:
        return reasons

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

    low = _agreement_low_over_window(new, history)
    if low is not None:
        reasons.append(low)

    if new.error_rate > ERROR_RATE_CEILING:
        message = f"error_rate {new.error_rate:.2f} exceeds the {ERROR_RATE_CEILING:.2f} ceiling"
        if new.error_classes:
            # The class is the first thing the reader needs: a gateway outage
            # and a token limit are two different repairs.
            message += (
                f". {new.n_error} of {new.n_ok + new.n_error} runs ended with no result: "
                f"{error_classes_text(new.error_classes)}"
            )
        reasons.append(AlarmReason(CODE_ERROR_CEILING, message))

    hist_fallback = [
        p.fallback_rate for p in history[:MEDIAN_WINDOW] if p.fallback_rate is not None
    ]
    if new.fallback_rate is not None and hist_fallback:
        med_fb = _median(hist_fallback)
        if new.fallback_rate - med_fb > FALLBACK_JUMP + _FLOAT_SLOP:
            reasons.append(
                AlarmReason(
                    CODE_FALLBACK_JUMP,
                    f"fallback_rate {new.fallback_rate:.2f} jumped more than "
                    f"{FALLBACK_JUMP:.2f} above the trailing median {med_fb:.2f}",
                )
            )

    return reasons


__all__ = [
    "AGREEMENT_FLOOR",
    "ALARM_KEY_SEP",
    "ALARM_P",
    "BASELINE_WINDOW",
    "CODE_AGREEMENT_DROP",
    "CODE_AGREEMENT_LOW",
    "CODE_ERROR_CEILING",
    "CODE_FALLBACK_JUMP",
    "CODE_SYNTH_MISS",
    "ERROR_RATE_CEILING",
    "FALLBACK_JUMP",
    "MEDIAN_WINDOW",
    "MIN_HISTORY",
    "NOT_RUN_ERROR",
    "PAIR_SEP",
    "SYNTH_CAUGHT",
    "SYNTH_MISSED",
    "SYNTH_NOT_MEASURED",
    "AlarmReason",
    "ServedModel",
    "SnapshotMetrics",
    "SynthOutcome",
    "TrendPoint",
    "alarm_codes_from_key",
    "alarm_conditions",
    "alarm_key_for",
    "classify_run_error",
    "compute_snapshot_metrics",
    "detect_regression",
    "ineligible_text",
    "not_measured_text",
    "run_errors_text",
    "run_outcome",
    "snapshot_detail",
    "synth_text",
    "verdict_class",
]
