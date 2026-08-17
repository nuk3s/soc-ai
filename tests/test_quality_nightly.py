"""Tests for the nightly quality micro-eval (I4).

Three layers, each stubbed at its natural boundary:

- **Pure analytics** (:mod:`soc_ai.eval.quality`): snapshot-metric reduction
  and the regression detector — plain values in, reasons out, no I/O.
- **Notification plumbing** (:mod:`soc_ai.notify`): the ``quality_regression``
  event builder + a fire through the mocked webhook transport (the same
  doubles as tests/test_notify.py — httpx is NEVER really called).
- **CLI wiring** (``soc-ai eval-nightly``): the batch machinery is MOCKED
  (a stub ``run_batch`` writes a canned ``index.jsonl``; no investigation,
  no oracle, no ES) and the tests assert what the CLI persists: the
  snapshot row, the mode/grade wiring, the alarm hand-off, the exit codes,
  and the suggested cron line.

The CLI tests are deliberately SYNC functions: ``_eval_nightly`` owns its own
``asyncio.run`` and would explode inside an already-running loop.
"""

from __future__ import annotations

import asyncio
import json
import os
from argparse import Namespace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr
from soc_ai import cli, notify
from soc_ai.config import Settings
from soc_ai.eval.batch import BatchSummary
from soc_ai.eval.nightly import resolve_out_dir, run_eval_nightly
from soc_ai.eval.quality import (
    AlarmReason,
    SnapshotMetrics,
    TrendPoint,
    alarm_codes_from_key,
    alarm_key_for,
    compute_snapshot_metrics,
    detect_regression,
)
from soc_ai.eval.report import aggregate
from soc_ai.store import quality as quality_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

# --------------------------------------------------------------------
# Shared builders
# --------------------------------------------------------------------


def _settings(**overrides: Any) -> Settings:
    kwargs: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "litellm_api_key": SecretStr("test-key"),
        "litellm_verify_ssl": False,
        "api_auth_required": False,
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


def _row(
    alert_id: str,
    *,
    verdict: str = "false_positive",
    agreement: str = "yes",
    is_fallback: bool = False,
    error: str | None = None,
    investigation_ms: int = 60_000,
) -> dict[str, Any]:
    """One canned index.jsonl row in the IndexRow dict shape."""
    return {
        "alert_id": alert_id,
        "bundle_path": None if error else f"evals/x/{alert_id}",
        "verdict": None if error else verdict,
        "confidence": None if error else 0.8,
        "agreement": None if error else agreement,
        "retask_count": 0,
        "investigation_ms": None if error else investigation_ms,
        "claude_ms": None,
        "input_tokens": None,
        "output_tokens": None,
        "cache_read_tokens": None,
        "error": error,
        "citations": [],
        "is_fallback": is_fallback,
        "is_synth": False,
        "synth_scenario_id": None,
    }


def _metrics(**overrides: Any) -> SnapshotMetrics:
    base: dict[str, Any] = {
        "mode": "graded",
        "n_ok": 5,
        "n_error": 0,
        "agreement_rate": 0.8,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {"false_positive": 5},
        "latency_p50_ms": 60_000,
    }
    base.update(overrides)
    return SnapshotMetrics(**base)


def _hist(
    n: int, *, agreement: float | None = 0.8, fallback: float | None = 0.0
) -> list[TrendPoint]:
    """LEGACY trailing points: a rate and nothing else.

    Rows written before migration 0026 carry no yes/classified counts, which is
    exactly what these stand for — every test built on ``_hist`` documents the
    median fallback the detector keeps for pre-0026 history.
    """
    return [TrendPoint(agreement_rate=agreement, fallback_rate=fallback) for _ in range(n)]


def _graded(rate: float, *, n: int = 5, fallback: float | None = 0.0) -> TrendPoint:
    """One POST-0026 trailing point: the rate plus the counts behind it."""
    return TrendPoint(
        agreement_rate=rate,
        fallback_rate=fallback,
        n_yes=round(rate * n),
        n_classified=n,
    )


def _point(rate: float, *, n: int = 5, **overrides: Any) -> SnapshotMetrics:
    """A new graded point that carries its counts (the post-0026 write path)."""
    return _metrics(
        agreement_rate=rate,
        n_ok=n,
        n_yes=round(rate * n),
        n_classified=n,
        **overrides,
    )


# The real prod graded series (25 rows, 24 graded) that produced the false
# alarm this fixture exists to kill: 14× 1.00, 8× 0.80, one 0.40 (row id 15)
# and one 0.60 (row id 27, the newest — the alarm on the dashboard). Pooled,
# that is 107 agreements of 120 classified critiques = 0.892.
#
# The interleaving of the 0.80 nights is NOT recoverable from prod (the batch
# bundles were deleted by a container recreate — see F3), so this ordering
# pins what the stored rows DO prove: the multiset above, the 0.40 mid-series,
# the 0.60 last, and a trailing-7 median of 1.00 at that last point (the stored
# alarm text names it). Under the old rule it reproduces the stored `alarmed`
# column exactly — 2 alarms — which is what makes it a regression fixture.
PROD_GRADED_SERIES: tuple[float, ...] = (
    1.00, 1.00, 1.00, 0.80, 1.00, 0.80, 1.00, 0.80,
    1.00, 1.00, 0.80, 1.00, 0.40, 1.00, 0.80, 1.00,
    1.00, 0.80, 1.00, 0.80, 1.00, 1.00, 0.80, 0.60,
)  # fmt: skip


def _replay(series: tuple[float, ...], *, counts: bool) -> list[int]:
    """Replay the detector over *series* oldest→newest; return firing indexes.

    ``counts=False`` builds pre-0026 history (rates only) — the shape that
    reproduces what prod actually stored.
    """
    fired: list[int] = []
    for i, rate in enumerate(series):
        # Newest-first, the order the store's recent_snapshots returns.
        history = [
            (_graded(r) if counts else TrendPoint(agreement_rate=r, fallback_rate=0.0))
            for r in reversed(series[:i])
        ]
        new = _point(rate) if counts else _metrics(agreement_rate=rate, n_ok=5)
        if any("agreement_rate" in r for r in detect_regression(new, history, alarm_drop=0.15)):
            fired.append(i)
    return fired


# --------------------------------------------------------------------
# compute_snapshot_metrics
# --------------------------------------------------------------------


def test_metrics_graded_carries_agreement_and_p50() -> None:
    rows = [
        _row("a", agreement="yes"),
        _row("b", agreement="yes", investigation_ms=120_000),
        _row("c", agreement="no"),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    assert m.mode == "graded"
    assert m.n_ok == 3 and m.n_error == 0
    assert m.agreement_rate == pytest.approx(2 / 3)
    assert m.fallback_rate == 0.0
    assert m.error_rate == 0.0
    assert m.latency_p50_ms == 60_000  # median of 60k/120k/60k
    assert m.verdict_counts == {"false_positive": 3}


def test_metrics_carry_the_grade_counts_behind_the_rate() -> None:
    """The rate alone can't be tested for significance and can't be explained.
    ``partial`` is the sharp edge: it sits in agreement_rate's DENOMINATOR but
    not its numerator, so "right verdict, thin reasoning" costs a full 0.2 on
    an n=5 batch exactly like a flat disagreement — the counts are what let the
    card say "3 agree, 1 partial, 1 no" instead of a bare 0.60."""
    rows = [
        _row("a", agreement="yes"),
        _row("b", agreement="yes"),
        _row("c", agreement="yes"),
        _row("d", agreement="partial"),
        _row("e", agreement="no"),
        _row("f", agreement="unknown"),  # never enters the rate at all
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    assert (m.n_yes, m.n_partial, m.n_no) == (3, 1, 1)
    assert m.n_classified == 5  # unknown excluded
    assert m.agreement_rate == pytest.approx(0.6)
    # The counts must reconcile with the headline the frontend already reads.
    assert m.n_yes / m.n_classified == pytest.approx(m.agreement_rate)


def test_metrics_local_mode_reports_no_grade_counts() -> None:
    """No oracle ⇒ no critiques ⇒ zero classified, matching the NULL rate."""
    rows = [_row("a", agreement="yes")]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")
    assert m.n_classified == 0
    assert (m.n_yes, m.n_partial, m.n_no) == (0, 0, 0)


def test_metrics_local_forces_agreement_to_none() -> None:
    """Even if the aggregator computed an agreement number, a local point must
    not carry one — otherwise it would masquerade as graded on the trend."""
    rows = [_row("a", agreement="yes")]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")
    assert m.agreement_rate is None


def test_metrics_fallback_and_error_rates() -> None:
    rows = [
        _row("a", is_fallback=True, verdict="needs_more_info"),
        _row("b"),
        _row("c", error="timeout after 60s"),
        _row("d", error="boom"),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")
    assert m.n_ok == 2 and m.n_error == 2
    assert m.fallback_rate == pytest.approx(0.5)  # 1 of 2 OK rows
    assert m.error_rate == pytest.approx(0.5)  # 2 of 4 attempted


def test_metrics_no_ok_rows_yields_null_fallback() -> None:
    """No successful run → no fallback denominator → NULL, never a fake 0."""
    rows = [_row("a", error="boom")]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")
    assert m.fallback_rate is None
    assert m.error_rate == 1.0
    assert m.latency_p50_ms is None


def test_metrics_tolerates_legacy_rows_without_is_fallback_key() -> None:
    """Rows written before the is_fallback flag simply count as non-fallback."""
    legacy = _row("a")
    del legacy["is_fallback"]
    m = compute_snapshot_metrics([legacy], aggregate([legacy]), mode="local")
    assert m.fallback_rate == 0.0


# --------------------------------------------------------------------
# detect_regression
# --------------------------------------------------------------------


def test_detector_skips_below_min_history() -> None:
    """<3 same-mode points: even a catastrophic new point stays silent — a
    young install must not page anyone off a median of two nights."""
    bad = _metrics(agreement_rate=0.0, error_rate=1.0, fallback_rate=1.0)
    assert detect_regression(bad, _hist(2), alarm_drop=0.15) == []


def test_detector_agreement_drop_fires_and_names_the_numbers() -> None:
    new = _metrics(agreement_rate=0.4)
    reasons = detect_regression(new, _hist(7, agreement=0.8), alarm_drop=0.15)
    assert len(reasons) == 1
    assert "agreement_rate 0.40" in reasons[0]
    assert "0.80" in reasons[0]  # the trailing median is in the message


def test_detector_agreement_drop_single_flip_stays_silent() -> None:
    """At the default n_ok=5, one flipped verdict moves agreement_rate by
    exactly 1/5 = 0.2 against a stable 0.8 median — that's a single flip,
    not a regression, and must never page anyone on its own."""
    new = _metrics(agreement_rate=0.6, n_ok=5)
    assert detect_regression(new, _hist(7, agreement=0.8), alarm_drop=0.15) == []


def test_detector_agreement_drop_two_flip_still_fires() -> None:
    """Two flipped verdicts at n_ok=5 is a real 0.4 drop — the self-scaling
    floor (1/n_ok = 0.2) must not swallow a genuine regression."""
    new = _metrics(agreement_rate=0.4, n_ok=5)
    reasons = detect_regression(new, _hist(7, agreement=0.8), alarm_drop=0.15)
    assert any("agreement_rate" in r for r in reasons)


def test_detector_agreement_drop_uses_median_not_mean() -> None:
    """One euphoric outlier night must not drag the baseline: median of
    [0.6, 0.6, 0.6, 1.0] is 0.6 — a new 0.5 is only a 0.1 drop, no alarm."""
    history = _hist(3, agreement=0.6) + _hist(1, agreement=1.0)
    new = _metrics(agreement_rate=0.5)
    assert detect_regression(new, history, alarm_drop=0.15) == []


def test_detector_stable_point_is_silent() -> None:
    new = _metrics(agreement_rate=0.75)
    assert detect_regression(new, _hist(7, agreement=0.8), alarm_drop=0.15) == []


def test_detector_error_rate_ceiling_is_absolute() -> None:
    """error_rate > 0.3 alarms regardless of what history looked like."""
    new = _metrics(error_rate=0.4)
    reasons = detect_regression(new, _hist(3), alarm_drop=0.15)
    assert any("error_rate" in r for r in reasons)


def test_detector_fallback_jump_over_median() -> None:
    new = _metrics(fallback_rate=0.5)
    reasons = detect_regression(new, _hist(5, fallback=0.1), alarm_drop=0.15)
    assert any("fallback_rate" in r for r in reasons)
    # A jump comfortably UNDER the 0.3 threshold stays silent. (Tested inside
    # the boundary, not on it — 0.4-0.1 lands on binary-float 0.3000…04 and
    # would flake an exact-boundary assertion.)
    below = _metrics(fallback_rate=0.35)
    assert detect_regression(below, _hist(5, fallback=0.1), alarm_drop=0.15) == []


def test_detector_local_mode_skips_agreement_but_keeps_fallback() -> None:
    """A local point (agreement None) can never trip the agreement rule, but
    the fallback tripwire — the engine-swap symptom — still works."""
    new = _metrics(mode="local", agreement_rate=None, fallback_rate=0.9)
    reasons = detect_regression(new, _hist(4, agreement=None, fallback=0.0), alarm_drop=0.15)
    assert len(reasons) == 1
    assert "fallback_rate" in reasons[0]


def test_detector_history_without_agreement_skips_agreement_rule() -> None:
    """Graded new point but no history point carries an agreement rate (e.g.
    the oracle classified nothing for a week) → no median to compare, skip."""
    new = _metrics(agreement_rate=0.1)
    assert detect_regression(new, _hist(5, agreement=None), alarm_drop=0.15) == []


# --------------------------------------------------------------------
# detect_regression — the counts-driven agreement test (F1, 2026-08-07)
# --------------------------------------------------------------------


def _prod_history() -> list[TrendPoint]:
    """The 24 graded prod points as post-0026 trailing history (107/120)."""
    return [_graded(r) for r in reversed(PROD_GRADED_SERIES)]


def test_pooled_baseline_is_the_prod_series_rate() -> None:
    """Guard the fixture itself: it must pool to the 0.892 the diagnosis used."""
    hist = _prod_history()
    n_yes = sum(p.n_yes or 0 for p in hist)
    n_cls = sum(p.n_classified or 0 for p in hist)
    assert (n_yes, n_cls) == (107, 120)
    assert n_yes / n_cls == pytest.approx(0.892, abs=0.001)


def test_counts_rule_does_not_fire_on_todays_false_alarm() -> None:
    """3 of 5 grades agreed against a 0.892 baseline is P≈0.09 — one night in
    eleven, i.e. INSIDE the detector's own sampling noise. This is the exact
    point (prod row id 27) that lit the dashboard's regression alarm under the
    median-of-rates rule, and it must stay silent."""
    new = _point(0.60)
    reasons = detect_regression(new, _prod_history(), alarm_drop=0.15)
    assert [r for r in reasons if "agreement_rate" in r] == []


def test_counts_rule_still_fires_on_a_real_drop() -> None:
    """2 of 5 against the same baseline is P≈0.011 — outside the noise, and the
    one graded night in prod's history (row id 15) that deserved a look."""
    new = _point(0.40)
    reasons = detect_regression(new, _prod_history(), alarm_drop=0.15)
    agreement = [r for r in reasons if "agreement_rate" in r]
    assert len(agreement) == 1
    # The message must carry the counts and the baseline, not just two rates —
    # an operator adjudicating an alarm needs the denominator.
    assert "agreement_rate 0.40" in agreement[0]
    assert "2/5" in agreement[0]
    assert "107/120" in agreement[0]


def test_counts_rule_ignores_a_single_flipped_grade() -> None:
    """4 of 5 vs a 0.892 baseline: P≈0.46. Nowhere near a regression."""
    assert detect_regression(_point(0.80), _prod_history(), alarm_drop=0.15) == []


def test_counts_rule_replays_the_prod_series_with_one_alarm() -> None:
    """The whole point, on the real data: the old rule fired twice over prod's
    24 graded nights (index 12 = the 0.40, index 23 = the 0.60 false alarm);
    the counts rule keeps the first and drops the second."""
    assert _replay(PROD_GRADED_SERIES, counts=False) == [12, 23]
    assert _replay(PROD_GRADED_SERIES, counts=True) == [12]


def test_counts_rule_survives_a_flawless_month() -> None:
    """The degenerate case the pooled baseline must not break on: 30 perfect
    nights pool to p=1.0, under which ANY miss is impossible and the very next
    flipped grade would page. Smoothing is what keeps the single-flip
    invariant (2026-07-24 dogfood fix) alive without the old floor."""
    perfect = [_graded(1.0) for _ in range(30)]
    assert detect_regression(_point(0.80), perfect, alarm_drop=0.15) == []
    # Two flips out of five against a flawless month IS a signal.
    assert any(
        "agreement_rate" in r for r in detect_regression(_point(0.60), perfect, alarm_drop=0.15)
    )


def test_counts_rule_pools_beyond_the_median_window() -> None:
    """The baseline pools up to 30 points, not 7, on purpose: 7 lucky nights
    (35/35) make a p≈1 baseline out of a rate that is really 0.89, and the next
    ordinary night pages. With the wider window prod's 0.60 stays silent —
    with only the 7 it would not."""
    lucky_week = [_graded(1.0) for _ in range(7)]
    assert any(
        "agreement_rate" in r for r in detect_regression(_point(0.60), lucky_week, alarm_drop=0.15)
    )
    assert detect_regression(_point(0.60), _prod_history(), alarm_drop=0.15) == []


def test_counts_rule_keeps_the_alarm_drop_knob_live() -> None:
    """The removed 1/denom floor pinned quality_alarm_drop at 0.20 for every
    n=5 night, so every setting <= 0.20 did nothing. With counts driving
    significance, the knob is what decides whether a statistically-real but
    small drop is worth waking someone for."""
    history = [_graded(0.95, n=100) for _ in range(10)]  # 950/1000, very tight
    # Statistically overwhelming (P ~ 0) but only a 7-point drop: under the
    # default 0.15 knob that is not worth an alarm.
    assert detect_regression(_point(0.88, n=100), history, alarm_drop=0.15) == []
    # Same shape, a 20-point drop: fires at 0.15…
    assert any(
        "agreement_rate" in r
        for r in detect_regression(_point(0.75, n=100), history, alarm_drop=0.15)
    )
    # …and an operator who only cares about 25-point drops gets silence.
    assert detect_regression(_point(0.75, n=100), history, alarm_drop=0.25) == []


def test_legacy_history_without_counts_falls_back_to_the_median_rule() -> None:
    """Pre-0026 rows carry no counts. The detector must NOT go quiet for the
    days it takes new history to accumulate — it falls back to the exact
    median rule (self-scaling floor included) those rows were written under."""
    legacy = _hist(7, agreement=1.0)
    # Two flips at n=5 — the old rule's alarm — still fires.
    assert any(
        "agreement_rate" in r for r in detect_regression(_point(0.60), legacy, alarm_drop=0.15)
    )
    # One flip still doesn't: the floor is intact on this path.
    assert detect_regression(_point(0.80), legacy, alarm_drop=0.15) == []


def test_new_point_without_counts_falls_back_to_the_median_rule() -> None:
    """The mirror case: counted history but a caller that passes no counts
    (an older SnapshotMetrics). Rate-vs-rate is all that's available."""
    new = _metrics(agreement_rate=0.60, n_ok=5)  # no n_classified
    assert any(
        "agreement_rate" in r
        for r in detect_regression(new, [_graded(1.0) for _ in range(7)], alarm_drop=0.15)
    )


def test_counts_rule_needs_min_history_counted_points() -> None:
    """Two counted rows do not make a baseline: below MIN_HISTORY counted
    points the detector uses the median rule over everything it has, rather
    than pooling 10 grades into a confident-looking p."""
    history = [_graded(1.0), _graded(1.0), *_hist(5, agreement=1.0)]
    # Pooled, 10/10 would leave a 3-of-5 night unremarkable; the median rule
    # (which is what must run here) fires on it.
    assert any(
        "agreement_rate" in r for r in detect_regression(_point(0.60), history, alarm_drop=0.15)
    )


def test_counts_rule_skips_history_rows_with_no_classified_critiques() -> None:
    """A graded night where the oracle classified nothing (0/0) carries no
    evidence: it must not count toward the pooled baseline's history quorum,
    or three empty nights plus two real ones would look like a baseline."""
    empty = [
        TrendPoint(agreement_rate=None, fallback_rate=0.0, n_yes=0, n_classified=0)
        for _ in range(5)
    ]
    history = [_graded(1.0), _graded(1.0), *empty]
    # Only 2 informative points → median fallback, which fires on a 3-of-5
    # night. Had the empty rows armed the pooled rule (10/10), it would not.
    assert any(
        "agreement_rate" in r for r in detect_regression(_point(0.60), history, alarm_drop=0.15)
    )


def test_median_crossover_self_resolves_once_counted_rows_exist() -> None:
    """Pins the promise in :func:`detect_regression`'s docstring, so nobody
    "fixes" the crossover with a special case: while an install still has only
    pre-0026 history the median rule is the only rule available and CAN fire on
    consecutive nights, but three counted rows — three nightlies — arm the
    pooled test, which knows what this install actually looks like."""
    legacy = _hist(7, agreement=1.0)
    assert any(
        r.code == "agreement_drop" for r in detect_regression(_point(0.60), legacy, alarm_drop=0.15)
    )
    counted = [_graded(0.6) for _ in range(3)]
    assert detect_regression(_point(0.60), [*counted, *legacy], alarm_drop=0.15) == []


def test_detector_can_stack_multiple_reasons() -> None:
    new = _metrics(agreement_rate=0.2, error_rate=0.5, fallback_rate=0.8)
    reasons = detect_regression(new, _hist(7, agreement=0.9, fallback=0.0), alarm_drop=0.15)
    assert len(reasons) == 3


# --------------------------------------------------------------------
# Alarm IDENTITY: codes + key (F1 follow-up, 2026-08-07)
# --------------------------------------------------------------------


def test_reasons_carry_a_stable_code_beside_the_message() -> None:
    """A reason string cannot identify a CONDITION: every one of them embeds
    live numbers ("0.80 vs median 1.00"), so the same condition re-observed
    tomorrow is a different string and no amount of string comparison can tell
    "still bad" from "newly bad". The code is the identity the transition gate
    keys on; the message stays byte-identical because it is what the row, the
    audit payload and the webhook body already carry."""
    new = _metrics(agreement_rate=0.2, error_rate=0.5, fallback_rate=0.8)
    reasons = detect_regression(new, _hist(7, agreement=0.9, fallback=0.0), alarm_drop=0.15)
    assert {r.code for r in reasons} == {"agreement_drop", "error_ceiling", "fallback_jump"}
    by_code = {r.code: r for r in reasons}
    # Byte-compatible with what the pre-0027 detector returned: these ARE
    # strings, so every existing consumer keeps working unchanged.
    assert by_code["error_ceiling"] == "error_rate 0.50 exceeds the 0.30 ceiling"
    assert isinstance(by_code["agreement_drop"], str)
    assert by_code["fallback_jump"].message.startswith("fallback_rate 0.80 jumped")


def test_agreement_code_is_the_same_on_both_agreement_paths() -> None:
    """The counts test and the pre-0026 median fallback are two ways to observe
    ONE condition. If they carried different codes, an install crossing over
    from legacy history would fire a fresh alarm for nothing."""
    counted = detect_regression(_point(0.40), _prod_history(), alarm_drop=0.15)
    legacy = detect_regression(_point(0.40), _hist(7, agreement=1.0), alarm_drop=0.15)
    assert [r.code for r in counted] == ["agreement_drop"]
    assert [r.code for r in legacy] == ["agreement_drop"]


def test_alarm_key_is_sorted_codes_and_none_when_clean() -> None:
    """The key must not depend on the order the detector happened to append its
    reasons in — an error+agreement night and an agreement+error night are the
    same condition and must not alarm twice."""
    assert alarm_key_for([]) is None
    a = AlarmReason("error_ceiling", "x")
    b = AlarmReason("agreement_drop", "y")
    assert alarm_key_for([a, b]) == alarm_key_for([b, a]) == "agreement_drop+error_ceiling"
    assert alarm_codes_from_key("agreement_drop+error_ceiling") == [
        "agreement_drop",
        "error_ceiling",
    ]
    # A pre-0027 row has no key at all — "unknown", which is not "clean".
    assert alarm_codes_from_key(None) == []


# --------------------------------------------------------------------
# Notification emission (the test_notify.py doubles: httpx never called)
# --------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_notify_dedup() -> Any:
    notify._dedup_seen.clear()
    yield
    notify._dedup_seen.clear()


def _notify_settings(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "notify_enabled": True,
        "notify_webhook_url": SecretStr("https://hooks.example.com/abc"),
        "notify_format": "json",
        "notify_verify_ssl": True,
        "notify_on_quality_regression": True,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_event_builder_respects_trigger_toggle() -> None:
    s = _notify_settings(notify_on_quality_regression=False)
    assert notify.event_for_quality_regression(mode="graded", reasons=["x"], settings=s) is None


def test_event_builder_requires_reasons() -> None:
    s = _notify_settings()
    assert notify.event_for_quality_regression(mode="graded", reasons=[], settings=s) is None


def test_event_builder_labels_the_measurement_mode() -> None:
    s = _notify_settings()
    ev = notify.event_for_quality_regression(mode="local", reasons=["fallback jumped"], settings=s)
    assert ev is not None
    assert ev.kind == "quality_regression"
    assert "locally measured" in ev.body
    assert "fallback jumped" in ev.body


async def test_quality_regression_fires_through_webhook() -> None:
    """End-to-end through fire(): the payload carries the new kind, and the
    per-trigger toggle + master switch gate it exactly like the other kinds."""
    s = _notify_settings()
    ev = notify.event_for_quality_regression(
        mode="graded", reasons=["agreement dropped"], settings=s
    )
    assert ev is not None
    with patch("soc_ai.notify._post_with_retries", AsyncMock(return_value=200)) as post:
        await notify.fire(ev, s)
    post.assert_awaited_once()
    _url, payload = post.await_args.args  # type: ignore[union-attr]
    assert payload["kind"] == "quality_regression"
    assert "agreement dropped" in payload["body"]


async def test_quality_regression_disabled_master_switch_no_egress() -> None:
    s = _notify_settings(notify_enabled=False)
    ev = notify.event_for_quality_regression(mode="graded", reasons=["x"], settings=s)
    assert ev is not None  # the builder is toggle-gated, not master-gated
    with patch("soc_ai.notify._post_with_retries", AsyncMock()) as post:
        await notify.fire(ev, s)
    post.assert_not_awaited()


# --------------------------------------------------------------------
# CLI wiring (batch machinery mocked — never a real eval)
# --------------------------------------------------------------------


class _FakeElastic:
    """Stands in for ElasticClient — the mocked run_batch never touches it."""

    def __init__(self, _settings: Settings) -> None:
        pass

    async def aclose(self) -> None:
        return None


def _stub_run_batch(
    rows: list[dict[str, Any]],
    *,
    aborted: str | None = None,
    captured: dict[str, Any] | None = None,
) -> Any:
    """A run_batch double: writes the canned index.jsonl, returns the summary."""

    async def _run(cfg: Any, **kw: Any) -> BatchSummary:
        if captured is not None:
            captured.update(kw)
            captured["cfg"] = cfg
        batch_dir = Path(cfg.out_dir) / "batch-test"
        batch_dir.mkdir(parents=True, exist_ok=True)
        with (batch_dir / "index.jsonl").open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        n_ok = sum(1 for r in rows if not r.get("error"))
        return BatchSummary(
            batch_dir=batch_dir,
            n_planned=len(rows),
            n_attempted=len(rows),
            n_ok=n_ok,
            n_error=len(rows) - n_ok,
            aborted_reason=aborted,
            elapsed_s=1,
        )

    return _run


def _args(tmp_path: Path, **overrides: Any) -> Namespace:
    base: dict[str, Any] = {
        "oql": None,
        "graded": False,
        "local": False,
        "out_dir": str(tmp_path / "evals"),
        "per_run_timeout_s": 60,
    }
    base.update(overrides)
    return Namespace(**base)


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    rows: list[dict[str, Any]],
    *,
    aborted: str | None = None,
) -> dict[str, Any]:
    """Standard CLI-test harness: settings, fake ES, stub batch, alarm recorder."""
    captured: dict[str, Any] = {"alarm": None}
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr("soc_ai.so_client.elastic.ElasticClient", _FakeElastic)
    monkeypatch.setattr(
        "soc_ai.eval.batch.run_batch",
        _stub_run_batch(rows, aborted=aborted, captured=captured),
    )

    async def _fake_alarm(_settings: Settings, **kw: Any) -> None:
        captured["alarm"] = kw

    monkeypatch.setattr(cli, "_fire_quality_alarm", _fake_alarm)
    return captured


def _read_snapshots(settings: Settings) -> list[Any]:
    async def _go() -> list[Any]:
        engine = make_engine(settings)
        try:
            await run_migrations(engine)
            async with make_sessionmaker(engine)() as db:
                return await quality_svc.recent_snapshots(db, limit=100)
        finally:
            await engine.dispose()

    return asyncio.run(_go())


def _seed_history(settings: Settings, *, mode: str, fallback_rates: list[float]) -> None:
    async def _go() -> None:
        engine = make_engine(settings)
        try:
            await run_migrations(engine)
            async with make_sessionmaker(engine)() as db:
                for fb in fallback_rates:
                    await quality_svc.insert_snapshot(
                        db,
                        mode=mode,
                        n_ok=5,
                        n_error=0,
                        agreement_rate=None if mode == "local" else 0.8,
                        fallback_rate=fb,
                        error_rate=0.0,
                        verdict_counts={},
                        latency_p50_ms=1000,
                        batch_dir=None,
                        alarmed=False,
                        alarm_reasons=None,
                    )
        finally:
            await engine.dispose()

    asyncio.run(_go())


def _seed_snapshots(settings: Settings, rows: list[dict[str, Any]]) -> None:
    """Write history rows straight to the store (one engine, one migration)."""

    async def _go() -> None:
        engine = make_engine(settings)
        try:
            await run_migrations(engine)
            async with make_sessionmaker(engine)() as db:
                for kw in rows:
                    await quality_svc.insert_snapshot(db, **kw)
        finally:
            await engine.dispose()

    asyncio.run(_go())


def _graded_row(
    rate: float, *, n: int = 5, counts: bool = True, **overrides: Any
) -> dict[str, Any]:
    """One graded history row. ``counts=False`` writes the pre-0026 shape."""
    row: dict[str, Any] = {
        "mode": "graded",
        "n_ok": n,
        "n_error": 0,
        "agreement_rate": rate,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {},
        "latency_p50_ms": 1000,
        "batch_dir": None,
        "alarmed": False,
        "alarm_reasons": None,
    }
    if counts:
        yes = round(rate * n)
        row.update(n_yes=yes, n_partial=0, n_no=n - yes, n_classified=n)
    row.update(overrides)
    return row


def _local_row(**overrides: Any) -> dict[str, Any]:
    """One local-mode history row: no oracle, so no agreement and no counts."""
    return _graded_row(1.0, counts=False, **{"mode": "local", "agreement_rate": None, **overrides})


def _seed_graded_history(
    settings: Settings, *, rates: list[float], n: int = 5, counts: bool = True
) -> None:
    """Seed graded history rows that CARRY their counts (post-0026 writes)."""
    _seed_snapshots(settings, [_graded_row(r, n=n, counts=counts) for r in rates])


def test_cli_local_run_writes_snapshot_and_suggests_cron(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Happy path, zero-egress default: oracle_enabled=False → local mode, the
    runner is wired grade=False, one snapshot lands, exit 0, cron line shown."""
    settings = _settings()  # oracle_enabled defaults False
    rows = [_row("a"), _row("b"), _row("c", is_fallback=True, verdict="needs_more_info")]
    captured = _wire(monkeypatch, settings, rows)

    rc = cli._eval_nightly(_args(tmp_path))

    assert rc == 0
    # grade=False is THE zero-egress wiring — the partial must carry it.
    assert captured["runner"].keywords == {"grade": False}
    # default OQL = the alerts-feed query
    assert captured["cfg"].oql == settings.webui_alerts_query
    assert captured["cfg"].concurrency == 1

    snaps = _read_snapshots(settings)
    assert len(snaps) == 1
    s = snaps[0]
    assert s.mode == "local"
    assert s.agreement_rate is None  # local mode never fakes agreement
    assert s.n_ok == 3 and s.n_error == 0
    assert s.fallback_rate == pytest.approx(1 / 3)
    assert s.alarmed is False
    assert s.batch_dir and s.batch_dir.endswith("batch-test")
    assert captured["alarm"] is None

    err = capsys.readouterr().err
    assert "eval-nightly" in err
    assert "17 2 * * *" in err  # the suggested cron line
    # the batch artifacts were aggregated (build_report ran, no oracle)
    assert (Path(s.batch_dir) / "aggregates.json").exists()


def test_cli_graded_mode_follows_oracle_enabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings(oracle_enabled=True)
    rows = [_row("a", agreement="yes"), _row("b", agreement="no")]
    captured = _wire(monkeypatch, settings, rows)

    rc = cli._eval_nightly(_args(tmp_path))

    assert rc == 0
    assert captured["runner"].keywords == {"grade": True}
    s = _read_snapshots(settings)[0]
    assert s.mode == "graded"
    assert s.agreement_rate == pytest.approx(0.5)


def test_cli_local_flag_overrides_oracle_enabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings(oracle_enabled=True)
    captured = _wire(monkeypatch, settings, [_row("a")])
    rc = cli._eval_nightly(_args(tmp_path, local=True))
    assert rc == 0
    assert captured["runner"].keywords == {"grade": False}
    assert _read_snapshots(settings)[0].mode == "local"


def test_cli_alarm_fires_with_enough_history(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """3 clean local nights on record, then a night where every verdict is a
    pipeline fallback → the jump rule trips, the snapshot records the alarm,
    and the alarm hand-off (audit + webhook) is invoked with the reasons."""
    settings = _settings()
    _seed_history(settings, mode="local", fallback_rates=[0.0, 0.0, 0.0])
    rows = [_row(a, is_fallback=True, verdict="needs_more_info") for a in ("a", "b", "c")]
    captured = _wire(monkeypatch, settings, rows)

    rc = cli._eval_nightly(_args(tmp_path))

    assert rc == 0  # an alarm is a finding, not a failure of the run itself
    snaps = _read_snapshots(settings)
    assert len(snaps) == 4
    latest = snaps[0]
    assert latest.alarmed is True
    assert latest.alarm_reasons and "fallback_rate" in latest.alarm_reasons[0]
    assert captured["alarm"] is not None
    assert captured["alarm"]["mode"] == "local"
    assert captured["alarm"]["reasons"] == latest.alarm_reasons


def test_cli_min_history_skips_alarm(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Same catastrophic night but only 2 history points → detector skips."""
    settings = _settings()
    _seed_history(settings, mode="local", fallback_rates=[0.0, 0.0])
    rows = [_row(a, is_fallback=True, verdict="needs_more_info") for a in ("a", "b", "c")]
    captured = _wire(monkeypatch, settings, rows)

    rc = cli._eval_nightly(_args(tmp_path))

    assert rc == 0
    assert _read_snapshots(settings)[0].alarmed is False
    assert captured["alarm"] is None


def test_cli_other_mode_history_does_not_feed_the_detector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Graded history must not arm a LOCAL run's detector — the modes are
    different instruments and never blend."""
    settings = _settings()
    _seed_history(settings, mode="graded", fallback_rates=[0.0, 0.0, 0.0])
    rows = [_row(a, is_fallback=True, verdict="needs_more_info") for a in ("a", "b", "c")]
    captured = _wire(monkeypatch, settings, rows)

    rc = cli._eval_nightly(_args(tmp_path))

    assert rc == 0
    latest = _read_snapshots(settings)[0]
    assert latest.mode == "local"
    assert latest.alarmed is False  # 0 same-mode history points < MIN_HISTORY
    assert captured["alarm"] is None


def test_cli_no_eligible_alerts_exits_2_without_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings()
    _wire(monkeypatch, settings, [])
    rc = cli._eval_nightly(_args(tmp_path))
    assert rc == 2
    assert _read_snapshots(settings) == []


def test_cli_aborted_batch_still_records_the_point(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failure-budget abort exits 4 but the snapshot IS written — a fully
    broken engine is exactly what the trend must record."""
    settings = _settings()
    rows = [_row(a, error="EngineDead: 503") for a in ("a", "b", "c")]
    _wire(monkeypatch, settings, rows, aborted="aborted: 3 consecutive failures")

    rc = cli._eval_nightly(_args(tmp_path))

    assert rc == 4
    s = _read_snapshots(settings)[0]
    assert s.n_error == 3 and s.n_ok == 0
    assert s.error_rate == 1.0
    assert s.fallback_rate is None  # no OK runs → no denominator, honest NULL


def test_cli_graded_run_persists_the_grade_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The counts the detector will test against must reach the row, not just
    the rate — a rate with no denominator cannot be re-tested later, which is
    how the trend ended up unable to tell noise from a regression."""
    settings = _settings(oracle_enabled=True)
    rows = [
        _row("a", agreement="yes"),
        _row("b", agreement="yes"),
        _row("c", agreement="partial"),
        _row("d", agreement="no"),
    ]
    _wire(monkeypatch, settings, rows)

    assert cli._eval_nightly(_args(tmp_path)) == 0

    s = _read_snapshots(settings)[0]
    assert (s.n_yes, s.n_partial, s.n_no, s.n_classified) == (2, 1, 1, 4)
    assert s.agreement_rate == pytest.approx(0.5)


def test_cli_alarm_uses_the_counts_of_the_seeded_history(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End-to-end on the shape that produced the false alarm: three perfect
    graded nights on record (with counts), then a 3-of-5 night. The pooled
    test says that is noise, so no row is flagged and nobody is paged."""
    settings = _settings(oracle_enabled=True)
    _seed_graded_history(settings, rates=[1.0, 1.0, 1.0])
    rows = [_row(a, agreement="yes") for a in ("a", "b", "c")] + [
        _row(a, agreement="no") for a in ("d", "e")
    ]
    captured = _wire(monkeypatch, settings, rows)

    assert cli._eval_nightly(_args(tmp_path)) == 0

    latest = _read_snapshots(settings)[0]
    assert latest.agreement_rate == pytest.approx(0.6)
    assert latest.alarmed is False
    assert captured["alarm"] is None


# --------------------------------------------------------------------
# The transition gate: alarm on entering a condition, not on re-observing it
# (prod rows 9/10/11, 2026-08-07)
# --------------------------------------------------------------------


class _Clock:
    """A frozen, test-advanced stand-in for ``store.auth.utcnow``.

    ``alarm_since`` is asserted exactly, and two nightlies inside one test would
    otherwise land microseconds apart — "carried forward" and "re-stamped" would
    then be indistinguishable from a timestamp alone.
    """

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now


# Prod rows 9/10/11 verbatim: agreement 0.80 against a trailing median of 1.00.
# Ten alerts, not the default five, because that is what the stored alarms imply
# — the median rule's 1/denom floor absorbs a 0.20 drop at n=5, so a night that
# DID alarm at 0.80 had more than five classified critiques (quality_nightly_n
# is capped at 10).
#
# Legacy (uncounted) history is the regime those rows were decided in, and the
# only one where a single condition can alarm on consecutive nights: three
# counted rows arm the pooled test, which then knows 0.80 is this install's
# normal. That is the crossover the detector's docstring refuses to special-case.
def _drop_night() -> list[dict[str, Any]]:
    return [_row(a, agreement="yes") for a in "abcdefgh"] + [_row(a, agreement="no") for a in "ij"]


def _clean_night() -> list[dict[str, Any]]:
    return [_row(a, agreement="yes") for a in "abcdefghij"]


def _error_night() -> list[dict[str, Any]]:
    """Prod row 26: pipeline health, not verdict quality — every run errored."""
    return [_row(a, error="EngineDead: 503") for a in "abcde"]


def _run_nights(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    tmp_path: Path,
    nights: list[list[dict[str, Any]]],
    *,
    clock: _Clock,
) -> list[dict[str, Any]]:
    """Run consecutive nightlies end-to-end against ONE real store.

    Returns the alarm HAND-OFFS that actually fired (audit + webhook), which is
    the thing the operator experiences — distinct from the alarmed rows, which
    are what was measured. A shared store is the only way to test a rule about
    what the previous row said.
    """
    handoffs: list[dict[str, Any]] = []
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr("soc_ai.so_client.elastic.ElasticClient", _FakeElastic)
    monkeypatch.setattr("soc_ai.store.auth.utcnow", clock)

    async def _fake_alarm(_settings: Settings, **kw: Any) -> None:
        handoffs.append(kw)

    monkeypatch.setattr(cli, "_fire_quality_alarm", _fake_alarm)
    for rows in nights:
        monkeypatch.setattr("soc_ai.eval.batch.run_batch", _stub_run_batch(rows))
        assert cli._eval_nightly(_args(tmp_path)) == 0
        clock.now += timedelta(days=1)
    return handoffs


def test_a_persisting_condition_fires_one_side_effect_not_one_per_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Prod rows 9, 10 and 11: ONE condition ("agreement 0.80 against a
    trailing median of 1.00"), three alarms in 27 hours.

    The detector has no memory and the caller fired on a bare ``if reasons``, so
    every run that re-observed the same condition paged again — and the
    operator's only exit was running another eval, which could re-alarm. Each
    row must still RECORD the alarm (the measurement is honest; the trend must
    not show a clean night that wasn't), but only the transition is news.
    """
    settings = _settings(oracle_enabled=True)
    _seed_graded_history(settings, rates=[1.0] * 7, counts=False)
    clock = _Clock(datetime(2026, 8, 6, 2, 17))

    handoffs = _run_nights(monkeypatch, settings, tmp_path, [_drop_night()] * 3, clock=clock)

    rows = _read_snapshots(settings)[:3]
    assert [r.alarmed for r in rows] == [True, True, True]
    assert {r.alarm_key for r in rows} == {"agreement_drop"}
    # One condition, one start date — the card renders "ongoing since 08-06".
    assert {r.alarm_since for r in rows} == {datetime(2026, 8, 6, 2, 17)}
    assert len(handoffs) == 1
    # Plain strings, not AlarmReason: the audit payload and the webhook body are
    # JSON wire surfaces and must not depend on the detector's return type.
    assert {type(r) for r in handoffs[0]["reasons"]} == {str}
    assert "agreement_rate 0.80" in handoffs[0]["reasons"][0]


def test_a_changed_condition_is_news_again(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """2026-08-07's rows 26 then 27: the pipeline erroring out, then a verdict
    drop. Different conditions, so both fire — the gate suppresses repetition,
    never a new failure mode. (This is also why the card needs the codes: "the
    eval runs are failing" is not a statement about verdict quality.)"""
    settings = _settings(oracle_enabled=True)
    _seed_graded_history(settings, rates=[1.0] * 7, counts=False)
    clock = _Clock(datetime(2026, 8, 6, 2, 17))

    handoffs = _run_nights(
        monkeypatch, settings, tmp_path, [_error_night(), _drop_night()], clock=clock
    )

    newest, previous = _read_snapshots(settings)[:2]
    assert [previous.alarm_key, newest.alarm_key] == ["error_ceiling", "agreement_drop"]
    assert len(handoffs) == 2
    # Re-stamped on the transition, never inherited from a different condition.
    assert previous.alarm_since == datetime(2026, 8, 6, 2, 17)
    assert newest.alarm_since == datetime(2026, 8, 7, 2, 17)


def test_a_clean_night_clears_the_condition_so_the_next_one_is_news(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Recovery must reset the gate: a clean row carries NULL key and NULL
    since, so the same condition returning a night later pages again instead of
    being mistaken for the one that already resolved."""
    settings = _settings(oracle_enabled=True)
    _seed_graded_history(settings, rates=[1.0] * 7, counts=False)
    clock = _Clock(datetime(2026, 8, 6, 2, 17))

    handoffs = _run_nights(
        monkeypatch,
        settings,
        tmp_path,
        [_drop_night(), _clean_night(), _drop_night()],
        clock=clock,
    )

    third, second, first = _read_snapshots(settings)[:3]
    assert second.alarmed is False
    assert (second.alarm_key, second.alarm_since) == (None, None)
    assert first.alarm_since == datetime(2026, 8, 6, 2, 17)
    assert third.alarm_since == datetime(2026, 8, 8, 2, 17)  # fresh, not the first's
    assert len(handoffs) == 2


def test_pre_0027_history_is_unknown_not_equal_and_still_fires(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The upgrade case: the newest row was written before 0027, so it is
    ``alarmed`` with a NULL key even though its condition looks like today's.
    NULL is UNKNOWN, not "same" — the gate must fire (a missed first page is
    the unrecoverable direction) and start the duration clock fresh, and it
    must not trip over the NULL on the way."""
    settings = _settings(oracle_enabled=True)
    _seed_graded_history(settings, rates=[1.0] * 6, counts=False)
    _seed_snapshots(
        settings,
        [
            _graded_row(
                0.8,
                counts=False,
                alarmed=True,
                alarm_reasons=["agreement_rate 0.80 is more than 0.15 below the median 1.00"],
            )
        ],
    )
    clock = _Clock(datetime(2026, 8, 6, 2, 17))

    handoffs = _run_nights(monkeypatch, settings, tmp_path, [_drop_night()], clock=clock)

    newest = _read_snapshots(settings)[0]
    assert newest.alarm_key == "agreement_drop"
    assert newest.alarm_since == datetime(2026, 8, 6, 2, 17)
    assert len(handoffs) == 1


def test_other_mode_history_cannot_suppress_an_alarm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The gate compares against the previous SAME-MODE row. A local night's
    alarm must not be silenced by a graded row carrying the same key — the two
    modes are different instruments, which is already how the detector reads
    history."""
    settings = _settings()  # local mode
    _seed_snapshots(
        settings,
        # The graded alarm is seeded LAST so it is the newest row in the table:
        # a gate that read "the previous snapshot" without the mode filter would
        # match its key and swallow tonight's local alarm.
        [_local_row(fallback_rate=0.0) for _ in range(3)]
        + [
            _graded_row(
                0.6,
                counts=False,
                alarmed=True,
                alarm_reasons=["fallback_rate 0.90 jumped more than 0.30 above the median 0.00"],
                alarm_key="fallback_jump",
                alarm_since=datetime(2026, 8, 1, 2, 17),
            )
        ],
    )
    clock = _Clock(datetime(2026, 8, 6, 2, 17))
    night = [_row(a, is_fallback=True, verdict="needs_more_info") for a in "abc"]

    handoffs = _run_nights(monkeypatch, settings, tmp_path, [night], clock=clock)

    newest = _read_snapshots(settings)[0]
    assert newest.mode == "local"
    assert newest.alarm_key == "fallback_jump"
    assert newest.alarm_since == datetime(2026, 8, 6, 2, 17)
    assert len(handoffs) == 1


# --------------------------------------------------------------------
# Bundle directory default (F3) — the artifacts an alarm is adjudicated from
# --------------------------------------------------------------------


def test_bundle_dir_defaults_beside_the_persisted_data_dir(tmp_path: Path) -> None:
    """A container install's data dir is an absolute path inside a mounted
    volume (/var/lib/soc-ai/data); the bundles belong on the same root, or a
    container recreate deletes the oracle critiques behind every alarm on the
    trend. Rooted at tmp_path here — the resolver CREATES the directory, and a
    test must not write outside its sandbox to prove that.
    """
    settings = _settings(soc_ai_data_dir=tmp_path / "var" / "lib" / "soc-ai" / "data")
    out_dir, note = resolve_out_dir(settings, None)
    assert out_dir == tmp_path / "var" / "lib" / "soc-ai" / "evals"
    assert out_dir.is_dir()  # created eagerly, so an unwritable mount is caught here
    assert note is None


def test_bundle_dir_stays_relative_for_a_plain_host_install() -> None:
    """A host/dev install keeps the historical ./evals — a relative data dir
    means there is no /var/lib root to be inside of."""
    settings = _settings(soc_ai_data_dir=Path("data"))
    out_dir, _note = resolve_out_dir(settings, None)
    assert out_dir == Path("evals")


def test_bundle_dir_explicit_argument_always_wins(tmp_path: Path) -> None:
    """--out-dir is the operator's override and is never second-guessed."""
    settings = _settings(soc_ai_data_dir=tmp_path / "var" / "data")
    out_dir, note = resolve_out_dir(settings, tmp_path / "custom")
    assert out_dir == tmp_path / "custom"
    assert not (tmp_path / "var" / "evals").exists()  # no dir created behind it
    assert note is None


@pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root bypasses the permission bits this simulates; CI runs as root, "
    "so the uid-independent twin below is what covers the fallback there",
)
def test_bundle_dir_falls_back_loudly_when_the_volume_is_unwritable(
    tmp_path: Path,
) -> None:
    """A volume mounted root-owned (old image, new compose file) must not kill
    the unattended run — but the operator has to be told the bundles are
    landing somewhere a recreate will delete.

    Simulates the real shape: the directory exists and is not writable by this
    user, which is the ``os.access`` branch."""
    unwritable = tmp_path / "ro"
    unwritable.mkdir(mode=0o500)
    settings = _settings(soc_ai_data_dir=unwritable / "data")
    out_dir, note = resolve_out_dir(settings, None)
    assert out_dir == Path("evals")
    assert note is not None
    assert str(unwritable / "evals") in note


def test_bundle_dir_falls_back_loudly_when_the_path_cannot_be_created(
    tmp_path: Path,
) -> None:
    """The same fallback via the ``OSError`` branch, provoked in a way no uid
    can bypass: the parent is a regular file, so ``mkdir`` raises
    ``NotADirectoryError`` for root and non-root alike.

    This twin exists because CI runs as root, where a chmod-based test silently
    stops testing anything — it passes locally and fails in CI, which is how it
    was found (2026-08-07)."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    settings = _settings(soc_ai_data_dir=blocker / "data")
    out_dir, note = resolve_out_dir(settings, None)
    assert out_dir == Path("evals")
    assert note is not None
    assert str(blocker / "evals") in note


async def test_nightly_writes_bundles_under_the_resolved_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The in-app scheduler and Run-now pass no out_dir at all — that path is
    the one that wrote into the container's ephemeral WORKDIR."""
    root = tmp_path / "var" / "lib" / "soc-ai"
    settings = _settings(soc_ai_data_dir=root / "data")
    monkeypatch.setattr("soc_ai.so_client.elastic.ElasticClient", _FakeElastic)
    monkeypatch.setattr("soc_ai.eval.batch.run_batch", _stub_run_batch([_row("a")]))

    result = await run_eval_nightly(settings, mode="local")

    assert result.batch_dir is not None
    assert result.batch_dir.startswith(str(root / "evals"))


def test_cli_eval_nightly_leaves_the_bundle_dir_to_the_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The documented cron line (docs/DOCKER.md) runs ``eval-nightly`` inside
    the container with no --out-dir, so this flag's DEFAULT is what decided
    that prod's oracle critiques lived in an ephemeral WORKDIR. It must defer
    to resolve_out_dir instead of pinning a relative path."""
    import sys

    captured: dict[str, Any] = {}

    def _capture(args: Namespace) -> int:
        captured["out_dir"] = args.out_dir
        return 0

    monkeypatch.setattr(cli, "_eval_nightly", _capture)
    monkeypatch.setattr(sys, "argv", ["soc-ai", "eval-nightly"])
    with pytest.raises(SystemExit):
        cli.main()
    assert captured["out_dir"] is None
