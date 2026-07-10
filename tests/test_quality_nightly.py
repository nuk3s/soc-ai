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
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr
from soc_ai import cli, notify
from soc_ai.config import Settings
from soc_ai.eval.batch import BatchSummary
from soc_ai.eval.quality import (
    SnapshotMetrics,
    TrendPoint,
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
    return [TrendPoint(agreement_rate=agreement, fallback_rate=fallback) for _ in range(n)]


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


def test_detector_can_stack_multiple_reasons() -> None:
    new = _metrics(agreement_rate=0.2, error_rate=0.5, fallback_rate=0.8)
    reasons = detect_regression(new, _hist(7, agreement=0.9, fallback=0.0), alarm_drop=0.15)
    assert len(reasons) == 3


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
