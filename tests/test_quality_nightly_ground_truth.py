"""The nightly evaluation measures a known positive, low agreement and its own grader.

Production review 2026-11-13, item G1. The production store held 113 nightly
batches with 539 rows. Not one row was synthetic. The evaluation therefore
measured no recall. Three more defects sat beside that one:

- The agreement rate stayed between 0.00 and 0.60 for six weeks. That rate
  grades the confidence and the reasoning with the verdict, so it is no gate:
  in the last 7 graded runs it read 6 of 35 while the Oracle named the verdict
  of the model in 26 of 26 critiques of a run that had a verdict. The alarm for
  low agreement therefore reads verdict agreement on real alerts and nothing
  else.
- Three nights lost every grade to the Oracle quota. The trend recorded each as
  ``error_rate 1.00``, which reads as a triage failure.
- Each snapshot recorded the configured model name. The gateway moved the route
  to another engine and a fallback route served runs under the same name.

Layers, each stubbed at its natural boundary, as in ``test_quality_nightly``:
the pure detector, the snapshot reduction, the batch runner, the harness, the
nightly wiring over a real store, the migration and the API read-model.
"""

from __future__ import annotations

import asyncio
import functools
import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from soc_ai import cli
from soc_ai.config import Settings
from soc_ai.eval import batch as batch_mod
from soc_ai.eval import harness as harness_mod
from soc_ai.eval import nightly as nightly_mod
from soc_ai.eval.batch import BatchConfig, BatchSummary, extract_oracle_verdict, run_batch
from soc_ai.eval.harness import GraderError, run_error_from_events, served_models_from_events
from soc_ai.eval.harness import run as harness_run
from soc_ai.eval.nightly import nightly_synth_pool, pick_nightly_scenarios, unmet_requirement
from soc_ai.eval.oracle_client import OracleError, OracleResponse
from soc_ai.eval.prompt import build_user_message
from soc_ai.eval.quality import (
    AGREEMENT_FLOOR,
    ALARM_P,
    CODE_AGREEMENT_DROP,
    CODE_AGREEMENT_LOW,
    CODE_ERROR_CEILING,
    CODE_SYNTH_MISS,
    MEDIAN_WINDOW,
    MIN_HISTORY,
    NOT_RUN_ERROR,
    TrendPoint,
    alarm_conditions,
    classify_run_error,
    compute_snapshot_metrics,
    detect_regression,
    not_measured_text,
    run_outcome,
    snapshot_detail,
    verdict_class,
)
from soc_ai.eval.report import aggregate
from soc_ai.eval.synth_ingest import (
    LEDGER_NAME,
    IngestResult,
    delete_synth_documents,
    plant_id_for,
    read_ledger,
    write_ledger,
)
from soc_ai.eval.synth_loader import load_all_scenarios
from soc_ai.store import config_overrides
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect, text

from tests.test_eval_batch import _make_runner, _make_sampler, _stub_eval_result
from tests.test_eval_batch import _settings as _batch_settings
from tests.test_eval_harness import _settings_for_eval as _harness_settings
from tests.test_eval_harness import _stub_oracle, patch_investigate  # noqa: F401
from tests.test_quality_api import _seed, _snap, client  # noqa: F401
from tests.test_quality_nightly import (
    _args,
    _Clock,
    _FakeElastic,
    _graded_row,
    _metrics,
    _point,
    _read_snapshots,
    _row,
    _seed_snapshots,
    _settings,
)

_CATALOGUE = Path(harness_mod.__file__).parent / "synth_scenarios"

# A 429 body in the shape the gateway returned on production on 2026-11-02,
# 11-08 and 11-09. The text is the gateway's own.
_QUOTA_ERROR = (
    'RuntimeError: LiteLLM/oracle call failed: LiteLLM returned 429: {"error":{"message":'
    '"litellm.RateLimitError: AnthropicException - rate_limit_error: '
    'Claude Max rate limit reached"}}'
)


# --------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------


def _synth_row(
    scenario_id: str,
    *,
    verdict: str = "true_positive",
    confidence: float = 0.8,
    expected: str = "true_positive",
    error: str | None = None,
    is_fallback: bool = False,
) -> dict[str, Any]:
    """One planted row in the IndexRow dict shape."""
    row = _row(
        f"synth-doc-{scenario_id}",
        verdict=verdict,
        agreement="unknown",
        error=error,
        is_fallback=is_fallback,
    )
    row.update(
        is_synth=True,
        synth_scenario_id=scenario_id,
        synth_plant_id=f"{scenario_id}::n20261113T030044",
        synth_expected_verdict=expected,
    )
    if not error:
        row["confidence"] = confidence
    return row


def _not_graded_row(
    alert_id: str, *, kind: str = "quota", verdict: str = "false_positive"
) -> dict[str, Any]:
    """A run whose triage completed and whose grade request failed."""
    row = _row(alert_id, verdict=verdict, agreement="unknown")
    row.update(grader_error=_QUOTA_ERROR, grader_error_kind=kind)
    return row


def _low(n_yes: int = 1, n: int = 5, **overrides: Any) -> TrendPoint:
    """A graded night by its RUBRIC counts: ``n_yes`` of ``n`` grades were "yes".

    It carries no verdict agreement, like every row written before the Oracle
    stated its own verdict.
    """
    base: dict[str, Any] = {
        "agreement_rate": n_yes / n,
        "fallback_rate": 0.0,
        "n_yes": n_yes,
        "n_classified": n,
    }
    base.update(overrides)
    return TrendPoint(**base)


_FP_NMI = "false_positive>needs_more_info"


def _pairs(agree: int, compared: int, pairs: dict[str, int] | None) -> dict[str, int]:
    if pairs is not None:
        return pairs
    return {_FP_NMI: compared - agree} if compared > agree else {}


def _vnight(
    agree: int, compared: int = 5, pairs: dict[str, int] | None = None, **overrides: Any
) -> TrendPoint:
    """A graded night by its VERDICT agreement: ``agree`` of ``compared`` verdicts.

    The rubric counts default to a steady 3 of 5, so the drop rule has nothing
    to say and a test reads the verdict rule alone.
    """
    base: dict[str, Any] = {
        "agreement_rate": 0.6,
        "fallback_rate": 0.0,
        "n_yes": 3,
        "n_classified": 5,
        "verdict_agree": agree,
        "verdict_compared": compared,
        "verdict_pairs": _pairs(agree, compared, pairs),
    }
    base.update(overrides)
    return TrendPoint(**base)


def _vpoint(
    agree: int, compared: int = 5, pairs: dict[str, int] | None = None, **overrides: Any
) -> Any:
    """Tonight, by its verdict agreement. Rubric counts steady at 3 of 5."""
    base: dict[str, Any] = {
        "agreement_rate": 0.6,
        "n_ok": 5,
        "n_yes": 3,
        "n_classified": 5,
        "verdict_agree": agree,
        "verdict_compared": compared,
        "verdict_pairs": _pairs(agree, compared, pairs),
    }
    base.update(overrides)
    return _metrics(**base)


def _codes(reasons: list[Any]) -> list[str]:
    return [r.code for r in reasons]


# The concrete index a synthetic alert is stored in: the backing index of the
# data stream, which is the address a delete by id needs.
_SYNTH_INDEX = ".ds-logs-synth-suricata-alert-2026.11.13-000001"


def _document(scenario_id: str) -> tuple[str, str]:
    """The address of the one document the planting double writes for a scenario."""
    return (_SYNTH_INDEX, f"synth-doc-{scenario_id}")


class _Feeds:
    """The reputation feeds a deployment has loaded, as the eligibility check reads them."""

    def __init__(self, loaded: tuple[str, ...] = (), listed: tuple[str, ...] = ()) -> None:
        self.loaded_sources = list(loaded)
        self._listed = set(listed)

    def lookup_ip(self, ip: str) -> list[str]:
        return ["hit"] if ip in self._listed else []


# The three addresses the easy scenarios rely on: Feodo, URLhaus and Tor.
_FEED_ADDRESSES = ("162.243.103.246", "193.42.39.117", "185.220.101.182")
_NO_FEEDS = _Feeds()
_ALL_FEEDS = _Feeds(loaded=("feodo", "urlhaus", "tor"), listed=_FEED_ADDRESSES)


def _stub_nightly_batch(
    real_rows: list[dict[str, Any]],
    *,
    synth_verdict: str | None = "true_positive",
    synth_error: str | None = None,
    plant_error: str | None = None,
    captured: dict[str, Any] | None = None,
) -> Any:
    """A run_batch double that plants what the nightly asked for.

    The nightly picks its scenario from the date, so a test cannot name the
    scenario ahead of the run. This double reads ``cfg.synth_scenarios`` and
    writes one planted row for each, with the outcome the test asked for.
    ``plant_error`` stands for a grid that refused the plant.
    """

    async def _run(cfg: Any, **kw: Any) -> BatchSummary:
        if captured is not None:
            captured.update(kw)
            captured["cfg"] = cfg
        rows = list(real_rows)
        documents: list[tuple[str, str]] = []
        if cfg.synth_scenarios and plant_error is None:
            for scenario in cfg.synth_scenarios:
                documents.append(_document(scenario.id))
                rows.append(
                    _synth_row(
                        scenario.id,
                        verdict=synth_verdict or "false_positive",
                        error=synth_error,
                    )
                )
        batch_dir = Path(cfg.out_dir) / "batch-test"
        batch_dir.mkdir(parents=True, exist_ok=True)
        with (batch_dir / "index.jsonl").open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        # As the real batch runner does: the ledger is on the disk before a run.
        (batch_dir / LEDGER_NAME).unlink(missing_ok=True)
        if documents:
            write_ledger(batch_dir, documents, planted_at=cfg.synth_run_time)
        n_ok = sum(1 for r in rows if not r.get("error"))
        return BatchSummary(
            batch_dir=batch_dir,
            n_planned=len(rows),
            n_attempted=len(rows),
            n_ok=n_ok,
            n_error=len(rows) - n_ok,
            aborted_reason=None,
            elapsed_s=1,
            synth_error=plant_error,
            synth_documents=tuple(documents),
        )

    return _run


def _wire_nightly(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    real_rows: list[dict[str, Any]],
    *,
    feeds: _Feeds = _NO_FEEDS,
    delete_error: str | None = None,
    **stub: Any,
) -> dict[str, Any]:
    """Settings, a fake grid, the planting double, and recorders for both side effects.

    ``feeds`` is what the deployment has loaded. The default is nothing, which
    is the production state for the two abuse.ch feeds, so only a scenario that
    needs no feed is eligible. ``delete_error`` makes the grid refuse each
    delete with that reason.
    """
    captured: dict[str, Any] = {"alarm": None, "deleted": []}
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(nightly_mod, "_loaded_blocklist", lambda _settings: feeds)
    monkeypatch.setattr("soc_ai.so_client.elastic.ElasticClient", _FakeElastic)
    monkeypatch.setattr(
        "soc_ai.eval.batch.run_batch", _stub_nightly_batch(real_rows, captured=captured, **stub)
    )

    async def _fake_alarm(_settings: Settings, **kw: Any) -> None:
        captured["alarm"] = kw

    async def _fake_delete(_elastic: Any, documents: Any) -> Any:
        """Each call is one list of ``(index, id)``. Nothing else can be asked for."""
        asked = [tuple(document) for document in documents]
        captured["deleted"].append(asked)
        if delete_error is not None:
            return 0, [(index, doc_id, delete_error) for index, doc_id in asked]
        return len(asked), []

    monkeypatch.setattr(cli, "_fire_quality_alarm", _fake_alarm)
    monkeypatch.setattr("soc_ai.eval.synth_ingest.delete_synth_documents", _fake_delete)
    return captured


def _five_real(agreement: str = "yes", oracle_verdict: str | None = None) -> list[dict[str, Any]]:
    """Five real alerts closed as false positives, with the Oracle's verdict."""
    rows = [_row(a, agreement=agreement) for a in "abcde"]
    for row in rows:
        row["oracle_verdict"] = oracle_verdict
    return rows


# --------------------------------------------------------------------
# The cause: the nightly never asked the batch runner for a scenario
# --------------------------------------------------------------------


def test_nightly_plants_a_synthetic_true_positive_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The batch runner has taken ``synth_scenarios`` since the catalogue landed.

    ``run_eval_nightly`` built its ``BatchConfig`` with no scenario and no
    setting existed to ask for one, so 113 production batches held 0 planted
    rows. The default follows the 2026-09-09 record: one known positive in each
    batch.
    """
    settings = _settings()
    assert settings.quality_nightly_synth_n == 1
    captured = _wire_nightly(monkeypatch, settings, _five_real())

    assert cli._eval_nightly(_args(tmp_path)) == 0

    cfg = captured["cfg"]
    assert cfg.synth_scenarios is not None and len(cfg.synth_scenarios) == 1
    planted = cfg.synth_scenarios[0]
    assert planted.ground_truth.verdict == "true_positive"
    assert planted.tier == "easy"
    # A refused plant must not cost the night its real rows.
    assert cfg.synth_optional is True
    # The plant carries a key of its own, so another night cannot read it.
    assert cfg.synth_plant_tag


def test_nightly_plants_nothing_when_the_setting_is_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The switch must switch. Zero is the documented off position."""
    settings = _settings(quality_nightly_synth_n=0)
    captured = _wire_nightly(monkeypatch, settings, _five_real())

    assert cli._eval_nightly(_args(tmp_path)) == 0

    assert not captured["cfg"].synth_scenarios
    snapshot = _read_snapshots(settings)[0]
    assert (snapshot.detail or {}).get("synth") == []
    # With nothing to plant and nothing left behind, the run deletes nothing.
    assert captured["deleted"] == []


def test_the_setting_is_clamped_to_its_documented_bounds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A stray environment value must not turn the nightly into a benchmark."""
    settings = _settings(quality_nightly_synth_n=40)
    captured = _wire_nightly(monkeypatch, settings, _five_real(), feeds=_ALL_FEEDS)

    assert cli._eval_nightly(_args(tmp_path)) == 0

    assert len(captured["cfg"].synth_scenarios) == nightly_mod.NIGHTLY_SYNTH_MAX


def test_the_console_can_set_the_synthetic_count() -> None:
    spec = next(s for s in config_overrides.WHITELIST if s.key == "quality_nightly_synth_n")
    assert spec.section == "Quality"
    assert (spec.min_value, spec.max_value) == (0, nightly_mod.NIGHTLY_SYNTH_MAX)
    assert spec.hot is True


def test_the_pool_is_the_easy_true_positives_and_nothing_else() -> None:
    """A miss raises an alarm, so the pool holds only scenarios that must be caught.

    The catalogue states that recall on the easy tier approaches 100% and that a
    miss there means the pipeline is broken. A benign twin has no positive to
    miss. A scenario with no alert cannot be triaged.
    """
    pool = nightly_synth_pool(load_all_scenarios(_CATALOGUE))
    assert [s.id for s in pool] == sorted(s.id for s in pool)
    assert len(pool) >= 3
    for scenario in pool:
        assert scenario.tier == "easy"
        assert scenario.ground_truth.verdict == "true_positive"
        assert any(event.is_triage_target for event in scenario.events)
    assert not any(s.id.startswith(("b", "s", "m", "h")) for s in pool)


def test_the_plant_rotates_through_the_whole_pool() -> None:
    """One fixed scenario every night would train the trend on one alert."""
    catalogue = load_all_scenarios(_CATALOGUE)
    pool = nightly_synth_pool(catalogue)
    start = date(2026, 11, 13)
    picked = [
        pick_nightly_scenarios(catalogue, n=1, day=start + timedelta(days=i))[0].id
        for i in range(len(pool))
    ]
    assert sorted(picked) == [s.id for s in pool]
    # The same day gives the same plant: a second run that day is comparable.
    assert pick_nightly_scenarios(catalogue, n=1, day=start)[0].id == picked[0]
    # More than the pool holds gives the pool once, never a duplicate plant.
    many = pick_nightly_scenarios(catalogue, n=len(pool) + 4, day=start)
    assert sorted(s.id for s in many) == [s.id for s in pool]
    assert pick_nightly_scenarios(catalogue, n=0, day=start) == []


async def test_a_planted_run_is_never_sent_to_the_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scenario carries its own ground truth, so a grade adds no fact.

    It would cost one Oracle call each night against a quota that already lost
    three nights. The real alert in the same batch keeps its grade.
    """
    seen: list[dict[str, Any]] = []

    async def _fake_run(alert_id: str, **kw: Any) -> str:
        seen.append({"alert_id": alert_id, **kw})
        return alert_id

    monkeypatch.setattr(harness_mod, "run", _fake_run)

    await nightly_mod._nightly_runner(
        "synth-doc", grade=True, expected_verdict="true_positive", include_synth="e1::n1"
    )
    await nightly_mod._nightly_runner("real-doc", grade=True, expected_verdict=None)
    await nightly_mod._nightly_runner("local-doc", grade=False, expected_verdict=None)

    assert [s["grade"] for s in seen] == [False, True, False]
    # A failed grade request must not lose the investigation of any row.
    assert all(s["tolerate_grader_failure"] is True for s in seen)


# --------------------------------------------------------------------
# The synthetic stratum on the snapshot
# --------------------------------------------------------------------


def test_a_caught_plant_is_recorded_and_stays_out_of_the_real_numbers() -> None:
    """The planted positive must not enter the numbers of the real alerts.

    One planted ``true_positive`` in each batch would put a positive verdict in
    every verdict distribution and would end the benign-only caveat for good.
    """
    rows = [*_five_real(), _synth_row("e2-urlhaus-pe-delivery", verdict="true_positive")]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    assert (m.n_ok, m.n_error) == (5, 0)
    assert m.verdict_counts == {"false_positive": 5}
    assert m.n_classified == 5 and m.agreement_rate == 1.0
    assert [(o.scenario_id, o.outcome) for o in m.synth] == [("e2-urlhaus-pe-delivery", "caught")]
    assert detect_regression(m, [], alarm_drop=0.15) == []


def test_a_missed_plant_raises_the_alarm_and_names_the_scenario() -> None:
    rows = [
        *_five_real(),
        _synth_row("e1-emotet-feodo-c2", verdict="false_positive", confidence=0.85),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    reasons = detect_regression(m, [], alarm_drop=0.15)

    assert _codes(reasons) == [CODE_SYNTH_MISS]
    message = str(reasons[0])
    assert "e1-emotet-feodo-c2" in message
    assert "false_positive" in message and "0.85" in message


def test_a_miss_alarms_on_a_new_install_with_no_history() -> None:
    """Every other rule waits for three nights. This rule has ground truth.

    The planted alert is a known positive, so one miss needs no baseline to be
    a miss.
    """
    rows = [_row("a"), _synth_row("e4-password-spray-vpn", verdict="needs_more_info")]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")
    assert _codes(detect_regression(m, [], alarm_drop=0.15)) == [CODE_SYNTH_MISS]
    # The rules that need a baseline still wait.
    bad = _metrics(agreement_rate=0.0, error_rate=1.0, fallback_rate=1.0)
    assert detect_regression(bad, [], alarm_drop=0.15) == []


def test_two_misses_are_one_alarm_that_names_both() -> None:
    rows = [
        _row("a"),
        _synth_row("e1-emotet-feodo-c2", verdict="false_positive"),
        _synth_row("e3-tor-exit-ssh", verdict="needs_more_info"),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    reasons = detect_regression(m, [], alarm_drop=0.15)
    assert _codes(reasons) == [CODE_SYNTH_MISS]
    assert "e1-emotet-feodo-c2" in reasons[0] and "e3-tor-exit-ssh" in reasons[0]


def test_a_plant_that_errored_is_not_measured_and_is_not_a_miss() -> None:
    """Negative control on the path the miss rule would take by default.

    An errored run has no verdict. Scoring it as a miss would raise a verdict
    alarm for a timeout. It is recorded as not measured, with its cause.
    """
    rows = [*_five_real(), _synth_row("e1-emotet-feodo-c2", error="timeout after 1800s")]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    assert [(o.outcome, o.cause) for o in m.synth] == [("not_measured", "timeout after 1800s")]
    assert detect_regression(m, [], alarm_drop=0.15) == []
    # The errored plant is not a triage error of the real alerts.
    assert (m.n_error, m.error_rate) == (0, 0.0)


def test_a_fallback_on_the_plant_is_not_measured_and_is_not_a_miss() -> None:
    """A fallback is a failed model call that carries a placeholder verdict."""
    rows = [
        *_five_real(),
        _synth_row("e1-emotet-feodo-c2", verdict="needs_more_info", is_fallback=True),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    assert [o.outcome for o in m.synth] == ["not_measured"]
    assert detect_regression(m, [], alarm_drop=0.15) == []
    assert m.fallback_rate == 0.0


def test_a_benign_twin_that_closes_benign_is_not_a_missed_positive() -> None:
    """Negative control: only an expected true positive can be missed."""
    rows = [
        _row("a"),
        _synth_row("b1-cdn-update-beacon", verdict="false_positive", expected="false_positive"),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    assert m.synth == ()
    assert detect_regression(m, [], alarm_drop=0.15) == []


def test_a_planned_scenario_with_no_row_is_not_measured() -> None:
    """A refused plant leaves no row. The snapshot must still state the plan."""
    rows = _five_real()
    m = compute_snapshot_metrics(
        rows,
        aggregate(rows),
        mode="graded",
        synth_planned=("e5-webshell-dmz-server",),
        synth_note="AuthorizationException: no write access to logs-synth-suricata-alert",
    )
    assert [(o.scenario_id, o.outcome) for o in m.synth] == [
        ("e5-webshell-dmz-server", "not_measured")
    ]
    assert "AuthorizationException" in (m.synth[0].cause or "")
    assert detect_regression(m, [], alarm_drop=0.15) == []


def test_the_benign_only_caveat_ends_when_the_batch_measured_a_plant() -> None:
    """The caveat says the batch held no known positive. A measured plant is one."""
    history = [_low(5) for _ in range(20)]
    benign_only = _point(0.0, n_partial=5, n_no=0, verdict_counts={"false_positive": 5})
    caveat = str(detect_regression(benign_only, history, alarm_drop=0.15)[0])
    assert "benign traffic only" in caveat

    rows = [*_five_real("partial"), _synth_row("e2-urlhaus-pe-delivery")]
    measured = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    drop = next(
        r
        for r in detect_regression(measured, history, alarm_drop=0.15)
        if r.code == CODE_AGREEMENT_DROP
    )
    assert "benign traffic only" not in drop

    # Negative control: a plant that was not measured ends nothing.
    rows = [*_five_real("partial"), _synth_row("e2-urlhaus-pe-delivery", error="boom")]
    unmeasured = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    drop = next(
        r
        for r in detect_regression(unmeasured, history, alarm_drop=0.15)
        if r.code == CODE_AGREEMENT_DROP
    )
    assert "benign traffic only" in drop


# --------------------------------------------------------------------
# The nightly end to end: plant, record, alarm, clean
# --------------------------------------------------------------------


def test_nightly_records_a_caught_plant_and_cleans_the_grid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = _settings(oracle_enabled=True)
    captured = _wire_nightly(monkeypatch, settings, _five_real())

    assert cli._eval_nightly(_args(tmp_path)) == 0

    planted = captured["cfg"].synth_scenarios[0].id
    snapshot = _read_snapshots(settings)[0]
    assert snapshot.alarmed is False
    assert snapshot.n_ok == 5 and snapshot.verdict_counts == {"false_positive": 5}
    assert snapshot.detail["synth"] == [
        {
            "scenario_id": planted,
            "outcome": "caught",
            "verdict": "true_positive",
            "confidence": 0.8,
            "cause": None,
        }
    ]
    assert captured["alarm"] is None
    # The document leaves the grid when the batch ends, named by its own id.
    assert captured["deleted"] == [[_document(planted)]]
    assert read_ledger(Path(snapshot.batch_dir))[1] == []
    assert f"The model caught the synthetic true positive {planted}." in capsys.readouterr().err


def test_nightly_alarms_on_a_missed_plant(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The whole path: a miss reaches the row, the key and the alarm hand-off."""
    settings = _settings(oracle_enabled=True)
    captured = _wire_nightly(monkeypatch, settings, _five_real(), synth_verdict="false_positive")

    assert cli._eval_nightly(_args(tmp_path)) == 0

    planted = captured["cfg"].synth_scenarios[0].id
    snapshot = _read_snapshots(settings)[0]
    assert snapshot.alarmed is True
    assert snapshot.alarm_key == CODE_SYNTH_MISS
    assert planted in snapshot.alarm_reasons[0]
    assert captured["alarm"] is not None
    assert planted in captured["alarm"]["reasons"][0]
    assert snapshot.detail["synth"][0]["outcome"] == "missed"


def test_a_refused_plant_keeps_the_real_rows_and_states_the_cause(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A grid that refuses the write must cost the night nothing else."""
    settings = _settings(oracle_enabled=True)
    cause = "AuthorizationException: action [indices:data/write/index] is unauthorized"
    captured = _wire_nightly(monkeypatch, settings, _five_real(), plant_error=cause)

    assert cli._eval_nightly(_args(tmp_path)) == 0

    snapshot = _read_snapshots(settings)[0]
    assert snapshot.n_ok == 5 and snapshot.agreement_rate == 1.0
    assert snapshot.alarmed is False
    assert [o["outcome"] for o in snapshot.detail["synth"]] == ["not_measured"]
    assert cause in snapshot.detail["synth_note"]
    assert captured["alarm"] is None
    err = capsys.readouterr().err
    assert "The batch planted no synthetic true positive." in err
    assert cause in err
    # Nothing was written, so there is nothing to delete and no request is sent.
    assert captured["deleted"] == []


def test_a_failed_delete_is_reported_and_does_not_fail_the_night(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The grid refuses the delete. The night keeps its numbers and says so.

    The report is in three places: the line of the run, the snapshot, and the
    ledger, which keeps the documents so the next run tries them again.
    """
    settings = _settings(oracle_enabled=True)
    captured = _wire_nightly(
        monkeypatch, settings, _five_real(), delete_error="AuthorizationException: no delete"
    )

    assert cli._eval_nightly(_args(tmp_path)) == 0

    planted = captured["cfg"].synth_scenarios[0].id
    snapshot = _read_snapshots(settings)[0]
    assert snapshot.n_ok == 5 and snapshot.alarmed is False
    assert snapshot.detail["synth"][0]["outcome"] == "caught"
    report = snapshot.detail["synth_cleanup_error"]
    assert report.startswith("1 synthetic documents are still on the grid.")
    assert "AuthorizationException: no delete" in report
    assert "soc-ai synth-clean" in report
    assert report in capsys.readouterr().err
    # The ledger still lists the document, so the next run tries it again.
    _planted_at, left = read_ledger(Path(snapshot.batch_dir))
    assert left == [_document(planted)]


def test_a_clean_delete_reports_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Negative control: the report is for a failure, not for every night."""
    settings = _settings(oracle_enabled=True)
    _wire_nightly(monkeypatch, settings, _five_real())
    assert cli._eval_nightly(_args(tmp_path)) == 0
    snapshot = _read_snapshots(settings)[0]
    assert snapshot.detail["synth_cleanup_error"] is None
    assert read_ledger(Path(snapshot.batch_dir))[1] == []


def _old_batch(
    tmp_path: Path, name: str, *, hours: float, documents: list[tuple[str, str]]
) -> Path:
    """A batch directory an earlier run left, with its ledger."""
    batch_dir = tmp_path / "evals" / name
    batch_dir.mkdir(parents=True)
    write_ledger(batch_dir, documents, planted_at=datetime.now(UTC) - timedelta(hours=hours))
    return batch_dir


def test_nightly_first_removes_what_a_killed_run_left_from_its_own_ledger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A run that was killed never reached its own removal.

    Production restarted inside the nightly hour on two of 13 nights. Its
    synthetic alert would sit in Security Onion until someone asked what it
    was. The ledger of that run is still in its batch directory, and the next
    run deletes exactly the documents it lists.
    """
    settings = _settings()
    killed = _old_batch(
        tmp_path,
        "batch-2026-11-12T030044Z",
        hours=24,
        documents=[(_SYNTH_INDEX, "left-1"), (_SYNTH_INDEX, "left-2")],
    )
    # Negative control: a batch another process is running now keeps its documents.
    running = _old_batch(
        tmp_path, "batch-2026-11-13T025900Z", hours=1, documents=[(_SYNTH_INDEX, "live-1")]
    )
    captured = _wire_nightly(monkeypatch, settings, _five_real())

    assert cli._eval_nightly(_args(tmp_path)) == 0

    planted = captured["cfg"].synth_scenarios[0].id
    assert captured["deleted"] == [
        [(_SYNTH_INDEX, "left-1"), (_SYNTH_INDEX, "left-2")],
        [_document(planted)],
    ]
    assert read_ledger(killed)[1] == []
    assert read_ledger(running)[1] == [(_SYNTH_INDEX, "live-1")]


def test_what_a_killed_run_left_is_removed_on_a_night_that_plants_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The documents are on the grid whatever tonight's setting is."""
    settings = _settings(quality_nightly_synth_n=0)
    killed = _old_batch(
        tmp_path, "batch-2026-11-12T030044Z", hours=24, documents=[(_SYNTH_INDEX, "left-1")]
    )
    captured = _wire_nightly(monkeypatch, settings, _five_real())

    assert cli._eval_nightly(_args(tmp_path)) == 0

    assert captured["deleted"] == [[(_SYNTH_INDEX, "left-1")]]
    assert read_ledger(killed)[1] == []


async def test_a_batch_that_dies_says_that_its_documents_can_still_be_on_the_grid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings()
    monkeypatch.setattr(nightly_mod, "_loaded_blocklist", lambda _settings: _NO_FEEDS)
    monkeypatch.setattr("soc_ai.so_client.elastic.ElasticClient", _FakeElastic)

    async def _dies(cfg: Any, **_kw: Any) -> BatchSummary:
        raise RuntimeError("LITELLM_API_KEY not set.")

    monkeypatch.setattr("soc_ai.eval.batch.run_batch", _dies)

    result = await nightly_mod.run_eval_nightly(settings, out_dir=tmp_path / "evals")

    assert result.exit_code == nightly_mod.EXIT_ERROR
    assert result.detail == (
        "eval-nightly failed: LITELLM_API_KEY not set. Synthetic documents of this run "
        "can still be on the grid. The next run removes them."
    )


# --------------------------------------------------------------------
# Eligibility: a scenario needs what the deployment has loaded
# --------------------------------------------------------------------


def _needs_a_feed(scenarios: Any) -> list[Any]:
    return [s for s in nightly_synth_pool(scenarios) if s.requires]


def test_each_scenario_that_cites_a_feed_states_the_feed_it_needs() -> None:
    """The guard for the next scenario someone adds.

    A scenario whose ground truth requires a ``blocklist_hit`` citation relies
    on a feed. If it does not declare the feed, the nightly plants it on a
    deployment that cannot detect it, and a miss raises a verdict alarm for a
    file that is not on the disk.
    """
    from soc_ai.enrichment.blocklists import _FEED_FILES

    pool = nightly_synth_pool(load_all_scenarios(_CATALOGUE))
    cites_a_feed = [s.id for s in pool if "blocklist_hit" in s.ground_truth.required_citation_kinds]
    declares = [s.id for s in pool if s.requires]
    assert cites_a_feed == declares
    assert declares == ["e1-emotet-feodo-c2", "e2-urlhaus-pe-delivery", "e3-tor-exit-ssh"]
    for scenario in pool:
        for need in scenario.requires:
            assert need.blocklist in _FEED_FILES
            assert need.ip in _FEED_ADDRESSES
            # The address is the one the scenario plants, not a second copy.
            planted = json.dumps([e.fields for e in scenario.events])
            assert need.ip in planted


def test_a_scenario_is_eligible_when_its_feed_is_loaded_and_lists_the_address() -> None:
    e1 = _scenario("e1-emotet-feodo-c2")
    assert unmet_requirement(e1, _NO_FEEDS) == "the blocklist feodo is not loaded"
    # Production holds the Tor list alone: a loaded feed is not the needed feed.
    assert unmet_requirement(e1, _Feeds(loaded=("tor",))) == "the blocklist feodo is not loaded"
    # The feed is on the disk and no longer lists the address.
    stale = _Feeds(loaded=("feodo",), listed=("198.51.100.9",))
    assert unmet_requirement(e1, stale) == "no loaded blocklist lists 162.243.103.246"
    assert unmet_requirement(e1, _ALL_FEEDS) is None
    # A scenario with its whole evidence in its own events needs nothing.
    assert unmet_requirement(_scenario("e4-password-spray-vpn"), _NO_FEEDS) is None


def test_the_rotation_runs_over_the_eligible_scenarios_only() -> None:
    catalogue = load_all_scenarios(_CATALOGUE)
    start = date(2026, 11, 13)
    days = [start + timedelta(days=i) for i in range(10)]

    without = {
        pick_nightly_scenarios(catalogue, n=1, day=d, blocklist=_NO_FEEDS)[0].id for d in days
    }
    assert without == {"e4-password-spray-vpn", "e5-webshell-dmz-server"}

    with_all = {
        pick_nightly_scenarios(catalogue, n=1, day=d, blocklist=_ALL_FEEDS)[0].id for d in days
    }
    assert with_all == {s.id for s in nightly_synth_pool(catalogue)}
    # More than the eligible scenarios hold gives each one time.
    many = pick_nightly_scenarios(catalogue, n=3, day=start, blocklist=_NO_FEEDS)
    assert sorted(s.id for s in many) == ["e4-password-spray-vpn", "e5-webshell-dmz-server"]


def test_the_eligibility_check_reads_the_feeds_the_run_will_read(tmp_path: Path) -> None:
    """The real loader over a real feed file, with no double in between."""
    feeds = tmp_path / "blocklists"
    feeds.mkdir()
    (feeds / "tor_exits.txt").write_text("# exits\n185.220.101.182\n198.51.100.9\n")
    settings = _settings(blocklist_data_dir=feeds)

    blocklist = nightly_mod._loaded_blocklist(settings)

    assert blocklist.loaded_sources == ["tor"]
    eligible, ineligible = nightly_mod.split_eligible(
        nightly_synth_pool(load_all_scenarios(_CATALOGUE)), blocklist
    )
    assert "e3-tor-exit-ssh" in {s.id for s in eligible}
    assert dict(ineligible) == {
        "e1-emotet-feodo-c2": "the blocklist feodo is not loaded",
        "e2-urlhaus-pe-delivery": "the blocklist urlhaus is not loaded",
    }


def test_nightly_does_not_plant_a_scenario_whose_feed_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = _settings(oracle_enabled=True, quality_nightly_synth_n=3)
    captured = _wire_nightly(monkeypatch, settings, _five_real())

    assert cli._eval_nightly(_args(tmp_path)) == 0

    planted = [s.id for s in captured["cfg"].synth_scenarios]
    assert sorted(planted) == ["e4-password-spray-vpn", "e5-webshell-dmz-server"]
    snapshot = _read_snapshots(settings)[0]
    assert snapshot.alarmed is False
    assert snapshot.detail["synth_ineligible"] == [
        {"scenario_id": "e1-emotet-feodo-c2", "reason": "the blocklist feodo is not loaded"},
        {"scenario_id": "e2-urlhaus-pe-delivery", "reason": "the blocklist urlhaus is not loaded"},
        {"scenario_id": "e3-tor-exit-ssh", "reason": "the blocklist tor is not loaded"},
    ]
    line = snapshot.detail["synth_ineligible_note"]
    assert "\n" not in line
    assert line == (
        "e1-emotet-feodo-c2 is not eligible: the blocklist feodo is not loaded. "
        "e2-urlhaus-pe-delivery is not eligible: the blocklist urlhaus is not loaded. "
        "e3-tor-exit-ssh is not eligible: the blocklist tor is not loaded."
    )
    assert line in capsys.readouterr().err


def test_no_eligible_scenario_plants_nothing_and_raises_no_alarm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pool where each scenario needs a feed, on a deployment with no feed."""
    settings = _settings(oracle_enabled=True)
    monkeypatch.setattr(nightly_mod, "nightly_synth_pool", _needs_a_feed)
    captured = _wire_nightly(monkeypatch, settings, _five_real())

    assert cli._eval_nightly(_args(tmp_path)) == 0

    assert not captured["cfg"].synth_scenarios
    snapshot = _read_snapshots(settings)[0]
    assert (snapshot.alarmed, snapshot.alarm_key) == (False, None)
    assert snapshot.detail["synth"] == []
    assert snapshot.detail["synth_note"] == "no scenario is eligible on this deployment"
    assert len(snapshot.detail["synth_ineligible"]) == 3
    assert captured["alarm"] is None
    # Nothing was written to the grid, so nothing is deleted from it.
    assert captured["deleted"] == []
    err = capsys.readouterr().err
    assert (
        "The batch planted no synthetic true positive. "
        "Cause: no scenario is eligible on this deployment." in err
    )
    assert "e1-emotet-feodo-c2 is not eligible: the blocklist feodo is not loaded." in err


def test_an_eligible_scenario_that_is_missed_still_raises_the_alarm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Negative control: eligibility removes a scenario, never a miss."""
    settings = _settings(oracle_enabled=True)
    captured = _wire_nightly(monkeypatch, settings, _five_real(), synth_verdict="false_positive")

    assert cli._eval_nightly(_args(tmp_path)) == 0

    planted = captured["cfg"].synth_scenarios[0].id
    assert planted in ("e4-password-spray-vpn", "e5-webshell-dmz-server")
    snapshot = _read_snapshots(settings)[0]
    assert snapshot.alarm_key == CODE_SYNTH_MISS
    assert planted in snapshot.alarm_reasons[0]
    assert captured["alarm"] is not None
    # The scenarios that were not eligible are stated beside the miss.
    assert len(snapshot.detail["synth_ineligible"]) == 3


def test_a_scenario_with_its_feed_loaded_is_planted_and_can_be_missed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Negative control on the other side: a met requirement removes nothing."""
    settings = _settings(oracle_enabled=True, quality_nightly_synth_n=3)
    monkeypatch.setattr(nightly_mod, "nightly_synth_pool", _needs_a_feed)
    captured = _wire_nightly(
        monkeypatch, settings, _five_real(), feeds=_ALL_FEEDS, synth_verdict="false_positive"
    )

    assert cli._eval_nightly(_args(tmp_path)) == 0

    planted = sorted(s.id for s in captured["cfg"].synth_scenarios)
    assert planted == ["e1-emotet-feodo-c2", "e2-urlhaus-pe-delivery", "e3-tor-exit-ssh"]
    snapshot = _read_snapshots(settings)[0]
    assert snapshot.alarm_key == CODE_SYNTH_MISS
    assert all(scenario_id in snapshot.alarm_reasons[0] for scenario_id in planted)
    assert snapshot.detail["synth_ineligible"] == []
    assert snapshot.detail["synth_ineligible_note"] is None


# --------------------------------------------------------------------
# The batch runner and the ingester
# --------------------------------------------------------------------


def _scenario(scenario_id: str) -> Any:
    return next(s for s in load_all_scenarios(_CATALOGUE) if s.id == scenario_id)


async def test_run_batch_survives_a_refused_plant_when_the_plant_is_optional(
    tmp_path: Path,
) -> None:
    async def _refusing(_scens: Any, **_kw: Any) -> list[IngestResult]:
        raise RuntimeError("synthetic document found in production index")

    cfg = BatchConfig(
        oql="x",
        n=2,
        concurrency=1,
        out_dir=tmp_path,
        synth_scenarios=(_scenario("e1-emotet-feodo-c2"),),
        synth_optional=True,
    )
    summary = await run_batch(
        cfg,
        settings=_batch_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=_make_sampler(["real-1", "real-2"]),
        runner=_make_runner(),
        synth_ingester=_refusing,
    )
    assert summary.n_ok == 2
    assert "synthetic document found in production index" in (summary.synth_error or "")
    assert summary.synth_documents == ()
    assert not (summary.batch_dir / LEDGER_NAME).exists()


async def test_run_batch_still_raises_on_a_refused_plant_by_default(tmp_path: Path) -> None:
    """Negative control: ``validate-batch --synth-set`` asked for the plant.

    A benchmark that ran without its scenarios would report a recall over
    nothing, so the default stays a hard failure.
    """

    async def _refusing(_scens: Any, **_kw: Any) -> list[IngestResult]:
        raise RuntimeError("synthetic document found in production index")

    cfg = BatchConfig(
        oql="x", n=2, out_dir=tmp_path, synth_scenarios=(_scenario("e1-emotet-feodo-c2"),)
    )
    with pytest.raises(RuntimeError, match="production index"):
        await run_batch(
            cfg,
            settings=_batch_settings(),
            elastic=None,  # type: ignore[arg-type]
            sampler=_make_sampler(["real-1", "real-2"]),
            runner=_make_runner(),
            synth_ingester=_refusing,
        )


async def test_an_optional_plant_is_skipped_when_no_real_alert_is_eligible(
    tmp_path: Path,
) -> None:
    """A grid with no eligible alert writes no snapshot. It must also plant nothing."""
    calls: list[Any] = []

    async def _ingester(scens: Any, **kw: Any) -> list[IngestResult]:
        calls.append(scens)
        return []

    cfg = BatchConfig(
        oql="x",
        n=2,
        out_dir=tmp_path,
        synth_scenarios=(_scenario("e1-emotet-feodo-c2"),),
        synth_optional=True,
    )
    summary = await run_batch(
        cfg,
        settings=_batch_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=_make_sampler([]),
        runner=_make_runner(),
        synth_ingester=_ingester,
    )
    assert summary.n_planned == 0
    assert calls == []


async def test_run_batch_tags_the_plant_and_records_the_expected_verdict(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    async def _ingester(scens: Any, **kw: Any) -> list[IngestResult]:
        seen.update(kw)
        return [
            IngestResult(
                scenario_id=s.id,
                triage_doc_id=f"synth-doc-{s.id}",
                triage_index="logs-synth-suricata-alert",
                doc_count=1,
                plant_id=plant_id_for(s.id, 0, kw.get("plant_tag")),
                documents=(_document(s.id),),
            )
            for s in scens
        ]

    cfg = BatchConfig(
        oql="x",
        n=1,
        concurrency=1,
        out_dir=tmp_path,
        synth_scenarios=(_scenario("e1-emotet-feodo-c2"),),
        synth_optional=True,
        synth_plant_tag="n20261113T030044",
    )
    summary = await run_batch(
        cfg,
        settings=_batch_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=_make_sampler(["real-1"]),
        runner=_make_runner(),
        synth_ingester=_ingester,
    )
    assert seen["plant_tag"] == "n20261113T030044"
    # The batch reports where the plant wrote, and keeps the same list on the disk.
    assert summary.synth_documents == (_document("e1-emotet-feodo-c2"),)
    assert read_ledger(summary.batch_dir)[1] == [_document("e1-emotet-feodo-c2")]
    rows = [
        json.loads(line)
        for line in (summary.batch_dir / "index.jsonl").read_text().splitlines()
        if line
    ]
    by_id = {r["alert_id"]: r for r in rows}
    assert by_id["synth-doc-e1-emotet-feodo-c2"]["synth_expected_verdict"] == "true_positive"
    assert (
        by_id["synth-doc-e1-emotet-feodo-c2"]["synth_plant_id"]
        == "e1-emotet-feodo-c2::n20261113T030044"
    )
    assert by_id["real-1"]["synth_expected_verdict"] is None


def test_a_tagged_plant_key_is_distinct_and_the_plain_key_is_unchanged() -> None:
    assert plant_id_for("e1", 0) == "e1"
    assert plant_id_for("e1", 2) == "e1::r2"
    assert plant_id_for("e1", 0, "n1") == "e1::n1"
    assert plant_id_for("e1", 2, "n1") == "e1::n1::r2"
    assert plant_id_for("e1", 0, "n1") != plant_id_for("e1", 0, "n2")


class _IdOnlyClient:
    """A grid client with ``delete`` by id and no delete by query at all.

    A call to ``delete_by_query`` raises ``AttributeError``, so a test that
    passes through this client proves that no such call was made.
    """

    def __init__(self, fail: dict[str, Exception] | None = None) -> None:
        self.deleted: list[tuple[str, str]] = []
        self._fail = fail or {}

    async def delete(self, *, index: str, id: str) -> dict[str, Any]:
        if id in self._fail:
            raise self._fail[id]
        self.deleted.append((index, id))
        return {"result": "deleted"}


class _IdOnlyGrid:
    def __init__(self, fail: dict[str, Exception] | None = None) -> None:
        self._client = _IdOnlyClient(fail)


async def test_documents_are_deleted_by_their_own_ids_and_by_nothing_else() -> None:
    grid = _IdOnlyGrid()
    backing = ".ds-logs-synth-zeek-conn-2026.11.13-000001"
    documents = [(_SYNTH_INDEX, "a1"), (backing, "b2")]

    removed, failures = await delete_synth_documents(grid, documents)  # type: ignore[arg-type]

    assert (removed, failures) == (2, [])
    assert grid._client.deleted == documents
    assert not hasattr(grid._client, "delete_by_query")
    # No document named: no request.
    assert await delete_synth_documents(grid, []) == (0, [])  # type: ignore[arg-type]
    assert len(grid._client.deleted) == 2


async def test_an_address_outside_a_synthetic_index_is_refused_and_never_sent() -> None:
    """The guard on the path a wrong ledger would take.

    A ledger that named a production index would point a delete at a real
    document. The address is refused, reported, and no request leaves.
    """
    grid = _IdOnlyGrid()
    production = ".ds-logs-suricata.alerts-so-2026.11.13-000001"

    removed, failures = await delete_synth_documents(
        grid,  # type: ignore[arg-type]
        [(production, "real-1"), (_SYNTH_INDEX, "a1")],
    )

    assert removed == 1
    assert failures == [(production, "real-1", "refused: the index is not a synthetic index")]
    assert grid._client.deleted == [(_SYNTH_INDEX, "a1")]


async def test_one_failed_delete_is_reported_and_does_not_stop_the_rest() -> None:
    from elasticsearch import NotFoundError

    gone = NotFoundError("not found", SimpleNamespace(status=404), {})  # type: ignore[arg-type]
    grid = _IdOnlyGrid(fail={"a2": RuntimeError("no delete right"), "a3": gone})

    removed, failures = await delete_synth_documents(
        grid,  # type: ignore[arg-type]
        [(_SYNTH_INDEX, "a1"), (_SYNTH_INDEX, "a2"), (_SYNTH_INDEX, "a3"), (_SYNTH_INDEX, "a4")],
    )

    # A document that is already gone counts as removed.
    assert removed == 3
    assert failures == [(_SYNTH_INDEX, "a2", "RuntimeError: no delete right")]
    assert grid._client.deleted == [(_SYNTH_INDEX, "a1"), (_SYNTH_INDEX, "a4")]


def test_the_ledger_keeps_what_it_is_given_and_reads_a_bad_file_as_nothing(tmp_path: Path) -> None:
    planted_at = datetime(2026, 11, 13, 3, 0, 44, tzinfo=UTC)
    write_ledger(tmp_path, [(_SYNTH_INDEX, "a1"), (_SYNTH_INDEX, "a2")], planted_at=planted_at)
    assert read_ledger(tmp_path) == (planted_at, [(_SYNTH_INDEX, "a1"), (_SYNTH_INDEX, "a2")])
    write_ledger(tmp_path, [], planted_at=planted_at)
    assert read_ledger(tmp_path) == (planted_at, [])
    # Nothing is deleted on the strength of a file that cannot be parsed.
    (tmp_path / LEDGER_NAME).write_text("{not json")
    assert read_ledger(tmp_path) == (None, [])
    assert read_ledger(tmp_path / "absent") == (None, [])


async def test_the_ingester_records_the_address_of_each_document_as_it_lands() -> None:
    """A plant that fails part way returns nothing. The list is the only record."""
    from soc_ai.eval.synth_ingest import ingest_scenario

    class _Client:
        def __init__(self, fail_at: int | None = None) -> None:
            self.count = 0
            self._fail_at = fail_at
            self.indices = self

        async def index(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
            self.count += 1
            if self.count == self._fail_at:
                raise RuntimeError("the grid refused the write")
            return {"_id": f"id-{self.count}", "_index": f".ds-{index}-2026.11.13-000001"}

        async def refresh(self, **_kw: Any) -> None:
            return None

    scenario = _scenario("e4-password-spray-vpn")
    now = datetime.now(UTC)

    grid = SimpleNamespace(_client=_Client())
    written: list[tuple[str, str]] = []
    result = await ingest_scenario(scenario, elastic=grid, run_time=now, written=written)  # type: ignore[arg-type]
    assert len(written) == len(scenario.events) == result.doc_count
    assert result.documents == tuple(written)
    # The address is the concrete index of the write response, with its id.
    assert all(index.startswith(".ds-logs-synth-") for index, _doc_id in written)
    assert [doc_id for _index, doc_id in written] == [f"id-{n}" for n in range(1, len(written) + 1)]

    failing = SimpleNamespace(_client=_Client(fail_at=3))
    partial: list[tuple[str, str]] = []
    with pytest.raises(RuntimeError, match="refused the write"):
        await ingest_scenario(scenario, elastic=failing, run_time=now, written=partial)  # type: ignore[arg-type]
    assert [doc_id for _index, doc_id in partial] == ["id-1", "id-2"]


async def test_run_batch_keeps_a_ledger_of_a_plant_that_failed_part_way(tmp_path: Path) -> None:
    """The documents a failed plant wrote are in the summary and in the ledger."""

    async def _fails_after_two(_scens: Any, *, written: list[tuple[str, str]], **_kw: Any) -> Any:
        written.extend([(_SYNTH_INDEX, "id-1"), (_SYNTH_INDEX, "id-2")])
        raise RuntimeError("the grid refused the write")

    cfg = BatchConfig(
        oql="x",
        n=1,
        concurrency=1,
        out_dir=tmp_path,
        synth_scenarios=(_scenario("e4-password-spray-vpn"),),
        synth_optional=True,
    )
    summary = await run_batch(
        cfg,
        settings=_batch_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=_make_sampler(["real-1"]),
        runner=_make_runner(),
        synth_ingester=_fails_after_two,
    )
    assert "refused the write" in (summary.synth_error or "")
    assert summary.synth_documents == ((_SYNTH_INDEX, "id-1"), (_SYNTH_INDEX, "id-2"))
    assert read_ledger(summary.batch_dir)[1] == list(summary.synth_documents)


async def test_a_plant_by_hand_writes_no_ledger(tmp_path: Path) -> None:
    """Negative control: the nightly must never take back a benchmark's plant.

    ``validate-batch`` plants without the ride-along flag. It gets no ledger, so
    no later nightly finds its documents to delete.
    """

    async def _ingester(scens: Any, **kw: Any) -> list[IngestResult]:
        assert "written" not in kw
        return [
            IngestResult(
                scenario_id=s.id,
                triage_doc_id=f"synth-doc-{s.id}",
                triage_index="logs-synth-suricata-alert",
                doc_count=1,
                documents=((_SYNTH_INDEX, f"synth-doc-{s.id}"),),
            )
            for s in scens
        ]

    cfg = BatchConfig(
        oql="x", n=1, out_dir=tmp_path, synth_scenarios=(_scenario("e4-password-spray-vpn"),)
    )
    summary = await run_batch(
        cfg,
        settings=_batch_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=_make_sampler(["real-1"]),
        runner=_make_runner(),
        synth_ingester=_ingester,
    )
    assert summary.synth_documents == ()
    assert not (summary.batch_dir / LEDGER_NAME).exists()


# --------------------------------------------------------------------
# Verdict agreement: what the low agreement alarm counts
# --------------------------------------------------------------------


def _graded_real(
    alert_id: str, local: str | None, oracle: str | None, **over: Any
) -> dict[str, Any]:
    """One graded real alert: the verdict of the model and the verdict of the Oracle."""
    row = _row(alert_id, verdict=local or "false_positive", agreement="partial")
    row["verdict"] = local
    row["oracle_verdict"] = oracle
    row.update(over)
    return row


def test_verdict_agreement_counts_the_verdict_class_and_nothing_else() -> None:
    """The definition, one row for each case.

    ``needs_more_info`` against a settled verdict is a disagreement in both
    directions. ``inconclusive`` is the same class as ``needs_more_info``: both
    say that the run did not settle the alert.
    """
    rows = [
        _graded_real("a", "true_positive", "true_positive"),
        _graded_real("b", "false_positive", "false_positive"),
        _graded_real("c", "needs_more_info", "needs_more_info"),
        _graded_real("d", "inconclusive", "needs_more_info"),
        _graded_real("e", "false_positive", "needs_more_info"),
        _graded_real("f", "needs_more_info", "false_positive"),
        _graded_real("g", "inconclusive", "true_positive"),
        _graded_real("h", "false_positive", "true_positive"),
        _graded_real("i", "false_positive", "needs_more_info"),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    assert (m.verdict_agree, m.verdict_compared) == (4, 9)
    assert m.verdict_pairs == {
        "false_positive>needs_more_info": 2,
        "needs_more_info>false_positive": 1,
        "inconclusive>true_positive": 1,
        "false_positive>true_positive": 1,
    }
    assert verdict_class("inconclusive") == verdict_class("needs_more_info")
    assert verdict_class("needs_more_info") != verdict_class("false_positive")
    assert verdict_class(None) is None and verdict_class("unknown") is None


def test_a_partial_grade_on_the_same_verdict_is_a_verdict_agreement() -> None:
    """The production shape of 2026-11-13: five ``partial`` grades, five same verdicts.

    Each critique opened "I agree with false_positive" and went on to the
    confidence and the wording. The agreement rate of that night is 0.00. Its
    verdict agreement is 5 of 5.
    """
    rows = _five_real("partial", oracle_verdict="false_positive")
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    assert (m.agreement_rate, m.n_yes, m.n_partial) == (0.0, 0, 5)
    assert (m.verdict_agree, m.verdict_compared, m.verdict_pairs) == (5, 5, {})


def test_runs_that_cannot_be_compared_are_counted_apart() -> None:
    """A run with no verdict has nothing to compare. Neither has a critique with none.

    The first is an error run and is not in the verdict pool at all. The second
    is a completed run, counted apart: it is every critique from before the
    Oracle was asked for its verdict.
    """
    rows = [
        _graded_real("a", None, "false_positive", agreement="no"),
        _graded_real("b", None, None, agreement="partial"),
        _graded_real("c", "false_positive", None, agreement="yes"),
        _graded_real("d", "false_positive", "false_positive"),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    assert (m.n_ok, m.n_error) == (2, 2)
    assert (m.verdict_agree, m.verdict_compared) == (1, 1)
    assert m.n_no_oracle_verdict == 1
    assert m.verdict_pairs == {}


def test_synthetic_rows_and_lost_grades_never_enter_the_verdict_pool() -> None:
    """Real alerts only. A planted run has ground truth and is not graded."""
    planted = _synth_row("e1-emotet-feodo-c2", verdict="false_positive")
    planted["oracle_verdict"] = "true_positive"
    lost = _not_graded_row("x")
    lost["oracle_verdict"] = "true_positive"
    rows = [*_five_real("partial", oracle_verdict="false_positive"), planted, lost]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    assert (m.verdict_agree, m.verdict_compared, m.verdict_pairs) == (5, 5, {})

    # Local mode asks no Oracle, so a stray field cannot invent a comparison.
    local = compute_snapshot_metrics(rows, aggregate(rows), mode="local")
    assert (local.verdict_agree, local.verdict_compared) == (0, 0)


def test_the_oracle_verdict_is_read_from_its_own_line_only() -> None:
    plain = "## 1. Verdict\nAGREEMENT: partial\nORACLE_VERDICT: false_positive\nI agree.\n"
    assert extract_oracle_verdict(plain) == "false_positive"
    marked = "## 1. Verdict\n\n**AGREEMENT:** no\n**ORACLE_VERDICT:** `needs_more_info`\n"
    assert extract_oracle_verdict(marked) == "needs_more_info"
    assert extract_oracle_verdict("ORACLE_VERDICT: TRUE_POSITIVE\n") == "true_positive"
    # Negative control: prose is not a verdict line, and nothing is inferred.
    prose = "## 1. Verdict\nAGREEMENT: partial\nI agree with `false_positive`.\n"
    assert extract_oracle_verdict(prose) is None
    other_section = "## 1. Verdict\nAGREEMENT: yes\n## 2. Why\nORACLE_VERDICT: true_positive\n"
    assert extract_oracle_verdict(other_section) is None
    assert extract_oracle_verdict("ORACLE_VERDICT: maybe\n") is None
    assert extract_oracle_verdict("") is None


def test_the_grader_prompt_asks_for_the_verdict_line_after_the_agreement_line() -> None:
    message = build_user_message(
        alert_id_label="ALERT_01", sanitized_events=[], sanitized_report={"verdict": "x"}
    )
    first = message.index("AGREEMENT: <yes|no|partial>")
    second = message.index("ORACLE_VERDICT: <true_positive|false_positive|needs_more_info>")
    assert first < second
    # The line is a verdict of its own. The prompt keeps the rubric out of it.
    assert "It is separate from AGREEMENT" in message


async def test_the_oracle_verdict_reaches_the_index_row(tmp_path: Path) -> None:
    critique = "## 1. Verdict\nAGREEMENT: partial\nORACLE_VERDICT: needs_more_info\nThin.\n"
    summary = await run_batch(
        BatchConfig(oql="x", n=2, concurrency=1, out_dir=tmp_path),
        settings=_batch_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=_make_sampler(["real-1", "real-2"]),
        runner=_make_runner(canned={"real-1": {"response_md": critique}}),
    )
    rows = {
        r["alert_id"]: r
        for r in map(json.loads, (summary.batch_dir / "index.jsonl").read_text().splitlines())
    }
    assert rows["real-1"]["agreement"] == "partial"
    assert rows["real-1"]["oracle_verdict"] == "needs_more_info"
    # A critique with no verdict line: nothing recorded, nothing guessed.
    assert rows["real-2"]["agreement"] == "yes"
    assert rows["real-2"]["oracle_verdict"] is None


# --------------------------------------------------------------------
# Low verdict agreement: a window of nights against a fixed floor
# --------------------------------------------------------------------


def test_low_verdict_agreement_across_a_window_raises_the_alarm_and_states_the_pairs() -> None:
    """Seven nights, 6 of 35 verdicts the same. No single night is news."""
    history = [_vnight(1) for _ in range(MEDIAN_WINDOW - 1)]
    tonight = _vpoint(
        0, pairs={"false_positive>true_positive": 2, "false_positive>needs_more_info": 3}
    )

    reasons = detect_regression(tonight, history, alarm_drop=0.15)

    assert _codes(reasons) == [CODE_AGREEMENT_LOW]
    message = str(reasons[0])
    assert message.startswith("Verdict agreement is low")
    assert "6 of 35 real alerts" in message
    assert f"{MEDIAN_WINDOW} graded nights" in message
    assert f"{AGREEMENT_FLOOR:.2f}" in message
    # The pairs say what the alarm means. A rate alone does not.
    assert "local false_positive against Oracle needs_more_info: 27" in message
    assert "local false_positive against Oracle true_positive: 2" in message
    assert message.index("needs_more_info: 27") < message.index("true_positive: 2")
    # The drop rule reads this text for its own. The two must stay apart.
    assert "agreement_rate" not in message


def test_the_rubric_score_does_not_feed_the_alarm() -> None:
    """The measure the owner judged invalid must not reach this rule.

    Seven nights where every grade is ``partial`` and every verdict is the
    same: an agreement rate of 0.00 and a verdict agreement of 35 of 35. Then
    the reverse, to show the rule reads the verdict counts and not their
    absence: a full rubric score cannot hide verdicts that differ.
    """
    all_partial = [_vnight(5, n_yes=0, agreement_rate=0.0) for _ in range(MEDIAN_WINDOW - 1)]
    tonight = _vpoint(5, n_yes=0, agreement_rate=0.0, n_partial=5)
    assert detect_regression(tonight, all_partial, alarm_drop=0.15) == []

    all_yes = [_vnight(0, n_yes=5, agreement_rate=1.0) for _ in range(MEDIAN_WINDOW - 1)]
    tonight = _vpoint(0, n_yes=5, agreement_rate=1.0)
    assert _codes(detect_regression(tonight, all_yes, alarm_drop=0.15)) == [CODE_AGREEMENT_LOW]


def test_one_bad_batch_does_not_raise_the_low_agreement_alarm() -> None:
    """Negative control: the noise band of one batch is 0.20 to 0.25.

    Six nights of full verdict agreement and one night with none pool to 30 of
    35. The window is above the floor, so the rule stays silent.
    """
    history = [_vnight(5) for _ in range(MEDIAN_WINDOW - 1)]
    assert detect_regression(_vpoint(0), history, alarm_drop=0.15) == []


def test_low_agreement_needs_three_graded_nights() -> None:
    """Two nights are not a window, however low they are."""
    empty = TrendPoint(agreement_rate=None, fallback_rate=0.0, n_yes=0, n_classified=0)
    history = [_vnight(0), empty, empty, empty, empty, empty, _vnight(0), _vnight(0)]
    # The window holds tonight and the newest six: two graded nights.
    assert MIN_HISTORY == 3
    reasons = detect_regression(_vpoint(0), history, alarm_drop=0.15)
    assert CODE_AGREEMENT_LOW not in _codes(reasons)
    # A third graded night inside the window arms the rule.
    reasons = detect_regression(_vpoint(0), [_vnight(0), _vnight(0), *history], alarm_drop=0.15)
    assert CODE_AGREEMENT_LOW in _codes(reasons)


def test_agreement_at_the_floor_is_silent() -> None:
    """Negative control: the rule needs a window that is surely below the floor."""
    at_floor = [_vnight(3), _vnight(2), _vnight(3), _vnight(2), _vnight(3), _vnight(2)]
    assert detect_regression(_vpoint(2), at_floor, alarm_drop=0.15) == []
    # 10 of 35 is the first count the rule accepts as below one half.
    borderline = [_vnight(2), _vnight(2), _vnight(2), _vnight(2), _vnight(1), _vnight(1)]
    assert _codes(detect_regression(_vpoint(0), borderline, alarm_drop=0.15)) == [
        CODE_AGREEMENT_LOW
    ]
    above = [_vnight(2), _vnight(2), _vnight(2), _vnight(2), _vnight(2), _vnight(1)]
    assert detect_regression(_vpoint(0), above, alarm_drop=0.15) == []


def test_a_low_month_cannot_teach_the_floor_to_accept_it() -> None:
    """The floor is a constant and holds no history.

    A rule that compared the night with a pooled baseline would read thirty low
    nights as the normal level and say nothing about the thirty-first.
    """
    month = [_vnight(1) for _ in range(30)]
    assert _codes(detect_regression(_vpoint(1), month, alarm_drop=0.15)) == [CODE_AGREEMENT_LOW]


def test_local_mode_has_no_agreement_and_no_low_agreement_alarm() -> None:
    history = [TrendPoint(agreement_rate=None, fallback_rate=0.0) for _ in range(10)]
    new = _metrics(mode="local", agreement_rate=None)
    assert detect_regression(new, history, alarm_drop=0.15) == []


def test_a_night_with_no_grade_keeps_the_standing_low_alarm() -> None:
    """A quota night says nothing new. It must not read as a recovery.

    If the window rule needed a grade from tonight, each quota night would
    clear the alarm and the next graded night would raise it again as news.
    """
    history = [_vnight(0) for _ in range(6)]
    tonight = _metrics(agreement_rate=None, n_ok=5, n_classified=0, n_not_graded=5)
    assert _codes(detect_regression(tonight, history, alarm_drop=0.15)) == [CODE_AGREEMENT_LOW]


# The graded production series, 2026-08-22 to 2026-11-13: snapshot ids 44 to
# 133, oldest first, as (n_yes, n_classified, agreement alarm recorded). These
# are RUBRIC counts. A classified count of 0 is a night the Oracle graded
# nothing. The alarms on record are the nights of 2026-09-06 to 09-09.
PROD_SERIES: tuple[tuple[int, int, bool], ...] = (
    (4, 5, False), (3, 5, False), (4, 5, False), (4, 5, False), (4, 5, False),
    (3, 5, False), (4, 5, False), (3, 5, False), (4, 5, False), (3, 5, False),
    (3, 5, False), (3, 5, False), (2, 5, False), (4, 5, False), (3, 5, False),
    (5, 5, False), (4, 5, False), (1, 5, True), (0, 5, True), (0, 5, True),
    (0, 5, True), (2, 5, False), (1, 5, False), (0, 5, True), (1, 5, False),
    (0, 0, False), (0, 0, False), (0, 0, False), (3, 5, False), (2, 5, False),
    (4, 5, False), (1, 5, False), (2, 5, False), (1, 5, False), (3, 5, False),
    (3, 5, False), (3, 5, False), (3, 5, False), (3, 5, False), (2, 5, False),
    (1, 5, False), (0, 5, False), (1, 5, False), (1, 5, False), (1, 5, False),
    (3, 5, False), (1, 5, False), (3, 5, False), (1, 5, False), (1, 5, False),
    (0, 5, False), (1, 5, False), (0, 5, False), (1, 5, False), (1, 5, False),
    (2, 5, False), (0, 5, False), (2, 5, False), (1, 5, False), (0, 5, False),
    (0, 5, False), (1, 5, False), (1, 5, False), (2, 5, False), (1, 5, False),
    (0, 0, False), (0, 0, False), (0, 0, False), (2, 5, False), (1, 5, False),
    (1, 5, False), (1, 5, False), (1, 5, False), (0, 5, False), (0, 5, False),
    (0, 1, False), (0, 5, False), (0, 5, False), (1, 5, False), (0, 0, False),
    (0, 4, False), (1, 5, False), (3, 5, False), (0, 5, False), (0, 0, False),
    (0, 0, False), (1, 5, False), (0, 5, False), (1, 5, False), (0, 5, False),
)  # fmt: skip

# The last 7 graded production runs, 2026-11-05 to 2026-11-13, as
# (rubric yes, rubric classified, verdicts the same, verdicts compared). The
# verdict columns come from reading the verdict section of each of the 35
# critiques: the Oracle stated no verdict line then. 9 critiques were of a run
# that died with no report, 4 on 11-05 and 5 on 11-07, so 26 runs compare. In
# 2 of the 26 the Oracle wrote "false_positive at about 0.65, or
# needs_more_info". They are counted as the same verdict here.
PROD_LAST_SEVEN: tuple[tuple[int, int, int, int], ...] = (
    (1, 5, 1, 1), (3, 5, 5, 5), (0, 5, 0, 0), (1, 5, 5, 5),
    (0, 5, 5, 5), (1, 5, 5, 5), (0, 5, 5, 5),
)  # fmt: skip


def _prod_point(n_yes: int, n: int, alarmed: bool) -> TrendPoint:
    return TrendPoint(
        agreement_rate=(n_yes / n) if n else None,
        fallback_rate=0.0,
        n_yes=n_yes,
        n_classified=n,
        agreement_alarmed=alarmed,
    )


def _replay_prod(code: str) -> list[int]:
    """Indexes of PROD_SERIES where the detector reports ``code``."""
    fired: list[int] = []
    for i, (n_yes, n, _alarmed) in enumerate(PROD_SERIES):
        history = [_prod_point(*p) for p in reversed(PROD_SERIES[:i])]
        new = _metrics(
            agreement_rate=(n_yes / n) if n else None, n_ok=5, n_yes=n_yes, n_classified=n
        )
        if code in _codes(detect_regression(new, history, alarm_drop=0.15)):
            fired.append(i)
    return fired


def test_the_production_rubric_series_does_not_raise_the_verdict_alarm() -> None:
    """90 points of rubric counts as low as 0 of 5, and the rule says nothing.

    The agreement rate of production fell to 26 of 165 over its last 40 nights.
    An alarm on that rate would have fired on the first night after the upgrade
    for a measure that is no gate. None of these rows states a verdict of the
    Oracle, so none is evidence for this rule.
    """
    assert _replay_prod(CODE_AGREEMENT_LOW) == []
    # The drop rule still reads the rubric rate. It is the older rule and is
    # not changed: its replay holds the alarms of 2026-09-06 to 09-09.
    assert _replay_prod(CODE_AGREEMENT_DROP) == [18, 19, 20, 23]


def test_the_last_seven_production_runs_do_not_raise_the_alarm() -> None:
    """Rubric 6 of 35. Verdict agreement 26 of 26. No alarm.

    Negative control beside it: the same seven nights with the two hedged
    critiques read as disagreements give 24 of 26, and still no alarm.
    """
    assert sum(yes for yes, _n, _a, _c in PROD_LAST_SEVEN) == 6
    assert sum(n for _yes, n, _a, _c in PROD_LAST_SEVEN) == 35
    assert sum(a for _yes, _n, a, _c in PROD_LAST_SEVEN) == 26
    assert sum(c for _yes, _n, _a, c in PROD_LAST_SEVEN) == 26

    def _night(yes: int, n: int, agree: int, compared: int) -> TrendPoint:
        return _vnight(agree, compared, n_yes=yes, n_classified=n, agreement_rate=yes / n)

    *earlier, (yes, n, agree, compared) = PROD_LAST_SEVEN
    history = [_night(*night) for night in reversed(earlier)]
    tonight = _vpoint(agree, compared, n_yes=yes, n_classified=n, agreement_rate=yes / n)
    assert CODE_AGREEMENT_LOW not in _codes(detect_regression(tonight, history, alarm_drop=0.15))

    hedged = [_night(1, 5, 4, 5), _night(0, 5, 4, 5), *history[2:]]
    assert CODE_AGREEMENT_LOW not in _codes(detect_regression(tonight, hedged, alarm_drop=0.15))


def test_the_window_rule_uses_the_false_alarm_budget_the_drop_rule_uses() -> None:
    """No new significance level: the binomial tail is tested against ALARM_P."""
    assert ALARM_P == 0.02
    empty = TrendPoint(agreement_rate=None, fallback_rate=0.0, n_yes=0, n_classified=0)
    # 3 of 15 has a tail of 0.018 under one half. 4 of 15 has 0.059.
    fires = [_vnight(1), _vnight(1), empty]
    assert CODE_AGREEMENT_LOW in _codes(detect_regression(_vpoint(1), fires, alarm_drop=0.15))
    holds = [_vnight(2), _vnight(1), empty]
    assert CODE_AGREEMENT_LOW not in _codes(detect_regression(_vpoint(1), holds, alarm_drop=0.15))


# --------------------------------------------------------------------
# A lost grade is not a triage failure
# --------------------------------------------------------------------


def test_a_quota_night_is_not_measured_and_is_not_a_triage_failure() -> None:
    """Production, 2026-11-02, 11-08 and 11-09: five runs, five 429 answers.

    The investigations completed. The Oracle refused the grade requests. The
    trend recorded ``error_rate 1.00 exceeds the 0.30 ceiling``.
    """
    rows = [_not_graded_row(a) for a in "abcde"]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    assert (m.n_ok, m.n_error, m.error_rate) == (5, 0, 0.0)
    assert m.verdict_counts == {"false_positive": 5}
    assert m.agreement_rate is None and m.n_classified == 0
    assert (m.n_not_graded, m.not_graded_kinds) == (5, {"quota": 5})

    history = [_low(4) for _ in range(10)]
    assert detect_regression(m, history, alarm_drop=0.15) == []

    sentence = not_measured_text(m)
    assert sentence is not None
    assert sentence.startswith("Agreement is not measured.")
    assert "The Oracle graded 0 of 5 runs." in sentence
    assert "The Oracle quota is used up." in sentence


def test_a_night_of_failed_investigations_still_raises_the_error_alarm() -> None:
    """Negative control: the guard must hold on the path the fix would loosen.

    A gateway that cannot reach the model engine fails the investigation, and
    the run never reaches the grader. That is a triage failure and stays one.
    """
    rows = [_row(a, error="ModelHTTPError: status_code: 502") for a in "abcde"]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    assert (m.n_error, m.error_rate, m.n_not_graded) == (5, 1.0, 0)
    assert not_measured_text(m) is None
    reasons = detect_regression(m, [_low(4) for _ in range(10)], alarm_drop=0.15)
    assert _codes(reasons) == [CODE_ERROR_CEILING]


def test_each_cause_of_a_lost_grade_has_its_own_sentence() -> None:
    quota = [_not_graded_row(a, kind="quota") for a in "ab"]
    gateway = [_not_graded_row(a, kind="gateway") for a in "cd"]
    refusal = [_not_graded_row("e", kind="refusal")]
    for rows, sentence in (
        (quota, "The Oracle quota is used up."),
        (gateway, "The Oracle gateway returned an error."),
        (refusal, "The sanitizer check stopped the send to the Oracle."),
    ):
        m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
        assert sentence in (not_measured_text(m) or "")


def test_a_night_with_some_grades_is_measured_and_states_the_loss() -> None:
    """Production, 2026-10-28: one run graded, four lost to a 502 from the gateway."""
    rows = [_row("a", agreement="partial"), *[_not_graded_row(x, kind="gateway") for x in "bcde"]]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    assert (m.n_classified, m.n_not_graded, m.error_rate) == (1, 4, 0.0)
    sentence = not_measured_text(m)
    assert sentence is not None
    assert not sentence.startswith("Agreement is not measured.")
    assert "The Oracle graded 1 of 5 runs." in sentence


def test_local_mode_never_reports_a_lost_grade() -> None:
    rows = _five_real()
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")
    assert not_measured_text(m) is None


def test_nightly_reports_a_quota_night_as_not_measured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = _settings(oracle_enabled=True)
    _seed_snapshots(settings, [_graded_row(0.8) for _ in range(5)])
    captured = _wire_nightly(monkeypatch, settings, [_not_graded_row(a) for a in "abcde"])

    assert cli._eval_nightly(_args(tmp_path)) == 0

    snapshot = _read_snapshots(settings)[0]
    assert snapshot.alarmed is False and snapshot.alarm_key is None
    assert (snapshot.n_ok, snapshot.n_error, snapshot.error_rate) == (5, 0, 0.0)
    assert snapshot.agreement_rate is None
    assert snapshot.detail["not_graded"] == {"n": 5, "kinds": {"quota": 5}}
    assert "The Oracle quota is used up." in snapshot.detail["not_measured"]
    assert captured["alarm"] is None
    assert "Agreement is not measured." in capsys.readouterr().err


# --------------------------------------------------------------------
# A run with no result is an error, with a cause class
# --------------------------------------------------------------------

_GATEWAY_TEXT = "status_code: 500, model_name: analyst-a, body: Cannot connect to host"


def _dead_row(alert_id: str, *, agreement: str = "no", **over: Any) -> dict[str, Any]:
    """A run that died on the model gateway and left no report.

    The harness returned, so the row carries no ``error``. The Oracle still
    graded the partial trail, which is how the rubric came to hold a grade for
    a run with no verdict.
    """
    row = _row(alert_id, agreement=agreement)
    row.update(
        verdict=None, confidence=None, run_error_type="ModelHTTPError", run_error=_GATEWAY_TEXT
    )
    row.update(over)
    return row


def test_a_run_with_no_report_is_an_error_with_its_class() -> None:
    """Production, 2026-11-07: 5 of 5 runs died on a gateway error.

    The snapshot recorded 5 completed runs, ``error_rate 0.00`` and no alarm,
    with an agreement rate of 0.00 from five grades of runs that had no verdict.
    """
    grades = ("no", "partial", "partial", "no", "no")
    rows = [_dead_row(a, agreement=g) for a, g in zip("abcde", grades, strict=True)]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    assert (m.n_ok, m.n_error, m.error_rate) == (0, 5, 1.0)
    assert m.error_classes == {"gateway": 5}
    assert m.verdict_counts == {}
    # A grade of a run with no verdict is not a grade of a verdict.
    assert (m.agreement_rate, m.n_classified, m.n_yes, m.n_no) == (None, 0, 0, 0)
    assert not_measured_text(m) is None

    reasons = detect_regression(m, [_low(4) for _ in range(5)], alarm_drop=0.15)
    assert _codes(reasons) == [CODE_ERROR_CEILING]
    assert str(reasons[0]) == (
        "error_rate 1.00 exceeds the 0.30 ceiling. 5 of 5 runs ended with no result: gateway 5"
    )


def test_each_error_class_is_read_from_what_the_run_recorded() -> None:
    cases = [
        ("ModelHTTPError", _GATEWAY_TEXT, "gateway"),
        ("ModelHTTPError", "status_code: 429, body: rate limit", "gateway"),
        ("ReadTimeout", "The read operation timed out", "gateway"),
        (None, "ModelHTTPError: status_code: 502, model_name: analyst-a", "gateway"),
        (
            "UnexpectedModelBehavior",
            "Model token limit (32000) exceeded before any response was generated",
            "token_limit",
        ),
        ("TimeoutError", "", "time_limit"),
        ("CancelledError", "", "time_limit"),
        (None, "timeout after 1800s", "time_limit"),
        ("ValueError", "bad alert id", "other"),
        (None, None, "other"),
    ]
    for error_type, message, expected in cases:
        assert classify_run_error(error_type, message) == expected, (error_type, message)


def test_a_fallback_run_and_a_run_that_raised_are_both_errors() -> None:
    """A fallback carries a verdict and the status of a completed run. It is neither."""
    fallback = _row("a", verdict="needs_more_info", is_fallback=True)
    fallback.update(run_error_type="UnexpectedModelBehavior", run_error="Model token limit (32000)")
    rows = [
        fallback,
        _row("b", error="timeout after 1800s"),
        _row("c", error="ModelHTTPError: status_code: 502, model_name: analyst-a"),
        _row("d"),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")

    assert [run_outcome(r) for r in rows] == ["error", "error", "error", "completed"]
    assert (m.n_ok, m.n_error, m.error_rate) == (1, 3, 0.75)
    assert m.error_classes == {"token_limit": 1, "time_limit": 1, "gateway": 1}
    # The placeholder verdict of the fallback is not in the distribution.
    assert m.verdict_counts == {"false_positive": 1}
    # The fallback rule keeps its own number: 1 of the 2 runs with a report.
    assert m.fallback_rate == 0.5


def test_a_run_with_a_report_and_a_verdict_is_completed_with_any_verdict() -> None:
    """Negative control: the rule removes a run with no result and no other run."""
    rows = [
        _row("a", verdict="true_positive"),
        _row("b", verdict="false_positive"),
        _row("c", verdict="needs_more_info"),
        _row("d", verdict="inconclusive"),
    ]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")
    assert (m.n_ok, m.n_error, m.error_rate, m.error_classes) == (4, 0, 0.0, {})
    assert m.verdict_counts == {
        "true_positive": 1,
        "false_positive": 1,
        "needs_more_info": 1,
        "inconclusive": 1,
    }
    assert detect_regression(m, [_low(4) for _ in range(5)], alarm_drop=0.15) == []


def test_a_lost_grade_and_a_dead_run_are_two_classes() -> None:
    """A run the Oracle did not grade stays not measured. A dead run is an error.

    The third row is both: it died, and its grade request also failed. It is an
    error and is not counted as a lost grade, because it had no verdict to grade.
    """
    dead_and_ungraded = _dead_row("c", agreement="unknown")
    dead_and_ungraded.update(grader_error="LiteLLM returned 429", grader_error_kind="quota")
    rows = [_not_graded_row("a"), _dead_row("b"), dead_and_ungraded, _row("d")]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    assert (m.n_ok, m.n_error) == (2, 2)
    assert m.error_classes == {"gateway": 2}
    assert (m.n_not_graded, m.not_graded_kinds) == (1, {"quota": 1})
    assert "The Oracle graded 1 of 2 runs." in (not_measured_text(m) or "")


def test_a_run_that_never_ended_is_neither_an_error_nor_a_completed_run() -> None:
    """The failure budget stopped the batch before two runs started."""
    rows = [
        _row("a"),
        _row("b", error="ModelHTTPError: status_code: 502"),
        _row("c", error=NOT_RUN_ERROR),
    ]
    assert run_outcome(rows[2]) == "unfinished"
    # Five runs were planned. One more never wrote a row at all.
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local", n_planned=4)

    assert (m.n_ok, m.n_error, m.n_unfinished) == (1, 1, 2)
    assert m.error_rate == 0.5
    assert m.error_classes == {"gateway": 1}
    detail = snapshot_detail(m, configured_model="analyst-a")
    assert detail["runs"] == {"completed": 1, "errors": 1, "unfinished": 2}
    assert detail["error_classes"] == {"gateway": 1}


def test_a_synthetic_run_that_died_is_not_measured_and_is_not_a_miss() -> None:
    """Negative control for the miss rule: no verdict is no answer."""
    planted = _synth_row("e4-password-spray-vpn")
    planted.update(
        verdict=None, confidence=None, run_error_type="ModelHTTPError", run_error=_GATEWAY_TEXT
    )
    rows = [*_five_real(), planted]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="graded")

    assert [(o.outcome, o.cause) for o in m.synth] == [("not_measured", _GATEWAY_TEXT)]
    assert detect_regression(m, [], alarm_drop=0.15) == []
    # The synthetic run is not in the numbers of the real alerts.
    assert (m.n_ok, m.n_error) == (5, 0)


def test_the_run_error_is_the_last_error_event_of_the_run() -> None:
    events = [
        ("session_start", {"alert_id": "x"}),
        ("error", {"phase": "synth_first_round1", "type": "ValueError", "message": "first"}),
        (
            "error",
            {"phase": "investigation_loop", "type": "ModelHTTPError", "message": _GATEWAY_TEXT},
        ),
        ("done", {"status": "error"}),
    ]
    assert run_error_from_events(events) == ("ModelHTTPError", _GATEWAY_TEXT)
    assert run_error_from_events([("done", {"status": "ok"})]) == (None, None)
    assert run_error_from_events([("error", "not a mapping")]) == (None, None)


async def test_the_index_row_records_why_a_run_left_no_verdict(tmp_path: Path) -> None:
    """From the last error event for a run with no report, and from a fallback report."""

    async def _runner(alert_id: str, *, settings: Any, out_dir: Path, **_kw: Any) -> Any:
        result = _stub_eval_result(out_dir / f"bundle-{alert_id}", response_md="")
        if alert_id == "dead":
            result.sanitized_report = None
            result.run_error_type, result.run_error = "ModelHTTPError", _GATEWAY_TEXT
        if alert_id == "fallback":
            result.sanitized_report = {
                "verdict": "needs_more_info",
                "confidence": 0.3,
                "summary": "Synth-first pipeline fallback: round 1 raised UnexpectedModelBehavior.",
                "resolution": {
                    "provenance": "pipeline_fallback",
                    "error_type": "UnexpectedModelBehavior",
                },
            }
        return result

    summary = await run_batch(
        BatchConfig(oql="x", n=3, concurrency=1, out_dir=tmp_path),
        settings=_batch_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=_make_sampler(["dead", "fallback", "fine"]),
        runner=_runner,
    )
    rows = {
        r["alert_id"]: r
        for r in map(json.loads, (summary.batch_dir / "index.jsonl").read_text().splitlines())
    }
    assert (rows["dead"]["verdict"], rows["dead"]["error"]) == (None, None)
    assert (rows["dead"]["run_error_type"], rows["dead"]["run_error"]) == (
        "ModelHTTPError",
        _GATEWAY_TEXT,
    )
    assert rows["fallback"]["is_fallback"] is True
    assert rows["fallback"]["run_error_type"] == "UnexpectedModelBehavior"
    assert (rows["fine"]["run_error_type"], rows["fine"]["run_error"]) == (None, None)
    assert [run_outcome(rows[k]) for k in ("dead", "fallback", "fine")] == [
        "error",
        "error",
        "completed",
    ]


def test_nightly_reports_a_night_of_dead_runs_as_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The whole path for the night of 2026-11-07: the row, the alarm and the line."""
    settings = _settings(oracle_enabled=True, quality_nightly_synth_n=0)
    _seed_snapshots(settings, [_graded_row(0.8) for _ in range(5)])
    captured = _wire_nightly(monkeypatch, settings, [_dead_row(a) for a in "abcde"])

    assert cli._eval_nightly(_args(tmp_path)) == 0

    snapshot = _read_snapshots(settings)[0]
    assert (snapshot.n_ok, snapshot.n_error, snapshot.error_rate) == (0, 5, 1.0)
    assert snapshot.agreement_rate is None
    assert snapshot.alarm_key == CODE_ERROR_CEILING
    assert "gateway 5" in snapshot.alarm_reasons[0]
    assert snapshot.detail["runs"] == {"completed": 0, "errors": 5, "unfinished": 0}
    assert snapshot.detail["error_classes"] == {"gateway": 5}
    assert snapshot.detail["not_measured"] is None
    assert captured["alarm"] is not None
    assert "5 of 5 runs ended with no result: gateway 5." in capsys.readouterr().err


# --------------------------------------------------------------------
# The harness: a failed grade request keeps the investigation
# --------------------------------------------------------------------


def _quota_caller(**_kw: Any) -> OracleResponse:
    raise OracleError(
        'LiteLLM returned 429: {"error":{"message":"Claude Max rate limit reached"}}',
        status_code=429,
    )


async def test_harness_keeps_the_investigation_when_the_grade_request_fails(
    tmp_path: Path,
    patch_investigate: list[Any],  # noqa: F811
) -> None:
    result = await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_harness_settings(),
        out_dir=tmp_path,
        oracle_caller=_quota_caller,
        tolerate_grader_failure=True,
    )

    assert result.grader_error_kind == "quota"
    assert "429" in (result.grader_error or "")
    assert (result.sanitized_report or {})["verdict"] == "false_positive"
    assert result.response_md == ""
    meta = json.loads((result.bundle_dir / "meta.json").read_text())
    assert meta["grader_error_kind"] == "quota"
    assert (result.bundle_dir / "events.jsonl").exists()


async def test_harness_still_raises_on_a_failed_grade_request_by_default(
    tmp_path: Path,
    patch_investigate: list[Any],  # noqa: F811
) -> None:
    """Negative control: ``validate`` and ``validate-batch`` asked for the grade."""
    with pytest.raises(GraderError, match="LiteLLM/oracle call failed") as caught:
        await harness_run(
            "KDG7CZ4BVBs3R9hXQbPY",
            settings=_harness_settings(),
            out_dir=tmp_path,
            oracle_caller=_quota_caller,
        )
    assert caught.value.kind == "quota"
    assert isinstance(caught.value, RuntimeError)


async def test_harness_separates_a_gateway_fault_from_the_quota(
    tmp_path: Path,
    patch_investigate: list[Any],  # noqa: F811
) -> None:
    def _bad_gateway(**_kw: Any) -> OracleResponse:
        raise OracleError("LiteLLM returned 502: ", status_code=502)

    result = await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_harness_settings(),
        out_dir=tmp_path,
        oracle_caller=_bad_gateway,
        tolerate_grader_failure=True,
    )
    assert result.grader_error_kind == "gateway"


async def test_a_lost_grade_reaches_the_index_row_as_a_completed_run(tmp_path: Path) -> None:
    """The row keeps its verdict and is not an error row."""

    async def _runner(alert_id: str, *, settings: Any, out_dir: Path, **_kw: Any) -> Any:
        result = await _make_runner(canned={alert_id: {"response_md": ""}})(
            alert_id, settings=settings, out_dir=out_dir
        )
        result.grader_error = "LiteLLM/oracle call failed: LiteLLM returned 429"
        result.grader_error_kind = "quota"
        result.served = [{"model": "analyst-a", "backend": "engine.example:8000"}]
        return result

    summary = await run_batch(
        BatchConfig(oql="x", n=1, concurrency=1, out_dir=tmp_path),
        settings=_batch_settings(),
        elastic=None,  # type: ignore[arg-type]
        sampler=_make_sampler(["real-1"]),
        runner=_runner,
    )
    row = json.loads((summary.batch_dir / "index.jsonl").read_text().splitlines()[0])
    assert row["error"] is None and row["verdict"] == "false_positive"
    assert row["agreement"] == "unknown"
    assert row["grader_error_kind"] == "quota"
    assert row["served"] == [{"model": "analyst-a", "backend": "engine.example:8000"}]
    assert (summary.n_ok, summary.n_error) == (1, 0)


# --------------------------------------------------------------------
# The served model
# --------------------------------------------------------------------


def _usage(model_group: str, api_base: str | None = None, **extra: Any) -> dict[str, Any]:
    backend: dict[str, Any] = {"model_group": model_group}
    if api_base:
        backend["api_base"] = api_base
    return {"phase": "synthesizer", "round": 1, "served_backend": backend, **extra}


def test_the_served_model_comes_from_what_the_run_records() -> None:
    """The gateway names the route and the engine in its response headers."""
    payloads = [
        {"alert_id": "x"},
        _usage("analyst-a", "http://engine.example:8000/v1"),
        _usage("analyst-a", "http://engine.example:8000/v1"),
    ]
    assert served_models_from_events(payloads) == [
        {"model": "analyst-a", "backend": "engine.example:8000"}
    ]


def test_a_run_that_changed_route_records_both() -> None:
    """Production, 2026-11-03: one batch, two routes under one configured name."""
    payloads = [
        _usage("analyst-a", "http://engine.example:8000"),
        _usage("analyst-temp-fallback", "http://spare.example:8006"),
    ]
    assert served_models_from_events(payloads) == [
        {"model": "analyst-a", "backend": "engine.example:8000"},
        {"model": "analyst-temp-fallback", "backend": "spare.example:8006"},
    ]


def test_a_served_model_field_on_the_run_wins_over_the_route_name() -> None:
    """A run may carry a ``served_model`` field of its own. Read it by name."""
    payloads = [
        {"served_model": "analyst-b", "served_backend": {"model_group": "analyst-a"}},
        {"verdict": "false_positive", "served_model": "analyst-b"},
    ]
    assert served_models_from_events(payloads) == [{"model": "analyst-b"}]


def test_the_per_run_record_is_read_by_name_and_merged_with_the_gateway_record() -> None:
    """The per-run record holds the model groups. The usage events hold the address.

    The two name the same routes. Each route is listed one time, with its
    address when an event gave one. The ``configured`` key is not a served name.
    """
    record = {
        "configured": "analyst-a",
        "model_groups": ["analyst-temp-fallback", "analyst-a"],
        "fallback": True,
    }
    assert served_models_from_events([{"verdict": "true_positive", "served_model": record}]) == [
        {"model": "analyst-temp-fallback"},
        {"model": "analyst-a"},
    ]
    payloads = [
        _usage("analyst-a", "http://engine.example:8000"),
        {"verdict": "true_positive", "served_model": record},
    ]
    assert served_models_from_events(payloads) == [
        {"model": "analyst-a", "backend": "engine.example:8000"},
        {"model": "analyst-temp-fallback"},
    ]
    # Negative control: a record with only the configured name names no served model.
    assert served_models_from_events([{"served_model": {"configured": "analyst-a"}}]) == []


def test_no_record_gives_no_served_model() -> None:
    """Negative control: nothing is invented from the configured name here."""
    assert served_models_from_events([{"alert_id": "x"}, {"phase": "synthesizer"}]) == []
    assert served_models_from_events([{"served_backend": "not-a-dict", "served_model": 7}]) == []
    # Credentials in a backend address never reach the record.
    assert served_models_from_events(
        [_usage("analyst-a", "https://user:secret@engine.example:8443/v1")]
    ) == [{"model": "analyst-a", "backend": "engine.example:8443"}]


def test_the_snapshot_counts_the_runs_of_each_served_model() -> None:
    rows = _five_real()
    for row in rows[:3]:
        row["served"] = [{"model": "analyst-a", "backend": "engine.example:8000"}]
    rows[3]["served"] = [{"model": "analyst-temp-fallback", "backend": "spare.example:8006"}]
    rows[4]["served"] = [{"model": "analyst-a", "backend": "engine.example:8888"}]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")

    detail = snapshot_detail(m, configured_model="analyst-a")
    assert detail["served_recorded"] is True
    assert detail["served"] == [
        {"model": "analyst-a", "backend": "engine.example:8000", "runs": 3, "recorded": True},
        {"model": "analyst-a", "backend": "engine.example:8888", "runs": 1, "recorded": True},
        {
            "model": "analyst-temp-fallback",
            "backend": "spare.example:8006",
            "runs": 1,
            "recorded": True,
        },
    ]


def test_a_snapshot_with_no_record_falls_back_to_the_configured_model() -> None:
    """The fallback carries a mark, so the configured name is not read as served."""
    rows = _five_real()
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")
    detail = snapshot_detail(m, configured_model="analyst-a")
    assert detail["served_recorded"] is False
    assert detail["served"] == [
        {"model": "analyst-a", "backend": None, "runs": 5, "recorded": False}
    ]

    # Negative control: one run with a record does not clear the mark of the rest.
    rows[0]["served"] = [{"model": "analyst-b"}]
    m = compute_snapshot_metrics(rows, aggregate(rows), mode="local")
    detail = snapshot_detail(m, configured_model="analyst-a")
    assert detail["served_recorded"] is False
    assert detail["served"] == [
        {"model": "analyst-b", "backend": None, "runs": 1, "recorded": True},
        {"model": "analyst-a", "backend": None, "runs": 4, "recorded": False},
    ]

    # No completed run: nothing served, and nothing to mark.
    failed = [_row(a, error="boom") for a in "ab"]
    m = compute_snapshot_metrics(failed, aggregate(failed), mode="local")
    detail = snapshot_detail(m, configured_model="analyst-a")
    assert (detail["served"], detail["served_recorded"]) == ([], None)


async def test_harness_records_the_served_model_before_the_sanitizer_runs(
    tmp_path: Path,
    patch_investigate: list[Any],  # noqa: F811
) -> None:
    """The sanitizer rewrites host names. The record must hold the real route."""
    from soc_ai.agent.orchestrator import StepEvent

    patch_investigate.insert(
        5,
        StepEvent(
            kind="usage",
            session_id="sess0001",
            sequence=99,
            payload=_usage("analyst-a", "http://engine.example:8000/v1"),
        ),
    )
    result = await harness_run(
        "KDG7CZ4BVBs3R9hXQbPY",
        settings=_harness_settings(),
        out_dir=tmp_path,
        oracle_caller=_stub_oracle("ok"),
    )
    assert result.served == [{"model": "analyst-a", "backend": "engine.example:8000"}]


def test_nightly_keeps_the_configured_model_and_adds_the_served_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings(ANALYST_MODEL="analyst-a", quality_nightly_synth_n=0)
    rows = _five_real()
    for row in rows:
        row["served"] = [{"model": "analyst-b", "backend": "engine.example:8888"}]
    _wire_nightly(monkeypatch, settings, rows)

    assert cli._eval_nightly(_args(tmp_path)) == 0

    snapshot = _read_snapshots(settings)[0]
    assert snapshot.analyst_model == "analyst-a"
    assert snapshot.detail["served_recorded"] is True
    assert snapshot.detail["served"] == [
        {"model": "analyst-b", "backend": "engine.example:8888", "runs": 5, "recorded": True}
    ]


# --------------------------------------------------------------------
# The notification gate: a new condition is news, a cleared one is not
# --------------------------------------------------------------------


def test_each_alarm_code_is_one_condition() -> None:
    """The two agreement rules read different measures, so they are two conditions."""
    assert alarm_conditions("agreement_drop") != alarm_conditions("agreement_low")
    assert alarm_conditions("agreement_low+synth_miss") == {"agreement_low", "synth_miss"}
    assert alarm_conditions(None) == frozenset()


def _run_nightlies(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    tmp_path: Path,
    nights: list[dict[str, Any]],
    *,
    clock: _Clock,
) -> list[dict[str, Any]]:
    """Consecutive nightlies over one real store. Returns the alarm hand-offs."""
    handoffs: list[dict[str, Any]] = []
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(nightly_mod, "_loaded_blocklist", lambda _settings: _NO_FEEDS)
    monkeypatch.setattr("soc_ai.so_client.elastic.ElasticClient", _FakeElastic)
    monkeypatch.setattr("soc_ai.store.auth.utcnow", clock)

    async def _fake_alarm(_settings: Settings, **kw: Any) -> None:
        handoffs.append(kw)

    async def _fake_delete(_elastic: Any, documents: Any) -> Any:
        return len(list(documents)), []

    monkeypatch.setattr(cli, "_fire_quality_alarm", _fake_alarm)
    monkeypatch.setattr("soc_ai.eval.synth_ingest.delete_synth_documents", _fake_delete)
    for night in nights:
        monkeypatch.setattr("soc_ai.eval.batch.run_batch", _stub_nightly_batch(**night))
        assert cli._eval_nightly(_args(tmp_path)) == 0
        clock.now += timedelta(days=1)
    return handoffs


def _low_history() -> list[dict[str, Any]]:
    """Six stored nights where the Oracle reached the model's verdict for 1 of 5 alerts.

    The rubric rate of each is 0.00, the rate of the nights that follow, so the
    drop rule has nothing to report and the tests read the verdict rule alone.
    """
    record = {"agree": 1, "compared": 5, "pairs": {_FP_NMI: 4}}
    return [_graded_row(0.0, detail={"verdict_agreement": record}) for _ in range(6)]


def _disputed() -> list[dict[str, Any]]:
    """Five real alerts closed as false positives that the Oracle would not close."""
    return _five_real("partial", oracle_verdict="needs_more_info")


def test_a_low_week_notifies_once_and_holds_its_start_date(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings(oracle_enabled=True)
    _seed_snapshots(settings, _low_history())
    clock = _Clock(datetime(2026, 11, 10, 3, 0))
    low_night = {"real_rows": _disputed()}

    handoffs = _run_nightlies(monkeypatch, settings, tmp_path, [low_night] * 3, clock=clock)

    rows = _read_snapshots(settings)[:3]
    assert {r.alarm_key for r in rows} == {CODE_AGREEMENT_LOW}
    assert {r.alarm_since for r in rows} == {datetime(2026, 11, 10, 3, 0)}
    assert len(handoffs) == 1
    assert "Verdict agreement is low" in handoffs[0]["reasons"][0]
    assert "local false_positive against Oracle needs_more_info" in handoffs[0]["reasons"][0]
    # The window read the counts the earlier nights stored, and stored its own.
    assert rows[0].detail["verdict_agreement"] == {
        "agree": 0,
        "compared": 5,
        "pairs": {_FP_NMI: 5},
        "no_oracle_verdict": 0,
    }


def test_a_miss_beside_a_standing_alarm_is_news_and_its_end_is_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Three nights: low agreement, low agreement with a miss, low agreement.

    The miss is a new condition and notifies. The night after it holds only the
    condition that already notified. Under a gate that compares whole keys that
    night would notify a third time, for nothing new.
    """
    settings = _settings(oracle_enabled=True)
    _seed_snapshots(settings, _low_history())
    clock = _Clock(datetime(2026, 11, 10, 3, 0))
    low = {"real_rows": _disputed()}
    low_and_miss = {"real_rows": _disputed(), "synth_verdict": "false_positive"}

    handoffs = _run_nightlies(
        monkeypatch, settings, tmp_path, [low, low_and_miss, low], clock=clock
    )

    third, second, first = _read_snapshots(settings)[:3]
    assert [first.alarm_key, second.alarm_key, third.alarm_key] == [
        "agreement_low",
        "agreement_low+synth_miss",
        "agreement_low",
    ]
    assert len(handoffs) == 2
    assert "missed the synthetic true positive" in handoffs[1]["reasons"][0]
    # The low agreement began on the first night. The date does not move.
    assert {first.alarm_since, second.alarm_since, third.alarm_since} == {
        datetime(2026, 11, 10, 3, 0)
    }


def test_a_miss_after_a_clean_night_is_news_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings(oracle_enabled=True)
    clock = _Clock(datetime(2026, 11, 10, 3, 0))
    miss = {"real_rows": _five_real(), "synth_verdict": "false_positive"}
    clean = {"real_rows": _five_real()}

    handoffs = _run_nightlies(monkeypatch, settings, tmp_path, [miss, clean, miss], clock=clock)

    third, second, first = _read_snapshots(settings)[:3]
    assert (second.alarmed, second.alarm_key, second.alarm_since) == (False, None, None)
    assert first.alarm_since == datetime(2026, 11, 10, 3, 0)
    assert third.alarm_since == datetime(2026, 11, 12, 3, 0)
    assert len(handoffs) == 2


# --------------------------------------------------------------------
# The store and the API read-model
# --------------------------------------------------------------------


async def test_migration_adds_the_detail_column_and_removes_it(tmp_path: Path) -> None:
    from alembic import command
    from soc_ai.store.db import _migration_config

    settings = _settings(soc_ai_data_dir=tmp_path)
    engine = make_engine(settings)
    await run_migrations(engine)

    def _columns(sync_conn: Any) -> set[str]:
        return {c["name"] for c in inspect(sync_conn).get_columns("quality_snapshots")}

    def _downgrade(sync_conn: Any) -> None:
        cfg = _migration_config()
        cfg.attributes["connection"] = sync_conn
        command.downgrade(cfg, "0065")

    async with engine.connect() as conn:
        assert "detail" in await conn.run_sync(_columns)
        head = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert head.scalar_one() == "0076"
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade)
    async with engine.connect() as conn:
        assert "detail" not in await conn.run_sync(_columns)
    await engine.dispose()


def test_a_row_from_before_the_column_reads_as_no_detail(tmp_path: Path) -> None:
    """NULL means that nothing was recorded. It is a real SQL absence."""
    settings = _settings(soc_ai_data_dir=tmp_path)
    _seed_snapshots(settings, [_graded_row(0.8)])
    assert _read_snapshots(settings)[0].detail is None

    async def _raw() -> Any:
        engine = make_engine(settings)
        try:
            async with make_sessionmaker(engine)() as db:
                return await db.scalar(text("SELECT detail FROM quality_snapshots"))
        finally:
            await engine.dispose()

    assert asyncio.run(_raw()) is None


def test_trend_exposes_the_plant_the_served_model_and_the_lost_grades(
    client: TestClient,  # noqa: F811
) -> None:
    detail = {
        "served": [
            {"model": "analyst-b", "backend": "engine.example:8888", "runs": 5, "recorded": True}
        ],
        "served_recorded": True,
        "synth": [
            {
                "scenario_id": "e1-emotet-feodo-c2",
                "outcome": "missed",
                "verdict": "false_positive",
                "confidence": 0.85,
                "cause": None,
            }
        ],
        "synth_note": None,
        "synth_ineligible": [
            {
                "scenario_id": "e2-urlhaus-pe-delivery",
                "reason": "the blocklist urlhaus is not loaded",
            }
        ],
        "synth_ineligible_note": (
            "e2-urlhaus-pe-delivery is not eligible: the blocklist urlhaus is not loaded."
        ),
        "not_graded": {"n": 5, "kinds": {"quota": 5}},
        "not_measured": (
            "Agreement is not measured. The Oracle graded 0 of 5 runs. The Oracle quota is used up."
        ),
        "verdict_agreement": {
            "agree": 3,
            "compared": 5,
            "pairs": {_FP_NMI: 2},
            "no_oracle_verdict": 0,
        },
        "runs": {"completed": 4, "errors": 5, "unfinished": 1},
        "error_classes": {"gateway": 4, "time_limit": 1},
    }
    _seed(client, [_snap(agreement_rate=None, analyst_model="analyst-a", detail=detail)])

    point = client.get("/api/v1/quality/trend").json()["points"][0]

    assert point["analyst_model"] == "analyst-a"
    assert point["served_models"] == detail["served"]
    assert point["served_model_recorded"] is True
    assert point["synth"] == detail["synth"]
    assert point["synth_note"] is None
    assert point["synth_ineligible"] == detail["synth_ineligible"]
    assert point["synth_ineligible_note"] == detail["synth_ineligible_note"]
    assert point["n_not_graded"] == 5
    assert point["not_graded_kinds"] == {"quota": 5}
    assert point["not_measured"] == detail["not_measured"]
    assert (point["verdict_agree"], point["verdict_compared"]) == (3, 5)
    assert point["verdict_disagreements"] == {_FP_NMI: 2}
    assert point["n_no_oracle_verdict"] == 0
    assert point["error_classes"] == {"gateway": 4, "time_limit": 1}
    assert point["n_unfinished"] == 1


def test_trend_serves_honest_absences_for_a_row_with_no_detail(
    client: TestClient,  # noqa: F811
) -> None:
    """An older row recorded none of this. It must not read as a clean answer."""
    _seed(client, [_snap()])
    point = client.get("/api/v1/quality/trend").json()["points"][0]
    assert point["served_models"] == []
    assert point["served_model_recorded"] is None
    assert point["synth"] == []
    assert (point["synth_ineligible"], point["synth_ineligible_note"]) == ([], None)
    assert point["n_not_graded"] is None
    assert point["not_measured"] is None
    assert (point["verdict_agree"], point["verdict_compared"]) == (None, None)
    assert point["verdict_disagreements"] == {}
    assert (point["error_classes"], point["n_unfinished"]) == ({}, None)


def test_the_clock_of_the_plant_is_aware_utc(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The scenario events are stamped relative to this time on the grid."""
    settings = _settings()
    captured = _wire_nightly(monkeypatch, settings, _five_real())
    assert cli._eval_nightly(_args(tmp_path)) == 0
    run_time = captured["cfg"].synth_run_time
    assert run_time.tzinfo is not None
    assert abs(datetime.now(UTC) - run_time) < timedelta(minutes=5)


# --------------------------------------------------------------------
# The real path: nightly, batch runner, ingester and renderer together
# --------------------------------------------------------------------


class _RecordingGrid:
    """A grid double that records every write and every delete.

    Only the grid and the harness are doubles in the test below. The nightly,
    the batch runner, the ingester and the scenario renderer are the real code,
    because a double of the batch runner cannot show that the key the nightly
    asks for is the key the documents carry.

    It has ``delete`` by id and no ``delete_by_query``. A call to the second
    raises ``AttributeError`` and fails the test.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.indexed: list[dict[str, Any]] = []
        self.deletes: list[tuple[str, str]] = []
        self._client = self
        self.indices = self

    async def index(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        doc_id = f"planted-{len(self.indexed) + 1}"
        stored_in = f".ds-{index}-2026.11.13-000001"
        self.indexed.append({"index": index, "body": body, "address": (stored_in, doc_id)})
        return {"_id": doc_id, "_index": stored_in}

    async def refresh(self, **_kw: Any) -> None:
        return None

    async def delete(self, *, index: str, id: str) -> dict[str, Any]:
        self.deletes.append((index, id))
        return {"result": "deleted"}

    async def search(self, *_a: Any, **_kw: Any) -> Any:
        return SimpleNamespace(hits=[], total=0, total_is_lower_bound=False)

    async def aclose(self) -> None:
        return None


def test_the_nightly_plants_runs_scores_and_removes_through_the_real_batch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings(oracle_enabled=True)
    grid = _RecordingGrid(settings)
    monkeypatch.setattr(nightly_mod, "_loaded_blocklist", lambda _settings: _NO_FEEDS)
    monkeypatch.setattr("soc_ai.so_client.elastic.ElasticClient", lambda _s: grid)
    monkeypatch.setattr(
        "soc_ai.eval.batch.run_batch",
        functools.partial(batch_mod.run_batch, sampler=_make_sampler(["real-1", "real-2"])),
    )
    runs: list[dict[str, Any]] = []

    async def _fake_run(alert_id: str, *, out_dir: Path, **kw: Any) -> Any:
        runs.append({"alert_id": alert_id, **kw})
        planted = kw["expected_verdict"] is not None
        return _stub_eval_result(
            out_dir / f"bundle-{alert_id}",
            # The model closes the known intrusion as benign.
            verdict="false_positive",
            # The production shape: a partial grade on the same verdict.
            response_md=""
            if planted
            else "## 1. Verdict\nAGREEMENT: partial\nORACLE_VERDICT: false_positive\nThin.\n",
        )

    monkeypatch.setattr(harness_mod, "run", _fake_run)

    result = asyncio.run(nightly_mod.run_eval_nightly(settings, out_dir=tmp_path / "evals"))

    assert result.exit_code == 0
    # The real alerts ran first, graded. The planted run came last, not graded.
    assert [r["alert_id"] for r in runs[:2]] == ["real-1", "real-2"]
    planted_run = runs[2]
    assert [r["grade"] for r in runs] == [True, True, False]
    assert planted_run["expected_verdict"] == "true_positive"

    # One key from the plan to the documents to the run to the delete.
    keys = {doc["body"]["synth.scenario_id"] for doc in grid.indexed}
    assert len(keys) == 1
    key = next(iter(keys))
    assert f"::{nightly_mod.NIGHTLY_PLANT_TAG_PREFIX}" in key
    assert planted_run["include_synth"] == key
    assert all(doc["index"].startswith("logs-synth-") for doc in grid.indexed)
    # Each document is deleted by the address the grid gave it, and nothing
    # else is deleted. The grid double has no delete by query to call.
    assert grid.indexed
    assert grid.deletes == [doc["address"] for doc in grid.indexed]
    assert not hasattr(grid, "delete_by_query")
    assert read_ledger(Path(result.batch_dir))[1] == []

    # The miss is on the point, and the real numbers hold two real alerts.
    assert result.alarm_key == CODE_SYNTH_MISS
    scenario_id = key.split("::")[0]
    assert scenario_id in (result.alarm_reasons or [""])[0]
    assert result.metrics.n_ok == 2
    assert result.metrics.n_classified == 2
    # Two partial grades and two verdicts the same: the rubric and the verdict
    # agreement are two numbers, and only the real alerts are in either.
    assert (result.metrics.n_yes, result.metrics.n_partial) == (0, 2)
    assert (result.metrics.verdict_agree, result.metrics.verdict_compared) == (2, 2)
    snapshot = _read_snapshots(settings)[0]
    assert snapshot.detail["synth"][0]["scenario_id"] == scenario_id
    assert snapshot.detail["synth"][0]["outcome"] == "missed"


# --------------------------------------------------------------------
# A run that is cancelled records its own outcome
# --------------------------------------------------------------------


async def test_a_cancelled_run_does_not_record_the_outcome_of_the_run_before_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Production, 2026-10-27: exit 0 on record, one row in the batch, no snapshot.

    A restart inside the nightly hour cancels the worker. The attempt was then
    written from a status slot that still held the run before it. With a note on
    every clean run, that slot would also repeat "The model caught the synthetic
    true positive" for a night that measured nothing.
    """
    from soc_ai.api.webui import routes_quality
    from soc_ai.store import quality as quality_svc

    settings = _settings(soc_ai_data_dir=tmp_path)
    engine = make_engine(settings)
    await run_migrations(engine)
    status = routes_quality._QualityEvalStatus(
        last_exit_code=0,
        last_detail="The model caught the synthetic true positive e2-urlhaus-pe-delivery.",
    )
    state = SimpleNamespace(
        settings=settings,
        audit=None,
        db_sessionmaker=make_sessionmaker(engine),
        _quality_eval_status=status,
    )
    started = asyncio.Event()

    async def _never_ends(*_a: Any, **_kw: Any) -> Any:
        started.set()
        await asyncio.sleep(3600)

    monkeypatch.setattr(routes_quality, "run_eval_nightly", _never_ends)
    task = asyncio.create_task(routes_quality._quality_eval_worker(state, trigger="schedule"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    async with state.db_sessionmaker() as db:
        attempt = await quality_svc.latest_attempt(db)
    await engine.dispose()
    assert attempt is not None
    assert attempt.exit_code == 5
    assert "stopped before the end" in attempt.detail
    assert "caught" not in attempt.detail
    assert status.running is False


async def test_a_run_that_finishes_still_records_its_own_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: the cancel branch must not touch a run that returned."""
    from soc_ai.api.webui import routes_quality
    from soc_ai.eval.nightly import NightlyRunResult
    from soc_ai.store import quality as quality_svc

    settings = _settings(soc_ai_data_dir=tmp_path)
    engine = make_engine(settings)
    await run_migrations(engine)
    state = SimpleNamespace(
        settings=settings,
        audit=None,
        db_sessionmaker=make_sessionmaker(engine),
        _quality_eval_status=routes_quality._QualityEvalStatus(),
    )
    note = "The model caught the synthetic true positive e2-urlhaus-pe-delivery."

    async def _clean(*_a: Any, **_kw: Any) -> Any:
        return NightlyRunResult(exit_code=0, mode="graded", detail=note)

    monkeypatch.setattr(routes_quality, "run_eval_nightly", _clean)
    await routes_quality._quality_eval_worker(state, trigger="schedule")

    async with state.db_sessionmaker() as db:
        attempt = await quality_svc.latest_attempt(db)
    await engine.dispose()
    assert attempt is not None
    assert (attempt.exit_code, attempt.detail) == (0, note)
