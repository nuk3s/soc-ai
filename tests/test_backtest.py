"""Tests for the Backtest feature: metric math, store CRUD + migration, endpoints.

Architecture notes
------------------
The pure :func:`soc_ai.webui.backtest.score` helper is tested directly with
synthetic ``(human_disposition, soc_ai_verdict)`` rows — no ES, no agent.

The endpoint tests fake ES (the dispositioned-alert sampling query) and patch
``soc_ai.api.runner.investigate`` so no real LLM traffic happens — the same
pattern as ``test_autotriage.py``. The faked agent emits a ``triage_report``
whose verdict the recorder persists on the Investigation row; the backtest reads
that verdict back and scores it against the sampled alert's disposition.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.agent.orchestrator import StepEvent
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import backtests as bt_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.webui import backtest as backtest_svc
from soc_ai.webui.backtest import HUMAN_FP, HUMAN_TP, score

ADMIN_PW = "test-bt-pw"


# ---------------------------------------------------------------------------
# 1. Pure metric math — score(rows)
# ---------------------------------------------------------------------------


def _row(disp: str, verdict: str | None, *, alert_id: str = "a", rule: str = "r") -> dict[str, Any]:
    return {
        "alert_id": alert_id,
        "rule_name": rule,
        "human_disposition": disp,
        "soc_ai_verdict": verdict,
    }


class TestScore:
    def test_perfect_agreement(self) -> None:
        rows = [
            _row(HUMAN_TP, "true_positive"),
            _row(HUMAN_TP, "true_positive"),
            _row(HUMAN_FP, "false_positive"),
            _row(HUMAN_FP, "false_positive"),
        ]
        m = score(rows)
        assert m["agreement_rate"] == 1.0
        assert m["fp_reduction"] == 1.0  # both human-FP also called FP by soc-ai
        assert m["missed_tp"] == 0
        assert m["missed_tp_rows"] == []
        assert m["counts"] == {
            "total": 4,
            "human_tp": 2,
            "human_fp": 2,
            "agreements": 4,
            "fp_cleared": 2,
        }

    def test_missed_tp_is_the_critical_number(self) -> None:
        # A human-escalated (TP) alert soc-ai calls false_positive = a missed incident.
        rows = [
            _row(HUMAN_TP, "false_positive", alert_id="danger", rule="ET MALWARE x"),
            _row(HUMAN_TP, "true_positive"),
            _row(HUMAN_FP, "false_positive"),
        ]
        m = score(rows)
        assert m["missed_tp"] == 1
        assert len(m["missed_tp_rows"]) == 1
        assert m["missed_tp_rows"][0]["alert_id"] == "danger"
        # 1 of 3 agree? TP→TP yes, FP→FP yes, TP→FP no → 2/3.
        assert m["agreement_rate"] == pytest.approx(2 / 3)

    def test_fp_reduction_fraction(self) -> None:
        # 4 human-FP; soc-ai clears 3 of them (calls FP), hedges 1.
        rows = [
            _row(HUMAN_FP, "false_positive"),
            _row(HUMAN_FP, "false_positive"),
            _row(HUMAN_FP, "false_positive"),
            _row(HUMAN_FP, "needs_more_info"),
        ]
        m = score(rows)
        assert m["fp_reduction"] == pytest.approx(0.75)
        assert m["counts"]["fp_cleared"] == 3
        # needs_more_info is NOT an agreement with an FP disposition.
        assert m["agreement_rate"] == pytest.approx(0.75)
        assert m["n_needs_more_info"] == 1

    def test_no_verdict_and_needs_more_info_counted(self) -> None:
        rows = [
            _row(HUMAN_TP, None),  # replay produced no verdict
            _row(HUMAN_FP, "needs_more_info"),
        ]
        m = score(rows)
        assert m["agreement_rate"] == 0.0
        assert m["n_needs_more_info"] == 1
        # None normalizes to the no_verdict bucket in the confusion matrix.
        assert m["confusion"][HUMAN_TP]["no_verdict"] == 1
        assert m["confusion"][HUMAN_FP]["needs_more_info"] == 1

    def test_confusion_matrix_shape_and_counts(self) -> None:
        rows = [
            _row(HUMAN_TP, "true_positive"),
            _row(HUMAN_TP, "false_positive"),
            _row(HUMAN_FP, "false_positive"),
            _row(HUMAN_FP, "true_positive"),
        ]
        m = score(rows)
        conf = m["confusion"]
        assert conf[HUMAN_TP]["true_positive"] == 1
        assert conf[HUMAN_TP]["false_positive"] == 1
        assert conf[HUMAN_FP]["false_positive"] == 1
        assert conf[HUMAN_FP]["true_positive"] == 1
        # Every bucket key present, even at zero.
        for disp in (HUMAN_TP, HUMAN_FP):
            assert set(conf[disp]) == {
                "true_positive",
                "false_positive",
                "needs_more_info",
                "no_verdict",
            }

    def test_empty_rows_no_division_by_zero(self) -> None:
        m = score([])
        assert m["agreement_rate"] == 0.0
        assert m["fp_reduction"] == 0.0
        assert m["missed_tp"] == 0
        assert m["counts"]["total"] == 0


# ---------------------------------------------------------------------------
# 2. Store CRUD + migration-creates-table
# ---------------------------------------------------------------------------


async def _db(settings: Settings) -> tuple[Any, Any]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_migration_creates_backtests_table(settings_kratos: Settings) -> None:
    from sqlalchemy import inspect

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = set(await conn.run_sync(lambda sc: inspect(sc).get_table_names()))
    assert "backtests" in tables
    await engine.dispose()


async def test_store_create_finalize_get_latest(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        bt = await bt_svc.create(
            db,
            params={"window_days": 30, "sample_size": 20, "min_severity": None},
            started_by="admin",
        )
    assert bt.id
    assert bt.status == "running"
    assert bt.sampled == 0

    results = {"metrics": {"agreement_rate": 0.8}, "rows": []}
    async with maker() as db:
        await bt_svc.finalize(db, bt.id, status="complete", sampled=5, results=results)

    async with maker() as db:
        got = await bt_svc.get(db, bt.id)
        latest = await bt_svc.latest(db)
    assert got is not None
    assert got.status == "complete"
    assert got.sampled == 5
    assert got.results == results
    assert got.finished_at is not None
    assert latest is not None and latest.id == bt.id
    await engine.dispose()


async def test_store_reap_stale_running(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        bt = await bt_svc.create(db, params={"window_days": 7}, started_by="admin")
    # older_than_minutes=None reaps every running row (startup semantics).
    async with maker() as db:
        n = await bt_svc.reap_stale_running(db, older_than_minutes=None, status="error")
    assert n == 1
    async with maker() as db:
        got = await bt_svc.get(db, bt.id)
    assert got is not None and got.status == "error"
    await engine.dispose()


# ---------------------------------------------------------------------------
# 3. Endpoints — sampling + replay + scoring, with a faked agent
# ---------------------------------------------------------------------------

# The verdict the faked agent lands for every replay.
_FAKE_VERDICT = "false_positive"

REPORT = {
    "verdict": _FAKE_VERDICT,
    "confidence": 0.9,
    "summary": "Benign scan.",
    "citations": ["a1"],
    "recommended_actions": [
        {
            "tool_name": "ack_alert",
            "tool_args": {"alert_id": "a1"},
            "rationale": "Internal scanner.",
        }
    ],
}

# ES response for the dispositioned-alert sampling query: 2 acked (human-FP) and
# 1 escalated (human-TP) alert. sort is present, no aggs.
SAMPLING_ES_RESPONSE: dict[str, Any] = {
    "took": 2,
    "hits": {
        "total": {"value": 3, "relation": "eq"},
        "hits": [
            {
                "_id": "a1",
                "_source": {
                    "@timestamp": "2026-06-30T06:41:00.000Z",
                    "rule": {"name": "ET SCAN thing"},
                    "event": {"severity_label": "high", "acknowledged": True},
                    "source": {"ip": "10.0.0.41"},
                    "destination": {"ip": "10.0.0.1"},
                },
            },
            {
                "_id": "a2",
                "_source": {
                    "@timestamp": "2026-06-30T06:42:00.000Z",
                    "rule": {"name": "ET POLICY other"},
                    "event": {"severity_label": "high", "acknowledged": True},
                    "source": {"ip": "10.0.0.42"},
                    "destination": {"ip": "10.0.0.2"},
                },
            },
            {
                "_id": "a3",
                "_source": {
                    "@timestamp": "2026-06-30T06:43:00.000Z",
                    "rule": {"name": "ET MALWARE beacon"},
                    "event": {"severity_label": "critical", "escalated": True},
                    "source": {"ip": "10.0.0.43"},
                    "destination": {"ip": "8.8.8.8"},
                },
            },
        ],
    },
}


async def _fake_investigate(
    alert_id: str,
    *,
    ctx: Any,
    agent: Any = None,
    investigator: Any = None,
    synthesizer: Any = None,
    session_id: str | None = None,
) -> AsyncIterator[StepEvent]:
    sid = session_id or "fake-bt-sid"
    yield StepEvent(
        kind="session_start", session_id=sid, sequence=1, payload={"alert_id": alert_id}
    )
    yield StepEvent(
        kind="enriched_alert_context",
        session_id=sid,
        sequence=2,
        payload={
            "alert": {
                "rule_name": "ET SCAN thing",
                "id": alert_id,
                "timestamp": "2026-06-30T06:41:00Z",
                "source_ip": "10.0.0.41",
                "destination_ip": "10.0.0.1",
            },
            "community_id_events": [],
            "host_events": [],
            "user_events": [],
            "process_events": [],
            "file_events": [],
            "pivot_summary": {},
            "prefetch_gaps": {},
        },
    )
    yield StepEvent(kind="triage_report", session_id=sid, sequence=3, payload=REPORT)
    yield StepEvent(kind="done", session_id=sid, sequence=4, payload={"recommended_count": 1})


@pytest.fixture
def bt_settings(settings_kratos: Settings) -> Settings:
    return settings_kratos.model_copy(
        update={
            "bootstrap_admin_password": SecretStr(ADMIN_PW),
            "webui_extra_detections": False,
            # api_auth off (lab default) so require_admin_api is a no-op in tests.
            "api_auth_required": False,
        }
    )


@pytest.fixture
def bt_client(bt_settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()

    async def _search(*args: Any, **kwargs: Any) -> dict[str, Any]:
        # The backtest issues exactly one search (the sampling query).
        return SAMPLING_ES_RESPONSE

    fake_es.search.side_effect = _search
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=bt_settings),
        patch("soc_ai.api.runner.investigate", _fake_investigate),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def _poll_backtest(client: TestClient, *, deadline_s: float = 6.0) -> dict[str, Any]:
    """Poll GET /api/v1/backtest until the run finishes; return final JSON."""
    deadline = time.time() + deadline_s
    data: dict[str, Any] = {}
    while time.time() < deadline:
        resp = client.get("/api/v1/backtest")
        assert resp.status_code == 200
        data = resp.json()
        if not data["active"] and data.get("status") in ("complete", "error"):
            return data
        time.sleep(0.1)
    return data


class TestBacktestEndpoints:
    def test_start_and_complete_scores_against_disposition(self, bt_client: TestClient) -> None:
        resp = bt_client.post(
            "/api/v1/backtest", json={"window_days": 30, "sample_size": 20}
        )
        assert resp.status_code == 200
        started = resp.json()
        assert started["active"] is True
        assert started["backtest_id"]
        assert started["total"] == 3  # 3 distinct (rule, disposition) samples

        data = _poll_backtest(bt_client)
        assert data["status"] == "complete"
        assert data["sampled"] == 3
        results = data["results"]
        metrics = results["metrics"]
        counts = metrics["counts"]
        # 2 human-FP (acked), 1 human-TP (escalated).
        assert counts["human_fp"] == 2
        assert counts["human_tp"] == 1
        # The faked agent always says false_positive. So:
        #  - both human-FP rows agree (FP↔FP) → fp_reduction = 1.0
        #  - the human-TP row is called FP → a MISSED true positive.
        assert metrics["fp_reduction"] == pytest.approx(1.0)
        assert metrics["missed_tp"] == 1
        assert len(results["missed_tp_rows"]) == 1
        assert results["missed_tp_rows"][0]["human_disposition"] == HUMAN_TP
        # agreement = 2/3 (both FP right, the one TP wrong).
        assert metrics["agreement_rate"] == pytest.approx(2 / 3)
        # The acked⇒FP proxy caveat must ride with the data.
        assert "acknowledged" in results["caveat"].lower()

    def test_sample_size_is_capped(self, bt_client: TestClient) -> None:
        # Request far over the hard cap; the params must reflect the clamp.
        resp = bt_client.post(
            "/api/v1/backtest", json={"window_days": 30, "sample_size": 9999}
        )
        assert resp.status_code == 200
        data = _poll_backtest(bt_client)
        assert data["params"]["sample_size"] <= backtest_svc.DEFAULT_SAMPLE_SIZE * 10
        assert data["params"]["sample_size"] == 50  # backtest_max_sample default
        assert data["params"]["requested_sample_size"] == 9999

    def test_get_by_id(self, bt_client: TestClient) -> None:
        resp = bt_client.post("/api/v1/backtest", json={"window_days": 7, "sample_size": 5})
        assert resp.status_code == 200
        bid = resp.json()["backtest_id"]
        _poll_backtest(bt_client)
        got = bt_client.get(f"/api/v1/backtest/{bid}")
        assert got.status_code == 200
        assert got.json()["backtest_id"] == bid
        assert got.json()["status"] == "complete"

    def test_get_by_id_404(self, bt_client: TestClient) -> None:
        resp = bt_client.get("/api/v1/backtest/DOESNOTEXIST")
        assert resp.status_code == 404

    def test_status_when_never_run(self, bt_client: TestClient) -> None:
        # A fresh client that never started a backtest reports idle, no results.
        resp = bt_client.get("/api/v1/backtest")
        assert resp.status_code == 200
        data = resp.json()
        assert data["active"] is False
        assert data["results"] is None
