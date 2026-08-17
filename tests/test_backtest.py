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
            # Every row was judged, so decided == total and the "over decided
            # rows only" rebasing is a no-op on a healthy run.
            "decided": 4,
            "no_verdict": 0,
            "human_tp": 2,
            "human_fp": 2,
            "human_fp_decided": 2,
            "agreements": 4,
            "fp_cleared": 2,
        }
        assert m["completion_rate"] == 1.0

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

    def test_inconclusive_is_a_non_decision(self) -> None:
        """`inconclusive` (self-consistency split) buckets with needs_more_info:
        it is NEVER a wrong TP/FP (no missed_tp, no false agreement) and never
        a `no_verdict` error row."""
        rows = [
            _row(HUMAN_TP, "inconclusive", alert_id="t1"),
            _row(HUMAN_FP, "inconclusive", alert_id="f1"),
            _row(HUMAN_TP, "true_positive"),
        ]
        m = score(rows)
        # Not an agreement with either disposition...
        assert m["agreement_rate"] == pytest.approx(1 / 3)
        # ...not a missed TP (the dangerous bucket is TP→false_positive only)...
        assert m["missed_tp"] == 0
        # ...not an FP clearance...
        assert m["counts"]["fp_cleared"] == 0
        # ...and counted as a hedge, in the needs_more_info confusion bucket,
        # NOT as no_verdict.
        assert m["n_needs_more_info"] == 2
        assert m["confusion"][HUMAN_TP]["needs_more_info"] == 1
        assert m["confusion"][HUMAN_FP]["needs_more_info"] == 1
        assert m["confusion"][HUMAN_TP]["no_verdict"] == 0
        assert m["confusion"][HUMAN_FP]["no_verdict"] == 0


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
    focus_hint: str | None = None,
    deep: bool = False,
) -> AsyncIterator[StepEvent]:
    sid = "fake-bt-sid"
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
        resp = bt_client.post("/api/v1/backtest", json={"window_days": 30, "sample_size": 20})
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
        resp = bt_client.post("/api/v1/backtest", json={"window_days": 30, "sample_size": 9999})
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


# ---------------------------------------------------------------------------
# 4. Degraded-grid honesty — G4 (sweep 2026-08-13)
#
# An outage was reported as "no dispositioned alerts in the window to replay":
# a false statement about the operator's own triage history, made on the screen
# built to earn their trust.
# ---------------------------------------------------------------------------


class TestBacktestRefusesToReportAnOutageAsAnEmptyWindow:
    def test_start_on_a_down_grid_is_503_not_an_empty_window(self, bt_settings: Settings) -> None:
        """The status code is the assertion: a changed note still passes if the
        route keeps answering 200 with an idle, finished status."""
        from elastic_transport import ConnectionError as EsConnectionError

        fake_es = AsyncMock()
        fake_es.search.side_effect = EsConnectionError("connection refused")
        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=bt_settings),
            patch("soc_ai.api.runner.investigate", _fake_investigate),
        ):
            app = create_app()
            with TestClient(app) as client:
                resp = client.post("/api/v1/backtest", json={"window_days": 30})
                assert resp.status_code == 503
                assert resp.json()["detail"]["reason"] == "grid_unavailable"
                after = client.get("/api/v1/backtest").json()
                # No fake finished run may be written: a note-only assertion
                # misses a persisted row that later reads as a real, empty one.
                assert after["backtest_id"] is None
                assert after["results"] is None
                # ...and the single-flight slot is released, or every later
                # backtest silently no-ops with "already running".
                assert after["active"] is False

    def test_start_on_a_down_grid_persists_no_backtest_row(self, bt_settings: Settings) -> None:
        import asyncio

        from elastic_transport import ConnectionError as EsConnectionError

        async def _rows() -> int:
            engine, maker = await _db(bt_settings)
            async with maker() as db:
                latest = await bt_svc.latest(db)
            await engine.dispose()
            return 0 if latest is None else 1

        fake_es = AsyncMock()
        fake_es.search.side_effect = EsConnectionError("connection refused")
        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=bt_settings),
            patch("soc_ai.api.runner.investigate", _fake_investigate),
        ):
            app = create_app()
            with TestClient(app) as client:
                client.post("/api/v1/backtest", json={"window_days": 30})
        assert asyncio.run(_rows()) == 0

    def test_a_readable_but_empty_window_still_reports_empty(self, bt_settings: Settings) -> None:
        """The control: a grid that answers with zero dispositioned alerts is a
        genuinely empty window and must still say so, at 200."""
        fake_es = AsyncMock()
        fake_es.search.return_value = {"took": 1, "hits": {"total": {"value": 0}, "hits": []}}
        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=bt_settings),
            patch("soc_ai.api.runner.investigate", _fake_investigate),
        ):
            app = create_app()
            with TestClient(app) as client:
                resp = client.post("/api/v1/backtest", json={"window_days": 30})
        assert resp.status_code == 200
        assert resp.json()["active"] is False
        assert "no dispositioned alerts" in (resp.json()["note"] or "")

    def test_the_note_that_outlives_the_error_still_carries_the_remedy(
        self, bt_settings: Settings
    ) -> None:
        """D18 (dogfood 2026-08-14): the durable half of the failure lost its advice.

        Two things say the run failed and they do not say the same thing. The
        inline error the POST raises carries the guidance — "slow or unreachable,
        retry shortly" — and it is gone the moment the page reloads. What survives
        is this note, rendered on its own in the empty panel, and it was a
        lowercase fragment with no next move on it: "grid unavailable — the window
        could not be read". The remedy has to be on the copy that LASTS, not only
        on the one that flashes.
        """
        from elastic_transport import ConnectionError as EsConnectionError

        fake_es = AsyncMock()
        fake_es.search.side_effect = EsConnectionError("connection refused")
        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=bt_settings),
            patch("soc_ai.api.runner.investigate", _fake_investigate),
        ):
            app = create_app()
            with TestClient(app) as client:
                assert client.post("/api/v1/backtest", json={"window_days": 30}).status_code == 503
                note = str(client.get("/api/v1/backtest").json()["note"] or "")

        assert note, "the failure left no durable note at all"
        assert note[0].isupper(), f"the note reads as a fragment, not a sentence: {note!r}"
        assert "retry" in note.lower(), f"the surviving note dropped its remedy: {note!r}"
        # It must still blame the grid rather than the operator's window: "your
        # window holds nothing" was the original lie this whole class exists for.
        assert "window" in note.lower() and "grid" in note.lower(), note

    def test_the_durable_note_reaches_a_console_that_has_run_a_backtest_before(
        self, bt_settings: Settings
    ) -> None:
        """The same note, on the only instance shape that ships: one with history.

        ``GET /backtest`` serves the newest STORED row whenever one exists, and a
        run that dies in its sampling read never gets a row — the row is created
        after the sampling search returns. So on any console that has completed a
        backtest even once, the failed run was served as the PREVIOUS run's
        finished results with ``note: null``: the remedy above is real and
        unreachable, and the failure vanishes behind a stale score. That is the
        "hides under the stale verdict" shape this dogfood found twice, and the
        empty fixture DB is the one state where it does not happen.
        """
        from elastic_transport import ConnectionError as EsConnectionError

        grid_down = {"yes": False}

        async def _search(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            if grid_down["yes"]:
                raise EsConnectionError("connection refused")
            return SAMPLING_ES_RESPONSE

        fake_es = AsyncMock()
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
                # The history: one real, completed, scored run.
                assert client.post("/api/v1/backtest", json={"window_days": 30}).status_code == 200
                stored = _poll_backtest(client)
                assert stored["status"] == "complete" and stored["results"], stored

                grid_down["yes"] = True
                assert client.post("/api/v1/backtest", json={"window_days": 30}).status_code == 503
                after = client.get("/api/v1/backtest").json()

        note = str(after["note"] or "")
        assert note, (
            "the failed run left no trace on a console with history — it is served as the "
            f"previous run's finished results, which is the false all-clear: {after}"
        )
        assert "retry" in note.lower(), f"the surviving note dropped its remedy: {note!r}"
        # The over-correction control, and the reason this is a merge rather than a
        # swap: a real measurement from last week is not deleted by today's outage.
        # It is dated on screen ("Ran …") and the newest attempt is stated over it.
        assert after["results"], (
            "today's grid outage threw away a score that was actually measured — the run "
            f"the operator adopted this product on: {after}"
        )

    def test_a_sampling_read_in_flight_outranks_the_last_run_on_the_status(
        self, bt_settings: Settings
    ) -> None:
        """The sampling phase has to be visible on a console with history too.

        ``start_backtest`` claims the slot with
        ``status.reset(active=True, total=0, backtest_id=None)`` and only then
        issues the sampling search, so for the length of that read the live status
        is active with no id — which is exactly what the screen reads as "reading
        Security Onion", and exactly what ``_bt_row_out`` dropped on the floor
        whenever a stored row existed (its ``active`` is ``live.backtest_id ==
        bt.id``, and during sampling there is no id to match). The console then
        showed the last finished run, idle, while a read was in flight.
        """
        fake_es = AsyncMock()
        fake_es.search.return_value = SAMPLING_ES_RESPONSE
        fake_auth = AsyncMock()
        with (
            patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
            patch("soc_ai.main.make_auth", return_value=fake_auth),
            patch("soc_ai.main.get_settings", return_value=bt_settings),
            patch("soc_ai.api.runner.investigate", _fake_investigate),
        ):
            app = create_app()
            with TestClient(app) as client:
                assert client.post("/api/v1/backtest", json={"window_days": 30}).status_code == 200
                stored = _poll_backtest(client)
                assert stored["status"] == "complete", stored
                # Put the live status in the exact shape start_backtest leaves it
                # in while the sampling search is out, rather than racing a real
                # one: a tarpit read would make this a timing test.
                backtest_svc.get_status(app.state).reset(active=True, total=0, backtest_id=None)
                during = client.get("/api/v1/backtest").json()

        assert during["active"] is True, (
            "a sampling read in flight was reported as an idle console — the run the "
            f"analyst just started is invisible: {during}"
        )
        assert during["backtest_id"] is None, (
            "the in-flight run was labelled with the PREVIOUS run's id, so the screen "
            f"renders it as a replay in progress of a run that already finished: {during}"
        )

    async def test_a_caller_that_walks_away_mid_sample_does_not_wedge_the_slot(
        self, bt_settings: Settings
    ) -> None:
        """The other half of D18's stalled screenshot: a claim that outlived its request.

        ``stalled/backtest-after-run-backtest-later.png`` shows the button stuck on
        "Running…" over "0 / 0 replayed" for a run that did not exist. The POST was
        abandoned by the browser at 20 s while the sampling read was still out;
        Starlette cancelled the handler, ``CancelledError`` sailed past every arm
        below (it is a BaseException), and the single-flight claim stayed set — so
        every later backtest answered "already running" until the process
        restarted. The grid budget makes the 20 s case unreachable, but a user who
        navigates away two seconds in cancels the same way, so the claim has to be
        released on the cancellation path itself.
        """
        import asyncio
        from types import SimpleNamespace

        reading = asyncio.Event()

        class _NeverAnswers:
            async def search(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
                reading.set()
                await asyncio.Event().wait()  # the tarpit: accepted, never answered
                return {}

        state = SimpleNamespace(settings=bt_settings, elastic=_NeverAnswers())
        task = asyncio.create_task(
            backtest_svc.start_backtest(
                state, window_days=30, sample_size=5, min_severity=None, started_by="test"
            )
        )
        await asyncio.wait_for(reading.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert backtest_svc.get_status(state).active is False, (
            "the single-flight slot survived the cancelled request — every later backtest "
            "will answer 'already running' and the console will render a run that is gone"
        )


# ---------------------------------------------------------------------------
# 5. Degraded-grid honesty — G5 (sweep 2026-08-13)
#
# A backtest that lost the grid MID-RUN finalized status=complete and priced
# every unreadable replay as a model disagreement: the report an owner uses to
# judge adoption read "soc-ai disagrees with human analysts 90% of the time"
# when the truth was the sensor was blind for 18 of 20 replays. That is a
# persisted, wrong conclusion about model quality caused by an infrastructure
# failure.
# ---------------------------------------------------------------------------


class TestScoreDoesNotPriceOutagesAsDisagreement:
    def test_agreement_is_over_decided_rows_not_all_rows(self) -> None:
        """18 of 20 replays produced NO verdict. soc-ai decided twice and was
        right twice: that is 100% agreement over what it judged, at 10%
        coverage — not 10% agreement."""
        rows = [
            _row(HUMAN_FP, "false_positive", alert_id="d1"),
            _row(HUMAN_TP, "true_positive", alert_id="d2"),
        ]
        rows += [_row(HUMAN_FP, None, alert_id=f"n{i}") for i in range(18)]
        m = score(rows)
        assert m["agreement_rate"] == 1.0
        assert m["counts"]["no_verdict"] == 18
        assert m["counts"]["decided"] == 2
        assert m["completion_rate"] == pytest.approx(0.1)
        # fp_reduction was depressed by the same arithmetic: 1 human-FP row was
        # decided, and soc-ai cleared it.
        assert m["fp_reduction"] == 1.0

    def test_all_no_verdict_is_zero_coverage_not_zero_agreement(self) -> None:
        rows = [_row(HUMAN_TP, None), _row(HUMAN_FP, None)]
        m = score(rows)
        assert m["completion_rate"] == 0.0
        assert m["counts"]["decided"] == 0
        # No opinion was formed, so no agreement rate can be claimed.
        assert m["agreement_rate"] == 0.0
        assert m["counts"]["no_verdict"] == 2

    def test_a_missed_tp_still_counts_when_others_were_unreadable(self) -> None:
        """The safety number must NOT be diluted away by the coverage fix."""
        rows = [
            _row(HUMAN_TP, "false_positive", alert_id="danger", rule="ET MALWARE x"),
            _row(HUMAN_TP, None, alert_id="blind"),
        ]
        m = score(rows)
        assert m["missed_tp"] == 1
        assert m["agreement_rate"] == 0.0  # the one decided row disagreed


def _dispositioned_investigation(settings: Settings, alert_es_id: str, verdict: str) -> None:
    """Persist a complete Investigation the backtest can read a verdict back off."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _go() -> None:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id=alert_es_id, started_by="backtest")
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict=verdict, confidence=0.9, rationale="x"
            )
        await engine.dispose()

    asyncio.run(_go())


class TestBacktestInterruptedMidRunIsNotComplete:
    def test_losing_the_grid_mid_run_does_not_finalize_clean(self, bt_settings: Settings) -> None:
        """20 samples, the grid goes away after sample 2. The PERSISTED record —
        not the transient in-memory counter, which already existed and did not
        help — must say the run was cut short, and must not price the 18 blind
        replays as model disagreement."""
        import asyncio

        from elastic_transport import ConnectionError as EsConnectionError
        from soc_ai.webui import backtest as bt

        samples = [
            backtest_svc.BacktestSample(
                alert_es_id=f"a{i}", rule_name=f"rule {i}", human_disposition=HUMAN_FP
            )
            for i in range(20)
        ]
        # The two replays that landed before the outage agree with the analyst.
        for s in samples[:2]:
            _dispositioned_investigation(bt_settings, s.alert_es_id, "false_positive")

        calls = {"n": 0}

        def _run_recorded(*args: Any, **kwargs: Any) -> AsyncIterator[Any]:
            calls["n"] += 1
            nth = calls["n"]

            async def _gen() -> AsyncIterator[Any]:
                if nth > 2:
                    raise EsConnectionError("connection refused")
                return
                yield  # pragma: no cover - makes this an async generator

            return _gen()

        async def _go() -> Any:
            engine = make_engine(bt_settings)
            await run_migrations(engine)
            maker = make_sessionmaker(engine)

            class _State:
                settings = bt_settings
                db_sessionmaker = maker

            async with maker() as db:
                row = await bt_svc.create(db, params={"window_days": 30}, started_by="admin")
            with (
                patch.object(bt, "run_recorded", _run_recorded),
                patch.object(bt, "ctx_from_state", lambda _s: None),
            ):
                await bt.run_backtest(
                    _State(), backtest_id=row.id, samples=samples, params={"window_days": 30}
                )
            async with maker() as db:
                got = await bt_svc.get(db, row.id)
            await engine.dispose()
            return got

        got = asyncio.run(_go())
        assert got is not None
        # Distinguishable from a clean run, on the record a reader loads later.
        assert got.status != "complete"
        results = got.results or {}
        completion = results.get("completion") or {}
        assert completion.get("degraded") is True
        assert completion.get("no_verdict") == 18
        assert completion.get("decided") == 2
        # And the headline number is NOT a 90% model regression.
        assert results["metrics"]["agreement_rate"] == 1.0

    def test_a_clean_run_is_still_complete_and_not_degraded(self, bt_client: TestClient) -> None:
        """The control: without it the fix could be 'always degrade'."""
        resp = bt_client.post("/api/v1/backtest", json={"window_days": 30, "sample_size": 20})
        assert resp.status_code == 200
        data = _poll_backtest(bt_client)
        assert data["status"] == "complete"
        assert data["results"]["completion"]["degraded"] is False
        assert data["results"]["completion"]["no_verdict"] == 0
