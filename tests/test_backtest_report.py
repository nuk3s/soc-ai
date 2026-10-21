"""What the Backtest report states, read back from the API (dogfood 2026-10-19).

R5-D13: the console labelled the share of acknowledged alerts that soc-ai
called a false positive "false-positive toil cleared ... would auto-clear 5 of
9". Auto-acknowledge applies a confidence threshold, an evidence test and a
severity guard, and the figure applies none of them. The figure is an
agreement figure, and the API now names it one.

R5-D25: a run kept the caveat prose of the day it ran. The page showed the old
wording for every old run.

R5-I10: a result row named no investigation, so the operator could not open
the replay behind a verdict. GET /backtest listed one run only.

R5-I9: the console asked for a backtest with no cost on screen. The API now
serves the cap and the median time of one replay.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import backtests as bt_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Backtest, Investigation
from soc_ai.webui import backtest as backtest_svc
from soc_ai.webui.backtest import HUMAN_FP, HUMAN_TP, score

from tests.test_backtest import (
    SAMPLING_ES_RESPONSE,
    _fake_investigate,
    _poll_backtest,
    bt_settings,  # noqa: F401  (fixture)
)

# The caveat a run of 2026-10-01 stored. It is the text the range served.
_OLD_CAVEAT = (
    "Ground truth is read from Security Onion: event.escalated ⇒ true positive; "
    "acknowledged-and-not-escalated ⇒ false positive. The false-positive proxy is "
    "imperfect — an analyst acknowledges alerts for several reasons."
)


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()

    async def _search(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return SAMPLING_ES_RESPONSE

    fake_es.search.side_effect = _search
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
        patch("soc_ai.api.runner.investigate", _fake_investigate),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(bt_settings: Settings) -> Iterator[TestClient]:  # noqa: F811
    yield from _client(bt_settings)


def _seed(settings: Settings, fn: Any) -> Any:
    """Run ``fn(db)`` against the test store before the app opens it."""

    async def _go() -> Any:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            out = await fn(db)
        await engine.dispose()
        return out

    return asyncio.run(_go())


def _old_results(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The results shape a run stored before 2026-10-19: no fp_agreement_rate."""
    metrics = score(rows)
    return {
        "metrics": {
            "agreement_rate": metrics["agreement_rate"],
            "fp_reduction": metrics["fp_reduction"],
            "missed_tp": metrics["missed_tp"],
            "n_needs_more_info": metrics["n_needs_more_info"],
            "counts": metrics["counts"],
        },
        "confusion": metrics["confusion"],
        "missed_tp_rows": metrics["missed_tp_rows"],
        "rows": rows,
        "caveat": _OLD_CAVEAT,
    }


def _old_row(alert_id: str, disposition: str, verdict: str) -> dict[str, Any]:
    return {
        "alert_id": alert_id,
        "rule_name": f"rule {alert_id}",
        "human_disposition": disposition,
        "soc_ai_verdict": verdict,
        "match": disposition == verdict,
    }


# ---------------------------------------------------------------------------
# R5-D13: the false-positive figure is an agreement figure
# ---------------------------------------------------------------------------


class TestTheFalsePositiveFigureIsAnAgreement:
    def test_score_names_the_figure_an_agreement(self) -> None:
        rows = [
            {"human_disposition": HUMAN_FP, "soc_ai_verdict": "false_positive"},
            {"human_disposition": HUMAN_FP, "soc_ai_verdict": "true_positive"},
            {"human_disposition": HUMAN_TP, "soc_ai_verdict": "true_positive"},
        ]
        m = score(rows)
        assert m["fp_agreement_rate"] == pytest.approx(0.5)
        # The old field stays for an older reader, with the same value.
        assert m["fp_reduction"] == m["fp_agreement_rate"]

    def test_a_new_run_stores_the_agreement_figure(self, client: TestClient) -> None:
        client.post("/api/v1/backtest", json={"window_days": 30, "sample_size": 20})
        data = _poll_backtest(client)
        metrics = data["results"]["metrics"]
        assert metrics["fp_agreement_rate"] == pytest.approx(1.0)
        assert metrics["fp_reduction"] == pytest.approx(1.0)

    def test_an_old_run_is_served_with_the_agreement_figure(self, bt_settings: Settings) -> None:  # noqa: F811
        rows = [
            _old_row("o1", HUMAN_FP, "false_positive"),
            _old_row("o2", HUMAN_FP, "needs_more_info"),
        ]

        async def _make(db: Any) -> None:
            bt = await bt_svc.create(db, params={"window_days": 14}, started_by="admin")
            await bt_svc.finalize(
                db, bt.id, status="complete", sampled=2, results=_old_results(rows)
            )

        _seed(bt_settings, _make)
        for client in _client(bt_settings):
            metrics = client.get("/api/v1/backtest").json()["results"]["metrics"]
        assert metrics["fp_agreement_rate"] == pytest.approx(0.5)
        assert metrics["fp_reduction"] == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# R5-D25: every run carries the current caveat
# ---------------------------------------------------------------------------


class TestEveryRunCarriesTheCurrentCaveat:
    def test_an_old_run_is_served_with_the_current_caveat(self, bt_settings: Settings) -> None:  # noqa: F811
        async def _make(db: Any) -> str:
            bt = await bt_svc.create(db, params={"window_days": 14}, started_by="admin")
            await bt_svc.finalize(
                db,
                bt.id,
                status="complete",
                sampled=1,
                results=_old_results([_old_row("o1", HUMAN_FP, "false_positive")]),
            )
            return bt.id

        bid = _seed(bt_settings, _make)
        for client in _client(bt_settings):
            latest = client.get("/api/v1/backtest").json()
            by_id = client.get(f"/api/v1/backtest/{bid}").json()
        assert latest["results"]["caveat"] == backtest_svc.CAVEAT
        assert by_id["results"]["caveat"] == backtest_svc.CAVEAT
        assert "—" not in latest["results"]["caveat"]

    def test_the_stored_row_keeps_what_it_stored(self, bt_settings: Settings) -> None:  # noqa: F811
        """The read serves the current text. It does not rewrite the record."""

        async def _make(db: Any) -> str:
            bt = await bt_svc.create(db, params={}, started_by="admin")
            await bt_svc.finalize(
                db,
                bt.id,
                status="complete",
                sampled=1,
                results=_old_results([_old_row("o1", HUMAN_FP, "false_positive")]),
            )
            return bt.id

        bid = _seed(bt_settings, _make)
        for client in _client(bt_settings):
            client.get("/api/v1/backtest")

        async def _read(db: Any) -> Any:
            return await bt_svc.get(db, bid)

        stored = _seed(bt_settings, _read)
        assert stored.results["caveat"] == _OLD_CAVEAT

    def test_a_new_run_stores_the_current_caveat(self, client: TestClient) -> None:
        client.post("/api/v1/backtest", json={})
        data = _poll_backtest(client)
        assert data["results"]["caveat"] == backtest_svc.CAVEAT


# ---------------------------------------------------------------------------
# R5-I10: each row names its replay investigation
# ---------------------------------------------------------------------------


class TestEachRowNamesItsReplay:
    def test_a_new_run_stores_the_replay_id_on_each_row(
        self,
        client: TestClient,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        client.post("/api/v1/backtest", json={})
        data = _poll_backtest(client)
        rows = data["results"]["rows"]
        assert len(rows) == 3
        ids = [row["investigation_id"] for row in rows]
        assert all(ids), ids

        async def _read(db: Any) -> list[Investigation | None]:
            return [await db.get(Investigation, i) for i in ids]

        for row, inv in zip(rows, _seed(bt_settings, _read), strict=True):
            assert inv is not None
            assert inv.alert_es_id == row["alert_id"]
            assert inv.started_by == "backtest"

    def test_an_old_run_finds_the_replays_of_its_own_window(
        self,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        """An old row has no id. The read finds the replay that ran inside the
        run. A later replay of the same alert, and a live run of it inside the
        window, are other runs, and the read must not pick them."""
        now = utcnow()
        start = now - timedelta(hours=3)
        end = now - timedelta(hours=2)

        async def _make(db: Any) -> str:
            bt = Backtest(
                id="BT-OLD",
                params={"window_days": 14},
                status="complete",
                sampled=2,
                results=_old_results(
                    [
                        _old_row("o1", HUMAN_FP, "false_positive"),
                        _old_row("o2", HUMAN_TP, "true_positive"),
                    ]
                ),
                started_by="admin",
                created_at=start,
                finished_at=end,
            )
            db.add(bt)
            db.add_all(
                [
                    # The replay of o1 inside the run.
                    Investigation(
                        id="INV-IN",
                        alert_es_id="o1",
                        started_by="backtest",
                        status="complete",
                        created_at=start + timedelta(minutes=5),
                    ),
                    # A live run of o1 inside the window: not a replay.
                    Investigation(
                        id="INV-LIVE",
                        alert_es_id="o1",
                        started_by="analyst",
                        status="complete",
                        created_at=start + timedelta(minutes=10),
                    ),
                    # A replay of o1 by a later backtest.
                    Investigation(
                        id="INV-LATER",
                        alert_es_id="o1",
                        started_by="backtest",
                        status="complete",
                        created_at=now - timedelta(minutes=30),
                    ),
                    # o2 has a replay by a later backtest only.
                    Investigation(
                        id="INV-O2-LATER",
                        alert_es_id="o2",
                        started_by="backtest",
                        status="complete",
                        created_at=now - timedelta(minutes=20),
                    ),
                ]
            )
            await db.commit()
            return bt.id

        bid = _seed(bt_settings, _make)
        for client in _client(bt_settings):
            rows = client.get(f"/api/v1/backtest/{bid}").json()["results"]["rows"]
            latest_rows = client.get("/api/v1/backtest").json()["results"]["rows"]
        by_alert = {row["alert_id"]: row.get("investigation_id") for row in rows}
        assert by_alert == {"o1": "INV-IN", "o2": None}
        assert {r["alert_id"]: r.get("investigation_id") for r in latest_rows} == by_alert

    def test_a_replay_in_the_second_the_run_started_is_inside_the_run(
        self,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        """The store writes a server-default time to the second. The first
        replay starts in the run's own second, and a bound with microseconds
        compared it below the start."""
        from soc_ai.store import investigations as inv_svc

        async def _make(db: Any) -> str:
            bt = await bt_svc.create(db, params={}, started_by="admin")
            inv = await inv_svc.create(db, alert_es_id="o1", started_by="backtest")
            await bt_svc.finalize(
                db,
                bt.id,
                status="complete",
                sampled=1,
                results=_old_results([_old_row("o1", HUMAN_FP, "false_positive")]),
            )
            return f"{bt.id}:{inv.id}"

        bid, inv_id = _seed(bt_settings, _make).split(":")
        for client in _client(bt_settings):
            rows = client.get(f"/api/v1/backtest/{bid}").json()["results"]["rows"]
        assert rows[0]["investigation_id"] == inv_id


# ---------------------------------------------------------------------------
# R5-I10: the past runs
# ---------------------------------------------------------------------------


class TestThePastRuns:
    def test_the_list_holds_every_run_newest_first(
        self,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        now = utcnow()

        async def _make(db: Any) -> None:
            rows = [_old_row("o1", HUMAN_FP, "false_positive")]
            db.add_all(
                [
                    Backtest(
                        id="BT-A",
                        params={"window_days": 14, "sample_size": 10},
                        status="complete",
                        sampled=1,
                        results=_old_results(rows),
                        started_by="admin",
                        created_at=now - timedelta(days=2),
                        finished_at=now - timedelta(days=2) + timedelta(minutes=9),
                    ),
                    Backtest(
                        id="BT-B",
                        params={"window_days": 7, "sample_size": 20},
                        status="error",
                        sampled=0,
                        results=None,
                        started_by="admin",
                        created_at=now - timedelta(hours=1),
                        finished_at=now - timedelta(hours=1) + timedelta(minutes=1),
                    ),
                ]
            )
            await db.commit()

        _seed(bt_settings, _make)
        for client in _client(bt_settings):
            resp = client.get("/api/v1/backtests")
        assert resp.status_code == 200
        runs = resp.json()["runs"]
        assert [r["backtest_id"] for r in runs] == ["BT-B", "BT-A"]
        a = runs[1]
        assert a["status"] == "complete"
        assert a["window_days"] == 14
        assert a["sampled"] == 1
        assert a["agreement_rate"] == pytest.approx(1.0)
        assert a["fp_agreement_rate"] == pytest.approx(1.0)
        assert a["missed_tp"] == 0
        assert a["finished_at"].endswith("Z")
        assert a["started_at"].endswith("Z")
        b = runs[0]
        assert b["status"] == "error"
        assert b["agreement_rate"] is None

    def test_an_empty_store_lists_no_run(self, client: TestClient) -> None:
        resp = client.get("/api/v1/backtests")
        assert resp.status_code == 200
        assert resp.json()["runs"] == []


# ---------------------------------------------------------------------------
# R5-I9: the cost of a run
# ---------------------------------------------------------------------------


class TestTheCostOfARun:
    def test_the_status_serves_the_cap(self, client: TestClient) -> None:
        data = client.get("/api/v1/backtest").json()
        assert data["max_sample"] == 50

    def test_no_history_serves_no_estimate(self, client: TestClient) -> None:
        assert client.get("/api/v1/backtest").json()["estimate"] is None

    def test_the_estimate_is_the_median_replay_time(
        self,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        now = utcnow()

        def _inv(i: int, *, wall_ms: int | None, minutes: float, started_by: str) -> Investigation:
            created = now - timedelta(hours=i + 1)
            return Investigation(
                id=f"INV-{started_by}-{i}",
                alert_es_id=f"e{i}",
                started_by=started_by,
                status="complete",
                created_at=created,
                finished_at=created + timedelta(minutes=minutes),
                wall_ms=wall_ms,
            )

        async def _make(db: Any) -> None:
            db.add_all(
                [
                    _inv(0, wall_ms=60_000, minutes=1, started_by="backtest"),
                    _inv(1, wall_ms=None, minutes=2, started_by="backtest"),
                    _inv(2, wall_ms=180_000, minutes=3, started_by="backtest"),
                    # A live run is faster here. The replays are the better basis.
                    _inv(3, wall_ms=1_000, minutes=0.1, started_by="analyst"),
                ]
            )
            await db.commit()

        _seed(bt_settings, _make)
        for client in _client(bt_settings):
            estimate = client.get("/api/v1/backtest").json()["estimate"]
        assert estimate == {
            "seconds_per_alert": pytest.approx(120.0),
            "runs": 3,
            "basis": "backtest",
        }

    def test_with_no_replay_the_estimate_reads_the_other_runs(
        self,
        bt_settings: Settings,  # noqa: F811
    ) -> None:
        now = utcnow()

        async def _make(db: Any) -> None:
            for i, wall in enumerate((30_000, 90_000)):
                created = now - timedelta(hours=i + 1)
                db.add(
                    Investigation(
                        id=f"INV-{i}",
                        alert_es_id=f"e{i}",
                        started_by="analyst",
                        status="complete",
                        created_at=created,
                        finished_at=created + timedelta(seconds=wall / 1000),
                        wall_ms=wall,
                    )
                )
            # An errored run says nothing about the time of a full investigation.
            db.add(
                Investigation(
                    id="INV-ERR",
                    alert_es_id="e9",
                    started_by="analyst",
                    status="error",
                    created_at=now - timedelta(hours=5),
                    finished_at=now - timedelta(hours=4),
                    wall_ms=3_600_000,
                )
            )
            await db.commit()

        _seed(bt_settings, _make)
        for client in _client(bt_settings):
            estimate = client.get("/api/v1/backtest").json()["estimate"]
        assert estimate == {
            "seconds_per_alert": pytest.approx(60.0),
            "runs": 2,
            "basis": "investigations",
        }
