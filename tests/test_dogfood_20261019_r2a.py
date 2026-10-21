"""Dogfood 2026-10-19, round 2 verify (R2-A): the standing analyst verdict.

V1-A2 and V1-A3 extend R2-D1: an analyst verdict is never replaced without a
confirm that names it. The confirm lives in the console. The server half is
here: the detail names the standing analyst verdict of the alert, on ANY run
of it, and a replay names the live verdict a new run would replace. The
Alerts row names the analyst verdict too. Every positive test has a negative
control beside it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.webui.alerts_query import AlertGroup, GroupPage


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _run(
    client: TestClient,
    *,
    alert_es_id: str,
    rule_name: str = "ET INFO NTLMv1 Session Setup Response",
    verdict: str | None = "false_positive",
    confidence: float | None = 0.8,
    started_by: str = "tester",
    age_minutes: int = 0,
) -> str:
    async def _go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(
                db, alert_es_id=alert_es_id, started_by=started_by, rule_name=rule_name
            )
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict=verdict, confidence=confidence
            )
            if age_minutes:
                inv.created_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
                    minutes=age_minutes
                )
                await db.commit()
            return str(inv.id)

    return asyncio.run(_go())


def _override(client: TestClient, inv_id: str, verdict: str, by: str = "alice") -> None:
    """The analyst's manual override, through the store call the route uses."""

    async def _go() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            await inv_svc.resolve(
                db,
                inv_id,
                verdict=verdict,
                confidence=1.0,
                rationale=f"Verdict set by {by}.",
                recommended_actions=[],
                resolved_by=by,
                resolved_via="manual",
            )

    asyncio.run(_go())


def _detail(client: TestClient, inv_id: str) -> dict[str, Any]:
    resp = client.get(f"/api/v1/investigations/{inv_id}")
    assert resp.status_code == 200, resp.text
    return dict(resp.json())


# ── V1-A3: the detail names the analyst verdict on an earlier run ───────────


def test_the_newer_run_names_the_analyst_verdict_on_an_earlier_run(client: TestClient) -> None:
    """The analyst set true positive on the older run. A re-run reached false
    positive. The newer page read only its own run and said "soc-ai verdict"."""
    older = _run(client, alert_es_id="ev-ntlm", age_minutes=90)
    _override(client, older, "true_positive")
    newer = _run(client, alert_es_id="ev-ntlm", verdict="false_positive", age_minutes=5)

    standing = _detail(client, newer)["standingAnalystVerdict"]

    assert standing is not None
    assert standing["investigationId"] == older
    assert standing["verdict"] == "true_positive"
    assert standing["by"] == "alice"
    assert standing["via"] == "manual"


def test_the_analyst_run_names_itself(client: TestClient) -> None:
    run = _run(client, alert_es_id="ev-self")
    _override(client, run, "true_positive")

    assert _detail(client, run)["standingAnalystVerdict"]["investigationId"] == run


def test_a_model_verdict_names_no_analyst(client: TestClient) -> None:
    """NEGATIVE CONTROL. No person set a verdict on the alert."""
    run = _run(client, alert_es_id="ev-model")
    assert _detail(client, run)["standingAnalystVerdict"] is None


def test_an_analyst_verdict_on_another_alert_is_not_this_alerts(client: TestClient) -> None:
    """NEGATIVE CONTROL. The analyst verdict sits on another alert of the rule."""
    other = _run(client, alert_es_id="ev-other-alert")
    _override(client, other, "true_positive")
    run = _run(client, alert_es_id="ev-this-alert")

    assert _detail(client, run)["standingAnalystVerdict"] is None


# ── V1-A2: a replay names the live verdict a new run replaces ───────────────


def test_a_replay_names_the_live_verdict_of_its_alert(client: TestClient) -> None:
    """Request more info on a replay started a live run. That run replaced
    the live true positive at 0.65, and the page said nothing."""
    live = _run(client, alert_es_id="ev-kerb", verdict="true_positive", confidence=0.65)
    replay = _run(
        client,
        alert_es_id="ev-kerb",
        verdict="needs_more_info",
        confidence=0.5,
        started_by="backtest",
    )

    out = _detail(client, replay)["alertLiveRun"]

    assert out is not None
    assert out["id"] == live
    assert out["verdict"] == "true_positive"
    assert out["conf"] == pytest.approx(0.65)


def test_a_replay_with_no_live_run_names_none(client: TestClient) -> None:
    replay = _run(client, alert_es_id="ev-kerb-2", verdict="needs_more_info", started_by="backtest")
    assert _detail(client, replay)["alertLiveRun"] is None


def test_a_live_run_carries_no_live_run_field(client: TestClient) -> None:
    """NEGATIVE CONTROL. A live run IS the live verdict. The field is for a replay."""
    _run(client, alert_es_id="ev-live", age_minutes=30)
    newer = _run(client, alert_es_id="ev-live")
    assert _detail(client, newer)["alertLiveRun"] is None


# ── V1-A3: the Alerts row names the analyst verdict ─────────────────────────


def _row(client: TestClient, rule: str, latest_id: str) -> dict[str, Any]:
    groups = [
        AlertGroup(
            rule_name=rule,
            count=1,
            severity="low",
            latest_ts="2026-10-19T10:00:00Z",
            latest_id=latest_id,
            kind="suricata",
        )
    ]
    with patch(
        "soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=GroupPage(groups, 1))
    ):
        body = client.get("/api/v1/alerts").json()
    return dict(body["groups"][0])


def test_the_row_names_the_analyst_verdict_under_a_newer_model_run(client: TestClient) -> None:
    rule = "ET INFO NTLMv1 Session Setup Response"
    older = _run(client, alert_es_id="ev-row", rule_name=rule, age_minutes=90)
    _override(client, older, "true_positive")
    newer = _run(client, alert_es_id="ev-row", rule_name=rule, verdict="false_positive")

    row = _row(client, rule, "ev-row")

    assert row["invId"] == newer
    assert row["verdict"] == "false_positive"
    assert row["analystVerdict"] == "true_positive"
    assert row["analystBy"] == "alice"
    assert row["analystInvId"] == older


def test_a_row_with_no_analyst_verdict_names_none(client: TestClient) -> None:
    """NEGATIVE CONTROL."""
    rule = "ET INFO Observed DNS Query"
    _run(client, alert_es_id="ev-row-2", rule_name=rule)

    row = _row(client, rule, "ev-row-2")

    assert row["analystVerdict"] is None
    assert row["analystInvId"] is None


# ── One rule: the bulk Re-investigate of the Investigations list ────────────


def _manager(client: TestClient) -> Any:
    """A hunt manager whose start writes a real row, as the real one does."""

    async def start(_state: Any, *, alert_id: str, started_by: str, **_kw: Any) -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(db, alert_es_id=alert_id, started_by=started_by)
            return str(inv.id)

    mgr = AsyncMock()
    mgr.start = start
    return mgr


def test_the_bulk_rerun_skips_an_alert_with_an_analyst_verdict(client: TestClient) -> None:
    """The list has no confirm. A bulk Re-investigate replaced the analyst
    verdict with no question, the path R2-D1 closed on the page. It now skips
    the alert and names the reason. The page of the run asks and names it."""
    older = _run(client, alert_es_id="ev-bulk", age_minutes=60)
    _override(client, older, "true_positive")
    newer = _run(client, alert_es_id="ev-bulk")
    clean = _run(client, alert_es_id="ev-bulk-clean")

    with patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=_manager(client)):
        body = client.post(
            "/api/v1/investigations/rehunt", json={"inv_ids": [newer, older, clean]}
        ).json()

    assert {s["invId"]: s["reason"] for s in body["skipped"]} == {
        newer: "analyst_verdict",
        older: "analyst_verdict",
    }
    # NEGATIVE CONTROL: the alert with no analyst verdict starts.
    assert [s["invId"] for s in body["started"]] == [clean]
