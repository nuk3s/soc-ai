"""An alert group row names the worst verdict among its alerts (dogfood 2026-10-06, S5).

The row said "False positive · inherited 1d ago" while one event of the group
carried a true-positive investigation at 0.62. Only the Investigations list
and a lead showed it. The row now carries the verdict counts of its alerts and
the worst verdict, and each event carries the verdict that applies to it.
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
from soc_ai.webui.alerts_query import AlertEvent, AlertGroup, GroupPage

_RULE = "Security Onion - Grid Node Login Failure (SSH)"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _ago(hours: float) -> datetime:
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _run(
    client: TestClient,
    run_id: str,
    *,
    alert_id: str,
    verdict: str,
    hours_ago: float,
    src: str = "192.0.2.26",
    fallback: bool = False,
) -> None:
    from soc_ai.store.models import Investigation

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id=run_id,
                    alert_es_id=alert_id,
                    rule_name=_RULE,
                    status="complete",
                    verdict=verdict,
                    confidence=0.62 if verdict == "true_positive" else 0.9,
                    src_ip=src,
                    dest_ip="192.0.2.1",
                    is_fallback=fallback,
                    report={"verdict": verdict},
                    created_at=_ago(hours_ago),
                    finished_at=_ago(hours_ago),
                )
            )
            await db.commit()

    asyncio.run(go())


def _page() -> GroupPage:
    return GroupPage(
        [
            AlertGroup(
                rule_name=_RULE,
                count=9,
                severity="medium",
                latest_ts=datetime.now(UTC).isoformat(),
                latest_id="es-latest",
            )
        ],
        9,
    )


def _group(client: TestClient, range_: str = "30d") -> dict[str, Any]:
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=_page())):
        res = client.get("/api/v1/alerts", params={"range": range_})
    assert res.status_code == 200, res.text
    groups: list[dict[str, Any]] = res.json()["groups"]
    assert len(groups) == 1
    return groups[0]


def test_a_group_row_names_the_true_positive_among_its_false_positives(
    client: TestClient,
) -> None:
    # Eight alerts closed as false positive, one true positive four days ago,
    # and the newest run (the standing verdict) a false positive.
    for n in range(8):
        _run(client, f"INV-FP{n}", alert_id=f"es-fp{n}", verdict="false_positive", hours_ago=24 + n)
    _run(
        client,
        "INV-TP",
        alert_id="es-tp",
        verdict="true_positive",
        hours_ago=96,
        src="192.0.2.29",
    )
    group = _group(client)
    assert group["verdict"] == "false_positive"
    assert group["verdictCounts"] == {"false_positive": 8, "true_positive": 1}
    assert group["worstVerdict"] == "true_positive"
    assert group["worstConf"] == pytest.approx(0.62)
    assert group["worstInvId"] == "INV-TP"


def test_a_group_whose_standing_verdict_is_the_worst_names_no_other(client: TestClient) -> None:
    """NEGATIVE CONTROL. No worse verdict, no second chip."""
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=30)
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=2)
    group = _group(client)
    assert group["verdict"] == "true_positive"
    assert group["worstVerdict"] is None
    assert group["verdictCounts"] == {"false_positive": 1, "true_positive": 1}


def test_one_alert_counts_once_with_its_newest_verdict(client: TestClient) -> None:
    """A re-run replaced the true positive of one alert. It no longer counts."""
    _run(client, "INV-OLD", alert_id="es-1", verdict="true_positive", hours_ago=10)
    _run(client, "INV-NEW", alert_id="es-1", verdict="false_positive", hours_ago=2)
    group = _group(client)
    assert group["verdictCounts"] == {"false_positive": 1}
    assert group["worstVerdict"] is None


def test_a_pipeline_fallback_counts_as_no_verdict(client: TestClient) -> None:
    """NEGATIVE CONTROL. A run that reached no verdict says nothing about an alert."""
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=3)
    _run(client, "INV-FB", alert_id="es-fb", verdict="needs_more_info", hours_ago=2, fallback=True)
    group = _group(client)
    assert group["verdictCounts"] == {"false_positive": 1}
    assert group["worstVerdict"] is None


def test_a_run_older_than_both_windows_is_not_counted(client: TestClient) -> None:
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=2)
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=24 * 40)
    group = _group(client)
    assert group["verdictCounts"] == {"false_positive": 1}


def test_each_event_carries_the_verdict_that_applies_to_it(client: TestClient) -> None:
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=96)
    events = [
        AlertEvent(
            es_id="es-tp",
            timestamp=datetime.now(UTC).isoformat(),
            src="192.0.2.29",
            dst="192.0.2.1",
            severity="medium",
            host="—",
            src_ip="192.0.2.29",
            dst_ip="192.0.2.1",
        ),
        AlertEvent(
            es_id="es-none",
            timestamp=datetime.now(UTC).isoformat(),
            src="192.0.2.26",
            dst="192.0.2.9",
            severity="medium",
            host="—",
            src_ip="192.0.2.26",
            dst_ip="192.0.2.9",
        ),
    ]
    with patch("soc_ai.webui.alerts_query.fetch_group_events", AsyncMock(return_value=events)):
        res = client.get("/api/v1/alerts/events", params={"rule_name": _RULE, "range": "30d"})
    assert res.status_code == 200, res.text
    by_id = {e["id"]: e for e in res.json()}
    assert by_id["es-tp"]["verdict"] == "true_positive"
    assert by_id["es-tp"]["conf"] == pytest.approx(0.62)
    assert by_id["es-tp"]["investigated"] is True
