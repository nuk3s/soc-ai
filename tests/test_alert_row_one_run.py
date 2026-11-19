"""One investigation for one alert row (dogfood 2026-11-17, AA4).

The row showed the worst verdict of the window, the hosts of the newest alert
and "Open report" on the newest run. "Open report" then opened a false
positive under a row that read true positive. The row now carries the source
and the target of the run behind the standing verdict and of the run behind
the window verdict, so the console shows the hosts of the run on its pill.
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
from soc_ai.store.models import Investigation
from soc_ai.webui.alerts_query import AlertGroup, GroupPage

_RULE = "GPL SHELLCODE x86 setgid 0"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        TestClient(create_app()) as c,
    ):
        yield c


def _ago(hours: float) -> datetime:
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _run(
    client: TestClient, run_id: str, *, verdict: str, hours_ago: float, src: str, dst: str
) -> None:
    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            db.add(
                Investigation(
                    id=run_id,
                    alert_es_id=f"es-{run_id}",
                    rule_name=_RULE,
                    status="complete",
                    verdict=verdict,
                    confidence=0.8,
                    src_ip=src,
                    dest_ip=dst,
                    report={"verdict": verdict, "recommended_actions": []},
                    started_by="scheduler",
                    created_at=_ago(hours_ago),
                    finished_at=_ago(hours_ago),
                )
            )
            await db.commit()

    asyncio.run(go())


def _group(client: TestClient) -> dict[str, Any]:
    page = GroupPage(
        [
            AlertGroup(
                rule_name=_RULE,
                count=302,
                severity="medium",
                latest_ts=datetime.now(UTC).isoformat(),
                latest_id="es-latest",
                src_ip="198.51.100.149",
                dst_ip="192.0.2.119",
            )
        ],
        302,
    )
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=page)):
        res = client.get("/api/v1/alerts", params={"range": "24h"})
    assert res.status_code == 200, res.text
    groups: list[dict[str, Any]] = res.json()["groups"]
    return groups[0]


def test_the_row_carries_the_hosts_of_the_true_positive_run_and_of_the_newer_run(
    client: TestClient,
) -> None:
    _run(
        client,
        "INV-TP",
        verdict="true_positive",
        hours_ago=5,
        src="203.0.113.44",
        dst="192.0.2.119",
    )
    _run(
        client,
        "INV-FP",
        verdict="false_positive",
        hours_ago=2,
        src="198.51.100.149",
        dst="192.0.2.119",
    )

    g = _group(client)

    # The worst verdict rule stands: the window verdict is the true positive.
    assert (g["windowVerdict"], g["windowInvId"]) == ("true_positive", "INV-TP")
    assert (g["verdict"], g["invId"]) == ("false_positive", "INV-FP")
    assert (g["windowSrc"], g["windowDst"]) == ("203.0.113.44", "192.0.2.119")
    assert (g["verdictSrc"], g["verdictDst"]) == ("198.51.100.149", "192.0.2.119")
    # The group keeps the flow of its newest alert.
    assert (g["src"], g["dst"]) == ("198.51.100.149", "192.0.2.119")


def test_a_group_with_no_run_carries_no_run_hosts(client: TestClient) -> None:
    """NEGATIVE CONTROL. An untriaged group names no run, so the row keeps its alert flow."""
    g = _group(client)
    assert (g["verdictSrc"], g["verdictDst"], g["windowSrc"], g["windowDst"]) == (None,) * 4
