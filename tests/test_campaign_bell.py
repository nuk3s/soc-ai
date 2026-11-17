"""The bell and the campaigns: one row for each change of a campaign (D7).

A change ``formed``, ``stage``, ``party`` or ``reopened`` of the last 24
hours is one danger row, ``campaign:<change id>``, in the tier of the true
positives. A decision, an acknowledgement and an open again by an analyst
raise no row. The true positive row of an investigation that a campaign
holds is not sent: the row of the campaign speaks for it.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_meta import NotificationOut, by_urgency
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store.auth import utcnow
from soc_ai.store.models import CampaignChange
from sqlalchemy import update

from tests.test_campaign_facts import OUTSIDE, seed_hosts, seed_run


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _seed(client: TestClient, alert_id: str, **over: Any) -> str:
    async def work(db: Any) -> str:
        return await seed_run(db, alert_id, **over)

    run_id: str = _do(client, work)
    return run_id


def _seed_campaign(client: TestClient) -> tuple[int, list[str]]:
    _do(client, seed_hosts)
    runs = [_seed(client, f"alert-000{n}", event_hours_ago=4 - n) for n in (1, 2)]
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    return int(row["id"]), runs


def _bell(client: TestClient) -> list[dict[str, Any]]:
    res = client.get("/api/v1/notifications", params={"limit": 50})
    assert res.status_code == 200, res.text
    rows: list[dict[str, Any]] = res.json()
    return rows


def _campaign_rows(client: TestClient) -> list[dict[str, Any]]:
    return [row for row in _bell(client) if row["id"].startswith("campaign:")]


def test_a_new_campaign_is_one_danger_row_and_its_true_positives_raise_none(
    client: TestClient,
) -> None:
    campaign_id, runs = _seed_campaign(client)
    alone = _seed(client, "alert-x1", src=OUTSIDE, dst=OUTSIDE)
    rows = _bell(client)
    (row,) = [r for r in rows if r["id"].startswith("campaign:")]
    assert row["tone"] == "danger"
    assert row["title"] == "A new campaign formed: actor-a against web-1."
    assert row["href"] == f"/campaigns/{campaign_id}"
    assert row["stage"] == "attempt"
    assert row["at"]
    ids = {r["id"] for r in rows}
    assert not {f"inv-done:{run}" for run in runs} & ids
    # A negative control: a true positive in no campaign keeps its row.
    assert f"inv-done:{alone}" in ids


def test_the_row_id_is_the_change_id_so_a_dismissal_holds(client: TestClient) -> None:
    _seed_campaign(client)
    first = [r["id"] for r in _campaign_rows(client)]
    client.get("/api/v1/campaigns")
    assert [r["id"] for r in _campaign_rows(client)] == first


def test_a_stage_and_a_reopen_by_activity_raise_rows_and_a_person_raises_none(
    client: TestClient,
) -> None:
    campaign_id, _runs = _seed_campaign(client)
    res = client.post(f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "test_over"})
    assert res.status_code == 200, res.text
    assert len(_campaign_rows(client)) == 1
    _seed(client, "alert-s", event_hours_ago=0.5, report={"stage": "access"})
    client.get("/api/v1/campaigns")
    titles = [r["title"] for r in _campaign_rows(client)]
    assert "The campaign actor-a against web-1 reached the stage Access." in titles
    assert "A higher stage opened the campaign actor-a against web-1 again." in titles
    assert len(titles) == 3
    # An open again by an analyst, after a new close, raises no row.
    client.post(f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "test_over"})
    client.post(f"/api/v1/campaigns/{campaign_id}/reopen", json={})
    assert len(_campaign_rows(client)) == 3


def test_a_change_older_than_the_bell_window_raises_no_row(client: TestClient) -> None:
    _seed_campaign(client)

    async def age(db: Any) -> None:
        await db.execute(update(CampaignChange).values(created_at=utcnow() - timedelta(hours=25)))
        await db.commit()

    _do(client, age)
    assert _campaign_rows(client) == []


def test_a_campaign_row_sorts_in_the_tier_of_the_true_positives() -> None:
    now = utcnow().isoformat()
    rows = [
        NotificationOut(id="lead:4", tone="warn", title="Lead", when="", at=now),
        NotificationOut(id="campaign:7", tone="danger", title="Campaign", when="", at=now),
        NotificationOut(id="inv-fp:2", tone="accent", title="Closed", when="", at=now),
    ]
    assert [r.id for r in by_urgency(rows)] == ["campaign:7", "lead:4", "inv-fp:2"]
