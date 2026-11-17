"""A lead of a campaign closes with the campaign (D6).

A close and an authorization dismiss each open lead of the campaign with a
reason of soc-ai, ``campaign_closed`` or ``campaign_authorized``, and one
lead decision record. A reopen and a revoke change no lead. A lead with an
observation beyond the authorization stays open: outside activity stays loud.
No analyst closes a lead with the reason of a campaign.

The data is synthetic: placeholder addresses, names and rule names.
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
from soc_ai.store import leads as leads_store
from soc_ai.store.models import Lead
from sqlalchemy import select

from tests.test_campaign_authorize_api import _Audit
from tests.test_campaign_facts import RULE_B, seed_run
from tests.test_campaign_lead_tags import ACTOR, TARGET, THIRD, seed_machines


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            app.state.audit = _Audit()
            yield test_client


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _leads(client: TestClient) -> dict[str, Lead]:
    """The leads by the address of their first entity."""

    async def work(db: Any) -> dict[str, Lead]:
        rows = (await db.scalars(select(Lead).order_by(Lead.id))).all()
        return {str(lead.entities_json[0][1]): lead for lead in rows}

    out: dict[str, Lead] = _do(client, work)
    return out


def _seed(client: TestClient, *, third: bool = False) -> int:
    """One campaign of actor-a on web-1, and with ``third`` one more on db-1."""

    async def work(db: Any) -> None:
        await seed_machines(db)
        await seed_run(db, "alert-1", src=ACTOR, dst=TARGET, event_hours_ago=3)
        if third:
            await seed_run(db, "alert-3", src=ACTOR, dst=THIRD, event_hours_ago=1)

    _do(client, work)
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    return int(row["id"])


def _close(client: TestClient, campaign_id: int) -> None:
    res = client.post(f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "accepted_risk"})
    assert res.status_code == 200, res.text


def test_a_close_dismisses_each_lead_of_the_campaign(client: TestClient) -> None:
    campaign_id = _seed(client)
    _close(client, campaign_id)
    for lead in _leads(client).values():
        assert lead.campaign_id == campaign_id
        assert (lead.status, lead.dismissed_reason, lead.dismissed_by) == (
            "dismissed",
            "campaign_closed",
            "system:campaign",
        )
        (record,) = leads_store.decisions_of(lead)
        assert record["action"] == "dismissed"
        assert record["reason"] == "campaign_closed"
        assert record["note"] == f"The analyst closed campaign {campaign_id}."


def test_a_reopen_changes_no_lead(client: TestClient) -> None:
    campaign_id = _seed(client)
    _close(client, campaign_id)
    res = client.post(f"/api/v1/campaigns/{campaign_id}/reopen", json={"note": ""})
    assert res.status_code == 200, res.text
    for lead in _leads(client).values():
        assert lead.status == "dismissed"
        assert len(leads_store.decisions_of(lead)) == 1


def test_an_authorization_dismisses_the_inside_leads_and_keeps_the_outside_ones(
    client: TestClient,
) -> None:
    """The negative control: a lead with an investigation beyond the record stays open."""
    campaign_id = _seed(client, third=True)
    before = _leads(client)
    assert {lead.campaign_id for lead in before.values()} == {campaign_id}
    res = client.post(
        f"/api/v1/campaigns/{campaign_id}/authorize",
        json={
            "label": "Red team test",
            "note": "The owner runs the test.",
            "expiresAt": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
            "machineKeys": ["agent:a1", "ip:t1"],
        },
    )
    assert res.status_code == 200, res.text
    after = _leads(client)
    # The target lead holds the inside investigation only.
    assert (after[TARGET].status, after[TARGET].dismissed_reason) == (
        "dismissed",
        "campaign_authorized",
    )
    # The actor lead holds the investigation beyond the record too, and db-1 holds it alone.
    for address in (ACTOR, THIRD):
        assert after[address].status == "open"
        assert after[address].campaign_id is None


def test_a_lead_that_joins_a_closed_campaign_closes_with_it(client: TestClient) -> None:
    campaign_id = _seed(client)
    _close(client, campaign_id)

    async def late(db: Any) -> list[int]:
        # A late verdict of another rule on an event before the last event.
        await seed_run(db, "alert-late", src=ACTOR, dst=TARGET, rule=RULE_B, event_hours_ago=3.5)
        return [int(i) for i in (await db.scalars(select(Lead.id).where(Lead.status == "open")))]

    formed = _do(client, late)
    assert formed, "the late verdict forms its own lead"
    client.get("/api/v1/campaigns")
    after = {lead.id: lead for lead in _leads_by_id(client)}
    row = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    assert row["decision"]["type"] == "closed"
    for lead_id in formed:
        assert after[lead_id].campaign_id == campaign_id
        assert (after[lead_id].status, after[lead_id].dismissed_reason) == (
            "dismissed",
            "campaign_closed",
        )


def _leads_by_id(client: TestClient) -> list[Lead]:
    async def work(db: Any) -> list[Lead]:
        return list((await db.scalars(select(Lead))).all())

    out: list[Lead] = _do(client, work)
    return out


def test_no_analyst_closes_a_lead_with_the_reason_of_a_campaign(client: TestClient) -> None:
    _seed(client)
    lead = _leads(client)[ACTOR]
    detail = client.get(f"/api/v1/hunts/leads/{lead.id}").json()
    assert "campaign_closed" not in detail["dismiss_reasons"]
    res = client.post(f"/api/v1/hunts/leads/{lead.id}/dismiss", json={"reason": "campaign_closed"})
    assert res.status_code == 422, res.text
    assert set(leads_store.SYSTEM_DISMISS_REASONS).isdisjoint(leads_store.DISMISS_REASONS)
