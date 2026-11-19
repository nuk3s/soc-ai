"""The answers of the hunts and the campaign of a lead in the API (LH3, LH4).

``CampaignOut.answers`` lists what the hunts that read the campaign found,
newest first, and ``CampaignOut.hunts`` lists those hunts with their answer.
``LeadDetailOut.answers`` lists what the other hunts that read the lead found.
``LeadDetailOut.campaign_context`` names the campaign of the lead and its
decision, and ``authorized`` counts the observations whose investigation
matched an authorization.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting import hunt_answers
from soc_ai.main import create_app
from soc_ai.store.auth import utcnow
from soc_ai.store.models import AuthorizedActivity, Hunt, HuntEvent, Investigation, Lead
from sqlalchemy import update

from tests.test_campaign_lead_payloads import _do, _seed


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


_OBSERVATION = {"title": "No new traffic", "category": "observation", "hosts": ["10.40.50.7"]}


def _scheduled_hunt(client: TestClient, hunt_id: str, campaign_id: int, lead_id: int) -> None:
    async def work(db: Any) -> None:
        now = utcnow()
        db.add(
            Hunt(
                id=hunt_id,
                objective="Hunt the network.",
                kind="scheduled",
                starter="schedule",
                status="complete",
                report={"findings": [_OBSERVATION], "narrative": "Nothing new."},
                findings_count=1,
                created_at=now - timedelta(minutes=30),
                finished_at=now - timedelta(minutes=10),
            )
        )
        await db.flush()
        db.add(
            HuntEvent(
                hunt_id=hunt_id,
                sequence=0,
                kind="hunt_started",
                payload={
                    "objective": "Hunt the network.",
                    "campaign_ids": [campaign_id],
                    "earlier_refs": {"leads": [str(lead_id)]},
                },
            )
        )
        db.add(HuntEvent(hunt_id=hunt_id, sequence=1, kind="done", payload={"partial": False}))
        await db.commit()
        assert await hunt_answers.record(db, hunt_id, now=utcnow()) == 2

    _do(client, work)


def test_the_campaign_and_the_lead_show_the_answer_of_a_hunt_that_read_them(
    client: TestClient,
) -> None:
    seeded = _seed(client)
    campaign_id, lead_id = seeded["campaign"], seeded["own"][0]
    _scheduled_hunt(client, "01HUNTREAD", campaign_id, lead_id)
    detail = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    assert detail["answers"][0] == {
        "huntId": "01HUNTREAD",
        "huntAt": detail["answers"][0]["huntAt"],
        "starter": "schedule",
        "outcome": "no_new_event",
        "findingOrdinal": None,
        "findingTitle": None,
    }
    # The fold lists the hunt that read the campaign, with its answer.
    hunts = {h["id"]: h for h in detail["hunts"]}
    assert hunts["01HUNTREAD"]["answer"] == "no_new_event"
    lead = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert [(a["hunt_id"], a["outcome"]) for a in lead["answers"]] == [
        ("01HUNTREAD", "no_new_event")
    ]
    assert lead["campaign_context"] == {
        "id": campaign_id,
        "title": lead["campaign_context"]["title"],
        "decision": None,
        "decided_at": None,
        "decided_by": None,
        "closed_with_campaign": False,
        "closed_at": None,
        "closed_by_decision": None,
        "closed_by": None,
        "reopened_at": None,
    }
    # The negative control: a lead that the hunt did not read holds no answer.
    other = client.get(f"/api/v1/hunts/leads/{seeded['other']}").json()
    assert other["answers"] == []
    assert other["campaign_context"] is None


def test_a_lead_that_closed_with_its_campaign_says_so(client: TestClient) -> None:
    seeded = _seed(client)
    campaign_id, lead_id = seeded["campaign"], seeded["own"][0]
    res = client.post(f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "accepted_risk"})
    assert res.status_code == 200, res.text
    lead = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert lead["status"] == "dismissed"
    context = lead["campaign_context"]
    assert (context["id"], context["decision"], context["closed_with_campaign"]) == (
        campaign_id,
        "closed",
        True,
    )
    assert context["decided_at"].endswith("Z")
    assert context["closed_at"].endswith("Z")

    # N4: a lead that joins the decided campaign later closes later. The
    # payload states the time of the close of the lead, apart from the
    # time of the decision.
    async def later(db: Any) -> None:
        when = utcnow() + timedelta(days=2)
        await db.execute(update(Lead).where(Lead.id == lead_id).values(dismissed_at=when))
        await db.commit()

    _do(client, later)
    context = client.get(f"/api/v1/hunts/leads/{lead_id}").json()["campaign_context"]
    assert context["closed_at"] > context["decided_at"]


def test_a_lead_that_closed_with_its_campaign_states_the_reopen(client: TestClient) -> None:
    """W4: the words follow the state of the campaign at read time, and the lead stays closed.

    Lead 73 read "Its campaign is closed" beside the chip "Campaign 2 · Open".
    """
    from soc_ai.campaigns import decisions
    from soc_ai.store.models import Campaign

    seeded = _seed(client)
    campaign_id, lead_id = seeded["campaign"], seeded["own"][0]
    res = client.post(f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "test_over"})
    assert res.status_code == 200, res.text
    context = client.get(f"/api/v1/hunts/leads/{lead_id}").json()["campaign_context"]
    # A negative control: before the reopen the decision in force names its analyst.
    assert (context["closed_by_decision"], context["closed_by"]) == ("closed", "anonymous")
    assert context["reopened_at"] is None

    async def reopen(db: Any) -> None:
        row = await db.get(Campaign, campaign_id)
        db.add(decisions.reopen(row, decisions.CAUSE_ACTIVITY, utcnow() + timedelta(minutes=5)))
        await db.commit()

    _do(client, reopen)
    lead = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert lead["status"] == "dismissed"
    context = lead["campaign_context"]
    assert (context["decision"], context["closed_with_campaign"]) == (None, True)
    assert (context["closed_by_decision"], context["closed_by"]) == ("closed", "anonymous")
    assert context["reopened_at"] > context["closed_at"]


def test_the_lead_counts_its_authorized_observations(client: TestClient) -> None:
    seeded = _seed(client)
    lead_id = seeded["own"][0]

    async def work(db: Any) -> None:
        now = utcnow()
        record = AuthorizedActivity(
            label="The test of the lab",
            sources=[],
            target_address="10.40.50.7",
            rule_names=[],
            rule_class="any",
            starts_at=now - timedelta(days=1),
            expires_at=now + timedelta(days=1),
            created_by="admin",
        )
        db.add(record)
        await db.flush()
        await db.execute(
            update(Investigation)
            .where(Investigation.alert_es_id == "alert-1")
            .values(authorization_id=record.id)
        )
        await db.commit()

    _do(client, work)
    lead = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert lead["authorized"] == [{"label": "The test of the lab", "observations": 1}]
    # The negative control: a lead whose observations match no authorization.
    other = client.get(f"/api/v1/hunts/leads/{seeded['other']}").json()
    assert other["authorized"] == []
