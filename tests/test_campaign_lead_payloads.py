"""The campaign of a lead and of a hunt in the API (L7).

``LeadOut.campaign``, ``HuntOut.campaign`` and the ``campaign`` of a hunt list
row are the campaign link. ``CampaignOut.leads`` lists the leads of the
campaign and, with ``related`` true, the leads that no campaign holds on a
machine of the campaign in its period. ``CampaignOut.hunts`` lists the hunts
for the campaign, the newest first, at most 20. The Hunts type filter takes
``campaign``.

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
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Campaign, EntityObservation, Hunt, HuntEvent, Lead
from sqlalchemy import select

from tests.test_campaign_facts import RULE_B, seed_run
from tests.test_campaign_lead_tags import ACTOR, TARGET, seed_machines

_LINK = {"id", "title", "status", "stage", "differs", "decision", "state"}


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


def _observation(lead_id: int, entity: str, at: Any, fingerprint: str) -> EntityObservation:
    return EntityObservation(
        entity_kind="host",
        entity_key=entity,
        kind="above_baseline",
        spec_id="profile-bytes-out",
        fingerprint=fingerprint,
        birth_weight=0.6,
        born_at=at,
        first_seen_at=at,
        observed_at=at,
        source="profile",
        lead_id=lead_id,
    )


def _seed(client: TestClient) -> dict[str, Any]:
    """A campaign from 3 h to 1 h ago, its two leads, and three leads beside it.

    ``related`` is a lead with an observation on the actor 2 h ago. ``late``
    is a lead with an observation on the actor 10 h after the period.
    ``other`` is a lead on a machine of no campaign.
    """

    async def work(db: Any) -> dict[str, Any]:
        await seed_machines(db)
        await seed_run(db, "alert-1", src=ACTOR, dst=TARGET, event_hours_ago=3)
        await seed_run(db, "alert-2", src=ACTOR, dst=TARGET, rule=RULE_B, event_hours_ago=1)
        own = sorted(int(i) for i in (await db.scalars(select(Lead.id))).all())
        now = utcnow()
        made: dict[str, int] = {}
        for name, entity, at in (
            ("related", ACTOR, now - timedelta(hours=2)),
            ("late", ACTOR, now + timedelta(hours=9)),
            ("other", "10.40.50.33", now - timedelta(hours=2)),
        ):
            lead = Lead(
                status="open", shadow=False, formed_at=now, entities_json=[["host", entity]]
            )
            db.add(lead)
            await db.flush()
            db.add(_observation(int(lead.id), entity, at, f"fp-{name}"))
            made[name] = int(lead.id)
        await db.commit()
        return {"own": own, **made}

    seeded: dict[str, Any] = _do(client, work)
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    seeded["campaign"] = int(row["id"])
    return seeded


def test_a_lead_of_a_campaign_names_its_campaign(client: TestClient) -> None:
    seeded = _seed(client)
    rows = {int(r["id"]): r for r in client.get("/api/v1/leads", params={"status": "all"}).json()}
    for lead_id in seeded["own"]:
        link = rows[lead_id]["campaign"]
        assert set(link) == _LINK
        assert (link["id"], link["differs"], link["decision"]) == (seeded["campaign"], False, None)
        detail = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
        assert detail["campaign"]["id"] == seeded["campaign"]
    # The negative control: a lead that no campaign holds names none.
    assert rows[seeded["related"]]["campaign"] is None


def test_the_campaign_lists_its_leads_and_its_related_leads(client: TestClient) -> None:
    seeded = _seed(client)
    detail = client.get(f"/api/v1/campaigns/{seeded['campaign']}").json()
    leads = detail["leads"]
    for lead in leads:
        assert set(lead) == {"id", "title", "state", "hunted", "related"}
    own = [lead for lead in leads if not lead["related"]]
    related = [lead for lead in leads if lead["related"]]
    assert [lead["id"] for lead in own] == seeded["own"]
    assert {lead["state"] for lead in own} == {"open"}
    assert own[0]["title"].startswith(f"Lead {seeded['own'][0]} on ")
    assert [lead["id"] for lead in related] == [seeded["related"]]
    # The negative controls: an observation outside the period, and a machine
    # of no campaign, list no lead.
    assert seeded["late"] not in {lead["id"] for lead in leads}
    assert seeded["other"] not in {lead["id"] for lead in leads}


def test_the_campaign_lists_its_hunts_newest_first(client: TestClient) -> None:
    seeded = _seed(client)
    campaign_id = seeded["campaign"]
    now = utcnow()

    async def work(db: Any) -> None:
        merged = Campaign(
            status="merged",
            merged_into_id=campaign_id,
            seed_run_id="seed",
            title="t",
            bottom_line="b",
            first_event=now,
            last_event=now,
            member_count=1,
            detail={},
            built_at=now,
        )
        db.add(merged)
        await db.flush()
        for n in range(22):
            db.add(
                Hunt(
                    id=f"01HUNT{n:02d}",
                    objective=f"[campaign {campaign_id}] x",
                    kind="campaign",
                    starter="campaign",
                    started_by="campaign-hunt",
                    status="complete",
                    campaign_id=campaign_id,
                    created_at=now - timedelta(hours=30 + n),
                    findings_count=2,
                    threat_findings_count=1,
                )
            )
        db.add(
            Hunt(
                id="01HUNTLEAD",
                objective="[lead 1] x",
                kind="lead",
                starter="lead",
                lead_id=seeded["own"][0],
                campaign_id=merged.id,
                status="running",
                created_at=now,
            )
        )
        db.add(
            Hunt(
                id="01HUNTEVAL",
                objective="x",
                is_synth_eval=True,
                campaign_id=campaign_id,
                created_at=now,
            )
        )
        await db.commit()

    _do(client, work)
    detail = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    hunts = detail["hunts"]
    assert len(hunts) == 20
    assert hunts[0] == {
        "id": "01HUNTLEAD",
        "starter": "lead",
        "status": "running",
        "startedAt": hunts[0]["startedAt"],
        "findings": 0,
        "threatFindings": 0,
        "answer": None,
        "steps": None,
    }
    assert hunts[1]["id"] == "01HUNT00"
    assert (hunts[1]["starter"], hunts[1]["findings"], hunts[1]["threatFindings"]) == (
        "campaign",
        2,
        1,
    )
    assert [h["startedAt"] for h in hunts] == sorted((h["startedAt"] for h in hunts), reverse=True)
    # The negative control: an evaluation hunt is no hunt of the campaign.
    assert "01HUNTEVAL" not in {h["id"] for h in hunts}
    # A lead of the campaign that had a hunt reads hunted.
    leads = {lead["id"]: lead for lead in detail["leads"]}
    assert leads[seeded["own"][0]]["hunted"] is True


def test_a_hunt_names_its_campaign_and_the_type_filter_takes_campaign(client: TestClient) -> None:
    seeded = _seed(client)
    campaign_id = seeded["campaign"]

    async def work(db: Any) -> None:
        db.add(
            Hunt(
                id="01HUNTCAMP",
                objective=f"[campaign {campaign_id}] Hunt for new activity.",
                kind="campaign",
                starter="campaign",
                started_by="campaign-hunt",
                status="complete",
                campaign_id=campaign_id,
            )
        )
        db.add(Hunt(id="01HUNTCHAT", objective="Hunt the network.", status="complete"))
        await db.commit()

    _do(client, work)
    rows = {r["id"]: r for r in client.get("/api/v1/hunts").json()}
    assert rows["01HUNTCAMP"]["campaign"]["id"] == campaign_id
    assert set(rows["01HUNTCAMP"]["campaign"]) == _LINK
    assert rows["01HUNTCAMP"]["starter"] == "campaign"
    assert rows["01HUNTCAMP"]["title"] == f"Campaign {campaign_id} hunt"
    assert rows["01HUNTCHAT"]["campaign"] is None
    detail = client.get("/api/v1/hunts/01HUNTCAMP").json()
    assert detail["campaign"]["id"] == campaign_id
    only = client.get("/api/v1/hunts", params={"kind": "campaign"}).json()
    assert [r["id"] for r in only] == ["01HUNTCAMP"]
    totals = client.get("/api/v1/hunts/totals").json()
    assert totals["by_kind"]["campaign"]["hunts"] == 1


def test_a_withdrawn_campaign_names_no_lead_and_no_hunt(client: TestClient) -> None:
    """The negative control: the link reads an active campaign only."""
    seeded = _seed(client)

    async def work(db: Any) -> None:
        row = await db.get(Campaign, seeded["campaign"])
        row.status = "withdrawn"
        db.add(Hunt(id="01HUNTW", objective="x", status="complete", campaign_id=row.id))
        await db.commit()

    _do(client, work)
    rows = {int(r["id"]): r for r in client.get("/api/v1/leads", params={"status": "all"}).json()}
    assert all(rows[lead_id]["campaign"] is None for lead_id in seeded["own"])
    hunts = {r["id"]: r for r in client.get("/api/v1/hunts").json()}
    assert hunts["01HUNTW"]["campaign"] is None


def test_the_fold_counts_the_steps_of_a_hunt_that_stopped(client: TestClient) -> None:
    """F5: the fold reads "Stopped with an error after N steps", as the hunt
    page does. The payload carries the steps of a hunt that stopped."""
    seeded = _seed(client)
    campaign_id = seeded["campaign"]
    now = utcnow()

    async def work(db: Any) -> None:
        for hunt_id, status in (("01HUNTSTOP", "error"), ("01HUNTDONE", "complete")):
            db.add(
                Hunt(
                    id=hunt_id,
                    objective=f"[campaign {campaign_id}] x",
                    kind="campaign",
                    starter="campaign",
                    status=status,
                    campaign_id=campaign_id,
                    created_at=now,
                )
            )
            await db.flush()
            for seq, kind in enumerate(("tool_call", "tool_result", "tool_call")):
                db.add(HuntEvent(hunt_id=hunt_id, sequence=seq, kind=kind, payload={}))
        await db.commit()

    _do(client, work)
    hunts = {h["id"]: h for h in client.get(f"/api/v1/campaigns/{campaign_id}").json()["hunts"]}
    assert hunts["01HUNTSTOP"]["steps"] == 2
    # Negative control: a complete hunt carries no stop count.
    assert hunts["01HUNTDONE"]["steps"] is None
