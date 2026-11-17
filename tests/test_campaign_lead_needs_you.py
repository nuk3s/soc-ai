"""A lead of a campaign waits on its campaign: no Needs you item, no bell row (L5).

The Needs you count, the Needs you list, the Needs decision tab and the bell
read one clause (:func:`soc_ai.store.leads.campaign_lead_clause`). A lead of a
campaign is never "hunt queued". A lead with one observation of another type
keeps its row, and a lead of a withdrawn campaign returns to Needs you.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store.auth import utcnow
from soc_ai.store.models import CampaignRunOverride, EntityObservation, Lead
from soc_ai.webui.alerts_query import GroupPage
from sqlalchemy import select

from tests.test_campaign_facts import seed_run
from tests.test_campaign_lead_tags import ACTOR, TARGET, seed_machines

_NO_GROUPS = "soc_ai.webui.alerts_query.fetch_groups"


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


def _auto_hunt(client: TestClient, on: bool) -> None:
    client.app.state.settings = client.app.state.settings.model_copy(update={"lead_auto_hunt": on})


def _seed(client: TestClient, *, stray: bool = False) -> dict[str, Any]:
    """One campaign from one true positive. Its two ends each form a lead.

    ``stray`` gives the lead on the actor one statistics observation.
    """

    async def work(db: Any) -> dict[str, Any]:
        await seed_machines(db)
        run_id = await seed_run(db, "alert-1", src=ACTOR, dst=TARGET)
        leads = {
            str(entity[0][1]): int(lead_id)
            for lead_id, entity in (await db.execute(select(Lead.id, Lead.entities_json))).all()
        }
        if stray:
            now = utcnow()
            db.add(
                EntityObservation(
                    entity_kind="host",
                    entity_key=ACTOR,
                    kind="above_baseline",
                    spec_id="profile-bytes-out",
                    fingerprint="fp-stat",
                    birth_weight=0.6,
                    born_at=now,
                    first_seen_at=now,
                    source="profile",
                    lead_id=leads[ACTOR],
                )
            )
            await db.commit()
        return {"run": run_id, "actor": leads[ACTOR], "target": leads[TARGET]}

    seeded: dict[str, Any] = _do(client, work)
    # The campaign route builds the campaigns, and the step after it tags the leads.
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    seeded["campaign"] = int(row["id"])
    return seeded


def _lead_items(client: TestClient) -> tuple[set[str], int]:
    with patch(_NO_GROUPS, AsyncMock(return_value=GroupPage([], 0))):
        body = client.get("/api/v1/needs-you/items").json()
    ids = {item["id"] for item in body["items"] if item["type"] == "lead"}
    return ids, int(client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"])


def _tab(client: TestClient) -> set[int]:
    rows = client.get("/api/v1/leads", params={"status": "needs_decision"}).json()
    return {int(r["id"]) for r in rows}


def _bell(client: TestClient) -> set[str]:
    return {n["id"] for n in client.get("/api/v1/notifications").json()}


def test_a_lead_of_a_campaign_is_no_item_and_no_bell_row(client: TestClient) -> None:
    _auto_hunt(client, False)
    seeded = _seed(client)
    items, count = _lead_items(client)
    assert items == set()
    assert count == 0
    assert _tab(client) == set()
    assert not {f"lead:{seeded['actor']}", f"lead:{seeded['target']}"} & _bell(client)


def test_a_lead_of_a_campaign_is_never_hunt_queued(client: TestClient) -> None:
    _auto_hunt(client, True)
    seeded = _seed(client)
    rows = {int(r["id"]): r for r in client.get("/api/v1/leads").json()}
    assert rows[seeded["actor"]]["hunt_queued"] is False
    detail = client.get(f"/api/v1/hunts/leads/{seeded['actor']}").json()
    assert detail["hunt_queued"] is False


def test_a_lead_with_a_statistics_observation_keeps_its_place(client: TestClient) -> None:
    """The negative control (L8): one observation of another type keeps normal handling."""
    _auto_hunt(client, False)
    seeded = _seed(client, stray=True)
    items, count = _lead_items(client)
    assert items == {str(seeded["actor"])}
    assert count == 1
    assert _tab(client) == {seeded["actor"]}
    assert f"lead:{seeded['actor']}" in _bell(client)
    assert f"lead:{seeded['target']}" not in _bell(client)
    _auto_hunt(client, True)
    rows = {int(r["id"]): r for r in client.get("/api/v1/leads").json()}
    assert rows[seeded["actor"]]["hunt_queued"] is True
    assert rows[seeded["target"]]["hunt_queued"] is False


def test_a_lead_returns_to_needs_you_when_its_campaign_is_withdrawn(client: TestClient) -> None:
    """The negative control (L8): the tag follows the engine."""
    _auto_hunt(client, False)
    seeded = _seed(client)
    assert _lead_items(client) == (set(), 0)

    async def exclude(db: Any) -> None:
        db.add(
            CampaignRunOverride(
                run_id=seeded["run"],
                type="excluded",
                campaign_id=seeded["campaign"],
                by="analyst",
                reason="A test of the lab.",
                created_at=utcnow(),
            )
        )
        await db.commit()

    _do(client, exclude)
    # The route rebuilds. The campaign is withdrawn, and the step removes the tag.
    assert client.get("/api/v1/campaigns").json()["rows"] == []
    items, count = _lead_items(client)
    assert items == {str(seeded["actor"]), str(seeded["target"])}
    assert count == 2
    assert {f"lead:{seeded['actor']}", f"lead:{seeded['target']}"} <= _bell(client)


def _count(client: TestClient, status: str, **params: str) -> dict[str, Any]:
    res = client.get("/api/v1/leads/count", params={"status": status, **params})
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_the_lead_tabs_count_the_leads_that_wait_on_a_campaign(client: TestClient) -> None:
    """The tabs and ``in_campaign`` sum to the All tab. No lead reads as waiting on auto-hunt."""
    _auto_hunt(client, False)
    seeded = _seed(client)

    async def hunting(db: Any) -> None:
        from soc_ai.store.models import Hunt

        db.add(Hunt(id="01HUNTRUN", objective="x", status="running", lead_id=seeded["actor"]))
        lead = await db.get(Lead, seeded["actor"])
        lead.status, lead.hunt_id = "hunting", "01HUNTRUN"
        await db.commit()

    _do(client, hunting)
    tabs = {s: _count(client, s) for s in ("needs_decision", "in_progress", "closed", "all")}
    tabs["fleet_condition"] = _count(client, "fleet_condition")
    assert tabs["all"]["total"] == 2
    assert tabs["all"]["in_campaign"] == 2
    assert tabs["needs_decision"]["total"] == 0
    assert tabs["in_progress"]["total"] == 0
    in_tabs = sum(tabs[s]["total"] for s in ("needs_decision", "in_progress", "closed"))
    assert tabs["all"]["total"] - in_tabs - tabs["fleet_condition"]["total"] == 2
    # The list of a tab agrees with its count.
    rows = client.get("/api/v1/leads", params={"status": "in_progress"}).json()
    assert rows == []
    # The entity filter reads the same rule.
    assert _count(client, "all", entity=ACTOR)["in_campaign"] == 1


def test_a_lead_with_a_statistics_observation_counts_in_its_tab(client: TestClient) -> None:
    """The negative control: a lead that no campaign holds is in no campaign count."""
    _auto_hunt(client, False)
    _seed(client, stray=True)
    assert _count(client, "all")["in_campaign"] == 1
    assert _count(client, "needs_decision")["total"] == 1
