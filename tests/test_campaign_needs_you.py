"""Needs you and the campaigns: one item for each campaign that waits (D5).

Every active campaign with no decision is one item of the part
``campaigns``, at any age. An investigation that a campaign holds is no item
of its own: it leaves ``pending_actions``, ``investigations_waiting`` and the
Needs you list, by one rule. An investigation in no campaign, and an
investigation whose verdict differs, keep their own place.
``GET /needs-you/items`` lists every item, the most important first, and its
``total`` is the number of the top bar.

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
from soc_ai.store.models import Campaign, Investigation
from soc_ai.webui.alerts_query import GroupPage

from tests.test_campaign_facts import OUTSIDE, TARGET, seed_hosts, seed_run

_NO_GROUPS = "soc_ai.webui.alerts_query.fetch_groups"


def _escalate(alert_id: str) -> dict[str, Any]:
    return {
        "recommended_actions": [
            {
                "tool_name": "escalate_to_case",
                "tool_args": {"alert_id": alert_id, "case_title": "t", "case_description": "d"},
                "rationale": "Open a case for the upload.",
            }
        ]
    }


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


def _seed(client: TestClient) -> dict[str, str]:
    """A campaign of two investigations with an action, and three investigations outside it.

    ``alone`` is a true positive between two addresses of no machine: it is in no campaign.
    ``differs`` is a needs-more-info verdict on the session of the campaign.
    ``old`` is a needs-more-info verdict of 40 days ago, in no campaign.
    """

    async def work(db: Any) -> dict[str, str]:
        await seed_hosts(db)
        runs = {
            "held": await seed_run(
                db, "alert-h1", community_id="1:sess", report=_escalate("alert-h1")
            ),
            "held_2": await seed_run(
                db, "alert-h2", event_hours_ago=1, report=_escalate("alert-h2")
            ),
            "alone": await seed_run(
                db, "alert-x1", src=OUTSIDE, dst=OUTSIDE, report=_escalate("alert-x1")
            ),
            "differs": await seed_run(
                db,
                "alert-d1",
                src=TARGET,
                dst=OUTSIDE,
                verdict="needs_more_info",
                community_id="1:sess",
                event_hours_ago=1.9,
            ),
            "old": await seed_run(
                db,
                "alert-o1",
                src=OUTSIDE,
                dst=OUTSIDE,
                verdict="needs_more_info",
                event_hours_ago=40 * 24,
                created_minutes_ago=40 * 24 * 60,
            ),
        }
        old = await db.get(Investigation, runs["old"])
        old.finished_at = old.created_at
        await db.commit()
        return runs

    runs: dict[str, str] = _do(client, work)
    # The campaign route builds the campaigns.
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    runs["campaign"] = str(row["id"])
    return runs


def _needs_you(client: TestClient) -> dict[str, Any]:
    with patch(_NO_GROUPS, AsyncMock(return_value=GroupPage([], 0))):
        res = client.get("/api/v1/needs-you")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _items(client: TestClient) -> dict[str, Any]:
    with patch(_NO_GROUPS, AsyncMock(return_value=GroupPage([], 0))):
        res = client.get("/api/v1/needs-you/items")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _close(client: TestClient, campaign_id: str) -> None:
    res = client.post(f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "accepted_risk"})
    assert res.status_code == 200, res.text


def test_a_campaign_that_waits_is_one_part_and_its_investigations_are_no_items(
    client: TestClient,
) -> None:
    runs = _seed(client)
    body = _needs_you(client)
    assert body["campaigns"] == 1
    # The investigation in no campaign still waits with its action.
    assert body["pending_actions"] == 1
    # The verdict that differs and the verdict of 40 days ago still wait.
    assert body["needs_more_info"] == 2
    assert body["investigations_waiting"] == 3
    # The campaign and the three investigations that wait.
    assert body["decisions"] == 1 + 3
    assert body["total"] == body["decisions"] + (body["review"] or 0)
    listed = client.get("/api/v1/investigations", params={"needs_you": "true"}).json()
    assert {row["id"] for row in listed["rows"]} == {runs["alone"], runs["differs"], runs["old"]}
    assert listed["total"] == body["investigations_waiting"]
    # The same rule for the action filter of the list.
    pending = client.get("/api/v1/investigations", params={"pending_action": "true"}).json()
    assert {row["id"] for row in pending["rows"]} == {runs["alone"]}


def test_a_closed_campaign_leaves_needs_you_and_its_investigations_stay_out(
    client: TestClient,
) -> None:
    runs = _seed(client)
    _close(client, runs["campaign"])
    body = _needs_you(client)
    assert body["campaigns"] == 0
    assert body["pending_actions"] == 1
    assert body["investigations_waiting"] == 3
    # A negative control: an open again campaign waits again.
    client.post(f"/api/v1/campaigns/{runs['campaign']}/reopen", json={})
    assert _needs_you(client)["campaigns"] == 1


def test_an_ended_campaign_with_no_decision_still_waits(client: TestClient) -> None:
    runs = _seed(client)

    async def age(db: Any) -> None:
        row = await db.get(Campaign, int(runs["campaign"]))
        row.first_event = row.first_event.replace(year=row.first_event.year - 1)
        row.last_event = row.last_event.replace(year=row.last_event.year - 1)
        await db.commit()

    with patch("soc_ai.campaigns.service.ensure_fresh", AsyncMock(return_value=True)):
        _do(client, age)
        assert _needs_you(client)["campaigns"] == 1


def test_the_items_list_each_decision_once_the_most_important_first(client: TestClient) -> None:
    runs = _seed(client)
    body = _items(client)
    assert set(body) == {"items", "total", "unknown"}
    assert body["unknown"] == []
    items = body["items"]
    assert {item["type"] for item in items} == {"campaign", "investigation"}
    from tests.test_needs_you_items_facts import FIELDS

    for item in items:
        assert set(item) == FIELDS
    (campaign,) = [i for i in items if i["type"] == "campaign"]
    assert campaign["id"] == runs["campaign"]
    assert campaign["href"] == f"/campaigns/{runs['campaign']}"
    assert campaign["stage"] == "attempt"
    assert campaign["detail"].startswith("Stage reached: Attempt.")
    ids = [i["id"] for i in items if i["type"] == "investigation"]
    assert set(ids) == {runs["alone"], runs["differs"], runs["old"]}
    # The most important first: the campaign, the true positive, then the two
    # verdicts that need more info with the newest event first. The verdict of
    # 40 days ago led the list before.
    assert [i["id"] for i in items] == [
        runs["campaign"],
        runs["alone"],
        runs["differs"],
        runs["old"],
    ]
    alone = next(i for i in items if i["id"] == runs["alone"])
    assert alone["detail"] == "1 recommended action waits."
    # The count and the list use one rule.
    count = _needs_you(client)
    assert body["total"] == count["campaigns"] + count["investigations_waiting"]
    assert body["total"] == count["decisions"]
    assert body["total"] == len(items)


def test_the_alert_groups_are_one_item_with_their_count(client: TestClient) -> None:
    with patch(
        "soc_ai.api.webui.routes_alerts.untriaged_group_count",
        AsyncMock(return_value=(14, False)),
    ):
        body = client.get("/api/v1/needs-you/items").json()
    (item,) = body["items"]
    assert (item["type"], item["id"], item["since"]) == ("alerts", "alerts", None)
    assert item["detail"] == "14 alert groups have no verdict in the last 7 days."
    assert item["href"] == "/alerts?range=7d&verdict=untriaged"
    # The one item of the alert groups counts its groups in the total.
    assert body["total"] == 14


# ── One rule for the number (R1) ───────────────────────────────────────────

_THREE_GROUPS = "soc_ai.api.webui.routes_alerts.untriaged_group_count"


def _seed_each_part(client: TestClient) -> dict[str, str]:
    """A campaign, an investigation with two waiting actions, a verdict that
    needs more info, a lead. The test adds three alert groups with no verdict."""
    from tests.test_needs_you_count import _seed_lead

    async def work(db: Any) -> dict[str, str]:
        await seed_hosts(db)
        two = _escalate("alert-x1")
        two["recommended_actions"].append(
            {
                "tool_name": "ack_alert",
                "tool_args": {"alert_id": "alert-x1"},
                "rationale": "Close the alert.",
            }
        )
        return {
            "held": await seed_run(
                db, "alert-h1", community_id="1:sess", report=_escalate("alert-h1")
            ),
            "held_2": await seed_run(
                db, "alert-h2", event_hours_ago=1, report=_escalate("alert-h2")
            ),
            "two_actions": await seed_run(db, "alert-x1", src=OUTSIDE, dst=OUTSIDE, report=two),
            "more_info": await seed_run(
                db, "alert-m1", src=OUTSIDE, dst=OUTSIDE, verdict="needs_more_info"
            ),
        }

    runs: dict[str, str] = _do(client, work)
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    runs["campaign"] = str(row["id"])
    runs["lead"] = str(_seed_lead(client))
    return runs


def test_the_number_counts_each_decision_once_and_the_list_states_it(
    client: TestClient,
) -> None:
    runs = _seed_each_part(client)
    with patch(_THREE_GROUPS, AsyncMock(return_value=(3, False))):
        count = client.get("/api/v1/needs-you").json()
        items = client.get("/api/v1/needs-you/items").json()
    # The parts of the number: one campaign, two investigations that wait,
    # one lead and three alert groups.
    assert count["campaigns"] == 1
    assert count["investigations_waiting"] == 2
    assert count["leads_needing_decision"] == 1
    assert count["untriaged_groups"] == 3
    # The detail stays in the payload. It is no part of the sum: the two
    # actions of one investigation are one decision.
    assert count["pending_actions"] == 2
    assert count["needs_more_info"] == 1
    assert count["decisions"] == 1 + 2 + 1 + 3
    assert items["total"] == count["decisions"]
    assert count["total"] == count["decisions"] + (count["review"] or 0)
    ids = {(item["type"], item["id"]) for item in items["items"]}
    assert ids == {
        ("campaign", runs["campaign"]),
        ("investigation", runs["two_actions"]),
        ("investigation", runs["more_info"]),
        ("lead", runs["lead"]),
        ("alerts", "alerts"),
    }


def test_a_part_that_soc_ai_cannot_read_leaves_the_number_a_floor(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL. A failed read of the investigations is no zero."""
    _seed_each_part(client)
    with (
        patch(_THREE_GROUPS, AsyncMock(return_value=(3, False))),
        patch(
            "soc_ai.api.webui.routes_investigations.list_investigations",
            AsyncMock(side_effect=RuntimeError("the store is locked")),
        ),
    ):
        count = client.get("/api/v1/needs-you").json()
    assert count["investigations_waiting"] is None
    assert "investigations_waiting" in count["unknown"]
    # The floor: the campaign, the lead and the three alert groups.
    assert count["decisions"] == 1 + 1 + 3


def test_a_type_that_soc_ai_cannot_read_is_named_and_the_others_stand(
    client: TestClient,
) -> None:
    runs = _seed(client)
    with (
        patch(
            "soc_ai.campaigns.service.waiting_campaigns",
            AsyncMock(side_effect=RuntimeError("the store is locked")),
        ),
        patch(
            "soc_ai.api.webui.routes_alerts.untriaged_group_count",
            AsyncMock(side_effect=ConnectionError("the grid refused the connection")),
        ),
    ):
        body = client.get("/api/v1/needs-you/items").json()
    assert body["unknown"] == ["campaign", "alerts"]
    assert {i["id"] for i in body["items"]} == {runs["alone"], runs["differs"], runs["old"]}
    assert body["total"] == 3


# ── The action card (D6) ───────────────────────────────────────────────────


def test_the_execute_route_refuses_the_escalate_of_a_held_investigation(
    client: TestClient,
) -> None:
    runs = _seed(client)
    write = AsyncMock(return_value=({"case_id": "case-1", "alert_linked": True}, None))
    with patch("soc_ai.api.webui.routes_actions.execute_write_tool", write):
        res = client.post(
            f"/api/v1/investigations/{runs['held']}/actions/0/execute",
            json={},
            headers={"Origin": "http://testserver"},
        )
        assert res.status_code == 409, res.text
        detail = res.json()["detail"]
        assert (detail["reason"], detail["hint"]) == ("campaign", "Open the case on the campaign.")
        assert detail["href"] == f"/campaigns/{runs['campaign']}"
        write.assert_not_called()
        # A negative control: the investigation in no campaign keeps its Escalate.
        with patch(
            "soc_ai.api.webui.routes_actions._reserve_escalate", AsyncMock(return_value=None)
        ):
            alone = client.post(
                f"/api/v1/investigations/{runs['alone']}/actions/0/execute",
                json={},
                headers={"Origin": "http://testserver"},
            )
    assert alone.status_code == 200, alone.text
    assert write.await_count == 1


def test_the_action_of_an_investigation_that_a_campaign_holds_names_the_campaign(
    client: TestClient,
) -> None:
    runs = _seed(client)
    held = client.get(f"/api/v1/investigations/{runs['held']}").json()
    (card,) = held["actions"]
    assert card["noteCode"] == "campaign"
    assert card["note"] == "Part of the campaign actor-a against web-1. Decide on the campaign."
    assert card["noteHref"] == f"/campaigns/{runs['campaign']}"
    # Part C: the campaign opens the one case, so the Escalate is blocked.
    assert card["blockedReason"] == "Open the case on the campaign."
    # A negative control: the investigation in no campaign has no note and
    # keeps its Escalate.
    (alone,) = client.get(f"/api/v1/investigations/{runs['alone']}").json()["actions"]
    assert (alone["noteCode"], alone["note"], alone["noteHref"]) == (None, None, None)
    assert alone["blockedReason"] is None


def test_the_campaign_fact_stops_the_wait_and_blocks_only_the_escalate() -> None:
    from soc_ai.api.webui import action_rules
    from soc_ai.campaigns.service import CampaignLink

    facts = action_rules.ActionFacts(alert_id="alert-h1", run_verdict="true_positive")
    link = CampaignLink(
        id=2, title="actor-a against web-1", status="open", stage=None, differs=False
    )
    held = action_rules.with_campaign(facts, link)
    assert action_rules.action_waits(facts, "escalate_to_case") is True
    assert action_rules.action_waits(held, "escalate_to_case") is False
    assert action_rules.action_waits(held, "ack_alert") is False
    # Part C: the Escalate is blocked with the code campaign. The acknowledge
    # stays executable.
    block = action_rules.action_block(held, "escalate_to_case")
    assert block is not None
    assert (block.code, block.reason) == ("campaign", "Open the case on the campaign.")
    assert action_rules.action_block(held, "ack_alert") is None
    assert action_rules.action_block(facts, "escalate_to_case") is None
    # A negative control: an investigation beyond the authorization keeps its Escalate.
    beyond = CampaignLink(id=2, title="x", status="open", stage=None, differs=False, beyond=True)
    assert (
        action_rules.action_block(action_rules.with_campaign(facts, beyond), "escalate_to_case")
        is None
    )
    note = action_rules.action_note(held)
    assert note is not None and note.code == "campaign"
    # A verdict that differs holds nothing: the run keeps its own place.
    differs = CampaignLink(id=2, title="x", status="open", stage=None, differs=True)
    assert action_rules.with_campaign(facts, differs) == facts
    assert action_rules.with_campaign(facts, None) == facts
    assert action_rules.action_note(facts) is None
