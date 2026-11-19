"""The prepared row of Needs you: each item states the facts of its decision (NY1).

``GET /needs-you/items`` gives each item its verdict, confidence, impact,
severity, at most three machines with the count of the rest, the time of the
newest event, why it waits and the action that waits with what it writes. A
value that soc-ai does not hold is null, never a guess.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui import needs_you_facts as ny_facts
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui.alerts_query import GroupPage

from tests.test_campaign_facts import (
    LEASED,
    OUTSIDE,
    TARGET,
    alert_doc,
    seed_hosts,
    seed_run,
)

_NO_GROUPS = "soc_ai.webui.alerts_query.fetch_groups"
_GROUPS = "soc_ai.api.webui.routes_alerts.untriaged_group_count"

FIELDS = {
    "type",
    "id",
    "title",
    "detail",
    "since",
    "href",
    "stage",
    "verdict",
    "confidence",
    "impact",
    "severity",
    "machines",
    "machinesMore",
    "eventAt",
    "why",
    "action",
    "machinesDirected",
    "newFacts",
    # The item of a rule with open false positives (round 3, RS3). Null on
    # every other item.
    "count",
    "confident",
    "weak",
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


def _escalate(alert_id: str) -> list[dict[str, Any]]:
    return [
        {
            "tool_name": "escalate_to_case",
            "tool_args": {"alert_id": alert_id, "case_title": "t", "case_description": "d"},
            "rationale": "Open a case for the upload.",
        }
    ]


def _context(alert_id: str, src: str, dst: str, severity: str | None) -> dict[str, Any]:
    from soc_ai.store.auth import utcnow

    doc = alert_doc(alert_id, utcnow(), src=src, dst=dst)
    if severity is not None:
        doc["severity_label"] = severity
    return {"alert": doc}


def _items(client: TestClient, groups: tuple[int, bool] = (0, False)) -> dict[str, Any]:
    with (
        patch(_NO_GROUPS, AsyncMock(return_value=GroupPage([], 0))),
        patch(_GROUPS, AsyncMock(return_value=groups)),
    ):
        res = client.get("/api/v1/needs-you/items")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _by_id(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in body["items"]}


def test_an_investigation_with_a_waiting_action_states_its_facts(client: TestClient) -> None:
    async def work(db: Any) -> str:
        await seed_hosts(db)
        return await seed_run(
            db,
            "alert-x1",
            src=LEASED,
            dst=OUTSIDE,
            context=_context("alert-x1", LEASED, OUTSIDE, "High"),
            report={"recommended_actions": _escalate("alert-x1"), "impact": "succeeded"},
        )

    run = _do(client, work)
    item = _by_id(_items(client))[run]
    assert set(item) == FIELDS
    assert item["verdict"] == "true_positive"
    assert item["confidence"] == pytest.approx(0.85)
    assert item["impact"] == "succeeded"
    assert item["severity"] == "high"
    # The Hosts data names the leased address. The outside address has no name.
    assert item["machines"] == [
        {"name": "laptop-1", "address": LEASED},
        {"name": None, "address": OUTSIDE},
    ]
    assert item["machinesMore"] == 0
    assert item["eventAt"] is not None
    assert item["why"] == "1 recommended action waits for a person."
    assert item["action"] == {
        "label": "Escalate to case",
        "writes": "Opens a case in Security Onion.",
    }


def test_a_verdict_that_needs_more_info_holds_no_impact_and_no_severity(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL. A value that soc-ai does not hold is null, never a guess."""

    async def work(db: Any) -> str:
        await seed_hosts(db)
        return await seed_run(
            db,
            "alert-m1",
            src=OUTSIDE,
            dst=OUTSIDE,
            verdict="needs_more_info",
            context=_context("alert-m1", OUTSIDE, OUTSIDE, None),
        )

    run = _do(client, work)
    item = _by_id(_items(client))[run]
    assert item["verdict"] == "needs_more_info"
    assert item["impact"] is None
    # The stored document states no severity.
    assert item["severity"] is None
    assert item["machines"] == [{"name": None, "address": OUTSIDE}]
    # The run stores no open question, and the row says so (round 3 part 2, P2).
    assert item["why"] == (
        "The verdict needs more info. The investigation states no open question."
    )
    assert item["action"] == ny_facts.VERDICT_ACTION.model_dump()


def test_a_verdict_that_needs_more_info_states_what_soc_ai_needs(client: TestClient) -> None:
    """Round 3 part 2, P2: the 17 rows "Needs more info" of Needs you stated
    no missing fact. The row states the first open question that the
    investigation page shows, from the transcript of the run, and the count."""
    first = "Did web-1 run the downloaded file after 10:02 UTC"
    second = "Which account opened the session from 198.51.100.7?"

    async def work(db: Any) -> tuple[str, str]:
        await seed_hosts(db)
        many = await seed_run(
            db,
            "alert-q1",
            src=OUTSIDE,
            dst=OUTSIDE,
            verdict="needs_more_info",
            events=[
                {"kind": "investigation_transcript", "payload": {"open_questions": [first, second]}}
            ],
        )
        one = await seed_run(
            db,
            "alert-q2",
            src=OUTSIDE,
            dst=OUTSIDE,
            verdict="needs_more_info",
            events=[{"kind": "investigation_transcript", "payload": {"open_questions": [second]}}],
        )
        return many, one

    many, one = _do(client, work)
    items = _by_id(_items(client))
    assert items[many]["why"] == (
        f"The verdict needs more info. The first of 2 open questions: {first}."
    )
    assert items[one]["why"] == f"The verdict needs more info. Open question: {second}"
    # Negative control: a true positive with a waiting action keeps its own why.
    assert all(
        "open question" not in str(i["why"])
        for i in items.values()
        if i["verdict"] != "needs_more_info"
    )


def test_the_why_reads_the_list_that_the_investigation_page_shows() -> None:
    """The row and the page read one function, so the two state one list."""
    assert ny_facts.verdict_why([]).endswith("The investigation states no open question.")
    assert ny_facts.verdict_why(["  ", "Which host?"]) == (
        "The verdict needs more info. Open question: Which host?"
    )


def test_a_severity_outside_the_ladder_is_unknown(client: TestClient) -> None:
    """NEGATIVE CONTROL. A label that is no severity reads as null."""

    async def work(db: Any) -> str:
        return await seed_run(
            db,
            "alert-m2",
            src=OUTSIDE,
            dst=OUTSIDE,
            verdict="needs_more_info",
            context=_context("alert-m2", OUTSIDE, OUTSIDE, "loud"),
        )

    run = _do(client, work)
    assert _by_id(_items(client))[run]["severity"] is None


def test_a_campaign_states_the_worst_impact_and_its_machines(client: TestClient) -> None:
    async def work(db: Any) -> None:
        await seed_hosts(db)
        await seed_run(
            db,
            "alert-h1",
            community_id="1:sess",
            context=_context("alert-h1", "192.0.2.10", TARGET, "Medium"),
            report={"impact": "attempted"},
        )
        await seed_run(
            db,
            "alert-h2",
            event_hours_ago=1,
            context=_context("alert-h2", "192.0.2.10", TARGET, "Critical"),
            report={"impact": "succeeded"},
        )

    _do(client, work)
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    item = _by_id(_items(client))[str(row["id"])]
    assert item["type"] == "campaign"
    # A campaign forms from true positives. It holds no confidence of its own.
    assert item["verdict"] == "true_positive"
    assert item["confidence"] is None
    assert item["impact"] == "succeeded"
    assert item["severity"] == "critical"
    names = {m["name"] for m in item["machines"]}
    assert names == {"web-1", "actor-a"}
    assert item["eventAt"] is not None
    assert item["why"] == "The campaign has no decision."
    assert item["action"]["label"] == "Decide on the campaign"


def test_a_lead_states_its_machines_and_no_verdict(client: TestClient) -> None:
    from tests.test_needs_you_count import _seed_lead

    lead = str(_seed_lead(client))
    item = _by_id(_items(client))[lead]
    assert item["type"] == "lead"
    assert (item["verdict"], item["confidence"], item["impact"], item["severity"]) == (
        None,
        None,
        None,
        None,
    )
    assert item["machines"] == [{"name": None, "address": "10.1.2.3"}]
    # No observation of the lead holds a document time.
    assert item["eventAt"] is None
    assert item["why"] == ny_facts.LEAD_HUNTED_WHY
    assert item["action"]["label"] == "Decide on the lead"


def test_the_alert_groups_name_no_machine(client: TestClient) -> None:
    item = _by_id(_items(client, groups=(4, True)))["alerts"]
    assert item["verdict"] == "untriaged"
    assert item["machines"] is None
    assert item["machinesMore"] == 0
    assert item["eventAt"] is None
    assert item["why"] == "At least 4 alert groups have no verdict in the last 7 days."
    assert item["action"]["label"] == "Set a verdict on each group"


def test_a_row_names_three_machines_and_counts_the_rest() -> None:
    machines = [ny_facts.NeedsYouMachineOut(address=f"192.0.2.{n}") for n in range(1, 6)]
    shown, more = ny_facts.capped([*machines, machines[0]], more=2)
    assert [m.address for m in shown or []] == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    # Two more of the list, and two that the campaign did not list.
    assert more == 4
    assert ny_facts.capped([]) == (None, 0)


# ── The order of the list (NY2) ────────────────────────────────────────────


def _item(type_: str, id_: str, **facts: Any) -> Any:
    from soc_ai.api.webui.routes_meta import NeedsYouItemOut

    return NeedsYouItemOut(type=type_, id=id_, title=id_, detail="", href=f"/{id_}", **facts)


def test_the_groups_come_in_the_order_of_importance() -> None:
    items = [
        _item("alerts", "alerts", verdict="untriaged"),
        _item("investigation", "nmi", verdict="needs_more_info"),
        _item("lead", "lead"),
        _item("investigation", "tp", verdict="true_positive"),
        _item("campaign", "camp", verdict="true_positive"),
    ]
    order = [i.id for i in sorted(items, key=ny_facts.order_key)]
    assert order == ["camp", "tp", "lead", "nmi", "alerts"]


def test_inside_a_group_the_impact_then_the_severity_then_the_newest_event_decide() -> None:
    old, new = "2026-10-01T00:00:00+00:00", "2026-11-16T00:00:00+00:00"
    tp = "true_positive"
    items = [
        _item("investigation", "none", verdict=tp, impact="none", severity="critical", eventAt=new),
        _item("investigation", "unstated", verdict=tp, severity="low", eventAt=new),
        _item("investigation", "unknown", verdict=tp, impact="unknown", severity="high"),
        _item("investigation", "attempted", verdict=tp, impact="attempted", eventAt=old),
        _item("investigation", "succ-old", verdict=tp, impact="succeeded", eventAt=old),
        _item("investigation", "succ-new", verdict=tp, impact="succeeded", eventAt=new),
    ]
    order = [i.id for i in sorted(items, key=ny_facts.order_key)]
    # An impact that the item does not state sorts as unknown.
    assert order == ["succ-new", "succ-old", "attempted", "unknown", "unstated", "none"]


def test_an_item_with_no_impact_sorts_by_severity_and_time() -> None:
    """NEGATIVE CONTROL. No impact is no reason to sort an item first or last."""
    old, new = "2026-10-01T00:00:00+00:00", "2026-11-16T00:00:00+00:00"
    items = [
        _item("lead", "no-time"),
        _item("lead", "low-new", severity="low", eventAt=new),
        _item("lead", "plain-new", eventAt=new),
        _item("lead", "high-old", severity="high", eventAt=old),
        _item("lead", "plain-old", eventAt=old),
    ]
    order = [i.id for i in sorted(items, key=ny_facts.order_key)]
    assert order == ["high-old", "low-new", "plain-new", "plain-old", "no-time"]


def test_the_list_states_the_true_positive_before_the_older_verdicts(client: TestClient) -> None:
    async def work(db: Any) -> dict[str, str]:
        await seed_hosts(db)
        return {
            "old": await seed_run(
                db,
                "alert-o1",
                src=OUTSIDE,
                dst=OUTSIDE,
                verdict="needs_more_info",
                event_hours_ago=40 * 24,
                created_minutes_ago=40 * 24 * 60,
            ),
            "new": await seed_run(
                db,
                "alert-n1",
                src=OUTSIDE,
                dst=OUTSIDE,
                verdict="needs_more_info",
                event_hours_ago=1,
            ),
            "tp": await seed_run(
                db,
                "alert-x1",
                src=LEASED,
                dst=OUTSIDE,
                event_hours_ago=5,
                report={"recommended_actions": _escalate("alert-x1"), "impact": "attempted"},
            ),
        }

    runs = _do(client, work)
    from tests.test_needs_you_count import _seed_lead

    lead = str(_seed_lead(client))
    body = _items(client, groups=(2, False))
    order = [i["id"] for i in body["items"]]
    assert order == [runs["tp"], lead, runs["new"], runs["old"], "alerts"]
    # The cap keeps the most important items, and the total counts every item.
    with patch("soc_ai.api.webui.routes_meta.NEEDS_YOU_ITEMS_MAX", 2):
        capped = _items(client, groups=(2, False))
    assert [i["id"] for i in capped["items"]] == [runs["tp"], lead]
    # Three investigations, the lead and the two alert groups.
    assert capped["total"] == 6


def test_a_lead_of_a_campaign_and_a_decided_campaign_are_no_items(client: TestClient) -> None:
    """NEGATIVE CONTROL. The campaign is the item, and a decision takes it out."""
    from tests.test_campaign_lead_needs_you import _seed as seed_campaign_leads

    seeded = seed_campaign_leads(client)
    body = _items(client)
    assert {i["id"] for i in body["items"] if i["type"] == "lead"} == set()
    assert [i["id"] for i in body["items"] if i["type"] == "campaign"] == [str(seeded["campaign"])]
    res = client.post(
        f"/api/v1/campaigns/{seeded['campaign']}/close", json={"reason": "accepted_risk"}
    )
    assert res.status_code == 200, res.text
    assert [i for i in _items(client)["items"] if i["type"] == "campaign"] == []
    # Open again: the campaign waits again, first in the list.
    client.post(f"/api/v1/campaigns/{seeded['campaign']}/reopen", json={})
    assert _items(client)["items"][0]["id"] == str(seeded["campaign"])
