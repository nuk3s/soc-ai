"""One rule for a true positive that waits (round "decide once" part 2, OW1 and OW2).

Production on 2026-11-17 held two rules. The tile, the Confirmed threats
panel and the host page said that 16 true positives waited. Needs you listed
13. Two true positives held no recommended action, so no queue asked the
analyst about them. One held an analyst resolution and three text-only
actions, and the tile still said that it waited.

Now a standing true positive is in exactly one part
(:func:`soc_ai.campaigns.threat_parts.part_of`): ``decided``, ``authorized``,
``handled`` or ``waits``. Needs you holds each run that waits and that no
campaign holds, and its count reads the same function.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from soc_ai.api.webui import needs_you_facts as ny_facts
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import AlertEscalation, InvestigationEvent
from soc_ai.webui.alerts_query import AlertEvent, GroupPage
from sqlalchemy import select

from tests.test_threat_decided import _decide
from tests.test_threats_api import (  # noqa: F401
    _ESCALATE,
    OTHER,
    RULE_A,
    _do,
    _seed_campaign,
    _seed_hosts,
    _seed_run,
    _threats,
    client,
)

_TEXT_ONLY = {"tool_name": "isolate_host", "tool_args": {}, "rationale": "Isolate the host."}
_ACK = {"tool_name": "ack_alert", "tool_args": {}, "rationale": "Close the alert."}


def _patched() -> Any:
    return (
        patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=GroupPage([], 0))),
        patch(
            "soc_ai.api.webui.routes_alerts.untriaged_group_count",
            AsyncMock(return_value=(0, False)),
        ),
    )


def _items(client: TestClient) -> dict[str, dict[str, Any]]:  # noqa: F811
    """The investigation items of Needs you, by id."""
    first, second = _patched()
    with first, second:
        res = client.get("/api/v1/needs-you/items")
    assert res.status_code == 200, res.text
    return {i["id"]: i for i in res.json()["items"] if i["type"] == "investigation"}


def _count(client: TestClient) -> dict[str, Any]:  # noqa: F811
    first, second = _patched()
    with first, second:
        res = client.get("/api/v1/needs-you")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _parts(client: TestClient) -> dict[str, Any]:  # noqa: F811
    """The parts of the true positives over all time: the header of the true positives view."""
    res = client.get(
        "/api/v1/investigations", params={"verdict": "true_positive", "tp_parts": "true"}
    )
    assert res.status_code == 200, res.text
    parts: dict[str, Any] = res.json()["truePositiveParts"]
    return parts


def _resolve(client: TestClient, run_id: str) -> None:  # noqa: F811
    """An analyst resolution by chat that keeps the verdict, as the chat resolve writes it."""

    async def work(db: Any) -> None:
        await inv_svc.resolve(
            db,
            run_id,
            verdict="true_positive",
            confidence=0.9,
            rationale="The analyst agrees.",
            recommended_actions=None,
            resolved_by="analyst",
        )

    _do(client, work)


def _surfaces(client: TestClient, run_id: str) -> tuple[bool, bool]:  # noqa: F811
    """(waits on the tile, is an item of Needs you) for one run."""
    body = _threats(client)
    listed = client.get(
        "/api/v1/investigations",
        params={"verdict": "true_positive", "waits": "true"},
    ).json()
    on_tile = run_id in {r["id"] for r in listed["rows"]}
    assert body["waiting"] >= int(on_tile)
    return on_tile, run_id in _items(client)


# ── The part handled ───────────────────────────────────────────────────────


def test_a_resolution_with_text_only_actions_is_handled_on_every_surface(
    client: TestClient,  # noqa: F811
) -> None:
    """The third run of production: a resolution and three text-only actions."""
    _seed_hosts(client)
    run = _seed_run(client, "r-1", actions=[_TEXT_ONLY, _TEXT_ONLY, _TEXT_ONLY])
    _resolve(client, run)
    assert _surfaces(client, run) == (False, False)
    parts = _parts(client)
    assert (parts["handled"], parts["waiting"]) == (1, 0)
    assert _threats(client)["waiting"] == 0


def test_text_only_actions_with_no_resolution_wait_with_their_words(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: the same run with no resolution waits on every surface."""
    _seed_hosts(client)
    run = _seed_run(client, "r-1", actions=[_TEXT_ONLY])
    assert _surfaces(client, run) == (True, True)
    item = _items(client)[run]
    assert item["why"] == ny_facts.NO_EXECUTABLE_ACTION_WHY
    assert item["action"] == {
        "label": "Acknowledge or escalate",
        "writes": "The analyst decides on the investigation page.",
    }


def test_a_resolution_does_not_close_an_open_escalate(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL: a resolution leaves an open write waiting for a person."""
    _seed_hosts(client)
    run = _seed_run(client, "r-1", actions=[_ESCALATE])
    _resolve(client, run)
    assert _surfaces(client, run) == (True, True)
    assert _items(client)[run]["action"]["label"] == "Escalate to case"


def test_a_dismissed_action_makes_the_true_positive_handled_and_an_undo_returns_it(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    run = _seed_run(client, "r-1", actions=[_ESCALATE])
    assert _surfaces(client, run) == (True, True)
    res = client.post(f"/api/v1/investigations/{run}/actions/0/dismiss", json={})
    assert res.status_code == 200, res.text
    assert _surfaces(client, run) == (False, False)
    assert _parts(client)["handled"] == 1
    # NEGATIVE CONTROL: the undo opens the action again, and the run waits.
    res = client.post(f"/api/v1/investigations/{run}/actions/0/restore", json={})
    assert res.status_code == 200, res.text
    assert _surfaces(client, run) == (True, True)


# ── No recommended action ──────────────────────────────────────────────────


def test_a_true_positive_with_no_action_is_one_item_with_the_words(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    run = _seed_run(client, "r-1")
    items = _items(client)
    assert list(items) == [run]
    assert items[run]["why"] == (
        "soc-ai recommends no action. This true positive waits for a decision."
    )
    assert items[run]["action"] == {
        "label": "Acknowledge or escalate",
        "writes": "The analyst decides on the investigation page.",
    }
    assert items[run]["verdict"] == "true_positive"
    body = _count(client)
    assert (body["investigations_waiting"], body["pending_actions"]) == (1, 0)


def test_an_escalated_true_positive_waits_on_no_surface(client: TestClient) -> None:  # noqa: F811
    """A row of the escalation ledger: the analyst escalated the alert."""
    _seed_hosts(client)
    run = _seed_run(client, "r-1")

    async def work(db: Any) -> None:
        db.add(AlertEscalation(alert_id="r-1", escalated_by="analyst", case_id="case-1"))
        await db.commit()

    _do(client, work)
    assert _surfaces(client, run) == (False, False)
    assert _count(client)["investigations_waiting"] == 0
    assert _parts(client)["handled"] == 1


def _ack_press(
    client: TestClient,  # noqa: F811
    run_id: str,
    *,
    rule: str = RULE_A,
    acknowledged: bool = False,
) -> Any:
    """The Acknowledge of the card "No automatic action", on a grid of one event."""
    event = AlertEvent(
        es_id="ev-1",
        timestamp="t",
        src="host-a",
        dst="host-b",
        severity="high",
        host="wks-1",
        acknowledged=acknowledged,
    )

    async def fetch(*_args: Any, **kwargs: Any) -> list[AlertEvent]:
        return [event] if int(kwargs.get("offset", 0)) == 0 else []

    async def write(_tool: str, _args: dict[str, Any], **_kwargs: Any) -> tuple[Any, Any]:
        return ({"acknowledged": True}, None) if not acknowledged else (None, "refused")

    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", fetch),
        patch("soc_ai.api.webui_api.aq.count_group_events", AsyncMock(return_value=1)),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", write),
    ):
        return client.post(
            "/api/v1/alerts/ack-group",
            json={"rule_name": rule, "range": "24h", "investigation_id": run_id},
        )


def _settled(client: TestClient, run_id: str) -> list[dict[str, Any]]:  # noqa: F811
    async def work(db: Any) -> list[dict[str, Any]]:
        rows = await db.scalars(
            select(InvestigationEvent).where(
                InvestigationEvent.investigation_id == run_id,
                InvestigationEvent.kind == "analyst_settled",
            )
        )
        return [dict(e.payload) for e in rows.all()]

    found: list[dict[str, Any]] = _do(client, work)
    return found


def test_the_acknowledge_of_the_card_is_recorded_and_the_run_waits_no_more(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    run = _seed_run(client, "r-1")
    res = _ack_press(client, run)
    assert res.status_code == 200, res.text
    assert res.json()["acked"] == 1
    [record] = _settled(client, run)
    assert (record["action"], record["alerts"]) == ("ack", 1)
    assert _surfaces(client, run) == (False, False)
    assert _parts(client)["handled"] == 1


def test_a_press_for_another_rule_records_nothing(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL: the record names the investigation of the same rule only."""
    _seed_hosts(client)
    run = _seed_run(client, "r-1")
    res = _ack_press(client, run, rule="ET EXPLOIT Another Rule")
    assert res.status_code == 200, res.text
    assert _settled(client, run) == []
    assert _surfaces(client, run) == (True, True)


# ── The negative controls of the contract ──────────────────────────────────


def test_a_false_positive_with_an_open_acknowledge_is_no_item_and_no_wait(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    run = _seed_run(client, "f-1", verdict="false_positive", actions=[_ACK])
    assert run not in _items(client)
    assert _count(client)["investigations_waiting"] == 0
    assert _threats(client)["waiting"] == 0


def test_a_true_positive_of_a_decided_campaign_is_decided_on_every_surface(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    run = _seed_run(client, "d-1")
    _decide(client, _seed_campaign(client, [run]), "closed")
    assert _surfaces(client, run) == (False, False)
    parts = _parts(client)
    assert (parts["decided"], parts["waiting"], parts["handled"]) == (1, 0, 0)
    assert _count(client)["campaigns"] == 0


def test_a_campaign_with_no_decision_is_the_item_and_the_tile_states_the_split(
    client: TestClient,  # noqa: F811
) -> None:
    """A true positive of a campaign with no decision waits on the campaign."""
    _seed_hosts(client)
    first = _seed_run(client, "c-1", minutes_ago=10)
    second = _seed_run(client, "c-2", minutes_ago=20)
    alone = _seed_run(client, "x-1", dst=OTHER, minutes_ago=30)
    _seed_campaign(client, [first, second])
    items = _items(client)
    assert set(items) == {alone}
    body = _threats(client)
    assert (body["waiting"], body["waitingInCampaigns"], body["waitingCampaigns"]) == (3, 2, 1)


def test_the_count_equals_the_list_for_a_seeded_mix(client: TestClient) -> None:  # noqa: F811
    _seed_hosts(client)
    waits_action = _seed_run(client, "m-1", actions=[_ESCALATE], minutes_ago=5)
    waits_none = _seed_run(client, "m-2", minutes_ago=6)
    waits_text = _seed_run(client, "m-3", actions=[_TEXT_ONLY], minutes_ago=7)
    resolved = _seed_run(client, "m-4", actions=[_TEXT_ONLY], minutes_ago=8)
    _resolve(client, resolved)
    escalated = _seed_run(client, "m-5", minutes_ago=9)

    async def work(db: Any) -> None:
        db.add(AlertEscalation(alert_id="m-5", escalated_by="analyst"))
        await db.commit()

    _do(client, work)
    _seed_run(client, "m-6", verdict="false_positive", actions=[_ACK], minutes_ago=10)
    _seed_run(client, "m-7", verdict="needs_more_info", minutes_ago=11)
    held = _seed_run(client, "m-8", dst=OTHER, minutes_ago=12)
    _seed_campaign(client, [held], title="a campaign with no decision")
    decided = _seed_run(client, "m-9", minutes_ago=13)
    _decide(client, _seed_campaign(client, [decided], title="a closed campaign"), "closed")

    items = _items(client)
    body = _count(client)
    listed = client.get("/api/v1/investigations", params={"needs_you": "true"}).json()
    tps = {i for i, item in items.items() if item["verdict"] == "true_positive"}
    assert tps == {waits_action, waits_none, waits_text}
    assert not {resolved, escalated, held, decided} & set(items)
    assert body["investigations_waiting"] == len(items) == listed["total"] == 4
    assert {r["id"] for r in listed["rows"]} == set(items)
    parts = _parts(client)
    assert (parts["waiting"], parts["handled"], parts["decided"]) == (4, 2, 1)
    # The tile counts the waiting true positives of the window, the one of
    # the campaign with no decision included.
    assert _threats(client)["waiting"] == 4


# ── The action of a row (OW3) ──────────────────────────────────────────────


def test_the_row_states_the_escalate_before_the_acknowledge(client: TestClient) -> None:  # noqa: F811
    _seed_hosts(client)
    run = _seed_run(client, "e-1", actions=[_ACK, _ESCALATE])
    item = _items(client)[run]
    assert item["action"] == {
        "label": "Escalate to case",
        "writes": "Opens a case in Security Onion.",
    }
    # NEGATIVE CONTROL: the investigation page keeps the order of the report.
    page = client.get(f"/api/v1/investigations/{run}").json()
    assert [a["tag"] for a in page["actions"]] == ["ack", "escalate"]


def test_a_row_with_an_acknowledge_alone_states_the_acknowledge(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: the rule picks the largest effect that waits, not a fixed type."""
    _seed_hosts(client)
    run = _seed_run(client, "e-1", actions=[_ACK])
    assert _items(client)[run]["action"]["label"] == "Acknowledge"


# ── A decided campaign asks for nothing (OW4) ──────────────────────────────


def test_an_investigation_of_a_closed_campaign_states_the_decision_on_its_card(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    run = _seed_run(client, "k-1", actions=[_ACK, _ESCALATE])
    _decide(client, _seed_campaign(client, [run]), "closed")
    page = client.get(f"/api/v1/investigations/{run}").json()
    decided_at = page["campaign"]["decidedAt"]
    assert decided_at is not None
    when = decided_at[:16].replace("T", " ")
    sentence = f"The analyst closed the campaign on {when} UTC. No action waits."
    ack, escalate = page["actions"]
    assert escalate["blockedReason"] == sentence
    assert ack["note"] == f"Part of the campaign devbox against mainsrv. {sentence}"
    assert not any(a["waits"] for a in page["actions"])


def test_an_investigation_of_a_campaign_with_no_decision_keeps_open_the_case(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: no decision, the card still sends the analyst to the campaign."""
    _seed_hosts(client)
    run = _seed_run(client, "k-1", actions=[_ESCALATE])
    _seed_campaign(client, [run])
    page = client.get(f"/api/v1/investigations/{run}").json()
    assert page["campaign"]["decidedAt"] is None
    assert page["actions"][0]["blockedReason"] == "Open the case on the campaign."
    assert page["actions"][0]["note"].endswith("Decide on the campaign.")


def test_the_words_follow_the_decision() -> None:
    from datetime import datetime

    from soc_ai.api.webui import action_rules

    at = datetime(2026, 11, 15, 14, 2)
    assert action_rules.campaign_decided_sentence("authorized", at) == (
        "The analyst authorized the activity of the campaign on 2026-11-15 14:02 UTC. "
        "No action waits."
    )
    assert action_rules.campaign_decided_sentence("case", "2026-11-15T14:02:00+00:00") == (
        "The analyst opened a case for the campaign on 2026-11-15 14:02 UTC. No action waits."
    )
    # NEGATIVE CONTROL: no decision in force gives no sentence.
    assert action_rules.campaign_decided_sentence(None, at) is None


# ── The Needs you page (OW5) ───────────────────────────────────────────────


def test_a_row_states_a_direction_only_when_the_record_holds_a_source_and_a_target(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    pair = _seed_run(client, "p-1", minutes_ago=5)
    alone = _seed_run(client, "p-2", src=None, minutes_ago=6)
    items = _items(client)
    assert items[pair]["machinesDirected"] is True
    assert len(items[pair]["machines"]) == 2
    # NEGATIVE CONTROL: one host on record gives no direction.
    assert items[alone]["machinesDirected"] is False
