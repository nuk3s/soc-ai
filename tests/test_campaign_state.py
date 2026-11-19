"""The one state of a campaign on every payload (DC1, round "decide once").

The campaign header showed the chip "Open" above "admin closed this
campaign", and the list, the Confirmed threats row and the host page showed
"Open" beside "Closed". Each payload now carries ``state``: the decision when
one is in force (:func:`soc_ai.campaigns.decisions.in_force`, the rule that
takes a campaign out of Needs you), else the activity status.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from soc_ai.campaigns import decisions
from soc_ai.campaigns import service as campaign_svc

from tests.test_campaign_decision_api import _close, _seed_campaign, client  # noqa: F401


@pytest.mark.parametrize(
    ("status", "decision", "state"),
    [
        ("open", None, "open"),
        ("ended", None, "ended"),
        ("open", "closed", "closed"),
        ("ended", "closed", "closed"),
        ("open", "authorized", "authorized"),
        ("ended", "case", "case"),
        # A merged or a withdrawn campaign states its status: no decision of
        # it is in force.
        ("merged", "closed", "merged"),
        ("withdrawn", None, "withdrawn"),
    ],
)
def test_the_state_is_the_decision_in_force_else_the_status(
    status: str, decision: str | None, state: str
) -> None:
    assert campaign_svc.api_state(status, decision) == state


def test_the_decision_in_force_is_the_rule_of_needs_you() -> None:
    assert decisions.in_force(None) is False
    for decision in decisions.DECISIONS:
        assert decisions.in_force(decision) is True
    # The same rule gives the wait: a campaign with a decision in force waits
    # on nothing.
    from datetime import datetime

    first = datetime(2026, 11, 1, 8, 0)
    assert decisions.waits_since("closed", first, None) is None
    assert decisions.waits_since(None, first, None) == first


def _states(client: TestClient, campaign_id: int) -> dict[str, set[str]]:  # noqa: F811
    """The state of the campaign on each payload that names it."""
    detail = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    rows = client.get("/api/v1/campaigns").json()["rows"]
    page = client.get("/api/v1/investigations").json()["rows"]
    host = client.get("/api/v1/hosts/agent:a1").json()["campaigns"]
    return {
        "detail": {detail["state"]},
        "list": {r["state"] for r in rows if r["id"] == campaign_id},
        "links": {r["campaign"]["state"] for r in page if r.get("campaign")},
        "host": {c["state"] for c in host if c["id"] == campaign_id},
    }


def test_every_payload_states_one_state_through_a_close_and_an_open_again(
    client: TestClient,  # noqa: F811
) -> None:
    campaign_id = _seed_campaign(client)
    waits = _states(client, campaign_id)
    assert waits == {name: {"open"} for name in waits}

    assert _close(client, campaign_id).status_code == 200
    closed = _states(client, campaign_id)
    assert closed == {name: {"closed"} for name in closed}
    # The status and the decision stay. The state does not replace them.
    detail = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    assert (detail["status"], detail["decision"]["type"]) == ("open", "closed")

    # Negative control: "Open again" clears the decision, and each payload
    # states the activity status again.
    assert client.post(f"/api/v1/campaigns/{campaign_id}/reopen", json={}).status_code == 200
    again = _states(client, campaign_id)
    assert again == {name: {"open"} for name in again}
