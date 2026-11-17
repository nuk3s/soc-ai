"""The authorization on the campaign page (A6).

``CampaignOut`` states the authorization of the campaign, the true positive
investigations beyond it with the reason, and the excluded investigations. A
member states whether its mark holds and whether an analyst included it. An
arrow of the attack graph is beyond when an investigation beyond the
authorization is on its pair.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_campaign_authorize_api import _authorize, client, seed_campaign
from tests.test_campaign_facts import RULE

__all__ = ["client"]


def test_a_campaign_with_no_authorization_states_none(client: TestClient) -> None:
    campaign_id, _web_1, _web_2 = seed_campaign(client)
    body = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    assert (body["authorization"], body["beyond"], body["excluded"]) == (None, [], [])
    assert {m["authorized"] for m in body["members"]} == {False}
    assert {m["included"] for m in body["members"]} == {False}
    assert {e["beyond"] for e in body["graph"]["edges"]} == {False}


def test_the_page_states_the_authorization_and_the_activity_beyond_it(
    client: TestClient,
) -> None:
    campaign_id, web_1, web_2 = seed_campaign(client)
    unauthorized = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    body = _authorize(client, campaign_id).json()
    held = body["authorization"]
    assert (held["label"], held["note"], held["by"], held["state"]) == (
        "Red team test",
        "The owner runs the test.",
        "anonymous",
        "active",
    )
    assert sorted(held["machineKeys"]) == ["agent:a1", "ip:t1"]
    assert (held["inside"], held["outside"]) == (3, 1)
    assert held["startsAt"] == body["firstEvent"]
    assert held["at"] and held["expiresAt"]
    assert body["decision"]["type"] == "authorized"

    (beyond,) = body["beyond"]
    assert (beyond["runId"], beyond["why"], beyond["label"]) == (web_2, "target", RULE)
    assert (beyond["sourceKey"], beyond["targetKey"]) == ("agent:a1", "ip:t2")
    assert beyond["eventAt"]

    flags = {m["runId"]: m["authorized"] for m in body["members"]}
    assert all(flags[r] for r in web_1)
    assert flags[web_2] is False
    # The arrows keep the meaning of the engine. The page draws the pairs
    # beyond the authorization from the list ``beyond``.
    before = {(e["source"], e["target"]): e["beyond"] for e in unauthorized["graph"]["edges"]}
    assert {(e["source"], e["target"]): e["beyond"] for e in body["graph"]["edges"]} == before


def test_a_revoked_authorization_covers_nothing_and_lists_nothing_beyond(
    client: TestClient,
) -> None:
    campaign_id, _web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    res = client.post(
        f"/api/v1/campaigns/{campaign_id}/revoke-authorization", json={"reason": "Ended."}
    )
    body = res.json()
    assert body["authorization"]["state"] == "revoked"
    assert body["beyond"] == []
    assert body["decision"] is None
    assert {m["authorized"] for m in body["members"]} == {False}


def test_the_page_lists_an_excluded_investigation(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    res = client.post(
        f"/api/v1/campaigns/{campaign_id}/exclude",
        json={"runId": web_1[2], "reason": "Another test."},
    )
    (excluded,) = res.json()["excluded"]
    assert (excluded["runId"], excluded["label"], excluded["by"], excluded["reason"]) == (
        web_1[2],
        RULE,
        "anonymous",
        "Another test.",
    )
    assert excluded["at"]


def test_a_row_of_the_list_states_the_authorization_and_the_count_beyond_it(
    client: TestClient,
) -> None:
    campaign_id, _web_1, _web_2 = seed_campaign(client)
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    assert (row["authorization"], row["beyond"]) == (None, 0)
    body = _authorize(client, campaign_id).json()
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    assert row["authorization"] == {
        "expiresAt": body["authorization"]["expiresAt"],
        "state": "active",
    }
    assert row["beyond"] == 1
    client.post(f"/api/v1/campaigns/{campaign_id}/revoke-authorization", json={"reason": "Ended."})
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    assert (row["authorization"]["state"], row["beyond"]) == ("revoked", 0)
