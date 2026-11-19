"""Needs you and the bell of an authorized campaign (A7).

Each loud case stays loud: an investigation beyond the authorization of its
campaign is not held by the campaign. Its action waits, it is a Needs you
item of its own, and it has its bell row. The campaign states one danger
row for it. An inside investigation stays quiet. A higher stage of a
campaign with an authorization in force is a neutral row. A revoke raises
no row, because a person made it.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from soc_ai.campaigns import decisions
from soc_ai.store.auth import utcnow

from tests.test_campaign_authorize_api import _ESCALATE, _authorize, _do, client
from tests.test_campaign_facts import TARGET_2, seed_hosts, seed_run

__all__ = ["client"]

_ACTIONS = {"recommended_actions": [_ESCALATE]}


def _seed(client: TestClient) -> tuple[int, str, str]:
    """One campaign: two investigations on web-1 and one on web-2, each with an escalate."""

    async def work(db: Any) -> tuple[str, str]:
        await seed_hosts(db)
        inside = await seed_run(
            db, "alert-0001", event_hours_ago=3, created_minutes_ago=40, report=_ACTIONS
        )
        await seed_run(db, "alert-0002", event_hours_ago=2, created_minutes_ago=30)
        outside = await seed_run(
            db,
            "alert-0003",
            dst=TARGET_2,
            event_hours_ago=1,
            created_minutes_ago=20,
            report=_ACTIONS,
        )
        return inside, outside

    inside, outside = _do(client, work)
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    return int(row["id"]), inside, outside


def _waiting(client: TestClient) -> set[str]:
    res = client.get("/api/v1/investigations", params={"needs_you": "true", "range": "all"})
    return {r["id"] for r in res.json()["rows"]}


def _bell(client: TestClient) -> dict[str, dict[str, Any]]:
    rows = client.get("/api/v1/notifications", params={"limit": 50}).json()
    return {r["id"]: r for r in rows}


def test_an_investigation_beyond_the_authorization_waits_on_its_own(client: TestClient) -> None:
    campaign_id, inside, outside = _seed(client)
    # No decision: the campaign holds both. The campaign is the one item.
    assert _waiting(client).isdisjoint({inside, outside})
    assert f"inv-done:{outside}" not in _bell(client)

    assert _authorize(client, campaign_id).status_code == 200

    # The investigation on the unlisted web-2 is beyond the authorization.
    assert outside in _waiting(client)
    count = client.get("/api/v1/needs-you").json()
    assert count["pending_actions"] >= 1
    assert count["campaigns"] == 0, "the authorized campaign waits on nothing"
    bell = _bell(client)
    assert bell[f"inv-done:{outside}"]["tone"] == "danger"
    beyond = [
        r for r in bell.values() if r["title"].startswith("Activity beyond the authorization")
    ]
    assert len(beyond) == 1
    assert beyond[0]["tone"] == "danger"
    assert beyond[0]["href"] == f"/campaigns/{campaign_id}"
    page = client.get(f"/api/v1/investigations/{outside}").json()
    assert "beyond" not in page["campaign"], "the answer has no new field"
    assert {a.get("noteCode") for a in page["actions"]} == {None}, "the card waits on its own"
    items = client.get("/api/v1/needs-you/items").json()["items"]
    (item,) = [i for i in items if i["id"] == outside]
    assert item["detail"].startswith("Beyond the authorization of the campaign ")
    # The row states `why`, and the sentence keeps the count of the actions.
    assert item["why"].startswith("The investigation is beyond the authorization of the campaign ")
    assert item["why"].endswith(" recommended action waits for a person.")

    # A negative control: the inside investigation stays quiet.
    assert inside not in _waiting(client)
    assert f"inv-done:{inside}" not in bell
    assert inside not in {i["id"] for i in client.get("/api/v1/needs-you/items").json()["items"]}


def test_a_higher_stage_under_an_authorization_in_force_is_a_neutral_row(
    client: TestClient,
) -> None:
    campaign_id, _inside, _outside = _seed(client)

    def stage_change() -> None:
        async def work(db: Any) -> None:
            db.add(
                decisions.change(
                    campaign_id,
                    decisions.CHANGE_STAGE,
                    {"from": "attempt", "to": "access"},
                    utcnow(),
                )
            )
            await db.commit()

        _do(client, work)

    stage_change()
    loud = [r for r in _bell(client).values() if "reached the stage" in r["title"]]
    assert [r["tone"] for r in loud] == ["danger"]

    assert _authorize(client, campaign_id).status_code == 200
    stage_change()
    rows = [r for r in _bell(client).values() if "reached the stage" in r["title"]]
    assert sorted(r["tone"] for r in rows) == ["accent", "accent"]


def test_a_revoke_raises_no_row_and_the_campaign_waits_as_one_item(client: TestClient) -> None:
    campaign_id, inside, outside = _seed(client)
    assert _authorize(client, campaign_id).status_code == 200
    res = client.post(
        f"/api/v1/campaigns/{campaign_id}/revoke-authorization", json={"reason": "Ended."}
    )
    assert res.status_code == 200
    assert not [r["title"] for r in _bell(client).values() if "opened the campaign" in r["title"]]
    assert client.get("/api/v1/needs-you").json()["campaigns"] == 1
    # The campaign holds both again.
    assert _waiting(client).isdisjoint({inside, outside})


def _case_runs(client: TestClient, case: str) -> tuple[int, str, str]:
    """A campaign, its authorization, and one investigation of a loud case.

    Returns the campaign id, an inside investigation and the investigation of
    the case. Each has an escalate action.
    """
    from datetime import timedelta

    from soc_ai.store.models import AuthorizedActivity, HostDossier, HostMachine
    from sqlalchemy import select

    from tests.test_campaign_facts import ACTOR, ACTOR_2, TARGET

    async def first(db: Any) -> str:
        await seed_hosts(db)
        return await seed_run(
            db, "alert-0001", event_hours_ago=5, created_minutes_ago=50, report=_ACTIONS
        )

    inside = _do(client, first)
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    campaign_id = int(row["id"])
    assert _authorize(client, campaign_id, machineKeys=["agent:a1", "ip:t1"]).status_code == 200

    async def loud(db: Any) -> str:
        fields: dict[str, Any] = {"event_hours_ago": 1, "created_minutes_ago": 5}
        if case == "a source that is not listed":
            fields["src"] = ACTOR_2
        elif case == "a listed target as the source against an unlisted machine":
            fields.update(src=TARGET, dst=TARGET_2)
        elif case == "a listed actor against a target that is not listed":
            fields["dst"] = TARGET_2
        elif case == "an event after the expiry":
            record = (await db.scalars(select(AuthorizedActivity))).one()
            record.expires_at = utcnow() - timedelta(hours=2)
            await db.commit()
        elif case == "an address that now resolves to another machine":
            other = (
                await db.scalars(select(HostMachine).where(HostMachine.machine_key == "agent:a2"))
            ).one()
            dossier = (await db.scalars(select(HostDossier).where(HostDossier.ip == ACTOR))).one()
            dossier.machine_id = other.id
            await db.commit()
        return await seed_run(db, "alert-0002", report=_ACTIONS, **fields)

    return campaign_id, inside, _do(client, loud)


@pytest.mark.parametrize(
    "case",
    [
        "a source that is not listed",
        "a listed target as the source against an unlisted machine",
        "a listed actor against a target that is not listed",
        "an event after the expiry",
        "an address that now resolves to another machine",
    ],
)
def test_each_loud_case_waits_is_an_item_and_has_its_bell_row(
    client: TestClient, case: str
) -> None:
    campaign_id, inside, outside = _case_runs(client, case)
    # The page reads the campaigns again after the new investigation.
    body = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    runs = {
        inv["id"]: inv
        for inv in client.get(
            "/api/v1/investigations", params={"range": "all", "limit": 50}
        ).json()["rows"]
    }
    assert runs[outside].get("authorization") is None, case
    items = client.get("/api/v1/needs-you/items").json()["items"]
    held = client.get(f"/api/v1/investigations/{outside}").json()["campaign"]
    if held is not None and held["id"] != campaign_id:
        # The investigation starts a campaign of its own, with no decision:
        # normal handling. That campaign is the item, with its bell row.
        assert held["decision"] is None, case
        assert str(held["id"]) in {i["id"] for i in items if i["type"] == "campaign"}, case
        rows = [r for r in _bell(client).values() if r["href"] == f"/campaigns/{held['id']}"]
        assert rows and {r["tone"] for r in rows} == {"danger"}, case
    else:
        assert outside in _waiting(client), case
        assert outside in {i["id"] for i in items if i["type"] == "investigation"}, case
        assert _bell(client)[f"inv-done:{outside}"]["tone"] == "danger", case
    if outside in {m["runId"] for m in body["members"]}:
        assert outside in {b["runId"] for b in body["beyond"]}, case
    # A negative control: the inside investigation stays quiet.
    assert inside not in _waiting(client), case
    assert f"inv-done:{inside}" not in _bell(client), case
