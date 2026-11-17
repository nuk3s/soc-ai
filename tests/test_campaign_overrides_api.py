"""Exclude, include and undo on a campaign (A5).

An analyst excludes an investigation of a campaign with a reason: it joins
no campaign, the mark of a campaign record on it ends, and it waits again as
an item of its own. An analyst includes an investigation of "Related, not
proven": it joins the campaign of the seed. Both can be undone. Each writes
one change and one audit record, and a failed audit write changes nothing.
None of them sends an investigation to the lead path.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient
from soc_ai.store import authorized_activity as aa
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import CampaignRunOverride, Investigation
from sqlalchemy import select

from tests.test_campaign_authorize_api import (
    _ESCALATE,
    _authorize,
    _changes,
    _do,
    _Down,
    _runs,
    client,
    seed_campaign,
)
from tests.test_campaign_decision_api import commit_fails_after, failed_records
from tests.test_campaign_facts import ACTOR, TARGET, seed_run

__all__ = ["client"]


def _members(client: TestClient, campaign_id: int) -> set[str]:
    body = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    return {m["runId"] for m in body["members"]}


def _overrides(client: TestClient) -> list[tuple[str, str]]:
    async def work(db: Any) -> list[tuple[str, str]]:
        rows = (await db.scalars(select(CampaignRunOverride))).all()
        return [(r.run_id, r.type) for r in rows]

    out: list[tuple[str, str]] = _do(client, work)
    return out


def _waiting(client: TestClient) -> set[str]:
    rows = client.get("/api/v1/investigations", params={"needs_you": "true", "range": "all"})
    return {r["id"] for r in rows.json()["rows"]}


def test_an_excluded_investigation_loses_its_campaign_mark_and_waits_again(
    client: TestClient,
) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    target = web_1[0]  # It holds an escalate action.
    assert _runs(client)[target].authorization_id is not None
    assert target not in _waiting(client)

    with patch.object(inv_svc, "_observe_verdict") as observed:
        res = client.post(
            f"/api/v1/campaigns/{campaign_id}/exclude",
            json={"runId": target, "reason": "This upload is another test."},
        )
    assert res.status_code == 200, res.text
    assert observed.call_count == 0, "an exclusion forms no lead"
    run = _runs(client)[target]
    assert run.authorization_id is None
    assert "authorized_activity" not in (run.report or {})
    assert target not in _members(client, campaign_id)
    assert target in _waiting(client), "its escalate waits on the analyst again"
    assert _changes(client, campaign_id)[-1] == ("excluded", {"runId": target, "by": "anonymous"})
    kinds = [(k, m) for k, _p, m in client.app.state.audit.records]
    assert ("campaign_excluded", True) in kinds
    excluded = res.json().get("excluded")
    if excluded is not None:
        assert [e["runId"] for e in excluded] == [target]


def test_an_exclusion_keeps_the_mark_of_a_rule_list_record(client: TestClient) -> None:
    from datetime import timedelta

    from soc_ai.store.auth import utcnow

    from tests.test_campaign_facts import RULE

    campaign_id, web_1, _web_2 = seed_campaign(client)

    async def old(db: Any) -> int:
        now = utcnow()
        row = await aa.create(
            db,
            label="Rule list test",
            sources=[aa.ScopeEntry(ACTOR, "agent:a1")],
            target=aa.ScopeEntry(TARGET, "ip:t1"),
            rule_names=[RULE],
            rule_class="exploit_attempt",
            starts_at=now - timedelta(hours=6),
            expires_at=now + timedelta(days=2),
            created_by="casey",
            now=now,
        )
        inv = await db.get(Investigation, web_1[1])
        inv.authorization_id = row.id
        await db.commit()
        return int(row.id)

    old_id = _do(client, old)
    res = client.post(
        f"/api/v1/campaigns/{campaign_id}/exclude", json={"runId": web_1[1], "reason": "Other."}
    )
    assert res.status_code == 200, res.text
    assert _runs(client)[web_1[1]].authorization_id == old_id


def test_exclude_refusals(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    url = f"/api/v1/campaigns/{campaign_id}/exclude"
    assert client.post(url, json={"runId": web_1[0], "reason": "  "}).status_code == 422
    stranger = client.post(url, json={"runId": "01JNOSUCHRUN000000000000AA", "reason": "x"})
    assert (stranger.status_code, stranger.json()["detail"]["reason"]) == (404, "not_in_campaign")
    assert client.post(url, json={"runId": web_1[2], "reason": "Other."}).status_code == 200
    again = client.post(url, json={"runId": web_1[2], "reason": "Other."})
    assert (again.status_code, again.json()["detail"]["reason"]) == (409, "already_overridden")
    assert (
        client.post("/api/v1/campaigns/999/exclude", json={"runId": "x", "reason": "x"}).status_code
        == 404
    )


def test_a_failed_audit_write_changes_nothing(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    client.app.state.audit = _Down()
    res = client.post(
        f"/api/v1/campaigns/{campaign_id}/exclude", json={"runId": web_1[0], "reason": "Other."}
    )
    assert res.status_code == 503
    assert _overrides(client) == []
    assert _runs(client)[web_1[0]].authorization_id is not None
    assert web_1[0] in _members(client, campaign_id)


def test_an_override_whose_commit_fails_records_the_failure(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    url = f"/api/v1/campaigns/{campaign_id}"
    with commit_fails_after(client, "campaign_excluded"):
        res = client.post(f"{url}/exclude", json={"runId": web_1[0], "reason": "Other."})
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "store_unavailable")
    assert _overrides(client) == []
    assert _runs(client)[web_1[0]].authorization_id is not None
    assert web_1[0] in _members(client, campaign_id)

    # The undo of a saved exclusion fails the same way and keeps the exclusion.
    assert client.post(f"{url}/exclude", json={"runId": web_1[0], "reason": "Other."}).is_success
    with commit_fails_after(client, "campaign_override_undone"):
        undo = client.post(f"{url}/overrides/{web_1[0]}/undo")
    assert (undo.status_code, undo.json()["detail"]["reason"]) == (503, "store_unavailable")
    assert _overrides(client) == [(web_1[0], "excluded")]
    assert [k for k, _p in failed_records(client)] == [
        "campaign_exclude_failed",
        "campaign_override_undo_failed",
    ]


def test_an_undo_returns_the_investigation_and_its_mark(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    url = f"/api/v1/campaigns/{campaign_id}"
    assert (
        client.post(f"{url}/exclude", json={"runId": web_1[1], "reason": "Other."}).status_code
        == 200
    )
    undo = client.post(f"{url}/overrides/{web_1[1]}/undo")
    assert undo.status_code == 200, undo.text
    assert _overrides(client) == []
    assert web_1[1] in _members(client, campaign_id)
    assert _runs(client)[web_1[1]].authorization_id is not None, "the rebuild marks it again"
    assert client.post(f"{url}/overrides/{web_1[1]}/undo").status_code == 404
    kinds = [k for k, _p, _m in client.app.state.audit.records]
    assert "campaign_override_undone" in kinds


def test_an_included_investigation_joins_the_campaign_of_the_seed(client: TestClient) -> None:
    campaign_id, _web_1, _web_2 = seed_campaign(client)

    async def loose(db: Any) -> str:
        return await seed_run(
            db,
            "alert-0042",
            verdict="needs_more_info",
            event_hours_ago=2,
            created_minutes_ago=15,
            report={"recommended_actions": [_ESCALATE]},
        )

    run_id = _do(client, loose)
    page = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    assert run_id in {r["runId"] for r in page["related"]["needsMoreInfo"]}
    url = f"/api/v1/campaigns/{campaign_id}"
    res = client.post(f"{url}/include", json={"runId": run_id, "reason": "The same upload."})
    assert res.status_code == 200, res.text
    member = next(m for m in res.json()["members"] if m["runId"] == run_id)
    assert member["link"] == "included"
    assert _changes(client, campaign_id)[-1] == ("included", {"runId": run_id, "by": "anonymous"})
    # A negative control: a member is not under "Related, not proven".
    again = client.post(f"{url}/include", json={"runId": run_id, "reason": "Again."})
    assert again.status_code == 409
    undo = client.post(f"{url}/overrides/{run_id}/undo")
    assert undo.status_code == 200
    assert run_id not in {m["runId"] for m in undo.json()["members"]}
    # An inclusion whose commit fails records the failure and changes nothing.
    with commit_fails_after(client, "campaign_included"):
        failed = client.post(f"{url}/include", json={"runId": run_id, "reason": "The same."})
    assert (failed.status_code, failed.json()["detail"]["reason"]) == (503, "store_unavailable")
    assert _overrides(client) == []
    assert [k for k, _p in failed_records(client)] == ["campaign_include_failed"]
    undo = client.post(f"{url}/overrides/{run_id}/undo")
    assert undo.status_code == 404
