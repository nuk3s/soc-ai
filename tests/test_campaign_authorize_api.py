"""The authorization of a campaign through the API (A3).

``GET /campaigns/{id}/authorize-draft`` states what a record covers before
the press. ``POST /campaigns/{id}/authorize`` records it: admin only, the
audit record first, fail closed. ``POST /campaigns/{id}/revoke-authorization``
revokes it with a reason: every mark ends, the decision is cleared, and no
investigation goes to the lead path. The revoke route of an authorization id
does the same for a campaign record.

The data is synthetic: placeholder addresses, names and rule names. No test
calls a real grid.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import authorized_activity as aa
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import AuthorizedActivity, Campaign, CampaignChange, Investigation
from sqlalchemy import select

from tests.test_campaign_decision_api import commit_fails_after, failed_records
from tests.test_campaign_facts import ACTOR, RULE, TARGET, TARGET_2, seed_hosts, seed_run

_ORIGIN = {"Origin": "http://testserver"}
_ESCALATE = {
    "tool_name": "escalate_to_case",
    "tool_args": {"case_title": "Exploit", "case_description": "Exploit requests."},
    "rationale": "Open a case for the exploit requests.",
}


class _Audit:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any], bool]] = []

    async def log_kind(
        self, session_id: str, kind: str, payload: dict[str, Any], **kw: Any
    ) -> None:
        self.records.append((kind, payload, bool(kw.get("mutating"))))


class _Down:
    async def log_kind(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("the audit index did not answer")


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            app.state.audit = _Audit()
            yield test_client


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def seed_campaign(client: TestClient) -> tuple[int, list[str], str]:
    """Three true positives of actor-a on web-1 and one on web-2: one campaign.

    Returns the campaign id, the ids on web-1 and the id on web-2.
    """

    async def work(db: Any) -> tuple[list[str], str]:
        await seed_hosts(db)
        web_1 = [
            await seed_run(
                db,
                f"alert-000{n}",
                event_hours_ago=5 - n,
                created_minutes_ago=50 - n,
                report={"recommended_actions": [_ESCALATE]} if n == 1 else None,
            )
            for n in (1, 2, 3)
        ]
        web_2 = await seed_run(
            db, "alert-0009", dst=TARGET_2, event_hours_ago=0.5, created_minutes_ago=10
        )
        return web_1, web_2

    web_1, web_2 = _do(client, work)
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    return int(row["id"]), web_1, web_2


def _expiry(days: float = 7) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def _authorize(client: TestClient, campaign_id: int, **body: Any) -> Any:
    payload = {
        "label": "Red team test",
        "note": "The owner runs the test.",
        "expiresAt": _expiry(),
        "machineKeys": ["agent:a1", "ip:t1"],
        **body,
    }
    return client.post(f"/api/v1/campaigns/{campaign_id}/authorize", json=payload)


def _runs(client: TestClient) -> dict[str, Investigation]:
    async def work(db: Any) -> dict[str, Investigation]:
        return {inv.id: inv for inv in (await db.scalars(select(Investigation))).all()}

    out: dict[str, Investigation] = _do(client, work)
    return out


def _changes(client: TestClient, campaign_id: int) -> list[tuple[str, dict[str, Any]]]:
    async def work(db: Any) -> list[tuple[str, dict[str, Any]]]:
        rows = await db.scalars(
            select(CampaignChange)
            .where(CampaignChange.campaign_id == campaign_id)
            .order_by(CampaignChange.id)
        )
        return [(c.type, c.detail) for c in rows.all()]

    out: list[tuple[str, dict[str, Any]]] = _do(client, work)
    return out


def _campaign(client: TestClient, campaign_id: int) -> Campaign:
    async def work(db: Any) -> Campaign:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        return row

    row: Campaign = _do(client, work)
    return row


def _records(client: TestClient) -> list[AuthorizedActivity]:
    async def work(db: Any) -> list[AuthorizedActivity]:
        return list((await db.scalars(select(AuthorizedActivity))).all())

    out: list[AuthorizedActivity] = _do(client, work)
    return out


# ── The draft ──────────────────────────────────────────────────────────────


def test_the_draft_lists_every_party_and_counts_the_cover(client: TestClient) -> None:
    campaign_id, web_1, web_2 = seed_campaign(client)
    res = client.get(f"/api/v1/campaigns/{campaign_id}/authorize-draft")
    assert res.status_code == 200, res.text
    body = res.json()
    assert {(p["machineKey"], p["role"], p["listed"]) for p in body["parties"]} == {
        ("agent:a1", "actor", True),
        ("ip:t1", "target", True),
        ("ip:t2", "target", True),
    }
    web = next(p for p in body["parties"] if p["machineKey"] == "ip:t1")
    assert (web["name"], web["address"]) == ("web-1", TARGET)
    assert (body["inside"], body["outside"]) == (4, 0)
    assert body["waiting"] == 1, "one inside investigation has an escalate that waits"
    assert body["label"] == ""
    assert body["earlier"] is None
    now = datetime.now(UTC)
    expires = datetime.fromisoformat(body["expiresAt"].replace("Z", "+00:00"))
    most = datetime.fromisoformat(body["maxExpiresAt"].replace("Z", "+00:00"))
    assert timedelta(days=6.9) < expires - now < timedelta(days=7.1)
    assert timedelta(days=29.9) < most - now < timedelta(days=30.1)
    assert body["startsAt"] == client.get(f"/api/v1/campaigns/{campaign_id}").json()["firstEvent"]
    assert web_1 and web_2


def test_the_draft_takes_the_label_and_the_expiry_of_an_earlier_record(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)

    async def old_record(db: Any) -> int:
        now = utcnow()
        row = await aa.create(
            db,
            label="Rule list test",
            sources=[aa.ScopeEntry(ACTOR, "agent:a1", "actor-a")],
            target=aa.ScopeEntry(TARGET, "ip:t1"),
            rule_names=[RULE],
            rule_class="exploit_attempt",
            starts_at=now - timedelta(hours=6),
            expires_at=now + timedelta(days=3),
            created_by="casey",
            now=now,
        )
        for run_id in web_1[:2]:
            inv = await db.get(Investigation, run_id)
            inv.authorization_id = row.id
        await db.commit()
        return int(row.id)

    old_id = _do(client, old_record)
    body = client.get(f"/api/v1/campaigns/{campaign_id}/authorize-draft").json()
    assert body["earlier"] == {"id": old_id, "label": "Rule list test", "covers": 2, "of": 4}
    assert body["label"] == "Rule list test"
    expires = datetime.fromisoformat(body["expiresAt"].replace("Z", "+00:00"))
    assert timedelta(days=2.9) < expires - datetime.now(UTC) < timedelta(days=3.1)


# ── Create ─────────────────────────────────────────────────────────────────


def test_create_writes_the_record_the_decision_the_marks_and_the_beyond_change(
    client: TestClient,
) -> None:
    campaign_id, web_1, web_2 = seed_campaign(client)
    res = _authorize(client, campaign_id)
    assert res.status_code == 200, res.text
    assert res.json()["decision"]["type"] == "authorized"

    (record,) = _records(client)
    assert (record.campaign_id, record.rule_names, record.label) == (
        campaign_id,
        [],
        "Red team test",
    )
    assert {p["machine_key"] for p in record.parties or []} == {"agent:a1", "ip:t1"}
    campaign = _campaign(client, campaign_id)
    assert (campaign.decision, campaign.authorization_id) == ("authorized", record.id)
    assert record.starts_at == campaign.first_event

    runs = _runs(client)
    assert {runs[r].authorization_id for r in web_1} == {record.id}
    for run_id in web_1:
        assert runs[run_id].report["authorized_activity"]["campaign_id"] == campaign_id
    # A negative control: the investigation on the unlisted web-2 stays loud.
    assert runs[web_2].authorization_id is None

    changes = _changes(client, campaign_id)
    assert (
        "decided",
        {
            "decision": "authorized",
            "authorizationId": record.id,
            "label": "Red team test",
            "by": "anonymous",
        },
    ) in changes
    assert ("beyond", {"runId": web_2, "why": "target"}) in changes

    records = client.app.state.audit.records
    assert (records[0][0], records[0][2]) == ("authorized_activity_created", True)
    assert records[0][1]["campaign_id"] == campaign_id
    assert (records[0][1]["inside"], records[0][1]["outside"]) == (3, 1)
    assert sorted(
        p["investigation_id"] for k, p, _m in records if k == "authorized_activity_matched"
    ) == sorted(web_1)


def test_a_failed_audit_write_changes_nothing(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    client.app.state.audit = _Down()
    res = _authorize(client, campaign_id)
    assert res.status_code == 503, res.text
    assert res.json()["detail"]["reason"] == "audit_unavailable"
    assert _records(client) == []
    campaign = _campaign(client, campaign_id)
    assert (campaign.decision, campaign.authorization_id) == (None, None)
    assert {_runs(client)[r].authorization_id for r in web_1} == {None}
    assert [t for t, _d in _changes(client, campaign_id) if t in ("decided", "beyond")] == []


@pytest.mark.parametrize(
    ("label", "body", "reason"),
    [
        (
            "a machine that is no party",
            {"machineKeys": ["agent:a1", "ip:t1", "agent:zz"]},
            "machine_not_party",
        ),
        ("no target", {"machineKeys": ["agent:a1"]}, "target_required"),
        ("no actor", {"machineKeys": ["ip:t1"]}, "actor_required"),
        ("an empty label", {"label": "   "}, "label_required"),
        ("an expiry that is no time", {"expiresAt": "next week"}, "bad_expiry"),
        ("an expiry in the past", {"expiresAt": _expiry(-1)}, "expiry_in_past"),
        ("an expiry past 30 days", {"expiresAt": _expiry(31)}, "expiry_too_far"),
    ],
)
def test_create_refuses_a_bad_scope(
    client: TestClient, label: str, body: dict[str, Any], reason: str
) -> None:
    campaign_id, _web_1, _web_2 = seed_campaign(client)
    res = _authorize(client, campaign_id, **body)
    assert res.status_code == 422, label
    assert res.json()["detail"]["reason"] == reason, label
    assert _records(client) == []


def test_create_refuses_a_campaign_that_holds_a_decision(client: TestClient) -> None:
    campaign_id, _web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    again = _authorize(client, campaign_id)
    assert again.status_code == 409
    assert again.json()["detail"]["reason"] == "campaign_decided"
    assert client.get(f"/api/v1/campaigns/{campaign_id}/authorize-draft").status_code == 409
    assert len(_records(client)) == 1
    assert client.get("/api/v1/campaigns/999/authorize-draft").status_code == 404


def test_an_authorized_campaign_does_not_open_again_by_the_reopen_route(
    client: TestClient,
) -> None:
    campaign_id, _web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    res = client.post(f"/api/v1/campaigns/{campaign_id}/reopen", json={})
    assert res.status_code == 409
    assert res.json()["detail"]["reason"] == "campaign_authorized"
    assert _campaign(client, campaign_id).decision == "authorized"


# ── Revoke ─────────────────────────────────────────────────────────────────


def _holds(client: TestClient, run_ids: list[str]) -> list[bool]:
    async def work(db: Any) -> list[bool]:
        return [await aa.holds_run(db, await db.get(Investigation, r)) for r in run_ids]

    out: list[bool] = _do(client, work)
    return out


@pytest.mark.parametrize("route", ["campaign", "record"])
def test_a_revoke_clears_each_mark_and_the_decision_and_forms_no_lead(
    client: TestClient, route: str
) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    assert _holds(client, web_1) == [True, True, True]
    (record,) = _records(client)
    with patch.object(inv_svc, "_observe_verdict") as observed:
        if route == "campaign":
            res = client.post(
                f"/api/v1/campaigns/{campaign_id}/revoke-authorization",
                json={"reason": "The test ended early."},
            )
        else:
            res = client.post(
                f"/api/v1/authorized-activity/{record.id}/revoke",
                json={"reason": "The test ended early."},
            )
    assert res.status_code == 200, res.text
    assert observed.call_count == 0, "a revoke forms no lead for each investigation"
    assert _holds(client, web_1) == [False, False, False]
    campaign = _campaign(client, campaign_id)
    assert (campaign.decision, campaign.authorization_id) == (None, record.id)
    assert _changes(client, campaign_id)[-1] == (
        "reopened",
        {"cause": "revoked", "by": "anonymous"},
    )
    kinds = [(k, m) for k, _p, m in client.app.state.audit.records]
    assert ("authorized_activity_revoked", True) in kinds
    if route == "record":
        assert res.json()["runs_returned"] == 3


def test_a_revoke_needs_a_reason_and_an_authorization(client: TestClient) -> None:
    campaign_id, _web_1, _web_2 = seed_campaign(client)
    url = f"/api/v1/campaigns/{campaign_id}/revoke-authorization"
    none = client.post(url, json={"reason": "The test ended."})
    assert none.status_code == 409
    assert none.json()["detail"]["reason"] == "no_authorization"
    assert _authorize(client, campaign_id).status_code == 200
    blank = client.post(url, json={"reason": "   "})
    assert blank.status_code == 422
    assert blank.json()["detail"]["reason"] == "reason_required"


def test_a_failed_revoke_record_changes_nothing(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    client.app.state.audit = _Down()
    res = client.post(
        f"/api/v1/campaigns/{campaign_id}/revoke-authorization", json={"reason": "Ended."}
    )
    assert res.status_code == 503
    assert _holds(client, web_1) == [True, True, True]
    assert _campaign(client, campaign_id).decision == "authorized"
    (record,) = _records(client)
    assert record.revoked_at is None


def test_an_authorization_whose_commit_fails_records_the_failure(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    with commit_fails_after(client, "authorized_activity_created") as store:
        res = _authorize(client, campaign_id)
    assert store["failed"] == 1
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "store_unavailable")
    assert _records(client) == []
    assert _campaign(client, campaign_id).decision is None
    assert {_runs(client)[r].authorization_id for r in web_1} == {None}
    ((kind, payload),) = failed_records(client)
    assert (kind, payload["campaign_id"]) == ("authorized_activity_create_failed", campaign_id)
    # A negative control: the same authorization with the store up saves.
    assert _authorize(client, campaign_id).status_code == 200
    assert len(failed_records(client)) == 1


def test_a_revoke_whose_commit_fails_records_the_failure(client: TestClient) -> None:
    campaign_id, web_1, _web_2 = seed_campaign(client)
    assert _authorize(client, campaign_id).status_code == 200
    with commit_fails_after(client, "authorized_activity_revoked"):
        res = client.post(
            f"/api/v1/campaigns/{campaign_id}/revoke-authorization", json={"reason": "Ended."}
        )
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "store_unavailable")
    assert _holds(client, web_1) == [True, True, True]
    assert _campaign(client, campaign_id).decision == "authorized"
    (record,) = _records(client)
    assert record.revoked_at is None
    assert [k for k, _p in failed_records(client)] == ["authorized_activity_revoke_failed"]


# ── Roles ──────────────────────────────────────────────────────────────────


def test_the_draft_and_the_create_need_an_admin(
    audit_client: TestClient, analyst: TestClient, admin: TestClient
) -> None:
    draft = analyst.get("/api/v1/campaigns/1/authorize-draft")
    assert draft.status_code == 403
    assert draft.json()["detail"]["reason"] == "admin_required"
    create = analyst.post(
        "/api/v1/campaigns/1/authorize",
        json={"label": "x", "expiresAt": _expiry(), "machineKeys": []},
        headers=_ORIGIN,
    )
    assert create.status_code == 403
    assert audit_client.get("/api/v1/campaigns/1/authorize-draft").status_code in (401, 403)
    # An admin passes the role check. No campaign has the id.
    assert admin.get("/api/v1/campaigns/1/authorize-draft").status_code == 404
