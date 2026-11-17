"""What the authorized activity mark changes, and what it must not change.

A run inside an authorized scope requests no case, raises no notification of
its own and forms no lead. Nothing else changes: the run stays in every list
and in every count of true positives. Each test has its control: a run that
is outside the scope, or a run whose authorization an analyst revoked, gets
normal handling on the same surface.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai import notify
from soc_ai.agent import authorized_activity as aam
from soc_ai.api.webui import action_rules
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import authorized_activity as aa
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import EntityObservation, Investigation, Lead
from sqlalchemy import func, select

TARGET = "10.40.0.164"
SOURCE = "10.50.0.26"
STRANGER = "10.50.0.200"
RULE = "ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)"

_ESCALATE = {
    "tool_name": "escalate_to_case",
    "tool_args": {"case_title": "php2shell", "case_description": "Exploit requests."},
    "rationale": "Open a case for the exploit requests.",
}
_ACK = {"tool_name": "ack_alert", "tool_args": {}, "rationale": "Acknowledge the alert."}


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
    """Run one store call on the app's own store."""

    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _authorize(client: TestClient, **overrides: Any) -> int:
    now = utcnow()
    fields: dict[str, Any] = {
        "label": "php2shell test",
        "sources": [aa.ScopeEntry(SOURCE, "agent:a-1", "agent-a")],
        "target": aa.ScopeEntry(TARGET, None),
        "rule_names": [RULE],
        "rule_class": "exploit_attempt",
        "starts_at": now - timedelta(hours=6),
        "expires_at": now + timedelta(days=7),
        "created_by": "casey",
        "now": now,
    }
    fields.update(overrides)

    async def work(db: Any) -> int:
        return int((await aa.create(db, **fields)).id)

    return int(_do(client, work))


def _scope(client: TestClient, authorization_id: int) -> aa.Scope:
    async def work(db: Any) -> aa.Scope:
        row = await aa.get(db, authorization_id)
        assert row is not None
        return aa.scope_of(row)

    scope: aa.Scope = _do(client, work)
    return scope


def _seed_run(
    client: TestClient,
    alert_id: str,
    *,
    mark: dict[str, Any] | None = None,
    src: str = SOURCE,
    actions: list[dict[str, Any]] | None = None,
) -> str:
    """One finalized true positive run of the campaign rule. Returns its id."""
    report: dict[str, Any] = {
        "verdict": "true_positive",
        "confidence": 0.85,
        "summary": "The source sent php2shell exploit requests.",
        "recommended_actions": actions if actions is not None else [_ESCALATE],
    }
    if mark is not None:
        report["authorized_activity"] = mark

    async def work(db: Any) -> str:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_id,
            started_by="auto-triage",
            rule_name=RULE,
            src_ip=src,
            dest_ip=TARGET,
        )
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="true_positive",
            confidence=0.85,
            summary=report["summary"],
            report=report,
        )
        return str(inv.id)

    run_id: str = _do(client, work)
    return run_id


def _matched(client: TestClient, authorization_id: int) -> dict[str, Any]:
    return aam.matched_mark(_scope(client, authorization_id), at=utcnow())


def _outside(client: TestClient, authorization_id: int) -> dict[str, Any]:
    return aam.outside_mark(_scope(client, authorization_id), [aam.PART_SOURCE])


def _revoke(client: TestClient, authorization_id: int) -> None:
    async def work(db: Any) -> None:
        await aa.revoke(db, authorization_id, by="casey", reason="wrong target")

    _do(client, work)


def _count(client: TestClient, model: Any) -> int:
    async def work(db: Any) -> int:
        return int(await db.scalar(select(func.count()).select_from(model)) or 0)

    return int(_do(client, work))


def _row(client: TestClient, run_id: str) -> Investigation:
    async def work(db: Any) -> Investigation:
        row = await db.get(Investigation, run_id)
        assert row is not None
        return row

    row: Investigation = _do(client, work)
    return row


# ── The lead ───────────────────────────────────────────────────────────────


def test_a_run_inside_the_scope_forms_no_lead_and_keeps_its_link(client: TestClient) -> None:
    authorization_id = _authorize(client)
    run_id = _seed_run(client, "alert-in", mark=_matched(client, authorization_id))
    assert _row(client, run_id).authorization_id == authorization_id
    assert (_count(client, EntityObservation), _count(client, Lead)) == (0, 0)


def test_control_a_run_outside_the_scope_forms_a_lead(client: TestClient) -> None:
    """The same verdict on the same target. A rule that stopped every lead
    on the target would pass the test above."""
    authorization_id = _authorize(client)
    run_id = _seed_run(client, "alert-out", mark=_outside(client, authorization_id), src=STRANGER)
    assert _row(client, run_id).authorization_id is None
    assert _count(client, EntityObservation) == 2, "one on each internal end of the flow"
    assert _count(client, Lead) >= 1


def test_control_a_run_with_no_authorization_forms_a_lead(client: TestClient) -> None:
    _seed_run(client, "alert-plain")
    assert _count(client, Lead) >= 1


def test_a_revoke_returns_the_run_to_the_lead_path(client: TestClient) -> None:
    authorization_id = _authorize(client)
    run_id = _seed_run(client, "alert-in", mark=_matched(client, authorization_id))
    _revoke(client, authorization_id)

    async def work(db: Any) -> None:
        await inv_svc._observe_verdict(db, await db.get(Investigation, run_id))

    _do(client, work)
    assert _count(client, Lead) >= 1


# ── The webhook ────────────────────────────────────────────────────────────


def test_a_run_inside_the_scope_sends_no_webhook(client: TestClient) -> None:
    authorization_id = _authorize(client)
    settings = SimpleNamespace(notify_on_tp=True, notify_tp_confidence_threshold=0.5)
    plain = {"verdict": "true_positive", "confidence": 0.9, "summary": "Exploit requests."}
    inside = {**plain, "authorized_activity": _matched(client, authorization_id)}
    outside = {**plain, "authorized_activity": _outside(client, authorization_id)}

    assert (
        notify.event_for_investigation(investigation_id="i1", report=inside, settings=settings)
        is None
    )
    # Controls: the same report with no mark, and with the outside line.
    for report in (plain, outside):
        event = notify.event_for_investigation(
            investigation_id="i1", report=report, settings=settings
        )
        assert event is not None and event.kind == "tp"


# ── The bell ───────────────────────────────────────────────────────────────


def _bell(client: TestClient) -> list[dict[str, Any]]:
    res = client.get("/api/v1/notifications", params={"limit": 200})
    assert res.status_code == 200, res.text
    rows: list[dict[str, Any]] = res.json()
    return rows


def test_the_bell_lists_no_row_for_a_run_inside_the_scope(client: TestClient) -> None:
    authorization_id = _authorize(client)
    inside = _seed_run(client, "alert-in", mark=_matched(client, authorization_id))
    outside = _seed_run(client, "alert-out", mark=_outside(client, authorization_id), src=STRANGER)

    ids = {row["id"] for row in _bell(client)}
    assert f"inv-done:{inside}" not in ids
    assert f"inv-done:{outside}" in ids, "a run outside the scope raises its row"

    _revoke(client, authorization_id)
    assert f"inv-done:{inside}" in {row["id"] for row in _bell(client)}, (
        "a revoke returns the run to normal handling"
    )


def test_an_expiry_raises_one_row_with_the_label_and_the_run_count(client: TestClient) -> None:
    now = utcnow()
    ended = _authorize(
        client,
        label="ended test",
        now=now - timedelta(days=2),
        starts_at=now - timedelta(days=2),
        expires_at=now - timedelta(hours=1),
    )
    live = _authorize(client, label="live test")
    revoked = _authorize(
        client,
        label="revoked test",
        now=now - timedelta(days=2),
        starts_at=now - timedelta(days=2),
        expires_at=now - timedelta(hours=1),
    )
    _revoke(client, revoked)
    _seed_run(client, "alert-1", mark=_matched(client, ended))
    _seed_run(client, "alert-2", mark=_matched(client, ended))

    rows = [row for row in _bell(client) if row["id"].startswith("authorized-expired:")]
    assert [row["id"] for row in rows] == [f"authorized-expired:{ended}"], (live, revoked)
    assert rows[0]["title"] == (
        'The authorized activity "ended test" expired. 2 investigations matched it. '
        "New investigations get normal handling."
    )
    assert rows[0]["href"] == f"/investigations?authorization={ended}&range=all"


def test_the_bell_counts_the_expired_records_past_its_three_rows(client: TestClient) -> None:
    """Review defect 9. Five records expired. No expiry is left out of the bell."""
    now = utcnow()
    ids = [
        _authorize(
            client,
            label=f"test {n}",
            now=now - timedelta(days=2),
            starts_at=now - timedelta(days=2),
            expires_at=now - timedelta(hours=n),
        )
        for n in range(1, 6)
    ]
    # One run matched each of the two records the fold row covers.
    _seed_run(client, "alert-4", mark=_matched(client, ids[3]))
    _seed_run(client, "alert-5", mark=_matched(client, ids[4]))

    rows = [row for row in _bell(client) if row["id"].startswith("authorized-expired")]

    assert [row["id"] for row in rows[:3]] == [f"authorized-expired:{i}" for i in ids[:3]]
    assert len(rows) == 4
    assert rows[3]["title"] == (
        "2 more authorized activity records expired. 2 investigations matched them. "
        "New investigations get normal handling."
    )


# ── The case request and the needs-you count ───────────────────────────────


def _needs_you(client: TestClient) -> dict[str, Any]:
    res = client.get("/api/v1/needs-you")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_the_needs_you_count_leaves_out_the_run_inside_the_scope(client: TestClient) -> None:
    authorization_id = _authorize(client)
    _seed_run(client, "alert-in", mark=_matched(client, authorization_id))
    assert _needs_you(client)["pending_actions"] == 0

    # Control: a run outside the scope waits for a person.
    _seed_run(client, "alert-out", mark=_outside(client, authorization_id), src=STRANGER)
    assert _needs_you(client)["pending_actions"] == 1

    # A revoke returns the first run to the queue.
    _revoke(client, authorization_id)
    assert _needs_you(client)["pending_actions"] == 2


def test_an_acknowledge_of_an_authorized_run_does_not_wait(client: TestClient) -> None:
    authorization_id = _authorize(client)
    _seed_run(
        client,
        "alert-in",
        mark=_matched(client, authorization_id),
        actions=[_ESCALATE, _ACK],
    )
    assert _needs_you(client)["pending_actions"] == 0


def test_the_run_page_closes_the_case_request_and_states_the_authorization(
    client: TestClient,
) -> None:
    authorization_id = _authorize(client)
    run_id = _seed_run(
        client,
        "alert-in",
        mark=_matched(client, authorization_id),
        actions=[_ESCALATE, _ACK],
    )
    body = client.get(f"/api/v1/investigations/{run_id}").json()

    assert body["verdict"] == "true_positive", "the verdict stays"
    assert body["authorizationId"] == authorization_id
    assert body["authorization"]["label"] == "php2shell test"
    assert body["authorization"]["state"] == "active"
    assert body["authorization"]["by"] == "casey"
    assert body["authorization"]["expiresAt"].endswith("+00:00")
    assert body["outsideAuthorizedScope"] is None
    escalate, ack = body["actions"]
    assert escalate["blockedReason"] == (
        'This investigation matches the authorized activity "php2shell test". '
        "soc-ai requests no case for it."
    )
    assert escalate["rationale"] == _ESCALATE["rationale"], "the text of the model stays"
    assert ack["blockedReason"] is None, "the analyst can still acknowledge the alert"


def test_the_run_page_of_an_outside_run_states_the_line_and_keeps_the_action(
    client: TestClient,
) -> None:
    authorization_id = _authorize(client)
    run_id = _seed_run(client, "alert-out", mark=_outside(client, authorization_id), src=STRANGER)
    body = client.get(f"/api/v1/investigations/{run_id}").json()

    assert body["authorizationId"] is None
    assert body["authorization"] is None
    assert body["outsideAuthorizedScope"] == (
        "This activity is outside the authorized scope of php2shell test: the source is new."
    )
    assert body["actions"][0]["blockedReason"] is None

    _revoke(client, authorization_id)
    body = client.get(f"/api/v1/investigations/{run_id}").json()
    assert body["outsideAuthorizedScope"] is None, "a revoked scope names nothing"


def test_a_revoke_opens_the_case_request_again(client: TestClient) -> None:
    authorization_id = _authorize(client)
    run_id = _seed_run(client, "alert-in", mark=_matched(client, authorization_id))
    _revoke(client, authorization_id)
    body = client.get(f"/api/v1/investigations/{run_id}").json()

    assert body["authorizationId"] == authorization_id, "the link stays as history"
    assert body["authorization"]["state"] == "revoked"
    assert body["actions"][0]["blockedReason"] is None


def test_the_execute_route_refuses_the_case_request(client: TestClient) -> None:
    authorization_id = _authorize(client)
    run_id = _seed_run(client, "alert-in", mark=_matched(client, authorization_id))
    res = client.post(f"/api/v1/investigations/{run_id}/actions/0/execute", json={})
    assert res.status_code == 409, res.text
    assert res.json()["detail"]["reason"] == "authorized_activity"


def test_the_rule_closes_the_case_tools_only() -> None:
    facts = action_rules.ActionFacts(
        alert_id="alert-in", run_verdict="true_positive", authorized="php2shell test"
    )
    plain = action_rules.ActionFacts(alert_id="alert-in", run_verdict="true_positive")
    for tool in ("escalate_to_case", "add_case_comment"):
        block = action_rules.action_block(facts, tool)
        assert block is not None and block.code == action_rules.CODE_AUTHORIZED, tool
    assert action_rules.action_block(facts, "ack_alert") is None
    assert action_rules.action_block(facts, None) is None, "the run itself is not closed"
    # No action of an authorized run waits. Control: the same actions wait without it.
    assert action_rules.action_waits(facts, "ack_alert") is False
    assert action_rules.action_waits(plain, "ack_alert") is True
    assert action_rules.action_waits(plain, "escalate_to_case") is True
    assert action_rules.action_block(plain, "escalate_to_case") is None


def test_an_older_rule_keeps_its_place_before_the_authorized_rule() -> None:
    """A replay and a promotion explain more than the authorization does.

    The promotion is a lead run. The escalate of a promoted finding opens a
    case from the finding, so the promotion rule does not close it, and a
    finding run never carries the mark of an authorization.
    """
    replay = action_rules.ActionFacts(replay=True, authorized="x", alert_id="a")
    promoted = action_rules.ActionFacts(promoted="lead", authorized="x", alert_id="a")
    replay_block = action_rules.action_block(replay, "escalate_to_case")
    promoted_block = action_rules.action_block(promoted, "escalate_to_case")
    assert replay_block is not None and replay_block.code == action_rules.CODE_REPLAY
    assert promoted_block is not None and promoted_block.code == action_rules.CODE_PROMOTED


# ── Every list and every count of true positives keeps the run ─────────────


def test_a_run_inside_the_scope_stays_in_every_list_and_true_positive_count(
    client: TestClient,
) -> None:
    authorization_id = _authorize(client)
    inside = _seed_run(client, "alert-in", mark=_matched(client, authorization_id))
    outside = _seed_run(client, "alert-out", mark=_outside(client, authorization_id), src=STRANGER)

    listed = client.get("/api/v1/investigations").json()
    assert {row["id"] for row in listed["rows"]} == {inside, outside}
    assert listed["truePositives"] == 2, "the count of true positives keeps the run"

    by_verdict = client.get("/api/v1/investigations", params={"verdict": "true_positive"}).json()
    assert by_verdict["total"] == 2
    rows = {row["id"]: row for row in by_verdict["rows"]}
    assert rows[inside]["verdict"] == "true_positive"
    assert rows[inside]["authorizationId"] == authorization_id
    assert rows[inside]["authorization"]["label"] == "php2shell test"
    assert rows[inside]["authorization"]["state"] == "active"
    assert rows[outside]["authorizationId"] is None
    assert rows[outside]["authorization"] is None

    # The card of the authorization links to its runs.
    of_card = client.get("/api/v1/investigations", params={"authorization": authorization_id})
    assert [row["id"] for row in of_card.json()["rows"]] == [inside]

    # Only the case request is dropped: the waiting list holds the outside run.
    waiting = client.get("/api/v1/investigations", params={"pending_action": "true"}).json()
    assert [row["id"] for row in waiting["rows"]] == [outside]

    stored = _row(client, inside)
    assert stored.verdict == "true_positive"
    assert stored.report is not None
    assert stored.report["recommended_actions"] == [_ESCALATE], "the request stays in the report"


def test_the_expiry_keeps_the_mark_of_a_run(client: TestClient) -> None:
    now = utcnow()
    ended = _authorize(
        client,
        now=now - timedelta(days=2),
        starts_at=now - timedelta(days=2),
        expires_at=now - timedelta(hours=1),
    )
    run_id = _seed_run(client, "alert-in", mark=_matched(client, ended))

    body = client.get(f"/api/v1/investigations/{run_id}").json()
    assert body["authorization"]["state"] == "expired"
    assert body["actions"][0]["blockedReason"] is not None
    assert _needs_you(client)["pending_actions"] == 0
    assert datetime.fromisoformat(body["authorization"]["expiresAt"]) < datetime.now(UTC)
