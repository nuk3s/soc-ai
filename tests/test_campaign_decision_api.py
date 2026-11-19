"""POST /campaigns/{id}/close, POST /campaigns/{id}/reopen and GET /campaigns/{id}/close-scope (D3).

A close hides work, so it writes its audit record first and fails closed: a
failed audit write changes nothing. The close then writes the decision and
one ``decided`` change. With ``acknowledge``, a task acknowledges the alerts
of the close scope after the commit, through the acknowledge path of the
Alerts page, and a failed acknowledgement never undoes the close. A grid
failure gives a close scope of null alerts, never 0.

The data is synthetic: placeholder addresses, names and rule names. No test
calls a real grid: the grid and the Security Onion write are fakes.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store.models import Campaign, CampaignChange, Investigation
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_campaign_facts import RULE, seed_hosts, seed_run

_ACK_PATH = "soc_ai.api.webui.routes_alert_actions.execute_write_tool"


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


class _Grid:
    """The grid of the app: canned hits, or an error. Keeps each query."""

    def __init__(self, hits: list[dict[str, Any]] | None = None) -> None:
        self.hits = hits
        self.queries: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.queries.append({"query": query, **kwargs})
        if self.hits is None:
            raise ConnectionError("the grid refused the connection")
        return EsSearchResult(total=len(self.hits), took_ms=2, hits=self.hits)


def _hit(n: int, *, acknowledged: bool = False, rule: str = RULE) -> dict[str, Any]:
    source: dict[str, Any] = {"rule": {"name": rule}}
    if acknowledged:
        source["event"] = {"acknowledged": True}
    return {"_id": f"evt-{n}", "_index": "logs-suricata", "_source": source}


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
            app.state.elastic = _Grid()
            yield test_client


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _seed_campaign(client: TestClient) -> int:
    """Three true positive runs of one actor on one target, and the campaign they form."""

    async def work(db: Any) -> None:
        await seed_hosts(db)
        for n in (1, 2, 3):
            await seed_run(db, f"alert-000{n}", event_hours_ago=4 - n, created_minutes_ago=40 - n)

    _do(client, work)
    listing = client.get("/api/v1/campaigns").json()
    (row,) = listing["rows"]
    return int(row["id"])


def _row(client: TestClient, campaign_id: int) -> Campaign:
    async def work(db: Any) -> Campaign:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        return row

    row: Campaign = _do(client, work)
    return row


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


def _close(client: TestClient, campaign_id: int, **body: Any) -> Any:
    return client.post(
        f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "test_over", **body}
    )


def _kinds(client: TestClient) -> list[str]:
    return [kind for kind, _payload, _mutating in client.app.state.audit.records]


@contextmanager
def commit_fails_after(client: TestClient, kind: str) -> Iterator[dict[str, int]]:
    """The store fails at the first commit after the audit record *kind*.

    The audit record is on the trail, and the change it states never reaches
    the store: the case of a full disk or a locked database at the commit.
    Yields the count of failed commits.
    """
    audit = client.app.state.audit
    real_log = audit.log_kind
    real_commit = AsyncSession.commit
    state = {"armed": 0, "failed": 0}

    async def log_kind(session_id: str, k: str, payload: dict[str, Any], **kw: Any) -> None:
        await real_log(session_id, k, payload, **kw)
        if k == kind:
            state["armed"] = 1

    async def commit(self: AsyncSession) -> None:
        if state["armed"]:
            state["armed"] = 0
            state["failed"] += 1
            raise OperationalError("COMMIT", {}, Exception("database or disk is full"))
        await real_commit(self)

    with patch.object(audit, "log_kind", log_kind), patch.object(AsyncSession, "commit", commit):
        yield state


def failed_records(client: TestClient) -> list[tuple[str, dict[str, Any]]]:
    return [(k, p) for k, p, _m in client.app.state.audit.records if k.endswith("_failed")]


# ── Close ──────────────────────────────────────────────────────────────────


def test_a_close_writes_its_mutating_audit_record_then_the_decision(client: TestClient) -> None:
    campaign_id = _seed_campaign(client)
    res = _close(client, campaign_id, note="  The red team ended the test.  ")
    assert res.status_code == 200, res.text
    assert res.json()["id"] == campaign_id
    ((kind, payload, mutating),) = client.app.state.audit.records
    assert (kind, mutating) == ("campaign_closed", True)
    assert (payload["campaign_id"], payload["reason"]) == (campaign_id, "test_over")
    assert payload["basis"]["parties"] == ["agent:a1", "ip:t1"]
    row = _row(client, campaign_id)
    assert (row.decision, row.close_reason, row.decision_note) == (
        "closed",
        "test_over",
        "The red team ended the test.",
    )
    assert row.decided_by == "anonymous"
    assert row.decision_basis == payload["basis"]
    assert _changes(client, campaign_id)[-1] == (
        "decided",
        {"decision": "closed", "reason": "test_over", "by": "anonymous", "acknowledge": False},
    )

    # A close changes no verdict.
    async def verdicts(db: Any) -> set[str]:
        return set((await db.scalars(select(Investigation.verdict))).all())

    assert _do(client, verdicts) == {"true_positive"}


def test_a_close_with_a_failed_audit_write_changes_nothing(client: TestClient) -> None:
    campaign_id = _seed_campaign(client)
    good = client.app.state.audit
    client.app.state.audit = _Down()
    res = _close(client, campaign_id)
    assert res.status_code == 503
    assert res.json()["detail"]["reason"] == "audit_unavailable"
    row = _row(client, campaign_id)
    assert (row.decision, row.decision_basis) == (None, None)
    assert [t for t, _d in _changes(client, campaign_id)] == ["formed"]
    # A negative control: the same close with the audit up closes.
    client.app.state.audit = good
    assert _close(client, campaign_id).status_code == 200
    assert _row(client, campaign_id).decision == "closed"


def test_a_close_refuses_an_unknown_a_decided_and_an_inactive_campaign(
    client: TestClient,
) -> None:
    campaign_id = _seed_campaign(client)
    assert _close(client, 999).status_code == 404
    assert (
        client.post(f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "x"}).status_code
        == 422
    )
    assert _close(client, campaign_id).status_code == 200
    again = _close(client, campaign_id)
    assert (again.status_code, again.json()["detail"]["reason"]) == (409, "campaign_decided")

    async def withdraw(db: Any) -> None:
        row = await db.get(Campaign, campaign_id)
        row.status = "withdrawn"
        row.decision = None
        await db.commit()

    _do(client, withdraw)
    # The route rebuilds first. Here the rebuild is a no-op, so the row stays withdrawn.
    with patch("soc_ai.campaigns.service.ensure_fresh", AsyncMock(return_value=True)):
        res = _close(client, campaign_id)
    assert (res.status_code, res.json()["detail"]["reason"]) == (409, "campaign_not_active")
    # Each refusal wrote no audit record.
    assert _kinds(client) == ["campaign_closed"]


# ── Reopen ─────────────────────────────────────────────────────────────────


def test_reopen_clears_the_decision_records_the_analyst_and_writes_its_record(
    client: TestClient,
) -> None:
    campaign_id = _seed_campaign(client)
    url = f"/api/v1/campaigns/{campaign_id}/reopen"
    none = client.post(url, json={})
    assert (none.status_code, none.json()["detail"]["reason"]) == (409, "campaign_not_decided")
    assert client.post("/api/v1/campaigns/999/reopen", json={}).status_code == 404
    assert _close(client, campaign_id).status_code == 200
    res = client.post(url, json={"note": "A new upload."})
    assert res.status_code == 200, res.text
    row = _row(client, campaign_id)
    assert (row.decision, row.close_reason, row.decision_basis) == (None, None, None)
    kind, detail = _changes(client, campaign_id)[-1]
    assert kind == "reopened"
    was = detail.pop("was")
    assert detail == {"cause": "analyst", "by": "anonymous", "note": "A new upload."}
    # SD1: the change keeps the close that the analyst ended.
    assert (was["decision"], was["reason"], was["by"]) == ("closed", "test_over", "anonymous")
    assert was["decidedAt"] and was["basis"]["last_event"]
    assert _kinds(client) == ["campaign_closed", "campaign_reopened"]
    # The campaign takes a new close.
    assert _close(client, campaign_id).status_code == 200


def test_a_close_whose_commit_fails_records_the_failure_and_answers_503(
    client: TestClient,
) -> None:
    campaign_id = _seed_campaign(client)
    with (
        patch(_ACK_PATH, AsyncMock()) as ack,
        commit_fails_after(client, "campaign_closed") as store,
    ):
        res = _close(client, campaign_id, acknowledge=True)
    assert store["failed"] == 1
    assert res.status_code == 503, res.text
    detail = res.json()["detail"]
    assert detail["reason"] == "store_unavailable"
    assert detail["hint"] == "soc-ai could not save the close, so nothing changed. Try again."
    # The trail states the close and then that the close did not happen.
    assert _kinds(client) == ["campaign_closed", "campaign_close_failed"]
    ((_kind, payload),) = failed_records(client)
    assert payload["campaign_id"] == campaign_id
    assert payload["cause"] == "store: OperationalError"
    row = _row(client, campaign_id)
    assert (row.decision, row.decision_basis) == (None, None)
    assert [t for t, _d in _changes(client, campaign_id)] == ["formed"]
    ack.assert_not_called()
    # A negative control: the same close with the store up closes, with no failed record.
    assert _close(client, campaign_id).status_code == 200
    assert _row(client, campaign_id).decision == "closed"
    assert _kinds(client) == ["campaign_closed", "campaign_close_failed", "campaign_closed"]


def test_a_failed_record_of_the_failure_still_answers_503(client: TestClient) -> None:
    """The record of the failure is best effort. Its own failure never turns the 503 into a 500."""
    campaign_id = _seed_campaign(client)
    audit = client.app.state.audit
    real_log = audit.log_kind

    async def log_kind(session_id: str, kind: str, payload: dict[str, Any], **kw: Any) -> None:
        if kind.endswith("_failed"):
            raise RuntimeError("the audit index did not answer")
        await real_log(session_id, kind, payload, **kw)

    with patch.object(audit, "log_kind", log_kind), commit_fails_after(client, "campaign_closed"):
        res = _close(client, campaign_id)
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "store_unavailable")
    assert _row(client, campaign_id).decision is None


def test_a_close_that_another_decision_wins_records_the_failure(client: TestClient) -> None:
    """The audit record comes first, so a close that loses the race states that it failed."""
    campaign_id = _seed_campaign(client)
    with patch("soc_ai.campaigns.decisions.write_close", AsyncMock(return_value=None)):
        res = _close(client, campaign_id)
    assert (res.status_code, res.json()["detail"]["reason"]) == (409, "campaign_decided")
    assert _kinds(client) == ["campaign_closed", "campaign_close_failed"]
    ((_kind, payload),) = failed_records(client)
    assert payload["cause"] == "campaign_decided"


def test_a_reopen_whose_commit_fails_answers_503_and_writes_no_record(
    client: TestClient,
) -> None:
    """The reopen writes its record after the commit, so a failed commit leaves no record."""
    campaign_id = _seed_campaign(client)
    assert _close(client, campaign_id).status_code == 200
    from soc_ai.campaigns import decisions

    real_write = decisions.write_reopen
    with commit_fails_after(client, "no_record") as store:

        def write(*args: Any, **kwargs: Any) -> None:
            real_write(*args, **kwargs)
            store["armed"] = 1

        with patch("soc_ai.campaigns.decisions.write_reopen", write):
            res = client.post(f"/api/v1/campaigns/{campaign_id}/reopen", json={})
    assert store["failed"] == 1
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "store_unavailable")
    assert _row(client, campaign_id).decision == "closed"
    assert _kinds(client) == ["campaign_closed"]


def test_each_failed_kind_is_a_valid_audit_kind() -> None:
    """An audit kind off the list is dropped with no warning, so each failed kind must be on it."""
    from typing import get_args

    from soc_ai.api.webui._decision_commit import FAILED_KIND
    from soc_ai.audit.schemas import AuditKind

    kinds = set(get_args(AuditKind))
    assert set(FAILED_KIND) <= kinds
    assert set(FAILED_KIND.values()) <= kinds
    assert FAILED_KIND["campaign_closed"] == "campaign_close_failed"


# ── Close scope ────────────────────────────────────────────────────────────


def test_the_close_scope_counts_the_alerts_that_soc_ai_did_not_acknowledge(
    client: TestClient,
) -> None:
    campaign_id = _seed_campaign(client)
    grid = _Grid([_hit(1), _hit(2), _hit(3, acknowledged=True), _hit(4, rule="ET OTHER rule")])
    client.app.state.elastic = grid
    res = client.get(f"/api/v1/campaigns/{campaign_id}/close-scope")
    assert res.status_code == 200, res.text
    assert res.json() == {"alerts": 3, "rules": 2, "capped": False}
    (asked,) = grid.queries
    text = repr(asked["query"])
    assert "event.acknowledged" in text and RULE in text
    assert asked["require_complete"] is True
    assert client.get("/api/v1/campaigns/999/close-scope").status_code == 404


def test_a_grid_failure_gives_a_close_scope_of_null_alerts_never_zero(client: TestClient) -> None:
    campaign_id = _seed_campaign(client)
    client.app.state.elastic = _Grid(None)
    res = client.get(f"/api/v1/campaigns/{campaign_id}/close-scope")
    assert res.status_code == 200
    assert res.json() == {"alerts": None, "rules": None, "capped": False}


def test_the_close_scope_holds_2000_alerts_and_states_the_cap(client: TestClient) -> None:
    campaign_id = _seed_campaign(client)
    client.app.state.elastic = _Grid([_hit(n) for n in range(2001)])
    res = client.get(f"/api/v1/campaigns/{campaign_id}/close-scope")
    assert res.json() == {"alerts": 2000, "rules": 1, "capped": True}


# ── The acknowledge after a close ──────────────────────────────────────────


def _close_and_ack(client: TestClient, campaign_id: int, fake_write: Any) -> Any:
    with patch(_ACK_PATH, fake_write):
        return _close(client, campaign_id, acknowledge=True)


def test_a_close_with_acknowledge_writes_each_alert_through_the_ack_path(
    client: TestClient,
) -> None:
    campaign_id = _seed_campaign(client)
    client.app.state.elastic = _Grid([_hit(1), _hit(2), _hit(3, acknowledged=True)])
    acked: list[tuple[str, str]] = []

    async def fake_write(tool: str, args: dict[str, Any], **kw: Any) -> tuple[Any, None]:
        acked.append((tool, args["alert_id"]))
        assert kw["session_id"] == f"campaign-close:{campaign_id}"
        return {"acknowledged": True}, None

    res = _close_and_ack(client, campaign_id, fake_write)
    assert res.status_code == 200, res.text
    assert sorted(acked) == [("ack_alert", "evt-1"), ("ack_alert", "evt-2")]
    assert _changes(client, campaign_id)[-1] == ("acknowledged", {"alerts": 2, "failed": 0})
    assert _row(client, campaign_id).decision == "closed"


def test_a_failed_acknowledge_never_undoes_the_close(client: TestClient) -> None:
    campaign_id = _seed_campaign(client)
    client.app.state.elastic = _Grid([_hit(1), _hit(2)])

    async def fake_write(tool: str, args: dict[str, Any], **kw: Any) -> tuple[None, str]:
        return None, "Security Onion answered 500"

    assert _close_and_ack(client, campaign_id, fake_write).status_code == 200
    assert _changes(client, campaign_id)[-1] == ("acknowledged", {"alerts": 0, "failed": 2})
    assert _row(client, campaign_id).decision == "closed"


def test_a_close_scope_that_soc_ai_cannot_read_acknowledges_nothing_and_keeps_the_close(
    client: TestClient,
) -> None:
    campaign_id = _seed_campaign(client)
    client.app.state.elastic = _Grid(None)
    calls: list[str] = []

    async def fake_write(tool: str, args: dict[str, Any], **kw: Any) -> tuple[Any, None]:
        calls.append(args["alert_id"])
        return {}, None

    assert _close_and_ack(client, campaign_id, fake_write).status_code == 200
    assert calls == []
    assert _changes(client, campaign_id)[-1] == (
        "acknowledged",
        {"alerts": 0, "failed": 0, "unread": True},
    )
    assert _row(client, campaign_id).decision == "closed"


def test_a_close_with_no_acknowledge_writes_nothing_to_security_onion(client: TestClient) -> None:
    campaign_id = _seed_campaign(client)
    client.app.state.elastic = _Grid([_hit(1)])
    calls: list[str] = []

    async def fake_write(tool: str, args: dict[str, Any], **kw: Any) -> tuple[Any, None]:
        calls.append(args["alert_id"])
        return {}, None

    with patch(_ACK_PATH, fake_write):
        assert _close(client, campaign_id).status_code == 200
    assert calls == []
    assert "acknowledged" not in [t for t, _d in _changes(client, campaign_id)]


# ── Acknowledge the remaining alerts ───────────────────────────────────────


def _acknowledge(client: TestClient, campaign_id: int) -> Any:
    return client.post(f"/api/v1/campaigns/{campaign_id}/acknowledge")


def _types(client: TestClient, campaign_id: int) -> list[str]:
    return [t for t, _d in _changes(client, campaign_id)]


def test_the_acknowledge_route_acknowledges_what_is_still_open_and_records_one_change(
    client: TestClient,
) -> None:
    """A restart after the close lost the task. The route does its work again."""
    campaign_id = _seed_campaign(client)
    lost = AsyncMock()
    with patch("soc_ai.api.webui.routes_campaigns._acknowledge_after_close", lost):
        assert _close(client, campaign_id, acknowledge=True).status_code == 200
    lost.assert_called_once()
    assert "acknowledged" not in _types(client, campaign_id)
    decided = [d for t, d in _changes(client, campaign_id) if t == "decided"]
    assert decided[-1]["acknowledge"] is True

    client.app.state.elastic = _Grid([_hit(1), _hit(2), _hit(3, acknowledged=True)])
    acked: list[str] = []

    async def fake_write(tool: str, args: dict[str, Any], **kw: Any) -> tuple[Any, None]:
        assert (tool, kw["session_id"]) == ("ack_alert", f"campaign-close:{campaign_id}")
        acked.append(args["alert_id"])
        return {"acknowledged": True}, None

    with patch(_ACK_PATH, fake_write):
        res = _acknowledge(client, campaign_id)
    assert res.status_code == 200, res.text
    assert sorted(acked) == ["evt-1", "evt-2"]
    assert [(t, d) for t, d in _changes(client, campaign_id) if t == "acknowledged"] == [
        ("acknowledged", {"alerts": 2, "failed": 0})
    ]
    # The newest change first.
    assert res.json()["changes"][0]["type"] == "acknowledged"
    assert _row(client, campaign_id).decision == "closed"


def test_a_failed_acknowledgement_of_the_route_states_the_failed_count(
    client: TestClient,
) -> None:
    campaign_id = _seed_campaign(client)
    assert _close(client, campaign_id).status_code == 200
    client.app.state.elastic = _Grid([_hit(1), _hit(2)])

    async def fake_write(tool: str, args: dict[str, Any], **kw: Any) -> tuple[None, str]:
        return None, "Security Onion answered 500"

    with patch(_ACK_PATH, fake_write):
        res = _acknowledge(client, campaign_id)
    assert res.status_code == 200
    assert _changes(client, campaign_id)[-1] == ("acknowledged", {"alerts": 0, "failed": 2})


def test_the_acknowledge_route_refuses_a_campaign_that_is_not_closed(client: TestClient) -> None:
    campaign_id = _seed_campaign(client)
    client.app.state.elastic = _Grid([_hit(1)])
    calls: list[str] = []

    async def fake_write(tool: str, args: dict[str, Any], **kw: Any) -> tuple[Any, None]:
        calls.append(args["alert_id"])
        return {}, None

    with patch(_ACK_PATH, fake_write):
        waits = _acknowledge(client, campaign_id)
        unknown = _acknowledge(client, 999)
    assert (waits.status_code, waits.json()["detail"]["reason"]) == (409, "campaign_not_closed")
    assert waits.json()["detail"]["hint"]
    assert unknown.status_code == 404
    # A negative control: the refusal writes nothing to Security Onion and records no change.
    assert calls == []
    assert "acknowledged" not in _types(client, campaign_id)


def test_the_acknowledge_route_with_a_grid_that_does_not_answer_records_nothing(
    client: TestClient,
) -> None:
    campaign_id = _seed_campaign(client)
    assert _close(client, campaign_id).status_code == 200
    client.app.state.elastic = _Grid(None)
    res = _acknowledge(client, campaign_id)
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "grid_unavailable")
    assert "acknowledged" not in _types(client, campaign_id)


def test_the_demo_refuses_the_acknowledge_route() -> None:
    from tests.test_demo_mode import _app_client, _demo_app_settings

    with _app_client(_demo_app_settings()) as demo:
        res = demo.post("/api/v1/campaigns/1/acknowledge")
    assert (res.status_code, res.json()["detail"]["reason"]) == (403, "demo_mode")


# ── The payloads (D4) ──────────────────────────────────────────────────────


def test_the_campaign_states_its_decision_its_wait_and_its_changes(client: TestClient) -> None:
    campaign_id = _seed_campaign(client)
    before = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    assert before["decision"] is None
    # An undecided campaign waits since its first event.
    assert before["waitsSince"] == before["firstEvent"]
    assert [c["type"] for c in before["changes"]] == ["formed"]
    assert set(before["changes"][0]) == {"id", "type", "at", "detail"}

    closed = _close(client, campaign_id, note="Scheduled scan.").json()
    assert set(closed["decision"]) == {"type", "reason", "note", "by", "at"}
    assert (closed["decision"]["type"], closed["decision"]["reason"]) == ("closed", "test_over")
    assert (closed["decision"]["note"], closed["decision"]["by"]) == (
        "Scheduled scan.",
        "anonymous",
    )
    assert closed["decision"]["at"].endswith("+00:00")
    assert closed["waitsSince"] is None
    # The newest change first.
    assert [c["type"] for c in closed["changes"]] == ["decided", "formed"]
    assert closed["changes"][0]["detail"] == {
        "decision": "closed",
        "reason": "test_over",
        "by": "anonymous",
        "acknowledge": False,
    }
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    assert (row["decision"], row["waitsSince"]) == ("closed", None)

    reopened = client.post(f"/api/v1/campaigns/{campaign_id}/reopen", json={}).json()
    assert reopened["decision"] is None
    # A reopened campaign waits since the reopen.
    assert reopened["waitsSince"] == reopened["changes"][0]["at"]
    assert reopened["waitsSince"] > reopened["firstEvent"]
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    assert (row["decision"], row["waitsSince"]) == (None, reopened["waitsSince"])


def test_the_link_of_a_member_investigation_and_the_host_page_state_the_decision(
    client: TestClient,
) -> None:
    campaign_id = _seed_campaign(client)
    page = client.get("/api/v1/investigations").json()
    assert {r["campaign"]["decision"] for r in page["rows"]} == {None}
    assert _close(client, campaign_id).status_code == 200
    page = client.get("/api/v1/investigations").json()
    assert {r["campaign"]["decision"] for r in page["rows"]} == {"closed"}
    (host,) = client.get("/api/v1/hosts/agent:a1").json()["campaigns"]
    assert (host["id"], host["decision"]) == (campaign_id, "closed")
