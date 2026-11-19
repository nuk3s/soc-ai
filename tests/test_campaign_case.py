"""The one Security Onion case of a campaign (phase 2, part C).

``GET /campaigns/{id}/case-scope`` states what "Open one case" writes.
``POST /campaigns/{id}/case`` records the intent, reserves each alert in the
ledger, makes the three Security Onion calls of the escalate path, and
records the result. ``POST /campaigns/{id}/case/retry`` clears an open
intent. The step after a rebuild adds one comment for a higher stage and for
a new machine.

The data is synthetic: placeholder addresses, names and rule names. No test
calls a real grid: the grid and Security Onion are fakes.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store.models import AlertEscalation, Campaign, CampaignChange
from sqlalchemy import select

from tests.test_campaign_facts import TARGET_2, seed_hosts, seed_run


class _Audit:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any], bool]] = []
        self.down: set[str] = set()

    async def log_kind(
        self, session_id: str, kind: str, payload: dict[str, Any], **kw: Any
    ) -> None:
        if kind in self.down:
            from soc_ai.audit.logger import AuditWriteError

            raise AuditWriteError(f"the audit index refused {kind}")
        self.records.append((kind, payload, bool(kw.get("mutating"))))

    def kinds(self) -> list[str]:
        return [kind for kind, _payload, _mutating in self.records]


def _ids_of(query: Any) -> list[str] | None:
    """The ids of an ``ids`` filter anywhere in the query, or None."""
    if isinstance(query, dict):
        held = query.get("ids")
        if isinstance(held, dict) and isinstance(held.get("values"), list):
            return [str(v) for v in held["values"]]
        for value in query.values():
            found = _ids_of(value)
            if found is not None:
                return found
    if isinstance(query, list):
        for value in query:
            found = _ids_of(value)
            if found is not None:
                return found
    return None


class _Feed:
    """The alert feed of the grid: the source of each alert id. ``down`` refuses each read."""

    def __init__(self, alerts: dict[str, dict[str, Any]] | None = None) -> None:
        self.alerts = alerts or {}
        self.down = False
        self.reads: list[list[str]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        if self.down:
            raise ConnectionError("the grid refused the connection")
        ids = _ids_of(query)
        if ids is None:
            return EsSearchResult(total=0, took_ms=1, hits=[], aggregations={})
        self.reads.append(ids)
        hits = [
            {"_id": i, "_index": "logs-suricata", "_source": self.alerts[i]}
            for i in ids
            if i in self.alerts
        ]
        return EsSearchResult(total=len(hits), took_ms=1, hits=hits)


class _Response:
    def __init__(self, body: dict[str, Any], status_code: int = 200) -> None:
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self) -> dict[str, Any]:
        return self._body


class _SecurityOnion:
    """Records each write. ``create_status`` 0 raises a transport fault on the create."""

    def __init__(self, *, create_status: int = 200, case_id: str | None = "case-77") -> None:
        self.create_status = create_status
        self.case_id = case_id
        self.calls: list[tuple[str, dict[str, Any]]] = []
        # Runs at each create, before the answer: a test reads the store there.
        self.on_create: Any = None
        self.comment_status = 200

    async def request(self, method: str, url: str, **kwargs: Any) -> _Response:
        body = dict(kwargs.get("json") or {})
        self.calls.append((url, body))
        if url == "/api/case/" and self.on_create is not None:
            await self.on_create()
        if url == "/api/case/comments" and self.comment_status >= 400:
            return _Response({"error": "refused"}, self.comment_status)
        if url == "/api/case/":
            if self.create_status == 0:
                raise ConnectionError("Security Onion went away")
            if self.create_status >= 400:
                return _Response({"error": "refused"}, self.create_status)
            return _Response({"id": self.case_id} if self.case_id else {})
        if url == "/api/case/events":
            return _Response({"count": 1})
        return _Response({})

    def bodies(self, url: str) -> list[dict[str, Any]]:
        return [body for called, body in self.calls if called == url]

    @property
    def created(self) -> list[dict[str, Any]]:
        return self.bodies("/api/case/")

    @property
    def attached(self) -> list[str]:
        return [str(b["fields"]["soc_id"]) for b in self.bodies("/api/case/events")]

    @property
    def marked(self) -> list[str]:
        return [str(b["eventFilter"]["soc_id"]) for b in self.bodies("/api/events/ack")]

    @property
    def comments(self) -> list[dict[str, Any]]:
        return self.bodies("/api/case/comments")


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
            app.state.elastic = _Feed()
            app.state.auth = _SecurityOnion()
            yield test_client


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


# Five alert investigations of one actor on one target: the newest event first
# is alert-0005. The fourth alert is acknowledged in Security Onion.
_ALERTS = [f"alert-000{n}" for n in range(1, 6)]


def _seed(client: TestClient, alerts: list[str] | None = None) -> int:
    """True positive runs of one actor on one target, and the campaign they form."""
    wanted = alerts or _ALERTS

    async def work(db: Any) -> None:
        await seed_hosts(db)
        for n, alert_id in enumerate(wanted, start=1):
            await seed_run(db, alert_id, event_hours_ago=8 - n, created_minutes_ago=60 - n)

    _do(client, work)
    feed: _Feed = client.app.state.elastic
    feed.alerts = {a: {"rule": {"name": "x"}} for a in wanted}
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    return int(row["id"])


def _scope(client: TestClient, campaign_id: int) -> dict[str, Any]:
    res = client.get(f"/api/v1/campaigns/{campaign_id}/case-scope")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


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
        return [(c.type, dict(c.detail)) for c in rows.all()]

    out: list[tuple[str, dict[str, Any]]] = _do(client, work)
    return out


def _case_rows(client: TestClient, campaign_id: int) -> list[tuple[str, dict[str, Any]]]:
    return [c for c in _changes(client, campaign_id) if c[0].startswith("case")]


def _claim(client: TestClient, alert_id: str, case_id: str | None) -> None:
    async def work(db: Any) -> None:
        db.add(AlertEscalation(alert_id=alert_id, case_id=case_id, escalated_by="earlier"))
        await db.commit()

    _do(client, work)


# ── C1: the scope ──────────────────────────────────────────────────────────


def test_the_scope_counts_the_alerts_the_newest_first_and_names_each_skip(
    client: TestClient,
) -> None:
    campaign_id = _seed(client)
    feed: _Feed = client.app.state.elastic
    feed.alerts["alert-0004"] = {"event": {"acknowledged": True}}
    feed.alerts["alert-0003"] = {"event": {"escalated": True, "acknowledged": True}}
    del feed.alerts["alert-0001"]  # the alert feed does not hold it
    body = _scope(client, campaign_id)
    assert body["title"].startswith("soc-ai campaign: ")
    assert body["alerts"] == 2
    assert body["capped"] is False
    assert body["skipped"] == {"acknowledged": 1, "escalated": 1, "noAlert": 1}
    assert body["existing"] is None
    # The read asks for the newest event first.
    assert feed.reads[-1] == ["alert-0005", "alert-0004", "alert-0003", "alert-0002", "alert-0001"]


def test_an_alert_on_another_case_is_skipped_and_the_count_says_so(client: TestClient) -> None:
    """A negative control: the ledger has the alert on a case, the grid shows no flag."""
    campaign_id = _seed(client)
    _claim(client, "alert-0002", "case-other")
    body = _scope(client, campaign_id)
    assert body["alerts"] == 4
    assert body["skipped"]["escalated"] == 1


def test_a_failed_grid_read_gives_alerts_null_never_0(client: TestClient) -> None:
    campaign_id = _seed(client)
    client.app.state.elastic.down = True
    body = _scope(client, campaign_id)
    assert body["alerts"] is None
    assert body["existing"] is None


def test_the_scope_takes_at_most_25_alerts_and_states_the_cap(client: TestClient) -> None:
    alerts = [f"alert-{n:04d}" for n in range(1, 28)]
    campaign_id = _seed(client, alerts)
    body = _scope(client, campaign_id)
    assert (body["alerts"], body["capped"]) == (25, True)


def test_the_scope_of_an_unknown_campaign_is_404(client: TestClient) -> None:
    res = client.get("/api/v1/campaigns/999/case-scope")
    assert (res.status_code, res.json()["detail"]["reason"]) == (404, "campaign_not_found")


# ── C6: the audit kinds ────────────────────────────────────────────────────


def test_each_audit_kind_of_the_campaign_case_is_valid() -> None:
    """A kind outside AuditKind is dropped by the best-effort wrappers with no warning."""
    from typing import get_args

    from soc_ai.api.webui._decision_commit import FAILED_KIND
    from soc_ai.audit.schemas import AuditKind

    kinds = set(get_args(AuditKind))
    wanted = {
        "campaign_case_opened",
        "campaign_case_failed",
        "campaign_case_retry",
        "campaign_case_commented",
    }
    assert wanted <= kinds
    assert FAILED_KIND["campaign_case_opened"] == "campaign_case_failed"
    assert FAILED_KIND["campaign_case_retry"] == "campaign_case_failed"


# ── C2: open one case, and try again ───────────────────────────────────────


def _press(client: TestClient, campaign_id: int, note: str = "") -> Any:
    return client.post(f"/api/v1/campaigns/{campaign_id}/case", json={"note": note})


def _so(client: TestClient) -> _SecurityOnion:
    so: _SecurityOnion = client.app.state.auth
    return so


def _ledger(client: TestClient) -> dict[str, str | None]:
    async def work(db: Any) -> dict[str, str | None]:
        rows = await db.scalars(select(AlertEscalation))
        return {r.alert_id: r.case_id for r in rows.all()}

    out: dict[str, str | None] = _do(client, work)
    return out


def test_the_press_records_the_intent_then_opens_one_case_with_the_alerts(
    client: TestClient,
) -> None:
    campaign_id = _seed(client)
    client.app.state.elastic.alerts["alert-0004"] = {"event": {"acknowledged": True}}
    seen: list[list[str]] = []

    async def at_create() -> None:
        # Rule 2: the intent is committed before the first call.
        async with client.app.state.db_sessionmaker() as db:
            rows = await db.scalars(
                select(CampaignChange.type).where(CampaignChange.campaign_id == campaign_id)
            )
            seen.append([t for t in rows.all() if t.startswith("case")])

    _so(client).on_create = at_create
    res = _press(client, campaign_id, note="The red team ended.")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["decision"]["type"] == "case"
    assert seen == [["case_intent"]]
    so = _so(client)
    (created,) = so.created
    assert created["title"] == f"soc-ai campaign: {body['title']}"
    text = created["description"]
    assert text.startswith(body["bottomLine"])
    for part in (
        "Stages reached:",
        "Machines:",
        "Period: ",
        "The campaign holds 5 alerts and 0 findings with a true positive verdict.",
        "Note of the analyst: The red team ended.",
        f"Campaign page: http://testserver/app/campaigns/{campaign_id}",
    ):
        assert part in text, part
    # The newest first, and the acknowledged alert stays off the case.
    assert so.attached == ["alert-0005", "alert-0003", "alert-0002", "alert-0001"]
    assert so.marked == so.attached
    row = _row(client, campaign_id)
    assert (row.decision, row.case_id) == ("case", "case-77")
    rows = _case_rows(client, campaign_id)
    assert [t for t, _d in rows] == ["case_intent", "case"]
    intent, case = rows[0][1], rows[1][1]
    assert intent["alerts"] == 4 and intent["intentId"] == case["intentId"]
    assert (case["caseId"], case["alerts"], case["by"]) == ("case-77", 4, "anonymous")
    # One alert on one case: the ledger holds each attached alert.
    assert _ledger(client) == dict.fromkeys(so.attached, "case-77")
    kinds = client.app.state.audit.kinds()
    assert (
        kinds.index("tool_call") < kinds.index("tool_result") < kinds.index("campaign_case_opened")
    )
    opened = next(p for k, p, m in client.app.state.audit.records if k == "campaign_case_opened")
    assert opened["case_id"] == "case-77"


def test_a_second_press_opens_no_second_case(client: TestClient) -> None:
    """A negative control for rule 1."""
    campaign_id = _seed(client)
    assert _press(client, campaign_id).status_code == 200
    again = _press(client, campaign_id)
    assert again.status_code == 200
    assert again.json()["decision"]["type"] == "case"
    assert len(_so(client).created) == 1
    assert [t for t, _d in _case_rows(client, campaign_id)] == ["case_intent", "case"]


def test_a_failed_intent_write_makes_no_call(client: TestClient) -> None:
    """A negative control for rule 2: no intent, no call."""
    from soc_ai.campaigns import decisions
    from sqlalchemy.exc import OperationalError

    campaign_id = _seed(client)
    real = decisions.change

    def refuse(campaign: int, type_: str, detail: Any, at: Any) -> Any:
        if type_ == "case_intent":
            raise OperationalError("INSERT", {}, Exception("database is locked"))
        return real(campaign, type_, detail, at)

    with patch("soc_ai.api.webui.routes_campaign_case.decisions.change", refuse):
        res = _press(client, campaign_id)
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "store_unavailable")
    assert _so(client).calls == []
    assert _ledger(client) == {}
    assert _case_rows(client, campaign_id) == []
    assert _row(client, campaign_id).decision is None


@pytest.mark.parametrize("status", [500, 0])
def test_an_unreadable_result_keeps_the_intent_and_blocks_a_call_until_try_again(
    client: TestClient, status: int
) -> None:
    campaign_id = _seed(client)
    _so(client).create_status = status
    first = _press(client, campaign_id)
    assert (first.status_code, first.json()["detail"]["reason"]) == (502, "case_unknown")
    assert "could not read the answer of Security Onion" in first.json()["detail"]["hint"]
    assert [t for t, _d in _case_rows(client, campaign_id)] == ["case_intent"]
    assert _row(client, campaign_id).decision is None
    # A second press makes no call.
    _so(client).create_status = 200
    second = _press(client, campaign_id)
    assert (second.status_code, second.json()["detail"]["reason"]) == (409, "case_pending")
    assert len(_so(client).created) == 1
    # "Try again" writes the audit record first, then clears the intent.
    cleared = client.post(f"/api/v1/campaigns/{campaign_id}/case/retry")
    assert cleared.status_code == 200, cleared.text
    retry = next(r for r in client.app.state.audit.records if r[0] == "campaign_case_retry")
    assert retry[2] is True
    assert [t for t, _d in _case_rows(client, campaign_id)] == ["case_intent", "case_failed"]
    assert _press(client, campaign_id).status_code == 200
    assert len(_so(client).created) == 2


def test_a_retry_with_no_open_intent_is_409(client: TestClient) -> None:
    campaign_id = _seed(client)
    res = client.post(f"/api/v1/campaigns/{campaign_id}/case/retry")
    assert (res.status_code, res.json()["detail"]["reason"]) == (409, "no_case_pending")


def test_a_retry_whose_audit_record_fails_keeps_the_intent(client: TestClient) -> None:
    campaign_id = _seed(client)
    _so(client).create_status = 500
    assert _press(client, campaign_id).status_code == 502
    client.app.state.audit.down = {"campaign_case_retry"}
    res = client.post(f"/api/v1/campaigns/{campaign_id}/case/retry")
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "audit_unavailable")
    assert [t for t, _d in _case_rows(client, campaign_id)] == ["case_intent"]


def test_a_refusal_of_security_onion_leaves_no_decision(client: TestClient) -> None:
    campaign_id = _seed(client)
    _so(client).create_status = 403
    res = _press(client, campaign_id)
    assert (res.status_code, res.json()["detail"]["reason"]) == (502, "security_onion_refused")
    assert "status 403" in res.json()["detail"]["hint"]
    row = _row(client, campaign_id)
    assert (row.decision, row.case_id) == (None, None)
    rows = _case_rows(client, campaign_id)
    assert [t for t, _d in rows] == ["case_intent", "case_failed"]
    assert "403" in rows[1][1]["reason"]
    # No alert was attached or marked, and the claims are free again.
    assert (_so(client).attached, _so(client).marked) == ([], [])
    assert _ledger(client) == {}
    assert "campaign_case_failed" in client.app.state.audit.kinds()
    # The next press runs.
    _so(client).create_status = 200
    assert _press(client, campaign_id).status_code == 200


def test_a_deployment_whose_writes_cannot_be_audited_writes_nothing(client: TestClient) -> None:
    """A negative control: the write is fail closed, so Security Onion gets no call."""
    campaign_id = _seed(client)
    client.app.state.audit.down = {"tool_call"}
    res = _press(client, campaign_id)
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "audit_unavailable")
    assert _so(client).calls == []
    assert _ledger(client) == {}
    assert _row(client, campaign_id).decision is None
    assert [t for t, _d in _case_rows(client, campaign_id)] == ["case_intent", "case_failed"]


def test_a_closed_campaign_takes_no_case(client: TestClient) -> None:
    campaign_id = _seed(client)
    closed = client.post(f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "test_over"})
    assert closed.status_code == 200
    res = _press(client, campaign_id)
    assert (res.status_code, res.json()["detail"]["reason"]) == (409, "campaign_decided")
    assert _so(client).calls == []
    assert _case_rows(client, campaign_id) == []


def test_a_failed_case_record_keeps_the_case_and_the_next_press_opens_none(
    client: TestClient,
) -> None:
    campaign_id = _seed(client)
    client.app.state.audit.down = {"campaign_case_opened"}
    res = _press(client, campaign_id)
    assert (res.status_code, res.json()["detail"]["reason"]) == (503, "audit_unavailable")
    assert "case-77" in res.json()["detail"]["hint"]
    row = _row(client, campaign_id)
    assert (row.decision, row.case_id) == (None, "case-77")
    client.app.state.audit.down = set()
    again = _press(client, campaign_id)
    assert again.status_code == 200, again.text
    assert again.json()["decision"]["type"] == "case"
    assert len(_so(client).created) == 1


def test_open_again_keeps_the_case_and_a_second_press_finds_it(client: TestClient) -> None:
    """Rule 6: the case in Security Onion stays, so the press opens none."""
    campaign_id = _seed(client)
    assert _press(client, campaign_id).status_code == 200
    reopened = client.post(f"/api/v1/campaigns/{campaign_id}/reopen", json={})
    assert reopened.status_code == 200, reopened.text
    row = _row(client, campaign_id)
    assert (row.decision, row.case_id) == (None, "case-77")
    scope = _scope(client, campaign_id)
    assert scope["existing"]["id"] == "case-77"
    assert scope["alerts"] == 0
    again = _press(client, campaign_id)
    assert again.status_code == 200
    assert again.json()["decision"]["type"] == "case"
    assert len(_so(client).created) == 1
    last = _case_rows(client, campaign_id)[-1]
    assert last[0] == "case" and last[1]["existing"] is True


def test_the_demo_lock_refuses_the_case_routes() -> None:
    from tests.test_demo_mode import _app_client, _demo_app_settings

    with _app_client(_demo_app_settings()) as demo:
        opened = demo.post("/api/v1/campaigns/1/case", json={"note": ""})
        retry = demo.post("/api/v1/campaigns/1/case/retry")
    assert (opened.status_code, opened.json()["detail"]["reason"]) == (403, "demo_mode")
    assert (retry.status_code, retry.json()["detail"]["reason"]) == (403, "demo_mode")


# ── C3: one comment for a higher stage and for a new machine ───────────────


def _opened(client: TestClient) -> int:
    campaign_id = _seed(client)
    assert _press(client, campaign_id).status_code == 200
    return campaign_id


def _add_run(client: TestClient, alert_id: str, **kwargs: Any) -> None:
    async def work(db: Any) -> None:
        await seed_run(db, alert_id, event_hours_ago=0.5, created_minutes_ago=5, **kwargs)

    _do(client, work)
    client.app.state.elastic.alerts[alert_id] = {"rule": {"name": "x"}}
    assert client.get("/api/v1/campaigns").status_code == 200


def _step(client: TestClient) -> int:
    from soc_ai.campaigns import case_comments

    async def work(db: Any) -> int:
        return await case_comments.after_rebuild(db, state=client.app.state)

    added: int = _do(client, work)
    return added


def test_a_new_machine_adds_one_comment_with_the_machine_the_time_and_the_link(
    client: TestClient,
) -> None:
    campaign_id = _opened(client)
    _add_run(client, "alert-0101", dst=TARGET_2)
    (comment,) = _so(client).comments
    assert comment["caseId"] == "case-77"
    text = comment["description"]
    assert "A new machine joined the campaign" in text and "web-2" in text and " UTC" in text
    assert text.endswith(f"Campaign page: http://testserver/app/campaigns/{campaign_id}")
    rows = [d for t, d in _case_rows(client, campaign_id) if t == "case_comment"]
    assert [(d["caseId"], d["for"]) for d in rows] == [("case-77", "party")]
    # The case holds the work: the decision stays.
    assert _row(client, campaign_id).decision == "case"
    assert "campaign_case_commented" in client.app.state.audit.kinds()


def test_two_steps_add_one_comment_for_one_change(client: TestClient) -> None:
    """A negative control: a change with a recorded comment gets no second one."""
    _opened(client)
    _add_run(client, "alert-0101", dst=TARGET_2)
    assert _step(client) == 0
    assert _step(client) == 0
    assert len(_so(client).comments) == 1


def test_a_higher_stage_adds_one_comment_with_the_stage(client: TestClient) -> None:
    campaign_id = _opened(client)
    _add_run(client, "alert-0102", report={"stage": "access"})
    (comment,) = _so(client).comments
    assert "reached the stage Access at " in comment["description"]
    rows = [d for t, d in _case_rows(client, campaign_id) if t == "case_comment"]
    assert [d["for"] for d in rows] == ["stage"]
    assert _row(client, campaign_id).decision == "case"


def test_a_new_investigation_with_no_new_stage_and_no_new_machine_adds_no_comment(
    client: TestClient,
) -> None:
    """A negative control: a new investigation alone adds none."""
    campaign_id = _opened(client)
    _add_run(client, "alert-0103")
    assert _so(client).comments == []
    assert _step(client) == 0
    assert _row(client, campaign_id).decision == "case"


def test_soc_ai_comments_only_on_a_case_that_its_own_case_row_holds(client: TestClient) -> None:
    """A negative control: a case id with no case row of soc-ai gets no comment."""
    campaign_id = _seed(client)

    async def foreign(db: Any) -> None:
        row = await db.get(Campaign, campaign_id)
        row.case_id = "case-foreign"
        row.decision = "case"
        await db.commit()

    _do(client, foreign)
    _add_run(client, "alert-0101", dst=TARGET_2)
    assert _so(client).comments == []


def test_a_refused_comment_records_nothing_and_the_next_step_adds_it(client: TestClient) -> None:
    campaign_id = _opened(client)
    _so(client).comment_status = 500
    _add_run(client, "alert-0101", dst=TARGET_2)
    # The rebuild stands: the new machine is a party.
    parties = client.get(f"/api/v1/campaigns/{campaign_id}").json()["parties"]
    assert any(p["name"] == "web-2" for p in parties)
    assert [t for t, _d in _case_rows(client, campaign_id) if t == "case_comment"] == []
    _so(client).comment_status = 200
    assert _step(client) == 1
    assert len(_so(client).comments) == 2
    assert _step(client) == 0


# ── C5: the payloads, Needs you, the bell and the list ─────────────────────


def _campaign(client: TestClient, campaign_id: int) -> dict[str, Any]:
    res = client.get(f"/api/v1/campaigns/{campaign_id}")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_the_campaign_states_its_open_case_with_the_alerts_and_the_comments(
    client: TestClient,
) -> None:
    campaign_id = _seed(client)
    assert _campaign(client, campaign_id)["case"] is None
    _press(client, campaign_id)
    case = _campaign(client, campaign_id)["case"]
    assert set(case) == {
        "id",
        "url",
        "openedAt",
        "by",
        "alerts",
        "comments",
        "state",
        "failure",
    }
    assert (case["id"], case["state"], case["alerts"], case["comments"]) == (
        "case-77",
        "open",
        5,
        0,
    )
    assert case["url"] == "https://so.example.com/#/case/case-77"
    assert (case["by"], case["failure"]) == ("anonymous", None)
    assert datetime.fromisoformat(case["openedAt"]).tzinfo is not None
    _add_run(client, "alert-0101", dst=TARGET_2)
    detail = _campaign(client, campaign_id)
    assert detail["case"]["comments"] == 1
    assert {c["type"] for c in detail["changes"]} >= {"case_intent", "case", "case_comment"}


def test_a_press_with_no_answer_is_pending_and_a_refusal_is_failed(client: TestClient) -> None:
    campaign_id = _seed(client)
    _so(client).create_status = 500
    _press(client, campaign_id)
    case = _campaign(client, campaign_id)["case"]
    assert (case["state"], case["id"], case["alerts"]) == ("pending", None, 5)
    client.post(f"/api/v1/campaigns/{campaign_id}/case/retry")
    cleared = _campaign(client, campaign_id)["case"]
    assert cleared["state"] == "failed"
    assert "cleared the earlier press" in cleared["failure"]
    _so(client).create_status = 403
    _press(client, campaign_id)
    failed = _campaign(client, campaign_id)
    assert failed["decision"] is None
    assert failed["case"]["state"] == "failed"
    assert "403" in failed["case"]["failure"]


def test_the_rows_the_threats_and_the_link_carry_the_case(client: TestClient) -> None:
    campaign_id = _seed(client)
    (before,) = client.get("/api/v1/campaigns").json()["rows"]
    assert (before["decision"], before["case"]) == (None, None)
    _press(client, campaign_id)
    opened_at = _campaign(client, campaign_id)["case"]["openedAt"]
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    assert (row["decision"], row["case"]) == ("case", {"openedAt": opened_at})
    # A case is a decision in force: the campaign leaves the red list of the
    # confirmed threats, and the decided line counts it (round "decide once").
    threats = client.get("/api/v1/threats", params={"since": "2000-01-01T00:00:00Z"}).json()
    assert [c for c in threats["campaigns"] if c["id"] == campaign_id] == []
    assert threats["decided"]["campaigns"] == 1
    assert threats["decided"]["investigations"] >= 1
    assert row["state"] == "case"
    run_id = _campaign(client, campaign_id)["members"][0]["runId"]
    link = client.get(f"/api/v1/investigations/{run_id}").json()["campaign"]
    assert link["decision"] == "case"


def test_a_campaign_with_a_case_is_no_needs_you_item(client: TestClient) -> None:
    campaign_id = _seed(client)
    assert client.get("/api/v1/needs-you").json()["campaigns"] == 1
    _press(client, campaign_id)
    assert client.get("/api/v1/needs-you").json()["campaigns"] == 0
    items = client.get("/api/v1/needs-you/items").json()["items"]
    assert [i for i in items if i["type"] == "campaign"] == []
    # Open again: the campaign waits again.
    client.post(f"/api/v1/campaigns/{campaign_id}/reopen", json={})
    assert client.get("/api/v1/needs-you").json()["campaigns"] == 1


def test_a_new_machine_of_a_campaign_with_a_case_is_a_danger_row(client: TestClient) -> None:
    campaign_id = _opened(client)
    _add_run(client, "alert-0101", dst=TARGET_2)
    party = next(c for c in _campaign(client, campaign_id)["changes"] if c["type"] == "party")
    rows = client.get("/api/v1/notifications", params={"limit": 50}).json()
    found = [r for r in rows if r["id"] == f"campaign:{party['id']}"]
    assert [r["tone"] for r in found] == ["danger"]
    # The case changes of soc-ai raise no row.
    case_ids = {
        c["id"] for c in _campaign(client, campaign_id)["changes"] if c["type"].startswith("case")
    }
    assert not {r["id"] for r in rows} & {f"campaign:{i}" for i in case_ids}
