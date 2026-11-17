"""The authorized activity routes: the draft, the create, the revoke and the list.

The record takes work out of the queue, so the routes refuse every request
that would make a scope wider than the run allows. The target address and
the alert class come from the run. A source address and a rule name must be
ones the draft offers, and the draft offers only an address that an agent
reports. The create needs an admin and its audit record, and the revoke
needs a reason.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.agent import authorized_activity as aam
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import authorized_activity as aa
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import (
    EntityObservation,
    HostDossier,
    HostMachine,
    Investigation,
    Lead,
)
from sqlalchemy import func, select

TARGET = "10.40.0.164"
SOURCE_A = "10.50.0.26"
SOURCE_A_NAMED = "10.50.0.27"
SOURCE_B = "10.50.0.52"
STRANGER = "10.50.0.200"
BRIDGE_GW = "10.89.0.1"
CONTAINER = "10.89.0.5"
RULE_NESTED = "ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)"
RULE_CHUNKED = (
    "ET EXPLOIT PHP php2shell Chunked Multipart Request without Content-Length (CVE-2026-109618)"
)
RULE_HUNTING = "ET HUNTING PHP Generic Upload Progress Session Manipulation"
_ORIGIN = {"Origin": "http://testserver"}
_ESCALATE = {
    "tool_name": "escalate_to_case",
    "tool_args": {"case_title": "php2shell", "case_description": "Exploit requests."},
    "rationale": "Open a case for the exploit requests.",
}


class _Audit:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any], str]] = []

    async def log_kind(
        self, session_id: str, kind: str, payload: dict[str, Any], **kw: Any
    ) -> None:
        self.records.append((kind, payload, str(kw.get("user"))))


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


def _seed_machines(client: TestClient) -> None:
    """The production shape: agent machines as sources, a target known by its address."""

    async def work(db: Any) -> None:
        agent_a = HostMachine(machine_key="agent:a-1", name="agent-a", address_count=2)
        agent_b = HostMachine(machine_key="agent:b-2", name="agent-b", address_count=1)
        target = HostMachine(machine_key=f"ip:{TARGET}", address_count=1)
        gateway = HostMachine(machine_key=f"ip:{BRIDGE_GW}", address_count=1)
        db.add_all([agent_a, agent_b, target, gateway])
        await db.flush()

        def row(address: str, machine: HostMachine, kind: str) -> HostDossier:
            return HostDossier(
                host_key=address, ip=address, machine_id=machine.id, address_kind=kind
            )

        db.add_all(
            [
                row(SOURCE_A, agent_a, "agent"),
                # A static address that joined agent-a by its DNS name only.
                row(SOURCE_A_NAMED, agent_a, "name"),
                row(SOURCE_B, agent_b, "agent"),
                row(TARGET, target, "network"),
                # A container bridge: every container host has these two.
                row(BRIDGE_GW, gateway, "network"),
                row(CONTAINER, agent_a, "container"),
            ]
        )
        await db.commit()

    _do(client, work)


def _seed_run(
    client: TestClient,
    alert_id: str,
    *,
    rule: str = RULE_NESTED,
    src: str | None = SOURCE_A,
    dst: str | None = TARGET,
    verdict: str = "true_positive",
    hours_ago: float = 1.0,
    started_by: str = "auto-triage",
    kind: str = "suricata",
    alert: dict[str, Any] | None = None,
    with_context: bool = True,
    citations: list[str] | None = None,
    session_events: list[dict[str, Any]] | None = None,
) -> str:
    """One finalized alert run with its alert context event. Returns its id."""
    when = datetime.now(UTC) - timedelta(hours=hours_ago)
    payload: dict[str, Any] = {
        "id": alert_id,
        "timestamp": when.isoformat(),
        "rule_name": rule,
        "source_ip": src,
        "destination_ip": dst,
        "classtype": "web-application-attack",
        "event_dataset": "suricata.alert",
        "event_module": "suricata",
    }
    payload.update(alert or {})

    async def work(db: Any) -> str:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_id,
            started_by=started_by,
            rule_name=rule,
            src_ip=src,
            dest_ip=dst,
            kind=kind,
        )
        if with_context:
            context = {"alert": payload, "community_id_events": session_events or []}
            await inv_svc.append_events(
                db,
                inv.id,
                [{"sequence": 1, "kind": "enriched_alert_context", "payload": context}],
            )
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict=verdict,
            confidence=0.85,
            summary="The source sent exploit requests.",
            report={
                "verdict": verdict,
                "confidence": 0.85,
                "summary": "The source sent exploit requests.",
                "citations": citations if citations is not None else [alert_id],
                "recommended_actions": [_ESCALATE],
            },
        )
        row = await db.get(Investigation, inv.id)
        row.created_at = when.replace(tzinfo=None)
        await db.commit()
        return str(inv.id)

    run_id: str = _do(client, work)
    return run_id


def _row(client: TestClient, run_id: str) -> Investigation:
    async def work(db: Any) -> Investigation:
        row = await db.get(Investigation, run_id)
        assert row is not None
        return row

    row: Investigation = _do(client, work)
    return row


def _count(client: TestClient, model: Any) -> int:
    async def work(db: Any) -> int:
        return int(await db.scalar(select(func.count()).select_from(model)) or 0)

    return int(_do(client, work))


def _draft(client: TestClient, run_id: str, **params: Any) -> dict[str, Any]:
    res = client.get(f"/api/v1/investigations/{run_id}/authorized-activity/draft", params=params)
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _create(client: TestClient, run_id: str, **overrides: Any) -> Any:
    body: dict[str, Any] = {
        "investigation_id": run_id,
        "label": "php2shell test",
        "sources": [SOURCE_A],
        "rule_names": [RULE_NESTED],
    }
    body.update(overrides)
    return client.post("/api/v1/authorized-activity", json=body)


def _audit_kinds(client: TestClient) -> list[str]:
    return [kind for kind, _payload, _user in client.app.state.audit.records]


# ── The draft ──────────────────────────────────────────────────────────────


def test_the_draft_names_the_pair_and_offers_the_rules_and_sources_of_its_runs(
    client: TestClient,
) -> None:
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    _seed_run(client, "a-2", rule=RULE_CHUNKED, src=SOURCE_B)
    _seed_run(client, "a-3", rule=RULE_CHUNKED)
    _seed_run(client, "a-4", rule=RULE_HUNTING)
    # Not offered: a replay, a synthetic run, a run of another alert class.
    _seed_run(client, "a-5", rule="ET EXPLOIT replayed rule", started_by="backtest")
    _seed_run(
        client,
        "a-6",
        rule="ET MALWARE Cobalt Strike Beacon Observed",
        alert={"classtype": "trojan-activity"},
    )

    draft = _draft(client, run_id)

    assert draft["allowed"] is True
    assert draft["rule_class"] == "exploit_attempt"
    assert draft["target"] == {
        "address": TARGET,
        "name": None,
        "machine_key": f"ip:{TARGET}",
        "identity": "address",
    }
    assert draft["target_has_agent"] is False, "the dialog says that the record follows the address"
    sources = {s["address"]: s for s in draft["sources"]}
    assert list(sources) == [SOURCE_A, SOURCE_B], "the source of the run comes first"
    assert sources[SOURCE_A]["of_this_run"] is True
    assert (sources[SOURCE_A]["identity"], sources[SOURCE_A]["name"]) == ("agent", "agent-a")
    assert sources[SOURCE_A]["runs"] == 4
    assert sources[SOURCE_B]["of_this_run"] is False
    # What the dialog lists is exactly what can match: the rule names of the
    # live true positive alert runs on this pair, with the class of this run.
    assert draft["rules"] == [
        {"name": RULE_NESTED, "runs": 1, "of_this_run": True},
        {"name": RULE_CHUNKED, "runs": 2, "of_this_run": False},
        {"name": RULE_HUNTING, "runs": 1, "of_this_run": False},
    ]
    assert draft["this_run_outside"] is None
    assert (draft["default_days"], draft["max_days"]) == (7, 30)
    assert draft["expiry_choices"] == [1, 7, 14, 30]


def test_the_draft_leaves_out_a_source_that_no_agent_proves_and_says_why(
    client: TestClient,
) -> None:
    """Review defects 3 and 4. A name, a bridge and no agent prove no machine."""
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    _seed_run(client, "a-2", src=SOURCE_A_NAMED)
    _seed_run(client, "a-3", src=STRANGER)
    _seed_run(client, "a-4", src=CONTAINER)

    draft = _draft(client, run_id)

    assert [s["address"] for s in draft["sources"]] == [SOURCE_A]
    excluded = {e["address"]: e for e in draft["excluded_sources"]}
    assert excluded[SOURCE_A_NAMED]["reason"] == "source_joined_by_name"
    assert excluded[STRANGER]["reason"] == "source_not_agent_address"
    assert excluded[CONTAINER]["reason"] == "source_on_bridge"
    assert "More than one machine can hold it." in excluded[CONTAINER]["hint"]
    for address in (SOURCE_A_NAMED, STRANGER, CONTAINER):
        res = _create(client, run_id, sources=[SOURCE_A, address])
        assert res.status_code == 422, address
        assert res.json()["detail"]["reason"] == "source_not_offered"


def test_the_draft_counts_the_earlier_runs_of_the_chosen_scope(client: TestClient) -> None:
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    _seed_run(client, "a-2", rule=RULE_CHUNKED)
    _seed_run(client, "a-3", rule=RULE_CHUNKED, src=SOURCE_B)
    _seed_run(client, "a-4")

    assert _draft(client, run_id)["earlier_runs"] == 1, "the same rule from the same address"
    assert _draft(client, run_id, rule=[RULE_CHUNKED])["earlier_runs"] == 2
    both = _draft(client, run_id, rule=[RULE_CHUNKED], source=[SOURCE_B])
    assert both["earlier_runs"] == 3

    res = client.get(
        f"/api/v1/investigations/{run_id}/authorized-activity/draft",
        params={"rule": ["ET SCAN not offered"]},
    )
    assert res.status_code == 422
    assert res.json()["detail"]["reason"] == "rule_not_offered"


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"verdict": "needs_more_info"}, "not_true_positive"),
        ({"verdict": "false_positive"}, "not_true_positive"),
        ({"started_by": "backtest"}, "measurement_run"),
        ({"kind": "hunt"}, "promoted_run"),
        ({"with_context": False}, "no_alert_context"),
        (
            {"alert": {"event_dataset": "opencanary", "event_module": "opencanary"}},
            "decoy_alert",
        ),
        ({"alert": {"rule_name": None}}, "no_rule_name"),
        ({"src": None}, "no_flow"),
        ({"hours_ago": 24 * 31}, "run_too_old"),
        # The source must be an address that the agent of its machine reports.
        ({"src": STRANGER}, "source_not_agent_address"),
        ({"src": SOURCE_A_NAMED}, "source_joined_by_name"),
        # Review scenario m1: a scope of bridge addresses covers every machine.
        ({"src": BRIDGE_GW, "dst": CONTAINER}, "source_on_bridge"),
        ({"dst": CONTAINER}, "target_on_bridge"),
        ({"dst": BRIDGE_GW}, "target_on_bridge"),
    ],
)
def test_a_run_that_cannot_start_a_record_says_why(
    client: TestClient, kwargs: dict[str, Any], reason: str
) -> None:
    _seed_machines(client)
    run_id = _seed_run(client, "a-1", **kwargs)

    draft = _draft(client, run_id)
    assert (draft["allowed"], draft["reason"]) == (False, reason)
    assert draft["hint"]

    res = _create(client, run_id)
    assert res.status_code == 409, res.text
    assert res.json()["detail"]["reason"] == reason
    assert _audit_kinds(client) == []


def test_an_unknown_run_answers_404(client: TestClient) -> None:
    res = client.get("/api/v1/investigations/nope/authorized-activity/draft")
    assert res.status_code == 404
    assert _create(client, "nope").status_code == 404


# ── The create ─────────────────────────────────────────────────────────────


def test_the_create_stores_the_scope_of_the_run_and_marks_that_run(client: TestClient) -> None:
    _seed_machines(client)
    earlier = _seed_run(client, "a-0", hours_ago=30)
    run_id = _seed_run(client, "a-1")

    res = _create(client, run_id, note="Exploit test of the week.")

    assert res.status_code == 201, res.text
    body = res.json()
    assert body["state"] == "active"
    assert body["label"] == "php2shell test"
    assert body["created_by"] == "anonymous"
    assert body["rule_names"] == [RULE_NESTED]
    assert body["rule_class"] == "exploit_attempt", "the class comes from the run"
    assert body["target"]["address"] == TARGET, "the target comes from the run"
    assert [(s["address"], s["machine_key"]) for s in body["sources"]] == [(SOURCE_A, "agent:a-1")]
    expires = datetime.fromisoformat(body["expires_at"])
    assert timedelta(days=6, hours=23) < expires - datetime.now(UTC) <= timedelta(days=7)
    assert body["source_investigation_id"] == run_id
    assert body["runs_total"] == 1
    assert body["runs_href"] == f"/investigations?authorization={body['id']}&range=all"

    # The run of the record carries the mark. The earlier run does not: the
    # checkbox is off by default.
    assert _row(client, run_id).authorization_id == body["id"]
    assert _row(client, earlier).authorization_id is None
    marked = _row(client, run_id).report
    assert marked is not None
    assert marked["authorized_activity"]["state"] == "matched"
    assert marked["verdict"] == "true_positive"
    assert marked["recommended_actions"] == [_ESCALATE]

    assert _audit_kinds(client) == ["authorized_activity_created", "authorized_activity_matched"]
    created = client.app.state.audit.records[0][1]
    assert created["rule_names"] == [RULE_NESTED]
    assert created["target"]["address"] == TARGET
    assert created["apply_to_earlier"] is False


def test_the_checkbox_marks_the_earlier_runs_the_scope_matches(client: TestClient) -> None:
    _seed_machines(client)
    earlier = _seed_run(client, "a-0", hours_ago=30)
    listed = _seed_run(client, "a-c", rule=RULE_CHUNKED, hours_ago=28)
    old = _seed_run(client, "a-old", hours_ago=24 * 40)
    other_rule = _seed_run(client, "a-h", rule=RULE_HUNTING, hours_ago=20)
    other_source = _seed_run(client, "a-s", src=SOURCE_B, hours_ago=10)
    named = _seed_run(client, "a-n", src=SOURCE_A_NAMED, hours_ago=9)
    stranger = _seed_run(client, "a-x", src=STRANGER, hours_ago=8)
    replay = _seed_run(client, "a-r", hours_ago=6, started_by="backtest")
    beacon = {"id": "zeek-conn-doc-0201", "source_ip": TARGET, "destination_ip": "203.0.113.9"}
    cites_more = _seed_run(
        client,
        "a-b",
        hours_ago=5,
        citations=["a-b", "zeek-conn-doc-0201"],
        session_events=[beacon],
    )
    run_id = _seed_run(client, "a-1")

    res = _create(client, run_id, rule_names=[RULE_NESTED, RULE_CHUNKED], apply_to_earlier=True)

    assert res.status_code == 201, res.text
    body = res.json()
    authorization_id = body["id"]
    for inside in (run_id, earlier, listed):
        assert _row(client, inside).authorization_id == authorization_id, inside
    earlier_report = _row(client, earlier).report
    assert earlier_report is not None
    assert earlier_report["authorized_activity"]["earlier"] is True
    # Negative controls: none of these is inside the scope.
    for outside in (old, other_rule, other_source, named, stranger, replay, cites_more):
        assert _row(client, outside).authorization_id is None, outside
    assert (body["runs_total"], body["earlier_runs"]) == (3, 3)
    assert _audit_kinds(client).count("authorized_activity_matched") == 3


def test_a_rule_and_a_source_must_be_ones_the_draft_offers(client: TestClient) -> None:
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    _seed_run(client, "a-2", rule=RULE_CHUNKED, src=SOURCE_B)

    refused = _create(client, run_id, rule_names=[RULE_NESTED, "ET EXPLOIT PHP php2shell"])
    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"]["reason"] == "rule_not_offered"
    refused = _create(client, run_id, sources=[SOURCE_A, STRANGER])
    assert refused.json()["detail"]["reason"] == "source_not_offered"

    ok = _create(client, run_id, sources=[SOURCE_B], rule_names=[RULE_CHUNKED])
    assert ok.status_code == 201, ok.text
    assert [s["address"] for s in ok.json()["sources"]] == [SOURCE_A, SOURCE_B], (
        "the source of the run is always in the scope"
    )
    assert ok.json()["rule_names"] == [RULE_NESTED, RULE_CHUNKED], (
        "the rule of the run is always in the scope"
    )


def test_the_run_of_the_record_stays_outside_when_its_report_cites_more(
    client: TestClient,
) -> None:
    """Review defect 7. The dialog says it before the save."""
    _seed_machines(client)
    beacon = {"id": "zeek-conn-doc-0201", "source_ip": TARGET, "destination_ip": "203.0.113.9"}
    run_id = _seed_run(
        client, "a-1", citations=["a-1", "zeek-conn-doc-0201"], session_events=[beacon]
    )

    draft = _draft(client, run_id)
    assert draft["allowed"] is True
    assert draft["this_run_outside"].endswith("the report cites activity beyond the scope.")

    res = _create(client, run_id)
    assert res.status_code == 201, res.text
    assert res.json()["runs_total"] == 0
    assert _row(client, run_id).authorization_id is None
    assert client.get("/api/v1/needs-you").json()["pending_actions"] == 1


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"label": "   "}, "label_required"),
        ({"rule_names": ["ET EXPLOIT"]}, "rule_not_offered"),
        ({"rule_names": [RULE_NESTED + " variant"]}, "rule_not_offered"),
    ],
)
def test_the_create_refuses_a_scope_wider_than_the_run(
    client: TestClient, overrides: dict[str, Any], reason: str
) -> None:
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    res = _create(client, run_id, **overrides)
    assert res.status_code == 422, res.text
    assert res.json()["detail"]["reason"] == reason
    assert _row(client, run_id).authorization_id is None


@pytest.mark.parametrize("days", [0, 31, -1])
def test_the_expiry_is_at_most_thirty_days(client: TestClient, days: int) -> None:
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    assert _create(client, run_id, expires_in_days=days).status_code == 422
    assert _create(client, run_id, expires_in_days=30).status_code == 201


def test_a_body_cannot_set_the_target_or_the_class(client: TestClient) -> None:
    """Extra keys are ignored. The scope has the target and the class of the run."""
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    res = _create(
        client,
        run_id,
        target="10.40.0.9",
        target_address="10.40.0.9",
        rule_class="informational_visibility",
    )
    assert res.status_code == 201, res.text
    assert res.json()["target"]["address"] == TARGET
    assert res.json()["rule_class"] == "exploit_attempt"


def test_a_run_that_holds_a_mark_cannot_start_a_second_record(client: TestClient) -> None:
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    assert _create(client, run_id).status_code == 201
    again = _create(client, run_id)
    assert again.status_code == 409
    assert again.json()["detail"]["reason"] == "already_authorized"


def test_no_record_is_in_force_when_the_audit_write_fails(client: TestClient) -> None:
    """Review defect 10. The create is atomic with its audit record."""
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    good = client.app.state.audit

    class _Down:
        async def log_kind(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("the audit index did not answer")

    client.app.state.audit = _Down()
    res = _create(client, run_id)
    assert res.status_code == 503, res.text
    assert res.json()["detail"]["reason"] == "audit_unavailable"
    assert client.get("/api/v1/authorized-activity").json()["rows"] == []
    assert _row(client, run_id).authorization_id is None
    assert client.get("/api/v1/needs-you").json()["pending_actions"] == 1

    # Control: with the audit write back, the same request saves the record.
    client.app.state.audit = good
    assert _create(client, run_id).status_code == 201
    assert _audit_kinds(client)[0] == "authorized_activity_created"


# ── The revoke ─────────────────────────────────────────────────────────────


def test_a_revoke_needs_a_reason_and_returns_the_runs_to_normal_handling(
    client: TestClient,
) -> None:
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    authorization_id = _create(client, run_id).json()["id"]
    url = f"/api/v1/authorized-activity/{authorization_id}/revoke"
    assert client.get("/api/v1/needs-you").json()["pending_actions"] == 0

    assert client.post(url, json={}).status_code == 422
    blank = client.post(url, json={"reason": "   "})
    assert blank.status_code == 422
    assert blank.json()["detail"]["reason"] == "reason_required"

    res = client.post(url, json={"reason": "The test ended early."})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["state"] == "revoked"
    assert body["revoke_reason"] == "The test ended early."
    assert body["revoked_by"] == "anonymous"
    assert body["runs_total"] == 1, "the link of the run stays as history"
    assert body["runs_returned"] == 1, "the answer states the count"

    assert client.get("/api/v1/needs-you").json()["pending_actions"] == 1
    assert _audit_kinds(client)[-1] == "authorized_activity_revoked"
    assert client.app.state.audit.records[-1][1]["reason"] == "The test ended early."
    assert client.app.state.audit.records[-1][1]["runs"] == 1

    again = client.post(url, json={"reason": "second"})
    assert again.status_code == 409
    assert again.json()["detail"]["reason"] == "already_revoked"
    missing = client.post("/api/v1/authorized-activity/9999/revoke", json={"reason": "x"})
    assert missing.status_code == 404


def test_a_revoke_returns_every_marked_run_whatever_its_age_and_count(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review defect 9. More runs than one batch, and runs older than 7 days."""
    from soc_ai.api.webui import routes_authorized_activity as routes

    monkeypatch.setattr(routes, "_REVOKE_BATCH", 3)
    _seed_machines(client)
    first = _seed_run(client, "a-1")
    authorization_id = _create(client, first).json()["id"]

    async def later_runs(db: Any) -> None:
        row = await aa.get(db, authorization_id)
        assert row is not None
        for n in range(7):
            inv = await inv_svc.create(
                db,
                alert_es_id=f"late-{n}",
                started_by="auto-triage",
                rule_name=RULE_NESTED,
                src_ip=SOURCE_B,
                dest_ip=f"10.40.1.{n}",
            )
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="true_positive",
                confidence=0.85,
                report={
                    "verdict": "true_positive",
                    "authorized_activity": aam.matched_mark(aa.scope_of(row), at=utcnow()),
                },
            )
            stored = await db.get(Investigation, inv.id)
            stored.created_at = utcnow() - timedelta(days=9 + n)
            await db.commit()

    _do(client, later_runs)
    before = _count(client, EntityObservation)

    res = client.post(
        f"/api/v1/authorized-activity/{authorization_id}/revoke", json={"reason": "Wrong scope."}
    )

    assert res.status_code == 200, res.text
    assert res.json()["runs_returned"] == 8
    # Each of the 7 runs the lead path skipped is observed now: two internal
    # ends each.
    assert _count(client, EntityObservation) - before >= 14
    assert _count(client, Lead) >= 1


# ── The list ───────────────────────────────────────────────────────────────


def test_the_list_states_the_counts_and_keeps_an_ended_record_for_seven_days(
    client: TestClient,
) -> None:
    _seed_machines(client)
    run_id = _seed_run(client, "a-1")
    live = _create(client, run_id).json()["id"]

    async def ended(db: Any) -> tuple[int, int]:
        now = utcnow()
        recent = await aa.create(
            db,
            label="ended test",
            sources=[aa.ScopeEntry(SOURCE_B, "agent:b-2")],
            target=aa.ScopeEntry(TARGET, f"ip:{TARGET}"),
            rule_names=[RULE_NESTED],
            rule_class="exploit_attempt",
            expires_at=now - timedelta(days=1),
            created_by="casey",
            now=now - timedelta(days=5),
        )
        old = await aa.create(
            db,
            label="old test",
            sources=[aa.ScopeEntry(SOURCE_B, "agent:b-2")],
            target=aa.ScopeEntry(TARGET, f"ip:{TARGET}"),
            rule_names=[RULE_NESTED],
            rule_class="exploit_attempt",
            expires_at=now - timedelta(days=9),
            created_by="casey",
            now=now - timedelta(days=20),
        )
        return int(recent.id), int(old.id)

    recent_id, old_id = _do(client, ended)

    body = client.get("/api/v1/authorized-activity").json()
    assert [row["id"] for row in body["rows"]] == [live, recent_id]
    assert old_id not in {row["id"] for row in body["rows"]}
    assert body["active"] == 1
    first = body["rows"][0]
    assert (first["state"], first["runs_total"], first["runs_since_decision"]) == ("active", 1, 0)
    assert first["earlier_runs"] == 1, "the run of the record was made before the decision"
    assert first["last_match_at"] is not None
    assert first["runs_returned"] is None
    assert body["rows"][1]["state"] == "expired"

    only_active = client.get("/api/v1/authorized-activity", params={"ended": "false"}).json()
    assert [row["id"] for row in only_active["rows"]] == [live]


# ── Who may write ──────────────────────────────────────────────────────────


def test_the_create_needs_an_admin_and_the_revoke_a_signed_in_caller(
    audit_client: TestClient, analyst: TestClient, admin: TestClient
) -> None:
    _seed_machines(audit_client)
    run_id = _seed_run(audit_client, "a-1")
    body = {
        "investigation_id": run_id,
        "label": "php2shell test",
        "sources": [SOURCE_A],
        "rule_names": [RULE_NESTED],
    }

    assert audit_client.post("/api/v1/authorized-activity", json=body).status_code in (401, 403)
    refused = analyst.post("/api/v1/authorized-activity", json=body, headers=_ORIGIN)
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["reason"] == "admin_required"
    assert _row(audit_client, run_id).authorization_id is None

    created = admin.post("/api/v1/authorized-activity", json=body, headers=_ORIGIN)
    assert created.status_code == 201, created.text
    authorization_id = created.json()["id"]
    assert created.json()["created_by"] == "audit-admin"

    # The list and the draft are reads of any signed-in caller.
    assert analyst.get("/api/v1/authorized-activity").status_code == 200
    assert audit_client.get("/api/v1/authorized-activity").status_code in (401, 403)

    url = f"/api/v1/authorized-activity/{authorization_id}/revoke"
    assert audit_client.post(url, json={"reason": "x"}).status_code in (401, 403)
    revoked = analyst.post(url, json={"reason": "The test is over."}, headers=_ORIGIN)
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked_by"] == "audit-analyst"


# ── The expiry record ──────────────────────────────────────────────────────


def _expired(label: str = "ended test") -> Any:
    async def seed(db: Any) -> int:
        now = utcnow()
        row = await aa.create(
            db,
            label=label,
            sources=[aa.ScopeEntry(SOURCE_A, "agent:a-1")],
            target=aa.ScopeEntry(TARGET, None),
            rule_names=[RULE_NESTED],
            rule_class="exploit_attempt",
            expires_at=now - timedelta(minutes=5),
            created_by="casey",
            now=now - timedelta(days=2),
        )
        return int(row.id)

    return seed


def test_the_expiry_loop_writes_one_record_for_each_expired_row(client: TestClient) -> None:
    ended = _do(client, _expired())

    async def live(db: Any) -> None:
        now = utcnow()
        await aa.create(
            db,
            label="live test",
            sources=[aa.ScopeEntry(SOURCE_A, "agent:a-1")],
            target=aa.ScopeEntry(TARGET, None),
            rule_names=[RULE_NESTED],
            rule_class="exploit_attempt",
            expires_at=now + timedelta(days=2),
            created_by="casey",
            now=now,
        )

    _do(client, live)

    assert asyncio.run(aam.record_expiries(client.app.state)) == 1
    assert asyncio.run(aam.record_expiries(client.app.state)) == 0, "one record for each row"

    records = [r for r in client.app.state.audit.records if r[0] == "authorized_activity_expired"]
    assert len(records) == 1
    assert records[0][1]["authorization_id"] == ended
    assert records[0][1]["label"] == "ended test"
    assert records[0][1]["runs"] == 0


def test_a_failed_audit_write_leaves_the_expiry_for_the_next_wake(client: TestClient) -> None:
    _do(client, _expired())
    good = client.app.state.audit

    class _Down:
        async def log_kind(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("the audit index did not answer")

    client.app.state.audit = _Down()
    assert asyncio.run(aam.record_expiries(client.app.state)) == 0
    client.app.state.audit = good
    assert asyncio.run(aam.record_expiries(client.app.state)) == 1
