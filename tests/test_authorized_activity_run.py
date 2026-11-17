"""The authorized activity decision on the run path.

``recorded_run`` hands the finished report to the decision, after the last
gate. A run inside a scope keeps its true positive verdict, its confidence
and every sentence of the model. It gains one key and the link to the
authorization. Each negative control is a run that must get normal handling.
"""

from __future__ import annotations

import copy
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, get_args

import pytest
from soc_ai.agent import authorized_activity as aam
from soc_ai.agent.orchestrator import StepEvent
from soc_ai.api.runner import recorded_run
from soc_ai.audit.schemas import AuditKind
from soc_ai.config import Settings
from soc_ai.store import authorized_activity as aa
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import HostDossier, HostMachine, Investigation

pytestmark = pytest.mark.asyncio

TARGET = "10.40.0.164"
SOURCE_A = "10.50.0.26"
STRANGER = "10.50.0.200"
SOURCE_A_SECOND = "10.50.0.27"
THIRD_HOST = "203.0.113.9"
RULE = "ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)"

TP_REPORT: dict[str, Any] = {
    "verdict": "true_positive",
    "confidence": 0.85,
    "summary": (
        "The source sent php2shell exploit requests. No case or authorization record exists."
    ),
    "citations": ["alert-1"],
    "recommended_actions": [
        {
            "tool_name": "escalate_to_case",
            "tool_args": {"case_title": "php2shell", "case_description": "Exploit requests."},
            "rationale": "Open a case for the exploit requests.",
        }
    ],
    "validator_note": None,
}


class _Audit:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []

    async def log_kind(self, session_id: str, kind: str, payload: dict[str, Any], **_: Any) -> None:
        self.records.append((session_id, kind, payload))


async def _state(settings: Settings) -> SimpleNamespace:
    engine = make_engine(settings)
    await run_migrations(engine)
    return SimpleNamespace(
        db_sessionmaker=make_sessionmaker(engine), audit=_Audit(), settings=settings
    )


async def _seed(state: SimpleNamespace, **overrides: Any) -> int:
    """The Hosts rows of the pair and one authorization for it."""
    now = utcnow()
    async with state.db_sessionmaker() as db:
        agent = HostMachine(machine_key="agent:a-1", name="agent-a", address_count=1)
        other = HostMachine(machine_key="agent:z-9", name="agent-z", address_count=1)
        target = HostMachine(machine_key=f"ip:{TARGET}", address_count=1)
        db.add_all([agent, other, target])
        await db.flush()
        db.add_all(
            [
                HostDossier(
                    host_key=SOURCE_A, ip=SOURCE_A, machine_id=agent.id, address_kind="agent"
                ),
                HostDossier(
                    host_key=SOURCE_A_SECOND,
                    ip=SOURCE_A_SECOND,
                    machine_id=agent.id,
                    address_kind="agent",
                ),
                HostDossier(
                    host_key=STRANGER, ip=STRANGER, machine_id=other.id, address_kind="agent"
                ),
                HostDossier(
                    host_key=TARGET, ip=TARGET, machine_id=target.id, address_kind="network"
                ),
            ]
        )
        await db.commit()
        fields: dict[str, Any] = {
            "label": "php2shell test",
            "sources": [aa.ScopeEntry(SOURCE_A, "agent:a-1", "agent-a")],
            "target": aa.ScopeEntry(TARGET, f"ip:{TARGET}"),
            "rule_names": [RULE],
            "rule_class": "exploit_attempt",
            "starts_at": now - timedelta(hours=1),
            "expires_at": now + timedelta(days=7),
            "created_by": "casey",
            "now": now,
        }
        fields.update(overrides)
        row = await aa.create(db, **fields)
        return int(row.id)


def _alert(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": "alert-1",
        "timestamp": datetime.now(UTC).isoformat(),
        "rule_name": RULE,
        "source_ip": SOURCE_A,
        "destination_ip": TARGET,
        "classtype": "web-application-attack",
        "event_dataset": "suricata.alert",
        "event_module": "suricata",
    }
    fields.update(overrides)
    return fields


async def _stream(
    alert: dict[str, Any],
    report: dict[str, Any],
    *,
    session_events: list[dict[str, Any]] | None = None,
    tool_hits: list[dict[str, Any]] | None = None,
) -> AsyncIterator[StepEvent]:
    """One run: the alert context, an optional tool result, the report.

    ``session_events`` are documents the prefetch recorded. ``tool_hits`` are
    documents a tool returned.
    """
    sid = "run-sid"
    yield StepEvent(kind="session_start", session_id=sid, sequence=1, payload={})
    yield StepEvent(
        kind="enriched_alert_context",
        session_id=sid,
        sequence=2,
        payload={"alert": alert, "community_id_events": session_events or []},
    )
    if tool_hits is not None:
        yield StepEvent(
            kind="tool_result",
            session_id=sid,
            sequence=3,
            payload={"tool_name": "t_query_zeek_logs", "result": {"hits": tool_hits}},
        )
    yield StepEvent(kind="triage_report", session_id=sid, sequence=4, payload=report)
    yield StepEvent(kind="done", session_id=sid, sequence=5, payload={"recommended_count": 1})


async def _run(
    state: SimpleNamespace,
    *,
    alert: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
    started_by: str = "auto-triage",
    session_events: list[dict[str, Any]] | None = None,
    tool_hits: list[dict[str, Any]] | None = None,
    **kwargs: Any,
) -> tuple[Investigation, dict[str, Any]]:
    """Drive one recorded run. Returns the stored row and the report frame."""
    frames: dict[str, Any] = {}
    inv_id = ""
    async for name, data in recorded_run(
        state,
        alert_id="alert-1",
        started_by=started_by,
        event_stream=_stream(
            alert or _alert(),
            report if report is not None else TP_REPORT,
            session_events=session_events,
            tool_hits=tool_hits,
        ),
        **kwargs,
    ):
        if name == "investigation_created":
            inv_id = data["investigation_id"]
        frames[name] = data
    async with state.db_sessionmaker() as db:
        row = await db.get(Investigation, inv_id)
    assert row is not None
    return row, frames["triage_report"]["payload"]


async def test_a_run_inside_the_scope_keeps_its_verdict_and_carries_the_mark(
    settings_kratos: Settings,
) -> None:
    state = await _state(settings_kratos)
    authorization_id = await _seed(state)
    before = copy.deepcopy(TP_REPORT)

    row, frame = await _run(state)

    assert before == TP_REPORT, "the caller's report is not changed in place"
    mark = frame["authorized_activity"]
    assert (mark["state"], mark["id"], mark["label"]) == (
        "matched",
        authorization_id,
        "php2shell test",
    )
    assert mark["by"] == "casey"
    assert row.authorization_id == authorization_id
    # The verdict, the confidence and the text of the model stay.
    assert (row.verdict, row.confidence, row.status) == ("true_positive", 0.85, "complete")
    assert row.summary == TP_REPORT["summary"]
    assert row.report is not None
    for key, value in TP_REPORT.items():
        assert row.report[key] == value, key
    assert row.report["authorized_activity"]["state"] == "matched"
    kinds = [(kind, payload["investigation_id"]) for _sid, kind, payload in state.audit.records]
    assert kinds == [("authorized_activity_matched", row.id)]
    assert state.audit.records[0][0] == "run-sid", "the record sits on the trail of the run"


async def test_a_new_source_gets_normal_handling_and_the_outside_line(
    settings_kratos: Settings,
) -> None:
    state = await _state(settings_kratos)
    await _seed(state)

    row, frame = await _run(state, alert=_alert(source_ip=STRANGER))

    assert row.authorization_id is None
    assert row.verdict == "true_positive"
    mark = frame["authorized_activity"]
    assert mark["state"] == "outside"
    assert mark["line"] == (
        "This activity is outside the authorized scope of php2shell test: the source is new."
    )
    assert [kind for _sid, kind, _payload in state.audit.records] == ["authorized_activity_outside"]


@pytest.mark.parametrize(
    ("label", "alert", "report", "run_kwargs"),
    [
        ("a backtest replay", {}, None, {"started_by": "backtest"}),
        ("a synthetic run", {}, None, {"is_synth_eval": True}),
        ("a needs more info verdict", {}, {**TP_REPORT, "verdict": "needs_more_info"}, {}),
        ("a false positive", {}, {**TP_REPORT, "verdict": "false_positive"}, {}),
        ("a promoted lead", {}, None, {"kind": "lead"}),
        (
            "a run between other machines",
            {"source_ip": STRANGER, "destination_ip": "10.40.0.9"},
            None,
            {},
        ),
    ],
)
async def test_a_run_the_decision_does_not_judge_has_no_key(
    settings_kratos: Settings,
    label: str,
    alert: dict[str, Any],
    report: dict[str, Any] | None,
    run_kwargs: dict[str, Any],
) -> None:
    state = await _state(settings_kratos)
    await _seed(state)

    row, frame = await _run(state, alert=_alert(**alert), report=report, **run_kwargs)

    assert "authorized_activity" not in frame, label
    assert row.authorization_id is None, label
    assert state.audit.records == [], label


async def test_a_revoked_authorization_marks_no_run(settings_kratos: Settings) -> None:
    state = await _state(settings_kratos)
    authorization_id = await _seed(state)
    async with state.db_sessionmaker() as db:
        await aa.revoke(db, authorization_id, by="casey", reason="wrong target")

    row, frame = await _run(state)

    assert "authorized_activity" not in frame
    assert row.authorization_id is None


async def test_an_alert_after_the_expiry_is_outside(settings_kratos: Settings) -> None:
    state = await _state(settings_kratos)
    now = utcnow()
    await _seed(
        state,
        now=now - timedelta(days=3),
        starts_at=now - timedelta(days=3),
        expires_at=now - timedelta(hours=2),
    )

    row, frame = await _run(state)

    assert row.authorization_id is None
    assert frame["authorized_activity"]["line"].endswith(
        "the alert time is outside the authorized time."
    )


async def test_a_late_triage_of_an_alert_from_inside_the_window_matches(
    settings_kratos: Settings,
) -> None:
    """The alert time decides. The time of the triage does not."""
    state = await _state(settings_kratos)
    now = utcnow()
    authorization_id = await _seed(
        state,
        now=now - timedelta(days=3),
        starts_at=now - timedelta(days=3),
        expires_at=now - timedelta(hours=2),
    )
    inside = (now - timedelta(hours=5)).replace(tzinfo=UTC).isoformat()

    row, _frame = await _run(state, alert=_alert(timestamp=inside))

    assert row.authorization_id == authorization_id


async def test_a_failed_store_read_gives_normal_handling(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = await _state(settings_kratos)
    await _seed(state)

    async def _down(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("the store did not answer")

    monkeypatch.setattr(aa, "in_force", _down)

    row, frame = await _run(state)

    assert "authorized_activity" not in frame
    assert (row.verdict, row.authorization_id) == ("true_positive", None)


async def test_no_authorization_returns_the_report_itself(settings_kratos: Settings) -> None:
    state = await _state(settings_kratos)
    report = copy.deepcopy(TP_REPORT)
    marked = await aam.mark_report(
        state,
        report,
        enriched_payload={"alert": _alert()},
        started_by="auto-triage",
        kind="suricata",
        synthetic=False,
    )
    assert marked is report


async def test_each_audit_type_is_declared() -> None:
    """An undeclared type raises inside the audit writer, and the record is lost."""
    declared = set(get_args(AuditKind))
    for kind in ("matched", "outside"):
        assert f"authorized_activity_{kind}" in declared


# ── The addresses of the record ────────────────────────────────────────────


async def test_a_second_address_of_the_source_machine_is_outside(
    settings_kratos: Settings,
) -> None:
    """The agent reports both addresses. The record stored one of them."""
    state = await _state(settings_kratos)
    await _seed(state)

    row, frame = await _run(state, alert=_alert(source_ip=SOURCE_A_SECOND))

    assert row.authorization_id is None
    assert frame["authorized_activity"]["line"].endswith("the source is new.")


async def test_an_address_that_joined_the_source_machine_by_a_dns_name_is_outside(
    settings_kratos: Settings,
) -> None:
    """Review scenario m2. A name is not proof of the machine."""
    from sqlalchemy import select

    state = await _state(settings_kratos)
    await _seed(state)
    attacker = "10.50.0.77"
    async with state.db_sessionmaker() as db:
        agent = (
            await db.scalars(select(HostMachine).where(HostMachine.machine_key == "agent:a-1"))
        ).one()
        db.add(
            HostDossier(host_key=attacker, ip=attacker, machine_id=agent.id, address_kind="name")
        )
        await db.commit()

    row, frame = await _run(state, alert=_alert(id="alert-n", source_ip=attacker))

    assert row.authorization_id is None
    assert frame["authorized_activity"]["state"] == "outside"


async def test_a_stored_source_address_on_another_machine_today_is_outside(
    settings_kratos: Settings,
) -> None:
    """The address is on the list. The Hosts data of today maps it to another agent."""
    from sqlalchemy import select

    state = await _state(settings_kratos)
    await _seed(state)
    async with state.db_sessionmaker() as db:
        other = (
            await db.scalars(select(HostMachine).where(HostMachine.machine_key == "agent:z-9"))
        ).one()
        dossier = (
            await db.scalars(select(HostDossier).where(HostDossier.host_key == SOURCE_A))
        ).one()
        dossier.machine_id = other.id
        await db.commit()

    row, frame = await _run(state)

    assert row.authorization_id is None
    assert frame["authorized_activity"]["line"].endswith("the source is new.")


# ── The cited evidence ─────────────────────────────────────────────────────

SESSION_A = "1:session-a"
DOC_EXPLOIT = "zeek-http-doc-0001"
DOC_BEACON = "zeek-conn-doc-0201"


def _zeek(doc_id: str, session: str, **overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": doc_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "rule_name": None,
        "source_ip": SOURCE_A,
        "destination_ip": TARGET,
        "event_dataset": "zeek.http",
        "event_module": "zeek",
        "network_community_id": session,
    }
    fields.update(overrides)
    return fields


async def test_a_report_that_cites_only_documents_of_the_pair_is_matched(
    settings_kratos: Settings,
) -> None:
    state = await _state(settings_kratos)
    authorization_id = await _seed(state)
    report = {**TP_REPORT, "citations": ["alert-1", DOC_EXPLOIT, "zeek-conn-doc-0002"]}

    row, frame = await _run(
        state,
        report=report,
        session_events=[_zeek(DOC_EXPLOIT, SESSION_A)],
        tool_hits=[
            _zeek("zeek-conn-doc-0002", SESSION_A, source_ip=TARGET, destination_ip=SOURCE_A)
        ],
    )

    assert frame["authorized_activity"]["state"] == "matched"
    assert row.authorization_id == authorization_id


@pytest.mark.parametrize(
    ("cited", "why"),
    [
        (["alert-1", DOC_BEACON], "a beacon from the target to a third host"),
        (["alert-1", "zeek-http-doc-9999"], "a document the run did not record"),
        (["alert-1", "t_host_summary:10.40.0.164"], "a tool call"),
    ],
)
async def test_a_report_that_cites_activity_beyond_the_scope_gets_normal_handling(
    settings_kratos: Settings, cited: list[str], why: str
) -> None:
    """Review defect 7. The alert is inside the scope, and the report is about more."""
    state = await _state(settings_kratos)
    await _seed(state)
    beacon = _zeek(DOC_BEACON, "1:session-c2", source_ip=TARGET, destination_ip=THIRD_HOST)

    row, frame = await _run(
        state,
        report={**TP_REPORT, "citations": cited},
        session_events=[_zeek(DOC_EXPLOIT, SESSION_A)],
        tool_hits=[beacon],
    )

    assert row.authorization_id is None, why
    assert frame["authorized_activity"]["line"] == (
        "This activity is outside the authorized scope of php2shell test: "
        "the report cites activity beyond the scope."
    )


# The citation shapes of the nine true positive runs of the 2026-11 campaign.
PRODUCTION_CITATIONS = [
    "alert.payload_printable",
    "alert.rule_name",
    "alert.id",
    "alert.network_community_id",
    "community_id_events.0.zeek_http_status",
    "tool t_origin_chain",
    "tool t_query_events_oql",
    "host_alert_profile",
    "host_alert_profiles.0.alert_count",
    f"host_alert_profile.{RULE}",
    "alert-1",
    "01M6Y98DBWJ8JHFJJ4KSTC15EP",
]


async def test_a_run_with_the_production_citation_shapes_is_matched(
    settings_kratos: Settings,
) -> None:
    state = await _state(settings_kratos)
    authorization_id = await _seed(state)
    report = {
        **TP_REPORT,
        "summary": f"agent-a at {SOURCE_A} sent php2shell exploit requests to {TARGET}.",
        "citations": PRODUCTION_CITATIONS,
    }

    row, frame = await _run(state, report=report, session_events=[_zeek(DOC_EXPLOIT, SESSION_A)])

    assert frame["authorized_activity"]["state"] == "matched"
    assert row.authorization_id == authorization_id


@pytest.mark.parametrize(
    ("summary", "named"),
    [
        (f"The target {TARGET} then connected to {THIRD_HOST}.", THIRD_HOST),
        ("The target then reached Agent-Z over SMB.", "Agent-Z"),
    ],
)
async def test_a_report_that_names_a_host_beyond_the_scope_gets_normal_handling(
    settings_kratos: Settings, summary: str, named: str
) -> None:
    state = await _state(settings_kratos)
    await _seed(state)
    report = {**TP_REPORT, "summary": summary, "citations": PRODUCTION_CITATIONS}

    row, frame = await _run(state, report=report)

    assert row.authorization_id is None
    assert frame["authorized_activity"]["parts"] == ["cited_evidence"]
    assert frame["authorized_activity"]["line"] == (
        "This activity is outside the authorized scope of php2shell test: "
        f"the report names {named}, which is beyond the scope."
    )


async def test_a_failed_read_of_the_machine_names_puts_the_run_outside(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = await _state(settings_kratos)
    await _seed(state)

    async def _down(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("the store did not answer")

    monkeypatch.setattr(aa, "machine_names", _down)

    row, frame = await _run(state)

    assert row.authorization_id is None
    assert frame["authorized_activity"]["parts"] == ["cited_evidence"]


# ── A hunt finding ─────────────────────────────────────────────────────────
#
# soc-ai always judges a finding on its own. A finding run never carries the
# mark: its case request, its notification and its lead stay. When the run is
# on machines of a record in force, one line names the record.


async def _finding_run(
    state: SimpleNamespace, documents: list[dict[str, Any]], *, judges: str | None = "finding"
) -> tuple[Investigation, dict[str, Any]]:
    """Drive the run of one promoted finding. The run records the documents of its hunt."""
    subject: dict[str, Any] = {"type": "hunt", "hunt_id": "hunt-1"}
    if judges:
        subject["judges"] = judges

    async def _events() -> AsyncIterator[StepEvent]:
        sid = "finding-sid"
        yield StepEvent(
            kind="enriched_alert_context",
            session_id=sid,
            sequence=1,
            payload={"alert": documents[0], "subject_documents": documents, "subject": "hunt"},
        )
        yield StepEvent(kind="triage_report", session_id=sid, sequence=2, payload=TP_REPORT)
        yield StepEvent(kind="done", session_id=sid, sequence=3, payload={})

    frames: dict[str, Any] = {}
    inv_id = ""
    async for name, data in recorded_run(
        state,
        alert_id=documents[0]["id"],
        started_by="auto-hunt",
        event_stream=_events(),
        kind="hunt" if judges else "lead",
        hunt_id="hunt-1",
        finding_ordinal=0 if judges else None,
        subject=subject,
    ):
        if name == "investigation_created":
            inv_id = data["investigation_id"]
        frames[name] = data
    async with state.db_sessionmaker() as db:
        row = await db.get(Investigation, inv_id)
    assert row is not None
    return row, frames["triage_report"]["payload"]


FINDING_LINE = (
    "This activity is outside the authorized scope of php2shell test: "
    "a finding is always judged on its own."
)


@pytest.mark.parametrize(
    ("scenario", "documents"),
    [
        (
            "f1: webshell commands on the session of the exploit request",
            [_zeek("zeek-http-doc-0101", SESSION_A), _zeek("zeek-http-doc-0102", SESSION_A)],
        ),
        (
            "f2: a cited alert of another rule on the same session",
            [
                _alert(
                    id="suricata-doc-0301",
                    rule_name="ET MALWARE Cobalt Strike Beacon Observed",
                    classtype="trojan-activity",
                    network_community_id=SESSION_A,
                )
            ],
        ),
        (
            "f3: the one recorded document of a finding that cites more",
            [_zeek(DOC_EXPLOIT, SESSION_A)],
        ),
        (
            "f4: a flow on a session id that an alert run proved days ago",
            [_zeek("zeek-http-doc-0401", "1:icmp-pair")],
        ),
        (
            "the exploit requests themselves",
            [_zeek(DOC_EXPLOIT, SESSION_A), _zeek("zeek-http-doc-0002", SESSION_A)],
        ),
    ],
)
async def test_a_finding_run_always_gets_normal_handling(
    settings_kratos: Settings, scenario: str, documents: list[dict[str, Any]]
) -> None:
    """Review defects 1 and 2. A matched alert run on the session proves nothing
    about a finding."""
    state = await _state(settings_kratos)
    authorization_id = await _seed(state)
    old = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
    alert_run, _ = await _run(state, alert=_alert(network_community_id=SESSION_A))
    await _run(state, alert=_alert(timestamp=old, network_community_id="1:icmp-pair"))
    assert alert_run.authorization_id == authorization_id
    state.audit.records.clear()

    row, frame = await _finding_run(state, documents)

    assert row.authorization_id is None, scenario
    assert frame["authorized_activity"]["state"] == "outside", scenario
    assert frame["authorized_activity"]["line"] == FINDING_LINE, scenario
    assert (row.verdict, row.kind) == ("true_positive", "hunt")
    assert [kind for _sid, kind, _payload in state.audit.records] == ["authorized_activity_outside"]


async def test_a_finding_run_on_other_machines_and_a_lead_run_have_no_line(
    settings_kratos: Settings,
) -> None:
    state = await _state(settings_kratos)
    await _seed(state)
    elsewhere = _zeek(
        "zeek-http-doc-0501", "1:other", source_ip=STRANGER, destination_ip="10.40.0.9"
    )

    row, frame = await _finding_run(state, [elsewhere])
    assert "authorized_activity" not in frame
    assert row.authorization_id is None

    row, frame = await _finding_run(state, [_zeek(DOC_EXPLOIT, SESSION_A)], judges=None)
    assert "authorized_activity" not in frame
    assert row.authorization_id is None
