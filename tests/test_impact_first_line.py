"""The impact of a verdict and the first line of a run (H2, 2026-11-13).

A true positive says that the detection is correct. On production three
identical unanswered SYN probes got TP 0.65, TP 0.75 and FP 0.72, 46% of the
summaries named a host by its bare address, and 10% stated the verdict first.

- The report states an impact: none, attempted, succeeded or unknown. Only a
  true positive states one.
- A guard, beside the evidence gates, keeps ``succeeded`` only when the
  report cites a fetched record with content of the event.
- The server builds the first line: the verdict, the impact and the two
  hosts as the Hosts data names them.
- The list and the page return ``impact`` and ``firstLine``. The list filters
  on the impact and orders by it inside the true positives.

The data is synthetic: placeholder addresses and host names.
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
from soc_ai.agent import prompts
from soc_ai.agent.gates import (
    IMPACT_GATE,
    _settle_impact,
    _synth_first_post_validate,
    impact_change_from_audit,
    impact_change_line,
)
from soc_ai.agent.triage import TriageReport
from soc_ai.api.webui.routes_hunts import promoted_finding_out
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.oracle.client import ORACLE_SYSTEM_PROMPT, OracleVerdict, _verdict_to_report
from soc_ai.so_client.models import SoAlert
from soc_ai.store import first_line
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import (
    HostDossier,
    HostDossierField,
    HostMachine,
    Investigation,
)
from soc_ai.tools.get_alert_context import EnrichedAlertContext
from soc_ai.triage_models import IMPACT_ORDER, settled_impact, stored_impact

from tests import test_hunt_subject as hs

SRC, DST = "10.40.50.7", "10.20.30.5"
STRANGER = "10.40.50.99"
FLOW_ID, HTTP_ID = "ev-flow-0001", "ev-http-0001"
STORY = "The source host sent one exploit request to the web server."

HTTP_RECORD = {
    "_id": HTTP_ID,
    "event": {"dataset": "zeek.http"},
    "source": {"ip": SRC},
    "destination": {"ip": DST},
    "http": {"method": "POST", "uri": "/upload.php", "response_body": "uid=33(www-data)"},
}
FLOW_RECORD = {
    "_id": FLOW_ID,
    "event": {"dataset": "zeek.conn"},
    "source": {"ip": SRC},
    "destination": {"ip": DST},
    "connection": {"state": "S0"},
}


def _enriched() -> EnrichedAlertContext:
    return EnrichedAlertContext(
        alert=SoAlert(
            id="alert-0001",
            rule_name="ET EXPLOIT Example Upload Request",
            event_dataset="suricata.alert",
            source_ip=SRC,
            destination_ip=DST,
        ),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


def _report(verdict: str = "true_positive", **over: Any) -> TriageReport:
    fields: dict[str, Any] = {
        "verdict": verdict,
        "confidence": 0.85,
        "summary": STORY,
        "citations": [FLOW_ID],
        "recommended_actions": [],
    }
    fields.update(over)
    return TriageReport(**fields)


def _fetched(*records: dict[str, Any]) -> list[Any]:
    """The message history of one successful tool call that returned *records*."""
    call = SimpleNamespace(
        tool_name="t_query_events_oql",
        args={"query": "x"},
        tool_call_id="tc1",
        part_kind="tool-call",
    )
    ret = SimpleNamespace(
        tool_name="t_query_events_oql",
        content={"total": len(records), "hits": list(records)},
        tool_call_id="tc1",
        part_kind="tool-return",
    )
    return [SimpleNamespace(parts=[call]), SimpleNamespace(parts=[ret])]


def _settle(report: TriageReport, **kw: Any) -> tuple[Any, dict[str, Any]]:
    audit: dict[str, Any] = {}
    return _settle_impact(report, _enriched(), audit, **kw), audit


# ── The schema ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("written", "read"),
    [
        ("succeeded", "succeeded"),
        ("Attempted", "attempted"),
        (" none. ", "none"),
        # The string "None" is the impact none on this field, never a null.
        ("None", "none"),
        ("unknown", "unknown"),
        (None, None),
        # A word the schema does not know costs no schema retry.
        ("low", None),
        ("n/a", None),
        (3, None),
    ],
)
def test_the_report_schema_folds_the_impact_to_one_of_four_values(written: Any, read: Any) -> None:
    assert _report(impact=written).impact == read


def test_a_report_with_no_impact_key_still_validates() -> None:
    report = TriageReport.model_validate(
        {"verdict": "false_positive", "confidence": 0.9, "summary": STORY}
    )
    assert report.impact is None


def test_only_a_true_positive_states_an_impact() -> None:
    assert settled_impact("true_positive", "succeeded") == "succeeded"
    assert settled_impact("true_positive", None) == "unknown"
    assert settled_impact("true_positive", "certain") == "unknown"
    for verdict in ("false_positive", "needs_more_info", "inconclusive", None):
        assert settled_impact(verdict, "succeeded") is None
    assert stored_impact({"impact": "attempted"}, "true_positive") == "attempted"
    assert stored_impact({}, "true_positive") is None
    assert stored_impact({"impact": "attempted"}, "false_positive") is None


# ── The guard ──────────────────────────────────────────────────────────────


def test_a_probe_with_no_response_evidence_cannot_stay_succeeded() -> None:
    """Negative control. The model says the action worked. The run fetched
    only the flow record of the probe, and the report cites it. A flow record
    holds no content of the event."""
    out, audit = _settle(_report(impact="succeeded"), messages=_fetched(FLOW_RECORD))
    assert out.impact == "attempted"
    assert out.verdict == "true_positive"
    assert out.confidence == 0.85
    assert out.summary == STORY
    assert audit[IMPACT_GATE]["original_impact"] == "succeeded"
    assert audit[IMPACT_GATE]["settled_impact"] == "attempted"

    change = impact_change_from_audit(audit)
    assert change is not None
    assert (change["gate"], change["from_impact"], change["to_impact"]) == (
        IMPACT_GATE,
        "succeeded",
        "attempted",
    )
    assert change["steps"] == [
        {
            "gate": IMPACT_GATE,
            "from_impact": "succeeded",
            "to_impact": "attempted",
            "reason": change["reason"],
        }
    ]
    assert change["missing"]
    assert impact_change_line(change).startswith(
        "soc-ai changed the impact from succeeded to attempted."
    )


@pytest.mark.parametrize(
    ("citations", "why"),
    [
        ([], "the report cites nothing"),
        (["alert.payload_printable"], "a field path is no record id"),
        ([f"the record {HTTP_ID} shows the answer"], "prose that holds an id"),
        (["ev-never-fetched"], "an id that no tool of the run fetched"),
    ],
)
def test_succeeded_needs_a_cited_record_id(citations: list[str], why: str) -> None:
    """Negative controls on the paths the guard would miss: the content
    record exists in the run, and the report does not cite it by id."""
    out, audit = _settle(
        _report(impact="succeeded", citations=citations),
        messages=_fetched(HTTP_RECORD, FLOW_RECORD),
    )
    assert out.impact == "attempted", why
    assert IMPACT_GATE in audit


def test_succeeded_stands_when_the_report_cites_a_fetched_content_record() -> None:
    report = _report(impact="succeeded", citations=[HTTP_ID])
    out, audit = _settle(report, messages=_fetched(HTTP_RECORD))
    assert out is report
    assert out.impact == "succeeded"
    assert audit == {}
    assert impact_change_from_audit(audit) is None


def test_a_content_record_of_two_other_hosts_does_not_back_succeeded() -> None:
    away = {**HTTP_RECORD, "source": {"ip": "10.77.0.1"}, "destination": {"ip": "10.77.0.2"}}
    out, audit = _settle(_report(impact="succeeded", citations=[HTTP_ID]), messages=_fetched(away))
    assert out.impact == "attempted"
    assert IMPACT_GATE in audit


def test_the_citations_that_the_oracle_named_count_for_its_report() -> None:
    out, audit = _settle(
        _report(impact="succeeded", citations=["alert.rule_name"]),
        messages=_fetched(HTTP_RECORD),
        extra_citations=[HTTP_ID],
    )
    assert out.impact == "succeeded"
    assert out.citations == ["alert.rule_name"]
    assert audit == {}


@pytest.mark.parametrize("impact", ["none", "attempted", "unknown"])
def test_the_other_values_stand_without_a_record(impact: str) -> None:
    report = _report(impact=impact)
    out, audit = _settle(report)
    assert out is report
    assert audit == {}


def test_a_true_positive_with_no_impact_from_the_model_reads_unknown() -> None:
    out, audit = _settle(_report())
    assert out.impact == "unknown"
    assert audit == {}


@pytest.mark.parametrize("verdict", ["false_positive", "needs_more_info", "inconclusive"])
def test_a_verdict_that_is_no_true_positive_carries_no_impact(verdict: str) -> None:
    """Negative control: the model wrote an impact beside a false positive."""
    out, audit = _settle(_report(verdict, impact="succeeded"), messages=_fetched(HTTP_RECORD))
    assert out.impact is None
    assert audit == {}


def test_the_guard_runs_with_the_evidence_gates() -> None:
    """The post-validation step settles the impact of the verdict that stands."""
    report, audit = _synth_first_post_validate(
        _report(impact="succeeded"),
        _enriched(),
        None,
        targeted_messages=_fetched(FLOW_RECORD),
    )
    assert report.verdict == "true_positive", audit
    assert report.impact == "attempted"
    assert IMPACT_GATE in audit

    # A gate lowers the verdict: the report then states no impact.
    lowered, audit = _synth_first_post_validate(
        _report(impact="succeeded", citations=[]), _enriched(), None
    )
    assert lowered.verdict == "needs_more_info", audit
    assert lowered.impact is None
    assert IMPACT_GATE not in audit


# ── The prompt and the Oracle answer ───────────────────────────────────────


def test_every_report_prompt_defines_the_impact() -> None:
    for text in (
        prompts.SYNTHESIZER_PROMPT,
        prompts.SYNTH_FIRST_SYSTEM_PROMPT,
        prompts.build_investigator_prompt(emits_report=True),
        prompts.build_investigator_prompt(
            emits_report=True, planes=frozenset({"network"}), visible_tools=frozenset()
        ),
    ):
        assert text.count(prompts.IMPACT_RULE) == 1
    for value in IMPACT_ORDER:
        assert f"`{value}`:" in prompts.IMPACT_RULE
    assert "Example 1" in prompts.IMPACT_RULE
    assert "Example 2" in prompts.IMPACT_RULE
    assert "`impact`" in prompts.BUDGET_PARTIAL_SYNTH_PROMPT
    assert '"impact"' in ORACLE_SYSTEM_PROMPT


def test_the_oracle_report_carries_the_impact() -> None:
    local = _report("needs_more_info", confidence=0.4)
    answer = OracleVerdict(
        verdict="true_positive",
        confidence=0.8,
        summary="The probe got no answer.",
        reasoning="One SYN and no reply.",
        impact="None",
    )
    assert answer.impact == "none"
    assert _verdict_to_report(answer, local_report=local, backed=True).impact == "none"

    # An answer of an older prompt has no impact: a true positive reads unknown.
    old = OracleVerdict(
        verdict="true_positive", confidence=0.8, summary="The probe got no answer.", reasoning="x"
    )
    assert _verdict_to_report(old, local_report=local, backed=True).impact == "unknown"
    benign = OracleVerdict(
        verdict="false_positive", confidence=0.8, summary="Benign.", reasoning="x", impact="none"
    )
    assert _verdict_to_report(benign, local_report=local, backed=True).impact is None


# ── The first line ─────────────────────────────────────────────────────────

SERVER = first_line.HostLabel(address=DST, name="mainsrv", role="server", machine_key="ip:m1")
DEVBOX = first_line.HostLabel(address=SRC, name="devbox", role=None, machine_key="agent:d1")
LABELS = {DST: SERVER, SRC: DEVBOX}


def test_the_first_line_states_the_verdict_the_impact_and_the_named_hosts() -> None:
    line = first_line.build("true_positive", "attempted", SRC, DST, LABELS)
    assert line == f"True positive. Impact: attempted. devbox {SRC} to mainsrv (server) {DST}."
    assert first_line.headline(line) == (
        f"Impact: attempted. devbox {SRC} to mainsrv (server) {DST}."
    )


@pytest.mark.parametrize(
    ("verdict", "words"),
    [
        ("false_positive", "False positive"),
        ("needs_more_info", "Needs more info"),
        ("inconclusive", "Inconclusive"),
    ],
)
def test_a_verdict_that_is_no_true_positive_leaves_the_impact_out(verdict: str, words: str) -> None:
    line = first_line.build(verdict, "succeeded", SRC, DST, LABELS)
    assert line == f"{words}. devbox {SRC} to mainsrv (server) {DST}."
    assert "Impact" not in line


def test_an_unknown_address_prints_with_no_name_and_no_empty_brackets() -> None:
    """Negative control: the Hosts data holds one end only."""
    line = first_line.build("true_positive", "none", STRANGER, DST, LABELS)
    assert line == f"True positive. Impact: none. {STRANGER} to mainsrv (server) {DST}."
    bare = first_line.build("true_positive", "none", STRANGER, "10.40.50.98", {})
    assert bare == f"True positive. Impact: none. {STRANGER} to 10.40.50.98."
    for text in (line, bare):
        assert "()" not in text
        assert "( )" not in text
        assert "None" not in text
        assert "  " not in text
    assert first_line.end_text(STRANGER, first_line.HostLabel(address=STRANGER)) == STRANGER


def test_each_end_prints_what_the_hosts_data_has() -> None:
    role_only = first_line.HostLabel(address=DST, role="domain controller")
    assert first_line.end_text(DST, role_only) == f"{DST} (domain controller)"
    assert first_line.end_text(DST, SERVER) == f"mainsrv (server) {DST}"
    assert first_line.end_text(SRC, DEVBOX) == f"devbox {SRC}"
    # A host name with no address in the Hosts data.
    assert first_line.end_text("mainsrv", None) == "mainsrv"
    assert first_line.end_text("mainsrv", SERVER) == f"mainsrv (server) {DST}"
    assert first_line.end_text(None, None) == ""


def test_a_run_with_one_end_or_no_end_still_has_a_line() -> None:
    assert first_line.build("true_positive", "unknown", None, DST, LABELS) == (
        f"True positive. Impact: unknown. mainsrv (server) {DST}."
    )
    assert first_line.build("false_positive", None, None, None) == "False positive."
    assert first_line.build(None, None, SRC, DST) is None
    # A host log names its own address as the source: one machine, one end.
    same = {SRC: first_line.HostLabel(address=SRC, name="mainsrv", machine_key="ip:m1")}
    same["mainsrv"] = SERVER
    assert first_line.build("true_positive", "attempted", SRC, "mainsrv", same) == (
        f"True positive. Impact: attempted. mainsrv (server) {DST}."
    )


def test_an_impact_that_is_none_of_the_four_reads_not_stated() -> None:
    assert first_line.build("true_positive", None, SRC, DST) == (
        f"True positive. Impact: not stated. {SRC} to {DST}."
    )


def test_a_finding_run_takes_its_direction_from_the_finding() -> None:
    """The anchor of a finding can be the response of the victim. The rule is
    the one of the run page, and the two must agree."""
    cases = [
        (DST, SRC, [DST]),  # the anchor is the response: the victim is its source
        (SRC, DST, [DST]),
        (SRC, DST, [SRC, DST]),
        (SRC, DST, ["10.77.0.9"]),
        (SRC, DST, []),
        (None, None, [DST]),
    ]
    for src, dst, hosts in cases:
        inv = SimpleNamespace(finding_ordinal=0, src_ip=src, dest_ip=dst)
        hunt = SimpleNamespace(
            id="01HUNT0000000000000000000",
            objective="find web attacks",
            report={"findings": [{"title": "Requests", "hosts": hosts}]},
        )
        page = promoted_finding_out(inv, hunt)  # type: ignore[arg-type]
        assert page is not None
        attacker, victim = first_line.finding_ends(src, dst, hosts)
        if hosts:
            assert (attacker, victim) == (page["attacker"], page["victim"]), (src, dst, hosts)
        else:
            assert (attacker, victim) == (src, dst)
    assert first_line.finding_ends(DST, SRC, [DST]) == (SRC, DST)


def test_an_alert_with_no_destination_has_its_machine_as_the_target() -> None:
    assert first_line.alert_ends(SRC, DST, "mainsrv") == (SRC, DST)
    assert first_line.alert_ends(SRC, None, "mainsrv") == (SRC, "mainsrv")
    assert first_line.alert_ends(None, None, None) == (None, None)


def _row(**over: Any) -> SimpleNamespace:
    fields: dict[str, Any] = {
        "verdict": "true_positive",
        "report": {},
        "src_ip": SRC,
        "dest_ip": DST,
        "host_name": None,
    }
    fields.update(over)
    return SimpleNamespace(**fields)


def test_an_old_row_gets_its_line_at_read_time_with_the_impact_not_stated() -> None:
    row = _row(report={"verdict": "true_positive", "summary": STORY})
    assert first_line.of_run(row, LABELS) == (
        f"True positive. Impact: not stated. devbox {SRC} to mainsrv (server) {DST}."
    )
    assert first_line.of_run(_row(verdict="false_positive"), {}) == (
        f"False positive. {SRC} to {DST}."
    )


def test_the_stored_line_stands_while_its_verdict_stands() -> None:
    stored = "True positive. Impact: attempted. oldname 10.40.50.7 to mainsrv 10.20.30.5."
    report = {"first_line": stored, "impact": "attempted"}
    assert first_line.of_run(_row(report=report), LABELS) == stored
    # An analyst set the verdict to a false positive after the run.
    changed = _row(
        verdict="false_positive", report={**report, "resolution": {"resolved_via": "manual"}}
    )
    assert first_line.of_run(changed, LABELS) == (
        f"False positive. devbox {SRC} to mainsrv (server) {DST}."
    )


def test_a_pipeline_error_and_a_run_with_no_verdict_have_no_line() -> None:
    fallback = {"resolution": {"provenance": "pipeline_fallback"}}
    assert first_line.of_run(_row(verdict="needs_more_info", report=fallback), {}) is None
    assert first_line.of_run(_row(verdict=None), {}) is None


def test_the_stored_ends_decide_the_target_of_a_run() -> None:
    row = _row(report={"ends": {"source": DST, "target": SRC}})
    assert first_line.run_ends(row) == (DST, SRC)
    assert first_line.run_target(row) == SRC
    assert first_line.run_target(_row(dest_ip=None, host_name="mainsrv")) == "mainsrv"
    assert first_line.run_target(_row(dest_ip=None)) == SRC


def test_a_stored_time_reads_as_naive_utc() -> None:
    aware = first_line.parse_time("2026-11-10T12:00:00+02:00")
    assert aware == datetime(2026, 11, 10, 10, 0, 0)
    assert first_line.parse_time("2026-11-10T10:00:00Z") == datetime(2026, 11, 10, 10, 0, 0)
    assert first_line.parse_time("2026-11-10T10:00:00") == datetime(2026, 11, 10, 10, 0, 0)
    assert first_line.parse_time("not a time") is None
    assert first_line.parse_time(None) is None


# ── The Hosts data ─────────────────────────────────────────────────────────


async def _seed_hosts(db: Any) -> None:
    """Three machines: a named server with a declared role, a named agent
    machine with a stale role guess, and a container on the server."""
    server = HostMachine(
        machine_key="ip:m1",
        name="mainsrv",
        names_json=[{"value": "mainsrv", "source": "dns"}],
        primary_ip=DST,
        address_count=1,
    )
    devbox = HostMachine(
        machine_key="agent:d1", agent_name="devbox", primary_ip=SRC, address_count=1
    )
    db.add_all([server, devbox])
    await db.flush()
    server_row = HostDossier(host_key=DST, ip=DST, machine_id=server.id, address_kind="network")
    devbox_row = HostDossier(host_key=SRC, ip=SRC, machine_id=devbox.id, address_kind="agent")
    container = HostDossier(
        host_key="10.89.0.5", ip="10.89.0.5", machine_id=server.id, address_kind="container"
    )
    db.add_all([server_row, devbox_row, container])
    await db.flush()
    stale = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=30)
    db.add_all(
        [
            HostDossierField(dossier_id=server_row.id, field="role", operator_value="server"),
            HostDossierField(
                dossier_id=devbox_row.id,
                field="role",
                inferred_value="workstation",
                inferred_confidence=0.9,
                inferred_last_run_at=stale,
            ),
        ]
    )
    await db.commit()


async def test_the_labels_come_from_the_hosts_data_in_one_call(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    try:
        async with maker() as db:
            await _seed_hosts(db)
            labels = await first_line.labels_for(
                db, [SRC, DST, STRANGER, "10.89.0.5", "mainsrv", "nobody", None, ""]
            )
    finally:
        await engine.dispose()
    assert labels[DST] == first_line.HostLabel(
        address=DST, name="mainsrv", role="server", machine_key="ip:m1"
    )
    # A stale role guess is no role: the resolver withholds it.
    assert labels[SRC] == first_line.HostLabel(
        address=SRC, name="devbox", role=None, machine_key="agent:d1"
    )
    # A host name resolves to its machine and brings the primary address.
    assert labels["mainsrv"].machine_key == "ip:m1"
    assert labels["mainsrv"].address == DST
    # An unknown address, an unknown name and a container address have no label.
    assert set(labels) == {SRC, DST, "mainsrv"}


# ── The pipeline ───────────────────────────────────────────────────────────


_make_investigator = hs._fake_investigator


def _loop_with(found: dict[str, Any]) -> Any:
    agent = _make_investigator()
    message = agent.run.return_value.all_messages.return_value[0]
    message.parts[1].content = {"hits": [found]}
    return agent


def _pipeline_enriched(alert_id: str = hs.ANCHOR_ID) -> EnrichedAlertContext:
    enriched = _enriched()
    enriched.alert = enriched.alert.model_copy(
        update={"id": alert_id, "timestamp": datetime(2026, 11, 10, 9, 30, tzinfo=UTC)}
    )
    return enriched


async def _pipeline(
    settings: Settings, report: TriageReport, record: dict[str, Any], maker: Any = None
) -> list[Any]:
    with (
        patch.object(hs, "_enriched", _pipeline_enriched),
        patch.object(hs, "_fake_investigator", lambda: _loop_with(record)),
    ):
        events, _spies = await hs._run(settings, subject=None, report=report, db_sessionmaker=maker)
    return events


async def test_the_pipeline_lowers_an_unbacked_succeeded_and_records_the_step(
    settings_kratos: Settings,
) -> None:
    events = await _pipeline(settings_kratos, _report(impact="succeeded"), FLOW_RECORD)
    final = hs._payload(events, "triage_report")
    assert final["verdict"] == "true_positive", final.get("summary")
    assert final["impact"] == "attempted"
    assert final["impact_change"]["from_impact"] == "succeeded"
    assert final["impact_change"]["to_impact"] == "attempted"
    step = hs._payload(events, IMPACT_GATE)
    assert step["original_impact"] == "succeeded"
    # No store on the context: each end prints as its address.
    assert final["first_line"] == f"True positive. Impact: attempted. {SRC} to {DST}."
    assert final["ends"] == {"source": SRC, "target": DST}
    assert final["event_time"] == "2026-11-10T09:30:00+00:00"
    assert final["summary"] == STORY


async def test_the_pipeline_keeps_a_backed_succeeded_and_names_the_hosts(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    try:
        async with maker() as db:
            await _seed_hosts(db)
        events = await _pipeline(
            settings_kratos, _report(impact="succeeded", citations=[HTTP_ID]), HTTP_RECORD, maker
        )
    finally:
        await engine.dispose()
    final = hs._payload(events, "triage_report")
    assert final["verdict"] == "true_positive", final.get("summary")
    assert final["impact"] == "succeeded"
    assert "impact_change" not in final
    assert not any(e.kind == IMPACT_GATE for e in events)
    assert final["first_line"] == (
        f"True positive. Impact: succeeded. devbox {SRC} to mainsrv (server) {DST}."
    )


async def test_a_finding_run_of_the_pipeline_names_the_victim_as_the_target(
    settings_kratos: Settings,
) -> None:
    """The anchor document of the finding is the response of the server: its
    source is the victim. The first line and the stored ends take the
    direction of the finding, and a run with no finding keeps the direction
    of its alert."""

    def _response_anchor(alert_id: str = hs.ANCHOR_ID) -> EnrichedAlertContext:
        enriched = _pipeline_enriched(alert_id)
        enriched.alert = enriched.alert.model_copy(
            update={"source_ip": DST, "destination_ip": SRC, "event_dataset": "zeek.http"}
        )
        return enriched

    subject = hs._subject(
        findings=[
            hs.SubjectFinding(
                ordinal=0,
                title="Exploit requests to the web server",
                hosts=[DST],
                citations=[hs.ANCHOR_ID],
                promoted=True,
            )
        ]
    )
    report = _report(impact="attempted", citations=[hs.ANCHOR_ID])
    with patch.object(hs, "_enriched", _response_anchor):
        events, _spies = await hs._run(settings_kratos, subject=subject, report=report)
        plain, _spies = await hs._run(settings_kratos, subject=None, report=report)
    final = hs._payload(events, "triage_report")
    assert final["verdict"] == "true_positive", final.get("summary")
    assert final["ends"] == {"source": SRC, "target": DST}
    assert final["first_line"] == f"True positive. Impact: attempted. {SRC} to {DST}."
    # Negative control: the alert run keeps the direction of its alert.
    assert hs._payload(plain, "triage_report")["ends"] == {"source": DST, "target": SRC}


async def test_a_false_positive_from_the_pipeline_carries_no_impact(
    settings_kratos: Settings,
) -> None:
    """Negative control on the whole path: the model wrote an impact beside a
    false positive."""
    report = _report("false_positive", impact="succeeded", citations=[HTTP_ID])
    events = await _pipeline(settings_kratos, report, HTTP_RECORD)
    final = hs._payload(events, "triage_report")
    assert final["verdict"] == "false_positive", final.get("summary")
    assert final["impact"] is None
    assert "impact_change" not in final
    assert final["first_line"] == f"False positive. {SRC} to {DST}."


# ── The API ────────────────────────────────────────────────────────────────


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
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _seed_run(
    client: TestClient,
    alert_id: str,
    *,
    verdict: str = "true_positive",
    minutes_ago: float = 60.0,
    src: str | None = SRC,
    dst: str | None = DST,
    report: dict[str, Any] | None = None,
    rationale: str | None = None,
    status: str = "complete",
) -> str:
    when = datetime.now(UTC) - timedelta(minutes=minutes_ago)

    async def work(db: Any) -> str:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_id,
            started_by="auto-triage",
            rule_name="ET EXPLOIT Example Upload Request",
            src_ip=src,
            dest_ip=dst,
        )
        await inv_svc.finalize(
            db,
            inv.id,
            status=status,
            verdict=verdict,
            confidence=0.85,
            rationale=rationale,
            summary=STORY,
            report={"verdict": verdict, "confidence": 0.85, "summary": STORY, **(report or {})},
        )
        row = await db.get(Investigation, inv.id)
        row.created_at = when.replace(tzinfo=None)
        await db.commit()
        return str(inv.id)

    run_id: str = _do(client, work)
    return run_id


def _list(client: TestClient, **params: Any) -> dict[str, Any]:
    res = client.get("/api/v1/investigations", params=params)
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_the_list_and_the_page_return_the_impact_and_the_first_line(client: TestClient) -> None:
    _do(client, _seed_hosts)
    stored = "True positive. Impact: succeeded. devbox 10.40.50.7 to mainsrv (server) 10.20.30.5."
    new = _seed_run(client, "a-new", report={"impact": "succeeded", "first_line": stored})
    old = _seed_run(client, "a-old", src=STRANGER, minutes_ago=120)
    benign = _seed_run(client, "a-fp", verdict="false_positive", report={"impact": "succeeded"})

    rows = {row["id"]: row for row in _list(client)["rows"]}
    assert rows[new]["impact"] == "succeeded"
    assert rows[new]["firstLine"] == stored
    # A row of an older release: no impact, and the line is built now.
    assert rows[old]["impact"] is None
    assert rows[old]["firstLine"] == (
        f"True positive. Impact: not stated. {STRANGER} to mainsrv (server) {DST}."
    )
    assert "()" not in rows[old]["firstLine"]
    # A false positive carries no impact, whatever its report holds.
    assert rows[benign]["impact"] is None
    assert rows[benign]["firstLine"] == f"False positive. devbox {SRC} to mainsrv (server) {DST}."

    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        detail = client.get(f"/api/v1/investigations/{new}").json()
        old_detail = client.get(f"/api/v1/investigations/{old}").json()
    assert detail["impact"] == "succeeded"
    assert detail["firstLine"] == stored
    assert detail["impactChange"] is None
    assert old_detail["impact"] is None
    assert old_detail["firstLine"] == rows[old]["firstLine"]


def test_the_list_row_states_the_headline_of_the_run(client: TestClient) -> None:
    # Polish review 2026-11-13: the row printed the first line, which repeats
    # the verdict chip and the Source to Dest cells. It states the headline.
    said = _seed_run(client, "h-said", rationale="The upload request carries a web shell.")
    told = _seed_run(client, "h-told", minutes_ago=90)
    secret = _seed_run(
        client,
        "h-secret",
        minutes_ago=100,
        rationale="The request logs in with password=Hunter2Secret99 to the server.",
    )
    rows = {row["id"]: row for row in _list(client)["rows"]}
    assert rows[said]["headline"] == "The upload request carries a web shell."
    # A run that stored no headline states its summary, as its page does.
    assert rows[told]["headline"] == STORY
    assert "Hunter2Secret99" not in rows[secret]["headline"]
    # NEGATIVE CONTROL: a run with no verdict and a pipeline error state none.
    running = _seed_run(client, "h-running", verdict="", status="running", minutes_ago=5)
    broken = _seed_run(
        client,
        "h-broken",
        verdict="needs_more_info",
        minutes_ago=6,
        report={"resolution": {"provenance": "pipeline_fallback"}},
    )
    rows = {row["id"]: row for row in _list(client)["rows"]}
    assert rows[running]["headline"] is None
    assert rows[broken]["fallback"] is True
    assert rows[broken]["headline"] is None


def test_the_page_returns_the_impact_change(client: TestClient) -> None:
    change = {
        "gate": IMPACT_GATE,
        "from_impact": "succeeded",
        "to_impact": "attempted",
        "reason": "The report cites no fetched record with content of the event.",
        "missing": ["A record of the host with content of the event."],
    }
    run_id = _seed_run(client, "a-chg", report={"impact": "attempted", "impact_change": change})
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        detail = client.get(f"/api/v1/investigations/{run_id}").json()
    assert detail["impactChange"] == {
        "gate": IMPACT_GATE,
        "fromImpact": "succeeded",
        "toImpact": "attempted",
        "reason": change["reason"],
        "missing": change["missing"],
    }


def test_the_list_filters_on_the_impact(client: TestClient) -> None:
    worked = _seed_run(client, "f-1", report={"impact": "succeeded"})
    sent = _seed_run(client, "f-2", report={"impact": "attempted"})
    nothing = _seed_run(client, "f-3", report={"impact": "none"})
    unsure = _seed_run(client, "f-4", report={"impact": "unknown"})
    old = _seed_run(client, "f-5")
    _seed_run(client, "f-6", verdict="false_positive", report={"impact": "succeeded"})

    def ids(**params: Any) -> set[str]:
        return {row["id"] for row in _list(client, **params)["rows"]}

    assert ids(impact="succeeded") == {worked}
    assert ids(impact="attempted,none") == {sent, nothing}
    # A true positive that states no impact counts as unknown.
    assert ids(impact="unknown") == {unsure, old}
    assert _list(client, impact="succeeded")["total"] == 1
    # The four values cover every true positive, and no other verdict.
    assert ids(impact=",".join(IMPACT_ORDER)) == ids(verdict="true_positive")

    res = client.get("/api/v1/investigations", params={"impact": "certain"})
    assert res.status_code == 422
    assert "succeeded" in res.text


def test_the_verdict_order_puts_the_impact_first_inside_the_true_positives(
    client: TestClient,
) -> None:
    nothing = _seed_run(client, "s-1", report={"impact": "none"}, minutes_ago=1)
    benign = _seed_run(client, "s-2", verdict="false_positive", minutes_ago=2)
    old = _seed_run(client, "s-3", minutes_ago=3)
    sent = _seed_run(client, "s-4", report={"impact": "attempted"}, minutes_ago=4)
    unsure = _seed_run(client, "s-5", verdict="needs_more_info", minutes_ago=5)
    worked_old = _seed_run(client, "s-6", report={"impact": "succeeded"}, minutes_ago=7)
    worked_new = _seed_run(client, "s-7", report={"impact": "succeeded"}, minutes_ago=6)

    by_verdict = [row["id"] for row in _list(client, sort="verdict")["rows"]]
    assert by_verdict == [worked_new, worked_old, sent, old, nothing, unsure, benign]
    # The default order does not change: the newest run first.
    newest = [row["id"] for row in _list(client)["rows"]]
    assert newest == [nothing, benign, old, sent, unsure, worked_new, worked_old]
    assert [row["id"] for row in _list(client, sort="newest")["rows"]] == newest

    res = client.get("/api/v1/investigations", params={"sort": "severity"})
    assert res.status_code == 422
