"""The host history gate keeps the story of the model (change A, 2026-10-30).

The gate ``_downgrade_ungrounded_host_anchored_tp`` changes a true positive
that rests only on the alert history of the host to needs_more_info. On prod it
fired on four hunt-finding investigations with web attack evidence, replaced
their summaries with a fixed text, and reset two Oracle true positives. These
tests pin the fix:

- On a hunt finding, the documents that the promoted finding cites count for
  the exploit and attack-type exemption. The documents of other findings and of
  the lead do not count.
- Web attack evidence in the summary or the citations keeps the true positive,
  unless a rule name in the alert history of the host names the same type.
- When the gate fires, the summary keeps the text of the model behind a lead.
- The gate does not run on an Oracle report.

The data is synthetic: TEST-NET and 10.0.0.x addresses, generic rule names.
"""

from __future__ import annotations

import json
import re
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic_ai.models.test import TestModel
from soc_ai.agent.context import HuntSubject, SubjectFinding
from soc_ai.agent.gates import (
    _HOST_ANCHORED_TP_LEAD,
    _downgrade_ungrounded_host_anchored_tp,
    _host_anchored_tp_note,
    _host_anchored_tp_reason,
)
from soc_ai.agent.orchestrator import investigate
from soc_ai.agent.triage import TriageReport
from soc_ai.api.recorder import _first_rationale
from soc_ai.config import Settings
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext

from tests import test_hunt_subject as hs
from tests.test_agent import _make_vpn_icmp_enriched

_GATE_KEY = "ungrounded_host_anchored_tp_downgrade"
PROFILE = {"ET EXPLOIT Example PHP Code Injection in Filename": 12}
ANCHOR = "anchor-http-001"
CITED = "cited-http-002"
EXPLOIT_DOC = "doc-exploit-001"
NO_EVIDENCE = "The source host sent requests to the web server and the server answered."


def _hunt_enriched(
    docs: list[SoAlert], focus: list[str], profile: dict[str, int] | None = None
) -> EnrichedAlertContext:
    """The enriched context of a hunt-finding run: a zeek.http anchor, the
    documents of the subject and the ids the promoted finding cites."""
    return EnrichedAlertContext(
        alert=SoAlert(
            id=ANCHOR,
            event_dataset="zeek.http",
            source_ip="10.0.0.5",
            destination_ip="10.0.0.9",
        ),
        subject_documents=docs,
        subject_focus_document_ids=focus,
        host_alert_profile=PROFILE if profile is None else profile,
    )


def _tp(
    summary: str = NO_EVIDENCE,
    citations: list[str] | None = None,
    note: str | None = None,
) -> TriageReport:
    return TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary=summary,
        citations=citations or [ANCHOR],
        recommended_actions=[],
        validator_note=note,
    )


# ── gate 3b on a hunt finding ─────────────────────────────────────────────────


def test_a_finding_keeps_its_true_positive_when_it_cites_an_exploit_alert() -> None:
    docs = [
        SoAlert(id=ANCHOR, event_dataset="zeek.http"),
        SoAlert(
            id=EXPLOIT_DOC,
            rule_name="ET EXPLOIT Example PHP Code Injection in Filename",
            classtype="Misc Attack",
        ),
    ]
    audit: dict[str, Any] = {}
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp(), _hunt_enriched(docs, [ANCHOR, EXPLOIT_DOC]), audit
    )
    assert out.verdict == "true_positive"
    assert audit == {}


@pytest.mark.parametrize(
    "classtype", ["Attempted Administrator Privilege Gain", "Web Application Attack"]
)
def test_a_finding_keeps_its_true_positive_when_a_cited_alert_has_an_attack_type(
    classtype: str,
) -> None:
    docs = [
        SoAlert(
            id="doc-post-0001",
            rule_name="ET HUNTING Generic POST with Control Character in Filename Parameter",
            classtype=classtype,
        )
    ]
    audit: dict[str, Any] = {}
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp(), _hunt_enriched(docs, ["doc-post-0001"]), audit
    )
    assert out.verdict == "true_positive"
    assert audit == {}


def test_documents_of_other_findings_and_of_the_lead_do_not_keep_the_true_positive() -> None:
    """Negative control on the path a wide exemption would open. A hunt subject
    also holds the documents of the other findings and of the lead, and prod
    replay showed noise alerts among them exempt most hunt runs."""
    docs = [
        SoAlert(id=ANCHOR, event_dataset="zeek.http"),
        SoAlert(
            id="doc-dns-00001",
            rule_name="ET MALWARE Example DNS TXT Command and Control",
            classtype="A Network Trojan was detected",
        ),
        SoAlert(
            id="doc-icmp-0001",
            rule_name="ET EXPLOIT Possible CVE-2020-11910 anomalous ICMPv4",
            classtype="Attempted Administrator Privilege Gain",
        ),
        SoAlert(
            id="doc-lead-0001",
            rule_name="ET MALWARE Example BPFDoor Heartbeat",
            classtype="A Network Trojan was detected",
        ),
    ]
    audit: dict[str, Any] = {}
    # B1 (2026-11-13): the report cites the alerts of the other findings and of
    # the lead only. A cited record of the promoted finding is evidence now,
    # and the tests of the next section cover it.
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp(citations=["doc-dns-00001", "doc-icmp-0001", "doc-lead-0001"]),
        _hunt_enriched(docs, [ANCHOR]),
        audit,
    )
    assert out.verdict == "needs_more_info"
    assert _GATE_KEY in audit
    assert audit[_GATE_KEY]["reason"] == _host_anchored_tp_reason(True)


async def test_the_pipeline_reads_the_documents_of_the_promoted_finding(
    settings_kratos: Settings,
) -> None:
    subject = HuntSubject(
        hunt_id="01HUNT0000000000000000000",
        objective="find web attacks",
        findings=[
            SubjectFinding(
                ordinal=0,
                title="Exploit on the web server",
                citations=[hs.ANCHOR_ID, EXPLOIT_DOC],
                promoted=True,
            ),
            SubjectFinding(ordinal=1, title="Other", citations=["doc-other-0001"]),
        ],
        documents=[
            SoAlert(id=hs.ANCHOR_ID, event_dataset="zeek.http"),
            SoAlert(
                id=EXPLOIT_DOC,
                rule_name="ET EXPLOIT Example PHP Code Injection in Filename",
                classtype="Misc Attack",
            ),
            SoAlert(id="doc-other-0001", event_dataset="zeek.conn"),
        ],
    )
    assert subject.promoted_document_ids() == [hs.ANCHOR_ID, EXPLOIT_DOC]
    local = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary=NO_EVIDENCE,
        citations=[hs.ANCHOR_ID],
        recommended_actions=[],
    )
    original = hs._enriched

    def _with_profile(alert_id: str = hs.ANCHOR_ID) -> EnrichedAlertContext:
        enriched = original(alert_id)
        enriched.host_alert_profile = PROFILE
        return enriched

    with patch.object(hs, "_enriched", _with_profile):
        events, _spies = await hs._run(settings_kratos, subject=subject, report=local)
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["verdict"] == "true_positive", final.get("summary")
    assert not any(e.kind == _GATE_KEY for e in events)
    context = next(e.payload for e in events if e.kind == "enriched_alert_context")
    assert "subject_focus_document_ids" not in context


# ── per-event evidence (B1, 2026-11-13) ───────────────────────────────────────
#
# The gate fired 9 times on prod from 2026-10-31 to 2026-11-12. Five fires were
# finding runs of the PHP2Shell activity: each finding cited Zeek HTTP records
# of the exploit requests, each report cited them by id, and the plain story
# held no word of the list. The fix is structural. A word list misses the next
# plain story.
#
# One rule for both run types. The gate keeps a true positive when the report
# cites, by id, a resolved record that meets all three:
#   (a) a tool of this run fetched it, or it is a stored document of the
#       promoted finding;
#   (b) it involves a host of the focus document;
#   (c) it holds content of the event: a payload, an HTTP, DNS, SSH, file or
#       process record. A bare flow record, a host profile and a rule label
#       hold none.
# The first version of this fix was weaker, and a review found two holes. It
# kept a true positive for an attack alert on the same flow, which is the
# BPFDoor case that the gate exists for. It also kept one for the anchor id
# alone, which each hunt run gets as its alert id.

PLAIN_STORY = (
    "The source host sends exploitation attempts to the web server. The requests "
    "match a tight exploit pattern, a multipart POST with empty file names."
)
HISTORY_ONLY = "The host has many exploit alerts in its history, so this is an attack."
FLOW = "1:flowflowflowflowflowflowflow="
SRC, DST = "10.0.0.5", "10.0.0.9"


def _http(doc_id: str, **over: Any) -> SoAlert:
    """A Zeek HTTP record of the focus hosts, with the content of the request."""
    fields: dict[str, Any] = {
        "id": doc_id,
        "event_dataset": "zeek.http",
        "source_ip": SRC,
        "destination_ip": DST,
        "zeek_http_method": "POST",
        "zeek_http_uri": "/upload.php",
    }
    fields.update(over)
    return SoAlert(**fields)


def _conn(doc_id: str) -> SoAlert:
    return SoAlert(
        id=doc_id,
        event_dataset="zeek.conn",
        source_ip=SRC,
        destination_ip=DST,
        zeek_conn_state="SF",
        zeek_conn_orig_bytes=451384,
    )


def _gate(report: TriageReport, enriched: Any, **kw: Any) -> tuple[Any, dict[str, Any]]:
    audit: dict[str, Any] = {}
    return _downgrade_ungrounded_host_anchored_tp(report, enriched, audit, **kw), audit


def test_a_finding_keeps_its_true_positive_when_the_report_cites_a_content_record() -> None:
    """The shape of run 01M6Y7MDY1GQ7RC00ANYEYESRJ: the finding cites Zeek HTTP
    records of the exploit requests, and the report cites them by id."""
    docs = [_http(ANCHOR), _http(CITED)]
    out, audit = _gate(
        _tp(PLAIN_STORY, [CITED, "tool t_get_rule_content:content"]),
        _hunt_enriched(docs, [ANCHOR, CITED]),
    )
    assert out.verdict == "true_positive"
    assert out.summary == PLAIN_STORY
    assert audit == {}


def test_the_anchor_counts_when_it_is_a_content_record_of_the_finding() -> None:
    out, audit = _gate(_tp(PLAIN_STORY, [ANCHOR]), _hunt_enriched([_http(ANCHOR)], [ANCHOR]))
    assert out.verdict == "true_positive"
    assert audit == {}


def test_the_anchor_id_of_a_flow_record_plus_the_host_profile_is_lowered() -> None:
    """Review defect 2. The report rests on the alert history and cites the
    anchor, the id that the run gets as its alert id. The anchor is a bare
    flow record, so the id proves nothing."""
    out, audit = _gate(
        _tp(HISTORY_ONLY, [ANCHOR, "host_alert_profile"]),
        _hunt_enriched([_conn(ANCHOR)], [ANCHOR]),
    )
    assert out.verdict == "needs_more_info"
    assert _GATE_KEY in audit


def test_a_lead_run_is_lowered_with_a_record_of_the_lead() -> None:
    """Review defect 2. A lead promotion has no promoted finding. Its anchor
    is a record of a lead observation, so the rule does not apply."""
    doc = SoAlert(
        id=ANCHOR,
        event_dataset="zeek.dns",
        source_ip=SRC,
        destination_ip=DST,
        zeek_dns_query="updates.example.test",
    )
    enriched = _hunt_enriched([doc], [])
    enriched.alert = doc
    out, audit = _gate(_tp(HISTORY_ONLY, [f"(id {ANCHOR})"]), enriched)
    assert out.verdict == "needs_more_info"
    assert _GATE_KEY in audit


def test_a_finding_with_no_resolved_document_is_lowered() -> None:
    """The finding cites no document that the grid holds, so the gate reads
    the anchor of another finding. The rule does not apply."""
    docs = [_http(ANCHOR), _http("doc-other-0001")]
    out, audit = _gate(_tp(PLAIN_STORY, [ANCHOR]), _hunt_enriched(docs, []))
    assert out.verdict == "needs_more_info"
    assert _GATE_KEY in audit


def test_a_finding_whose_only_support_is_the_alert_history_is_lowered() -> None:
    """Negative control on the path the rule would miss. The finding has
    content records, and the report cites none of them."""
    docs = [_http(ANCHOR), _http(CITED)]
    out, audit = _gate(
        _tp(HISTORY_ONLY, ["host_alert_profile", "alert.source_ip"]),
        _hunt_enriched(docs, [ANCHOR, CITED]),
    )
    assert out.verdict == "needs_more_info"
    assert _GATE_KEY in audit


@pytest.mark.parametrize(
    ("citations", "why"),
    [
        (["doc-other-0001"], "a content record of another finding"),
        (["doc-unknown-0001"], "an id that is no document of the subject"),
        (["doc-info-00001"], "an alert that is not a malware or attack detection"),
        ([f"the record {CITED} shows it"], "prose that holds an id"),
        (["doc-conn-0001"], "a bare flow record of the finding"),
        (["doc-empty-0001"], "an HTTP record with no content"),
        (["doc-away-0001"], "a content record of two other hosts"),
    ],
)
def test_other_citations_do_not_keep_the_true_positive(citations: list[str], why: str) -> None:
    """Negative controls, one for each condition of the rule."""
    docs = [
        _conn(ANCHOR),
        _http(CITED),
        _http("doc-other-0001"),
        _conn("doc-conn-0001"),
        SoAlert(id="doc-empty-0001", event_dataset="zeek.http", source_ip=SRC, destination_ip=DST),
        _http("doc-away-0001", source_ip="172.16.9.9", destination_ip="172.16.0.1"),
        SoAlert(
            id="doc-info-00001",
            event_dataset="suricata.alert",
            rule_name="ET INFO Example Observed Developer Domain in TLS SNI",
            classtype="Misc activity",
            source_ip=SRC,
            destination_ip=DST,
        ),
    ]
    focus = [ANCHOR, CITED, "doc-conn-0001", "doc-empty-0001", "doc-away-0001", "doc-info-00001"]
    out, audit = _gate(_tp(PLAIN_STORY, citations), _hunt_enriched(docs, focus))
    assert out.verdict == "needs_more_info", why
    assert _GATE_KEY in audit


def _alert_run(same_flow: list[SoAlert] | None = None) -> Any:
    """An alert run: an ICMP info rule on one flow, with a malware rule in the
    alert history of the host."""
    enriched = _make_vpn_icmp_enriched()
    enriched.alert = enriched.alert.model_copy(update={"network_community_id": FLOW})
    enriched.community_id_events = same_flow or []
    return enriched


def _tool_return(content: Any, *, tool: str = "t_query_events_oql", call_id: str = "tc1") -> Any:
    """The message history of one successful tool call of this run."""
    from types import SimpleNamespace

    call = SimpleNamespace(
        tool_name=tool,
        args={"event_id": "ev-fetched-001"},
        tool_call_id=call_id,
        part_kind="tool-call",
    )
    ret = SimpleNamespace(
        tool_name=tool, content=content, tool_call_id=call_id, part_kind="tool-return"
    )
    return [SimpleNamespace(parts=[call]), SimpleNamespace(parts=[ret])]


def _hit(doc_id: str, source: dict[str, Any]) -> dict[str, Any]:
    return {"total": 1, "hits": [{"_id": doc_id, "_source": source}]}


ALERT_SRC, ALERT_DST = "192.0.2.1", "10.0.0.100"
PAYLOAD_SOURCE = {
    "event": {"dataset": "suricata.alert"},
    "source": {"ip": ALERT_SRC},
    "destination": {"ip": ALERT_DST},
    "network": {"community_id": FLOW},
    "payload_printable": "GET /cmd.php?c=id HTTP/1.1",
}


def test_an_alert_keeps_its_true_positive_with_a_fetched_payload_record() -> None:
    """The run fetched a record of its own flow with the payload, and the
    report cites that record by id."""
    out, audit = _gate(
        _tp(PLAIN_STORY, ["ev-payload-001"]),
        _alert_run(),
        messages=_tool_return(_hit("ev-payload-001", PAYLOAD_SOURCE)),
    )
    assert out.verdict == "true_positive"
    assert audit == {}


def test_a_raw_event_that_a_tool_fetched_by_its_id_counts() -> None:
    """The raw event tool returns the document with no id inside. The id is
    the argument of the call."""
    out, audit = _gate(
        _tp(PLAIN_STORY, ["ev-fetched-001"]),
        _alert_run(),
        messages=_tool_return(PAYLOAD_SOURCE, tool="t_get_event_raw"),
    )
    assert out.verdict == "true_positive"
    assert audit == {}


def test_a_dispatch_result_counts_as_a_tool_of_the_run() -> None:
    out, audit = _gate(
        _tp(PLAIN_STORY, ["ev-payload-001"]),
        _alert_run(),
        tool_results=[_hit("ev-payload-001", PAYLOAD_SOURCE)],
    )
    assert out.verdict == "true_positive"
    assert audit == {}


def test_the_malware_alert_on_the_same_flow_does_not_keep_the_true_positive() -> None:
    """Review defect 1, the case that the gate exists for. The focus alert is
    an ICMP info rule. The noisy malware rule of the host history fired on the
    same ping flow. The report rests on the host profile. The label of a
    sibling alert is no evidence of this event."""
    sibling = SoAlert(
        id="bpfdoor-sibling-1",
        event_dataset="suricata.alert",
        rule_name="ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat",
        classtype="trojan-activity",
        source_ip=ALERT_SRC,
        destination_ip=ALERT_DST,
        network_community_id=FLOW,
    )
    for citations in (["host_alert_profile"], ["bpfdoor-sibling-1", "host_alert_profile"]):
        out, audit = _gate(
            _tp("BPFDoor C2 confirmed by host profile and absence of reputation.", citations),
            _alert_run([sibling]),
        )
        assert out.verdict == "needs_more_info", citations
        assert _GATE_KEY in audit


@pytest.mark.parametrize(
    ("cited", "content", "why"),
    [
        (
            "ev-conn-001",
            _hit(
                "ev-conn-001",
                {
                    "event": {"dataset": "zeek.conn"},
                    "source": {"ip": ALERT_SRC},
                    "destination": {"ip": ALERT_DST},
                    "connection": {"state": "SF"},
                    "network": {"bytes": 7080},
                },
            ),
            "a fetched flow record",
        ),
        (
            "ev-away-001",
            _hit(
                "ev-away-001",
                {
                    **PAYLOAD_SOURCE,
                    "source": {"ip": "172.16.9.9"},
                    "destination": {"ip": "172.16.0.1"},
                },
            ),
            "a fetched payload record of two other hosts",
        ),
        (
            "ev-label-001",
            _hit(
                "ev-label-001",
                {
                    "event": {"dataset": "suricata.alert"},
                    "source": {"ip": ALERT_SRC},
                    "destination": {"ip": ALERT_DST},
                    "rule": {"name": "ET MALWARE Example Heartbeat"},
                },
            ),
            "a fetched alert that holds a rule label and no payload",
        ),
        ("ev-not-fetched", _hit("ev-payload-001", PAYLOAD_SOURCE), "an id that no tool fetched"),
        (
            "ev-error-001",
            {"error": "timeout", "hits": [{"_id": "ev-error-001", "_source": PAYLOAD_SOURCE}]},
            "a tool call that failed",
        ),
    ],
)
def test_other_fetched_records_do_not_keep_an_alert_true_positive(
    cited: str, content: Any, why: str
) -> None:
    """Negative controls on the alert run, one for each condition."""
    out, audit = _gate(
        _tp(PLAIN_STORY, [cited, "host_alert_profile"]),
        _alert_run(),
        messages=_tool_return(content),
    )
    assert out.verdict == "needs_more_info", why
    assert _GATE_KEY in audit


def test_a_prefetched_flow_record_does_not_keep_an_alert_true_positive() -> None:
    """Negative control: the shape of run 01M6WEC0CG156GP1YX38YEAKV5. The
    prefetch holds Zeek records of the flow, and the report cites them. No
    tool of the run fetched them. The review of 2026-11-12 found needs more
    info reasonable for this run."""
    enriched = _alert_run(
        [
            SoAlert(id="conn-0001", event_dataset="zeek.conn", network_community_id=FLOW),
            SoAlert(
                id="ssl-00001",
                event_dataset="zeek.ssl",
                source_ip=ALERT_SRC,
                destination_ip=ALERT_DST,
                zeek_ssl_server_name="shop-status.example.test",
                network_community_id=FLOW,
            ),
        ]
    )
    out, audit = _gate(
        _tp(
            "The host contacts this domain on 7 days. Escalate.",
            [
                "community_id_events.0.zeek_conn_state",
                "conn-0001",
                "ssl-00001",
                "tool t_prevalence",
            ],
        ),
        enriched,
    )
    assert out.verdict == "needs_more_info"
    assert _GATE_KEY in audit


async def test_the_pipeline_gives_the_gate_the_tool_results_of_the_run(
    settings_kratos: Settings,
) -> None:
    """The loop of this run fetched a Kerberos record of the focus host, and
    the report cites it by id. The gate reads the message history."""
    local = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary=PLAIN_STORY,
        citations=["ev-loop-0001"],
        recommended_actions=[],
    )
    record = {
        "_id": "ev-loop-0001",
        "event": {"dataset": "zeek.kerberos"},
        "source": {"ip": "10.1.2.3"},
        "kerberos": {"cipher": "rc4-hmac", "service": "MSSQLSvc/db.example.test"},
    }
    original = hs._enriched
    make_investigator = hs._fake_investigator

    def _with_profile(alert_id: str = hs.ANCHOR_ID) -> EnrichedAlertContext:
        enriched = original(alert_id)
        enriched.host_alert_profile = PROFILE
        enriched.alert = enriched.alert.model_copy(update={"source_ip": "10.1.2.3"})
        return enriched

    def _loop_with(found: dict[str, Any]) -> Any:
        agent = make_investigator()
        message = agent.run.return_value.all_messages.return_value[0]
        message.parts[1].content = {"kerberos": [found]}
        return agent

    with (
        patch.object(hs, "_enriched", _with_profile),
        patch.object(hs, "_fake_investigator", lambda: _loop_with(record)),
    ):
        events, _spies = await hs._run(settings_kratos, subject=None, report=local)
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["verdict"] == "true_positive", final.get("summary")
    assert not any(e.kind == _GATE_KEY for e in events)

    # Negative control: the same run with a flow record is lowered.
    flow_record = {**record, "event": {"dataset": "zeek.conn"}, "kerberos": None}
    with (
        patch.object(hs, "_enriched", _with_profile),
        patch.object(hs, "_fake_investigator", lambda: _loop_with(flow_record)),
    ):
        events, _spies = await hs._run(settings_kratos, subject=None, report=local)
    assert any(e.kind == _GATE_KEY for e in events)


# ── gate 3c: web attack evidence ──────────────────────────────────────────────

_WEB_EVIDENCE = [
    "The URI carried a path-traversal to /etc/passwd.",
    "A directory traversal reached the config file.",
    "The upload wrote a PHP webshell.",
    "A web shell answered on the server.",
    "The request tried a local file inclusion.",
    "The scanner sent LFI probes.",
    "The form field carried a command injection.",
    "The filename carried a code injection.",
    "The parameter carried an SQL injection.",
    "The server ran remote code execution.",
    "The filename was <?php system($_REQUEST[1]);?> in the POST.",
    "The upload gives RCE on the server.",
    "The query string held SQLi.",
]


@pytest.mark.parametrize("summary", _WEB_EVIDENCE)
def test_web_attack_evidence_keeps_the_true_positive(summary: str) -> None:
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp(summary, ["alert.rule_name"]), _make_vpn_icmp_enriched(), {}
    )
    assert out.verdict == "true_positive", summary


_HISTORY = {
    "ET EXPLOIT Example Apache log4j RCE Attempt": 3,
    "ET HUNTING Generic POST with Control Character in Filename - Possible Command "
    "Injection Attempt": 2,
}


@pytest.mark.parametrize(
    ("summary", "citations"),
    [
        ("The host history holds log4j RCE attempt alerts.", ["host_alert_profile"]),
        (
            "The rule prevalence is low.",
            [
                "tool t_rule_prevalence:ET HUNTING Generic POST with Control Character in "
                "Filename - Possible Command Injection Attempt"
            ],
        ),
    ],
)
def test_a_web_attack_word_from_the_alert_history_does_not_keep_the_true_positive(
    summary: str, citations: list[str]
) -> None:
    """Negative control. A model quotes rule names from the alert history, and
    such a quote is not evidence of its own."""
    enriched = _make_vpn_icmp_enriched()
    enriched.host_alert_profile = _HISTORY
    out = _downgrade_ungrounded_host_anchored_tp(_tp(summary, citations), enriched, {})
    assert out.verdict == "needs_more_info"


def test_the_alert_history_does_not_block_another_type_of_evidence() -> None:
    """The exclusion acts on one type of evidence at a time."""
    enriched = _make_vpn_icmp_enriched()
    enriched.host_alert_profile = _HISTORY
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp("The URI carried a path traversal to /etc/passwd.", ["host_alert_profile"]),
        enriched,
        {},
    )
    assert out.verdict == "true_positive"


@pytest.mark.parametrize(
    "summary",
    [
        "The host has ET EXPLOIT and CVE rules in its alert history.",
        "The resource was sourced from a forced update.",
        "The sqlite database on the host is unknown.",
        "NAT traversal over the VPN reached an unknown address.",
        "The selfie upload went to an unknown address.",
        "An RFI went to the owner of the host.",
    ],
)
def test_exploit_words_and_word_fragments_do_not_keep_the_true_positive(summary: str) -> None:
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp(summary, ["alert.rule_name"]), _make_vpn_icmp_enriched(), {}
    )
    assert out.verdict == "needs_more_info", summary


# ── what the gate writes ──────────────────────────────────────────────────────


def test_the_gate_keeps_the_model_text_and_states_the_change() -> None:
    original = "BPFDoor C2 confirmed by host profile and absence of reputation."
    audit: dict[str, Any] = {}
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp(original, ["alert.rule_name"], note="An earlier gate wrote this."),
        _make_vpn_icmp_enriched(),
        audit,
    )
    assert out.verdict == "needs_more_info"
    assert out.recommended_actions == []
    # B2 (2026-11-13): the summary is the text of the model, with no lead.
    assert out.summary == original
    assert out.validator_note == "An earlier gate wrote this.\n" + _host_anchored_tp_note(False)
    assert audit[_GATE_KEY]["reason"] == _host_anchored_tp_reason(False)
    assert audit[_GATE_KEY]["on_finding"] is False
    assert "original_summary" not in audit[_GATE_KEY]


def test_the_row_headline_is_the_sentence_of_the_model() -> None:
    """The first sentence of the summary is the row headline and the digest of
    the session prior (recorder._first_rationale). Run
    01M6WEC0CG156GP1YX38YEAKV5 showed "soc-ai changed the verdict from a true
    positive to needs more info" as its headline, in the list rows and in the
    bell (review 2026-11-12, console finding 1)."""
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp("BPFDoor C2 confirmed by host profile. The host is a laptop.", ["alert.rule_name"]),
        _make_vpn_icmp_enriched(),
        {},
    )
    assert out.verdict == "needs_more_info"
    assert _first_rationale(out.model_dump(mode="json")) == "BPFDoor C2 confirmed by host profile"


def test_the_gate_text_reads_in_ste() -> None:
    for text in (
        _HOST_ANCHORED_TP_LEAD,
        _host_anchored_tp_note(True),
        _host_anchored_tp_note(False),
    ):
        # No en dash, no em dash, no arrow and no parenthetical aside.
        assert not re.search("[\u2013\u2014\u2192(]", text), text
        assert "true_positive" not in text
        for sentence in re.split(r"(?<=\.)\s+", text):
            assert len(sentence.split()) <= 25, sentence


# ── the Oracle on a hunt finding ──────────────────────────────────────────────


def _capturing_gateway(answer: str, bodies: list[str]) -> Any:
    """The real single-shot Oracle client against a fake gateway that records
    each request body."""
    real_client = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/chat/completions"):
            bodies.append(request.content.decode())
            return httpx.Response(200, json={"choices": [{"message": {"content": answer}}]})
        return httpx.Response(404, json={"error": {"message": "not here"}})

    def _client(**kw: Any) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(_handler), **kw)

    return patch("httpx.AsyncClient", _client)


def _oracle_answer(citations: list[str] | None) -> str:
    body: dict[str, Any] = {
        "verdict": "true_positive",
        "confidence": 0.88,
        "summary": "The source host attacked the web server.",
        "reasoning": "The cited record shows the attack.",
    }
    if citations is not None:
        body["citations"] = citations
    return json.dumps(body)


async def _run_hunt_oracle(settings: Settings, oracle_answer: str) -> tuple[list[Any], list[str]]:
    """A finding whose local true positive the gate changes, then the Oracle."""
    settings.investigate_when_unsure = True
    settings.oracle_enabled = True
    ctx = hs._make_ctx(settings)
    subject = HuntSubject(
        hunt_id="01HUNT0000000000000000000",
        objective="find web attacks on the web server",
        findings=[
            SubjectFinding(
                ordinal=0,
                title="Requests to the web server",
                hosts=["10.0.0.5", "10.0.0.9"],
                citations=[ANCHOR, CITED],
                promoted=True,
            )
        ],
        documents=[
            SoAlert(id=ANCHOR, event_dataset="zeek.http"),
            SoAlert(id=CITED, event_dataset="zeek.http"),
        ],
    )
    # The local report cites the alert history only, so the gate changes its
    # verdict. A report that cites a record of the finding keeps the true
    # positive since B1 (2026-11-13), and the Oracle is then not asked.
    local = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary=NO_EVIDENCE,
        citations=["host_alert_profile"],
        recommended_actions=[],
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return EnrichedAlertContext(
            alert=SoAlert(
                id=alert_id,
                severity_label="low",
                event_dataset="zeek.http",
                source_ip="10.0.0.5",
                destination_ip="10.0.0.9",
            ),
            pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
            host_alert_profile=PROFILE,
        )

    bodies: list[str] = []
    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=hs._fake_investigator()),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer", return_value=hs._fake_loop_synth(local)
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            MagicMock(return_value=None),
        ),
        patch("soc_ai.store.investigations.session_verdicts", AsyncMock(return_value=[])),
        patch("soc_ai.agent.orchestrator.maybe_auto_ack_fp", AsyncMock(return_value=None)),
        patch("soc_ai.oracle.client.asyncio.sleep", AsyncMock()),
        _capturing_gateway(oracle_answer, bodies),
    ):
        events = [ev async for ev in investigate(ANCHOR, ctx=ctx, subject=subject)]
    return events, bodies


async def test_an_oracle_true_positive_on_a_finding_survives(settings_kratos: Settings) -> None:
    """The owner rule of 2026-10-30: the gate never overrides an Oracle true
    positive. On 2026-10-29 it reset two backed Oracle true positives on hunt
    findings to needs more info."""
    events, bodies = await _run_hunt_oracle(settings_kratos, _oracle_answer([CITED]))
    local_gate = next(e.payload for e in events if e.kind == _GATE_KEY)
    assert local_gate["downgraded_verdict"] == "needs_more_info"
    adjudication = next(e.payload for e in events if e.kind == "oracle_adjudication")
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["verdict"] == "true_positive"
    assert final["summary"].startswith(
        "[Oracle adjudicated] The source host attacked the web server."
    )
    assert _GATE_KEY not in (adjudication.get("oracle_targeted_downgrades") or {})
    # The Oracle read the change of the local gate at the start of local_summary.
    assert any("changed the verdict from a true positive to needs more info" in b for b in bodies)
    # Change E. The case names the claim of the finding the run judged.
    assert any("subject_claim" in b and "Requests to the web server" in b for b in bodies)


async def test_an_oracle_true_positive_without_evidence_on_a_finding_is_withheld(
    settings_kratos: Settings,
) -> None:
    """The control. An Oracle flip that names no evidence beyond the alert is
    still withheld, so the removal of the gate opens no flip without evidence."""
    events, _bodies = await _run_hunt_oracle(settings_kratos, _oracle_answer(None))
    adjudication = next(e.payload for e in events if e.kind == "oracle_adjudication")
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["verdict"] == "needs_more_info"
    assert adjudication.get("override_withheld") is True
    assert adjudication["oracle_verdict"] == "true_positive"


# ── A finding that cites no stored document (production, 2026-11-13) ──────────
#
# Run 01M7BHDHYD20B45HJQ2QVZ507F judged the finding "LFI returns
# /proc/self/maps with 200". The hunt stored no citation for that finding, so
# the subject held only the documents of another finding. The run fetched
# three Zeek HTTP records of the file read and cited each by id. The rule
# refused every finding with no resolved document, so the impact guard read
# "attempted" for a read that the records prove.

HTTP_SOURCE = {
    "event": {"dataset": "zeek.http"},
    "source": {"ip": SRC},
    "destination": {"ip": DST},
    "http": {"method": "GET", "uri": "/vuln.php?f=/proc/self/maps", "status_code": 200},
}
FLOW_SOURCE = {
    "event": {"dataset": "zeek.conn"},
    "source": {"ip": SRC},
    "destination": {"ip": DST},
    "connection": {"state": "SF"},
}


def _finding_with_no_document(hosts: list[str]) -> EnrichedAlertContext:
    """The subject holds the documents of another finding. The promoted
    finding cites none, and names ``hosts``."""
    enriched = _hunt_enriched([_http(ANCHOR), _http("doc-other-0001")], [])
    enriched.subject_focus_hosts = hosts
    return enriched


def test_a_finding_with_no_document_keeps_its_verdict_with_a_fetched_content_record() -> None:
    out, audit = _gate(
        _tp(PLAIN_STORY, ["ev-httprecord-001"]),
        _finding_with_no_document([SRC, DST]),
        messages=_tool_return(_hit("ev-httprecord-001", HTTP_SOURCE)),
    )
    assert out.verdict == "true_positive"
    assert audit == {}


def test_a_finding_with_no_document_keeps_the_impact_that_a_fetched_record_proves() -> None:
    from soc_ai.agent.gates import _settle_impact

    report = _tp(PLAIN_STORY, ["ev-httprecord-001"]).model_copy(update={"impact": "succeeded"})
    audit: dict[str, Any] = {}
    out = _settle_impact(
        report,
        _finding_with_no_document([SRC, DST]),
        audit,
        messages=_tool_return(_hit("ev-httprecord-001", HTTP_SOURCE)),
    )
    assert out.impact == "succeeded"
    assert audit == {}


@pytest.mark.parametrize(
    ("hosts", "citations", "source", "why"),
    [
        ([SRC, DST], ["ev-httprecord-001"], FLOW_SOURCE, "a flow record holds no content"),
        ([], ["ev-httprecord-001"], HTTP_SOURCE, "the finding names no host"),
        (["10.0.0.77"], ["ev-httprecord-001"], HTTP_SOURCE, "the record is of other hosts"),
        ([SRC, DST], ["ev-never-fetched"], HTTP_SOURCE, "no tool fetched the cited id"),
        ([SRC, DST], [ANCHOR], HTTP_SOURCE, "the anchor is a record of another finding"),
        ([SRC, DST], ["doc-other-0001"], HTTP_SOURCE, "a document of another finding"),
    ],
)
def test_a_finding_with_no_document_is_still_lowered(
    hosts: list[str], citations: list[str], source: dict[str, Any], why: str
) -> None:
    out, audit = _gate(
        _tp(PLAIN_STORY, citations),
        _finding_with_no_document(hosts),
        messages=_tool_return(_hit("ev-httprecord-001", source)),
    )
    assert out.verdict == "needs_more_info", why
    assert _GATE_KEY in audit, why


def test_a_lead_run_gets_no_hosts_and_stays_lowered_with_a_fetched_record() -> None:
    """A lead promotion has no promoted finding, so it names no focus host."""
    enriched = _hunt_enriched([_http(ANCHOR)], [])
    out, audit = _gate(
        _tp(PLAIN_STORY, ["ev-httprecord-001"]),
        enriched,
        messages=_tool_return(_hit("ev-httprecord-001", HTTP_SOURCE)),
    )
    assert enriched.subject_focus_hosts == []
    assert out.verdict == "needs_more_info"
    assert _GATE_KEY in audit


def test_the_subject_gives_the_hosts_of_the_promoted_finding_only() -> None:
    promoted = SubjectFinding(ordinal=1, title="LFI", hosts=[SRC, DST], promoted=True)
    other = SubjectFinding(ordinal=0, title="Wave", hosts=["10.0.0.77"])
    with_finding = HuntSubject(hunt_id="h1", objective="o", findings=[other, promoted])
    assert with_finding.promoted_hosts() == [SRC, DST]
    assert HuntSubject(hunt_id="h1", objective="o", findings=[other]).promoted_hosts() == []
