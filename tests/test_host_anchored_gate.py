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
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp(citations=[ANCHOR, "doc-dns-00001", "doc-icmp-0001", "doc-lead-0001"]),
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
    assert out.summary == f"{_HOST_ANCHORED_TP_LEAD} {original}"
    assert out.validator_note == "An earlier gate wrote this.\n" + _host_anchored_tp_note(False)
    assert audit[_GATE_KEY]["reason"] == _host_anchored_tp_reason(False)
    assert "original_summary" not in audit[_GATE_KEY]


def test_the_row_headline_states_the_change() -> None:
    """The first sentence of the summary is the row headline and the digest of
    the session prior (recorder._first_rationale)."""
    out = _downgrade_ungrounded_host_anchored_tp(
        _tp("BPFDoor C2 confirmed by host profile.", ["alert.rule_name"]),
        _make_vpn_icmp_enriched(),
        {},
    )
    assert (
        _first_rationale(out.model_dump(mode="json"))
        == "soc-ai changed the verdict from a true positive to needs more info"
    )


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
    local = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary=NO_EVIDENCE,
        citations=[ANCHOR, CITED],
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
