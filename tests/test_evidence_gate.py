"""Evidence gate: what may — and may not — unlock a settled verdict.

The hard evidence gate is the zero-tool-verdict defense: a ``true_positive`` /
``false_positive`` has to rest on something the agent actually OBSERVED this run,
or it is coerced to ``needs_more_info``.

These tests pin the boundary for a class of tool the gate had never seen before
the host dossier landed: a tool whose result is soc-ai's own INFERENCE rather
than an observation. ``t_host_dossier`` answers "I believe this is a hypervisor,
0.9, from behavioural signals" — a conclusion drawn by an earlier build job from
telemetry the host itself can influence (the name it announces over DHCP, the
banner it serves). Letting that satisfy the gate would hand the model a one-call
route to a confident verdict having investigated nothing, which is the exact
"inference presented as observation" failure the gate exists to stop.

The dossier stays fully available to the agent as CONTEXT — registered, in the
prompt, reasoned with. It just never counts as the evidence.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.agent.evidence import (
    NON_EVIDENTIAL_TOOLS,
    _loop_evidence_marker,
    count_successful_tool_calls,
)
from soc_ai.agent.gates import _downgrade_unevidenced_verdict
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext
from soc_ai.triage_models import RecommendedAction, TriageReport


class _FakeToolReturnPart:
    """Stand-in for ``pydantic_ai.messages.ToolReturnPart``."""

    def __init__(self, tool_name: str, content: Any) -> None:
        self.tool_name = tool_name
        self.content = content
        self.part_kind = "tool-return"


class _FakeMessage:
    def __init__(self, parts: list[Any]) -> None:
        self.parts = parts


def _returns(*named: tuple[str, Any]) -> list[Any]:
    """One message carrying a ``ToolReturnPart`` per ``(tool_name, content)``."""
    return [_FakeMessage([_FakeToolReturnPart(name, content) for name, content in named])]


def _dossier_result() -> dict[str, Any]:
    """A FOUND dossier, shaped exactly as ``t_host_dossier`` returns it.

    Every key here is truthy and none of them is a bookkeeping flag, so the
    generic "does this result carry discriminating data?" test says yes — which
    is precisely why the exclusion has to be keyed on the TOOL, not the shape.
    """
    return {
        "ip": "192.168.10.202",
        "found": True,
        "fields": {
            "role": {
                "value": "hypervisor",
                "source": "behaviour",
                "confidence": 0.9,
                "strength": "strong",
                "evidence": ["responds on tcp/8006 (from behaviour)"],
            },
        },
        "event_count": 3412,
        "note": "System-inferred asset context.",
    }


def _benign_enriched() -> EnrichedAlertContext:
    """Prefetch with no pivots and no IOC hits — nothing else can ground a verdict."""
    return EnrichedAlertContext(
        alert=SoAlert(
            id="dossier-gate-001",
            rule_name="GPL ICMP Destination Unreachable Port Unreachable",
            classtype="misc-activity",
            source_ip="192.0.2.1",
            destination_ip="192.168.10.202",
            severity_label="informational",
        )
    )


def test_host_dossier_is_declared_non_evidential() -> None:
    """The exclusion list is a trust boundary — pin its membership explicitly."""
    assert "t_host_dossier" in NON_EVIDENTIAL_TOOLS


def test_decode_payload_is_declared_non_evidential() -> None:
    """t_decode_payload is in-process compute over model-supplied bytes —
    inference, not observation — so it must not, on its own, count as an
    investigation (it would otherwise let the Oracle flip a verdict class by
    decoding a string it invented, with zero grid access)."""
    assert "t_decode_payload" in NON_EVIDENTIAL_TOOLS


def test_decode_payload_return_alone_is_not_gathered_evidence() -> None:
    """A data-bearing decode result is compute over bytes the model chose, not an
    observation — it must not count toward the hard evidence / override gate."""
    decoded = {
        "encoding_used": "hex",
        "decoded_bytes": 5,
        "printable_ratio": 1.0,
        "preview": "Hello",
        "strings": ["Hello"],
    }
    assert count_successful_tool_calls(_returns(("t_decode_payload", decoded))) == 0


def test_dossier_return_alone_is_not_gathered_evidence() -> None:
    """A found dossier is a CONCLUSION about the host, not an observation of it."""
    assert count_successful_tool_calls(_returns(("t_host_dossier", _dossier_result()))) == 0


def test_absent_dossier_is_not_gathered_evidence_either() -> None:
    """``found: false`` carries a truthy ``note``; it still observed nothing."""
    absent = {
        "ip": "8.8.8.8",
        "found": False,
        "reason": "no dossier — the network sweep has no record of this address",
        "note": "Absence is an answer, not evidence.",
    }
    assert count_successful_tool_calls(_returns(("t_host_dossier", absent))) == 0


def test_dossier_plus_a_real_tool_still_counts_the_real_tool() -> None:
    """Excluding the dossier must not blind the gate to the observation beside it."""
    msgs = _returns(
        ("t_host_dossier", _dossier_result()),
        ("t_query_zeek_logs", {"total": 2, "hits": [{"_id": "z1"}, {"_id": "z2"}]}),
    )
    assert count_successful_tool_calls(msgs) == 1


def test_loop_marker_is_not_earned_by_a_dossier_call() -> None:
    """``investigation_loop`` exempts a verdict from the gate AND from GATE A."""
    assert _loop_evidence_marker(True, _returns(("t_host_dossier", _dossier_result()))) is None
    assert (
        _loop_evidence_marker(True, _returns(("t_enrich_ip", {"asn": {"number": 15169}})))
        == "investigation_loop"
    )


@pytest.mark.parametrize("verdict", ["true_positive", "false_positive"])
def test_evidence_gate_downgrades_a_dossier_only_verdict(verdict: str) -> None:
    """End-to-end: reading the dossier and nothing else does not settle an alert."""
    report = TriageReport(
        verdict=verdict,
        confidence=0.9,
        summary="The dossier says this box is a hypervisor, so I am sure.",
        citations=["t_host_dossier"],
        recommended_actions=[
            RecommendedAction(tool_name="escalate_to_case", tool_args={}, rationale="x")
        ],
    )
    audit: dict[str, Any] = {}

    out = _downgrade_unevidenced_verdict(
        report,
        _benign_enriched(),
        None,
        audit,
        targeted_messages=_returns(("t_host_dossier", _dossier_result())),
        targeted_tool_called=None,
    )

    assert out.verdict == "needs_more_info"
    assert out.confidence <= 0.4
    assert out.recommended_actions == []
    assert audit["evidence_gate_downgrade"]["successful_tool_calls"] == 0


def test_evidence_gate_keeps_a_verdict_that_also_ran_a_real_tool() -> None:
    """The gate must still be satisfied by ordinary observational tools."""
    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="Interactive SSH into a hypervisor, confirmed in Zeek.",
        citations=["t_query_zeek_logs"],
    )
    audit: dict[str, Any] = {}

    out = _downgrade_unevidenced_verdict(
        report,
        _benign_enriched(),
        None,
        audit,
        targeted_messages=_returns(
            ("t_host_dossier", _dossier_result()),
            ("t_query_zeek_logs", {"total": 1, "hits": [{"_id": "z1"}]}),
        ),
        targeted_tool_called=None,
    )

    assert out.verdict == "true_positive"
    assert "evidence_gate_downgrade" not in audit


# ---------------------------------------------------------------------------
# A decision template is not a substitute for retrieval
# ---------------------------------------------------------------------------
#
# The gate's template exemption was keyed on confidence: any benign candidate at
# 0.8 or above counted as "strong, rule-grounded" and settled the alert. On the
# production instance that let `clean_internal_traffic` close 13 alerts at
# 0.85-0.90 with zero tool calls over nine days, nine of them the same
# exploitation-attempt signature, and auto-acknowledge wrote every one of them
# back to Security Onion. The exemption is keyed on the template's authority
# now, which is a statement about its GROUNDS rather than about how sure it
# sounds.


def _ognl_enriched() -> EnrichedAlertContext:
    """The production alert, reduced to what the gate reads.

    An exploitation-attempt signature on an internal HTTP service. Suricata's
    own category for it is the benign-sounding "Misc activity", the signature
    severity is Minor, and the rule name carries no malware word, so every
    existing guard reads it as routine.
    """
    return EnrichedAlertContext(
        alert=SoAlert(
            id="ognl-gate-001",
            rule_name="ET HUNTING Potential Forced OGNL Evaluation - HTTP Body",
            classtype="Misc activity",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            severity_label="low",
            severity_score=1,
        )
    )


def _candidate(template_id: str, authority: str) -> Any:
    from soc_ai.agent.decision_templates import CandidateVerdict

    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.rule_name"],
        template_id=template_id,
        rationale="x",
        authority=authority,  # type: ignore[arg-type]
    )


def test_a_provisional_template_does_not_settle_a_zero_tool_verdict() -> None:
    """The production defect, at the gate that was supposed to stop it."""
    report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Both endpoints are internal and nothing is on a blocklist.",
        citations=[],
    )
    audit: dict[str, Any] = {}

    out = _downgrade_unevidenced_verdict(
        report,
        _ognl_enriched(),
        _candidate("clean_internal_traffic", "provisional"),
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )

    assert out.verdict == "needs_more_info"
    assert out.confidence <= 0.4
    assert audit["evidence_gate_downgrade"]["successful_tool_calls"] == 0


def test_a_dispositive_template_still_settles_a_zero_tool_verdict() -> None:
    """NEGATIVE CONTROL. Routine traffic a template legitimately disposes of
    must still cost nothing, or every triage on the grid gets an investigation
    it did not need."""
    report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="STUN binding request with a clean Zeek conn.",
        citations=["alert.rule_name=ET INFO STUN Binding Request"],
    )
    audit: dict[str, Any] = {}

    out = _downgrade_unevidenced_verdict(
        report,
        _benign_enriched(),
        _candidate("stun_quic_keepalive", "dispositive"),
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )

    assert out.verdict == "false_positive"
    assert "evidence_gate_downgrade" not in audit


# ---------------------------------------------------------------------------
# A template that settles an alert has to say what it settled it on
# ---------------------------------------------------------------------------


def test_a_dispositive_template_does_not_settle_a_verdict_that_cites_nothing() -> None:
    """Zero citations AND zero retrieval is the state with nothing in it. The
    template exemption exists so routine traffic can settle on the template's
    own grounds, which means those grounds have to be on the record."""
    report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="STUN binding request with a clean Zeek conn.",
        citations=[],
    )
    audit: dict[str, Any] = {}

    out = _downgrade_unevidenced_verdict(
        report,
        _benign_enriched(),
        _candidate("stun_quic_keepalive", "dispositive"),
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
        resolved_citations=0,
    )

    assert out.verdict == "needs_more_info"
    assert audit["evidence_gate_downgrade"]["resolved_citations"] == 0


def test_a_dispositive_template_lends_its_grounds_to_an_uncited_report() -> None:
    """Which is why the report almost never reaches the gate uncited. The
    synthesizer emits no citations on most runs (41 of the 47 production runs
    that DID call tools emitted none either), so a dispositive template's own
    cited_evidence is adopted as the report's citations. Those are code-set
    paths into the retrieved alert, not model prose, and the analyst sees the
    reason the alert was closed instead of an empty list."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="STUN binding request with a clean Zeek conn.",
        citations=[],
    )
    out, audit = _synth_first_post_validate(
        report,
        _benign_enriched(),
        _candidate("stun_quic_keepalive", "dispositive"),
    )

    assert out.verdict == "false_positive"
    assert out.citations == ["alert.rule_name"]
    assert audit["template_grounds_adopted"]["template_id"] == "stun_quic_keepalive"
    assert "evidence_gate_downgrade" not in audit


def test_a_provisional_template_does_not_lend_its_grounds() -> None:
    """The grounds are the thing in dispute. clean_internal_traffic citing
    "both endpoints internal" would launder locality into the citation list."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="Both endpoints are internal.",
        citations=[],
    )
    out, audit = _synth_first_post_validate(
        report,
        _ognl_enriched(),
        _candidate("clean_internal_traffic", "provisional"),
    )

    assert out.citations == []
    assert "template_grounds_adopted" not in audit
    assert out.verdict == "needs_more_info"


def test_grounds_are_not_adopted_over_the_model_s_own_citations() -> None:
    """NEGATIVE CONTROL. Adoption fills an empty list; it never overwrites."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="STUN binding request.",
        citations=["alert.severity_label"],
    )
    out, audit = _synth_first_post_validate(
        report,
        _benign_enriched(),
        _candidate("stun_quic_keepalive", "dispositive"),
    )

    assert out.citations == ["alert.severity_label"]
    assert "template_grounds_adopted" not in audit


# ---------------------------------------------------------------------------
# The investigator's evidence is thrown away at the handoff
# ---------------------------------------------------------------------------


class _FakeToolCallPart:
    """Stand-in for ``pydantic_ai.messages.ToolCallPart`` — carries ``args``,
    which is what ``_tool_was_invoked`` discriminates on."""

    def __init__(self, tool_name: str, args: Any = None) -> None:
        self.tool_name = tool_name
        self.args = args or {}
        self.part_kind = "tool-call"


def _loop_history(*tool_names: str) -> list[Any]:
    """A message history in which each named tool was really called."""
    return [_FakeMessage([_FakeToolCallPart(n) for n in tool_names])]


# What the investigator writes: a fact plus the thing that supports it. These
# are the shapes the deployed instance actually produces — a tool reference and
# a typed path into the retrieved alert.
_REAL_BULLETS = [
    "Rule content matches only the APT-HTTP user-agent header (tool t_get_rule_content)",
    "Alert metadata says Informational (path alert.rule_name)",
]


def test_the_investigators_evidence_is_carried_into_an_uncited_report() -> None:
    """The failing case. The synthesizer is handed a transcript listing eight or
    nine grounded findings and writes a report citing none of them: on the
    deployed instance 1,187 of 3,379 runs, and 713 of those uncited reports were
    then acknowledged in Security Onion as verdicts resting on nothing."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="Ordinary package management.",
        citations=[],
    )
    out, audit = _synth_first_post_validate(
        report,
        _benign_enriched(),
        None,
        investigator_evidence=_REAL_BULLETS,
        targeted_messages=_loop_history("t_get_rule_content"),
        targeted_tool_called="investigation_loop",
    )

    assert out.citations == _REAL_BULLETS
    assert audit["investigator_evidence_carried"]["count"] == 2
    assert audit["citation_validation"]["vacuous"] is False


def test_the_carried_evidence_is_measured_not_assumed() -> None:
    """The carry must not manufacture coverage. A bullet naming a tool the loop
    never called resolves no better than a fabricated citation would, and the
    coverage number says so."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(verdict="false_positive", confidence=0.85, summary="x", citations=[])
    out, audit = _synth_first_post_validate(
        report,
        _benign_enriched(),
        None,
        investigator_evidence=["Checked the flow (tool t_query_zeek_logs)"],
        targeted_messages=_loop_history("t_get_rule_content"),
        targeted_tool_called="investigation_loop",
    )

    assert out.citations == ["Checked the flow (tool t_query_zeek_logs)"]
    assert audit["citation_validation"]["coverage_ratio"] == 0.0


def test_a_tool_bullet_cannot_resolve_itself() -> None:
    """NEGATIVE CONTROL, and the one that matters most. Without the loop's real
    message history ``_tool_was_invoked`` falls back to a substring match
    against the transcript's own evidence text — so a ``(tool X)`` bullet
    carried out of that transcript would resolve ITSELF, and the citation gate
    would be grading its own homework. Nothing is carried when the history is
    not there to judge it against."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(verdict="false_positive", confidence=0.85, summary="x", citations=[])
    out, audit = _synth_first_post_validate(
        report,
        _benign_enriched(),
        None,
        investigator_evidence=["Ran the check (tool t_query_zeek_logs)"],
        targeted_messages=None,
    )

    assert out.citations == []
    assert "investigator_evidence_carried" not in audit


def test_the_models_own_citations_are_never_overwritten_by_the_carry() -> None:
    """NEGATIVE CONTROL. The carry fills an empty list; it never pads one."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="x",
        citations=["alert.severity_label"],
    )
    out, audit = _synth_first_post_validate(
        report,
        _benign_enriched(),
        None,
        investigator_evidence=_REAL_BULLETS,
        targeted_messages=_loop_history("t_get_rule_content"),
    )

    assert out.citations == ["alert.severity_label"]
    assert "investigator_evidence_carried" not in audit


def test_an_empty_transcript_carries_nothing() -> None:
    """A loop that gathered nothing has nothing to lend, and a blank string is
    not a citation."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(verdict="false_positive", confidence=0.85, summary="x", citations=[])
    for evidence in ([], ["   "], None):
        out, audit = _synth_first_post_validate(
            report,
            _benign_enriched(),
            None,
            investigator_evidence=evidence,
            targeted_messages=_loop_history("t_get_rule_content"),
        )
        assert out.citations == []
        assert "investigator_evidence_carried" not in audit


def test_the_carry_outranks_a_templates_canned_grounds() -> None:
    """Where both are available, the run's own retrieval answers "what is this
    verdict resting on" better than two code-set sentences about the alert's
    shape."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(verdict="false_positive", confidence=0.85, summary="x", citations=[])
    out, audit = _synth_first_post_validate(
        report,
        _benign_enriched(),
        _candidate("stun_quic_keepalive", "dispositive"),
        investigator_evidence=_REAL_BULLETS,
        targeted_messages=_loop_history("t_get_rule_content"),
    )

    assert out.citations == _REAL_BULLETS
    assert "template_grounds_adopted" not in audit


def test_grounds_are_not_adopted_when_the_synth_overrode_the_template() -> None:
    """NEGATIVE CONTROL. A synthesizer that escalated past a benign template is
    not grounded by it, so it must not inherit its citations either."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="This is not a keepalive.",
        citations=[],
    )
    out, audit = _synth_first_post_validate(
        report,
        _benign_enriched(),
        _candidate("stun_quic_keepalive", "dispositive"),
    )

    assert out.citations == []
    assert "template_grounds_adopted" not in audit
