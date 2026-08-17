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
