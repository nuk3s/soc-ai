"""A triage may not close benign a detection the catalog says has no baseline.

Measured on the range: the same real DCSync alert triaged false_positive 0.62
on 2026-09-08 and true_positive 0.75 on 2026-09-09, both runs grounded with
twelve tool calls. The verdict depended on which way the model leaned. The
decoy already had a gate for exactly this property; this is that gate for every
spec that declares it.
"""

from __future__ import annotations

from typing import Any

from soc_ai.agent.gates import (
    _refuse_benign_decoy_verdict,
    _refuse_benign_verdict_without_baseline,
)
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext
from soc_ai.triage_models import TriageReport

_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
_RULE = "Active Directory Replication from Non Machine Account"


def _dcsync_alert(user: str = "localuser") -> SoAlert:
    """The Sigma alert as triage saw it, raw document included."""
    event = {
        "event": {"code": "4662"},
        "winlog": {"event_data": {"Properties": f"%%7688 {{{_GUID}}}", "SubjectUserName": user}},
    }
    return SoAlert(
        id="dcsync-001",
        rule_name=_RULE,
        event_dataset="sigma.alert",
        host_name="dc-01",
        raw={"rule": {"name": _RULE}, "event_data": event},
    )


def _ordinary_alert() -> SoAlert:
    return SoAlert(
        id="ordinary-001",
        rule_name="ET INFO Microsoft Connection Test",
        event_dataset="suricata.alert",
        source_ip="10.0.0.5",
        destination_ip="10.0.0.9",
        raw={
            "event": {"dataset": "suricata.alert"},
            "rule": {"name": "ET INFO Microsoft Connection Test"},
        },
    )


def _ctx(alert: SoAlert) -> EnrichedAlertContext:
    return EnrichedAlertContext(alert=alert)


def _benign_on_a_rate() -> TriageReport:
    """The 2026-09-08 verdict's shape: closed on how often the account replicates."""
    return TriageReport(
        verdict="false_positive",
        confidence=0.62,
        summary=(
            "localuser has requested directory replication 26 times in 24h from the "
            "same host, a steady pattern consistent with a sync job."
        ),
        citations=["alert.rule_name", "tool t_rule_prevalence:total_fires"],
        recommended_actions=[],
    )


def test_the_gate_refuses_the_measured_verdict() -> None:
    """THE CASE."""
    audit: dict[str, Any] = {}
    report = _refuse_benign_verdict_without_baseline(
        _benign_on_a_rate(), _ctx(_dcsync_alert()), audit
    )

    assert report.verdict == "needs_more_info"
    assert report.confidence <= 0.4
    assert report.recommended_actions == []
    refused = audit["no_baseline_verdict_refused"]
    assert refused["spec_id"] == "identity-4662-dcsync-nonmachine"
    assert refused["original_verdict"] == "false_positive"


def test_the_note_hands_the_reader_the_spec_s_own_exceptions() -> None:
    """The refusal is not a dead end: the spec's false-positive list is exactly
    the set of identities a human can confirm, so it travels in the note."""
    audit: dict[str, Any] = {}
    report = _refuse_benign_verdict_without_baseline(
        _benign_on_a_rate(), _ctx(_dcsync_alert()), audit
    )
    assert report.validator_note is not None
    assert "no benign population" in report.validator_note
    assert "Azure AD Connect" in report.validator_note


def test_the_gate_leaves_an_ordinary_alert_alone() -> None:
    """NEGATIVE CONTROL. Same verdict, same reasoning, a detection with a baseline."""
    audit: dict[str, Any] = {}
    report = _refuse_benign_verdict_without_baseline(
        _benign_on_a_rate(), _ctx(_ordinary_alert()), audit
    )
    assert report.verdict == "false_positive"
    assert report.confidence == 0.62
    assert audit == {}


def test_the_gate_leaves_a_machine_account_alone() -> None:
    """NEGATIVE CONTROL. The spec's own exclusion: a DC replicating under its
    machine account is not the detection, so it keeps whatever verdict it earned."""
    audit: dict[str, Any] = {}
    report = _refuse_benign_verdict_without_baseline(
        _benign_on_a_rate(), _ctx(_dcsync_alert(user="DC-01$")), audit
    )
    assert report.verdict == "false_positive"
    assert audit == {}


def test_the_gate_refuses_closure_not_escalation() -> None:
    audit: dict[str, Any] = {}
    escalated = _benign_on_a_rate().model_copy(
        update={"verdict": "true_positive", "confidence": 0.8}
    )
    report = _refuse_benign_verdict_without_baseline(escalated, _ctx(_dcsync_alert()), audit)
    assert report.verdict == "true_positive"
    assert report.confidence == 0.8
    assert audit == {}


def test_the_gate_leaves_an_unsettled_verdict_alone() -> None:
    audit: dict[str, Any] = {}
    unsettled = _benign_on_a_rate().model_copy(
        update={"verdict": "needs_more_info", "confidence": 0.5}
    )
    report = _refuse_benign_verdict_without_baseline(unsettled, _ctx(_dcsync_alert()), audit)
    assert report.verdict == "needs_more_info"
    assert audit == {}


def test_the_gate_survives_a_context_it_cannot_read() -> None:
    audit: dict[str, Any] = {}
    report = _refuse_benign_verdict_without_baseline(_benign_on_a_rate(), object(), audit)
    assert report.verdict == "false_positive"
    assert audit == {}


def test_the_decoy_path_is_unchanged_underneath() -> None:
    """The general gate calls the decoy gate first, so a decoy alert still
    produces the decoy audit key its own tests assert on."""
    decoy = SoAlert(
        id="decoy-001",
        event_dataset="opencanary.events",
        event_module="opencanary",
        source_ip="10.0.0.254",
        destination_ip="10.0.0.31",
        destination_port=22,
    )
    audit: dict[str, Any] = {}
    report = _refuse_benign_verdict_without_baseline(_benign_on_a_rate(), _ctx(decoy), audit)
    assert report.verdict == "needs_more_info"
    assert "decoy_benign_verdict_refused" in audit
    assert "no_baseline_verdict_refused" not in audit
    # And the decoy gate on its own still behaves exactly as before.
    assert (
        _refuse_benign_decoy_verdict(_benign_on_a_rate(), _ctx(decoy), {}).verdict
        == "needs_more_info"
    )


# ---------------------------------------------------------------------------
# The whole chain — a gate that exists but is not wired is the failure mode
# this codebase keeps finding, so the wiring gets a test of its own.
# ---------------------------------------------------------------------------


class _ToolReturn:
    def __init__(self, tool_name: str, content: Any) -> None:
        self.tool_name = tool_name
        self.content = content
        self.part_kind = "tool-return"


class _Message:
    def __init__(self, parts: list[Any]) -> None:
        self.parts = parts


def _grounded_investigation() -> list[Any]:
    """A run that really did query the grid, so no evidence gate intervenes and
    the only thing between the verdict and the report is this gate."""
    return [
        _Message(
            [
                _ToolReturn(
                    "t_rule_prevalence",
                    {"total_fires": 26, "provenance": "live", "searched_datasets": ["sigma.alert"]},
                )
            ]
        )
    ]


def test_the_full_validator_chain_refuses_the_measured_verdict() -> None:
    from soc_ai.agent.gates import _synth_first_post_validate

    report, audit = _synth_first_post_validate(
        _benign_on_a_rate(),
        _ctx(_dcsync_alert()),
        None,
        targeted_messages=_grounded_investigation(),
    )
    assert report.verdict == "needs_more_info"
    assert audit["no_baseline_verdict_refused"]["spec_id"] == "identity-4662-dcsync-nonmachine"


def test_the_full_validator_chain_still_settles_an_ordinary_alert() -> None:
    """NEGATIVE CONTROL for the chain: a gate wired so broadly it refuses every
    benign verdict in the queue would pass the test above."""
    from soc_ai.agent.gates import _synth_first_post_validate

    report, audit = _synth_first_post_validate(
        _benign_on_a_rate(),
        _ctx(_ordinary_alert()),
        None,
        targeted_messages=_grounded_investigation(),
    )
    assert report.verdict == "false_positive"
    assert "no_baseline_verdict_refused" not in audit
