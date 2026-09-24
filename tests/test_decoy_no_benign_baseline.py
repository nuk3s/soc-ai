"""A decoy has no benign population, so no volume baseline can clear one.

Measured defect. An OpenCanary decoy recorded an inbound SSH interaction from an
internal router and triage closed it false_positive at 0.9 on this reasoning:
"This is routine east-west management traffic: over the prior 72h the router
made 358 SSH connections to internal hosts (111 to one host)."

Checked against the grid, the volume claim was built from periodic flow records
rather than sessions, and the decoy's own log — the authoritative record of what
touched it — held two documents from that source, ever, both of them this
interaction. That half is fixed separately, in the tool that handed over a count
without saying what it counted (``tests/test_oql_count_composition.py``).

This file is about the route rather than the number. The catalog spec for this
detection says in its own text that nothing has a legitimate reason to talk to a
decoy: it advertises services that exist only to be touched, it is in no DNS
zone, and no real workload routes to it, so unlike every other detection there
is no benign population to separate from and therefore no threshold, no baseline
and no tuning. Triage reasoned in the opposite direction and built a baseline.
That route generalises to a miss, because "the router talks to this host a lot,
so a decoy hit from the router is routine" auto-closes an intruder pivoting
through the router, which is the case a decoy exists to catch. A defensible
answer reached by a route that also produces the wrong answer is not triage.

Correcting the number alone would not have helped. A second measured run on the
same alert closed it false_positive at 0.85 by a different argument — it named
the decoy, noted the absence of a credential attempt, and still concluded
routine internal east-west traffic. So the refusal here is on the verdict class,
not on the prose: what is unsafe is closure, whatever carries it.

The decision template got there first. ``clean_internal_traffic`` seeded
false_positive at 0.85 before a single tool ran, on the sole ground that both
endpoints were internal — which a decoy interaction always is, since the decoy
sits inside the network it protects.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.agent.decision_templates import _alert_signals_decoy, match_decision_template
from soc_ai.agent.gates import _refuse_benign_decoy_verdict, _synth_first_post_validate
from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext
from soc_ai.triage_models import TriageReport

# ─────────────────────────────────────────────────────────────────────────────
# Recognising a decoy
# ─────────────────────────────────────────────────────────────────────────────


def _decoy_alert() -> SoAlert:
    """The alert as triage saw it. OpenCanary hits carry no ``rule.name``."""
    return SoAlert(
        id="decoy-001",
        event_dataset="opencanary.events",
        event_module="opencanary",
        event_category="intrusion_detection",
        source_ip="10.0.0.254",
        source_port=40160,
        destination_ip="10.0.0.31",
        destination_port=22,
        host_name="decoy-host-01",
    )


def _ordinary_internal_alert() -> SoAlert:
    """The negative control's alert: same locality, same ports, no decoy."""
    return SoAlert(
        id="ordinary-001",
        rule_name="GPL MISC SSH banner observed",
        classtype="misc-activity",
        event_dataset="suricata.alerts",
        event_module="suricata",
        source_ip="10.0.0.254",
        source_port=40160,
        destination_ip="10.0.0.31",
        destination_port=22,
        severity_label="informational",
    )


def test_a_decoy_alert_is_recognised_from_its_dataset() -> None:
    assert _alert_signals_decoy(_decoy_alert()) is True


def test_an_ordinary_internal_alert_is_not_a_decoy() -> None:
    """NEGATIVE CONTROL for the predicate itself."""
    assert _alert_signals_decoy(_ordinary_internal_alert()) is False


@pytest.mark.parametrize(
    "rule_name",
    [
        "Honeypot interaction observed",
        "Canarytoken triggered",
        "DECOY service touched",
    ],
)
def test_a_decoy_is_recognised_from_its_rule_name_too(rule_name: str) -> None:
    """Not every deployment ships OpenCanary; the name carries the class."""
    assert _alert_signals_decoy(SoAlert(id="d", rule_name=rule_name)) is True


@pytest.mark.parametrize(
    "rule_name",
    [
        "ET POLICY Vulnerable Java Version",
        "GPL ICMP Echo Reply",
        "Suspicious DNS query for canaryislands.example",
    ],
)
def test_the_decoy_predicate_does_not_grab_ordinary_rules(rule_name: str) -> None:
    """NEGATIVE CONTROL. A token buried in a hostname is not a decoy detection."""
    assert _alert_signals_decoy(SoAlert(id="d", rule_name=rule_name)) is False


# ─────────────────────────────────────────────────────────────────────────────
# The auto-acknowledge guard, which is the one that writes to the grid
# ─────────────────────────────────────────────────────────────────────────────
#
# The verdict gate above only reaches an alert that was itself investigated. The
# volume of unattended acknowledgements does not come from there: it comes from
# the inherited path, which acks an alert on a verdict produced for a DIFFERENT
# alert in the same cluster. On that path ``_is_high_stakes_alert`` is the only
# thing consulted about the alert being written to, and an acknowledged honeypot
# hit is a silenced intrusion.


def test_the_four_older_arms_are_all_blind_to_a_honeypot_document() -> None:
    """Why the arm has to exist, asserted rather than described.

    Every arm that predates this one reads a field OpenCanary does not write.
    If a future change makes one of them fire on a decoy, this test says so, and
    the arm below stops being load-bearing — which is worth knowing either way.
    """
    from soc_ai.agent.classifier import AlertClass, classify_alert, normalize_classtype
    from soc_ai.agent.decision_templates import _ATTACK_CLASSTYPES, _alert_signals_malware

    alert = _decoy_alert()

    assert alert.classtype is None, "a honeypot hit is not a Suricata signature"
    assert alert.rule_name is None, "OpenCanary hits carry no rule.name"
    assert alert.severity_label is None and alert.severity_score is None

    assert classify_alert(alert) not in (AlertClass.EXPLOIT_ATTEMPT, AlertClass.POST_COMPROMISE)
    assert normalize_classtype(alert.classtype) not in _ATTACK_CLASSTYPES
    assert _alert_signals_malware(alert) is False


def test_a_honeypot_hit_is_too_high_stakes_to_auto_acknowledge() -> None:
    """The defect. Nothing has a legitimate reason to touch a decoy, so there is
    no benign population for an unattended ack to be drawn from."""
    from soc_ai.agent.orchestrator import _is_high_stakes_alert

    assert _is_high_stakes_alert(_decoy_alert()) is True


def test_an_ordinary_low_severity_alert_is_still_auto_acknowledgeable() -> None:
    """NEGATIVE CONTROL. A guard that refused everything would pass the test
    above and destroy the feature — auto-ack exists to clear the benign queue."""
    from soc_ai.agent.orchestrator import _is_high_stakes_alert

    ordinary = _ordinary_internal_alert().model_copy(update={"severity_label": "low"})
    assert _is_high_stakes_alert(ordinary) is False


# ─────────────────────────────────────────────────────────────────────────────
# The template must not pre-seed benign on a decoy
# ─────────────────────────────────────────────────────────────────────────────


def _ctx(alert: SoAlert) -> EnrichedAlertContext:
    return EnrichedAlertContext(alert=alert)


def test_clean_internal_traffic_does_not_anchor_a_decoy_benign() -> None:
    """Locality says nothing about a host that sits inside the network it watches."""
    candidate = match_decision_template(_ctx(_decoy_alert()))
    assert candidate is None or candidate.verdict != "false_positive"


def test_clean_internal_traffic_still_anchors_ordinary_internal_traffic() -> None:
    """NEGATIVE CONTROL. The guard must not cost the template its real job."""
    candidate = match_decision_template(_ctx(_ordinary_internal_alert()))
    assert candidate is not None
    assert candidate.template_id == "clean_internal_traffic"
    assert candidate.verdict == "false_positive"
    assert candidate.confidence == 0.85


# ─────────────────────────────────────────────────────────────────────────────
# The gate
# ─────────────────────────────────────────────────────────────────────────────


class _FakeToolReturnPart:
    def __init__(self, tool_name: str, content: Any) -> None:
        self.tool_name = tool_name
        self.content = content
        self.part_kind = "tool-return"


class _FakeMessage:
    def __init__(self, parts: list[Any]) -> None:
        self.parts = parts


def _real_tool_evidence() -> list[Any]:
    """A genuine, successful investigation — the run really did query the grid.

    This is what makes the new gate necessary rather than redundant. Every
    existing evidence gate is satisfied here, because evidence WAS gathered; it
    simply did not support the conclusion drawn from it. A gate keyed on whether
    the agent looked cannot catch an agent that looked and then argued backwards.
    """
    return [
        _FakeMessage(
            [
                _FakeToolReturnPart(
                    "t_query_events_oql",
                    {"total": 358, "hits": [], "aggregations": {"by_destination_ip": {}}},
                )
            ]
        )
    ]


def _the_measured_report() -> TriageReport:
    """The verdict the live run produced, reasoning included."""
    return TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary=(
            "This is routine east-west management traffic: over the prior 72h the router "
            "made 358 SSH connections to internal hosts (111 to one host)."
        ),
        citations=["alert.source_ip", "alert.destination_ip"],
        recommended_actions=[],
    )


def test_the_gate_refuses_the_measured_verdict() -> None:
    """THE CASE. false_positive 0.9 on a decoy, carried by a volume baseline."""
    audit: dict[str, Any] = {}
    report = _refuse_benign_decoy_verdict(_the_measured_report(), _ctx(_decoy_alert()), audit)

    assert report.verdict == "needs_more_info"
    assert report.confidence <= 0.4
    assert report.recommended_actions == []
    assert "decoy_benign_verdict_refused" in audit


def test_the_gate_refuses_the_second_run_s_different_argument_too() -> None:
    """The second measured run reached the same close without a volume claim.

    It named the decoy, cited the absence of a credential attempt and called the
    interaction routine. A gate reading the prose for baseline language would
    have let this through, which is why the refusal is on the verdict class.
    """
    audit: dict[str, Any] = {}
    other_route = _the_measured_report().model_copy(
        update={
            "confidence": 0.85,
            "summary": (
                "The honeypot recorded an SSH banner exchange but no authentication "
                "attempt, both endpoints are internal, and no inbound session drove "
                "the source, so this is routine internal east-west traffic."
            ),
        }
    )
    report = _refuse_benign_decoy_verdict(other_route, _ctx(_decoy_alert()), audit)

    assert report.verdict == "needs_more_info"
    assert "decoy_benign_verdict_refused" in audit


def test_the_gate_leaves_ordinary_internal_traffic_alone() -> None:
    """NEGATIVE CONTROL. Identical verdict, identical reasoning, no decoy.

    A gate firing here would be refusing volume baselines everywhere, which is
    not the finding and would wreck triage on the rest of the queue.
    """
    audit: dict[str, Any] = {}
    report = _refuse_benign_decoy_verdict(
        _the_measured_report(), _ctx(_ordinary_internal_alert()), audit
    )

    assert report.verdict == "false_positive"
    assert report.confidence == 0.9
    assert audit == {}


def test_the_gate_leaves_an_escalated_decoy_alone() -> None:
    """NEGATIVE CONTROL. The gate refuses closure, not escalation."""
    audit: dict[str, Any] = {}
    escalated = _the_measured_report().model_copy(
        update={"verdict": "true_positive", "confidence": 0.8}
    )
    report = _refuse_benign_decoy_verdict(escalated, _ctx(_decoy_alert()), audit)

    assert report.verdict == "true_positive"
    assert report.confidence == 0.8
    assert audit == {}


def test_the_gate_leaves_an_unsettled_decoy_alone() -> None:
    """NEGATIVE CONTROL. needs_more_info is already where the gate would land it."""
    audit: dict[str, Any] = {}
    unsettled = _the_measured_report().model_copy(
        update={"verdict": "needs_more_info", "confidence": 0.5}
    )
    report = _refuse_benign_decoy_verdict(unsettled, _ctx(_decoy_alert()), audit)

    assert report.verdict == "needs_more_info"
    assert audit == {}


def test_the_gate_survives_a_context_it_cannot_read() -> None:
    """A gate that raises on an odd context takes the whole investigation down."""
    audit: dict[str, Any] = {}
    report = _refuse_benign_decoy_verdict(_the_measured_report(), object(), audit)

    assert report.verdict == "false_positive"
    assert audit == {}


# ─────────────────────────────────────────────────────────────────────────────
# The whole chain, which is what actually shipped the wrong verdict
# ─────────────────────────────────────────────────────────────────────────────


def test_the_full_validator_chain_refuses_the_measured_verdict() -> None:
    """End to end, with real tool evidence so no pre-existing gate intervenes."""
    report, audit = _synth_first_post_validate(
        _the_measured_report(),
        _ctx(_decoy_alert()),
        None,
        targeted_messages=_real_tool_evidence(),
    )

    assert report.verdict == "needs_more_info"
    assert "decoy_benign_verdict_refused" in audit


def test_the_full_validator_chain_still_settles_ordinary_internal_traffic() -> None:
    """NEGATIVE CONTROL for the chain. The same inputs minus the decoy settle FP.

    This is the test that catches a gate wired in so broadly it refuses every
    benign verdict in the queue.
    """
    report, audit = _synth_first_post_validate(
        _the_measured_report(),
        _ctx(_ordinary_internal_alert()),
        None,
        targeted_messages=_real_tool_evidence(),
    )

    assert report.verdict == "false_positive"
    assert "decoy_benign_verdict_refused" not in audit


# ─────────────────────────────────────────────────────────────────────────────
# The Oracle path, which the local refusal routes the case straight into
# ─────────────────────────────────────────────────────────────────────────────


def _decoy_enriched(alert_id: str) -> EnrichedAlertContext:
    return _ctx(_decoy_alert().model_copy(update={"id": alert_id}))


def _ordinary_enriched(alert_id: str) -> EnrichedAlertContext:
    return _ctx(_ordinary_internal_alert().model_copy(update={"id": alert_id}))


async def _run_with_oracle(
    settings: Settings,
    enriched: EnrichedAlertContext,
    oracle_verdict: str,
) -> list[Any]:
    """Drive a full investigation whose Oracle returns ``oracle_verdict``.

    The local synth is scripted unsure so the run escalates on the confidence
    trigger, which is the route a refused decoy actually takes: the local gate
    caps it at 0.4, below ``oracle_escalate_below_confidence``.
    """
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import investigate
    from soc_ai.oracle.client import OracleResult

    settings.investigate_when_unsure = False
    settings.oracle_enabled = True
    settings.oracle_escalate_below_confidence = 0.6

    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    ctx = InvestigationContext(settings=settings, auth=AsyncMock(), elastic=elastic)

    local = TriageReport(
        verdict="needs_more_info",
        confidence=0.3,
        summary="Local model is unsure.",
        citations=["alert.event_dataset"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    oracle_result = OracleResult(
        report=TriageReport(
            verdict=oracle_verdict,  # type: ignore[arg-type]
            confidence=0.9,
            summary="Routine internal traffic; the source reaches this host constantly.",
            citations=["alert.source_ip"],
            recommended_actions=[],
        ),
        redaction_summary={},
        oracle_model="test-oracle",
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return enriched

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=local),
        ),
        patch("soc_ai.oracle.client.adjudicate", new=AsyncMock(return_value=oracle_result)),
    ):
        return [ev async for ev in investigate(enriched.alert.id, ctx=ctx)]


@pytest.mark.asyncio
async def test_the_oracle_cannot_close_a_decoy_the_local_path_refused(
    settings_kratos: Settings,
) -> None:
    """The refusal itself is what sends the case to the Oracle.

    Capping a refused decoy at 0.4 puts it under
    ``oracle_escalate_below_confidence``, so the Oracle is asked exactly the
    question the local path just declined to answer benign. Without parity the
    Oracle's false_positive lands unrefused and the gate is a detour.
    """
    events = await _run_with_oracle(
        settings_kratos, _decoy_enriched("decoy-oracle"), "false_positive"
    )

    report = next(e for e in events if e.kind == "triage_report")
    assert report.payload["verdict"] != "false_positive"


@pytest.mark.asyncio
async def test_the_oracle_can_still_close_ordinary_internal_traffic(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. Parity must not leave the Oracle unable to clear anything."""
    events = await _run_with_oracle(
        settings_kratos, _ordinary_enriched("ordinary-oracle"), "false_positive"
    )

    report = next(e for e in events if e.kind == "triage_report")
    assert report.payload["verdict"] == "false_positive"


@pytest.mark.asyncio
async def test_the_oracle_can_still_escalate_a_decoy(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. Escalation is what the gate wants, not something it blocks."""
    events = await _run_with_oracle(
        settings_kratos, _decoy_enriched("decoy-oracle-tp"), "true_positive"
    )

    report = next(e for e in events if e.kind == "triage_report")
    assert report.payload["verdict"] == "true_positive"
