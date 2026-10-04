"""A report may not say a host has no host telemetry while the host ships a plane.

Production stored twelve such sentences about one Linux server that shipped
system logs, auth logs and osquery. The sentences below are the production
sentences, anonymised: the host is app-01 at an RFC 5737 address, and the
external names are example.test names. A plane-level sentence ("no endpoint
process telemetry") is true on such a host and must survive.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.agent.narrative_grounding import (
    claims_no_host_telemetry,
    coverage_subject,
    ground_host_coverage_claims,
    rewrite_host_gap_claims,
)
from soc_ai.dossier.coverage import (
    DatasetCount,
    HostAgent,
    HostCoverage,
    PlaneCoverage,
)
from soc_ai.triage_models import RecommendedAction, TriageReport

_HOST = "192.0.2.41"

# The false claims, as production wrote them.
_FALSE_CLAIMS = (
    "The initiating process (presumed pip) could not be confirmed because no host-level "
    "endpoint telemetry exists for app-01 on this grid, but the destination is a "
    "legitimate, well-known package index and there is no positive malicious signal in "
    "the payload or behavior.",
    "No host-level telemetry exists.",
    "The initiating process is unconfirmed (no host-level events), but the benign "
    "payload, allowed action, and informational severity support a false positive.",
    "The only gap is that host-level endpoint telemetry is not indexed for this host, so "
    "the specific process making the lookup cannot be identified, but the network-level "
    "evidence is uniformly benign.",
    "The initiating process could not be identified because endpoint telemetry does not "
    "cover this host, but the absence of any malicious payload, beacon cadence, or "
    "reputation signal supports a benign disposition.",
    "No endpoint process/network events reference lookup.example.test or 203.0.113.80 on "
    "this host in the window, endpoint plane does not cover app-01.",
    "Without host telemetry, lateral movement over the remote shell would be invisible.",
)

# Plane-level sentences from the same runs. They are true on this host.
_TRUE_PLANE_CLAIMS = (
    "The only gap is lack of host-level process corroboration, since app-01.example.test "
    "is not covered by endpoint process telemetry, but the payload, destination, and "
    "behavior are all consistent with benign, routine outbound web access from this host.",
    "Because this grid carries no endpoint process or network telemetry for app-01, the "
    "responsible process cannot be identified and a malicious origin can neither be "
    "confirmed nor excluded.",
    "No inbound remote-access session drove this connection, and no host-level process "
    "visibility exists to attribute it to a specific app.",
    "This is consistent with routine package registry access from a development server, "
    "and no endpoint process events were found for this host in the window.",
)


def _coverage(*, covered: bool = True, read_ok: bool = True) -> HostCoverage:
    host_logs = PlaneCoverage(
        plane="host_logs",
        present=covered,
        count=11309 if covered else 0,
        datasets=[DatasetCount(dataset="system.auth", count=11309)] if covered else [],
    )
    planes = [host_logs] + [
        PlaneCoverage(plane=p, present=False)
        for p in ("process", "endpoint_network", "windows_security", "osquery", "agent_self")
    ]
    return HostCoverage(
        read_ok=read_ok,
        reason=None if read_ok else "the coverage read failed (TimeoutError)",
        addresses=[_HOST],
        names=["app-01", "app-01.example.test"],
        planes=planes,
        agents=[HostAgent(id="agent-1", name="app-01", os="Fedora Linux")] if covered else [],
    )


@pytest.mark.parametrize("sentence", _FALSE_CLAIMS)
def test_each_production_claim_is_detected(sentence: str) -> None:
    assert claims_no_host_telemetry(sentence)


@pytest.mark.parametrize("sentence", _TRUE_PLANE_CLAIMS)
def test_a_plane_level_sentence_is_not_a_host_claim(sentence: str) -> None:
    assert not claims_no_host_telemetry(sentence)


def test_the_report_states_the_planes_in_place_of_each_false_claim() -> None:
    summary = " ".join((*_FALSE_CLAIMS[:3], *_TRUE_PLANE_CLAIMS[:2]))
    report = TriageReport(
        verdict="false_positive",
        confidence=0.8,
        summary=summary,
        citations=["(tool t_host_dossier)"],
        recommended_actions=[
            RecommendedAction(
                tool_name="ack_alert",
                tool_args={"alert_id": "a-1"},
                rationale=_FALSE_CLAIMS[4],
            )
        ],
        field_reconciliation=_FALSE_CLAIMS[5],
    )
    grounded, changed = ground_host_coverage_claims(report, [coverage_subject(_HOST, _coverage())])

    assert changed == 5
    facts = (
        "app-01 ships host logs (system.auth 11,309). "
        "app-01 ships no process events and no endpoint network events."
    )
    # One statement of the facts, however many false claims it replaced.
    assert grounded.summary.count(facts) == 1
    for claim in _FALSE_CLAIMS[:3]:
        assert claim not in grounded.summary
    for kept in _TRUE_PLANE_CLAIMS[:2]:
        assert kept in grounded.summary
    assert grounded.recommended_actions[0].rationale == facts
    assert grounded.field_reconciliation == facts
    for text in (grounded.summary, grounded.field_reconciliation):
        assert "no host-level" not in text.lower()
        assert not claims_no_host_telemetry(text)


def test_a_host_that_ships_nothing_keeps_the_claim() -> None:
    report = TriageReport(
        verdict="false_positive", confidence=0.7, summary=_FALSE_CLAIMS[1], citations=[]
    )
    grounded, changed = ground_host_coverage_claims(
        report, [coverage_subject(_HOST, _coverage(covered=False))]
    )
    assert changed == 0
    assert grounded.summary == _FALSE_CLAIMS[1]


def test_an_unread_coverage_keeps_the_claim() -> None:
    report = TriageReport(
        verdict="false_positive", confidence=0.7, summary=_FALSE_CLAIMS[1], citations=[]
    )
    grounded, changed = ground_host_coverage_claims(
        report, [coverage_subject(_HOST, _coverage(read_ok=False))]
    )
    assert changed == 0
    assert grounded.summary == _FALSE_CLAIMS[1]


def test_a_claim_that_names_an_uncovered_peer_stays() -> None:
    """Two internal hosts: the claim names the one that ships nothing."""
    peer = HostCoverage(
        read_ok=True,
        addresses=["198.51.100.20"],
        names=["printer-01"],
        planes=[PlaneCoverage(plane="host_logs", present=False)],
    )
    text = "No host-level telemetry exists for printer-01. The flow is routine."
    out, changed = rewrite_host_gap_claims(
        text,
        __import__("soc_ai.agent.narrative_grounding", fromlist=["x"]).coverage_replacer(
            [coverage_subject(_HOST, _coverage()), coverage_subject("198.51.100.20", peer)]
        ),
    )
    assert changed == 0
    assert out == text


def test_bullets_and_line_breaks_survive_a_rewrite() -> None:
    text = (
        "Benign lookup.\n"
        "- The only gap is that host-level endpoint telemetry is not indexed for this host.\n"
        "- The destination is a known package index."
    )
    out, changed = rewrite_host_gap_claims(text, lambda _s: "The host ships host logs.")
    assert changed == 1
    assert out == (
        "Benign lookup.\n- The host ships host logs.\n- The destination is a known package index."
    )
    stripped, n = rewrite_host_gap_claims(text, lambda _s: "")
    assert n == 1
    assert stripped == "Benign lookup.\n- The destination is a known package index."


@pytest.mark.asyncio
async def test_the_triage_report_is_grounded_before_it_is_emitted(
    settings_kratos: Any,
) -> None:
    """Wiring: investigate() emits the grounded summary and an audit event."""
    from soc_ai.tools.get_alert_context import EndpointCoverage

    from tests.test_agent import (
        _make_ctx,
        _run_synth_first,
        _strong_benign_candidate,
        _stub_enriched_alert_context,
    )

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)
    report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary=(
            "Routine package download from app-01. The initiating process is unconfirmed "
            "(no host-level events), but the benign payload, allowed action, and "
            "informational severity support a false positive."
        ),
        citations=["alert.rule_name"],
        recommended_actions=[],
    )

    def _enriched(alert_id: str) -> Any:
        enriched = _stub_enriched_alert_context(alert_id)
        enriched.host_coverage = [EndpointCoverage(ip=_HOST, end="source", coverage=_coverage())]
        return enriched

    events = await _run_synth_first(
        ctx, report=report, candidate=_strong_benign_candidate(), enriched_factory=_enriched
    )
    final = next(e for e in events if e.kind == "triage_report")
    summary = final.payload["summary"]
    assert "no host-level events" not in summary
    assert "app-01 ships host logs (system.auth 11,309)." in summary
    assert "Routine package download from app-01." in summary
    grounding = next(e for e in events if e.kind == "host_coverage_grounding")
    assert grounding.payload["sentences_rewritten"] == 1
