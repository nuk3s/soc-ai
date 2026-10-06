"""Budget classes: the rungs plan a run's class, and the row records what ran.

Stage 1, item 2 (docs/dev/specs/2026-10-04-four-tier-detection-methodology.md,
"The ladder"). Cheap is one synthesis request with no loop and no Oracle.
Standard is the loop. Deep is the loop with the full budget. A person's
request is standard or deep and always runs the loop.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic_ai.models.test import TestModel
from soc_ai.agent import budget
from soc_ai.agent.budget import plan_run_class, ran_class
from soc_ai.agent.decision_templates import CandidateVerdict
from soc_ai.agent.orchestrator import InvestigationContext, investigate
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings

from tests.test_agent import (
    _fake_loop_investigator_with_zeek_call,
    _make_ctx,
    _strong_benign_candidate,
    _stub_enriched_alert_context,
)

# ── The plan ─────────────────────────────────────────────────────────────────


def _plan(**kw: Any) -> budget.ClassPlan:
    base: dict[str, Any] = {
        "requested": None,
        "subject_is_hunt": False,
        "round1_can_settle": False,
        "session_true_positive": False,
        "fast_triage_enabled": True,
    }
    base.update(kw)
    return plan_run_class(**base)


def test_a_deep_request_is_deep_and_forces_the_loop() -> None:
    plan = _plan(requested="deep", round1_can_settle=True)
    assert (plan.run_class, plan.forces_loop) == ("deep", True)


def test_an_analyst_request_is_standard_even_where_a_template_settles() -> None:
    """A person asked for an investigation. The cheap rung serves the scheduler."""
    plan = _plan(requested="standard", round1_can_settle=True)
    assert (plan.run_class, plan.reason, plan.forces_loop) == ("standard", "analyst_run", True)


def test_the_scheduler_gets_cheap_only_from_a_dispositive_template() -> None:
    assert _plan(round1_can_settle=True).run_class == "cheap"
    assert _plan(round1_can_settle=False).run_class == "standard"


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"subject_is_hunt": True}, "hunt_subject"),
        ({"fast_triage_enabled": False}, "fast_triage_disabled"),
        ({"session_true_positive": True}, "session_true_positive_stands"),
    ],
)
def test_a_rung_that_needs_the_loop_never_plans_cheap(kw: dict[str, Any], reason: str) -> None:
    """Negative control on the path the cheap rung would miss: a settleable template."""
    plan = _plan(round1_can_settle=True, **kw)
    assert (plan.run_class, plan.reason) == ("standard", reason)


def test_the_class_that_ran_follows_the_loop() -> None:
    cheap = _plan(round1_can_settle=True)
    assert ran_class(cheap, ran_loop=False) == "cheap"
    # A cheap plan that entered the loop escalated.
    assert ran_class(cheap, ran_loop=True) == "standard"
    assert ran_class(_plan(requested="deep"), ran_loop=True) == "deep"
    # The loop switched off by the operator: still the standard path, Oracle included.
    assert ran_class(_plan(), ran_loop=False) == "standard"


# ── The pipeline ─────────────────────────────────────────────────────────────


def _stun_enriched(alert_id: str = "alert-001") -> Any:
    """A STUN keepalive alert: the shape a dispositive template clears."""
    from soc_ai.so_client.models import SoAlert

    enriched = _stub_enriched_alert_context(alert_id)
    enriched.alert = SoAlert(
        id=alert_id, rule_name="ET INFO STUN Binding Request", severity_label="low"
    )
    return enriched


def _benign_round1(confidence: float = 0.85) -> TriageReport:
    return TriageReport(
        verdict="false_positive",
        confidence=confidence,
        summary="STUN keepalive. Routine.",
        citations=["alert.rule_name"],
        recommended_actions=[],
    )


def _loop_report() -> TriageReport:
    return TriageReport(
        verdict="false_positive",
        confidence=0.88,
        summary="The Zeek record shows a keepalive to a known service.",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[],
    )


async def _drive(
    ctx: InvestigationContext,
    *,
    candidate: Any,
    round1: TriageReport,
    deep: bool = False,
    enriched_factory: Callable[[str], Any] = _stun_enriched,
    oracle: Any = None,
) -> tuple[list[Any], MagicMock, MagicMock]:
    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return enriched_factory(aid)

    synth = MagicMock()
    synth.run = AsyncMock(return_value=MagicMock(output=round1))
    investigator = _fake_loop_investigator_with_zeek_call()
    loop_synth = MagicMock()
    loop_synth.run = AsyncMock(return_value=MagicMock(output=_loop_report()))
    adjudicate = oracle if oracle is not None else AsyncMock(return_value=None)
    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_synth_first_agent", return_value=synth),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=investigator),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=loop_synth),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=candidate,
        ),
        patch("soc_ai.oracle.client.adjudicate", new=adjudicate),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx, deep=deep)]
    return events, synth, investigator


def _report(events: list[Any]) -> dict[str, Any]:
    payload: dict[str, Any] = next(e for e in events if e.kind == "triage_report").payload
    return payload


async def test_a_scheduler_run_on_a_dispositive_template_is_cheap(
    settings_kratos: Settings,
) -> None:
    """One synthesis request, no loop, and no Oracle even when one is enabled."""
    settings_kratos.oracle_enabled = True
    # A floor this high would send any standard verdict to the Oracle.
    settings_kratos.oracle_escalate_below_confidence = 0.99
    ctx = _make_ctx(settings_kratos)
    oracle = AsyncMock(return_value=None)
    events, synth, investigator = await _drive(
        ctx, candidate=_strong_benign_candidate(), round1=_benign_round1(), oracle=oracle
    )
    kinds = [e.kind for e in events]
    assert synth.run.await_count == 1
    assert "investigation_loop_entered" not in kinds
    investigator.iter.assert_not_called()
    assert "oracle_escalation" not in kinds
    oracle.assert_not_awaited()
    report = _report(events)
    assert report["verdict"] == "false_positive"
    assert report["run_class"] == "cheap"
    assert report["run_class_reason"] == "dispositive_template"


async def test_an_analyst_run_on_the_same_alert_runs_the_loop(settings_kratos: Settings) -> None:
    """Standard is the loop. Round 1 is skipped: its verdict could not end the run."""
    ctx = _make_ctx(settings_kratos)
    ctx.requested_run_class = "standard"
    events, synth, investigator = await _drive(
        ctx, candidate=_strong_benign_candidate(), round1=_benign_round1()
    )
    synth.run.assert_not_awaited()
    investigator.iter.assert_called_once()
    skipped = next(e for e in events if e.kind == "synth_round1_skipped")
    assert skipped.payload["reason"] == "class_runs_loop"
    entered = next(e for e in events if e.kind == "investigation_loop_entered")
    assert entered.payload["reason"] == "analyst_run"
    assert entered.payload["run_class"] == "standard"
    assert _report(events)["run_class"] == "standard"
    start = next(e for e in events if e.kind == "session_start")
    assert start.payload["run_class"] == "standard"


async def test_a_deep_rerun_is_the_deep_class(settings_kratos: Settings) -> None:
    ctx = _make_ctx(settings_kratos)
    events, _synth, _inv = await _drive(
        ctx, candidate=_strong_benign_candidate(), round1=_benign_round1(), deep=True
    )
    assert _report(events)["run_class"] == "deep"
    assert next(e for e in events if e.kind == "session_start").payload["run_class"] == "deep"


async def test_a_cheap_verdict_a_gate_would_change_escalates_to_standard(
    settings_kratos: Settings,
) -> None:
    """The planted needle: a dispositive template too weak to exempt the evidence gate.

    ``_round1_can_settle`` reads only the authority, so round 1 settles. The
    evidence gate wants confidence 0.8, so it would coerce the zero-tool false
    positive to needs_more_info. Before the classes, this run skipped the loop
    and then lost its verdict to the gate. Now the cheap run escalates.
    """
    weak = CandidateVerdict(
        verdict="false_positive",
        confidence=0.7,
        cited_evidence=["alert.rule_name"],
        template_id="stun_quic_keepalive",
        rationale="STUN keepalive",
        authority="dispositive",
    )
    ctx = _make_ctx(settings_kratos)
    events, synth, _inv = await _drive(ctx, candidate=weak, round1=_benign_round1())
    assert synth.run.await_count == 1
    entered = next(e for e in events if e.kind == "investigation_loop_entered")
    assert entered.payload["reason"] == "gate_would_change"
    report = _report(events)
    assert report["run_class"] == "standard"
    assert report["run_class_reason"] == "gate_would_change"
    assert report["verdict"] == "false_positive"


async def test_a_cheap_round1_that_is_not_a_false_positive_escalates(
    settings_kratos: Settings,
) -> None:
    ctx = _make_ctx(settings_kratos)
    unsure = TriageReport(
        verdict="needs_more_info",
        confidence=0.5,
        summary="Unclear.",
        citations=[],
        recommended_actions=[],
    )
    events, _synth, _inv = await _drive(ctx, candidate=_strong_benign_candidate(), round1=unsure)
    assert "investigation_loop_entered" in [e.kind for e in events]
    assert _report(events)["run_class"] == "standard"


def test_the_list_and_the_detail_carry_the_run_class(settings_kratos: Settings) -> None:
    """The column first, the stored report second, and nothing for an old run."""
    from datetime import timedelta

    from soc_ai.store.auth import utcnow

    from tests.test_investigations_query import _client, _mk, _seed_route

    gen = _client(settings_kratos)
    client = next(gen)
    try:
        now = utcnow()
        stamped = _mk(1, status="complete", verdict="false_positive", created_at=now)
        stamped.run_class = "cheap"
        from_report = _mk(
            2,
            status="complete",
            verdict="false_positive",
            created_at=now - timedelta(minutes=5),
            report={
                "verdict": "false_positive",
                "run_class": "deep",
                "run_class_reason": "deep_rerun",
            },
        )
        old = _mk(
            3,
            status="complete",
            verdict="false_positive",
            created_at=now - timedelta(minutes=9),
            report={"verdict": "false_positive"},
        )
        _seed_route(client, [stamped, from_report, old])
        rows = {r["id"]: r for r in client.get("/api/v1/investigations").json()["rows"]}
        assert rows[f"{1:026d}"]["runClass"] == "cheap"
        assert rows[f"{2:026d}"]["runClass"] == "deep"
        assert rows[f"{3:026d}"]["runClass"] is None
        detail = client.get(f"/api/v1/investigations/{2:026d}").json()
        assert detail["runClass"] == "deep"
        assert detail["runClassReason"] == "deep_rerun"
        assert client.get(f"/api/v1/investigations/{3:026d}").json()["runClass"] is None
    finally:
        gen.close()


def test_the_oracle_predicate_refuses_a_cheap_run(settings_kratos: Settings) -> None:
    from soc_ai.agent.orchestrator import _should_escalate_to_oracle

    settings_kratos.oracle_enabled = True
    # In the gate band, so a standard run escalates it.
    nmi = TriageReport(
        verdict="needs_more_info",
        confidence=0.45,
        summary="x",
        citations=[],
        recommended_actions=[],
    )
    enriched = _stub_enriched_alert_context()
    assert _should_escalate_to_oracle(nmi, enriched, settings_kratos, run_class="standard")
    assert not _should_escalate_to_oracle(nmi, enriched, settings_kratos, run_class="cheap")
    assert not _should_escalate_to_oracle(nmi, enriched, settings_kratos, run_class="rule_prior")
