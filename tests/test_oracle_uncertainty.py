"""The Oracle escalates on uncertainty, never on the verdict class alone (stage 1, item 6).

Three triggers: a confidence in the gate band, a split between the decision
template and the model, a deep run that ended needs_more_info. The per-verdict
opt-ins narrow the triggers and never add one. The ledger row of each
escalation (the ``oracle_escalation`` audit event) names the trigger.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic_ai.models.test import TestModel
from soc_ai.agent.decision_templates import CandidateVerdict
from soc_ai.agent.gates import _downgrade_unevidenced_verdict, gate_band
from soc_ai.agent.orchestrator import investigate, oracle_escalation_reason
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.triage_models import PIPELINE_FALLBACK_PROVENANCE

from tests.test_agent import (
    _fake_loop_investigator_with_zeek_call,
    _make_ctx,
    _malware_signal_enriched,
    _non_malware_benign_enriched,
    _oracle_settings,
)


def _report(verdict: str, confidence: float) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        summary="Test.",
        citations=[],
        recommended_actions=[],
    )


def _template(verdict: str = "false_positive", authority: str = "provisional") -> Any:
    return CandidateVerdict(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=0.85,
        cited_evidence=["alert.rule_name"],
        template_id="clean_internal_traffic",
        rationale="Both endpoints are internal.",
        authority=authority,  # type: ignore[arg-type]
    )


def _reason(report: TriageReport, **kw: Any) -> str | None:
    settings = kw.pop("settings", None) or _oracle_settings()
    enriched = kw.pop("enriched", None) or _non_malware_benign_enriched()
    return oracle_escalation_reason(report, enriched, settings, **kw)


# ── The band ─────────────────────────────────────────────────────────────────


def test_the_band_is_read_from_the_evidence_gate() -> None:
    """The low edge is the confidence the evidence gate writes on a verdict it coerces."""
    low, high = gate_band()
    coerced = _downgrade_unevidenced_verdict(
        _report("false_positive", 0.9),
        _non_malware_benign_enriched(),
        None,
        {},
        targeted_messages=None,
        targeted_tool_called=None,
    )
    assert coerced.verdict == "needs_more_info"
    assert coerced.confidence == low
    assert (low, high) == (0.4, 0.7)


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        (0.39, None),
        (0.4, "confidence_in_band"),
        (0.55, "confidence_in_band"),
        (0.69, "confidence_in_band"),
        (0.7, None),
        (0.95, None),
    ],
)
def test_a_verdict_in_the_band_escalates(confidence: float, expected: str | None) -> None:
    assert _reason(_report("false_positive", confidence)) == expected


# ── The split ────────────────────────────────────────────────────────────────


def test_a_template_split_escalates_above_the_band() -> None:
    """The model overturned a benign template with confidence: a second opinion."""
    assert _reason(_report("true_positive", 0.9), candidate=_template()) == "template_split"


def test_a_split_ignores_the_band_ceiling_setting() -> None:
    """``oracle_escalate_below_confidence`` narrows the band trigger only."""
    settings = _oracle_settings(oracle_escalate_below_confidence=0.5)
    assert (
        _reason(_report("true_positive", 0.9), candidate=_template(), settings=settings)
        == "template_split"
    )
    assert _reason(_report("false_positive", 0.6), settings=settings) is None


def test_agreement_above_the_band_never_escalates() -> None:
    """The template and the model agree, confidently: never, in any class."""
    agreed = _report("false_positive", 0.9)
    for run_class in ("standard", "deep"):
        assert _reason(agreed, candidate=_template(), run_class=run_class) is None


# ── The deep needs_more_info ─────────────────────────────────────────────────


def test_a_deep_run_that_ended_unsure_escalates() -> None:
    unsure = _report("needs_more_info", 0.2)
    assert _reason(unsure, run_class="deep") == "deep_needs_more_info"
    # Negative control: the same verdict from a standard run is below the band.
    assert _reason(unsure, run_class="standard") is None


# ── The opt-ins narrow ───────────────────────────────────────────────────────


def test_the_needs_more_info_opt_in_narrows() -> None:
    off = _oracle_settings(oracle_escalate_needs_more_info=False)
    assert _reason(_report("needs_more_info", 0.5), settings=off) is None
    assert _reason(_report("needs_more_info", 0.2), settings=off, run_class="deep") is None


def test_a_malware_true_positive_stays_local_in_the_band() -> None:
    enriched = _malware_signal_enriched()
    assert _reason(_report("true_positive", 0.54), enriched=enriched) is None


def test_the_malware_opt_in_narrows_a_non_true_positive() -> None:
    enriched = _malware_signal_enriched()
    on = _reason(_report("false_positive", 0.55), enriched=enriched)
    off = _reason(
        _report("false_positive", 0.55),
        enriched=enriched,
        settings=_oracle_settings(oracle_escalate_malware_non_tp=False),
    )
    assert (on, off) == ("confidence_in_band", None)


def test_a_confident_loop_on_a_malware_rule_stays_local_on_a_split() -> None:
    enriched = _malware_signal_enriched()
    split = _report("false_positive", 0.85)
    candidate = _template(verdict="needs_more_info")
    assert _reason(split, enriched=enriched, candidate=candidate) == "template_split"
    assert _reason(split, enriched=enriched, candidate=candidate, ran_loop=True) is None


def test_an_opt_in_never_widens() -> None:
    """Every opt-in on: a confident, unsplit verdict still stays local."""
    for verdict in ("false_positive", "true_positive", "needs_more_info"):
        assert _reason(_report(verdict, 0.95)) is None


def test_no_escalation_for_a_cheap_run_a_rule_prior_run_or_a_fallback() -> None:
    in_band = _report("false_positive", 0.5)
    assert _reason(in_band, run_class="cheap") is None
    assert _reason(in_band, run_class="rule_prior") is None
    fallback = _report("needs_more_info", 0.45)
    fallback.resolution = {"provenance": PIPELINE_FALLBACK_PROVENANCE, "phase": "x"}
    assert _reason(fallback) is None
    assert _reason(in_band, settings=_oracle_settings(oracle_enabled=False)) is None


# ── The ledger ───────────────────────────────────────────────────────────────


async def test_the_ledger_row_names_the_trigger(settings_kratos: Settings) -> None:
    """A provisional benign template, overturned by the loop: a split, on the record."""
    settings_kratos.oracle_enabled = True
    settings_kratos.oracle_rule_mode = "uncertainty"
    ctx = _make_ctx(settings_kratos)
    loop_tp = _report("true_positive", 0.9).model_copy(
        update={"citations": ["(tool t_query_zeek_logs)"]}
    )
    loop_synth = MagicMock()
    loop_synth.run = AsyncMock(return_value=MagicMock(output=loop_tp))
    adjudicate = AsyncMock(return_value=None)

    async def _stub(aid: str, **_kw: Any) -> Any:
        return _non_malware_benign_enriched()

    with (
        patch("soc_ai.tools.get_alert_context.get_enriched_alert_context", side_effect=_stub),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_investigator",
            return_value=_fake_loop_investigator_with_zeek_call(),
        ),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=loop_synth),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=_template(),
        ),
        patch("soc_ai.oracle.client.adjudicate", new=adjudicate),
    ):
        events = [ev async for ev in investigate("alert-split", ctx=ctx)]
    ledger = next(e for e in events if e.kind == "oracle_escalation")
    assert ledger.payload["reason"] == "template_split"
    assert ledger.payload["template_verdict"] == "false_positive"
    assert ledger.payload["local_verdict"] == "true_positive"
    assert ledger.payload["gate_band"] == [0.4, 0.7]
    adjudicate.assert_awaited_once()
