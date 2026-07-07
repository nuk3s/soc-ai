"""Tests for the flag-gated N-sample self-consistency vote + `inconclusive`.

Covers:
- the pure `_self_consistency_vote` helper (majority / split / tie / single),
- `inconclusive` as a constructable TriageReport verdict,
- the synth-first pipeline hook: samples=1 skips the vote entirely (single
  synthesis call, byte-identical default), samples>1 re-runs the final synth
  and votes, a failed sample is dropped (<2 survivors ⇒ no vote).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError
from soc_ai.agent.decision_templates import CandidateVerdict
from soc_ai.agent.orchestrator import (
    InvestigationContext,
    _self_consistency_vote,
    investigate,
)
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert


def _rep(verdict: str, confidence: float, **kw: Any) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        summary=kw.pop("summary", f"summary for {verdict}"),
        citations=kw.pop("citations", []),
        **kw,
    )


# ---------------------------------------------------------------------------
# 1. Pure vote math — _self_consistency_vote
# ---------------------------------------------------------------------------


class TestVoteHelper:
    def test_unanimous_three_samples(self) -> None:
        reports = [
            _rep("true_positive", 0.8),
            _rep("true_positive", 0.9),
            _rep("true_positive", 0.7),
        ]
        verdict, conf, note = _self_consistency_vote(reports)
        assert verdict == "true_positive"
        assert conf == pytest.approx(0.8)  # mean of the agreeing samples
        assert "3/3 agreed on true_positive" in note

    def test_two_of_three_majority(self) -> None:
        reports = [
            _rep("false_positive", 0.9),
            _rep("true_positive", 0.4),
            _rep("false_positive", 0.7),
        ]
        verdict, conf, note = _self_consistency_vote(reports)
        assert verdict == "false_positive"
        # Mean of the MAJORITY voters only (0.9, 0.7) — the dissenter's 0.4
        # never contaminates the winning confidence.
        assert conf == pytest.approx(0.8)
        assert "2/3 agreed on false_positive" in note

    def test_three_way_split_is_inconclusive_capped(self) -> None:
        reports = [
            _rep("true_positive", 0.9),
            _rep("false_positive", 0.8),
            _rep("needs_more_info", 0.7),
        ]
        verdict, conf, note = _self_consistency_vote(reports)
        assert verdict == "inconclusive"
        assert conf <= 0.5  # mean 0.8 capped at 0.5
        assert conf == pytest.approx(0.5)
        assert "split 3 ways" in note
        assert "inconclusive" in note

    def test_split_below_cap_keeps_mean(self) -> None:
        # A low-confidence split isn't RAISED to the 0.5 cap — the mean stands.
        reports = [
            _rep("true_positive", 0.2),
            _rep("false_positive", 0.3),
            _rep("needs_more_info", 0.1),
        ]
        verdict, conf, _note = _self_consistency_vote(reports)
        assert verdict == "inconclusive"
        assert conf == pytest.approx(0.2)

    def test_two_sample_tie_is_inconclusive(self) -> None:
        reports = [_rep("true_positive", 0.9), _rep("false_positive", 0.9)]
        verdict, conf, note = _self_consistency_vote(reports)
        assert verdict == "inconclusive"
        assert conf <= 0.5
        assert "split 2 ways" in note

    def test_four_sample_two_two_tie_is_inconclusive(self) -> None:
        # 2-2 is NOT a strict majority (count must exceed N/2).
        reports = [
            _rep("true_positive", 0.9),
            _rep("true_positive", 0.8),
            _rep("false_positive", 0.7),
            _rep("false_positive", 0.6),
        ]
        verdict, _conf, note = _self_consistency_vote(reports)
        assert verdict == "inconclusive"
        assert "split 2 ways" in note

    def test_tie_one_one_with_third_distinct(self) -> None:
        # tp/fp tied 1-1 plus a distinct third verdict ⇒ no strict majority.
        reports = [
            _rep("true_positive", 0.6),
            _rep("false_positive", 0.6),
            _rep("needs_more_info", 0.6),
        ]
        verdict, _conf, note = _self_consistency_vote(reports)
        assert verdict == "inconclusive"
        assert "split 3 ways" in note

    def test_single_report_passthrough(self) -> None:
        # Defensive: caller guards N>1, but a single report passes through
        # verdict/confidence UNCHANGED (no cap, no note-driven rewrite).
        verdict, conf, _note = _self_consistency_vote([_rep("true_positive", 0.42)])
        assert verdict == "true_positive"
        assert conf == pytest.approx(0.42)

    def test_three_of_five_majority(self) -> None:
        reports = [
            _rep("needs_more_info", 0.5),
            _rep("true_positive", 0.9),
            _rep("needs_more_info", 0.6),
            _rep("false_positive", 0.8),
            _rep("needs_more_info", 0.4),
        ]
        verdict, conf, note = _self_consistency_vote(reports)
        assert verdict == "needs_more_info"
        assert conf == pytest.approx(0.5)  # mean of 0.5, 0.6, 0.4
        assert "3/5 agreed on needs_more_info" in note


# ---------------------------------------------------------------------------
# 2. `inconclusive` is a first-class TriageReport verdict
# ---------------------------------------------------------------------------


def test_inconclusive_is_constructable_verdict() -> None:
    report = TriageReport(
        verdict="inconclusive",
        confidence=0.5,
        summary="self-consistency split — inconclusive",
        citations=[],
    )
    assert report.verdict == "inconclusive"
    # ...and it survives a serialization round-trip (persist/read-back shape).
    again = TriageReport.model_validate_json(report.model_dump_json())
    assert again.verdict == "inconclusive"


def test_unknown_verdict_still_rejected() -> None:
    with pytest.raises(ValidationError):
        TriageReport(verdict="maybe", confidence=0.5, summary="x")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 3. Pipeline hook — synth-first final synthesis sampling
# ---------------------------------------------------------------------------


class _StubResult:
    def __init__(self, output: Any) -> None:
        self.output = output

    def usage(self) -> Any:  # _usage_ev() catches this and skips the event
        raise RuntimeError("no usage in stub")


class _StubSynthAgent:
    """Sequential canned outputs; an Exception entry raises on that call."""

    def __init__(self, outputs: list[Any]) -> None:
        self._outputs = list(outputs)
        self.calls = 0

    async def run(self, *_a: Any, **_kw: Any) -> _StubResult:
        i = self.calls
        self.calls += 1
        out = self._outputs[min(i, len(self._outputs) - 1)]
        if isinstance(out, Exception):
            raise out
        return _StubResult(out)


def _make_ctx(settings: Settings) -> InvestigationContext:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    return InvestigationContext(
        settings=settings,
        auth=AsyncMock(),
        elastic=elastic,
    )


def _stub_enriched_alert_context(alert_id: str = "alert-001") -> Any:
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(id=alert_id, severity_label="low"),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


# A strong benign template so the hard evidence gate exempts the zero-tool FP
# (mirrors test_agent.py's template-match integration test).
_STRONG_CANDIDATE = CandidateVerdict(
    verdict="false_positive",
    confidence=0.85,
    cited_evidence=["alert.severity_label"],
    template_id="clean_internal_traffic",
    rationale="internal scanner",
)


def _fp_report(conf: float = 0.85) -> TriageReport:
    return TriageReport(
        verdict="false_positive",
        confidence=conf,
        summary="Internal scanner; expected periodic ICMP.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )


async def _run_pipeline(settings: Settings, stub_agent: _StubSynthAgent) -> list[Any]:
    settings.investigate_when_unsure = False
    ctx = _make_ctx(settings)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=object(),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=stub_agent,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=_STRONG_CANDIDATE,
        ),
    ):
        return [ev async for ev in investigate("alert-001", ctx=ctx)]


@pytest.mark.asyncio
async def test_samples_1_default_skips_vote_entirely(settings_kratos: Settings) -> None:
    """Default (samples=1): ONE synthesis call, no vote event, verdict untouched."""
    assert settings_kratos.verdict_consistency_samples == 1  # the shipped default
    stub = _StubSynthAgent([_fp_report()])
    events = await _run_pipeline(settings_kratos, stub)

    kinds = [e.kind for e in events]
    assert stub.calls == 1  # single synthesis call — no extra samples
    assert "self_consistency_vote" not in kinds
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["confidence"] == pytest.approx(0.85)
    assert "self-consistency" not in report_ev.payload["summary"]


@pytest.mark.asyncio
async def test_samples_3_unanimous_votes_and_annotates(settings_kratos: Settings) -> None:
    settings_kratos.verdict_consistency_samples = 3
    stub = _StubSynthAgent([_fp_report(0.9), _fp_report(0.8), _fp_report(0.7)])
    events = await _run_pipeline(settings_kratos, stub)

    kinds = [e.kind for e in events]
    assert stub.calls == 3  # round-1 + 2 extra samples
    assert "self_consistency_vote" in kinds
    vote_ev = next(e for e in events if e.kind == "self_consistency_vote")
    assert vote_ev.payload["samples"] == 3
    assert vote_ev.payload["tally"] == {"false_positive": 3}
    assert vote_ev.payload["chosen_verdict"] == "false_positive"
    assert "3/3 agreed" in vote_ev.payload["note"]

    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["confidence"] == pytest.approx(0.8)  # mean of voters
    assert "self-consistency 3/3 agreed" in report_ev.payload["summary"]


@pytest.mark.asyncio
async def test_samples_3_split_lands_inconclusive(settings_kratos: Settings) -> None:
    settings_kratos.verdict_consistency_samples = 3
    tp = TriageReport(
        verdict="true_positive",
        confidence=0.9,
        summary="looks bad",
        citations=["alert.severity_label"],
    )
    nmi = TriageReport(
        verdict="needs_more_info",
        confidence=0.6,
        summary="unsure",
        citations=["alert.severity_label"],
    )
    stub = _StubSynthAgent([_fp_report(0.8), tp, nmi])
    events = await _run_pipeline(settings_kratos, stub)

    vote_ev = next(e for e in events if e.kind == "self_consistency_vote")
    assert vote_ev.payload["chosen_verdict"] == "inconclusive"
    assert vote_ev.payload["tally"] == {
        "false_positive": 1,
        "true_positive": 1,
        "needs_more_info": 1,
    }

    report_ev = next(e for e in events if e.kind == "triage_report")
    # Terminal non-committed verdict: survives every post-validator (the floor
    # rewrite must NOT coerce it to needs_more_info).
    assert report_ev.payload["verdict"] == "inconclusive"
    assert report_ev.payload["confidence"] <= 0.5
    # Representative = highest-confidence sample (the TP one) for a split.
    assert "looks bad" in report_ev.payload["summary"]
    assert "split 3 ways" in report_ev.payload["summary"]


@pytest.mark.asyncio
async def test_failed_samples_fall_back_to_single_report(
    settings_kratos: Settings,
) -> None:
    """If every extra sample raises, no vote fires — the primary report stands."""
    settings_kratos.verdict_consistency_samples = 3
    stub = _StubSynthAgent([_fp_report(), RuntimeError("boom"), RuntimeError("boom")])
    events = await _run_pipeline(settings_kratos, stub)

    kinds = [e.kind for e in events]
    assert stub.calls == 3  # both extra samples were attempted...
    assert "self_consistency_vote" not in kinds  # ...but no vote on 1 survivor
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["confidence"] == pytest.approx(0.85)


@pytest.mark.asyncio
async def test_one_failed_sample_still_votes_on_survivors(
    settings_kratos: Settings,
) -> None:
    settings_kratos.verdict_consistency_samples = 3
    stub = _StubSynthAgent([_fp_report(0.9), RuntimeError("boom"), _fp_report(0.7)])
    events = await _run_pipeline(settings_kratos, stub)

    vote_ev = next(e for e in events if e.kind == "self_consistency_vote")
    assert vote_ev.payload["samples"] == 2  # dropped the failed one
    assert vote_ev.payload["chosen_verdict"] == "false_positive"
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["confidence"] == pytest.approx(0.8)
