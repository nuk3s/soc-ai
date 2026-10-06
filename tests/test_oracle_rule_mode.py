"""The Oracle rule mode: classic, shadow or uncertainty (oracle_rule_mode).

The uncertainty rule does not go live cold. Shadow, the default, lets the
classic verdict-class rule decide and records what the uncertainty rule would
have done on an ``oracle_shadow`` event. Detection tuning tallies those rows.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic_ai.models.test import TestModel
from soc_ai.agent.decision_templates import CandidateVerdict
from soc_ai.agent.orchestrator import (
    _should_escalate_to_oracle,
    classic_oracle_escalation_reason,
    investigate,
    oracle_rule_decision,
)
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.store import oracle_ledger
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Investigation, InvestigationEvent

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


def _template(verdict: str = "false_positive") -> Any:
    return CandidateVerdict(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=0.85,
        cited_evidence=["alert.rule_name"],
        template_id="clean_internal_traffic",
        rationale="Both endpoints are internal.",
        authority="provisional",
    )


# ── The setting ──────────────────────────────────────────────────────────────


def test_the_default_mode_is_shadow() -> None:
    assert Settings.model_fields["oracle_rule_mode"].default == "shadow"


def test_the_mode_is_a_hot_select_with_three_options() -> None:
    from soc_ai.store.config_overrides import WHITELIST

    spec = next(s for s in WHITELIST if s.key == "oracle_rule_mode")
    assert spec.hot is True
    assert spec.options == ("classic", "shadow", "uncertainty")
    assert "—" not in spec.help and "–" not in spec.help


# ── The classic rule ─────────────────────────────────────────────────────────


def test_the_classic_rule_sends_a_confident_malware_false_positive() -> None:
    """The 48-a-month case: the uncertainty rule keeps it local, the classic sends it."""
    settings = _oracle_settings(oracle_rule_mode="classic")
    enriched = _malware_signal_enriched()
    fp = _report("false_positive", 0.75)
    assert classic_oracle_escalation_reason(fp, enriched, settings) == "malware_non_tp"
    decision = oracle_rule_decision(fp, enriched, settings)
    assert (decision.reason, decision.uncertainty_reason) == ("malware_non_tp", None)


def test_the_classic_floor_stays_at_point_six() -> None:
    """Stage 1 moved the setting default to 0.7. The classic rule keeps 0.6."""
    settings = _oracle_settings(oracle_rule_mode="classic")
    enriched = _non_malware_benign_enriched()
    assert (
        classic_oracle_escalation_reason(_report("false_positive", 0.65), enriched, settings)
        is None
    )
    assert (
        classic_oracle_escalation_reason(_report("false_positive", 0.55), enriched, settings)
        == "below_confidence"
    )
    lower = _oracle_settings(oracle_rule_mode="classic", oracle_escalate_below_confidence=0.5)
    assert (
        classic_oracle_escalation_reason(_report("false_positive", 0.55), enriched, lower) is None
    )


def test_the_classic_rule_keeps_a_malware_true_positive_local() -> None:
    settings = _oracle_settings(oracle_rule_mode="classic")
    tp = _report("true_positive", 0.5)
    assert classic_oracle_escalation_reason(tp, _malware_signal_enriched(), settings) is None


def test_the_classic_rule_sends_needs_more_info() -> None:
    settings = _oracle_settings(oracle_rule_mode="classic")
    nmi = _report("needs_more_info", 0.8)
    assert (
        classic_oracle_escalation_reason(nmi, _non_malware_benign_enriched(), settings)
        == "needs_more_info"
    )


# ── The modes ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("mode", "decides", "classic", "uncertainty"),
    [
        ("classic", None, None, None),
        ("shadow", None, None, "confidence_in_band"),
        ("uncertainty", "confidence_in_band", None, "confidence_in_band"),
    ],
)
def test_each_mode_picks_the_deciding_rule(
    mode: str, decides: str | None, classic: str | None, uncertainty: str | None
) -> None:
    """A false positive at 0.65 on a benign rule: in band, above the classic floor."""
    settings = _oracle_settings(oracle_rule_mode=mode)
    report = _report("false_positive", 0.65)
    enriched = _non_malware_benign_enriched()
    decision = oracle_rule_decision(report, enriched, settings)
    assert decision.mode == mode
    assert decision.reason == decides
    assert decision.classic_reason == classic
    assert decision.uncertainty_reason == uncertainty
    assert _should_escalate_to_oracle(report, enriched, settings) is (decides is not None)


def test_shadow_escalates_what_classic_escalates() -> None:
    settings = _oracle_settings(oracle_rule_mode="shadow")
    decision = oracle_rule_decision(
        _report("false_positive", 0.75), _malware_signal_enriched(), settings
    )
    assert (decision.reason, decision.classic_reason, decision.uncertainty_reason) == (
        "malware_non_tp",
        "malware_non_tp",
        None,
    )


# ── The pipeline ─────────────────────────────────────────────────────────────


async def _run_split(settings: Settings) -> tuple[list[Any], AsyncMock]:
    """A provisional benign template overturned by a confident loop TP.

    The uncertainty rule names a template split. The classic rule keeps the
    verdict local: a benign rule and a confidence of 0.9.
    """
    settings.oracle_enabled = True
    ctx = _make_ctx(settings)
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
    return events, adjudicate


async def test_shadow_records_the_uncertainty_rule_and_calls_no_oracle(
    settings_kratos: Settings,
) -> None:
    settings_kratos.oracle_rule_mode = "shadow"
    events, adjudicate = await _run_split(settings_kratos)
    kinds = [e.kind for e in events]
    assert "oracle_escalation" not in kinds
    adjudicate.assert_not_awaited()
    shadow = next(e for e in events if e.kind == "oracle_shadow")
    assert shadow.payload["uncertainty_reason"] == "template_split"
    assert shadow.payload["classic_reason"] is None
    assert shadow.payload["would_escalate"] is True
    assert shadow.payload["classic_escalates"] is False
    assert shadow.payload["template_verdict"] == "false_positive"


async def test_classic_records_no_shadow_row(settings_kratos: Settings) -> None:
    settings_kratos.oracle_rule_mode = "classic"
    events, adjudicate = await _run_split(settings_kratos)
    kinds = [e.kind for e in events]
    assert "oracle_shadow" not in kinds
    assert "oracle_escalation" not in kinds
    adjudicate.assert_not_awaited()


async def test_uncertainty_decides_and_names_the_mode(settings_kratos: Settings) -> None:
    settings_kratos.oracle_rule_mode = "uncertainty"
    events, adjudicate = await _run_split(settings_kratos)
    ledger = next(e for e in events if e.kind == "oracle_escalation")
    assert ledger.payload["reason"] == "template_split"
    assert ledger.payload["rule_mode"] == "uncertainty"
    assert "oracle_shadow" not in [e.kind for e in events]
    adjudicate.assert_awaited_once()


# ── The tally ────────────────────────────────────────────────────────────────


def test_the_tally_counts_each_rule_and_the_overlap() -> None:
    payloads = [
        {"uncertainty_reason": "confidence_in_band", "classic_reason": "below_confidence"},
        {"uncertainty_reason": "confidence_in_band", "classic_reason": None},
        {"uncertainty_reason": "template_split", "classic_reason": None},
        {"uncertainty_reason": None, "classic_reason": "malware_non_tp"},
        {"uncertainty_reason": None, "classic_reason": "malware_non_tp"},
    ]
    tally = oracle_ledger.tally_shadow_payloads(payloads, days=7)
    assert (tally.recorded, tally.would_escalate, tally.classic, tally.both) == (5, 3, 3, 1)
    rows = {(r.rule, r.reason): (r.count, r.overlap) for r in tally.by_reason}
    assert rows == {
        ("uncertainty", "confidence_in_band"): (2, 1),
        ("uncertainty", "template_split"): (1, 0),
        ("classic", "below_confidence"): (1, 1),
        ("classic", "malware_non_tp"): (2, 0),
    }
    # Display order: the uncertainty triggers first, in their rule order.
    assert [r.reason for r in tally.by_reason][:2] == ["confidence_in_band", "template_split"]


def test_the_tally_route_reads_the_window_and_names_the_mode(settings_kratos: Settings) -> None:
    """Only the runs inside the window count. An older shadow row is out."""
    from datetime import timedelta

    from tests.test_investigations_query import _client

    settings = settings_kratos.model_copy(update={"oracle_rule_mode": "shadow"})
    gen = _client(settings)
    client = next(gen)
    try:

        async def seed() -> None:
            async with client.app.state.db_sessionmaker() as db:
                now = utcnow()
                for i, (age_days, unc, cls) in enumerate(
                    [
                        (1, "confidence_in_band", None),
                        (2, "confidence_in_band", "below_confidence"),
                        (3, None, "malware_non_tp"),
                        (20, "template_split", None),
                    ]
                ):
                    inv_id = f"shadow{i:026d}"
                    db.add(
                        Investigation(
                            id=inv_id,
                            alert_es_id=f"ev-{i}",
                            status="complete",
                            created_at=now - timedelta(days=age_days),
                        )
                    )
                    db.add(
                        InvestigationEvent(
                            investigation_id=inv_id,
                            sequence=1,
                            kind="oracle_shadow",
                            payload={"uncertainty_reason": unc, "classic_reason": cls},
                        )
                    )
                await db.commit()

        asyncio.run(seed())
        body = client.get("/api/v1/detection-tuning/oracle-shadow").json()
        assert body["mode"] == "shadow"
        assert body["days"] == 7
        assert (body["recorded"], body["would_escalate"], body["classic"], body["both"]) == (
            3,
            2,
            2,
            1,
        )
        reasons = {(r["rule"], r["reason"]): (r["count"], r["overlap"]) for r in body["by_reason"]}
        assert reasons[("uncertainty", "confidence_in_band")] == (2, 1)
        assert ("uncertainty", "template_split") not in reasons
        wide = client.get("/api/v1/detection-tuning/oracle-shadow?days=30").json()
        assert wide["recorded"] == 4
    finally:
        gen.close()
