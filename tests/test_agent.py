"""Tests for :mod:`soc_ai.agent` - reasoning, prompts, routing, orchestration.

LLM calls are short-circuited via PydanticAI's ``TestModel`` which canonically
emits a ``TriageReport`` matching the ``output_type``. No network traffic,
no LiteLLM, no real models.
"""

from __future__ import annotations

import json
from ipaddress import IPv4Network
from typing import Any, ClassVar
from unittest.mock import AsyncMock, patch

import pytest
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import (
    InvestigationContext,
    build_investigator,
    investigate,
)
from soc_ai.agent.prompts import (
    INVESTIGATOR_PROMPT,
    SYNTHESIZER_PROMPT,
    build_investigator_prompt,
    build_synthesizer_prompt,
)
from soc_ai.agent.reasoning import (
    ReasoningMode,
    extract_reasoning_trace,
    reasoning_extra_body,
)
from soc_ai.agent.triage import (
    InvestigationTranscript,
    RecommendedAction,
    TriageReport,
)
from soc_ai.config import Settings
from soc_ai.enrichment.blocklists import BlocklistDB, BlocklistHit
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import AlertContext

# =====================================================================
# Reasoning trace extraction
# =====================================================================


def test_extract_reasoning_trace_plain() -> None:
    trace, content = extract_reasoning_trace("just an answer")
    assert trace is None
    assert content == "just an answer"


def test_extract_reasoning_trace_with_think_block() -> None:
    trace, content = extract_reasoning_trace(
        "<think>The user asked for X. I should look at Y.</think>The answer is 42."
    )
    assert trace == "The user asked for X. I should look at Y."
    assert content == "The answer is 42."


def test_extract_reasoning_trace_multiline_think() -> None:
    raw = "<think>line1\nline2\nline3</think>final"
    trace, content = extract_reasoning_trace(raw)
    assert trace == "line1\nline2\nline3"
    assert content == "final"


def test_extract_reasoning_trace_strips_all_blocks() -> None:
    raw = "<think>a</think>middle<think>b</think>tail"
    trace, content = extract_reasoning_trace(raw)
    # Trace returns the FIRST block; content has all blocks stripped
    assert trace == "a"
    assert content == "middletail"


def test_extract_reasoning_trace_empty() -> None:
    trace, content = extract_reasoning_trace("")
    assert trace is None
    assert content == ""


def test_reasoning_extra_body_shape() -> None:
    body = reasoning_extra_body(ReasoningMode.FULL)
    assert body["reasoning"] == {"mode": "full"}
    assert body["chat_template_kwargs"]["thinking_mode"] == "full"


# =====================================================================
# System prompt
# =====================================================================


def test_investigator_prompt_includes_rubric_and_oql_primer() -> None:
    prompt = build_investigator_prompt()
    assert "investigation rubric" in prompt.lower()
    assert "community_id" in prompt
    assert "OQL primer" in prompt


def test_oql_primer_block_teaches_exact_pipe_stage_surface() -> None:
    """U3: every OQL-running agent's primer must state the complete pipe-stage
    list, explicitly disclaim the invented `fields` projection stage, and
    state the leading-wildcard restriction."""
    from soc_ai.agent.prompts import oql_primer_block

    block = oql_primer_block()
    assert "the complete list" in block
    for stage in ("groupby", "sortby", "head", "count"):
        assert f"| {stage}" in block, f"pipe stage {stage!r} missing from primer"
    assert "NO `fields` / projection stage" in block
    assert "PARSE ERROR" in block
    assert "`*foo`" in block and "anchor the wildcard" in block
    # The addendum rides along wherever the primer goes — investigator included.
    assert "NO `fields` / projection stage" in INVESTIGATOR_PROMPT


def test_investigator_prompt_constant_matches_function() -> None:
    assert build_investigator_prompt() == INVESTIGATOR_PROMPT


def test_synthesizer_prompt_has_no_oql_primer() -> None:
    prompt = build_synthesizer_prompt()
    # The synthesizer never writes OQL, so the primer must NOT leak into its
    # context — that's a chunk of tokens we save on every synthesis call.
    assert "OQL primer" not in prompt
    assert "investigation rubric" not in prompt.lower()
    # But it must still spell out the verdict + citation policy.
    assert "verdict" in prompt.lower()
    assert "citation" in prompt.lower()


def test_synthesizer_prompt_constant_matches_function() -> None:
    assert build_synthesizer_prompt() == SYNTHESIZER_PROMPT


# =====================================================================
# TriageReport schema
# =====================================================================


def test_triage_report_validates_confidence_range() -> None:
    with pytest.raises(ValueError, match="confidence"):
        TriageReport(
            verdict="true_positive",
            confidence=1.5,
            summary="x",
            citations=["a"],
        )


def test_triage_report_recommended_action_carries_tool_call() -> None:
    action = RecommendedAction(
        tool_name="ack_alert",
        tool_args={"alert_id": "a1", "comment": "FP"},
        rationale="Internal scanner; expected.",
    )
    assert action.tool_name == "ack_alert"
    assert action.tool_args["alert_id"] == "a1"


def test_triage_report_field_reconciliation_optional() -> None:
    """field_reconciliation is optional (default None).
    When set, it's a one-line explanation of layered protocols / action
    vs severity contradictions."""
    # Default — no contradictions.
    r = TriageReport(verdict="false_positive", confidence=0.7, summary="x", citations=[])
    assert r.field_reconciliation is None
    # Set — surfaces in serialization.
    r2 = TriageReport(
        verdict="false_positive",
        confidence=0.7,
        summary="ICMP PMTUD over the same community_id as the UDP flow.",
        citations=["alert.proto"],
        field_reconciliation=(
            "alert.proto=ICMP refers to the UDP flow (PMTUD T3/C4, not a standalone TCP/UDP conn)"
        ),
    )
    assert r2.field_reconciliation
    assert "PMTUD" in r2.field_reconciliation


@pytest.mark.asyncio
async def test_triage_report_event_includes_field_reconciliation(
    settings_kratos: Settings,
) -> None:
    """The orchestrator surfaces field_reconciliation in the
    triage_report SSE event so the WebUI can render it."""
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)
    events = await _run_synth_first(
        ctx,
        report=TriageReport(
            verdict="false_positive",
            confidence=0.7,
            summary="x",
            citations=["alert.severity_label"],
            field_reconciliation="ICMP refers to the UDP flow",
        ),
        candidate=_strong_benign_candidate(),
    )
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["field_reconciliation"] == "ICMP refers to the UDP flow"
    # The verdict itself is untouched by the reconciliation note.
    assert report_ev.payload["verdict"] == "false_positive"


# =====================================================================
# Orchestrator with TestModel
# =====================================================================


def _make_ctx(
    settings: Settings,
    *,
    blocklist: BlocklistDB | None = None,
) -> InvestigationContext:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    auth = AsyncMock()
    kwargs: dict[str, Any] = {}
    if blocklist is not None:
        kwargs["blocklist"] = blocklist
    return InvestigationContext(
        settings=settings,
        auth=auth,
        elastic=elastic,
        **kwargs,
    )


def _stub_transcript(open_qs: list[str] | None = None) -> InvestigationTranscript:
    return InvestigationTranscript(
        evidence=["alert.severity_label=high (id=alert-001)"],
        tentative_summary="Internal traffic to internal target.",
        open_questions=open_qs or [],
    )


def _strong_benign_candidate() -> Any:
    """A strong benign template match (clean_internal_traffic @ 0.85).

    Rule-grounded and ≥0.8 confidence, so it exempts a zero-tool
    false_positive verdict from the hard evidence gate — the production
    shape for a trivially-benign settle."""
    from soc_ai.agent.decision_templates import CandidateVerdict

    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal scanner",
    )


async def _run_synth_first(
    ctx: InvestigationContext,
    *,
    report: TriageReport,
    candidate: Any = None,
    enriched_factory: Any = None,
    alert_id: str = "alert-001",
) -> list[Any]:
    """Drive investigate() end-to-end on the synth-first pipeline.

    Stubs the enriched prefetch (``enriched_factory``, default
    ``_stub_enriched_alert_context``), pins the decision-template match to
    ``candidate``, and wires a fake synth agent that always returns
    ``report``. Callers that need the investigation loop should set
    ``settings.investigate_when_unsure`` / ``fast_triage_enabled`` and add
    their own ``build_investigator`` / ``build_synthesizer`` patches
    instead of using this helper."""
    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    factory = enriched_factory or _stub_enriched_alert_context

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return factory(aid)

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(return_value=MagicMock(output=report))

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=candidate,
        ),
    ):
        return [ev async for ev in investigate(alert_id, ctx=ctx)]


def _fake_loop_investigator_with_zeek_call() -> Any:
    """A fake investigation-loop investigator whose ``iter()`` streams one
    successful ``t_query_zeek_logs`` call+return and then exposes a settled
    transcript result.

    The tool RETURN part matters: ``count_successful_tool_calls`` counts it,
    and only a loop with ≥1 successful call earns the evidence-gate
    exemption (see ``orchestrator._loop_evidence_marker``)."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    class _ToolCallPart(SimpleNamespace):
        pass

    class _ToolReturnPart(SimpleNamespace):
        pass

    zeek_call = _ToolCallPart(
        tool_name="t_query_zeek_logs", args={"community_id": "1:abc"}, tool_call_id="tc1"
    )
    zeek_return = _ToolReturnPart(
        tool_name="t_query_zeek_logs",
        content={"ssl": {"server_name": "evil.example.com"}},
        tool_call_id="tc1",
        part_kind="tool-return",
    )
    loop_msg = SimpleNamespace(parts=[zeek_call, zeek_return])
    loop_transcript = InvestigationTranscript(
        evidence=[
            "t_query_zeek_logs(community_id=1:abc) -> ssl.server_name=evil.example.com "
            "(tool t_query_zeek_logs)",
        ],
        tentative_summary="Zeek SSL SNI gathered.",
        open_questions=[],
    )
    inv_result = MagicMock()
    inv_result.output = loop_transcript
    inv_result.all_messages = MagicMock(return_value=[loop_msg])
    inv_result.usage = MagicMock(
        return_value=SimpleNamespace(
            tool_calls=1, requests=2, input_tokens=10, output_tokens=5, total_tokens=15
        )
    )
    fake_investigator = MagicMock()
    fake_investigator.run = AsyncMock(return_value=inv_result)
    _install_fake_iter(fake_investigator, [loop_msg], inv_result)
    return fake_investigator


@pytest.mark.asyncio
async def test_investigate_yields_session_transcript_report_done(
    settings_kratos: Settings,
) -> None:
    """A loop-running synth-first investigation yields the canonical stream:
    session_start first, an investigation_transcript stamped with the
    investigation_loop phase, a triage_report, and done last — with
    monotonically increasing sequence numbers and no Phase-D retask."""
    from unittest.mock import MagicMock

    settings_kratos.investigate_when_unsure = True
    ctx = _make_ctx(settings_kratos)

    fake_investigator = _fake_loop_investigator_with_zeek_call()
    settled_report = TriageReport(
        verdict="true_positive",
        confidence=0.9,
        summary="Confirmed beacon to evil.example.com via Zeek SSL SNI.",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    loop_synth_result = MagicMock()
    loop_synth_result.output = settled_report
    loop_synth_result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))
    fake_loop_synth = MagicMock()
    fake_loop_synth.run = AsyncMock(return_value=loop_synth_result)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)  # → definitely_investigate

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=fake_loop_synth),
    ):
        events = [ev async for ev in investigate("beacon-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert kinds[0] == "session_start"
    assert "investigation_transcript" in kinds
    transcript_ev = next(e for e in events if e.kind == "investigation_transcript")
    assert transcript_ev.payload["phase"] == "investigation_loop"
    assert "triage_report" in kinds
    assert kinds[-1] == "done"
    # Sequence numbers increase
    sequences = [e.sequence for e in events]
    assert sequences == sorted(sequences)
    # The loop supersedes Phase D → no retask on a clean run.
    assert "retask" not in kinds
    # The settled verdict carries through the post-validators.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "true_positive"


@pytest.mark.asyncio
async def test_investigate_session_id_consistent(settings_kratos: Settings) -> None:
    """Every event in one synth-first run carries the SAME session_id.

    The pipeline mints its own session id (the legacy caller-supplied
    ``session_id`` kwarg is not threaded into the synth-first stream); the
    invariant the SSE consumers rely on is per-run consistency."""
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)
    events = await _run_synth_first(
        ctx,
        report=TriageReport(
            verdict="needs_more_info",
            confidence=0.7,
            summary="Insufficient evidence.",
            citations=[],
        ),
    )
    assert events, "pipeline must emit events"
    sid = events[0].session_id
    assert sid
    assert all(e.session_id == sid for e in events)


@pytest.mark.asyncio
async def test_investigation_loop_synth_failure_falls_back_to_round1_verdict(
    settings_kratos: Settings,
) -> None:
    """A loop-synthesizer crash surfaces as a typed error event AND the
    stream still lands a structured triage_report — the settled round-1
    verdict, annotated so the operator knows the loop did not complete.
    (No verdict=None rows; failures must stay scoreable.)"""
    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    settings_kratos.fast_triage_enabled = False  # force the investigation loop
    ctx = _make_ctx(settings_kratos)

    round1_report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Benign east-west traffic.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_first_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    synth_first_agent.run = AsyncMock(return_value=MagicMock(output=round1_report))

    fake_investigator = _fake_loop_investigator_with_zeek_call()
    fake_loop_synth = MagicMock()
    fake_loop_synth.run = AsyncMock(side_effect=RuntimeError("boom"))

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=synth_first_agent,
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=fake_loop_synth),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    loop_ev = next(e for e in events if e.kind == "investigation_loop_entered")
    assert loop_ev.payload["reason"] == "fast_triage_disabled"
    error_evs = [e for e in events if e.kind == "error"]
    assert len(error_evs) == 1
    assert error_evs[0].payload["type"] == "RuntimeError"
    assert error_evs[0].payload["phase"] == "investigation_loop_synth"
    assert error_evs[0].payload["round"] == 2
    assert "boom" in error_evs[0].payload["message"]
    # Fallback: the settled round-1 verdict stands, annotated.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["confidence"] == pytest.approx(0.9)
    assert "did not complete" in report_ev.payload["summary"]
    assert [e.kind for e in events][-1] == "done"


# =====================================================================
# Pre-fetch + typed errors + retask routing (robustness pass)
# =====================================================================


@pytest.mark.asyncio
async def test_investigate_emits_enriched_alert_context_event_first(
    settings_kratos: Settings,
) -> None:
    """The pre-fetched (enriched) alert context is yielded as an SSE event
    immediately after `session_start`, before any synthesis activity, so the
    side panel can render it immediately."""
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)
    events = await _run_synth_first(
        ctx,
        report=TriageReport(
            verdict="false_positive",
            confidence=0.9,
            summary="x",
            citations=["alert.severity_label"],
        ),
        candidate=_strong_benign_candidate(),
    )

    kinds = [e.kind for e in events]
    # Order: session_start → enriched_alert_context → synthesis → ... → done.
    assert kinds[0] == "session_start"
    assert kinds[1] == "enriched_alert_context"
    # The payload mirrors the EnrichedAlertContext model_dump.
    ac_ev = events[1]
    assert ac_ev.payload["alert"]["id"] == "alert-001"
    assert ac_ev.payload["alert"]["severity_label"] == "low"
    assert "pivot_summary" in ac_ev.payload


@pytest.mark.asyncio
async def test_investigation_loop_passes_enriched_context_to_investigator_user_message(
    settings_kratos: Settings,
) -> None:
    """The loop investigator is invoked with a user message that contains the
    pre-fetched enriched alert context as JSON, so the model can never miss
    it — and is told not to re-fetch it."""
    from unittest.mock import MagicMock

    settings_kratos.investigate_when_unsure = True
    ctx = _make_ctx(settings_kratos)

    fake_investigator = _fake_loop_investigator_with_zeek_call()
    settled_report = TriageReport(
        verdict="true_positive",
        confidence=0.9,
        summary="Confirmed beacon.",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[],
    )
    loop_synth_result = MagicMock()
    loop_synth_result.output = settled_report
    loop_synth_result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))
    fake_loop_synth = MagicMock()
    fake_loop_synth.run = AsyncMock(return_value=loop_synth_result)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)  # → definitely_investigate

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=fake_loop_synth),
    ):
        [ev async for ev in investigate("beacon-001", ctx=ctx)]

    fake_investigator.iter.assert_called_once()
    prompt = fake_investigator.iter.call_args[0][0]
    assert "Triage alert beacon-001" in prompt
    assert "Pre-fetched alert context" in prompt
    # The actual JSON dump of the EnrichedAlertContext lands in the prompt.
    assert '"id":"beacon-001"' in prompt or '"id": "beacon-001"' in prompt
    # And the rubric instructs the model NOT to call get_alert_context again.
    assert "Do NOT call `t_get_alert_context`" in prompt


@pytest.mark.asyncio
async def test_investigate_stops_with_error_when_prefetch_fails(
    settings_kratos: Settings,
) -> None:
    """If enriched-context prefetch fails (alert not found, ES down), the
    stream ends with a typed error event whose `phase=='prefetch'` and a
    non-empty hint — and NO fabricated verdict. The recorder marks the run
    error (retryable) instead of landing a fake needs_more_info."""
    from soc_ai.errors import SoNotFoundError

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    async def _fail(_alert_id: str, **_kw: Any) -> Any:
        raise SoNotFoundError("alert not found: alert-001")

    with patch(
        "soc_ai.tools.get_alert_context.get_enriched_alert_context",
        side_effect=_fail,
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert kinds == ["session_start", "error"]

    err = events[1].payload
    assert err["phase"] == "prefetch"
    assert err["round"] == 0
    assert err["type"] == "SoNotFoundError"
    assert "alert not found" in err["message"]
    assert err.get("hint")


@pytest.mark.asyncio
async def test_error_event_carries_phase_round_type_and_hint(
    settings_kratos: Settings,
) -> None:
    """Errors flow through `_error_payload` and gain a hint when the exception
    type is recognized (OqlValidationError → field-name guidance)."""
    from unittest.mock import MagicMock

    from soc_ai.errors import OqlValidationError

    settings_kratos.investigate_when_unsure = True
    ctx = _make_ctx(settings_kratos)

    fake_investigator = MagicMock()
    fake_investigator.iter = MagicMock(
        side_effect=OqlValidationError("unknown or forbidden field: 'dest.ip'", fragment="dest.ip")
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)  # → definitely_investigate

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
    ):
        events = [ev async for ev in investigate("mal-001", ctx=ctx)]

    err = next(e for e in events if e.kind == "error").payload
    assert err["phase"] == "investigation_loop"
    assert err["round"] == 1
    assert err["type"] == "OqlValidationError"
    assert "dest.ip" in err["message"]
    # Hint mentions the offending fragment AND the canonical replacement.
    assert "dest.ip" in err["hint"]
    assert "destination.ip" in err["hint"]


# =====================================================================
# E1.2: Honest pipeline-fallback provenance marker
# =====================================================================


def test_synth_failure_fallback_report_stamps_pipeline_fallback_marker() -> None:
    """The synth-failure fallback report carries the pipeline_fallback marker
    (E1.2): verdict stays needs_more_info, but the report's `resolution` names
    the provenance, phase, error type, and an analyst hint — so downstream it
    renders distinctly from a genuine needs_more_info and stays out of the KPI."""
    from soc_ai.agent.orchestrator import _synth_failure_fallback_report
    from soc_ai.triage_models import is_pipeline_fallback

    # A token-limit truncation → _hint_for produces the "burned the budget" hint.
    exc = RuntimeError("token limit reached before any response was produced")
    report = _synth_failure_fallback_report("alert-9", "synth_first_round1", exc)

    # Verdict is unchanged — we do NOT invent a new verdict.
    assert report.verdict == "needs_more_info"
    assert report.confidence == pytest.approx(0.3)

    # The marker lives in the report's serialized dict under `resolution`.
    report_dict = report.model_dump(mode="json")
    assert is_pipeline_fallback(report_dict) is True
    marker = report_dict["resolution"]
    assert marker["provenance"] == "pipeline_fallback"
    assert marker["phase"] == "synth_first_round1"
    assert marker["error_type"] == "RuntimeError"
    # The hint is the analyst-actionable _hint_for string for a token-limit crash.
    assert marker["hint"] is not None
    assert "response-token cap" in marker["hint"]


def test_is_pipeline_fallback_distinguishes_manual_resolution() -> None:
    """`is_pipeline_fallback` keys on `resolution.provenance` ONLY — a manual/chat
    override's `resolution` (keyed `resolved_via`, no `provenance`) is NOT a
    pipeline fallback, so the two markers never conflate. A genuine
    needs_more_info (no resolution) is likewise False."""
    from soc_ai.triage_models import is_pipeline_fallback

    # Manual override shape (from store.investigations.resolve).
    manual = {
        "verdict": "false_positive",
        "resolution": {
            "original_verdict": "needs_more_info",
            "resolved_via": "manual",
            "resolved_by": "analyst",
            "resolved_at": "2026-07-07T00:00:00+00:00",
        },
    }
    assert is_pipeline_fallback(manual) is False

    # Genuine needs_more_info — no resolution marker at all.
    genuine = {"verdict": "needs_more_info", "citations": ["ev-1"]}
    assert is_pipeline_fallback(genuine) is False

    # Defensive: non-dict inputs never raise.
    assert is_pipeline_fallback(None) is False
    assert is_pipeline_fallback({"resolution": "not-a-dict"}) is False


# =====================================================================
# F1: Enrichment cache + prefetch materialization
# =====================================================================


def test_materialize_prefetch_evidence_includes_rule_metadata_and_pivots() -> None:
    """Helper that extracts evidence items from prefetched
    context. Should include rule_metadata, classtype, alert_action, and
    community_id pivot ids."""
    from soc_ai.agent.orchestrator import _materialize_prefetch_evidence
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert = SoAlert(
        id="a1",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
        classtype="misc-activity",
        severity_label="low",
        payload_printable=".....a-us.storyblok.com.....",
    )
    pivot = SoAlert(id="pivot-evt-1", event_dataset="zeek.conn")
    ctx = AlertContext(
        alert=alert,
        community_id_events=[pivot],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 1, "host": 0, "user": 0, "process": 0, "file": 0},
    )
    evidence = _materialize_prefetch_evidence(ctx)
    assert any("signature_severity=Informational" in e for e in evidence)
    assert any("alert_action=allowed" in e for e in evidence)
    assert any("classtype=misc-activity" in e for e in evidence)
    assert any("pivot-evt-1" in e for e in evidence)
    # All items must carry citations (path ... or id ...).
    assert all("(path " in e or "(id " in e for e in evidence)


def test_materialize_prefetch_evidence_handles_empty_prefetch() -> None:
    """Empty prefetch returns empty list — no crash, no garbage items."""
    from soc_ai.agent.orchestrator import _materialize_prefetch_evidence
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    ctx = AlertContext(alert=SoAlert(id="a"))
    assert _materialize_prefetch_evidence(ctx) == []


def test_materialize_prefetch_evidence_includes_blocklist_hits() -> None:
    """Enrichment data MUST be surfaced as materialized
    evidence so the synth doesn't have to dig into the alert_ctx JSON for
    signals as central as a Feodo blocklist hit. Eval receipts showed synth
    alerts with strong blocklist matches still hedging because the synth
    prompt's materialized_evidence block didn't name the hit explicitly.
    """
    from soc_ai.agent.orchestrator import _materialize_prefetch_evidence
    from soc_ai.enrichment.blocklists import BlocklistHit
    from soc_ai.enrichment.maxmind import AsnInfo
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.enrichment import IndicatorEnrichment
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    alert = SoAlert(
        id="a1",
        source_ip="10.0.0.42",
        destination_ip="162.243.103.246",
    )
    enrichments = {
        "162.243.103.246": IndicatorEnrichment(
            indicator="162.243.103.246",
            indicator_type="ip",
            internal=False,
            blocklist_hits=[
                BlocklistHit(
                    indicator="162.243.103.246",
                    indicator_type="ip",
                    source="abuse.ch Feodo Tracker",
                    tags=("emotet", "c2"),
                )
            ],
            asn=AsnInfo(number=14061, org="DigitalOcean"),
        ),
        "10.0.0.42": IndicatorEnrichment(
            indicator="10.0.0.42",
            indicator_type="ip",
            internal=True,
        ),
    }
    ctx = EnrichedAlertContext(
        alert=alert,
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        enrichments=enrichments,
        typed_zeek=TypedZeekFields(),
    )

    evidence = _materialize_prefetch_evidence(ctx)
    # The Feodo hit MUST be named in the materialized evidence list.
    assert any("Feodo" in e and "162.243.103.246" in e for e in evidence), (
        f"blocklist hit on Feodo Tracker not surfaced; got {evidence}"
    )
    # The hit must carry a path citation the validator can resolve.
    assert any("blocklist_hits" in e for e in evidence)


def test_materialize_prefetch_evidence_includes_misp_hits() -> None:
    """MISP findings also surfaced as materialized evidence."""
    from soc_ai.agent.orchestrator import _materialize_prefetch_evidence
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.enrichment import Finding, IndicatorEnrichment
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    alert = SoAlert(
        id="a1",
        source_ip="10.0.0.42",
        destination_ip="1.2.3.4",
    )
    enrichments = {
        "1.2.3.4": IndicatorEnrichment(
            indicator="1.2.3.4",
            indicator_type="ip",
            internal=False,
            misp_hits=[
                Finding(
                    source="misp",
                    category="ioc_match",
                    description="Emotet C2 server (MISP event 12345)",
                )
            ],
        ),
    }
    ctx = EnrichedAlertContext(
        alert=alert,
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        enrichments=enrichments,
        typed_zeek=TypedZeekFields(),
    )

    evidence = _materialize_prefetch_evidence(ctx)
    assert any("MISP" in e and "1.2.3.4" in e for e in evidence)


@pytest.mark.asyncio
async def test_verdict_floor_rewrite_below_floor(
    settings_kratos: Settings,
) -> None:
    """B3: when final confidence is
    STRICTLY below the synthesis floor, the verdict isn't already
    needs_more_info AND the report carries no semantic evidence (zero
    citations here), the orchestrator mechanically rewrites verdict to
    needs_more_info and clears recommended_actions."""
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)
    events = await _run_synth_first(
        ctx,
        report=TriageReport(
            verdict="false_positive",  # Synth says FP...
            confidence=0.45,  # ...but confidence below 0.6 floor
            summary="thin evidence",
            citations=[],  # ...and no evidence at all
        ),
    )

    rewrite_ev = next(e for e in events if e.kind == "verdict_floor_rewrite")
    assert rewrite_ev.payload["original_verdict"] == "false_positive"
    assert rewrite_ev.payload["capped_verdict"] == "needs_more_info"
    # B3: payload shape matches the synth-first validator's audit entry.
    assert rewrite_ev.payload["n_citations"] == 0
    assert "coverage_ratio" in rewrite_ev.payload
    # Final triage_report shows the rewrite.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "needs_more_info"
    assert report_ev.payload["recommended_actions"] == []


@pytest.mark.asyncio
async def test_verdict_floor_rewrite_survives_with_evidence(
    settings_kratos: Settings,
) -> None:
    """B3: the floor rewrite is evidence-conditional — a verdict whose
    citations semantically resolve SURVIVES low confidence. Citation-shape
    noise must not erase a well-evidenced verdict."""
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)
    events = await _run_synth_first(
        ctx,
        report=TriageReport(
            verdict="false_positive",
            confidence=0.55,  # below the 0.6 floor...
            summary="well-evidenced but hedged",
            # ...but the citation resolves against the prefetched bundle.
            citations=["alert.severity_label"],
        ),
        # Strong benign template: keeps the zero-tool FP past the hard
        # evidence gate so this test isolates the floor-rewrite behavior.
        candidate=_strong_benign_candidate(),
    )

    assert not any(e.kind == "verdict_floor_rewrite" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["confidence"] == pytest.approx(0.55)


@pytest.mark.asyncio
async def test_verdict_floor_rewrite_skips_when_verdict_already_nmi(
    settings_kratos: Settings,
) -> None:
    """Don't double-rewrite when verdict is already
    needs_more_info — the rewrite would be a no-op anyway, but emitting
    the SSE event would be noisy."""
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)
    events = await _run_synth_first(
        ctx,
        report=TriageReport(
            verdict="needs_more_info",
            confidence=0.3,  # well below the floor, but already NMI
            summary="x",
            citations=["alert.severity_label"],
        ),
    )

    assert not any(e.kind == "verdict_floor_rewrite" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "needs_more_info"


def _stub_icmp_ping_alert_context(
    alert_id: str = "alert-001",
    *,
    icmp_echo: bool = True,
) -> AlertContext:
    """AlertContext for the BPFDoor-class false escalation (B2).

    Mirrors the field finding: an 'ET MALWARE BPFDoor ICMP Echo Reply'
    alert on a benign internal ping. The community_id pivot carries the
    Zeek conn record whose ICMP pseudo-ports (orig_p=8 → resp_p=0) prove
    the echo was solicited. With ``icmp_echo=False`` the pivot is a plain
    TCP conn instead — the downgrade must NOT fire on that shape (protects
    internal lateral-movement TPs)."""
    conn_message = (
        json.dumps({"proto": "icmp", "id.orig_p": 8, "id.resp_p": 0, "conn_state": "OTH"})
        if icmp_echo
        else json.dumps({"proto": "tcp", "id.orig_p": 51515, "id.resp_p": 445, "conn_state": "SF"})
    )
    zeek_conn_pivot = SoAlert(
        id="zeek-conn-001",
        event_dataset="zeek.conn",
        message=conn_message,
        source_ip="10.20.30.1",
        destination_ip="10.20.30.15",
    )
    return AlertContext(
        alert=SoAlert(
            id=alert_id,
            severity_label="high",
            rule_name="ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat (Outbound)",
            classtype="trojan-activity",
            source_ip="10.20.30.1",
            destination_ip="10.20.30.15",
        ),
        community_id_events=[zeek_conn_pivot],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 1, "host": 0, "user": 0, "process": 0, "file": 0},
    )


def _loaded_blocklist(*, hit_ips: tuple[str, ...] = ()) -> BlocklistDB:
    """A BlocklistDB that LOADED at least one source (so it can prove
    cleanliness), optionally seeded with IP hits. Mirrors the singleton
    the enrich_* tools receive via ``build_local_enrichment_context``."""
    db = BlocklistDB()
    db.loaded_sources.append("threatfox")
    for ip in hit_ips:
        db.ips[ip] = [
            BlocklistHit(
                indicator=ip,
                indicator_type="ip",
                source="abuse.ch ThreatFox",
                tags=("c2",),
            )
        ]
    return db


def _bpfdoor_tp_report() -> TriageReport:
    return TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="BPFDoor ICMP heartbeat — symmetric byte counts indicate C2 tunnel.",
        citations=["alert.rule_name"],
    )


def _icmp_enriched_variant(
    alert_id: str = "alert-001",
    *,
    icmp_echo: bool = True,
    with_enrichments: bool = True,
    blocklisted_dst: bool = False,
) -> Any:
    """EnrichedAlertContext variants for the BPFDoor-class ICMP ping (B2).

    Default shape: typed_zeek proves the solicited echo (type-8 → type-0)
    and both endpoints carry clean internal IndicatorEnrichment entries —
    the ``"enrichment"`` verification branch of
    ``_is_solicited_internal_icmp_echo``. ``blocklisted_dst`` seeds a
    blocklist hit on the destination's enrichment (vetoes the downgrade);
    ``with_enrichments=False`` drops the per-indicator enrichments (forces
    the explicit-blocklist branch, which then demands ``ctx.blocklist``
    proof); ``icmp_echo=False`` removes the echo signal (plain TCP conn —
    the lateral-movement shape the downgrade must never touch)."""
    from soc_ai.enrichment.zeek_parser import TypedZeekFields
    from soc_ai.tools.enrichment import IndicatorEnrichment
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    src, dst = "10.20.30.1", "10.20.30.15"
    enrichments: dict[str, Any] = {}
    if with_enrichments:
        dst_hits = (
            [
                BlocklistHit(
                    indicator=dst,
                    indicator_type="ip",
                    source="abuse.ch ThreatFox",
                    tags=("c2",),
                )
            ]
            if blocklisted_dst
            else []
        )
        enrichments = {
            src: IndicatorEnrichment(indicator=src, indicator_type="ip", internal=True),
            dst: IndicatorEnrichment(
                indicator=dst, indicator_type="ip", internal=True, blocklist_hits=dst_hits
            ),
        }
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            rule_name="ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat (Outbound)",
            classtype="trojan-activity",
            source_ip=src,
            destination_ip=dst,
            severity_label="high",
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(icmp_echo_request_reply=icmp_echo),
        enrichments=enrichments,
    )


async def _run_synth_first_icmp_investigation(
    ctx: InvestigationContext,
    *,
    report: TriageReport | None = None,
    **variant_kw: Any,
) -> list[Any]:
    """Drive investigate() end-to-end against the BPFDoor ping prefetch."""
    ctx.settings.investigate_when_unsure = False  # isolate the validator chain
    return await _run_synth_first(
        ctx,
        report=report or _bpfdoor_tp_report(),
        enriched_factory=lambda aid: _icmp_enriched_variant(aid, **variant_kw),
    )


@pytest.mark.asyncio
async def test_synth_first_downgrades_solicited_icmp_echo_tp(
    settings_kratos: Settings,
) -> None:
    """B2: a true_positive resting on a solicited internal ICMP echo
    (the BPFDoor false-escalation shape) is deterministically downgraded to
    false_positive by `_synth_first_post_validate` /
    `_apply_targeted_downgrades`.

    The enriched context carries clean internal enrichments for both
    endpoints, so the verification that ran is the enrichment-derived
    IOC scan — and the audit reason must say exactly that (not the
    explicit-blocklist wording used for enrichment-less contexts)."""
    ctx = _make_ctx(settings_kratos)
    events = await _run_synth_first_icmp_investigation(ctx)

    dg_ev = next(e for e in events if e.kind == "icmp_solicited_downgrade")
    assert dg_ev.payload["original_verdict"] == "true_positive"
    assert dg_ev.payload["downgraded_verdict"] == "false_positive"
    assert "solicited" in dg_ev.payload["reason"]
    # The reason states what actually ran: the enrichment-derived IOC scan
    # ("no blocklist/MISP hit") — NOT the explicit-blocklist wording, which
    # is reserved for contexts that carry no enrichments.
    assert "no blocklist/MISP hit" in dg_ev.payload["reason"]
    assert "explicit blocklist lookup" not in dg_ev.payload["reason"]
    # Final report downgraded, actions cleared, confidence capped at 0.8.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["recommended_actions"] == []
    assert report_ev.payload["confidence"] == pytest.approx(0.8)
    # Summary must lead with the correct conclusion — no confusing inline bracket.
    assert not report_ev.payload["summary"].lower().startswith("[auto-corrected")
    assert "solicited" in report_ev.payload["summary"].lower()
    # Original synth narrative preserved in validator_note, not in summary.
    assert "symmetric byte counts" not in report_ev.payload["summary"]
    assert "symmetric byte counts" in (report_ev.payload.get("validator_note") or "")


@pytest.mark.asyncio
async def test_icmp_downgrade_refused_when_endpoint_blocklisted(
    settings_kratos: Settings,
) -> None:
    """A blocklist hit on either endpoint (e.g. operator-curated
    internal_seed.yaml flagging a known-bad internal host) must veto the
    downgrade — the TP survives end-to-end (the concrete IOC hit also
    exempts it from the malware-rule-name and hard evidence gates)."""
    ctx = _make_ctx(settings_kratos)
    events = await _run_synth_first_icmp_investigation(ctx, blocklisted_dst=True)

    assert not any(e.kind == "icmp_solicited_downgrade" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "true_positive"


@pytest.mark.asyncio
async def test_icmp_downgrade_refused_when_blocklist_unavailable(
    settings_kratos: Settings,
) -> None:
    """Absence of proof is not proof: a context with NO per-indicator
    enrichments demands an EXPLICIT blocklist probe, and when the blocklist
    source is unavailable (default-empty BlocklistDB — zero loaded sources)
    the downgrade must NOT fire. The alert is never auto-cleared to
    false_positive; the uncorroborated zero-tool TP is instead coerced to
    needs_more_info by the malware-rule-name gate (investigate, don't
    rationalize) — wrongly suppressing a real TP as benign is worse than
    letting a false escalation through."""
    ctx = _make_ctx(settings_kratos)  # no blocklist on ctx
    events = await _run_synth_first_icmp_investigation(ctx, with_enrichments=False)

    assert not any(e.kind == "icmp_solicited_downgrade" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] != "false_positive"
    # GATE A (#21) picks it up instead: TP on a malware-signalling rule with
    # no corroboration → needs_more_info for a real investigation.
    assert any(e.kind == "malware_rule_name_ungrounded_downgrade" for e in events)
    assert report_ev.payload["verdict"] == "needs_more_info"


@pytest.mark.asyncio
async def test_synth_first_keeps_internal_tp_without_icmp_echo(
    settings_kratos: Settings,
) -> None:
    """B2 scope guard: internal→internal WITHOUT a solicited ICMP echo
    (e.g. SMB lateral movement) must NOT be touched by the ICMP downgrade —
    protects h2-PsExec / h1-Kerberoasting class TPs from being auto-cleared
    as benign. (The zero-tool TP still lands in needs_more_info via the
    malware-rule-name gate — investigated, never suppressed to FP.)"""
    ctx = _make_ctx(settings_kratos)
    events = await _run_synth_first_icmp_investigation(
        ctx,
        report=TriageReport(
            verdict="true_positive",
            confidence=0.85,
            summary="SMB lateral movement to the DC.",
            citations=["alert.rule_name"],
        ),
        icmp_echo=False,
    )

    assert not any(e.kind == "icmp_solicited_downgrade" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] != "false_positive"
    assert report_ev.payload["verdict"] == "needs_more_info"


def test_legacy_downgrade_internal_cidrs_narrower_than_rfc1918() -> None:
    """Internal-semantics parity: on the enriched path "internal" means
    membership in settings.internal_cidrs. The legacy fallback must use the
    same definition — a 10.x endpoint OUTSIDE a narrower internal_cidrs is
    NOT internal, so no downgrade. The ipaddress is_private fallback applies
    ONLY when internal_cidrs is empty/unset."""
    from soc_ai.agent.orchestrator import _is_solicited_internal_icmp_echo

    alert_ctx = _stub_icmp_ping_alert_context()  # endpoints 10.20.30.1 → .15
    bl = _loaded_blocklist()

    narrow = [IPv4Network("192.168.0.0/16")]
    assert _is_solicited_internal_icmp_echo(alert_ctx, blocklist=bl, internal_cidrs=narrow) is None
    # Sanity contrast: a covering CIDR opens the gate via the explicit lookup.
    covering = [IPv4Network("10.0.0.0/8")]
    assert (
        _is_solicited_internal_icmp_echo(alert_ctx, blocklist=bl, internal_cidrs=covering)
        == "explicit_blocklist_lookup"
    )
    # Empty/unset internal_cidrs → preserve the ipaddress-based fallback.
    assert (
        _is_solicited_internal_icmp_echo(alert_ctx, blocklist=bl, internal_cidrs=None)
        == "explicit_blocklist_lookup"
    )


def test_legacy_downgrade_refused_when_blocklist_lookup_raises() -> None:
    """An unloadable/erroring blocklist on the legacy path = no proof = no
    downgrade (never fail-open into suppressing a TP)."""
    from soc_ai.agent.orchestrator import _is_solicited_internal_icmp_echo

    class _ExplodingBlocklist:
        loaded_sources: ClassVar[list[str]] = ["threatfox"]

        def lookup_ip(self, ip: str) -> list[Any]:
            raise RuntimeError("blocklist backend gone")

    alert_ctx = _stub_icmp_ping_alert_context()
    assert _is_solicited_internal_icmp_echo(alert_ctx, blocklist=_ExplodingBlocklist()) is None


def test_legacy_downgrade_refused_when_endpoint_ip_missing() -> None:
    """A None source_ip or destination_ip on the legacy path means no proof
    of cleanliness — no downgrade (fail toward keeping the TP)."""
    from soc_ai.agent.orchestrator import _is_solicited_internal_icmp_echo

    bl = _loaded_blocklist()
    conn_message = json.dumps(
        {"proto": "icmp", "id.orig_p": 8, "id.resp_p": 0, "conn_state": "OTH"}
    )
    zeek_conn_pivot = SoAlert(
        id="zeek-conn-001",
        event_dataset="zeek.conn",
        message=conn_message,
        source_ip="10.20.30.1",
        destination_ip="10.20.30.15",
    )
    # Alert with missing source_ip — cannot prove cleanliness, no downgrade.
    alert_no_src = AlertContext(
        alert=SoAlert(
            id="alert-no-src",
            source_ip=None,
            destination_ip="10.20.30.15",
        ),
        community_id_events=[zeek_conn_pivot],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 1, "host": 0, "user": 0, "process": 0, "file": 0},
    )
    assert _is_solicited_internal_icmp_echo(alert_no_src, blocklist=bl) is None
    # Alert with missing destination_ip — same: no downgrade.
    alert_no_dst = AlertContext(
        alert=SoAlert(
            id="alert-no-dst",
            source_ip="10.20.30.1",
            destination_ip=None,
        ),
        community_id_events=[zeek_conn_pivot],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 1, "host": 0, "user": 0, "process": 0, "file": 0},
    )
    assert _is_solicited_internal_icmp_echo(alert_no_dst, blocklist=bl) is None


# =====================================================================
# Coverage floor + dedup gate + reasoning cap
# =====================================================================


def test_dedup_tracker_first_call_passes_second_call_dups() -> None:
    """Same (tool_name, args) seen twice → second call is duplicate."""
    from soc_ai.agent.orchestrator import _DedupTracker

    tracker = _DedupTracker()
    args = {"query": "rule.name:foo", "max_results": 10}
    assert tracker.is_duplicate("t_query_events_oql", args) is False
    assert tracker.is_duplicate("t_query_events_oql", args) is True


def test_dedup_tracker_normalizes_arg_order() -> None:
    """{a:1, b:2} and {b:2, a:1} hash the same — dict-order shouldn't fool dedup."""
    from soc_ai.agent.orchestrator import _DedupTracker

    tracker = _DedupTracker()
    assert tracker.is_duplicate("t", {"a": 1, "b": 2}) is False
    assert tracker.is_duplicate("t", {"b": 2, "a": 1}) is True


def test_dedup_tracker_distinct_tools_dont_collide() -> None:
    """Same args with different tool_name are NOT duplicates."""
    from soc_ai.agent.orchestrator import _DedupTracker

    tracker = _DedupTracker()
    args = {"query": "x"}
    assert tracker.is_duplicate("t_query_cases", args) is False
    assert tracker.is_duplicate("t_query_detections", args) is False  # different tool


def test_dedup_result_helper_returns_payload_on_dup(settings_kratos: Settings) -> None:
    """_dedup_result returns a structured payload only on duplicates."""
    from soc_ai.agent.orchestrator import _dedup_result

    ctx = _make_ctx(settings_kratos)
    args = {"query": "foo", "max_results": 10}
    assert _dedup_result(ctx, "t_query_events_oql", args) is None  # first call
    dup = _dedup_result(ctx, "t_query_events_oql", args)
    assert dup is not None
    assert dup["duplicate_call"] is True
    assert dup["tool_name"] == "t_query_events_oql"
    assert "hint" in dup


def test_investigator_agent_has_higher_retry_budget(
    settings_kratos: Settings,
) -> None:
    """The investigator agent's `retries` is bumped above the
    PydanticAI default so Nemotron-30B's schema-format wobble (it often
    needs 2-3 attempts to land a valid InvestigationTranscript JSON)
    doesn't blow the run."""
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import build_investigator

    ctx = _make_ctx(settings_kratos)
    agent = build_investigator(TestModel(), ctx)
    assert agent._max_output_retries >= 3


# The four online-enrichment tools gated behind the master egress toggle.
_ONLINE_ENRICHMENT_TOOLS = {
    "t_greynoise",
    "t_shodan_internetdb",
    "t_shodan_host",
    "t_cve_lookup",
}


def test_investigator_online_tools_not_registered_when_enrichment_off(
    settings_kratos: Settings,
) -> None:
    """U4: with allow_online_enrichment=False the online tools must not be
    REGISTERED at all — otherwise the model burns a tool-budget slot per call
    just to receive a 'skipped (online enrichment off)' result."""
    assert settings_kratos.allow_online_enrichment is False  # fixture default
    agent = build_investigator(TestModel(), _make_ctx(settings_kratos))
    tool_names = set(agent._function_toolset.tools.keys())  # type: ignore[attr-defined]
    assert not (_ONLINE_ENRICHMENT_TOOLS & tool_names), (
        f"online tools registered despite allow_online_enrichment=False: "
        f"{sorted(_ONLINE_ENRICHMENT_TOOLS & tool_names)}"
    )
    # The core read surface is unaffected by the gate.
    assert "t_query_events_oql" in tool_names


def test_investigator_online_tools_registered_when_enrichment_on(
    settings_kratos: Settings,
) -> None:
    settings_on = settings_kratos.model_copy(update={"allow_online_enrichment": True})
    agent = build_investigator(TestModel(), _make_ctx(settings_on))
    tool_names = set(agent._function_toolset.tools.keys())  # type: ignore[attr-defined]
    assert tool_names >= _ONLINE_ENRICHMENT_TOOLS, (
        f"missing online tools with allow_online_enrichment=True: "
        f"{sorted(_ONLINE_ENRICHMENT_TOOLS - tool_names)}"
    )


def test_investigator_model_has_response_token_cap(
    settings_kratos: Settings,
) -> None:
    """F2: investigator model carries `max_tokens` set to
    `settings.investigator_max_response_tokens` so a chatty turn can't
    burn the per-alert wallclock on reasoning trace alone.

    History: round-2 attempted `extra_body=reasoning_extra_body(LOW_EFFORT)`
    and reverted (it broke `final_result` tool calls). The `max_tokens`
    approach is a different mechanism — it just truncates the response.
    """
    from soc_ai.agent.orchestrator import build_investigator_model

    inv = build_investigator_model(settings_kratos)
    assert inv.settings is not None
    assert inv.settings.get("max_tokens") == settings_kratos.investigator_max_response_tokens


def test_synthesizer_model_has_explicit_response_cap(
    settings_kratos: Settings,
) -> None:
    """The synth ALWAYS sends an explicit max_tokens. "Unrestricted" really
    meant "provider default" — and on a reasoning model that accidental budget
    can be consumed entirely by thinking, truncating before any TriageReport is
    generated (observed live: 'Model token limit (provider default) exceeded
    before any response was generated' → fallback NMI). The knob keeps the
    budget generous but real."""
    from soc_ai.agent.orchestrator import build_synthesizer_model

    synth = build_synthesizer_model(settings_kratos)
    assert synth.settings is not None
    assert synth.settings.get("max_tokens") == settings_kratos.synthesizer_max_response_tokens
    # temperature merges alongside the cap when given
    warm = build_synthesizer_model(settings_kratos, temperature=0.1)
    assert warm.settings is not None
    assert warm.settings.get("max_tokens") == settings_kratos.synthesizer_max_response_tokens
    assert warm.settings.get("temperature") == 0.1


@pytest.mark.asyncio
async def test_zeek_logs_short_circuits_when_community_id_prefetched(
    settings_kratos: Settings,
) -> None:
    """The orchestrator pre-populates `prefetched_community_ids` from the
    alert + its community_id_events. A subsequent `t_query_zeek_logs`
    call with that community_id returns a structured short-circuit
    payload instead of hitting ES."""
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import build_investigator

    ctx = _make_ctx(settings_kratos)
    ctx.prefetched_community_ids = {"1:abc=="}
    model = TestModel(call_tools=[], custom_output_args=_stub_transcript())
    agent = build_investigator(model, ctx)

    # Reach into the agent's tool registry to invoke the wrapper directly,
    # bypassing the LLM. The wrapper is a closure over `ctx` so it sees
    # the prefetched_community_ids set.
    tool = agent._function_toolset.tools["t_query_zeek_logs"]
    result = await tool.function(community_id="1:abc==")
    assert result["prefetch_already_has_this"] is True
    assert result["community_id"] == "1:abc=="
    assert "hint" in result


def test_clamp_tool_result_passes_small_values_through() -> None:
    """Small lists and dicts return unchanged."""
    from soc_ai.agent.orchestrator import _clamp_tool_result

    assert _clamp_tool_result([{"a": 1}]) == [{"a": 1}]
    assert _clamp_tool_result({"k": "v"}) == {"k": "v"}
    assert _clamp_tool_result("short") == "short"


def test_clamp_tool_result_truncates_large_lists() -> None:
    """A list whose serialization exceeds the budget is truncated and signaled."""
    from soc_ai.agent.orchestrator import _TOOL_RESULT_BUDGET_BYTES, _clamp_tool_result

    big = [{"i": i, "pad": "x" * 200} for i in range(200)]
    out = _clamp_tool_result(big)
    assert isinstance(out, dict)
    assert out["truncated"] is True
    assert out["total"] == 200
    assert 0 < out["shown"] < 200
    # The clipped serialization MUST fit the budget.
    import json as _json

    assert len(_json.dumps(out["items"])) <= _TOOL_RESULT_BUDGET_BYTES
    # Items kept are a prefix slice of the original.
    assert out["items"] == big[: out["shown"]]


def test_clamp_tool_result_marks_oversize_dicts_with_flag() -> None:
    """A dict over budget gets a __truncated__ marker but keeps its keys."""
    from soc_ai.agent.orchestrator import _clamp_tool_result

    big = {"alert": {"x": "y" * (16 * 1024)}}
    out = _clamp_tool_result(big)
    assert out["__truncated__"] is True
    # Original keys preserved.
    assert "alert" in out
    assert out["__total_bytes__"] > 0


def test_clamp_tool_result_slices_es_envelope_hits() -> None:
    """An EsSearchResult-shape dict (wrapper + ``hits`` list) gets its
    ``hits`` list bisected to fit budget — the wrapper survives. Without
    this path, a single t_query_events_oql call returning 100 fat docs
    sneaks through unsliced and bloats the investigator's context."""
    from soc_ai.agent.orchestrator import _TOOL_RESULT_BUDGET_BYTES, _clamp_tool_result

    big = {
        "total": 12345,
        "took_ms": 17,
        "aggregations": None,
        "hits": [{"_id": f"abc{i}", "_source": {"pad": "x" * 400}} for i in range(200)],
    }
    out = _clamp_tool_result(big)
    assert out["__truncated__"] is True
    # Wrapper survives.
    assert out["total"] == 12345
    assert out["took_ms"] == 17
    # Slicing happened.
    assert out["__total_items__"] == 200
    assert 0 < out["__shown_items__"] < 200
    assert len(out["hits"]) == out["__shown_items__"]
    # Whole envelope now fits the budget.
    assert len(json.dumps(out)) <= _TOOL_RESULT_BUDGET_BYTES


def test_classify_citation_recognizes_three_kinds() -> None:
    """Synth citations may be `(id ...)`, `(path ...)`, or
    `(tool ...)`. The classifier must extract the kind and target."""
    from soc_ai.agent.orchestrator import _classify_citation

    assert _classify_citation("(id sB86B54BVBs3R9hX_qZR)") == ("id", "sB86B54BVBs3R9hX_qZR")
    assert _classify_citation("(path alert.rule_metadata.signature_severity)") == (
        "path",
        "alert.rule_metadata.signature_severity",
    )
    assert _classify_citation("(tool t_enrich_ip:result.internal=true)") == (
        "tool",
        "t_enrich_ip",
    )
    # Forgiving on outer parens.
    assert _classify_citation("path alert.dns_query") == ("path", "alert.dns_query")
    # Unknown shape doesn't classify.
    assert _classify_citation("just some text") == ("unknown", None)


def test_classify_citation_plain_form_fallback() -> None:
    """Live smoke testing showed the model emits
    plain-form citations most of the time (no `(path ...)` wrapper)
    rather than the explicit-prefix form. The classifier accepts both
    so the validator's metrics aren't dominated by `unknown`."""
    from soc_ai.agent.orchestrator import _classify_citation

    # Plain dotted path → path
    assert _classify_citation("alert.rule_metadata.signature_severity") == (
        "path",
        "alert.rule_metadata.signature_severity",
    )
    assert _classify_citation("alert.dns_query") == ("path", "alert.dns_query")
    # Plain long alphanumeric → id
    assert _classify_citation("FDG7CZ4BVBs3R9hXQbPW") == ("id", "FDG7CZ4BVBs3R9hXQbPW")
    assert _classify_citation("KDG7CZ4BVBs3R9hXQbPY") == ("id", "KDG7CZ4BVBs3R9hXQbPY")
    # Short tokens / words don't false-positive.
    assert _classify_citation("foo") == ("unknown", None)
    assert _classify_citation("a short note") == ("unknown", None)


def test_path_exists_in_alert_walks_typed_fields() -> None:
    """The path validator walks against the AlertContext dump.
    `alert.rule_metadata.signature_severity` IS legal when populated;
    a typo'd path must reject."""
    from soc_ai.agent.orchestrator import _path_exists_in_alert
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert = SoAlert(
        id="a1",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        dns_query="example.com",
    )
    ctx = AlertContext(alert=alert)

    assert _path_exists_in_alert(ctx, "alert.rule_metadata.signature_severity") is True
    assert _path_exists_in_alert(ctx, "alert.dns_query") is True
    # Typo rejects.
    assert _path_exists_in_alert(ctx, "alert.rule_metadata.signature_sevarity") is False
    # Missing top-level pivot rejects.
    assert _path_exists_in_alert(ctx, "host_events.7.id") is False


def test_validate_citations_returns_coverage_ratio_and_preserves_all_citations() -> None:
    """`_resolve_citations` returns `coverage_ratio` (the new
    semantic measure) while preserving `invalid_ratio` for backward-compat.
    Unlike the legacy validator, ALL citations are preserved in
    `valid_citations` — the cap reflects coverage instead of stripping.
    """
    from soc_ai.agent.orchestrator import _resolve_citations
    from soc_ai.agent.triage import InvestigationTranscript
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert = SoAlert(
        id="a1",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
    )
    ctx = AlertContext(alert=alert)
    transcript = InvestigationTranscript(
        evidence=["t_enrich_ip ran"],
        tentative_summary="x",
    )
    citations = [
        "alert.rule_metadata.signature_severity",  # strict path — resolves
        "(id KDG7CZ4BVBs3R9hX)",  # strict id — resolves (model-trusted)
        "alert.bogus_field",  # path resolution fails; semantic fallback also fails
        "(tool t_enrich_domain)",  # tool ref — not invoked; semantic fallback fails
    ]
    out = _resolve_citations(citations, ctx, [transcript])
    assert out["total"] == 4
    assert out["counts"]["valid"] == 2  # 2 of 4 resolved
    assert out["coverage_ratio"] == 0.5
    assert out["invalid_ratio"] == 0.5  # legacy backward-compat
    # All 4 citations preserved in valid_citations (we don't strip).
    assert len(out["valid_citations"]) == 4
    for c in citations:
        assert c in out["valid_citations"]


def test_validate_citations_tool_ref_requires_actual_tool_call() -> None:
    """F7: tool-ref citations must be backed by a real
    ToolCallPart in the message history, not just a substring in evidence
    text. Catches the 'model claims to have called t_enrich_ip but never
    did' failure mode. Under semantic resolution the citation is still
    unresolved if the tool wasn't called AND the tool name doesn't appear
    semantically in the bundle.
    """
    from soc_ai.agent.orchestrator import _resolve_citations
    from soc_ai.agent.triage import InvestigationTranscript
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    ctx = AlertContext(alert=SoAlert(id="a"))
    transcript = InvestigationTranscript(
        evidence=["claims to have called t_enrich_ip but didn't"],
        tentative_summary="x",
    )

    # Without any ToolCallPart for t_enrich_ip, the citation is unresolved
    # (tool name isn't in the empty alert_ctx bundle either).
    out = _resolve_citations(
        ["(tool t_enrich_ip)"],
        ctx,
        [transcript],
        messages=[_msg(("t_query_zeek_logs", {"community_id": "x"}))],
    )
    assert out["counts"]["unresolved"] == 1
    assert out["counts"]["valid"] == 0
    # WITH a ToolCallPart for t_enrich_ip, the citation resolves strictly.
    out2 = _resolve_citations(
        ["(tool t_enrich_ip)"],
        ctx,
        [transcript],
        messages=[_msg(("t_enrich_ip", {"ip": "8.8.8.8"}))],
    )
    assert out2["counts"]["valid"] == 1
    assert out2["counts"]["strict"] == 1


def test_validate_citations_legacy_substring_fallback_when_no_messages() -> None:
    """F7: when `messages` is None (legacy callers), falls back to the
    pre-F7 substring-on-evidence behavior to avoid breaking those callers."""
    from soc_ai.agent.orchestrator import _validate_citations
    from soc_ai.agent.triage import InvestigationTranscript
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    ctx = AlertContext(alert=SoAlert(id="a"))
    transcript = InvestigationTranscript(
        evidence=["t_enrich_ip ran"],
        tentative_summary="x",
    )
    # No `messages` argument — falls back to substring match in evidence.
    out = _validate_citations(["(tool t_enrich_ip)"], ctx, [transcript])
    assert out["counts"]["valid"] == 1


def test_citation_confidence_cap_uses_banded_penalty() -> None:
    """Replaces legacy multiplicative-to-zero scaling with
    banded penalties so confidence is never erased by citation-shape
    mismatches. Detailed band tests are in
    ``tests/test_validator_model_variance.py::TestBandedConfidenceCap``.
    """
    from soc_ai.agent.orchestrator import _citation_confidence_cap

    # coverage 1.0 → no cap.
    assert _citation_confidence_cap(0.9, coverage_ratio=1.0) == 0.9
    # coverage 0.5 → band ≥0.5 → 0.9x → 0.9 * 0.9 = 0.81. NEVER 0.45 like legacy.
    assert _citation_confidence_cap(0.9, coverage_ratio=0.5) == pytest.approx(0.81)
    # Legacy `invalid_ratio` kwarg still accepted (backward-compat).
    assert _citation_confidence_cap(0.9, invalid_ratio=0.5) == pytest.approx(0.81)
    # Already-below-floor confidence is preserved unchanged — the cap is
    # a *reduction* mechanism, not a reshape; double-penalizing genuine
    # low-confidence reports defeats the verdict-floor's purpose.
    assert _citation_confidence_cap(0.3, coverage_ratio=0.5, floor=0.4) == pytest.approx(0.3)


# =====================================================================
# pydantic-ai message stand-ins (shared unit-test fakes)
# =====================================================================


class _FakeToolCallPart:
    """Stand-in for pydantic_ai.messages.ToolCallPart for unit tests."""

    def __init__(self, tool_name: str, args: dict[str, Any] | str):
        self.tool_name = tool_name
        self.args = args


class _FakeMessage:
    """Stand-in for pydantic_ai.messages.ModelRequest/Response for unit tests."""

    def __init__(self, parts: list[Any]):
        self.parts = parts


def _msg(*tool_calls: tuple[str, dict[str, Any] | str]) -> _FakeMessage:
    return _FakeMessage([_FakeToolCallPart(t, a) for t, a in tool_calls])


class _FakeToolReturnPart:
    """Stand-in for pydantic_ai.messages.ToolReturnPart for unit tests."""

    def __init__(self, tool_name: str, content: Any):
        self.tool_name = tool_name
        self.content = content
        # count_successful_tool_calls now discriminates on part_kind, so the
        # stub must carry the real ToolReturnPart discriminator.
        self.part_kind = "tool-return"


def test_validate_citations_classifies_and_counts() -> None:
    """End-to-end mix under the semantic-resolution schema.

    The legacy per-kind invalid_path / invalid_tool / unknown counters are
    collapsed into a single `unresolved` bucket — the new ``per_citation``
    list carries the per-citation detail (kind + resolution_kind) for any
    consumer that needs the breakdown.
    """
    from soc_ai.agent.orchestrator import _resolve_citations
    from soc_ai.agent.triage import InvestigationTranscript
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert = SoAlert(
        id="a1",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
    )
    ctx = AlertContext(alert=alert)
    transcript = InvestigationTranscript(
        evidence=["t_enrich_ip returned reputation=null for 10.0.0.1"],
        tentative_summary="benign",
    )

    citations = [
        "(id KDG7CZ4BVBs3R9hXQbPY)",  # strict id
        "(path alert.rule_metadata.signature_severity)",  # strict path
        "(path alert.host_name)",  # strict path fails; semantic fallback also fails
        "(tool t_enrich_ip)",  # tool was invoked per transcript evidence — resolves
        "(tool t_enrich_domain)",  # tool not invoked, name not in bundle → unresolved
        "freeform reasoning",  # unknown form; tokens fail semantic match
    ]
    out = _resolve_citations(citations, ctx, [transcript])

    assert out["total"] == 6
    # 3 resolve (id + valid path + valid tool), 3 don't.
    assert out["counts"]["valid"] == 3
    assert out["counts"]["unresolved"] == 3
    # The new schema carries per-citation detail for any consumer that
    # needs the path/tool/unknown breakdown.
    per_kind = {p["kind"] for p in out["per_citation"]}
    assert "path" in per_kind
    assert "tool" in per_kind
    # Sample of bad citations bounded.
    assert len(out["invalid_examples"]) >= 2
    assert all(len(e) <= 160 for e in out["invalid_examples"])


def test_clamp_tool_result_slices_other_envelope_keys() -> None:
    """Same path for dicts whose nested list lives under ``items`` or
    ``rows`` (Zeek tools, page-shaped tools)."""
    from soc_ai.agent.orchestrator import _TOOL_RESULT_BUDGET_BYTES, _clamp_tool_result

    big = {"total": 99, "rows": [{"v": "x" * 500} for _ in range(100)]}
    out = _clamp_tool_result(big)
    assert out["__truncated__"] is True
    assert len(out["rows"]) < 100
    assert len(json.dumps(out)) <= _TOOL_RESULT_BUDGET_BYTES


@pytest.mark.asyncio
async def test_walk_message_lifts_thinking_part_into_reasoning_trace() -> None:
    """A ThinkingPart in a model message becomes the reasoning_trace on the
    next emitted model_response. Verifies the Nemotron `reasoning_content`
    plumbing — without it, the trace is silently dropped.
    """
    from pydantic_ai.messages import (
        ModelResponse,
        TextPart,
        ThinkingPart,
    )
    from soc_ai.agent.orchestrator import StepEvent, _walk_message

    msg = ModelResponse(
        parts=[
            ThinkingPart(content="The user wants me to triage. Let me start with..."),
            TextPart(content="OK, I see the alert is benign DNS traffic."),
        ]
    )

    seq = 0

    def _ev(kind: str, payload: dict[str, Any]) -> StepEvent:
        nonlocal seq
        seq += 1
        return StepEvent(kind=kind, session_id="t", sequence=seq, payload=payload)

    events = [ev async for ev in _walk_message(msg, _ev, phase="investigator", round_num=1)]

    assert len(events) == 1
    assert events[0].kind == "model_response"
    p = events[0].payload
    assert "OK, I see the alert" in p["content"]
    assert "user wants me to triage" in p["reasoning_trace"]
    assert p["phase"] == "investigator"
    assert p["round"] == 1


@pytest.mark.asyncio
async def test_walk_message_emits_standalone_reasoning_when_no_textpart() -> None:
    """If a model message has only ThinkingPart (no TextPart, e.g. tool-only
    turn), the trace is emitted as a standalone model_response so it isn't
    silently dropped."""
    from pydantic_ai.messages import (
        ModelResponse,
        ThinkingPart,
        ToolCallPart,
    )
    from soc_ai.agent.orchestrator import StepEvent, _walk_message

    msg = ModelResponse(
        parts=[
            ThinkingPart(content="I should call query_zeek_logs first."),
            ToolCallPart(
                tool_name="t_query_zeek_logs",
                args={"community_id": "1:abc"},
                tool_call_id="x",
            ),
        ]
    )

    seq = 0

    def _ev(kind: str, payload: dict[str, Any]) -> StepEvent:
        nonlocal seq
        seq += 1
        return StepEvent(kind=kind, session_id="t", sequence=seq, payload=payload)

    events = [ev async for ev in _walk_message(msg, _ev, phase="investigator", round_num=1)]

    # Expect: tool_call (from ToolCallPart) + model_response (carrying the
    # reasoning_trace, no TextPart text). Order: tool_call first, then trace.
    kinds = [e.kind for e in events]
    assert "tool_call" in kinds
    trace_evs = [e for e in events if e.kind == "model_response"]
    assert len(trace_evs) == 1
    assert trace_evs[0].payload["content"] == ""
    assert "query_zeek_logs" in trace_evs[0].payload["reasoning_trace"]


@pytest.mark.asyncio
async def test_error_event_hint_for_es_unreachable(
    settings_kratos: Settings,
) -> None:
    """When the prefetch fails because ES is unreachable (host restarting,
    network down), the error event carries a hint pointing the analyst at
    the SO grid + ES_HOSTS config."""
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    async def _connection_refused(_alert_id: str, **_kw: Any) -> Any:
        raise ConnectionError(
            "Cannot connect to host 10.0.0.253:9200 ssl:default [Connect call failed]"
        )

    with patch(
        "soc_ai.tools.get_alert_context.get_enriched_alert_context",
        side_effect=_connection_refused,
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    err = next(e for e in events if e.kind == "error").payload
    assert err["phase"] == "prefetch"
    assert err["round"] == 0
    assert "unreachable" in err["hint"].lower()
    assert "ES_HOSTS" in err["hint"]


def test_targeted_gap_round_trips() -> None:
    """TargetedGap is a Pydantic model; round-trips through JSON."""
    from soc_ai.agent.triage import TargetedGap

    gap = TargetedGap(
        question="What was the SSL SNI for community_id 1:abc?",
        tool_name="t_query_zeek_logs",
        tool_args={"community_id": "1:abc", "log_types": ["ssl"]},
        why_this_matters=(
            "If the SNI is api.giphy.com (already enriched as benign), "
            "this is FP. Anything else is suspicious."
        ),
    )
    rt = TargetedGap.model_validate_json(gap.model_dump_json())
    assert rt == gap


def test_triage_report_with_gap_for_investigator() -> None:
    """TriageReport accepts gap_for_investigator and defaults to None."""
    from soc_ai.agent.triage import TargetedGap, TriageReport

    r = TriageReport(
        verdict="needs_more_info",
        confidence=0.4,
        summary="Need SSL SNI to decide.",
        citations=["alert.rule_metadata.signature_severity"],
        recommended_actions=[],
    )
    assert r.gap_for_investigator is None

    gap = TargetedGap(
        question="x",
        tool_name="t_query_zeek_logs",
        tool_args={},
        why_this_matters="x",
    )
    r2 = r.model_copy(update={"gap_for_investigator": gap})
    assert r2.gap_for_investigator is not None
    assert r2.gap_for_investigator.question == "x"


def test_build_synth_first_user_message_with_candidate() -> None:
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.prompts import build_synth_first_user_message

    msg = build_synth_first_user_message(
        alert_id="abc",
        enriched_ctx_json='{"alert": {"id": "abc"}}',
        materialized_evidence=["alert.rule_metadata.signature_severity=Informational"],
        candidate=CandidateVerdict(
            verdict="false_positive",
            confidence=0.8,
            cited_evidence=["alert.alert_action=allowed"],
            template_id="informational_external_clean_benign_cloud",
            rationale="Routine cloud destination.",
        ),
    )
    assert "false_positive" in msg
    assert "informational_external_clean_benign_cloud" in msg
    assert "alert.rule_metadata.signature_severity=Informational" in msg
    assert "Routine cloud destination" in msg


def test_build_synth_first_user_message_no_candidate() -> None:
    from soc_ai.agent.prompts import build_synth_first_user_message

    msg = build_synth_first_user_message(
        alert_id="abc",
        enriched_ctx_json="{}",
        materialized_evidence=[],
        candidate=None,
    )
    assert "No template matched" in msg
    assert "abc" in msg


def test_build_synth_first_user_message_threads_focus_hint() -> None:
    """A focus_hint (prior open questions from a 'request more info' re-run) is
    woven into the seed message so the fresh investigation targets those gaps."""
    from soc_ai.agent.prompts import build_synth_first_user_message

    msg = build_synth_first_user_message(
        alert_id="abc",
        enriched_ctx_json="{}",
        materialized_evidence=[],
        candidate=None,
        focus_hint="1. Was the payload executed?\n2. Is the C2 domain resolvable?",
    )
    assert "needs_more_info" in msg  # the focus block names the prior verdict
    assert "Was the payload executed?" in msg
    assert "Is the C2 domain resolvable?" in msg
    # No hint ⇒ no focus block (byte-identical to the pre-feature message).
    plain = build_synth_first_user_message(
        alert_id="abc", enriched_ctx_json="{}", materialized_evidence=[], candidate=None
    )
    assert "prior investigation ended" not in plain


def test_format_focus_hint_block_empty_is_noop() -> None:
    from soc_ai.agent.prompts import format_focus_hint_block

    assert format_focus_hint_block(None) == ""
    assert format_focus_hint_block("   ") == ""
    block = format_focus_hint_block("1. Check the hash")
    assert "Check the hash" in block
    assert "needs_more_info" in block


def test_build_synth_first_user_message_candidate_before_evidence() -> None:
    """B4: candidate block must appear BEFORE the evidence/context blocks so the
    synth reads evidence last, not the template verdict last (anchoring mitigation)."""
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.prompts import build_synth_first_user_message

    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.8,
        cited_evidence=["alert.alert_action=allowed"],
        template_id="clean_internal_traffic",
        rationale="Both endpoints internal.",
    )
    msg = build_synth_first_user_message(
        alert_id="abc",
        enriched_ctx_json='{"alert": {"id": "abc"}}',
        materialized_evidence=["alert.rule_metadata.signature_severity=Informational"],
        candidate=candidate,
    )
    # Candidate section header must come before the enriched-context / evidence section.
    idx_candidate = msg.index("Decision-template candidate")
    idx_evidence = msg.index("Enriched alert context")
    assert idx_candidate < idx_evidence, (
        "candidate block must appear before the evidence block "
        f"(candidate at {idx_candidate}, evidence at {idx_evidence})"
    )


def test_build_synth_first_user_message_has_reconcile_instruction() -> None:
    """B4: message must contain the mandatory reconcile instruction text."""
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.prompts import build_synth_first_user_message

    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.8,
        cited_evidence=[],
        template_id="clean_internal_traffic",
        rationale="Both endpoints internal.",
    )
    msg = build_synth_first_user_message(
        alert_id="abc",
        enriched_ctx_json="{}",
        materialized_evidence=[],
        candidate=candidate,
    )
    assert "heuristic suggestion, not evidence" in msg
    assert "payload wins" in msg


def test_build_synth_first_user_message_no_candidate_has_no_heuristic_suggestion() -> None:
    """Fix 2: when candidate is None the reconcile instruction must NOT reference
    'The candidate above is a heuristic suggestion' — there is no candidate above."""
    from soc_ai.agent.prompts import build_synth_first_user_message

    msg = build_synth_first_user_message(
        alert_id="abc",
        enriched_ctx_json="{}",
        materialized_evidence=[],
        candidate=None,
    )
    assert "heuristic suggestion" not in msg


def test_build_synth_first_user_message_no_candidate_has_evidence_primacy_instruction() -> None:
    """Fix 2: when candidate is None the message must still carry the
    evidence-primacy core: 'payload wins'."""
    from soc_ai.agent.prompts import build_synth_first_user_message

    msg = build_synth_first_user_message(
        alert_id="abc",
        enriched_ctx_json="{}",
        materialized_evidence=[],
        candidate=None,
    )
    assert "payload wins" in msg


def test_build_synth_first_user_message_with_candidate_keeps_full_reconcile_text() -> None:
    """Fix 2: when a candidate IS present the full reconcile text including
    'heuristic suggestion' must still appear."""
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.prompts import build_synth_first_user_message

    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.8,
        cited_evidence=[],
        template_id="clean_internal_traffic",
        rationale="Both endpoints internal.",
    )
    msg = build_synth_first_user_message(
        alert_id="abc",
        enriched_ctx_json="{}",
        materialized_evidence=[],
        candidate=candidate,
    )
    assert "heuristic suggestion" in msg
    assert "payload wins" in msg


def test_build_synth_first_round2_user_message_includes_targeted_result() -> None:
    from soc_ai.agent.prompts import build_synth_first_round2_user_message
    from soc_ai.agent.triage import TargetedGap

    gap = TargetedGap(
        question="What was the SSL SNI?",
        tool_name="t_query_zeek_logs",
        tool_args={"community_id": "1:abc", "log_types": ["ssl"]},
        why_this_matters="If api.giphy.com -> FP; else suspicious.",
    )
    msg = build_synth_first_round2_user_message(
        alert_id="abc",
        enriched_ctx_json="{}",
        materialized_evidence=[],
        candidate=None,
        round1_gap=gap,
        targeted_tool_result={"sni_servers": ["api.giphy.com"]},
    )
    assert "api.giphy.com" in msg
    assert "What was the SSL SNI?" in msg
    assert "MUST emit a `gap_for_investigator=None`" in msg


def test_build_synth_first_round2_user_message_allow_further_gap() -> None:
    """allow_further_gap=True (non-final Phase-D round) permits ONE more gap;
    the default (final round) keeps the hard MUST-emit-None instruction."""
    from soc_ai.agent.prompts import build_synth_first_round2_user_message
    from soc_ai.agent.triage import TargetedGap

    gap = TargetedGap(
        question="What was the SSL SNI?",
        tool_name="t_query_zeek_logs",
        tool_args={"community_id": "1:abc", "log_types": ["ssl"]},
        why_this_matters="If api.giphy.com -> FP; else suspicious.",
    )
    msg = build_synth_first_round2_user_message(
        alert_id="abc",
        enriched_ctx_json="{}",
        materialized_evidence=[],
        candidate=None,
        round1_gap=gap,
        targeted_tool_result={"sni_servers": ["api.giphy.com"]},
        allow_further_gap=True,
    )
    assert "MUST emit a `gap_for_investigator=None`" not in msg
    assert "MAY" in msg
    assert "emit another `gap_for_investigator`" in msg
    # The rest of the round-2 message structure is unchanged.
    assert "api.giphy.com" in msg
    assert "What was the SSL SNI?" in msg


# =====================================================================
# Task 15c: Integration tests for _run_synth_first_pipeline
# =====================================================================


def _stub_enriched_alert_context(alert_id: str = "alert-001") -> Any:
    """Minimal EnrichedAlertContext for synth-first pipeline tests."""
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


@pytest.mark.asyncio
async def test_synth_first_pipeline_template_match_path(
    settings_kratos: Settings,
) -> None:
    """Template-matching alert: synth-first runs A->B->C->done with one synth call.

    Verifies the event stream contains: session_start, enriched_alert_context,
    decision_template_match, triage_report, done.  NO targeted_dispatch event
    (synth doesn't request a Phase D call).
    """
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    fake_report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="Internal scanner; expected periodic ICMP.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_model = TestModel(call_tools=[], custom_output_args=fake_report)
    from soc_ai.agent.decision_templates import CandidateVerdict

    # A strong benign template (clean_internal_traffic @ 0.85) — a real
    # template-match path that also exempts the hard evidence gate.
    strong_candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal scanner",
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=synth_model,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=strong_candidate,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert kinds[0] == "session_start"
    assert "enriched_alert_context" in kinds
    assert "decision_template_match" in kinds
    assert "triage_report" in kinds
    assert kinds[-1] == "done"
    # Synth-first-only events present
    assert "targeted_dispatch" not in kinds
    assert "targeted_tool_result" not in kinds
    # Legacy pipeline events absent
    assert "investigation_transcript" not in kinds
    assert "retask" not in kinds
    # Triage report carries the expected verdict
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["confidence"] == pytest.approx(0.85)
    # session_start payload marks the pipeline
    session_ev = next(e for e in events if e.kind == "session_start")
    assert session_ev.payload["pipeline"] == "synth_first"
    # Synth-first emits a `usage` event so the userscript token
    # KPI / sparkline populate (previously only the legacy path did → 📊 0).
    assert "usage" in kinds
    usage_ev = next(e for e in events if e.kind == "usage")
    assert usage_ev.payload["phase"] == "synthesizer"
    assert "input_tokens" in usage_ev.payload
    assert "total_tokens" in usage_ev.payload
    # Sequence numbers are monotonically increasing
    sequences = [e.sequence for e in events]
    assert sequences == sorted(sequences)


@pytest.mark.asyncio
async def test_synth_first_pipeline_no_template_match_synth_reasons(
    settings_kratos: Settings,
    monkeypatch: Any,
) -> None:
    """Alert with no template match: synth still runs and gets None candidate.

    Checks that decision_template_match event has matched=False and no
    Phase D dispatch (synth immediately produces a verdict).
    """
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    monkeypatch.setattr(
        "soc_ai.agent.decision_templates.match_decision_template",
        lambda ctx: None,
    )

    fake_report = TriageReport(
        verdict="needs_more_info",
        confidence=0.5,
        summary="Insufficient evidence without template context.",
        citations=[],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_model = TestModel(call_tools=[], custom_output_args=fake_report)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        # Return a minimal context that will NOT match any decision template
        # (no blocklist hits, no special classtype, no zeek conn states)
        return _stub_enriched_alert_context(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=synth_model,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "enriched_alert_context" in kinds
    assert "decision_template_match" in kinds
    assert "triage_report" in kinds
    assert "done" in kinds
    assert "targeted_dispatch" not in kinds

    template_ev = next(e for e in events if e.kind == "decision_template_match")
    assert template_ev.payload["matched"] is False
    assert template_ev.payload["template_id"] is None

    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "needs_more_info"


@pytest.mark.asyncio
async def test_synth_first_pipeline_phase_d_dispatch_then_round2(
    settings_kratos: Settings,
) -> None:
    """Synth round 1 emits gap_for_investigator -> targeted dispatch -> synth round 2.

    Event stream: session_start, enriched_alert_context, decision_template_match,
    targeted_dispatch, targeted_tool_result, triage_report, done.
    """
    from soc_ai.agent.triage import TargetedGap

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    gap = TargetedGap(
        question="What was the SSL SNI for community_id 1:abc?",
        tool_name="t_query_zeek_logs",
        tool_args={"community_id": "1:abc", "log_types": ["ssl"]},
        why_this_matters="If api.giphy.com -> FP; else suspicious.",
    )
    # Round 1: synth requests a targeted investigation
    round1_report = TriageReport(
        verdict="needs_more_info",
        confidence=0.4,
        summary="Waiting on SSL SNI data.",
        citations=[],
        recommended_actions=[],
        gap_for_investigator=gap,
    )
    # Round 2: synth produces final verdict after seeing targeted result.
    # Use a valid citation (alert.severity_label exists in stub context) so
    # post-validators don't cap confidence — this test covers the Phase D
    # event flow; validator behavior is in test_synth_first_phase_d_validators_run_on_round2.
    round2_report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="SNI confirmed api.giphy.com — benign CDN traffic.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )

    # build_synth_first_agent is called ONCE and its agent is reused for both
    # synth rounds (run() called twice on the same agent).  TestModel always
    # returns the same output, so we patch the agent's .run method directly to
    # return round1_report then round2_report on successive calls.
    targeted_result = {"sni_servers": ["api.giphy.com"]}

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    # Build a real agent backed by a dummy TestModel; then replace .run with an
    # AsyncMock that cycles through the two reports.
    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    run_results = [MagicMock(output=round1_report), MagicMock(output=round2_report)]
    fake_agent.run = AsyncMock(side_effect=run_results)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=round1_report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.targeted_investigator.run_targeted_investigation",
            new=AsyncMock(return_value=targeted_result),
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "session_start" in kinds
    assert "enriched_alert_context" in kinds
    assert "decision_template_match" in kinds
    assert "targeted_dispatch" in kinds
    assert "targeted_tool_result" in kinds
    assert "triage_report" in kinds
    assert kinds[-1] == "done"

    dispatch_ev = next(e for e in events if e.kind == "targeted_dispatch")
    assert dispatch_ev.payload["question"] == gap.question
    assert dispatch_ev.payload["tool_name"] == "t_query_zeek_logs"

    tool_result_ev = next(e for e in events if e.kind == "targeted_tool_result")
    assert tool_result_ev.payload["tool_name"] == "t_query_zeek_logs"
    assert tool_result_ev.payload["result"] == targeted_result

    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["confidence"] == pytest.approx(0.9)
    # Round 2 must NOT emit a gap (defensive strip enforced by orchestrator)
    assert report_ev.payload.get("gap_for_investigator") is None


@pytest.mark.asyncio
async def test_synth_first_phase_d_bounded_loop_two_rounds(
    settings_kratos: Settings,
) -> None:
    """phase_d_max_rounds=2: gap -> dispatch -> gap -> dispatch -> final report.

    The synth names a SECOND gap after seeing the first targeted result and
    the orchestrator honors it — two full retask/targeted_dispatch/
    targeted_tool_result sequences — before the final synthesis lands with
    no gap (e.g. the t_get_event_raw -> t_decode_payload chain).
    """
    from soc_ai.agent.triage import TargetedGap

    settings_kratos.investigate_when_unsure = False
    settings_kratos.phase_d_max_rounds = 2
    ctx = _make_ctx(settings_kratos)

    gap1 = TargetedGap(
        question="What are the raw bytes of the alert payload?",
        tool_name="t_get_event_raw",
        tool_args={"event_id": "alert-001"},
        why_this_matters="Need the encoded payload before decoding.",
    )
    gap2 = TargetedGap(
        question="What does the base64 payload decode to?",
        tool_name="t_decode_payload",
        tool_args={"data": "aGVsbG8="},
        why_this_matters="The decoded payload settles the verdict.",
    )
    round1_report = TriageReport(
        verdict="needs_more_info",
        confidence=0.4,
        summary="Need the raw event first.",
        citations=[],
        recommended_actions=[],
        gap_for_investigator=gap1,
    )
    round2_report = TriageReport(
        verdict="needs_more_info",
        confidence=0.5,
        summary="Got the raw bytes; need them decoded.",
        citations=[],
        recommended_actions=[],
        gap_for_investigator=gap2,
    )
    final_report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="Payload decodes to a benign keepalive.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    targeted_results = [{"raw": "aGVsbG8="}, {"decoded": "hello"}]

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    run_results = [
        MagicMock(output=round1_report),
        MagicMock(output=round2_report),
        MagicMock(output=final_report),
    ]
    fake_agent.run = AsyncMock(side_effect=run_results)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=round1_report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.targeted_investigator.run_targeted_investigation",
            new=AsyncMock(side_effect=targeted_results),
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert kinds.count("retask") == 2
    assert kinds.count("targeted_dispatch") == 2
    assert kinds.count("targeted_tool_result") == 2

    dispatches = [e for e in events if e.kind == "targeted_dispatch"]
    assert dispatches[0].payload["tool_name"] == "t_get_event_raw"
    assert dispatches[1].payload["tool_name"] == "t_decode_payload"
    results = [e for e in events if e.kind == "targeted_tool_result"]
    assert results[0].payload["result"] == {"raw": "aGVsbG8="}
    assert results[1].payload["result"] == {"decoded": "hello"}

    # Three synth runs: round 1 + one re-synthesis per dispatch round.
    assert fake_agent.run.await_count == 3

    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload.get("gap_for_investigator") is None
    assert kinds[-1] == "done"


@pytest.mark.asyncio
async def test_synth_first_phase_d_default_single_round_strips_round2_gap(
    settings_kratos: Settings,
) -> None:
    """Regression pin: default phase_d_max_rounds=1 keeps the old behavior.

    When the round-2 synth ignores the MUST-emit-None instruction and names
    another gap, the orchestrator strips it defensively — exactly ONE
    dispatch happens and the round-2 verdict stands.
    """
    from soc_ai.agent.triage import TargetedGap

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)
    assert settings_kratos.phase_d_max_rounds == 1  # the default

    gap1 = TargetedGap(
        question="What was the SSL SNI for community_id 1:abc?",
        tool_name="t_query_zeek_logs",
        tool_args={"community_id": "1:abc", "log_types": ["ssl"]},
        why_this_matters="If api.giphy.com -> FP; else suspicious.",
    )
    gap2 = TargetedGap(
        question="One more pivot?",
        tool_name="t_query_events_oql",
        tool_args={"query": "event.dataset:zeek.conn"},
        why_this_matters="Model over-asking despite the final-round rule.",
    )
    round1_report = TriageReport(
        verdict="needs_more_info",
        confidence=0.4,
        summary="Waiting on SSL SNI data.",
        citations=[],
        recommended_actions=[],
        gap_for_investigator=gap1,
    )
    # Round 2 misbehaves: emits a verdict AND another gap.
    round2_report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="SNI confirmed api.giphy.com — benign CDN traffic.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=gap2,
    )
    targeted_result = {"sni_servers": ["api.giphy.com"]}

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(
        side_effect=[MagicMock(output=round1_report), MagicMock(output=round2_report)]
    )
    dispatch_mock = AsyncMock(return_value=targeted_result)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=round1_report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.targeted_investigator.run_targeted_investigation",
            new=dispatch_mock,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    # ONE dispatch round only — the round-2 gap must NOT trigger another.
    assert kinds.count("retask") == 1
    assert kinds.count("targeted_dispatch") == 1
    assert kinds.count("targeted_tool_result") == 1
    assert dispatch_mock.await_count == 1
    assert fake_agent.run.await_count == 2

    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload.get("gap_for_investigator") is None
    assert kinds[-1] == "done"


@pytest.mark.asyncio
async def test_synth_first_pipeline_phase_d_emits_retask_event(
    settings_kratos: Settings,
) -> None:
    """Phase D dispatch must co-emit a `retask` SSE event.

    Eval/batch.py:read_retask_count counts `kind == "retask"` events. The
    legacy investigate() emits them; the synth-first pipeline previously
    only emitted `targeted_dispatch`, leaving retask_rate=0 even when
    Phase D fired. This test pins the contract: when Phase D fires, both
    `retask` AND `targeted_dispatch` appear in the event stream, with
    retask preceding targeted_dispatch so downstream consumers see the
    semantic "agent asked for more" signal before the dispatch detail.
    """
    from soc_ai.agent.triage import TargetedGap

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    gap = TargetedGap(
        question="What was the SSL SNI for community_id 1:abc?",
        tool_name="t_query_zeek_logs",
        tool_args={"community_id": "1:abc", "log_types": ["ssl"]},
        why_this_matters="If api.giphy.com -> FP; else suspicious.",
    )
    round1_report = TriageReport(
        verdict="needs_more_info",
        confidence=0.4,
        summary="Waiting on SSL SNI data.",
        citations=[],
        recommended_actions=[],
        gap_for_investigator=gap,
    )
    round2_report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="SNI confirmed api.giphy.com — benign CDN traffic.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    targeted_result = {"sni_servers": ["api.giphy.com"]}

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    run_results = [MagicMock(output=round1_report), MagicMock(output=round2_report)]
    fake_agent.run = AsyncMock(side_effect=run_results)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=round1_report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.targeted_investigator.run_targeted_investigation",
            new=AsyncMock(return_value=targeted_result),
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "retask" in kinds, (
        "Phase D dispatch MUST emit a `retask` SSE event so "
        "eval/batch.py:read_retask_count can detect it; only "
        "targeted_dispatch is insufficient."
    )
    # retask must precede targeted_dispatch (semantic: "agent asked for more"
    # before "here's the specific call").
    retask_idx = kinds.index("retask")
    dispatch_idx = kinds.index("targeted_dispatch")
    assert retask_idx < dispatch_idx, (
        f"retask (idx={retask_idx}) must precede targeted_dispatch "
        f"(idx={dispatch_idx}) in the event stream"
    )

    retask_ev = next(e for e in events if e.kind == "retask")
    payload = retask_ev.payload
    assert payload["reason"] == "phase_d_targeted_dispatch"
    assert payload["tool_name"] == "t_query_zeek_logs"
    assert payload["gap_question"] == gap.question
    assert payload["confidence"] == pytest.approx(0.4)


@pytest.mark.asyncio
async def test_synth_first_pipeline_no_phase_d_emits_no_retask(
    settings_kratos: Settings,
) -> None:
    """Negative path: when synth round 1 has no gap, no retask event."""
    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    round1_report = TriageReport(
        verdict="false_positive",
        confidence=0.8,
        summary="Clean east-west traffic.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(return_value=MagicMock(output=round1_report))

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=round1_report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "retask" not in kinds
    assert "targeted_dispatch" not in kinds


# ---------------------------------------------------------------------------
# Synthesizer reasoning-trace emission (the "Model reasoning" panel for
# no-loop investigations). The synth agent.run() results carry ThinkingParts
# (deepseek reasoning_content via the model profile) that were previously
# dropped — a round-1-settled run stored NO model_response event.
# ---------------------------------------------------------------------------


class _SynthStubResult:
    """pydantic_ai-shaped run result: .output + .all_messages() with parts."""

    def __init__(self, output: Any, messages: list[Any]) -> None:
        self.output = output
        self._messages = messages

    def all_messages(self) -> list[Any]:
        return self._messages

    def usage(self) -> Any:  # _usage_ev() catches this and skips the event
        raise RuntimeError("no usage in stub")


class _SynthStubAgent:
    """Returns canned _SynthStubResults sequentially (last one repeats)."""

    def __init__(self, results: list[_SynthStubResult]) -> None:
        self._results = results
        self.calls = 0

    async def run(self, *_a: Any, **_kw: Any) -> _SynthStubResult:
        i = self.calls
        self.calls += 1
        return self._results[min(i, len(self._results) - 1)]


def _thinking_message(thinking: str | None, text: str = "") -> Any:
    """A fake ModelResponse whose part CLASS NAMES match what _walk_message /
    _synth_reasoning_payload detect (ThinkingPart / TextPart)."""

    class ThinkingPart:
        def __init__(self, content: str) -> None:
            self.content = content

    class TextPart:
        def __init__(self, content: str) -> None:
            self.content = content

    from types import SimpleNamespace

    parts: list[Any] = []
    if thinking is not None:
        parts.append(ThinkingPart(thinking))
    if text:
        parts.append(TextPart(text))
    return SimpleNamespace(parts=parts)


def _reasoning_test_setup(settings: Settings) -> tuple[Any, TriageReport, Any]:
    """(ctx, fp_report, strong_candidate) for a round-1-settled synth-first run."""
    settings.investigate_when_unsure = False
    ctx = _make_ctx(settings)
    report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="Internal scanner; expected periodic ICMP.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    from soc_ai.agent.decision_templates import CandidateVerdict

    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal scanner",
    )
    return ctx, report, candidate


async def _run_reasoning_pipeline(
    settings: Settings, stub_agent: _SynthStubAgent, candidate: Any, ctx: Any
) -> list[Any]:
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
            return_value=candidate,
        ),
    ):
        return [ev async for ev in investigate("alert-001", ctx=ctx)]


@pytest.mark.asyncio
async def test_synth_first_round1_emits_model_response_with_reasoning(
    settings_kratos: Settings,
) -> None:
    """A round-1-settled run (no loop, no Phase D) emits ONE model_response
    event carrying the synthesizer's thinking — the reasoning panel's source."""
    ctx, report, candidate = _reasoning_test_setup(settings_kratos)
    stub = _SynthStubAgent(
        [
            _SynthStubResult(
                report,
                [_thinking_message("Benign east-west ICMP; template corroborates.", "done")],
            )
        ]
    )
    events = await _run_reasoning_pipeline(settings_kratos, stub, candidate, ctx)

    mrs = [e for e in events if e.kind == "model_response"]
    assert len(mrs) == 1
    payload = mrs[0].payload
    assert payload["reasoning_trace"] == "Benign east-west ICMP; template corroborates."
    assert payload["content"] == "done"
    assert payload["phase"] == "synthesizer"
    assert payload["round"] == 1
    # The verdict itself is unchanged by the emission.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"


@pytest.mark.asyncio
async def test_synth_first_round1_no_thinking_emits_no_model_response(
    settings_kratos: Settings,
) -> None:
    """Defensive: no ThinkingPart / <think> block -> NO model_response event."""
    ctx, report, candidate = _reasoning_test_setup(settings_kratos)
    stub = _SynthStubAgent([_SynthStubResult(report, [_thinking_message(None, "just text")])])
    events = await _run_reasoning_pipeline(settings_kratos, stub, candidate, ctx)
    assert [e for e in events if e.kind == "model_response"] == []


@pytest.mark.asyncio
async def test_synth_first_inline_think_block_also_surfaces(
    settings_kratos: Settings,
) -> None:
    """Models that embed <think>...</think> in the text (no ThinkingPart) still
    surface reasoning — same extract_reasoning_trace projection as the loop."""
    ctx, report, candidate = _reasoning_test_setup(settings_kratos)
    stub = _SynthStubAgent(
        [_SynthStubResult(report, [_thinking_message(None, "<think>weighing it</think>fine")])]
    )
    events = await _run_reasoning_pipeline(settings_kratos, stub, candidate, ctx)
    mrs = [e for e in events if e.kind == "model_response"]
    assert len(mrs) == 1
    assert mrs[0].payload["reasoning_trace"] == "weighing it"
    assert mrs[0].payload["content"] == "fine"


@pytest.mark.asyncio
async def test_self_consistency_samples_do_not_multiply_reasoning_events(
    settings_kratos: Settings,
) -> None:
    """verdict_consistency_samples>1: only the PRIMARY synthesis emits reasoning
    — the extra vote samples never add model_response events."""
    settings_kratos.verdict_consistency_samples = 3
    ctx, report, candidate = _reasoning_test_setup(settings_kratos)
    stub = _SynthStubAgent([_SynthStubResult(report, [_thinking_message("thinking hard", "t")])])
    events = await _run_reasoning_pipeline(settings_kratos, stub, candidate, ctx)
    assert stub.calls == 3  # primary + 2 extra samples all ran...
    mrs = [e for e in events if e.kind == "model_response"]
    assert len(mrs) == 1  # ...but only the primary emitted reasoning
    assert mrs[0].payload["round"] == 1


# =====================================================================
# Synth-first post-validators
# =====================================================================


@pytest.mark.asyncio
async def test_synth_first_no_template_ceiling_keeps_real_confidence(
    settings_kratos: Settings,
) -> None:
    """The template ceiling was removed — the synthesizer LLM's own
    confidence stands even when it exceeds the matched template's constant."""
    from unittest.mock import MagicMock

    from pydantic_ai import Agent
    from soc_ai.agent.decision_templates import CandidateVerdict

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    # Candidate is the real clean_internal_traffic template (0.85); synth
    # over-claims 0.9. (A strong benign template also exempts the evidence gate.)
    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="Internal ICMP scanner.",
    )

    # Synth emits confidence=0.9 (> the template constant) with a valid citation.
    fake_report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Benign internal scanner.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=fake_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(return_value=MagicMock(output=fake_report))

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=fake_report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=candidate,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "template_ceiling" not in kinds  # ceiling dropped

    report_ev = next(e for e in events if e.kind == "triage_report")
    # The model's own 0.9 stands (> template 0.85; citations validate, no cap;
    # strong benign template exempts the evidence gate).
    assert report_ev.payload["confidence"] == pytest.approx(0.9)
    assert report_ev.payload["verdict"] == "false_positive"


@pytest.mark.asyncio
async def test_synth_first_post_validate_invalid_citation_caps_confidence(
    settings_kratos: Settings,
) -> None:
    """Synth emits citations that don't validate against the enriched context.
    citation_cap fires, confidence drops proportionally."""
    from unittest.mock import MagicMock

    from pydantic_ai import Agent
    from soc_ai.agent.decision_templates import CandidateVerdict

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    # A strong benign template so the verdict survives the hard evidence gate —
    # this test isolates the citation-cap behaviour, not the gate.
    strong_candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal scanner",
    )

    # citation "alert.nonexistent_field" will fail path validation.
    # "alert.severity_label" is valid (present in SoAlert).
    fake_report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="Based on some dubious citations.",
        citations=["alert.severity_label", "alert.nonexistent_field"],
        recommended_actions=[],
        gap_for_investigator=None,
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=fake_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(return_value=MagicMock(output=fake_report))

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=fake_report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=strong_candidate,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "citation_validation" in kinds
    assert "citation_cap" in kinds

    cite_ev = next(e for e in events if e.kind == "citation_validation")
    # Both the new `coverage_ratio` and the legacy `invalid_ratio` are emitted.
    assert cite_ev.payload["coverage_ratio"] == pytest.approx(0.5)
    assert cite_ev.payload["invalid_ratio"] == pytest.approx(0.5)

    cap_ev = next(e for e in events if e.kind == "citation_cap")
    assert cap_ev.payload["original_confidence"] == pytest.approx(0.85)
    # Banded: coverage 0.5 → band ≥0.5 → multiplier 0.9 → 0.85 * 0.9 = 0.765
    # (NOT 0.425 — the old multiplicative-to-zero behavior is gone)
    assert cap_ev.payload["capped_confidence"] == pytest.approx(0.765)

    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["confidence"] == pytest.approx(0.765)
    # 0.765 ≥ 0.6 floor AND citations resolve partially → verdict PRESERVED.
    # Under the legacy logic the cascade would have erased this to NMI;
    # the evidence-conditional floor rewrite keeps the verdict label.
    assert report_ev.payload["verdict"] == "false_positive"


@pytest.mark.asyncio
async def test_synth_first_post_validate_floor_rewrite_to_nmi(
    settings_kratos: Settings,
) -> None:
    """After cap chain drops confidence below floor (0.6), verdict rewrites to NMI
    and recommended_actions clears. verdict_floor_rewrite event emitted."""
    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    # Synth emits false_positive @ 0.55 — already below the 0.6 floor.
    fake_report = TriageReport(
        verdict="false_positive",
        confidence=0.55,
        summary="Weak FP conclusion.",
        citations=[],
        recommended_actions=[],
        gap_for_investigator=None,
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=fake_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(return_value=MagicMock(output=fake_report))

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=fake_report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=None,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "verdict_floor_rewrite" in kinds

    rewrite_ev = next(e for e in events if e.kind == "verdict_floor_rewrite")
    assert rewrite_ev.payload["original_verdict"] == "false_positive"
    assert rewrite_ev.payload["capped_verdict"] == "needs_more_info"
    assert rewrite_ev.payload["confidence"] == pytest.approx(0.55)
    assert rewrite_ev.payload["floor"] == pytest.approx(0.6)

    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "needs_more_info"
    assert report_ev.payload["confidence"] == pytest.approx(0.55)
    assert report_ev.payload["recommended_actions"] == []


@pytest.mark.asyncio
async def test_synth_first_phase_d_validators_run_on_round2(
    settings_kratos: Settings,
) -> None:
    """When Phase D fires, the round-2 output gets citation + floor validators
    applied — but NOT the template_ceiling.

    Phase D counts as an investigator round (single-tool); its evidence
    legitimately upgrades confidence beyond the heuristic's certainty. So
    when round-2 emits confidence=0.92 with a valid citation, the ceiling
    must NOT clamp it back to the template's 0.75.
    """
    from unittest.mock import MagicMock

    from pydantic_ai import Agent
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.triage import TargetedGap

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    gap = TargetedGap(
        question="What was the SSL SNI?",
        tool_name="t_query_zeek_logs",
        tool_args={"community_id": "1:abc", "log_types": ["ssl"]},
        why_this_matters="Determines if traffic is benign CDN.",
    )

    round1_report = TriageReport(
        verdict="needs_more_info",
        confidence=0.4,
        summary="Need SNI to decide.",
        citations=[],
        recommended_actions=[],
        gap_for_investigator=gap,
    )
    # Round 2 over-claims confidence=0.92; template says 0.75.
    round2_report = TriageReport(
        verdict="false_positive",
        confidence=0.92,
        summary="SNI confirmed benign.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )

    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.75,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="Benign internal traffic.",
    )

    targeted_result = {"sni_servers": ["api.giphy.com"]}

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    run_results = [MagicMock(output=round1_report), MagicMock(output=round2_report)]
    fake_agent.run = AsyncMock(side_effect=run_results)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=round1_report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=candidate,
        ),
        patch(
            "soc_ai.agent.targeted_investigator.run_targeted_investigation",
            new=AsyncMock(return_value=targeted_result),
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "targeted_dispatch" in kinds
    assert "targeted_tool_result" in kinds
    # citation_validation always fires; template_ceiling does NOT when Phase D ran.
    assert "citation_validation" in kinds
    assert "template_ceiling" not in kinds

    # Phase D evidence legitimately upgrades confidence past the template's 0.75.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["confidence"] == pytest.approx(0.92)
    assert report_ev.payload["verdict"] == "false_positive"
    assert "done" in kinds


def test_round2_failure_fallback_keeps_settled_round1_verdict() -> None:
    """A round-2 crash should land the round-1 verdict (annotated), not error."""
    from soc_ai.agent.orchestrator import _round2_failure_fallback
    from soc_ai.agent.triage import TriageReport

    r1 = TriageReport(
        verdict="false_positive",
        confidence=0.95,
        summary="legitimate WebMD CDN",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    out = _round2_failure_fallback("alert-1", r1, TimeoutError("gateway timeout"))
    assert out.verdict == "false_positive"
    assert out.confidence == 0.95
    assert "did not complete" in out.summary  # annotated so the operator knows


def test_round2_failure_fallback_nmi_when_round1_inconclusive() -> None:
    """A round-2 crash with no settled round-1 verdict falls back to needs_more_info."""
    from soc_ai.agent.orchestrator import _round2_failure_fallback
    from soc_ai.agent.triage import TriageReport

    inconclusive = TriageReport(
        verdict="needs_more_info",
        confidence=0.0,
        summary="round-1 was inconclusive",
        citations=[],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    # needs_more_info is not a settled verdict, so it falls through to the
    # synth-failure NMI report rather than being "kept".
    from_inconclusive = _round2_failure_fallback("a", inconclusive, TimeoutError("x"))
    assert from_inconclusive.verdict == "needs_more_info"
    assert _round2_failure_fallback("a", None, TimeoutError("x")).verdict == "needs_more_info"


@pytest.mark.asyncio
async def test_synth_first_round1_failure_emits_fallback_nmi_triage_report(
    settings_kratos: Settings,
) -> None:
    """When synth-first round-1 raises (e.g.
    UnexpectedModelBehavior from schema-validation exhaustion), the
    orchestrator MUST emit a fallback NMI triage_report rather than
    silently returning with verdict=None.

    Pre-fix behavior: eval batches had synth alerts fail with
    'Exceeded maximum retries for output validation' and produce
    verdict=None rows in index.jsonl — unscoreable. Post-fix: same
    failure path emits verdict=needs_more_info + the error in the
    summary, runs through post-validators, and emits a proper
    triage_report event.
    """

    from pydantic_ai import Agent
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    settings_kratos.investigate_when_unsure = False
    ctx = _make_ctx(settings_kratos)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(alert_id)

    fake_agent = Agent(
        model=TestModel(
            call_tools=[],
            custom_output_args=TriageReport(
                verdict="false_positive",
                confidence=0.5,
                summary="dummy",
                citations=[],
            ),
        ),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(
        side_effect=UnexpectedModelBehavior("Exceeded maximum retries (3) for output validation")
    )

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    # Error event still emitted for audit/diagnostic.
    assert "error" in kinds
    error_ev = next(e for e in events if e.kind == "error")
    assert error_ev.payload["phase"] == "synth_first_round1"
    # AND a fallback triage_report MUST be emitted — pre-fix this was missing.
    assert "triage_report" in kinds, (
        "fallback triage_report not emitted — synth failure should not "
        "produce verdict=None rows in index.jsonl"
    )
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "needs_more_info"
    assert report_ev.payload["confidence"] == pytest.approx(0.3)
    assert "synth_first_failure" in report_ev.payload["citations"]
    assert kinds[-1] == "done"


# =====================================================================
# E5.1: fail-closed residue sweep for the analyst egress guard
# =====================================================================

# A NetBIOS-style bare hostname: the guard's sanitize pass does NOT redact it
# (no internal suffix, not in extra_hosts), but the INDEPENDENT unsafe_residue
# sweep flags it — so it stands in for a real sanitize MISS on a composed
# outbound message. Threaded through the alert's host_name into enriched_json.
_LEAK_HOST = "DESKTOP-AB12"


def _leaky_enriched(alert_id: str = "alert-001") -> Any:
    """Enriched context whose host_name survives sanitize but trips residue."""
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(id=alert_id, severity_label="low", host_name=_LEAK_HOST),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


def _never_call_synth_agent() -> Any:
    """A synth agent whose .run MUST NOT be reached when egress is blocked."""
    from pydantic_ai import Agent

    agent = Agent(
        model=TestModel(call_tools=[]),
        system_prompt="stub",
        output_type=TriageReport,
    )
    agent.run = AsyncMock(
        side_effect=AssertionError("analyst model was called despite a blocked egress")
    )
    return agent


@pytest.mark.asyncio
async def test_egress_fail_closed_blocks_and_lands_pipeline_fallback(
    settings_kratos: Settings,
) -> None:
    """With analyst_cloud_redaction + analyst_redaction_fail_closed ON, a payload
    whose sanitized form still carries an internal identifier is BLOCKED: the
    model is never called, the run lands a pipeline_fallback naming the leaked
    COUNT (never the value), and an egress_blocked audit event is emitted."""
    from soc_ai.triage_models import is_pipeline_fallback

    settings_kratos.investigate_when_unsure = False
    settings_kratos.analyst_cloud_redaction = True
    settings_kratos.analyst_redaction_fail_closed = True
    ctx = _make_ctx(settings_kratos)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _leaky_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=_never_call_synth_agent(),
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    # The block was audited.
    assert "egress_blocked" in kinds, "a blocked egress must emit an egress_blocked audit event"
    block_ev = next(e for e in events if e.kind == "egress_blocked")
    assert block_ev.payload["phase"] == "synth_first_round1"
    assert block_ev.payload["leaked_count"] >= 1
    # The audit payload carries ONLY the count — NEVER the raw leaked value.
    assert _LEAK_HOST not in json.dumps(block_ev.payload)

    # The run rendered as a pipeline error (E1.2 fallback), not a real verdict.
    assert "triage_report" in kinds
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "needs_more_info"
    assert is_pipeline_fallback(report_ev.payload) is True
    assert report_ev.payload["resolution"]["phase"] == "egress_blocked"
    # The summary names the leaked class/count, NEVER the raw value.
    assert _LEAK_HOST not in json.dumps(report_ev.payload)
    assert "survived sanitization" in report_ev.payload["summary"].lower() or (
        "identifier" in report_ev.payload["resolution"]["hint"].lower()
    )
    assert kinds[-1] == "done"


@pytest.mark.asyncio
async def test_egress_fail_closed_off_proceeds_best_effort(
    settings_kratos: Settings,
) -> None:
    """Same leaky payload, but fail-closed OFF → the guard is best-effort: the
    model IS called and the run proceeds (current behavior). No egress_blocked."""
    from soc_ai.agent.decision_templates import CandidateVerdict

    settings_kratos.investigate_when_unsure = False
    settings_kratos.analyst_cloud_redaction = True
    settings_kratos.analyst_redaction_fail_closed = False
    ctx = _make_ctx(settings_kratos)

    proceed_report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="benign internal host",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_model = TestModel(call_tools=[], custom_output_args=proceed_report)
    # Strong benign template exempts the hard evidence gate so the FP verdict
    # survives to the report (the point is that the model was CALLED, not blocked).
    strong_candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal scanner",
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _leaky_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=synth_model,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=strong_candidate,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "egress_blocked" not in kinds, "fail-closed OFF must not block egress"
    report_ev = next(e for e in events if e.kind == "triage_report")
    # Proceeded to a real verdict, not a pipeline fallback.
    assert report_ev.payload["verdict"] == "false_positive"
    assert kinds[-1] == "done"


@pytest.mark.asyncio
async def test_egress_local_model_unaffected(settings_kratos: Settings) -> None:
    """analyst_cloud_redaction OFF (local model) → no guard is built at all, so
    fail-closed is inert even when set: the leaky payload proceeds untouched."""
    from soc_ai.agent.decision_templates import CandidateVerdict

    settings_kratos.investigate_when_unsure = False
    settings_kratos.analyst_cloud_redaction = False
    settings_kratos.analyst_redaction_fail_closed = True  # set, but no guard exists
    ctx = _make_ctx(settings_kratos)

    proceed_report = TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary=f"benign host {_LEAK_HOST}",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_model = TestModel(call_tools=[], custom_output_args=proceed_report)
    strong_candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal scanner",
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _leaky_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=synth_model,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=strong_candidate,
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "egress_blocked" not in kinds
    assert ctx.egress_guard is None, "no guard is built when analyst_cloud_redaction is off"
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    # A local-model run leaves the host_name in the report verbatim (no redaction).
    assert _LEAK_HOST in report_ev.payload["summary"]
    assert kinds[-1] == "done"


def test_build_synth_first_agent_uses_three_retries() -> None:
    """Bumped from pydantic_ai's default of 1 to 3.

    Some reasoning models can need a few attempts to emit schema-valid
    JSON. Eval batches showed several synth alerts failing with
    'Exceeded maximum retries (1)' — the same scenarios across repeated
    runs, indicating the retry budget was the bottleneck, not transient
    model fault.
    """
    from soc_ai.agent.orchestrator import build_synth_first_agent

    agent = build_synth_first_agent(TestModel(call_tools=[]))
    # pydantic_ai exposes the retries config on the agent instance.
    assert agent._max_output_retries >= 3


# =====================================================================
# D1: domain/hash enrichment tool wrappers populate the global cache
# =====================================================================


@pytest.mark.asyncio
@pytest.mark.asyncio
def _malware_signal_enriched(alert_id: str = "beacon-001") -> Any:
    """EnrichedAlertContext for a malware-signalling rule (Cobalt Strike beacon).

    `_rule_signals_malware` keys on rule_name / metadata_tags tokens — 'beacon'
    is in _MALWARE_SIGNAL_TOKENS, so this context is never trivially benign.
    """
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            rule_name="ET MALWARE Cobalt Strike Beacon Observed",
            classtype="trojan-activity",
            payload_printable="GET /api/v2/...",
            source_ip="10.0.0.42",
            destination_ip="45.61.136.10",
            severity_label="high",
            rule_metadata=RuleMetadata(signature_severity="Major"),
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
    )


def test_is_evidence_backed_qvod_all_alert_paths_false() -> None:
    """QVOD-shaped citation set (all `alert.*` self-references) → not evidence-backed.

    This is the exact failure shape: 5 citations, every one a path into the
    alert under triage (rule_name, payload_printable, classtype,
    rule_metadata.*). The verdict restates the alert; it never investigated.
    """
    from soc_ai.agent.orchestrator import _is_evidence_backed

    enriched = _malware_signal_enriched()
    report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Looks like benign QVOD P2P based on the rule name and payload.",
        citations=[
            "alert.rule_name",
            "alert.payload_printable",
            "alert.classtype",
            "alert.rule_metadata.signature_severity",
            "alert.rule_metadata.attack_target",
        ],
        recommended_actions=[],
    )
    assert _is_evidence_backed(report, enriched) is False


def test_is_evidence_backed_empty_citations_false() -> None:
    """No citations at all → definitionally not evidence-backed."""
    from soc_ai.agent.orchestrator import _is_evidence_backed

    enriched = _malware_signal_enriched()
    report = TriageReport(
        verdict="false_positive", confidence=0.8, summary="No basis.", citations=[]
    )
    assert _is_evidence_backed(report, enriched) is False


def test_is_evidence_backed_pivot_path_true() -> None:
    """A citation into a real pivot event (community_id_events.*) → evidence-backed
    ONLY when an investigation loop has run (messages is not None).

    Fix A update: path citations into pivot lists now require messages is not None.
    At round 1 (messages=None) these paths come from _materialize_prefetch_evidence;
    citing them is restating the prefetch, not investigation. After a real loop runs
    (messages provided) the same citation is valid evidence.
    """
    from types import SimpleNamespace

    from soc_ai.agent.orchestrator import _is_evidence_backed
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="beacon-001",
            rule_name="ET MALWARE Cobalt Strike Beacon Observed",
            source_ip="10.0.0.42",
            destination_ip="45.61.136.10",
            rule_metadata=RuleMetadata(signature_severity="Major"),
        ),
        # One real Zeek pivot event the agent could have read.
        community_id_events=[SoAlert(id="zeek-evt-1", zeek_ssl_server_name="evil.example.com")],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 1, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
    )
    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="Beacon to evil.example.com confirmed via Zeek SSL SNI.",
        citations=["community_id_events.0.zeek_ssl_server_name"],
        recommended_actions=[],
    )
    # Round 1: messages=None → NOT evidence-backed (prefetch citation, no tool ran).
    assert _is_evidence_backed(report, enriched) is False
    assert _is_evidence_backed(report, enriched, messages=None) is False
    # After loop: messages present → the pivot path IS valid evidence (loop ran).
    fake_messages: list[Any] = [SimpleNamespace(parts=[])]
    assert _is_evidence_backed(report, enriched, messages=fake_messages) is True


def test_is_evidence_backed_tool_citation_true_when_invoked() -> None:
    """A tool citation resolves to evidence only when the tool actually ran."""
    from types import SimpleNamespace

    from soc_ai.agent.orchestrator import _is_evidence_backed

    enriched = _malware_signal_enriched()
    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="Zeek flow confirms beaconing.",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[],
    )
    # No message history → the tool can't be proven called → not evidence-backed.
    assert _is_evidence_backed(report, enriched) is False
    # With a ToolCallPart for t_query_zeek_logs in the history → evidence-backed.
    call_part = SimpleNamespace(tool_name="t_query_zeek_logs", args={"community_id": "x"})
    messages = [SimpleNamespace(parts=[call_part])]
    assert _is_evidence_backed(report, enriched, messages=messages) is True


def test_should_investigate_malware_signal_unsupported_verdict_true() -> None:
    """Malware-signal rule + unsupported (all-`alert.*`) verdict → investigate."""
    from soc_ai.agent.orchestrator import _should_investigate

    enriched = _malware_signal_enriched()
    report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Cleared on rule name alone.",
        citations=["alert.rule_name", "alert.payload_printable"],
        recommended_actions=[],
    )
    # Even with a benign template candidate, a malware-signal rule must not be
    # short-circuited — the synth has to reason from evidence.
    assert _should_investigate(report, enriched, candidate=None) is True


def test_should_investigate_clean_internal_benign_false() -> None:
    """Clean-internal benign (non-malware rule + FP template + FP verdict) → skip."""
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import _should_investigate
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="fp-001",
            rule_name="ET INFO Observed DNS Query to .icu TLD",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            severity_label="low",
            rule_metadata=RuleMetadata(signature_severity="Informational"),
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
    )
    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.7,
        cited_evidence=["alert.severity_label"],
        template_id="internal_informational",
        rationale="internal east-west, informational severity",
    )
    report = TriageReport(
        verdict="false_positive",
        confidence=0.7,
        summary="Internal informational DNS; benign.",
        citations=["alert.severity_label"],
        recommended_actions=[],
    )
    assert _should_investigate(report, enriched, candidate) is False


def test_should_investigate_external_reputation_template_true() -> None:
    """An 'informational external unknown ASN' template settling FP on an
    EXTERNAL host must route INTO the loop (web_search/context can corroborate),
    unlike a clean-internal benign which short-circuits."""
    from soc_ai.agent.decision_templates import CandidateVerdict, _rule_signals_malware
    from soc_ai.agent.orchestrator import _should_investigate
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="ext-001",
            rule_name="ET INFO Abused Hosting Domain (azurewebsites .net) in TLS SNI",
            source_ip="10.0.0.1",
            destination_ip="40.82.255.132",
            severity_label="low",
            rule_metadata=RuleMetadata(signature_severity="Informational"),
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
    )
    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.7,
        cited_evidence=["alert.alert_action=allowed"],
        template_id="informational_external_unknown_asn",
        rationale="external allowed, unknown ASN",
    )
    report = TriageReport(
        verdict="false_positive",
        confidence=0.7,
        summary="External informational; presumed benign.",
        citations=["alert.alert_action=allowed"],
        recommended_actions=[],
    )
    # Ensure we are exercising the EXTERNAL_REPUTATION branch, not the malware one.
    assert _rule_signals_malware(enriched) is False
    assert _should_investigate(report, enriched, candidate) is True


def test_definitely_investigate_predicate() -> None:
    """Report-independent triggers that let the pipeline skip the round-1 synth."""
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import _definitely_investigate

    ext = CandidateVerdict(
        verdict="false_positive",
        confidence=0.7,
        cited_evidence=[],
        template_id="informational_external_unknown_asn",
        rationale="x",
    )
    internal = CandidateVerdict(
        verdict="false_positive",
        confidence=0.7,
        cited_evidence=[],
        template_id="clean_internal_traffic",
        rationale="x",
    )
    # malware signal → True regardless of candidate
    assert _definitely_investigate(_malware_signal_enriched(), None) is True
    # external-reputation template → True
    assert _definitely_investigate(_non_malware_benign_enriched(), ext) is True
    # benign rule + internal template / no candidate → False (round-1 still runs)
    assert _definitely_investigate(_non_malware_benign_enriched(), internal) is False
    assert _definitely_investigate(_non_malware_benign_enriched(), None) is False

    # A benign focus alert whose HOST is concurrently firing a RAT
    # check-in → True even with the clean_internal_traffic candidate. The
    # maliciousness lives in the host context, not the focus packet.
    from soc_ai.so_client.models import SoAlert

    host_threat = _non_malware_benign_enriched()
    host_threat.host_events = [
        SoAlert(
            id="c2",
            rule_name="ET REMOTE_ACCESS NetSupport Remote Admin Checkin",
            source_ip="10.0.0.1",
            destination_ip="203.0.113.9",
            severity_label="low",
        )
    ]
    assert _definitely_investigate(host_threat, internal) is True


def test_loop_synth_message_includes_candidate_prior() -> None:
    """The loop synthesizer message anchors on the decision-template prior."""
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import _format_transcript_for_synthesizer
    from soc_ai.agent.triage import InvestigationTranscript

    t = InvestigationTranscript(
        evidence=["benign (path alert.id)"], tentative_summary="benign", open_questions=[]
    )
    cand = CandidateVerdict(
        verdict="false_positive",
        confidence=0.7,
        cited_evidence=[],
        template_id="informational_external_unknown_asn",
        rationale="external allowed, unknown ASN",
    )
    msg = _format_transcript_for_synthesizer("a1", [t], candidate=cand)
    assert "Decision-template prior" in msg
    assert "informational_external_unknown_asn" in msg
    assert "rule name is" in msg  # anchor instruction present
    # No candidate → no prior block (legacy callers unaffected).
    assert "Decision-template prior" not in _format_transcript_for_synthesizer("a1", [t])


def test_should_investigate_malware_signal_with_prefetched_pivot_citation_true() -> None:
    """Malware-signal rule + round-1 FP whose citations resolve to a PREFETCHED pivot
    → _should_investigate must return True (the loop must run).

    This is the exact bypass that was broken: the synthesizer cited a community_id
    pivot id/path that came from _materialize_prefetch_evidence (zero tool ran),
    _is_evidence_backed accepted that citation, and _should_investigate returned False
    — skipping the investigation loop on exactly the alerts it exists to fix.

    Must FAIL before Fix A + Fix B are applied, PASS after.
    """
    from soc_ai.agent.orchestrator import _should_investigate
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    # Malware-signal alert with a real prefetched Zeek pivot event.
    prefetched_pivot_id = "zeek-conn-abc123"
    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="beacon-bypass-001",
            rule_name="ET MALWARE Cobalt Strike Beacon Observed",
            classtype="trojan-activity",
            source_ip="10.0.0.42",
            destination_ip="45.61.136.10",
            rule_metadata=RuleMetadata(signature_severity="Major"),
        ),
        # Prefetched pivot — the synth was spoon-fed this; no tool ran.
        community_id_events=[SoAlert(id=prefetched_pivot_id, event_dataset="zeek.conn")],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 1, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
    )
    # Round-1 report: confident FP, cites the prefetched pivot by BOTH id and path.
    # This is exactly what _materialize_prefetch_evidence emits for community_id pivots.
    report = TriageReport(
        verdict="false_positive",
        confidence=0.92,
        summary="Beacon looks like internal scanner based on Zeek pivot record.",
        citations=[
            f"community_id pivot: zeek.conn record (id {prefetched_pivot_id})",
            "community_id_events.0.event_dataset",
        ],
        recommended_actions=[],
    )
    # No tool ran (messages=None at round 1) — this must still trigger the loop.
    assert _should_investigate(report, enriched, candidate=None) is True


def test_is_evidence_backed_pivot_citation_not_counted_at_round1() -> None:
    """Pivot id/path citations with messages=None (round 1) → NOT evidence-backed.

    At round 1 no tool ran; the synth was given the pivot data via
    _materialize_prefetch_evidence. Citing those items is restating the
    prefetch, not investigation. Fix A makes both the id-citation branch and
    the path-citation branch require messages is not None.

    Also asserts the True direction: with a fake messages list showing a
    tool ran (for the tool-citation path), or that the intent is clear for
    future tool invocations.
    """
    from soc_ai.agent.orchestrator import _is_evidence_backed
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    prefetched_pivot_id = "zeek-conn-abc123"
    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="beacon-bypass-002",
            rule_name="ET MALWARE Cobalt Strike Beacon Observed",
            classtype="trojan-activity",
            source_ip="10.0.0.42",
            destination_ip="45.61.136.10",
            rule_metadata=RuleMetadata(signature_severity="Major"),
        ),
        community_id_events=[SoAlert(id=prefetched_pivot_id, event_dataset="zeek.conn")],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 1, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
    )

    # Citation by prefetched pivot ID — must be False at round 1 (messages=None).
    report_id_cite = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Cleared via Zeek pivot.",
        citations=[f"community_id pivot: zeek.conn record (id {prefetched_pivot_id})"],
        recommended_actions=[],
    )
    assert _is_evidence_backed(report_id_cite, enriched) is False
    assert _is_evidence_backed(report_id_cite, enriched, messages=None) is False

    # Citation by prefetched pivot PATH — must also be False at round 1.
    report_path_cite = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Cleared via Zeek pivot path.",
        citations=["community_id_events.0.event_dataset"],
        recommended_actions=[],
    )
    assert _is_evidence_backed(report_path_cite, enriched) is False
    assert _is_evidence_backed(report_path_cite, enriched, messages=None) is False


class _FakeIterNode:
    """A pydantic-ai-style node whose ``model_response`` the orchestrator projects."""

    def __init__(self, message: Any) -> None:
        self.model_response = message


class _FakeAgentRun:
    """Async-iterable run that yields one node per message, then exposes ``result``."""

    def __init__(self, messages: list[Any], result: Any) -> None:
        self._nodes = [_FakeIterNode(m) for m in messages]
        self.result = result

    def __aiter__(self) -> Any:
        return self._agen()

    async def _agen(self) -> Any:
        for node in self._nodes:
            yield node


class _FakeIterCM:
    def __init__(self, run: _FakeAgentRun) -> None:
        self._run = run

    async def __aenter__(self) -> _FakeAgentRun:
        return self._run

    async def __aexit__(self, *exc: Any) -> bool:
        return False


def _install_fake_iter(fake_agent: Any, messages: list[Any], result: Any) -> None:
    """Make ``fake_agent.iter(...)`` stream *messages* as nodes and expose
    *result* after iteration — mirrors how the orchestrator now drives the
    investigator via ``agent.iter()`` (live streaming) instead of one blocking
    ``run()``."""
    from unittest.mock import MagicMock

    fake_agent.iter = MagicMock(return_value=_FakeIterCM(_FakeAgentRun(messages, result)))


@pytest.mark.asyncio
async def test_investigation_loop_runs_and_flips_verdict(
    settings_kratos: Settings,
) -> None:
    """Malware-signal alert, unsupported round-1 FP → loop runs, verdict flips to TP.

    The fake investigator returns a transcript whose evidence (a Zeek pivot)
    lets the loop synthesizer conclude true_positive — flipping the zero-tool
    round-1 false_positive. Asserts: investigation_loop_entered emitted, the
    investigator WAS called, and the final verdict changed FP -> TP.
    """
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    settings_kratos.investigate_when_unsure = True
    ctx = _make_ctx(settings_kratos)

    # Round-1 synth: confidently (and wrongly) clears the beacon as FP, citing
    # only the alert's own fields → not evidence-backed.
    round1_report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Looks benign from the rule name and payload.",
        citations=["alert.rule_name", "alert.payload_printable"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_first_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    synth_first_agent.run = AsyncMock(return_value=MagicMock(output=round1_report))

    # Fake investigator: gathers real evidence (a Zeek SSL pivot). Its message
    # history carries a real ToolCallPart so the loop synth's tool citation
    # resolves in post-validate (otherwise the floor rewrite would coerce the
    # verdict back to needs_more_info).
    class _ToolCallPart(SimpleNamespace):
        pass

    class _ToolReturnPart(SimpleNamespace):
        pass

    zeek_call = _ToolCallPart(
        tool_name="t_query_zeek_logs", args={"community_id": "1:abc"}, tool_call_id="tc1"
    )
    # A REAL pydantic-ai history records the tool RETURN too — that non-error
    # return is what count_successful_tool_calls() counts, and only a loop that
    # produced >=1 successful call earns the evidence-gate exemption. Without it
    # the loop gathered nothing and the verdict must NOT be laundered past the
    # gate (see orchestrator._loop_evidence_marker).
    zeek_return = _ToolReturnPart(
        tool_name="t_query_zeek_logs",
        content={"ssl": {"server_name": "evil.example.com"}},
        tool_call_id="tc1",
        part_kind="tool-return",
    )
    loop_msg = SimpleNamespace(parts=[zeek_call, zeek_return])
    loop_transcript = InvestigationTranscript(
        evidence=[
            "t_query_zeek_logs(community_id=1:abc) -> ssl.server_name=evil.example.com "
            "(tool t_query_zeek_logs)",
        ],
        tentative_summary="Zeek SSL SNI resolves to a known C2 host.",
        open_questions=[],
    )
    inv_result = MagicMock()
    inv_result.output = loop_transcript
    inv_result.all_messages = MagicMock(return_value=[loop_msg])
    inv_result.usage = MagicMock(
        return_value=SimpleNamespace(
            tool_calls=1, requests=2, input_tokens=10, output_tokens=5, total_tokens=15
        )
    )
    fake_investigator = MagicMock()
    fake_investigator.run = AsyncMock(return_value=inv_result)
    _install_fake_iter(fake_investigator, [loop_msg], inv_result)

    # Loop synthesizer: concludes true_positive from the gathered transcript.
    flipped_report = TriageReport(
        verdict="true_positive",
        confidence=0.9,
        summary="Confirmed Cobalt Strike beacon to evil.example.com via Zeek SSL SNI.",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    loop_synth_result = MagicMock()
    loop_synth_result.output = flipped_report
    loop_synth_result.usage = MagicMock(
        return_value=SimpleNamespace(
            tool_calls=0, requests=1, input_tokens=8, output_tokens=4, total_tokens=12
        )
    )
    fake_loop_synth = MagicMock()
    fake_loop_synth.run = AsyncMock(return_value=loop_synth_result)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=synth_first_agent,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_investigator",
            return_value=fake_investigator,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer",
            return_value=fake_loop_synth,
        ),
    ):
        events = [ev async for ev in investigate("beacon-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    # The loop ran.
    assert "investigation_loop_entered" in kinds
    loop_ev = next(e for e in events if e.kind == "investigation_loop_entered")
    # Malware-signal alert is a "definitely investigate" case → the round-1 synth
    # is skipped (speed) and the loop runs directly.
    assert "synth_round1_skipped" in kinds
    assert loop_ev.payload["round1_verdict"] is None
    assert loop_ev.payload["reason"] == "definitely_investigate"
    # The investigator was actually invoked (streamed via iter()).
    fake_investigator.iter.assert_called_once()
    fake_loop_synth.run.assert_awaited_once()
    # The final verdict changed FP -> TP.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "true_positive"
    # No Phase D dispatch — the loop supersedes it.
    assert "targeted_dispatch" not in kinds
    # Loop transcript surfaced to the stream.
    assert "investigation_transcript" in kinds


@pytest.mark.asyncio
async def test_investigation_loop_investigator_failure_errors_not_nmi(
    settings_kratos: Settings,
) -> None:
    """A gateway/model failure in the investigator surfaces as an ERROR with NO
    triage_report — not a fabricated needs_more_info verdict (which read as if the
    agent had investigated and was unsure). The recorder then marks the run error."""
    from unittest.mock import MagicMock

    settings_kratos.investigate_when_unsure = True
    ctx = _make_ctx(settings_kratos)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)  # malware → definitely_investigate

    fake_investigator = MagicMock()
    fake_investigator.iter = MagicMock(side_effect=ConnectionError("Connection error."))

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
    ):
        events = [ev async for ev in investigate("mal-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "investigation_loop_entered" in kinds  # the loop started
    assert "error" in kinds  # failure surfaced
    assert "triage_report" not in kinds  # NO fabricated verdict
    assert "done" not in kinds


@pytest.mark.asyncio
async def test_investigation_loop_streams_tool_events(
    settings_kratos: Settings,
) -> None:
    """The loop's tool_call / tool_result parts reach the SSE stream (UI activity)."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from pydantic_ai import Agent

    settings_kratos.investigate_when_unsure = True
    ctx = _make_ctx(settings_kratos)

    round1_report = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Benign from rule name.",
        citations=["alert.rule_name"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_first_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    synth_first_agent.run = AsyncMock(return_value=MagicMock(output=round1_report))

    # Duck-typed PydanticAI message with a ToolCallPart + ToolReturnPart. The
    # part class names are what _walk_message switches on.
    class ToolCallPart(SimpleNamespace):
        pass

    class ToolReturnPart(SimpleNamespace):
        pass

    call_part = ToolCallPart(
        tool_name="t_query_zeek_logs", args={"community_id": "1:abc"}, tool_call_id="tc1"
    )
    return_part = ToolReturnPart(
        tool_name="t_query_zeek_logs", content={"ssl": ["evil.example.com"]}, tool_call_id="tc1"
    )
    fake_msg = SimpleNamespace(parts=[call_part, return_part])

    loop_transcript = InvestigationTranscript(
        evidence=["t_query_zeek_logs -> evil.example.com (tool t_query_zeek_logs)"],
        tentative_summary="C2 confirmed.",
        open_questions=[],
    )
    inv_result = MagicMock()
    inv_result.output = loop_transcript
    inv_result.all_messages = MagicMock(return_value=[fake_msg])
    inv_result.usage = MagicMock(
        return_value=SimpleNamespace(
            tool_calls=1, requests=2, input_tokens=10, output_tokens=5, total_tokens=15
        )
    )
    fake_investigator = MagicMock()
    fake_investigator.run = AsyncMock(return_value=inv_result)
    _install_fake_iter(fake_investigator, [fake_msg], inv_result)

    flipped_report = TriageReport(
        verdict="true_positive",
        confidence=0.9,
        summary="Confirmed beacon.",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[],
    )
    loop_synth_result = MagicMock()
    loop_synth_result.output = flipped_report
    loop_synth_result.usage = MagicMock(
        return_value=SimpleNamespace(
            tool_calls=0, requests=1, input_tokens=8, output_tokens=4, total_tokens=12
        )
    )
    fake_loop_synth = MagicMock()
    fake_loop_synth.run = AsyncMock(return_value=loop_synth_result)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=synth_first_agent,
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=fake_loop_synth),
    ):
        events = [ev async for ev in investigate("beacon-001", ctx=ctx)]

    tool_calls = [e for e in events if e.kind == "tool_call"]
    tool_results = [e for e in events if e.kind == "tool_result"]
    assert any(e.payload.get("tool_name") == "t_query_zeek_logs" for e in tool_calls), (
        "loop's tool_call part must reach the SSE stream"
    )
    assert any(e.payload.get("tool_name") == "t_query_zeek_logs" for e in tool_results)
    # Tool events are stamped with the investigation_loop phase.
    assert all(e.payload.get("phase") == "investigation_loop" for e in tool_calls)


@pytest.mark.asyncio
async def test_investigation_loop_skipped_for_trivially_benign(
    settings_kratos: Settings,
) -> None:
    """Trivially-benign alert → loop skipped, investigator NOT called."""
    from unittest.mock import MagicMock

    from pydantic_ai import Agent
    from soc_ai.agent.decision_templates import CandidateVerdict

    settings_kratos.investigate_when_unsure = True
    ctx = _make_ctx(settings_kratos)

    # Decision template clears a non-malware internal alert FP. A real strong
    # benign template (clean_internal_traffic @ 0.85) both skips the loop AND
    # exempts the evidence gate — the production shape for this case.
    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal east-west informational",
    )
    round1_report = TriageReport(
        verdict="false_positive",
        confidence=0.7,
        summary="Internal informational DNS; benign.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_first_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=round1_report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    synth_first_agent.run = AsyncMock(return_value=MagicMock(output=round1_report))

    fake_investigator = MagicMock()
    fake_investigator.run = AsyncMock(
        side_effect=AssertionError("investigator must NOT run for a trivially-benign alert")
    )

    def _benign_enriched(alert_id: str) -> Any:
        from soc_ai.so_client.models import RuleMetadata, SoAlert
        from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

        return EnrichedAlertContext(
            alert=SoAlert(
                id=alert_id,
                rule_name="ET INFO Observed DNS Query to .icu TLD",
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
                severity_label="low",
                rule_metadata=RuleMetadata(signature_severity="Informational"),
            ),
            community_id_events=[],
            host_events=[],
            user_events=[],
            process_events=[],
            file_events=[],
            pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
            typed_zeek=TypedZeekFields(),
        )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _benign_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=synth_first_agent,
        ),
        patch("soc_ai.agent.decision_templates.match_decision_template", return_value=candidate),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
    ):
        events = [ev async for ev in investigate("fp-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "investigation_loop_entered" not in kinds
    fake_investigator.run.assert_not_awaited()
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"


# =====================================================================
# Theme-1 Task 3: Oracle escalation gate + wiring
# =====================================================================


def _non_malware_benign_enriched(alert_id: str = "dns-001") -> Any:
    """EnrichedAlertContext for a benign informational rule (no malware signal)."""
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            rule_name="ET INFO Observed DNS Query to .icu TLD",
            source_ip="10.0.0.1",
            destination_ip="8.8.8.8",
            severity_label="low",
            rule_metadata=RuleMetadata(signature_severity="Informational"),
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
    )


def _oracle_settings(**overrides: Any) -> Settings:
    """Settings with Oracle enabled (all escalation flags at defaults)."""
    kwargs: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": "password123",
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "oracle_enabled": True,
        "oracle_model": "claude-sonnet-4-6",
        "oracle_escalate_needs_more_info": True,
        "oracle_escalate_malware_non_tp": True,
        "oracle_escalate_below_confidence": 0.6,
    }
    kwargs.update(overrides)
    return Settings(**kwargs)


# ---------------------------------------------------------------------------
# Gate matrix tests
# ---------------------------------------------------------------------------


class TestShouldEscalateToOracle:
    """Unit tests for _should_escalate_to_oracle gate matrix."""

    def _gate(
        self,
        report: TriageReport,
        enriched: Any,
        settings: Settings,
    ) -> bool:
        from soc_ai.agent.orchestrator import _should_escalate_to_oracle

        return _should_escalate_to_oracle(report, enriched, settings)

    def _report(
        self,
        verdict: str = "false_positive",
        confidence: float = 0.85,
    ) -> TriageReport:
        return TriageReport(
            verdict=verdict,  # type: ignore[arg-type]
            confidence=confidence,
            summary="Test.",
            citations=[],
        )

    def test_needs_more_info_escalates(self) -> None:
        """needs_more_info → escalate (condition 1)."""
        settings = _oracle_settings()
        enriched = _non_malware_benign_enriched()
        report = self._report(verdict="needs_more_info", confidence=0.4)
        assert self._gate(report, enriched, settings) is True

    def test_malware_signal_fp_escalates(self) -> None:
        """Malware-signal rule + false_positive (zero-tool path) → escalate (condition 2)."""
        settings = _oracle_settings()
        enriched = _malware_signal_enriched()
        report = self._report(verdict="false_positive", confidence=0.85)
        # ran_loop defaults False → the zero-tool QVOD/BPFDoor safety net fires.
        assert self._gate(report, enriched, settings) is True

    def test_malware_signal_confident_fp_after_loop_no_escalate(self) -> None:
        """COST GATE: a confident FP AFTER a real investigation loop → NO escalation."""
        from soc_ai.agent.orchestrator import _should_escalate_to_oracle

        settings = _oracle_settings()
        enriched = _malware_signal_enriched()
        report = self._report(verdict="false_positive", confidence=0.85)
        # 0.85 >= oracle_skip_after_confident_loop (0.8) and the loop ran → trust it.
        assert _should_escalate_to_oracle(report, enriched, settings, ran_loop=True) is False
        # but the same verdict from the zero-tool path STILL escalates:
        assert _should_escalate_to_oracle(report, enriched, settings, ran_loop=False) is True

    def test_malware_signal_low_conf_fp_after_loop_still_escalates(self) -> None:
        """A loop that stayed low-confidence does NOT earn the skip (still escalates)."""
        from soc_ai.agent.orchestrator import _should_escalate_to_oracle

        settings = _oracle_settings()
        enriched = _malware_signal_enriched()
        # 0.65: above the 0.6 floor (condition 3 quiet) but below the 0.8 skip.
        report = self._report(verdict="false_positive", confidence=0.65)
        assert _should_escalate_to_oracle(report, enriched, settings, ran_loop=True) is True

    def test_malware_signal_confident_tp_no_escalate(self) -> None:
        """Malware-signal + true_positive at confidence ≥ 0.7 → NO escalation."""
        settings = _oracle_settings()
        enriched = _malware_signal_enriched()
        report = self._report(verdict="true_positive", confidence=0.85)
        assert self._gate(report, enriched, settings) is False

    def test_malware_signal_low_conf_tp_no_escalate(self) -> None:
        """CryptoWall: a malware-signal TP at LOW confidence (0.54,
        a citation_cap artifact) must stay LOCAL. A flagged-malicious verdict is
        the right call regardless of the confidence number; the Oracle cannot
        improve 'this malware is malicious.' Before the fix this tripped BOTH the
        malware-non-TP gate (conf < 0.7) and the low-confidence floor (conf < 0.6)
        and bounced a correct local verdict to the Oracle."""
        settings = _oracle_settings()
        enriched = _malware_signal_enriched()
        report = self._report(verdict="true_positive", confidence=0.54)
        # Both the zero-tool and post-loop paths keep it local.
        assert self._gate(report, enriched, settings) is False
        from soc_ai.agent.orchestrator import _should_escalate_to_oracle

        assert _should_escalate_to_oracle(report, enriched, settings, ran_loop=True) is False

    def test_non_malware_confident_fp_no_escalate(self) -> None:
        """Non-malware rule + confident false_positive → NO escalation."""
        settings = _oracle_settings()
        enriched = _non_malware_benign_enriched()
        report = self._report(verdict="false_positive", confidence=0.9)
        assert self._gate(report, enriched, settings) is False

    def test_below_confidence_threshold_escalates(self) -> None:
        """Any rule + confidence 0.5 (below default 0.6) → escalate (condition 3)."""
        settings = _oracle_settings()
        enriched = _non_malware_benign_enriched()
        report = self._report(verdict="false_positive", confidence=0.5)
        assert self._gate(report, enriched, settings) is True

    def test_oracle_disabled_never_escalates(self) -> None:
        """oracle_enabled=False → False regardless of verdict/confidence."""
        settings = _oracle_settings(oracle_enabled=False)
        enriched = _malware_signal_enriched()

        # Even NMI + malware-signal + below-floor confidence won't escalate.
        report = self._report(verdict="needs_more_info", confidence=0.1)
        assert self._gate(report, enriched, settings) is False

        report2 = self._report(verdict="false_positive", confidence=0.85)
        assert self._gate(report2, enriched, settings) is False

    def test_needs_more_info_flag_off_non_malware_does_not_escalate(self) -> None:
        """When oracle_escalate_needs_more_info=False and the only trigger is NMI
        on a non-malware rule with confidence above floor → no escalation."""
        settings = _oracle_settings(
            oracle_escalate_needs_more_info=False,
            oracle_escalate_below_confidence=0.0,  # disable confidence gate
        )
        enriched = _non_malware_benign_enriched()
        # NMI but confidence is exactly 0.6 (not < 0.0 floor) → no escalation
        report = self._report(verdict="needs_more_info", confidence=0.6)
        assert self._gate(report, enriched, settings) is False


# ---------------------------------------------------------------------------
# Wiring tests: escalated FP on malware rule → Oracle overrides to TP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oracle_wiring_escalated_fp_overridden_to_tp(
    settings_kratos: Settings,
) -> None:
    """With oracle_enabled + a patched adjudicate returning TP:
    - an escalated local FP on a malware rule → final verdict becomes TP
    - oracle_escalation and oracle_adjudication events are emitted
    - the local verdict is preserved as local_verdict in the triage_report payload.
    """
    settings_kratos.investigate_when_unsure = False
    settings_kratos.oracle_enabled = True
    settings_kratos.oracle_escalate_malware_non_tp = True
    settings_kratos.oracle_escalate_below_confidence = 0.6
    ctx = _make_ctx(settings_kratos)

    # Local synth says FP (malware-signal rule → should escalate).
    local_fp_report = TriageReport(
        verdict="false_positive",
        confidence=0.75,
        summary="Looks benign to local model.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_model = TestModel(call_tools=[], custom_output_args=local_fp_report)

    # Oracle says TP.
    oracle_tp_report = TriageReport(
        verdict="true_positive",
        confidence=0.92,
        summary="Cobalt Strike C2 traffic confirmed.",
        citations=["alert.payload_printable"],
        recommended_actions=[],
    )
    from soc_ai.oracle.client import OracleResult

    oracle_result = OracleResult(
        report=oracle_tp_report,
        redaction_summary={"IP": 2},
        oracle_model="claude-sonnet-4-6",
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=synth_model,
        ),
        patch(
            "soc_ai.oracle.client.adjudicate",
            new=AsyncMock(return_value=oracle_result),
        ),
    ):
        events = [ev async for ev in investigate("beacon-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "oracle_escalation" in kinds
    assert "oracle_adjudication" in kinds
    assert "triage_report" in kinds

    # Final verdict must be the Oracle's TP.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "true_positive"
    # Summary gets the [Oracle adjudicated] prefix.
    assert "[Oracle adjudicated]" in report_ev.payload["summary"]
    # Local verdict preserved. The local zero-tool FP on a MALWARE rule is itself
    # caught by the hard evidence gate (→ needs_more_info) before escalation —
    # defense in depth — and the Oracle then overrides it to TP.
    assert report_ev.payload["local_verdict"] == "needs_more_info"

    # oracle_adjudication payload must carry oracle_verdict + redaction.
    adj_ev = next(e for e in events if e.kind == "oracle_adjudication")
    assert adj_ev.payload["oracle_verdict"] == "true_positive"
    assert adj_ev.payload["oracle_confidence"] == pytest.approx(0.92)
    assert adj_ev.payload["redaction"] == {"IP": 2}


@pytest.mark.asyncio
async def test_oracle_wiring_adjudicate_returns_none_local_verdict_stands(
    settings_kratos: Settings,
) -> None:
    """When adjudicate returns None (refusal or gateway failure), the local verdict
    is kept unchanged and no oracle_adjudication event is emitted."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.oracle_enabled = True
    settings_kratos.oracle_escalate_malware_non_tp = True
    ctx = _make_ctx(settings_kratos)

    local_fp_report = TriageReport(
        verdict="false_positive",
        confidence=0.75,
        summary="Local verdict: benign.",
        citations=["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_model = TestModel(call_tools=[], custom_output_args=local_fp_report)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=synth_model,
        ),
        patch(
            "soc_ai.oracle.client.adjudicate",
            new=AsyncMock(return_value=None),
        ),
    ):
        events = [ev async for ev in investigate("beacon-001", ctx=ctx)]

    kinds = [e.kind for e in events]
    assert "oracle_escalation" in kinds
    # Refusal → no adjudication event.
    assert "oracle_adjudication" not in kinds

    report_ev = next(e for e in events if e.kind == "triage_report")
    # Local verdict stands (Oracle refused). The zero-tool FP on a malware rule
    # was caught by the hard evidence gate → needs_more_info before escalation.
    assert report_ev.payload["verdict"] == "needs_more_info"
    assert "[Oracle adjudicated]" not in (report_ev.payload["summary"] or "")
    # local_verdict field is None when Oracle didn't override.
    assert report_ev.payload["local_verdict"] is None


# ---------------------------------------------------------------------------
# Fix 1: _should_escalate_to_oracle now covers attack-class rules too
# ---------------------------------------------------------------------------


def _attack_class_enriched(alert_id: str = "lateral-001") -> Any:
    """EnrichedAlertContext for an attack-class rule (kerberoast).

    classtype is in _ATTACK_CLASSTYPES; rule_name has NO malware tokens so
    _rule_signals_malware is False — the previous gate-2 missed this.
    """
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext, TypedZeekFields

    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            rule_name="ET ATTACK_RESPONSE Kerberoast SPN Request",
            classtype="attempted-admin",
            source_ip="10.1.2.3",
            destination_ip="10.1.2.10",
            severity_label="high",
            rule_metadata=RuleMetadata(signature_severity="Major"),
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
    )


class TestShouldEscalateToOracleAttackClass:
    """Fix 1: gate-2 now uses (_rule_signals_malware OR _rule_signals_attack)."""

    def _gate(
        self,
        report: TriageReport,
        enriched: Any,
        settings: Settings,
    ) -> bool:
        from soc_ai.agent.orchestrator import _should_escalate_to_oracle

        return _should_escalate_to_oracle(report, enriched, settings)

    def _report(
        self,
        verdict: str = "false_positive",
        confidence: float = 0.85,
    ) -> TriageReport:
        return TriageReport(
            verdict=verdict,  # type: ignore[arg-type]
            confidence=confidence,
            summary="Test.",
            citations=[],
        )

    def test_attack_class_confident_fp_escalates(self) -> None:
        """ATTACK-class classtype + confident false_positive → escalates (Fix 1).

        Before Fix 1, gate-2 keyed on _rule_signals_malware only.
        'ET ATTACK_RESPONSE Kerberoast SPN Request' has no malware token →
        would return False. With Fix 1, _rule_signals_attack sees classtype
        'attempted-admin' ∈ _ATTACK_CLASSTYPES → returns True.
        """
        settings = _oracle_settings()
        enriched = _attack_class_enriched()
        report = self._report(verdict="false_positive", confidence=0.85)
        assert self._gate(report, enriched, settings) is True

    def test_attack_class_confident_tp_does_not_escalate(self) -> None:
        """ATTACK-class rule + true_positive confidence ≥ 0.7 → NO escalation."""
        settings = _oracle_settings()
        enriched = _attack_class_enriched()
        report = self._report(verdict="true_positive", confidence=0.85)
        assert self._gate(report, enriched, settings) is False

    def test_genuine_benign_non_attack_no_escalate(self) -> None:
        """Non-malware, non-attack rule + confident FP → still no escalation."""
        settings = _oracle_settings(
            oracle_escalate_below_confidence=0.0,  # disable confidence gate too
        )
        enriched = _non_malware_benign_enriched()
        report = self._report(verdict="false_positive", confidence=0.9)
        assert self._gate(report, enriched, settings) is False

    def test_attack_class_rule_signals_attack_helper(self) -> None:
        """_rule_signals_attack returns True for attack-class classtypes."""
        from soc_ai.agent.decision_templates import _rule_signals_attack

        enriched = _attack_class_enriched()
        assert _rule_signals_attack(enriched) is True

    def test_non_attack_class_rule_signals_attack_false(self) -> None:
        """_rule_signals_attack returns False for non-attack classtypes."""
        from soc_ai.agent.decision_templates import _rule_signals_attack

        enriched = _non_malware_benign_enriched()
        assert _rule_signals_attack(enriched) is False


# ---------------------------------------------------------------------------
# Fix 2: Oracle output is post-validated with _apply_targeted_downgrades
# ---------------------------------------------------------------------------


def _stub_icmp_enriched(alert_id: str = "ping-001") -> Any:
    """EnrichedAlertContext for the BPFDoor-class ICMP ping (synth-first path).

    Carries:
    - typed_zeek.icmp_echo_request_reply=True (Zeek saw type-8→type-0)
    - both endpoints internal (10.20.30.x)
    - clean IndicatorEnrichment entries with no blocklist/MISP hits for both
      source and destination IPs — this triggers the "enrichment" verification
      path in _is_solicited_internal_icmp_echo, which returns "enrichment" and
      allows _apply_targeted_downgrades to fire.

    Same shape as the BPFDoor false escalation, expressed as an
    EnrichedAlertContext (synth-first path) rather than the legacy AlertContext.
    """
    from soc_ai.enrichment.zeek_parser import TypedZeekFields
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.enrichment import IndicatorEnrichment
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    src, dst = "10.20.30.1", "10.20.30.15"
    clean_enrichments = {
        src: IndicatorEnrichment(indicator=src, indicator_type="ip", internal=True),
        dst: IndicatorEnrichment(indicator=dst, indicator_type="ip", internal=True),
    }
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            rule_name="ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat (Outbound)",
            classtype="trojan-activity",
            source_ip=src,
            destination_ip=dst,
            severity_label="high",
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(icmp_echo_request_reply=True),
        enrichments=clean_enrichments,
    )


def test_oracle_post_validate_downgrades_solicited_icmp_tp() -> None:
    """Fix 2: Oracle returning a solicited-ICMP TP is downgraded by
    _apply_targeted_downgrades before triage_final is set.

    The Oracle might re-introduce the BPFDoor false-positive (because it
    sees the malware rule label and believes it).  After Fix 2, the same
    deterministic downgrade that ran on the local verdict also runs on the
    Oracle's output — resulting triage_final must be false_positive.
    """
    from soc_ai.agent.orchestrator import _apply_targeted_downgrades

    oracle_tp_report = TriageReport(
        verdict="true_positive",
        confidence=0.88,
        summary="BPFDoor ICMP heartbeat confirmed by Oracle.",
        citations=["alert.rule_name"],
        recommended_actions=[],
    )
    enriched = _stub_icmp_enriched()
    audit: dict[str, Any] = {}
    # Run the same post-validate that Fix 2 wires into the Oracle path.
    result = _apply_targeted_downgrades(oracle_tp_report, enriched, audit)
    assert result.verdict == "false_positive", (
        "_apply_targeted_downgrades must downgrade solicited-ICMP Oracle TP to FP"
    )
    assert "icmp_solicited_downgrade" in audit, (
        "icmp_solicited_downgrade audit entry must be written"
    )
    assert audit["icmp_solicited_downgrade"]["original_verdict"] == "true_positive"
    assert audit["icmp_solicited_downgrade"]["downgraded_verdict"] == "false_positive"


@pytest.mark.asyncio
async def test_oracle_wiring_post_validates_icmp_tp(
    settings_kratos: Settings,
) -> None:
    """Fix 2 end-to-end: Oracle says TP on a BPFDoor ICMP alert →
    post-validate step in _run_synth_first_pipeline downgrades to FP.

    The local synth returns needs_more_info (so the oracle_escalate_needs_more_info
    gate fires).  The Oracle stub returns true_positive for the ICMP ping.
    After Fix 2, triage_final must be false_positive.
    """
    settings_kratos.investigate_when_unsure = False
    settings_kratos.oracle_enabled = True
    settings_kratos.oracle_escalate_needs_more_info = True
    settings_kratos.oracle_escalate_malware_non_tp = True
    ctx = _make_ctx(settings_kratos)

    # Local synth is uncertain.
    local_nmi_report = TriageReport(
        verdict="needs_more_info",
        confidence=0.5,
        summary="Uncertain — looks like ICMP but rule says malware.",
        citations=["alert.rule_name"],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    synth_model = TestModel(call_tools=[], custom_output_args=local_nmi_report)

    # Oracle stub returns TP for the ICMP alert.
    oracle_tp_report = TriageReport(
        verdict="true_positive",
        confidence=0.9,
        summary="BPFDoor ICMP heartbeat — Oracle confirmed C2.",
        citations=["alert.payload_printable"],
        recommended_actions=[],
    )
    from soc_ai.oracle.client import OracleResult

    oracle_result = OracleResult(
        report=oracle_tp_report,
        redaction_summary={"IP": 2},
        oracle_model="claude-sonnet-4-6",
    )

    async def _stub_enriched_icmp(alert_id: str, **_kw: Any) -> Any:
        return _stub_icmp_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched_icmp,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=synth_model,
        ),
        patch(
            "soc_ai.oracle.client.adjudicate",
            new=AsyncMock(return_value=oracle_result),
        ),
    ):
        events = [ev async for ev in investigate("ping-001", ctx=ctx)]

    report_ev = next(e for e in events if e.kind == "triage_report")
    # Despite Oracle returning TP, the post-validate must downgrade to FP.
    assert report_ev.payload["verdict"] == "false_positive", (
        "Oracle TP on solicited ICMP ping must be downgraded to FP by Fix 2"
    )


# ---------------------------------------------------------------------------
# _downgrade_ungrounded_host_anchored_tp — unit tests (D17)
# ---------------------------------------------------------------------------


def _make_vpn_icmp_enriched(
    alert_id: str = "vpn-icmp-001",
    *,
    blocklist_hit: bool = False,
    misp_hit: bool = False,
) -> Any:
    """EnrichedAlertContext for a benign Mac/VPN ICMP alert with a non-empty
    host_alert_profile listing a malware rule — the exact FP escalation scenario.

    The focus alert is 'GPL ICMP Destination Unreachable Port Unreachable'
    (classtype misc-activity, not a malware/exploit class). The host_alert_profile
    contains one BPFDoor entry that is itself a separate, unconfirmed alert.
    Enrichments have NO hits by default; set blocklist_hit or misp_hit to True
    to model a grounded TP scenario.
    """
    from soc_ai.enrichment.blocklists import BlocklistHit
    from soc_ai.enrichment.zeek_parser import TypedZeekFields
    from soc_ai.tools.enrichment import IndicatorEnrichment
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    src, dst = "192.0.2.1", "10.0.0.100"
    hits: list[BlocklistHit] = (
        [BlocklistHit(indicator=src, indicator_type="ip", source="test", tags=("malware",))]
        if blocklist_hit
        else []
    )
    misp_hits_list: list[Any] = []
    if misp_hit:
        from soc_ai.tools.enrichment import Finding

        misp_hits_list = [
            Finding(
                source="test-misp",
                category="ioc_match",
                description="known C2 infrastructure",
            )
        ]
    enrichments = {
        src: IndicatorEnrichment(
            indicator=src,
            indicator_type="ip",
            internal=False,
            blocklist_hits=hits,
            misp_hits=misp_hits_list,
        ),
        dst: IndicatorEnrichment(
            indicator=dst,
            indicator_type="ip",
            internal=True,
        ),
    }
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            rule_name="GPL ICMP Destination Unreachable Port Unreachable",
            classtype="misc-activity",
            source_ip=src,
            destination_ip=dst,
            severity_label="informational",
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
        enrichments=enrichments,
        host_alert_profile={
            "ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat (Outbound)": 1,
        },
    )


def test_downgrade_ungrounded_host_anchored_tp_fires_on_no_evidence() -> None:
    """TP resting on host_alert_profile + no per-alert evidence → downgraded to NMI.

    Scenario: benign Mac/VPN ICMP alert, host_alert_profile has a BPFDoor entry
    (separate unconfirmed alert), enrichments have no blocklist/MISP hits, focus
    alert is misc-activity (not malware class), no beacon/payload tokens in summary.
    Expected: verdict=needs_more_info, recommended_actions=[], audit entry written.
    """
    from soc_ai.agent.orchestrator import _downgrade_ungrounded_host_anchored_tp

    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="BPFDoor C2 confirmed by host profile and absence of reputation.",
        citations=["alert.rule_name"],
        recommended_actions=[
            RecommendedAction(
                tool_name="escalate_to_case",
                tool_args={"alert_id": "vpn-icmp-001"},
                rationale="Confirmed C2.",
            )
        ],
    )
    enriched = _make_vpn_icmp_enriched()
    audit: dict[str, Any] = {}

    result = _downgrade_ungrounded_host_anchored_tp(report, enriched, audit)

    assert result.verdict == "needs_more_info", (
        "Ungrounded host-anchored TP must be downgraded to needs_more_info"
    )
    assert result.recommended_actions == [], "recommended_actions must be cleared on downgrade"
    assert result.confidence <= 0.5
    assert "ungrounded_host_anchored_tp_downgrade" in audit, "audit entry must be written"
    assert audit["ungrounded_host_anchored_tp_downgrade"]["original_verdict"] == "true_positive"
    assert audit["ungrounded_host_anchored_tp_downgrade"]["downgraded_verdict"] == "needs_more_info"
    # Summary must lead with the correct conclusion — no inline bracket.
    assert not result.summary.startswith("[Auto-downgraded")
    assert "insufficient" in result.summary.lower() or "re-investigate" in result.summary.lower()
    # Override explanation in validator_note; original summary preserved there.
    assert result.validator_note is not None
    assert "true_positive" in result.validator_note
    assert "BPFDoor" in result.validator_note  # original summary text


def test_downgrade_ungrounded_host_anchored_tp_skipped_with_blocklist_hit() -> None:
    """Grounded TP (blocklist hit on indicator) must NOT be downgraded.

    Same scenario but the external IP has a blocklist hit — that is real per-alert
    evidence, so the validator must leave the verdict as true_positive.
    """
    from soc_ai.agent.orchestrator import _downgrade_ungrounded_host_anchored_tp

    report = TriageReport(
        verdict="true_positive",
        confidence=0.88,
        summary="External IP on blocklist; confirmed malicious.",
        citations=["alert.source_ip"],
        recommended_actions=[],
    )
    enriched = _make_vpn_icmp_enriched(blocklist_hit=True)
    audit: dict[str, Any] = {}

    result = _downgrade_ungrounded_host_anchored_tp(report, enriched, audit)

    assert result.verdict == "true_positive", "TP with a blocklist hit must NOT be downgraded"
    assert "ungrounded_host_anchored_tp_downgrade" not in audit


def test_downgrade_ungrounded_host_anchored_tp_skipped_with_misp_hit() -> None:
    """Grounded TP (MISP hit on indicator) must NOT be downgraded."""
    from soc_ai.agent.orchestrator import _downgrade_ungrounded_host_anchored_tp

    report = TriageReport(
        verdict="true_positive",
        confidence=0.88,
        summary="IP in MISP as known C2.",
        citations=["alert.source_ip"],
        recommended_actions=[],
    )
    enriched = _make_vpn_icmp_enriched(misp_hit=True)
    audit: dict[str, Any] = {}

    result = _downgrade_ungrounded_host_anchored_tp(report, enriched, audit)

    assert result.verdict == "true_positive", "TP with a MISP hit must NOT be downgraded"
    assert "ungrounded_host_anchored_tp_downgrade" not in audit


def test_downgrade_ungrounded_host_anchored_tp_skipped_for_non_tp() -> None:
    """false_positive and needs_more_info verdicts pass through unchanged."""
    from soc_ai.agent.orchestrator import _downgrade_ungrounded_host_anchored_tp

    enriched = _make_vpn_icmp_enriched()

    for verdict in ("false_positive", "needs_more_info"):
        report = TriageReport(
            verdict=verdict,  # type: ignore[arg-type]
            confidence=0.8,
            summary="Some summary.",
            citations=["alert.rule_name"],
            recommended_actions=[],
        )
        audit: dict[str, Any] = {}
        result = _downgrade_ungrounded_host_anchored_tp(report, enriched, audit)
        assert result.verdict == verdict, (
            f"Non-TP verdict '{verdict}' must not be altered by the validator"
        )
        assert "ungrounded_host_anchored_tp_downgrade" not in audit


def test_downgrade_ungrounded_host_anchored_tp_skipped_when_focus_alert_is_malware_class() -> None:
    """Gate 3b: focus alert is a malware-class signature → TP must NOT be downgraded.

    Scenario: TP with non-empty host_alert_profile, NO blocklist/MISP hits on any
    indicator, but the FOCUS alert is itself "ET MALWARE …" (rule_name prefix that
    _alert_signals_malware recognises). Gate 3b must short-circuit and preserve the
    true_positive verdict.
    """
    from soc_ai.agent.orchestrator import _downgrade_ungrounded_host_anchored_tp
    from soc_ai.enrichment.zeek_parser import TypedZeekFields
    from soc_ai.tools.enrichment import IndicatorEnrichment
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    src, dst = "192.0.2.50", "10.0.0.200"
    enrichments = {
        src: IndicatorEnrichment(
            indicator=src,
            indicator_type="ip",
            internal=False,
            blocklist_hits=[],  # no blocklist hit
            misp_hits=[],  # no MISP hit
        ),
        dst: IndicatorEnrichment(
            indicator=dst,
            indicator_type="ip",
            internal=True,
        ),
    }
    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="malware-sig-001",
            rule_name="ET MALWARE SomeFamily C2 Beacon",
            classtype="trojan-activity",
            source_ip=src,
            destination_ip=dst,
            severity_label="high",
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        typed_zeek=TypedZeekFields(),
        enrichments=enrichments,
        host_alert_profile={
            "ET MALWARE SomeFamily C2 Beacon": 5,
            "ET POLICY Suspicious Outbound": 2,
        },
    )
    report = TriageReport(
        verdict="true_positive",
        confidence=0.90,
        summary="ET MALWARE rule fired; consistent with C2 beacon activity.",
        citations=["alert.rule_name"],
        recommended_actions=[
            RecommendedAction(
                tool_name="escalate_to_case",
                tool_args={"alert_id": "malware-sig-001"},
                rationale="Malware-class rule on this alert.",
            )
        ],
    )
    audit: dict[str, Any] = {}

    result = _downgrade_ungrounded_host_anchored_tp(report, enriched, audit)

    assert result.verdict == "true_positive", (
        "Gate 3b: focus alert is malware-class (ET MALWARE rule_name) — "
        "TP must NOT be downgraded even without blocklist/MISP hits"
    )
    assert "ungrounded_host_anchored_tp_downgrade" not in audit, (
        "audit must NOT record a downgrade when the focus alert is malware-class"
    )


# ---------------------------------------------------------------------------
# Hard evidence gate — count_successful_tool_calls / _is_strong_grounded_template
# / _downgrade_unevidenced_verdict (the zero-tool-verdict defense)
# ---------------------------------------------------------------------------


def _ret(*contents: Any) -> _FakeMessage:
    """A message carrying one or more ToolReturnParts (tool RESULTS) — reuses the
    existing _FakeToolReturnPart(tool_name, content) stand-in defined above."""
    return _FakeMessage([_FakeToolReturnPart("t_tool", c) for c in contents])


def test_count_successful_tool_calls_counts_only_real_data() -> None:
    from soc_ai.agent.orchestrator import count_successful_tool_calls

    assert count_successful_tool_calls(None) == 0
    assert count_successful_tool_calls([]) == 0
    # a CALL part (has .args) is not a return → not counted
    assert count_successful_tool_calls([_msg(("t_enrich_ip", {"ip": "1.2.3.4"}))]) == 0
    # one good return
    assert count_successful_tool_calls([_ret({"reputation": "clean"})]) == 1
    # error / dedup / prefetch-short-circuit returns don't count; only the real one does
    msgs = [
        _ret(
            {"error": True, "type": "X", "message": "boom"},
            {"duplicate_call": True},
            {"prefetch_already_has_this": True},
            {"ports": [80, 443]},
        )
    ]
    assert count_successful_tool_calls(msgs) == 1


def test_count_successful_tool_calls_ignores_text_thinking_retry_parts() -> None:
    """Regression: real ModelResponse parts other than tool returns must NOT
    count as tool evidence. TextPart/ThinkingPart/RetryPromptPart all carry
    .content and lack .args — the old duck-type check miscounted them, silently
    defeating the hard evidence gate for zero-tool verdicts."""
    from pydantic_ai.messages import (
        ModelResponse,
        RetryPromptPart,
        TextPart,
        ThinkingPart,
        ToolReturnPart,
    )
    from soc_ai.agent.orchestrator import count_successful_tool_calls

    # A response that only reasoned + emitted text (zero real tool calls).
    text_only = ModelResponse(
        parts=[
            ThinkingPart(content="the alert looks benign because..."),
            TextPart(content="Verdict: false_positive"),
        ]
    )
    assert count_successful_tool_calls([text_only]) == 0

    # A failed tool-arg validation retry is NOT evidence (both content shapes).
    retry_str = ModelResponse(parts=[RetryPromptPart(content="bad tool args")])
    retry_list = ModelResponse(
        parts=[
            RetryPromptPart(content=[{"type": "missing", "loc": ("ip",), "msg": "field required"}])
        ]
    )
    assert count_successful_tool_calls([retry_str]) == 0
    assert count_successful_tool_calls([retry_list]) == 0

    # A real tool return mixed with text counts exactly once.
    mixed = ModelResponse(
        parts=[
            TextPart(content="let me check the IP"),
            ToolReturnPart(
                tool_name="t_enrich_ip",
                content={"reputation": "malicious"},
                tool_call_id="1",
            ),
        ]
    )
    assert count_successful_tool_calls([mixed]) == 1


def test_targeted_result_has_data() -> None:
    """The Phase-D evidence check requires DISCRIMINATING data — an empty-but-
    non-error result (zero OQL hits, internal IP with no hits) is not evidence."""
    from soc_ai.agent.orchestrator import _targeted_result_has_data

    # No data → does not exempt the gate.
    assert _targeted_result_has_data({"total": 0, "hits": []}) is False
    assert _targeted_result_has_data({"internal": True, "blocklist_hits": [], "asn": None}) is False
    assert _targeted_result_has_data({"error": "boom"}) is False
    assert _targeted_result_has_data("targeted dispatch error: x") is False
    assert _targeted_result_has_data({}) is False
    # Real data → counts as evidence.
    assert _targeted_result_has_data({"total": 3, "hits": [{"_id": "a"}]}) is True
    assert _targeted_result_has_data({"blocklist_hits": [{"src": "feodo"}]}) is True
    assert _targeted_result_has_data({"asn": {"number": 15169}}) is True
    assert _targeted_result_has_data({"is_novel": True, "rarity": "rare"}) is True


def test_evidence_gate_downgrades_zero_tool_true_positive() -> None:
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="true_positive",
        confidence=0.9,
        summary="C2 confirmed (from prefetch alone).",
        citations=["alert.rule_name"],
        recommended_actions=[
            RecommendedAction(tool_name="escalate_to_case", tool_args={}, rationale="x")
        ],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        None,
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"
    assert out.confidence <= 0.4
    assert out.recommended_actions == []
    assert audit["evidence_gate_downgrade"]["original_verdict"] == "true_positive"


def test_evidence_gate_downgrades_zero_tool_false_positive() -> None:
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="false_positive", confidence=0.7, summary="benign per prefetch", citations=[]
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        None,
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"


def test_evidence_gate_keeps_verdict_with_successful_tool_call() -> None:
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="true_positive",
        confidence=0.8,
        summary="C2 confirmed by zeek conn bytes",
        citations=["t_query_zeek_logs"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        None,
        audit,
        targeted_messages=[_ret({"conn": {"orig_bytes": 999}})],
        targeted_tool_called=None,
    )
    assert out.verdict == "true_positive"
    assert "evidence_gate_downgrade" not in audit


def test_evidence_gate_keeps_verdict_with_phase_d_dispatch() -> None:
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="false_positive",
        confidence=0.7,
        summary="clean per enrich",
        citations=["t_enrich_ip"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        None,
        audit,
        targeted_messages=None,
        targeted_tool_called="t_enrich_ip",
    )
    assert out.verdict == "false_positive"


def test_evidence_gate_downgrades_loop_that_made_zero_successful_tool_calls() -> None:
    """QVOD shape: the loop ran but every tool errored → still ungrounded → NMI."""
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="TP from prefetch",
        citations=["alert.payload_printable"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        None,
        audit,
        targeted_messages=[_ret({"error": True, "message": "tool failed"})],
        targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"


def test_evidence_gate_exempts_strong_benign_template() -> None:
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="false_positive", confidence=0.85, summary="clean internal traffic", citations=[]
    )
    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=[],
        template_id="clean_internal_traffic",
        rationale="both endpoints internal, no IOC",
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        candidate,
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )
    assert out.verdict == "false_positive"
    assert "evidence_gate_downgrade" not in audit


def test_evidence_gate_does_not_exempt_weak_template() -> None:
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(verdict="false_positive", confidence=0.7, summary="x", citations=[])
    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.6,
        cited_evidence=[],
        template_id="informational_external_unknown_asn",
        rationale="y",
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        candidate,
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"


def test_evidence_gate_leaves_needs_more_info_untouched() -> None:
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(verdict="needs_more_info", confidence=0.3, summary="x", citations=[])
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        None,
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"
    assert "evidence_gate_downgrade" not in audit


def test_evidence_gate_exempts_deterministic_icmp_downgrade() -> None:
    """An FP produced by the solicited-ICMP-echo validator is prefetch-GROUNDED
    (typed Zeek), so the gate must not re-downgrade it to needs_more_info."""
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="false_positive",
        confidence=0.8,
        summary="solicited internal ICMP echo",
        citations=[],
    )
    audit: dict[str, Any] = {"icmp_solicited_downgrade": {"original_verdict": "true_positive"}}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        None,
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )
    assert out.verdict == "false_positive"
    assert "evidence_gate_downgrade" not in audit


def test_evidence_gate_exempts_blocklist_ioc_hit() -> None:
    """A verdict grounded in a concrete blocklist/MISP IOC is real evidence — exempt."""
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="C2 to a known-bad IP",
        citations=["alert.rule_name"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(blocklist_hit=True),
        None,
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )
    assert out.verdict == "true_positive"
    assert "evidence_gate_downgrade" not in audit


def test_count_successful_tool_calls_excludes_none_content() -> None:
    from soc_ai.agent.orchestrator import count_successful_tool_calls

    assert count_successful_tool_calls([_ret(None)]) == 0
    assert count_successful_tool_calls([_ret(None, {"data": 1})]) == 1


def test_evidence_gate_strong_template_must_agree_with_verdict() -> None:
    """A synth TP that OVERRODE a strong benign (FP) template is NOT grounded by
    it → still gated."""
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="escalated despite a clean-internal template",
        citations=[],
    )
    candidate = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=[],
        template_id="clean_internal_traffic",
        rationale="x",
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report,
        _make_vpn_icmp_enriched(),
        candidate,
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"


def test_is_strong_grounded_template_logic() -> None:
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import _is_strong_grounded_template

    strong = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=[],
        template_id="clean_internal_traffic",
        rationale="x",
    )
    # non-malware focus alert + strong benign template → exempt
    assert _is_strong_grounded_template(strong, _make_vpn_icmp_enriched()) is True
    # a malware/attack-class rule is never fast-settled benign
    assert _is_strong_grounded_template(strong, _malware_signal_enriched()) is False
    # None / sub-0.8 confidence → not strong
    assert _is_strong_grounded_template(None, _make_vpn_icmp_enriched()) is False
    weak = CandidateVerdict(
        verdict="false_positive",
        confidence=0.7,
        cited_evidence=[],
        template_id="clean_internal_traffic",
        rationale="x",
    )
    assert _is_strong_grounded_template(weak, _make_vpn_icmp_enriched()) is False
    # external-reputation template is excluded even at high confidence
    ext = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=[],
        template_id="informational_external_unknown_asn",
        rationale="x",
    )
    assert _is_strong_grounded_template(ext, _make_vpn_icmp_enriched()) is False
