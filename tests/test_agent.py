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
    build_synthesizer,
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
from soc_ai.tools._registry import ApprovalGate
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
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.7,
            summary="x",
            citations=["alert.severity_label"],
            field_reconciliation="ICMP refers to the UDP flow",
        ),
        ctx=ctx,
    )

    events = [
        ev
        async for ev in investigate(
            "alert-001",
            ctx=ctx,
            investigator=investigator,
            synthesizer=synthesizer,
        )
    ]
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["field_reconciliation"] == "ICMP refers to the UDP flow"


# =====================================================================
# Orchestrator with TestModel
# =====================================================================


def _stub_alert_context(alert_id: str = "alert-001") -> AlertContext:
    """Minimal AlertContext for orchestrator tests — no ES round-trip needed."""
    return AlertContext(
        alert=SoAlert(id=alert_id, severity_label="low"),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


async def _stub_get_alert_context(alert_id: str, **_kw: Any) -> AlertContext:
    """Drop-in replacement for the orchestrator's prefetch — returns a fixed shape."""
    return _stub_alert_context(alert_id)


@pytest.fixture(autouse=True)
def _patch_orchestrator_prefetch():
    """Autopatch get_alert_context so investigate() never reaches ES.

    Tests that need a custom AlertContext or want to assert the prefetch
    failure path can override the patch in their own with-block.
    """
    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_stub_get_alert_context,
    ):
        yield


@pytest.fixture(autouse=True)
def _reset_enrichment_cache():
    """Tests must not leak fast-path cache hits between
    them. Reset the process-wide enrichment cache before each test."""
    from soc_ai.agent.enrichment_cache import reset_global_cache

    reset_global_cache()
    yield
    reset_global_cache()


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
        gate=ApprovalGate(),
        **kwargs,
    )


def _stub_transcript(open_qs: list[str] | None = None) -> InvestigationTranscript:
    return InvestigationTranscript(
        evidence=["alert.severity_label=high (id=alert-001)"],
        tentative_summary="Internal traffic to internal target.",
        open_questions=open_qs or [],
    )


def _build_test_pair(
    *,
    transcript: InvestigationTranscript,
    report: TriageReport,
    ctx: InvestigationContext,
) -> tuple[Any, Any]:
    """Build (investigator, synthesizer) wired to TestModels with fixed outputs."""
    inv_model = TestModel(call_tools=[], custom_output_args=transcript)
    synth_model = TestModel(call_tools=[], custom_output_args=report)
    return build_investigator(inv_model, ctx), build_synthesizer(synth_model)


@pytest.mark.asyncio
async def test_investigate_yields_session_done_with_test_models(
    settings_kratos: Settings,
) -> None:
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.85,
            summary="Internal traffic to internal target.",
            citations=["alert.severity_label"],
            recommended_actions=[],
        ),
        ctx=ctx,
    )

    events = [
        ev
        async for ev in investigate(
            "alert-001",
            ctx=ctx,
            investigator=investigator,
            synthesizer=synthesizer,
        )
    ]

    kinds = [e.kind for e in events]
    assert "session_start" in kinds
    assert "investigation_transcript" in kinds
    assert "triage_report" in kinds
    assert "done" in kinds
    # Sequence numbers increase
    sequences = [e.sequence for e in events]
    assert sequences == sorted(sequences)
    # Confidence above floor → no retask.
    assert "retask" not in kinds


@pytest.mark.asyncio
async def test_investigate_retasks_when_synthesis_below_floor(
    settings_kratos: Settings,
) -> None:
    """Low-confidence synthesis triggers exactly one investigator retask.

    The retask path builds a fresh round-2 investigator via
    `build_synthesizer_model` (heavy model, ~120K ctx — see
    ``soc_ai/agent/orchestrator.py``). Patch that factory so the test
    runs without LiteLLM.
    """
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(open_qs=["unenriched destination IP"]),
        report=TriageReport(
            verdict="needs_more_info",
            confidence=0.3,  # below default floor of 0.6
            summary="Not enough evidence yet.",
            citations=[],
        ),
        ctx=ctx,
    )
    retask_round_2_transcript = InvestigationTranscript(
        evidence=["enriched destination IP not on any TI list (id event-002)"],
        tentative_summary="Round 2 closed the open question; no malicious indicators.",
        open_questions=[],
    )
    retask_model = TestModel(call_tools=[], custom_output_args=retask_round_2_transcript)

    with patch(
        "soc_ai.agent.orchestrator.build_synthesizer_model",
        return_value=retask_model,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    kinds = [e.kind for e in events]
    assert kinds.count("retask") == 1
    # Two investigation transcripts (round 1 + round 2) and two triage reports
    # would be the *internal* count, but only ONE final triage_report is
    # emitted (the retask synthesis replaces the round-1 report).
    assert kinds.count("investigation_transcript") == 2
    assert kinds.count("triage_report") == 1
    # The retask payload should carry the floor + the original confidence.
    retask_ev = next(e for e in events if e.kind == "retask")
    assert retask_ev.payload["reason"] == "synthesis_below_floor"
    assert retask_ev.payload["confidence"] == 0.3
    assert retask_ev.payload["floor"] == ctx.settings.synthesis_confidence_floor
    # The done event reports rounds=2 so the SSE consumer can render it.
    done_ev = next(e for e in events if e.kind == "done")
    assert done_ev.payload["rounds"] == 2


def test_format_retask_prompt_names_missing_field_and_tool() -> None:
    """F4: the retask user message names each missing rubric
    field AND a specific tool call to satisfy it, with the alert's
    actual identifiers pre-filled where possible."""
    from soc_ai.agent.orchestrator import _format_retask_prompt
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(
        alert=SoAlert(
            id="a1",
            host_name="endpoint-42",
            destination_ip="8.8.8.8",
            network_community_id="1:abc==",
        )
    )
    prior = InvestigationTranscript(
        evidence=["something (id evt-1)"],
        tentative_summary="x",
        open_questions=["unenriched destination IP"],
    )
    prompt = _format_retask_prompt(
        "a1",
        prior,
        missing_rubric=["enrichment_called", "related_alerts_checked"],
        alert_ctx=alert_ctx,
        reason="rubric_gap",
    )
    # Mentions each missing field
    assert "enrichment_called=False" in prompt
    assert "related_alerts_checked=False" in prompt
    # Specific tool calls with alert's actual identifiers
    assert "t_enrich_ip" in prompt
    assert "8.8.8.8" in prompt
    assert "host.name" in prompt
    assert "endpoint-42" in prompt
    # Reason is named in the header
    assert "rubric_gap" in prompt


def test_format_retask_prompt_handles_empty_missing_rubric() -> None:
    """F4: when missing_rubric is empty (legacy synthesis_below_floor
    path), the prompt still works — just doesn't include the targeted
    section."""
    from soc_ai.agent.orchestrator import _format_retask_prompt

    prior = InvestigationTranscript(
        evidence=["x"],
        tentative_summary="y",
        open_questions=["q"],
    )
    prompt = _format_retask_prompt("a1", prior, missing_rubric=[], alert_ctx=None)
    assert "missing rubric coverage" not in prompt
    # Still names the alert + the open question
    assert "a1" in prompt
    assert "q" in prompt


@pytest.mark.asyncio
async def test_retask_fires_on_rubric_gap_even_above_floor(
    settings_kratos: Settings,
) -> None:
    """F4: rubric-gap retask trigger fires when ≥2 required rubric
    fields are missing, even if confidence is above the floor."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    # Confidence ABOVE the standard floor (0.6) — should NOT have triggered
    # the legacy retask. But with 2 missing required fields, F4 fires
    # the retask anyway.
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.85,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    # External-IOC alert WITH dns/sni signal — needs both enrichment_called
    # AND dns_or_sni_pivoted. The stub investigator never called any tools,
    # so both will be missing.
    async def _ext_ioc_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return AlertContext(
            alert=SoAlert(
                id="alert-001",
                source_ip="10.0.0.1",
                destination_ip="8.8.8.8",
                payload_printable=".....example.com.....",
                severity_label="medium",  # so citation validates
            ),
            community_id_events=[],
            host_events=[],
            user_events=[],
            process_events=[],
            file_events=[],
            pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        )

    retask_round_2_transcript = InvestigationTranscript(
        evidence=["round-2 enriched (id evt-2)"],
        tentative_summary="closed gaps",
        open_questions=[],
    )
    retask_model = TestModel(call_tools=[], custom_output_args=retask_round_2_transcript)

    with (
        patch(
            "soc_ai.agent.orchestrator.get_alert_context",
            side_effect=_ext_ioc_prefetch,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=retask_model,
        ),
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    retask_ev = next(e for e in events if e.kind == "retask")
    assert retask_ev.payload["reason"] == "rubric_gap"
    assert "enrichment_called" in retask_ev.payload["missing_rubric"]
    assert "dns_or_sni_pivoted" in retask_ev.payload["missing_rubric"]


@pytest.mark.asyncio
async def test_investigate_emits_approval_required_per_action(
    settings_kratos: Settings,
) -> None:
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="true_positive",
            confidence=0.92,
            summary="Confirmed C2 beaconing.",
            citations=["alert.severity_label", "alert.id"],
            recommended_actions=[
                RecommendedAction(
                    tool_name="escalate_to_case",
                    tool_args={
                        "alert_id": "alert-001",
                        "case_title": "C2 beaconing",
                        "case_description": "Outbound beacon to known-bad host.",
                    },
                    rationale="Multiple alerts; community_id pivot confirms persistence.",
                ),
                RecommendedAction(
                    tool_name="ack_alert",
                    tool_args={"alert_id": "alert-001", "comment": "Escalated to case"},
                    rationale="Closing the alert now that a case is open.",
                ),
            ],
        ),
        ctx=ctx,
    )

    events = [
        ev
        async for ev in investigate(
            "alert-001",
            ctx=ctx,
            investigator=investigator,
            synthesizer=synthesizer,
        )
    ]
    approval_events = [e for e in events if e.kind == "approval_required"]
    assert len(approval_events) == 2
    tools = {e.payload["tool_name"] for e in approval_events}
    assert tools == {"escalate_to_case", "ack_alert"}
    for ev in approval_events:
        token = ev.payload["token"]
        req = await ctx.gate.get(token)
        assert req is not None
        assert req.tool_name == ev.payload["tool_name"]


@pytest.mark.asyncio
async def test_investigate_session_id_consistent(settings_kratos: Settings) -> None:
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="needs_more_info",
            confidence=0.7,  # above floor → no retask, simpler trace
            summary="Insufficient evidence.",
            citations=[],
        ),
        ctx=ctx,
    )

    events = [
        ev
        async for ev in investigate(
            "alert-001",
            ctx=ctx,
            investigator=investigator,
            synthesizer=synthesizer,
            session_id="custom-sid",
        )
    ]
    assert all(e.session_id == "custom-sid" for e in events)


@pytest.mark.asyncio
async def test_investigate_error_event_on_investigator_failure(
    settings_kratos: Settings,
) -> None:
    """Investigator failure in round 1 surfaces as an error event but the
    orchestrator continues with a synthetic transcript so the synthesizer
    still produces a triage_report. Smoke testing against Nemotron-30B
    showed structured-output retries are stochastic and we don't want
    those failures to leave the eval batch with null verdicts."""
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="needs_more_info",
            confidence=0.7,
            summary="x",
            citations=[],
        ),
        ctx=ctx,
    )
    investigator.run = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]

    events = [
        ev
        async for ev in investigate(
            "alert-001",
            ctx=ctx,
            investigator=investigator,
            synthesizer=synthesizer,
        )
    ]
    error_evs = [e for e in events if e.kind == "error"]
    assert len(error_evs) == 1
    assert error_evs[0].payload["type"] == "RuntimeError"
    assert error_evs[0].payload["phase"] == "investigator"
    assert error_evs[0].payload["round"] == 1
    assert "boom" in error_evs[0].payload["message"]
    # Synthetic-transcript fallback: synth still runs, triage_report still emits.
    assert any(e.kind == "triage_report" for e in events)
    # The synthetic transcript event names the failure mode in tentative_summary.
    transcript_evs = [e for e in events if e.kind == "investigation_transcript"]
    assert len(transcript_evs) == 1
    assert "did not produce" in transcript_evs[0].payload["tentative_summary"]


# =====================================================================
# Pre-fetch + typed errors + retask routing (robustness pass)
# =====================================================================


@pytest.mark.asyncio
async def test_investigate_emits_alert_context_event_before_investigator(
    settings_kratos: Settings,
) -> None:
    """The pre-fetched alert context is yielded as an SSE event between
    `session_start` and the first investigator activity, so the side panel
    can render it immediately."""
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.9,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    events = [
        ev
        async for ev in investigate(
            "alert-001",
            ctx=ctx,
            investigator=investigator,
            synthesizer=synthesizer,
        )
    ]

    kinds = [e.kind for e in events]
    # Order: session_start → alert_context → investigator activity → ... → done.
    assert kinds[0] == "session_start"
    assert kinds[1] == "alert_context"
    # The alert_context payload mirrors the AlertContext model_dump.
    ac_ev = events[1]
    assert ac_ev.payload["alert"]["id"] == "alert-001"
    assert ac_ev.payload["alert"]["severity_label"] == "low"
    assert "pivot_summary" in ac_ev.payload


@pytest.mark.asyncio
async def test_investigate_passes_alert_context_to_investigator_user_message(
    settings_kratos: Settings,
) -> None:
    """The investigator agent is invoked with a user message that contains the
    pre-fetched alert context as JSON, so the fast model can never miss it."""
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.9,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )
    captured: dict[str, str] = {}
    real_run = investigator.run

    async def _spy(prompt: str, **kw: Any) -> Any:
        captured["prompt"] = prompt
        return await real_run(prompt, **kw)

    investigator.run = _spy  # type: ignore[method-assign]

    [
        ev
        async for ev in investigate(
            "alert-001",
            ctx=ctx,
            investigator=investigator,
            synthesizer=synthesizer,
        )
    ]

    prompt = captured["prompt"]
    assert "Triage alert alert-001" in prompt
    assert "Pre-fetched alert context" in prompt
    # The actual JSON dump of the AlertContext lands in the prompt.
    assert '"id": "alert-001"' in prompt
    # And the rubric instructs the model NOT to call get_alert_context again.
    assert "Do NOT call `t_get_alert_context`" in prompt


@pytest.mark.asyncio
async def test_investigate_aborts_when_prefetch_fails(
    settings_kratos: Settings,
) -> None:
    """If alert-context prefetch fails (alert not found, ES down), the stream
    ends with a typed error event whose `phase=='prefetch'` and a non-empty
    hint."""
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.9,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    from soc_ai.errors import SoNotFoundError

    async def _fail(_alert_id: str, **_kw: Any) -> AlertContext:
        raise SoNotFoundError("alert not found: alert-001")

    # Override the autouse patch for this test only.
    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fail,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    kinds = [e.kind for e in events]
    # Synthetic-failure-report contract (added after eval batches surfaced
    # frequent prefetch ConnectionTimeouts): the orchestrator now ALWAYS
    # emits a TriageReport so the supervisor never goes silent on terminal
    # upstream failure. Stub the verdict at `needs_more_info`, summary names
    # the failure mode, then a `done` event with `synthetic=True`.
    assert kinds == ["session_start", "error", "triage_report", "done"]

    err = events[1].payload
    assert err["phase"] == "prefetch"
    assert err["round"] == 0
    assert err["type"] == "SoNotFoundError"
    assert "alert not found" in err["message"]
    assert err.get("hint")

    report = events[2].payload
    assert report["verdict"] == "needs_more_info"
    assert report["confidence"] == 0.0
    assert "SoNotFoundError" in report["summary"]
    assert report["recommended_actions"] == []
    assert report["citations"] == []

    done = events[3].payload
    assert done["synthetic"] is True
    assert done["reason"] == "prefetch_failed"
    assert done["recommended_count"] == 0
    assert done["rounds"] == 0


@pytest.mark.asyncio
async def test_retask_uses_synthesizer_model_for_round_2_investigator(
    settings_kratos: Settings,
) -> None:
    """When retask fires, the round-2 investigator is built off
    `build_synthesizer_model` (structured-output config) — not
    `build_investigator_model`. Both use the single analyst model."""
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(open_qs=["unenriched IP"]),
        report=TriageReport(
            verdict="needs_more_info",
            confidence=0.3,  # forces retask
            summary="x",
            citations=[],
        ),
        ctx=ctx,
    )
    retask_round_2_transcript = InvestigationTranscript(
        evidence=["enriched IP clean (id=event-x)"],
        tentative_summary="Round 2 closed the gap.",
        open_questions=[],
    )
    retask_model = TestModel(call_tools=[], custom_output_args=retask_round_2_transcript)

    with (
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=retask_model,
        ) as synth_model_spy,
        patch(
            "soc_ai.agent.orchestrator.build_investigator_model",
        ) as inv_model_spy,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    # build_investigator_model is for round-1 only; the orchestrator gets the
    # round-1 investigator pre-built from the test, so the factory should
    # never be called.
    assert inv_model_spy.call_count == 0
    # build_synthesizer_model is called exactly once: for the retask
    # round-2 investigator. (The synthesizer was pre-built as a TestModel.)
    assert synth_model_spy.call_count == 1

    kinds = [e.kind for e in events]
    assert kinds.count("retask") == 1
    assert kinds.count("investigation_transcript") == 2
    done_ev = next(e for e in events if e.kind == "done")
    assert done_ev.payload["rounds"] == 2


@pytest.mark.asyncio
async def test_error_event_carries_phase_round_type_and_hint(
    settings_kratos: Settings,
) -> None:
    """Errors flow through `_error_payload` and gain a hint when the exception
    type is recognized (OqlValidationError → field-name guidance)."""
    from soc_ai.errors import OqlValidationError

    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.9,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )
    investigator.run = AsyncMock(  # type: ignore[method-assign]
        side_effect=OqlValidationError("unknown or forbidden field: 'dest.ip'", fragment="dest.ip")
    )

    events = [
        ev
        async for ev in investigate(
            "alert-001",
            ctx=ctx,
            investigator=investigator,
            synthesizer=synthesizer,
        )
    ]
    err = next(e for e in events if e.kind == "error").payload
    assert err["phase"] == "investigator"
    assert err["round"] == 1
    assert err["type"] == "OqlValidationError"
    assert "dest.ip" in err["message"]
    # Hint mentions the offending fragment AND the canonical replacement.
    assert "dest.ip" in err["hint"]
    assert "destination.ip" in err["hint"]


# =====================================================================
# Rule-class fast-path
# =====================================================================


def _stub_informational_alert_context(alert_id: str = "alert-001") -> AlertContext:
    """AlertContext for a fast-path-eligible alert (Informational + low)."""
    from soc_ai.so_client.models import RuleMetadata

    return AlertContext(
        alert=SoAlert(
            id=alert_id,
            severity_label="low",
            rule_metadata=RuleMetadata(signature_severity="Informational"),
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


@pytest.mark.asyncio
async def test_fast_path_classification_event_emitted(
    settings_kratos: Settings,
) -> None:
    """The classification event surfaces the alert class and fast-path
    routing decision so the SSE consumer + audit log can render them."""
    settings_kratos.fast_path_sampling_rate = 0.0  # deterministic
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.8,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    cls_ev = next(e for e in events if e.kind == "classification")
    assert cls_ev.payload["alert_class"] == "informational_visibility"
    assert cls_ev.payload["fast_path_eligible"] is True
    assert cls_ev.payload["fast_path_taken"] is True
    assert cls_ev.payload["sampled_to_full"] is False


@pytest.mark.asyncio
async def test_fast_path_uses_lower_retask_floor(
    settings_kratos: Settings,
) -> None:
    """Fast-path alerts with confidence ≥ fast_path_synthesis_floor (0.4)
    skip the retask, even though the standard floor (0.6) would have
    triggered one. This is the whole point of the fast-path."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.5,  # below 0.6 (would retask) but above 0.4 (no retask on fast-path)
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    kinds = [e.kind for e in events]
    assert "retask" not in kinds  # fast-path floor=0.4 means 0.5 passes


@pytest.mark.asyncio
async def test_fast_path_disabled_via_setting_uses_full_pipeline(
    settings_kratos: Settings,
) -> None:
    """When `enable_rule_class_fast_path=False`, the orchestrator never
    fast-paths even for an INFORMATIONAL_VISIBILITY + low alert."""
    settings_kratos.enable_rule_class_fast_path = False
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.5,  # below standard 0.6 → retask
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    retask_round_2_transcript = InvestigationTranscript(
        evidence=["round-2 evidence (id=evt-2)"],
        tentative_summary="closed gaps",
        open_questions=[],
    )
    retask_model = TestModel(call_tools=[], custom_output_args=retask_round_2_transcript)

    with (
        patch(
            "soc_ai.agent.orchestrator.get_alert_context",
            side_effect=_fast_path_prefetch,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=retask_model,
        ),
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    kinds = [e.kind for e in events]
    cls_ev = next(e for e in events if e.kind == "classification")
    # Classifier still runs (always emits the event), but fast-path is gated.
    assert cls_ev.payload["alert_class"] == "informational_visibility"
    assert cls_ev.payload["fast_path_eligible"] is False
    assert cls_ev.payload["fast_path_taken"] is False
    # Standard floor (0.6) catches the 0.5 confidence and retasks.
    assert "retask" in kinds


@pytest.mark.asyncio
async def test_fast_path_sampling_routes_to_full_pipeline(
    settings_kratos: Settings,
) -> None:
    """When the sampling RNG selects this alert for drift monitoring,
    `fast_path_taken` is False and the standard floor applies."""
    settings_kratos.fast_path_sampling_rate = 1.0  # always sample
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.5,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    retask_round_2_transcript = InvestigationTranscript(
        evidence=["round-2 evidence (id=evt-2)"],
        tentative_summary="closed gaps",
        open_questions=[],
    )
    retask_model = TestModel(call_tools=[], custom_output_args=retask_round_2_transcript)

    with (
        patch(
            "soc_ai.agent.orchestrator.get_alert_context",
            side_effect=_fast_path_prefetch,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=retask_model,
        ),
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    cls_ev = next(e for e in events if e.kind == "classification")
    assert cls_ev.payload["fast_path_eligible"] is True
    assert cls_ev.payload["sampled_to_full"] is True
    assert cls_ev.payload["fast_path_taken"] is False
    # Standard floor (0.6) wins on the sampled-to-full path.
    assert "retask" in [e.kind for e in events]


@pytest.mark.asyncio
async def test_non_informational_alert_not_fast_pathed(
    settings_kratos: Settings,
) -> None:
    """Recon / exploit / post-compromise classes always run the full
    pipeline regardless of severity."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.8,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    async def _recon_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return AlertContext(
            alert=SoAlert(id="alert-001", severity_label="low", classtype="attempted-recon"),
            community_id_events=[],
            host_events=[],
            user_events=[],
            process_events=[],
            file_events=[],
            pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        )

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_recon_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    cls_ev = next(e for e in events if e.kind == "classification")
    assert cls_ev.payload["alert_class"] == "recon"
    assert cls_ev.payload["fast_path_eligible"] is False
    assert cls_ev.payload["fast_path_taken"] is False


# =====================================================================
# F1: Real fast-path short-circuit
# =====================================================================


def test_enrichment_cache_lru_behavior() -> None:
    """EnrichmentCache is a small LRU.
    Capacity overflow evicts the oldest entry."""
    from soc_ai.agent.enrichment_cache import EnrichmentCache

    cache = EnrichmentCache(capacity=3)
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)
    assert cache.contains("a")
    assert cache.contains("b")
    assert cache.contains("c")
    # Overflow → "a" evicted (oldest).
    cache.put("d", 4)
    assert not cache.contains("a")
    assert cache.contains("b")
    assert cache.contains("c")
    assert cache.contains("d")
    # `get` refreshes recency, so re-inserting another should evict "c"
    # next (not "b" which we just touched).
    assert cache.get("b") == 2
    cache.put("e", 5)
    assert cache.contains("b")
    assert cache.contains("d")
    assert cache.contains("e")
    assert not cache.contains("c")


def test_is_fast_path_eligible_external_ip_requires_cache_hit() -> None:
    """External-destination alerts require a prior
    enrichment cache hit to fast-path; internal-only alerts skip the
    cache check entirely."""
    from soc_ai.agent.classifier import AlertClass, is_fast_path_eligible
    from soc_ai.agent.enrichment_cache import EnrichmentCache
    from soc_ai.so_client.models import RuleMetadata, SoAlert

    cache = EnrichmentCache()
    ext = SoAlert(
        id="a1",
        severity_label="low",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        destination_ip="8.8.8.8",
    )
    # First-encounter external → NOT eligible.
    assert (
        is_fast_path_eligible(ext, AlertClass.INFORMATIONAL_VISIBILITY, enrichment_cache=cache)
        is False
    )
    # After cache hit → eligible.
    cache.put("8.8.8.8", {})
    assert (
        is_fast_path_eligible(ext, AlertClass.INFORMATIONAL_VISIBILITY, enrichment_cache=cache)
        is True
    )
    # Internal-only alert: cache check skipped entirely.
    internal = SoAlert(
        id="a2",
        severity_label="low",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        destination_ip="10.0.0.2",
    )
    assert (
        is_fast_path_eligible(internal, AlertClass.INFORMATIONAL_VISIBILITY, enrichment_cache=cache)
        is True
    )


def test_is_fast_path_eligible_without_cache_keeps_pre_29_behavior() -> None:
    """When enrichment_cache is None (test/legacy callers), the gate
    is skipped — the earlier cache-free behavior is preserved."""
    from soc_ai.agent.classifier import AlertClass, is_fast_path_eligible
    from soc_ai.so_client.models import RuleMetadata, SoAlert

    ext = SoAlert(
        id="a",
        severity_label="low",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        destination_ip="8.8.8.8",
    )
    # No cache passed → eligible regardless of cache state.
    assert is_fast_path_eligible(ext, AlertClass.INFORMATIONAL_VISIBILITY) is True


def test_has_closeable_rubric_gap_finds_unused_tool() -> None:
    """A missing rubric field with an unused mapped tool
    is closeable. Drives the retask trigger."""
    from soc_ai.agent.orchestrator import _has_closeable_rubric_gap

    # enrichment_called missing; no t_enrich_* call in messages → closeable.
    msgs = [_msg(("t_query_zeek_logs", {"community_id": "x"}))]
    assert _has_closeable_rubric_gap(["enrichment_called"], msgs) is True


def test_has_closeable_rubric_gap_skips_when_all_tools_used() -> None:
    """If all mapped tools for every missing field were called,
    retasking won't help — closeable is False."""
    from soc_ai.agent.orchestrator import _has_closeable_rubric_gap

    msgs = [
        _msg(
            ("t_enrich_ip", {"ip": "8.8.8.8"}),
            ("t_enrich_domain", {"domain": "x.com"}),
            ("t_enrich_hash", {"hash_value": "deadbeef", "algo": "sha256"}),
        )
    ]
    # All enrichment tools already called → enrichment_called is not closeable.
    assert _has_closeable_rubric_gap(["enrichment_called"], msgs) is False


def test_has_closeable_rubric_gap_skips_unmapped_fields() -> None:
    """payload_inspected_if_banner_rule has no tool — not closeable."""
    from soc_ai.agent.orchestrator import _has_closeable_rubric_gap

    assert _has_closeable_rubric_gap(["payload_inspected_if_banner_rule"], []) is False


def test_fast_path_external_indicator_picks_external_dest() -> None:
    """Helper returns the highest-priority external IOC."""
    from soc_ai.agent.orchestrator import _fast_path_external_indicator
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    ctx = AlertContext(alert=SoAlert(id="a", source_ip="10.0.0.1", destination_ip="8.8.8.8"))
    assert _fast_path_external_indicator(ctx) == "8.8.8.8"


def test_fast_path_external_indicator_returns_none_for_internal_only() -> None:
    """Pure-internal alerts skip enrichment."""
    from soc_ai.agent.orchestrator import _fast_path_external_indicator
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    ctx = AlertContext(alert=SoAlert(id="a", source_ip="10.0.0.1", destination_ip="10.0.0.2"))
    assert _fast_path_external_indicator(ctx) is None


def test_enrichment_has_threat_signal_misp_hit() -> None:
    """A MISP IOC match flags the enrichment as a threat signal,
    triggering escalation to the full pipeline."""
    from soc_ai.agent.orchestrator import _enrichment_has_threat_signal
    from soc_ai.tools.enrichment import EnrichmentResult, Finding

    result_threat = EnrichmentResult(
        indicator="8.8.8.8",
        indicator_type="ip",
        findings=[
            Finding(
                source="misp",
                category="ioc_match",
                description="MISP malware: known C2",
            )
        ],
    )
    assert _enrichment_has_threat_signal(result_threat) is True

    # Empty findings → not a threat signal.
    result_clean = EnrichmentResult(indicator="8.8.8.8", indicator_type="ip", findings=[])
    assert _enrichment_has_threat_signal(result_clean) is False


@pytest.mark.asyncio
async def test_fast_path_runs_mandatory_enrichment_on_external_ip(
    settings_kratos: Settings,
) -> None:
    """Fast-path with external IP emits a synthetic t_enrich_ip
    tool_call/tool_result pair and adds the result to materialized
    evidence. Pre-populates the enrichment cache to satisfy fast-path
    eligibility for the external destination."""
    from unittest.mock import AsyncMock

    from soc_ai.agent.enrichment_cache import get_global_cache
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.enrichment import EnrichmentResult, Finding
    from soc_ai.tools.get_alert_context import AlertContext

    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    # Pre-populate cache so the external dest IP is eligible for fast-path.
    get_global_cache().put("8.8.8.8", {"prior": "enrichment"})
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.7,
            summary="x",
            citations=["alert.rule_metadata.signature_severity"],
        ),
        ctx=ctx,
    )

    async def _ctx_with_ext_ip(_alert_id: str, **_kw: Any) -> AlertContext:
        return AlertContext(
            alert=SoAlert(
                id="alert-001",
                severity_label="low",
                rule_metadata=RuleMetadata(signature_severity="Informational"),
                source_ip="10.0.0.1",
                destination_ip="8.8.8.8",
            ),
            community_id_events=[],
            host_events=[],
            user_events=[],
            process_events=[],
            file_events=[],
            pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        )

    clean_result = EnrichmentResult(
        indicator="8.8.8.8",
        indicator_type="ip",
        findings=[
            Finding(
                source="internal_cidr",
                category="external_network",
                description="external IP, not in internal_cidrs",
            )
        ],
    )

    with (
        patch(
            "soc_ai.agent.orchestrator.get_alert_context",
            side_effect=_ctx_with_ext_ip,
        ),
        patch(
            "soc_ai.agent.orchestrator.enrich_ip",
            new=AsyncMock(return_value=clean_result),
        ),
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    # Synthetic tool_call event with fast_path phase
    tool_calls = [
        e for e in events if e.kind == "tool_call" and e.payload.get("phase") == "fast_path"
    ]
    assert len(tool_calls) == 1
    assert tool_calls[0].payload["tool_name"] == "t_enrich_ip"
    assert tool_calls[0].payload["args"] == {"ip": "8.8.8.8"}
    # Materialized evidence carries the enrichment summary
    transcript_ev = next(e for e in events if e.kind == "investigation_transcript")
    assert any("t_enrich_ip(8.8.8.8)" in item for item in transcript_ev.payload["evidence"])


@pytest.mark.asyncio
async def test_fast_path_escalates_on_misp_hit(
    settings_kratos: Settings,
) -> None:
    """A MISP IOC match on fast-path enrichment escalates to the
    FULL investigator pipeline. Emits fast_path_escalation SSE event."""
    from unittest.mock import AsyncMock

    from soc_ai.agent.enrichment_cache import get_global_cache
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.enrichment import EnrichmentResult, Finding
    from soc_ai.tools.get_alert_context import AlertContext

    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    # Pre-populate cache so the external dest IP is eligible for fast-path.
    get_global_cache().put("1.2.3.4", {"prior": "enrichment"})
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="needs_more_info",
            confidence=0.7,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    async def _ctx_with_ext_ip(_alert_id: str, **_kw: Any) -> AlertContext:
        return AlertContext(
            alert=SoAlert(
                id="alert-001",
                severity_label="low",
                rule_metadata=RuleMetadata(signature_severity="Informational"),
                destination_ip="1.2.3.4",
            ),
            community_id_events=[],
            host_events=[],
            user_events=[],
            process_events=[],
            file_events=[],
            pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        )

    threat_result = EnrichmentResult(
        indicator="1.2.3.4",
        indicator_type="ip",
        findings=[
            Finding(
                source="misp",
                category="ioc_match",
                description="MISP malware: C2 infrastructure",
            )
        ],
    )

    with (
        patch(
            "soc_ai.agent.orchestrator.get_alert_context",
            side_effect=_ctx_with_ext_ip,
        ),
        patch(
            "soc_ai.agent.orchestrator.enrich_ip",
            new=AsyncMock(return_value=threat_result),
        ),
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    # Escalation event fires
    esc_ev = next(e for e in events if e.kind == "fast_path_escalation")
    assert "threat-signal" in esc_ev.payload["reason"]
    # Standard pipeline runs — the test-model investigator emits a transcript
    transcript_evs = [e for e in events if e.kind == "investigation_transcript"]
    assert len(transcript_evs) == 1
    # Fast-path skipped flag should NOT be set on escalated transcript
    assert not transcript_evs[0].payload.get("fast_path_skipped")


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
async def test_fast_path_emits_materialized_evidence(
    settings_kratos: Settings,
) -> None:
    """Fast-path transcript includes orchestrator-materialized
    evidence drawn from prefetch (rule_metadata, classtype, etc.), not
    the empty list from F1's original design. Evidence list size is
    surfaced in the investigation_transcript event."""
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.65,
            summary="x",
            citations=["alert.rule_metadata.signature_severity"],
        ),
        ctx=ctx,
    )

    async def _ctx_with_pivot(_alert_id: str, **_kw: Any) -> AlertContext:
        return AlertContext(
            alert=SoAlert(
                id="alert-001",
                severity_label="low",
                rule_metadata=RuleMetadata(signature_severity="Informational"),
                alert_action="allowed",
                classtype="misc-activity",
            ),
            community_id_events=[SoAlert(id="pivot-evt-1", event_dataset="zeek.conn")],
            host_events=[],
            user_events=[],
            process_events=[],
            file_events=[],
            pivot_summary={"community_id": 1, "host": 0, "user": 0, "process": 0, "file": 0},
        )

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_ctx_with_pivot,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    transcript_ev = next(e for e in events if e.kind == "investigation_transcript")
    assert transcript_ev.payload.get("fast_path_skipped") is True
    assert transcript_ev.payload.get("evidence_materialized", 0) > 0
    # The transcript's evidence list itself is non-empty now.
    assert transcript_ev.payload["evidence"]
    # And one of the items cites the community_id pivot.
    assert any("pivot-evt-1" in item for item in transcript_ev.payload["evidence"])


@pytest.mark.asyncio
async def test_fast_path_evidence_guard_downgrades_when_synth_emits_no_citations(
    settings_kratos: Settings,
) -> None:
    """If the fast-path synth ignores the materialized
    evidence and emits a non-NMI verdict with NO citations, the
    orchestrator force-downgrades to needs_more_info. Closes the
    'rubber-stamp without positive signal' failure mode."""
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",  # synth ignores prefetch...
            confidence=0.7,
            summary="x",
            citations=[],  # ...and emits no citations
        ),
        ctx=ctx,
    )

    async def _ctx_with_pivot(_alert_id: str, **_kw: Any) -> AlertContext:
        return AlertContext(
            alert=SoAlert(
                id="alert-001",
                severity_label="low",
                rule_metadata=RuleMetadata(signature_severity="Informational"),
            ),
            community_id_events=[SoAlert(id="pivot-evt-1", event_dataset="zeek.conn")],
            host_events=[],
            user_events=[],
            process_events=[],
            file_events=[],
            pivot_summary={"community_id": 1, "host": 0, "user": 0, "process": 0, "file": 0},
        )

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_ctx_with_pivot,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    guard_ev = next(e for e in events if e.kind == "fast_path_evidence_guard")
    assert guard_ev.payload["original_verdict"] == "false_positive"
    assert guard_ev.payload["capped_verdict"] == "needs_more_info"
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "needs_more_info"


@pytest.mark.asyncio
async def test_fast_path_skips_investigator_entirely(
    settings_kratos: Settings,
) -> None:
    """F1: when fast_path_taken=True, the investigator is not called.
    The synthetic transcript has fast_path_skipped=True flag and no tool
    calls flow into the event stream."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.65,
            summary="ET INFO routine traffic.",
            citations=["alert.rule_metadata.signature_severity"],
        ),
        ctx=ctx,
    )
    # Spy on investigator.run — it must NOT be called on fast-path.
    investigator.run = AsyncMock(side_effect=AssertionError("investigator should be skipped"))  # type: ignore[method-assign]

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    investigator.run.assert_not_called()
    transcript_ev = next(e for e in events if e.kind == "investigation_transcript")
    assert transcript_ev.payload.get("fast_path_skipped") is True
    # No investigator-phase tool_call / model_response events.
    inv_phase_evs = [e for e in events if e.payload.get("phase") == "investigator"]
    assert inv_phase_evs == []
    # The triage_report still emerges.
    assert any(e.kind == "triage_report" for e in events)


@pytest.mark.asyncio
async def test_fast_path_verdict_ceiling_downgrades_true_positive(
    settings_kratos: Settings,
) -> None:
    """F1: fast-path NEVER emits true_positive. If the synth disagrees
    with the classifier and emits true_positive, the orchestrator
    downgrades to needs_more_info and emits a fast_path_verdict_cap event."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="true_positive",  # synth disagrees with classifier
            confidence=0.9,
            summary="actually malicious",
            citations=["alert.rule_metadata.signature_severity"],
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    cap_ev = next(e for e in events if e.kind == "fast_path_verdict_cap")
    assert cap_ev.payload["original_verdict"] == "true_positive"
    assert cap_ev.payload["capped_verdict"] == "needs_more_info"
    # Final report shows the capped verdict.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "needs_more_info"


@pytest.mark.asyncio
async def test_fast_path_skips_coverage_cap(
    settings_kratos: Settings,
) -> None:
    """F1: coverage_cap is bound to investigator-derived rubric.
    On fast-path the investigator is skipped; coverage_cap MUST NOT fire."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.8,
            summary="x",
            citations=["alert.rule_metadata.signature_severity"],
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    kinds = [e.kind for e in events]
    assert "coverage_cap" not in kinds
    # And no retask either (F1 unconditional skip).
    assert "retask" not in kinds


@pytest.mark.asyncio
async def test_verdict_floor_rewrite_below_floor(
    settings_kratos: Settings,
) -> None:
    """B3: when final confidence is
    STRICTLY below the synthesis floor, the verdict isn't already
    needs_more_info AND the report carries no semantic evidence (zero
    citations here), the orchestrator mechanically rewrites verdict to
    needs_more_info and clears recommended_actions."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",  # Synth says FP...
            confidence=0.45,  # ...but confidence below 0.6 floor
            summary="thin evidence",
            citations=[],  # ...and no evidence at all
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

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
    """B3: the LEGACY floor rewrite must be evidence-
    conditional like `_synth_first_post_validate` — a verdict whose
    citations semantically resolve SURVIVES low confidence. Citation-shape
    noise must not erase a well-evidenced verdict on the fallback path."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.55,  # below the 0.6 floor...
            summary="well-evidenced but hedged",
            # ...but the citation resolves against the prefetched bundle.
            citations=["alert.rule_metadata.signature_severity"],
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    assert not any(e.kind == "verdict_floor_rewrite" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"


@pytest.mark.asyncio
async def test_verdict_floor_rewrite_skips_when_verdict_already_nmi(
    settings_kratos: Settings,
) -> None:
    """Don't double-rewrite when verdict is already
    needs_more_info — the rewrite would be a no-op anyway, but emitting
    the SSE event would be noisy."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="needs_more_info",
            confidence=0.3,
            summary="x",
            citations=["alert.rule_metadata.signature_severity"],
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    assert not any(e.kind == "verdict_floor_rewrite" for e in events)


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


async def _run_legacy_icmp_investigation(
    ctx: InvestigationContext,
    *,
    report: TriageReport | None = None,
    icmp_echo: bool = True,
) -> list[Any]:
    """Drive investigate() end-to-end against the BPFDoor ping prefetch."""
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=report or _bpfdoor_tp_report(),
        ctx=ctx,
    )

    async def _icmp_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_icmp_ping_alert_context(icmp_echo=icmp_echo)

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_icmp_prefetch,
    ):
        return [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]


@pytest.mark.asyncio
async def test_legacy_pipeline_downgrades_solicited_icmp_echo_tp(
    settings_kratos: Settings,
) -> None:
    """B2: the LEGACY pipeline — still the fallback when
    synth-first errors or the flag is off — must apply the same solicited-
    ICMP-echo true_positive downgrade as `_synth_first_post_validate`.
    Before B2 the downgrade lived only inside the synth-first validator, so
    the legacy path reproduced the original BPFDoor false escalation.

    Legacy contexts carry no enrichments, so the downgrade requires an
    EXPLICIT blocklist lookup against the same singleton BlocklistDB the
    enrich_* tools use (ctx.blocklist) — and the audit reason must say
    that's what was verified (no enrichment/MISP claims on this path)."""
    ctx = _make_ctx(settings_kratos, blocklist=_loaded_blocklist())
    events = await _run_legacy_icmp_investigation(ctx)

    # Same audit entry the synth-first pipeline emits for this validator.
    dg_ev = next(e for e in events if e.kind == "icmp_solicited_downgrade")
    assert dg_ev.payload["original_verdict"] == "true_positive"
    assert dg_ev.payload["downgraded_verdict"] == "false_positive"
    assert "solicited" in dg_ev.payload["reason"]
    # The reason states what actually ran: an explicit blocklist lookup —
    # not the enrichment-derived "no blocklist/MISP hit" wording (no MISP
    # check runs on this path, so the reason must not claim one).
    assert "explicit blocklist lookup" in dg_ev.payload["reason"]
    assert "MISP hit" not in dg_ev.payload["reason"]
    # Final report downgraded identically to the synth-first behavior.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert report_ev.payload["recommended_actions"] == []
    # Summary must lead with the correct conclusion — no confusing inline bracket.
    assert not report_ev.payload["summary"].lower().startswith("[auto-corrected")
    assert "solicited" in report_ev.payload["summary"].lower()
    # Original synth narrative preserved in validator_note, not in summary.
    assert "symmetric byte counts" not in report_ev.payload["summary"]
    assert "symmetric byte counts" in (report_ev.payload.get("validator_note") or "")


@pytest.mark.asyncio
async def test_legacy_icmp_downgrade_refused_when_endpoint_blocklisted(
    settings_kratos: Settings,
) -> None:
    """Safety parity with synth-first: a blocklist hit on either endpoint
    (e.g. operator-curated internal_seed.yaml flagging a known-bad internal
    host) must veto the legacy downgrade — the TP survives. Before this fix
    the legacy IOC loop was vacuous (no enrichments on AlertContext), so the
    blocklist was never consulted and the TP was wrongly suppressed."""
    ctx = _make_ctx(
        settings_kratos,
        blocklist=_loaded_blocklist(hit_ips=("10.20.30.15",)),
    )
    events = await _run_legacy_icmp_investigation(ctx)

    assert not any(e.kind == "icmp_solicited_downgrade" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "true_positive"


@pytest.mark.asyncio
async def test_legacy_icmp_downgrade_refused_when_blocklist_unavailable(
    settings_kratos: Settings,
) -> None:
    """Absence of proof is not proof: when the blocklist source is
    unavailable (default-empty BlocklistDB — zero loaded sources, as legacy
    callers get when no data dir is provisioned) the legacy path must NOT
    downgrade. Wrongly suppressing a real TP is worse than letting a false
    escalation through."""
    ctx = _make_ctx(settings_kratos)  # default BlocklistDB(): nothing loaded
    events = await _run_legacy_icmp_investigation(ctx)

    assert not any(e.kind == "icmp_solicited_downgrade" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "true_positive"


@pytest.mark.asyncio
async def test_legacy_pipeline_keeps_internal_tp_without_icmp_echo(
    settings_kratos: Settings,
) -> None:
    """B2 scope guard: internal→internal WITHOUT a solicited ICMP echo
    (e.g. SMB lateral movement) must NOT be downgraded on the legacy
    path — protects h2-PsExec / h1-Kerberoasting class TPs. Uses a loaded,
    clean blocklist so the test exercises the ICMP-echo scope gate, not
    the blocklist-unavailable gate."""
    ctx = _make_ctx(settings_kratos, blocklist=_loaded_blocklist())
    events = await _run_legacy_icmp_investigation(
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
    assert report_ev.payload["verdict"] == "true_positive"


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


@pytest.mark.asyncio
async def test_recommended_actions_blocked_when_no_evidence_at_floor(
    settings_kratos: Settings,
) -> None:
    """Block recommended_actions when the
    fast-path produces evidence=[] AND confidence ≤ floor. The previous
    behavior auto-acked alerts at 0.6 confidence with zero supporting
    evidence — rubber-stamping under uncertainty."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.6,  # AT the floor
            summary="x",
            citations=["alert.rule_metadata.signature_severity"],
            recommended_actions=[
                RecommendedAction(
                    tool_name="ack_alert",
                    tool_args={"alert_id": "alert-001", "comment": "ET INFO"},
                    rationale="rubber-stamp test",
                ),
            ],
        ),
        ctx=ctx,
    )

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    block_ev = next(e for e in events if e.kind == "recommended_actions_blocked")
    assert block_ev.payload["reason"] == "no_evidence_at_or_below_floor"
    assert block_ev.payload["blocked_count"] == 1
    # Final triage_report has no recommended_actions, no approval events fire.
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["recommended_actions"] == []
    assert not any(e.kind == "approval_required" for e in events)


@pytest.mark.asyncio
async def test_fast_path_synth_user_message_contains_alert_class(
    settings_kratos: Settings,
) -> None:
    """F1: the fast-path synth user message names the alert class so the
    synth can constrain its verdict appropriately."""
    settings_kratos.fast_path_sampling_rate = 0.0
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.65,
            summary="x",
            citations=["alert.rule_metadata.signature_severity"],
        ),
        ctx=ctx,
    )
    captured: dict[str, str] = {}
    real_run = synthesizer.run

    async def _spy(prompt: str, **kw: Any) -> Any:
        captured["prompt"] = prompt
        return await real_run(prompt, **kw)

    synthesizer.run = _spy  # type: ignore[method-assign]

    async def _fast_path_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        return _stub_informational_alert_context()

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_fast_path_prefetch,
    ):
        [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    prompt = captured["prompt"]
    assert "FAST PATH" in prompt
    assert "informational_visibility" in prompt
    assert "MUST be `false_positive` or `needs_more_info`" in prompt
    # The pre-fetched alert context goes into the prompt.
    assert "alert-001" in prompt


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
    assert agent._max_result_retries >= 3


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


def test_synthesizer_model_unrestricted(
    settings_kratos: Settings,
) -> None:
    """The synth's reasoning is genuinely load-bearing for verdict
    synthesis — keep it unrestricted (no max_tokens cap)."""
    from soc_ai.agent.orchestrator import build_synthesizer_model

    synth = build_synthesizer_model(settings_kratos)
    if synth.settings is not None:
        assert "max_tokens" not in synth.settings


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


def test_required_rubric_fields_for_external_ioc_alert() -> None:
    """F3: alerts with external IPs require enrichment.
    `dns_or_sni_pivoted` only required when the alert ACTUALLY has a
    DNS/SNI signal to pivot on (decoupled from the generic IOC check).
    Pure-internal alerts have no enrichment requirement."""
    from soc_ai.agent.orchestrator import _required_rubric_fields
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    # External-IP alert WITHOUT DNS/SNI signal — only enrichment required.
    ext = SoAlert(id="a1", source_ip="10.0.0.1", destination_ip="8.8.8.8")
    required = _required_rubric_fields(AlertContext(alert=ext))
    assert "enrichment_called" in required
    assert "dns_or_sni_pivoted" not in required  # no DNS/SNI signal to pivot on

    # External-IP alert WITH payload_printable (a DNS/SNI signal proxy).
    ext_dns = SoAlert(
        id="a1b",
        source_ip="10.0.0.1",
        destination_ip="8.8.8.8",
        payload_printable=".....example.com.....",
    )
    required_dns = _required_rubric_fields(AlertContext(alert=ext_dns))
    assert "enrichment_called" in required_dns
    assert "dns_or_sni_pivoted" in required_dns

    # Pure-internal alert.
    internal = SoAlert(id="a2", source_ip="10.0.0.1", destination_ip="10.0.0.2")
    required_int = _required_rubric_fields(AlertContext(alert=internal))
    assert "enrichment_called" not in required_int


# =====================================================================
# F3: orchestrator-derived rubric_coverage
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


def test_derive_rubric_coverage_marks_enrichment_called() -> None:
    """F3: a `t_enrich_*` tool call sets enrichment_called=True."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(alert=SoAlert(id="a", payload_printable="example.com"))
    messages = [_msg(("t_enrich_domain", {"domain": "example.com"}))]
    rubric = _derive_rubric_coverage(messages, alert_ctx)
    assert rubric.enrichment_called is True


def test_derive_rubric_coverage_marks_dns_pivot_from_log_types() -> None:
    """F3: t_query_zeek_logs with log_types=['dns'] sets dns_or_sni_pivoted."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(alert=SoAlert(id="a", payload_printable="x.com"))
    messages = [_msg(("t_query_zeek_logs", {"community_id": "1:abc", "log_types": ["dns"]}))]
    rubric = _derive_rubric_coverage(messages, alert_ctx)
    assert rubric.dns_or_sni_pivoted is True


def test_derive_rubric_coverage_related_alerts_requires_host_pivot() -> None:
    """F3 / F8: related_alerts_checked requires query filter on
    host/user/process. A bare community_id query is the SAME alert —
    not a related-alerts check.

    Calibration dropped the previous co-requirement
    that the query also include `event.kind` — the model often pivots
    on host.name combined with a different kind filter (zeek.dns.query,
    network.community_id of related conns, etc) and the strict rule
    rejected those valid pivots."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(alert=SoAlert(id="a"))

    # Bare community_id query — does NOT count.
    bare_q = 'network.community_id:"1:abc" AND event.kind:alert'
    rubric_bad = _derive_rubric_coverage(
        [_msg(("t_query_events_oql", {"query": bare_q}))],
        alert_ctx,
    )
    assert rubric_bad.related_alerts_checked is False

    # host.name pivot WITH event.kind:alert — counts.
    rubric_good = _derive_rubric_coverage(
        [_msg(("t_query_events_oql", {"query": 'host.name:"foo" AND event.kind:alert'}))],
        alert_ctx,
    )
    assert rubric_good.related_alerts_checked is True

    # host.name pivot WITHOUT event.kind — also counts (relaxed rule).
    rubric_zeek_pivot = _derive_rubric_coverage(
        [_msg(("t_query_events_oql", {"query": 'host.name:"foo" AND zeek.dns.query:*'}))],
        alert_ctx,
    )
    assert rubric_zeek_pivot.related_alerts_checked is True

    # process.entity_id pivot — counts.
    rubric_proc = _derive_rubric_coverage(
        [_msg(("t_query_events_oql", {"query": 'process.entity_id:"abc"'}))],
        alert_ctx,
    )
    assert rubric_proc.related_alerts_checked is True


def test_derive_rubric_coverage_playbook_consulted() -> None:
    """F3: t_get_playbooks or t_lookup_runbook sets playbook_consulted."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(alert=SoAlert(id="a"))
    rubric = _derive_rubric_coverage(
        [_msg(("t_get_playbooks", {"alert_id": "a"}))],
        alert_ctx,
    )
    assert rubric.playbook_consulted is True


def test_derive_rubric_coverage_dns_or_sni_auto_satisfied_when_no_signal() -> None:
    """F3: dns_or_sni_pivoted is auto-True when alert has no DNS/SNI
    signal at all — there's nothing to pivot on."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(alert=SoAlert(id="a"))  # no payload, no dns_query
    rubric = _derive_rubric_coverage([], alert_ctx)
    assert rubric.dns_or_sni_pivoted is True


def test_derive_rubric_coverage_or_merges_seed() -> None:
    """F3: cumulative across retask rounds. Round-2 derivation OR-merges
    INTO the round-1 rubric so a field satisfied in round 1 isn't
    re-failed by round 2."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.agent.triage import RubricCoverage
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(alert=SoAlert(id="a", payload_printable="x.com"))
    seed = RubricCoverage(enrichment_called=True, related_alerts_checked=True)
    # Round 2 doesn't fire any new tools; round-1 fields preserved.
    rubric = _derive_rubric_coverage([], alert_ctx, seed=seed)
    assert rubric.enrichment_called is True
    assert rubric.related_alerts_checked is True


def test_derive_rubric_coverage_handles_string_args() -> None:
    """F3: ToolCallPart.args is sometimes a JSON-string instead of dict
    (depending on PydanticAI version). Auto-parse and continue."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(alert=SoAlert(id="a"))
    messages = [_msg(("t_enrich_ip", '{"ip": "8.8.8.8"}'))]
    rubric = _derive_rubric_coverage(messages, alert_ctx)
    assert rubric.enrichment_called is True


class _FakeToolReturnPart:
    """Stand-in for pydantic_ai.messages.ToolReturnPart for unit tests."""

    def __init__(self, tool_name: str, content: Any):
        self.tool_name = tool_name
        self.content = content
        # count_successful_tool_calls now discriminates on part_kind, so the
        # stub must carry the real ToolReturnPart discriminator.
        self.part_kind = "tool-return"


def test_derive_rubric_coverage_payload_inspected_from_alert_payload() -> None:
    """B5: `payload_inspected_if_banner_rule` is derived MECHANICALLY —
    a banner-class alert whose payload_printable is non-empty was
    embedded in the prompt the model received, so the field is True
    with zero tool calls and regardless of any self-report."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(alert=SoAlert(id="a", payload_printable="GET /generate_204 HTTP/1.1"))
    rubric = _derive_rubric_coverage([], alert_ctx)
    assert rubric.payload_inspected_if_banner_rule is True


def test_derive_rubric_coverage_payload_inspected_from_tool_return() -> None:
    """B5: when the alert itself has no payload but a tool return in the
    message history carried a record with non-empty payload_printable,
    the model received payload evidence → field derived True."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    # Banner-class via Informational severity; alert payload empty.
    alert_ctx = AlertContext(
        alert=SoAlert(
            id="a",
            rule_metadata=RuleMetadata(signature_severity="Informational"),
        )
    )
    messages = [
        _FakeMessage(
            [
                _FakeToolReturnPart(
                    "t_query_events_oql",
                    {
                        "hits": [
                            {"id": "ev-1", "payload_printable": "POST /beacon HTTP/1.1"},
                        ],
                    },
                ),
            ]
        )
    ]
    rubric = _derive_rubric_coverage(messages, alert_ctx)
    assert rubric.payload_inspected_if_banner_rule is True


def test_derive_rubric_coverage_payload_not_inspected_without_payload_data() -> None:
    """B5: banner-class alert with NO payload data anywhere (not on the
    alert, not in pivots, not in tool returns) derives False — the v5
    meta-analysis showed model self-reports of payload inspection are
    fabricated, so nothing the model claims can flip this field."""
    from soc_ai.agent.orchestrator import _derive_rubric_coverage
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    alert_ctx = AlertContext(
        alert=SoAlert(
            id="a",
            rule_metadata=RuleMetadata(signature_severity="Informational"),
        )
    )
    # Tool calls fired, but none of the returned content carries payload.
    messages = [
        _msg(("t_enrich_ip", {"ip": "8.8.8.8"})),
        _FakeMessage([_FakeToolReturnPart("t_enrich_ip", {"internal": False, "asn": 15169})]),
    ]
    rubric = _derive_rubric_coverage(messages, alert_ctx)
    assert rubric.payload_inspected_if_banner_rule is False


def test_content_has_payload_printable_depth_guard() -> None:
    """Depth guard: deeply nested structure must not recurse past depth 10."""
    from soc_ai.agent.orchestrator import _content_has_payload_printable

    # Build a 20-deep nested dict with payload_printable at the bottom.
    nested: dict = {"payload_printable": "found"}
    for _ in range(20):
        nested = {"child": nested}
    # Should return False — depth guard fires before reaching the value.
    assert _content_has_payload_printable(nested) is False

    # Shallow nesting (depth ≤ 10) should still find it.
    shallow: dict = {"payload_printable": "found"}
    for _ in range(3):
        shallow = {"child": shallow}
    assert _content_has_payload_printable(shallow) is True


@pytest.mark.asyncio
async def test_legacy_pipeline_ignores_self_reported_payload_inspection(
    settings_kratos: Settings,
) -> None:
    """B5: the orchestrator must NOT OR-merge the investigator's
    self-reported `payload_inspected_if_banner_rule` into the derived
    rubric. A banner-class alert with no payload data anywhere + a
    fabricated self-report=True must still trip the coverage cap."""
    from soc_ai.agent.triage import RubricCoverage
    from soc_ai.so_client.models import RuleMetadata

    ctx = _make_ctx(settings_kratos)
    transcript = InvestigationTranscript(
        evidence=["alert.rule_metadata.signature_severity=Informational (id=alert-001)"],
        tentative_summary="Looked at everything, honest.",
        open_questions=[],
        # Fabricated self-report — the v5 meta-analysis failure mode.
        rubric_coverage=RubricCoverage(payload_inspected_if_banner_rule=True),
    )
    investigator, synthesizer = _build_test_pair(
        transcript=transcript,
        report=TriageReport(
            verdict="false_positive",
            confidence=0.9,
            summary="x",
            citations=["alert.rule_metadata.signature_severity"],
        ),
        ctx=ctx,
    )

    async def _banner_prefetch(_alert_id: str, **_kw: Any) -> AlertContext:
        # Informational rule (banner-class) but severity HIGH → standard
        # pipeline, not fast-path. No payload_printable anywhere.
        return AlertContext(
            alert=SoAlert(
                id="alert-001",
                severity_label="high",
                rule_metadata=RuleMetadata(signature_severity="Informational"),
            ),
            community_id_events=[],
            host_events=[],
            user_events=[],
            process_events=[],
            file_events=[],
            pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        )

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_banner_prefetch,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

    # The derivation event surfaces the disagreement: model claimed True,
    # orchestrator derived False.
    deriv_ev = next(e for e in events if e.kind == "rubric_derivation")
    assert deriv_ev.payload["model_reported"]["payload_inspected_if_banner_rule"] is True
    assert deriv_ev.payload["orchestrator_derived"]["payload_inspected_if_banner_rule"] is False
    # And the coverage cap fires on the missing required field.
    cap_ev = next(e for e in events if e.kind == "coverage_cap")
    assert "payload_inspected_if_banner_rule" in cap_ev.payload["missing_fields"]
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["confidence"] == pytest.approx(0.6)


def test_required_rubric_fields_for_banner_class_rule() -> None:
    """Banner-class rules (Informational severity OR non-empty
    payload_printable) require payload inspection."""
    from soc_ai.agent.orchestrator import _required_rubric_fields
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.get_alert_context import AlertContext

    # Informational-severity → banner-class.
    a = SoAlert(
        id="x",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
    )
    required = _required_rubric_fields(AlertContext(alert=a))
    assert "payload_inspected_if_banner_rule" in required

    # Non-banner alert (no Informational, no payload).
    b = SoAlert(
        id="y",
        rule_metadata=RuleMetadata(signature_severity="Major"),
    )
    required_b = _required_rubric_fields(AlertContext(alert=b))
    assert "payload_inspected_if_banner_rule" not in required_b


def test_coverage_cap_pins_confidence_when_required_field_missing() -> None:
    """The coverage cap caps confidence at 0.6 when required fields
    are False. Already-below-cap values are unchanged."""
    from soc_ai.agent.orchestrator import _coverage_cap
    from soc_ai.agent.triage import RubricCoverage

    rubric = RubricCoverage(
        related_alerts_checked=True,
        playbook_consulted=True,
        enrichment_called=False,  # missing
        dns_or_sni_pivoted=False,  # missing
        payload_inspected_if_banner_rule=True,
    )
    required = {"enrichment_called", "dns_or_sni_pivoted"}

    # High-confidence with missing fields → capped to 0.6.
    capped, missing = _coverage_cap(0.9, rubric, required)
    assert capped == 0.6
    assert set(missing) == {"enrichment_called", "dns_or_sni_pivoted"}

    # Low-confidence already below cap → unchanged.
    capped_low, _ = _coverage_cap(0.3, rubric, required)
    assert capped_low == 0.3


def test_coverage_cap_no_change_when_all_required_met() -> None:
    """When the rubric has every required field True, confidence is
    untouched."""
    from soc_ai.agent.orchestrator import _coverage_cap
    from soc_ai.agent.triage import RubricCoverage

    rubric = RubricCoverage(
        related_alerts_checked=True,
        playbook_consulted=True,
        enrichment_called=True,
        dns_or_sni_pivoted=True,
        payload_inspected_if_banner_rule=True,
    )
    required = {"enrichment_called", "dns_or_sni_pivoted"}
    capped, missing = _coverage_cap(0.9, rubric, required)
    assert capped == 0.9
    assert missing == []


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
    ctx = _make_ctx(settings_kratos)
    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.9,
            summary="x",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    async def _connection_refused(_alert_id: str, **_kw: Any) -> AlertContext:
        raise ConnectionError(
            "Cannot connect to host 10.0.0.253:9200 ssl:default [Connect call failed]"
        )

    with patch(
        "soc_ai.agent.orchestrator.get_alert_context",
        side_effect=_connection_refused,
    ):
        events = [
            ev
            async for ev in investigate(
                "alert-001",
                ctx=ctx,
                investigator=investigator,
                synthesizer=synthesizer,
            )
        ]

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
    settings_kratos.synth_first_pipeline = True
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
    settings_kratos.synth_first_pipeline = True
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

    settings_kratos.synth_first_pipeline = True
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

    settings_kratos.synth_first_pipeline = True
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
    settings_kratos.synth_first_pipeline = True
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


@pytest.mark.asyncio
async def test_synth_first_pipeline_flag_off_runs_legacy_path(
    settings_kratos: Settings,
) -> None:
    """When settings.synth_first_pipeline=False (default), legacy path runs.

    Confirms that synth-first-only event kinds are absent and the standard
    investigation_transcript/triage_report sequence appears.
    """
    # Default is False; be explicit for clarity.
    settings_kratos.synth_first_pipeline = False
    ctx = _make_ctx(settings_kratos)

    investigator, synthesizer = _build_test_pair(
        transcript=_stub_transcript(),
        report=TriageReport(
            verdict="false_positive",
            confidence=0.85,
            summary="Legacy path ran.",
            citations=["alert.severity_label"],
        ),
        ctx=ctx,
    )

    events = [
        ev
        async for ev in investigate(
            "alert-001",
            ctx=ctx,
            investigator=investigator,
            synthesizer=synthesizer,
        )
    ]

    kinds = [e.kind for e in events]
    # Legacy events present
    assert "investigation_transcript" in kinds
    assert "triage_report" in kinds
    assert "done" in kinds
    # Synth-first-only events absent
    assert "enriched_alert_context" not in kinds
    assert "decision_template_match" not in kinds
    assert "targeted_dispatch" not in kinds
    assert "targeted_tool_result" not in kinds


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

    settings_kratos.synth_first_pipeline = True
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

    settings_kratos.synth_first_pipeline = True
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

    settings_kratos.synth_first_pipeline = True
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

    settings_kratos.synth_first_pipeline = True
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

    settings_kratos.synth_first_pipeline = True
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
    assert agent._max_result_retries >= 3


# =====================================================================
# D1: domain/hash enrichment tool wrappers populate the global cache
# =====================================================================


@pytest.mark.asyncio
async def test_t_enrich_domain_populates_global_cache(
    settings_kratos: Settings,
) -> None:
    """D1: t_enrich_domain must write to the
    global enrichment cache on success, mirroring t_enrich_ip's
    cache-write so the fast-path first-encounter gate works for domain
    indicators too."""
    from unittest.mock import AsyncMock, patch

    from soc_ai.agent.enrichment_cache import get_global_cache
    from soc_ai.tools.enrichment import EnrichmentResult, Finding

    ctx = _make_ctx(settings_kratos)
    agent = build_investigator(TestModel(call_tools=[]), ctx)

    mock_result = EnrichmentResult(
        indicator="evil.example.com",
        indicator_type="domain",
        findings=[Finding(source="misp", category="malware", description="known C2 domain")],
    )

    with patch(
        "soc_ai.agent.orchestrator.enrich_domain",
        new=AsyncMock(return_value=mock_result),
    ):
        tool = agent._function_toolset.tools["t_enrich_domain"]
        await tool.function(domain="evil.example.com")

    assert get_global_cache().contains("evil.example.com"), (
        "t_enrich_domain should write the enrichment result to the global cache"
    )


@pytest.mark.asyncio
async def test_t_enrich_hash_populates_global_cache(
    settings_kratos: Settings,
) -> None:
    """D1: t_enrich_hash must write to the
    global enrichment cache on success, mirroring t_enrich_ip's
    cache-write so the fast-path first-encounter gate works for hash
    indicators too."""
    from unittest.mock import AsyncMock, patch

    from soc_ai.agent.enrichment_cache import get_global_cache
    from soc_ai.tools.enrichment import EnrichmentResult, Finding

    ctx = _make_ctx(settings_kratos)
    agent = build_investigator(TestModel(call_tools=[]), ctx)

    mock_result = EnrichmentResult(
        indicator="deadbeef01234567",
        indicator_type="hash",
        findings=[Finding(source="misp", category="malware", description="known ransomware hash")],
    )

    with patch(
        "soc_ai.agent.orchestrator.enrich_hash",
        new=AsyncMock(return_value=mock_result),
    ):
        tool = agent._function_toolset.tools["t_enrich_hash"]
        await tool.function(hash_value="deadbeef01234567", algo="sha256")

    assert get_global_cache().contains("deadbeef01234567"), (
        "t_enrich_hash should write the enrichment result to the global cache"
    )


# =====================================================================
# D2: EnrichmentCache.contains() refreshes LRU recency
# =====================================================================


def test_enrichment_cache_contains_refreshes_lru_recency() -> None:
    """D2: contains() must bump the touched
    entry to most-recent so that probing membership keeps it alive across
    subsequent inserts."""
    from soc_ai.agent.enrichment_cache import EnrichmentCache

    cache = EnrichmentCache(capacity=3)
    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)
    # "a" is the LRU candidate; calling contains("a") must refresh its recency.
    assert cache.contains("a") is True
    # Insert a fourth entry — without the contains() recency bump, "a" would
    # be evicted (it was still the oldest); with the fix "b" is evicted instead.
    cache.put("d", 4)
    assert cache.contains("a"), "'a' was touched by contains() and must survive eviction"
    assert not cache.contains("b"), "'b' was the untouched second-oldest and should be evicted"
    assert cache.contains("c")
    assert cache.contains("d")


# =====================================================================
# D3: fast-path synthesizer runs under fast_path_usage_limits
# =====================================================================


@pytest.mark.asyncio
async def test_fast_path_synth_uses_fast_path_usage_limits(
    settings_kratos: Settings,
) -> None:
    """D3: the fast-path synthesizer run must
    use fast_path_usage_limits (the tighter budget) rather than the full
    usage_limits.  Verify by observing that the synthesizer's run() is
    called with a UsageLimits whose request_limit matches
    settings.fast_path_request_limit (not settings.agent_request_limit)."""
    from unittest.mock import AsyncMock, patch

    from pydantic_ai import UsageLimits
    from soc_ai.agent.enrichment_cache import get_global_cache
    from soc_ai.so_client.models import RuleMetadata, SoAlert
    from soc_ai.tools.enrichment import EnrichmentResult, Finding
    from soc_ai.tools.get_alert_context import AlertContext

    # Ensure the fast path is taken: disable sampling, pre-populate cache.
    settings_kratos.fast_path_sampling_rate = 0.0
    # Set distinct limits so we can distinguish them.
    settings_kratos.fast_path_request_limit = 3
    settings_kratos.agent_request_limit = 20
    ctx = _make_ctx(settings_kratos)
    get_global_cache().put("8.8.8.8", {"prior": "enrichment"})

    report = TriageReport(
        verdict="false_positive",
        confidence=0.75,
        summary="fast-path test",
        citations=["alert.severity_label"],
    )
    synth_model = TestModel(call_tools=[], custom_output_args=report)
    synthesizer = build_synthesizer(synth_model)

    # Spy on synthesizer.run to capture the usage_limits kwarg.
    captured_limits: list[UsageLimits] = []
    original_run = synthesizer.run

    async def _spy_run(*args: Any, **kwargs: Any) -> Any:
        if "usage_limits" in kwargs:
            captured_limits.append(kwargs["usage_limits"])
        return await original_run(*args, **kwargs)

    synthesizer.run = _spy_run  # type: ignore[method-assign]

    async def _ctx_with_ext_ip(_alert_id: str, **_kw: Any) -> AlertContext:
        return AlertContext(
            alert=SoAlert(
                id="fp-alert-d3",
                severity_label="low",
                rule_metadata=RuleMetadata(signature_severity="Informational"),
                source_ip="10.0.0.1",
                destination_ip="8.8.8.8",
            ),
            community_id_events=[],
            host_events=[],
            user_events=[],
            process_events=[],
            file_events=[],
            pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
        )

    clean_result = EnrichmentResult(
        indicator="8.8.8.8",
        indicator_type="ip",
        findings=[Finding(source="internal_cidr", category="external_network", description="ext")],
    )

    with (
        patch("soc_ai.agent.orchestrator.get_alert_context", side_effect=_ctx_with_ext_ip),
        patch("soc_ai.agent.orchestrator.enrich_ip", new=AsyncMock(return_value=clean_result)),
    ):
        _ = [
            ev
            async for ev in investigate(
                "fp-alert-d3",
                ctx=ctx,
                synthesizer=synthesizer,
            )
        ]

    assert len(captured_limits) >= 1, "synthesizer.run must have been called"
    fast_path_limit = captured_limits[0]
    assert fast_path_limit.request_limit == settings_kratos.fast_path_request_limit, (
        f"fast-path synth should run under fast_path_request_limit="
        f"{settings_kratos.fast_path_request_limit}, "
        f"not agent_request_limit={settings_kratos.agent_request_limit}; "
        f"got {fast_path_limit.request_limit}"
    )


# =====================================================================
# Theme-1 Task 1: bounded investigation loop
# =====================================================================


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

    settings_kratos.synth_first_pipeline = True
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

    zeek_call = _ToolCallPart(
        tool_name="t_query_zeek_logs", args={"community_id": "1:abc"}, tool_call_id="tc1"
    )
    loop_msg = SimpleNamespace(parts=[zeek_call])
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

    settings_kratos.synth_first_pipeline = True
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

    settings_kratos.synth_first_pipeline = True
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

    settings_kratos.synth_first_pipeline = True
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
        "synth_first_pipeline": False,
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
    settings_kratos.synth_first_pipeline = True
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
    settings_kratos.synth_first_pipeline = True
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
    settings_kratos.synth_first_pipeline = True
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
        report, _make_vpn_icmp_enriched(), None, audit,
        targeted_messages=None, targeted_tool_called=None,
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
        report, _make_vpn_icmp_enriched(), None, audit,
        targeted_messages=None, targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"


def test_evidence_gate_keeps_verdict_with_successful_tool_call() -> None:
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="true_positive", confidence=0.8, summary="C2 confirmed by zeek conn bytes",
        citations=["t_query_zeek_logs"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _make_vpn_icmp_enriched(), None, audit,
        targeted_messages=[_ret({"conn": {"orig_bytes": 999}})], targeted_tool_called=None,
    )
    assert out.verdict == "true_positive"
    assert "evidence_gate_downgrade" not in audit


def test_evidence_gate_keeps_verdict_with_phase_d_dispatch() -> None:
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="false_positive", confidence=0.7, summary="clean per enrich",
        citations=["t_enrich_ip"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _make_vpn_icmp_enriched(), None, audit,
        targeted_messages=None, targeted_tool_called="t_enrich_ip",
    )
    assert out.verdict == "false_positive"


def test_evidence_gate_downgrades_loop_that_made_zero_successful_tool_calls() -> None:
    """QVOD shape: the loop ran but every tool errored → still ungrounded → NMI."""
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="true_positive", confidence=0.85, summary="TP from prefetch",
        citations=["alert.payload_printable"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _make_vpn_icmp_enriched(), None, audit,
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
        verdict="false_positive", confidence=0.85, cited_evidence=[],
        template_id="clean_internal_traffic", rationale="both endpoints internal, no IOC",
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _make_vpn_icmp_enriched(), candidate, audit,
        targeted_messages=None, targeted_tool_called=None,
    )
    assert out.verdict == "false_positive"
    assert "evidence_gate_downgrade" not in audit


def test_evidence_gate_does_not_exempt_weak_template() -> None:
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(verdict="false_positive", confidence=0.7, summary="x", citations=[])
    candidate = CandidateVerdict(
        verdict="false_positive", confidence=0.6, cited_evidence=[],
        template_id="informational_external_unknown_asn", rationale="y",
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _make_vpn_icmp_enriched(), candidate, audit,
        targeted_messages=None, targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"


def test_evidence_gate_leaves_needs_more_info_untouched() -> None:
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(verdict="needs_more_info", confidence=0.3, summary="x", citations=[])
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _make_vpn_icmp_enriched(), None, audit,
        targeted_messages=None, targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"
    assert "evidence_gate_downgrade" not in audit


def test_evidence_gate_exempts_deterministic_icmp_downgrade() -> None:
    """An FP produced by the solicited-ICMP-echo validator is prefetch-GROUNDED
    (typed Zeek), so the gate must not re-downgrade it to needs_more_info."""
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="false_positive", confidence=0.8,
        summary="solicited internal ICMP echo", citations=[],
    )
    audit: dict[str, Any] = {"icmp_solicited_downgrade": {"original_verdict": "true_positive"}}
    out = _downgrade_unevidenced_verdict(
        report, _make_vpn_icmp_enriched(), None, audit,
        targeted_messages=None, targeted_tool_called=None,
    )
    assert out.verdict == "false_positive"
    assert "evidence_gate_downgrade" not in audit


def test_evidence_gate_exempts_blocklist_ioc_hit() -> None:
    """A verdict grounded in a concrete blocklist/MISP IOC is real evidence — exempt."""
    from soc_ai.agent.orchestrator import _downgrade_unevidenced_verdict

    report = TriageReport(
        verdict="true_positive", confidence=0.85, summary="C2 to a known-bad IP",
        citations=["alert.rule_name"],
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _make_vpn_icmp_enriched(blocklist_hit=True), None, audit,
        targeted_messages=None, targeted_tool_called=None,
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
        verdict="true_positive", confidence=0.85,
        summary="escalated despite a clean-internal template", citations=[],
    )
    candidate = CandidateVerdict(
        verdict="false_positive", confidence=0.85, cited_evidence=[],
        template_id="clean_internal_traffic", rationale="x",
    )
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        report, _make_vpn_icmp_enriched(), candidate, audit,
        targeted_messages=None, targeted_tool_called=None,
    )
    assert out.verdict == "needs_more_info"


def test_is_strong_grounded_template_logic() -> None:
    from soc_ai.agent.decision_templates import CandidateVerdict
    from soc_ai.agent.orchestrator import _is_strong_grounded_template

    strong = CandidateVerdict(
        verdict="false_positive", confidence=0.85, cited_evidence=[],
        template_id="clean_internal_traffic", rationale="x",
    )
    # non-malware focus alert + strong benign template → exempt
    assert _is_strong_grounded_template(strong, _make_vpn_icmp_enriched()) is True
    # a malware/attack-class rule is never fast-settled benign
    assert _is_strong_grounded_template(strong, _malware_signal_enriched()) is False
    # None / sub-0.8 confidence → not strong
    assert _is_strong_grounded_template(None, _make_vpn_icmp_enriched()) is False
    weak = CandidateVerdict(
        verdict="false_positive", confidence=0.7, cited_evidence=[],
        template_id="clean_internal_traffic", rationale="x",
    )
    assert _is_strong_grounded_template(weak, _make_vpn_icmp_enriched()) is False
    # external-reputation template is excluded even at high confidence
    ext = CandidateVerdict(
        verdict="false_positive", confidence=0.85, cited_evidence=[],
        template_id="informational_external_unknown_asn", rationale="x",
    )
    assert _is_strong_grounded_template(ext, _make_vpn_icmp_enriched()) is False
