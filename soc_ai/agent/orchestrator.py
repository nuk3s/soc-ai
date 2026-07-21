"""Investigation orchestrator: the synth-first pipeline entry point.

The API layer calls :func:`investigate` directly, passing an
:class:`~soc_ai.agent.context.InvestigationContext` assembled per request.
Agents are built lazily inside the pipeline — there is no lifecycle-managed
``build_agent`` construction at the API layer.

The pipeline (:func:`_run_synth_first_pipeline`) runs:

1. **Phase A** — :func:`get_enriched_alert_context` pivots + locally enriches
   the alert into an :class:`EnrichedAlertContext`.
2. **Phase B** — :func:`match_decision_template` produces an optional
   *candidate verdict* anchor.
3. **definitely-investigate check** — if the alert carries malware/exploit
   signal or a threat-context flag, the synth round-1 is skipped entirely
   (``synth_round1_skipped`` event emitted) and the pipeline goes straight to
   the investigation loop.
4. **Phase C round 1** — the heavy synthesizer model reads materialized
   evidence + candidate and emits a :class:`TriageReport`.  It has no tools;
   it may name one gap via ``gap_for_investigator``.
5. **Phase D** — if a gap was named and the loop was not entered,
   :mod:`soc_ai.agent.targeted_investigator` dispatches that single tool
   deterministically (no LLM), then round-2 synthesis re-reads the result.
6. **Investigation loop** — full tool-equipped agent, entered when
   ``_should_investigate`` returns true, the definitely-investigate flag was
   set, OR ``fast_triage_enabled=false`` forces it for every alert
   (``loop_reason="fast_triage_disabled"``); synthesizer runs over the
   transcript to produce the final report.
7. **Post-synth validators** — :func:`~soc_ai.agent.gates._synth_first_post_validate`
   applies citation validation, confidence caps, verdict floor rewrites, and
   targeted downgrades deterministically.
8. **Oracle escalation** — optional second-opinion raw HTTP call (opt-in;
   not a pydantic-ai agent).

Write tools surface via :attr:`TriageReport.recommended_actions` only — the
pipeline never pauses waiting for a human mid-run.  The analyst executes
recommended actions on demand through the actions API
(:mod:`soc_ai.api.webui.routes_actions`), which runs them through the single
audited :func:`~soc_ai.tools.write_exec.execute_write_tool` path.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from collections import Counter
from collections.abc import AsyncGenerator, AsyncIterator, Sequence
from datetime import datetime
from typing import Any

from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models import Model
from pydantic_ai.usage import UsageLimits

from soc_ai import metrics
from soc_ai.agent import context_budget
from soc_ai.agent._partial_replay import (
    repair_dangling_tool_calls,
    replay_reasoning_context,
)
from soc_ai.agent.classifier import AlertClass, classify_alert

# Backward-compat re-exports — _DedupTracker, InvestigationContext, StepEvent now
# live in soc_ai.agent.context; tests and callers reach these via orchestrator.
from soc_ai.agent.context import (
    InvestigationContext,
    StepEvent,
    _DedupTracker,
)
from soc_ai.agent.egress_guard import EgressGuard, EgressResidueError

# Backward-compat re-exports — evidence helpers now live in soc_ai.agent.evidence;
# tests and callers reach these via orchestrator.
from soc_ai.agent.evidence import (  # noqa: F401
    _beacon_profile_bullet,
    _bundle_dump_text,
    _classify_citation,
    _dns_tunnel_profile_bullet,
    _loop_evidence_marker,
    _materialize_prefetch_evidence,
    _num,
    _path_exists_in_alert,
    _pivot_decisive_evidence,
    _tool_was_invoked,
    count_successful_tool_calls,
)

# Backward-compat re-exports — the deterministic verdict gates (citation
# validation + the post-synthesis downgrade stack) now live in
# soc_ai.agent.gates; tests and callers reach these via orchestrator.
from soc_ai.agent.gates import (  # noqa: F401
    _CITATION_STOP_WORDS,
    _ESCALATION_CONF_FLOOR,
    _FUZZY_TOKEN_RE,
    _GROUNDED_EVIDENCE_TOKENS,
    _NON_EVIDENCE_RESULT_KEYS,
    _PIVOT_ATTRS,
    _PIVOT_DECISIVE_ATTRS,
    _apply_targeted_downgrades,
    _citation_confidence_cap,
    _downgrade_unevidenced_verdict,
    _downgrade_ungrounded_host_anchored_tp,
    _has_ioc_hit,
    _is_solicited_internal_icmp_echo,
    _is_strong_grounded_template,
    _no_semantic_evidence,
    _pivot_evidence_tokens,
    _resolve_citations,
    _synth_first_post_validate,
    _targeted_result_has_data,
    _validate_citations,
    _verdict_cites_decisive_pivot_value,
    _verdict_grounded_in_pivot,
)
from soc_ai.agent.models import (
    build_investigator_model,
    build_model,
    build_synthesizer_model,
)
from soc_ai.agent.prompts import (
    BUDGET_PARTIAL_SYNTH_PROMPT,
    INVESTIGATOR_PROMPT,
    SYNTHESIZER_PROMPT,
    _format_investigator_prompt,
    _format_transcript_for_synthesizer,
)
from soc_ai.agent.reasoning import extract_reasoning_trace

# The unified read-tool surface (single registration source for all three
# agents) lives in soc_ai.agent.toolset. The private helpers are re-imported
# here because existing tests and callers reach them via this module
# (`from soc_ai.agent.orchestrator import _clamp_tool_result`, ...).
from soc_ai.agent.toolset import (  # noqa: F401
    _TOOL_RESULT_BUDGET_BYTES,
    _clamp_tool_result,
    _dedup_result,
    _tool_error,
    register_read_tools,
)
from soc_ai.agent.triage import InvestigationTranscript, RecommendedAction, TriageReport
from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError, SoApiError

# Module import (not `from ... import adjudicate`) so tests patching
# `soc_ai.oracle.client.adjudicate` keep intercepting the escalation call.
from soc_ai.oracle import client as _oracle_client
from soc_ai.oracle.identifiers import EffectiveIdentifiers, effective_internal_identifiers
from soc_ai.so_client.inventory import inventory_prompt_block
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.enrichment import build_local_enrichment_context
from soc_ai.tools.write_exec import execute_write_tool
from soc_ai.triage_models import is_pipeline_fallback

_LOGGER = logging.getLogger(__name__)


# =====================================================================
# Agent factory
# =====================================================================


# The model + provider builders — ``build_investigator_model``,
# ``build_synthesizer_model``, ``build_model`` and their ``_build_provider`` /
# ``_nemotron_profile`` helpers — now live in :mod:`soc_ai.agent.models`. They
# are re-imported at the top of this module so every existing call site, the
# ``agent`` package re-exports, and the tests that patch
# ``soc_ai.agent.orchestrator.build_*_model`` keep working unchanged.


# `build_local_enrichment_context` now lives in `soc_ai.tools.enrichment`
# (so the MCP server can build the same local sources without importing this
# heavy module); it is re-imported above and re-exported below for the
# existing `soc_ai.agent.orchestrator.build_local_enrichment_context` callers.


def build_investigator(
    model: Model,
    ctx: InvestigationContext,
    *,
    system_prompt: str | None = None,
) -> Agent[None, InvestigationTranscript]:
    """Investigator agent: fast model + read tools + InvestigationTranscript output.

    The read-tool surface comes from
    :func:`soc_ai.agent.toolset.register_read_tools` (role ``investigator``);
    closures there capture ``ctx`` so the LLM-facing tool signatures stay
    semantic-only (no auth/elastic/etc. parameters in the schema).

    ``system_prompt`` overrides the default :data:`INVESTIGATOR_PROMPT`.

    The coverage gate previously lived here as an
    ``output_validator`` raising ``ModelRetry``. Smoke testing surfaced a
    pathological interaction: PydanticAI's ``retries`` budget is shared
    between schema-validation retries (Nemotron-30B routinely needs 2-3
    attempts to land a schema-valid InvestigationTranscript) AND
    output_validator retries. The combined retry budget exhausted before
    the model could produce a schema-valid transcript. The coverage gate
    was removed; the synthesis-floor rewrite handles missing enrichment by
    downing confidence below the floor when semantic citation coverage is
    absent. ``retries=5`` gives schema validation room.
    """
    agent: Agent[None, InvestigationTranscript] = Agent(
        model,
        output_type=InvestigationTranscript,
        system_prompt=system_prompt or INVESTIGATOR_PROMPT,
        # The default of 10 retries is generous on a per-output basis but
        # Nemotron-30B's schema-format wobble is genuinely stochastic (some
        # runs land in 2 attempts, others need 8+); stronger models may need
        # far less — tune via the investigator_retries setting. The
        # per-investigation request_limit still bounds the worst case, and a
        # failed alert burns ~10 quick retries (each emitting almost no
        # output) which is cheaper than an unrecoverable run.
        retries=ctx.settings.investigator_retries,
    )

    # Note: no `t_get_alert_context` tool is registered for the investigator
    # since the orchestrator pre-fetches the alert context and embeds it in
    # the user prompt. The fast 30B was unable to consistently honor a
    # "do not call this tool" rubric — removing the tool entirely is the
    # only reliable way to enforce the contract. If a future iteration
    # needs secondary-alert context, expose it through a renamed tool
    # (`t_get_other_alert_context(alert_id)`) so the model can't
    # accidentally re-fetch the alert under triage.

    register_read_tools(agent, ctx, role="investigator")

    return agent


def build_synthesizer(model: Model) -> Agent[None, TriageReport]:
    """Synthesizer agent: heavy model, no tools, TriageReport output.

    The synthesizer reads the investigator's transcript (passed as the user
    message) and emits a TriageReport. It has no tools — synthesis happens
    entirely from the gathered evidence.
    """
    return Agent(
        model,
        output_type=TriageReport,
        system_prompt=SYNTHESIZER_PROMPT,
    )


def build_partial_triage_synthesizer(model: Model) -> Agent[None, TriageReport]:
    """No-tools synthesizer that concludes a budget-cut investigation loop.

    Mirrors the hunt runner's partial-report path (:func:`soc_ai.api.
    hunt_runner._synthesize_partial_hunt`): replays the loop's gathered
    (repaired) message history and forces a TriageReport from ONLY that
    evidence. ``retries=3`` for reasoning-model schema-wobble parity with
    :func:`build_synth_first_agent`.
    """
    return Agent(
        model,
        output_type=TriageReport,
        system_prompt=BUDGET_PARTIAL_SYNTH_PROMPT,
        retries=3,
    )


# Error-shaped on purpose: ``count_successful_tool_calls`` must never count a
# synthetic closure as gathered evidence (the hunt path's plain-string closure
# predates that gate and stays as-is for prompt-compat).
_PARTIAL_CLOSURE_CONTENT: dict[str, Any] = {
    "error": True,
    "message": "not executed — tool-call budget exhausted",
}


async def _synthesize_partial_triage(
    settings: Settings, guard: EgressGuard | None, gathered: list[Any]
) -> tuple[Any, list[Any]]:
    """Force a TriageReport from a budget-cut investigation loop's history.

    Returns ``(report, repaired_history)``. The repaired history doubles as
    ``loop_messages`` for the downstream evidence/citation gates, so the
    partial verdict earns the loop evidence exemption ONLY from tool results
    that actually landed. Raises on any failure — the caller lands the honest
    pipeline-fallback as the last resort.
    """
    repaired = repair_dangling_tool_calls(gathered, closure_content=_PARTIAL_CLOSURE_CONTENT)
    user_msg = replay_reasoning_context(repaired) + (
        "Write the TriageReport now from the evidence already gathered above."
    )
    if guard is not None:
        # The replayed history is already label space (the loop conversed over
        # sanitized inputs); this sweep covers the lifted reasoning block.
        user_msg = guard.sanitize_text(user_msg)
    user_msg = _guard_egress(guard, user_msg, settings)
    agent = build_partial_triage_synthesizer(
        build_synthesizer_model(settings, temperature=settings.synthesizer_temperature)
    )
    async with asyncio.timeout(settings.investigation_turn_timeout_s):
        result = await agent.run(
            user_msg,
            message_history=repaired,
            usage_limits=UsageLimits(request_limit=3, tool_calls_limit=0),
        )
    return result.output, repaired


def build_synth_first_agent(model: Model) -> Agent[None, TriageReport]:
    """Build the synth Agent for the synth-first pipeline (no tools).

    Identical to build_synthesizer except it uses the synth-first system
    prompt that includes the gap_for_investigator + decision-template
    rules.

    ``retries=3`` (vs pydantic_ai's default of 1) gives some reasoning
    models multiple chances to emit valid
    TriageReport JSON. Repeated batches showed a recurring fraction of
    synth alerts failing with ``UnexpectedModelBehavior: Exceeded maximum
    retries (1) for output validation`` — the same scenarios across runs,
    so the schema-validation retry budget was the bottleneck, not a
    transient model fault.
    """
    from soc_ai.agent.prompts import SYNTH_FIRST_SYSTEM_PROMPT  # noqa: PLC0415

    return Agent(
        model=model,
        system_prompt=SYNTH_FIRST_SYSTEM_PROMPT,
        output_type=TriageReport,
        retries=3,
    )


def _guard_egress(guard: EgressGuard | None, text: str, settings: Settings) -> str:
    """Fail-closed residue check on a FINAL composed outbound analyst message.

    Returns *text* unchanged when there is nothing to enforce — either no guard
    (``analyst_cloud_redaction`` off ⇒ local model, byte-identical to the
    pre-feature path) or fail-closed mode off (best-effort: a sanitize miss is
    logged elsewhere but still egresses). When the guard is present AND
    ``settings.analyst_redaction_fail_closed`` is on, run the INDEPENDENT residue
    sweep on the (already-sanitized) composed string and raise
    :class:`~soc_ai.agent.egress_guard.EgressResidueError` if an internal
    identifier survived — the caller catches it, does NOT call the model, and
    lands a pipeline error.

    Wire it as ``msg = _guard_egress(guard, guard.sanitize_text(msg), settings)``
    so the check runs on the FINAL string that is about to hit the model, not on
    any single fragment composed into it.
    """
    if guard is None:
        return text
    guard.check_or_raise(text, fail_closed=settings.analyst_redaction_fail_closed)
    return text


def _synth_failure_fallback_report(
    alert_id: str,
    phase: str,
    exc: BaseException,
    *,
    retry_causes: list[str] | None = None,
) -> Any:
    """Build a fallback TriageReport when the synth-first model raises.

    When the synth fails schema-validation
    retries (UnexpectedModelBehavior) or any other exception, the
    pipeline previously emitted an ``error`` event and returned without
    a ``triage_report``. That produced ``verdict=None`` rows in
    ``index.jsonl`` that were unscoreable. Now we synthesize a low-
    confidence ``needs_more_info`` report from the failure so the row is
    structured and the downstream post-validators + audit run uniformly.

    The fallback report:

    - ``verdict='needs_more_info'`` (correct: we genuinely don't know)
    - ``confidence=0.3`` (visibly low — analyst sees it's a fallback)
    - ``summary`` names the failure phase + exception type
    - ``citations=['synth_first_failure']`` (single audit-trail marker)
    - ``gap_for_investigator=None`` (don't recurse into Phase D)
    - ``resolution={'provenance': 'pipeline_fallback', ...}`` — the marker that
      makes this failure-driven needs_more_info render distinctly from a genuine
      one, filterable, and excluded from the Needs-info KPI (E1.2). The verdict
      stays needs_more_info by design; only the presentation differs. This is a
      DIFFERENT key from the manual/chat override's ``resolved_via`` (added
      post-hoc by the resolve endpoint), so the two never conflate — see
      :func:`soc_ai.triage_models.is_pipeline_fallback`.
    """
    from soc_ai.agent.triage import (  # noqa: PLC0415
        PIPELINE_FALLBACK_PROVENANCE,
        TriageReport,
    )

    return TriageReport(
        verdict="needs_more_info",
        confidence=0.3,
        summary=(
            f"Synth-first pipeline fallback: {phase} raised "
            f"{type(exc).__name__}. The alert is recorded as "
            f"needs_more_info pending investigator-path retry. "
            f"Underlying error: {str(exc)[:200]}"
        ),
        citations=["synth_first_failure"],
        recommended_actions=[],
        gap_for_investigator=None,
        resolution={
            "provenance": PIPELINE_FALLBACK_PROVENANCE,
            "phase": phase,
            "error_type": type(exc).__name__,
            "hint": _hint_for(exc),
            # Only when captured (a schema-retry exhaustion): WHY each attempt
            # failed, so the pipeline-error drilldown is actionable. Old rows /
            # other failure classes keep their exact shape.
            **({"retry_causes": retry_causes} if retry_causes else {}),
        },
    )


def _round2_failure_fallback(
    alert_id: str,
    round1: Any,
    exc: BaseException,
    retry_causes: list[str] | None = None,
) -> Any:
    """Fallback verdict when the round-2 investigation loop / synth crashes.

    The agent already reached a round-1 verdict before the (expensive, flakier)
    round-2 path ran — don't discard it on a round-2 crash. If round-1 settled on
    a confident verdict, land THAT (annotated in the summary so the operator sees
    round-2 didn't finish) rather than erroring the whole run with no verdict. If
    round-1 was itself inconclusive (skipped / untriaged), fall back to the
    needs_more_info synth-failure report.
    """
    settled = {"true_positive", "false_positive"}
    verdict = getattr(round1, "verdict", None)
    if round1 is not None and verdict in settled:
        note = (
            f" (Round-2 deep investigation did not complete: {type(exc).__name__}; "
            "showing the round-1 verdict.)"
        )
        try:
            return round1.model_copy(
                update={"summary": (getattr(round1, "summary", "") or "") + note}
            )
        except Exception:
            return round1
    return _synth_failure_fallback_report(
        alert_id, "investigation_loop_synth", exc, retry_causes=retry_causes
    )


# Backwards-compat shim — pre-split callers used `build_agent(model, ctx)`
# and assumed Agent[None, TriageReport]. Their tests build a single agent
# manually; route to the synthesizer (no tools) since that produces the
# TriageReport. Tests that need tool-calling now build the investigator
# directly.
def build_agent(  # pragma: no cover - thin alias
    model: Model, ctx: InvestigationContext
) -> Agent[None, TriageReport]:
    """Deprecated: use build_investigator + build_synthesizer."""
    return build_synthesizer(model)


# =====================================================================
# Investigation runner
# =====================================================================


def _hint_for(exc: BaseException) -> str | None:
    """Return a short, actionable hint string for the analyst, or None."""
    if isinstance(exc, EgressResidueError):
        # Name only the COUNT/CLASS — never the leaked values (that would defect
        # on the fail-closed block). This hint lands in the report summary.
        return (
            f"redacted egress blocked: {len(exc.leaked)} internal identifier(s) "
            "survived sanitization on the outbound analyst payload, so the model "
            "was not called (analyst_redaction_fail_closed is on). Investigate "
            "locally or run with a local analyst model."
        )
    if isinstance(exc, OqlValidationError):
        frag = getattr(exc, "fragment", None)
        base = "OQL validator rejected the query"
        if frag:
            return (
                f"{base}; offending fragment: {frag!r}. "
                "Common pitfall: use full ECS field names like 'destination.ip', "
                "not shortened ones like 'dest.ip'."
            )
        return f"{base}; check field names against the OQL primer."
    if isinstance(exc, SoApiError):
        return "alert id may be wrong; verify it exists in ES."
    msg = str(exc).lower()
    # Pattern-match on the LiteLLM/PydanticAI error strings.
    if "exceeded maximum output retries" in msg or (
        "exceeded maximum retries" in msg and "output validation" in msg
    ):
        return (
            "the model repeatedly produced output that failed TriageReport "
            "schema validation until the retry budget ran out. The per-attempt "
            "validation errors are recorded as retry_causes on this run's error "
            "event and resolution — read those: persistent schema failures "
            "usually mean the analyst model or its gateway route changed shape "
            "(reasoning/tool-call format), not a transient fault."
        )
    if "token limit" in msg and "before any response" in msg:
        return (
            "the model hit its response-token cap while still reasoning, so no "
            "structured output was produced. Reasoning models can burn the whole "
            "budget thinking — raise synthesizer_max_response_tokens (config "
            "console → Agent) or switch to a less verbose analyst model."
        )
    if "contextwindowexceeded" in msg or "context length" in msg:
        return (
            "context window exceeded; transcript or prompt is too large. "
            "The alert context or accumulated evidence may exceed the model's window."
        )
    if "timed out" in msg or "timeout" in msg:
        return "LiteLLM gateway slow or unreachable; retry."
    # Generic transport-layer "can't reach the host" — fires when SO/ES is
    # restarting, the network is down, etc.
    if "cannot connect to host" in msg or "connection error" in msg or "connection refused" in msg:
        return (
            "elasticsearch / Security Onion unreachable. Verify the SO grid is "
            "online and ES_HOSTS in soc-ai's .env points at the right node."
        )
    return None


def _retry_causes_from_messages(messages: Any) -> list[str]:
    """Lift the per-attempt validation errors out of a captured message history.

    When a synth run dies with ``UnexpectedModelBehavior: Exceeded maximum
    output retries``, the actual reasons live in the ``RetryPromptPart``s
    pydantic-ai fed back to the model — and are otherwise discarded with the
    run. Called on a ``capture_run_messages()`` capture from the failing run;
    returns compact, whitespace-normalized strings (most recent last, at most
    4, each capped at 400 chars) for the error event payload and the fallback
    report's ``resolution`` marker. Defensive: a surprise message/part shape is
    skipped, never raised — this runs inside an error handler.
    """
    causes: list[str] = []
    try:
        for msg in messages or []:
            for part in getattr(msg, "parts", None) or []:
                if type(part).__name__ != "RetryPromptPart":
                    continue
                try:
                    rendered = part.model_response()
                except Exception:
                    rendered = str(getattr(part, "content", "") or "")
                compact = " ".join(str(rendered).split())
                if compact:
                    causes.append(compact[:400])
    except Exception:
        return causes[-4:]
    return causes[-4:]


def _error_payload(
    exc: BaseException,
    *,
    phase: str,
    round_num: int,
    retry_causes: list[str] | None = None,
) -> dict[str, Any]:
    """Typed error event payload with phase/round/type/message + optional hint."""
    payload: dict[str, Any] = {
        "phase": phase,
        "round": round_num,
        "type": type(exc).__name__,
        "message": str(exc),
    }
    hint = _hint_for(exc)
    if hint:
        payload["hint"] = hint
    if retry_causes:
        payload["retry_causes"] = retry_causes
    return payload


def _is_high_stakes_alert(alert: SoAlert) -> bool:
    """Whether an alert is too high-stakes to auto-ack, even on a confident FP.

    Reuses the existing deterministic rule-class signals (no new classifier):

    - :func:`classify_alert` lands the alert in EXPLOIT_ATTEMPT / POST_COMPROMISE
      when its Suricata ``classtype`` or ``signature_severity`` declares an
      exploit / attack / malware / C2 family.
    - :func:`_alert_signals_malware` (from :mod:`decision_templates`) catches the
      malware/exploit token case where ``classtype`` is absent but the rule name
      or ``rule_metadata.metadata_tags`` carry a malware-family signal (the
      BPFDoor-style ET MALWARE label).
    - SO's own severity: ``severity_label`` of critical/high, or
      ``severity_score`` >= 3 (SO buckets 3=high, 4=critical).

    Any one of these makes the alert high-stakes. The verdict still stands —
    we just refuse to *auto-write* an ack on it.
    """
    from soc_ai.agent.decision_templates import _alert_signals_malware  # noqa: PLC0415 — circular

    if classify_alert(alert) in (AlertClass.EXPLOIT_ATTEMPT, AlertClass.POST_COMPROMISE):
        return True
    if _alert_signals_malware(alert):
        return True
    sev_label = (alert.severity_label or "").strip().lower()
    if sev_label in ("critical", "high"):
        return True
    return alert.severity_score is not None and alert.severity_score >= 3


async def maybe_auto_ack_fp(
    report: TriageReport,
    es_id: str,
    *,
    alert: SoAlert,
    ctx: InvestigationContext,
    emit_ev: Any,
    audit_ev: Any,
) -> StepEvent | None:
    """Auto-acknowledge a high-confidence FP alert in Security Onion.

    Called from both the synth-first and legacy finalization paths after the
    final verdict and confidence are settled (including Oracle adjudication).

    Gating (all must be true):
    - ``settings.auto_ack_fp_enabled`` is True
    - ``report.verdict == "false_positive"``
    - ``report.confidence >= settings.auto_ack_fp_threshold``
    - the alert is NOT high-stakes (see :func:`_is_high_stakes_alert`)

    The high-stakes guard is a blast-radius cap: a prompt-injected confident
    ``false_positive`` must never auto-ack a critical/high-severity or
    malware/exploit/attack-class alert. We skip the auto-write (the verdict is
    unchanged) and leave the ack to a human.

    Best-effort: any write error is logged as a warning and does NOT propagate.
    The investigation is never failed by auto-ack.

    The ack is written DIRECTLY (via :func:`execute_write_tool`) — it does NOT
    wait for an analyst action. That is the whole point of the opt-in:
    ``auto_ack_fp_enabled`` is an explicit operator decision to let confident,
    low-stakes FP acks write to SO unattended. The audit logger is routed
    through so the unattended write is always recorded (fail-closed on intent).

    Coupling: this only runs from investigation finalisation, so an alert is
    auto-acked ONLY if it is investigated while the toggle is on — there is no
    retroactive backlog sweep. See ``Settings.auto_ack_fp_enabled`` for how this
    interacts with the auto-triage floor.

    Returns the ``auto_ack`` StepEvent (for the caller to yield into the stream)
    when the write was attempted; an ``auto_ack_skipped`` StepEvent (with
    ``reason`` = ``below_threshold`` | ``high_stakes``) when auto-ack was armed
    for this FP but a guard held it back — recorded so the drawer can explain
    why the pending ack needs a human; or ``None`` when auto-ack simply doesn't
    apply (disabled, or a non-FP verdict).
    """
    settings = ctx.settings
    if not settings.auto_ack_fp_enabled:
        return None
    if report.verdict != "false_positive":
        return None
    if (report.confidence or 0.0) < settings.auto_ack_fp_threshold:
        # Record WHY this FP wasn't auto-acked so the drawer can explain the
        # pending ack instead of leaving the analyst to guess (two identical-
        # looking ack cards behaved differently in dogfood 2026-07-15).
        skipped_ev: StepEvent = emit_ev(
            "auto_ack_skipped",
            {
                "es_id": es_id,
                "reason": "below_threshold",
                "confidence": report.confidence,
                "threshold": settings.auto_ack_fp_threshold,
            },
        )
        return skipped_ev
    if _is_high_stakes_alert(alert):
        # Blast-radius cap: never auto-write an ack on a high-stakes alert, even
        # on a confident FP. The verdict stands; a human must ack it.
        _LOGGER.info(
            "auto-ack suppressed for high-stakes alert %s "
            "(class/severity gate) despite verdict=false_positive conf=%.2f",
            es_id,
            report.confidence or 0.0,
        )
        high_stakes_ev: StepEvent = emit_ev(
            "auto_ack_skipped",
            {
                "es_id": es_id,
                "reason": "high_stakes",
                "confidence": report.confidence,
                "threshold": settings.auto_ack_fp_threshold,
            },
        )
        return high_stakes_ev

    _LOGGER.info(
        "auto-acking FP alert %s (confidence=%.2f >= threshold=%.2f)",
        es_id,
        report.confidence or 0.0,
        settings.auto_ack_fp_threshold,
    )
    success: bool
    try:
        # Auto-ack is an unattended write. Route the audit logger through so the
        # ack is recorded as a mutating tool_call intent BEFORE the SO write
        # (fail-closed under audit_fail_closed) and a result record after — an
        # analyst-review-free write must always land in the audit trail.
        _result, error = await execute_write_tool(
            "ack_alert",
            {"alert_id": es_id},
            auth=ctx.auth,
            settings=settings,
            audit=ctx.audit,
            session_id=f"auto-ack:{es_id}",
            user="auto-ack",
        )
        if error:
            _LOGGER.warning("auto-ack write failed for alert %s: %s", es_id, error)
            success = False
        else:
            success = True
    except Exception as exc:
        _LOGGER.warning("auto-ack unexpected error for alert %s: %s", es_id, exc)
        success = False

    ack_ev: StepEvent = emit_ev(
        "auto_ack",
        {
            "es_id": es_id,
            "confidence": report.confidence,
            "threshold": settings.auto_ack_fp_threshold,
            "success": success,
        },
    )
    try:
        await audit_ev(ack_ev)
    except Exception as exc:
        _LOGGER.warning("auto-ack audit log failed for alert %s: %s", es_id, exc)
    # Yield is caller's responsibility — we return the event for the caller to yield.
    # (Generators can't be called from non-generator helpers in Python.)
    return ack_ev


async def investigate(
    alert_id: str,
    *,
    ctx: InvestigationContext,
    focus_hint: str | None = None,
    deep: bool = False,
) -> AsyncIterator[StepEvent]:
    """Public entry point for the synth-first triage pipeline.

    Async-yields :class:`StepEvent` items throughout the run.

    ``deep`` (optional): force the full tool-driven investigation loop for THIS
    run regardless of ``fast_triage_enabled`` — the analyst's "deep re-run" of
    a heuristic verdict must go deeper than the heuristic it double-checks.

    ``focus_hint`` (optional): when this run was launched to close a prior
    ``needs_more_info`` verdict (the "request more info" action), the prior
    open questions are passed here and woven into the seed prompt so the fresh
    run TARGETS those gaps. ``None`` ⇒ normal cold run.

    **Pipeline stages** (all executed by :func:`_run_synth_first_pipeline`):

    1. **Prefetch / enrichment** — alert fields extracted; IOC enrichment tools
       run; enrichment results written to the cross-alert cache.
    2. **Decision-template candidate** — deterministic template match attempted;
       strong grounded templates may produce a verdict without any LLM call.
    3. **Tool-less synthesis round 1** — analyst model synthesizes over the
       prefetch payload; emits a :class:`TriageReport` candidate.
    4. **Phase D or investigation loop** (optional) — if round-1 leaves a
       ``gap_for_investigator``, either a single targeted tool dispatch (Phase D)
       or a full tool-equipped investigation loop gathers additional evidence.
    5. **Synthesis over result** — analyst model re-synthesizes over the
       combined evidence to produce the final :class:`TriageReport`.
    6. **Deterministic gates / downgrades** — evidence floor rewrite, malware
       payload gate (GATE A), distinctive-token citation gate (GATE C), targeted
       verdict downgrades.
    7. **Oracle escalation** (optional) — a second analyst-model opinion when the
       Oracle feature is enabled and the confidence warrants it.
    8. **Final TriageReport** — recommended actions persisted (analyst-executed
       via the actions API); optional auto-ack applied.

    Per-phase ``usage`` SSE events expose real token / tool-call counts so we
    can right-size limits and the confidence floor with audit data.

    The pipeline constructs its own agents internally; callers supply only the
    alert, the context, and an optional focus hint.
    """
    # Single pipeline: synth-first (A→B→C→optional D→C round 2). The legacy
    # investigator→synthesizer loop was deleted 2026-07 after synth-first had
    # been the production default since 2026-05-29 (0a02f9c).
    async for ev in _run_synth_first_pipeline(
        alert_id=alert_id,
        ctx=ctx,
        focus_hint=focus_hint,
        deep=deep,
    ):
        yield ev


# Citation-path prefixes that point at REAL gathered evidence (tool returns,
# enrichment results, or pivot events) rather than the alert's own fields.
# A verdict cited only against `alert.*` paths is self-referential — it
# restates the alert rather than investigating it. The QVOD beacon false-FP
# cited 5 `alert.*` paths (rule_name, payload_printable, classtype,
# rule_metadata.*) and called a Cobalt Strike beacon benign on that basis.
_EVIDENCE_PATH_PREFIXES: tuple[str, ...] = (
    "community_id_events",
    "host_events",
    "user_events",
    "process_events",
    "file_events",
    "enrichments",
    "typed_zeek",
)


def _pivot_event_ids(alert_ctx: Any) -> set[str]:
    """Collect the ES ``_id`` of every prefetched pivot event.

    An ``id``-shaped citation only counts as real evidence when it matches a
    pivot event the orchestrator actually pulled — otherwise the model could
    fabricate a long-alphanumeric string and have it trusted by
    :func:`_classify_citation`'s id branch.
    """
    ids: set[str] = set()
    for pivot_attr in _EVIDENCE_PATH_PREFIXES[:5]:  # the *_events pivot lists
        for ev in getattr(alert_ctx, pivot_attr, None) or []:
            ev_id = getattr(ev, "id", None)
            if isinstance(ev_id, str) and ev_id:
                ids.add(ev_id)
    return ids


def _is_evidence_backed(report: Any, enriched: Any, *, messages: list[Any] | None = None) -> bool:
    """True only when the verdict rests on REAL gathered evidence.

    Theme-1 Task 1. "Real evidence" means at least one citation resolves to
    an actual tool/enrichment result or a prefetched pivot event — NOT merely
    to a self-referential field on the alert under triage
    (``alert.rule_name``, ``alert.payload_printable``, ``alert.classtype``,
    ``alert.rule_metadata.*``, …). A citation qualifies when:

    - it names a tool (``(tool t_query_zeek_logs)`` / bare ``t_…``) that was
      actually invoked in the loop's message history, OR
    - it is a path into a pivot list / enrichment / typed-Zeek block
      (``community_id_events.0.…``, ``enrichments.1.2.3.4.…``, …) that
      resolves against the bundle, OR
    - it is an id that matches a prefetched pivot event's ``_id``.

    Pure ``alert.*`` paths (and bare ``alert.*`` field names) are
    self-referential and never count. An empty citation list is, by
    definition, not evidence-backed.

    ``messages`` is the loop's ``all_messages()`` history when available
    (lets tool citations resolve against real ``ToolCallPart`` events). At
    round-1 there is no message history, so tool citations can't be proven —
    which is correct: a zero-tool round-1 guess naming a tool it never
    called is exactly what this gate exists to catch.
    """
    citations = list(getattr(report, "citations", None) or [])
    if not citations:
        return False

    pivot_ids = _pivot_event_ids(enriched)
    for c in citations:
        kind, target = _classify_citation(c)
        if kind == "tool":
            if target and _tool_was_invoked([], target, messages=messages):
                return True
        elif kind == "path":
            if not target:
                continue
            head = target.split(".", 1)[0]
            # `alert.*` is self-referential; only non-alert evidence paths count.
            # Fix A: path citations into pivot/enrichment lists only count when
            # messages is not None — i.e. a real investigation loop ran. At
            # round 1 (messages=None) these paths come from _materialize_prefetch_evidence;
            # citing them is restating the prefetch, not investigation.
            if (
                head in _EVIDENCE_PATH_PREFIXES
                and messages is not None
                and _path_exists_in_alert(enriched, target)
            ):
                return True
        elif (
            kind == "id"
            and target
            and target in pivot_ids
            # Fix A: id citations matching prefetched pivot events only count when
            # messages is not None. At round 1 the synth was given these ids via
            # _materialize_prefetch_evidence; a zero-tool citation of a prefetched
            # id is not evidence of investigation.
            and messages is not None
        ):
            return True
    return False


def _definitely_investigate(enriched: Any, candidate: Any) -> bool:
    """Report-INDEPENDENT investigate triggers.

    True when the case will run the investigation loop REGARDLESS of the round-1
    verdict — a malware/exploit-signalled rule (the QVOD/beacon/BPFDoor failure
    mode: a zero-tool synth citing prefetched pivots is not evidence of
    benignness), or an external-reputation decision template (e.g.
    pushplanet settled FP on an unknown external host with zero tools).

    Because these don't depend on the round-1 report, the pipeline pre-checks
    this BEFORE Phase C and skips the ~10-15s round-1 synth call when True — that
    verdict would be discarded the moment the loop runs.
    """
    from soc_ai.agent.decision_templates import (  # noqa: PLC0415
        EXTERNAL_REPUTATION_TEMPLATES,
        _host_has_concurrent_threat,
        _rule_signals_malware,
    )

    if _rule_signals_malware(enriched):
        return True
    # Host-context trigger: the focus alert may look benign
    # (internal east-west, INFO) while its host is concurrently beaconing to a
    # C2 — the "context not being considered" failure. A threat-signalling pivot
    # alert on the same host/flow forces a real investigation of this leg.
    if _host_has_concurrent_threat(enriched):
        return True
    return (
        candidate is not None
        and getattr(candidate, "template_id", None) in EXTERNAL_REPUTATION_TEMPLATES
    )


def _should_investigate(report: Any, enriched: Any, candidate: Any) -> bool:
    """Decide whether to run the real investigation loop after round 1.

    Theme-1 Task 1. True when ALL hold:

    - ``investigate_when_unsure`` is on (settings flag is read by the
      caller, passed positionally via ``report``'s pipeline — see below),
    - the round-1 verdict is NOT evidence-backed
      (:func:`_is_evidence_backed`), AND
    - the alert is non-trivial — i.e. NOT a clean-internal benign that a
      decision template already cleared without any malware signal.

    "Trivially benign" = a non-malware-signalling alert whose decision
    template landed a benign verdict (``false_positive`` /
    ``needs_more_info`` is treated as non-benign; only ``false_positive``
    from a template on a non-malware rule short-circuits). Such alerts keep
    the fast zero-tool path; everything else that lacks evidence gets the
    loop.

    Note: the ``investigate_when_unsure`` flag check lives at the call site
    (it needs ``ctx.settings``); this helper assumes it has already passed
    and concerns itself only with the evidence + triviality gates.
    """
    # Report-INDEPENDENT triggers (malware/exploit signal, external-reputation
    # template). Extracted to _definitely_investigate so the pipeline can
    # pre-check them BEFORE Phase C and skip the wasted round-1 synth. Checked
    # before _is_evidence_backed because a template's own cited evidence (or a
    # round-1 FP citing a prefetched pivot) would otherwise read as "backed".
    if _definitely_investigate(enriched, candidate):
        return True

    if _is_evidence_backed(report, enriched):
        return False
    # Clean-internal benign: a decision template cleared it false_positive on
    # a rule with no malware signal → keep the fast path. Everything else that
    # lacks evidence gets the loop.
    return not (
        candidate is not None
        and getattr(candidate, "verdict", None) == "false_positive"
        and getattr(report, "verdict", None) == "false_positive"
    )


def _synth_reasoning_payload(run_result: Any) -> dict[str, Any] | None:
    """Project a synthesizer run's thinking into a ``model_response`` payload.

    The synth-first synthesizer runs (round-1 / loop-synth / Phase-D round-2)
    complete via ``agent.run`` — nothing walks their messages, so their
    ThinkingParts (deepseek ``reasoning_content`` bound via the model profile)
    were silently dropped and a no-loop investigation surfaced NO "Model
    reasoning" panel. Same part projection as :func:`_walk_message` (named
    ThinkingPart content, plus inline ``<think>`` blocks in TextParts), but
    collapsed to ONE payload for the whole run since a no-tools synthesis is a
    single model turn. Returns None when there is no non-empty trace (emit
    nothing) or on any message-shape surprise (defensive: never fail a verdict
    over explainability bookkeeping).
    """
    try:
        messages = run_result.all_messages()
    except Exception:
        return None
    traces: list[str] = []
    texts: list[str] = []
    try:
        for msg in messages or []:
            for part in getattr(msg, "parts", []) or []:
                ptype = type(part).__name__
                if ptype == "ThinkingPart":
                    content = getattr(part, "content", "") or ""
                    if content.strip():
                        traces.append(content.strip())
                elif ptype == "TextPart":
                    content = getattr(part, "content", "") or ""
                    trace, cleaned = extract_reasoning_trace(content)
                    if trace and trace.strip():
                        traces.append(trace.strip())
                    if cleaned.strip():
                        texts.append(cleaned.strip())
    except Exception:
        return None
    if not traces:
        return None
    return {"content": "\n\n".join(texts), "reasoning_trace": "\n\n".join(traces)}


async def _walk_message(
    msg: Any,
    ev_factory: Any,
    *,
    phase: str | None = None,
    round_num: int | None = None,
) -> AsyncIterator[StepEvent]:
    """Yield StepEvent records for every interesting part of a PydanticAI message.

    PydanticAI's message objects are a structured (model_request, model_response,
    tool_call, tool_return) sequence; we project only what the SSE consumer cares
    about and capture the ``<think>`` trace separately for audit. ``phase`` /
    ``round_num`` are stamped onto every emitted payload so consumers can
    distinguish investigator-vs-synthesizer events and round 1 vs round 2.
    """

    def _stamp(payload: dict[str, Any]) -> dict[str, Any]:
        if phase is not None:
            payload["phase"] = phase
        if round_num is not None:
            payload["round"] = round_num
        return payload

    parts = getattr(msg, "parts", []) or []
    # Track the most-recent ThinkingPart so we can attach it to the next
    # TextPart (or emit it standalone if no TextPart follows in this message).
    pending_trace: str | None = None
    for part in parts:
        ptype = type(part).__name__
        if ptype == "ThinkingPart":
            content = getattr(part, "content", "") or ""
            if content:
                pending_trace = (pending_trace + "\n\n" + content) if pending_trace else content
            continue
        if ptype == "TextPart":
            content = getattr(part, "content", "") or ""
            trace, cleaned = extract_reasoning_trace(content)
            payload: dict[str, Any] = {"content": cleaned}
            # Prefer a same-message ThinkingPart trace; fall back to inline
            # <think>...</think> if the model embedded the trace in text.
            if pending_trace:
                payload["reasoning_trace"] = pending_trace
                pending_trace = None
            elif trace:
                payload["reasoning_trace"] = trace
            yield ev_factory("model_response", _stamp(payload))
        elif ptype == "ToolCallPart":
            yield ev_factory(
                "tool_call",
                _stamp(
                    {
                        "tool_name": getattr(part, "tool_name", ""),
                        "args": getattr(part, "args", {}),
                        "tool_call_id": getattr(part, "tool_call_id", ""),
                    }
                ),
            )
        elif ptype == "ToolReturnPart":
            yield ev_factory(
                "tool_result",
                _stamp(
                    {
                        "tool_name": getattr(part, "tool_name", ""),
                        "result": getattr(part, "content", None),
                        "tool_call_id": getattr(part, "tool_call_id", ""),
                    }
                ),
            )
    # Trace without a follow-up TextPart in the same message — emit it as a
    # standalone reasoning-only model_response so it isn't lost.
    if pending_trace:
        yield ev_factory(
            "model_response",
            _stamp({"content": "", "reasoning_trace": pending_trace}),
        )


def _should_escalate_to_oracle(
    report: TriageReport,
    enriched: Any,
    settings: Settings,
    *,
    ran_loop: bool = False,
) -> bool:
    """Return True when the local verdict should be escalated to the Oracle.

    The Oracle is for cases the local path got WRONG or could not resolve — not
    for re-confirming correct verdicts. Policy (oracle_enabled is a mandatory
    prerequisite for any escalation):

    0. SHORT-CIRCUIT: a malware/attack-signalled rule the local path flagged
       ``true_positive`` is correct regardless of its confidence number — keep it
       LOCAL. Observed failure: correct local malware TPs were bouncing
       to the Oracle only because a citation_cap pushed confidence below 0.7/0.6.
    1. ``oracle_escalate_needs_more_info`` AND verdict == needs_more_info.
    2. ``oracle_escalate_malware_non_tp`` AND the rule signals malware/exploit OR
       attack-class (classtype in ``_ATTACK_CLASSTYPES``) AND the local verdict is
       NOT true_positive (i.e. cleared false_positive) — the wrongly-cleared-
       malware safety net (QVOD/BPFDoor). Attack-class rules (kerberoast, psexec
       lateral movement, data exfil, DNS tunnel) don't carry malware tokens, so
       ``_rule_signals_malware`` alone was too narrow.
       COST GATE: skipped when the investigation ``ran_loop`` AND
       ``report.confidence >= oracle_skip_after_confident_loop`` — a confident
       verdict after a real tool-driven investigation is trustworthy. The
       zero-tool fast path (``ran_loop`` False) still escalates here.
    3. confidence < ``oracle_escalate_below_confidence`` (any remaining verdict).

    Confident-benign verdicts on non-malware, non-attack rules are NOT escalated.
    """
    if not settings.oracle_enabled:
        return False

    # A pipeline-fallback placeholder is a MECHANICAL failure (model truncation,
    # gateway 5xx), not a model opinion — there is nothing for the Oracle to
    # adjudicate and its needs_more_info verdict would trip condition 1 below.
    # Re-running is the fix; escalating just burnt heavy-model tokens on
    # "Oracle did not return a verdict" (dogfood 2026-07-15).
    if is_pipeline_fallback({"resolution": report.resolution}):
        return False

    from soc_ai.agent.decision_templates import (  # noqa: PLC0415
        _rule_signals_attack,
        _rule_signals_malware,
    )

    malware_or_attack = _rule_signals_malware(enriched) or _rule_signals_attack(enriched)

    # Condition 1: local model genuinely uncertain.
    if settings.oracle_escalate_needs_more_info and report.verdict == "needs_more_info":
        return True

    # A malware/attack-signalled rule that the local path flagged TRUE_POSITIVE is
    # already correctly handled — a flagged-malicious verdict is the right call
    # regardless of the confidence number, and the Oracle cannot improve "this
    # malware is malicious." Observed failure (CryptoWall, DNS-PowerShell
    # scenarios): the loop reached TP, but a citation_cap dragged confidence to 0.54,
    # which tripped BOTH the malware-non-TP gate and the low-confidence floor and
    # bounced a correct local verdict to the Oracle. The user's bar: "if we
    # cannot adjudicate that locally there is something wrong with the path." Keep
    # flagged-malicious verdicts local; the Oracle is for cases the local path
    # got WRONG or could not resolve, not for re-confirming correct TPs.
    if malware_or_attack and report.verdict == "true_positive":
        return False

    # Condition 2: a malware/attack-signalled rule the local path did NOT flag TP
    # (i.e. cleared false_positive) — the QVOD/BPFDoor wrongly-cleared-malware
    # safety net — UNLESS a real investigation loop already resolved it
    # confidently. The zero-tool fast path (``ran_loop`` False) still escalates.
    resolved_by_confident_loop = (
        ran_loop and report.confidence >= settings.oracle_skip_after_confident_loop
    )
    if (
        settings.oracle_escalate_malware_non_tp
        and malware_or_attack
        and not resolved_by_confident_loop
    ):
        return True

    # Condition 3: below-floor confidence on any remaining verdict / rule.
    return report.confidence < settings.oracle_escalate_below_confidence


async def _resolve_effective_identifiers(
    ctx: InvestigationContext,
) -> EffectiveIdentifiers | None:
    """Resolve the full effective internal-identifier set ONCE per investigation.

    Opens a one-off session from ``ctx.db_sessionmaker`` and computes the merged
    *effective* set (env-config union active detected/manual identifiers, minus
    muted) via
    :func:`~soc_ai.oracle.identifiers.effective_internal_identifiers`. The
    returned :class:`EffectiveIdentifiers` carries ``.suffixes``/``.hosts`` (for
    the Oracle egress sanitizer) and ``.cidrs`` (for internal-IP classification).

    Returns ``None`` when:

    * no ``db_sessionmaker`` is on ``ctx`` (CLI / eval / direct callers), or
    * resolution raised (DB error, missing table).

    A ``None`` return is the BACKWARD-COMPAT escape hatch: callers fall back to
    the raw ``settings`` values (``oracle_internal_suffixes`` / ``oracle_extra_hosts``
    for redaction, ``internal_cidrs`` for classification), so a db-less path — or
    any failure — leaves both redaction and classification behavior unchanged.

    SECURITY (redaction): threading this can never under-redact relative to
    today's settings-only behavior. The effective suffix/host set is
    ``(settings/reserved, always) + (active detected/manual) - (muted)``, and the
    sanitizer always re-adds ``settings.oracle_internal_suffixes`` (plus the
    reserved ``.lan/.local/.internal/.corp`` floor), so reserved/env defaults
    cannot be muted away — relative to raw settings this only ever *adds*.

    CLASSIFICATION (cidrs): with NO active ``cidr`` rows the effective cidrs ==
    ``settings.internal_cidrs`` (a muted detected CIDR is suppressed, an active
    one is added) — so classification is byte-identical to today until an
    operator un-mutes a suggested subnet. Detected CIDRs are always muted, so
    discovery alone never reclassifies a host.
    """
    maker = ctx.db_sessionmaker
    if maker is None:
        return None
    try:
        async with maker() as db:
            return await effective_internal_identifiers(db, ctx.settings)
    except Exception:  # pragma: no cover - defensive; never block egress on a DB hiccup
        _LOGGER.warning(
            "orchestrator: failed to resolve effective internal-identifier set; "
            "falling back to settings (oracle suffixes/hosts + internal_cidrs)",
            exc_info=True,
        )
        return None


def _classification_cidrs(
    ctx: InvestigationContext, effective: EffectiveIdentifiers | None
) -> Sequence[Any]:
    """The internal CIDR set internal-IP classification should use.

    ``effective.cidrs`` when the effective set resolved (env ``internal_cidrs``
    union active ``cidr`` rows minus muted), else ``settings.internal_cidrs``
    (db-less path / resolution failure). With no active ``cidr`` rows the two are
    identical, so classification is unchanged until an operator un-mutes a
    suggested subnet.
    """
    if effective is not None:
        return effective.cidrs
    return ctx.settings.internal_cidrs


async def _resolve_oracle_identifiers(
    ctx: InvestigationContext,
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Resolve the effective (suffixes, hosts) for the Oracle egress sanitizer.

    Thin wrapper over :func:`_resolve_effective_identifiers` preserving the
    historical ``(suffixes, hosts)`` shape the Oracle client consumes. ``None``
    ⇒ fall back to the raw settings tuples (redaction unchanged). See
    :func:`_resolve_effective_identifiers` for the full contract.
    """
    effective = await _resolve_effective_identifiers(ctx)
    if effective is None:
        return None
    return effective.suffixes, effective.hosts


def _desanitize_report(report: TriageReport, guard: EgressGuard) -> TriageReport:
    """Restore real identifiers in every string field of a *report*.

    When the cloud-egress guard is active the synth/loop models emit their
    TriageReports in LABEL space (``HOST_01`` cited in summaries, citations,
    recommended-action args, and ``gap_for_investigator.tool_args``). This
    round-trips the whole report through ``guard.desanitize_obj`` —
    ``model_dump`` → recursive label restore → ``model_validate`` — so
    everything downstream (the deterministic gates comparing against real
    enriched values, Phase-D dispatch args hitting Elasticsearch, the stored
    ``triage_report`` event, the analyst-facing UI) sees real values.

    Defensive: a desanitize/validation surprise must never cost the verdict —
    on any failure the labeled report is returned unchanged (labels in the UI
    beat a crashed investigation).
    """
    try:
        restored = guard.desanitize_obj(report.model_dump(mode="json"))
        return TriageReport.model_validate(restored)
    except Exception:
        _LOGGER.warning(
            "egress guard: TriageReport desanitize failed; keeping labeled report",
            exc_info=True,
        )
        return report


def _round1_skipped_report(alert_id: str) -> TriageReport:
    """Placeholder round-1 verdict for cases that skip the round-1 synth and
    route straight to the investigation loop. Always overwritten by the loop's
    synthesizer output — it only serves as the ``triage_final`` default."""
    return TriageReport(
        verdict="needs_more_info",
        confidence=0.0,
        summary="Round-1 synth skipped — routed directly to the investigation loop.",
        citations=[],
    )


def _self_consistency_vote(reports: list[Any]) -> tuple[str, float, str]:
    """Majority-vote a verdict across N independent final-synthesis samples.

    Pure helper for the flag-gated self-consistency vote
    (``settings.verdict_consistency_samples > 1``). Given the TriageReports
    from N runs of the SAME final synthesis call, returns
    ``(verdict, confidence, note)``:

    - STRICT majority (count > N/2): that verdict wins; confidence is the mean
      of the confidences of the samples that voted for it (3 dp); note =
      ``"self-consistency K/N agreed on <verdict>"``.
    - No strict majority (tie or 3-way split): ``("inconclusive", mean
      confidence of ALL samples capped at 0.5, "self-consistency split M ways:
      <tally> — inconclusive")``.
    - Single report (defensive — the caller guards N>1): passthrough of that
      report's verdict/confidence unchanged.
    """
    if len(reports) == 1:
        r = reports[0]
        return r.verdict, r.confidence, "self-consistency: single sample — no vote"
    n = len(reports)
    tally = Counter(r.verdict for r in reports)
    top_verdict, top_count = tally.most_common(1)[0]
    if top_count > n / 2:
        confs = [r.confidence for r in reports if r.verdict == top_verdict]
        mean_conf = round(sum(confs) / len(confs), 3)
        return (
            top_verdict,
            mean_conf,
            f"self-consistency {top_count}/{n} agreed on {top_verdict}",
        )
    conf = round(min(sum(r.confidence for r in reports) / n, 0.5), 3)
    tally_str = ", ".join(
        f"{v}={c}" for v, c in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return (
        "inconclusive",
        conf,
        f"self-consistency split {len(tally)} ways: {tally_str} — inconclusive",
    )


# Header framing the E4.2 prior-outcome memory block. The anti-anchoring
# instruction lives HERE (read before any verdict line), because the whole
# point of the default-off flag is that prior verdicts can bias the model —
# the block must present as fallible context, never as evidence to cite.
_PRIOR_OUTCOMES_HEADER = (
    "## Prior outcomes for similar alerts (CONTEXT ONLY — NOT evidence. "
    "Do not cite these; they may be wrong; weigh the current evidence on its "
    "own merits.)"
)


def _prior_age_phrase(created_at: datetime | None, now: datetime) -> str:
    """Compact "how long ago" phrase for one prior-outcome line ("3d ago").

    Both datetimes are naive UTC (the store's convention — ``created_at`` is
    stamped by SQLite ``func.now()`` and compared against
    :func:`soc_ai.store.auth.utcnow` everywhere else). Sub-hour ages render
    "<1h ago". A missing value or an aware/naive mismatch renders "recently"
    instead of raising — the memory block is advisory context and must never
    kill an investigation over a timestamp quirk (fail-soft, like the fetch).
    """
    if created_at is None:
        return "recently"
    try:
        delta_s = max((now - created_at).total_seconds(), 0.0)
    except TypeError:  # aware vs naive mismatch from an exotic backend
        return "recently"
    days = int(delta_s // 86400)
    if days >= 1:
        return f"{days}d ago"
    hours = int(delta_s // 3600)
    return f"{hours}h ago" if hours >= 1 else "<1h ago"


def _format_prior_outcomes_block(digests: list[dict[str, Any]]) -> str:
    """Render prior-outcome digests into the round-1 memory block (E4.2).

    One compact line per digest — age, match tier, verdict (+confidence), and
    the word-boundary-truncated rationale — under the anti-anchoring header.
    The returned block is passed into :func:`build_synth_first_user_message`
    BEFORE the composed message's final sanitize sweep + ``_guard_egress``, so
    internal identifiers inside a prior rationale are redacted on the
    cloud-analyst path exactly like the rest of the prompt.
    """
    from soc_ai.store.auth import utcnow  # noqa: PLC0415 - lazy: store dep only when memory is on

    now = utcnow()
    lines = [_PRIOR_OUTCOMES_HEADER, ""]
    for d in digests:
        conf = d.get("confidence")
        conf_part = f" ({conf:.2f})" if isinstance(conf, int | float) else ""
        digest = d.get("rationale_digest") or "(no rationale recorded)"
        lines.append(
            f"- {_prior_age_phrase(d.get('created_at'), now)} · {d.get('matched_on')} · "
            f"{d.get('verdict')}{conf_part} — {digest}"
        )
    return "\n".join(lines)


# Header framing the chat-transcript memory block. Like the priors header the
# anti-grounding instruction lives HERE (read before any excerpt line) — and it
# is stronger, per the operator's hard rule: a transcript's USER turns are an
# analyst's unverified opinion (the user is NOT always right), and its
# ASSISTANT turns reasoned about DIFFERENT alerts. Context only, never evidence.
_CHAT_MEMORY_HEADER = (
    "## Prior discussion excerpts (CONTEXT ONLY — NOT evidence. These are past "
    "chat messages; USER statements are unverified operator opinions and may be "
    "wrong; ASSISTANT statements were about different alerts. Do not cite; "
    "weigh current evidence on its own merits.)"
)


def _chat_memory_query_terms(
    rule_name: str | None, src_ip: str | None, dest_ip: str | None
) -> list[str]:
    """Alert-derived FTS query terms for the chat-transcript recall.

    Rule-name WORDS (split here, so each word matches independently — the
    store would treat a multi-word term as an exact phrase) plus the endpoint
    IPs as whole terms (the store turns each into an FTS phrase, keeping an IP
    selective). Everything is deterministic alert-row data — no model in the
    loop, mirroring the E4.2 (rule, src, dest) keying.
    """
    terms: list[str] = re.findall(r"[A-Za-z0-9]+", rule_name or "")
    terms.extend(ip for ip in (src_ip, dest_ip) if ip)
    return terms


def _format_chat_memory_block(digests: list[dict[str, Any]]) -> str:
    """Render chat-snippet digests into the round-1 "prior discussion" block.

    One compact line per snippet — ``[age · source · ROLE] "snippet"`` — under
    the context-NEVER-evidence header. The ROLE is uppercased so a USER line is
    visibly labeled as operator opinion right where it's read, not only in the
    header. Same egress contract as the priors block: the returned text is
    composed BEFORE the final sanitize sweep + ``_guard_egress``, so internal
    identifiers inside a snippet are redacted on the cloud-analyst path.
    """
    from soc_ai.store.auth import utcnow  # noqa: PLC0415 - lazy: store dep only when memory is on

    now = utcnow()
    lines = [_CHAT_MEMORY_HEADER, ""]
    for d in digests:
        role = str(d.get("role") or "").upper() or "UNKNOWN"
        lines.append(
            f"- [{_prior_age_phrase(d.get('created_at'), now)} · {d.get('source')} · "
            f'{role}] "{d.get("snippet")}"'
        )
    return "\n".join(lines)


async def _run_synth_first_pipeline(  # noqa: PLR0912, PLR0915 - multi-phase pipeline is inherently long
    *,
    alert_id: str,
    ctx: InvestigationContext,
    focus_hint: str | None = None,
    deep: bool = False,
) -> AsyncGenerator[StepEvent, None]:
    """Phase A → B → C → optional D → C round 2 → done.

    The synth-first pipeline. Defaults OFF until v8 measurement validates.

    ``focus_hint`` (optional): prior open questions from a re-launched
    ``needs_more_info`` investigation, woven into the round-1 seed + the
    investigation-loop investigator prompt so this run targets those gaps.
    """
    from soc_ai.agent.decision_templates import match_decision_template  # noqa: PLC0415
    from soc_ai.agent.prompts import (  # noqa: PLC0415
        build_synth_first_round2_user_message,
        build_synth_first_user_message,
    )
    from soc_ai.agent.targeted_investigator import (  # noqa: PLC0415
        run_targeted_investigation,
    )
    from soc_ai.tools.enrichment import EnrichmentContext  # noqa: PLC0415
    from soc_ai.tools.get_alert_context import get_enriched_alert_context  # noqa: PLC0415

    session_id = uuid.uuid4().hex
    sequence_counter = [0]

    def _ev(kind: str, payload: dict[str, Any]) -> StepEvent:
        sequence_counter[0] += 1
        return StepEvent(
            kind=kind, session_id=session_id, sequence=sequence_counter[0], payload=payload
        )

    async def _audit(ev: StepEvent) -> None:
        # Audit must never crash the in-flight investigation. The audit logger
        # already swallows ES errors, but a Pydantic ValidationError on
        # AuditKind would propagate before the ES call - catch it here too.
        # Also feed the per-process Prometheus counters so /metrics reflects this
        # run — the synth-first pipeline is the DEFAULT path, and without this the
        # /metrics counters stay frozen at 0 in production (mirrors the legacy
        # investigate() _audit).
        try:
            await metrics.get_metrics().record_event(ev.kind, ev.payload)
        except Exception as e:
            _LOGGER.warning("metrics record failed (kind=%s): %s", ev.kind, e)
        if ctx.audit is None:
            return
        try:
            await ctx.audit.log_kind(session_id, ev.kind, ev.payload)
        except Exception as e:  # audit must never crash the investigation
            _LOGGER.warning("audit log_kind failed: %s", e)

    def _usage_ev(round_num: int, run_result: Any) -> StepEvent | None:
        """Build a ``usage`` event from a pydantic_ai result.

        The synth-first pipeline previously emitted NO usage events (only
        the legacy investigate() path did), so the UI's token KPI /
        sparkline / context meter stayed dead at 0. Mirror the legacy
        `_build_usage_event` shape so the panel populates.
        """
        try:
            u = run_result.usage()
        except Exception:
            return None
        return _ev(
            "usage",
            {
                "phase": "synthesizer",
                "round": round_num,
                "tool_calls": u.tool_calls,
                "requests": u.requests,
                "input_tokens": u.input_tokens,
                "output_tokens": u.output_tokens,
                "total_tokens": u.total_tokens,
            },
        )

    def _reasoning_ev(round_num: int, run_result: Any) -> StepEvent | None:
        """``model_response`` event carrying the synthesizer's reasoning trace.

        The loop's investigator turns already stream model_response via
        ``_walk_message``; the synthesizer ``agent.run`` calls did not, so a
        round-1/round-2-settled investigation had an empty "Model reasoning"
        panel. None when the run produced no trace — no event is emitted.
        Called ONLY for the primary/final synthesis runs, never for the
        self-consistency extra samples.
        """
        payload = _synth_reasoning_payload(run_result)
        if payload is None:
            return None
        if guard is not None:
            # The synthesizer thought in LABEL space (its inputs were
            # sanitized) — restore real identifiers before the trace is
            # stored/displayed so the reasoning panel reads like the rest of
            # the investigation. Local storage only, never egress.
            payload = guard.desanitize_obj(payload)
        return _ev("model_response", {**payload, "phase": "synthesizer", "round": round_num})

    async def _emit_egress_blocked(
        phase: str, exc: EgressResidueError
    ) -> AsyncGenerator[StepEvent, None]:
        """Audit + stream a fail-closed egress block into the timeline.

        Yields (and audits) an ``egress_blocked`` event carrying ONLY the
        leaked-identifier COUNT + the call site — NEVER the leaked values
        (logging them would defect on the whole point of the block) — then the
        paired ``error`` event, so the block renders in the timeline exactly like
        every other synth-failure path. Best-effort: a failed audit index must
        never turn a blocked egress into an actual egress. Drive it with
        ``async for ev in _emit_egress_blocked(...): yield ev``.
        """
        block_ev = _ev("egress_blocked", {"phase": phase, "leaked_count": len(exc.leaked)})
        await _audit(block_ev)
        yield block_ev
        err_ev = _ev("error", _error_payload(exc, phase=phase, round_num=0))
        await _audit(err_ev)
        yield err_ev

    yield _ev("session_start", {"alert_id": alert_id, "pipeline": "synth_first"})

    # Resolve the effective internal-identifier set ONCE per investigation
    # (env-config union active detected/manual identifiers, minus muted). Used
    # for BOTH internal-IP classification (``.cidrs`` → the targeted downgrades /
    # post-validator below) and the Oracle egress sanitizer (``.suffixes`` /
    # ``.hosts`` at the adjudication call). ``None`` ⇒ no DB on ctx (CLI / eval /
    # tests) or a resolution failure → classification falls back to
    # ``settings.internal_cidrs`` and redaction to the raw settings tuples
    # (behavior unchanged). With no active ``cidr`` rows the effective cidrs ==
    # ``settings.internal_cidrs``, so classification is byte-identical to today.
    effective_idents = await _resolve_effective_identifiers(ctx)
    classification_cidrs = _classification_cidrs(ctx, effective_idents)

    # ----- Cloud-egress guard for the ANALYST model path (opt-in) -----
    # When analyst_cloud_redaction is on, everything sent to the analyst model
    # below (enriched context, prompts, tool results — the toolset wraps tools
    # via _guarded at registration) is redacted with ONE per-run label mapping,
    # and every model output is label-restored where it lands. `is True` (not
    # truthiness) so a non-Settings test double can never flip redaction on.
    if ctx.settings.analyst_cloud_redaction is True and ctx.egress_guard is None:
        if effective_idents is not None:
            # Reuse the effective identifier set already resolved above —
            # avoids a second DB round-trip and guarantees the guard redacts
            # with exactly the same host/suffix set the classifier uses.
            ctx.egress_guard = EgressGuard(
                extra_hosts=effective_idents.hosts,
                extra_suffixes=effective_idents.suffixes,
            )
        else:
            # No DB on ctx (CLI / eval / tests) or resolution failed —
            # env-only identifiers, same fallback as the Oracle path.
            ctx.egress_guard = await EgressGuard.for_settings(ctx.settings)
    guard = ctx.egress_guard
    if guard is not None and focus_hint:
        # focus_hint carries prior open questions (real host/IP text from a
        # stored report) and is woven into every seed prompt below.
        focus_hint = guard.sanitize_text(focus_hint)

    # ----- Phase A: rich precompute -----
    enrichment_ctx = EnrichmentContext(
        blocklist=ctx.blocklist,
        maxmind=ctx.maxmind,
        cloud=ctx.cloud,
    )
    try:
        enriched = await get_enriched_alert_context(
            alert_id,
            elastic=ctx.elastic,
            settings=ctx.settings,
            enrichment=enrichment_ctx,
            misp=ctx.misp,
            include_synth=ctx.include_synth,
            # Thread the effective CIDR set (settings.internal_cidrs union active
            # 'cidr' rows minus muted, resolved once above) into Phase-A enrichment
            # so an activated CIDR marks hosts internal here too — consistent
            # with the ICMP-downgrade classification path. No active cidr rows /
            # no DB ⇒ classification_cidrs == settings.internal_cidrs (unchanged).
            internal_cidrs=classification_cidrs,
        )
    except Exception as e:
        err_ev = _ev("error", _error_payload(e, phase="prefetch", round_num=0))
        await _audit(err_ev)
        yield err_ev
        return
    enriched_ev = _ev("enriched_alert_context", enriched.model_dump(mode="json"))
    await _audit(enriched_ev)
    yield enriched_ev

    # ----- Phase B: decision template -----
    candidate = match_decision_template(enriched)
    template_ev = _ev(
        "decision_template_match",
        {
            "matched": candidate is not None,
            "template_id": candidate.template_id if candidate else None,
            "verdict": candidate.verdict if candidate else None,
            "confidence": candidate.confidence if candidate else None,
            "rationale": candidate.rationale if candidate else None,
        },
    )
    await _audit(template_ev)
    yield template_ev

    # ----- Phase C: synth round 1 -----
    # Speed: when the case will investigate REGARDLESS of the round-1 verdict
    # (malware/exploit signal or external-reputation template), skip the round-1
    # synth entirely — it's a ~10-15s HEAVY call whose verdict the loop discards.
    #
    # Context budgeting: the enriched context feeds EVERY model call below
    # (round-1 synth, the investigation loop, round-2 synth). If it exceeds the
    # analyst model's input budget (window discovered from the gateway, or the
    # model_context_window_tokens override), drop the oldest pivot events now —
    # a ContextWindowExceeded later burns the whole run into a fallback verdict.
    _ctx_window = await context_budget.resolve_model_window(ctx.settings)
    enriched_json, _trim_note = context_budget.trim_enriched_for_budget(
        enriched, context_budget.input_budget_tokens(_ctx_window)
    )
    if guard is not None:
        # EGRESS BOUNDARY: enriched_json feeds every analyst-model call below
        # (round-1 synth, the investigation-loop prompt, round-2 synth) —
        # sanitize it ONCE here, after trimming, so all consumers share the
        # same labeled text. The raw `enriched_alert_context` event above is
        # deliberately untouched: it is local storage, never egress.
        enriched_json = guard.sanitize_text(enriched_json)
    if _trim_note is not None:
        trim_ev = _ev("context_trimmed", _trim_note)
        await _audit(trim_ev)
        yield trim_ev
    definitely_investigate = ctx.settings.investigate_when_unsure and _definitely_investigate(
        enriched, candidate
    )
    round1_ok = False
    # (agent, user_message, usage_limits|None) describing how to RE-RUN the
    # final verdict synthesis — consumed by the flag-gated self-consistency
    # vote below. Set at each site whose output becomes ``triage_final``;
    # cleared (None) on every fallback path so a vote never re-runs a call
    # that just failed.
    final_synth_rerun: tuple[Any, str, Any] | None = None
    if definitely_investigate:
        triage_round1 = _round1_skipped_report(alert_id)
        skip_ev = _ev("synth_round1_skipped", {"reason": "definitely_investigate"})
        await _audit(skip_ev)
        yield skip_ev
    else:
        materialized = _materialize_prefetch_evidence(enriched)
        if guard is not None:
            # list[str] of evidence bullets built from RAW enriched fields —
            # redact before it joins the synth prompt (labels stay stable
            # because the guard's mapping is shared with enriched_json above).
            materialized = guard.sanitize_obj(materialized)
        # ----- E4.2: deterministic prior-outcome memory (round-1 ONLY) -----
        # Flag-gated context block: the most relevant PRIOR verdicts for this
        # alert's (rule, src, dest), fetched with one indexed SQL query — no
        # embeddings, no extra model calls. Fail-SOFT end to end: no DB on ctx
        # (CLI / eval / tests), no rule name, a store error, or zero matches
        # all just skip the block — memory must never kill an investigation.
        # ``is True`` (not truthiness) so a non-Settings test double can never
        # flip it on. The loop / round-2 / retask prompts are deliberately
        # untouched: they reason over GATHERED evidence, where a prior verdict
        # would compete with real tool results.
        prior_outcomes_block: str | None = None
        prior_digests: list[dict[str, Any]] = []
        if (
            getattr(ctx.settings, "memory_enabled", False) is True
            and ctx.db_sessionmaker is not None
            and enriched.alert.rule_name
        ):
            from soc_ai.store import investigations as investigations_store  # noqa: PLC0415

            try:
                async with ctx.db_sessionmaker() as mem_db:
                    prior_digests = await investigations_store.prior_outcomes(
                        mem_db,
                        rule_name=enriched.alert.rule_name,
                        src_ip=enriched.alert.source_ip,
                        dest_ip=enriched.alert.destination_ip,
                        # This run's own row is still status='running' (finalize
                        # lands after the stream ends) and prior_outcomes is
                        # complete-only, so it can never self-match — there is
                        # no row id to exclude from inside the pipeline.
                        exclude_id=None,
                        window_days=ctx.settings.memory_window_days,
                        limit=ctx.settings.memory_max_items,
                    )
            except Exception as e:
                _LOGGER.warning("prior-outcome memory lookup failed (skipping block): %s", e)
                prior_digests = []
        if prior_digests:
            prior_outcomes_block = _format_prior_outcomes_block(prior_digests)
            # Timeline transparency: record WHAT was recalled — ids/verdicts/
            # tier only, never rationale text (the digests live in the prompt;
            # the event payload stays light). Emitted ONLY when a non-empty
            # block is actually injected.
            mem_ev = _ev(
                "prior_outcomes",
                {
                    "count": len(prior_digests),
                    "window_days": ctx.settings.memory_window_days,
                    "items": [
                        {
                            "id": d.get("id"),
                            "verdict": d.get("verdict"),
                            "matched_on": d.get("matched_on"),
                        }
                        for d in prior_digests
                    ],
                },
            )
            await _audit(mem_ev)
            yield mem_ev
        # ----- Chat-transcript memory (round-1 ONLY, sub-switch of E4.2) -----
        # Operator intent, verbatim rule: past chat transcripts are CONTEXT,
        # never evidence — the user is not always right. Same fail-soft +
        # same window/limit knobs as the priors; gated on memory_enabled AND
        # memory_include_chat (both `is True` so a test double can't flip it).
        chat_memory_block: str | None = None
        chat_digests: list[dict[str, Any]] = []
        if (
            getattr(ctx.settings, "memory_enabled", False) is True
            and getattr(ctx.settings, "memory_include_chat", False) is True
            and ctx.db_sessionmaker is not None
        ):
            from soc_ai.store import chat_memory as chat_memory_store  # noqa: PLC0415

            chat_terms = _chat_memory_query_terms(
                enriched.alert.rule_name,
                enriched.alert.source_ip,
                enriched.alert.destination_ip,
            )
            if chat_terms:
                try:
                    async with ctx.db_sessionmaker() as mem_db:
                        chat_digests = await chat_memory_store.relevant_chat_snippets(
                            mem_db,
                            query_terms=chat_terms,
                            # This run has no chat thread yet (chats attach to
                            # COMPLETED investigations), so there is no own
                            # thread to exclude from inside the pipeline —
                            # mirrors the prior_outcomes exclude_id=None note.
                            exclude_thread=None,
                            window_days=ctx.settings.memory_window_days,
                            limit=ctx.settings.memory_max_items,
                        )
                except Exception as e:
                    _LOGGER.warning("chat-transcript memory lookup failed (skipping): %s", e)
                    chat_digests = []
        if chat_digests:
            chat_memory_block = _format_chat_memory_block(chat_digests)
            # Sibling of the prior_outcomes event, same light-payload rule:
            # source/thread/role only — snippet text lives in the prompt,
            # never in the timeline payload. Emitted ONLY on injection.
            chat_ev = _ev(
                "chat_memory",
                {
                    "count": len(chat_digests),
                    "window_days": ctx.settings.memory_window_days,
                    "items": [
                        {
                            "source": d.get("source"),
                            "thread_id": d.get("thread_id"),
                            "role": d.get("role"),
                        }
                        for d in chat_digests
                    ],
                },
            )
            await _audit(chat_ev)
            yield chat_ev
        user_msg_round1 = build_synth_first_user_message(
            alert_id=alert_id,
            enriched_ctx_json=enriched_json,
            materialized_evidence=materialized,
            candidate=candidate,
            focus_hint=focus_hint,
            # Included BEFORE the final sanitize sweep + _guard_egress below,
            # so prior rationale text is redacted on the cloud-analyst path.
            prior_outcomes_block=prior_outcomes_block,
            # Same egress contract as the priors block (composed pre-sweep).
            chat_memory_block=chat_memory_block,
        )
        if guard is not None:
            # Final sweep over the COMPOSED message — catches the decision-
            # template candidate block (rationale/cited_evidence carry real
            # values) without mutating the candidate object itself, which the
            # post-synth gates must later compare against RAW enriched values.
            # Re-sanitizing the already-labeled parts is a no-op (labels don't
            # match any redaction pattern).
            user_msg_round1 = guard.sanitize_text(user_msg_round1)
        synth_agent = build_synth_first_agent(
            build_synthesizer_model(ctx.settings, temperature=ctx.settings.synthesizer_temperature)
        )
        # Captures the run's message history even when the run raises — on a
        # schema-retry exhaustion the RetryPromptParts in here are the only
        # record of WHY each attempt failed (the prod 2026-07-17/18 fallbacks
        # recorded just "Exceeded maximum output retries (3)" with hint=null).
        r1_captured: list[Any] = []
        try:
            # Fail-closed residue sweep on the FINAL composed outbound message
            # (after every sanitize_text above): if fail-closed is on and an
            # internal identifier survived, this raises BEFORE the model call so
            # the payload never egresses. No-op when off / no guard.
            user_msg_round1 = _guard_egress(guard, user_msg_round1, ctx.settings)
            with capture_run_messages() as r1_captured:
                async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                    synth_result_round1 = await synth_agent.run(user_msg_round1)
        except EgressResidueError as e:
            # Blocked egress: the model was NOT called. Audit the block (count
            # only) + emit the paired error event, then land the SAME honest
            # pipeline-fallback (E1.2) a synth crash would — the run couldn't
            # safely proceed, so it IS a pipeline error.
            async for ev in _emit_egress_blocked("synth_first_round1", e):
                yield ev
            triage_round1 = _synth_failure_fallback_report(alert_id, "egress_blocked", e)
            await metrics.get_metrics().record_event("fallback_verdict", {})
        except Exception as e:
            # Emit error event for the audit trail, then
            # fall through with a fallback NMI TriageReport so the row in
            # index.jsonl is structured (not verdict=None). The post-validators
            # + triage_report emission below run uniformly on the fallback.
            r1_causes = _retry_causes_from_messages(r1_captured)
            err_ev = _ev(
                "error",
                _error_payload(e, phase="synth_first_round1", round_num=1, retry_causes=r1_causes),
            )
            await _audit(err_ev)
            yield err_ev
            triage_round1 = _synth_failure_fallback_report(
                alert_id, "synth_first_round1", e, retry_causes=r1_causes
            )
            await metrics.get_metrics().record_event("fallback_verdict", {})
        else:
            triage_round1 = synth_result_round1.output
            if guard is not None:
                # Restore real identifiers AT THE ASSIGNMENT SOURCE (not at a
                # later convergence point): the desanitized report drives
                # _should_investigate's evidence checks AND Phase-D dispatch
                # (gap_for_investigator.tool_args must hit Elasticsearch with
                # real values, not labels). Egress re-sanitizes downstream.
                triage_round1 = _desanitize_report(triage_round1, guard)
            round1_ok = True
            # Round-1 IS the final synthesis when neither the loop nor Phase D
            # supersedes it below (each overwrites/clears this on its own path).
            final_synth_rerun = (synth_agent, user_msg_round1, None)
            # Surface the synthesizer's thinking — without this a round-1-settled
            # run stored NO model_response event and the reasoning panel was empty.
            r1_reasoning_ev = _reasoning_ev(1, synth_result_round1)
            if r1_reasoning_ev is not None:
                await _audit(r1_reasoning_ev)
                yield r1_reasoning_ev
            usage_ev = _usage_ev(1, synth_result_round1)
            if usage_ev is not None:
                await _audit(usage_ev)
                yield usage_ev

    triage_final = triage_round1

    # ----- Bounded investigation loop (Theme-1 Task 1) -----
    # The Phase C synth is a NO-tools structured-output guess that
    # rationalizes the prefetch. When its verdict isn't evidence-backed and
    # the alert isn't trivially benign, run a REAL investigation loop: the
    # tool-bound investigator (on the HEAVY model) chooses which read tools
    # to call, then the synthesizer concludes from the gathered transcript.
    # This replaces the zero-tool synthesis that scored 1-4/9 on synth-TP
    # (confidently clearing a Cobalt Strike beacon). Reversible via the
    # investigate_when_unsure flag.
    ran_investigation_loop = False
    loop_messages: list[Any] | None = None
    # fast_triage_enabled=False forces the tool-driven loop regardless of how
    # confident round-1 was ("agent does agent things"): deeper but slower.
    # `deep` is the same override scoped to THIS run (the analyst's deep re-run).
    force_investigate = deep or not ctx.settings.fast_triage_enabled
    if force_investigate or (
        ctx.settings.investigate_when_unsure
        and (
            definitely_investigate
            or (round1_ok and _should_investigate(triage_round1, enriched, candidate))
        )
    ):
        ran_investigation_loop = True
        if definitely_investigate:
            loop_reason = "definitely_investigate"
        elif deep:
            loop_reason = "deep_rerun"
        elif force_investigate:
            loop_reason = "fast_triage_disabled"
        else:
            loop_reason = "verdict_not_evidence_backed"
        loop_ev = _ev(
            "investigation_loop_entered",
            {
                "reason": loop_reason,
                "round1_verdict": None if definitely_investigate else triage_round1.verdict,
                "round1_confidence": None if definitely_investigate else triage_round1.confidence,
            },
        )
        await _audit(loop_ev)
        yield loop_ev

        # Reset per-investigation tool state so the investigator's tools
        # anchor on THIS alert (mirrors the legacy investigate() prefetch
        # block): time anchor, dedup tracker, prefetched community_ids.
        ctx.default_time_anchor = enriched.alert.timestamp
        ctx.dedup = _DedupTracker()
        ctx.prefetched_community_ids = {
            cid
            for cid in (
                getattr(enriched.alert, "network_community_id", None),
                *(getattr(e, "network_community_id", None) for e in enriched.community_id_events),
            )
            if isinstance(cid, str) and cid
        }

        loop_usage_limits = UsageLimits(
            request_limit=ctx.settings.agent_request_limit,
            tool_calls_limit=ctx.settings.agent_tool_calls_limit,
        )
        # HEAVY model (build_synthesizer_model), NOT the fast investigator
        # model — the loop must reason on the strong model. The Nemotron
        # profile on the heavy builder already carries the tool_choice
        # workaround so tool-calling works. Moderate temperature: keep some
        # pivot exploration while staying broadly reproducible.
        investigator = build_investigator(
            build_synthesizer_model(
                ctx.settings, temperature=ctx.settings.investigator_temperature
            ),
            ctx,
        )
        inv_user_msg = _format_investigator_prompt(
            alert_id, enriched_json, focus_hint=focus_hint
        ) + await inventory_prompt_block(ctx.elastic, ctx.settings)
        if guard is not None:
            # enriched_json/focus_hint are already labeled; this sweep covers
            # the dataset-inventory block (grid host/dataset names) so the
            # WHOLE investigator prompt crosses the egress boundary sanitized.
            inv_user_msg = guard.sanitize_text(inv_user_msg)
        inv_result: Any = None
        # The labeled node messages streamed so far — the budget-partial
        # synthesis replays these when the loop is cut short (mirrors the hunt
        # runner's `gathered`).
        loop_gathered: list[Any] = []
        budget_exc: BaseException | None = None
        # Set when the fail-closed residue sweep blocks the loop's first model
        # call: routes the budget-boundary convergence below to the HONEST
        # pipeline-fallback (E1.2) instead of preserving a round-1 verdict, so a
        # blocked egress renders as a pipeline error.
        egress_blocked_exc: EgressResidueError | None = None
        try:
            # Fail-closed residue sweep on the FINAL composed investigator prompt
            # BEFORE the loop's first model call — if an internal identifier
            # survived, this raises so the payload never reaches the model.
            inv_user_msg = _guard_egress(guard, inv_user_msg, ctx.settings)
            # Stream the run NODE-BY-NODE via agent.iter() so each tool_call /
            # tool_result / model_response lands in the timeline THE MOMENT it
            # happens (the recorder persists every event immediately, FLUSH_EVERY=1)
            # instead of replaying the whole investigation in one burst at the end.
            # CallToolsNode carries the model's response (text + tool requests);
            # the following ModelRequestNode carries that step's tool results.
            node_msg: Any = None
            async with investigator.iter(inv_user_msg, usage_limits=loop_usage_limits) as inv_run:
                # Advance NODE-BY-NODE with a PER-TURN wall-clock timeout on each
                # iterator step (the model-run await that produces the next node),
                # NOT one timeout spanning the whole multi-turn loop. Event
                # projection + yielding stays outside the timeout so streaming is
                # unchanged. A per-turn TimeoutError propagates to the same
                # except-handlers below (error event + honest stop) as any other
                # investigator failure.
                node_iter = inv_run.__aiter__()
                while True:
                    async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                        try:
                            node = await node_iter.__anext__()
                        except StopAsyncIteration:
                            break
                    # CallToolsNode carries the model's response (text + tool
                    # requests); the following ModelRequestNode carries that
                    # step's tool results. Detect by attribute so the message is
                    # projected the moment its node arrives.
                    node_msg = getattr(node, "model_response", None)
                    if node_msg is None:
                        node_msg = getattr(node, "request", None)
                    if node_msg is not None:
                        loop_gathered.append(node_msg)
                        async for ev in _walk_message(
                            node_msg, _ev, phase="investigation_loop", round_num=1
                        ):
                            # The loop converses in label space; restore real
                            # values in the streamed timeline events (tool
                            # calls/results, reasoning traces) — they are
                            # local storage/display, never egress.
                            out_ev = (
                                ev
                                if guard is None
                                else ev.model_copy(
                                    update={"payload": guard.desanitize_obj(ev.payload)}
                                )
                            )
                            await _audit(out_ev)
                            yield out_ev
            inv_result = inv_run.result
        except asyncio.CancelledError:
            raise  # cooperative cancel — propagate, never swallow
        except EgressResidueError as e:
            # Fail-closed block on the investigator prompt — the model was NEVER
            # called. Audit the block (count only) + emit the paired error event,
            # then route the convergence below to the HONEST pipeline-fallback.
            async for ev in _emit_egress_blocked("investigation_loop", e):
                yield ev
            egress_blocked_exc = e
        except UsageLimitExceeded as e:
            # Budget exhaustion is an EXPECTED outcome of a thorough investigation,
            # NOT an infrastructure failure. The tool calls + model responses
            # already streamed live above, so don't discard them with status=error
            # and no verdict: land the round-1 verdict via the same fallback used
            # when the loop-synth crashes. (This is the "conclude gracefully at the
            # budget boundary" behaviour, vs. the old "error out" one.)
            _LOGGER.warning("investigation loop hit budget limit: %s", e)
            err_ev = _ev("error", _error_payload(e, phase="investigation_loop_budget", round_num=1))
            await _audit(err_ev)
            yield err_ev
            budget_exc = e
        except TimeoutError as e:
            # A per-turn wall-clock timeout (investigation_turn_timeout_s) fired
            # while advancing the investigator on a slow stack. The evidence
            # gathered before the hung turn already streamed live, so conclude
            # GRACEFULLY with the round-1 verdict via the same budget-boundary
            # fallback as UsageLimitExceeded — do NOT discard the run with
            # status=error. (Mirrors the hunt runner's timeout→partial-report
            # behaviour; a slow stack is the expected trigger, not an infra fault.)
            _LOGGER.warning("investigation loop turn timed out: %s", e)
            err_ev = _ev(
                "error", _error_payload(e, phase="investigation_loop_timeout", round_num=1)
            )
            await _audit(err_ev)
            yield err_ev
            budget_exc = e
        except BaseException as e:
            # The investigator could not gather evidence — most often a transient
            # LLM-gateway connection drop (the openai client has already retried
            # litellm_max_retries times). Do NOT fabricate a needs_more_info
            # verdict from an empty transcript: that reads as if the agent
            # investigated and was unsure. Surface an honest error and stop — the
            # recorder marks the run 'error' (retryable), not a fake verdict.
            _LOGGER.exception("investigation loop investigator run failed")
            err_ev = _ev("error", _error_payload(e, phase="investigation_loop", round_num=1))
            await _audit(err_ev)
            yield err_ev
            return

        if egress_blocked_exc is not None:
            # A blocked egress is a pipeline error (the run couldn't safely
            # proceed) — land the HONEST pipeline-fallback (E1.2), NOT the
            # round-1-preserving budget fallback. loop_messages stays None.
            triage_final = _synth_failure_fallback_report(
                alert_id, "egress_blocked", egress_blocked_exc
            )
            final_synth_rerun = None  # fallback verdict — never vote on it
            await metrics.get_metrics().record_event("fallback_verdict", {})
        elif budget_exc is not None:
            # A settled round-1 verdict stands (evidence gathered pre-budget is
            # preserved in the streamed timeline). With NO settled round-1
            # (definitely_investigate skipped it, or round-1 was itself NMI)
            # the old path discarded every gathered tool result into a generic
            # 0.3 fallback — the 2026-07-18 prod BPFDoor run burned 25 tool
            # calls and landed nothing. Now: synthesize a PARTIAL verdict from
            # the gathered history (mirrors the hunt runner's budget path);
            # the honest fallback remains the last resort.
            partial_report: Any = None
            repaired_history: list[Any] = []
            settled_r1 = getattr(triage_round1, "verdict", None) in (
                "true_positive",
                "false_positive",
            )
            if not settled_r1 and loop_gathered:
                try:
                    partial_report, repaired_history = await _synthesize_partial_triage(
                        ctx.settings, guard, loop_gathered
                    )
                except asyncio.CancelledError:
                    raise  # cooperative cancel — propagate, never swallow
                except EgressResidueError as e:
                    async for ev in _emit_egress_blocked("investigation_loop_partial_synth", e):
                        yield ev
                except BaseException as e:
                    err_ev = _ev(
                        "error",
                        _error_payload(e, phase="investigation_loop_partial_synth", round_num=1),
                    )
                    await _audit(err_ev)
                    yield err_ev
            if partial_report is not None:
                triage_final = partial_report.model_copy(
                    update={
                        # A cut-short investigation must not assert high
                        # confidence (mirrors the hunt humility clamp).
                        "confidence": min(partial_report.confidence, 0.6),
                        "summary": (partial_report.summary or "")
                        + " (Investigation stopped at the tool-call budget; "
                        "verdict synthesized from the evidence gathered before "
                        "the cutoff.)",
                        # Never recurse into Phase D off a budget-cut synthesis.
                        "gap_for_investigator": None,
                    }
                )
                if guard is not None:
                    # Assignment-source restore — the gates below compare this
                    # report's text against RAW enriched/pivot values.
                    triage_final = _desanitize_report(triage_final, guard)
                # The repaired history feeds the downstream evidence/citation
                # gates: the partial verdict earns the loop exemption only from
                # tool results that actually landed (synthetic closures are
                # error-shaped and never counted).
                loop_messages = repaired_history
                final_synth_rerun = None  # budget-cut verdict — never vote on it
            else:
                triage_final = _round2_failure_fallback(alert_id, triage_round1, budget_exc)
                final_synth_rerun = None  # fallback verdict — never vote on it
                await metrics.get_metrics().record_event("fallback_verdict", {})
        elif inv_result is None:
            # The agent run ended without a final result (no End node reached, and
            # no exception raised). Emit an honest error instead of crashing with an
            # UnboundLocalError on loop_transcript below.
            err_ev = _ev(
                "error",
                _error_payload(
                    RuntimeError("investigation loop returned no result"),
                    phase="investigation_loop",
                    round_num=1,
                ),
            )
            await _audit(err_ev)
            yield err_ev
            return
        else:
            # Events already streamed live above; land the transcript + usage, and
            # keep the full message history for the downstream citation/evidence
            # check (loop_messages feeds _is_evidence_backed / targeted-cite check).
            loop_transcript = inv_result.output
            loop_messages = inv_result.all_messages()
            inv_usage_ev = _usage_ev(1, inv_result)
            if inv_usage_ev is not None:
                await _audit(inv_usage_ev)
                yield inv_usage_ev

            transcript_payload = {
                "round": 1,
                "phase": "investigation_loop",
                **loop_transcript.model_dump(mode="json"),
            }
            if guard is not None:
                # Stored/displayed copy gets real values; loop_transcript
                # itself stays in label space — it feeds the loop-synth
                # message below, which crosses the egress boundary.
                transcript_payload = guard.desanitize_obj(transcript_payload)
            transcript_ev = _ev("investigation_transcript", transcript_payload)
            await _audit(transcript_ev)
            yield transcript_ev

            # Synthesize over the gathered evidence — REUSE the legacy
            # synthesizer-over-transcript (build_synthesizer + the transcript
            # user-message formatter). HEAVY model, no tools.
            loop_synth = build_synthesizer(
                build_synthesizer_model(
                    ctx.settings, temperature=ctx.settings.synthesizer_temperature
                )
            )
            loop_synth_msg = _format_transcript_for_synthesizer(
                alert_id, [loop_transcript], candidate=candidate
            )
            if guard is not None:
                # The transcript is already in label space (the loop ran over
                # sanitized inputs/tool results); this sweep covers the RAW
                # candidate block woven into the synthesizer message.
                loop_synth_msg = guard.sanitize_text(loop_synth_msg)
            # Same capture as round-1: on schema-retry exhaustion the causes
            # live only in the run's RetryPromptParts.
            ls_captured: list[Any] = []
            try:
                # Fail-closed residue sweep on the FINAL composed loop-synth
                # message before the model call — raises BEFORE egress on residue.
                loop_synth_msg = _guard_egress(guard, loop_synth_msg, ctx.settings)
                with capture_run_messages() as ls_captured:
                    async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                        loop_synth_result = await loop_synth.run(
                            loop_synth_msg,
                            usage_limits=loop_usage_limits,
                        )
            except asyncio.CancelledError:
                raise  # cooperative cancel — propagate, never swallow
            except EgressResidueError as e:
                # Blocked egress: the model was NOT called. Audit the block (count
                # only) + emit the paired error event, then land the HONEST
                # pipeline-fallback (E1.2) — a blocked run IS a pipeline error.
                async for ev in _emit_egress_blocked("investigation_loop_synth", e):
                    yield ev
                triage_final = _synth_failure_fallback_report(alert_id, "egress_blocked", e)
                final_synth_rerun = None  # fallback verdict — never vote on it
                await metrics.get_metrics().record_event("fallback_verdict", {})
            except BaseException as e:
                # A BaseException here (e.g. a gateway timeout/cancel that escaped
                # the client retries) previously propagated past the recorder,
                # landing status=error with NO verdict + no recorded error event.
                # Catch it, record the error, and DON'T discard the round-1 verdict.
                ls_causes = _retry_causes_from_messages(ls_captured)
                err_ev = _ev(
                    "error",
                    _error_payload(
                        e,
                        phase="investigation_loop_synth",
                        round_num=2,
                        retry_causes=ls_causes,
                    ),
                )
                await _audit(err_ev)
                yield err_ev
                triage_final = _round2_failure_fallback(alert_id, triage_round1, e, ls_causes)
                final_synth_rerun = None  # fallback verdict — never vote on it
                await metrics.get_metrics().record_event("fallback_verdict", {})
            else:
                triage_final = loop_synth_result.output
                if guard is not None:
                    # Assignment-source restore — the gates below compare this
                    # report's text against RAW enriched/pivot values.
                    triage_final = _desanitize_report(triage_final, guard)
                # The loop synth is now the final synthesis (supersedes round-1).
                final_synth_rerun = (loop_synth, loop_synth_msg, loop_usage_limits)
                # The loop's investigator turns streamed their own reasoning via
                # _walk_message above; this covers only the concluding synth run.
                loop_reasoning_ev = _reasoning_ev(2, loop_synth_result)
                if loop_reasoning_ev is not None:
                    await _audit(loop_reasoning_ev)
                    yield loop_reasoning_ev
                loop_synth_usage_ev = _usage_ev(2, loop_synth_result)
                if loop_synth_usage_ev is not None:
                    await _audit(loop_synth_usage_ev)
                    yield loop_synth_usage_ev
                # The loop replaces Phase D — strip any gap so we don't also
                # dispatch a single-tool targeted round on top of it.
                if triage_final.gap_for_investigator is not None:
                    triage_final = triage_final.model_copy(update={"gap_for_investigator": None})

    # ----- Phase D (optional): targeted investigator -----
    # Skipped when the investigation loop ran — the loop already gathered
    # evidence agentically (it supersedes the deterministic targeted
    # dispatch). Bounded loop: up to ctx.settings.phase_d_max_rounds
    # gap→dispatch→re-synthesize rounds (default 1 = the original single
    # dispatch). A non-final round's message allows the synth to chain ONE
    # more gap (e.g. t_get_event_raw -> t_decode_payload).
    targeted_result: dict[str, Any] | str | None = None
    # Tool name of the most recent dispatch whose result carried discriminating
    # data — feeds the post-validators' evidence exemption below.
    targeted_tool_with_data: str | None = None
    phase_d_synth_ok = False
    if not ran_investigation_loop and triage_round1.gap_for_investigator is not None:
        gap = triage_round1.gap_for_investigator
        current_report = triage_round1
        max_rounds = ctx.settings.phase_d_max_rounds
        for dispatch_round in range(1, max_rounds + 1):
            rounds_left = max_rounds - dispatch_round
            # Co-emit `retask` so eval/batch.py:read_retask_count
            # picks up Phase D dispatches. Without this the metric is
            # mathematically guaranteed 0 even when Phase D fires every alert.
            # retask precedes targeted_dispatch — semantic ordering: "agent asked
            # for more" then "here's the specific call".
            retask_ev = _ev(
                "retask",
                {
                    "reason": "phase_d_targeted_dispatch",
                    "tool_name": gap.tool_name,
                    "gap_question": gap.question,
                    "gap_why_this_matters": gap.why_this_matters,
                    "confidence": current_report.confidence,
                },
            )
            await _audit(retask_ev)
            yield retask_ev

            dispatch_ev = _ev(
                "targeted_dispatch",
                {
                    "question": gap.question,
                    "tool_name": gap.tool_name,
                    "tool_args": gap.tool_args,
                    "why_this_matters": gap.why_this_matters,
                },
            )
            await _audit(dispatch_ev)
            yield dispatch_ev

            targeted_result = await run_targeted_investigation(gap, ctx=ctx)
            targeted_result_ev = _ev(
                "targeted_tool_result",
                {"tool_name": gap.tool_name, "result": targeted_result},
            )
            await _audit(targeted_result_ev)
            yield targeted_result_ev
            # Only a SUCCESSFUL dispatch that returned DISCRIMINATING DATA
            # counts as evidence for the post-validators. An errored dispatch
            # (error string / tool error dict) OR an empty-but-non-error result
            # (zero OQL hits, internal IP with no blocklist/MISP hit) must NOT
            # exempt the hard evidence gate.
            if _targeted_result_has_data(targeted_result):
                targeted_tool_with_data = gap.tool_name

            # Re-synthesize with the targeted result. On a non-final round the
            # message permits ONE more gap; the final round demands closure.
            user_msg_round2 = build_synth_first_round2_user_message(
                alert_id=alert_id,
                enriched_ctx_json=enriched_json,
                materialized_evidence=materialized,
                candidate=candidate,
                round1_gap=gap,
                targeted_tool_result=targeted_result,
                focus_hint=focus_hint,
                allow_further_gap=rounds_left > 0,
            )
            if guard is not None:
                # The Phase-D dispatch ran with REAL args (the round-1 report
                # was desanitized at its assignment source) and returned a RAW
                # targeted_result — correct for the local targeted_tool_result
                # event above, but it and the gap text must be re-labeled
                # before this composed message crosses the egress boundary.
                user_msg_round2 = guard.sanitize_text(user_msg_round2)
            try:
                # Fail-closed residue sweep on the FINAL composed round-2 message
                # before the model call — raises BEFORE egress on residue.
                user_msg_round2 = _guard_egress(guard, user_msg_round2, ctx.settings)
                async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                    synth_result_round2 = await synth_agent.run(user_msg_round2)
            except asyncio.CancelledError:
                raise  # cooperative cancel — propagate, never swallow
            except EgressResidueError as e:
                # Blocked egress: the model was NOT called. Audit the block (count
                # only) + emit the paired error event, then land the HONEST
                # pipeline-fallback (E1.2) and stop dispatching — a blocked run IS
                # a pipeline error.
                async for ev in _emit_egress_blocked("synth_first_round2", e):
                    yield ev
                triage_final = _synth_failure_fallback_report(alert_id, "egress_blocked", e)
                final_synth_rerun = None  # fallback verdict — never vote on it
                await metrics.get_metrics().record_event("fallback_verdict", {})
                phase_d_synth_ok = False
                break
            except BaseException as e:
                # Emit a recorded error, then fall back to the round-1 verdict (or a
                # scoreable NMI) so the row is never a silent status=error.
                err_ev = _ev(
                    "error",
                    _error_payload(e, phase="synth_first_round2", round_num=dispatch_round + 1),
                )
                await _audit(err_ev)
                yield err_ev
                triage_final = _round2_failure_fallback(alert_id, triage_round1, e)
                final_synth_rerun = None  # fallback verdict — never vote on it
                await metrics.get_metrics().record_event("fallback_verdict", {})
                phase_d_synth_ok = False
                break
            else:
                phase_d_synth_ok = True
                triage_final = synth_result_round2.output
                if guard is not None:
                    # Assignment-source restore — a chained next-round gap's
                    # tool_args must dispatch with real values, and the gates
                    # compare against raw enriched values.
                    triage_final = _desanitize_report(triage_final, guard)
                # This synthesis is now the final one (supersedes the previous).
                final_synth_rerun = (synth_agent, user_msg_round2, None)
                r2_reasoning_ev = _reasoning_ev(dispatch_round + 1, synth_result_round2)
                if r2_reasoning_ev is not None:
                    await _audit(r2_reasoning_ev)
                    yield r2_reasoning_ev
                usage2_ev = _usage_ev(dispatch_round + 1, synth_result_round2)
                if usage2_ev is not None:
                    await _audit(usage2_ev)
                    yield usage2_ev
                if triage_final.gap_for_investigator is None:
                    break  # verdict settled — no further dispatch wanted
                current_report = triage_final
                gap = triage_final.gap_for_investigator
        # Defensive: enforce the dispatch budget — the FINAL round's synth must
        # NOT emit a gap. Fires only when the model ignored the final-round
        # closure instruction (never on the failure fallback above, whose
        # round-1-derived gap is left as-is, matching the pre-loop behavior).
        if phase_d_synth_ok and triage_final.gap_for_investigator is not None:
            triage_final = triage_final.model_copy(update={"gap_for_investigator": None})

    # ----- Self-consistency vote (flag-gated; OFF by default) -----
    # verdict_consistency_samples=1 (the default) skips this entirely: single
    # synthesis call, no vote, `inconclusive` never produced — byte-identical
    # to the pre-vote pipeline. When >1, re-run the SAME final synthesis
    # (same agent + prompt) N-1 more times and majority-vote the verdict
    # BEFORE the deterministic post-validators (the evidence/citation guards
    # below still apply to the voted report). Defensive: a failed sample is
    # dropped; fewer than 2 surviving samples ⇒ no vote (the single available
    # report stands). Fallback-produced verdicts never vote (rerun is None).
    vote_samples = int(getattr(ctx.settings, "verdict_consistency_samples", 1) or 1)
    if vote_samples > 1 and final_synth_rerun is not None:
        sample_agent, sample_msg, sample_limits = final_synth_rerun
        sample_reports: list[TriageReport] = [triage_final]
        for _ in range(vote_samples - 1):
            try:
                async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                    if sample_limits is not None:
                        extra_result = await sample_agent.run(
                            sample_msg, usage_limits=sample_limits
                        )
                    else:
                        extra_result = await sample_agent.run(sample_msg)
            except asyncio.CancelledError:
                raise  # cooperative cancel — propagate, never swallow
            except BaseException as e:
                _LOGGER.warning("self-consistency sample failed (dropped): %s", e)
                continue
            extra_report = extra_result.output
            if guard is not None:
                # Samples re-ran the SAME already-sanitized message, so their
                # outputs are labeled too; restore before the vote so a winning
                # sample's summary/citations land in real-value space.
                extra_report = _desanitize_report(extra_report, guard)
            # Samples never trigger Phase D — strip any gap defensively.
            if extra_report.gap_for_investigator is not None:
                extra_report = extra_report.model_copy(update={"gap_for_investigator": None})
            sample_reports.append(extra_report)
        if len(sample_reports) >= 2:
            voted_verdict, voted_conf, vote_note = _self_consistency_vote(sample_reports)
            vote_tally = dict(Counter(r.verdict for r in sample_reports))
            # Representative sample: first report matching the winning verdict;
            # for an inconclusive split, the highest-confidence sample (its
            # summary/citations/actions are kept — only verdict+confidence are
            # overwritten by the vote, and the note is appended).
            if voted_verdict == "inconclusive":
                representative = max(sample_reports, key=lambda r: r.confidence)
            else:
                representative = next(r for r in sample_reports if r.verdict == voted_verdict)
            triage_final = representative.model_copy(
                update={
                    "verdict": voted_verdict,
                    "confidence": voted_conf,
                    "summary": f"{representative.summary}\n\n[{vote_note}]",
                }
            )
            vote_ev = _ev(
                "self_consistency_vote",
                {
                    "samples": len(sample_reports),
                    "tally": vote_tally,
                    "chosen_verdict": voted_verdict,
                    "note": vote_note,
                },
            )
            await _audit(vote_ev)
            yield vote_ev

    # ----- Post-synth validators -----
    # Mirror the legacy post-synth validator chain: citation validation,
    # citation cap, and verdict floor rewrite. Coverage cap is NOT
    # applied — no investigator ran, so there's no tool-call ledger.
    # When the investigation loop ran, it supersedes Phase D: thread the
    # loop's real message history into citation resolution (so tool/pivot
    # citations resolve against actual ToolCallParts) and treat it like an
    # investigator round — gathered evidence legitimately grounds the
    # verdict, same as a Phase-D round-2. Otherwise keep the existing
    # synth-first behavior.
    targeted_tool: str | None = None
    targeted_messages: list[Any] | None = None
    if ran_investigation_loop:
        targeted_messages = loop_messages
        # Mark "an investigation gathered evidence" — which exempts the verdict
        # from the hard evidence gate + GATE A — ONLY when the loop produced at
        # least one SUCCESSFUL tool call. On the budget/timeout fallback path
        # ``loop_messages`` is None (the round-1 verdict just stands), and a loop
        # whose every call errored gathered nothing; treating either as tool
        # evidence would launder a non-evidence-backed round-1 TP/FP straight
        # past the gate. ``targeted_messages`` is still threaded for tool/pivot
        # citation resolution regardless.
        targeted_tool = _loop_evidence_marker(ran_investigation_loop, loop_messages)
    elif targeted_tool_with_data is not None:
        # A Phase-D dispatch returned DISCRIMINATING DATA (tracked per round in
        # the bounded loop above — errored or empty dispatches never set it, so
        # they can't exempt the hard evidence gate).
        targeted_tool = targeted_tool_with_data
    triage_final, validation_audit = _synth_first_post_validate(
        triage_final,
        enriched,
        candidate,
        targeted_messages=targeted_messages,
        targeted_tool_called=targeted_tool,
        synthesis_confidence_floor=ctx.settings.synthesis_confidence_floor,
        blocklist=ctx.blocklist,
        internal_cidrs=classification_cidrs,
    )

    # Emit validator events in order.
    if "citation_validation" in validation_audit:
        ev = _ev("citation_validation", {"round": 1, **validation_audit["citation_validation"]})
        await _audit(ev)
        yield ev
    if "citation_cap" in validation_audit:
        ev = _ev("citation_cap", {"round": 1, **validation_audit["citation_cap"]})
        await _audit(ev)
        yield ev
    if "verdict_floor_rewrite" in validation_audit:
        ev = _ev("verdict_floor_rewrite", validation_audit["verdict_floor_rewrite"])
        await _audit(ev)
        yield ev
    if "icmp_solicited_downgrade" in validation_audit:
        ev = _ev("icmp_solicited_downgrade", validation_audit["icmp_solicited_downgrade"])
        await _audit(ev)
        yield ev
    if "ungrounded_host_anchored_tp_downgrade" in validation_audit:
        ev = _ev(
            "ungrounded_host_anchored_tp_downgrade",
            validation_audit["ungrounded_host_anchored_tp_downgrade"],
        )
        await _audit(ev)
        yield ev

    if "malware_rule_name_ungrounded_downgrade" in validation_audit:
        ev = _ev(
            "malware_rule_name_ungrounded_downgrade",
            validation_audit["malware_rule_name_ungrounded_downgrade"],
        )
        await _audit(ev)
        yield ev

    if "evidence_gate_downgrade" in validation_audit:
        ev = _ev("evidence_gate_downgrade", validation_audit["evidence_gate_downgrade"])
        await _audit(ev)
        yield ev
        # Metric: a zero-tool TP/FP was coerced to needs_more_info by the hard
        # evidence gate. Counts how often the gate fires (reliability signal).
        await metrics.get_metrics().record_event("zero_tool_verdict_blocked", {})

    # ----- Oracle escalation (optional, explicit opt-in) -----
    # After all post-validators, escalate to the frontier Oracle when the local
    # triage needs it (uncertain, malware non-TP, or below-floor confidence).
    # The local verdict is preserved in the audit via `local_verdict` in the
    # oracle_escalation event so evaluators can compare both.
    local_triage_final = triage_final  # snapshot before any Oracle override
    if _should_escalate_to_oracle(
        triage_final, enriched, ctx.settings, ran_loop=ran_investigation_loop
    ):
        from soc_ai.agent.decision_templates import (  # noqa: PLC0415
            _rule_signals_attack,
            _rule_signals_malware,
        )

        # Derive the audit reason to match the ACTUAL gate that fired in
        # _should_escalate_to_oracle (same flag + predicate order as above).
        # Previously only _rule_signals_malware was checked here, so an
        # attack-class escalation was mis-labelled "below_confidence".
        if (
            ctx.settings.oracle_escalate_needs_more_info
            and triage_final.verdict == "needs_more_info"
        ):
            escalation_reason = "needs_more_info"
        elif (
            ctx.settings.oracle_escalate_malware_non_tp
            and (_rule_signals_malware(enriched) or _rule_signals_attack(enriched))
            and not (triage_final.verdict == "true_positive" and triage_final.confidence >= 0.7)
            and not (
                ran_investigation_loop
                and triage_final.confidence >= ctx.settings.oracle_skip_after_confident_loop
            )
        ):
            escalation_reason = "malware_non_tp"
        else:
            escalation_reason = "below_confidence"

        esc_ev = _ev(
            "oracle_escalation",
            {
                "reason": escalation_reason,
                "local_verdict": triage_final.verdict,
                "local_confidence": triage_final.confidence,
            },
        )
        await _audit(esc_ev)
        yield esc_ev

        # Build a compact text transcript for the Oracle payload.
        transcript_text = ""
        if loop_messages is not None:
            # Extract evidence text from the investigation loop messages where available.
            parts: list[str] = []
            for msg in loop_messages:
                for part in getattr(msg, "parts", []) or []:
                    content = getattr(part, "content", None)
                    if isinstance(content, str) and content.strip():
                        parts.append(content.strip())
            transcript_text = "\n".join(parts)

        # Reuse the effective internal-identifier set resolved ONCE at the top of
        # the pipeline (env-config union active detected/manual identifiers, minus
        # muted) for the Oracle egress sanitizer's suffixes/hosts. DB access stays
        # in the caller; the sanitizer stays pure. None ⇒ no DB on ctx (CLI / eval
        # / tests) or a resolution failure → the client falls back to the raw
        # settings tuples (behavior unchanged).
        oracle_suffixes = effective_idents.suffixes if effective_idents is not None else None
        oracle_hosts = effective_idents.hosts if effective_idents is not None else None

        oracle_result = await _oracle_client.adjudicate(
            ctx,
            enriched=enriched,
            local_report=triage_final,
            transcript_text=transcript_text,
            extra_hosts=oracle_hosts,
            extra_suffixes=oracle_suffixes,
        )

        if oracle_result is not None:
            # Fix M2: post-validate the Oracle's output with the same
            # deterministic targeted downgrades that ran on the local verdict.
            # Closes the path where the Oracle re-introduces a
            # solicited-internal-ICMP-echo true_positive that the local
            # BPFDoor guard already corrected.  Zero egress — deterministic.
            oracle_audit: dict[str, Any] = {}
            oracle_report = _apply_targeted_downgrades(
                oracle_result.report,
                enriched,
                oracle_audit,
                blocklist=ctx.blocklist,
                internal_cidrs=classification_cidrs,
            )
            # I2: ungrounded host-anchored TP guard — Oracle path parity.
            # Prevents the Oracle from re-escalating to TP solely on host_alert_profile
            # context that the local path already downgraded. enriched is an
            # EnrichedAlertContext: carries .alert, .enrichments, .host_alert_profile.
            oracle_report = _downgrade_ungrounded_host_anchored_tp(
                oracle_report, enriched, oracle_audit
            )
            if guard is not None:
                # The Oracle desanitizes its OWN labels (its independent
                # pipeline/mapping), but the loop-transcript text it was shown
                # can carry THIS guard's labels — if it echoed any (e.g.
                # HOST_01 quoted from loop evidence), restore them too.
                oracle_report = _desanitize_report(oracle_report, guard)

            adj_ev = _ev(
                "oracle_adjudication",
                {
                    "oracle_verdict": oracle_report.verdict,
                    "oracle_confidence": oracle_report.confidence,
                    "redaction": oracle_result.redaction_summary,
                    "oracle_model": oracle_result.oracle_model,
                    **({"oracle_targeted_downgrades": oracle_audit} if oracle_audit else {}),
                },
            )
            await _audit(adj_ev)
            yield adj_ev

            # Mark the Oracle report so UI/audit shows it was adjudicated.
            adjudicated_summary = f"[Oracle adjudicated] {oracle_report.summary}"
            triage_final = oracle_report.model_copy(update={"summary": adjudicated_summary})
        # If oracle_result is None (refusal or failure), triage_final stays
        # unchanged and the local verdict stands.

    # ----- Final triage emit -----
    triage_ev = _ev(
        "triage_report",
        {
            "verdict": triage_final.verdict,
            "confidence": triage_final.confidence,
            "summary": triage_final.summary,
            "citations": triage_final.citations,
            "recommended_actions": [
                a.model_dump(mode="json") for a in triage_final.recommended_actions
            ],
            "field_reconciliation": triage_final.field_reconciliation,
            "validator_note": triage_final.validator_note,
            # Pipeline-fallback provenance marker (E1.2). Present ONLY on the
            # synth-failure path (`_synth_failure_fallback_report`) — a real
            # verdict leaves it None and it's dropped below. The persisted report
            # dict (recorder captures THIS payload) then carries
            # `resolution.provenance == "pipeline_fallback"`, which every
            # downstream consumer reads via `is_pipeline_fallback`. Distinct key
            # from the manual/chat override's `resolved_via`, so a later manual
            # resolution overwrites it cleanly (a resolved run is no longer a
            # "pipeline error to retry").
            **(
                {"resolution": triage_final.resolution}
                if triage_final.resolution is not None
                else {}
            ),
            # Preserve local verdict in the audit when Oracle overrode it.
            "local_verdict": local_triage_final.verdict
            if triage_final is not local_triage_final
            else None,
        },
    )
    await _audit(triage_ev)
    yield triage_ev

    # ----- Auto-acknowledge high-confidence false positives (opt-in) -----
    auto_ack_ev = await maybe_auto_ack_fp(
        triage_final, alert_id, alert=enriched.alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
    )
    if auto_ack_ev is not None:
        yield auto_ack_ev

    yield _ev("done", {"recommended_count": len(triage_final.recommended_actions)})


__all__ = [
    "InvestigationContext",
    "InvestigationTranscript",
    "RecommendedAction",
    "StepEvent",
    "TriageReport",
    "_should_escalate_to_oracle",
    "build_agent",
    "build_investigator",
    "build_investigator_model",
    "build_local_enrichment_context",
    "build_model",
    "build_synth_first_agent",
    "build_synthesizer",
    "build_synthesizer_model",
    "investigate",
    "maybe_auto_ack_fp",
]
