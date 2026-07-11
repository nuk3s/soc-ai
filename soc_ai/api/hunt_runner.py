"""Recorded hunt runner (SSE route + background drainer).

Mirrors :mod:`soc_ai.api.runner`. ``run_hunt`` streams the chat-driven hunt
agent NODE-BY-NODE (via ``agent.iter()`` + the orchestrator's ``_walk_message``
projector, exactly like the investigation loop) so each tool_call / tool_result
/ model_response lands the moment it happens; it emits a leading ``hunt_started``
event and a trailing ``hunt_report`` event carrying the final
:class:`~soc_ai.agent.hunt.HuntReport`.

``hunt_recorded_run`` wraps that stream with :class:`HuntRecorder` so every run
is persisted (leading ``hunt_created`` event carries the new row's id), whether
consumed by the SSE route or drained in the background.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.usage import UsageLimits

from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.hunt import (
    HUNT_SYSTEM_PROMPT,
    HuntReport,
    build_hunt_agent,
    build_hunt_prompt,
    build_hunt_synthesizer,
)
from soc_ai.agent.hunt_gates import _validate_hunt_charts, _validate_hunt_findings
from soc_ai.agent.models import build_investigator_model
from soc_ai.agent.orchestrator import InvestigationContext, StepEvent, _walk_message
from soc_ai.agent.prompts import oql_primer_block
from soc_ai.api.hunt_recorder import HuntRecorder
from soc_ai.api.runner import CancelToken
from soc_ai.so_client.inventory import inventory_prompt_block

_LOGGER = logging.getLogger(__name__)


async def _build_hunt_run(
    ctx: InvestigationContext, *, objective: str, prior: str | None
) -> tuple[EgressGuard | None, Agent[None, HuntReport], str]:
    """Compose the (guard, agent, user message) triple for one hunt run.

    The egress guard MUST be attached to ``ctx`` before ``build_hunt_agent``
    runs — ``register_read_tools`` wraps the tool closures at registration
    time. When the guard is active, the system prompt (objective + dataset
    inventory) and the user message (objective + prior-hunt summary) are
    sanitized here — they are the hunt's prompt-side egress boundary.
    """
    guard = await _egress_guard_for(ctx)
    # The hunt agent runs OQL — append the primer so it writes VALID queries
    # (no parentheses, no leading wildcards) instead of churning through parse
    # errors. And append the auto-discovered dataset inventory so the hunt knows
    # what data ACTUALLY exists on this grid (network today, host logs later)
    # instead of guessing from a hardcoded list.
    system_prompt = (
        HUNT_SYSTEM_PROMPT.format(objective=objective)
        + oql_primer_block()
        + await inventory_prompt_block(ctx.elastic, ctx.settings)
    )
    if guard is not None:
        # The objective is analyst-typed free text that may name internal
        # hosts, and the inventory block carries grid dataset detail.
        system_prompt = guard.sanitize_text(system_prompt)
    agent = build_hunt_agent(
        build_investigator_model(ctx.settings), ctx, system_prompt=system_prompt
    )
    user_msg = build_hunt_prompt(objective, prior=prior)
    if guard is not None:
        user_msg = guard.sanitize_text(user_msg)
    return guard, agent, user_msg


async def _egress_guard_for(ctx: InvestigationContext) -> EgressGuard | None:
    """Attach/return the opt-in cloud-egress guard for this hunt run.

    Same pattern as the investigation pipeline: when
    ``analyst_cloud_redaction`` is on, ONE guard (one label mapping) covers the
    whole hunt — prompts out, tool results out (via the toolset's ``_guarded``
    wrapper at registration), labels restored in everything persisted.
    ``is True`` (not truthiness) so a non-Settings test double can never flip
    redaction on. ``None`` = redaction off (the default).
    """
    if ctx.settings.analyst_cloud_redaction is True and ctx.egress_guard is None:
        ctx.egress_guard = await EgressGuard.for_settings(ctx.settings, ctx.db_sessionmaker)
    return ctx.egress_guard


def _desanitize_hunt_report(report: Any, guard: EgressGuard | None) -> Any:
    """Restore real identifiers in a labeled HuntReport before persistence.

    The model wrote the report in label space (its inputs were sanitized);
    round-trip every string field through the guard's mapping. Defensive: a
    desanitize surprise must never cost the hunt its report — on failure the
    labeled report is returned unchanged.
    """
    if guard is None:
        return report
    try:
        return type(report).model_validate(guard.desanitize_obj(report.model_dump(mode="json")))
    except Exception:
        _LOGGER.warning(
            "hunt: egress-guard desanitize failed; persisting labeled report", exc_info=True
        )
        return report


def _repair_dangling_tool_calls(gathered: list[Any]) -> list[Any]:
    """Close out unexecuted trailing tool calls so the transcript can be replayed.

    pydantic-ai raises :class:`UsageLimitExceeded` AFTER the ``ModelResponse``
    carrying the next tool-call batch has landed in the history but BEFORE the
    calls execute — so a budget-exhausted hunt transcript ALWAYS ends with
    unprocessed tool calls, and replaying it with a new user prompt is rejected
    with ``UserError: Cannot provide a new user prompt when the message history
    contains unprocessed tool calls`` (the 2026-07 prod failure: every
    budget-capped hunt errored and its evidence was discarded). Repair: append a
    synthetic ``ModelRequest`` with one ``ToolReturnPart`` per dangling call in
    the trailing batch (prod batches ran ~3 calls), preserving the model's final
    reasoning for the synthesizer. Returns a NEW list; ``gathered`` is never
    mutated.

    Defensive by design — this path must never be able to crash the hunt again:
    if the trailing ``ModelResponse`` is any shape we can't repair (message-class
    drift after a pydantic-ai bump, surprise part payloads), fall back to
    TRIMMING it off — losing the final unexecuted step beats losing the whole
    report. The caller's error handling remains the LAST resort, not the first.
    """
    if not gathered:
        return gathered
    last = gathered[-1]
    if not isinstance(last, ModelResponse):
        return gathered  # tail already ends on a request — replayable as-is
    try:
        dangling = [p for p in last.parts if isinstance(p, ToolCallPart)]
        if not dangling:
            return gathered  # plain text/thinking tail — replayable as-is
        return [
            *gathered,
            ModelRequest(
                parts=[
                    ToolReturnPart(
                        tool_name=part.tool_name,
                        tool_call_id=part.tool_call_id,
                        content="not executed — hunt budget exhausted",
                    )
                    for part in dangling
                ]
            ),
        ]
    except Exception:
        # Unexpected tail shape: trim the trailing ModelResponse rather than
        # replay a history pydantic-ai will reject.
        _LOGGER.warning(
            "hunt: could not close out dangling tool calls; trimming the trailing "
            "model response before partial synthesis",
            exc_info=True,
        )
        return gathered[:-1]


def _replay_reasoning_context(gathered: list[Any]) -> str:
    """Surface the exploration model's own reasoning as explicit synthesizer input.

    The trust-erosion bug (two prod hunts, 2026-07): the exploration model had
    ALREADY debunked the false positive IN ITS REASONING ("Apple service
    discovery, not C2"), but that debunking lived in ``ThinkingPart``s the
    partial synthesizer never saw — pydantic-ai does NOT feed a prior turn's
    thinking back into a fresh agent's ``message_history`` (thinking is stripped
    from replayed context), so only the loud alert TITLES survived and the
    synthesizer reasserted the FP. This lifts the reasoning text back out of the
    gathered ``ModelResponse`` ``ThinkingPart``s and returns it as a plain-text
    block to prepend to the synthesizer's user message, so the model's own
    debunking is in front of it when it writes up a cut-short hunt.

    Returns ``""`` when there is no reasoning to replay (a non-reasoning model, or
    an empty trace) — the caller then simply omits the block. Defensive: any
    surprise part shape is skipped, never raised.
    """
    traces: list[str] = []
    for msg in gathered:
        for part in getattr(msg, "parts", None) or []:
            if type(part).__name__ != "ThinkingPart":
                continue
            content = str(getattr(part, "content", "") or "").strip()
            if content:
                traces.append(content)
    if not traces:
        return ""
    joined = "\n\n".join(traces)
    return (
        "## Your own reasoning from the exploration above (do NOT ignore it)\n"
        "While hunting you already reasoned about this evidence — including any "
        "false positives you debunked. That reasoning is NOT in the replayed "
        "message history, so it is reproduced here verbatim. Weight it: if you "
        "concluded an alert was a false positive (e.g. 'solicited echo reply, not "
        "C2' / 'Apple service discovery, not a Linux backdoor'), do NOT reassert "
        "it as a threat now just because the alert title is loud.\n\n"
        f"{joined}\n\n---\n\n"
    )


async def _synthesize_partial_hunt(
    ctx: InvestigationContext, *, objective: str, gathered: list[Any]
) -> Any:
    """Force a :class:`HuntReport` from an already-gathered transcript (no tools).

    Called when a hunt exhausts its budget before emitting a report: repairs the
    transcript tail (budget exhaustion always leaves unprocessed tool calls —
    see :func:`_repair_dangling_tool_calls`), then replays the accumulated
    message history through the no-tools hunt synthesizer so the analyst still
    gets a grounded partial report instead of a bare error.

    The exploration model's own reasoning (its ``ThinkingPart``s, where the
    debunking of a false positive lives) is NOT carried into a fresh agent's
    replayed history by pydantic-ai, so it is lifted out via
    :func:`_replay_reasoning_context` and prepended to the synthesizer's user
    message — otherwise only the loud alert titles survive and the write-up
    reasserts an FP the hunt had already dismissed.
    """
    synth = build_hunt_synthesizer(build_investigator_model(ctx.settings), objective=objective)
    reasoning_block = _replay_reasoning_context(gathered)
    user_msg = (
        reasoning_block + "Write the HuntReport now from the evidence already gathered above."
    )
    return await synth.run(
        user_msg,
        message_history=_repair_dangling_tool_calls(gathered),
        usage_limits=UsageLimits(request_limit=3, tool_calls_limit=0),
    )


async def _stream_node(
    node: Any,
    ev_factory: Any,
    guard: EgressGuard | None,
    gathered: list[Any],
    gathered_tool_results: list[Any],
) -> AsyncIterator[StepEvent]:
    """Project one streamed hunt node into display StepEvents, capturing evidence.

    Extracts the node's message (``model_response`` or ``request``), appends it to
    ``gathered`` (the labeled originals the partial-report synthesizer replays),
    then runs the shared ``_walk_message`` projector. Restores real identifiers
    for display when a guard is active, and appends each ``tool_result`` payload
    to ``gathered_tool_results`` — the desanitized evidence bundle the E1.3
    citation gate resolves findings against (same values the desanitized report
    cites). A node with no message yields nothing.
    """
    node_msg = getattr(node, "model_response", None)
    if node_msg is None:
        node_msg = getattr(node, "request", None)
    if node_msg is None:
        return
    gathered.append(node_msg)
    async for ev in _walk_message(node_msg, ev_factory, phase="hunt", round_num=1):
        disp = (
            ev
            if guard is None
            else ev.model_copy(update={"payload": guard.desanitize_obj(ev.payload)})
        )
        if disp.kind == "tool_result":
            # Capture a LABELED evidence item ({tool_name, result}) — not just the
            # bare result. The E1.3 finding gate resolves citations against
            # ``result`` (unchanged — the JSON dump still contains it, so existing
            # resolution is unaffected), and the corroboration gate additionally
            # classifies each item by ``tool_name`` to tell a detector-alert
            # citation apart from a corroborating-evidence one. ``_walk_message``
            # already surfaces the ToolReturnPart's ``tool_name`` on the payload.
            gathered_tool_results.append(
                {
                    "tool_name": disp.payload.get("tool_name", ""),
                    "result": disp.payload.get("result"),
                }
            )
        yield disp


async def run_hunt(
    ctx: InvestigationContext,
    *,
    objective: str,
    prior: str | None = None,
    session_id: str | None = None,
) -> AsyncIterator[StepEvent]:
    """Stream a chat-driven hunt as StepEvents.

    Builds the hunt agent (reusing the investigator's read tools) with the
    hunt-oriented system prompt, runs it node-by-node, and yields:

    - ``hunt_started`` — the objective, first;
    - ``tool_call`` / ``tool_result`` / ``model_response`` — the live trace;
    - ``hunt_report`` — the final HuntReport (or an ``error`` event on failure);
    - ``done`` — a small terminal marker with the finding count.
    """
    sid = session_id or uuid.uuid4().hex[:12]
    sequence = 0

    def _ev(kind: str, payload: dict[str, Any]) -> StepEvent:
        nonlocal sequence
        sequence += 1
        return StepEvent(kind=kind, session_id=sid, sequence=sequence, payload=payload)

    yield _ev("hunt_started", {"objective": objective})

    # Guard (opt-in cloud-egress redaction) + agent + sanitized prompts. The
    # guard is attached to ctx BEFORE the agent is built so the toolset wraps
    # the tool closures at registration time.
    guard, agent, user_msg = await _build_hunt_run(ctx, objective=objective, prior=prior)
    # Hunts get a bigger budget than a single-alert investigation — they explore
    # broadly (many hosts/queries) before synthesizing, and the investigation-sized
    # request_limit ran out mid-hunt, erroring before the findings report.
    usage_limits = UsageLimits(
        request_limit=ctx.settings.hunt_request_limit,
        tool_calls_limit=ctx.settings.hunt_tool_calls_limit,
    )

    result: Any = None
    # Accumulate the streamed node messages so that, if the hunt exhausts its budget
    # before emitting a report, we can synthesize a partial report from what it
    # actually gathered instead of erroring with nothing.
    gathered: list[Any] = []
    # Accumulate the tool-result PAYLOADS the hunt actually pulled — the evidence
    # bundle the post-hunt citation gate resolves findings against (E1.3). Collected
    # from the streamed tool_result events (desanitized to match the desanitized
    # report's citations), so a finding citing an id the hunt never pulled is caught.
    gathered_tool_results: list[Any] = []
    budget_exhausted = False
    try:
        # Whole-hunt wall-clock safety net: a HUNG LLM stream has no budget-based
        # stopping point and would otherwise stall the background task forever.
        # On expiry the TimeoutError falls through to the same partial-report path
        # as budget exhaustion so the hunt lands a grounded PARTIAL report.
        async with (
            asyncio.timeout(ctx.settings.hunt_run_timeout_s),
            agent.iter(user_msg, usage_limits=usage_limits) as run,
        ):
            async for node in run:
                async for disp in _stream_node(node, _ev, guard, gathered, gathered_tool_results):
                    yield disp
        result = run.result
    except asyncio.CancelledError:
        raise  # cooperative cancel — propagate, never swallow
    except (UsageLimitExceeded, TimeoutError) as e:
        # Budget exhaustion (UsageLimitExceeded) and the whole-hunt wall-clock
        # backstop (TimeoutError) are both EXPECTED outcomes of a broad hunt on a
        # slow stack, not infra failures. The queries + results already streamed
        # live — don't discard them with status=error and no report. Fall through
        # to synthesize a PARTIAL report from what was gathered.
        _LOGGER.warning(
            "hunt hit its exploration budget/time limit; synthesizing partial report: %s", e
        )
        budget_exhausted = True
    except BaseException as e:
        _LOGGER.exception("hunt agent run failed")
        yield _ev("error", {"message": str(e), "type": type(e).__name__})
        return

    # True ONLY when the report below came from the budget/timeout partial path —
    # gates the deterministic humility clamp (a full-run report is never clamped).
    partial_synthesis = False
    if result is None and budget_exhausted and gathered:
        # Replay the accumulated transcript through a no-tools synthesizer to land a
        # grounded partial HuntReport rather than an empty error.
        yield _ev(
            "model_response",
            {
                "text": (
                    "Reached the hunt's exploration budget — synthesizing a partial "
                    "report from the evidence gathered so far."
                )
            },
        )
        try:
            result = await _synthesize_partial_hunt(ctx, objective=objective, gathered=gathered)
            partial_synthesis = True
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            _LOGGER.exception("hunt partial synthesis failed")
            yield _ev(
                "error",
                {
                    "message": f"hunt hit its budget and partial synthesis failed: {e}",
                    "type": type(e).__name__,
                },
            )
            return

    if result is None:
        yield _ev("error", {"message": "hunt produced no report", "type": "EmptyResult"})
        return

    report = _desanitize_hunt_report(result.output, guard)

    # ── Partial-report humility clamp (deterministic) ────────────────────────
    # A budget/timeout-truncated hunt is written up by the no-tools synthesizer
    # from a transcript dominated by loud alert titles — the prompt ASKS for lower
    # confidence and threat skepticism, but two prod hunts still emitted HIGH
    # severity at 0.75-0.78 conf. Make the humility a RULE, not a request: on the
    # partial path clamp overall confidence to <= 0.5 and cap any threat finding to
    # medium with a note. Runs BEFORE the citation gate so a partial's caps compose
    # with the corroboration cap (min-severity wins either way).
    if partial_synthesis:
        report = _apply_partial_humility(report)

    # ── Post-hunt citation gate (E1.3) ───────────────────────────────────────
    # Deterministically resolve each finding's citations against the evidence the
    # hunt ACTUALLY gathered; strip non-resolving citations + cap such findings'
    # severity. Returns the validated report + the citation_validation event (or
    # None on a validator error — the gate is fail-soft).
    report, citation_ev = _gate_hunt_citations(report, gathered_tool_results, _ev)
    if citation_ev is not None:
        yield citation_ev

    report_payload = report.model_dump(mode="json")
    yield _ev("hunt_report", report_payload)
    yield _ev("done", {"finding_count": len(report.findings)})


_PARTIAL_HUMILITY_NOTE = "budget/timeout-partial — uncorroborated; corroborate before acting"


def _apply_partial_humility(report: Any) -> Any:
    """Clamp a budget/timeout-PARTIAL HuntReport's confidence + threat severities.

    A cut-short hunt is synthesized (no tools) from a transcript that is often
    dominated by loud detector-alert titles. Even with the synth prompt asking for
    humility, the model over-claimed on two prod hunts (HIGH severity, 0.75-0.78
    conf). This makes it deterministic:

    * ``confidence`` is clamped to at most ``0.5`` (the mid default) — a partial
      hunt cannot report high confidence in its conclusions.
    * every ``category == "threat"`` finding at high/critical severity is capped to
      ``"medium"`` and annotated with :data:`_PARTIAL_HUMILITY_NOTE` (preserving any
      note the citation gate later sets is handled by ordering — this runs first).

    Fail-soft and PURE: on any surprise shape the original report is returned
    unchanged (a humility clamp must never cost the hunt its report). Uses the
    hunt-gate severity machinery so "cap" only ever LOWERS a severity.
    """
    try:
        from soc_ai.agent.hunt_gates import _SEV_RANK, _cap_severity  # noqa: PLC0415

        new_findings: list[Any] = []
        for finding in report.findings:
            category = str(getattr(finding, "category", None) or "").strip().lower()
            severity = str(getattr(finding, "severity", None) or "info")
            if category == "threat" and _SEV_RANK.get(severity.lower(), 0) >= _SEV_RANK["high"]:
                new_findings.append(
                    finding.model_copy(
                        update={
                            "severity": _cap_severity(severity, "medium"),
                            "validator_note": _PARTIAL_HUMILITY_NOTE,
                        }
                    )
                )
            else:
                new_findings.append(finding)
        confidence = min(float(getattr(report, "confidence", 0.5) or 0.0), 0.5)
        return report.model_copy(update={"findings": new_findings, "confidence": confidence})
    except Exception:
        _LOGGER.warning(
            "hunt partial-humility clamp failed; persisting report as-is", exc_info=True
        )
        return report


def _gate_hunt_citations(
    report: Any, tool_results: list[Any], ev_factory: Any
) -> tuple[Any, StepEvent | None]:
    """Run the E1.3 finding gate + E3.3 chart gate; return (validated_report, event).

    Deterministically resolves each finding's citations against the evidence the
    hunt gathered this run, strips non-resolving citations, caps such findings'
    severity, and caps a high/critical finding that cites nothing. Then, over the
    SAME gathered tool-results, resolves each chart's ``source_citations`` with the
    SAME distinctive-token resolver and DROPS any chart whose citations don't
    resolve (or which has no series / no citations), capped at 4 — an invented
    series is never rendered. The event carries the per-hunt counts (finding tallies
    plus ``charts`` / ``charts_dropped``), mirroring the investigation path's
    ``citation_validation`` emission. Fail-soft: a validator surprise must never
    cost the hunt its report — on error the unvalidated report is returned with a
    ``None`` event.
    """
    try:
        validated_findings, counts = _validate_hunt_findings(report.findings, tool_results)
        kept_charts, chart_counts = _validate_hunt_charts(report.charts, tool_results)
        report = report.model_copy(update={"findings": validated_findings, "charts": kept_charts})
        return report, ev_factory("citation_validation", {"round": 1, **counts, **chart_counts})
    except Exception:
        _LOGGER.warning("hunt citation gate failed; persisting unvalidated report", exc_info=True)
        return report, None


async def hunt_recorded_run(
    state: Any,
    *,
    ctx: InvestigationContext,
    objective: str,
    started_by: str,
    prior: str | None = None,
    kind: str = "chat",
    cancel_token: CancelToken | None = None,
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """Wrap :func:`run_hunt` with the hunt recorder tee.

    Yields ``(event_name, data_dict)`` pairs. The leading ``hunt_created`` event
    (carrying the new row id) is always first. Mirrors
    :func:`soc_ai.api.runner.recorded_run`.
    """
    recorder = HuntRecorder(
        state.db_sessionmaker,
        objective=objective,
        started_by=started_by,
        kind=kind,
    )
    hunt_id = await recorder.start()

    yield "hunt_created", {"hunt_id": hunt_id}

    try:
        async for ev in run_hunt(ctx, objective=objective, prior=prior):
            await recorder.record(ev.kind, ev.sequence, ev.payload)
            yield (
                ev.kind,
                {
                    "session_id": ev.session_id,
                    "sequence": ev.sequence,
                    "payload": ev.payload,
                },
            )
        await recorder.finish("complete")
        # E2.4 notification trigger — a completed hunt whose report contains a
        # threat-category finding pings on-call. THIN + fail-soft: build a
        # NotifyEvent from the recorder's captured report and fire it (a hard
        # no-op unless notifications are enabled + a webhook is configured). Wrapped
        # so a webhook can never break the finalized hunt.
        await _maybe_notify_hunt(state, recorder)
    except asyncio.CancelledError:
        # Only an EXPLICIT operator cancel is 'cancelled'; any other cancellation
        # (SSE client disconnect, app/container shutdown) is an interrupted run
        # that never reached a report → 'error'. finish() is idempotent.
        await recorder.finish(
            "cancelled" if (cancel_token is not None and cancel_token.requested) else "error"
        )
        raise
    except Exception as exc:
        _LOGGER.exception("hunt stream crashed")
        await recorder.finish("error")
        yield "error", {"message": str(exc), "type": type(exc).__name__}
    finally:
        # no-op if already finished; lands rows abandoned by client disconnect
        await recorder.finish("error")


async def _maybe_notify_hunt(state: Any, recorder: HuntRecorder) -> None:
    """Fire the E2.4 hunt-threat notification for a finalized hunt (fail-soft).

    Reads the recorder's captured HuntReport + hunt id, builds a NotifyEvent iff
    the report has a threat-category finding (per settings), and fires it. Every
    failure mode is swallowed — a notification must NEVER break the just-finalized
    hunt. Zero egress unless notifications are enabled + a webhook is configured.
    """
    try:
        from soc_ai import notify  # noqa: PLC0415 - local, keeps import graph light

        hunt_id = recorder.hunt_id
        report = recorder._report  # the captured hunt_report payload (or None)
        if hunt_id is None or not report:
            return
        event = notify.event_for_hunt(
            hunt_id=hunt_id,
            report=report,
            settings=state.settings,
        )
        if event is not None:
            await notify.fire_safe(event, state.settings, getattr(state, "audit", None))
    except Exception:  # a notification trigger must never break the primary flow
        _LOGGER.warning("hunt notify trigger failed (continuing)", exc_info=True)


def sse_encode(name: str, data: dict[str, Any]) -> dict[str, Any]:
    """Encode a (name, data) pair into the SSE dict format used by EventSourceResponse."""
    return {"event": name, "data": json.dumps(data, default=str)}
