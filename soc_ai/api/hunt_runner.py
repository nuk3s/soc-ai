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
from pydantic_ai.usage import UsageLimits

from soc_ai.agent._partial_replay import (
    repair_dangling_tool_calls,
    replay_reasoning_context,
)
from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.hunt import (
    HUNT_SYSTEM_PROMPT,
    HuntFinding,
    HuntReport,
    build_hunt_agent,
    build_hunt_prompt,
    build_hunt_synthesizer,
)
from soc_ai.agent.hunt_gates import _validate_hunt_charts, _validate_hunt_findings
from soc_ai.agent.models import build_investigator_model
from soc_ai.agent.orchestrator import InvestigationContext, StepEvent, _walk_message
from soc_ai.agent.prompts import oql_primer_block
from soc_ai.agent.toolset import GRID_BACKED_TOOLS, GRID_UNAVAILABLE_REASON
from soc_ai.api.hunt_recorder import HuntRecorder
from soc_ai.api.runner import CancelToken
from soc_ai.dossier.prompt import host_dossier_prompt_block, internal_ips_in_text
from soc_ai.so_client.inventory import inventory_prompt_block

_LOGGER = logging.getLogger(__name__)


async def _build_hunt_run(
    ctx: InvestigationContext, *, objective: str, prior: str | None
) -> tuple[EgressGuard | None, Agent[None, HuntReport], str]:
    """Compose the (guard, agent, user message) triple for one hunt run.

    The egress guard MUST be attached to ``ctx`` before ``build_hunt_agent``
    runs — ``register_read_tools`` wraps the tool closures at registration
    time. When the guard is active, the system prompt (objective + dataset
    inventory + host dossier) and the user message (objective + prior-hunt
    summary) are sanitized here — they are the hunt's prompt-side egress
    boundary.
    """
    guard = await _egress_guard_for(ctx)
    # The hunt agent runs OQL — append the primer so it writes VALID queries
    # (no parentheses, no leading wildcards) instead of churning through parse
    # errors. And append the auto-discovered dataset inventory so the hunt knows
    # what data ACTUALLY exists on this grid (network today, host logs later)
    # instead of guessing from a hardcoded list.
    #
    # The dossier block goes on the same seam, and for the same reason the
    # inventory does: a hunt should know what the hosts its objective names ARE
    # before it plans what to look for. Composed HERE, above the sanitize sweep
    # below — appending it after the sweep would send the network's hostnames and
    # addresses to a cloud model in the clear.
    system_prompt = (
        HUNT_SYSTEM_PROMPT.format(objective=objective)
        + oql_primer_block(flavor="hunt")
        + await inventory_prompt_block(ctx.elastic, ctx.settings)
        + await _objective_dossier_block(ctx, objective, prior)
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


async def _objective_dossier_block(
    ctx: InvestigationContext, objective: str, prior: str | None
) -> str:
    """The host-dossier block for the addresses the hunt's own brief names.

    A hunt has no alert to read endpoints off, so the host set comes from the
    text the analyst wrote plus the prior hunt's narrative it is refining —
    those are the addresses the hunt is already about. Nothing is discovered
    here: this is not a sweep of the network, it is the identity of the hosts
    already on the page, bounded by
    :data:`~soc_ai.dossier.prompt.MAX_PROMPT_HOSTS`.

    Returns ``""`` on every off-switch and every failure (the renderer's
    contract), so a deployment with the dossier off pays nothing.

    ``known_only`` because the addresses came from free text: an analyst can
    type an address that was never observed, and a rendered "no dossier" line
    would put it into the hunt's own prompt as though it were an asset. Only
    hosts the sweep knows are described.
    """
    named = internal_ips_in_text(f"{objective}\n{prior or ''}", ctx.settings)
    if not named:
        return ""
    return await host_dossier_prompt_block(
        {ip: "named in the objective" for ip in named}, ctx=ctx, known_only=True
    )


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


# Shared with the triage loop's budget-partial path — extracted verbatim to
# soc_ai.agent._partial_replay (2026-07-18). Module aliases keep the names
# callers and tests use; the hunt closure content is the shared default.
_repair_dangling_tool_calls = repair_dangling_tool_calls
_replay_reasoning_context = replay_reasoning_context


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

    # ── Evidence-count gate (deterministic, G6) ──────────────────────────────
    # Count what the tools ACTUALLY returned rather than trusting the write-up to
    # mention the failures. A hunt may only stand as a clean sweep if at least ONE
    # grid read SUCCEEDED — whether every grid call errored (an outage), every
    # query was rejected by the grid (the model wrote queries ES said no to), or
    # the hunt never made a grid call at all, it looked at nothing, so its report
    # cannot read as "the network is quiet" however confidently it is worded.
    # Runs LAST so the visibility-gap finding it adds is not stripped by the
    # citation gate for citing nothing — a blind hunt has nothing to cite.
    report, degraded_reason = _gate_hunt_evidence(report, gathered_tool_results)

    report_payload = report.model_dump(mode="json")
    yield _ev("hunt_report", report_payload)
    yield _ev(
        "done",
        {
            "finding_count": len(report.findings),
            # Read by hunt_recorded_run to finalize the row as a degraded run
            # rather than a completed hunt. On the done event (not a new event
            # kind) so the persisted trace carries it without a UI that must
            # learn a kind. The reason names the CAUSE: ``grid_unavailable``
            # (the grid could not be read), ``grid_queries_rejected`` (the grid
            # answered and rejected every query), or ``no_grid_reads`` (the hunt
            # never ran a grid query).
            "degraded": degraded_reason is not None,
            "degraded_reason": degraded_reason,
        },
    )


_PARTIAL_HUMILITY_NOTE = "budget/timeout-partial — uncorroborated; corroborate before acting"

_GRID_OUTAGE_NOTE = (
    "grid unavailable — every grid query in this hunt failed, so nothing was checked "
    "and nothing was ruled out"
)
_GRID_OUTAGE_TITLE = "Grid unavailable — this hunt could not look"

# The two evidence-count reasons beside the transport outage. Persisted on the
# ``done`` event's ``degraded_reason``, so they are vocabulary, not prose: the
# refused/rejected distinction matters — ``grid_unavailable`` blames grid
# health, ``grid_queries_rejected`` blames the QUERIES (the grid answered every
# call; the model wrote queries ES said no to), and ``no_grid_reads`` means the
# hunt never asked the grid anything at all.
QUERIES_REJECTED_REASON = "grid_queries_rejected"
NO_GRID_READS_REASON = "no_grid_reads"

_QUERIES_REJECTED_NOTE = (
    "every grid query rejected — the grid answered and turned down each query this "
    "hunt wrote as invalid, so nothing was checked and nothing was ruled out"
)
_QUERIES_REJECTED_TITLE = "Every query rejected — this hunt could not look"

_NO_GRID_READS_NOTE = (
    "no grid reads — this hunt never ran a successful grid query, so nothing was "
    "checked and nothing was ruled out"
)
_NO_GRID_READS_TITLE = "No grid reads — this hunt never looked"


def _grid_tool_outcomes(tool_results: list[Any]) -> tuple[int, int, int]:
    """Count ``(succeeded, failed, rejected)`` over the GRID-backed tool results.

    The arithmetic behind the evidence-count gate, and the hunt-side mirror of
    :func:`soc_ai.agent.evidence.count_successful_tool_calls`, which already
    excludes errored results from the triage evidence gate.

    Only grid-backed tools count (:data:`~soc_ai.agent.toolset.GRID_BACKED_TOOLS`)
    — the question is whether this hunt could read the NETWORK, and a working web
    search or a local dossier lookup says nothing about that. A FAILURE is a
    result the tool boundary stamped ``reason: "grid_unavailable"`` (the grid
    could not be read). A REJECTION is any other error from a grid-backed tool —
    a bad query or bad arguments the grid answered and said no to; the model can
    fix those and try again, which is why a rejection is not a failure, but a run
    made of NOTHING BUT rejections still read nothing, which is why they are
    counted at all.

    A zero-hit result counts as a SUCCESS: the grid answered, and an empty answer
    from a healthy grid is a real, valuable result. Distinguishing "quiet" from
    "blind" is the entire point.

    A SHORT-CIRCUITED call never reached the grid, so it is none of the three:
    the tool wrappers answer some calls from local state without querying — a
    repeat of an identical call (``duplicate_call``) and a community_id the
    orchestrator already prefetched (``prefetch_already_has_this``). Both come
    back as non-error dicts from a grid-backed tool, and counting them as reads
    would let a blind hunt certify itself: the dedup tracker registers a call's
    key BEFORE the underlying query runs, so the retry of a query that timed out
    is a duplicate hit, and one such retry would silence the gate. These are the
    same two exclusions ``count_successful_tool_calls`` carries — deliberately
    without its DISCRIMINATING-DATA standard, which is right for the evidence gate
    (a throwaway zero-hit call must not license a verdict) and wrong here (a
    zero-hit answer is exactly what a healthy quiet grid returns).
    """
    succeeded = failed = rejected = 0
    for item in tool_results:
        if not isinstance(item, dict):
            continue
        grid_tool = str(item.get("tool_name") or "") in GRID_BACKED_TOOLS
        result = item.get("result")
        if not isinstance(result, dict):
            if grid_tool:
                succeeded += 1
            continue
        if result.get("error"):
            if result.get("reason") == GRID_UNAVAILABLE_REASON:
                failed += 1
            elif grid_tool:
                rejected += 1
        elif result.get("duplicate_call") or result.get("prefetch_already_has_this"):
            continue
        elif grid_tool:
            succeeded += 1
    return succeeded, failed, rejected


def _gate_hunt_evidence(report: Any, tool_results: list[Any]) -> tuple[Any, str | None]:
    """Run the deterministic evidence-count gate; return ``(report, degraded_reason)``.

    Counterpart to :func:`_gate_hunt_citations`, and the half of G6 that does not
    depend on the model cooperating. A hunt may only stand as a clean
    ``complete`` if it made AT LEAST ONE successful grid read — a genuine
    zero-hit answer included (the grid answered; quiet is a real result). Absent
    that, the report is stamped blind and a non-``None`` reason comes back for
    the caller to finalize the row as a degraded run instead of a completed
    hunt, worded by cause:

    * :data:`~soc_ai.agent.toolset.GRID_UNAVAILABLE_REASON` — at least one grid
      call failed as a transport outage: the GRID could not be read. Wins when
      causes mix, because "re-run once the grid is reachable" is the instruction
      that fixes it.
    * :data:`QUERIES_REJECTED_REASON` — every grid call was rejected (an ES 4xx
      / bad arguments): the grid was reachable, the QUERIES were the problem.
    * :data:`NO_GRID_READS_REASON` — the hunt never made a grid call at all:
      the zero-tool hunt, or one that answered purely from off-grid tools.

    The gate applies to EVERY hunt — no hunt path legitimately completes without
    a fresh grid read. A hunt context carries no prefetched alert evidence
    (``ctx_from_state`` builds it with an empty ``prefetched_community_ids``;
    hunts are not alert-anchored), and the off-grid tools (dossier, enrichment,
    web) are context ABOUT the network, not a look AT it — a hunt is, by
    contract, a look.

    The reason is computed from the counts alone, so it survives a decoration
    failure — a marker that blew up must still not leave a clean, complete hunt.
    """
    succeeded, failed, rejected = _grid_tool_outcomes(tool_results)
    if succeeded:
        return report, None
    if failed:
        _LOGGER.warning(
            "hunt could not read the grid (%d grid queries failed, none succeeded); "
            "marking the report degraded",
            failed,
        )
        return _mark_grid_outage(report, failed), GRID_UNAVAILABLE_REASON
    if rejected:
        _LOGGER.warning(
            "hunt read nothing (%d grid queries rejected, none succeeded); "
            "marking the report degraded",
            rejected,
        )
        return _mark_queries_rejected(report, rejected), QUERIES_REJECTED_REASON
    _LOGGER.warning("hunt made no grid reads at all; marking the report degraded")
    return _mark_no_grid_reads(report), NO_GRID_READS_REASON


def _mark_grid_outage(report: Any, failures: int) -> Any:
    """Stamp a hunt report that could not read the grid as exactly that."""
    return _mark_blind_hunt(
        report,
        title=_GRID_OUTAGE_TITLE,
        detail=(
            f"All {failures} Security Onion queries this hunt ran failed and none "
            "succeeded, so the objective was neither confirmed nor ruled out. This "
            "report is not evidence that the network is quiet — it is evidence that "
            "the grid could not be read. Re-run the hunt once the grid is reachable."
        ),
        note=_GRID_OUTAGE_NOTE,
        banner=(
            "**Grid unavailable — this hunt could not read the network.** "
            f"All {failures} grid queries failed and none succeeded, so nothing below "
            "rules anything out. The write-up that follows was produced without grid "
            "data."
        ),
    )


def _mark_queries_rejected(report: Any, rejections: int) -> Any:
    """Stamp a hunt report whose every grid query was rejected as exactly that.

    Worded at the QUERIES, not at grid health: the grid was reachable and
    answered every call — it rejected what the model asked. The remedy is a
    re-run (fresh queries), not waiting out an outage.
    """
    return _mark_blind_hunt(
        report,
        title=_QUERIES_REJECTED_TITLE,
        detail=(
            f"All {rejections} Security Onion queries this hunt ran were rejected as "
            "invalid (bad query or arguments) and none succeeded — the grid was "
            "reachable, but every question this hunt asked it was malformed, so the "
            "objective was neither confirmed nor ruled out. This report is not "
            "evidence that the network is quiet — it is evidence that nothing was "
            "successfully read. Re-run the hunt; if every query is rejected again, "
            "the queries being written no longer match this grid."
        ),
        note=_QUERIES_REJECTED_NOTE,
        banner=(
            "**Every grid query was rejected — this hunt read nothing.** "
            f"All {rejections} queries were rejected as invalid and none succeeded, so "
            "nothing below rules anything out. The write-up that follows was produced "
            "without grid data."
        ),
    )


def _mark_no_grid_reads(report: Any) -> Any:
    """Stamp a hunt report produced without a single grid query as exactly that.

    The zero-tool arm: the hunt wrote its report without ever asking the grid a
    question (no grid call at all, or only off-grid context lookups). Nothing was
    checked, so nothing was cleared.
    """
    return _mark_blind_hunt(
        report,
        title=_NO_GRID_READS_TITLE,
        detail=(
            "This hunt produced its report without running a single Security Onion "
            "query, so the objective was neither confirmed nor ruled out against the "
            "network's actual telemetry. This report is not evidence that the network "
            "is quiet — it is evidence that nothing was looked at. Re-run the hunt."
        ),
        note=_NO_GRID_READS_NOTE,
        banner=(
            "**No grid reads — this hunt never queried the network.** "
            "Not one grid query ran, so nothing below rules anything out. The "
            "write-up that follows was produced without grid data."
        ),
    )


def _mark_blind_hunt(report: Any, *, title: str, detail: str, note: str, banner: str) -> Any:
    """Stamp a hunt report that never successfully read the grid.

    Three marks, because three different readers need them: the narrative (what
    the analyst reads) gets ``banner`` prepended, a ``visibility_gap`` finding
    carrying ``note`` in ``validator_note`` (the structured, machine-readable
    record, and the channel the deterministic gates already own) is prepended to
    the findings, and confidence drops to ``0.0`` (a hunt that never saw the
    network has no confidence in anything — this is a floor-to-zero, not the
    partial path's 0.5 ceiling).

    The finding is a ``visibility_gap`` and never a ``threat``: the schema's own
    rule is that telemetry you cannot read is a coverage statement, and a blind
    hunt must not page anyone.

    Fail-soft and PURE, like the humility clamp: on any surprise shape the report
    is returned unchanged. The caller's degraded REASON does not depend on this
    succeeding, so a decoration failure can still not land a clean hunt.
    """
    try:
        gap = HuntFinding(
            title=title,
            detail=detail,
            severity="high",
            category="visibility_gap",
            validator_note=note,
        )
        narrative = (banner + "\n\n" + str(getattr(report, "narrative", "") or "")).strip()
        return report.model_copy(
            update={
                "findings": [gap, *report.findings],
                "narrative": narrative,
                "confidence": 0.0,
            }
        )
    except Exception:
        _LOGGER.warning("hunt blind-hunt marker failed; persisting report as-is", exc_info=True)
        return report


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

    # Set from the terminal ``done`` event when the runner's deterministic
    # evidence-count gate fired: the run made not one successful grid read —
    # every grid query failed, or every one was rejected, or none ever ran — so
    # it never looked at the network. Such a hunt must NOT finalize 'complete' —
    # a completed hunt is a covered objective (it seeds the vs-last-run diff, the
    # per-host findings scan and the schedule's freshness marker), and a blind
    # hunt covered nothing.
    grid_blind = False
    try:
        async for ev in run_hunt(ctx, objective=objective, prior=prior):
            if ev.kind == "done" and ev.payload.get("degraded"):
                grid_blind = True
            await recorder.record(ev.kind, ev.sequence, ev.payload)
            yield (
                ev.kind,
                {
                    "session_id": ev.session_id,
                    "sequence": ev.sequence,
                    "payload": ev.payload,
                },
            )
        await recorder.finish("error" if grid_blind else "complete")
        # E2.4 notification trigger — a completed hunt whose report contains a
        # threat-category finding pings on-call. THIN + fail-soft: build a
        # NotifyEvent from the recorder's captured report and fire it (a hard
        # no-op unless notifications are enabled + a webhook is configured). Wrapped
        # so a webhook can never break the finalized hunt.
        #
        # Skipped when the hunt was blind: a "threat" asserted by a hunt that made
        # no successful grid read has nothing behind it, and waking on-call for it
        # is the blindness generating the alarm.
        if not grid_blind:
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
