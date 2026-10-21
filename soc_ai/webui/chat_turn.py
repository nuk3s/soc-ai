"""The chat TURN ENGINE — one read-only agent turn, shared by every chat shape.

soc-ai has more than one conversational surface (per-investigation chat, hunt
follow-ups, the dashboard general chat) and they differ only in what ANCHORS the
turn and where the answer is stored. Everything else — attaching the egress
guard and sanitizing at that boundary, composing the system prompt, reporting
live tool progress, bounding the run with a wall clock, closing the grounding
loop, redacting what stays ungrounded, refusing fabricated tool citations,
resolving the pending row on every terminal path — is identical.

It did not stay identical when it was copied. ``hunt_console_manager`` forked
``chat_manager`` and the hunt chat therefore has no progress reporting, no
grounding check and no regrounding loop: it missed both features shipped
2026-08-06 because they landed in the original only. This module is the
un-forked half, so the next chat shape inherits the guardrails instead of
re-deriving them.

The shape-specific half arrives as a :class:`ChatTurnSpec`. The engine NEVER
touches a store: it persists exclusively through the spec's callables, which is
what keeps it from re-acquiring a favourite table.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.models import Model
from pydantic_ai.usage import UsageLimits

from soc_ai.agent._partial_replay import repair_dangling_tool_calls, replay_reasoning_context
from soc_ai.agent.chat_agent import CHAT_SYSTEM_PROMPT, build_chat_agent
from soc_ai.agent.context import InvestigationContext
from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.models import build_investigator_model
from soc_ai.agent.narrative_grounding import (
    NOTHING_GROUNDED_REPLY,
    check_narrative_grounding,
    redact_ungrounded,
    regrounding_instruction,
    strip_correction_talk,
    strip_sentences,
)
from soc_ai.agent.prompts import oql_primer_block
from soc_ai.so_client.inventory import inventory_prompt_block
from soc_ai.webui.probes import _scrub

_LOGGER = logging.getLogger(__name__)

# Strong refs for in-flight progress writes — asyncio only holds weak refs to
# tasks, so without this a write can be garbage-collected before it commits.
_PROGRESS_TASKS: set[asyncio.Task[None]] = set()

# Tool-call-shaped citations the model sometimes fabricates on a zero-tool turn
# ("verified by the tools", `t_enrich_ip(...)`). If meta.tools is empty and the
# prose contains these, the answer is claiming evidence it never produced.
_FABRICATED_TOOL_CITATION_RE = re.compile(
    r"\bt_[a-z][a-z0-9_]*\s*\(|verified by the tool|evidence citations?\b",
    re.IGNORECASE,
)

# Same shapes as above, widened for REDACTION rather than detection: consumes
# the full `t_xxx(args)` call through its closing paren, and "tool(s)" /
# "citation(s)" whole, so the stripped list records the whole citation. Kept
# separate from the detection regex above so widening this one can never
# change what a zero-tool turn gets FLAGGED for — only what gets redacted once
# it is.
_FABRICATED_CITATION_REDACT_RE = re.compile(
    r"\bt_[a-z][a-z0-9_]*\s*\([^)]*\)|verified by the tools?|evidence citations?",
    re.IGNORECASE,
)

MAX_HISTORY = 12  # prior turns embedded into the prompt

# Wall clock for the TAIL that runs after the agent has already produced an
# answer: the grounding re-check, ground-or-strip redaction, finalize_meta,
# and spec.finish's DB write. Normally sub-millisecond sync code plus one DB
# round trip — but it sits entirely OUTSIDE the `asyncio.timeout(spec.timeout_s)`
# block that bounds the agent run (that block ends the instant agent.run()
# returns), so nothing bounded it at all. A live incident (2026-08-21) left a
# turn's answer already generated but its pending row unresolved for several
# minutes while this tail contended with a concurrent background job for the
# same SQLite database; nothing here would have caught it even if the
# contention had never cleared. Small and fixed rather than derived from
# spec.timeout_s: this phase's real work is orders of magnitude cheaper than
# the agent run it follows, so it does not need — and should not get — that
# budget too.
_TAIL_TIMEOUT_S = 20

# Wall clock for the partial answer. When the agent run hits ``spec.timeout_s``
# after its tools already returned results, a no-tools pass writes an answer
# from those results. The range chat of 2026-10-19 ran 12 event queries,
# timed out at 300 s and showed only "ran out of time": every result was
# discarded. The reaper adds this budget to the chat age, so it does not
# reap a turn while the partial answer is written.
PARTIAL_ANSWER_TIMEOUT_S = 60

# The progress entry the partial pass writes, so the panel names the step.
PARTIAL_ANSWER_STEP = "partial_answer"

# What a tool call that the deadline cut off returns in the replayed
# transcript. The partial pass reads it as "no result".
_PARTIAL_CLOSURE_CONTENT = "Not run. The time for the question ran out."

# The instructions of the partial pass. ``instructions=`` reaches the model on
# every request, also with a replayed history (see build_hunt_synthesizer).
PARTIAL_ANSWER_INSTRUCTIONS = (
    "The time for this question is over. You cannot call a tool now. "
    "Answer the analyst's question from the tool results above and the context only. "
    "Say which part of the question those results do not answer. "
    "Do not state a fact that no tool result and no context line states."
)


class FinishRow(Protocol):
    """Write the turn's terminal row. The engine's ONLY persistence surface."""

    async def __call__(self, *, content: str, status: str, meta: dict[str, Any] | None) -> None: ...


class SetProgress(Protocol):
    """Record the tools called so far on the still-pending row (cosmetic)."""

    async def __call__(self, tools: list[str]) -> None: ...


class BuildAgent(Protocol):
    """Build the turn's agent. A seam, not a convenience: the chat shapes differ
    in which proposal tool they register (``propose_verdict`` vs none)."""

    def __call__(
        self, model: Model, ctx: InvestigationContext, system_prompt: str
    ) -> Agent[None, str]: ...


def _default_build_agent(
    model: Model, ctx: InvestigationContext, system_prompt: str
) -> Agent[None, str]:
    """Read-only chat agent with no proposal tool (the hunt-chat shape)."""
    return build_chat_agent(model, ctx, system_prompt=system_prompt)


@dataclass(slots=True)
class TurnInputs:
    """What preparing one turn produced — the anchor and the agent to run.

    Separate from :class:`ChatTurnSpec` because preparing a turn does real I/O
    (loading the investigation, fetching alert context, reading the grid's
    inventory) and can fail; the engine has to be able to write a terminal row
    for that failure, so the persistence callables must exist BEFORE this does.
    """

    ctx: InvestigationContext
    # The anchor block embedded in the system prompt. Also the corpus the
    # grounding check compares the answer against, so anything legitimately
    # stated without a tool call has to be in here.
    seed_context: str
    question: str
    prior: list[tuple[str, str]] = field(default_factory=list)
    # Template containing a single ``{context}`` placeholder.
    system_prompt: str = CHAT_SYSTEM_PROMPT
    # ``"hunt"`` swaps the alert-triage OQL examples for telemetry-first ones —
    # sweep-shaped chats should slice datasets, not pivot from an alert.
    oql_flavor: str = "triage"
    # Whether the engine appends the grid's dataset inventory to the system
    # prompt. A shape sets False when its seed_context ALREADY carries the
    # inventory — the general chat must, because seed_context is the corpus the
    # grounding check grades against, and without it the answer to "what
    # datasets do I have" ships with an Unverified caveat. Default True keeps
    # the investigation/hunt prompts byte-identical.
    append_inventory: bool = True
    build_agent: BuildAgent | None = None
    # Post-answer hook: (meta, tool_evidence, egress_guard). Where a shape drains
    # its proposal sink and stamps its own ``meta.kind``.
    finalize_meta: Callable[[dict[str, Any], list[dict[str, Any]], Any], None] | None = None


@dataclass(slots=True)
class ChatTurnSpec:
    """One chat shape's contract with the turn engine."""

    row_id: int
    # Identifies the turn in logs ("inv=abc123", "thread=analyst@lab").
    label: str
    # Wall clock for the agent run. Per-shape state, not a settings lookup: the
    # hunt chat's budget is minutes where the investigation chat's is seconds.
    timeout_s: float
    finish: FinishRow
    prepare: Callable[[], Awaitable[TurnInputs | None]]
    # None disables live progress. A shape opts in by supplying the writer for
    # its own table.
    set_progress: SetProgress | None = None


def build_turn_prompt(prior: list[tuple[str, str]], question: str) -> str:
    """Fold the bounded prior turns into the new question."""
    if not prior:
        return question
    convo = "\n\n".join(
        f"{'Analyst' if role == 'user' else 'You'}: {content}" for role, content in prior
    )
    return f"Conversation so far:\n{convo}\n\nAnalyst's new question: {question}"


def split_history(
    history: list[tuple[str, str]], *, max_history: int = MAX_HISTORY
) -> tuple[str, list[tuple[str, str]]]:
    """Split a stored thread into (this turn's question, bounded prior turns).

    The question is the latest row and is always a ``user`` row on the live path
    — the POST handler writes it immediately before spawning the turn. Anything
    else means the thread is in a shape we did not write (a reaped row, a
    hand-edited DB), so the turn runs with an empty question rather than
    silently answering an older question again.
    """
    if history and history[-1][0] == "user":
        return history[-1][1], history[:-1][-max_history:]
    return "", history


def _tool_names(messages: list[Any]) -> list[str]:
    """Tool names called in a message log, oldest first."""
    names: list[str] = []
    for msg in messages:
        for part in getattr(msg, "parts", []) or []:
            if type(part).__name__ == "ToolCallPart":
                name = getattr(part, "tool_name", "")
                if name:
                    names.append(name)
    return names


def _tool_returns(messages: list[Any]) -> list[dict[str, Any]]:
    """[{tool, result}] from a message log. A proposal is not evidence."""
    out: list[dict[str, Any]] = []
    for msg in messages:
        for part in getattr(msg, "parts", []) or []:
            if type(part).__name__ == "ToolReturnPart":
                tool_for = getattr(part, "tool_name", None)
                content = getattr(part, "content", None)
                if tool_for and tool_for != "propose_verdict" and content is not None:
                    out.append({"tool": tool_for, "result": str(content)})
    return out


def _tool_call_args(messages: list[Any]) -> list[dict[str, Any]]:
    """[{tool, args}] from a message log."""
    out: list[dict[str, Any]] = []
    for msg in messages:
        for part in getattr(msg, "parts", []) or []:
            if type(part).__name__ != "ToolCallPart":
                continue
            tool_for = getattr(part, "tool_name", None)
            args = getattr(part, "args", None)
            if isinstance(args, str):
                with contextlib.suppress(ValueError):
                    args = json.loads(args)
            if tool_for and tool_for != "propose_verdict" and isinstance(args, dict):
                out.append({"tool": tool_for, "args": args})
    return out


def _extract_tools(result: Any) -> list[str]:
    """Tool names called during the turn (for the live trace + stored meta)."""
    return _tool_names(result.all_messages())


def _extract_tool_evidence(result: Any) -> list[dict[str, Any]]:
    """[{tool, result}] from the run, for grounding a verdict proposal."""
    return _tool_returns(result.all_messages())


def _extract_tool_calls(result: Any) -> list[dict[str, Any]]:
    """[{tool, args}] from the run: the names a call used ground a claim too.

    A dataset that a zero-hit query asked for grounds the claim that the
    dataset holds nothing (``narrative_grounding.argument_names``).
    """
    return _tool_call_args(result.all_messages())


def _finish_run(result: Any, guard: Any) -> tuple[str, dict[str, Any], Any, Any]:
    """Normalize one agent run into (answer, meta, tool_evidence, tool_calls).

    Desanitizes BEFORE the grounding check so answer artifacts compare against
    seed_context / tool_evidence / tool_calls in the same (real-value) space.
    Extracted so the regrounding loop can re-derive all four per attempt.
    """
    answer = (str(result.output) or "").strip() or "(no answer produced)"
    meta: dict[str, Any] = {"tools": _extract_tools(result)}
    tool_evidence = _extract_tool_evidence(result)
    tool_calls = _extract_tool_calls(result)
    if guard is not None:
        answer = str(guard.desanitize_obj(answer))
        tool_evidence = guard.desanitize_obj(tool_evidence)
        tool_calls = guard.desanitize_obj(tool_calls)
    return answer, meta, tool_evidence, tool_calls


def _redact_fabricated_citations(answer: str) -> tuple[str, list[str]]:
    """Ground-or-strip for the OTHER shape a zero-tool answer can fake: not an
    ungrounded identifier (:func:`~soc_ai.agent.narrative_grounding.redact_ungrounded`
    handles that), but a citation of evidence that was never pulled — "verified
    by the tools", `t_enrich_ip(...)`. Takes out each sentence that carries a
    fabricated citation, with no placeholder in its place, and returns the
    citations it removed, so the caller can record them in meta (the trace
    keeps the receipts) the same way the artifact path does.
    """
    stripped = [m.group(0) for m in _FABRICATED_CITATION_REDACT_RE.finditer(answer)]
    redacted = strip_sentences(
        answer, lambda sentence: bool(_FABRICATED_CITATION_REDACT_RE.search(sentence))
    )
    return redacted, stripped


def _progress_reporter(write: SetProgress) -> Callable[[str], None]:
    """Adapt the toolset's sync progress hook to the spec's async writer.

    Scheduled fire-and-forget because the callback runs inside the tool wrapper
    (sync) while the write is async. Fully guarded — a progress write must never
    break the turn producing the real answer.
    """
    called: list[str] = []

    def _note_tool(name: str) -> None:
        called.append(name)
        snapshot = list(called)

        async def _write() -> None:
            try:
                await write(snapshot)
            except Exception:  # cosmetic — never surface
                _LOGGER.debug("chat progress write failed", exc_info=True)

        with contextlib.suppress(RuntimeError):  # no running loop (sync tests)
            task = asyncio.create_task(_write())
            _PROGRESS_TASKS.add(task)
            task.add_done_callback(_PROGRESS_TASKS.discard)

    return _note_tool


async def run_chat_turn(state: Any, spec: ChatTurnSpec) -> None:  # noqa: PLR0915, PLR0912
    """Run one chat turn end to end and resolve *spec.row_id* to a terminal row.

    Never raises: every exit — answer, timeout, failure while preparing, failure
    mid-run — goes through ``spec.finish``, because a pending row that is never
    written is a thread the analyst can never use again (the POST handler 409s
    while one is in flight).
    """
    # Which phase raised, for the handlers below to report accurately:
    # "prepare" covers spec.prepare() and the prompt build (store and grid
    # reads), "run" covers the agent-run block (model calls only, because every
    # tool catches its own grid failure), and "finalize" covers the post-answer
    # tail bounded by `_TAIL_TIMEOUT_S` (an answer that was produced but could
    # not be saved promptly, a different failure with a different message).
    stage = "prepare"
    try:
        settings = state.settings
        inputs = await spec.prepare()
        if inputs is None:
            # The shape already resolved the row itself — the demo
            # short-circuit, which must not build a model or touch the grid.
            return
        ctx = inputs.ctx
        # Live progress: report each tool the turn calls onto the pending row so
        # the poll endpoint can show what the agent is DOING (dogfood
        # 2026-08-06 — the turn was "nothing, then everything").
        if spec.set_progress is not None:
            ctx.on_tool_call = _progress_reporter(spec.set_progress)
        # Cloud-egress guard (opt-in): same pattern as the orchestrator/hunt
        # runner. Attach BEFORE building the agent so register_read_tools
        # wraps the tool closures. `is True` (not truthiness) so a MagicMock
        # settings double in tests can never flip redaction on.
        if settings.analyst_cloud_redaction is True and ctx.egress_guard is None:
            ctx.egress_guard = await EgressGuard.for_settings(
                settings, getattr(state, "db_sessionmaker", None)
            )
        guard = ctx.egress_guard
        # The chat agent runs OQL — append the primer + the auto-discovered dataset
        # inventory so it writes valid queries and knows what data exists on this grid.
        # A shape whose seed_context already carries the inventory opts out
        # (append_inventory=False) rather than stating the same block twice.
        sys_prompt = inputs.system_prompt.format(context=inputs.seed_context) + oql_primer_block(
            flavor=inputs.oql_flavor
        )
        inv_block = ""
        if inputs.append_inventory:
            inv_block = await inventory_prompt_block(ctx.elastic, settings)
            sys_prompt += inv_block
        if guard is not None:
            # seed_context (stored verdict/rationale from real investigation
            # data) + inventory both carry internal identifiers; sanitize the
            # composed system prompt at the egress boundary. seed_context
            # itself stays RAW — the narrative-grounding check below compares
            # against it in real-value space.
            sys_prompt = guard.sanitize_text(sys_prompt)
            # Independent fail-closed residue sweep over the DYNAMIC (untrusted)
            # system-prompt fragments — the identifiers only the sweep catches
            # (NetBIOS bare hostnames, credential usernames) must not egress.
            # The STATIC template + OQL primer stay outside the sweep: the
            # primer's worked examples (`workstation-01`) are residue-shaped by
            # construction and would otherwise fail-close every turn on
            # version-controlled repo text that carries no deployment data.
            fail_closed = settings.analyst_redaction_fail_closed is True
            for fragment in (inputs.seed_context, inv_block):
                guard.check_or_raise(guard.sanitize_text(fragment), fail_closed=fail_closed)
        build = inputs.build_agent or _default_build_agent
        agent = build(build_investigator_model(settings), ctx, sys_prompt)
        turn_prompt = build_turn_prompt(inputs.prior, inputs.question)
        if guard is not None:
            # The analyst's question + prior turns carry real identifiers.
            turn_prompt = guard.sanitize_text(turn_prompt)
            # Fully dynamic, so the whole final user string is swept — refuse
            # to call the model rather than egress a sanitize miss.
            guard.check_or_raise(
                turn_prompt, fail_closed=settings.analyst_redaction_fail_closed is True
            )
        # Run the turn, then CLOSE THE GROUNDING LOOP: if the answer asserts
        # per-event facts that appear in neither this turn's tool results nor
        # the seeded evidence, hand the validator's finding back to the agent
        # and let it fix its own answer (cite it or drop it). Bounded by
        # `chat_regrounding_attempts`; the caveat below remains the terminal
        # fallback when the agent will not comply.
        #
        # Why this exists: on 2026-08-05 the chat asserted `auth.success=true`
        # to justify overturning a correct true_positive verdict. The validator
        # flagged exactly that claim — and the answer shipped anyway with a
        # caveat attached. Detecting a fabrication and then publishing it is
        # not a guardrail.
        attempts = max(0, int(getattr(settings, "chat_regrounding_attempts", 1)))
        prompt_for_run = turn_prompt
        reground_used = 0
        # The long part. Bound it with `asyncio.timeout` (NOT `wait_for` around
        # the whole task): on the deadline this raises `TimeoutError` (a normal
        # Exception in 3.11+), so the `except` below runs and writes a terminal
        # error row — instead of `wait_for`'s CancelledError, which is a
        # BaseException that the except never catches and which leaves the row
        # stuck pending forever.
        stage = "run"
        # ``gathered`` is the first run's message log, kept by
        # ``capture_run_messages`` as the run goes. When the deadline cuts the
        # run off, the tool results in it are what the partial answer reads.
        gathered: list[Any] = []
        answered = False
        try:
            async with asyncio.timeout(spec.timeout_s):
                with capture_run_messages() as gathered:
                    result = await agent.run(prompt_for_run)
                answer, meta, tool_evidence, tool_calls = _finish_run(result, guard)
                answered = True
                for _ in range(attempts):
                    probe = check_narrative_grounding(
                        answer,
                        seed_context=inputs.seed_context,
                        tool_evidence=tool_evidence,
                        tool_calls=tool_calls,
                    )
                    if probe.grounded or not probe.ungrounded:
                        break
                    correction = regrounding_instruction(probe.ungrounded)
                    if not correction:
                        break
                    if guard is not None:
                        correction = guard.sanitize_text(correction)
                        # The correction quotes the answer's ungrounded
                        # artifacts. It is dynamic text, so sweep it before the
                        # re-run egresses it.
                        guard.check_or_raise(
                            correction, fail_closed=settings.analyst_redaction_fail_closed is True
                        )
                    _LOGGER.info(
                        "chat: regrounding attempt %d for %s — %s",
                        reground_used + 1,
                        spec.label,
                        probe.ungrounded[:5],
                    )
                    prompt_for_run = prompt_for_run + correction
                    result = await agent.run(prompt_for_run)
                    answer, meta, tool_evidence, tool_calls = _finish_run(result, guard)
                    reground_used += 1
        except TimeoutError:
            if not answered:
                partial = await _write_partial_answer(
                    settings, spec, guard=guard, gathered=list(gathered)
                )
                if partial is None:
                    # No tool result to answer from, or the partial pass
                    # failed. The handler below writes the timeout row, with
                    # the tools that ran.
                    raise _TurnTimedOut(_tool_names(list(gathered))) from None
                answer, meta, tool_evidence, tool_calls = partial
            else:
                # A regrounding re-run hit the deadline. The last answer
                # stands, and the tail below grounds or strips it.
                _LOGGER.warning(
                    "chat: regrounding for %s hit the %ss deadline; keeping the last answer",
                    spec.label,
                    spec.timeout_s,
                )
        if reground_used:
            meta["regrounding_attempts"] = reground_used
            # The analyst never saw the correction. A sentence about it is the
            # grounder's vocabulary in the reply (2026-10-02: "The correction is
            # now properly grounded: ...").
            answer = strip_correction_talk(answer) or answer

        # The answer is produced from here on — what remains is bookkeeping
        # (grounding re-check, ground-or-strip redaction, finalize_meta) and one
        # DB write (spec.finish), not model/tool work. It still gets its OWN
        # wall clock (see _TAIL_TIMEOUT_S) rather than none at all.
        stage = "finalize"
        async with asyncio.timeout(_TAIL_TIMEOUT_S):
            # Layer 2 — narrative grounding (defense-in-depth for the free-text answer).
            # Detect concrete per-event artifacts (hostnames, domains, IPs, JA3, SMB) the
            # answer asserts and verify each is grounded in either a tool result from this
            # turn or the seeded context. The canonical failure is the zero-tool turn that
            # fabricates a host/DNS/SMB story. Ground-or-strip (2026-08-20, the owner's
            # ruling): once the regrounding loop above has exhausted its attempts, an
            # artifact that is STILL ungrounded gets mechanically redacted out of the
            # answer — never shipped under a "verify before acting" caveat naming it.
            grounding = check_narrative_grounding(
                answer,
                seed_context=inputs.seed_context,
                tool_evidence=tool_evidence,
                tool_calls=tool_calls,
            )
            if not grounding.grounded:
                _LOGGER.warning(
                    "chat: ungrounded narrative for %s (tools=%d) — %s",
                    spec.label,
                    len(meta["tools"]),
                    grounding.reason,
                )
                # Each ungrounded artifact leaves with its clause: a list item,
                # else its sentence. No placeholder and no closing line says so
                # (owner, 2026-08-21: ground or strip, never banner; a
                # 2026-10-02 host chat reply still carried both). Tool calls or
                # not, the treatment is identical. The meta keeps the receipts.
                redacted = redact_ungrounded(answer, grounding.ungrounded)
                stripped = list(grounding.ungrounded) if redacted != answer else []
                if stripped:
                    answer = redacted or NOTHING_GROUNDED_REPLY
                meta["narrative_grounding"] = {
                    "grounded": False,
                    "ungrounded": grounding.ungrounded,
                    "stripped": stripped,
                    "reason": grounding.reason,
                }
            else:
                meta["narrative_grounding"] = {"grounded": True}

            # F1: a zero-tool turn must never present tool-call citations it never
            # made ("verified by the tools", `t_enrich_ip(...)`) — that is fabricated
            # evidence to the analyst. Same ground-or-strip policy, applied to the
            # OTHER shape a zero-tool answer can fake: strip the sentence that
            # carries the fabricated citation rather than caveat around it. ALWAYS
            # redact — even when Layer 2 above already fired — because a
            # confabulating zero-tool model routinely produces BOTH shapes in the
            # same breath (an ungrounded artifact AND a fake citation); skipping
            # the redaction here left the citation phrase shipping unredacted
            # while meta claimed it was caught (2026-08-20 review finding). The
            # two detectors' reasons/stripped lists merge rather than clobber
            # each other.
            if not meta["tools"] and _FABRICATED_TOOL_CITATION_RE.search(answer):
                _LOGGER.warning(
                    "chat: fabricated tool citations on a zero-tool turn for %s", spec.label
                )
                prior_grounding = meta.get("narrative_grounding", {})
                answer, fab_stripped = _redact_fabricated_citations(answer)
                answer = answer or NOTHING_GROUNDED_REPLY
                if prior_grounding.get("grounded", True):
                    meta["narrative_grounding"] = {
                        "grounded": False,
                        "reason": "fabricated tool citations on a zero-tool turn",
                        "stripped": fab_stripped,
                    }
                else:
                    prior_reason = prior_grounding.get("reason") or ""
                    merged_reason = (
                        f"{prior_reason}; fabricated tool citations on a zero-tool turn"
                        if prior_reason
                        else "fabricated tool citations on a zero-tool turn"
                    )
                    meta["narrative_grounding"] = {
                        **prior_grounding,
                        "reason": merged_reason,
                        "stripped": [*prior_grounding.get("stripped", []), *fab_stripped],
                    }

            if inputs.finalize_meta is not None:
                inputs.finalize_meta(meta, tool_evidence, guard)
            await spec.finish(content=answer, status="done", meta=meta)
    except _TurnTimedOut as e:
        _LOGGER.warning("chat turn timed out for %s after %ss", spec.label, spec.timeout_s)
        await _persist_terminal_error(
            spec,
            timeout_text(spec.timeout_s),
            meta={"tools": e.tools, "timed_out": True} if e.tools else None,
        )
    except TimeoutError:
        if stage == "finalize":
            # The answer existed; only saving it ran over _TAIL_TIMEOUT_S (e.g.
            # DB contention). Distinct log + message from the agent-run timeout
            # below — "narrower question" would be actively wrong advice here.
            _LOGGER.warning(
                "chat turn tail timed out for %s after %ss (post-answer finalize/persist)",
                spec.label,
                _TAIL_TIMEOUT_S,
            )
            await _persist_terminal_error(
                spec,
                "The assistant wrote the reply and ran out of time saving the reply. "
                "The store was slow. Try again.",
            )
        else:
            # A timeout outside the agent-run block. Write a user-facing,
            # actionable terminal row so the pending status never gets stuck.
            _LOGGER.warning("chat turn timed out for %s after %ss", spec.label, spec.timeout_s)
            await _persist_terminal_error(spec, timeout_text(spec.timeout_s))
    except Exception as e:
        _LOGGER.exception("chat turn failed for %s", spec.label)
        await _persist_terminal_error(spec, failure_text(e, stage=stage))


class _TurnTimedOut(Exception):
    """The agent run hit its deadline and no partial answer was written."""

    def __init__(self, tools: list[str]) -> None:
        super().__init__("chat turn timed out")
        self.tools = tools


def _seconds(value: float) -> str:
    """300.0 as "300", 0.01 as "0.01"."""
    return f"{value:g}"


def timeout_text(timeout_s: float) -> str:
    """The terminal row of a turn that hit its deadline with no answer."""
    return (
        f"soc-ai stopped after {_seconds(timeout_s)} seconds with no answer. "
        "Ask a narrower question."
    )


def partial_note(timeout_s: float, results: int) -> str:
    """The first line of a partial answer. It says what the answer rests on."""
    calls = "tool call" if results == 1 else "tool calls"
    return (
        f"soc-ai stopped the question after {_seconds(timeout_s)} seconds. "
        f"This answer uses only the results of the {results} {calls} that finished."
    )


# Exception class names that mean "the gateway did not take the call". The
# OpenAI client raises APIConnectionError ("Connection error.") and httpx and
# aiohttp raise their own connect errors. A chat read "The chat turn failed:
# Connection error.. Try again." while the gateway was down (dogfood
# 2026-10-19, H1).
_UNREACHABLE_NAMES = frozenset(
    {
        "APIConnectionError",
        "APITimeoutError",
        "ConnectError",
        "ConnectTimeout",
        "ClientConnectorError",
        "ServerDisconnectedError",
    }
)


def _is_unreachable(exc: BaseException) -> bool:
    """True when the exception, or one it came from, is a connect failure."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ConnectionError) or any(
            cls.__name__ in _UNREACHABLE_NAMES for cls in type(cur).__mro__
        ):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def failure_text(exc: BaseException, *, stage: str) -> str:
    """The terminal row of a turn that failed.

    The agent run calls only the model gateway: every tool catches its own
    grid failure and hands the model a result. A connect failure in that stage
    is the gateway. The detail of any other failure is scrubbed first, because
    a verbose provider error body can echo a credential.
    """
    if stage == "run" and _is_unreachable(exc):
        return "The model did not answer. soc-ai cannot reach the model gateway. Try again later."
    detail = _scrub(str(exc)).strip().rstrip(".").strip()
    if not detail:
        return "The chat turn failed. Try again."
    return f"The chat turn failed. {detail}. Try again."


async def _write_partial_answer(
    settings: Any,
    spec: ChatTurnSpec,
    *,
    guard: Any,
    gathered: list[Any],
) -> tuple[str, dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]] | None:
    """Answer from the tool results of a run that hit its deadline.

    Returns (answer, meta, tool_evidence, tool_calls) for the tail, which
    grounds or strips the answer like any other. None when no tool returned a
    result, or when the partial pass fails or runs over
    :data:`PARTIAL_ANSWER_TIMEOUT_S`.

    The pass is a no-tools agent over the replayed message log, the pattern
    of the hunt's partial report (``hunt_runner._synthesize_partial_hunt``).
    The log is in label space when a guard is on, because the model only ever
    saw labels. The answer is desanitized after the run.
    """
    results = _tool_returns(gathered)
    if not results:
        return None
    names = _tool_names(gathered)
    if spec.set_progress is not None:
        # Name the step on the panel. The progress write is cosmetic.
        with contextlib.suppress(Exception):
            await spec.set_progress([*names, PARTIAL_ANSWER_STEP])
    user_msg = (
        replay_reasoning_context(gathered) + "Answer the question now from the tool results above."
    )
    try:
        if guard is not None:
            user_msg = guard.sanitize_text(user_msg)
            guard.check_or_raise(
                user_msg, fail_closed=settings.analyst_redaction_fail_closed is True
            )
        synth: Agent[None, str] = Agent(
            build_investigator_model(settings),
            output_type=str,
            instructions=PARTIAL_ANSWER_INSTRUCTIONS,
        )
        async with asyncio.timeout(PARTIAL_ANSWER_TIMEOUT_S):
            result = await synth.run(
                user_msg,
                message_history=repair_dangling_tool_calls(
                    gathered, closure_content=_PARTIAL_CLOSURE_CONTENT
                ),
                usage_limits=UsageLimits(request_limit=2, tool_calls_limit=0),
            )
    except Exception:
        _LOGGER.warning("chat: the partial answer failed for %s", spec.label, exc_info=True)
        return None
    answer = str(result.output or "").strip()
    if not answer:
        return None
    tool_evidence: Any = results
    tool_calls: Any = _tool_call_args(gathered)
    if guard is not None:
        answer = str(guard.desanitize_obj(answer))
        tool_evidence = guard.desanitize_obj(tool_evidence)
        tool_calls = guard.desanitize_obj(tool_calls)
    answer = f"{partial_note(spec.timeout_s, len(results))}\n\n{answer}"
    meta: dict[str, Any] = {"tools": names, "partial": True}
    return answer, meta, tool_evidence, tool_calls


async def _persist_terminal_error(
    spec: ChatTurnSpec, content: str, *, meta: dict[str, Any] | None = None
) -> None:
    """Write a terminal ``error`` row, swallowing+logging any secondary error.

    The last line of defense in run_chat_turn's handlers: a failure here can't be
    retried in-band, so it is logged loudly (the row stays pending → the chat
    reaper resolves it on the next sweep / restart).
    """
    try:
        await spec.finish(content=content, status="error", meta=meta)
    except Exception:
        _LOGGER.exception(
            "chat: FAILED to persist error row for msg=%s — pending stuck", spec.row_id
        )


class ChatTaskManager:
    """Tracks in-flight chat-turn tasks to prevent GC collection.

    Shape-agnostic: it holds a strong ref to the runner (asyncio only keeps weak
    ones) and guarantees a still-pending row gets resolved when the task did not
    exit cleanly. Both are properties of running a turn in the background, not of
    any one chat surface, so every shape gets them from here.
    """

    def __init__(self) -> None:
        self._tasks: dict[int, asyncio.Task[None]] = {}
        # Backstop tasks spawned from the (sync) done-callback. Held so the event
        # loop keeps a strong reference until they finish (else they can be GC'd
        # mid-flight); each discards itself on completion.
        self._backstops: set[asyncio.Task[None]] = set()

    def spawn(
        self,
        *,
        row_id: int,
        runner: Coroutine[Any, Any, None],
        backstop: Callable[[], Awaitable[None]],
    ) -> None:
        """Run *runner* in the background, keyed on the pending row it resolves.

        NOTE: the per-turn timeout lives INSIDE the runner (an `asyncio.timeout`
        block around agent.run), NOT here as `asyncio.wait_for(..., timeout=)`.
        `wait_for` enforces the deadline by *cancelling* the coroutine, which
        raises `asyncio.CancelledError` — a `BaseException` on 3.11+, so the
        runner's `except Exception` never runs and the assistant row is left
        stuck `pending` forever.
        """
        task: asyncio.Task[None] = asyncio.create_task(runner)
        self._tasks[row_id] = task
        task.add_done_callback(lambda t: self._on_task_done(row_id, backstop, t))

    def _on_task_done(
        self,
        row_id: int,
        backstop: Callable[[], Awaitable[None]],
        task: asyncio.Task[None],
    ) -> None:
        """Defense-in-depth: clear the registry and, if the task ended via
        cancellation or an exception that escaped the runner (e.g. true shutdown
        cancellation, or the narrow window before the runner's own handler runs),
        resolve a still-``pending`` row to a terminal ``error`` state.

        run_chat_turn already persists a terminal row on success/timeout/exception;
        this callback only fires a backstop write when the task did NOT exit
        cleanly. The backstop write is itself spawned as a task (the callback is
        sync) and best-effort: a still-pending row is the only thing it touches.
        """
        self._tasks.pop(row_id, None)
        if task.cancelled():
            _LOGGER.warning("chat: task for msg=%s was cancelled", row_id)
            self._spawn_backstop(backstop)
            return
        exc = task.exception()
        if exc is not None:
            _LOGGER.error(
                "chat: task for msg=%s ended with an unhandled exception: %r", row_id, exc
            )
            self._spawn_backstop(backstop)

    def _spawn_backstop(self, backstop: Callable[[], Awaitable[None]]) -> None:
        """Spawn the pending-row resolver, holding a strong reference so the
        loop doesn't GC it mid-flight."""
        bt: asyncio.Task[None] = asyncio.ensure_future(backstop())
        self._backstops.add(bt)
        bt.add_done_callback(self._backstops.discard)
