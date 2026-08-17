"""The chat TURN ENGINE — one read-only agent turn, shared by every chat shape.

soc-ai has more than one conversational surface (per-investigation chat, hunt
follow-ups, the dashboard general chat) and they differ only in what ANCHORS the
turn and where the answer is stored. Everything else — attaching the egress
guard and sanitizing at that boundary, composing the system prompt, reporting
live tool progress, bounding the run with a wall clock, closing the grounding
loop, caveating what stays ungrounded, refusing fabricated tool citations,
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
import logging
import re
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.chat_agent import CHAT_SYSTEM_PROMPT, build_chat_agent
from soc_ai.agent.context import InvestigationContext
from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.models import build_investigator_model
from soc_ai.agent.narrative_grounding import (
    UNVERIFIED_CAVEAT,
    check_narrative_grounding,
    regrounding_instruction,
    scoped_unverified_caveat,
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

MAX_HISTORY = 12  # prior turns embedded into the prompt


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


def _extract_tools(result: Any) -> list[str]:
    """Tool names called during the turn (for the live trace + stored meta)."""
    names: list[str] = []
    for msg in result.all_messages():
        for part in getattr(msg, "parts", []) or []:
            if type(part).__name__ == "ToolCallPart":
                name = getattr(part, "tool_name", "")
                if name:
                    names.append(name)
    return names


def _extract_tool_evidence(result: Any) -> list[dict[str, Any]]:
    """[{tool, result}] from the run, for grounding a verdict proposal."""
    out: list[dict[str, Any]] = []
    for msg in result.all_messages():
        for part in getattr(msg, "parts", []) or []:
            if type(part).__name__ == "ToolReturnPart":
                tool_for = getattr(part, "tool_name", None)
                content = getattr(part, "content", None)
                if tool_for and tool_for != "propose_verdict" and content is not None:
                    out.append({"tool": tool_for, "result": str(content)})
    return out


def _finish_run(result: Any, guard: Any) -> tuple[str, dict[str, Any], Any]:
    """Normalize one agent run into (answer, meta, tool_evidence).

    Desanitizes BEFORE the grounding check so answer artifacts compare against
    seed_context / tool_evidence in the same (real-value) space. Extracted so
    the regrounding loop can re-derive all three per attempt.
    """
    answer = (str(result.output) or "").strip() or "(no answer produced)"
    meta: dict[str, Any] = {"tools": _extract_tools(result)}
    tool_evidence = _extract_tool_evidence(result)
    if guard is not None:
        answer = str(guard.desanitize_obj(answer))
        tool_evidence = guard.desanitize_obj(tool_evidence)
    return answer, meta, tool_evidence


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


async def run_chat_turn(state: Any, spec: ChatTurnSpec) -> None:  # noqa: PLR0915
    """Run one chat turn end to end and resolve *spec.row_id* to a terminal row.

    Never raises: every exit — answer, timeout, failure while preparing, failure
    mid-run — goes through ``spec.finish``, because a pending row that is never
    written is a thread the analyst can never use again (the POST handler 409s
    while one is in flight).
    """
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
        if inputs.append_inventory:
            sys_prompt += await inventory_prompt_block(ctx.elastic, settings)
        if guard is not None:
            # seed_context (stored verdict/rationale from real investigation
            # data) + inventory both carry internal identifiers; sanitize the
            # composed system prompt at the egress boundary. seed_context
            # itself stays RAW — the narrative-grounding check below compares
            # against it in real-value space.
            sys_prompt = guard.sanitize_text(sys_prompt)
        build = inputs.build_agent or _default_build_agent
        agent = build(build_investigator_model(settings), ctx, sys_prompt)
        turn_prompt = build_turn_prompt(inputs.prior, inputs.question)
        if guard is not None:
            # The analyst's question + prior turns carry real identifiers.
            turn_prompt = guard.sanitize_text(turn_prompt)
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
        async with asyncio.timeout(spec.timeout_s):
            result = await agent.run(prompt_for_run)
            answer, meta, tool_evidence = _finish_run(result, guard)
            for _ in range(attempts):
                probe = check_narrative_grounding(
                    answer, seed_context=inputs.seed_context, tool_evidence=tool_evidence
                )
                if probe.grounded or not probe.ungrounded:
                    break
                correction = regrounding_instruction(probe.ungrounded)
                if not correction:
                    break
                if guard is not None:
                    correction = guard.sanitize_text(correction)
                _LOGGER.info(
                    "chat: regrounding attempt %d for %s — %s",
                    reground_used + 1,
                    spec.label,
                    probe.ungrounded[:5],
                )
                prompt_for_run = prompt_for_run + correction
                result = await agent.run(prompt_for_run)
                answer, meta, tool_evidence = _finish_run(result, guard)
                reground_used += 1
        if reground_used:
            meta["regrounding_attempts"] = reground_used

        # Layer 2 — narrative grounding (defense-in-depth for the free-text answer).
        # Detect concrete per-event artifacts (hostnames, domains, IPs, JA3, SMB) the
        # answer asserts and verify each is grounded in either a tool result from this
        # turn or the seeded context. The canonical failure is the zero-tool turn that
        # fabricates a host/DNS/SMB story; when the answer asserts such artifacts and
        # NONE are grounded, append a clearly-marked caveat to the stored answer
        # (rendered as Markdown) and record the verdict in meta.
        grounding = check_narrative_grounding(
            answer, seed_context=inputs.seed_context, tool_evidence=tool_evidence
        )
        if not grounding.grounded:
            _LOGGER.warning(
                "chat: ungrounded narrative for %s (tools=%d) — %s",
                spec.label,
                len(meta["tools"]),
                grounding.reason,
            )
            # A turn that RAN tools gets the scoped caveat naming the suspect
            # claims — the blanket "not backed by a tool result" under a
            # footer listing real tool calls read as a contradiction
            # (dogfood 2026-07-15). Zero-tool turns keep the blanket wording.
            answer = answer + (
                scoped_unverified_caveat(grounding.ungrounded)
                if tool_evidence and grounding.ungrounded
                else UNVERIFIED_CAVEAT
            )
            meta["narrative_grounding"] = {
                "grounded": False,
                "ungrounded": grounding.ungrounded,
                "reason": grounding.reason,
            }
        else:
            meta["narrative_grounding"] = {"grounded": True}

        # F1: a zero-tool turn must never present tool-call citations it never
        # made ("verified by the tools", `t_enrich_ip(...)`) — that is fabricated
        # evidence to the analyst. Force the unverified caveat + ungrounded meta.
        if not meta["tools"] and _FABRICATED_TOOL_CITATION_RE.search(answer):
            _LOGGER.warning(
                "chat: fabricated tool citations on a zero-tool turn for %s", spec.label
            )
            if meta.get("narrative_grounding", {}).get("grounded", True):
                answer = answer + UNVERIFIED_CAVEAT
            meta["narrative_grounding"] = {
                "grounded": False,
                "reason": "fabricated tool citations on a zero-tool turn",
            }

        if inputs.finalize_meta is not None:
            inputs.finalize_meta(meta, tool_evidence, guard)
        await spec.finish(content=answer, status="done", meta=meta)
    except TimeoutError:
        # The turn hit spec.timeout_s (the asyncio.timeout block above). Write a
        # user-facing, actionable terminal row so the pending status never gets stuck.
        _LOGGER.warning("chat turn timed out for %s after %ss", spec.label, spec.timeout_s)
        await _persist_terminal_error(
            spec,
            f"The assistant ran out of time on this question (hit the {spec.timeout_s}s "
            "limit). Try a narrower follow-up.",
        )
    except Exception as e:
        _LOGGER.exception("chat turn failed for %s", spec.label)
        # Scrub the exception text before it becomes user-facing content — a
        # verbose provider/gateway error body could otherwise echo a credential
        # (same defensive scrub probes.py applies to its error surfaces).
        await _persist_terminal_error(
            spec, f"Sorry — the chat turn failed ({_scrub(str(e))}). Try again."
        )


async def _persist_terminal_error(spec: ChatTurnSpec, content: str) -> None:
    """Write a terminal ``error`` row, swallowing+logging any secondary error.

    The last line of defense in run_chat_turn's handlers: a failure here can't be
    retried in-band, so it is logged loudly (the row stays pending → the chat
    reaper resolves it on the next sweep / restart).
    """
    try:
        await spec.finish(content=content, status="error", meta=None)
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
