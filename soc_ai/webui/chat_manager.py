"""ChatManager — runs a "Chat about this" turn as a background task.

Mirrors HuntManager: the POST handler writes the user message + a *pending*
assistant row and spawns a background task here; the UI polls the thread fragment
until the assistant row flips to done/error. The chat agent is read-only and
seeded with the investigation's verdict + alert context.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
from typing import Any

from soc_ai.agent.chat_agent import (
    CHAT_SYSTEM_PROMPT,
    build_chat_agent,
    build_chat_context_block,
)
from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.models import build_investigator_model
from soc_ai.agent.narrative_grounding import (
    UNVERIFIED_CAVEAT,
    check_narrative_grounding,
    scoped_unverified_caveat,
)
from soc_ai.agent.prompts import oql_primer_block
from soc_ai.agent.proposal_validation import Proposal, validate_proposal
from soc_ai.api.deps import ctx_from_state
from soc_ai.so_client.inventory import inventory_prompt_block
from soc_ai.store import chat as chat_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.tools.get_alert_context import get_alert_context
from soc_ai.webui.probes import _scrub

_LOGGER = logging.getLogger(__name__)

# Tool-call-shaped citations the model sometimes fabricates on a zero-tool turn
# ("verified by the tools", `t_enrich_ip(...)`). If meta.tools is empty and the
# prose contains these, the answer is claiming evidence it never produced.
_FABRICATED_TOOL_CITATION_RE = re.compile(
    r"\bt_[a-z][a-z0-9_]*\s*\(|verified by the tool|evidence citations?\b",
    re.IGNORECASE,
)
_STATE_ATTR = "_chat_manager"
_MAX_HISTORY = 12  # prior turns embedded into the prompt


class ChatManager:
    """Tracks in-flight chat-turn tasks to prevent GC collection."""

    def __init__(self) -> None:
        self._tasks: dict[int, asyncio.Task[None]] = {}
        # Backstop tasks spawned from the (sync) done-callback. Held so the event
        # loop keeps a strong reference until they finish (else they can be GC'd
        # mid-flight); each discards itself on completion.
        self._backstops: set[asyncio.Task[None]] = set()

    def start(self, state: Any, *, inv_id: str, assistant_msg_id: int) -> None:
        # NOTE: the per-turn timeout lives INSIDE _run_turn (an `asyncio.timeout`
        # block around agent.run), NOT here as `asyncio.wait_for(..., timeout=)`.
        # `wait_for` enforces the deadline by *cancelling* the coroutine, which
        # raises `asyncio.CancelledError` — a `BaseException` on 3.11+, so
        # _run_turn's `except Exception` never runs and the assistant row is left
        # stuck `pending` forever. `asyncio.timeout` instead raises `TimeoutError`
        # (a normal Exception), which the existing error path catches and turns
        # into a terminal error row.
        task: asyncio.Task[None] = asyncio.create_task(_run_turn(state, inv_id, assistant_msg_id))
        self._tasks[assistant_msg_id] = task
        task.add_done_callback(lambda t: self._on_task_done(state, assistant_msg_id, t))

    def _on_task_done(self, state: Any, assistant_msg_id: int, task: asyncio.Task[None]) -> None:
        """Defense-in-depth: clear the registry and, if the task ended via
        cancellation or an exception that escaped _run_turn (e.g. true shutdown
        cancellation, or the narrow window before _run_turn's own handler runs),
        resolve a still-``pending`` assistant row to a terminal ``error`` state.

        _run_turn already persists a terminal row on success/timeout/exception;
        this callback only fires a backstop write when the task did NOT exit
        cleanly. The backstop write is itself spawned as a task (the callback is
        sync) and best-effort: a still-pending row is the only thing it touches.
        """
        self._tasks.pop(assistant_msg_id, None)
        if task.cancelled():
            _LOGGER.warning("chat: task for msg=%s was cancelled", assistant_msg_id)
            self._spawn_backstop(state, assistant_msg_id)
            return
        exc = task.exception()
        if exc is not None:
            _LOGGER.error(
                "chat: task for msg=%s ended with an unhandled exception: %r",
                assistant_msg_id,
                exc,
            )
            self._spawn_backstop(state, assistant_msg_id)

    def _spawn_backstop(self, state: Any, assistant_msg_id: int) -> None:
        """Spawn the pending-row resolver, holding a strong reference so the
        loop doesn't GC it mid-flight."""
        bt: asyncio.Task[None] = asyncio.ensure_future(_resolve_if_pending(state, assistant_msg_id))
        self._backstops.add(bt)
        bt.add_done_callback(self._backstops.discard)


def get_manager(state: Any) -> ChatManager:
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, ChatManager())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


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


def _build_prompt(prior: list[tuple[str, str]], question: str) -> str:
    if not prior:
        return question
    convo = "\n\n".join(
        f"{'Analyst' if role == 'user' else 'You'}: {content}" for role, content in prior
    )
    return f"Conversation so far:\n{convo}\n\nAnalyst's new question: {question}"


async def _run_turn(state: Any, inv_id: str, assistant_msg_id: int) -> None:  # noqa: PLR0915
    try:
        settings = state.settings
        # Demo mode: never build the model/gateway (the egress guard would raise).
        # Short-circuit BEFORE any agent/ES work with a canned, zero-egress reply
        # looked up from the seeded fixtures, then finish the pending row exactly
        # as the live path does. `is True` (not truthy) so a MagicMock settings in
        # a unit test can't accidentally trip the demo branch (real Settings is a bool).
        if getattr(settings, "soc_ai_demo", False) is True:
            from soc_ai.demo.chat import canned_reply  # noqa: PLC0415

            text = canned_reply(getattr(state, "demo_fixtures", None), "investigation", inv_id)
            async with state.db_sessionmaker() as db:
                await chat_svc.finish_assistant(
                    db, assistant_msg_id, content=text, status="done", meta={"demo": True}
                )
            return
        ctx = ctx_from_state(state)
        async with state.db_sessionmaker() as db:
            loaded = await inv_svc.get_with_events(db, inv_id)
            history = await chat_svc.history_for_agent(db, inv_id)
        if loaded is None:
            raise RuntimeError("investigation not found")
        inv, _events = loaded

        # The user's question is the latest done message; everything before it is
        # prior conversation.
        question = history[-1][1] if history and history[-1][0] == "user" else ""
        prior = history[:-1][-_MAX_HISTORY:] if history and history[-1][0] == "user" else history

        alert_summary = f"{inv.rule_name or 'alert'} ({inv.src_ip or '?'} → {inv.dest_ip or '?'})"
        # Fetch the alert context so queries center on the alert time + the
        # summary reflects the real flow. Best-effort: the stored verdict alone
        # still seeds a useful chat.
        try:
            ac = await get_alert_context(inv.alert_es_id, elastic=ctx.elastic, settings=settings)
            ctx.default_time_anchor = ac.alert.timestamp
            alert_summary = (
                f"{ac.alert.rule_name or inv.rule_name} "
                f"({ac.alert.source_ip} → {ac.alert.destination_ip})"
            )
        except Exception as e:
            _LOGGER.warning("chat: alert-context fetch failed for %s: %s", inv.alert_es_id, e)

        seed_context = build_chat_context_block(
            alert_summary=alert_summary,
            verdict=inv.verdict,
            confidence=inv.confidence,
            rationale=inv.rationale,
            summary=inv.summary,
        )
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
        sys_prompt = (
            CHAT_SYSTEM_PROMPT.format(context=seed_context)
            + oql_primer_block()
            + await inventory_prompt_block(ctx.elastic, settings)
        )
        if guard is not None:
            # seed_context (stored verdict/rationale from real investigation
            # data) + inventory both carry internal identifiers; sanitize the
            # composed system prompt at the egress boundary. seed_context
            # itself stays RAW — the narrative-grounding check below compares
            # against it in real-value space.
            sys_prompt = guard.sanitize_text(sys_prompt)
        proposal_sink: list[dict[str, Any]] = []
        agent = build_chat_agent(
            build_investigator_model(settings),
            ctx,
            system_prompt=sys_prompt,
            proposal_sink=proposal_sink,
        )
        # The long part. Bound it with `asyncio.timeout` (not `wait_for` in
        # start()): on the deadline this raises `TimeoutError` (a normal
        # Exception in 3.11+), so the `except Exception` below runs and writes a
        # terminal error row — instead of `wait_for`'s CancelledError, which is a
        # BaseException that the except never catches and which leaves the row
        # stuck pending forever.
        turn_prompt = _build_prompt(prior, question)
        if guard is not None:
            # The analyst's question + prior turns carry real identifiers.
            turn_prompt = guard.sanitize_text(turn_prompt)
        async with asyncio.timeout(settings.chat_turn_timeout_s):
            result = await agent.run(turn_prompt)
        answer = (str(result.output) or "").strip() or "(no answer produced)"
        meta: dict[str, Any] = {"tools": _extract_tools(result)}
        tool_evidence = _extract_tool_evidence(result)
        if guard is not None:
            # Model output + captured tool evidence are in label space —
            # restore real values BEFORE persistence and before the grounding
            # check, so answer artifacts compare against seed_context /
            # tool_evidence in the same (real-value) space.
            answer = str(guard.desanitize_obj(answer))
            tool_evidence = guard.desanitize_obj(tool_evidence)

        # Layer 2 — narrative grounding (defense-in-depth for the free-text answer).
        # Detect concrete per-event artifacts (hostnames, domains, IPs, JA3, SMB) the
        # answer asserts and verify each is grounded in either a tool result from this
        # turn or the seeded investigation context. The canonical failure is the
        # zero-tool turn that fabricates a host/DNS/SMB story; when the answer asserts
        # such artifacts and NONE are grounded, append a clearly-marked caveat to the
        # stored answer (rendered as Markdown) and record the verdict in meta.
        grounding = check_narrative_grounding(
            answer, seed_context=seed_context, tool_evidence=tool_evidence
        )
        if not grounding.grounded:
            _LOGGER.warning(
                "chat: ungrounded narrative for inv=%s (tools=%d) — %s",
                inv_id,
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
                "chat: fabricated tool citations on a zero-tool turn for inv=%s", inv_id
            )
            if meta.get("narrative_grounding", {}).get("grounded", True):
                answer = answer + UNVERIFIED_CAVEAT
            meta["narrative_grounding"] = {
                "grounded": False,
                "reason": "fabricated tool citations on a zero-tool turn",
            }

        if proposal_sink:
            # If the agent proposed more than once this turn, the last proposal
            # wins — it reflects its final reasoning and matches the narrative
            # answer persisted above.
            prop = proposal_sink[-1]
            if guard is not None:
                # propose_verdict is registered in chat_agent (not the guarded
                # toolset), so its captured args are still in label space —
                # restore before validation/persistence.
                prop = guard.desanitize_obj(prop)
            v = validate_proposal(
                Proposal(
                    verdict=prop["verdict"],
                    confidence=prop["confidence"],
                    rationale=prop["rationale"],
                    citations=prop["citations"],
                    recommended_actions=prop["recommended_actions"],
                ),
                tool_evidence=tool_evidence,
            )
            meta.update(
                {
                    "kind": "verdict_proposal",
                    "validation": "pass" if v.ok else "fail",
                    "objection": v.objection,
                    "token": secrets.token_urlsafe(16),
                    "proposal": prop,
                }
            )
        async with state.db_sessionmaker() as db:
            await chat_svc.finish_assistant(
                db,
                assistant_msg_id,
                content=answer,
                status="done",
                meta=meta,
            )
    except TimeoutError:
        # The turn hit chat_turn_timeout_s (the asyncio.timeout block above).
        # Write a user-facing, actionable terminal row so the pending status
        # never gets stuck.
        timeout_s = getattr(state.settings, "chat_turn_timeout_s", 180)
        _LOGGER.warning("chat turn timed out for inv=%s after %ss", inv_id, timeout_s)
        await _persist_terminal_error(
            state,
            assistant_msg_id,
            f"The assistant ran out of time on this question (hit the {timeout_s}s "
            "limit). Try a narrower follow-up.",
        )
    except Exception as e:
        _LOGGER.exception("chat turn failed for inv=%s", inv_id)
        # Scrub the exception text before it becomes user-facing content — a
        # verbose provider/gateway error body could otherwise echo a credential
        # (same defensive scrub probes.py applies to its error surfaces).
        await _persist_terminal_error(
            state,
            assistant_msg_id,
            f"Sorry — the chat turn failed ({_scrub(str(e))}). Try again.",
        )


async def _persist_terminal_error(state: Any, assistant_msg_id: int, content: str) -> None:
    """Write a terminal ``error`` row, swallowing+logging any secondary DB error.

    The last line of defense in _run_turn's handlers: a failure here can't be
    retried in-band, so it is logged loudly (the row stays pending → the chat
    reaper resolves it on the next sweep / restart).
    """
    try:
        async with state.db_sessionmaker() as db:
            await chat_svc.finish_assistant(
                db,
                assistant_msg_id,
                content=content,
                status="error",
                meta=None,
            )
    except Exception:
        _LOGGER.exception(
            "chat: FAILED to persist error row for msg=%s — pending stuck",
            assistant_msg_id,
        )


async def _resolve_if_pending(state: Any, assistant_msg_id: int) -> None:
    """Backstop for the done-callback: mark a still-``pending`` assistant row as
    ``error``. Only writes when the row is genuinely still pending, so it never
    clobbers a terminal row _run_turn already wrote on the normal path."""
    try:
        async with state.db_sessionmaker() as db:
            msg = await chat_svc.get_message(db, assistant_msg_id)
            if msg is None or msg.status != "pending":
                return
            await chat_svc.finish_assistant(
                db,
                assistant_msg_id,
                content="The assistant was interrupted — please ask again.",
                status="error",
                meta=None,
            )
        _LOGGER.warning(
            "chat: resolved stuck-pending msg=%s to error via task-done backstop",
            assistant_msg_id,
        )
    except Exception:
        _LOGGER.exception("chat: backstop failed to resolve pending msg=%s", assistant_msg_id)
