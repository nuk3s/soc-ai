"""HuntConsoleManager — chat-driven hunts as decoupled background tasks.

POST /api/v1/hunts/chat creates the hunt row via ``hunt_recorded_run``'s first
``hunt_created`` event, then drains the REST of the stream in a background
asyncio.Task that runs to completion regardless of client state — so a hunt
survives an SSE-client disconnect and lands its report.

Mirrors :mod:`soc_ai.webui.hunt_manager` (the interactive-investigation drainer)
but for free-form Hunt Console objectives.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from soc_ai.agent.chat_agent import CHAT_SYSTEM_PROMPT, build_chat_agent
from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.models import build_investigator_model
from soc_ai.agent.prompts import oql_primer_block
from soc_ai.api.deps import ctx_from_state
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.api.runner import CancelToken
from soc_ai.so_client.inventory import inventory_prompt_block
from soc_ai.store import hunts as hunt_svc

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_hunt_console_manager"
_CHAT_STATE_ATTR = "_hunt_chat_manager"


class HuntConsoleManager:
    """Tracks in-flight background hunt tasks to prevent GC collection."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._tokens: dict[str, CancelToken] = {}

    async def start(
        self,
        state: Any,
        *,
        objective: str,
        started_by: str,
        prior: str | None = None,
        kind: str = "chat",
    ) -> str | None:
        """Create the hunt row and spawn a background drainer task.

        Consumes ``hunt_recorded_run`` until the first ``hunt_created`` event to
        capture the hunt id, then hands the remaining generator to a background
        task that runs it to completion. Returns the hunt id, or None if the
        generator ended/errored before emitting ``hunt_created``.

        ``kind`` tags the hunt row (``"chat"`` for an operator-typed hunt,
        ``"scheduled"`` for a recurring hunt fired by the schedule loop) — it is
        threaded straight into ``hunt_recorded_run`` → ``hunt_svc.create``.
        """
        ctx = ctx_from_state(state)
        token = CancelToken()
        gen = hunt_recorded_run(
            state,
            ctx=ctx,
            objective=objective,
            started_by=started_by,
            prior=prior,
            kind=kind,
            cancel_token=token,
        )

        hunt_id: str | None = None
        try:
            async for name, data in gen:
                if name == "hunt_created":
                    hunt_id = data.get("hunt_id")
                    break
        except Exception:
            _LOGGER.exception("hunt_console_manager: failed to start hunt")
            return None

        if hunt_id is None:
            return None

        task: asyncio.Task[None] = asyncio.create_task(_drain(gen, hunt_id=hunt_id))
        self._tasks[hunt_id] = task
        self._tokens[hunt_id] = token

        def _cleanup(_t: asyncio.Task[None]) -> None:
            self._tasks.pop(hunt_id, None)
            self._tokens.pop(hunt_id, None)

        task.add_done_callback(_cleanup)
        return hunt_id

    def cancel(self, hunt_id: str) -> bool:
        """Cancel an in-flight hunt — an EXPLICIT operator cancel.

        Marks the cancel token requested FIRST so ``hunt_recorded_run`` records
        the run as ``cancelled`` (an unmarked cancellation lands as ``error``).
        Returns True if a live task was found and cancelled.
        """
        task = self._tasks.get(hunt_id)
        if task is None or task.done():
            return False
        token = self._tokens.get(hunt_id)
        if token is not None:
            token.requested = True
        task.cancel()
        return True


async def _drain(gen: Any, *, hunt_id: str) -> None:
    """Exhaust the remaining events in *gen* (the recorder persists everything)."""
    try:
        async for _name, _data in gen:
            pass
    except Exception:
        _LOGGER.exception("hunt_console_manager: background drain failed for hunt_id=%s", hunt_id)


def get_manager(state: Any) -> HuntConsoleManager:
    """Lazily attach a :class:`HuntConsoleManager` to *app.state* and return it."""
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, HuntConsoleManager())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


# ── "Chat about this hunt" follow-up thread ──────────────────────────────────
#
# A completed hunt gets a read-only Q&A thread, mirroring the investigation
# "Chat about this" feature (soc_ai.webui.chat_manager) but for a HuntReport. The
# POST handler writes the user turn + a pending assistant turn (as hunt_events),
# spawns a background task here, and the UI polls the thread until the assistant
# row flips to done/error. The agent is the SAME read-only chat agent the
# investigation chat uses — no write tools, no Oracle, and NO propose_verdict
# (a hunt never acks/escalates), so ``proposal_sink`` is left None.

_MAX_HISTORY = 12  # prior chat turns embedded into the prompt


def _hunt_chat_seed_context(hunt: Any) -> str:
    """Render the hunt's report/narrative/findings as the chat agent's seed block.

    The investigation chat seeds the alert + verdict + rationale; the hunt chat
    seeds the objective + narrative + the findings the hunt landed, so follow-ups
    are grounded in what the hunt actually concluded.
    """
    report = hunt.report if isinstance(hunt.report, dict) else {}
    lines = [f"Hunt objective: {hunt.objective}"]
    narrative = hunt.narrative or report.get("narrative")
    if narrative:
        lines.append(f"Hunt narrative: {narrative}")
    findings = report.get("findings") or []
    if isinstance(findings, list) and findings:
        lines.append("Findings:")
        for f in findings[:12]:
            if not isinstance(f, dict):
                continue
            title = f.get("title") or "(untitled finding)"
            sev = f.get("severity") or "info"
            detail = f.get("detail") or ""
            hosts = ", ".join(f.get("hosts") or [])
            cites = ", ".join(f.get("citations") or [])
            line = f"- [{sev}] {title}: {detail}"
            if hosts:
                line += f" (hosts: {hosts})"
            if cites:
                line += f" (evidence: {cites})"
            lines.append(line)
    affected = report.get("affected_hosts") or []
    if isinstance(affected, list) and affected:
        lines.append(f"Affected hosts: {', '.join(str(h) for h in affected)}")
    techniques = report.get("mitre_techniques") or []
    if isinstance(techniques, list) and techniques:
        lines.append(f"MITRE techniques: {', '.join(str(t) for t in techniques)}")
    return "\n".join(lines)


def _hunt_chat_build_prompt(prior: list[tuple[str, str]], question: str) -> str:
    if not prior:
        return question
    convo = "\n\n".join(
        f"{'Analyst' if role == 'user' else 'You'}: {content}" for role, content in prior
    )
    return f"Conversation so far:\n{convo}\n\nAnalyst's new question: {question}"


def _hunt_chat_extract_tools(result: Any) -> list[str]:
    names: list[str] = []
    for msg in result.all_messages():
        for part in getattr(msg, "parts", []) or []:
            if type(part).__name__ == "ToolCallPart":
                name = getattr(part, "tool_name", "")
                if name:
                    names.append(name)
    return names


class HuntChatManager:
    """Tracks in-flight hunt-chat-turn tasks to prevent GC collection.

    Mirrors :class:`soc_ai.webui.chat_manager.ChatManager` but for the hunt
    thread (stored as ``hunt_events``, keyed by the hunt id).
    """

    def __init__(self) -> None:
        self._tasks: dict[int, asyncio.Task[None]] = {}
        self._backstops: set[asyncio.Task[None]] = set()

    def start(self, state: Any, *, hunt_id: str, assistant_event_id: int) -> None:
        task: asyncio.Task[None] = asyncio.create_task(
            _run_hunt_chat_turn(state, hunt_id, assistant_event_id)
        )
        self._tasks[assistant_event_id] = task
        task.add_done_callback(lambda t: self._on_task_done(state, assistant_event_id, t))

    def _on_task_done(self, state: Any, assistant_event_id: int, task: asyncio.Task[None]) -> None:
        self._tasks.pop(assistant_event_id, None)
        if task.cancelled():
            _LOGGER.warning("hunt-chat: task for event=%s was cancelled", assistant_event_id)
            self._spawn_backstop(state, assistant_event_id)
            return
        if task.exception() is not None:
            _LOGGER.error(
                "hunt-chat: task for event=%s ended with an unhandled exception: %r",
                assistant_event_id,
                task.exception(),
            )
            self._spawn_backstop(state, assistant_event_id)

    def _spawn_backstop(self, state: Any, assistant_event_id: int) -> None:
        bt: asyncio.Task[None] = asyncio.ensure_future(
            _hunt_chat_resolve_if_pending(state, assistant_event_id)
        )
        self._backstops.add(bt)
        bt.add_done_callback(self._backstops.discard)


def get_chat_manager(state: Any) -> HuntChatManager:
    """Lazily attach a :class:`HuntChatManager` to *app.state* and return it."""
    if not hasattr(state, _CHAT_STATE_ATTR):
        setattr(state, _CHAT_STATE_ATTR, HuntChatManager())
    return getattr(state, _CHAT_STATE_ATTR)  # type: ignore[no-any-return]


async def _run_hunt_chat_turn(state: Any, hunt_id: str, assistant_event_id: int) -> None:
    """Run one read-only follow-up turn on a COMPLETED hunt and persist the answer."""
    try:
        settings = state.settings
        # Demo mode: never build the model/gateway (the egress guard would raise).
        # Short-circuit BEFORE any agent/ES work with a canned, zero-egress reply
        # looked up from the seeded fixtures, then finish the pending row exactly
        # as the live path does. `is True` (not truthy) so a MagicMock settings in
        # a unit test can't accidentally trip the demo branch (real Settings is a bool).
        if getattr(settings, "soc_ai_demo", False) is True:
            from soc_ai.demo.chat import canned_reply  # noqa: PLC0415

            text = canned_reply(getattr(state, "demo_fixtures", None), "hunt", hunt_id)
            async with state.db_sessionmaker() as db:
                await hunt_svc.finish_chat_assistant(
                    db, assistant_event_id, content=text, status="done", meta={"demo": True}
                )
            return
        ctx = ctx_from_state(state)
        async with state.db_sessionmaker() as db:
            loaded = await hunt_svc.get_with_events(db, hunt_id)
            history = await hunt_svc.chat_history_for_agent(db, hunt_id)
        if loaded is None:
            raise RuntimeError("hunt not found")
        hunt, _events = loaded

        # The user's question is the latest done chat turn; everything before it is
        # prior conversation.
        question = history[-1][1] if history and history[-1][0] == "user" else ""
        prior = history[:-1][-_MAX_HISTORY:] if history and history[-1][0] == "user" else history

        seed_context = _hunt_chat_seed_context(hunt)
        # Cloud-egress guard (opt-in): same pattern as the orchestrator/hunt
        # runner. Attach BEFORE building the agent so register_read_tools
        # wraps the tool closures. `is True` (not truthiness) so a MagicMock
        # settings double in tests can never flip redaction on.
        if settings.analyst_cloud_redaction is True and ctx.egress_guard is None:
            ctx.egress_guard = await EgressGuard.for_settings(
                settings, getattr(state, "db_sessionmaker", None)
            )
        guard = ctx.egress_guard
        # The chat agent runs OQL too — give it the primer AND the auto-discovered
        # dataset inventory so a follow-up like "what about SSH?" both writes a valid
        # query and knows zeek.ssh (or endpoint/windows/etc.) actually exists here.
        sys_prompt = (
            CHAT_SYSTEM_PROMPT.format(context=seed_context)
            + oql_primer_block(flavor="hunt")
            + await inventory_prompt_block(ctx.elastic, settings)
        )
        if guard is not None:
            # The seed block (stored hunt narrative/findings/hosts) and the
            # inventory both carry internal identifiers — sanitize the
            # composed system prompt at the egress boundary.
            sys_prompt = guard.sanitize_text(sys_prompt)
        # proposal_sink=None → the read-only chat agent WITHOUT propose_verdict:
        # a hunt never dispositions an alert, so there is no verdict to propose.
        agent = build_chat_agent(build_investigator_model(settings), ctx, system_prompt=sys_prompt)
        turn_prompt = _hunt_chat_build_prompt(prior, question)
        if guard is not None:
            # The analyst's question + prior turns carry real identifiers.
            turn_prompt = guard.sanitize_text(turn_prompt)
        async with asyncio.timeout(settings.hunt_chat_turn_timeout_s):
            result = await agent.run(turn_prompt)
        answer = (str(result.output) or "").strip() or "(no answer produced)"
        if guard is not None:
            # The reply is in label space — restore real values before it is
            # persisted/displayed.
            answer = str(guard.desanitize_obj(answer))
        meta: dict[str, Any] = {"tools": _hunt_chat_extract_tools(result)}
        async with state.db_sessionmaker() as db:
            await hunt_svc.finish_chat_assistant(
                db, assistant_event_id, content=answer, status="done", meta=meta
            )
    except TimeoutError:
        timeout_s = getattr(state.settings, "hunt_chat_turn_timeout_s", 600)
        _LOGGER.warning("hunt-chat turn timed out for hunt=%s after %ss", hunt_id, timeout_s)
        await _hunt_chat_persist_error(
            state,
            assistant_event_id,
            f"The assistant ran out of time on this question (hit the {timeout_s}s "
            "limit). Try a narrower follow-up.",
        )
    except Exception as e:
        _LOGGER.exception("hunt-chat turn failed for hunt=%s", hunt_id)
        await _hunt_chat_persist_error(
            state, assistant_event_id, f"Sorry — the chat turn failed ({e}). Try again."
        )


async def _hunt_chat_persist_error(state: Any, assistant_event_id: int, content: str) -> None:
    try:
        async with state.db_sessionmaker() as db:
            await hunt_svc.finish_chat_assistant(
                db, assistant_event_id, content=content, status="error", meta=None
            )
    except Exception:
        _LOGGER.exception(
            "hunt-chat: FAILED to persist error row for event=%s — pending stuck",
            assistant_event_id,
        )


async def _hunt_chat_resolve_if_pending(state: Any, assistant_event_id: int) -> None:
    """Backstop: mark a still-``pending`` assistant chat row as ``error``."""
    try:
        async with state.db_sessionmaker() as db:
            ev = await hunt_svc.get_chat_event(db, assistant_event_id)
            if ev is None or (ev.payload or {}).get("status") != "pending":
                return
            await hunt_svc.finish_chat_assistant(
                db,
                assistant_event_id,
                content="The assistant was interrupted — please ask again.",
                status="error",
                meta=None,
            )
        _LOGGER.warning(
            "hunt-chat: resolved stuck-pending event=%s to error via backstop",
            assistant_event_id,
        )
    except Exception:
        _LOGGER.exception(
            "hunt-chat: backstop failed to resolve pending event=%s", assistant_event_id
        )
