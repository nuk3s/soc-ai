"""ChatManager — runs a "Chat about this" turn as a background task.

Mirrors HuntManager: the POST handler writes the user message + a *pending*
assistant row and spawns a background task here; the UI polls the thread fragment
until the assistant row flips to done/error. The chat agent is read-only and
seeded with the investigation's verdict + alert context.

The turn itself is NOT implemented here. Everything that is true of any chat
shape — egress guard, prompt composition, live tool progress, the wall clock,
the regrounding loop, the grounding caveat, the terminal error rows — lives in
:mod:`soc_ai.webui.chat_turn`; this module supplies the investigation-shaped
half (which alert anchors the turn, where the answer is stored, what a verdict
proposal means) as a :class:`~soc_ai.webui.chat_turn.ChatTurnSpec`. Copying the
engine instead of specifying against it is what left the hunt chat without
progress or grounding.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.chat_agent import (
    CHAT_SYSTEM_PROMPT,
    build_chat_agent,
    build_chat_context_block,
)
from soc_ai.agent.context import InvestigationContext
from soc_ai.agent.orchestrator import dossier_hosts_for_alert
from soc_ai.agent.proposal_validation import Proposal, validate_proposal
from soc_ai.api.deps import ctx_from_state
from soc_ai.demo.chat import canned_reply
from soc_ai.demo.guard import is_demo
from soc_ai.dossier.prompt import host_dossier_prompt_block
from soc_ai.so_client.models import SoAlert
from soc_ai.store import chat as chat_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.tools.get_alert_context import get_alert_context
from soc_ai.webui.chat_turn import (
    ChatTaskManager,
    ChatTurnSpec,
    TurnInputs,
    run_chat_turn,
    split_history,
)

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_chat_manager"


class ChatManager(ChatTaskManager):
    """Investigation-chat task tracker.

    The GC-safe task registry and the stuck-pending backstop come from
    :class:`~soc_ai.webui.chat_turn.ChatTaskManager`; this subclass only knows
    how to name an investigation turn, so the chat route keeps a narrow call site.
    """

    def start(self, state: Any, *, inv_id: str, assistant_msg_id: int) -> None:
        self.spawn(
            row_id=assistant_msg_id,
            runner=_run_turn(state, inv_id, assistant_msg_id),
            backstop=lambda: _resolve_if_pending(state, assistant_msg_id),
        )


def get_manager(state: Any) -> ChatManager:
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, ChatManager())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


def demo_reply(state: Any, inv_id: str) -> str:
    """The demo's scripted answer for this investigation's chat.

    Public because the ROUTE serves it: on the public demo
    ``api_auth_required`` is false, so every visitor is the same caller and this
    thread is keyed on an investigation they all share — persisted, one visitor's
    typed question shows up in another's panel. So the demo answers on the POST
    and stores nothing (see :func:`soc_ai.api.webui.routes_chat._demo_thread`).

    It lives HERE rather than in the route for the same reason
    :data:`soc_ai.webui.general_chat_manager.DEMO_REPLY` does: this module owns
    what the investigation chat says, so there is ONE answer per surface instead
    of two that can drift. The import runs route → manager; the reverse would be
    a cycle.
    """
    return canned_reply(getattr(state, "demo_fixtures", None), "investigation", inv_id)


async def _run_turn(state: Any, inv_id: str, assistant_msg_id: int) -> None:
    """Run one investigation-chat turn through the shared engine."""
    await run_chat_turn(state, _investigation_spec(state, inv_id, assistant_msg_id))


def _investigation_spec(state: Any, inv_id: str, assistant_msg_id: int) -> ChatTurnSpec:
    """Bind the engine to ONE investigation's alert, thread and chat_messages row."""

    async def _finish(*, content: str, status: str, meta: dict[str, Any] | None) -> None:
        async with state.db_sessionmaker() as db:
            await chat_svc.finish_assistant(
                db, assistant_msg_id, content=content, status=status, meta=meta
            )

    async def _set_progress(tools: list[str]) -> None:
        async with state.db_sessionmaker() as pdb:
            await chat_svc.set_progress(pdb, assistant_msg_id, tools)

    async def _prepare() -> TurnInputs | None:
        settings = state.settings
        # Demo mode: never build the model/gateway (the egress guard would raise).
        # Short-circuit BEFORE any agent/ES work with the canned, zero-egress
        # reply, then finish the pending row exactly as the live path does.
        #
        # Now a BACKSTOP, not the live path — the route answers the demo POST
        # itself without spawning a turn (see :func:`demo_reply`). Kept so any
        # future caller that does spawn one still resolves its pending row from
        # here instead of reaching the gateway, which the demo guard refuses.
        if is_demo(settings):
            await _finish(content=demo_reply(state, inv_id), status="done", meta={"demo": True})
            return None
        ctx = ctx_from_state(state)
        async with state.db_sessionmaker() as db:
            loaded = await inv_svc.get_with_events(db, inv_id)
            history = await chat_svc.history_for_agent(db, inv_id)
        if loaded is None:
            raise RuntimeError("investigation not found")
        inv, _events = loaded

        question, prior = split_history(history)

        alert_summary = f"{inv.rule_name or 'alert'} ({inv.src_ip or '?'} → {inv.dest_ip or '?'})"
        # Fetch the alert context so queries center on the alert time + the
        # summary reflects the real flow. Best-effort: the stored verdict alone
        # still seeds a useful chat.
        alert_context: Any = SoAlert(
            id=inv.alert_es_id, source_ip=inv.src_ip, destination_ip=inv.dest_ip
        )
        try:
            ac = await get_alert_context(inv.alert_es_id, elastic=ctx.elastic, settings=settings)
            ctx.default_time_anchor = ac.alert.timestamp
            alert_summary = (
                f"{ac.alert.rule_name or inv.rule_name} "
                f"({ac.alert.source_ip} → {ac.alert.destination_ip})"
            )
            alert_context = ac
        except Exception as e:
            _LOGGER.warning("chat: alert-context fetch failed for %s: %s", inv.alert_es_id, e)

        # The alert's hosts as IDENTITY, appended to the seed rather than to the
        # system prompt. seed_context is the corpus the engine's grounding gate
        # grades the answer against, so putting it here is what makes "pve01 is
        # the hypervisor" a GROUNDED sentence instead of one that ships under an
        # ⚠ Unverified caveat — the same reason the general chat seeds the
        # grid's own identifiers. The engine sanitizes the composed prompt
        # later, so this stays RAW and collapses onto the same egress labels the
        # rest of the seed gets.
        #
        # Degrades with the fetch above: on an ES failure the host set is the
        # stored endpoints, which is what the summary line falls back to too.
        #
        # `known_only` is deliberately NOT set here: unlike the hunt and general
        # chats, these addresses come from the alert's typed fields rather than
        # from free text, so nothing the model wrote can enter this set and the
        # "no record" line stays load-bearing for the alert's own destination.
        #
        # The tradeoff this makes, stated plainly: the grounding corpus grew
        # from two addresses to up to eight plus their hostnames, so per-event
        # claims about any of those hosts now pass the identifier gate without a
        # tool call. That is defensible — every one of them is a real host this
        # alert put in play, which is the same standard the alert's own endpoints
        # already met — but it IS a widening, and the gate is weaker for the
        # hosts in it than it was.
        seed_context = build_chat_context_block(
            alert_summary=alert_summary,
            verdict=inv.verdict,
            confidence=inv.confidence,
            rationale=inv.rationale,
            summary=inv.summary,
        ) + await host_dossier_prompt_block(
            dossier_hosts_for_alert(alert_context, settings), ctx=ctx
        )

        proposal_sink: list[dict[str, Any]] = []

        def _build_agent(
            model: Model, ctx: InvestigationContext, system_prompt: str
        ) -> Agent[None, str]:
            # Only the investigation chat gets propose_verdict: it is the only
            # shape with an alert to disposition.
            return build_chat_agent(
                model, ctx, system_prompt=system_prompt, proposal_sink=proposal_sink
            )

        def _finalize(
            meta: dict[str, Any], tool_evidence: list[dict[str, Any]], guard: Any
        ) -> None:
            if not proposal_sink:
                return
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

        return TurnInputs(
            ctx=ctx,
            seed_context=seed_context,
            question=question,
            prior=prior,
            system_prompt=CHAT_SYSTEM_PROMPT,
            build_agent=_build_agent,
            finalize_meta=_finalize,
        )

    return ChatTurnSpec(
        row_id=assistant_msg_id,
        label=f"inv={inv_id}",
        timeout_s=state.settings.chat_turn_timeout_s,
        finish=_finish,
        prepare=_prepare,
        set_progress=_set_progress,
    )


async def _resolve_if_pending(state: Any, assistant_msg_id: int) -> None:
    """Backstop for the done-callback: mark a still-``pending`` assistant row as
    ``error``. Only writes when the row is genuinely still pending, so it never
    clobbers a terminal row the turn already wrote on the normal path."""
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
