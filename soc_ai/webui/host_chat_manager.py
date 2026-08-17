"""HostChatManager — the host page chat's half of one shared turn engine.

"Chat about this host": the bubble on ``/hosts/<ip>``, anchored on ONE machine
the way the investigation chat is anchored on one alert. Everything true of any
chat shape — egress guard, prompt composition, live tool progress, the wall
clock, the regrounding loop, the grounding caveat, the terminal error rows —
lives in :mod:`soc_ai.webui.chat_turn`; here we supply only the host-shaped
half as a :class:`~soc_ai.webui.chat_turn.ChatTurnSpec`:

* the ANCHOR is the host — its address plus its dossier block
  (:func:`soc_ai.dossier.prompt.host_dossier_prompt_block`), seeded into the
  grounding corpus so naming the machine correctly is GROUNDED, not caveated;
* the thread is keyed on the HOST (``host:<ip>``), shared by every analyst —
  the investigation-chat precedent for object-scoped chats, not the dashboard's
  per-caller scratchpad. Storage is the EXISTING ``GeneralChatMessage`` table
  via :mod:`soc_ai.store.general_chat`: ``thread_key`` is ``String(64)`` and a
  canonical IPv6 address is at most 45 chars + the 5-char prefix, so the key
  fits with no migration — and no third chat table to drift;
* the proposal tool is ``propose_hunt`` ("show me everything this host talked
  to in 7d" is exactly a sweep), finalized through the SAME
  :func:`~soc_ai.webui.general_chat_manager.apply_hunt_proposal_meta` the
  dashboard chat uses.

There is deliberately NO kill switch here: the host chat gates on what the
investigation chat gates on — the subject must be addressable (the route 404s a
non-IP) — and not on ``general_chat_enabled``, which stops the always-available
dashboard box only.

Copying the engine instead of specifying against it is what left the hunt chat
without progress reporting or grounding. If this file starts growing turn
logic, that is the signal to widen ``ChatTurnSpec`` — not to fork again.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.chat_agent import (
    HOST_CHAT_SYSTEM_PROMPT,
    build_chat_agent,
    build_host_context_block,
)
from soc_ai.agent.context import InvestigationContext
from soc_ai.api.deps import ctx_from_state
from soc_ai.dossier.prompt import host_dossier_prompt_block
from soc_ai.store import general_chat as gc_svc
from soc_ai.webui.chat_turn import (
    ChatTaskManager,
    ChatTurnSpec,
    TurnInputs,
    run_chat_turn,
    split_history,
)
from soc_ai.webui.general_chat_manager import (
    GENERAL_CHAT_WINDOW_MINUTES,
    _resolve_if_pending,
    apply_hunt_proposal_meta,
)

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_host_chat_manager"

# The same demo posture as the dashboard chat, for the same reason: the public
# demo has no login, so this SHARED per-host thread would put one visitor's
# questions in front of the next. The route answers the POST with this and
# stores nothing; the _prepare short-circuit below is the backstop for any
# caller that does spawn a turn (a turn that reached the gateway would raise).
DEMO_REPLY = (
    "This is a recorded demo, so the host assistant isn't available here — "
    "answering you live would mean querying a real Security Onion grid and "
    "calling a model. In a real deployment I'd answer from this host's dossier "
    "and its live telemetry (peers, DNS, services), and propose a hunt when a "
    "question needs a sweep."
)


def thread_key_for(ip: str) -> str:
    """The host's shared thread key in the general-chat table.

    Callers pass the CANONICAL address (the route normalizes through
    ``normalize_host_key``), so two spellings of one host land on one thread.
    ``host:`` + a canonical IPv6 (≤45 chars) stays under the column's 64.
    """
    return f"host:{ip}"


class HostChatManager(ChatTaskManager):
    """Host-chat task tracker.

    The GC-safe task registry and the stuck-pending backstop come from
    :class:`~soc_ai.webui.chat_turn.ChatTaskManager`; this subclass only knows
    how to name a host turn, so the route keeps a narrow call site. The
    backstop is the general chat's — same table, same "resolve if still
    pending" contract.
    """

    def start(self, state: Any, *, ip: str, assistant_msg_id: int) -> None:
        self.spawn(
            row_id=assistant_msg_id,
            runner=_run_turn(state, ip, assistant_msg_id),
            backstop=lambda: _resolve_if_pending(state, assistant_msg_id),
        )


def get_manager(state: Any) -> HostChatManager:
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, HostChatManager())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


async def _run_turn(state: Any, ip: str, assistant_msg_id: int) -> None:
    """Run one host-chat turn through the shared engine."""
    await run_chat_turn(state, _host_spec(state, ip, assistant_msg_id))


def _host_spec(state: Any, ip: str, assistant_msg_id: int) -> ChatTurnSpec:
    """Bind the engine to ONE host's shared thread, anchored on its dossier."""
    thread_key = thread_key_for(ip)

    async def _finish(*, content: str, status: str, meta: dict[str, Any] | None) -> None:
        async with state.db_sessionmaker() as db:
            await gc_svc.finish_assistant(
                db, assistant_msg_id, content=content, status=status, meta=meta
            )

    async def _set_progress(tools: list[str]) -> None:
        async with state.db_sessionmaker() as pdb:
            await gc_svc.set_progress(pdb, assistant_msg_id, tools)

    async def _prepare() -> TurnInputs | None:
        settings = state.settings
        # Demo backstop — the route already answers demo POSTs itself (see
        # DEMO_REPLY above); a spawned turn must still never build a model.
        # `is True` (not truthy) so a MagicMock settings double can't trip it.
        if getattr(settings, "soc_ai_demo", False) is True:
            await _finish(content=DEMO_REPLY, status="done", meta={"demo": True})
            return None
        ctx = ctx_from_state(state)
        async with state.db_sessionmaker() as db:
            history = await gc_svc.history_for_agent(db, thread_key)
        question, prior = split_history(history)
        # The anchor line + the dossier block, in seed_context (not the system
        # prompt) so both join the corpus the grounding gate grades against —
        # correctly naming the host must come back grounded, not caveated.
        # Composed RAW, before the engine's guard.sanitize_text sweep (the
        # egress rule): the dossier's IP must collapse onto the same label the
        # rest of the prompt gets.
        #
        # `known_only` stays OFF: this address comes from the page's URL, a
        # typed field like the alert path's endpoints — the "no record" line is
        # load-bearing for a host the sweep has never met, and nothing the
        # model wrote can enter this one-address set.
        seed_context = build_host_context_block(ip=ip) + await host_dossier_prompt_block(
            {ip: "the host under discussion"}, ctx=ctx
        )

        hunt_sink: list[dict[str, Any]] = []

        def _build_agent(
            model: Model, ctx: InvestigationContext, system_prompt: str
        ) -> Agent[None, str]:
            # propose_hunt, no propose_verdict: there is no alert here to
            # disposition, and a host question that needs a week of zeek.conn
            # is exactly a sweep.
            return build_chat_agent(
                model,
                ctx,
                system_prompt=system_prompt,
                hunt_sink=hunt_sink,
                # A host page has no alert to anchor time on; like the
                # dashboard chat, an unqualified question is routinely about
                # the last day, not the last hour.
                default_window=GENERAL_CHAT_WINDOW_MINUTES,
            )

        def _finalize(
            meta: dict[str, Any], tool_evidence: list[dict[str, Any]], guard: Any
        ) -> None:
            apply_hunt_proposal_meta(meta, hunt_sink, guard)

        return TurnInputs(
            ctx=ctx,
            seed_context=seed_context,
            question=question,
            prior=prior,
            system_prompt=HOST_CHAT_SYSTEM_PROMPT,
            # Telemetry-first OQL examples: host questions slice datasets by
            # address, they do not pivot from an alert.
            oql_flavor="hunt",
            # The engine appends the dataset inventory (default True): unlike
            # the general chat, this seed does not already carry it.
            build_agent=_build_agent,
            finalize_meta=_finalize,
        )

    return ChatTurnSpec(
        row_id=assistant_msg_id,
        label=f"host={ip}",
        # An ANSWER at investigation-chat latency — the investigation chat's
        # budget, not the hunt chat's minutes.
        timeout_s=state.settings.chat_turn_timeout_s,
        finish=_finish,
        prepare=_prepare,
        set_progress=_set_progress,
    )
