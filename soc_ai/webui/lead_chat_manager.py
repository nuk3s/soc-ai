"""LeadChatManager: the lead page chat's half of one shared turn engine.

"Ask soc-ai about this lead": the console's one chat panel, opened on
``/leads/<id>``, anchored on ONE lead the way the host chat is anchored on one
machine. Everything true of any chat shape lives in
:mod:`soc_ai.webui.chat_turn`; here we supply only the lead-shaped half as a
:class:`~soc_ai.webui.chat_turn.ChatTurnSpec`:

* the ANCHOR is the lead: its entities, its kinds, its status, one line per
  observation, the evidence documents the observations cite, and the dossier
  of each host entity. All of it lands in ``seed_context``, the corpus the
  grounding gate grades against;
* the thread is keyed on the LEAD (``lead:<id>``), shared by every analyst, in
  the EXISTING ``GeneralChatMessage`` table, the host chat's precedent. A lead
  id is an integer, so the key fits ``String(64)`` with no migration;
* the proposal tool is ``propose_hunt``, finalized through the SAME
  :func:`~soc_ai.webui.general_chat_manager.apply_hunt_proposal_meta` the host
  and the general chats use.

There is no kill switch here, for the host chat's reason: the subject must
exist (the route 404s an unknown lead) and nothing else gates it.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.chat_agent import (
    LEAD_CHAT_SYSTEM_PROMPT,
    build_chat_agent,
    build_lead_context_block,
)
from soc_ai.agent.context import InvestigationContext
from soc_ai.api.deps import ctx_from_state
from soc_ai.api.webui.kind_labels import kind_label
from soc_ai.dossier.prompt import host_dossier_prompt_block
from soc_ai.store import general_chat as gc_svc
from soc_ai.store import leads as leads_store
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

_STATE_ATTR = "_lead_chat_manager"

# The host chat's demo posture, for the same reason: the public demo has no
# login, so this SHARED per-lead thread would put one visitor's questions in
# front of the next. The route answers the POST with this and stores nothing.
DEMO_REPLY = (
    "This is a recorded demo. The lead assistant does not answer here, because "
    "a live answer queries a real Security Onion grid and calls a model. In a "
    "real deployment I answer from the observations of this lead, the evidence "
    "they cite and the live telemetry. I propose a hunt if a question needs a sweep."
)


def thread_key_for(lead_id: int) -> str:
    """The lead's shared thread key in the general-chat table."""
    return f"lead:{int(lead_id)}"


class LeadChatManager(ChatTaskManager):
    """Lead-chat task tracker. The registry and the backstop are the base class's."""

    def start(self, state: Any, *, lead_id: int, assistant_msg_id: int) -> None:
        self.spawn(
            row_id=assistant_msg_id,
            runner=_run_turn(state, lead_id, assistant_msg_id),
            backstop=lambda: _resolve_if_pending(state, assistant_msg_id),
        )


def get_manager(state: Any) -> LeadChatManager:
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, LeadChatManager())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


async def _run_turn(state: Any, lead_id: int, assistant_msg_id: int) -> None:
    """Run one lead-chat turn through the shared engine."""
    await run_chat_turn(state, _lead_spec(state, lead_id, assistant_msg_id))


def _entity_pairs(entities: Any) -> list[tuple[str, str]]:
    """The (kind, key) pairs a lead stores, in order. A malformed entry is skipped."""
    return [
        (str(e[0]), str(e[1]))
        for e in (entities or [])
        if isinstance(e, (list, tuple)) and len(e) == 2
    ]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


async def lead_seed_context(db: Any, lead: Any, *, ctx: InvestigationContext) -> str:
    """The lead block, the evidence block, and the dossier of each host entity.

    Composed RAW, before the engine's egress sweep, like the host chat's seed:
    an address in the dossier must collapse onto the label the rest of the
    prompt gets. The addresses come from the stored lead, a typed record, so
    the dossier block states a host the sweep has never met (``known_only``
    stays off, as on the alert path).
    """
    observations = await leads_store.timeline(db, lead.id)
    entities = _entity_pairs(lead.entities_json)
    block = build_lead_context_block(
        lead_id=lead.id,
        status=str(lead.status),
        entities=entities,
        kinds=[kind_label(str(k)) for k in (lead.kinds_json or [])],
        observations=[(o.summary or kind_label(o.kind)).strip() for o in observations],
    )
    evidence = leads_store.evidence_block_for(observations) if observations else ""
    hosts = {
        key: "an entity of this lead" for kind, key in entities if kind == "host" and _is_ip(key)
    }
    dossier = await host_dossier_prompt_block(hosts, ctx=ctx) if hosts else ""
    return "\n\n".join(part for part in (block, evidence) if part) + dossier


def _lead_spec(state: Any, lead_id: int, assistant_msg_id: int) -> ChatTurnSpec:
    """Bind the engine to ONE lead's shared thread, anchored on its observations."""
    thread_key = thread_key_for(lead_id)

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
        # Demo backstop. The route already answers demo POSTs itself.
        if getattr(settings, "soc_ai_demo", False) is True:
            await _finish(content=DEMO_REPLY, status="done", meta={"demo": True})
            return None
        ctx = ctx_from_state(state)
        async with state.db_sessionmaker() as db:
            history = await gc_svc.history_for_agent(db, thread_key)
            lead = await leads_store.get(db, lead_id)
            if lead is None:
                # Deleted between the POST and the turn. Say so in the thread.
                await _finish(
                    content=f"Lead {lead_id} is no longer in the store.",
                    status="error",
                    meta=None,
                )
                return None
            seed_context = await lead_seed_context(db, lead, ctx=ctx)
        question, prior = split_history(history)

        hunt_sink: list[dict[str, Any]] = []

        def _build_agent(
            model: Model, ctx: InvestigationContext, system_prompt: str
        ) -> Agent[None, str]:
            # propose_hunt, no propose_verdict: a lead has no verdict to set.
            # Promote on the lead page starts the investigation that does.
            return build_chat_agent(
                model,
                ctx,
                system_prompt=system_prompt,
                hunt_sink=hunt_sink,
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
            system_prompt=LEAD_CHAT_SYSTEM_PROMPT,
            oql_flavor="hunt",
            build_agent=_build_agent,
            finalize_meta=_finalize,
        )

    return ChatTurnSpec(
        row_id=assistant_msg_id,
        label=f"lead={lead_id}",
        timeout_s=state.settings.chat_turn_timeout_s,
        finish=_finish,
        prepare=_prepare,
        set_progress=_set_progress,
    )
