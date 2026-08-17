"""GeneralChatManager — the Dashboard chat's half of one shared turn engine.

The dashboard's "Ask soc-ai" box used to hand every question to the hunt
console: a multi-minute background job producing a formal report. Most questions
asked at a launcher screen ("what datasets do I have", "what's my noisiest
rule", "what did overnight look like") deserve an ANSWER at investigation-chat
latency, and a hunt only when the question genuinely needs a sweep — which the
agent PROPOSES and the analyst starts.

This module is deliberately small. Everything true of any chat shape — egress
guard, prompt composition, live tool progress, the wall clock, the regrounding
loop, the grounding caveat, the terminal error rows — lives in
:mod:`soc_ai.webui.chat_turn`; here we supply only the general-shaped half as a
:class:`~soc_ai.webui.chat_turn.ChatTurnSpec`:

* the ANCHOR is the grid, not an alert (:func:`build_general_context_block`);
* the thread is keyed on the analyst, not an investigation;
* the proposal tool is ``propose_hunt``, not ``propose_verdict``.

Copying the engine instead of specifying against it is what left the hunt chat
without progress reporting or grounding. If this file starts growing turn logic,
that is the signal to widen ``ChatTurnSpec`` — not to fork again.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.chat_agent import (
    GENERAL_CHAT_SYSTEM_PROMPT,
    build_chat_agent,
    build_general_context_block,
)
from soc_ai.agent.context import InvestigationContext
from soc_ai.api.deps import ctx_from_state
from soc_ai.dossier.prompt import host_dossier_prompt_block, internal_ips_in_text
from soc_ai.oracle.identifiers import EffectiveIdentifiers, effective_internal_identifiers
from soc_ai.so_client.inventory import inventory_prompt_block
from soc_ai.store import general_chat as gc_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.webui import alerts_query as aq
from soc_ai.webui.chat_turn import (
    ChatTaskManager,
    ChatTurnSpec,
    TurnInputs,
    run_chat_turn,
    split_history,
)

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_general_chat_manager"

# The implicit window the two time-windowed query tools use when the model does
# not name one. The chat role's default is 60 minutes because an investigation
# chat pivots around an alert; a dashboard question has no such anchor and is
# routinely about last night or last week, so a 1h default would answer "what
# did overnight look like" with the last hour and sound confident about it.
GENERAL_CHAT_WINDOW_MINUTES = 1440

# The posture block's window, for both halves of it (verdicts reached, alert
# volume). Must stay a value ``alerts_query.TIME_RANGES`` knows ("1h"/"4h"/"24h"
# …) or the volume half silently falls back to 24h while the block's header
# claims otherwise.
POSTURE_WINDOW_HOURS = 24

# Rules named in the posture block. build_general_context_block caps its own
# rendering too; this only bounds what we ask Elasticsearch to hand back.
_POSTURE_TOP_RULES = 5

# A model-written hunt objective is a brief the analyst reads and confirms, not
# a report. Capped because the objective is forwarded to ``POST /api/v1/hunt``,
# which rejects an over-long body — a proposal card that cannot be started is a
# worse outcome than one that was trimmed.
MAX_PROPOSED_OBJECTIVE_CHARS = 4000

# Demo mode's answer, and the only one: the route
# (:mod:`soc_ai.api.webui.routes_chat`) serves it directly on the POST without
# storing a turn, because a public demo folds every visitor onto one caller
# identity and so must not persist a thread at all. It is defined HERE rather
# than there because this module owns what the dashboard assistant says, and the
# import runs route → manager (the reverse would be a cycle).
#
# Not routed through ``soc_ai.demo.chat.canned_reply``: that helper looks a
# script up by (target, target_id), and this chat's "id" is a per-analyst thread
# key that no shipped fixture can name.
#
# The demo branch in ``_prepare`` below is now a BACKSTOP, not the live path —
# kept so that any future caller which does spawn a general turn on a demo still
# resolves its pending row from here instead of building a model, which the demo
# egress guard refuses.
DEMO_REPLY = (
    "This is a recorded demo, so the dashboard assistant isn't available here — "
    "answering you live would mean querying a real Security Onion grid and calling "
    "a model. In a real deployment I'd answer this from the grid's own telemetry "
    "(datasets, hosts, recent verdicts) and propose a hunt when a question needs a "
    "sweep. The seeded investigations and hunts show that reasoning end to end."
)


class GeneralChatManager(ChatTaskManager):
    """Dashboard-chat task tracker.

    The GC-safe task registry and the stuck-pending backstop come from
    :class:`~soc_ai.webui.chat_turn.ChatTaskManager`; this subclass only knows
    how to name a general turn, so the route keeps a narrow call site.
    """

    def start(self, state: Any, *, thread_key: str, assistant_msg_id: int) -> None:
        self.spawn(
            row_id=assistant_msg_id,
            runner=_run_turn(state, thread_key, assistant_msg_id),
            backstop=lambda: _resolve_if_pending(state, assistant_msg_id),
        )


def get_manager(state: Any) -> GeneralChatManager:
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, GeneralChatManager())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


def is_enabled(settings: Any) -> bool:
    """Whether the dashboard chat is switched on.

    Read through ``getattr`` with a True default so the routes work before the
    setting is declared, and so a duck-typed settings double in a unit test does
    not accidentally disable the feature. Only an explicit ``False`` kills it —
    an always-available agent on the landing screen is the one surface that has
    to be stoppable without a redeploy.
    """
    return getattr(settings, "general_chat_enabled", True) is not False


async def _run_turn(state: Any, thread_key: str, assistant_msg_id: int) -> None:
    """Run one dashboard-chat turn through the shared engine."""
    await run_chat_turn(state, _general_spec(state, thread_key, assistant_msg_id))


def _general_spec(state: Any, thread_key: str, assistant_msg_id: int) -> ChatTurnSpec:
    """Bind the engine to ONE analyst's thread, anchored on the grid."""

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
        # Demo mode: never build the model/gateway (the egress guard would
        # raise). Short-circuit BEFORE any agent/ES work and resolve the pending
        # row exactly as the live path does. `is True` (not truthy) so a
        # MagicMock settings in a unit test can't trip the demo branch.
        # Unreachable from the route today (it answers the POST itself without
        # spawning a turn — see DEMO_REPLY); kept as the backstop for any caller
        # that does spawn one, since a turn that reached the gateway would raise.
        if getattr(settings, "soc_ai_demo", False) is True:
            await _finish(content=DEMO_REPLY, status="done", meta={"demo": True})
            return None
        ctx = ctx_from_state(state)
        async with state.db_sessionmaker() as db:
            history = await gc_svc.history_for_agent(db, thread_key)
            identifiers = await _identifiers(db, settings)
            verdict_counts = await _verdict_counts(db)
        question, prior = split_history(history)
        # NOTE — this seed now stacks four ambient blocks: internal identifiers,
        # the dataset inventory, recent posture, and the host dossier. NONE of
        # them is charged against a token budget, unlike the investigation
        # pipeline, which subtracts the dossier's cost from the enriched
        # context's allowance before trimming. The asymmetry is deliberate and
        # not an oversight: there is no large trimmable payload here to take the
        # tokens FROM — the investigation path budgets because its enriched-alert
        # JSON is the thing being squeezed. Each block is individually capped
        # (`_MAX_*` here, MAX_TOKENS_TOTAL in the dossier, the discovery
        # aggregation in the inventory), so the total is bounded. A fifth block
        # is the point at which that reasoning should be revisited.
        seed_context = build_general_context_block(
            identifiers=identifiers,
            inventory_block=await inventory_prompt_block(ctx.elastic, settings),
            verdict_counts=verdict_counts,
            top_rules=await _top_rules(ctx.elastic, settings),
            window_hours=POSTURE_WINDOW_HOURS,
        ) + await _thread_dossier_block(ctx, question, prior)

        hunt_sink: list[dict[str, Any]] = []

        def _build_agent(
            model: Model, ctx: InvestigationContext, system_prompt: str
        ) -> Agent[None, str]:
            # Only the general chat gets propose_hunt, and it gets no
            # propose_verdict: there is no alert here to disposition.
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
            system_prompt=GENERAL_CHAT_SYSTEM_PROMPT,
            # Telemetry-first OQL examples: a dashboard question slices
            # datasets, it does not pivot from an alert.
            oql_flavor="hunt",
            # The inventory is already IN seed_context (above) because that block
            # is what the grounding check grades the answer against; letting the
            # engine append its own copy too would state the grid's datasets
            # twice in one prompt.
            append_inventory=False,
            build_agent=_build_agent,
            finalize_meta=_finalize,
        )

    return ChatTurnSpec(
        row_id=assistant_msg_id,
        label=f"thread={thread_key}",
        # No new knob: a dashboard turn is an ANSWER, so it gets the
        # investigation chat's budget, not the hunt chat's minutes.
        timeout_s=state.settings.chat_turn_timeout_s,
        finish=_finish,
        prepare=_prepare,
        set_progress=_set_progress,
    )


def apply_hunt_proposal_meta(
    meta: dict[str, Any], hunt_sink: list[dict[str, Any]], guard: Any
) -> None:
    """Stamp the turn's ``propose_hunt`` call (if any) into the stored ``meta``.

    Shared by every surface that registers ``propose_hunt`` (the dashboard chat
    and the host chat) — a second copy of this is exactly the drift
    ``chat_turn.py``'s docstring warns about, and the desanitize step is the
    part a fork would forget first.

    The prompt asks for at most one proposal per reply; if the model made
    several, the last one wins — it reflects its final reasoning and matches
    the narrative answer stored alongside it.
    """
    if not hunt_sink:
        return
    prop = hunt_sink[-1]
    if guard is not None:
        # propose_hunt is registered in chat_agent (not the guarded toolset),
        # so its captured args are still in label space — restore before the
        # objective is shown to the analyst and replayed into a hunt.
        prop = guard.desanitize_obj(prop)
    meta.update(
        {
            "kind": "hunt_proposal",
            "proposal": {
                "objective": str(prop.get("objective") or "")[:MAX_PROPOSED_OBJECTIVE_CHARS],
                "why": str(prop.get("why") or ""),
            },
        }
    )


# ── seed-context inputs (each best-effort: a degraded grid still gets a chat) ──


async def _thread_dossier_block(
    ctx: InvestigationContext, question: str, prior: list[tuple[str, str]]
) -> str:
    """Host identity for the addresses this THREAD names — and nothing else.

    The investigation chat takes its host set from an alert; this chat has no
    alert, so the conversation is the scope. An analyst who types an address has
    named the host they are asking about.

    Deliberately NOT the whole network: seeding every host a grid knows would be
    an unbounded prompt that answers a question nobody asked, and on a large
    deployment it would push the grid block and the posture out of the window.
    ``t_host_dossier`` is the on-demand route for a host the thread has not
    named — the model has the tool and the grid block tells it which addresses
    are ours.

    Lands in ``seed_context`` (not the system prompt) so it joins the corpus
    the grounding gate grades against: the answer that names the host correctly
    should come back grounded, not caveated.

    ``known_only`` is REQUIRED here, not an optimisation. ``prior`` carries the
    model's own previous turns, so an address in this text may be one the model
    produced rather than one anybody observed; rendering a "no dossier" line for
    it would put it in the grounding corpus and let it ground itself. Only hosts
    the sweep actually knows are described — ``t_host_dossier`` remains the route
    for anything else, and it answers per address.
    """
    thread_text = "\n".join([question, *(text for _role, text in prior)])
    named = internal_ips_in_text(thread_text, ctx.settings)
    if not named:
        return ""
    return await host_dossier_prompt_block(
        {ip: "named in this conversation" for ip in named}, ctx=ctx, known_only=True
    )


async def _identifiers(db: Any, settings: Any) -> EffectiveIdentifiers | None:
    """The network's own addresses/suffixes/hosts, or None if they won't resolve.

    None is rendered by :func:`build_general_context_block` as a stated unknown,
    which is the honest failure: the model is told it does not know which ranges
    are internal rather than left to assume.
    """
    try:
        return await effective_internal_identifiers(db, settings)
    except Exception as exc:
        _LOGGER.warning("general chat: identifier resolution failed: %s", exc)
        return None


async def _verdict_counts(db: Any) -> dict[str, int] | None:
    """Verdicts reached in the posture window — the store's tally, or None.

    The query itself lives in :func:`soc_ai.store.investigations.
    verdict_counts_since` (aggregated in SQL, never a capped scan: a floor
    reported as a total is a lie the seed block would state as fact). What is
    this manager's own is the DEGRADE — None, which the block renders as a
    stated unknown, so a sick database costs the analyst a posture line and not
    the whole chat.
    """
    try:
        return await inv_svc.verdict_counts_since(
            db, utcnow() - timedelta(hours=POSTURE_WINDOW_HOURS)
        )
    except Exception as exc:
        _LOGGER.warning("general chat: posture tally failed: %s", exc)
        return None


async def _top_rules(elastic: Any, settings: Any) -> list[tuple[str, int]] | None:
    """The grid's busiest alert rules, straight from the alerts aggregation.

    Reusing :func:`soc_ai.webui.alerts_query.fetch_groups` (rather than a second
    aggregation of our own) is what keeps "your noisiest rule" in the chat and
    the top row of the Alerts screen from disagreeing. None on any ES failure —
    Elasticsearch being down must degrade the seed, not the chat.

    The range is derived from :data:`POSTURE_WINDOW_HOURS` rather than left to
    the query default, so the volumes always cover the window the block's own
    header claims.
    """
    try:
        groups, _total = await aq.fetch_groups(
            elastic, settings, time_range=f"{POSTURE_WINDOW_HOURS}h", sort="count"
        )
    except Exception as exc:
        _LOGGER.warning("general chat: top-rule lookup failed: %s", exc)
        return None
    return [(g.rule_name, g.count) for g in groups[:_POSTURE_TOP_RULES]]


async def _resolve_if_pending(state: Any, assistant_msg_id: int) -> None:
    """Backstop for the done-callback: mark a still-``pending`` assistant row as
    ``error``. Only writes when the row is genuinely still pending, so it never
    clobbers a terminal row the turn already wrote on the normal path."""
    try:
        async with state.db_sessionmaker() as db:
            msg = await gc_svc.get_message(db, assistant_msg_id)
            if msg is None or msg.status != "pending":
                return
            await gc_svc.finish_assistant(
                db,
                assistant_msg_id,
                content="The assistant was interrupted — please ask again.",
                status="error",
                meta=None,
            )
        _LOGGER.warning(
            "general chat: resolved stuck-pending msg=%s to error via task-done backstop",
            assistant_msg_id,
        )
    except Exception:
        _LOGGER.exception(
            "general chat: backstop failed to resolve pending msg=%s", assistant_msg_id
        )
