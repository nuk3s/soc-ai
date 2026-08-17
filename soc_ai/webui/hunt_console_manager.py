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

from soc_ai.agent.chat_agent import CHAT_SYSTEM_PROMPT
from soc_ai.api.deps import ctx_from_state
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.api.runner import CancelToken
from soc_ai.demo.chat import canned_reply
from soc_ai.demo.guard import is_demo
from soc_ai.dossier.prompt import host_dossier_prompt_block, internal_ips_in_text
from soc_ai.store import hunts as hunt_svc
from soc_ai.webui.chat_turn import (
    ChatTaskManager,
    ChatTurnSpec,
    TurnInputs,
    run_chat_turn,
    split_history,
)

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_hunt_console_manager"
_CHAT_STATE_ATTR = "_hunt_chat_manager"

# Hard ceiling on simultaneous background hunts this manager will run. Every hunt
# holds the single model route for up to ``hunt_run_timeout_s`` with a
# ``hunt_request_limit``-deep budget, so unbounded concurrency melts the gateway —
# a real incident ran 7 at once, all hit the wall-clock, all produced garbage.
# This is the SHARED limit across the ad-hoc (POST /hunts/chat), bulk re-hunt, and
# scheduled paths; the bulk endpoint's ``_REHUNT_START_CAP`` is a smaller
# per-request cap that sits under this global one.
_MAX_CONCURRENT_HUNTS = 5


class HuntConsoleManager:
    """Tracks in-flight background hunt tasks to prevent GC collection."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._tokens: dict[str, CancelToken] = {}
        # Slots claimed by start() calls that are past the ceiling check but have
        # not yet registered their task in ``_tasks``. Counted alongside
        # ``_tasks`` so the ceiling holds across the ``await`` inside start() — a
        # naive ``len(self._tasks)`` check would let a concurrent burst all slip
        # through the window before any of them registered.
        self._reserved = 0

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
        generator ended/errored before emitting ``hunt_created`` — or if the
        shared concurrency ceiling (``_MAX_CONCURRENT_HUNTS``) is already full.

        ``kind`` tags the hunt row (``"chat"`` for an operator-typed hunt,
        ``"scheduled"`` for a recurring hunt fired by the schedule loop) — it is
        threaded straight into ``hunt_recorded_run`` → ``hunt_svc.create``.
        """
        # Concurrency guard: this manager is fire-and-forget (one unbounded
        # background asyncio.Task per call), so without a cap a scripted/rapid-fire
        # burst of starts puts N simultaneous hunts on the single model route.
        # Reserve a slot ATOMICALLY (no await between the check and the +=1) so the
        # ceiling holds even under a concurrent burst. A None return is surfaced by
        # callers as 503/"could_not_start" (ad-hoc + bulk) or a skipped cycle (the
        # scheduler), i.e. retry in a smaller batch / a moment later.
        if len(self._tasks) + self._reserved >= _MAX_CONCURRENT_HUNTS:
            _LOGGER.warning(
                "hunt_console_manager: at concurrency ceiling (%d in flight) — rejecting start",
                _MAX_CONCURRENT_HUNTS,
            )
            return None
        self._reserved += 1
        try:
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
        finally:
            # Release the reservation: once the task is registered in ``_tasks`` it
            # holds the slot instead (a clean hand-off with no gap); on any early
            # return the slot is simply freed.
            self._reserved -= 1

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
# "Chat about this" feature but for a HuntReport. The POST handler writes the
# user turn + a pending assistant turn (as hunt_events), spawns a background
# task here, and the UI polls the thread until the assistant row flips to
# done/error.
#
# This surface is a CLIENT of the shared turn engine
# (:mod:`soc_ai.webui.chat_turn`), exactly like the investigation, host and
# general chats. It used to fork the engine, so it silently missed the live tool
# progress, grounding check, regrounding loop and fabricated-citation gate that
# shipped 2026-08-06 (the un-fork the ``chat_turn`` docstring names). Everything
# generic to a turn now comes from the engine; here we supply only the
# hunt-shaped half as a :class:`~soc_ai.webui.chat_turn.ChatTurnSpec`:
#
# * the ANCHOR is the HuntReport — its objective + narrative + findings, plus
#   the identity of the hosts the report named (seeded into the grounding corpus
#   so naming a host correctly comes back grounded, not caveated);
# * the thread is stored as ``hunt_events`` keyed by the hunt id, so ``finish``
#   and ``set_progress`` route through ``hunt_svc``;
# * there is NO proposal tool — a hunt never acks/escalates and a follow-up is
#   not itself a sweep — so the engine's default read-only agent (no
#   ``propose_verdict``, no ``propose_hunt``) is exactly right.


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


async def _hunt_chat_seed_block(ctx: Any, hunt: Any) -> str:
    """The hunt-chat seed corpus, RAW: what the hunt concluded + who its hosts ARE.

    Two blocks ride the seed: what the hunt concluded (:func:`_hunt_chat_seed_context`)
    and what the hosts the report named ARE. The host identity is read off the
    seed text itself (a hunt has no alert to take endpoints from), so a follow-up
    like "was that host even allowed to answer SSH?" is answerable without
    re-deriving the host's role from telemetry the hunt already read.

    Returned unsanitized ON PURPOSE: it lands in ``TurnInputs.seed_context``,
    which the engine folds into the system prompt and THEN sweeps as one string,
    so the dossier's addresses collapse onto the same egress labels the seed's
    own addresses get. Sanitizing here would leak the block in the clear when the
    engine appended it after its own sweep. seed_context is also the corpus the
    grounding check grades against, so it must stay in real-value space.

    The OQL primer and the dataset inventory are NOT composed here — the shared
    engine appends both (``oql_flavor="hunt"``, ``append_inventory=True``), the
    same way it does for every other chat shape.
    """
    seed_context = _hunt_chat_seed_context(hunt)
    named = internal_ips_in_text(seed_context, ctx.settings)
    # `known_only`: the addresses come from the stored REPORT — text a model
    # wrote. Rendering a "no dossier" line for one would put it in this thread's
    # grounding corpus and let a host the hunt merely asserted ground itself.
    dossier = (
        await host_dossier_prompt_block(
            {ip: "named in this hunt" for ip in named}, ctx=ctx, known_only=True
        )
        if named
        else ""
    )
    return seed_context + dossier


class HuntChatManager(ChatTaskManager):
    """Hunt-chat task tracker.

    The GC-safe task registry and the stuck-pending backstop come from
    :class:`~soc_ai.webui.chat_turn.ChatTaskManager`; this subclass only knows
    how to name a hunt-chat turn, so the route keeps a narrow call site. The
    backstop resolves a still-``pending`` assistant *hunt_event*, since this
    thread lives in ``hunt_events`` keyed by the hunt id — not the general-chat
    table the host/dashboard chats share.
    """

    def start(self, state: Any, *, hunt_id: str, assistant_event_id: int) -> None:
        self.spawn(
            row_id=assistant_event_id,
            runner=_run_turn(state, hunt_id, assistant_event_id),
            backstop=lambda: _hunt_chat_resolve_if_pending(state, assistant_event_id),
        )


def get_chat_manager(state: Any) -> HuntChatManager:
    """Lazily attach a :class:`HuntChatManager` to *app.state* and return it."""
    if not hasattr(state, _CHAT_STATE_ATTR):
        setattr(state, _CHAT_STATE_ATTR, HuntChatManager())
    return getattr(state, _CHAT_STATE_ATTR)  # type: ignore[no-any-return]


def demo_chat_reply(state: Any, hunt_id: str) -> str:
    """The demo's scripted answer for this hunt's follow-up chat.

    Public because the ROUTE serves it: on the public demo
    ``api_auth_required`` is false, so every visitor is the same caller and this
    thread is keyed on a hunt they all share — persisted, one visitor's typed
    question shows up in another's panel. So the demo answers on the POST and
    stores nothing (see
    :func:`soc_ai.api.webui.routes_hunts._demo_hunt_chat_thread`).

    It lives HERE rather than in the route for the same reason
    :func:`soc_ai.webui.chat_manager.demo_reply` does: this module owns what the
    hunt chat says, so there is ONE answer per surface instead of two that can
    drift. The import runs route → manager; the reverse would be a cycle.
    """
    return canned_reply(getattr(state, "demo_fixtures", None), "hunt", hunt_id)


async def _run_turn(state: Any, hunt_id: str, assistant_event_id: int) -> None:
    """Run one hunt-chat follow-up turn through the shared engine."""
    await run_chat_turn(state, _hunt_chat_spec(state, hunt_id, assistant_event_id))


def _hunt_chat_spec(state: Any, hunt_id: str, assistant_event_id: int) -> ChatTurnSpec:
    """Bind the shared turn engine to ONE completed hunt's follow-up thread.

    Read-only Q&A anchored on a HuntReport instead of an alert, stored as
    ``hunt_events``. No proposal tool (a hunt never acks/escalates, and a
    follow-up is not itself a sweep), so ``build_agent`` and ``finalize_meta``
    stay unset — the engine's default read-only agent is exactly right.
    """

    async def _finish(*, content: str, status: str, meta: dict[str, Any] | None) -> None:
        async with state.db_sessionmaker() as db:
            await hunt_svc.finish_chat_assistant(
                db, assistant_event_id, content=content, status=status, meta=meta
            )

    async def _set_progress(tools: list[str]) -> None:
        async with state.db_sessionmaker() as pdb:
            await hunt_svc.set_progress(pdb, assistant_event_id, tools)

    async def _prepare() -> TurnInputs | None:
        settings = state.settings
        # Demo backstop — the route answers demo POSTs itself (see
        # :func:`demo_chat_reply`); a spawned turn must still never build a model,
        # since the demo egress guard refuses to construct an outbound client.
        # Resolve the pending row from here and tell the engine to stop.
        if is_demo(settings):
            await _finish(
                content=demo_chat_reply(state, hunt_id), status="done", meta={"demo": True}
            )
            return None
        ctx = ctx_from_state(state)
        async with state.db_sessionmaker() as db:
            loaded = await hunt_svc.get_with_events(db, hunt_id)
            history = await hunt_svc.chat_history_for_agent(db, hunt_id)
        if loaded is None:
            raise RuntimeError("hunt not found")
        hunt, _events = loaded
        question, prior = split_history(history)
        # RAW seed — the engine folds it into the system prompt and sanitizes the
        # whole string at the egress boundary, and grades the answer against it.
        seed_context = await _hunt_chat_seed_block(ctx, hunt)
        return TurnInputs(
            ctx=ctx,
            seed_context=seed_context,
            question=question,
            prior=prior,
            system_prompt=CHAT_SYSTEM_PROMPT,
            # Telemetry-first OQL examples: a hunt follow-up slices datasets, it
            # does not pivot from an alert.
            oql_flavor="hunt",
            # The engine appends the dataset inventory (default True): the seed
            # does not already carry it.
        )

    return ChatTurnSpec(
        row_id=assistant_event_id,
        label=f"hunt={hunt_id}",
        # The hunt chat's budget is MINUTES (a follow-up can run a real sweep),
        # not the investigation chat's seconds — its own setting, unchanged from
        # the fork this replaces.
        timeout_s=state.settings.hunt_chat_turn_timeout_s,
        finish=_finish,
        prepare=_prepare,
        set_progress=_set_progress,
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
