"""Analyst chat endpoints: per-investigation, and the Dashboard's general chat.

Both surfaces speak the SAME wire format (:class:`ChatThreadOut` built by
:func:`_thread`) even though they read different tables, because the SPA has one
chat transport and should not learn a second shape to talk to the second chat.
``GeneralChatMessage`` is column-for-column ``ChatMessage`` with ``thread_key``
in place of ``investigation_id``, which is what makes that reuse a duck-type
rather than a coincidence.

Both surfaces' routes carry a demo branch (:func:`_demo_thread`): on the public
demo every visitor is the same caller and the threads they'd write to are shared,
so a demo chat answers without persisting anything at all.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    router,
)
from soc_ai.api.webui._timeline import (
    ChatMessageOut,
    _chat_msg_out,
)
from soc_ai.api.webui.routes_dossier import _require_ip
from soc_ai.demo.guard import is_demo
from soc_ai.store import chat as chat_svc
from soc_ai.store import general_chat as gc_svc
from soc_ai.store.models import Investigation
from soc_ai.webui import (
    chat_manager,
    general_chat_manager,
    host_chat_manager,
)

_LOGGER = logging.getLogger(__name__)


class ChatThreadOut(BaseModel):
    messages: list[ChatMessageOut]
    pending: bool
    # Tools the in-flight turn has called so far, oldest first. Lets the client
    # show what the agent is DOING during a long turn rather than a bare typing
    # indicator (dogfood 2026-08-06). Empty unless a turn is pending.
    progress_tools: list[str] = []


def _thread(msgs: list[Any]) -> ChatThreadOut:
    pending_rows = [m for m in msgs if m.status == "pending"]
    progress: list[str] = []
    if pending_rows:
        meta = pending_rows[-1].meta
        if isinstance(meta, dict):
            raw = meta.get("progress_tools")
            if isinstance(raw, list):
                progress = [str(t) for t in raw]
    return ChatThreadOut(
        messages=[_chat_msg_out(m) for m in msgs],
        pending=bool(pending_rows),
        progress_tools=progress,
    )


@router.get("/investigations/{inv_id}/chat", response_model=ChatThreadOut)
async def get_chat(request: Request, inv_id: str) -> ChatThreadOut:
    """Poll target — the chat thread, with a pending flag while the assistant works.

    On the public demo it is always empty — see :func:`_demo_thread`.
    """
    if is_demo(request.app.state.settings):
        # Empty rather than a read of the shared thread, for the same reason the
        # general chat's GET is: the demo never writes one, and returning empty
        # unconditionally keeps "no visitor sees another's messages" a property
        # of this route instead of a bet on the table having stayed empty.
        return _thread([])
    async with request.app.state.db_sessionmaker() as db:
        msgs = await chat_svc.list_messages(db, inv_id)
    return _thread(msgs)


class ChatIn(BaseModel):
    # Bound the analyst's follow-up turn: the value is stored in SQLite and
    # forwarded verbatim to the LLM, so an unbounded body burns tokens / can blow
    # the context window. Mirrors HuntChatIn.objective's cap.
    message: str = Field(min_length=1, max_length=4000)


@router.post("/investigations/{inv_id}/chat", response_model=ChatThreadOut)
async def post_chat(request: Request, inv_id: str, body: ChatIn) -> ChatThreadOut:
    """Ask a follow-up. Writes the user turn + a pending assistant turn, spawns the
    background chat task, and returns the thread (poll GET .../chat until !pending).

    On the public demo it neither writes nor spawns anything — see
    :func:`_demo_thread`.
    """
    text = body.message.strip()
    if not text:
        raise HTTPException(status_code=400, detail={"reason": "empty_message"})
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if inv.status == "running":
            raise HTTPException(status_code=409, detail={"reason": "still_running"})
        if is_demo(request.app.state.settings):
            # AFTER the 404/still-running checks, so the demo rejects the same
            # requests a real deployment does — it answers differently, it does
            # not validate differently. Before the busy check and the writes,
            # which are the two that cross demo visitors.
            return _demo_thread(text, chat_manager.demo_reply(request.app.state, inv_id))
        existing = await chat_svc.list_messages(db, inv_id)
        if any(m.status == "pending" for m in existing):
            # A prior turn's assistant is still working — one in-flight turn at a
            # time, or a second POST orphans a duplicate pending row and spawns a
            # duplicate agent run (mirrors the hunt-chat guard in routes_hunts.py).
            raise HTTPException(status_code=409, detail={"reason": "chat_busy"})
        await chat_svc.add_user_message(db, inv_id, text)
        pending = await chat_svc.create_pending_assistant(db, inv_id)
        msgs = await chat_svc.list_messages(db, inv_id)
    chat_manager.get_manager(request.app.state).start(
        request.app.state, inv_id=inv_id, assistant_msg_id=pending.id
    )
    return _thread(msgs)


# ── The Dashboard's general chat ────────────────────────────────────────────
# One rolling thread per analyst, no thread list and no naming: the dashboard is
# a launcher screen, and a ChatGPT-shaped history IA is the obvious scope trap.
# These routes reuse ``_thread`` unchanged; the hunt-proposal card reaches the
# client because ``hunt_proposal`` is registered in ``PROPOSAL_KINDS``, not
# because this surface serializes differently.

# ``GeneralChatMessage.thread_key`` is a 64-char column and ``identify_caller``
# can exceed it (``token:<name>`` where name is itself up to 64). Truncation
# alone would silently MERGE two long-named callers into one thread — one
# analyst reading another's scratchpad — so an over-long key keeps a digest of
# the full value.
_MAX_THREAD_KEY = 64
_THREAD_KEY_DIGEST = 12


def _thread_key_for(caller: str) -> str:
    """Fold a caller identity into a collision-safe, column-sized thread key."""
    key = (caller or "").strip() or "anonymous"
    if len(key) <= _MAX_THREAD_KEY:
        return key
    digest = hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:_THREAD_KEY_DIGEST]
    return f"{key[: _MAX_THREAD_KEY - _THREAD_KEY_DIGEST - 1]}-{digest}"


async def _thread_key(request: Request) -> str:
    """This caller's thread — the same actor string ``started_by`` records."""
    return _thread_key_for(await identify_caller(request))


def _require_general_chat(request: Request) -> None:
    """Refuse when the feature is switched off.

    A live kill switch, not a config error: an always-available agent on the
    landing screen is the one surface an operator may need to stop without a
    redeploy (cost, a misbehaving gateway). 403 rather than 404 so a disabled
    feature is distinguishable from a broken route.
    """
    if not general_chat_manager.is_enabled(request.app.state.settings):
        raise HTTPException(
            status_code=403,
            detail={
                "reason": "general_chat_disabled",
                "hint": "enable general_chat_enabled to use the dashboard assistant",
            },
        )


# ── the public demo: an answer nobody else can read ─────────────────────────


def _demo_thread(text: str, reply: str) -> ChatThreadOut:
    """One ephemeral turn — the visitor's question and the canned *reply*.

    Shared by every chat surface on the demo (the general chat below, and the
    investigation chat above), because they all have the same problem and a
    second demo path is how this bug survived on two surfaces after the third
    was fixed. Only the *reply* differs: each manager owns its own answer.

    **Why the demo does not persist at all.** On the public demo
    ``api_auth_required`` is false and nobody logs in, so ``identify_caller``
    answers ``"anonymous"`` for every visitor and :func:`_thread_key_for` folds
    the whole internet onto ONE thread. Stored, that means visitor two reads
    visitor one's questions and gets a 409 ``chat_busy`` from a turn they did
    not start. The investigation and hunt chats key their thread on the
    investigation/hunt instead, which the demo's visitors also all share — same
    outcome by a different route, so they take the same treatment.

    The alternative was a per-visitor thread key, and it needs a per-browser
    identity this app does not have to give: the session cookie is issued only
    by ``POST /login`` (``routes_auth``), which a demo visitor never calls, and
    nothing else sets a cookie. What is left is the client's own word for who it
    is — a header or a remote address. Behind Render's proxy the address is the
    proxy's, and anything client-supplied is attacker-chosen, which would turn
    an unauthenticated visitor's request into a write keyed on a string they
    pick — a worse surface than the one being fixed.

    So: no store, no key, nothing to collide over. The answer is canned, and the
    client renders the thread the POST returns, so the visitor still sees their
    question and the reply for the turn. The only thing lost is persistence
    across a reload, which a canned reply should arguably not have. That property
    also holds under concurrency by construction — two visitors share no state at
    all, so neither ordering nor timing can cross them.
    """
    return ChatThreadOut(
        messages=[
            ChatMessageOut(role="user", text=text),
            # The caller sources *reply* from the surface's manager so the demo
            # has ONE answer per surface, not two that can drift; each manager
            # keeps its own short-circuit as the backstop for any future path
            # that does spawn a turn (it must never build a model — the demo
            # egress guard raises).
            ChatMessageOut(role="assistant", text=reply),
        ],
        pending=False,
    )


@router.get("/chat", response_model=ChatThreadOut)
async def get_general_chat(request: Request) -> ChatThreadOut:
    """Poll target — this analyst's rolling thread, pending flag while it works.

    Also the Dashboard's mount cost: one GET, after which the client only
    re-arms the poll while ``pending`` is true.
    """
    _require_general_chat(request)
    if is_demo(request.app.state.settings):
        # Empty rather than a read of the shared anonymous thread: the demo never
        # writes one (see _demo_thread), and returning empty unconditionally
        # keeps "no visitor sees another's messages" a property of this route
        # instead of a bet on the table having stayed empty.
        return _thread([])
    async with request.app.state.db_sessionmaker() as db:
        msgs = await gc_svc.list_messages(db, await _thread_key(request))
    return _thread(msgs)


@router.post("/chat", response_model=ChatThreadOut)
async def post_general_chat(request: Request, body: ChatIn) -> ChatThreadOut:
    """Ask the dashboard assistant. Writes the user turn + a pending assistant
    turn, spawns the background turn, and returns the thread (poll GET /chat
    until !pending).

    Answers directly; it never starts a hunt — when a question genuinely needs a
    sweep the turn comes back with a PROPOSED objective for the analyst to
    confirm.

    On the public demo it neither writes nor spawns anything — see
    :func:`_demo_thread`.
    """
    _require_general_chat(request)
    text = body.message.strip()
    if not text:
        raise HTTPException(status_code=400, detail={"reason": "empty_message"})
    if is_demo(request.app.state.settings):
        # After validation, so the demo rejects the same requests a real
        # deployment does — it answers differently, it does not validate
        # differently.
        return _demo_thread(text, general_chat_manager.DEMO_REPLY)
    key = await _thread_key(request)
    async with request.app.state.db_sessionmaker() as db:
        existing = await gc_svc.list_messages(db, key)
        if any(m.status == "pending" for m in existing):
            # One in-flight turn per thread — a second POST would orphan a
            # duplicate pending row and spawn a duplicate agent run (the same
            # guard the investigation and hunt chats carry).
            raise HTTPException(status_code=409, detail={"reason": "chat_busy"})
        await gc_svc.add_user_message(db, key, text)
        pending = await gc_svc.create_pending_assistant(db, key)
        msgs = await gc_svc.list_messages(db, key)
    general_chat_manager.get_manager(request.app.state).start(
        request.app.state, thread_key=key, assistant_msg_id=pending.id
    )
    return _thread(msgs)


# ── The host page chat ──────────────────────────────────────────────────────
# One SHARED thread per host: the subject is the machine, so every analyst on
# its page reads one conversation — the investigation-chat precedent for
# object-scoped chats, not the dashboard's per-caller scratchpad. Rows live in
# the SAME GeneralChatMessage table under a ``host:<canonical ip>`` key
# (``thread_key`` is String(64); a canonical IPv6 is ≤45 chars + the 5-char
# prefix — no migration, and no third chat table to drift).
#
# Deliberately NOT behind ``general_chat_enabled``: that switch exists to stop
# the always-available landing-screen assistant. This chat is gated the way the
# investigation chat is — the subject must be addressable, so a path segment
# that is not an IP is a 404 (``_require_ip``, the dossier routes' own
# validator) — and by nothing else.


@router.get("/dossiers/{ip}/chat", response_model=ChatThreadOut)
async def get_host_chat(request: Request, ip: str) -> ChatThreadOut:
    """Poll target — this host's shared thread, pending flag while a turn runs.

    On the public demo it is always empty — see :func:`_demo_thread`.
    """
    key = host_chat_manager.thread_key_for(_require_ip(ip))
    if is_demo(request.app.state.settings):
        return _thread([])
    async with request.app.state.db_sessionmaker() as db:
        msgs = await gc_svc.list_messages(db, key)
    return _thread(msgs)


@router.post("/dossiers/{ip}/chat", response_model=ChatThreadOut)
async def post_host_chat(request: Request, ip: str, body: ChatIn) -> ChatThreadOut:
    """Ask about this host. Writes the user turn + a pending assistant turn,
    spawns the background turn, and returns the thread (poll GET until
    ``!pending``).

    On the public demo it neither writes nor spawns anything — see
    :func:`_demo_thread`.
    """
    text = body.message.strip()
    if not text:
        raise HTTPException(status_code=400, detail={"reason": "empty_message"})
    host = _require_ip(ip)
    if is_demo(request.app.state.settings):
        # After validation, so the demo rejects the same requests a real
        # deployment does — it answers differently, it does not validate
        # differently.
        return _demo_thread(text, host_chat_manager.DEMO_REPLY)
    key = host_chat_manager.thread_key_for(host)
    async with request.app.state.db_sessionmaker() as db:
        existing = await gc_svc.list_messages(db, key)
        if any(m.status == "pending" for m in existing):
            # One in-flight turn per thread — the guard every chat surface
            # carries. On a SHARED thread this also means one turn per HOST:
            # a second analyst's question waits for the first answer, exactly
            # as it does on a shared investigation thread.
            raise HTTPException(status_code=409, detail={"reason": "chat_busy"})
        await gc_svc.add_user_message(db, key, text)
        pending = await gc_svc.create_pending_assistant(db, key)
        msgs = await gc_svc.list_messages(db, key)
    host_chat_manager.get_manager(request.app.state).start(
        request.app.state, ip=host, assistant_msg_id=pending.id
    )
    return _thread(msgs)


@router.delete("/dossiers/{ip}/chat", response_model=ChatThreadOut)
async def clear_host_chat(request: Request, ip: str) -> ChatThreadOut:
    """Start over. Deletes THIS host's thread only, and returns it empty.

    Safe while a turn is in flight for the same reason the general chat's
    DELETE is: every write the background turn still makes targets a row id
    and no-ops once that row is gone.

    On the public demo it deletes nothing — see :func:`_demo_thread`.
    """
    key = host_chat_manager.thread_key_for(_require_ip(ip))
    if is_demo(request.app.state.settings):
        return _thread([])
    async with request.app.state.db_sessionmaker() as db:
        await gc_svc.trim_thread(db, key, keep_last=0)
        msgs = await gc_svc.list_messages(db, key)
    return _thread(msgs)


@router.delete("/chat", response_model=ChatThreadOut)
async def clear_general_chat(request: Request) -> ChatThreadOut:
    """Start over. Deletes THIS caller's thread only, and returns it empty so the
    client can reuse the same response handler.

    Allowed while a turn is in flight: every write the background turn still
    makes (progress, the answer, the stuck-pending backstop) targets a row id
    and no-ops once that row is gone, so clearing can never resurrect the
    discarded thread.

    On the public demo it deletes nothing — see :func:`_demo_thread`.
    """
    _require_general_chat(request)
    if is_demo(request.app.state.settings):
        # A no-op that reports success: the demo thread lives only in the
        # browser, so there is nothing of the visitor's to delete — and an
        # unauthenticated visitor must not be handed a delete over the store,
        # which is exactly what running the real branch under the shared
        # "anonymous" key would be.
        return _thread([])
    key = await _thread_key(request)
    async with request.app.state.db_sessionmaker() as db:
        await gc_svc.trim_thread(db, key, keep_last=0)
        msgs = await gc_svc.list_messages(db, key)
    return _thread(msgs)
