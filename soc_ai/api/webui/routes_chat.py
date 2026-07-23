"""Per-investigation analyst chat endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.webui._shared import (
    router,
)
from soc_ai.api.webui._timeline import (
    ChatMessageOut,
    _chat_msg_out,
)
from soc_ai.store import chat as chat_svc
from soc_ai.store.models import Investigation
from soc_ai.webui import (
    chat_manager,
)

_LOGGER = logging.getLogger(__name__)


class ChatThreadOut(BaseModel):
    messages: list[ChatMessageOut]
    pending: bool


def _thread(msgs: list[Any]) -> ChatThreadOut:
    return ChatThreadOut(
        messages=[_chat_msg_out(m) for m in msgs],
        pending=any(m.status == "pending" for m in msgs),
    )


@router.get("/investigations/{inv_id}/chat", response_model=ChatThreadOut)
async def get_chat(request: Request, inv_id: str) -> ChatThreadOut:
    """Poll target — the chat thread, with a pending flag while the assistant works."""
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
    background chat task, and returns the thread (poll GET .../chat until !pending)."""
    text = body.message.strip()
    if not text:
        raise HTTPException(status_code=400, detail={"reason": "empty_message"})
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if inv.status == "running":
            raise HTTPException(status_code=409, detail={"reason": "still_running"})
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
