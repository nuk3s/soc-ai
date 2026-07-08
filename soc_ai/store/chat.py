"""Store helpers for the per-investigation follow-up chat thread.

One thread per investigation. A user turn writes a ``user`` row; the answer is a
``assistant`` row created ``pending`` and filled in by a background task so the
UI can poll live progress (mirrors the hunt pattern).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store import chat_memory
from soc_ai.store.auth import utcnow
from soc_ai.store.models import ChatMessage


async def add_user_message(db: AsyncSession, inv_id: str, content: str) -> ChatMessage:
    msg = ChatMessage(investigation_id=inv_id, role="user", content=content, status="done")
    db.add(msg)
    # Dual-write into the chat_memory projection (same transaction, so message
    # and projection land atomically) — user turns are complete on arrival.
    chat_memory.record_message(
        db,
        source=chat_memory.SOURCE_INVESTIGATION,
        thread_id=inv_id,
        role="user",
        content=content,
    )
    await db.commit()
    await db.refresh(msg)
    return msg


async def create_pending_assistant(db: AsyncSession, inv_id: str) -> ChatMessage:
    msg = ChatMessage(investigation_id=inv_id, role="assistant", content="", status="pending")
    db.add(msg)
    await db.commit()
    await db.refresh(msg)
    return msg


async def finish_assistant(
    db: AsyncSession,
    msg_id: int,
    *,
    content: str,
    status: str = "done",
    meta: dict[str, Any] | None = None,
) -> None:
    msg = await db.get(ChatMessage, msg_id)
    if msg is None:
        return
    msg.content = content
    msg.status = status
    msg.meta = meta
    # An assistant turn only becomes institutional knowledge once it COMPLETES —
    # project it into chat_memory now (pending rows are empty; errored rows are
    # apology strings; neither is worth recalling). Same-transaction, atomic.
    if status == "done":
        chat_memory.record_message(
            db,
            source=chat_memory.SOURCE_INVESTIGATION,
            thread_id=msg.investigation_id,
            role="assistant",
            content=content,
        )
    await db.commit()


async def reap_stale_pending(db: AsyncSession, *, older_than: timedelta | None = None) -> int:
    """Mark orphaned ``pending`` assistant chat rows as ``error``. Returns the count.

    Mirrors :func:`soc_ai.store.investigations.reap_stale_running`. A ``pending``
    assistant row is filled in by a background task; if that task is gone (a
    restart) or hung past the turn timeout, the row would stay ``pending`` —
    empty content, forever — with no user-visible resolution.

    ``older_than=None`` reaps EVERY pending assistant row — used at startup, where
    any row still ``pending`` was orphaned by the restart (its background task is
    gone). A positive ``timedelta`` reaps only rows whose ``created_at`` is older
    than that — used by the periodic sweep so a legitimately in-flight turn is
    never killed. ``created_at`` and ``utcnow()`` are both naive UTC, so the
    comparison is consistent.
    """
    q = select(ChatMessage).where(
        ChatMessage.role == "assistant",
        ChatMessage.status == "pending",
    )
    if older_than is not None:
        cutoff = utcnow() - older_than
        q = q.where(ChatMessage.created_at < cutoff)
    rows = list((await db.scalars(q)).all())
    for msg in rows:
        msg.status = "error"
        if not msg.content:
            msg.content = (
                "The assistant was interrupted (likely a restart or timeout) — please ask again."
            )
    if rows:
        await db.commit()
    return len(rows)


async def list_messages(db: AsyncSession, inv_id: str) -> list[ChatMessage]:
    rows = (
        await db.scalars(
            select(ChatMessage)
            .where(ChatMessage.investigation_id == inv_id)
            .order_by(ChatMessage.id)
        )
    ).all()
    return list(rows)


async def get_message(db: AsyncSession, msg_id: int) -> ChatMessage | None:
    return await db.get(ChatMessage, msg_id)


async def history_for_agent(db: AsyncSession, inv_id: str) -> list[tuple[str, str]]:
    """Completed (role, content) turns to seed the agent — excludes the in-flight
    pending assistant row and any errored turns."""
    return [
        (m.role, m.content)
        for m in await list_messages(db, inv_id)
        if m.status == "done" and m.content
    ]


async def counts_for(db: AsyncSession, inv_ids: list[str]) -> dict[str, int]:
    """Return a mapping of investigation_id -> done-message count.

    A single grouped COUNT query; investigations with no done messages are
    omitted (callers should treat missing keys as 0).
    """
    if not inv_ids:
        return {}
    rows = (
        await db.execute(
            select(ChatMessage.investigation_id, func.count().label("n"))
            .where(
                ChatMessage.investigation_id.in_(inv_ids),
                ChatMessage.status == "done",
            )
            .group_by(ChatMessage.investigation_id)
        )
    ).all()
    return {row.investigation_id: row.n for row in rows}
