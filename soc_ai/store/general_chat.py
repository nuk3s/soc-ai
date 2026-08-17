"""Store helpers for the dashboard's general chat — one rolling thread per analyst.

Function-for-function a mirror of :mod:`soc_ai.store.chat`, keyed on a
``thread_key`` (the ``identify_caller`` actor string) instead of an investigation
id. The duplication is deliberate and bounded: the two tables stay separate (see
migration 0025), and keeping the names identical means folding them together
later is a rename rather than a redesign.

Two things differ from investigation chat, both on purpose:

* **No ``chat_memory`` projection.** ``chat_memory`` is retrieved as "prior
  discussion excerpts" *into investigation verdict prompts*. The dashboard chat
  is a scratchpad — an analyst thinking out loud, or an answer about grid
  inventory — and feeding that back into verdict reasoning is the prompt
  poisoning this project has repeatedly had to undo. The useful direction is the
  inverse (general chat reading past-chat memory), which is a separate feature.
* **A trim.** An investigation thread is naturally bounded by the investigation;
  a per-analyst thread that never ends is not, so :func:`trim_thread` runs at the
  end of every turn.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.auth import utcnow
from soc_ai.store.models import GeneralChatMessage

# Rows kept per thread. The thread is persistent and per-user, so nothing else
# ever prunes it — 200 messages is roughly a week of dashboard questions and
# still a trivial read.
MAX_THREAD_MESSAGES = 200

# Completed turns fed back to the agent as conversation history. Well under
# MAX_THREAD_MESSAGES: the stored thread is the analyst's record, the prompt
# window is a cost decision, and they should not be the same number.
MAX_HISTORY_TURNS = 20


async def add_user_message(db: AsyncSession, thread_key: str, content: str) -> GeneralChatMessage:
    msg = GeneralChatMessage(thread_key=thread_key, role="user", content=content, status="done")
    db.add(msg)
    await db.commit()
    await db.refresh(msg)
    return msg


async def create_pending_assistant(db: AsyncSession, thread_key: str) -> GeneralChatMessage:
    msg = GeneralChatMessage(thread_key=thread_key, role="assistant", content="", status="pending")
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
    msg = await db.get(GeneralChatMessage, msg_id)
    if msg is None:
        return
    msg.content = content
    msg.status = status
    msg.meta = meta
    # Trim here rather than at the call site: this is the one hook every turn
    # passes through, success or failure. A caller that forgets would leave a
    # thread growing forever, and the symptom (a slow, expensive prompt months
    # later) would not point back at the omission.
    await _trim(db, msg.thread_key, keep_last=MAX_THREAD_MESSAGES)
    await db.commit()


async def set_progress(db: AsyncSession, msg_id: int, tools: list[str]) -> None:
    """Record the tools a still-pending turn has called so far.

    Written from the agent's per-tool callback so the poll endpoint can render
    live progress instead of a bare typing indicator. Best-effort by contract:
    the caller swallows failures, because a progress write must never break the
    turn that is producing the real answer.
    """
    msg = await db.get(GeneralChatMessage, msg_id)
    if msg is None or msg.status != "pending":
        return  # finished (or trimmed away) between the tool call and this write
    msg.meta = {**(msg.meta or {}), "progress_tools": tools[-12:]}
    await db.commit()


async def reap_stale_pending(db: AsyncSession, *, older_than: timedelta | None = None) -> int:
    """Mark orphaned ``pending`` assistant rows as ``error``. Returns the count.

    The general chat needs its own reaper: :func:`soc_ai.store.chat.reap_stale_pending`
    only scans ``chat_messages``, so without this a restart mid-turn leaves a
    dashboard row ``pending`` with empty content forever — the exact bug already
    fixed once for investigation chat.

    ``older_than=None`` reaps EVERY pending assistant row — used at startup,
    where any row still ``pending`` was orphaned by the restart (its background
    task is gone). A positive ``timedelta`` reaps only rows older than that —
    used by the periodic sweep, so a legitimately in-flight turn is never
    killed. ``created_at`` and ``utcnow()`` are both naive UTC.
    """
    q = select(GeneralChatMessage).where(
        GeneralChatMessage.role == "assistant",
        GeneralChatMessage.status == "pending",
    )
    if older_than is not None:
        cutoff = utcnow() - older_than
        q = q.where(GeneralChatMessage.created_at < cutoff)
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


async def list_messages(
    db: AsyncSession, thread_key: str, *, limit: int | None = None
) -> list[GeneralChatMessage]:
    """Thread messages oldest-first. ``limit`` takes the NEWEST that many.

    Ordering is applied after the limit so a bounded read still renders forwards
    — a UI that reverses the transcript when a thread gets long is a bug, not a
    feature.
    """
    if limit is None:
        rows = (
            await db.scalars(
                select(GeneralChatMessage)
                .where(GeneralChatMessage.thread_key == thread_key)
                .order_by(GeneralChatMessage.id)
            )
        ).all()
        return list(rows)
    newest = (
        await db.scalars(
            select(GeneralChatMessage)
            .where(GeneralChatMessage.thread_key == thread_key)
            .order_by(GeneralChatMessage.id.desc())
            .limit(limit)
        )
    ).all()
    return sorted(newest, key=lambda m: m.id)


async def get_message(db: AsyncSession, msg_id: int) -> GeneralChatMessage | None:
    return await db.get(GeneralChatMessage, msg_id)


async def history_for_agent(
    db: AsyncSession, thread_key: str, *, limit: int = MAX_HISTORY_TURNS
) -> list[tuple[str, str]]:
    """Completed (role, content) turns to seed the agent — excludes the in-flight
    pending assistant row and any errored turns.

    Bounded to the newest ``limit`` completed turns: this thread is persistent,
    so an unbounded history would make every question on a well-used dashboard
    progressively slower and more expensive than the last.
    """
    done = [m for m in await list_messages(db, thread_key) if m.status == "done" and m.content]
    return [(m.role, m.content) for m in done[-limit:]]


async def trim_thread(
    db: AsyncSession, thread_key: str, *, keep_last: int = MAX_THREAD_MESSAGES
) -> int:
    """Delete everything but the newest ``keep_last`` rows of one thread.

    Returns the number of rows deleted. Called automatically at the end of every
    turn by :func:`finish_assistant`; exposed for maintenance paths that want it
    explicitly.
    """
    deleted = await _trim(db, thread_key, keep_last=keep_last)
    if deleted:
        await db.commit()
    return deleted


async def _trim(db: AsyncSession, thread_key: str, *, keep_last: int) -> int:
    """Stage the deletes for :func:`trim_thread` without committing.

    Split out so :func:`finish_assistant` trims in the SAME transaction that
    writes the answer — a commit in between would expose a thread that is
    trimmed but whose newest turn is still empty.

    Ids are selected first and deleted by id, rather than one DELETE with a
    correlated NOT IN subquery, because SQLite will not read and delete from the
    same table in one statement without materializing it anyway.
    """
    doomed = list(
        (
            await db.scalars(
                select(GeneralChatMessage.id)
                .where(GeneralChatMessage.thread_key == thread_key)
                .order_by(GeneralChatMessage.id.desc())
                .offset(max(0, keep_last))
            )
        ).all()
    )
    if not doomed:
        return 0
    await db.execute(
        sa_delete(GeneralChatMessage)
        .where(GeneralChatMessage.id.in_(doomed))
        .execution_options(synchronize_session=False)
    )
    return len(doomed)
