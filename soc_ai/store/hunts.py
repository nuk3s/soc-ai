"""Persistence service for threat hunts (Hunt Console).

A hunt row is created when a chat-driven hunt starts; events append as the
agent's trace streams; :func:`finalize` lands the narrative + the HuntReport.
Mirrors :mod:`soc_ai.store.investigations` — the hunt is broader (findings +
narrative across hosts/time) but the lifecycle + tee/finalize shape is the same.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from soc_ai.store import chat_memory
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Hunt, HuntEvent

STATUS_RUNNING = "running"
STATUS_COMPLETE = "complete"

_WS_RE = re.compile(r"\s+")


def _objective_hash(objective: str) -> str:
    """Stable content hash of the NORMALIZED objective.

    Normalization = lowercase + collapse all whitespace runs to a single space +
    strip. So two re-runs whose objective text differs only in case or spacing
    ("Hunt for beaconing" vs "hunt   for  beaconing\n") share a hash and link as
    the same objective; a genuinely different objective does not. SHA-256 hex,
    truncated to 32 chars — plenty of collision resistance for one deployment's
    hunt history, and fits the indexed ``String(64)`` column.
    """
    normalized = _WS_RE.sub(" ", objective.strip().lower())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


async def create(
    db: AsyncSession,
    *,
    objective: str,
    started_by: str,
    kind: str = "chat",
) -> Hunt:
    hunt = Hunt(
        id=str(ULID()),
        objective=objective,
        objective_hash=_objective_hash(objective),
        started_by=started_by,
        kind=kind[:16],
    )
    db.add(hunt)
    await db.commit()
    await db.refresh(hunt)
    return hunt


async def previous_completed_run(
    db: AsyncSession,
    *,
    objective_hash: str | None,
    before_created_at: datetime,
    exclude_id: str,
) -> Hunt | None:
    """The most recent COMPLETE hunt with the same objective_hash, before this one.

    Powers the "vs last run" diff: given the current hunt's ``objective_hash`` and
    ``created_at``, find the prior COMPLETE run of the SAME objective to diff
    against. Excludes ``exclude_id`` (the current hunt) so a self-match can't
    happen, and requires ``created_at`` strictly earlier so only an EARLIER run is
    the baseline. Returns ``None`` when there is no prior run (first run of an
    objective, or a legacy row with a NULL hash — the diff is then omitted).
    """
    if not objective_hash:
        return None
    q = (
        select(Hunt)
        .where(
            Hunt.objective_hash == objective_hash,
            Hunt.status == STATUS_COMPLETE,
            Hunt.id != exclude_id,
            Hunt.created_at < before_created_at,
        )
        .order_by(Hunt.created_at.desc(), Hunt.id.desc())
        .limit(1)
    )
    return (await db.scalars(q)).first()


async def append_events(db: AsyncSession, hunt_id: str, events: list[dict[str, Any]]) -> None:
    for ev in events:
        db.add(
            HuntEvent(
                hunt_id=hunt_id,
                sequence=int(ev.get("sequence", 0)),
                kind=str(ev.get("kind", ""))[:40],
                payload=ev.get("payload") or {},
            )
        )
    await db.commit()


async def finalize(
    db: AsyncSession,
    hunt_id: str,
    *,
    status: str,
    narrative: str | None = None,
    report: dict[str, Any] | None = None,
) -> None:
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return
    hunt.status = status
    if narrative is not None:
        hunt.narrative = narrative
    if report is not None:
        hunt.report = report
    hunt.finished_at = utcnow()
    await db.commit()


async def get_with_events(db: AsyncSession, hunt_id: str) -> tuple[Hunt, list[HuntEvent]] | None:
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return None
    events = (
        await db.scalars(
            select(HuntEvent)
            .where(HuntEvent.hunt_id == hunt_id)
            .order_by(HuntEvent.sequence, HuntEvent.id)
        )
    ).all()
    return hunt, list(events)


async def list_recent(
    db: AsyncSession,
    *,
    status: str | None = None,
    limit: int = 100,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Hunt]:
    """Return hunts ordered by created_at desc, with optional status filter.

    ``since``/``until`` bound ``created_at`` INCLUSIVELY on both ends
    (``since <= created_at <= until``) — matching the frontend's ``inRange``
    inclusive ``[from, to]`` (lib/timeRange.ts) and the store's inclusive
    lower-bound convention (``created_at >= cutoff``). Bounds must be naive
    UTC, like every stored timestamp (:func:`soc_ai.store.auth.utcnow`).
    Absent bounds keep the original unbounded behavior.
    """
    q = select(Hunt).order_by(Hunt.created_at.desc(), Hunt.id.desc())
    if status is not None:
        q = q.where(Hunt.status == status)
    if since is not None:
        q = q.where(Hunt.created_at >= since)
    if until is not None:
        q = q.where(Hunt.created_at <= until)
    q = q.limit(limit)
    return list((await db.scalars(q)).all())


async def findings_for_entity(
    db: AsyncSession, value: str, *, scan_limit: int = 100
) -> list[dict[str, Any]]:
    """Hunt findings that name an entity in their ``hosts[]`` — for the entity page.

    Findings live inside the ``report`` JSON (``report["findings"][].hosts[]``),
    which is NOT indexed, so this is the one potentially-costly bit of the E3.5
    read-model: it scans the last ``scan_limit`` hunts' reports in Python. BOUND it
    (default 100 hunts) so it stays cheap. A future index / denormalization of
    finding→host is Epoch territory (a `hunt_findings` projection table) — until
    then, the bound is the guardrail.

    Returns light dicts (NOT the whole finding), newest hunt first:
    ``{hunt_id, hunt_objective, title, severity, category, ts}`` where ``ts`` is the
    hunt's ``created_at`` (findings have no own timestamp). Only COMPLETE hunts
    carry a report worth scanning; running/errored rows are skipped.
    """
    if not value:
        return []
    recent = await list_recent(db, status=STATUS_COMPLETE, limit=scan_limit)
    out: list[dict[str, Any]] = []
    for hunt in recent:
        report = hunt.report if isinstance(hunt.report, dict) else {}
        findings = report.get("findings")
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            hosts = f.get("hosts") or []
            if not isinstance(hosts, list) or value not in [str(h) for h in hosts]:
                continue
            out.append(
                {
                    "hunt_id": hunt.id,
                    "hunt_objective": hunt.objective,
                    "title": str(f.get("title") or ""),
                    "severity": str(f.get("severity") or "info"),
                    "category": str(f.get("category") or "threat"),
                    "ts": hunt.created_at,
                }
            )
    return out


async def reap_stale_running(
    db: AsyncSession, *, older_than_minutes: int | None, status: str = "error"
) -> int:
    """Mark orphaned ``running`` hunts terminal. Returns the count.

    ``older_than_minutes=None`` reaps EVERY running row (startup: any row still
    ``running`` was orphaned by the restart); a positive int reaps only rows
    older than that many minutes (periodic sweep). Mirrors the investigation
    reaper: startup uses ``interrupted`` (a clean restart cut the run off, not a
    failure), the periodic sweep uses ``error``.
    """
    q = select(Hunt).where(Hunt.status == STATUS_RUNNING)
    if older_than_minutes is not None:
        cutoff = utcnow() - timedelta(minutes=older_than_minutes)
        q = q.where(Hunt.created_at < cutoff)
    rows = list((await db.scalars(q)).all())
    now = utcnow()
    interrupted = status == "interrupted"
    for hunt in rows:
        hunt.status = status
        hunt.finished_at = now
        if not hunt.narrative:
            hunt.narrative = (
                "Hunt was interrupted by a service restart before it finished — re-run it."
                if interrupted
                else "Hunt did not finish (interrupted by a restart or timed out)."
            )
    if rows:
        await db.commit()
    return len(rows)


async def delete(db: AsyncSession, hunt_id: str) -> bool:
    """Delete a hunt and its events in one transaction.

    Returns True if the hunt existed (and was removed), False otherwise.
    """
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return False
    await db.execute(sa_delete(HuntEvent).where(HuntEvent.hunt_id == hunt_id))
    # The hunt's chat thread was projected into chat_memory (dual-write below) —
    # remove it in the same transaction so a deleted hunt can't keep echoing
    # into future prompts via retrieval.
    await chat_memory.delete_thread(db, hunt_id)
    await db.delete(hunt)
    await db.commit()
    return True


# ── Follow-up "Chat about this hunt" thread ──────────────────────────────────
#
# A completed hunt gets a read-only Q&A thread, exactly like an investigation's
# follow-up chat. Rather than reuse ``chat_messages`` (whose ``investigation_id``
# is a FK into ``investigations`` — a hunt id would violate it), the thread is
# stored as ``hunt_events`` on the SAME hunt, keyed by these two kinds. They are
# hidden from the hunt's execution timeline (see ``_HUNT_TL_SKIP``) and surfaced
# only through the dedicated ``/hunts/{id}/chat`` endpoint.

CHAT_USER = "chat_user"
CHAT_ASSISTANT = "chat_assistant"


async def _next_chat_sequence(db: AsyncSession, hunt_id: str) -> int:
    """One past the hunt's max event sequence — chat rows append after the trace."""
    top = (
        await db.execute(select(func.max(HuntEvent.sequence)).where(HuntEvent.hunt_id == hunt_id))
    ).scalar()
    return int(top or 0) + 1


async def add_chat_user_message(db: AsyncSession, hunt_id: str, content: str) -> HuntEvent:
    ev = HuntEvent(
        hunt_id=hunt_id,
        sequence=await _next_chat_sequence(db, hunt_id),
        kind=CHAT_USER,
        payload={"content": content, "status": "done"},
    )
    db.add(ev)
    # Dual-write into the chat_memory projection (same transaction — atomic).
    # App-level rather than a SQL trigger because content/status live inside
    # the JSON payload here; see soc_ai.store.chat_memory.
    chat_memory.record_message(
        db,
        source=chat_memory.SOURCE_HUNT,
        thread_id=hunt_id,
        role="user",
        content=content,
    )
    await db.commit()
    await db.refresh(ev)
    return ev


async def create_pending_chat_assistant(db: AsyncSession, hunt_id: str) -> HuntEvent:
    ev = HuntEvent(
        hunt_id=hunt_id,
        sequence=await _next_chat_sequence(db, hunt_id),
        kind=CHAT_ASSISTANT,
        payload={"content": "", "status": "pending"},
    )
    db.add(ev)
    await db.commit()
    await db.refresh(ev)
    return ev


async def finish_chat_assistant(
    db: AsyncSession,
    event_id: int,
    *,
    content: str,
    status: str = "done",
    meta: dict[str, Any] | None = None,
) -> None:
    ev = await db.get(HuntEvent, event_id)
    if ev is None:
        return
    payload = dict(ev.payload or {})
    payload["content"] = content
    payload["status"] = status
    if meta is not None:
        payload["meta"] = meta
    ev.payload = payload
    # Project the COMPLETED assistant turn into chat_memory (mirrors
    # soc_ai.store.chat.finish_assistant — done-only, same transaction).
    if status == "done":
        chat_memory.record_message(
            db,
            source=chat_memory.SOURCE_HUNT,
            thread_id=ev.hunt_id,
            role="assistant",
            content=content,
        )
    await db.commit()


async def list_chat_messages(db: AsyncSession, hunt_id: str) -> list[HuntEvent]:
    """The hunt's chat thread (user + assistant rows), in order."""
    rows = (
        await db.scalars(
            select(HuntEvent)
            .where(
                HuntEvent.hunt_id == hunt_id,
                HuntEvent.kind.in_((CHAT_USER, CHAT_ASSISTANT)),
            )
            .order_by(HuntEvent.sequence, HuntEvent.id)
        )
    ).all()
    return list(rows)


async def get_chat_event(db: AsyncSession, event_id: int) -> HuntEvent | None:
    return await db.get(HuntEvent, event_id)


async def chat_counts_for(db: AsyncSession, hunt_ids: list[str]) -> dict[str, int]:
    """hunt_id -> chat-message count, one grouped COUNT query (mirrors
    ``soc_ai.store.chat.counts_for``). Hunts with no chat rows are omitted —
    callers treat missing keys as 0."""
    if not hunt_ids:
        return {}
    rows = (
        await db.execute(
            select(HuntEvent.hunt_id, func.count().label("n"))
            .where(
                HuntEvent.hunt_id.in_(hunt_ids),
                HuntEvent.kind.in_((CHAT_USER, CHAT_ASSISTANT)),
            )
            .group_by(HuntEvent.hunt_id)
        )
    ).all()
    return {row.hunt_id: row.n for row in rows}


async def chat_history_for_agent(db: AsyncSession, hunt_id: str) -> list[tuple[str, str]]:
    """Completed (role, content) chat turns to seed the follow-up agent — excludes
    the in-flight pending assistant row and any errored turns."""
    out: list[tuple[str, str]] = []
    for ev in await list_chat_messages(db, hunt_id):
        p = ev.payload or {}
        content = str(p.get("content") or "")
        if p.get("status") == "done" and content:
            role = "user" if ev.kind == CHAT_USER else "assistant"
            out.append((role, content))
    return out
