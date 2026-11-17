"""A one-time clear of old items of Needs you (owner, 2026-11-16).

Needs you has no time limit since 2026-11-15: an investigation stays until a
person decides. On production 30 investigations waited, most of them from
July to September. The owner accepted "a one-time clear, with the list
first". He decides what goes, and this module never guesses: a clear needs a
date and a reason.

* :func:`waiting_investigations` is the investigation set of
  ``GET /needs-you/items``, read by the same two functions: the runs with a
  waiting action (:func:`routes_meta.pending_action_runs`) and the Needs you
  query (:func:`inv_svc.query_page` with ``needs_you_ids``). A lead and a
  campaign have their own decisions and are no part of it.
* :func:`clear_items` clears each investigation. The audit record
  ``needs_you_cleared`` comes first, with ``mutating=True``: a failed write
  stops the clear before the store write. Each waiting action of a true
  positive gets the event of the dismiss route
  (:func:`routes_actions.dismissal_event`), with the reason. Each cleared
  investigation gets the record ``report["needs_you_cleared"]``. That record
  stops the wait of a verdict that needs more info
  (:func:`inv_svc.needs_you_cleared_sql`), with no migration. A store write
  that fails after the audit record gets the audit record
  ``needs_you_clear_failed``, and the clear stops there.
* :func:`restore` undoes one clear: it removes the record and undoes the
  dismissals of that clear, and no other dismissal.

A clear writes no verdict, no confidence and no ``resolution``. It is no
analyst override, so the rule prior, the outcome counts and the analyst
verdicts read the investigation as before. It writes nothing to Security
Onion. The audit record goes to the audit index, as every record does.
"""

from __future__ import annotations

import contextlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Investigation, InvestigationEvent

__all__ = [
    "AUDIT_SESSION",
    "ONLY_VERDICTS",
    "ClearResult",
    "NotClearedError",
    "RestoreResult",
    "WaitingInvestigation",
    "check_before",
    "check_reason",
    "clear_items",
    "cleared_sentence",
    "restore",
    "waiting_investigations",
]

# The session id of the audit records of a clear and of a restore.
AUDIT_SESSION = "needs-you-clear"
# The verdicts that ``--only`` takes. A true positive waits with an action.
ONLY_VERDICTS = ("needs_more_info", "true_positive")
_KEY = inv_svc.NEEDS_YOU_CLEARED_KEY


@dataclass(frozen=True)
class WaitingInvestigation:
    """One investigation that waits on the analyst, as the list prints it.

    ``event_at`` is the time of the event that the investigation judges, and
    the date of a clear reads it. ``since`` is when it started to wait: the
    finish of the investigation. ``actions`` counts its waiting actions.
    """

    id: str
    verdict: str
    event_at: datetime | None
    since: datetime | None
    title: str
    source: str | None
    destination: str | None
    actions: int


@dataclass
class ClearResult:
    """What a clear did. ``failed`` is the investigation whose audit record
    failed, and the clear stopped there. ``error`` names the failure."""

    cleared: list[WaitingInvestigation] = field(default_factory=list)
    dismissed: int = 0
    failed: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class RestoreResult:
    investigation_id: str
    verdict: str | None
    restored_actions: int


class NotClearedError(LookupError):
    """The investigation holds no clear record, or it does not exist."""


def check_reason(reason: str | None) -> str:
    """The reason of a clear, stripped. An empty reason is refused."""
    text = (reason or "").strip()
    if not text:
        raise ValueError("A clear needs a reason. Give the reason with --reason.")
    return text


def check_before(before: datetime, *, now: datetime | None = None) -> datetime:
    """The date of a clear, naive UTC. A date that has not come is refused.

    A date in the future takes every item, the newest included. The tool
    never takes more than the operator saw in the list.
    """
    if before > (now or utcnow()):
        raise ValueError("The date must be in the past.")
    return before


async def waiting_investigations(
    db: AsyncSession,
    *,
    state: Any,
    before: datetime | None = None,
    only: str | None = None,
) -> list[WaitingInvestigation]:
    """The investigations that wait, the oldest event first.

    ``before`` keeps the investigations whose event time is before it (naive
    UTC). ``only`` keeps one verdict of :data:`ONLY_VERDICTS`. ``state`` is
    the app state, or an object with ``settings`` and ``elastic``: the action
    rule reads the anchors of the hunt findings through it, as the console
    does.
    """
    from soc_ai.api.webui.routes_meta import pending_action_runs  # noqa: PLC0415 - cycle

    if only is not None and only not in ONLY_VERDICTS:
        raise ValueError(f"--only takes one of these values: {', '.join(ONLY_VERDICTS)}.")
    pending = await pending_action_runs(db, since=None, state=state)
    wanted = sorted(pending)
    rows: list[Investigation] = []
    while True:
        page = await inv_svc.query_page(
            db, limit=inv_svc.MAX_PAGE_LIMIT, offset=len(rows), needs_you_ids=wanted
        )
        rows.extend(page.rows)
        if not page.rows or len(rows) >= page.total:
            break
    out: list[WaitingInvestigation] = []
    for inv in rows:
        if before is not None and (inv.event_at is None or inv.event_at >= before):
            continue
        if only is not None and inv.verdict != only:
            continue
        out.append(
            WaitingInvestigation(
                id=inv.id,
                verdict=str(inv.verdict or ""),
                event_at=inv.event_at,
                since=inv.finished_at or inv.created_at,
                title=inv.rule_name or f"Investigation {inv.id}",
                source=inv.src_ip,
                destination=inv.dest_ip,
                actions=pending.get(inv.id, 0),
            )
        )
    out.sort(key=lambda w: (w.event_at or w.since or datetime.min, w.id))
    return out


async def _next_sequence(db: AsyncSession, inv_id: str) -> int:
    top = await db.scalar(
        select(func.max(InvestigationEvent.sequence)).where(
            InvestigationEvent.investigation_id == inv_id
        )
    )
    return int(top or 0) + 1


def _now_iso() -> str:
    return utcnow().isoformat(timespec="seconds") + "Z"


async def _waiting_actions(
    db: AsyncSession, inv: Investigation, state: Any
) -> list[dict[str, Any]]:
    """The waiting actions of a true positive: the index, the identity and the tool."""
    from soc_ai.api.webui._timeline import _action_identity  # noqa: PLC0415 - cycle
    from soc_ai.api.webui.routes_meta import waiting_actions_by_run  # noqa: PLC0415 - cycle

    if inv.verdict != "true_positive":
        return []
    waiting = (await waiting_actions_by_run(db, [inv], state=state)).get(inv.id, [])
    report = inv.report if isinstance(inv.report, dict) else {}
    recs = report.get("recommended_actions") or []
    out: list[dict[str, Any]] = []
    for action in waiting:
        index = int(action.index)
        rec = recs[index] if 0 <= index < len(recs) else None
        if not isinstance(rec, dict):
            continue
        out.append(
            {
                "index": index,
                "action_key": _action_identity(rec),
                "tool_name": str(rec.get("tool_name") or ""),
            }
        )
    return out


async def clear_items(
    db: AsyncSession,
    items: Sequence[WaitingInvestigation],
    *,
    reason: str,
    by: str,
    audit: Any,
    state: Any,
) -> ClearResult:
    """Clear each investigation of ``items`` from Needs you.

    The order for one investigation: the audit record, then one store
    commit with the clear record and the dismissals. A failed audit write
    stops the clear, and that investigation and the ones after it stay. The
    ones before it are cleared, and each has its record.
    """
    from soc_ai.api.webui.routes_actions import dismissal_event  # noqa: PLC0415 - cycle

    text = check_reason(reason)
    result = ClearResult()
    for item in items:
        inv = await db.get(Investigation, item.id)
        if inv is None:
            continue
        actions = await _waiting_actions(db, inv, state)
        clear_id, at = uuid.uuid4().hex[:12], _now_iso()
        record: dict[str, Any] = {
            "id": clear_id,
            "at": at,
            "by": by,
            "reason": text,
            "verdict": inv.verdict,
            "actions": actions,
        }
        try:
            await audit.log_kind(
                AUDIT_SESSION,
                "needs_you_cleared",
                {
                    "investigation_id": inv.id,
                    "verdict": inv.verdict,
                    "reason": text,
                    "user": by,
                    "clear_id": clear_id,
                    "event_at": inv.event_at.isoformat() if inv.event_at else None,
                    "dismissed_actions": [a["tool_name"] for a in actions],
                },
                user=by,
                mutating=True,
            )
        except Exception as exc:
            await db.rollback()
            result.failed = item.id
            result.error = type(exc).__name__
            break
        inv.report = {**(inv.report if isinstance(inv.report, dict) else {}), _KEY: record}
        sequence = await _next_sequence(db, inv.id)
        events = [
            dismissal_event(
                sequence=sequence + n,
                kind="action_dismissed",
                index=a["index"],
                action_key=a["action_key"],
                tool_name=a["tool_name"],
                by=by,
                at=at,
                extra={"reason": text, "cleared": clear_id},
            )
            for n, a in enumerate(actions)
        ]
        try:
            # One commit: the record and the dismissals land together.
            await inv_svc.append_events(db, item.id, events)
        except Exception as exc:
            # The audit record came first. The trail must state that the
            # clear did not happen.
            await db.rollback()
            result.failed = item.id
            result.error = type(exc).__name__
            with contextlib.suppress(Exception):
                await audit.log_kind(
                    AUDIT_SESSION,
                    "needs_you_clear_failed",
                    {"investigation_id": item.id, "clear_id": clear_id, "error": result.error},
                    user=by,
                )
            break
        result.cleared.append(item)
        result.dismissed += len(events)
    return result


async def restore(db: AsyncSession, inv_id: str, *, by: str, audit: Any) -> RestoreResult:
    """Undo the clear of one investigation.

    The audit record ``needs_you_restored`` comes first and fails closed. A
    store write that then fails gets the record ``needs_you_restore_failed``.
    Then the clear record goes, and each dismissal of that clear gets its
    undo. A dismissal that a person made stays.
    """
    from soc_ai.api.webui._timeline import _dismissals  # noqa: PLC0415 - cycle
    from soc_ai.api.webui.routes_actions import dismissal_event  # noqa: PLC0415 - cycle

    inv = await db.get(Investigation, inv_id)
    report = inv.report if inv is not None and isinstance(inv.report, dict) else {}
    record = report.get(_KEY)
    if inv is None or not isinstance(record, dict):
        raise NotClearedError(inv_id)
    rows = (
        await db.scalars(
            select(InvestigationEvent).where(
                InvestigationEvent.investigation_id == inv.id,
                InvestigationEvent.kind.in_(("action_dismissed", "action_restored")),
            )
        )
    ).all()
    standing = _dismissals(list(rows))
    undo = [
        a
        for a in record.get("actions") or []
        if isinstance(a, dict)
        and (standing.get(str(a.get("action_key") or "")) or {}).get("cleared") == record.get("id")
    ]
    await audit.log_kind(
        AUDIT_SESSION,
        "needs_you_restored",
        {
            "investigation_id": inv.id,
            "verdict": inv.verdict,
            "user": by,
            "clear_id": record.get("id"),
            "restored_actions": [a.get("tool_name") for a in undo],
        },
        user=by,
        mutating=True,
    )
    verdict = inv.verdict
    inv.report = {k: v for k, v in report.items() if k != _KEY}
    sequence = await _next_sequence(db, inv_id)
    at = _now_iso()
    events = [
        dismissal_event(
            sequence=sequence + n,
            kind="action_restored",
            index=int(a.get("index") or 0),
            action_key=str(a.get("action_key") or ""),
            tool_name=str(a.get("tool_name") or ""),
            by=by,
            at=at,
            extra={"cleared": record.get("id")},
        )
        for n, a in enumerate(undo)
    ]
    try:
        await inv_svc.append_events(db, inv_id, events)
    except Exception as exc:
        # The audit record came first. The trail must state that the
        # restore did not happen.
        await db.rollback()
        with contextlib.suppress(Exception):
            await audit.log_kind(
                AUDIT_SESSION,
                "needs_you_restore_failed",
                {
                    "investigation_id": inv_id,
                    "clear_id": record.get("id"),
                    "error": type(exc).__name__,
                },
                user=by,
            )
        raise
    return RestoreResult(investigation_id=inv_id, verdict=verdict, restored_actions=len(undo))


def cleared_sentence(report: Any) -> str | None:
    """The line of the investigation page for a clear, or None with no clear."""
    record = report.get(_KEY) if isinstance(report, dict) else None
    if not isinstance(record, dict):
        return None
    day = str(record.get("at") or "")[:10] or "an unknown date"
    by = str(record.get("by") or "").strip() or "an unknown user"
    reason = str(record.get("reason") or "").strip().rstrip(".")
    return f"Cleared from Needs you on {day} by {by}: {reason}."
