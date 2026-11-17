"""The comments of soc-ai on the case of a campaign (rule 5 of the campaign case).

After a case exists, a higher stage and a new machine each add ONE comment to
the case, with the stage or the machine, the time and the link. A new
investigation adds none. soc-ai comments only on a case whose id its own
``case`` row holds (:func:`soc_ai.campaigns.case.state_of`), and only for a
``stage`` or ``party`` change after the press.

:func:`after_rebuild` runs after the commit of a rebuild, outside its
transaction, and on each wake of the refresh loop. Each comment goes through
:func:`soc_ai.tools.write_exec.execute_write_tool` with its audit records.
One ``case_comment`` change then records it, so a change with a recorded
comment gets no second one. Best effort: a failed write leaves the change
for the next step, and a failure never undoes the rebuild.

The app binds its state at startup (:func:`bind_state`). A CLI process binds
none, so its rebuild adds no comment: the app adds it at its next step.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import weakref
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns import case as campaign_case
from soc_ai.campaigns import decisions
from soc_ai.campaigns.types import STAGES, naive_utc
from soc_ai.campaigns.words import stage_words
from soc_ai.secret_scrub import scrub_secrets
from soc_ai.store.models import Campaign, CampaignChange

_LOGGER = logging.getLogger(__name__)

# The changes that add one comment to the case, and the word of each.
COMMENT_FOR: Mapping[str, str] = {
    decisions.CHANGE_STAGE: "stage",
    decisions.CHANGE_PARTY: "party",
}

# The hand of a comment of the step.
SYSTEM_USER = "system:campaign"

# The app state of this process: ``auth``, ``settings`` and ``audit``. Read at
# each step, so the state that the app holds then is the one that writes.
_STATE: Any = None
# One lock for each running event loop: two steps never post the same comment.
_LOCKS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    weakref.WeakKeyDictionary()
)


def bind_state(state: Any) -> None:
    """Bind the app state that writes the comments, or unbind it with None."""
    global _STATE  # noqa: PLW0603 - one app for each process
    _STATE = state


def release_state(state: Any) -> None:
    """Unbind ``state`` when it is the bound one. The app calls it at shutdown."""
    global _STATE  # noqa: PLW0603 - one app for each process
    if _STATE is state:
        _STATE = None


def _lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _LOCKS.get(loop)
    if lock is None:
        lock = _LOCKS[loop] = asyncio.Lock()
    return lock


def _detail(change: CampaignChange) -> Mapping[str, Any]:
    return change.detail if isinstance(change.detail, dict) else {}


def stage_time(detail: Mapping[str, Any], stage: str | None) -> datetime | None:
    """The first time of a stage on the stored ladder of a campaign, or None."""
    ladder = detail.get("ladder")
    for step in ladder if isinstance(ladder, list) else []:
        if isinstance(step, dict) and stage in STAGES and step.get("stage") == stage:
            return naive_utc(step.get("first_at"))
    return None


def comment_text(
    change: CampaignChange, *, title: str, link: str | None, stage_at: datetime | None
) -> str:
    """The comment of one change: the stage or the machine, the time and the link."""
    detail = _detail(change)
    if change.type == decisions.CHANGE_STAGE:
        to = detail.get("to")
        words = stage_words(to if isinstance(to, str) else None) or "a higher stage"
        at = campaign_case.stamp(stage_at or change.created_at)
        head = f"The campaign {title} reached the stage {words} at {at}."
    else:
        raw = detail.get("names")
        names = [str(n) for n in raw if n] if isinstance(raw, list) else []
        noun = "machine" if len(names) <= 1 else "machines"
        named = ", ".join(names) if names else "a new machine"
        at = campaign_case.stamp(change.created_at)
        head = f"A new {noun} joined the campaign {title} at {at}: {named}."
    tail = f" Campaign page: {link}" if link else ""
    return scrub_secrets(f"{head}{tail}")


@dataclass(frozen=True)
class _Due:
    campaign_id: int
    case_id: str
    change_id: int
    kind: str
    text: str


async def due(db: AsyncSession) -> list[_Due]:
    """The changes that wait on a comment: a higher stage or a new machine after the press."""
    rows = (
        await db.scalars(
            select(Campaign).where(
                Campaign.status == "active",
                Campaign.case_id.is_not(None),
            )
        )
    ).all()
    out: list[_Due] = []
    for row in rows:
        state = await campaign_case.state_of(db, row)
        record = state.record
        if record is None:
            continue
        changes = (
            await db.scalars(
                select(CampaignChange)
                .where(
                    CampaignChange.campaign_id == row.id,
                    CampaignChange.type.in_(tuple(COMMENT_FOR)),
                    CampaignChange.id > record.anchor_id,
                )
                .order_by(CampaignChange.id)
            )
        ).all()
        detail = row.detail if isinstance(row.detail, dict) else {}
        for change in changes:
            if change.id in state.commented:
                continue
            to = _detail(change).get("to")
            out.append(
                _Due(
                    campaign_id=row.id,
                    case_id=record.case_id,
                    change_id=change.id,
                    kind=COMMENT_FOR[change.type],
                    text=comment_text(
                        change,
                        title=row.title,
                        link=record.link,
                        stage_at=stage_time(detail, to if isinstance(to, str) else None),
                    ),
                )
            )
    return out


async def after_rebuild(db: AsyncSession, *, state: Any = None) -> int:
    """Add the comments that wait. Never raises. Returns the count of comments added.

    ``state`` is the app state that writes, else the bound one. With no
    Security Onion client the step writes nothing.
    """
    held = state if state is not None else _STATE
    if held is None or getattr(held, "auth", None) is None:
        return 0
    added = 0
    try:
        async with _lock():
            waiting = await due(db)
            # End the read snapshot: no transaction spans a Security Onion call.
            await db.rollback()
            for item in waiting:
                if await _comment(db, held, item):
                    added += 1
    except Exception:
        _LOGGER.warning(
            "campaigns: the comment step after a rebuild failed. The next step tries again.",
            exc_info=True,
        )
        with contextlib.suppress(Exception):
            await db.rollback()
    return added


async def _recorded(db: AsyncSession, item: _Due) -> bool:
    """True when the store records a comment for the change already."""
    rows = await db.scalars(
        select(CampaignChange).where(
            CampaignChange.campaign_id == item.campaign_id,
            CampaignChange.type == decisions.CHANGE_CASE_COMMENT,
        )
    )
    found = any(
        _detail(c).get("changeId") == item.change_id and _detail(c).get("caseId") == item.case_id
        for c in rows.all()
    )
    await db.rollback()
    return found


async def _comment(db: AsyncSession, state: Any, item: _Due) -> bool:
    from soc_ai.tools.write_exec import execute_write_tool  # noqa: PLC0415 - tool registry

    if await _recorded(db, item):
        return False
    audit = getattr(state, "audit", None)
    _result, error = await execute_write_tool(
        "add_case_comment",
        {"case_id": item.case_id, "comment": item.text},
        auth=state.auth,
        settings=state.settings,
        audit=audit,
        session_id=campaign_case.session_id(item.campaign_id),
        user=SYSTEM_USER,
    )
    if error is not None:
        _LOGGER.warning(
            "campaigns: Security Onion did not take the comment on case %s: %s",
            item.case_id,
            error,
        )
        return False
    from soc_ai.store.auth import utcnow  # noqa: PLC0415 - light import

    db.add(
        decisions.change(
            item.campaign_id,
            decisions.CHANGE_CASE_COMMENT,
            {"caseId": item.case_id, "for": item.kind, "changeId": item.change_id},
            utcnow(),
        )
    )
    await db.commit()
    if audit is not None:
        try:
            await audit.log_kind(
                campaign_case.session_id(item.campaign_id),
                "campaign_case_commented",
                {
                    "campaign_id": item.campaign_id,
                    "case_id": item.case_id,
                    "for": item.kind,
                    "change_id": item.change_id,
                },
                user=SYSTEM_USER,
            )
        except Exception:
            _LOGGER.warning("campaign_case_commented audit write failed (continuing)")
    return True


__all__ = [
    "COMMENT_FOR",
    "SYSTEM_USER",
    "after_rebuild",
    "bind_state",
    "comment_text",
    "due",
    "release_state",
    "stage_time",
]
