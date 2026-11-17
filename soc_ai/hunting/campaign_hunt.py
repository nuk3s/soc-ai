"""The hunts of a campaign: the limit of one hunt in 24 hours, and the campaign hunt.

The campaign is the unit of work. One test caused 20 hunts beside its
campaign (2026-11-16), and the findings of each hunt became members, which
wrote changes, which started the next hunt.

D1. One hunt for one campaign in 24 hours, from any starter. The limit is
read from the hunt rows: ``hunts.campaign_id``, any status. It then holds
after a restart, a merge and a CLI rebuild. A hunt of a campaign that a merge
took counts for the campaign that took it. :func:`refusal` states the rule.

The lead loop asks it for a lead of a campaign
(:mod:`soc_ai.hunting.lead_hunt`), and the campaign hunt loop asks it for
each change. Both hold :func:`campaign_lock` from the check to the hunt row,
so the two loops of one process cannot both start a hunt for one campaign.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from weakref import WeakValueDictionary

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns.types import STAGES
from soc_ai.store.models import (
    AuthorizedActivity,
    Campaign,
    CampaignChange,
    CampaignMember,
    CampaignParty,
    Hunt,
)

_LOGGER = logging.getLogger(__name__)

# D1: the window of the limit.
CAMPAIGN_HUNT_WINDOW = timedelta(hours=24)

# Why soc-ai starts no hunt for a campaign now. The words are the log words.
REFUSED_HUNTED = "campaign_hunted"
REFUSED_DECIDED = "campaign_decided"
REFUSED_INACTIVE = "campaign_inactive"

# The decisions of the analyst (soc_ai.campaigns.decisions holds the same
# words). After a close, and while an authorization is in force, soc-ai
# starts no hunt for the activity that the analyst decided on (D3).
_CLOSED = "closed"
_AUTHORIZED = "authorized"
_ACTIVE = "active"
_MERGED = "merged"
_MERGE_HOPS = 8

# The changes that start a campaign hunt (D3), as stored in
# ``campaign_changes.type`` (soc_ai.campaigns.decisions). A higher stage, a
# new machine, a reopen by new activity, and activity beyond an
# authorization. A reopen by the analyst or by a revoke is the analyst's.
CHANGE_STAGE = "stage"
CHANGE_PARTY = "party"
CHANGE_REOPENED = "reopened"
CHANGE_BEYOND = "beyond"
TRIGGERS: tuple[str, ...] = (CHANGE_STAGE, CHANGE_PARTY, CHANGE_REOPENED, CHANGE_BEYOND)
_ANALYST_CAUSES: frozenset[str] = frozenset({"analyst", "revoked"})
# A decision of the analyst stops a hunt for these changes only. Activity
# beyond an authorization is no activity that the analyst decided on.
_DECIDED_TYPES: frozenset[str] = frozenset({CHANGE_STAGE, CHANGE_PARTY})

# The oldest change that the loop reads. A change from before the upgrade, or
# from a week with the loop off, starts no hunt: the change stays on the
# campaign page, and the campaign waits on the analyst.
CHANGE_HORIZON = timedelta(hours=24)

# The hand the loop signs its hunts with.
CAMPAIGN_HUNT_ACTOR = "campaign-hunt"
KIND = "campaign"
STARTER = "campaign"

# The statuses of a hunt that has not ended (soc_ai.store.leads).
_RUNNING: tuple[str, ...] = ("running", "queued", "investigating")

# One lock for each campaign, held from the check to the hunt row. A
# WeakValueDictionary drops the lock once no start holds it.
_LOCKS: WeakValueDictionary[int, asyncio.Lock] = WeakValueDictionary()


def campaign_lock(campaign_id: int) -> asyncio.Lock:
    """The lock that two starts of a hunt for one campaign share."""
    lock = _LOCKS.get(int(campaign_id))
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS[int(campaign_id)] = lock
    return lock


async def family(db: AsyncSession, campaign_id: int) -> set[int]:
    """The campaign and each campaign that a merge put into it."""
    out = {int(campaign_id)}
    edge = {int(campaign_id)}
    for _hop in range(_MERGE_HOPS):
        rows = await db.scalars(select(Campaign.id).where(Campaign.merged_into_id.in_(edge)))
        edge = {int(r) for r in rows.all()} - out
        if not edge:
            break
        out |= edge
    return out


async def last_hunt_at(db: AsyncSession, campaign_id: int) -> datetime | None:
    """The time of the newest hunt for the campaign, of any status and any starter."""
    ids = await family(db, campaign_id)
    last: datetime | None = await db.scalar(
        select(Hunt.created_at)
        .where(Hunt.campaign_id.in_(sorted(ids)), Hunt.is_synth_eval.is_(False))
        .order_by(Hunt.created_at.desc())
        .limit(1)
    )
    return last


async def hunted_within(
    db: AsyncSession,
    campaign_id: int,
    *,
    now: datetime,
    window: timedelta = CAMPAIGN_HUNT_WINDOW,
) -> bool:
    """D1: whether a hunt for the campaign started in the last ``window``."""
    last = await last_hunt_at(db, campaign_id)
    return last is not None and last >= now - window


async def decided(db: AsyncSession, row: Campaign, *, now: datetime) -> bool:
    """Whether the campaign holds a close, or an authorization that is in force."""
    if row.decision == _CLOSED:
        return True
    if row.decision != _AUTHORIZED or row.authorization_id is None:
        return False
    record = await db.get(AuthorizedActivity, int(row.authorization_id))
    if record is None or record.revoked_at is not None:
        return False
    expires = record.expires_at.replace(tzinfo=None) if record.expires_at else None
    return expires is None or expires > now


async def refusal(
    db: AsyncSession, campaign_id: int, *, now: datetime, change: str | None = None
) -> str | None:
    """Why soc-ai starts no hunt for the campaign now, or None.

    A campaign that is not active starts none. A campaign that holds the
    decision ``closed`` or an authorization in force starts none for a lead
    or for a change of stage or of machines: the analyst decided on that
    activity. A ``beyond`` change is activity beyond the authorization, so
    the decision does not stop it. A campaign with a hunt in the last 24
    hours starts none (D1).
    """
    row = await db.get(Campaign, int(campaign_id), populate_existing=True)
    if row is None or row.status != _ACTIVE:
        return REFUSED_INACTIVE
    if (change is None or change in _DECIDED_TYPES) and await decided(db, row, now=now):
        return REFUSED_DECIDED
    if await hunted_within(db, int(campaign_id), now=now):
        return REFUSED_HUNTED
    return None


# ── The campaign hunt (D3) ─────────────────────────────────────────────────


def _naive_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


@dataclass(frozen=True)
class DueChange:
    """The newest change of one campaign that no hunt answered."""

    campaign_id: int
    change_id: int
    type: str
    at: datetime


def _starts_a_hunt(change: CampaignChange) -> bool:
    if change.type not in TRIGGERS:
        return False
    if change.type != CHANGE_REOPENED:
        return True
    detail = change.detail if isinstance(change.detail, dict) else {}
    return str(detail.get("cause") or "") not in _ANALYST_CAUSES


async def _active_of(db: AsyncSession, campaign_id: int) -> int | None:
    """The active campaign that a campaign id names, through its merges."""
    current: int | None = int(campaign_id)
    for _hop in range(_MERGE_HOPS):
        if current is None:
            return None
        row = await db.get(Campaign, current)
        if row is None:
            return None
        if row.status == _ACTIVE:
            return int(row.id)
        if row.status != _MERGED:
            return None
        current = row.merged_into_id
    return None


async def due_changes(db: AsyncSession, *, now: datetime) -> list[DueChange]:
    """The campaigns with a change that starts a hunt and that no hunt answered, oldest first.

    A hunt answers a change when it started at most 24 hours before the
    change, or after it. A change inside the window of a hunt is then covered
    by that hunt, and it starts no second hunt when the window ends: two
    changes in one hour start one hunt. The findings of a campaign hunt write
    changes too, so this rule also ends the loop of a hunt that starts the
    next hunt. The rows are the record, so the rule holds after a restart.
    """
    rows = await db.scalars(
        select(CampaignChange)
        .where(
            CampaignChange.created_at >= now - CHANGE_HORIZON,
            CampaignChange.type.in_(TRIGGERS),
        )
        .order_by(CampaignChange.created_at, CampaignChange.id)
    )
    newest: dict[int, CampaignChange] = {}
    for change in rows.all():
        if not _starts_a_hunt(change):
            continue
        target = await _active_of(db, int(change.campaign_id))
        if target is not None:
            newest[target] = change
    out: list[DueChange] = []
    for campaign_id, change in newest.items():
        last = await last_hunt_at(db, campaign_id)
        if last is not None and last >= change.created_at - CAMPAIGN_HUNT_WINDOW:
            continue
        out.append(DueChange(campaign_id, int(change.id), str(change.type), change.created_at))
    return sorted(out, key=lambda d: (d.at, d.campaign_id))


_ROLE_WORDS: dict[str, str] = {"actor": "actor", "target": "target"}
_TITLE_CHARS_MAX = 255
_ADDRESS_CHARS_MAX = 64
_ADDRESSES_MAX = 4
_MACHINES_MAX = 12


def _at(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if isinstance(value, datetime) else "unknown"


async def objective_for(db: AsyncSession, campaign_id: int) -> str | None:
    """The objective of a campaign hunt, written by code from stored facts only.

    The title, the machines with role and address, each reached stage with
    its times, the period, and the stage questions. The title and the
    addresses come from the grid, from DHCP, from DNS and from agents, so
    each passes the quoting of the other hunt blocks
    (:func:`soc_ai.hunting.earlier._quoted`) inside the untrusted markers. No
    rule name, no summary and no other text of the model goes in. The head
    line names the campaign by its id only. None for a campaign that is not
    active.
    """
    from soc_ai.campaigns.words import stage_words  # noqa: PLC0415 - lazy
    from soc_ai.detection.untrusted import UNTRUSTED_BEGIN, UNTRUSTED_END  # noqa: PLC0415
    from soc_ai.hunting.earlier import _quoted  # noqa: PLC0415 - the quoting of every block

    row = await db.get(Campaign, int(campaign_id))
    if row is None or row.status != _ACTIVE:
        return None
    parties = (
        await db.scalars(
            select(CampaignParty)
            .where(CampaignParty.campaign_id == row.id)
            .order_by(CampaignParty.role, CampaignParty.first_event, CampaignParty.id)
        )
    ).all()
    stages = (
        await db.execute(
            select(
                CampaignMember.stage,
                func.min(CampaignMember.event_time),
                func.max(CampaignMember.event_time),
            )
            .where(
                CampaignMember.campaign_id == row.id,
                CampaignMember.verdict_differs.is_(False),
                CampaignMember.stage.is_not(None),
            )
            .group_by(CampaignMember.stage)
        )
    ).all()
    facts = [
        f"- Title: {_quoted(row.title, _TITLE_CHARS_MAX)}",
        f"- Period: first event {_at(row.first_event)}, last event {_at(row.last_event)}",
    ]
    for party in list(parties)[:_MACHINES_MAX]:
        role = _ROLE_WORDS.get(str(party.role), "machine")
        if party.beyond:
            role = "machine that a target reached"
        addresses = [a for a in (party.addresses or []) if a][:_ADDRESSES_MAX]
        where = (
            ", addresses " + ", ".join(_quoted(a, _ADDRESS_CHARS_MAX) for a in addresses)
            if addresses
            else ", no address recorded"
        )
        facts.append(f"- Machine: {role}{where}")
    if len(parties) > _MACHINES_MAX:
        facts.append(f"- {len(parties) - _MACHINES_MAX} more machines")
    ranked = sorted(
        ((str(stage), first, last) for stage, first, last in stages if stage_words(stage)),
        key=lambda s: STAGES.index(s[0]) if s[0] in STAGES else 99,
    )
    for stage, first, last in ranked:
        facts.append(
            f"- Stage reached: {stage_words(stage)}, first event {_at(first)}, "
            f"last event {_at(last)}"
        )
    if not ranked:
        facts.append("- Stage reached: none is proven")
    return "\n".join(
        [
            f"[campaign {row.id}] Hunt for new activity of campaign {row.id}.",
            f"Records of soc-ai for campaign {row.id}:",
            UNTRUSTED_BEGIN,
            *facts,
            UNTRUSTED_END,
            "",
            "Answer each question from the grid. Cite the documents.",
            "1. Did the action on the target work?",
            "2. What ran on the target after it?",
            "3. Did the target reach a third machine?",
            f"4. Is there activity after the last event, {_at(row.last_event)}?",
            "Name what you could not check.",
        ]
    )


async def running_campaign_hunts(db: AsyncSession) -> int:
    """How many hunts the campaign loop has in flight."""
    return int(
        await db.scalar(
            select(func.count(Hunt.id)).where(
                Hunt.starter == STARTER,
                Hunt.started_by == CAMPAIGN_HUNT_ACTOR,
                Hunt.status.in_(_RUNNING),
            )
        )
        or 0
    )


async def start_due(state: Any, *, cap: int, now: datetime | None = None) -> list[str]:
    """Start one hunt for each campaign with a due change, up to ``cap`` in flight. The ids.

    Each start holds the lock of its campaign from the check to the hunt row,
    and asks :func:`refusal` again under it. The hunt runs inside the shared
    limit of concurrent hunts of the console: a full console starts nothing,
    and the next wake tries again. The changes stay unanswered until then.
    """
    from soc_ai.webui import hunt_console_manager as hcm  # noqa: PLC0415 - lazy

    at = now or _naive_now()
    async with state.db_sessionmaker() as db:
        running = await running_campaign_hunts(db)
        due = await due_changes(db, now=at) if running < cap else []
    started: list[str] = []
    for item in due:
        if running + len(started) >= cap:
            break
        async with campaign_lock(item.campaign_id):
            async with state.db_sessionmaker() as db:
                why = await refusal(db, item.campaign_id, now=at, change=item.type)
                objective = None if why else await objective_for(db, item.campaign_id)
            if why is not None or objective is None:
                _LOGGER.info(
                    "campaign hunt: campaign %s starts no hunt for its %s change (%s)",
                    item.campaign_id,
                    item.type,
                    why or REFUSED_INACTIVE,
                )
                continue
            hunt_id = await hcm.get_manager(state).start(
                state,
                objective=objective,
                started_by=CAMPAIGN_HUNT_ACTOR,
                kind=KIND,
                starter=STARTER,
                campaign_id=item.campaign_id,
            )
        if hunt_id is None:
            _LOGGER.info("campaign hunt: the console is full. The next wake tries again.")
            break
        started.append(str(hunt_id))
        _LOGGER.info(
            "campaign hunt: campaign %s started hunt %s for its %s change",
            item.campaign_id,
            hunt_id,
            item.type,
        )
    return started


__all__ = [
    "CAMPAIGN_HUNT_ACTOR",
    "CAMPAIGN_HUNT_WINDOW",
    "CHANGE_HORIZON",
    "KIND",
    "REFUSED_DECIDED",
    "REFUSED_HUNTED",
    "REFUSED_INACTIVE",
    "STARTER",
    "TRIGGERS",
    "DueChange",
    "campaign_lock",
    "decided",
    "due_changes",
    "family",
    "hunted_within",
    "last_hunt_at",
    "objective_for",
    "refusal",
    "running_campaign_hunts",
    "start_due",
]
