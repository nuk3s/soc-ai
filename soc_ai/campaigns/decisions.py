"""The decision of the analyst on a campaign, and the changes of a campaign.

The analyst decides once on a campaign. Part A of phase 2 writes one
decision, ``closed``, with a reason. A rebuild deletes and writes the member
and party rows again and plans the ids again, so the decision lives on the
``campaigns`` row and each change lives in ``campaign_changes``.

A close covers only the past. The row stores what the decision covered in
``decision_basis``: the last event time, the stage and the machine keys of
the parties. :func:`reopen_cause` compares a rebuilt campaign with that
basis. A later last event, a higher stage or a machine that the decision did
not cover opens the campaign again: the rebuild clears the decision and
writes one ``reopened`` change with the cause. Each ``reopened`` change holds
the decision that it ended in ``was`` (:func:`was_of`).

This module holds the rules and the store reads of the changes. It reads no
grid. :mod:`soc_ai.campaigns.service` calls it inside a rebuild, and the
decision routes call it for a close and a reopen.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns.facts import chunked
from soc_ai.campaigns.types import STAGES, naive_utc
from soc_ai.store.models import Campaign, CampaignChange, CampaignParty

DECISION_CLOSED = "closed"
DECISION_AUTHORIZED = "authorized"
DECISION_CASE = "case"
DECISIONS = (DECISION_CLOSED, DECISION_AUTHORIZED, DECISION_CASE)

# The reasons of a close, and their words in the console.
REASONS: Mapping[str, str] = {
    "handled_outside": "Handled outside soc-ai",
    "accepted_risk": "Accepted risk",
    "test_over": "Test that is over",
}

CHANGE_FORMED = "formed"
CHANGE_STAGE = "stage"
CHANGE_PARTY = "party"
CHANGE_DECIDED = "decided"
CHANGE_REOPENED = "reopened"
CHANGE_ACKNOWLEDGED = "acknowledged"
# An investigation of an authorized campaign that the authorization does not
# cover: ``{runId, why}``. One change for each such investigation.
CHANGE_BEYOND = "beyond"
# An analyst took an investigation out of the campaign, or joined one to it:
# ``{runId, by}``.
CHANGE_EXCLUDED = "excluded"
CHANGE_INCLUDED = "included"
# The record of the one Security Onion case of a campaign
# (:mod:`soc_ai.campaigns.case`): the intent before the first call, the case,
# a press that opened no case, and one comment for one change.
CHANGE_CASE_INTENT = "case_intent"
CHANGE_CASE = "case"
CHANGE_CASE_FAILED = "case_failed"
CHANGE_CASE_COMMENT = "case_comment"
CHANGE_TYPES = (
    CHANGE_FORMED,
    CHANGE_STAGE,
    CHANGE_PARTY,
    CHANGE_DECIDED,
    CHANGE_REOPENED,
    CHANGE_ACKNOWLEDGED,
    CHANGE_BEYOND,
    CHANGE_EXCLUDED,
    CHANGE_INCLUDED,
    CHANGE_CASE_INTENT,
    CHANGE_CASE,
    CHANGE_CASE_FAILED,
    CHANGE_CASE_COMMENT,
)

CAUSE_ACTIVITY = "activity"
CAUSE_STAGE = "stage"
CAUSE_PARTY = "party"
CAUSE_ANALYST = "analyst"
# An analyst revoked the authorization of the campaign.
CAUSE_REVOKED = "revoked"

# The most changes that the campaign page reads, the newest first.
MAX_CHANGES = 50

# The status of an active campaign row (``soc_ai.campaigns.service``).
_ACTIVE = "active"


def stage_rank(stage: str | None) -> int:
    """The place of a stage in :data:`STAGES`, or -1 for no stage."""
    return STAGES.index(stage) if stage in STAGES else -1


def basis_of(last_event: datetime, stage: str | None, parties: Iterable[str]) -> dict[str, Any]:
    """What a decision covers: the last event, the stage and the machine keys of the parties."""
    return {
        "last_event": last_event.isoformat(),
        "stage": stage,
        "parties": sorted({str(key) for key in parties if key}),
    }


async def basis_for(db: AsyncSession, row: Campaign) -> dict[str, Any]:
    """The basis of a decision on a campaign as the store holds it now."""
    keys = (
        await db.scalars(
            select(CampaignParty.machine_key).where(CampaignParty.campaign_id == row.id)
        )
    ).all()
    return basis_of(row.last_event, row.stage, keys)


def reopen_cause(
    basis: Mapping[str, Any] | None,
    last_event: datetime,
    stage: str | None,
    parties: Iterable[str],
    *,
    decision: str | None = None,
) -> str | None:
    """Why a rebuilt campaign goes past the basis of its decision, or None.

    A higher stage first, then a machine that the basis does not hold, then
    a later last event. A basis that soc-ai cannot read covers nothing, so the
    campaign opens again: a decision never hides work by a store error.

    An ``authorized`` decision never opens again here. Its record decides each
    investigation on its own: new activity between the listed machines is
    inside, and each other investigation keeps normal handling and is no
    item of the campaign (:mod:`soc_ai.campaigns.authorization`).

    A ``case`` decision never opens again here either. The case in Security
    Onion holds the work: a higher stage and a new machine each add one
    comment to the case (:mod:`soc_ai.campaigns.case_comments`).
    """
    if decision in (DECISION_AUTHORIZED, DECISION_CASE):
        return None
    if not isinstance(basis, Mapping):
        return CAUSE_ACTIVITY
    covered_at = naive_utc(basis.get("last_event"))
    held = basis.get("parties")
    covered = {str(key) for key in held} if isinstance(held, list) else set()
    if stage_rank(stage) > stage_rank(_stage_or_none(basis.get("stage"))):
        return CAUSE_STAGE
    if {str(key) for key in parties if key} - covered:
        return CAUSE_PARTY
    if covered_at is None or last_event > covered_at:
        return CAUSE_ACTIVITY
    return None


def _stage_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value in STAGES else None


def clear_decision(row: Campaign) -> None:
    """Remove the decision of a campaign. The changes keep its record."""
    row.decision = None
    row.decided_at = None
    row.decided_by = None
    row.decision_note = None
    row.close_reason = None
    row.decision_basis = None


def was_of(row: Campaign, *, label: str | None = None) -> dict[str, Any]:
    """The decision that a reopen ends, as the ``was`` of its ``reopened`` change.

    Read it before :func:`clear_decision`. The rebuild, the route "Open
    again" and the revoke each write it, so the campaign page and Needs you
    can state the earlier decision and what is new since it
    (:mod:`soc_ai.campaigns.since_decision`). ``label`` is the label of the
    authorization of an ``authorized`` decision: the revoke has the record at
    hand, and the row holds no label.
    """
    basis = row.decision_basis
    was: dict[str, Any] = {
        "decision": row.decision,
        "reason": row.close_reason,
        "note": row.decision_note,
        "by": row.decided_by,
        "decidedAt": row.decided_at.isoformat() if row.decided_at is not None else None,
        "basis": dict(basis) if isinstance(basis, Mapping) else None,
    }
    if label:
        was["label"] = label
    return was


def reopen(row: Campaign, cause: str, now: datetime, **extra: Any) -> CampaignChange:
    """Clear the decision of a campaign and give its ``reopened`` change.

    The change holds the cause, the decision that it ended in ``was``, and
    ``extra`` (the analyst and the note of an "Open again"). The caller adds
    the change to the session and commits.
    """
    label = extra.pop("label", None)
    detail: dict[str, Any] = {"cause": cause, **extra, "was": was_of(row, label=label)}
    clear_decision(row)
    return change(row.id, CHANGE_REOPENED, detail, now)


def change(campaign_id: int, type_: str, detail: Mapping[str, Any], at: datetime) -> CampaignChange:
    """One change row. The caller adds it to the session."""
    return CampaignChange(campaign_id=campaign_id, type=type_, detail=dict(detail), created_at=at)


async def changes_of(
    db: AsyncSession, campaign_id: int, *, limit: int = MAX_CHANGES
) -> list[CampaignChange]:
    """The changes of one campaign, the newest first, at most ``limit``."""
    rows = await db.scalars(
        select(CampaignChange)
        .where(CampaignChange.campaign_id == campaign_id)
        .order_by(CampaignChange.created_at.desc(), CampaignChange.id.desc())
        .limit(limit)
    )
    return list(rows.all())


async def last_reopened(db: AsyncSession, campaign_ids: Sequence[int]) -> dict[int, datetime]:
    """The time of the newest ``reopened`` change of each campaign that has one."""
    out: dict[int, datetime] = {}
    for ids in chunked(sorted(set(campaign_ids))):
        rows = await db.execute(
            select(CampaignChange.campaign_id, func.max(CampaignChange.created_at))
            .where(
                CampaignChange.campaign_id.in_(ids),
                CampaignChange.type == CHANGE_REOPENED,
            )
            .group_by(CampaignChange.campaign_id)
        )
        out.update({int(cid): at for cid, at in rows.all() if at is not None})
    return out


def in_force(decision: str | None) -> bool:
    """True when a decision of the analyst is in force on a campaign.

    The one rule of "decision in force". An active campaign with a decision
    in force is no item of Needs you (:func:`waits_since` and the SQL of
    ``soc_ai.campaigns.service.waiting_count``). Each other page reads this
    rule too: the state of a campaign, the confirmed threats that wait and
    the parts of the true positives. A decision stays in force until a
    rebuild, an "Open again" or a revoke clears it.
    """
    return decision is not None


def waits_since(
    decision: str | None, first_event: datetime, reopened_at: datetime | None
) -> datetime | None:
    """Since when a campaign waits on a decision, or None when it holds one.

    The time of the last ``reopened`` change, else the first event.
    """
    if in_force(decision):
        return None
    return reopened_at or first_event


async def write_close(
    db: AsyncSession,
    campaign_id: int,
    *,
    reason: str,
    note: str,
    by: str,
    basis: Mapping[str, Any],
    now: datetime,
    acknowledge: bool = False,
) -> Campaign | None:
    """Close a campaign and add one ``decided`` change. The caller commits.

    The row is read as the store holds it now. None when the campaign is not
    active or holds a decision: a second close lost the race, and it writes
    nothing. The change states whether the close asked for the
    acknowledgement, so the console can offer the rest after a lost task.
    """
    row = await db.get(Campaign, campaign_id, populate_existing=True)
    if row is None or row.status != _ACTIVE or row.decision is not None:
        return None
    row.decision = DECISION_CLOSED
    row.close_reason = reason
    row.decision_note = note or None
    row.decided_by = by
    row.decided_at = now
    row.decision_basis = dict(basis)
    db.add(
        change(
            campaign_id,
            CHANGE_DECIDED,
            {"decision": DECISION_CLOSED, "reason": reason, "by": by, "acknowledge": acknowledge},
            now,
        )
    )
    return row


def write_authorize(
    db: AsyncSession,
    row: Campaign,
    *,
    authorization_id: int,
    label: str,
    by: str,
    basis: Mapping[str, Any],
    now: datetime,
) -> None:
    """Set the ``authorized`` decision of a campaign and add one ``decided`` change.

    The caller read the row, checked that it is active with no decision,
    and commits.
    """
    row.decision = DECISION_AUTHORIZED
    row.authorization_id = authorization_id
    row.close_reason = None
    row.decision_note = None
    row.decided_by = by
    row.decided_at = now
    row.decision_basis = dict(basis)
    db.add(
        change(
            row.id,
            CHANGE_DECIDED,
            {
                "decision": DECISION_AUTHORIZED,
                "authorizationId": authorization_id,
                "label": label,
                "by": by,
            },
            now,
        )
    )


def write_case(
    db: AsyncSession,
    row: Campaign,
    *,
    case_id: str,
    by: str,
    note: str,
    basis: Mapping[str, Any],
    detail: Mapping[str, Any],
    now: datetime,
) -> None:
    """Set the ``case`` decision of a campaign and add one ``case`` change.

    The row then holds the id of the case. The caller read the row, checked
    that it is active with no decision, and commits.
    """
    row.decision = DECISION_CASE
    row.case_id = case_id
    row.close_reason = None
    row.decision_note = note or None
    row.decided_by = by
    row.decided_at = now
    row.decision_basis = dict(basis)
    db.add(change(row.id, CHANGE_CASE, detail, now))


def write_revoked(
    db: AsyncSession, row: Campaign, *, by: str, now: datetime, label: str | None = None
) -> None:
    """Clear the decision of a campaign and add one ``reopened`` change with the cause ``revoked``.

    The campaign keeps ``authorization_id``, so its page names the revoked
    record. ``label`` is the label of the revoked record. The caller commits.
    """
    db.add(reopen(row, CAUSE_REVOKED, now, by=by, label=label))


def write_reopen(db: AsyncSession, row: Campaign, *, by: str, note: str, now: datetime) -> None:
    """Clear the decision of a campaign and add one ``reopened`` change. The caller commits."""
    extra: dict[str, Any] = {"by": by}
    if note:
        extra["note"] = note
    db.add(reopen(row, CAUSE_ANALYST, now, **extra))


@dataclass(frozen=True)
class DecisionView:
    """The decision of a campaign as the API states it."""

    type: str
    reason: str | None
    note: str | None
    by: str | None
    at: datetime | None


def decision_of(row: Campaign) -> DecisionView | None:
    """The decision that a campaign row holds, or None."""
    if row.decision is None:
        return None
    return DecisionView(
        type=row.decision,
        reason=row.close_reason,
        note=row.decision_note,
        by=row.decided_by,
        at=row.decided_at,
    )


__all__ = [
    "CAUSE_ACTIVITY",
    "CAUSE_ANALYST",
    "CAUSE_PARTY",
    "CAUSE_REVOKED",
    "CAUSE_STAGE",
    "CHANGE_ACKNOWLEDGED",
    "CHANGE_BEYOND",
    "CHANGE_CASE",
    "CHANGE_CASE_COMMENT",
    "CHANGE_CASE_FAILED",
    "CHANGE_CASE_INTENT",
    "CHANGE_DECIDED",
    "CHANGE_EXCLUDED",
    "CHANGE_FORMED",
    "CHANGE_INCLUDED",
    "CHANGE_PARTY",
    "CHANGE_REOPENED",
    "CHANGE_STAGE",
    "CHANGE_TYPES",
    "DECISIONS",
    "DECISION_AUTHORIZED",
    "DECISION_CASE",
    "DECISION_CLOSED",
    "MAX_CHANGES",
    "REASONS",
    "DecisionView",
    "basis_for",
    "basis_of",
    "change",
    "changes_of",
    "clear_decision",
    "decision_of",
    "in_force",
    "last_reopened",
    "reopen",
    "reopen_cause",
    "stage_rank",
    "waits_since",
    "was_of",
    "write_authorize",
    "write_case",
    "write_close",
    "write_reopen",
    "write_revoked",
]
