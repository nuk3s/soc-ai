"""The one Security Onion case of a campaign: its record, its text and its comments.

"Open one case" on a campaign writes one Security Onion case. The record of
that press lives in ``campaign_changes``, because a rebuild deletes and writes
the member and party rows again:

* ``case_intent`` ``{intentId, by, title, alerts}``: committed before the
  first call to Security Onion. No intent, no call.
* ``case`` ``{caseId, alerts, by, intentId, url, link}``: the result. The
  campaign row then holds ``case_id`` and the decision ``case``.
* ``case_failed`` ``{reason, intentId, by}``: a press that is known to have
  opened no case, or an open intent that an analyst cleared with "Try again".
* ``case_comment`` ``{caseId, for, changeId}``: one comment that soc-ai added
  to the case for one ``stage`` or ``party`` change
  (:mod:`soc_ai.campaigns.case_comments`).

An intent with no ``case`` and no ``case_failed`` row of its id is a press
whose result soc-ai could not read. A case can exist, so a second press opens
none until an analyst presses "Try again".

:func:`state_of` reads the record. :func:`case_title` and
:func:`case_description` write the words from stored facts only. Code writes
every word. The model writes none.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns import decisions
from soc_ai.campaigns.words import stage_words
from soc_ai.secret_scrub import scrub_secrets
from soc_ai.store.models import Campaign, CampaignChange
from soc_ai.tools.escalate_to_case import fit_case_description, fit_case_title

_LOGGER = logging.getLogger(__name__)

# The most alerts that one campaign case attaches: the cap of the group
# escalate and of the finding case. Each attach also acknowledges the alert.
ATTACH_CAP = 25

# The change types of the case record.
CASE_TYPES = (
    decisions.CHANGE_CASE_INTENT,
    decisions.CHANGE_CASE,
    decisions.CHANGE_CASE_FAILED,
    decisions.CHANGE_CASE_COMMENT,
)


def session_id(campaign_id: int) -> str:
    """The session of the audit records and of the Security Onion writes of one campaign case."""
    return f"campaign-case:{campaign_id}"


STATE_OPEN = "open"
STATE_PENDING = "pending"
STATE_FAILED = "failed"

# The reason of an intent that an analyst cleared with "Try again".
CLEARED_REASON = "An analyst cleared the earlier press. Look in Security Onion before a new press."


@dataclass(frozen=True)
class CaseRecord:
    """The case that soc-ai opened for the campaign, from its ``case`` row."""

    case_id: str
    opened_at: datetime
    by: str
    alerts: int
    url: str | None
    link: str | None
    # A ``stage`` or ``party`` change with a higher id gets one comment. The
    # id of the intent of the press: a change after the text was written.
    anchor_id: int


@dataclass(frozen=True)
class CaseState:
    """What the record of one campaign says about its case."""

    # soc-ai's own case, whose id the campaign row holds. None for no case.
    record: CaseRecord | None = None
    # The intent of a press whose result soc-ai could not read.
    open_intent: CampaignChange | None = None
    # The newest settled press, when it failed after the newest case row.
    failed: CampaignChange | None = None
    # The ids of the changes that have a recorded comment on the case.
    commented: frozenset[int] = frozenset()

    @property
    def comments(self) -> int:
        return len(self.commented)


def _detail(change: CampaignChange) -> Mapping[str, Any]:
    return change.detail if isinstance(change.detail, dict) else {}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


async def _case_changes(db: AsyncSession, campaign_id: int) -> list[CampaignChange]:
    rows = await db.scalars(
        select(CampaignChange)
        .where(CampaignChange.campaign_id == campaign_id, CampaignChange.type.in_(CASE_TYPES))
        .order_by(CampaignChange.id)
    )
    return list(rows.all())


def state_from(case_id: str | None, changes: Sequence[CampaignChange]) -> CaseState:
    """The case state of a campaign whose row holds ``case_id``, from its case rows in id order."""
    settled = {
        intent
        for c in changes
        if c.type in (decisions.CHANGE_CASE, decisions.CHANGE_CASE_FAILED)
        and (intent := _text(_detail(c).get("intentId"))) is not None
    }
    intents = {
        intent: c
        for c in changes
        if c.type == decisions.CHANGE_CASE_INTENT
        and (intent := _text(_detail(c).get("intentId"))) is not None
    }
    open_intent = next(
        (
            c
            for c in reversed(changes)
            if c.type == decisions.CHANGE_CASE_INTENT
            and _text(_detail(c).get("intentId")) not in settled
        ),
        None,
    )
    record: CaseRecord | None = None
    if case_id:
        first = next(
            (
                c
                for c in changes
                if c.type == decisions.CHANGE_CASE and _detail(c).get("caseId") == case_id
            ),
            None,
        )
        if first is not None:
            detail = _detail(first)
            opened = intents.get(_text(detail.get("intentId")) or "")
            record = CaseRecord(
                case_id=case_id,
                opened_at=first.created_at,
                by=_text(detail.get("by")) or "",
                alerts=_int(detail.get("alerts")),
                url=_text(detail.get("url")),
                link=_text(detail.get("link")),
                anchor_id=opened.id if opened is not None else first.id,
            )
    results = [
        c for c in changes if c.type in (decisions.CHANGE_CASE, decisions.CHANGE_CASE_FAILED)
    ]
    failed = results[-1] if results and results[-1].type == decisions.CHANGE_CASE_FAILED else None
    commented = frozenset(
        _int(_detail(c).get("changeId"))
        for c in changes
        if c.type == decisions.CHANGE_CASE_COMMENT
        and record is not None
        and _detail(c).get("caseId") == record.case_id
    )
    return CaseState(record=record, open_intent=open_intent, failed=failed, commented=commented)


async def state_of(db: AsyncSession, row: Campaign) -> CaseState:
    """The case state of one campaign row, as the store holds it now."""
    return state_from(row.case_id, await _case_changes(db, row.id))


async def opened_at(db: AsyncSession, rows: Sequence[Campaign]) -> dict[int, datetime]:
    """The time of the press that opened the case of each row that holds a case id.

    The first ``case`` change whose case id the row holds. A row with no such
    change has no entry.
    """
    from soc_ai.campaigns.facts import chunked  # noqa: PLC0415 - light import

    wanted = {row.id: row.case_id for row in rows if row.case_id}
    out: dict[int, datetime] = {}
    for ids in chunked(sorted(wanted)):
        found = await db.scalars(
            select(CampaignChange)
            .where(
                CampaignChange.campaign_id.in_(ids),
                CampaignChange.type == decisions.CHANGE_CASE,
            )
            .order_by(CampaignChange.id)
        )
        for c in found.all():
            if c.campaign_id not in out and _detail(c).get("caseId") == wanted[c.campaign_id]:
                out[c.campaign_id] = c.created_at
    return out


def failure_of(change: CampaignChange) -> str:
    """The reason of a ``case_failed`` row, in words."""
    return _text(_detail(change).get("reason")) or "Security Onion opened no case."


# ── The words of the case ──────────────────────────────────────────────────


def case_title(title: str) -> str:
    """The title of the case: ``soc-ai campaign: {title}``, at most 100 bytes."""
    return fit_case_title(f"soc-ai campaign: {title}")


def stamp(at: datetime | None) -> str:
    """A stored time as the words of the case: ``2026-11-16 09:30 UTC``."""
    return f"{at:%Y-%m-%d %H:%M} UTC" if at is not None else "an unknown time"


@dataclass(frozen=True)
class StageLine:
    """One reached stage of the case text. ``by`` is true when ``at`` is the
    time of a later stage that needs this one: the stage held by that time."""

    stage: str
    at: datetime | None
    what: str
    by: bool = False


@dataclass(frozen=True)
class MachineLine:
    name: str
    role: str
    addresses: tuple[str, ...]


def case_description(
    *,
    campaign_id: int,
    bottom_line: str,
    stages: Sequence[StageLine],
    machines: Sequence[MachineLine],
    first_event: datetime,
    last_event: datetime,
    alerts: int,
    findings: int,
    note: str,
    link: str,
) -> str:
    """The description of the case, from the stored facts of the campaign.

    The bottom line, each reached stage with its time and what happened, the
    machines with role and address, the period, the counts of the alert
    investigations and the finding investigations, the note of the analyst,
    and the link to the campaign page.
    """
    lines = [scrub_secrets(bottom_line.strip()), ""]
    if stages:
        lines.append("Stages reached:")
        for step in stages:
            words = stage_words(step.stage) or step.stage
            what = scrub_secrets(step.what.strip())
            when = f"by {stamp(step.at)}" if step.by else stamp(step.at)
            lines.append(f"- {words}, {when}." + (f" {what}" if what else ""))
        lines.append("")
    if machines:
        lines.append("Machines:")
        for m in machines:
            address = f", {', '.join(m.addresses)}" if m.addresses else ""
            lines.append(f"- {m.name}: {m.role}{address}.")
        lines.append("")
    lines.append(f"Period: {stamp(first_event)} to {stamp(last_event)}.")
    lines.append(
        f"The campaign holds {_count(alerts, 'alert')} and {_count(findings, 'finding')} "
        "with a true positive verdict."
    )
    if note.strip():
        lines.append(f"Note of the analyst: {scrub_secrets(note.strip())}")
    lines.append(f"Campaign page: {link}")
    lines.append(f"Source: soc-ai campaign {campaign_id}.")
    return fit_case_description("\n".join(lines))


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


__all__ = [
    "ATTACH_CAP",
    "CASE_TYPES",
    "CLEARED_REASON",
    "STATE_FAILED",
    "STATE_OPEN",
    "STATE_PENDING",
    "CaseRecord",
    "CaseState",
    "MachineLine",
    "StageLine",
    "case_description",
    "case_title",
    "failure_of",
    "opened_at",
    "session_id",
    "stamp",
    "state_from",
    "state_of",
]
