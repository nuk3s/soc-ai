"""What a hunt found for each campaign and each lead that it read (LH2).

Production, 2026-11-16: the scheduled hunt of 18:41 UTC read campaign 2 and
lead 73 and found no new event. Neither page showed it, so a decision made
once came back as open work.

When a hunt ends complete and not degraded, soc-ai records one answer for
each campaign whose block the hunt read (``campaign_ids`` of its
``hunt_started`` record) and for each open lead that it read
(``earlier_refs.leads``). The answer of one hunt for one subject is written
once (migration 0074). The outcome comes from stored facts, never from model
text:

- ``new_activity``: a threat finding of the hunt that no campaign holds as a
  repeat names a machine of the subject.
- ``continues``: a campaign only. A finding of the hunt is held as a repeat
  of the campaign (:data:`soc_ai.store.hunts.LINK_CAMPAIGN`).
- ``no_new_event``: anything else.

A threat finding that a campaign holds is known activity, so it is no new
activity of a lead either. ``new_activity`` outranks ``continues``.

An evaluation hunt, a catalog run and a backtest replay write no answer. A
lead hunt writes no answer for its own lead: the settle rule of the lead
answers for it (:func:`soc_ai.store.leads.settle_after_hunt`).

A hunt writes its answers when it ends (:func:`after_end`). The start step
fills the answers of the hunts of the last :data:`FILL_DAYS` days that have
none (:func:`fill`), so a hunt that ended before this release, or while the
process stopped, also answers.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import exists, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai.hunting.findings import (
    finding_category,
    finding_entities,
    is_run_failure_finding,
    severity_rank,
)
from soc_ai.hunting.outcome import degraded_reason
from soc_ai.store.hunts import LINK_CAMPAIGN, STATUS_COMPLETE, FindingLink, finding_links
from soc_ai.store.models import Campaign, CampaignParty, Hunt, HuntAnswer, HuntEvent, Lead

__all__ = [
    "ANSWERS_MAX",
    "CONTINUES",
    "FILL_DAYS",
    "NEW_ACTIVITY",
    "NO_NEW_EVENT",
    "SUBJECT_CAMPAIGN",
    "SUBJECT_LEAD",
    "AnswerView",
    "Subjects",
    "after_end",
    "answerable",
    "answers_of",
    "decide",
    "fill",
    "record",
    "subjects_of",
]

_LOGGER = logging.getLogger(__name__)

SUBJECT_CAMPAIGN = "campaign"
SUBJECT_LEAD = "lead"
NEW_ACTIVITY = "new_activity"
CONTINUES = "continues"
NO_NEW_EVENT = "no_new_event"
# How far back the start step fills the answers of stored hunts.
FILL_DAYS = 30
# The most answers that one page reads.
ANSWERS_MAX = 20

_BACKTEST_ACTOR = "backtest"
# A catalog run calls no model and reads no campaign block.
_CATALOG_KIND = "triggered"
_OPEN_LEAD = ("open", "hunting")
_HOST_KINDS = frozenset({"host", "address"})
_MERGED = "merged"
_MERGE_HOPS = 8


@dataclass(frozen=True)
class Subjects:
    """The campaigns and the leads that one hunt read."""

    campaigns: tuple[int, ...] = ()
    leads: tuple[int, ...] = ()


@dataclass(frozen=True)
class AnswerView:
    """One stored answer, with the hunt that gave it, as a page reads it."""

    hunt_id: str
    subject_type: str
    subject_id: int
    outcome: str
    finding_ordinal: int | None
    finding_title: str | None
    hunt_at: datetime | None
    starter: str
    answered_at: datetime


def _ints(values: Any) -> tuple[int, ...]:
    """The positive ids among ``values``: an int, or a string of digits."""
    out: list[int] = []
    for value in values if isinstance(values, list) else []:
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            number = value
        elif isinstance(value, str) and value.strip().isdigit():
            number = int(value.strip())
        else:
            continue
        if number > 0 and number not in out:
            out.append(number)
    return tuple(out)


def subjects_of(payload: Any) -> Subjects:
    """The subjects of one ``hunt_started`` payload. Pure. Another shape gives none."""
    if not isinstance(payload, Mapping):
        return Subjects()
    refs = payload.get("earlier_refs")
    leads = refs.get("leads") if isinstance(refs, Mapping) else None
    return Subjects(campaigns=_ints(payload.get("campaign_ids")), leads=_ints(leads))


def answerable(hunt: Hunt, done: Any) -> bool:
    """Whether the hunt gives answers: it ended complete, read real data and is not degraded.

    ``done`` is the payload of its ``done`` event, or None. A partial or a
    degraded run, and a run whose findings are all failed queries, read too
    little to state that nothing is new (the rule of
    :func:`soc_ai.store.hunts.earlier_runs`).
    """
    if hunt.status != STATUS_COMPLETE or hunt.is_synth_eval:
        return False
    if hunt.kind == _CATALOG_KIND or (hunt.started_by or "") == _BACKTEST_ACTOR:
        return False
    if isinstance(done, Mapping) and (done.get("partial") or done.get("degraded")):
        return False
    report = hunt.report if isinstance(hunt.report, dict) else {}
    if degraded_reason(report) is not None:
        return False
    raw = report.get("findings")
    findings = [f for f in raw if isinstance(f, dict)] if isinstance(raw, list) else []
    return not (findings and all(is_run_failure_finding(f) for f in findings))


def _fold(value: Any) -> str:
    return str(value or "").strip().rstrip(".").casefold()


def finding_hosts(finding: Mapping[str, Any]) -> list[str]:
    """The hosts and the addresses that a finding names, folded."""
    return [_fold(v) for kind, v in finding_entities(finding) if kind in _HOST_KINDS and _fold(v)]


def decide(
    findings: Sequence[Any],
    links: Mapping[int, FindingLink],
    names_machine: Callable[[Mapping[str, Any]], bool],
    *,
    family: Collection[int] | None,
) -> tuple[str, int | None]:
    """The outcome for one subject, and the ordinal of the finding behind it. Pure.

    ``family`` holds the ids of a campaign subject and of the campaigns that
    a merge put into it. It is None for a lead. ``names_machine`` tells
    whether a finding names a machine of the subject. A new activity is the
    finding with the highest severity, then the first in the report.
    """
    repeat: int | None = None
    new: list[tuple[int, int]] = []
    for ordinal, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            continue
        if finding_category(finding) != "threat" or is_run_failure_finding(finding):
            continue
        link = links.get(ordinal)
        if link is not None and link.state == LINK_CAMPAIGN:
            if family is not None and link.campaign_id in family and repeat is None:
                repeat = ordinal
            continue
        if names_machine(finding):
            new.append((-severity_rank(finding.get("severity")), ordinal))
    if new:
        return NEW_ACTIVITY, min(new)[1]
    if repeat is not None:
        return CONTINUES, repeat
    return NO_NEW_EVENT, None


# ── the reads of one hunt ───────────────────────────────────────────────────


async def _payload(db: AsyncSession, hunt_id: str, kind: str) -> Any:
    rows = await db.scalars(
        select(HuntEvent.payload)
        .where(HuntEvent.hunt_id == hunt_id, HuntEvent.kind == kind)
        .order_by(HuntEvent.id)
        .limit(1)
    )
    return rows.first()


async def _family(db: AsyncSession, campaign_id: int) -> set[int]:
    from soc_ai.hunting import campaign_hunt  # noqa: PLC0415 - the hunting package reads this

    return await campaign_hunt.family(db, campaign_id)


async def _active_of(db: AsyncSession, campaign_id: int) -> int:
    """The campaign that holds the machines of ``campaign_id``.

    The campaign itself, or the campaign that a merge took it into.
    """
    current = int(campaign_id)
    for _hop in range(_MERGE_HOPS):
        row = await db.get(Campaign, current)
        if row is None or row.status != _MERGED or row.merged_into_id is None:
            return current
        current = int(row.merged_into_id)
    return current


async def _campaign_machines(db: AsyncSession, campaign_id: int) -> tuple[set[str], set[str]]:
    """The folded names and addresses, and the machine keys, of the machines of a campaign."""
    target = await _active_of(db, campaign_id)
    rows = await db.execute(
        select(CampaignParty.machine_key, CampaignParty.name, CampaignParty.addresses).where(
            CampaignParty.campaign_id == target
        )
    )
    values: set[str] = set()
    keys: set[str] = set()
    for key, name, addresses in rows.all():
        keys.add(str(key))
        values.update(_fold(v) for v in [key, name, *(addresses or [])] if _fold(v))
    return values, keys


async def _machine_key(db: AsyncSession, value: str, cache: dict[str, str | None]) -> str | None:
    """The machine key of one host value from the Hosts data, or None. Never raises."""
    from soc_ai.store import host_machines  # noqa: PLC0415 - keeps the import graph light

    if value in cache:
        return cache[value]
    key: str | None = None
    try:
        membership = await host_machines.resolve_membership(db, value)
        key = str(membership.key) if membership is not None else None
    except Exception:
        _LOGGER.warning("hunt answers: the machine of a host did not load", exc_info=True)
    cache[value] = key
    return key


async def _names(
    db: AsyncSession,
    findings: Sequence[Any],
    values: set[str],
    keys: set[str],
    cache: dict[str, str | None],
) -> Callable[[Mapping[str, Any]], bool]:
    """The test of :func:`decide`: a finding names one of ``values`` or of the machine ``keys``."""
    named: set[int] = set()
    for finding in findings:
        # Only a threat finding can give new activity (:func:`decide`).
        if not isinstance(finding, Mapping) or finding_category(finding) != "threat":
            continue
        for host in finding_hosts(finding):
            key = await _machine_key(db, host, cache)
            if host in values or (key is not None and key in keys):
                named.add(id(finding))
                break
    return lambda finding: id(finding) in named


async def _lead_read_open(db: AsyncSession, lead_id: int, hunt: Hunt) -> Lead | None:
    """The lead, when the hunt read it open: open now, or closed after the hunt started."""
    lead = await db.get(Lead, lead_id)
    if lead is None or (hunt.lead_id is not None and int(hunt.lead_id) == lead_id):
        return None
    if lead.status in _OPEN_LEAD:
        return lead
    closed_at = lead.dismissed_at or lead.updated_at
    if closed_at is not None and hunt.created_at is not None and closed_at >= hunt.created_at:
        return lead
    return None


async def _lead_machines(
    db: AsyncSession, lead: Lead, cache: dict[str, str | None]
) -> tuple[set[str], set[str]]:
    values: set[str] = set()
    keys: set[str] = set()
    for entity in lead.entities_json or []:
        if not isinstance(entity, list | tuple) or len(entity) != 2 or entity[0] != "host":
            continue
        value = _fold(entity[1])
        if not value:
            continue
        values.add(value)
        key = await _machine_key(db, value, cache)
        if key is not None:
            keys.add(key)
    return values, keys


# ── the writes ──────────────────────────────────────────────────────────────


async def record(db: AsyncSession, hunt_id: str, *, now: datetime) -> int:
    """Write the answers of one hunt that ended. The count of new rows.

    Written once: a subject that holds an answer of this hunt keeps it. A
    hunt that gives no answer writes nothing (:func:`answerable`).
    """
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None or not answerable(hunt, await _payload(db, hunt_id, "done")):
        return 0
    subjects = subjects_of(await _payload(db, hunt_id, "hunt_started"))
    if not subjects.campaigns and not subjects.leads:
        return 0
    have = {
        (str(t), int(i))
        for t, i in (
            await db.execute(
                select(HuntAnswer.subject_type, HuntAnswer.subject_id).where(
                    HuntAnswer.hunt_id == hunt_id
                )
            )
        ).all()
    }
    report = hunt.report if isinstance(hunt.report, dict) else {}
    raw = report.get("findings")
    findings: list[Any] = list(raw) if isinstance(raw, list) else []
    links = finding_links(hunt)
    cache: dict[str, str | None] = {}
    at = hunt.finished_at or now
    rows: list[HuntAnswer] = []
    for campaign_id in subjects.campaigns:
        if (SUBJECT_CAMPAIGN, campaign_id) in have or await db.get(Campaign, campaign_id) is None:
            continue
        values, keys = await _campaign_machines(db, campaign_id)
        names = await _names(db, findings, values, keys, cache)
        family = await _family(db, campaign_id)
        outcome, ordinal = decide(findings, links, names, family=family)
        rows.append(_row(hunt_id, SUBJECT_CAMPAIGN, campaign_id, outcome, ordinal, at))
    for lead_id in subjects.leads:
        if (SUBJECT_LEAD, lead_id) in have:
            continue
        lead = await _lead_read_open(db, lead_id, hunt)
        if lead is None:
            continue
        values, keys = await _lead_machines(db, lead, cache)
        names = await _names(db, findings, values, keys, cache)
        outcome, ordinal = decide(findings, links, names, family=None)
        rows.append(_row(hunt_id, SUBJECT_LEAD, lead_id, outcome, ordinal, at))
    if not rows:
        return 0
    db.add_all(rows)
    try:
        await db.commit()
    except IntegrityError:
        # Another writer recorded the answers of this hunt first.
        await db.rollback()
        return 0
    return len(rows)


def _row(
    hunt_id: str,
    subject_type: str,
    subject_id: int,
    outcome: str,
    ordinal: int | None,
    at: datetime,
) -> HuntAnswer:
    return HuntAnswer(
        hunt_id=hunt_id,
        subject_type=subject_type,
        subject_id=int(subject_id),
        outcome=outcome,
        finding_ordinal=ordinal,
        answered_at=at,
    )


async def after_end(maker: async_sessionmaker[AsyncSession], hunt_id: str, *, now: datetime) -> int:
    """:func:`record` for a hunt that ended now. Never raises: a failure logs one warning."""
    try:
        async with maker() as db:
            return await record(db, hunt_id, now=now)
    except Exception:
        _LOGGER.warning(
            "hunt %s: soc-ai could not record what the hunt found for the campaigns and the "
            "leads that it read. The next start fills the answers.",
            hunt_id,
            exc_info=True,
        )
        return 0


async def fill(db: AsyncSession, *, now: datetime, days: int = FILL_DAYS) -> int:
    """Record the answers of the complete hunts of the last ``days`` days that have none.

    The start step. The count of new rows.
    """
    since = now - timedelta(days=days)
    has_answer = exists().where(HuntAnswer.hunt_id == Hunt.id)
    ids = (
        await db.scalars(
            select(Hunt.id)
            .where(
                Hunt.status == STATUS_COMPLETE,
                Hunt.is_synth_eval.is_(False),
                Hunt.kind != _CATALOG_KIND,
                func.coalesce(Hunt.finished_at, Hunt.created_at) >= since,
                ~has_answer,
            )
            .order_by(Hunt.created_at, Hunt.id)
        )
    ).all()
    count = 0
    for hunt_id in ids:
        count += await record(db, str(hunt_id), now=now)
    return count


# ── the reads of a page ─────────────────────────────────────────────────────


def _title(report: Any, ordinal: int | None) -> str | None:
    if ordinal is None or not isinstance(report, dict):
        return None
    findings = report.get("findings")
    if not isinstance(findings, list) or not 0 <= ordinal < len(findings):
        return None
    finding = findings[ordinal]
    title = str(finding.get("title") or "").strip() if isinstance(finding, dict) else ""
    return title or None


async def answers_of(
    db: AsyncSession,
    subject_type: str,
    subject_ids: Collection[int],
    *,
    limit: int = ANSWERS_MAX,
) -> list[AnswerView]:
    """The answers for the subjects, newest hunt first, at most ``limit``.

    The page of a campaign passes the campaign and the campaigns that a merge
    put into it. The title of the finding behind an outcome comes from the
    stored report of the hunt.
    """
    ids = sorted({int(i) for i in subject_ids})
    if not ids:
        return []
    rows = (
        await db.execute(
            select(HuntAnswer, Hunt.created_at, Hunt.starter, Hunt.kind)
            .join(Hunt, Hunt.id == HuntAnswer.hunt_id)
            .where(HuntAnswer.subject_type == subject_type, HuntAnswer.subject_id.in_(ids))
            .order_by(Hunt.created_at.desc(), HuntAnswer.hunt_id.desc(), HuntAnswer.id)
            .limit(max(1, limit) * len(ids))
        )
    ).all()
    seen: set[str] = set()
    picked: list[tuple[HuntAnswer, datetime | None, str]] = []
    for answer, created, starter, kind in rows:
        # A hunt that read two campaigns of one family answers once on the page.
        if answer.hunt_id in seen:
            continue
        seen.add(answer.hunt_id)
        picked.append((answer, created, "catalog" if kind == _CATALOG_KIND else str(starter)))
        if len(picked) >= limit:
            break
    wanted = sorted({a.hunt_id for a, _c, _s in picked if a.finding_ordinal is not None})
    reports: dict[str, Any] = {}
    if wanted:
        found = await db.execute(select(Hunt.id, Hunt.report).where(Hunt.id.in_(wanted)))
        reports = {str(hunt_id): report for hunt_id, report in found.all()}
    return [
        AnswerView(
            hunt_id=a.hunt_id,
            subject_type=a.subject_type,
            subject_id=int(a.subject_id),
            outcome=a.outcome,
            finding_ordinal=a.finding_ordinal,
            finding_title=_title(reports.get(a.hunt_id), a.finding_ordinal),
            hunt_at=created,
            starter=starter,
            answered_at=a.answered_at,
        )
        for a, created, starter in picked
    ]
