"""The leads and the hunts of a campaign: the step after a rebuild (D4, D5).

One test caused 6 leads, 20 hunts and 48 finding investigations beside its
campaign (2026-11-16). The campaign is the unit of work, so the leads and the
lead hunts of a campaign fold into it.

A lead of a campaign is a lead whose every observation that counts maps to
an investigation that the campaign holds. Two types of observation map:

- An alert observation: its fingerprint is the alert id of an alert
  investigation.
- The observation of a promoted hunt finding (round "decide once",
  2026-11-17): its evidence names the hunt and the ordinal of the finding,
  and the finding investigation names the same two. Lead 73 on production
  held 9 alert observations and 4 such observations, each of an
  investigation of campaign 2, and it named no campaign.

Such a lead gets ``leads.campaign_id``. It waits on its campaign: it is no
Needs you item and no bell row
(:func:`soc_ai.store.leads.campaign_lead_clause`).

A lead with one observation of another type, of an investigation that the
campaign does not hold, or of a finding with no investigation, is no lead of
the campaign. It keeps normal handling.

The tag follows the engine. :func:`after_rebuild` sets it and removes it in
one step after each rebuild, from stored rows, and the refresh loop runs the
step again on each wake. A lead loses the tag when it gains another
observation, when its campaign is withdrawn, and when its investigation is
beyond an authorization. Nothing here predicts a campaign: the engine decides
the members first.

The same step gives ``hunts.campaign_id`` to the lead hunts of a lead of a
campaign, and to a hunt whose finding investigations one campaign holds. A
hunt of a campaign that a merge took moves to the campaign that took it. The
limit of one hunt for one campaign in 24 hours reads these ids
(:mod:`soc_ai.hunting.campaign_hunt`). A hunt keeps its campaign id when its
lead loses the tag: the hunt was for that campaign when it ran.

An evaluation hunt, a backtest replay and a lead formed from backtest
replays never take a campaign id.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns import decisions
from soc_ai.campaigns.facts import chunked
from soc_ai.store.models import (
    Campaign,
    CampaignMember,
    CampaignParty,
    EntityObservation,
    Hunt,
    HuntAnswer,
    Investigation,
    Lead,
)

_LOGGER = logging.getLogger(__name__)

_ACTIVE = "active"
_MERGED = "merged"
_PROMOTED_KINDS: tuple[str, ...] = ("hunt", "lead")
_BACKTEST_ACTOR = "backtest"
# How far back a hunt that reused an investigation of another hunt is read.
# A hunt that opened the investigation is found through the investigation
# row at any age.
REUSED_HUNT_DAYS = 7
# The most hops a merge chain is followed.
_MERGE_HOPS = 8


@dataclass(frozen=True)
class TagResult:
    """What one step changed: leads tagged and untagged, hunts given a campaign."""

    tagged: int = 0
    untagged: int = 0
    hunts: int = 0
    # Open leads that closed with their decided campaign.
    closed: int = 0


def _alert_spec_id() -> str:
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - one value for the readers

    return leads_store._ALERT_SPEC_ID


def _hunt_spec_id() -> str:
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - one value for the readers

    return leads_store._HUNT_SPEC_ID


def finding_key(hunt_id: Any, ordinal: Any) -> str | None:
    """The key of one hunt finding: the hunt and the ordinal. None for another shape."""
    if not hunt_id or isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
        return None
    return f"{hunt_id}#{ordinal}"


async def held_runs(db: AsyncSession) -> dict[str, int]:
    """The campaign of each investigation that an active campaign holds.

    A true positive member of an active campaign. In an authorized campaign
    only an inside investigation is held: one beyond the authorization keeps
    normal handling (:func:`soc_ai.campaigns.service.held`).
    """
    from soc_ai.campaigns import service  # noqa: PLC0415 - the service calls this module

    rows = await db.execute(
        select(CampaignMember.run_id)
        .join(Campaign, Campaign.id == CampaignMember.campaign_id)
        .where(Campaign.status == _ACTIVE, CampaignMember.verdict_differs.is_(False))
    )
    run_ids = [str(r) for (r,) in rows.all()]
    links = await service.links_of(db, run_ids)
    return {run_id: link.id for run_id, link in links.items() if service.held(link)}


async def _alert_campaigns(db: AsyncSession, held: Mapping[str, int]) -> dict[str, set[int]]:
    """The campaigns that hold an investigation of each alert id.

    An alert run only: a promoted run writes no alert observation. A
    synthetic run and a backtest replay write none either, and they are
    read out here as well.
    """
    out: dict[str, set[int]] = {}
    for ids in chunked(sorted(held)):
        rows = await db.execute(
            select(Investigation.id, Investigation.alert_es_id, Investigation.kind).where(
                Investigation.id.in_(ids),
                Investigation.alert_es_id.is_not(None),
                Investigation.is_synth_eval.is_(False),
                func.coalesce(Investigation.started_by, "") != _BACKTEST_ACTOR,
            )
        )
        for run_id, alert_id, kind in rows.all():
            if kind in _PROMOTED_KINDS:
                continue
            out.setdefault(str(alert_id), set()).add(held[str(run_id)])
    return out


async def _finding_campaigns(db: AsyncSession, held: Mapping[str, int]) -> dict[str, set[int]]:
    """The campaigns that hold the finding investigation of each hunt finding.

    The key is :func:`finding_key`. A synthetic run and a backtest replay
    are read out, as for an alert.
    """
    out: dict[str, set[int]] = {}
    for ids in chunked(sorted(held)):
        rows = await db.execute(
            select(Investigation.id, Investigation.hunt_id, Investigation.finding_ordinal).where(
                Investigation.id.in_(ids),
                Investigation.kind == "hunt",
                Investigation.hunt_id.is_not(None),
                Investigation.finding_ordinal.is_not(None),
                Investigation.is_synth_eval.is_(False),
                func.coalesce(Investigation.started_by, "") != _BACKTEST_ACTOR,
            )
        )
        for run_id, hunt_id, ordinal in rows.all():
            key = finding_key(hunt_id, ordinal)
            if key is not None:
                out.setdefault(key, set()).add(held[str(run_id)])
    return out


def campaign_of(
    observations: Iterable[tuple[str, str]],
    alerts: Mapping[str, set[int]],
    findings: Mapping[str, set[int]] | None = None,
) -> int | None:
    """The campaign that holds every observation, or None.

    ``observations`` holds the spec id and the key of each observation that
    counts: the fingerprint of an alert observation, and the
    :func:`finding_key` of the observation of a hunt finding. None for no
    observation, for an observation of another type, for an alert or a
    finding that no campaign holds, and for observations that two campaigns
    hold apart.
    """
    alert_spec, hunt_spec = _alert_spec_id(), _hunt_spec_id()
    common: set[int] | None = None
    for spec_id, key in observations:
        if spec_id == alert_spec:
            holders = alerts.get(key)
        elif spec_id == hunt_spec:
            holders = (findings or {}).get(key)
        else:
            return None
        if not holders:
            return None
        common = set(holders) if common is None else common & holders
        if not common:
            return None
    return min(common) if common else None


async def _candidates(
    db: AsyncSession, alerts: Mapping[str, set[int]], findings: Mapping[str, set[int]]
) -> list[int]:
    """The leads to judge: each that names a campaign, or holds a held alert or finding."""
    from soc_ai.hunting.leads import content_fingerprint  # noqa: PLC0415 - the hunting package

    ids = {int(i) for i in (await db.scalars(select(Lead.id).where(Lead.campaign_id.is_not(None))))}
    # The fingerprint of a finding observation is the hash of the hunt and
    # the ordinal (soc_ai.hunting.sources.observe_hunt_finding). It finds
    # the candidates only: the judge reads the evidence.
    prints: set[str] = set()
    for key in findings:
        hunt_id, _sep, ordinal = key.rpartition("#")
        prints.add(content_fingerprint(hunt_id, int(ordinal)))
    for spec_id, keys in ((_alert_spec_id(), sorted(alerts)), (_hunt_spec_id(), sorted(prints))):
        for chunk in chunked(keys):
            rows = await db.scalars(
                select(EntityObservation.lead_id).where(
                    EntityObservation.spec_id == spec_id,
                    EntityObservation.fingerprint.in_(chunk),
                    EntityObservation.lead_id.is_not(None),
                )
            )
            ids.update(int(i) for i in rows.all() if i is not None)
    return sorted(ids)


async def _observations(
    db: AsyncSession, lead_ids: Sequence[int]
) -> dict[int, list[tuple[str, str]]]:
    """The observations of each lead that count: attached and not dismissed.

    Each is the spec id and the key that :func:`campaign_of` reads. The key
    of a finding observation comes from its evidence, as in the SQL of
    :func:`soc_ai.store.leads.campaign_lead_clause`. Evidence with no hunt
    gives an empty key, which no campaign holds.
    """
    hunt_spec = _hunt_spec_id()
    out: dict[int, list[tuple[str, str]]] = {}
    for chunk in chunked(list(lead_ids)):
        rows = await db.execute(
            select(
                EntityObservation.lead_id,
                EntityObservation.spec_id,
                EntityObservation.fingerprint,
                EntityObservation.evidence_json,
            ).where(
                EntityObservation.lead_id.in_(chunk),
                EntityObservation.dismissed_at.is_(None),
            )
        )
        for lead_id, spec_id, fingerprint, evidence in rows.all():
            key = str(fingerprint)
            if spec_id == hunt_spec:
                ev = evidence if isinstance(evidence, dict) else {}
                key = finding_key(ev.get("hunt_id"), ev.get("ordinal")) or ""
            out.setdefault(int(lead_id), []).append((str(spec_id), key))
    return out


async def _tag_leads(
    db: AsyncSession, alerts: Mapping[str, set[int]], findings: Mapping[str, set[int]]
) -> tuple[int, int, dict[int, int]]:
    """Set and remove the tag of each lead. The counts, and the campaign of each tagged lead."""
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - the store reads this module

    candidates = await _candidates(db, alerts, findings)
    observations = await _observations(db, candidates)
    tagged = untagged = 0
    out: dict[int, int] = {}
    for chunk in chunked(candidates):
        for lead in (await db.scalars(select(Lead).where(Lead.id.in_(chunk)))).all():
            found = (
                None
                if leads_store.formed_from_backtest(lead)
                else campaign_of(observations.get(int(lead.id), []), alerts, findings)
            )
            if found is not None:
                out[int(lead.id)] = found
            if lead.campaign_id == found:
                continue
            if found is None:
                untagged += 1
            else:
                tagged += 1
            lead.campaign_id = found
    return tagged, untagged, out


def _held_by_one(entries: Any, held: Mapping[str, int]) -> int | None:
    """The campaign that holds every finding investigation of a hunt, or None."""
    if not isinstance(entries, dict):
        return None
    runs = [
        str(entry.get("investigation_id"))
        for entry in entries.values()
        if isinstance(entry, dict) and entry.get("investigation_id")
    ]
    if not runs or any(run not in held for run in runs):
        return None
    found = {held[run] for run in runs}
    return found.pop() if len(found) == 1 else None


async def _active_of(db: AsyncSession, campaign_id: int) -> int | None:
    """The active campaign that a campaign id names, through its merges."""
    current: int | None = campaign_id
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


async def _stamp_hunts(
    db: AsyncSession, leads: Mapping[int, int], held: Mapping[str, int], *, now: datetime
) -> int:
    """Give a campaign id to the hunts of a campaign that have none. The count.

    Three cases: a lead hunt of a lead of a campaign, a hunt whose finding
    investigations one campaign holds, and a hunt of a merged campaign. The
    reads take the id columns only: a hunt row holds its report.
    """
    free = (Hunt.campaign_id.is_(None), Hunt.is_synth_eval.is_(False))
    plan: dict[str, int] = {}
    for lead_ids in chunked(sorted(leads)):
        rows = await db.execute(
            select(Hunt.id, Hunt.lead_id).where(Hunt.lead_id.in_(lead_ids), *free)
        )
        for hunt_id, lead_id in rows.all():
            plan[str(hunt_id)] = leads[int(lead_id)]
    # A hunt whose finding investigations one campaign holds. The hunt that
    # opened an investigation is named on its row. A hunt that reused one is
    # read for a week.
    openers: set[str] = set()
    for run_ids in chunked(sorted(held)):
        rows_ = await db.scalars(
            select(Investigation.hunt_id).where(
                Investigation.id.in_(run_ids), Investigation.hunt_id.is_not(None)
            )
        )
        openers.update(str(h) for h in rows_.all() if h)
    links: dict[str, Any] = {}
    for hunt_ids in chunked(sorted(openers)):
        rows = await db.execute(
            select(Hunt.id, Hunt.finding_investigations).where(Hunt.id.in_(hunt_ids), *free)
        )
        links.update({str(hunt_id): entries for hunt_id, entries in rows.all()})
    recent = await db.execute(
        select(Hunt.id, Hunt.finding_investigations).where(
            *free,
            Hunt.finding_investigations.is_not(None),
            Hunt.created_at >= now - timedelta(days=REUSED_HUNT_DAYS),
        )
    )
    for hunt_id, entries in recent.all():
        links.setdefault(str(hunt_id), entries)
    for hunt_id, entries in links.items():
        found = _held_by_one(entries, held)
        if found is not None and hunt_id not in plan:
            plan[hunt_id] = found
    for hunt_id, campaign_id in plan.items():
        await db.execute(
            update(Hunt)
            .where(Hunt.id == hunt_id, Hunt.campaign_id.is_(None))
            .values(campaign_id=campaign_id)
            .execution_options(synchronize_session=False)
        )
    stamped = len(plan)
    # A hunt of a campaign that a merge took belongs to the campaign that took it.
    merged = await db.execute(
        select(Hunt.id, Hunt.campaign_id).where(
            Hunt.campaign_id.in_(select(Campaign.id).where(Campaign.status == _MERGED))
        )
    )
    for hunt_id, campaign_id in merged.all():
        target = await _active_of(db, int(campaign_id))
        if target is not None and target != campaign_id:
            await db.execute(
                update(Hunt)
                .where(Hunt.id == hunt_id)
                .values(campaign_id=target)
                .execution_options(synchronize_session=False)
            )
            stamped += 1
    return stamped


async def close_leads(
    db: AsyncSession, campaign_id: int, *, reason: str, now: datetime
) -> list[int]:
    """Dismiss each open lead of the campaign with a reason of soc-ai (D6). The ids.

    A close and an authorization of the campaign call it. Each lead gets the
    reason ``campaign_closed`` or ``campaign_authorized``, the hand
    ``system:campaign`` and one decision record. A lead that is dismissed or
    promoted keeps its decision. A reopen and a revoke change no lead: new
    activity forms its own observation. A lead with one observation of
    another type is no lead of the campaign, so it stays open.
    """
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - the store reads this module

    ids = (
        await db.scalars(
            select(Lead.id).where(
                Lead.campaign_id == int(campaign_id),
                Lead.status.in_(("open", "hunting")),
                leads_store.campaign_lead_clause(),
            )
        )
    ).all()
    note = (
        f"The analyst authorized the activity of campaign {int(campaign_id)}."
        if reason == leads_store.CAMPAIGN_AUTHORIZED_REASON
        else f"The analyst closed campaign {int(campaign_id)}."
    )
    closed: list[int] = []
    for lead_id in ids:
        await leads_store.dismiss(
            db,
            int(lead_id),
            reason=reason,
            note=note,
            by=leads_store.CAMPAIGN_ACTOR,
            now=now,
            system=True,
        )
        closed.append(int(lead_id))
    return closed


async def _close_decided(db: AsyncSession, campaign_ids: Iterable[int], *, now: datetime) -> int:
    """Close the open leads of each decided campaign. A lead can join after the decision."""
    from soc_ai.hunting import campaign_hunt  # noqa: PLC0415 - the hunting package reads this
    from soc_ai.store import leads as leads_store  # noqa: PLC0415

    count = 0
    for campaign_id in sorted(set(campaign_ids)):
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if (
            row is None
            or row.status != _ACTIVE
            or not await campaign_hunt.decided(db, row, now=now)
        ):
            continue
        reason = (
            leads_store.CAMPAIGN_CLOSED_REASON
            if row.decision == "closed"
            else leads_store.CAMPAIGN_AUTHORIZED_REASON
        )
        count += len(await close_leads(db, campaign_id, reason=reason, now=now))
    return count


async def tag(db: AsyncSession, *, now: datetime) -> TagResult:
    """Set and remove the tag of each lead and give the hunts their campaign.

    One commit for the tags and the hunts. Then a lead that joined a campaign
    after its close or its authorization closes with it (D6).
    """
    held = await held_runs(db)
    alerts = await _alert_campaigns(db, held)
    findings = await _finding_campaigns(db, held)
    tagged, untagged, leads = await _tag_leads(db, alerts, findings)
    hunts = await _stamp_hunts(db, leads, held, now=now)
    await db.commit()
    closed = await _close_decided(db, leads.values(), now=now)
    return TagResult(tagged=tagged, untagged=untagged, hunts=hunts, closed=closed)


async def after_rebuild(db: AsyncSession, *, now: datetime) -> TagResult | None:
    """:func:`tag`, after a rebuild and on each wake of the refresh loop. Never raises.

    A failure logs one warning and changes nothing. The leads then keep the
    tags of the last step, and the clause of the readers still gives a lead
    with a stray observation back to the analyst.
    """
    try:
        result = await tag(db, now=now)
    except Exception:
        _LOGGER.warning(
            "campaigns: soc-ai could not set the campaign of the leads after the rebuild. "
            "The leads keep their last campaign.",
            exc_info=True,
        )
        try:
            await db.rollback()
        except Exception:
            _LOGGER.debug("campaigns: the rollback failed", exc_info=True)
        return None
    if result.tagged or result.untagged or result.hunts or result.closed:
        _LOGGER.info(
            "campaigns: %d lead(s) joined a campaign, %d left one, %d hunt(s) took a campaign, "
            "%d lead(s) closed with a decided campaign",
            result.tagged,
            result.untagged,
            result.hunts,
            result.closed,
        )
    return result


# ── The leads and the hunts on the campaign page ──────────────────────────

# The most hunts and related leads that the page lists.
HUNTS_MAX = 20
RELATED_MAX = 20
LEADS_MAX = 100


@dataclass(frozen=True)
class CampaignLead:
    """One lead on the campaign page.

    ``related`` is false for a lead of the campaign. It is true for a lead
    that no campaign holds, whose entity is a machine of the campaign, with an
    observation in the period of the campaign: "Related, not proven".
    """

    id: int
    title: str
    state: str
    hunted: bool
    related: bool


def _lead_title(lead: Lead) -> str:
    entities = [
        str(entity[1])
        for entity in (lead.entities_json or [])
        if isinstance(entity, list | tuple) and len(entity) == 2
    ]
    return f"Lead {lead.id} on {', '.join(entities) or 'an entity'}"


async def _hunted(db: AsyncSession, leads: Sequence[Lead]) -> set[int]:
    """The leads among ``leads`` that had a hunt, of any status."""
    out = {int(lead.id) for lead in leads if lead.hunt_id}
    for chunk in chunked(sorted({int(lead.id) for lead in leads})):
        rows = await db.scalars(select(Hunt.lead_id).where(Hunt.lead_id.in_(chunk)))
        out.update(int(i) for i in rows.all() if i is not None)
    return out


async def _related(db: AsyncSession, row: Campaign, held: set[int]) -> list[Lead]:
    """The leads of D4, second sentence: no campaign holds them, and they touch the campaign."""
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - the store reads this module

    parties = (
        await db.execute(
            select(CampaignParty.addresses, CampaignParty.name).where(
                CampaignParty.campaign_id == row.id
            )
        )
    ).all()
    keys = {
        str(value).strip().casefold()
        for addresses, name in parties
        for value in [*(addresses or []), name]
        if value and str(value).strip()
    }
    if not keys:
        return []
    start, end = row.first_event, row.last_event
    seen_at = func.coalesce(EntityObservation.observed_at, EntityObservation.born_at)
    found: set[int] = set()
    for chunk in chunked(sorted(keys)):
        rows = await db.scalars(
            select(EntityObservation.lead_id).where(
                EntityObservation.entity_kind == "host",
                func.lower(EntityObservation.entity_key).in_(chunk),
                EntityObservation.lead_id.is_not(None),
                EntityObservation.dismissed_at.is_(None),
                or_(
                    seen_at.between(start, end),
                    EntityObservation.first_seen_at.between(start, end),
                ),
            )
        )
        found.update(int(i) for i in rows.all() if i is not None)
    found -= held
    if not found:
        return []
    # A lead that a campaign holds belongs to that campaign, and it is no
    # related lead of this one.
    found -= set(await leads_store.campaign_leads(db, sorted(found)))
    if not found:
        return []
    rows_ = await db.scalars(
        select(Lead)
        .where(Lead.id.in_(sorted(found)))
        .order_by(Lead.formed_at.desc(), Lead.id.desc())
        .limit(RELATED_MAX)
    )
    return list(rows_.all())


async def leads_of(db: AsyncSession, campaign_id: int) -> list[CampaignLead]:
    """The leads of the campaign, then its related leads. Empty for a campaign that is not active.

    The leads of the campaign are oldest first, at most :data:`LEADS_MAX`.
    The related leads are newest first, at most :data:`RELATED_MAX`.
    """
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - the store reads this module

    row = await db.get(Campaign, int(campaign_id))
    if row is None or row.status != _ACTIVE:
        return []
    own = list(
        (
            await db.scalars(
                select(Lead)
                .where(Lead.campaign_id == row.id, leads_store.campaign_lead_clause())
                .order_by(Lead.formed_at, Lead.id)
                .limit(LEADS_MAX)
            )
        ).all()
    )
    related = await _related(db, row, {int(lead.id) for lead in own})
    hunted = await _hunted(db, [*own, *related])
    return [
        CampaignLead(
            id=int(lead.id),
            title=_lead_title(lead),
            state=str(lead.status),
            hunted=int(lead.id) in hunted,
            related=flag,
        )
        for leads, flag in ((own, False), (related, True))
        for lead in leads
    ]


async def hunts_of(db: AsyncSession, campaign_id: int) -> list[Hunt]:
    """The hunts for the campaign and the hunts that read it, with the campaigns of its merges.

    A hunt for the campaign names it in ``hunts.campaign_id``. A hunt that
    read the campaign holds an answer for it (:mod:`soc_ai.hunting.hunt_answers`):
    the scheduled hunt reads the block of each active campaign. Newest first,
    at most :data:`HUNTS_MAX`, of any status and any starter. An evaluation
    hunt never takes a campaign id and writes no answer. Empty for a campaign
    that is not active.
    """
    from soc_ai.hunting import campaign_hunt  # noqa: PLC0415 - the hunting package reads this

    row = await db.get(Campaign, int(campaign_id))
    if row is None or row.status != _ACTIVE:
        return []
    ids = sorted(await campaign_hunt.family(db, row.id))
    read = select(HuntAnswer.hunt_id).where(
        HuntAnswer.subject_type == "campaign", HuntAnswer.subject_id.in_(ids)
    )
    rows = await db.scalars(
        select(Hunt)
        .where(
            or_(Hunt.campaign_id.in_(ids), Hunt.id.in_(read)),
            Hunt.is_synth_eval.is_(False),
        )
        .order_by(Hunt.created_at.desc(), Hunt.id.desc())
        .limit(HUNTS_MAX)
    )
    return list(rows.all())


# ── The campaign and the authorized activity on the lead page (LH4) ────────


@dataclass(frozen=True)
class LeadCampaign:
    """The campaign that a lead is part of, as the lead page states it.

    ``closed_with_campaign`` is true for a lead that soc-ai closed with the
    close or the authorization of its campaign (:func:`close_leads`).
    ``closed_at`` is the time of that close. A lead that joins a campaign
    after the decision closes later than the campaign (lead 73, dogfood N4).
    """

    id: int
    title: str
    decision: str | None
    decided_at: datetime | None
    decided_by: str | None
    closed_with_campaign: bool
    closed_at: datetime | None = None
    # Round 3 part 2, W4: the decision that closed the lead (``closed`` or
    # ``authorized``), the analyst of that decision, and the time of the
    # newest reopen of the campaign after the close of the lead. Lead 73
    # read "Its campaign is closed" beside the chip "Campaign 2 · Open".
    closed_by_decision: str | None = None
    closed_by: str | None = None
    reopened_at: datetime | None = None


@dataclass(frozen=True)
class AuthorizedPart:
    """The observations of a lead whose investigation matched one authorization."""

    label: str
    observations: int


async def lead_campaign(db: AsyncSession, lead: Lead) -> LeadCampaign | None:
    """The campaign of the lead, or None.

    A lead of a campaign by the clause of the readers. A lead that closed
    with its campaign names that campaign too.
    """
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - the store reads this module

    closed_with = (
        lead.status == "dismissed"
        and lead.dismissed_reason in leads_store.SYSTEM_DISMISS_REASONS
        and lead.dismissed_by == leads_store.CAMPAIGN_ACTOR
    )
    campaign_id = (await leads_store.campaign_leads(db, [int(lead.id)])).get(int(lead.id))
    if campaign_id is None and closed_with and lead.campaign_id is not None:
        campaign_id = int(lead.campaign_id)
    if campaign_id is None:
        return None
    row = await db.get(Campaign, int(campaign_id))
    if row is None:
        return None
    closed_by_decision: str | None = None
    closed_by: str | None = None
    reopened_at: datetime | None = None
    if closed_with:
        closed_by_decision = (
            decisions.DECISION_AUTHORIZED
            if lead.dismissed_reason == leads_store.CAMPAIGN_AUTHORIZED_REASON
            else decisions.DECISION_CLOSED
        )
        closed_by, reopened_at = await _closed_by(db, row, lead.dismissed_at)
    return LeadCampaign(
        id=int(row.id),
        title=str(row.title),
        decision=row.decision,
        decided_at=row.decided_at,
        decided_by=row.decided_by,
        closed_with_campaign=closed_with,
        closed_at=lead.dismissed_at if closed_with else None,
        closed_by_decision=closed_by_decision,
        closed_by=closed_by,
        reopened_at=reopened_at,
    )


async def _closed_by(
    db: AsyncSession, row: Campaign, closed_at: datetime | None
) -> tuple[str | None, datetime | None]:
    """The analyst of the decision that closed a lead, and the reopen of the campaign after it (W4).

    A decision in force names its analyst. After a reopen the campaign holds
    no decision, so the earlier decision of the reopen names the analyst
    (:func:`soc_ai.campaigns.since_decision.covered`). The reopen counts when
    it is after the close of the lead.
    """
    from soc_ai.campaigns import since_decision as since_svc  # noqa: PLC0415 - it reads this module

    if decisions.in_force(row.decision):
        return row.decided_by, None
    reopened = (await decisions.last_reopened(db, [int(row.id)])).get(int(row.id))
    if reopened is None or (closed_at is not None and reopened < closed_at):
        return None, None
    earlier = (await since_svc.covered(db, [int(row.id)])).get(int(row.id))
    return (earlier.earlier.by if earlier is not None else None), reopened


async def authorized_parts(db: AsyncSession, lead_id: int) -> list[AuthorizedPart]:
    """The observations of the lead that the store links to authorized activity.

    An observation maps to its investigation as in :func:`campaign_of`. The
    investigation names the authorization that it matched
    (``investigations.authorization_id``). The most observations first.
    """
    from soc_ai.store.models import AuthorizedActivity  # noqa: PLC0415 - one reader

    observations = (await _observations(db, [int(lead_id)])).get(int(lead_id), [])
    if not observations:
        return []
    alert_spec, hunt_spec = _alert_spec_id(), _hunt_spec_id()
    alerts = sorted({key for spec, key in observations if spec == alert_spec and key})
    findings = sorted({key for spec, key in observations if spec == hunt_spec and key})
    by_alert: dict[str, int] = {}
    for chunk in chunked(alerts):
        rows = await db.execute(
            select(Investigation.alert_es_id, Investigation.authorization_id).where(
                Investigation.alert_es_id.in_(chunk),
                Investigation.authorization_id.is_not(None),
                func.coalesce(Investigation.kind, "").not_in(_PROMOTED_KINDS),
            )
        )
        for alert_id, auth in rows.all():
            by_alert.setdefault(str(alert_id), int(auth))
    by_finding: dict[str, int] = {}
    hunts = sorted({key.rpartition("#")[0] for key in findings})
    for chunk in chunked(hunts):
        rows = await db.execute(
            select(
                Investigation.hunt_id, Investigation.finding_ordinal, Investigation.authorization_id
            ).where(
                Investigation.hunt_id.in_(chunk),
                Investigation.kind == "hunt",
                Investigation.authorization_id.is_not(None),
            )
        )
        for hunt_id, ordinal, auth in rows.all():
            key = finding_key(hunt_id, ordinal)
            if key is not None:
                by_finding.setdefault(key, int(auth))
    counts: dict[int, int] = {}
    for spec, key in observations:
        auth = by_alert.get(key) if spec == alert_spec else by_finding.get(key)
        if auth is not None:
            counts[auth] = counts.get(auth, 0) + 1
    if not counts:
        return []
    found = await db.execute(
        select(AuthorizedActivity.id, AuthorizedActivity.label).where(
            AuthorizedActivity.id.in_(sorted(counts))
        )
    )
    labels: dict[int, str] = {int(i): str(label) for i, label in found.all()}
    parts = [
        AuthorizedPart(label=str(labels[auth]), observations=n)
        for auth, n in counts.items()
        if auth in labels
    ]
    return sorted(parts, key=lambda p: (-p.observations, p.label))


__all__ = [
    "HUNTS_MAX",
    "LEADS_MAX",
    "RELATED_MAX",
    "REUSED_HUNT_DAYS",
    "AuthorizedPart",
    "CampaignLead",
    "LeadCampaign",
    "TagResult",
    "after_rebuild",
    "authorized_parts",
    "campaign_of",
    "close_leads",
    "finding_key",
    "held_runs",
    "hunts_of",
    "lead_campaign",
    "leads_of",
    "tag",
]
