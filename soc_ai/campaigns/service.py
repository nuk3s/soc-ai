"""The campaign service: rebuild the campaigns from the stored runs, and read them.

:func:`rebuild` reads the true positive runs that stand and the runs on their
sessions (:func:`_standing`: a run stands until a later run of its alert or
finding is complete), gives their facts to the engine, and writes the drafts to the four
campaign tables. A campaign keeps its id over a rebuild: a draft takes the
campaign of its seed run, else the lowest campaign of its members. A Re-run
takes the campaign of the run it replaced. A campaign that no draft takes is
merged into the draft that holds most of its members, or it is withdrawn. A
withdrawn campaign is active again when its seed run is a member again. A
campaign whose content did not change keeps its rows and its build time.
The rebuild writes the changes of each campaign (``formed``, ``stage``,
``party``), and it opens a decided campaign again when it goes past the
basis of the decision (:mod:`soc_ai.campaigns.decisions`). It gives the
engine the investigations that an analyst excluded or included
(``campaign_run_overrides``), and the later alerts that the stored grid read
of each active campaign holds (:func:`with_activity`). After the commit, each campaign record in
force marks the inside investigations of its campaign, and an authorized
campaign gets one ``beyond`` change for each new outside investigation
(:func:`soc_ai.campaigns.authorization.after_rebuild`).

:func:`ensure_fresh` runs :func:`rebuild` when a true positive run or a run
on a session of a campaign changed since the last rebuild. The campaign
routes call it first. The refresh loop (:mod:`soc_ai.campaigns.refresh`)
calls it after a verdict, an override or a dismissed action, and on a timer.
No code of the run pipeline calls the engine.

:func:`refresh_events` reads the events of one campaign from the grid and
stores them in the three event columns of its row. The detail route calls it
after :func:`ensure_fresh`. A rebuild never reads the grid and leaves the
event columns as they are. :func:`get_campaign` gives the stored grid events,
or the events that the investigations hold.

The service writes only the campaign tables.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import weakref
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, delete, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from soc_ai.campaigns import authorization, decisions, facts, lead_tags, since_decision, words
from soc_ai.campaigns import case as campaign_case
from soc_ai.campaigns import events as campaign_events
from soc_ai.campaigns.engine import build_campaigns
from soc_ai.campaigns.events import CampaignEvents, PairEvents, RuleEvents
from soc_ai.campaigns.facts import chunked
from soc_ai.campaigns.refresh import request_refresh
from soc_ai.campaigns.since_decision import SinceDecision
from soc_ai.campaigns.types import (
    LINK_INCLUDED,
    ROLE_ACTOR,
    ROLE_TARGET,
    STAGES,
    TRUE_POSITIVE,
    CampaignDraft,
    Detection,
    Edge,
    Link,
    Member,
    NamedHost,
    RunFacts,
    StageStep,
    Wave,
    jsonable,
    naive_utc,
)
from soc_ai.hunting.weight import decay_horizon_hours
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import (
    Campaign,
    CampaignChange,
    CampaignMember,
    CampaignParty,
    CampaignRunFacts,
    CampaignRunOverride,
    HostMachine,
    Investigation,
)
from soc_ai.triage_models import stored_impact

if TYPE_CHECKING:
    from soc_ai.config import Settings
    from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)

# The most runs that one rebuild reads in each of its two scans.
CAMPAIGN_SCAN_MAX = 20000
# The most targets that one row of the list names. The rest are a count.
MAX_LIST_TARGETS = 3
# The most needs-more-info runs that the related section of a campaign lists.
MAX_RELATED_RUNS = 50

STATUS_ACTIVE = "active"
STATUS_MERGED = "merged"
STATUS_WITHDRAWN = "withdrawn"

# The two types of an override of an analyst (``campaign_run_overrides``).
OVERRIDE_EXCLUDED = "excluded"
OVERRIDE_INCLUDED = "included"
# The status of an active campaign in the API.
STATUS_OPEN = "open"
STATUS_ENDED = "ended"

_NEEDS_MORE_INFO = "needs_more_info"
_FALSE_POSITIVE = "false_positive"

_FRESH_LINE = (
    "campaigns: soc-ai could not rebuild the campaigns. The campaign pages show the stored "
    "campaigns."
)
_EVENTS_LINE = (
    "campaigns: soc-ai could not refresh the events of campaign %s. The page shows the "
    "stored events."
)
_END_CHECK_LINE = (
    "campaigns: soc-ai could not check the end of campaign %s. The campaign keeps its state. "
    "The next wake tries again."
)
# An open campaign reads the grid again when its stored events are older.
EVENTS_MAX_AGE = timedelta(minutes=15)
# The most grid reads of one wake of the refresh loop (:func:`refresh_behind`),
# and the time that the step may take. A grid that does not answer then
# holds the next rebuild back by at most this time.
EVENTS_REFRESH_MAX = 5
EVENTS_REFRESH_BUDGET_S = 60.0


# ── Rebuild ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RebuildResult:
    """What one rebuild built, and what it changed in the store."""

    campaigns: int
    members: int
    created: int
    merged: int
    withdrawn: int
    # The standing true positive runs of an attack class with an end that the
    # Hosts data joins to no one machine.
    unresolved_runs: int
    drafts: tuple[CampaignDraft, ...]
    # The basis of the store that the rebuild read (:func:`ensure_fresh`), and
    # the session ids of the standing true positive runs.
    basis: str = ""
    session_ids: frozenset[str] = frozenset()
    revived: int = 0


@dataclass(frozen=True)
class IdPlan:
    """The campaign id of each draft, and the fate of each campaign that no draft takes.

    ``taken`` holds one entry for each draft: the id of the campaign it
    takes, or None for a new row. ``merged`` maps an old campaign to the
    index of the draft that holds most of its members. ``revived`` holds the
    withdrawn campaigns that a draft takes again.
    """

    taken: tuple[int | None, ...]
    merged: Mapping[int, int]
    withdrawn: tuple[int, ...]
    revived: tuple[int, ...] = ()


def plan_ids(
    drafts: Sequence[CampaignDraft],
    owner: Mapping[str, int],
    active: Iterable[int],
    *,
    groups: Mapping[str, str] | None = None,
    group_owner: Mapping[str, int] | None = None,
    withdrawn: Mapping[int, frozenset[str]] | None = None,
) -> IdPlan:
    """The stable ids. ``owner`` maps a run id to its active campaign.

    ``groups`` maps a run id of a draft to the key of its group: its alert,
    or its hunt finding. ``group_owner`` maps a group key to the active
    campaign of an old member of that group. A Re-run replaces the run of its
    group, so the new run owns the campaign of the run it replaced.

    The drafts come in order. A draft takes the campaign of its seed run when
    no earlier draft took it, else the lowest campaign of its members that no
    draft took. A draft that takes no active campaign takes a withdrawn
    campaign whose seed run, or a run of the group of that seed, is a member.
    ``withdrawn`` maps a withdrawn campaign to those keys. Else the draft gets
    a new row. An active campaign that no draft took is merged when a draft
    holds one of its members, into the draft that holds the most of them.
    Else it is withdrawn. A merged campaign is never taken again.
    """
    by_group = groups or {}
    of_group = group_owner or {}
    revivable = withdrawn or {}

    def owner_of(run_id: str) -> int | None:
        if run_id in owner:
            return owner[run_id]
        key = by_group.get(run_id)
        return of_group.get(key) if key is not None else None

    taken: set[int] = set()
    chosen: list[int | None] = []
    held: list[Counter[int]] = []
    revived: list[int] = []
    for draft in drafts:
        counts: Counter[int] = Counter(
            cid for r in draft.run_ids if (cid := owner_of(r)) is not None
        )
        held.append(counts)
        pick: int | None = None
        seed = owner_of(draft.seed_run_id)
        if seed is not None and seed not in taken:
            pick = seed
        else:
            free = sorted(set(counts) - taken)
            pick = free[0] if free else None
        if pick is None and revivable:
            keys = {f"run:{r}" for r in draft.run_ids} | {
                by_group[r] for r in draft.run_ids if r in by_group
            }
            again = [cid for cid in sorted(revivable) if cid not in taken and revivable[cid] & keys]
            if again:
                pick = again[0]
                revived.append(pick)
        if pick is not None:
            taken.add(pick)
        chosen.append(pick)
    merged: dict[int, int] = {}
    gone: list[int] = []
    for campaign_id in sorted(set(active) - taken):
        holders = [(n[campaign_id], -i) for i, n in enumerate(held) if n[campaign_id]]
        if holders:
            merged[campaign_id] = -max(holders)[1]
        else:
            gone.append(campaign_id)
    return IdPlan(tuple(chosen), merged, tuple(gone), tuple(revived))


def _standing() -> list[Any]:
    """The SQL of a run that stands for the campaigns, less the verdict.

    Complete, no pipeline error, no synthetic run, no backtest replay, and no
    newer run of its alert or of its finding that is complete (S2). The
    shared rule (:func:`inv_svc.superseded_sql`) lets a running Re-run
    replace the complete run at once. The subject then had no run that
    stands until the Re-run ended, and it left its campaign. Here a run
    stands until a later run of its group is complete and is no pipeline
    error, so a Re-run in progress and a Re-run that ends in an error keep
    the campaign and its id.
    """
    return [
        Investigation.status == "complete",
        Investigation.is_fallback.isnot(True),
        Investigation.is_synth_eval.isnot(True),
        inv_svc.not_backtest(),
        not_(inv_svc.superseded_sql(by_complete=True)),
    ]


async def _settled(db: AsyncSession, run_ids: Iterable[str]) -> set[str]:
    """The run ids of the runs that are complete and are no pipeline error."""
    settled: set[str] = set()
    for ids in chunked(sorted(set(run_ids))):
        found = await db.scalars(
            select(Investigation.id).where(
                Investigation.id.in_(ids),
                Investigation.status == "complete",
                Investigation.is_fallback.isnot(True),
            )
        )
        settled.update(found.all())
    return settled


async def _drop_answered(db: AsyncSession, rows: list[Investigation]) -> list[Investigation]:
    """The runs less each run that a complete follow-up run answered."""
    answers = {inv.id: fid for inv in rows if (fid := inv_svc.follow_up_id(inv)) and fid != inv.id}
    if not answers:
        return rows
    settled = await _settled(db, answers.values())
    return [inv for inv in rows if answers.get(inv.id) not in settled]


async def _standing_true_positives(db: AsyncSession, until: datetime) -> list[Investigation]:
    """The true positive runs that stand for the campaigns, newest first.

    :func:`inv_svc.standing_true_positives` under the rule of
    :func:`_standing`, at most :data:`CAMPAIGN_SCAN_MAX`.
    """
    rows = await db.scalars(
        select(Investigation)
        .where(
            *_standing(),
            Investigation.verdict == TRUE_POSITIVE,
            Investigation.created_at <= until,
        )
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        .limit(CAMPAIGN_SCAN_MAX)
    )
    return await _drop_answered(db, list(rows.all()))


async def _session_runs(
    db: AsyncSession, community_ids: Iterable[str], exclude: set[str]
) -> list[Investigation]:
    """The standing runs with a verdict that is no true positive, on one of the sessions."""
    found: dict[str, Investigation] = {}
    for ids in chunked(sorted(set(community_ids))):
        rows = await db.scalars(
            select(Investigation)
            .where(
                *_standing(),
                Investigation.verdict.is_not(None),
                Investigation.verdict != TRUE_POSITIVE,
                Investigation.community_id.in_(ids),
            )
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
            .limit(CAMPAIGN_SCAN_MAX)
        )
        for inv in rows.all():
            if inv.id not in exclude:
                found.setdefault(inv.id, inv)
        if len(found) >= CAMPAIGN_SCAN_MAX:
            break
    runs = await _drop_answered(db, list(found.values()))
    return runs[:CAMPAIGN_SCAN_MAX]


def _group_key(inv: Any) -> str | None:
    """The key of the group of a run: ``alert:<id>`` or ``finding:<hunt>:<ordinal>``.

    None for a run that stands alone. The pair of
    :func:`inv_svc.alert_group_id` and :func:`inv_svc.finding_group_id`, as
    the primacy rule reads them.
    """
    alert = inv_svc.alert_group_id(inv)
    if alert:
        return f"alert:{alert}"
    finding = inv_svc.finding_group_id(inv)
    return inv_svc.finding_group_key(finding) if finding is not None else None


async def _groups_of(db: AsyncSession, run_ids: Iterable[str]) -> dict[str, str]:
    """The group key of each run that is in the store and in a group."""
    out: dict[str, str] = {}
    for ids in chunked(sorted(set(run_ids))):
        rows = await db.execute(
            select(
                Investigation.id,
                Investigation.alert_es_id,
                Investigation.subject_json,
                Investigation.started_by,
                Investigation.hunt_id,
                Investigation.finding_ordinal,
            ).where(Investigation.id.in_(ids))
        )
        for row in rows.all():
            key = _group_key(row)
            if key is not None:
                out[str(row.id)] = key
    return out


async def _owners(db: AsyncSession, campaign_ids: Sequence[int]) -> dict[str, int]:
    """The campaign of each member run of the campaigns."""
    out: dict[str, int] = {}
    for ids in chunked(list(campaign_ids)):
        rows = await db.execute(
            select(CampaignMember.run_id, CampaignMember.campaign_id).where(
                CampaignMember.campaign_id.in_(ids)
            )
        )
        out.update({str(run_id): int(cid) for run_id, cid in rows.all()})
    return out


async def _revivable(db: AsyncSession) -> dict[int, frozenset[str]]:
    """Each withdrawn campaign, with the keys of its seed run: the run id and its group."""
    seeds = {
        int(cid): str(seed)
        for cid, seed in (
            await db.execute(
                select(Campaign.id, Campaign.seed_run_id).where(Campaign.status == STATUS_WITHDRAWN)
            )
        ).all()
    }
    groups = await _groups_of(db, seeds.values())
    return {
        cid: frozenset({f"run:{seed}", *([groups[seed]] if seed in groups else [])})
        for cid, seed in seeds.items()
    }


def _detail(draft: CampaignDraft) -> dict[str, Any]:
    return {
        "ladder": jsonable(draft.ladder),
        "waves": jsonable(draft.waves),
        "sessions": jsonable(draft.sessions),
        "named": jsonable(draft.named),
        "detection": jsonable(draft.detection),
        "pairs": sorted([list(pair) for pair in draft.pairs]),
        "edges": jsonable(draft.edges),
    }


def _evidence(link: Link) -> dict[str, Any]:
    data: dict[str, Any] = jsonable(link)
    data.pop("type", None)
    return data


def content_hash(draft: CampaignDraft, earlier: int | None) -> str:
    """A SHA-1 over what a rebuild writes for a draft.

    The title, the bottom line, the stage, the two event times, the earlier
    campaign, each member row, each party row and the other parts of the
    detail. Equal hashes mean equal rows, so a rebuild can leave them.
    """
    content = {
        "title": words.title(draft),
        "bottom_line": words.bottom_line(draft),
        "stage": draft.stage,
        "first_event": draft.first_event.isoformat(),
        "last_event": draft.last_event.isoformat(),
        "earlier": earlier,
        "members": [
            {
                "run_id": m.run.run_id,
                "link": m.link.type,
                "evidence": _evidence(m.link),
                "direction": m.direction,
                "stage": m.stage,
                "verdict_differs": m.verdict_differs,
                "event_time": jsonable(m.run.event_time),
                "actor_key": m.run.source,
                "target_key": m.run.target,
            }
            for m in draft.members
        ],
        "parties": jsonable(draft.parties),
        **_detail(draft),
    }
    text = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha1(text.encode(), usedforsecurity=False).hexdigest()


def _hash_of(row: Campaign) -> str | None:
    detail = row.detail if isinstance(row.detail, dict) else {}
    held = detail.get("hash")
    return held if isinstance(held, str) else None


def _fill(
    row: Campaign, draft: CampaignDraft, now: datetime, *, earlier: int | None, digest: str
) -> None:
    row.status = STATUS_ACTIVE
    row.merged_into_id = None
    row.earlier_campaign_id = earlier
    row.seed_run_id = draft.seed_run_id
    row.title = words.title(draft)[:255]
    row.bottom_line = words.bottom_line(draft)
    row.stage = draft.stage
    row.first_event = draft.first_event
    row.last_event = draft.last_event
    # The members with a true positive verdict: the Members table of the page.
    # A member whose verdict differs is in its own section.
    row.member_count = sum(1 for m in draft.members if not m.verdict_differs)
    row.detail = {**_detail(draft), "hash": digest}
    row.built_at = now


def _rows_of(campaign_id: int, draft: CampaignDraft) -> list[CampaignMember | CampaignParty]:
    out: list[CampaignMember | CampaignParty] = [
        CampaignMember(
            campaign_id=campaign_id,
            run_id=m.run.run_id,
            link=m.link.type,
            evidence=_evidence(m.link),
            direction=m.direction,
            stage=m.stage,
            verdict_differs=m.verdict_differs,
            event_time=m.run.event_time,
            actor_key=m.run.source,
            target_key=m.run.target,
        )
        for m in draft.members
    ]
    out.extend(
        CampaignParty(
            campaign_id=campaign_id,
            machine_key=p.machine_key,
            role=p.role,
            name=p.name,
            addresses=list(p.addresses),
            join_kind=p.join,
            first_event=p.first_event,
            last_event=p.last_event,
            member_runs=p.member_runs,
            beyond=p.beyond,
        )
        for p in draft.parties
    )
    return out


def _earlier(index: int, drafts: Sequence[CampaignDraft], ids: Sequence[int]) -> int | None:
    """The newest other campaign on a pair of the draft that ended before the draft starts.

    The end of the other campaign is the end of its activity
    (:attr:`CampaignDraft.active_until`, round 4, E3): its last event, or a
    later alert of a confirmed rule of one of its investigations. A campaign
    whose alerts go on past the start of the draft did not end before it.
    """
    draft = drafts[index]
    best: int | None = None
    for j, other in enumerate(drafts):
        if j == index or not (other.pairs & draft.pairs) or other.active_until >= draft.first_event:
            continue
        if best is None or (other.active_until, ids[j]) > (drafts[best].active_until, ids[best]):
            best = j
    return ids[best] if best is not None else None


async def _write(
    db: AsyncSession,
    drafts: Sequence[CampaignDraft],
    plan: IdPlan,
    rows: Mapping[int, Campaign],
    now: datetime,
) -> None:
    """Write the drafts. ``rows`` holds the active campaigns and the revived ones."""
    held: list[Campaign] = []
    for draft, campaign_id in zip(drafts, plan.taken, strict=True):
        if campaign_id is None:
            row = Campaign()
            _fill(row, draft, now, earlier=None, digest="")
            db.add(row)
        else:
            row = rows[campaign_id]
        held.append(row)
    # The new rows get their ids: the earlier campaign of a draft can be one.
    await db.flush()
    ids = [row.id for row in held]
    earlier = [_earlier(i, drafts, ids) for i in range(len(drafts))]
    digests = [content_hash(d, e) for d, e in zip(drafts, earlier, strict=True)]
    # An active campaign with the same content keeps its rows and its build time.
    rewrite = [
        i
        for i, row in enumerate(held)
        if not (
            plan.taken[i] is not None
            and row.status == STATUS_ACTIVE
            and _hash_of(row) == digests[i]
        )
    ]
    # What each rewritten campaign held before this rebuild: its stage and its
    # machines. The changes compare the new rows with it.
    before = {
        ids[i]: (held[i].stage, plan.taken[i] in plan.revived)
        for i in rewrite
        if plan.taken[i] is not None
    }
    old_parties = await _party_keys(db, sorted(before))
    # The member and party rows of every campaign that this rebuild rewrites,
    # merges or withdraws go first, as statements. SQLAlchemy inserts before
    # it deletes inside one flush, and a run can move from one campaign to
    # another: the unique index on the run id would refuse the new row.
    gone = sorted(
        {ids[i] for i in rewrite if plan.taken[i] is not None}
        | set(plan.merged)
        | set(plan.withdrawn)
    )
    for chunk in chunked(gone):
        await db.execute(
            delete(CampaignMember)
            .where(CampaignMember.campaign_id.in_(chunk))
            .execution_options(synchronize_session=False)
        )
        await db.execute(
            delete(CampaignParty)
            .where(CampaignParty.campaign_id.in_(chunk))
            .execution_options(synchronize_session=False)
        )
    for i in rewrite:
        _fill(held[i], drafts[i], now, earlier=earlier[i], digest=digests[i])
        db.add_all(_rows_of(ids[i], drafts[i]))
    for old, index in plan.merged.items():
        rows[old].status = STATUS_MERGED
        rows[old].merged_into_id = ids[index]
        rows[old].built_at = now
    for old in plan.withdrawn:
        rows[old].status = STATUS_WITHDRAWN
        rows[old].merged_into_id = None
        rows[old].built_at = now
    db.add_all(_changes(drafts, plan, held, ids, rewrite, before, old_parties, now))
    await db.flush()


async def _party_keys(db: AsyncSession, campaign_ids: Sequence[int]) -> dict[int, set[str]]:
    """The machine keys of the parties of each campaign, as the store holds them now."""
    out: dict[int, set[str]] = {}
    for ids in chunked(list(campaign_ids)):
        rows = await db.execute(
            select(CampaignParty.campaign_id, CampaignParty.machine_key).where(
                CampaignParty.campaign_id.in_(ids)
            )
        )
        for cid, key in rows.all():
            out.setdefault(int(cid), set()).add(str(key))
    return out


def _changes(
    drafts: Sequence[CampaignDraft],
    plan: IdPlan,
    held: Sequence[Campaign],
    ids: Sequence[int],
    rewrite: Sequence[int],
    before: Mapping[int, tuple[str | None, bool]],
    old_parties: Mapping[int, set[str]],
    now: datetime,
) -> list[CampaignChange]:
    """The changes of this rebuild, and the reopen of each decision that it goes past.

    A new campaign is ``formed``. A rewritten campaign that reached a higher
    stage gets ``stage``, and one with a machine that it did not hold gets
    ``party``. A withdrawn campaign that a draft takes again compares its
    stage only: the withdraw removed its party rows. A campaign whose content
    did not change gets nothing, so the first rebuild after the upgrade
    writes no change for a campaign that exists already.

    A campaign with a decision opens again when the draft goes past the basis
    of the decision (:func:`decisions.reopen_cause`): the decision is cleared
    and one ``reopened`` change states the cause and the decision that it
    ended (:func:`decisions.reopen`). A merged campaign passes no
    decision on: the campaign that takes its members keeps its own.
    """
    out: list[CampaignChange] = []
    rewritten = set(rewrite)
    for i, draft in enumerate(drafts):
        row, cid = held[i], ids[i]
        if plan.taken[i] is None:
            out.append(decisions.change(cid, decisions.CHANGE_FORMED, {}, now))
        elif i in rewritten:
            old_stage, revived = before[cid]
            if decisions.stage_rank(draft.stage) > decisions.stage_rank(old_stage):
                out.append(
                    decisions.change(
                        cid, decisions.CHANGE_STAGE, {"from": old_stage, "to": draft.stage}, now
                    )
                )
            known = old_parties.get(cid, set())
            joined = [p for p in draft.parties if p.machine_key not in known]
            if joined and not revived:
                out.append(
                    decisions.change(
                        cid,
                        decisions.CHANGE_PARTY,
                        {"names": [words.party_name(p) for p in joined]},
                        now,
                    )
                )
        if row.decision is None:
            continue
        cause = decisions.reopen_cause(
            row.decision_basis,
            draft.last_event,
            draft.stage,
            (p.machine_key for p in draft.parties),
            decision=row.decision,
        )
        if cause is not None:
            out.append(decisions.reopen(row, cause, now))
    return out


async def overrides(db: AsyncSession) -> tuple[frozenset[str], dict[str, str]]:
    """The investigations that an analyst excluded, and those included with their anchors."""
    rows = await db.execute(
        select(
            CampaignRunOverride.run_id, CampaignRunOverride.type, CampaignRunOverride.anchor_run_id
        )
    )
    excluded: set[str] = set()
    included: dict[str, str] = {}
    for run_id, type_, anchor in rows.all():
        if type_ == OVERRIDE_EXCLUDED:
            excluded.add(str(run_id))
        elif type_ == OVERRIDE_INCLUDED and anchor:
            included[str(run_id)] = str(anchor)
    return frozenset(excluded), included


async def _included_runs(db: AsyncSession, run_ids: Sequence[str]) -> list[Investigation]:
    """The standing investigations among ``run_ids``, with any verdict."""
    out: list[Investigation] = []
    for ids in chunked(sorted(set(run_ids))):
        rows = await db.scalars(
            select(Investigation).where(
                *_standing(), Investigation.verdict.is_not(None), Investigation.id.in_(ids)
            )
        )
        out.extend(rows.all())
    return out


async def _drop_stale_facts(db: AsyncSession, keep: set[str]) -> None:
    """Delete the facts of each run that no scan of this rebuild read."""
    held = set((await db.scalars(select(CampaignRunFacts.run_id))).all())
    for ids in chunked(sorted(held - keep)):
        await db.execute(
            delete(CampaignRunFacts)
            .where(CampaignRunFacts.run_id.in_(ids))
            .execution_options(synchronize_session=False)
        )


def _naive_now(now: datetime | None) -> datetime:
    return naive_utc(now) or utcnow()


async def _pair_lasts(db: AsyncSession) -> dict[str, Mapping[frozenset[str], datetime]]:
    """The last alert event of each pair of the stored grid read of each active campaign.

    Keyed by the run id of each investigation of the campaign whose verdict
    does not differ (E3). ``PairEvents.last_at`` counts the confirmed rules
    only, so an alert of a rule that soc-ai did not confirm gives no time.
    Two reads.
    """
    rows = (
        await db.execute(
            select(Campaign.id, Campaign.events).where(Campaign.status == STATUS_ACTIVE)
        )
    ).all()
    lasts: dict[int, dict[frozenset[str], datetime]] = {}
    for cid, value in rows:
        if not isinstance(value, dict):
            continue
        held = CampaignEvents.from_json(value)
        if held.source != campaign_events.SOURCE_GRID:
            continue
        pairs = {
            frozenset((p.source, p.target)): p.last_at
            for p in held.pairs
            if p.alerts and p.last_at is not None and p.source != p.target
        }
        if pairs:
            lasts[int(cid)] = pairs
    out: dict[str, Mapping[frozenset[str], datetime]] = {}
    for ids in chunked(sorted(lasts)):
        members = await db.execute(
            select(CampaignMember.run_id, CampaignMember.campaign_id).where(
                CampaignMember.campaign_id.in_(ids), CampaignMember.verdict_differs.is_(False)
            )
        )
        for run_id, cid in members.all():
            out[str(run_id)] = lasts[int(cid)]
    return out


def with_activity(
    run: RunFacts, lasts: Mapping[str, Mapping[frozenset[str], datetime]]
) -> RunFacts:
    """The facts of a run with the end of its activity, for the engine (E3).

    A true positive investigation of an active campaign ends its activity at
    the last alert event of a confirmed rule between its two machines that
    the stored grid read of the campaign holds, when that is later than its
    event time. Any other run keeps its facts as they are.
    """
    if (
        not run.is_true_positive
        or run.event_time is None
        or run.source is None
        or run.target is None
        or run.source == run.target
    ):
        return run
    last = lasts.get(run.run_id, {}).get(frozenset((run.source, run.target)))
    if last is None or last <= run.event_time:
        return run
    return dataclasses.replace(run, active_until=last)


async def rebuild(
    db: AsyncSession,
    *,
    dry_run: bool = False,
    refresh_facts: bool = False,
    now: datetime | None = None,
    audit: Any = None,
) -> RebuildResult:
    """Build the campaigns from the stored runs and write them. One commit.

    The read phase writes nothing, so a second writer is never locked out
    while the engine runs. A short write phase then reads the campaigns,
    plans the ids and writes the rows. ``dry_run`` stops after the plan and
    writes nothing: no campaign row and no facts row. ``refresh_facts`` reads
    the facts of every run again, for a change of the Hosts data.

    The rebuild ends the transaction of the session and detaches the objects
    that the session holds.
    """
    at = _naive_now(now)
    runs = await _standing_true_positives(db, at)
    attack_facts, attack_fresh = await facts.read(db, runs, refresh=refresh_facts)
    session_ids = frozenset(cid for f in attack_facts.values() for cid, _at in f.sessions)
    others = await _session_runs(db, session_ids, exclude={inv.id for inv in runs})
    excluded, included = await overrides(db)
    # An investigation that an analyst joined to a campaign is read even when
    # it is on no session of a campaign: the engine needs its facts.
    held = {inv.id for inv in runs} | {inv.id for inv in others}
    others.extend(await _included_runs(db, [r for r in included if r not in held]))
    other_facts, other_fresh = await facts.read(db, others, refresh=refresh_facts)
    basis = await _basis(db, session_ids)
    groups = {inv.id: key for inv in (*runs, *others) if (key := _group_key(inv)) is not None}
    scanned = {inv.id for inv in runs} | {inv.id for inv in others}
    # The later alerts of the investigations of each active campaign (E3).
    # The engine reads them as facts, and the stored facts do not hold them.
    lasts = await _pair_lasts(db)
    # End the read snapshot. In WAL mode a read transaction that turns into a
    # write fails when another writer committed in between. The runs leave
    # the session first, so the rollback does not expire what the facts
    # store reads of them.
    db.expunge_all()
    await db.rollback()
    drafts = await asyncio.to_thread(
        build_campaigns,
        [with_activity(f, lasts) for f in (*attack_facts.values(), *other_facts.values())],
        excluded=excluded,
        included=included,
    )
    unresolved = sum(
        1 for f in attack_facts.values() if f.is_attack and (f.source is None or f.target is None)
    )
    try:
        active = {
            row.id: row
            for row in (
                await db.scalars(select(Campaign).where(Campaign.status == STATUS_ACTIVE))
            ).all()
        }
        owner = await _owners(db, sorted(active))
        group_owner: dict[str, int] = {}
        for run_id, key in (await _groups_of(db, owner)).items():
            group_owner[key] = min(owner[run_id], group_owner.get(key, owner[run_id]))
        plan = plan_ids(
            drafts,
            owner,
            active,
            groups=groups,
            group_owner=group_owner,
            withdrawn=await _revivable(db),
        )
        result = RebuildResult(
            campaigns=len(drafts),
            members=sum(len(d.members) for d in drafts),
            created=sum(1 for campaign_id in plan.taken if campaign_id is None),
            merged=len(plan.merged),
            withdrawn=len(plan.withdrawn),
            unresolved_runs=unresolved,
            drafts=tuple(drafts),
            basis=basis,
            session_ids=session_ids,
            revived=len(plan.revived),
        )
        if dry_run:
            await db.rollback()
            return result
        await facts.store(db, runs, attack_fresh)
        await facts.store(db, others, other_fresh)
        rows = dict(active)
        for campaign_id in plan.revived:
            revived = await db.get(Campaign, campaign_id)
            if revived is not None:
                rows[campaign_id] = revived
        await _write(db, drafts, plan, rows, at)
        await _drop_stale_facts(db, scanned)
        await db.commit()
    except BaseException:
        with contextlib.suppress(Exception):
            await db.rollback()
        raise
    # The campaign records in force mark the inside investigations of their
    # campaigns, and a decided campaign records each new outside one. A
    # failure there gives normal handling and keeps the rebuild.
    await authorization.after_rebuild(db, audit, now=at)
    # The leads and the hunts of each campaign follow the members (D5). A
    # failure there keeps the last tags and the rebuild.
    await lead_tags.after_rebuild(db, now=at)
    # A higher stage and a new machine of a campaign with a case each add one
    # comment to the case. Best effort, outside the rebuild transaction.
    from soc_ai.campaigns import case_comments  # noqa: PLC0415 - imports the tool registry

    await case_comments.after_rebuild(db)
    return result


# ── Freshness ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Fresh:
    """The basis of the last rebuild of one store, and the session ids it read."""

    basis: str
    session_ids: frozenset[str]


# The last rebuild of each store, keyed by the store URL. Empty before the
# first rebuild of the process: the first call then rebuilds.
_LAST: dict[str, _Fresh] = {}
# One lock for each running event loop. A lock binds to its loop, and no lock
# outlives its loop.
_LOCKS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    weakref.WeakKeyDictionary()
)


def reset_fresh_cache() -> None:
    """Forget the last rebuild of each store, the failed grid reads and the locks. For tests."""
    _LAST.clear()
    _LOCKS.clear()
    _READ_FAILED.clear()
    _EVENT_LOCKS.clear()
    _ACTIVITY_CHECKED.clear()
    _NO_END_PAIRS.clear()


def _lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _LOCKS.get(loop)
    if lock is None:
        lock = _LOCKS[loop] = asyncio.Lock()
    return lock


def _store_key(db: AsyncSession) -> str:
    """The URL of the store that the session reads."""
    bind: Any = db.bind
    if isinstance(bind, AsyncConnection):
        bind = bind.engine
    return str(getattr(bind, "url", ""))


async def _basis(db: AsyncSession, session_ids: Iterable[str]) -> str:
    """A SHA-1 over what can change a campaign. Two parts.

    The id, the verdict, the finish time and the resolution time of each
    standing true positive run. And the count and the newest finish time of
    the complete runs with another verdict on one of the sessions. A run on
    no session of a campaign changes no campaign, so it causes no rebuild.
    Each override of an analyst counts too (``campaign_run_overrides``).
    """
    rows = await db.execute(
        select(
            Investigation.id,
            Investigation.verdict,
            Investigation.finished_at,
            Investigation.report[("resolution", "resolved_at")].as_string(),
        )
        .where(*_standing(), Investigation.verdict == TRUE_POSITIVE)
        .order_by(Investigation.id)
    )
    digest = hashlib.sha1(usedforsecurity=False)
    for run_id, verdict, finished, resolved in rows.all():
        digest.update(f"{run_id}|{verdict}|{finished}|{resolved}\n".encode())
    count = 0
    newest: datetime | None = None
    for ids in chunked(sorted(set(session_ids))):
        n, last = (
            await db.execute(
                select(func.count(Investigation.id), func.max(Investigation.finished_at)).where(
                    Investigation.status == "complete",
                    Investigation.verdict.is_not(None),
                    Investigation.verdict != TRUE_POSITIVE,
                    Investigation.community_id.in_(ids),
                )
            )
        ).one()
        count += int(n or 0)
        if last is not None and (newest is None or last > newest):
            newest = last
    digest.update(f"sessions|{count}|{newest}".encode())
    # An exclusion, an inclusion and an undo change a campaign.
    held = await db.execute(
        select(
            CampaignRunOverride.run_id,
            CampaignRunOverride.type,
            CampaignRunOverride.anchor_run_id,
        ).order_by(CampaignRunOverride.run_id)
    )
    for run_id, type_, anchor in held.all():
        digest.update(f"override|{run_id}|{type_}|{anchor}\n".encode())
    return digest.hexdigest()


async def ensure_fresh(db: AsyncSession, *, audit: Any = None) -> bool:
    """Rebuild the campaigns when the store changed. True when the rows are current.

    The first call of the process rebuilds. A failed rebuild logs one warning
    and gives False. The caller then serves the stored rows. ``audit`` takes
    the audit records of the marks that a rebuild sets.
    """
    key = _store_key(db)
    try:
        held = _LAST.get(key)
        if held is not None and await _basis(db, held.session_ids) == held.basis:
            return True
        # End the read snapshot before the wait: the check under the lock and
        # the rebuild read the store as it is then.
        await db.rollback()
        async with _lock():
            held = _LAST.get(key)
            if held is not None and await _basis(db, held.session_ids) == held.basis:
                return True
            result = await rebuild(db, audit=audit)
            _LAST[key] = _Fresh(result.basis, result.session_ids)
            return True
    except Exception:
        _LOGGER.warning(_FRESH_LINE, exc_info=True)
        with contextlib.suppress(Exception):
            await db.rollback()
        return False


# ── Read ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PartyBrief:
    """A party in short: the machine key, the name and the first address."""

    machine_key: str
    name: str | None = None
    address: str | None = None


@dataclass(frozen=True)
class CampaignRow:
    """One campaign of the list."""

    id: int
    title: str
    status: str
    stage: str | None
    actors: tuple[PartyBrief, ...]
    targets: tuple[PartyBrief, ...]
    targets_more: int
    first_event: datetime
    last_event: datetime
    members: int
    # The alert events of the stored grid read, or None before the first read.
    alerts: int | None = None
    # The decision of the analyst, or None. ``waits_since`` is None when the
    # campaign holds a decision or is not active.
    decision: str | None = None
    waits_since: datetime | None = None
    # The time of the stored grid read, and True when the content of the
    # campaign changed after it: the count can be behind (:func:`alerts_behind`).
    alerts_at: datetime | None = None
    alerts_behind: bool = False
    # The authorization that the campaign names: its expiry and its state,
    # and the count of the true positive investigations beyond it.
    authorization_expires_at: datetime | None = None
    authorization_state: str | None = None
    beyond: int = 0
    # The Security Onion case of a campaign with the decision ``case``: its id
    # and the time of the press that opened it. None for any other campaign.
    case_id: str | None = None
    case_opened_at: datetime | None = None
    # What is new since the decision that a reopen ended, or None
    # (:mod:`soc_ai.campaigns.since_decision`).
    since_decision: SinceDecision | None = None
    # The last alert event of a confirmed rule that a grid read saw, or None
    # (``Campaign.last_alert_at``). The status reads the same time.
    last_alert_at: datetime | None = None

    @property
    def state(self) -> str:
        """The one state of the campaign (:func:`api_state`)."""
        return api_state(self.status, self.decision)

    @property
    def last_activity(self) -> datetime:
        """The later of the last investigation event and the last alert event."""
        return last_activity(self.last_event, self.last_alert_at)


@dataclass(frozen=True)
class CampaignRef:
    id: int
    title: str


@dataclass(frozen=True)
class AuthorizationView:
    """An authorization that member runs matched, with the count of those runs.

    ``member_runs`` counts the members whose verdict does not differ: the
    investigations that the campaign holds.
    """

    id: int
    label: str
    state: str
    expires_at: datetime
    member_runs: int


@dataclass(frozen=True)
class PartyView:
    machine_key: str
    name: str | None
    role: str
    addresses: tuple[str, ...]
    join: str | None
    has_agent: bool
    first_event: datetime | None
    last_event: datetime | None
    member_runs: int
    beyond: bool


@dataclass(frozen=True)
class ActorWavesView:
    actor: PartyBrief
    waves: tuple[Wave, ...]


@dataclass(frozen=True)
class EvidenceView:
    member_run_id: str | None
    machine_key: str | None
    machine_name: str | None
    artifact: str | None
    community_id: str | None
    document_ids: tuple[str, ...]


@dataclass(frozen=True)
class MemberView:
    run_id: str
    kind: str
    label: str
    verdict: str | None
    impact: str | None
    stage: str | None
    link: str
    evidence: EvidenceView
    direction: str
    event_at: datetime | None
    finished_at: datetime | None
    tier: str
    source_address: str | None
    target_address: str | None
    verdict_differs: bool
    hunt_id: str | None
    # The machine key of each end of the run, or None for an end that is no machine.
    source_key: str | None
    target_key: str | None
    # True when the authorization mark of the investigation holds, and when an
    # analyst joined it to the campaign.
    authorized: bool = False
    included: bool = False


@dataclass(frozen=True)
class RelatedRun:
    run_id: str
    label: str
    finished_at: datetime | None
    source_address: str | None
    target_address: str | None


@dataclass(frozen=True)
class SessionView:
    source: PartyBrief
    target: PartyBrief
    port: int
    dataset: str | None
    documents: int
    first_at: datetime
    last_at: datetime
    document_ids: tuple[str, ...]


@dataclass(frozen=True)
class CampaignAuthorizationView:
    """The authorization of the campaign: the campaign record of its decision.

    ``inside`` and ``outside`` count the true positive investigations of the
    campaign that the record covers or does not cover.
    """

    id: int
    label: str
    note: str | None
    by: str
    at: datetime
    starts_at: datetime
    expires_at: datetime
    state: str
    machine_keys: tuple[str, ...]
    inside: int = 0
    outside: int = 0


@dataclass(frozen=True)
class BeyondView:
    """One true positive investigation of the campaign that its authorization does not cover."""

    run_id: str
    label: str
    event_at: datetime | None
    source_key: str | None
    target_key: str | None
    why: str


@dataclass(frozen=True)
class ExcludedView:
    """One investigation that an analyst took out of the campaign."""

    run_id: str
    label: str
    by: str
    at: datetime
    reason: str


@dataclass(frozen=True)
class CampaignView:
    """One campaign with its sections. A merged or withdrawn campaign has empty sections."""

    id: int
    title: str
    status: str
    merged_into: int | None
    earlier: CampaignRef | None
    bottom_line: str
    stage: str | None
    first_event: datetime
    last_event: datetime
    built_at: datetime
    authorizations: tuple[AuthorizationView, ...] = ()
    ladder: tuple[StageStep, ...] = ()
    parties: tuple[PartyView, ...] = ()
    waves: tuple[ActorWavesView, ...] = ()
    members: tuple[MemberView, ...] = ()
    needs_more_info: tuple[RelatedRun, ...] = ()
    sessions: tuple[SessionView, ...] = ()
    named: tuple[NamedHost, ...] = ()
    false_positive_from_targets: int = 0
    detection: tuple[Detection, ...] = ()
    edges: tuple[Edge, ...] = ()
    # ``source`` none for a merged or withdrawn campaign.
    events: CampaignEvents = dataclasses.field(default_factory=CampaignEvents)
    decision: decisions.DecisionView | None = None
    waits_since: datetime | None = None
    # The changes of the campaign, the newest first, at most 50.
    changes: tuple[CampaignChange, ...] = ()
    authorization: CampaignAuthorizationView | None = None
    beyond: tuple[BeyondView, ...] = ()
    excluded: tuple[ExcludedView, ...] = ()
    # What is new since the decision that a reopen ended, or None.
    since_decision: SinceDecision | None = None
    # The last alert event of a confirmed rule that a grid read saw, or None
    # (``Campaign.last_alert_at``). The status reads the same time.
    last_alert_at: datetime | None = None

    @property
    def last_activity(self) -> datetime:
        """The later of the last investigation event and the last alert event."""
        return last_activity(self.last_event, self.last_alert_at)


def last_activity(last_event: datetime, last_alert_at: datetime | None) -> datetime:
    """The last activity of a campaign: the later of its last investigation event and its
    last alert event.

    A later alert of a confirmed rule between the machines of a campaign takes
    its verdict from an earlier investigation and gets no investigation of its
    own (:mod:`soc_ai.campaigns.events`). Each surface that states the span or
    the last activity of a campaign states this time.
    """
    if last_alert_at is None:
        return last_event
    return max(last_event, last_alert_at)


def api_status(row: Campaign, now: datetime) -> str:
    """``merged`` and ``withdrawn`` from the store. An active campaign is
    ``ended`` when its last activity is more than one horizon old, else ``open``.

    The owner, 2026-11-19: "A later alert of a confirmed rule keeps a campaign
    open." The last activity is the later of the last investigation event and
    the last alert event of a confirmed rule that a grid read saw
    (``Campaign.last_alert_at``, :func:`last_activity`). An acknowledged alert
    counts. An alert of a rule that soc-ai did not confirm never counts: the
    grid read counts only the confirmed rules. :func:`open_sql` is the same
    rule in SQL.
    """
    return _status_of(row.status, row.last_event, row.last_alert_at, now)


def _horizon() -> timedelta:
    return timedelta(hours=decay_horizon_hours())


def _status_of(
    status: str, last_event: datetime, last_alert_at: datetime | None, now: datetime
) -> str:
    if status != STATUS_ACTIVE:
        return status
    ended = now - last_activity(last_event, last_alert_at) > _horizon()
    return STATUS_ENDED if ended else STATUS_OPEN


def open_sql(now: datetime) -> Any:
    """The SQL of a campaign whose last activity is inside one horizon (:func:`api_status`).

    The status of an active campaign is ``open`` exactly when this holds.
    Two plain comparisons, so SQLite and PostgreSQL read it the same way.
    """
    since = now - _horizon()
    return or_(Campaign.last_event >= since, Campaign.last_alert_at >= since)


def api_state(status: str, decision: str | None) -> str:
    """The one state of a campaign that each page shows.

    ``status`` is the API status (:func:`api_status`). An active campaign
    (``open`` or ``ended``) with a decision in force
    (:func:`decisions.in_force`) states the decision: ``closed``,
    ``authorized`` or ``case``. Else the state is the status. The rule that
    takes a campaign out of Needs you gives the state, so no page shows
    "Open" for a campaign that an analyst closed.
    """
    if status in (STATUS_OPEN, STATUS_ENDED) and decisions.in_force(decision):
        return str(decision)
    return status


@dataclass(frozen=True)
class CampaignLink:
    """The campaign that one investigation is in, as the other pages name it.

    ``status`` is ``open`` or ``ended`` (:func:`api_status`). ``differs`` is
    true for a member whose verdict is no true positive on a session of the
    campaign: a row of "Verdicts that differ" on the campaign page.
    """

    id: int
    title: str
    status: str
    stage: str | None
    differs: bool
    # The decision of the analyst on the campaign, or None.
    decision: str | None = None
    # True for an investigation of an authorized campaign that the
    # authorization does not cover: its mark does not hold. The campaign does
    # not hold it, so it keeps normal handling.
    beyond: bool = False
    # When the analyst made the decision (naive UTC), or None.
    decided_at: datetime | None = None

    @property
    def state(self) -> str:
        """The one state of the campaign (:func:`api_state`)."""
        return api_state(self.status, self.decision)


def _waits(row: Campaign, reopened: Mapping[int, datetime]) -> datetime | None:
    """Since when an active campaign with no decision waits, else None."""
    if row.status != STATUS_ACTIVE:
        return None
    return decisions.waits_since(row.decision, row.first_event, reopened.get(row.id))


def held(link: CampaignLink | None) -> bool:
    """True when a campaign holds the investigation: the analyst decides on the campaign.

    The investigation is a member of an active campaign and its verdict does
    not differ. An investigation in no campaign, and one whose verdict
    differs, keep their own place in Needs you. In an authorized campaign
    only an inside investigation is held: one beyond the authorization keeps
    normal handling (``beyond``). :func:`held_sql` is the same rule in SQL.
    """
    return link is not None and not link.differs and not link.beyond


def held_sql() -> Any:
    """The SQL of :func:`held`: the id of an investigation that a campaign holds."""
    return or_(
        Investigation.id.in_(
            select(CampaignMember.run_id)
            .join(Campaign, Campaign.id == CampaignMember.campaign_id)
            .where(
                Campaign.status == STATUS_ACTIVE,
                CampaignMember.verdict_differs.is_(False),
                or_(
                    Campaign.decision.is_(None),
                    Campaign.decision != decisions.DECISION_AUTHORIZED,
                ),
            )
        ),
        and_(
            Investigation.id.in_(
                select(CampaignMember.run_id)
                .join(Campaign, Campaign.id == CampaignMember.campaign_id)
                .where(
                    Campaign.status == STATUS_ACTIVE,
                    CampaignMember.verdict_differs.is_(False),
                    Campaign.decision == decisions.DECISION_AUTHORIZED,
                )
            ),
            authorized_svc.holds_sql(),
        ),
    )


def _waiting_sql() -> list[Any]:
    return [Campaign.status == STATUS_ACTIVE, Campaign.decision.is_(None)]


async def waiting_count(db: AsyncSession) -> int:
    """The active campaigns with no decision: the ``campaigns`` part of Needs you.

    At any age, open or ended. One read, and no rebuild: the refresh loop
    keeps the rows current.
    """
    return int(await db.scalar(select(func.count(Campaign.id)).where(*_waiting_sql())) or 0)


async def waiting_campaigns(db: AsyncSession) -> list[CampaignRow]:
    """The active campaigns with no decision, the oldest wait first."""
    ids = (await db.scalars(select(Campaign.id).where(*_waiting_sql()))).all()
    rows = await list_campaigns(db, ids=ids)
    return sorted(rows, key=lambda r: (r.waits_since or r.first_event, r.id))


async def links_of(
    db: AsyncSession, run_ids: Iterable[str], *, now: datetime | None = None
) -> dict[str, CampaignLink]:
    """The campaign of each investigation that is a member of an active campaign.

    One read for each chunk of ids, and no rebuild: the refresh loop keeps
    the rows current. An investigation in no campaign, or in a merged or a
    withdrawn campaign only, has no entry.
    """
    at = _naive_now(now)
    out: dict[str, CampaignLink] = {}
    for ids in chunked(sorted({str(r) for r in run_ids if r})):
        rows = await db.execute(
            select(
                CampaignMember.run_id,
                CampaignMember.verdict_differs,
                Campaign.id,
                Campaign.title,
                Campaign.status,
                Campaign.stage,
                Campaign.last_event,
                Campaign.decision,
                Campaign.decided_at,
                Campaign.last_alert_at,
            )
            .join(Campaign, Campaign.id == CampaignMember.campaign_id)
            .where(CampaignMember.run_id.in_(ids), Campaign.status == STATUS_ACTIVE)
        )
        found = rows.all()
        # An investigation of an authorized campaign is beyond when its mark
        # does not hold.
        decided = [str(r[0]) for r in found if r[7] == decisions.DECISION_AUTHORIZED]
        quiet = await _marked(db, decided)
        for (
            run_id,
            differs,
            cid,
            title,
            status,
            stage,
            last_event,
            decision,
            decided_at,
            last_alert_at,
        ) in found:
            out[str(run_id)] = CampaignLink(
                id=int(cid),
                title=str(title),
                status=_status_of(str(status), last_event, last_alert_at, at),
                stage=stage,
                differs=bool(differs),
                decision=decision,
                beyond=decision == decisions.DECISION_AUTHORIZED and str(run_id) not in quiet,
                decided_at=decided_at if decisions.in_force(decision) else None,
            )
    return out


async def links_by_id(
    db: AsyncSession, campaign_ids: Iterable[int | None], *, now: datetime | None = None
) -> dict[int, CampaignLink]:
    """The link of each campaign id that names an active campaign, through its merges.

    A lead and a hunt name their campaign by id (migration 0073). A merged
    campaign reads as the campaign that took it. A withdrawn campaign has no
    entry. ``differs`` is false: the lead and the hunt are of the campaign.
    """
    at = _naive_now(now)
    out: dict[int, CampaignLink] = {}
    for wanted in sorted({int(c) for c in campaign_ids if c is not None}):
        current: int | None = wanted
        for _hop in range(8):
            row = await db.get(Campaign, current) if current is not None else None
            if row is None or row.status not in (STATUS_ACTIVE, STATUS_MERGED):
                break
            if row.status == STATUS_ACTIVE:
                out[wanted] = CampaignLink(
                    id=int(row.id),
                    title=str(row.title),
                    status=api_status(row, at),
                    stage=row.stage,
                    differs=False,
                    decision=row.decision,
                )
                break
            current = row.merged_into_id
    return out


async def _marked(db: AsyncSession, run_ids: Sequence[str]) -> set[str]:
    """The ids among ``run_ids`` whose authorization mark holds."""
    if not run_ids:
        return set()
    rows = await db.scalars(
        select(Investigation.id).where(Investigation.id.in_(run_ids), authorized_svc.holds_sql())
    )
    return {str(r) for r in rows.all()}


# The role of a machine that is an actor and a target of one campaign.
ROLE_BOTH = "both"


@dataclass(frozen=True)
class HostCampaign:
    """One active campaign of one machine, for its host page.

    ``role`` is ``actor``, ``target`` or ``both``. A target is also an actor
    when a true positive member names it as its source. ``differs`` is true
    when each member that names the machine has a verdict that differs.
    ``alerts`` is the alert count of the stored grid read, as in the list.
    """

    id: int
    title: str
    status: str
    stage: str | None
    differs: bool
    role: str
    first_event: datetime
    last_event: datetime
    alerts: int | None
    decision: str | None = None
    # The time of the stored grid read, and whether the count can be behind.
    alerts_at: datetime | None = None
    alerts_behind: bool = False
    # The last alert event of a confirmed rule that a grid read saw, or None
    # (``Campaign.last_alert_at``). The status reads the same time.
    last_alert_at: datetime | None = None

    @property
    def state(self) -> str:
        """The one state of the campaign (:func:`api_state`)."""
        return api_state(self.status, self.decision)

    @property
    def last_activity(self) -> datetime:
        """The later of the last investigation event and the last alert event."""
        return last_activity(self.last_event, self.last_alert_at)


async def campaigns_of_machine(
    db: AsyncSession, machine_keys: Iterable[str], *, now: datetime | None = None
) -> list[HostCampaign]:
    """The active campaigns where one machine is a party, newest last event first.

    ``machine_keys`` holds the key of the machine and each key that a sweep
    merged into it. Three reads, and no rebuild.
    """
    at = _naive_now(now)
    keys = sorted({k for k in machine_keys if k})
    roles: dict[int, set[str]] = {}
    for chunk in chunked(keys):
        rows = await db.execute(
            select(CampaignParty.campaign_id, CampaignParty.role)
            .join(Campaign, Campaign.id == CampaignParty.campaign_id)
            .where(CampaignParty.machine_key.in_(chunk), Campaign.status == STATUS_ACTIVE)
        )
        for cid, role in rows.all():
            roles.setdefault(int(cid), set()).add(str(role))
    if not roles:
        return []
    # The members that name the machine at one end. A true positive member
    # adds the role of its end, so a target that acts as a source is both.
    named: dict[int, list[bool]] = {}
    for ids in chunked(sorted(roles)):
        rows = await db.execute(
            select(
                CampaignMember.campaign_id,
                CampaignMember.verdict_differs,
                CampaignMember.actor_key,
                CampaignMember.target_key,
            ).where(
                CampaignMember.campaign_id.in_(ids),
                or_(CampaignMember.actor_key.in_(keys), CampaignMember.target_key.in_(keys)),
            )
        )
        for cid, differs, actor, target in rows.all():
            named.setdefault(int(cid), []).append(bool(differs))
            if differs:
                continue
            if actor in keys:
                roles[int(cid)].add(ROLE_ACTOR)
            if target in keys:
                roles[int(cid)].add(ROLE_TARGET)
    out: list[HostCampaign] = []
    for ids in chunked(sorted(roles)):
        rows = await db.execute(
            select(
                Campaign.id,
                Campaign.title,
                Campaign.status,
                Campaign.stage,
                Campaign.first_event,
                Campaign.last_event,
                Campaign.events,
                Campaign.decision,
                Campaign.events_at,
                Campaign.built_at,
                Campaign.last_alert_at,
            ).where(Campaign.id.in_(ids))
        )
        for (
            cid,
            title,
            status,
            stage,
            first,
            last,
            events,
            decision,
            read,
            built,
            last_alert,
        ) in rows.all():
            held_roles = roles[int(cid)]
            flags = named.get(int(cid), [])
            out.append(
                HostCampaign(
                    id=int(cid),
                    title=str(title),
                    status=_status_of(str(status), last, last_alert, at),
                    stage=stage,
                    differs=bool(flags) and all(flags),
                    role=ROLE_BOTH
                    if {ROLE_ACTOR, ROLE_TARGET} <= held_roles
                    else (ROLE_ACTOR if ROLE_ACTOR in held_roles else ROLE_TARGET),
                    first_event=first,
                    last_event=last,
                    alerts=_grid_alerts(events),
                    decision=decision,
                    alerts_at=read if _grid_alerts(events) is not None else None,
                    alerts_behind=alerts_behind(events, read, built),
                    last_alert_at=last_alert,
                )
            )
    out.sort(key=lambda c: (c.last_event, c.id), reverse=True)
    return out


def _brief(key: str, party: CampaignParty | None) -> PartyBrief:
    if party is None:
        return PartyBrief(key)
    addresses = party.addresses if isinstance(party.addresses, list) else []
    return PartyBrief(key, party.name, str(addresses[0]) if addresses else None)


async def _parties_of(
    db: AsyncSession, campaign_ids: Sequence[int]
) -> dict[int, list[CampaignParty]]:
    out: dict[int, list[CampaignParty]] = {}
    for ids in chunked(list(campaign_ids)):
        rows = await db.scalars(
            select(CampaignParty)
            .where(CampaignParty.campaign_id.in_(ids))
            .order_by(CampaignParty.campaign_id, CampaignParty.id)
        )
        for party in rows.all():
            out.setdefault(party.campaign_id, []).append(party)
    return out


async def list_campaigns(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    active_only: bool = True,
    ids: Iterable[int] | None = None,
) -> list[CampaignRow]:
    """The campaigns, newest last event first. ``active_only`` False lists every status.

    ``ids`` keeps only the campaigns with those ids.
    """
    at = _naive_now(now)
    query = select(Campaign).order_by(Campaign.last_event.desc(), Campaign.id.desc())
    if active_only:
        query = query.where(Campaign.status == STATUS_ACTIVE)
    if ids is not None:
        wanted = sorted(set(ids))
        if not wanted:
            return []
        rows = [
            row
            for chunk in chunked(wanted)
            for row in (await db.scalars(query.where(Campaign.id.in_(chunk)))).all()
        ]
        rows.sort(key=lambda row: (row.last_event, row.id), reverse=True)
    else:
        rows = list((await db.scalars(query)).all())
    parties = await _parties_of(db, [row.id for row in rows])
    reopened = await decisions.last_reopened(db, [row.id for row in rows])
    # Only a campaign that opened again can state what is new since a decision.
    since = await since_decision.since_decisions(
        db, [row for row in rows if row.id in reopened and row.status == STATUS_ACTIVE]
    )
    records = await _records_of(db, rows, at)
    with_case = [row for row in rows if row.decision == decisions.DECISION_CASE]
    opened = await campaign_case.opened_at(db, with_case)
    out: list[CampaignRow] = []
    for row in rows:
        record = records.get(row.id)
        has_case = row.decision == decisions.DECISION_CASE
        held = parties.get(row.id, [])
        actors = tuple(_brief(p.machine_key, p) for p in held if p.role == ROLE_ACTOR)
        targets = [_brief(p.machine_key, p) for p in held if p.role == ROLE_TARGET]
        out.append(
            CampaignRow(
                id=row.id,
                title=row.title,
                status=api_status(row, at),
                stage=row.stage,
                actors=actors,
                targets=tuple(targets[:MAX_LIST_TARGETS]),
                targets_more=max(0, len(targets) - MAX_LIST_TARGETS),
                first_event=row.first_event,
                last_event=row.last_event,
                members=row.member_count,
                alerts=_grid_alerts(row.events),
                decision=row.decision,
                waits_since=_waits(row, reopened),
                alerts_at=row.events_at if _grid_alerts(row.events) is not None else None,
                alerts_behind=alerts_behind(row.events, row.events_at, row.built_at),
                authorization_expires_at=record[0] if record is not None else None,
                authorization_state=record[1] if record is not None else None,
                beyond=record[2] if record is not None else 0,
                case_id=row.case_id if has_case else None,
                case_opened_at=(opened.get(row.id) or row.decided_at) if has_case else None,
                since_decision=since.get(row.id),
                last_alert_at=row.last_alert_at,
            )
        )
    return out


async def _records_of(
    db: AsyncSession, rows: Sequence[Campaign], now: datetime
) -> dict[int, tuple[datetime, str, int]]:
    """The expiry, the state and the count beyond it of the authorization of each campaign.

    Only a campaign that names a campaign record has an entry. A revoked
    record covers nothing, so nothing is beyond it.
    """
    named = {row.id: row for row in rows if row.authorization_id is not None}
    if not named:
        return {}
    out: dict[int, tuple[datetime, str, int]] = {}
    for campaign_id, row in named.items():
        record = await authorized_svc.get(db, int(row.authorization_id or 0))
        if record is None or record.campaign_id is None:
            continue
        state = authorized_svc.state_of(record, now)
        beyond = 0
        if state != authorized_svc.STATE_REVOKED and row.status == STATUS_ACTIVE:
            scope = authorized_svc.scope_of(record)
            invs = await authorization.true_positive_members(db, campaign_id)
            beyond = len(await authorization.beyond_of(db, scope, invs))
        out[campaign_id] = (scope_expiry(record), state, beyond)
    return out


def scope_expiry(record: Any) -> datetime:
    """The expiry of a record as naive UTC."""
    return authorized_svc.scope_of(record).expires_at


def _grid_alerts(value: Any) -> int | None:
    """The alert count of a stored grid read, or None when the row holds none."""
    if not isinstance(value, Mapping) or value.get("source") != campaign_events.SOURCE_GRID:
        return None
    return _int(value.get("alerts"))


def alerts_behind(events: Any, read_at: datetime | None, built_at: datetime | None) -> bool:
    """True when a stored grid count is older than the content of its campaign (SD5).

    A rebuild that changed the campaign, for example with a new
    investigation, sets ``built_at``. The refresh loop then reads the grid
    (:func:`refresh_behind`). Until the grid answers, the stored count stays,
    and each surface that shows it states the time of the read.
    """
    if _grid_alerts(events) is None or read_at is None or built_at is None:
        return False
    return read_at < built_at


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _ids(value: Any) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str) and v) if isinstance(value, list) else ()


def _items(detail: Mapping[str, Any], name: str) -> list[Mapping[str, Any]]:
    raw = detail.get(name)
    return [item for item in raw if isinstance(item, Mapping)] if isinstance(raw, list) else []


def _ladder(detail: Mapping[str, Any]) -> tuple[StageStep, ...]:
    return tuple(
        StageStep(
            stage=str(item.get("stage") or ""),
            reached=bool(item.get("reached")),
            first_at=naive_utc(item.get("first_at")),
            members=_int(item.get("members")),
            proof_run_id=_text(item.get("proof_run_id")),
            proof_document_id=_text(item.get("proof_document_id")),
            # A ladder of an earlier release has no label and no time.
            proof_label=_text(item.get("proof_label")) or "",
            proof_at=naive_utc(item.get("proof_at")),
        )
        for item in _items(detail, "ladder")
    )


def _waves(
    detail: Mapping[str, Any], parties: Mapping[str, CampaignParty]
) -> tuple[ActorWavesView, ...]:
    out: list[ActorWavesView] = []
    for item in _items(detail, "waves"):
        key = _text(item.get("machine_key"))
        if key is None:
            continue
        waves: list[Wave] = []
        for wave in _items(item, "waves"):
            start, end = naive_utc(wave.get("start")), naive_utc(wave.get("end"))
            if start is not None and end is not None:
                waves.append(Wave(_int(wave.get("n")), start, end, _int(wave.get("events"))))
        out.append(ActorWavesView(_brief(key, parties.get(key)), tuple(waves)))
    return tuple(out)


def _sessions(
    detail: Mapping[str, Any], parties: Mapping[str, CampaignParty]
) -> tuple[SessionView, ...]:
    out: list[SessionView] = []
    for item in _items(detail, "sessions"):
        source, target = _text(item.get("source")), _text(item.get("target"))
        first, last = naive_utc(item.get("first_at")), naive_utc(item.get("last_at"))
        if source is None or target is None or first is None or last is None:
            continue
        out.append(
            SessionView(
                source=_brief(source, parties.get(source)),
                target=_brief(target, parties.get(target)),
                port=_int(item.get("port")),
                dataset=_text(item.get("dataset")),
                documents=_int(item.get("documents")),
                first_at=first,
                last_at=last,
                document_ids=_ids(item.get("document_ids")),
            )
        )
    return tuple(out)


def _named(detail: Mapping[str, Any]) -> tuple[NamedHost, ...]:
    return tuple(
        NamedHost(str(item["value"]), _int(item.get("documents")), _ids(item.get("document_ids")))
        for item in _items(detail, "named")
        if _text(item.get("value"))
    )


def _detection(detail: Mapping[str, Any]) -> tuple[Detection, ...]:
    out: list[Detection] = []
    for item in _items(detail, "detection"):
        event_at, verdict_at = naive_utc(item.get("event_at")), naive_utc(item.get("verdict_at"))
        run_id = _text(item.get("run_id"))
        if event_at is None or verdict_at is None or run_id is None:
            continue
        out.append(
            Detection(
                stage=str(item.get("stage") or ""),
                tier=str(item.get("tier") or ""),
                run_id=run_id,
                event_at=event_at,
                verdict_at=verdict_at,
                seconds=_int(item.get("seconds")),
            )
        )
    return tuple(out)


def _edges(detail: Mapping[str, Any]) -> tuple[Edge, ...]:
    """The arrows of the attack graph. A detail of an earlier release has none."""
    out: list[Edge] = []
    for item in _items(detail, "edges"):
        source, target = _text(item.get("source")), _text(item.get("target"))
        first, last = naive_utc(item.get("first_at")), naive_utc(item.get("last_at"))
        if source is None or target is None or first is None or last is None:
            continue
        stage = _text(item.get("stage"))
        out.append(
            Edge(
                source=source,
                target=target,
                runs=_int(item.get("runs")),
                stage=stage if stage in STAGES else None,
                first_at=first,
                last_at=last,
                beyond=item.get("beyond") is True,
                from_documents=item.get("from_documents") is True,
            )
        )
    return tuple(out)


async def _rows_by_id[T](
    db: AsyncSession, model: type[T], column: Any, ids: Sequence[str]
) -> dict[str, T]:
    out: dict[str, T] = {}
    for chunk in chunked(list(ids)):
        rows = await db.scalars(select(model).where(column.in_(chunk)))
        for row in rows.all():
            out[str(getattr(row, column.key))] = row
    return out


async def _agents(db: AsyncSession, keys: Sequence[str]) -> set[str]:
    """The machine keys of the machines that an agent reports."""
    out: set[str] = set()
    for chunk in chunked(list(keys)):
        rows = await db.execute(
            select(HostMachine.machine_key, HostMachine.agent_id).where(
                HostMachine.machine_key.in_(chunk)
            )
        )
        out.update(str(key) for key, agent_id in rows.all() if agent_id)
    return out


async def _authorizations(
    db: AsyncSession, invs: Iterable[Investigation], now: datetime
) -> tuple[AuthorizationView, ...]:
    counts = Counter(inv.authorization_id for inv in invs if inv.authorization_id is not None)
    out: list[AuthorizationView] = []
    for authorization_id in sorted(counts):
        row = await authorized_svc.get(db, authorization_id)
        if row is None:
            continue
        out.append(
            AuthorizationView(
                id=row.id,
                label=row.label,
                state=authorized_svc.state_of(row, now),
                expires_at=row.expires_at,
                member_runs=counts[authorization_id],
            )
        )
    return tuple(out)


async def _needs_more_info(
    db: AsyncSession, addresses: Sequence[str], members: set[str]
) -> tuple[RelatedRun, ...]:
    """The standing needs-more-info runs between two party addresses that are no member.

    The newest :data:`MAX_RELATED_RUNS` by finish time. The source address
    is read in chunks, and the destination address is checked here.
    """
    parties = set(addresses)
    found: dict[str, Any] = {}
    for chunk in chunked(sorted(parties)):
        rows = await db.execute(
            select(
                Investigation.id,
                Investigation.rule_name,
                Investigation.finished_at,
                Investigation.src_ip,
                Investigation.dest_ip,
                Investigation.report[("follow_up", "id")].as_string(),
            ).where(
                *_standing(),
                Investigation.verdict == _NEEDS_MORE_INFO,
                Investigation.src_ip.in_(chunk),
            )
        )
        for row in rows.all():
            if row.dest_ip in parties and row.id not in members:
                found[str(row.id)] = row
    answers = {run_id: str(row[5]) for run_id, row in found.items() if row[5] and row[5] != run_id}
    answered = await _settled(db, answers.values()) if answers else set()
    kept = sorted(
        (row for run_id, row in found.items() if answers.get(run_id) not in answered),
        key=lambda row: (row.finished_at or datetime.min, str(row.id)),
        reverse=True,
    )
    return tuple(
        RelatedRun(
            run_id=str(row.id),
            label=row.rule_name or "",
            finished_at=row.finished_at,
            source_address=row.src_ip,
            target_address=row.dest_ip,
        )
        for row in kept[:MAX_RELATED_RUNS]
    )


async def _false_positives_from(
    db: AsyncSession, targets: Sequence[str], addresses: Sequence[str]
) -> int:
    """The standing false positive runs from a target to a host that is no party.

    A run with no destination address counts: it names no party.
    """
    parties = set(addresses)
    count = 0
    for chunk in chunked(sorted(set(targets))):
        rows = await db.scalars(
            select(Investigation.dest_ip).where(
                *_standing(),
                Investigation.verdict == _FALSE_POSITIVE,
                Investigation.src_ip.in_(chunk),
            )
        )
        count += sum(1 for dest in rows.all() if dest is None or dest not in parties)
    return count


async def _authorization_of(
    db: AsyncSession, row: Campaign, invs: Sequence[Investigation], now: datetime
) -> tuple[CampaignAuthorizationView | None, tuple[BeyondView, ...]]:
    """The authorization of the campaign, and its true positive investigations beyond it.

    The record is the one that the campaign names, after a revoke too. A
    revoked record covers nothing, so no investigation is beyond it.
    """
    record = (
        await authorized_svc.get(db, row.authorization_id)
        if row.authorization_id is not None
        else None
    )
    if record is None or record.campaign_id is None:
        return None, ()
    scope = authorized_svc.scope_of(record)
    state = authorized_svc.state_of(record, now)
    positives = [i for i in invs if i.verdict == TRUE_POSITIVE and i.status == "complete"]
    beyond: list[BeyondView] = []
    if state != authorized_svc.STATE_REVOKED and row.status == STATUS_ACTIVE:
        for run in await authorization.beyond_of(db, scope, positives):
            ends = run.ends
            beyond.append(
                BeyondView(
                    run_id=run.inv.id,
                    label=run.inv.rule_name or "",
                    event_at=ends.event_time if ends is not None else None,
                    source_key=ends.source_key if ends is not None else None,
                    target_key=ends.target_key if ends is not None else None,
                    why=run.why,
                )
            )
    view = CampaignAuthorizationView(
        id=int(record.id),
        label=record.label,
        note=record.note,
        by=record.created_by,
        at=record.created_at,
        starts_at=scope.starts_at,
        expires_at=scope.expires_at,
        state=state,
        machine_keys=tuple(p.machine_key for p in scope.parties),
        inside=len(positives) - len(beyond),
        outside=len(beyond),
    )
    return view, tuple(beyond)


async def _excluded_of(db: AsyncSession, campaign_id: int) -> tuple[ExcludedView, ...]:
    rows = (
        await db.scalars(
            select(CampaignRunOverride)
            .where(
                CampaignRunOverride.campaign_id == campaign_id,
                CampaignRunOverride.type == OVERRIDE_EXCLUDED,
            )
            .order_by(CampaignRunOverride.created_at.desc(), CampaignRunOverride.id.desc())
        )
    ).all()
    if not rows:
        return ()
    labels = {
        str(i): (name or "")
        for i, name in (
            await db.execute(
                select(Investigation.id, Investigation.rule_name).where(
                    Investigation.id.in_([r.run_id for r in rows])
                )
            )
        ).all()
    }
    return tuple(
        ExcludedView(
            run_id=r.run_id,
            label=labels.get(r.run_id, ""),
            by=r.by,
            at=r.created_at,
            reason=r.reason,
        )
        for r in rows
    )


def _member_view(
    member: CampaignMember,
    run: RunFacts | None,
    inv: Investigation | None,
    parties: Mapping[str, CampaignParty],
) -> MemberView:
    evidence = member.evidence if isinstance(member.evidence, dict) else {}
    machine = _text(evidence.get("machine"))
    party = parties.get(machine) if machine else None
    machine_name = None
    if party is not None:
        machine_name = party.name or _brief(party.machine_key, party).address
    return MemberView(
        run_id=member.run_id,
        kind=run.kind if run is not None else "",
        label=(inv.rule_name or "") if inv is not None else (run.label if run else ""),
        verdict=inv.verdict if inv is not None else None,
        impact=stored_impact(inv.report, inv.verdict) if inv is not None else None,
        stage=member.stage,
        link=member.link,
        evidence=EvidenceView(
            member_run_id=_text(evidence.get("member_run_id")),
            machine_key=machine,
            machine_name=machine_name,
            artifact=_text(evidence.get("artifact")),
            community_id=_text(evidence.get("community_id")),
            document_ids=_ids(evidence.get("document_ids")),
        ),
        direction=member.direction,
        event_at=run.event_time if run is not None else member.event_time,
        finished_at=inv.finished_at if inv is not None else None,
        tier=run.tier if run is not None else "",
        source_address=run.source_address if run is not None else None,
        target_address=run.target_address if run is not None else None,
        verdict_differs=member.verdict_differs,
        hunt_id=inv.hunt_id if inv is not None else (run.hunt_id if run else None),
        source_key=member.actor_key,
        target_key=member.target_key,
        included=member.link == LINK_INCLUDED,
    )


async def get_campaign(
    db: AsyncSession, campaign_id: int, *, now: datetime | None = None
) -> CampaignView | None:
    """One campaign with its sections, or None for an unknown id.

    The member reads take three queries for all members: the stored facts,
    the runs and the machines of the parties.
    """
    at = _naive_now(now)
    row = await db.get(Campaign, campaign_id)
    if row is None:
        return None
    earlier: CampaignRef | None = None
    if row.earlier_campaign_id is not None:
        other = await db.get(Campaign, row.earlier_campaign_id)
        if other is not None:
            earlier = CampaignRef(other.id, other.title)
    view = CampaignView(
        id=row.id,
        title=row.title,
        status=api_status(row, at),
        merged_into=row.merged_into_id,
        earlier=earlier,
        bottom_line=row.bottom_line,
        stage=row.stage,
        first_event=row.first_event,
        last_event=row.last_event,
        built_at=row.built_at,
        last_alert_at=row.last_alert_at if row.status == STATUS_ACTIVE else None,
        decision=decisions.decision_of(row),
        waits_since=_waits(row, await decisions.last_reopened(db, [row.id])),
        changes=tuple(await decisions.changes_of(db, row.id)),
    )
    if row.status != STATUS_ACTIVE:
        held_authorization, _beyond = await _authorization_of(db, row, [], at)
        return dataclasses.replace(view, authorization=held_authorization)

    held = await _held(db, row.id)
    members, party_rows, runs = held.members, held.parties, held.runs
    parties = {p.machine_key: p for p in party_rows}
    run_ids = [m.run_id for m in members]
    invs = await _rows_by_id(db, Investigation, Investigation.id, run_ids)
    agents = await _agents(db, list(parties))

    marks = await authorized_svc.marks_for(db, [inv.authorization_id for inv in invs.values()])
    marked = {
        run_id
        for run_id, inv in invs.items()
        if inv.authorization_id is not None
        and (mark := marks.get(int(inv.authorization_id))) is not None
        and mark.holds
    }
    member_views = sorted(
        (
            dataclasses.replace(
                _member_view(m, runs.get(m.run_id), invs.get(m.run_id), parties),
                authorized=m.run_id in marked,
            )
            for m in members
        ),
        key=lambda v: (v.event_at or datetime.max, v.run_id),
    )
    held_authorization, beyond = await _authorization_of(
        db, row, [invs[m.run_id] for m in members if not m.verdict_differs and m.run_id in invs], at
    )
    addresses = sorted(
        {str(a) for p in party_rows for a in (p.addresses if isinstance(p.addresses, list) else [])}
    )
    targets = sorted(
        {
            str(a)
            for p in party_rows
            if p.role == ROLE_TARGET
            for a in (p.addresses if isinstance(p.addresses, list) else [])
        }
    )
    detail = row.detail if isinstance(row.detail, dict) else {}
    events = await _view_events(db, row, held, view.status, at)
    # The later alert events of the stored read stand when the read counted
    # after the time that the campaign has now (G6). The page states them
    # beside the answer of a hunt, with no new grid read.
    if events.later is not None and events.later.after != await _later_after(db, row):
        events = dataclasses.replace(events, later=None)
    return dataclasses.replace(
        view,
        # The bottom line states the period to the last activity.
        bottom_line=words.with_last_activity(
            row.bottom_line, row.first_event, row.last_event, row.last_alert_at
        ),
        # The line "covers N of the M investigations" counts the investigations
        # that the campaign holds, as the fold "Investigations" does (G5).
        authorizations=await _authorizations(
            db, [invs[m.run_id] for m in members if not m.verdict_differs and m.run_id in invs], at
        ),
        ladder=_ladder(detail),
        parties=tuple(
            PartyView(
                machine_key=p.machine_key,
                name=p.name,
                role=p.role,
                addresses=tuple(str(a) for a in (p.addresses or [])),
                join=p.join_kind,
                has_agent=p.machine_key in agents,
                first_event=p.first_event,
                last_event=p.last_event,
                member_runs=p.member_runs,
                beyond=p.beyond,
            )
            for p in party_rows
        ),
        waves=_waves(detail, parties),
        members=tuple(member_views),
        needs_more_info=await _needs_more_info(db, addresses, set(run_ids)),
        sessions=_sessions(detail, parties),
        named=_named(detail),
        false_positive_from_targets=await _false_positives_from(db, targets, addresses),
        detection=_detection(detail),
        edges=_edges(detail),
        events=events,
        authorization=held_authorization,
        beyond=beyond,
        excluded=await _excluded_of(db, row.id),
        since_decision=await since_decision.since_decision(db, row),
    )


# ── Events ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Held:
    """What the store holds of one active campaign: the member rows, the parties and the facts."""

    members: list[CampaignMember]
    parties: list[CampaignParty]
    runs: dict[str, RunFacts]


async def _held(db: AsyncSession, campaign_id: int) -> _Held:
    members = list(
        (
            await db.scalars(
                select(CampaignMember).where(CampaignMember.campaign_id == campaign_id)
            )
        ).all()
    )
    party_rows = (await _parties_of(db, [campaign_id])).get(campaign_id, [])
    stored = await _rows_by_id(
        db, CampaignRunFacts, CampaignRunFacts.run_id, [m.run_id for m in members]
    )
    runs: dict[str, RunFacts] = {}
    for run_id, fact_row in stored.items():
        if isinstance(fact_row.facts, dict):
            with contextlib.suppress(Exception):
                runs[run_id] = RunFacts.from_json(fact_row.facts)
    return _Held(members, party_rows, runs)


@dataclass(frozen=True)
class _EventsPlan:
    """The pairs of a campaign, the basis of a grid read of them, and the window.

    ``until`` is the end of the read of a campaign that is not ended: the
    read goes to now (:func:`campaign_events.read_window`). None for a
    campaign that ended: its read ends after its last event. ``after`` is
    the time after which the read counts the later alert events
    (:func:`_later_after`), or None for a read that does not count them.
    """

    members: tuple[Member, ...]
    addresses: Mapping[str, tuple[str, ...]]
    pairs: tuple[campaign_events.PairSpec, ...]
    basis: str
    start: datetime
    end: datetime
    until: datetime | None = None
    after: datetime | None = None


def _plan_of(row: Campaign, held: _Held, now: datetime) -> _EventsPlan:
    members = tuple(
        Member(
            run=held.runs[m.run_id],
            link=Link(m.link),
            direction=m.direction,
            stage=m.stage,
            verdict_differs=m.verdict_differs,
        )
        for m in held.members
        if m.run_id in held.runs
    )
    addresses = {
        p.machine_key: tuple(
            str(a) for a in (p.addresses if isinstance(p.addresses, list) else []) if a
        )
        for p in held.parties
    }
    pairs = campaign_events.campaign_pairs(members, addresses)
    until = now if api_status(row, now) == STATUS_OPEN else None
    basis = campaign_events.events_basis(
        pairs, row.first_event, row.last_event, to_now=until is not None
    )
    return _EventsPlan(members, addresses, pairs, basis, row.first_event, row.last_event, until)


def _grid_events(row: Campaign) -> CampaignEvents | None:
    """The events of the stored grid read of a row, or None when it holds none."""
    if not isinstance(row.events, dict):
        return None
    held = CampaignEvents.from_json(row.events)
    return held if held.source == campaign_events.SOURCE_GRID else None


def _wants_read(row: Campaign, basis: str, now: datetime, after: datetime | None = None) -> bool:
    """True when a grid read of the campaign is due.

    A row with no stored grid events reads. An ended campaign with stored
    grid events never reads its events again: the grid forgets old records.
    Its end check reads the horizon after its last activity once more
    (:func:`check_end`). Else a new basis reads, and the stored events of an
    open campaign read again after :data:`EVENTS_MAX_AGE`. A stored count of
    the later alert events after another time than ``after`` reads again
    too: a decision or a reopen moved the time.
    """
    if row.status != STATUS_ACTIVE:
        return False
    held = _grid_events(row)
    if held is None or row.events_at is None:
        return True
    if api_status(row, now) == STATUS_ENDED:
        return False
    if row.events_basis != basis:
        return True
    if after is not None and (held.later is None or held.later.after != after):
        return True
    return now - row.events_at > EVENTS_MAX_AGE


async def _later_after(db: AsyncSession, row: Campaign) -> datetime:
    """After what time an alert event of the campaign is later (G2).

    The newest investigation event of the campaign, or the boundary of a
    decision when that is later: the last event of the basis of a decision
    in force, else the boundary of the decision that a reopen ended
    (:func:`since_decision.boundaries`). An alert that a decision covered is
    no later alert.
    """
    boundary: datetime | None = None
    if decisions.in_force(row.decision):
        basis = row.decision_basis
        boundary = naive_utc(basis.get("last_event")) if isinstance(basis, Mapping) else None
    else:
        boundary = (await since_decision.boundaries(db, [row])).get(row.id)
    return since_decision.later_after(row.last_event, boundary)


# The basis of the last failed grid read of each campaign, keyed by the store
# URL and the campaign id. The page then keeps the older grid events.
_READ_FAILED: dict[tuple[str, int], str] = {}
# One lock for each campaign id and running event loop.
_EVENT_LOCKS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[int, asyncio.Lock]] = (
    weakref.WeakKeyDictionary()
)


def _events_lock(campaign_id: int) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    locks = _EVENT_LOCKS.get(loop)
    if locks is None:
        locks = _EVENT_LOCKS[loop] = {}
    lock = locks.get(campaign_id)
    if lock is None:
        lock = locks[campaign_id] = asyncio.Lock()
    return lock


async def _due(db: AsyncSession, campaign_id: int, now: datetime) -> _EventsPlan | None:
    """The plan of a due grid read, or None. Reads the row as the store holds it now."""
    row = await db.get(Campaign, campaign_id, populate_existing=True)
    if row is None or row.status != STATUS_ACTIVE:
        return None
    plan = _plan_of(row, await _held(db, campaign_id), now)
    if not plan.pairs:
        return None
    plan = dataclasses.replace(plan, after=await _later_after(db, row))
    if not _wants_read(row, plan.basis, now, plan.after):
        return None
    return plan


async def refresh_events(
    db: AsyncSession,
    campaign_id: int,
    elastic: ElasticClient,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> None:
    """Read the events of one campaign from the grid when a read is due, and store them.

    :func:`_wants_read` decides. One lock for each campaign id holds a second
    request back, and that request then finds the read done. The grid read
    holds no transaction of the store. A success writes the three event
    columns and the two columns of the end rule (``last_alert_at``,
    ``events_to``) in one short transaction. A failure leaves the stored
    events as they are. The call never raises.
    """
    at = _naive_now(now)
    key = (_store_key(db), campaign_id)
    try:
        if await _due(db, campaign_id, at) is None:
            return
        # End the read snapshot before the wait: the check under the lock
        # reads the store as it is then.
        await db.rollback()
        async with _events_lock(campaign_id):
            plan = await _due(db, campaign_id, at)
            if plan is None:
                return
            # The grid read can take seconds. It holds no read snapshot, so
            # the write below starts a fresh transaction.
            await db.rollback()
            got = await campaign_events.read_events(
                elastic,
                settings,
                pairs=plan.pairs,
                start=plan.start,
                end=plan.end,
                until=plan.until,
                after=plan.after,
            )
            if got is None:
                _READ_FAILED[key] = plan.basis
                return
            row = await db.get(Campaign, campaign_id, populate_existing=True)
            if row is None or row.status != STATUS_ACTIVE:
                await db.rollback()
                return
            row.events = jsonable(dataclasses.replace(got, read_at=at))
            row.events_at = at
            row.events_basis = plan.basis
            # The two facts of the end rule (:func:`api_status`).
            row.last_alert_at = got.last_alert_at
            row.events_to = got.read_to
            await db.commit()
            _READ_FAILED.pop(key, None)
    except Exception:
        _LOGGER.warning(_EVENTS_LINE, campaign_id, exc_info=True)
        with contextlib.suppress(Exception):
            await db.rollback()


async def refresh_behind(
    db: AsyncSession,
    elastic: ElasticClient,
    settings: Settings,
    *,
    now: datetime | None = None,
    limit: int = EVENTS_REFRESH_MAX,
) -> int:
    """Read the grid for each active campaign whose stored events are behind its content.

    Production, 2026-11-18: a rebuild added six investigations to campaign 2.
    Only a GET of the campaign page read the grid, so the Dashboard row and
    the Needs you row read the older count (1,104) and the page read the new
    one (1,118). The refresh loop calls this step after each rebuild. A
    campaign with no grid read, or with a read older than its content, is a
    candidate. :func:`refresh_events` decides each read and never raises. At
    most ``limit`` reads, the newest content first. A failed read keeps the
    stored count, and the next wake tries again. Returns the reads it asked for.

    A campaign that is not ended reads the grid to now, and later alerts of
    its rules can come with no new investigation. Each such campaign with a
    read older than :data:`EVENTS_MAX_AGE` is a candidate too, after the
    campaigns that are behind, the oldest read first. The same ``limit``
    holds for both.

    Last come the end checks (E2, :func:`check_end`): each ended campaign
    whose grid reads did not cover the horizon after its last activity, the
    oldest end first. A campaign that ended by the rule of an earlier
    release is such a campaign, so no one-time step exists. The same
    ``limit`` holds.
    """
    at = _naive_now(now)
    behind = (
        await db.scalars(
            select(Campaign.id)
            .where(
                Campaign.status == STATUS_ACTIVE,
                or_(Campaign.events_at.is_(None), Campaign.events_at < Campaign.built_at),
            )
            .order_by(Campaign.built_at.desc(), Campaign.id.desc())
        )
    ).all()
    stale = (
        await db.scalars(
            select(Campaign.id)
            .where(
                Campaign.status == STATUS_ACTIVE,
                open_sql(at),
                Campaign.events_at.is_not(None),
                Campaign.events_at < at - EVENTS_MAX_AGE,
            )
            .order_by(Campaign.events_at, Campaign.id)
        )
    ).all()
    ids = list(dict.fromkeys([*behind, *stale]))
    asked = 0
    for campaign_id in ids:
        if asked >= limit:
            break
        if await _due(db, int(campaign_id), at) is None:
            continue
        await db.rollback()
        await refresh_events(db, int(campaign_id), elastic, settings, now=at)
        asked += 1
    # The end check of each ended campaign, the oldest end first (E2).
    for campaign_id in await _ending(db, at):
        if asked >= limit:
            break
        if await _end_due(db, campaign_id, at) is None:
            continue
        await db.rollback()
        await check_end(db, campaign_id, elastic, settings, now=at)
        asked += 1
    return asked


# ── The end check (E2) ─────────────────────────────────────────────────────

# The built time of each ended campaign with no pair of a confirmed rule to
# read, keyed by the store URL and the campaign id. A rebuild that changes the
# campaign gives a new check. The end check then reads no row of it again.
_NO_END_PAIRS: dict[tuple[str, int], datetime] = {}


def ended_sql(now: datetime) -> Any:
    """The SQL of a campaign whose last activity is more than one horizon old.

    The negation of :func:`open_sql`, with the NULL of a campaign that no grid
    read gave an alert time: ``NOT`` of a comparison with NULL selects nothing.
    """
    since = now - _horizon()
    return and_(
        Campaign.last_event < since,
        or_(Campaign.last_alert_at.is_(None), Campaign.last_alert_at < since),
    )


@dataclass(frozen=True)
class _EndCheck:
    """The end check of one ended campaign: the pairs of its confirmed rules and the window.

    ``after`` is the last activity of the campaign, and ``until`` is
    ``min(now, after + horizon)``.
    """

    campaign_id: int
    pairs: tuple[campaign_events.PairSpec, ...]
    after: datetime
    until: datetime


def _end_window(
    status: str,
    last_event: datetime,
    last_alert_at: datetime | None,
    events_to: datetime | None,
    read: bool,
    now: datetime,
) -> tuple[datetime, datetime] | None:
    """The window of the end check of a campaign, or None when no check is due.

    A check is due for an active campaign that ended by :func:`api_status`,
    that holds a grid read, and whose grid reads end before
    ``min(now, last activity + horizon)``. A campaign with no grid read waits
    for its first read (:func:`refresh_behind`). A read of an earlier release
    states no end of its window, so its check is due.
    """
    if status != STATUS_ACTIVE or not read:
        return None
    if _status_of(status, last_event, last_alert_at, now) != STATUS_ENDED:
        return None
    after = last_activity(last_event, last_alert_at)
    until = min(now, after + _horizon())
    if events_to is not None and events_to >= until:
        return None
    return after, until


async def _ending(db: AsyncSession, now: datetime) -> list[int]:
    """The ended campaigns whose end check is due, the oldest end first. One read."""
    rows = (
        await db.execute(
            select(
                Campaign.id,
                Campaign.status,
                Campaign.last_event,
                Campaign.last_alert_at,
                Campaign.events_to,
            ).where(
                Campaign.status == STATUS_ACTIVE,
                ended_sql(now),
                Campaign.events_at.is_not(None),
            )
        )
    ).all()
    due: list[tuple[datetime, int]] = []
    for cid, status, last_event, last_alert, events_to in rows:
        window = _end_window(str(status), last_event, last_alert, events_to, True, now)
        if window is not None:
            due.append((window[0], int(cid)))
    return [cid for _after, cid in sorted(due)]


async def _end_due(db: AsyncSession, campaign_id: int, now: datetime) -> _EndCheck | None:
    """The end check of one campaign when it is due, or None.

    Reads the row as the store holds it now.
    """
    row = await db.get(Campaign, campaign_id, populate_existing=True)
    if row is None:
        return None
    window = _end_window(
        row.status,
        row.last_event,
        row.last_alert_at,
        row.events_to,
        row.events_at is not None and _grid_events(row) is not None,
        now,
    )
    if window is None:
        return None
    key = (_store_key(db), campaign_id)
    if _NO_END_PAIRS.get(key) == row.built_at:
        return None
    pairs = tuple(
        p
        for p in _plan_of(row, await _held(db, campaign_id), now).pairs
        if p.confirmed and p.source_addresses and p.target_addresses
    )
    if not pairs:
        _NO_END_PAIRS[key] = row.built_at
        return None
    return _EndCheck(campaign_id, pairs, *window)


async def check_end(
    db: AsyncSession,
    campaign_id: int,
    elastic: ElasticClient,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> None:
    """Read the horizon after the last activity of an ended campaign once more (E2).

    A campaign must not end on a grid read that did not cover the horizon
    after its last activity. A read of an open campaign each
    :data:`EVENTS_MAX_AGE` can end before that horizon, and a read of an
    earlier release ended 30 minutes after the last investigation event. One
    grid read (:func:`campaign_events.read_end`) reads the alert events of the
    confirmed rules after the last activity, until ``min(now, last activity +
    horizon)``. A found alert moves ``last_alert_at``, and :func:`api_status`
    decides again: the campaign is open when the new last activity is inside
    one horizon of now, else the next wake checks the next horizon. With no
    alert the read covers the horizon, ``events_to`` moves to its end, and no
    later wake reads the campaign again.

    The check writes only ``last_alert_at`` and ``events_to``, in one short
    transaction. A grid that does not answer changes nothing, and the next
    wake tries again. One lock for each campaign id holds a grid read of the
    same campaign back. The call never raises.
    """
    at = _naive_now(now)
    try:
        if await _end_due(db, campaign_id, at) is None:
            return
        await db.rollback()
        async with _events_lock(campaign_id):
            check = await _end_due(db, campaign_id, at)
            if check is None:
                return
            # The grid read holds no read snapshot of the store.
            await db.rollback()
            found = await campaign_events.read_end(
                elastic, settings, pairs=check.pairs, after=check.after, until=check.until
            )
            if found is None:
                return
            row = await db.get(Campaign, campaign_id, populate_existing=True)
            if (
                row is None
                or row.status != STATUS_ACTIVE
                or last_activity(row.last_event, row.last_alert_at) != check.after
            ):
                # The campaign changed during the read. The next wake checks again.
                await db.rollback()
                return
            if found.last_at is not None and found.last_at > check.after:
                row.last_alert_at = found.last_at
            row.events_to = check.until
            await db.commit()
    except Exception:
        _LOGGER.warning(_END_CHECK_LINE, campaign_id, exc_info=True)
        with contextlib.suppress(Exception):
            await db.rollback()


# The stored grid read of each closed campaign that the last activity check
# read after, keyed by the store URL and the campaign id (G4). A new grid
# read of the campaign gives a new check.
_ACTIVITY_CHECKED: dict[tuple[str, int], datetime] = {}


@dataclass(frozen=True)
class _Check:
    """What the activity check of one closed campaign needs, read before the grid read."""

    campaign_id: int
    events_at: datetime
    basis: dict[str, Any]
    covered: datetime
    pairs: tuple[campaign_events.PairSpec, ...]


def _covered_later(row: Campaign) -> tuple[datetime, frozenset[str]] | None:
    """The time that the close covers and the machines of its basis, when the stored grid
    read holds a later alert of the campaign. Else None.

    The stored read counts the alert events of the confirmed rules after
    the time that the close covers (:func:`_later_after`). With none, no
    grid read is due. A read that counted after another time is older than
    the decision, and the next read gives the count.
    """
    stored = _grid_events(row)
    basis = row.decision_basis
    if stored is None or row.events_at is None or not isinstance(basis, Mapping):
        return None
    covered = naive_utc(basis.get("last_event"))
    parties = basis.get("parties")
    if covered is None or not isinstance(parties, list):
        return None
    later = stored.later
    if later is None or not later.known or later.alerts <= 0:
        return None
    if later.after != since_decision.later_after(row.last_event, covered):
        return None
    return covered, frozenset(str(key) for key in parties)


async def _reopen_for_activity(
    db: AsyncSession,
    check: _Check,
    found: campaign_events.Activity,
    now: datetime,
) -> bool:
    """Open a closed campaign again with the cause ``activity``. One short transaction.

    The rebuild lock holds a rebuild back, and the row is read as the store
    holds it now. A campaign that is no longer closed, or whose close
    changed, keeps its state.
    """
    async with _lock():
        row = await db.get(Campaign, check.campaign_id, populate_existing=True)
        if (
            row is None
            or row.status != STATUS_ACTIVE
            or row.decision != decisions.DECISION_CLOSED
            or row.decision_basis != check.basis
        ):
            await db.rollback()
            return False
        db.add(
            decisions.reopen(
                row,
                decisions.CAUSE_ACTIVITY,
                now,
                alerts=found.alerts,
                rules=found.rules,
                firstAlertAt=found.first_at.isoformat() if found.first_at else None,
                lastAlertAt=found.last_at.isoformat() if found.last_at else None,
            )
        )
        await db.commit()
    return True


async def reopen_on_activity(
    db: AsyncSession,
    elastic: ElasticClient,
    settings: Settings,
    *,
    now: datetime | None = None,
    limit: int = EVENTS_REFRESH_MAX,
) -> int:
    """Open each closed campaign again whose activity goes on with no new investigation (G4).

    A later alert of a confirmed rule between the machines of a campaign
    takes its verdict from an earlier investigation, so no rebuild sees it.
    The refresh loop calls this step. A closed campaign that is not ended is
    a candidate when its stored grid read holds alert events of its
    confirmed rules after the time that the close covers. One grid read
    (:func:`campaign_events.read_activity`) then reads the alert events of
    those rules after that time, between the machines of the basis, that
    Security Onion has not acknowledged. With one or more, the campaign
    opens again with the cause ``activity``, as a rebuild does.

    An authorized decision and a case decision never open again here. A
    grid that does not answer opens nothing, and the next grid read of the
    campaign gives a new check. At most ``limit`` reads. Returns the reads
    it asked for.
    """
    at = _naive_now(now)
    rows = (
        await db.scalars(
            select(Campaign)
            .where(
                Campaign.status == STATUS_ACTIVE,
                Campaign.decision == decisions.DECISION_CLOSED,
                open_sql(at),
                Campaign.events_at.is_not(None),
            )
            .order_by(Campaign.events_at.desc(), Campaign.id)
        )
    ).all()
    store = _store_key(db)
    checks: list[_Check] = []
    for row in rows:
        if row.events_at is None or _ACTIVITY_CHECKED.get((store, row.id)) == row.events_at:
            continue
        held = _covered_later(row)
        if held is None:
            continue
        covered, machines = held
        # The pairs whose two machines the basis holds.
        pairs = tuple(
            p
            for p in _plan_of(row, await _held(db, row.id), at).pairs
            if p.source in machines and p.target in machines
        )
        basis = dict(row.decision_basis) if isinstance(row.decision_basis, Mapping) else {}
        checks.append(_Check(row.id, row.events_at, basis, covered, pairs))
    # The grid reads hold no transaction of the store.
    await db.rollback()
    asked = 0
    for check in checks:
        if asked >= limit:
            break
        if check.pairs:
            asked += 1
        found = await campaign_events.read_activity(
            elastic, settings, pairs=check.pairs, after=check.covered, until=at
        )
        # A failed read waits for the next grid read of the campaign.
        _ACTIVITY_CHECKED[(store, check.campaign_id)] = check.events_at
        if found is not None and found.alerts > 0:
            await _reopen_for_activity(db, check, found, at)
    return asked


def _page_read_to(
    row: Campaign, plan: _EventsPlan, key: tuple[str, int], now: datetime
) -> datetime | None:
    """The end of the grid read that the page of an open campaign states, or None.

    None for a campaign that ended, and for a page that states the events
    that the investigations hold or a read of an earlier release: the close
    then keeps the rule of today, the last event plus the pad.
    """
    status = api_status(row, now)
    if status != STATUS_OPEN:
        return None
    current = _current_events(row, plan, key, status)
    if current.source != campaign_events.SOURCE_GRID or current.read_to is None:
        return None
    return current.read_to if current.read_to > row.last_event else None


def _covered_to(row: Campaign) -> datetime | None:
    """The time that the close of a campaign covers, when it is after the last event.

    A close of an open campaign records the end of the grid read that the
    page stated as the last event of its basis (:func:`close_basis`). A close
    of an earlier release, or of a campaign that ended, recorded the last
    event: None, the rule of today.
    """
    if row.decision != decisions.DECISION_CLOSED or not isinstance(row.decision_basis, Mapping):
        return None
    covered = naive_utc(row.decision_basis.get("last_event"))
    return covered if covered is not None and covered > row.last_event else None


async def close_basis(
    db: AsyncSession, row: Campaign, *, now: datetime | None = None
) -> dict[str, Any]:
    """The basis of a close of a campaign: what the page states (G3).

    The last event of the basis is the end of the grid read that the page
    states, when that is after the last investigation event: the close
    covers the later alert events that the page shows. Else it is the last
    investigation event, as before.
    """
    at = _naive_now(now)
    basis = await decisions.basis_for(db, row)
    plan = _plan_of(row, await _held(db, row.id), at)
    until = _page_read_to(row, plan, (_store_key(db), row.id), at)
    if until is not None:
        basis["last_event"] = until.isoformat()
    return basis


async def close_scope(
    db: AsyncSession,
    campaign_id: int,
    elastic: ElasticClient,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> campaign_events.CloseScope | None:
    """The alert events that a close of one campaign acknowledges, or None for an unknown id.

    The pairs and the confirmed rules of the campaign, in its period
    (:func:`campaign_events.read_close_scope`). A campaign that is not active
    acknowledges nothing. The grid read holds no transaction of the store.

    The scope ends where the page ends (G3). For a closed campaign that is
    the time of its basis (:func:`close_basis`), so the acknowledge after the
    close and the route "Acknowledge" take no alert after the decision. For
    a campaign with no decision it is the end of the grid read that the page
    states. A campaign that ended keeps the rule of today.
    """
    at = _naive_now(now)
    row = await db.get(Campaign, campaign_id, populate_existing=True)
    if row is None:
        return None
    if row.status != STATUS_ACTIVE:
        return campaign_events.CloseScope(alerts=0, rules=0)
    plan = _plan_of(row, await _held(db, campaign_id), at)
    if row.decision == decisions.DECISION_CLOSED:
        until = _covered_to(row)
    else:
        until = _page_read_to(row, plan, (_store_key(db), row.id), at)
    await db.rollback()
    return await campaign_events.read_close_scope(
        elastic, settings, pairs=plan.pairs, start=plan.start, end=plan.end, until=until
    )


def _current_events(
    row: Campaign, plan: _EventsPlan, key: tuple[str, int], status: str
) -> CampaignEvents:
    """The stored grid events, or the events that the investigations hold.

    The stored grid events stand when their basis is current, when the last
    grid read of the current basis failed, and for an ended campaign: an
    ended campaign does not read the grid again.
    """
    held = _grid_events(row)
    if held is not None and (
        row.events_basis == plan.basis
        or _READ_FAILED.get(key) == plan.basis
        or status == STATUS_ENDED
    ):
        return dataclasses.replace(
            held,
            read_at=row.events_at or held.read_at,
            findings=campaign_events.findings_of(plan.members),
        )
    return campaign_events.stored_events(plan.members, plan.addresses)


# The verdicts that the store can give a rule that is no confirmed rule, first wins.
_JUDGED = (_FALSE_POSITIVE, _NEEDS_MORE_INFO)


async def _judge(
    db: AsyncSession, events: CampaignEvents, addresses: Mapping[str, Sequence[str]]
) -> CampaignEvents:
    """Give each rule that is no confirmed rule its verdict in the store. One read.

    The standing investigations with that rule name between an address of
    one machine of the pair and an address of the other: false positive,
    needs more info, else ``not_judged``.
    """
    names = sorted(
        {
            r.name
            for p in events.pairs
            for r in p.rules
            if r.verdict != campaign_events.VERDICT_CONFIRMED
        }
    )
    wanted = sorted(
        {a for p in events.pairs for k in (p.source, p.target) for a in addresses.get(k, ())}
    )
    if not names or not wanted:
        return events
    found: dict[str, set[tuple[str, str | None, str | None]]] = {}
    for name_chunk in chunked(names):
        for address_chunk in chunked(wanted):
            rows = await db.execute(
                select(
                    Investigation.rule_name,
                    Investigation.verdict,
                    Investigation.src_ip,
                    Investigation.dest_ip,
                ).where(
                    *_standing(),
                    Investigation.verdict.in_(_JUDGED),
                    Investigation.rule_name.in_(name_chunk),
                    Investigation.src_ip.in_(address_chunk),
                )
            )
            for rule_name, verdict, src, dest in rows.all():
                found.setdefault(authorized_svc.rule_name_key(rule_name), set()).add(
                    (str(verdict), src, dest)
                )

    def verdict_of(rule: RuleEvents, a: set[str], b: set[str]) -> str:
        if rule.verdict == campaign_events.VERDICT_CONFIRMED:
            return rule.verdict
        seen = {
            verdict
            for verdict, src, dest in found.get(authorized_svc.rule_name_key(rule.name), set())
            if (src in a and dest in b) or (src in b and dest in a)
        }
        return next((v for v in _JUDGED if v in seen), campaign_events.VERDICT_NOT_JUDGED)

    pairs: list[PairEvents] = []
    for pair in events.pairs:
        a, b = set(addresses.get(pair.source, ())), set(addresses.get(pair.target, ()))
        rules = tuple(dataclasses.replace(r, verdict=verdict_of(r, a, b)) for r in pair.rules)
        pairs.append(dataclasses.replace(pair, rules=rules))
    return dataclasses.replace(events, pairs=tuple(pairs))


async def _view_events(
    db: AsyncSession, row: Campaign, held: _Held, status: str, now: datetime
) -> CampaignEvents:
    plan = _plan_of(row, held, now)
    current = _current_events(row, plan, (_store_key(db), row.id), status)
    return await _judge(db, current, plan.addresses)


__all__ = [
    "CAMPAIGN_SCAN_MAX",
    "ActorWavesView",
    "AuthorizationView",
    "CampaignLink",
    "CampaignRef",
    "CampaignRow",
    "CampaignView",
    "EvidenceView",
    "HostCampaign",
    "IdPlan",
    "MemberView",
    "PartyBrief",
    "PartyView",
    "RebuildResult",
    "RelatedRun",
    "SessionView",
    "alerts_behind",
    "api_state",
    "api_status",
    "campaigns_of_machine",
    "check_end",
    "close_basis",
    "close_scope",
    "ended_sql",
    "ensure_fresh",
    "get_campaign",
    "held",
    "held_sql",
    "last_activity",
    "links_by_id",
    "links_of",
    "list_campaigns",
    "open_sql",
    "plan_ids",
    "rebuild",
    "refresh_behind",
    "refresh_events",
    "reopen_on_activity",
    "request_refresh",
    "reset_fresh_cache",
    "waiting_campaigns",
    "waiting_count",
    "with_activity",
]
