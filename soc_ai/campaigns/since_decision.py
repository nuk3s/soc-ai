"""What is new in a campaign since the decision that a reopen ended (SD2).

Production, 2026-11-18: the analyst closed campaign 2 on 2026-11-15 with the
reason "Test that is over". Three days later one actor of the campaign sent
new exploit requests to the target, soc-ai gave five true positive verdicts
and one false positive, and the rebuild opened the campaign again. Needs you
then read "The campaign has no decision." and the campaign page read "This
campaign waits on your decision since ...". No page stated the earlier close
or what was new, so the analyst had to find the new events by hand.

:func:`since_decisions` is the one reader of that difference. The campaign
payload, the rows of the campaign list, the Needs you item, the Confirmed
threats row and the bell line all read it. No surface computes its own.

The rules:

- No answer for a campaign with a decision in force
  (:func:`decisions.in_force`), and none for a campaign with no ``reopened``
  change: it never had a decision that ended.
- The earlier decision is ``was`` of the newest ``reopened`` change
  (:func:`decisions.was_of`). A change of an earlier release holds no
  ``was``: the newest ``decided`` change between the reopen before it and
  this one gives the decision, the reason, the analyst and the time, and a
  ``case`` change in that span gives a case decision. The note of such a
  decision is unknown, so no surface states one.
- The boundary is the last event of the basis of the earlier decision, else
  the time of the decision.
- An investigation of the campaign is new when its event is after the
  boundary. The time of the investigation does not count: an old event that
  soc-ai investigated later is not new.
- The stage before is the stage of the basis, else the ``from`` of the first
  ``stage`` change after the decision. A rebuild writes a ``stage`` change
  for each higher stage, so with neither the stage did not change. The new
  machines are the parties that the basis does not hold, else the names of
  the ``party`` changes after the decision.

The words of the server surfaces (the ``why`` of Needs you and the bell line)
live here too, so one module states the difference. The console words are in
``frontend/src/lib/campaignWords.ts``.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns import decisions
from soc_ai.campaigns.events import SOURCE_GRID, CampaignEvents
from soc_ai.campaigns.facts import chunked
from soc_ai.campaigns.types import ROLE_ACTOR, ROLE_TARGET, STAGES, naive_utc
from soc_ai.campaigns.words import stage_words
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store.models import (
    Campaign,
    CampaignChange,
    CampaignMember,
    CampaignParty,
    Investigation,
)

# Where the boundary comes from: the basis of the decision, or its time.
BOUNDARY_BASIS = "basis"
BOUNDARY_DECISION = "decision"

# The order of the verdicts in a count. A verdict that is not listed comes last.
_VERDICT_ORDER = ("true_positive", "false_positive", "needs_more_info", "inconclusive")
_TRUE_POSITIVE = "true_positive"
# The changes that this module reads.
_READ = (
    decisions.CHANGE_DECIDED,
    decisions.CHANGE_CASE,
    decisions.CHANGE_REOPENED,
    decisions.CHANGE_STAGE,
    decisions.CHANGE_PARTY,
)


@dataclass(frozen=True)
class Machine:
    """One machine of the new investigations: its key, its name and its first address."""

    key: str
    name: str | None = None
    address: str | None = None

    @property
    def words(self) -> str:
        """The name, else the address, else the key."""
        return self.name or self.address or self.key


@dataclass(frozen=True)
class EarlierDecision:
    """The decision that the reopen ended.

    ``label`` is the words of the reason: the reason of a close, or the label
    of an authorization. ``note_known`` is False for a decision of a change
    of an earlier release: its note is unknown.
    """

    decision: str
    reason: str | None = None
    label: str | None = None
    note: str | None = None
    note_known: bool = True
    by: str | None = None
    at: datetime | None = None


@dataclass(frozen=True)
class Holding:
    """One authorization that holds new investigations (W1).

    ``state`` is ``active``, ``expired`` or ``revoked``
    (:func:`soc_ai.store.authorized_activity.state_of`). ``investigations``
    counts the new investigations whose mark it is.
    """

    id: int
    label: str
    state: str
    expires_at: datetime | None
    investigations: int


@dataclass(frozen=True)
class SinceDecision:
    """What is new in a campaign since the earlier decision.

    ``run_ids`` are the new investigations, the oldest event first, with any
    verdict. ``verdicts`` counts them by verdict, the true positives first.
    ``authorized`` counts those whose authorization mark holds. ``actors``
    and ``targets`` are their machines. ``rules`` counts the distinct rules
    of the new alert investigations. ``stage`` is the highest stage among
    them. ``stage_before`` and ``stage_now`` are the stage of the campaign at
    the decision and now. ``new_machines`` names each machine that the
    earlier decision did not hold.

    Round 3 part 2, W1: the banner read "An authorization holds 3" and did
    not name what is outside it. ``outside`` counts the new true positive
    investigations that no authorization mark holds, and ``outside_names``
    holds their distinct rule names, the oldest event first. For a finding
    investigation the rule name is the title of the finding. ``holding``
    lists each authorization that holds new investigations, the most first.
    """

    campaign_id: int
    earlier: EarlierDecision
    cause: str
    reopened_at: datetime
    reopened_by: str | None
    boundary: datetime
    boundary_source: str
    run_ids: tuple[str, ...] = ()
    verdicts: tuple[tuple[str, int], ...] = ()
    authorized: int = 0
    actors: tuple[Machine, ...] = ()
    targets: tuple[Machine, ...] = ()
    rules: int = 0
    first_event: datetime | None = None
    last_event: datetime | None = None
    stage: str | None = None
    stage_before: str | None = None
    stage_now: str | None = None
    new_machines: tuple[str, ...] = ()
    outside: int = 0
    outside_names: tuple[str, ...] = ()
    holding: tuple[Holding, ...] = ()
    # The alert events of the confirmed rules after the newest investigation
    # event, or after the boundary when it is later (G2): the count, the
    # count of the rules and the time of the last. They take the verdict of
    # an earlier investigation. 0 and None when the stored grid read holds
    # none or is older than the campaign.
    later_alerts: int = 0
    later_rules: int = 0
    later_last_at: datetime | None = None

    @property
    def investigations(self) -> int:
        """The count of the new investigations."""
        return len(self.run_ids)

    @property
    def stage_rose(self) -> bool:
        """True when the stage of the campaign is higher than at the decision."""
        return decisions.stage_rank(self.stage_now) > decisions.stage_rank(self.stage_before)


# ── The plan of one campaign: its changes ──────────────────────────────────


@dataclass(frozen=True)
class _Plan:
    earlier: EarlierDecision
    cause: str
    reopened_at: datetime
    reopened_by: str | None
    boundary: datetime
    boundary_source: str
    # The parties that the basis holds, or None when no basis holds them.
    covered: frozenset[str] | None
    stage_before: str | None
    # The names of the ``party`` changes after the decision, for a decision with no basis.
    joined: tuple[str, ...]


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _stage(value: Any) -> str | None:
    return value if isinstance(value, str) and value in STAGES else None


def _detail(change: CampaignChange) -> dict[str, Any]:
    return change.detail if isinstance(change.detail, dict) else {}


def _from_was(was: Mapping[str, Any]) -> EarlierDecision | None:
    decision = _text(was.get("decision"))
    if decision is None:
        return None
    reason = _text(was.get("reason"))
    label = decisions.REASONS.get(reason or "") or _text(was.get("label"))
    return EarlierDecision(
        decision=decision,
        reason=reason,
        label=label,
        note=_text(was.get("note")),
        by=_text(was.get("by")),
        at=naive_utc(was.get("decidedAt")),
    )


def _from_changes(span: Sequence[CampaignChange]) -> EarlierDecision | None:
    """The decision of a change of an earlier release: the newest in the span."""
    for change in reversed(span):
        detail = _detail(change)
        if change.type == decisions.CHANGE_DECIDED:
            decision = _text(detail.get("decision"))
            if decision is None:
                continue
            reason = _text(detail.get("reason"))
            return EarlierDecision(
                decision=decision,
                reason=reason,
                label=decisions.REASONS.get(reason or "") or _text(detail.get("label")),
                note_known=False,
                by=_text(detail.get("by")),
                at=change.created_at,
            )
        if change.type == decisions.CHANGE_CASE and _text(detail.get("by")):
            return EarlierDecision(
                decision=decisions.DECISION_CASE,
                note_known=False,
                by=_text(detail.get("by")),
                at=change.created_at,
            )
    return None


def _plan(row: Campaign, changes: Sequence[CampaignChange]) -> _Plan | None:
    """The plan of one campaign from its changes, the oldest first, or None."""
    reopens = [i for i, c in enumerate(changes) if c.type == decisions.CHANGE_REOPENED]
    if not reopens:
        return None
    last = reopens[-1]
    reopened = changes[last]
    detail = _detail(reopened)
    was = detail.get("was")
    basis: Mapping[str, Any] | None = None
    earlier: EarlierDecision | None = None
    if isinstance(was, Mapping):
        earlier = _from_was(was)
        held = was.get("basis")
        basis = held if isinstance(held, Mapping) else None
    if earlier is None:
        start = reopens[-2] + 1 if len(reopens) > 1 else 0
        earlier = _from_changes(changes[start:last])
    if earlier is None:
        return None
    covered_at = naive_utc(basis.get("last_event")) if basis is not None else None
    decided_at = earlier.at or reopened.created_at
    boundary, source = (
        (covered_at, BOUNDARY_BASIS) if covered_at is not None else (decided_at, BOUNDARY_DECISION)
    )
    after = [c for c in changes if c.created_at >= decided_at]
    parties = basis.get("parties") if basis is not None else None
    covered = frozenset(str(k) for k in parties) if isinstance(parties, list) else None
    if basis is not None and "stage" in basis:
        stage_before = _stage(basis.get("stage"))
    else:
        rises = [c for c in after if c.type == decisions.CHANGE_STAGE]
        stage_before = _stage(_detail(rises[0]).get("from")) if rises else row.stage
    joined: list[str] = []
    for change in after:
        if change.type == decisions.CHANGE_PARTY:
            for name in _detail(change).get("names") or []:
                if isinstance(name, str) and name and name not in joined:
                    joined.append(name)
    return _Plan(
        earlier=earlier,
        cause=_text(detail.get("cause")) or decisions.CAUSE_ACTIVITY,
        reopened_at=reopened.created_at,
        reopened_by=_text(detail.get("by")),
        boundary=boundary,
        boundary_source=source,
        covered=covered,
        stage_before=stage_before,
        joined=tuple(joined),
    )


# ── The reader ─────────────────────────────────────────────────────────────


async def _changes_of(db: AsyncSession, ids: Sequence[int]) -> dict[int, list[CampaignChange]]:
    out: dict[int, list[CampaignChange]] = {}
    for chunk in chunked(sorted(set(ids))):
        rows = await db.scalars(
            select(CampaignChange)
            .where(CampaignChange.campaign_id.in_(chunk), CampaignChange.type.in_(_READ))
            .order_by(CampaignChange.created_at, CampaignChange.id)
        )
        for change in rows.all():
            out.setdefault(change.campaign_id, []).append(change)
    return out


async def _rows_of[T](db: AsyncSession, model: type[T], column: Any, ids: Sequence[Any]) -> list[T]:
    out: list[T] = []
    for chunk in chunked(sorted(set(ids))):
        out.extend((await db.scalars(select(model).where(column.in_(chunk)))).all())
    return out


def _machine(key: str, party: CampaignParty | None) -> Machine:
    if party is None:
        return Machine(key)
    addresses = party.addresses if isinstance(party.addresses, list) else []
    return Machine(key, _text(party.name), str(addresses[0]) if addresses else None)


def _verdicts(values: Sequence[str]) -> tuple[tuple[str, int], ...]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1

    def rank(verdict: str) -> tuple[int, str]:
        place = _VERDICT_ORDER.index(verdict) if verdict in _VERDICT_ORDER else len(_VERDICT_ORDER)
        return place, verdict

    return tuple((v, counts[v]) for v in sorted(counts, key=rank))


def is_new(event_time: datetime | None, boundary: datetime) -> bool:
    """True when an investigation of the campaign is new: its event is after the boundary.

    The one rule of "new". An investigation with no event time is not new.
    The part ``earlier`` of :mod:`soc_ai.campaigns.threat_parts` is the
    rest, so the banner and the counts of the true positives agree.
    """
    return event_time is not None and event_time > boundary


async def _plans_of(
    db: AsyncSession, rows: Sequence[Campaign]
) -> dict[int, tuple[Campaign, _Plan]]:
    """The plan of each campaign of ``rows`` with no decision in force and a readable reopen."""
    wanted = [row for row in rows if not decisions.in_force(row.decision)]
    if not wanted:
        return {}
    changes = await _changes_of(db, [row.id for row in wanted])
    plans: dict[int, tuple[Campaign, _Plan]] = {}
    for row in wanted:
        plan = _plan(row, changes.get(row.id, []))
        if plan is not None:
            plans[row.id] = (row, plan)
    return plans


@dataclass(frozen=True)
class Covered:
    """What the earlier decision of a reopened campaign covered (W2).

    ``boundary`` is the boundary of :func:`since_decisions`: an investigation
    whose event is not after it is not new (:func:`is_new`). ``earlier`` is
    the decision and ``cause`` the cause of the reopen.
    """

    campaign_id: int
    boundary: datetime
    earlier: EarlierDecision
    cause: str


async def covered(db: AsyncSession, campaign_ids: Iterable[int]) -> dict[int, Covered]:
    """The boundary and the earlier decision of each reopened campaign of the ids.

    One read of the campaigns and one of their changes. A campaign with a
    decision in force, or with no reopen that soc-ai can read, has no entry.
    """
    ids = sorted({int(i) for i in campaign_ids})
    if not ids:
        return {}
    rows = await _rows_of(db, Campaign, Campaign.id, ids)
    return {
        cid: Covered(
            campaign_id=cid,
            boundary=plan.boundary,
            earlier=plan.earlier,
            cause=plan.cause,
        )
        for cid, (_row, plan) in (await _plans_of(db, rows)).items()
    }


async def since_decisions(db: AsyncSession, rows: Sequence[Campaign]) -> dict[int, SinceDecision]:
    """What is new since the earlier decision, for each campaign of ``rows`` that has an answer.

    A campaign with a decision in force, a campaign with no ``reopened``
    change and a campaign whose earlier decision soc-ai cannot read have no
    entry. One read of the changes for all rows. The campaigns with a plan
    then take one read each of the members, the parties, the investigations
    and the authorization marks.
    """
    plans = await _plans_of(db, rows)
    if not plans:
        return {}
    ids = list(plans)
    members = await _rows_of(db, CampaignMember, CampaignMember.campaign_id, ids)
    parties = await _rows_of(db, CampaignParty, CampaignParty.campaign_id, ids)
    fresh = [m for m in members if is_new(m.event_time, plans[m.campaign_id][1].boundary)]
    invs = {
        inv.id: inv
        for inv in await _rows_of(db, Investigation, Investigation.id, [m.run_id for m in fresh])
    }
    marks = await authorized_svc.marks_for(db, [inv.authorization_id for inv in invs.values()])
    out: dict[int, SinceDecision] = {}
    for cid, (row, plan) in plans.items():
        held = {p.machine_key: p for p in parties if p.campaign_id == cid}
        new = sorted(
            (m for m in fresh if m.campaign_id == cid),
            key=lambda m: (m.event_time or datetime.min, m.run_id),
        )
        out[cid] = _with_later(_since(row, plan, new, held, invs, marks), row, plan.boundary)
    return out


async def since_decision(db: AsyncSession, row: Campaign) -> SinceDecision | None:
    """:func:`since_decisions` for one campaign."""
    return (await since_decisions(db, [row])).get(row.id)


def _since(
    row: Campaign,
    plan: _Plan,
    new: Sequence[CampaignMember],
    held: Mapping[str, CampaignParty],
    invs: Mapping[str, Investigation],
    marks: Mapping[int, Any],
) -> SinceDecision:
    actors: dict[str, Machine] = {}
    targets: dict[str, Machine] = {}
    for m in new:
        for key, side in ((m.actor_key, ROLE_ACTOR), (m.target_key, ROLE_TARGET)):
            if not key:
                continue
            party = held.get(key)
            role = party.role if party is not None else side
            (actors if role == ROLE_ACTOR else targets).setdefault(key, _machine(key, party))
    found = [invs[m.run_id] for m in new if m.run_id in invs]
    authorized = 0
    # W1: the marks that hold, and the true positives that no mark holds.
    by_mark: dict[int, tuple[Any, int]] = {}
    outside = 0
    outside_names: list[str] = []
    for inv in found:
        mark = marks.get(int(inv.authorization_id)) if inv.authorization_id is not None else None
        if mark is not None and mark.holds:
            authorized += 1
            held_by, n = by_mark.get(int(mark.id), (mark, 0))
            by_mark[int(mark.id)] = (held_by, n + 1)
        elif inv.verdict == _TRUE_POSITIVE:
            outside += 1
            name = (inv.rule_name or "").strip()
            if name and name not in outside_names:
                outside_names.append(name)
    holding = tuple(
        Holding(
            id=int(mark.id),
            label=str(mark.label),
            state=str(mark.state),
            expires_at=mark.expires_at,
            investigations=n,
        )
        for mark, n in sorted(by_mark.values(), key=lambda pair: (-pair[1], int(pair[0].id)))
    )
    rules = {
        inv.rule_name.strip()
        for inv in found
        if inv.hunt_id is None and inv.rule_name and inv.rule_name.strip()
    }
    stages = [m.stage for m in new if _stage(m.stage)]
    if plan.covered is not None:
        new_machines = tuple(
            _machine(key, party).words for key, party in held.items() if key not in plan.covered
        )
    else:
        new_machines = plan.joined
    times = [m.event_time for m in new if m.event_time is not None]
    return SinceDecision(
        campaign_id=row.id,
        earlier=plan.earlier,
        cause=plan.cause,
        reopened_at=plan.reopened_at,
        reopened_by=plan.reopened_by,
        boundary=plan.boundary,
        boundary_source=plan.boundary_source,
        run_ids=tuple(m.run_id for m in new),
        verdicts=_verdicts([(invs[m.run_id].verdict or "none") for m in new if m.run_id in invs]),
        authorized=authorized,
        actors=tuple(actors.values()),
        targets=tuple(targets.values()),
        rules=len(rules),
        first_event=min(times) if times else None,
        last_event=max(times) if times else None,
        stage=max(stages, key=decisions.stage_rank) if stages else None,
        stage_before=plan.stage_before,
        stage_now=_stage(row.stage),
        new_machines=new_machines,
        outside=outside,
        outside_names=tuple(outside_names),
        holding=holding,
    )


def iso(at: datetime | None) -> str | None:
    """A stored time as ISO-8601 UTC, or None."""
    if at is None:
        return None
    return (at if at.tzinfo else at.replace(tzinfo=UTC)).astimezone(UTC).isoformat()


# ── The words of the server surfaces (SD3) ─────────────────────────────────
#
# The console states the same facts with the same words
# (``frontend/src/lib/campaignWords.ts``, the block "What is new since the
# earlier decision"). A test of each side holds the same sentences.


def _utc(at: datetime) -> datetime:
    return at.astimezone(UTC).replace(tzinfo=None) if at.tzinfo else at


def stamp(at: datetime) -> str:
    """ "2026-11-18 13:02 UTC"."""
    return f"{_utc(at):%Y-%m-%d %H:%M} UTC"


def day(at: datetime) -> str:
    """ "2026-11-18"."""
    return f"{_utc(at):%Y-%m-%d}"


def window(start: datetime, end: datetime) -> str:
    """ "2026-11-18 12:55 to 13:12 UTC", with both dates when the window crosses midnight."""
    a, b = _utc(start), _utc(end)
    a_day, a_time, b_day, b_time = f"{a:%Y-%m-%d}", f"{a:%H:%M}", f"{b:%Y-%m-%d}", f"{b:%H:%M}"
    if (a_day, a_time) == (b_day, b_time):
        return f"{a_day} {a_time} UTC"
    if a_day == b_day:
        return f"{a_day} {a_time} to {b_time} UTC"
    return f"{a_day} {a_time} to {b_day} {b_time} UTC"


def _count(n: int, one: str, many: str) -> str:
    return f"{n:,} {one if n == 1 else many}"


def _join(words: Sequence[str]) -> str:
    if len(words) <= 1:
        return "".join(words)
    return f"{', '.join(words[:-1])} and {words[-1]}"


# The cause of a reopen in words: "Opened again on ... by new activity."
_CAUSE_WORDS = {
    decisions.CAUSE_ACTIVITY: "new activity",
    decisions.CAUSE_STAGE: "a higher stage",
    decisions.CAUSE_PARTY: "a new machine",
    decisions.CAUSE_REVOKED: "a revoke of the authorization",
}
# The earlier decision as a noun: "since the close of 2026-11-15".
_DECISION_NOUN = {
    decisions.DECISION_CLOSED: "close",
    decisions.DECISION_AUTHORIZED: "authorization",
    decisions.DECISION_CASE: "case",
}


def reopened_sentence(since: SinceDecision) -> str:
    """ "Opened again on 2026-11-18 13:02 UTC by new activity." The words follow the cause."""
    at = stamp(since.reopened_at)
    if since.cause == decisions.CAUSE_ANALYST:
        return f"Opened again on {at} by {since.reopened_by or 'an analyst'}."
    return f"Opened again on {at} by {_CAUSE_WORDS.get(since.cause, 'new activity')}."


def earlier_sentence(since: SinceDecision) -> str:
    """ "casey closed it on 2026-11-15: Test that is over." The words follow the decision."""
    earlier = since.earlier
    who = earlier.by or "The analyst"
    on = f" on {day(earlier.at)}" if earlier.at is not None else ""
    label = f": {earlier.label}." if earlier.label else "."
    if earlier.decision == decisions.DECISION_AUTHORIZED:
        return f"{who} authorized it{on}{label}"
    if earlier.decision == decisions.DECISION_CASE:
        return f"{who} opened a case for it{on}."
    return f"{who} closed it{on}{label}"


def why(since: SinceDecision) -> str:
    """Why a reopened campaign waits: the reopen, then the earlier decision."""
    return f"{reopened_sentence(since)} {earlier_sentence(since)}"


_FIRST = {
    "true_positive": ("true positive investigation", "true positive investigations"),
    "false_positive": ("false positive investigation", "false positive investigations"),
    "needs_more_info": ("investigation that needs more info", "investigations that need more info"),
    "inconclusive": ("inconclusive investigation", "inconclusive investigations"),
}
_REST = {
    "true_positive": ("true positive", "true positives"),
    "false_positive": ("false positive", "false positives"),
    "needs_more_info": ("that needs more info", "that need more info"),
    "inconclusive": ("inconclusive", "inconclusive"),
}
_NO_VERDICT = ("investigation with no verdict", "investigations with no verdict")
_NO_VERDICT_REST = ("with no verdict", "with no verdict")


def _verdict_words(verdicts: Sequence[tuple[str, int]]) -> str:
    parts: list[str] = []
    for i, (verdict, n) in enumerate(verdicts):
        words = (_FIRST if i == 0 else _REST).get(verdict)
        parts.append(_count(n, *(words or (_NO_VERDICT if i == 0 else _NO_VERDICT_REST))))
    return _join(parts)


def stage_sentence(since: SinceDecision) -> str:
    """ "The stage did not change." or "The stage rose from Attempt to Access."."""
    if not since.stage_rose:
        return "The stage did not change."
    now = stage_words(since.stage_now) or since.stage_now
    before = stage_words(since.stage_before)
    return f"The stage rose from {before} to {now}." if before else f"The stage rose to {now}."


# The most rule names that one sentence lists. A count states the rest.
NAMES_MAX = 5


def _names(names: Sequence[str]) -> str:
    """ "rule-a, rule-b and 3 more"."""
    if len(names) <= NAMES_MAX:
        return _join(list(names))
    return _join([*names[:NAMES_MAX], f"{len(names) - NAMES_MAX:,} more"])


def authorization_sentence(since: SinceDecision) -> str:
    """What the authorizations hold of the new investigations, and what they do not hold (W1).

    "An authorization holds 3. It does not hold 2 true positives: rule-a
    and rule-b." When the earlier decision was a close, each authorization
    in force states its name and its end: "The authorization Red team test
    holds 3. It expires 2026-11-20 22:09 UTC." Empty when no authorization
    holds a new investigation. The banner, the Needs you row, the Confirmed
    threats row and the bell read this one function.
    """
    if since.authorized <= 0:
        return ""
    named = since.earlier.decision == decisions.DECISION_CLOSED and bool(since.holding)
    named = named and all(h.state == authorized_svc.STATE_ACTIVE for h in since.holding)
    if named:
        parts = [
            f"The authorization {h.label.strip().rstrip('.')} holds {h.investigations:,}."
            + (f" It expires {stamp(h.expires_at)}." if h.expires_at is not None else "")
            for h in since.holding
        ]
    else:
        parts = [f"An authorization holds {since.authorized:,}."]
    if since.outside > 0:
        noun = "true positive" if since.outside == 1 else "true positives"
        who = "It does not hold" if len(since.holding) <= 1 else "No authorization holds"
        names = f": {_names(since.outside_names)}." if since.outside_names else "."
        parts.append(f"{who} {since.outside:,} {noun}{names}")
    return " ".join(parts)


def new_facts_sentence(since: SinceDecision) -> str:
    """The new facts in one line.

    "New: 5 true positive investigations and 1 false positive investigation
    from actor-a, 2026-11-18 12:55 to 13:12 UTC. An authorization holds 3.
    It does not hold 2 true positives: rule-a and rule-b."
    (:func:`authorization_sentence`). Then a higher stage and each new
    machine. With no new investigation the line states the boundary.
    """
    if since.investigations == 0:
        line = f"No investigation of the campaign has an event after {stamp(since.boundary)}."
    else:
        counted = _verdict_words(since.verdicts) or _count(since.investigations, *_NO_VERDICT)
        head = f"New: {counted}"
        actors = [m.words for m in since.actors]
        source = f" from {_join(actors)}" if actors else ""
        span = (
            f", {window(since.first_event, since.last_event)}"
            if since.first_event is not None and since.last_event is not None
            else ""
        )
        line = f"{head}{source}{span}."
        held = authorization_sentence(since)
        if held:
            line += f" {held}"
    if since.stage_rose:
        line += f" {stage_sentence(since)}"
    if since.new_machines:
        noun = "New machine" if len(since.new_machines) == 1 else "New machines"
        line += f" {noun}: {_join(list(since.new_machines))}."
    return line


def count_words(since: SinceDecision) -> str:
    """ "6 new investigations since the close of 2026-11-15."."""
    noun = _DECISION_NOUN.get(since.earlier.decision, "decision")
    on = f" of {day(since.earlier.at)}" if since.earlier.at is not None else ""
    new = _count(since.investigations, "new investigation", "new investigations")
    return f"{new} since the {noun}{on}."


def split_words(since: SinceDecision) -> str:
    """ "5 true positives and 1 false positive": the verdicts of the new investigations (W3)."""
    return _join([_count(n, *(_REST.get(v) or _NO_VERDICT_REST)) for v, n in since.verdicts])


def count_split_words(since: SinceDecision) -> str:
    """The count of the new investigations with their split, for one line (W3).

    "6 new investigations since the close of 2026-11-15: 5 true positives
    and 1 false positive. An authorization holds 3." Then what the
    authorization does not hold (:func:`authorization_sentence`). The
    Confirmed threats row and the bell read this line: they read "6 new
    investigations" and did not state that 1 of the 6 is a false positive.
    """
    line = count_words(since)
    split = split_words(since)
    if since.investigations > 0 and split:
        line = f"{line[:-1]}: {split}."
    held = authorization_sentence(since)
    return f"{line} {held}" if held else line


# ── The later alert events (G2) ─────────────────────────────────────────────
#
# Production, 2026-11-19: the grid held 20 alert events of 2 rules of campaign
# 2 after its newest investigation event. Each takes the verdict of an earlier
# investigation, so no investigation is new for them. The stored grid read
# counts them (:class:`soc_ai.campaigns.events.LaterAlerts`). This module
# reads no grid.


def later_after(last_event: datetime, boundary: datetime | None) -> datetime:
    """After what time an alert event of a campaign is later: its newest investigation
    event, or the boundary of a decision when that is later."""
    return last_event if boundary is None or boundary <= last_event else boundary


def _with_later(since: SinceDecision, row: Campaign, boundary: datetime) -> SinceDecision:
    """``since`` with the later alert events of the stored grid read of ``row``.

    The stored read counts after one time. When that time is not the time
    that the campaign has now, the read is older than the campaign, and the
    line states nothing until the next read.
    """
    held = CampaignEvents.from_json(row.events) if isinstance(row.events, dict) else None
    later = held.later if held is not None and held.source == SOURCE_GRID else None
    if later is None or not later.known or later.alerts <= 0:
        return since
    if later.after != later_after(row.last_event, boundary):
        return since
    return dataclasses.replace(
        since,
        later_alerts=later.alerts,
        later_rules=later.rules,
        later_last_at=later.last_at,
    )


async def boundaries(db: AsyncSession, rows: Sequence[Campaign]) -> dict[int, datetime]:
    """The boundary of each campaign of ``rows`` with an answer of :func:`since_decisions`.

    One read of the changes for all rows. The refresh loop counts the later
    alert events after :func:`later_after` of this boundary.
    """
    wanted = [row for row in rows if not decisions.in_force(row.decision)]
    if not wanted:
        return {}
    changes = await _changes_of(db, [row.id for row in wanted])
    out: dict[int, datetime] = {}
    for row in wanted:
        plan = _plan(row, changes.get(row.id, []))
        if plan is not None:
            out[row.id] = plan.boundary
    return out


def later_sentence(since: SinceDecision) -> str | None:
    """ "The grid holds 20 later alert events of 2 rules until 2026-11-19 15:08 UTC. They
    take the verdict of these investigations." None with no later alert event."""
    n = since.later_alerts
    if n <= 0:
        return None
    rules = _count(max(1, since.later_rules), "rule", "rules")
    until = f" until {stamp(since.later_last_at)}" if since.later_last_at is not None else ""
    head = (
        f"The grid holds {_count(n, 'later alert event', 'later alert events')} of {rules}{until}."
    )
    whose = "these investigations" if since.investigations else "the investigations of the campaign"
    verb = "It takes" if n == 1 else "They take"
    return f"{head} {verb} the verdict of {whose}."


__all__ = [
    "BOUNDARY_BASIS",
    "BOUNDARY_DECISION",
    "NAMES_MAX",
    "Covered",
    "EarlierDecision",
    "Holding",
    "Machine",
    "SinceDecision",
    "authorization_sentence",
    "boundaries",
    "count_split_words",
    "count_words",
    "covered",
    "day",
    "earlier_sentence",
    "is_new",
    "iso",
    "later_after",
    "later_sentence",
    "new_facts_sentence",
    "reopened_sentence",
    "since_decision",
    "since_decisions",
    "split_words",
    "stage_sentence",
    "stamp",
    "why",
    "window",
]
