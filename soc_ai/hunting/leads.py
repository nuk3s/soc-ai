"""Record observations, and form leads out of the ones that are worth it.

A lead is several observations that together are worth looking at. The point of
the layer is that no single one of them would have been.

Four rules here carry the weight, and each exists because the obvious
alternative fails in a specific way.

**A repeat refreshes; it does not accumulate.** Observations are keyed on
(entity, spec, content fingerprint). A beacon seen every five minutes would
otherwise become three hundred rows and outrank every other signal on the
network by arithmetic alone.

**Two kinds, not two observations.** One loud thing is a finding and is reported
as itself. Letting two observations of the same kind form a lead means a host
with two new destinations produces a "chain", which is how a novelty detector
with extra steps gets mistaken for correlation.

**Hubs do not merge leads.** The domain controller, the resolver and the proxy
talk to everything. Merging through them joins every lead on the network into
one, and a lead spanning the estate is not a lead.

**Past the span cap it is a fleet condition, not an intrusion.** A thing
happening on forty hosts at once is a software deployment far more often than
it is an attacker, and reporting it as a lead sends an analyst hunting for an
intruder inside one.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.weight import (
    DEFAULT_FLOOR,
    DEFAULT_HALF_LIFE_HOURS,
    DEFAULT_LEAD_THRESHOLD,
    DEFAULT_MIN_KINDS,
    Kind,
    birth_weight,
    decay_horizon_hours,
    is_finding_grade,
    lead_total,
    live_weight,
)
from soc_ai.store.models import EntityObservation, Lead

if TYPE_CHECKING:
    from sqlalchemy import CursorResult

__all__ = [
    "DEFAULT_SPAN_CAP",
    "HUB_LEAD_LIMIT",
    "SINGLE_SIGNAL_THRESHOLD",
    "LeadOutcome",
    "WeighedObservation",
    "content_fingerprint",
    "form_leads",
    "purge_out_of_scope_observations",
    "record_observation",
    "resync_lead_shadow",
    "weigh_entity",
]

_LOGGER = logging.getLogger(__name__)

# How many entities one lead may span before it stops being an intrusion and
# starts being a fleet condition. Eight is a guess to be moved in shadow, like
# every other number in this layer.
DEFAULT_SPAN_CAP = 8

# One kind alone forms a lead at this UNCAPPED stack. A 0.7 kind reaches it on
# the fourth sighting and a 0.5 kind on the eighth. The lead is flagged
# single_signal.
#
# The threshold was 1.0, which is the stacking cap, so every kind cleared it on
# its second sighting: a catalog hit seen twice stacks to 1.19 and reads 1.0
# after the cap. The rule fired on a repeat, which is not what "one signal loud
# enough to stand alone" means.
SINGLE_SIGNAL_THRESHOLD = 1.5
"""Derived, on 2026-09-18, from the sighting count that makes a repeat the signal.

It reads the uncapped stack, so a 0.7 kind reaches it on the fourth sighting
and a 0.5 kind on the eighth. The value it replaced, 1.0, was the stacking
cap itself, so every kind cleared it on its second sighting. It has not yet
been validated against a miss."""

# A related entity that sits on more than this many open leads is a hub (the
# domain controller, the resolver). A hub is listed on a lead. It does not
# pull other leads together.
HUB_LEAD_LIMIT = 8
"""Set on the range on 2026-09-17; not yet validated against a miss.

It shares the span cap's number and neither is measured. Read the lead
quality report for a week before moving it: a limit set too low stops two
leads about one machine from joining, and one set too high joins the estate
into a single lead through the resolver."""

STATUS_OPEN = "open"
STATUS_FLEET = "fleet_condition"

# The statuses an observation may join. A dismissed or promoted lead is closed,
# and attaching new work to it hides the work. A fleet condition is not an
# intrusion and must not collect more entities either.
MERGEABLE_STATUSES = (STATUS_OPEN, "hunting")


def content_fingerprint(*parts: Any) -> str:
    """A stable id for WHAT was noticed, so a repeat can be recognised.

    Deliberately excludes time and count. Including either makes every re-sweep
    a new observation, which is the accumulation this key exists to prevent.
    """
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class WeighedObservation:
    """One stored observation and what it is worth right now."""

    id: int
    entity_kind: str
    entity_key: str
    kind: Kind
    spec_id: str
    fingerprint: str
    weight: float
    occurrences: int
    born_at: datetime
    summary: str | None
    lead_id: int | None
    # Which adapter wrote it, whether its analytic is live, and what it was
    # worth when it was new. The birth weight decides finding grade, so the
    # live weight cannot stand in for it: decay takes a true-positive alert
    # below 1.0 within a day.
    source: str = "profile"
    shadow: bool = False
    birth_weight: float = 0.0
    # The same weight without the stacking cap. Only the single-signal rule
    # reads it. Anything that sums observations reads ``weight``.
    stack: float = 0.0
    # The other entities this observation's own evidence named. A catalog hit
    # scoped on an account names the machine it came from, which is what lets
    # one lead hold both.
    related: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class LeadOutcome:
    """What :func:`form_leads` did."""

    formed: tuple[int, ...] = ()
    updated: tuple[int, ...] = ()
    fleet_conditions: tuple[int, ...] = ()
    notes: tuple[str, ...] = ()


async def purge_out_of_scope_observations(db: AsyncSession, *, cidrs: Sequence[Any]) -> int:
    """Delete HOST observations whose address is outside the estate.

    Scoping the profile table was not enough. Observations already recorded
    against an external server, the loopback address and an upstream gateway
    stayed live — decaying, accumulating, and eligible to form leads about
    somebody else's infrastructure.

    Fails OPEN on an empty CIDR list and never touches user entities, matching
    :func:`soc_ai.store.entity_profiles.purge_out_of_scope` — two functions
    answering the same question differently is how they come to disagree.
    """
    if not cidrs:
        return 0

    from soc_ai.enrichment.discovery import _is_internal_ip  # noqa: PLC0415 - lazy, avoids a cycle

    rows = (
        (await db.execute(select(EntityObservation).where(EntityObservation.entity_kind == "host")))
        .scalars()
        .all()
    )
    doomed = [r.id for r in rows if not _is_internal_ip(r.entity_key, list(cidrs))]
    if not doomed:
        return 0

    from sqlalchemy import delete  # noqa: PLC0415 - lazy, avoids a cycle

    result = await db.execute(delete(EntityObservation).where(EntityObservation.id.in_(doomed)))
    await db.commit()
    # cast: AsyncSession.execute is typed Result, but a DELETE returns a
    # CursorResult, whose rowcount is the number of rows removed.
    return int(cast("CursorResult[Any]", result).rowcount or 0)


def _evidence_ids(evidence: Any) -> set[str]:
    """The document ids an evidence dict names."""
    if not isinstance(evidence, dict):
        return set()
    ids: set[str] = set()
    for key in ("anchor_id", "alert_id"):
        if evidence.get(key):
            ids.add(str(evidence[key]))
    for key in ("sample_ids", "citations", "matched_ids"):
        ids.update(str(c) for c in (evidence.get(key) or []) if c)
    receipts = evidence.get("receipts")
    if isinstance(receipts, dict):
        ids.update(str(c) for c in (receipts.get("matched_ids") or []) if c)
    return ids


async def record_observation(
    db: AsyncSession,
    *,
    entity_kind: str,
    entity_key: str,
    kind: Kind,
    spec_id: str,
    fingerprint: str,
    summary: str | None = None,
    evidence: Any | None = None,
    now: datetime | None = None,
    source: str = "profile",
    shadow: bool = False,
    weight: float | None = None,
) -> EntityObservation:
    """Write one observation, or refresh the existing one for the same content.

    On a repeat that cites a document the row has not cited, ``born_at``
    moves forward and ``occurrences`` increments, so the thing decays from
    when it was LAST seen and stacks on how often. A repeat over the same
    documents changes neither. The hourly sweep reads a 24 h window, and the
    same two documents sat inside it for nineteen sweeps: the row said "seen
    19 times" over a port one process used once, and the stack formed a lead
    from a re-read. The original sighting is preserved in ``first_seen_at``,
    because "started three weeks ago and is still going" is a different story
    from "started today" and a refreshed ``born_at`` alone cannot tell them
    apart.

    ``source`` names the adapter that wrote the row. ``shadow`` is true if the
    analytic is not live. ``weight`` overrides the birth weight of the kind.
    An alert passes its verdict weight here.

    ``shadow`` records the status the analytic had at the LATEST sighting. A
    refresh writes it again, so the sweep after an approval turns the row into
    a live observation and the card reads as a live hit.

    The approval itself changes no row. The analyst keeps the shadow hit that
    earned the approval, with its read state, until the analytic fires again.
    Written at birth only, the flag left an approved analytic's hit between the
    two halves of the hits surface for the life of the row.

    A refresh clears ``read_at`` on the same condition. The analyst read one
    sighting. The thing has fired again, and the second sighting asks for its
    own read.

    The summary and the evidence are rewritten on every repeat. The wording
    changes between builds, and the row reads in today's words on the next
    sweep whether or not that sweep saw a new document.
    """
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    born = birth_weight(kind) if weight is None else float(weight)

    existing = (
        await db.execute(
            select(EntityObservation).where(
                EntityObservation.entity_kind == entity_kind,
                EntityObservation.entity_key == entity_key,
                EntityObservation.spec_id == spec_id,
                EntityObservation.fingerprint == fingerprint,
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        # One condition answers three questions: does the sighting count,
        # does it decay from now, and does the analyst have to read it again.
        # A new document is a new sighting. The same documents are not.
        fresh = bool(_evidence_ids(evidence) - _evidence_ids(existing.evidence_json))
        if fresh:
            existing.born_at = at
            existing.occurrences = int(existing.occurrences or 0) + 1
            existing.read_at = None
        existing.birth_weight = born
        # The flag and the read mark answer two different questions. The flag
        # asks what the analytic is now. The read mark asks whether the analyst
        # has seen these documents.
        flipped = bool(existing.shadow) != bool(shadow)
        existing.shadow = bool(shadow)
        # Read before the commit. The lead it belongs to is what the mark is
        # recomputed on, and reading it after a commit is a load the caller
        # cannot see.
        lead_id = int(existing.lead_id) if existing.lead_id else 0
        if summary:
            existing.summary = summary
        if evidence is not None:
            existing.evidence_json = evidence
        await db.commit()
        if flipped and lead_id:
            await resync_lead_shadow(db, lead_id)
        return existing

    row = EntityObservation(
        entity_kind=entity_kind,
        entity_key=entity_key,
        kind=kind.value,
        spec_id=spec_id,
        fingerprint=fingerprint,
        birth_weight=born,
        born_at=at,
        first_seen_at=at,
        occurrences=1,
        summary=summary,
        evidence_json=evidence,
        source=source,
        shadow=shadow,
    )
    db.add(row)
    await db.commit()
    return row


async def resync_lead_shadow(db: AsyncSession, lead_id: int) -> bool:
    """Read a lead's shadow mark back from the observations it holds.

    A lead is a shadow lead while one of its observations is a shadow
    observation. The mark was written at formation and nothing read it back,
    so a lead kept the chip after its analytic went live. Returns True when the
    mark changed.

    Every attached row counts, decayed or not, which is the rule
    :func:`_lead_shape` applies when a sweep rebuilds the lead.
    """
    lead = await db.get(Lead, lead_id)
    if lead is None:
        return False
    marks = (
        (
            await db.execute(
                select(EntityObservation.shadow).where(EntityObservation.lead_id == lead_id)
            )
        )
        .scalars()
        .all()
    )
    mark = any(bool(m) for m in marks)
    if bool(lead.shadow) == mark:
        return False
    lead.shadow = mark
    await db.commit()
    return True


async def weigh_entity(
    db: AsyncSession,
    *,
    entity_kind: str,
    entity_key: str,
    now: datetime | None = None,
    half_life_hours: float = DEFAULT_HALF_LIFE_HOURS,
    floor: float = DEFAULT_FLOOR,
) -> list[WeighedObservation]:
    """Every LIVE observation for one entity, with its current weight.

    Observations below the floor are dropped rather than returned at zero: they
    are history, and a caller that sums what it is given must not have to
    remember to filter first.
    """
    at = now or datetime.now(UTC)
    rows = (
        (
            await db.execute(
                select(EntityObservation).where(
                    EntityObservation.entity_kind == entity_kind,
                    EntityObservation.entity_key == entity_key,
                )
            )
        )
        .scalars()
        .all()
    )

    out: list[WeighedObservation] = []
    for row in rows:
        weight = live_weight(
            float(row.birth_weight or 0.0),
            born_at=row.born_at,
            count=int(row.occurrences or 1),
            now=at,
            half_life_hours=half_life_hours,
            floor=floor,
        )
        if weight <= 0.0:
            continue
        stack = live_weight(
            float(row.birth_weight or 0.0),
            born_at=row.born_at,
            count=int(row.occurrences or 1),
            now=at,
            half_life_hours=half_life_hours,
            floor=floor,
            cap=None,
        )
        try:
            kind = Kind(row.kind)
        except ValueError:
            # A kind this build does not know cannot be weighed, and guessing a
            # weight for it would let a renamed kind contribute silently.
            _LOGGER.debug("observation %s has unknown kind %r", row.id, row.kind)
            continue
        out.append(
            WeighedObservation(
                id=row.id,
                entity_kind=row.entity_kind,
                entity_key=row.entity_key,
                kind=kind,
                spec_id=row.spec_id,
                fingerprint=row.fingerprint,
                weight=weight,
                occurrences=int(row.occurrences or 1),
                born_at=row.born_at,
                summary=row.summary,
                lead_id=row.lead_id,
                source=str(row.source or "profile"),
                shadow=bool(row.shadow),
                birth_weight=float(row.birth_weight or 0.0),
                stack=stack,
                related=_related_entities(row.evidence_json),
            )
        )
    return out


def _related_entities(evidence: Any) -> tuple[tuple[str, str], ...]:
    """The ``related`` pairs an observation's evidence names, if any.

    Reads defensively. The evidence is whatever the adapter wrote, and a bad
    shape must cost one observation its related entities rather than the whole
    sweep.
    """
    if not isinstance(evidence, dict):
        return ()
    out: list[tuple[str, str]] = []
    for item in evidence.get("related") or ():
        if isinstance(item, (list, tuple)) and len(item) == 2:
            pair = (str(item[0]), str(item[1]))
            if pair not in out:
                out.append(pair)
    return tuple(out)


def _forms_a_lead(
    observations: Sequence[WeighedObservation],
    *,
    total: float,
    kinds: set[Kind],
    threshold: float,
    min_kinds: int,
) -> tuple[bool, bool]:
    """Whether these observations form a lead, and whether one kind did it alone.

    A finding-grade observation forms alone. One kind stacked to full weight
    forms alone and says so. Anything else needs two kinds over the threshold.

    The single-signal test reads the largest SINGLE observation, never the sum.
    Two different new destinations are two observations of one kind at 0.5 each,
    and their sum is exactly 1.0. Summing would form a lead out of plain
    novelty, which is the one thing the two-kind rule exists to refuse.
    Stacking is what the design names: one thing seen often enough that the
    repeat itself is the signal.

    It reads the UNCAPPED stack. The capped weight tops out at the very value
    the threshold used to hold, so the rule fired on the second sighting of
    anything.
    """
    a_finding = any(is_finding_grade(o.kind, o.birth_weight) for o in observations)
    single_signal = (
        not a_finding
        and len(kinds) == 1
        and max(o.stack for o in observations) >= SINGLE_SIGNAL_THRESHOLD
    )
    if a_finding or single_signal:
        return True, single_signal
    return total >= threshold and len(kinds) >= min_kinds, False


async def _recent_hunt_closed_lead(
    db: AsyncSession, *, entity: tuple[str, str], at: datetime, horizon: timedelta
) -> Lead | None:
    """The newest lead the settle rule closed on this entity inside the horizon.

    Looked up by the lead, not by its observations: the observations that
    formed it may have decayed to nothing while the close is still recent,
    and the close is what answers for the entity.
    """
    from soc_ai.store.leads import AUTO_HUNT_ACTOR  # noqa: PLC0415 - avoids an import cycle

    rows = (
        (
            await db.execute(
                select(Lead)
                .where(
                    Lead.status == "dismissed",
                    Lead.dismissed_by == AUTO_HUNT_ACTOR,
                    Lead.dismissed_at >= at - horizon,
                )
                .order_by(Lead.dismissed_at.desc(), Lead.id.desc())
            )
        )
        .scalars()
        .all()
    )
    wanted = [entity[0], entity[1]]
    for lead in rows:
        if any(list(e) == wanted for e in (lead.entities_json or []) if len(e) == 2):
            return lead
    return None


async def _apply_closed_leads(
    db: AsyncSession,
    observations: Sequence[WeighedObservation],
    *,
    entity: tuple[str, str],
    at: datetime,
    half_life_hours: float,
    floor: float,
) -> list[WeighedObservation]:
    """What a closed lead does to the observations on its entity.

    A dismissed or promoted lead is an answer. Its observations are consumed.
    They do not count toward a new lead, and the closed lead does not change.
    A new lead can still form on the same entity from observations recorded
    after the close.

    A lead the settle rule closed is a narrower answer: the hunt read the
    types the lead held and found no threat. Inside the decay horizon of that
    close, an observation of a type the lead held joins it as history and
    forms nothing, because the same repeat would start the same hunt and
    land the same answer. An observation of a type the lead did NOT hold
    reopens it: the question changed. The automatic dismissal is cleared and
    the hunt id with it, so the loop hunts the reopened lead; the old hunt
    row keeps the lead id, as the record of the first hunt.

    An analyst's dismissal is never rejoined or reopened here. It stands.
    """
    from soc_ai.store.leads import CLOSED_STATUSES  # noqa: PLC0415 - avoids an import cycle

    naive_at = at.replace(tzinfo=None) if at.tzinfo is not None else at
    attached = {o.lead_id for o in observations if o.lead_id}
    closed: set[int] = set()
    if attached:
        rows = await db.execute(select(Lead.id, Lead.status).where(Lead.id.in_(list(attached))))
        closed = {int(i) for i, s in rows if s in CLOSED_STATUSES}
    kept = [o for o in observations if o.lead_id not in closed]
    loose = [o for o in kept if o.lead_id is None]
    if not loose:
        return kept
    horizon = timedelta(hours=decay_horizon_hours(half_life_hours, floor))
    lead = await _recent_hunt_closed_lead(db, entity=entity, at=naive_at, horizon=horizon)
    if lead is None:
        return kept
    held = {str(k) for k in (lead.kinds_json or [])}
    if {o.kind.value for o in loose} <= held:
        await _join_lead(db, lead.id, loose)
        await db.commit()
        return [o for o in kept if o.lead_id is not None]
    lead.status = STATUS_OPEN
    lead.hunt_id = None
    lead.dismissed_reason = None
    lead.dismissed_note = None
    lead.dismissed_by = None
    lead.dismissed_at = None
    lead.updated_at = naive_at
    await db.commit()
    reopened = int(lead.id)
    return [o for o in observations if o.lead_id is None or o.lead_id == reopened]


async def _join_lead(
    db: AsyncSession, lead_id: int, observations: Sequence[WeighedObservation]
) -> bool:
    """Attach every unattached observation to the lead. True if any joined."""
    joined = False
    for obs in observations:
        if obs.lead_id is None:
            row = await db.get(EntityObservation, obs.id)
            if row is not None:
                row.lead_id = lead_id
                joined = True
    return joined


async def _mergeable_leads(db: AsyncSession) -> list[Lead]:
    """Every lead an observation may still join, oldest first.

    Scanned rather than queried by entity: ``entities_json`` is a JSON array
    and the open leads are few. The order decides which lead a merge picks,
    so it is pinned here and not left to the database.
    """
    rows = (
        (
            await db.execute(
                select(Lead)
                .where(Lead.status.in_(MERGEABLE_STATUSES))
                .order_by(Lead.formed_at, Lead.id)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def _subject_lead_ids(
    db: AsyncSession, entities: Sequence[tuple[str, str]]
) -> dict[tuple[str, str], set[int]]:
    """Which leads hold an OBSERVATION about each of these entities.

    A lead names two sorts of entity: the ones its observations are about, and
    the ones those observations merely mentioned. Only the first sort may pull
    two leads together. Chaining through a mention joins every lead that names
    the domain controller into one, which is the estate-wide lead the hub rule
    exists to refuse.
    """
    if not entities:
        return {}
    keys = {key for _kind, key in entities}
    rows = (
        await db.execute(
            select(
                EntityObservation.entity_kind,
                EntityObservation.entity_key,
                EntityObservation.lead_id,
            ).where(
                EntityObservation.lead_id.isnot(None),
                EntityObservation.entity_key.in_(keys),
            )
        )
    ).all()
    out: dict[tuple[str, str], set[int]] = {}
    for kind, key, lead_id in rows:
        out.setdefault((kind, key), set()).add(int(lead_id))
    return out


async def _merge_target(
    db: AsyncSession, *, entity: tuple[str, str], related: Sequence[tuple[str, str]]
) -> Lead | None:
    """The oldest lead these observations belong to, or None to form one.

    Two ways in, and they are not the same rule:

    * A lead already NAMES this entity. The observation is about something the
      lead is already about, so it joins even if it is far too weak to form a
      lead of its own. That is the merge the design asks for: an off-hours
      departure on the domain controller joins the lead the DCSync hit opened
      on the account, because that lead names the controller.
    * A lead holds an observation ABOUT one of the entities this one named.
      Both are then about the same machine.

    An entity on more than ``HUB_LEAD_LIMIT`` open leads is a hub and joins
    nothing. Merging through the resolver makes one lead out of the estate.
    """
    leads = await _mergeable_leads(db)
    if not leads:
        return None
    named: dict[int, set[tuple[str, str]]] = {
        lead.id: {tuple(e) for e in (lead.entities_json or []) if len(e) == 2} for lead in leads
    }
    on_leads: dict[tuple[str, str], int] = {}
    for names in named.values():
        for key in names:
            on_leads[key] = on_leads.get(key, 0) + 1

    def a_hub(key: tuple[str, str]) -> bool:
        return on_leads.get(key, 0) > HUB_LEAD_LIMIT

    if not a_hub(entity):
        for lead in leads:
            if entity in named[lead.id]:
                return lead

    subjects = await _subject_lead_ids(db, related)
    for lead in leads:
        for key in related:
            if lead.id in subjects.get(key, set()) and not a_hub(key):
                return lead
    return None


async def _lead_shape(
    db: AsyncSession,
    lead_id: int,
    *,
    at: datetime,
    half_life_hours: float,
    floor: float,
) -> tuple[set[str], set[tuple[str, str]], bool]:
    """The kinds, the entities and the shadow mark of a lead's own observations.

    Read from every row attached to the lead, not from the one entity being
    weighed. A lead that spans two entities used to be rewritten from whichever
    of them the sweep reached last, which dropped the other one's kinds.
    """
    rows = (
        (await db.execute(select(EntityObservation).where(EntityObservation.lead_id == lead_id)))
        .scalars()
        .all()
    )
    kinds: set[str] = set()
    subjects: set[tuple[str, str]] = set()
    shadow = False
    for row in rows:
        subjects.add((row.entity_kind, row.entity_key))
        # The shadow mark reads EVERY attached row, decayed or not. A lead that
        # a shadow analytic contributed to keeps the mark after that
        # observation has decayed, because the analytic is still not live.
        shadow = shadow or bool(row.shadow)
        weight = live_weight(
            float(row.birth_weight or 0.0),
            born_at=row.born_at,
            count=int(row.occurrences or 1),
            now=at,
            half_life_hours=half_life_hours,
            floor=floor,
        )
        if weight <= 0.0:
            continue
        kinds.add(str(row.kind))
    return kinds, subjects, shadow


async def _new_lead(
    db: AsyncSession,
    observations: Sequence[WeighedObservation],
    *,
    at: datetime,
    total: float,
    kind_values: list[str],
    entities: Sequence[tuple[str, str]],
    span: int,
    span_cap: int,
    shadow: bool,
    single_signal: bool,
) -> Lead:
    """Write one lead and attach every observation that formed it.

    ``entities`` is what the lead NAMES: the entity the observations are about
    and the ones they mentioned. ``span`` counts only the first sort, because
    the span cap asks how many subjects share one condition and a hit that
    names eight machines is one subject, not nine.

    The subject comes first in the list. It was sorted, so a host a hit merely
    mentioned could lead a lead about an account, and every surface reads the
    first entity as the subject.
    """
    lead = Lead(
        status=STATUS_FLEET if span > span_cap else STATUS_OPEN,
        formed_at=at.replace(tzinfo=None),
        entities_json=[list(e) for e in entities],
        kinds_json=kind_values,
        weight_at_formation=total,
        scope_count=span,
        shadow=shadow,
        single_signal=single_signal,
    )
    db.add(lead)
    await db.flush()
    for obs in observations:
        row = await db.get(EntityObservation, obs.id)
        if row is not None:
            row.lead_id = lead.id
    await db.commit()
    return lead


async def _extend_lead(
    db: AsyncSession,
    lead: Lead,
    observations: Sequence[WeighedObservation],
    *,
    entity: tuple[str, str],
    related: Sequence[tuple[str, str]],
    at: datetime,
    half_life_hours: float,
    floor: float,
    single_signal: bool,
    shadow: bool,
    merged: bool,
) -> bool:
    """Attach these observations to a lead it already belongs to. True if it re-fired.

    Re-fires only when a new kind joins, a new entity is named, or the scope
    count crosses a step. Updating on every sweep would make a lead a
    notification stream, and an analyst learns to close one without reading it.
    ...but every live observation joins the lead regardless. A same-kind
    observation recorded after formation used to sit beside the lead,
    unattached, and the strip showed a lead of two while the host held three.

    A merge always re-fires: the lead now holds an entity it did not hold.
    """
    previous_kinds = set(lead.kinds_json or [])
    previous_names = {tuple(e) for e in (lead.entities_json or []) if len(e) == 2}
    joined = await _join_lead(db, lead.id, observations)
    live_kinds, subjects, lead_shadow = await _lead_shape(
        db, lead.id, at=at, half_life_hours=half_life_hours, floor=floor
    )
    # The entities the observations are ABOUT lead the list, in order. The
    # ones they merely mentioned follow. A sorted list put a mentioned host in
    # front of the account a lead was opened on.
    named = previous_names | {entity} | set(related)
    names = [*sorted(subjects & named), *sorted(named - subjects)]
    span = len(subjects)
    changed = (
        live_kinds != previous_kinds
        or set(names) != previous_names
        or span != int(lead.scope_count or 0)
    )
    # The shadow mark is recomputed from every observation the lead holds. A
    # shadow observation marks the whole lead, whether or not it changed the
    # kind set. A lead that holds one is not a live lead.
    lead.single_signal = single_signal and len(live_kinds) <= 1
    lead.shadow = shadow or lead_shadow
    if changed or merged:
        lead.kinds_json = sorted(live_kinds)
        lead.entities_json = [list(e) for e in names]
        lead.scope_count = span
        lead.updated_at = at.replace(tzinfo=None)
        await db.commit()
        return True
    if joined:
        await db.commit()
    return False


async def form_leads(
    db: AsyncSession,
    *,
    entity_keys: Sequence[tuple[str, str]],
    now: datetime | None = None,
    threshold: float = DEFAULT_LEAD_THRESHOLD,
    min_kinds: int = DEFAULT_MIN_KINDS,
    span_cap: int = DEFAULT_SPAN_CAP,
    half_life_hours: float = DEFAULT_HALF_LIFE_HOURS,
    floor: float = DEFAULT_FLOOR,
    shadow: bool = False,
) -> LeadOutcome:
    """Form or update a lead for every entity whose live weight has crossed.

    ``shadow`` marks the lead whatever its observations say. It defaults False.
    A lead is shadow when one of its OBSERVATIONS is, which is the fact the
    field records. The default was True, every caller took it, and the range
    therefore marked every lead it formed as shadow: the strip read as evidence
    nobody should act on. The posture that no lead starts a hunt by itself is a
    rule the screens keep, not a mark on every row.

    An entity that a lead already NAMES joins that lead whatever its weight.
    The threshold asks whether observations are worth opening a lead for, and
    that question is already answered once a lead names the entity.
    """
    at = now or datetime.now(UTC)
    formed: list[int] = []
    updated: list[int] = []
    fleet: list[int] = []
    notes: list[str] = []

    for entity_kind, entity_key in entity_keys:
        entity = (entity_kind, entity_key)
        observations = await weigh_entity(
            db,
            entity_kind=entity_kind,
            entity_key=entity_key,
            now=at,
            half_life_hours=half_life_hours,
            floor=floor,
        )
        if not observations:
            continue

        observations = await _apply_closed_leads(
            db,
            observations,
            entity=entity,
            at=at,
            half_life_hours=half_life_hours,
            floor=floor,
        )
        if not observations:
            continue

        # Capped per kind. Forty-five rows of one kind are one story told
        # forty-five times, and the sum said 25 where the story said 1.7.
        total = lead_total((o.kind, o.weight) for o in observations)
        kinds = {o.kind for o in observations}
        related = sorted({r for o in observations for r in o.related if tuple(r) != entity})

        forms, single_signal = _forms_a_lead(
            observations, total=total, kinds=kinds, threshold=threshold, min_kinds=min_kinds
        )
        any_shadow = any(o.shadow for o in observations)
        existing_id = next((o.lead_id for o in observations if o.lead_id), None)

        lead: Lead | None = None
        merged = False
        if existing_id is not None:
            lead = await db.get(Lead, existing_id)
            if lead is None:
                continue
        else:
            lead = await _merge_target(db, entity=entity, related=related)
            merged = lead is not None
        if lead is None and not forms:
            continue

        if lead is None:
            # A new lead names this entity and the ones its observations
            # mentioned. The span counts the subjects only. See _new_lead.
            new_lead = await _new_lead(
                db,
                observations,
                at=at,
                total=total,
                kind_values=sorted(k.value for k in kinds),
                entities=[entity, *sorted(set(related) - {entity})],
                span=len({(o.entity_kind, o.entity_key) for o in observations}),
                span_cap=span_cap,
                shadow=shadow or any_shadow,
                single_signal=single_signal,
            )
            if int(new_lead.scope_count or 0) > span_cap:
                fleet.append(new_lead.id)
                notes.append(
                    f"lead {new_lead.id} spans {new_lead.scope_count} entities. "
                    f"The cap is {span_cap}. soc-ai recorded it as a fleet condition"
                )
            else:
                formed.append(new_lead.id)
            continue

        if await _extend_lead(
            db,
            lead,
            observations,
            entity=entity,
            related=related,
            at=at,
            half_life_hours=half_life_hours,
            floor=floor,
            single_signal=single_signal,
            shadow=shadow,
            merged=merged,
        ):
            updated.append(lead.id)

    return LeadOutcome(
        formed=tuple(formed),
        updated=tuple(updated),
        fleet_conditions=tuple(fleet),
        notes=tuple(notes),
    )
