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
import ipaddress
import logging
from collections.abc import Sequence
from dataclasses import dataclass, replace
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
    "MAX_DOCUMENT_IDS",
    "SINGLE_SIGNAL_THRESHOLD",
    "HitMachine",
    "LeadOutcome",
    "WeighedObservation",
    "content_fingerprint",
    "decays_from",
    "departure_size",
    "form_leads",
    "machines_of",
    "no_lead_reasons",
    "no_lead_sentence",
    "purge_out_of_scope_observations",
    "read_hit",
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
    answering the same question differently is how they come to disagree. A
    host keyed on its agent name rather than an address (the process and logon
    planes key on ``host.name``) is kept, as the profile purge keeps it: a
    CIDR list cannot place a name.
    """
    if not cidrs:
        return 0

    from soc_ai.enrichment.discovery import (  # noqa: PLC0415 - lazy, avoids a cycle
        _is_internal_ip,
        _is_ip_literal,
    )

    rows = (
        (await db.execute(select(EntityObservation).where(EntityObservation.entity_kind == "host")))
        .scalars()
        .all()
    )
    doomed = [
        r.id
        for r in rows
        if _is_ip_literal(r.entity_key) and not _is_internal_ip(r.entity_key, list(cidrs))
    ]
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
    observed_at: datetime | None = None,
    statistic: str | None = None,
    statistic_value: float | None = None,
    baseline_value: float | None = None,
    document_ids: Sequence[str] | None = None,
    rerun_query: str | None = None,
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

    A refresh clears ``read_at`` on the same condition, when the sighting is
    materially new (:func:`_materially_new`). The analyst read one sighting.
    A repeat that is no larger than the one they read says nothing new, so it
    keeps the mark. Every repeat cleared it before, and 123 of 233 unread
    production hits were hits that the owner had read already.

    The read mark is keyed on the machine. The same analytic and the same
    value on another address of the machine is a repeat of the same hit, so a
    new row there is born read unless it is materially new. The row itself
    stays keyed on the address: each address has its own baseline, and the
    numbers on the row are the numbers of that address.

    A fresh sighting can also leave a closed lead (:func:`_released_by_close`).
    The row then belongs to no lead and its count starts at 1, because the
    closed lead answered the sightings before it.

    The summary and the evidence are rewritten on every repeat. The wording
    changes between builds, and the row reads in today's words on the next
    sweep whether or not that sweep saw a new document.

    ``observed_at`` is the newest document timestamp the observation cites.
    ``born_at`` is the time soc-ai wrote the row, and an observation used to
    decay from it: an event twenty hours old read as fresh on the sweep that
    found it. The decay reads ``observed_at`` when the row has one (see
    :func:`decays_from`). It is bounded by the record time, because a grid
    clock ahead of soc-ai's would otherwise date an event in the future. A
    fresh sighting moves it to the newer of the two event times. A fresh
    sighting with no event time clears it, so the row decays from the new
    record time and not from an older event. A re-read of the same documents
    fills it on a row that has none.

    ``statistic``, ``statistic_value`` and ``baseline_value`` are the numbers
    the departure is made of. ``rerun_query`` is the OQL query that shows it
    again. A repeat writes the newest of each, as it writes the summary.
    ``document_ids`` are the documents the row cites, up to ten. With none
    passed they are read from ``evidence``. A repeat keeps the newest first
    and the older ones after them, so the first sighting stays citable.
    """
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    born = birth_weight(kind) if weight is None else float(weight)
    event = _bounded_event_time(observed_at, at)
    cited = _document_ids(evidence, document_ids)

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

    size = departure_size(statistic, statistic_value)
    hit = {
        "entity_kind": entity_kind,
        "entity_key": entity_key,
        "spec_id": spec_id,
        "fingerprint": fingerprint,
    }

    if existing is not None:
        # A new document is a new sighting. The same documents are not. The
        # sighting then counts and decays from now. Whether the analyst has to
        # read it again is a second question: only a sighting that is
        # materially new asks for a read.
        fresh = bool(_evidence_ids(evidence) - _evidence_ids(existing.evidence_json))
        # Read before the row takes the numbers of this sighting. A read row
        # with no mark yet still shows the numbers that the analyst read.
        carried = _stored_read_mark(existing)
        if carried is None and existing.read_at is not None:
            carried = _read_mark_of(existing)
        bar: _ReadBar | None = None
        if fresh and existing.read_at is not None:
            bar = await _read_bar(db, own=existing, **hit)
        if fresh:
            await _count_sighting(db, existing, at=at, event=event)
            if bar is None or _materially_new(size, born, bar):
                existing.read_at = None
                bar = None
        elif existing.observed_at is None and event is not None:
            existing.observed_at = event
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
        if statistic is not None:
            existing.statistic = statistic
            existing.statistic_value = statistic_value
            existing.baseline_value = baseline_value
        existing.rerun_query = rerun_query if rerun_query is not None else existing.rerun_query
        existing.document_ids = (
            _merged_ids(cited, existing.document_ids) if cited else (existing.document_ids)
        )
        # The largest sighting the analyst read stays on the row while the row
        # stays read. The evidence is written again on every repeat, so the
        # mark is carried here.
        still_read = existing.read_at is not None
        _stamp_read_mark(existing, (bar.mark() if bar else carried) if still_read else None)
        await db.commit()
        if flipped and lead_id:
            await resync_lead_shadow(db, lead_id)
        return existing

    # A first sighting on this address. The analyst may have read the same hit
    # on another address of the same machine.
    born_read = await _read_bar(db, own=None, **hit) if shadow else None
    if born_read is not None and _materially_new(size, born, born_read):
        born_read = None
    row = EntityObservation(
        entity_kind=entity_kind,
        entity_key=entity_key,
        kind=kind.value,
        spec_id=spec_id,
        fingerprint=fingerprint,
        birth_weight=born,
        born_at=at,
        first_seen_at=at,
        observed_at=event,
        occurrences=1,
        summary=summary,
        evidence_json=evidence,
        source=source,
        shadow=shadow,
        statistic=statistic,
        statistic_value=statistic_value,
        baseline_value=baseline_value,
        document_ids=cited or None,
        rerun_query=rerun_query,
        read_at=born_read.read_at if born_read else None,
    )
    if born_read is not None:
        _stamp_read_mark(row, born_read.mark())
    db.add(row)
    await db.commit()
    return row


async def _count_sighting(
    db: AsyncSession, row: EntityObservation, *, at: datetime, event: datetime | None
) -> None:
    """A fresh sighting on a stored row: it counts, and it decays from now.

    A sighting after the close of the row's lead leaves that lead and starts
    a new count (:func:`_released_by_close`).
    """
    row.born_at = at
    row.occurrences = int(row.occurrences or 0) + 1
    if await _released_by_close(db, row, sighting=event or at):
        # The closed lead answered the sightings it held. This one is new,
        # so it starts its own count and belongs to no lead.
        _LOGGER.info(
            "observation %s left closed lead %s: a new sighting arrived after the close",
            row.id,
            row.lead_id,
        )
        row.lead_id = None
        row.occurrences = 1
    row.observed_at = (
        None
        if event is None
        else max(event, row.observed_at)
        if row.observed_at is not None
        else event
    )


# ---------------------------------------------------------------------------
# The read mark: keyed on the machine, cleared by a materially new sighting
# ---------------------------------------------------------------------------

# How the size of a departure reads off its statistic. The size is the
# distance from the baseline in the direction that makes the hit stronger. A
# statistic that is not listed has no size, and a repeat of it is new when it
# cites a new document. tests/test_lead_truth.py pins the names against the
# constants the analytics write.
#
# A z score is a distance in both directions: a collapse at -8 is further out
# than one at -6.
_SIZE_IS_DISTANCE: frozenset[str] = frozenset({"residual_z", "robust_z"})
# A count of documents or hosts: more is a larger departure.
_SIZE_RISES: frozenset[str] = frozenset({"documents", "hour_documents", "hosts_departing"})
# A count of holders, or of documents on a silent plane: fewer is a larger departure.
_SIZE_FALLS: frozenset[str] = frozenset({"estate_hosts", "peer_share", "plane_documents"})

# The evidence key that holds the largest sighting the analyst read.
_READ_MARK = "read_mark"


def departure_size(statistic: str | None, value: float | None) -> float | None:
    """How large one sighting is, on the scale of its own statistic. None for no scale.

    The number compares two sightings of the same hit. It is not a threshold:
    nothing reads it against a fixed value.
    """
    if value is None:
        return None
    name = str(statistic or "")
    if name in _SIZE_IS_DISTANCE:
        return abs(float(value))
    if name in _SIZE_RISES:
        return float(value)
    if name in _SIZE_FALLS:
        return -float(value)
    return None


@dataclass(frozen=True)
class _ReadBar:
    """The largest sighting of one hit that the analyst has read, on one machine."""

    size: float | None
    weight: float
    read_at: datetime

    def mark(self) -> dict[str, float | None]:
        return {"size": self.size, "weight": self.weight}


def _stored_read_mark(row: EntityObservation) -> dict[str, float | None] | None:
    """The read mark the row carries in its evidence, or None."""
    evidence = row.evidence_json if isinstance(row.evidence_json, dict) else {}
    mark = evidence.get(_READ_MARK)
    if not isinstance(mark, dict):
        return None
    size, weight = mark.get("size"), mark.get("weight")
    return {
        "size": float(size) if isinstance(size, (int, float)) else None,
        "weight": float(weight) if isinstance(weight, (int, float)) else 0.0,
    }


def _stamp_read_mark(row: EntityObservation, mark: dict[str, float | None] | None) -> None:
    """Write the read mark into the row's evidence, or take it out."""
    evidence = row.evidence_json
    if not isinstance(evidence, dict):
        if mark is None or evidence is not None:
            return
        evidence = {}
    if evidence.get(_READ_MARK) == mark:
        return
    stamped = {k: v for k, v in evidence.items() if k != _READ_MARK}
    if mark is not None:
        stamped[_READ_MARK] = mark
    row.evidence_json = stamped


def _read_mark_of(row: EntityObservation) -> dict[str, float | None]:
    """The size and the weight a row shows now, in the shape of a read mark."""
    return {
        "size": departure_size(row.statistic, row.statistic_value),
        "weight": float(row.birth_weight or 0.0),
    }


def _read_size_of(row: EntityObservation) -> tuple[float | None, float]:
    """The largest size and weight that the analyst read on a read row.

    The mark holds it once the row was written after the read. A sweep that
    reads the same documents again writes a new score on the row, and the
    analyst did not read that score, so the mark wins over the row. A row
    with no mark was not written since the read, and its own numbers are the
    ones the analyst read.
    """
    mark = _stored_read_mark(row) or _read_mark_of(row)
    return mark["size"], float(mark["weight"] or 0.0)


async def _machine_siblings(
    db: AsyncSession, *, entity_kind: str, entity_key: str, spec_id: str, fingerprint: str
) -> list[EntityObservation]:
    """The rows of the same hit on the other keys of the same machine.

    A hit is one analytic and one value on one machine. The machine holds
    every address, every container address and every name the store places on
    it. An entity on no machine record has no sibling.
    """
    if entity_kind != "host":
        return []
    from soc_ai.store import host_machines  # noqa: PLC0415 - lazy, avoids a cycle

    membership = await host_machines.resolve_membership(db, entity_key)
    if membership is None:
        return []
    keys = {*membership.addresses, *membership.containers, *membership.names} - {entity_key}
    if not keys:
        return []
    rows = await db.scalars(
        select(EntityObservation).where(
            EntityObservation.entity_kind == entity_kind,
            EntityObservation.spec_id == spec_id,
            EntityObservation.entity_key.in_(sorted(keys)),
        )
    )
    # A match analytic writes the entity into its fingerprint, so the same hit
    # on another address has another fingerprint. Its value is the analytic
    # alone, and the sibling is the row with the fingerprint of its own key.
    per_entity = fingerprint == content_fingerprint(spec_id, entity_key)
    return [
        row
        for row in rows.all()
        if row.fingerprint
        == (content_fingerprint(spec_id, row.entity_key) if per_entity else fingerprint)
    ]


async def _read_bar(
    db: AsyncSession,
    *,
    own: EntityObservation | None,
    entity_kind: str,
    entity_key: str,
    spec_id: str,
    fingerprint: str,
) -> _ReadBar | None:
    """The largest read sighting of this hit on this machine, or None when none is read."""
    rows = [own] if own is not None and own.read_at is not None else []
    siblings = await _machine_siblings(
        db,
        entity_kind=entity_kind,
        entity_key=entity_key,
        spec_id=spec_id,
        fingerprint=fingerprint,
    )
    rows.extend(r for r in siblings if r.read_at is not None)
    if not rows:
        return None
    read = [_read_size_of(r) for r in rows]
    sizes = [size for size, _weight in read if size is not None]
    return _ReadBar(
        size=max(sizes) if sizes else None,
        weight=max(weight for _size, weight in read),
        read_at=max(r.read_at for r in rows if r.read_at is not None),
    )


def _materially_new(size: float | None, weight: float, bar: _ReadBar) -> bool:
    """Whether a sighting says more than the largest one the analyst read.

    Two fields decide, and no number of its own. The weight is the severity
    of the sighting: a higher weight is new. The size is the score of the
    departure: a larger size is new. A sighting with no size cannot be
    compared, so it is new, as every new document was before.
    """
    if weight > bar.weight:
        return True
    if size is None or bar.size is None:
        return True
    return size > bar.size


async def read_hit(db: AsyncSession, row: EntityObservation, *, at: datetime) -> int:
    """Mark one shadow hit read, on every address of its machine. Returns the rows marked.

    The analyst opens the hit on one address. The hit is one analytic and
    one value on one machine, so the rows of the same hit on the other
    addresses of that machine are read with it. A row that is larger than
    the one the analyst opened stays unread: they did not see its numbers.
    """
    marked = 0
    if row.read_at is None:
        row.read_at = at
        marked += 1
    size, weight = _read_size_of(row)
    bar = _ReadBar(size=size, weight=weight, read_at=at)
    siblings = await _machine_siblings(
        db,
        entity_kind=row.entity_kind,
        entity_key=row.entity_key,
        spec_id=row.spec_id,
        fingerprint=row.fingerprint,
    )
    for other in siblings:
        if other.read_at is not None or not other.shadow:
            continue
        other_size, other_weight = _read_size_of(other)
        if not _materially_new(other_size, other_weight, bar):
            other.read_at = at
            marked += 1
    await db.commit()
    return marked


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class HitMachine:
    """The machine a hit is on: the key the Hosts page uses, and the name it shows."""

    key: str
    name: str | None


async def machines_of(db: AsyncSession, entity_keys: Sequence[str]) -> dict[str, HitMachine]:
    """The machine of each host key. A key on no machine record is left out.

    An address is read in one query for the page. A key that is no address is
    the agent name a model analytic keys on, and it resolves by name.
    """
    from soc_ai.store import host_machines  # noqa: PLC0415 - lazy, avoids a cycle
    from soc_ai.store.models import HostDossier, HostMachine  # noqa: PLC0415 - lazy

    keys = sorted({str(k) for k in entity_keys if k})
    out: dict[str, HitMachine] = {}
    if not keys:
        return out
    rows = await db.execute(
        select(HostDossier.host_key, HostMachine.machine_key, HostMachine.name)
        .join(HostMachine, HostMachine.id == HostDossier.machine_id)
        .where(HostDossier.host_key.in_(keys))
    )
    for host_key, machine_key, name in rows:
        out[str(host_key)] = HitMachine(key=str(machine_key), name=str(name) if name else None)
    for key in keys:
        if key in out or _is_address(key):
            continue
        membership = await host_machines.resolve_membership(db, key)
        if membership is not None:
            out[key] = HitMachine(
                key=membership.key, name=membership.names[0] if membership.names else None
            )
    return out


async def _released_by_close(
    db: AsyncSession, row: EntityObservation, *, sighting: datetime
) -> bool:
    """Whether a fresh sighting leaves the closed lead its row is attached to.

    A repeat refreshes the same row, and the row kept the id of its lead for
    good. A closed lead consumes its observations, so one close silenced that
    condition on that entity for all time. Production lead 34 closed on
    2026-10-14, and four telemetry silence rows on its host fired again four
    weeks later with no lead to join.

    A close answers for the decay horizon, the span in which a full-weight
    observation stays live. Inside it a repeat is the same question, and it
    stays on the closed lead as history. A sighting after it is new work: the
    row leaves the lead and is free to form a lead or to join an open one.

    Two things hold a row where it is:

    - A dismissal by an analyst. The console states its scope: the
      observations on the lead and their repeats form no new lead, with no
      time window, until Reopen. Every reason on the form mutes the same way.
    - A sighting whose newest document is not after the horizon. The sweep
      reads a window that reaches back before the close, so a new sample of
      the old event is no new sighting.
    """
    if not row.lead_id:
        return False
    from soc_ai.store.leads import (  # noqa: PLC0415 - avoids an import cycle
        CLOSED_STATUSES,
        analyst_dismissed,
        closed_at_of,
    )

    lead = await db.get(Lead, int(row.lead_id))
    if lead is None or lead.status not in CLOSED_STATUSES:
        return False
    if lead.status == "dismissed" and analyst_dismissed(lead):
        return False
    closed_at = closed_at_of(lead)
    if closed_at is None:
        return False
    horizon = timedelta(hours=decay_horizon_hours())
    return sighting > closed_at + horizon


# How many document ids one observation keeps in its column.
MAX_DOCUMENT_IDS = 10


def _document_ids(evidence: Any, explicit: Sequence[str] | None) -> list[str]:
    """The documents one sighting cites, in citation order, at most ten.

    The anchor and the alert come first, because they are the documents the
    row is about. The samples, the citations and the matched ids follow.
    """
    ordered: list[str] = []
    if explicit is not None:
        ordered.extend(str(i) for i in explicit if i)
    elif isinstance(evidence, dict):
        for key in ("anchor_id", "alert_id"):
            if evidence.get(key):
                ordered.append(str(evidence[key]))
        for key in ("sample_ids", "citations", "matched_ids"):
            ordered.extend(str(c) for c in (evidence.get(key) or []) if c)
        receipts = evidence.get("receipts")
        if isinstance(receipts, dict):
            ordered.extend(str(c) for c in (receipts.get("matched_ids") or []) if c)
    return _merged_ids(ordered, None)


def _merged_ids(newest: Sequence[str], older: Any) -> list[str]:
    """The newest ids first, then the older ones, without repeats, at most ten."""
    out: list[str] = []
    for one in (*newest, *(older if isinstance(older, list) else ())):
        text = str(one)
        if text and text not in out:
            out.append(text)
        if len(out) >= MAX_DOCUMENT_IDS:
            break
    return out


def _bounded_event_time(observed_at: datetime | None, at: datetime) -> datetime | None:
    """The event time as the store keeps it: naive UTC, never after *at*."""
    if observed_at is None:
        return None
    if observed_at.tzinfo is not None:
        observed_at = observed_at.astimezone(UTC).replace(tzinfo=None)
    return min(observed_at, at)


def decays_from(observed_at: datetime | None, born_at: datetime) -> datetime:
    """The clock an observation decays on: the event time when the row has one.

    ``born_at`` is the record time. Decaying from it made an event read as
    fresh on the sweep that found it, however old the event was.
    """
    return observed_at if observed_at is not None else born_at


async def resync_lead_shadow(db: AsyncSession, lead_id: int) -> bool:
    """Read a lead's shadow mark back from the observations it holds.

    A lead is a shadow lead while one of its observations is a shadow
    observation. The mark was written at formation and nothing read it back,
    so a lead kept the chip after its analytic went live. Returns True when the
    mark changed.

    Every attached row counts, decayed or not, which is the rule
    :func:`_lead_shape` applies when a sweep rebuilds the lead.

    A lead that holds a live finding is never marked. See :func:`_shadow_mark`.
    """
    lead = await db.get(Lead, lead_id)
    if lead is None:
        return False
    rows = (
        (await db.execute(select(EntityObservation).where(EntityObservation.lead_id == lead_id)))
        .scalars()
        .all()
    )
    mark = _shadow_mark(rows, at=datetime.now(UTC))
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

    An observation an analyst marked benign is not live (migration 0062). It
    counts toward no lead, the way the observations of a dismissed lead do.
    """
    at = now or datetime.now(UTC)
    rows = (
        (
            await db.execute(
                select(EntityObservation).where(
                    EntityObservation.entity_kind == entity_kind,
                    EntityObservation.entity_key == entity_key,
                    EntityObservation.dismissed_at.is_(None),
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
            born_at=decays_from(row.observed_at, row.born_at),
            count=int(row.occurrences or 1),
            now=at,
            half_life_hours=half_life_hours,
            floor=floor,
        )
        if weight <= 0.0:
            continue
        stack = live_weight(
            float(row.birth_weight or 0.0),
            born_at=decays_from(row.observed_at, row.born_at),
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


def no_lead_sentence(observations: Sequence[WeighedObservation]) -> str:
    """Why the observations on one entity form no lead, in the rule's numbers.

    The hits card said "This hit formed no lead and joined none." and gave no
    cause. The sentence states the types, their live weight and what the
    formation rule asks for. The numbers come from the constants that decide.
    """
    if not observations:
        return "The observation has decayed. It weighs nothing now and forms no lead."
    total = lead_total((o.kind, o.weight) for o in observations)
    kinds = {o.kind for o in observations}
    if len(kinds) == 1:
        return (
            f"One type at weight {total:.2f}. A lead needs {DEFAULT_LEAD_THRESHOLD:.2f} over "
            f"{DEFAULT_MIN_KINDS} types, or {SINGLE_SIGNAL_THRESHOLD:.2f} on one type."
        )
    return (
        f"{len(kinds)} types at weight {total:.2f}. "
        f"A lead needs {DEFAULT_LEAD_THRESHOLD:.2f} over {DEFAULT_MIN_KINDS} types."
    )


async def no_lead_reasons(
    db: AsyncSession,
    entities: Sequence[tuple[str, str]],
    *,
    now: datetime | None = None,
) -> dict[tuple[str, str], str]:
    """:func:`no_lead_sentence` for each entity, one weighing per entity."""
    out: dict[tuple[str, str], str] = {}
    for entity_kind, entity_key in dict.fromkeys(entities):
        weighed = await weigh_entity(db, entity_kind=entity_kind, entity_key=entity_key, now=now)
        out[(entity_kind, entity_key)] = no_lead_sentence(weighed)
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

    A live finding is the exception to the history rule. A true-positive
    alert that arrives after a clean hunt is an answer the hunt did not read.
    It is not joined to the closed lead, whatever types that lead held. An
    alert that joined as history and then became a true positive leaves the
    closed lead for the same reason (:func:`_release_from_hunt_close`).
    """
    from soc_ai.store.leads import CLOSED_STATUSES  # noqa: PLC0415 - avoids an import cycle

    naive_at = at.replace(tzinfo=None) if at.tzinfo is not None else at
    observations = await _release_from_hunt_close(db, observations)
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
    # A live finding is never history. The hunt that closed the lead did not
    # read it, so it goes on to an open lead of its own (see form_leads).
    #
    # A shadow observation leaves a closed lead that holds a live finding
    # alone. It cannot join that lead, so a reopen for it would hand the loop
    # a lead with nothing new in it: the hunt closes it, the observation is
    # still loose, and the next sweep reopens it. One alert took four hunts.
    out_of_reach = await _holds_finding(db, int(lead.id))
    repeats = [o for o in loose if not _is_live_finding(o) and not (out_of_reach and o.shadow)]
    if not repeats:
        return kept
    if {o.kind.value for o in repeats} <= held:
        await _join_lead(db, lead.id, repeats)
        await db.commit()
        joined = {o.id for o in repeats}
        return [o for o in kept if o.id not in joined]
    from soc_ai.store.leads import (  # noqa: PLC0415 - avoids an import cycle
        AUTO_HUNT_ACTOR,
        record_decision,
    )

    # The history keeps the close and states the reopen. Written before the
    # dismissal is cleared, so a row with no history yet keeps its close.
    # reopened_at stays empty: soc-ai reopened this lead, so the loop hunts it.
    record_decision(lead, "reopened", naive_at, by=AUTO_HUNT_ACTOR, reason="new_type")
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


def _is_live_finding(observation: WeighedObservation) -> bool:
    """Whether the observation forms a lead alone and comes from a live source.

    A true-positive alert, or a hit of a live analytic that declares no benign
    population. The same hit from a shadow analytic is not one: shadow records
    and never acts.
    """
    return not observation.shadow and is_finding_grade(observation.kind, observation.birth_weight)


def _is_live_lead(lead: Lead) -> bool:
    """Whether the loop and the analyst treat the lead as work: open or hunting, not shadow."""
    return lead.status in MERGEABLE_STATUSES and not lead.shadow


def _row_is_live_finding(row: EntityObservation) -> bool:
    """:func:`_is_live_finding` for a stored row. A row marked benign is not one."""
    if row.shadow or row.dismissed_at is not None:
        return False
    try:
        kind = Kind(str(row.kind))
    except ValueError:
        return False
    return is_finding_grade(kind, float(row.birth_weight or 0.0))


def _shadow_mark(
    rows: Sequence[EntityObservation],
    *,
    at: datetime,
    half_life_hours: float = DEFAULT_HALF_LIFE_HOURS,
    floor: float = DEFAULT_FLOOR,
) -> bool:
    """Whether the rows of one lead mark it shadow.

    One shadow row marks the lead, decayed or not. A lead that holds a live
    finding is the exception: it is never marked. soc-ai can move a live
    analytic back to shadow, and its row then turned the lead of a
    true-positive alert into a shadow lead that the loop does not hunt.

    Only a finding that still has weight counts for the exception. A decayed
    alert in an old shadow lead must not turn that lead live.
    """
    if not any(bool(row.shadow) for row in rows):
        return False
    for row in rows:
        if not _row_is_live_finding(row):
            continue
        weight = live_weight(
            float(row.birth_weight or 0.0),
            born_at=decays_from(row.observed_at, row.born_at),
            count=int(row.occurrences or 1),
            now=at,
            half_life_hours=half_life_hours,
            floor=floor,
        )
        if weight > 0.0:
            return False
    return True


_FINDING_KINDS = (Kind.ALERT.value, Kind.PRIOR_NO_BASELINE.value)


async def _finding_leads(db: AsyncSession) -> frozenset[int]:
    """The live leads that hold a live finding, decayed or not.

    A shadow observation must not join one of them. One shadow observation
    marks its whole lead shadow, and the loop hunts no shadow lead, so a
    shadow analytic would stop the hunt of a true-positive alert.
    """
    rows = await db.scalars(
        select(EntityObservation)
        .join(Lead, Lead.id == EntityObservation.lead_id)
        .where(
            Lead.status.in_(MERGEABLE_STATUSES),
            Lead.shadow.is_(False),
            EntityObservation.kind.in_(_FINDING_KINDS),
        )
    )
    return frozenset(int(row.lead_id) for row in rows if row.lead_id and _row_is_live_finding(row))


async def _holds_finding(db: AsyncSession, lead_id: int) -> bool:
    """Whether one lead, open or closed, holds a live finding, decayed or not."""
    rows = await db.scalars(
        select(EntityObservation).where(
            EntityObservation.lead_id == lead_id, EntityObservation.kind.in_(_FINDING_KINDS)
        )
    )
    return any(_row_is_live_finding(row) for row in rows)


async def _detach(
    db: AsyncSession, observations: Sequence[WeighedObservation], moved: set[int], *, why: str
) -> list[WeighedObservation]:
    """Take the observations named in ``moved`` out of their leads, and say why."""
    out: list[WeighedObservation] = []
    for obs in observations:
        if obs.id not in moved:
            out.append(obs)
            continue
        row = await db.get(EntityObservation, obs.id)
        if row is not None:
            _LOGGER.info("observation %s left lead %s: %s", obs.id, obs.lead_id, why)
            row.lead_id = None
        out.append(replace(obs, lead_id=None))
    await db.commit()
    return out


async def _release_from_hunt_close(
    db: AsyncSession, observations: Sequence[WeighedObservation]
) -> list[WeighedObservation]:
    """Release an alert that became a true positive after it joined a closed lead.

    An alert that needs more info joins the lead a clean hunt closed, as
    history. The Oracle can then confirm it, or a run is sent again, and the
    same row is a true positive. The hunt ended before the alert arrived, so
    the alert leaves the closed lead and goes to a live one.

    Only a lead that a hunt closed is read, and only an alert recorded after
    that close. The alert that the hunt did read stays: released, it would
    start the same hunt again. An alert row keeps its record time for good,
    because a new verdict on one alert cites no new document.
    """
    from soc_ai.store.leads import (  # noqa: PLC0415 - avoids an import cycle
        AUTO_HUNT_ACTOR,
        alert_rule_of,
        closed_at_of,
    )

    held = {o.lead_id for o in observations if o.lead_id and _late_alert_candidate(o)}
    if not held:
        return list(observations)
    leads = (await db.scalars(select(Lead).where(Lead.id.in_(sorted(held))))).all()
    closes = {
        int(lead.id): closed_at_of(lead)
        for lead in leads
        if lead.status == "dismissed" and lead.dismissed_by == AUTO_HUNT_ACTOR
    }
    late = [
        o
        for o in observations
        if _late_alert_candidate(o)
        and (closed_at := closes.get(o.lead_id or 0)) is not None
        and o.born_at > closed_at
    ]
    if not late:
        return list(observations)
    # An alert of a rule that the lead held at its close stays: it is a repeat
    # of the question the close answered (see _join_closed_lead_of_rule).
    entity = (late[0].entity_kind, late[0].entity_key)
    answered = await _rules_held_at_close(
        db, {k: v for k, v in closes.items() if v is not None}, entity=entity
    )
    moved: set[int] = set()
    for obs in late:
        row = await db.get(EntityObservation, obs.id)
        rule = alert_rule_of(row) if row is not None else None
        if not rule or rule not in answered.get(obs.lead_id or 0, set()):
            moved.add(obs.id)
    if not moved:
        return list(observations)
    return await _detach(db, observations, moved, why="the alert became a true positive")


async def _rules_held_at_close(
    db: AsyncSession, closes: dict[int, datetime], *, entity: tuple[str, str]
) -> dict[int, set[str]]:
    """The alert rules each closed lead held on this entity when it closed.

    ``closes`` maps a lead to its close time. An alert that joined the lead
    after that time is not counted: the close did not answer it.
    """
    from soc_ai.store.leads import alert_rule_of  # noqa: PLC0415 - avoids an import cycle

    if not closes:
        return {}
    rows = await db.scalars(
        select(EntityObservation).where(
            EntityObservation.entity_kind == entity[0],
            EntityObservation.entity_key == entity[1],
            EntityObservation.kind == Kind.ALERT.value,
            EntityObservation.lead_id.in_(sorted(closes)),
        )
    )
    held: dict[int, set[str]] = {}
    for row in rows:
        lead_id = int(row.lead_id or 0)
        rule = alert_rule_of(row)
        if rule and row.born_at <= closes[lead_id]:
            held.setdefault(lead_id, set()).add(rule)
    return held


async def _join_closed_lead_of_rule(
    db: AsyncSession,
    observations: Sequence[WeighedObservation],
    *,
    entity: tuple[str, str],
    rules: _Rules,
) -> list[WeighedObservation]:
    """Join a true-positive alert to the closed lead that answered its rule.

    After a lead closed, each new true positive on its host formed a new lead
    and a new hunt, with no limit. A host that draws internet scans got a
    hunt after every close. A true positive whose rule the lead held when it
    closed is a repeat of the question that close answered. Inside the decay
    horizon of the close it joins the closed lead and starts nothing, for
    each type of close. The lead row states the count and the newest repeat
    (:func:`soc_ai.store.leads.repeats_after_close`).

    The bound is one rule on one entity for one horizon. Another rule,
    another host and a later alert each form a live lead that the loop hunts.
    The caller asks only when the entity has no open live lead: an open lead
    takes the alert first. A lead that an analyst reopened is open.
    """
    from soc_ai.store.leads import (  # noqa: PLC0415 - avoids an import cycle
        CLOSED_STATUSES,
        alert_rule_of,
        closed_at_of,
    )

    waiting = [
        o
        for o in observations
        if o.lead_id is None and o.kind is Kind.ALERT and _is_live_finding(o)
    ]
    if not waiting:
        return list(observations)
    on_entity = await db.scalars(
        select(EntityObservation.lead_id).where(
            EntityObservation.entity_kind == entity[0],
            EntityObservation.entity_key == entity[1],
            EntityObservation.kind == Kind.ALERT.value,
            EntityObservation.lead_id.is_not(None),
        )
    )
    lead_ids = sorted({int(i) for i in on_entity if i})
    if not lead_ids:
        return list(observations)
    at = rules.at.replace(tzinfo=None) if rules.at.tzinfo is not None else rules.at
    since = at - timedelta(hours=decay_horizon_hours(rules.half_life_hours, rules.floor))
    leads = await db.scalars(
        select(Lead).where(Lead.id.in_(lead_ids), Lead.status.in_(tuple(CLOSED_STATUSES)))
    )
    closes = {
        int(lead.id): closed_at
        for lead in leads
        if (closed_at := closed_at_of(lead)) is not None and closed_at >= since
    }
    answered = await _rules_held_at_close(db, closes, entity=entity)
    newest_first = sorted(answered, key=lambda lead_id: closes[lead_id], reverse=True)
    joined: set[int] = set()
    for obs in waiting:
        row = await db.get(EntityObservation, obs.id)
        rule = alert_rule_of(row) if row is not None else None
        target = next((i for i in newest_first if rule and rule in answered[i]), None)
        if row is None or target is None:
            continue
        _LOGGER.info(
            "observation %s joined closed lead %s: the lead held its alert rule at the close",
            obs.id,
            target,
        )
        row.lead_id = target
        joined.add(obs.id)
    if not joined:
        return list(observations)
    await db.commit()
    return [o for o in observations if o.id not in joined]


def _late_alert_candidate(observation: WeighedObservation) -> bool:
    return observation.kind is Kind.ALERT and _is_live_finding(observation)


async def _release_misplaced_findings(
    db: AsyncSession, observations: Sequence[WeighedObservation], *, rules: _Rules
) -> list[WeighedObservation]:
    """Release each live finding that sits in a lead the loop does not hunt.

    A live finding never joins a shadow lead or a fleet condition. A row can
    still become one after it joined: an alert that needed more info gets a
    true-positive verdict. The row then leaves that lead, and the caller
    places it like a finding that just arrived. The true positives that
    joined a fleet condition before this rule take the same path.

    The lead that lost the row states the types it still holds.
    """
    held = {o.lead_id for o in observations if o.lead_id and _is_live_finding(o)}
    if not held:
        return list(observations)
    leads = (await db.scalars(select(Lead).where(Lead.id.in_(sorted(held))))).all()
    not_live = {int(lead.id): lead for lead in leads if not _is_live_lead(lead)}
    moved = {o.id for o in observations if _is_live_finding(o) and o.lead_id in not_live}
    if not moved:
        return list(observations)
    out = await _detach(
        db, observations, moved, why="a live finding does not stay in a lead with no hunt"
    )
    for lead in not_live.values():
        kinds, _subjects, _shadow = await _lead_shape(
            db, lead.id, at=rules.at, half_life_hours=rules.half_life_hours, floor=rules.floor
        )
        lead.kinds_json = sorted(kinds)
    await db.commit()
    return out


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
    db: AsyncSession,
    *,
    entity: tuple[str, str],
    related: Sequence[tuple[str, str]],
    live_only: bool = False,
    exclude: frozenset[int] = frozenset(),
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

    ``live_only`` leaves out the shadow leads, and ``exclude`` leaves out the
    leads named. The hub count reads every mergeable lead all the same: a
    filter must not turn a hub into an ordinary host.
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
    leads = [
        lead for lead in leads if lead.id not in exclude and not (live_only and bool(lead.shadow))
    ]

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
    # The shadow mark reads EVERY attached row, decayed or not. A lead that
    # a shadow analytic contributed to keeps the mark after that
    # observation has decayed, because the analytic is still not live. A
    # lead that holds a live finding is never marked.
    shadow = _shadow_mark(rows, at=at, half_life_hours=half_life_hours, floor=floor)
    for row in rows:
        subjects.add((row.entity_kind, row.entity_key))
        weight = live_weight(
            float(row.birth_weight or 0.0),
            born_at=decays_from(row.observed_at, row.born_at),
            count=int(row.occurrences or 1),
            now=at,
            half_life_hours=half_life_hours,
            floor=floor,
        )
        if weight <= 0.0:
            continue
        kinds.add(str(row.kind))
    return kinds, subjects, shadow


# A condition is WHAT was noticed, across entities: the kind and the content
# fingerprint. A profile fingerprint is the dimension and the member, so port
# 4444 newly served on three hosts is one condition on three subjects.
_Condition = tuple[str, str]


def _counts_toward_span(source: str | None, kind: str, birth: float) -> bool:
    """Whether an observation's condition can make a fleet condition.

    Only a profile departure. A catalog fingerprint carries the entity and an
    alert's is the alert id, so neither is shared across hosts. A promoted hunt
    finding names its hosts on purpose. A finding-grade observation forms a
    lead wherever it lands: the same finding on many hosts is an outbreak far
    more often than a deployment, and a fleet status keeps the loop from
    hunting it.
    """
    if (source or "profile") != "profile":
        return False
    try:
        return not is_finding_grade(Kind(kind), birth)
    except ValueError:
        return False


async def _condition_span(
    db: AsyncSession,
    conditions: set[_Condition],
    *,
    at: datetime,
    half_life_hours: float,
    floor: float,
) -> int:
    """The most subjects that hold one of these conditions live. 0 for none.

    This is the span the cap reads. Counting the observations of the one
    entity being weighed made the span 1 at every formation, so a fleet
    condition was unreachable and one condition on N hosts formed N leads.
    Only LIVE rows count: a sighting past the decay horizon is history.
    """
    if not conditions:
        return 0
    rows = (
        (
            await db.execute(
                select(EntityObservation).where(
                    EntityObservation.fingerprint.in_(sorted({fp for _k, fp in conditions}))
                )
            )
        )
        .scalars()
        .all()
    )
    holders: dict[_Condition, set[tuple[str, str]]] = {}
    for row in rows:
        condition = (str(row.kind), str(row.fingerprint))
        if condition not in conditions:
            continue
        if not _counts_toward_span(row.source, str(row.kind), float(row.birth_weight or 0.0)):
            continue
        weight = live_weight(
            float(row.birth_weight or 0.0),
            born_at=decays_from(row.observed_at, row.born_at),
            count=int(row.occurrences or 1),
            now=at,
            half_life_hours=half_life_hours,
            floor=floor,
        )
        if weight <= 0.0:
            continue
        holders.setdefault(condition, set()).add((row.entity_kind, row.entity_key))
    return max((len(h) for h in holders.values()), default=0)


def _conditions_of(observations: Sequence[WeighedObservation]) -> set[_Condition]:
    """The span-bearing conditions among these weighed observations."""
    return {
        (o.kind.value, o.fingerprint)
        for o in observations
        if _counts_toward_span(o.source, o.kind.value, o.birth_weight)
    }


async def _lead_conditions(
    db: AsyncSession,
    lead_id: int,
    *,
    at: datetime,
    half_life_hours: float,
    floor: float,
) -> set[_Condition]:
    """The span-bearing conditions of the LIVE observations attached to a lead.

    Read from every attached row, as :func:`_lead_shape` reads them, so a lead
    about two entities is not re-measured from whichever the sweep reached last.
    """
    rows = (
        (await db.execute(select(EntityObservation).where(EntityObservation.lead_id == lead_id)))
        .scalars()
        .all()
    )
    out: set[_Condition] = set()
    for row in rows:
        birth = float(row.birth_weight or 0.0)
        if not _counts_toward_span(row.source, str(row.kind), birth):
            continue
        weight = live_weight(
            birth,
            born_at=decays_from(row.observed_at, row.born_at),
            count=int(row.occurrences or 1),
            now=at,
            half_life_hours=half_life_hours,
            floor=floor,
        )
        if weight > 0.0:
            out.add((str(row.kind), str(row.fingerprint)))
    return out


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
    finding: bool = False,
) -> Lead:
    """Write one lead and attach every observation that formed it.

    ``entities`` is what the lead NAMES: the entity the observations are about
    and the ones they mentioned. ``span`` counts only the first sort, because
    the span cap asks how many subjects share one condition and a hit that
    names eight machines is one subject, not nine. The caller counts the
    subjects of the CONDITION, across entities (:func:`_condition_span`).

    The subject comes first in the list. It was sorted, so a host a hit merely
    mentioned could lead a lead about an account, and every surface reads the
    first entity as the subject.

    ``finding`` is true when a live finding forms the lead. Such a lead is
    never a fleet condition, whatever the span of the other observations. The
    status came from the span alone, and production lead 69 formed as a fleet
    condition on its first true-positive alert, so the loop never hunted it.
    """
    lead = Lead(
        status=STATUS_FLEET if span > span_cap and not finding else STATUS_OPEN,
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

    The span is measured as at formation: the subjects that share one of the
    lead's conditions, across entities. The status does not change here. A
    lead that is open or hunting stays the analyst's and the loop's to settle.
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
    conditions = await _lead_conditions(
        db, lead.id, at=at, half_life_hours=half_life_hours, floor=floor
    )
    span = max(
        len(subjects),
        await _condition_span(db, conditions, at=at, half_life_hours=half_life_hours, floor=floor),
    )
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


@dataclass
class _Tally:
    """What one :func:`form_leads` call did, collected as it goes."""

    formed: list[int]
    updated: list[int]
    fleet: list[int]
    notes: list[str]


@dataclass(frozen=True)
class _Rules:
    """The numbers one :func:`form_leads` call runs on."""

    at: datetime
    threshold: float
    min_kinds: int
    span_cap: int
    half_life_hours: float
    floor: float
    shadow: bool


def _related_of(
    observations: Sequence[WeighedObservation], entity: tuple[str, str]
) -> list[tuple[str, str]]:
    """The other entities these observations named, in order."""
    return sorted({r for o in observations for r in o.related if tuple(r) != entity})


async def _lead_of(
    db: AsyncSession,
    observations: Sequence[WeighedObservation],
    *,
    entity: tuple[str, str],
    live_only: bool = False,
    exclude: frozenset[int] = frozenset(),
) -> tuple[Lead | None, bool]:
    """The lead these observations belong to, and whether it is a merge.

    The lead one of them is attached to comes first. A lead that names the
    entity, or holds an observation about an entity they named, comes second
    and counts as a merge. ``live_only`` and ``exclude`` narrow both.

    An entity can hold two leads: a fleet condition or a shadow lead, and the
    live lead a finding formed beside it. Live observations then take the
    live lead, and a group that holds a shadow observation takes the other.
    The order of the rows decided it before, which is no rule.
    """
    attached: list[Lead] = []
    for lead_id in dict.fromkeys(o.lead_id for o in observations if o.lead_id):
        if lead_id in exclude:
            continue
        lead = await db.get(Lead, lead_id)
        if lead is not None and (not live_only or _is_live_lead(lead)):
            attached.append(lead)
    if attached:
        wants_live = not any(o.shadow for o in observations)
        return next((a for a in attached if _is_live_lead(a) == wants_live), attached[0]), False
    lead = await _merge_target(
        db,
        entity=entity,
        related=_related_of(observations, entity),
        live_only=live_only,
        exclude=exclude,
    )
    return lead, lead is not None


async def _place(
    db: AsyncSession,
    observations: Sequence[WeighedObservation],
    *,
    entity: tuple[str, str],
    lead: Lead | None,
    merged: bool,
    rules: _Rules,
    tally: _Tally,
) -> Lead | None:
    """Join these observations to ``lead``, or form a lead from the loose ones.

    Returns the lead they landed in, or None when they form nothing.
    """
    loose = [o for o in observations if o.lead_id is None]
    members = observations if lead is not None else loose
    if not members:
        return None
    # Capped per kind. Forty-five rows of one kind are one story told
    # forty-five times, and the sum said 25 where the story said 1.7.
    total = lead_total((o.kind, o.weight) for o in members)
    kinds = {o.kind for o in members}
    related = _related_of(members, entity)
    forms, single_signal = _forms_a_lead(
        members, total=total, kinds=kinds, threshold=rules.threshold, min_kinds=rules.min_kinds
    )
    if lead is None and not forms:
        return None

    if lead is None:
        # A new lead names this entity and the ones its observations
        # mentioned. The span counts the subjects only, and it counts the
        # subjects of each CONDITION across the estate. Counting this
        # entity's own observations made the span 1 at every formation,
        # and the fleet status unreachable. See _condition_span.
        span = max(
            len({(o.entity_kind, o.entity_key) for o in members}),
            await _condition_span(
                db,
                _conditions_of(members),
                at=rules.at,
                half_life_hours=rules.half_life_hours,
                floor=rules.floor,
            ),
        )
        new_lead = await _new_lead(
            db,
            members,
            at=rules.at,
            total=total,
            kind_values=sorted(k.value for k in kinds),
            entities=[entity, *sorted(set(related) - {entity})],
            span=span,
            span_cap=rules.span_cap,
            shadow=rules.shadow or any(o.shadow for o in members),
            single_signal=single_signal,
            finding=any(_is_live_finding(o) for o in members),
        )
        if new_lead.status == STATUS_FLEET:
            tally.fleet.append(new_lead.id)
            tally.notes.append(
                f"lead {new_lead.id} spans {new_lead.scope_count} entities. "
                f"The cap is {rules.span_cap}. soc-ai recorded it as a fleet condition"
            )
        else:
            tally.formed.append(new_lead.id)
        return new_lead

    if await _extend_lead(
        db,
        lead,
        members,
        entity=entity,
        related=related,
        at=rules.at,
        half_life_hours=rules.half_life_hours,
        floor=rules.floor,
        single_signal=single_signal,
        shadow=rules.shadow,
        merged=merged,
    ):
        tally.updated.append(lead.id)
    return lead


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

    **A live finding lands in a live lead.** A live finding is a true-positive
    alert, or a hit of a live analytic that declares no benign population. It
    joins a lead that is open or hunting and not shadow, or it forms one. It
    never joins a shadow lead or a fleet condition, and the lead it forms is
    never either. The loop hunts no shadow lead and no fleet condition. On
    production, 23 of 30 alert observations joined a fleet condition formed
    by a shadow rate analytic, and 13 of 17 true-positive verdicts started no
    hunt. A shadow analytic records and never acts, so it must not stop a
    live signal.

    The same rule read from the other side: a shadow observation never joins
    a live lead that holds a live finding. It would mark that lead shadow.

    A second live finding on an entity with a live lead joins that lead. The
    lead keeps the hunt it has, so twenty true positives on one host are one
    lead and one hunt.

    The bound after a close: a true-positive alert whose rule a lead held
    when it closed joins that closed lead for the decay horizon, and starts
    no hunt (:func:`_join_closed_lead_of_rule`).

    A row can become a live finding after it joined a lead: an alert that
    needed more info gets a true-positive verdict. Such a row leaves a shadow
    lead, a fleet condition and a lead that a hunt closed before the alert
    arrived, and it is placed like a finding that just arrived.
    """
    at = now or datetime.now(UTC)
    rules = _Rules(
        at=at,
        threshold=threshold,
        min_kinds=min_kinds,
        span_cap=span_cap,
        half_life_hours=half_life_hours,
        floor=floor,
        shadow=shadow,
    )
    tally = _Tally(formed=[], updated=[], fleet=[], notes=[])

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
        observations = await _release_misplaced_findings(db, observations, rules=rules)

        live = [o for o in observations if not o.shadow]
        in_shadow = [o for o in observations if o.shadow]
        guarded = await _finding_leads(db) if in_shadow else frozenset()
        a_finding_waits = any(o.lead_id is None and _is_live_finding(o) for o in live)
        # Where the live observations belong, read before anything moves. Only
        # a finding that waits, or a lead that holds one, asks the question.
        live_lead, live_merged = (
            await _lead_of(db, live, entity=entity, live_only=True)
            if live and (a_finding_waits or guarded)
            else (None, False)
        )
        if a_finding_waits and live_lead is None:
            # No open live lead takes the alert. A lead that closed inside
            # the decay horizon and held its rule takes it, and no hunt starts.
            observations = await _join_closed_lead_of_rule(
                db, observations, entity=entity, rules=rules
            )
            live = [o for o in observations if not o.shadow]
            in_shadow = [o for o in observations if o.shadow]
            a_finding_waits = any(o.lead_id is None and _is_live_finding(o) for o in live)
            if not observations:
                continue
        if in_shadow and (a_finding_waits or (live_lead is not None and live_lead.id in guarded)):
            # Two placements. The live observations land in a live lead, and
            # the shadow observations stay out of it.
            landed = await _place(
                db,
                live,
                entity=entity,
                lead=live_lead,
                merged=live_merged,
                rules=rules,
                tally=tally,
            )
            keep_out = guarded | ({landed.id} if landed is not None else frozenset())
            shadow_lead, shadow_merged = await _lead_of(
                db, in_shadow, entity=entity, exclude=keep_out
            )
            await _place(
                db,
                in_shadow,
                entity=entity,
                lead=shadow_lead,
                merged=shadow_merged,
                rules=rules,
                tally=tally,
            )
            continue

        if a_finding_waits:
            # No shadow observation is on the entity. The finding still must
            # not join a shadow lead or a fleet condition that names it.
            lead, merged = live_lead, live_merged
        else:
            lead, merged = await _lead_of(db, observations, entity=entity, exclude=guarded)
        await _place(
            db, observations, entity=entity, lead=lead, merged=merged, rules=rules, tally=tally
        )

    return LeadOutcome(
        formed=tuple(tally.formed),
        updated=tuple(tally.updated),
        fleet_conditions=tuple(tally.fleet),
        notes=tuple(tally.notes),
    )
