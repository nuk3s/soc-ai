"""What every tier 3 detector takes and returns. Pure: no grid, no store.

A detector reads the grid through the context it is given and returns one
state per entity it considered, with the hits it found on that entity. The
``model`` evaluator (:mod:`soc_ai.hunting.model`) turns the states into
sweep results and the hits into observations.

**The false-all-clear rule.** A detector never states an all-clear. Every
entity it considered carries one of seven states, and only ``measured`` means
that the entity was scored. The other six each name a different reason why it
was not, and a sweep that reports them as clean reports coverage it never
gave. Every hit cites at least one document. A hit with none is dropped by the
evaluator and counted, because the lead auto-hunt skips a lead with no cited
document, and an observation nobody can open is a claim, not evidence.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.hunting.weight import Kind

__all__ = [
    "DETECTOR_STATES",
    "STATE_BLIND",
    "STATE_DRIFTED",
    "STATE_HELD",
    "STATE_LEARNING",
    "STATE_MEASURED",
    "STATE_STALE",
    "STATE_UNMEASURABLE",
    "STATISTIC_CHAIN_MINUTES",
    "STATISTIC_PLANE_DOCUMENTS",
    "Detector",
    "DetectorContext",
    "DetectorRun",
    "EntityState",
    "ModelHit",
    "complete_hours",
    "hour_floor",
    "iso",
    "oql_stamp",
    "plain_address",
]

# The entity was scored against what the detector learned.
STATE_MEASURED = "measured"
# The entity has too little history to score.
STATE_LEARNING = "learning"
# The detector could not read the plane it needs.
STATE_BLIND = "blind"
# The entity cannot be scored by this detector at all: a machine with one
# telemetry plane has no second plane to compare against.
STATE_UNMEASURABLE = "unmeasurable"
# What the detector learned is older than it may be.
STATE_STALE = "stale"
# The entity's features moved past what the detector learned. Refit first.
STATE_DRIFTED = "drifted"
# The detector found a hit and held it: the condition is the grid's, not the
# entity's.
STATE_HELD = "held"

DETECTOR_STATES: tuple[str, ...] = (
    STATE_MEASURED,
    STATE_LEARNING,
    STATE_BLIND,
    STATE_UNMEASURABLE,
    STATE_STALE,
    STATE_DRIFTED,
    STATE_HELD,
)

# The names of the statistics a detector hit records. The console formats each
# one in words (lib/statistics.ts and soc_ai.hunting.wording), so a name is
# part of the API and does not change.
STATISTIC_PLANE_DOCUMENTS = "plane_documents"
STATISTIC_CHAIN_MINUTES = "chain_minutes"


@dataclass(frozen=True)
class ModelHit:
    """One departure a detector found on one entity, with its evidence.

    ``fingerprint`` names WHAT was noticed, without time or count, so the same
    condition on the same entity refreshes one observation. ``features`` are
    the top contributing features and their values, in the order the reason
    sentence names them. ``reason`` is that sentence.
    """

    entity_key: str
    kind: Kind
    fingerprint: tuple[str, ...]
    statistic: str
    statistic_value: float
    baseline_value: float | None
    document_ids: tuple[str, ...]
    rerun_query: str | None
    reason: str
    features: Mapping[str, Any] = field(default_factory=dict)
    observed_at: datetime | None = None
    entity_kind: str = "host"


@dataclass(frozen=True)
class EntityState:
    """What a detector concluded about one entity."""

    entity_key: str
    state: str
    note: str = ""
    hits: tuple[ModelHit, ...] = ()
    entity_kind: str = "host"


@dataclass(frozen=True)
class DetectorRun:
    """Everything one detector run concluded.

    ``blind`` is set when the detector could read nothing it needs. The run
    then has no entity, and the evaluator records one blind result that says
    why. It is never an empty run that reads as a quiet estate.
    """

    entities: tuple[EntityState, ...] = ()
    notes: tuple[str, ...] = ()
    blind: str | None = None


@dataclass(frozen=True)
class DetectorContext:
    """What a detector may read. One per sweep, shared by every model spec.

    ``now`` is the time anchor: the recent window ends there. ``census`` and
    ``cidrs`` say which addresses are the estate's. ``windows`` are the
    windows an investigation confirmed as an attack, per host key. A
    detector does not learn from them.
    """

    elastic: Any
    settings: Any
    db: Any
    now: datetime
    tz: str = "UTC"
    census: frozenset[str] = frozenset()
    cidrs: tuple[Any, ...] = ()
    windows: Mapping[str, list[tuple[datetime, datetime]]] = field(default_factory=dict)

    @property
    def index(self) -> str:
        return str(getattr(self.settings, "events_index_pattern", "logs-*") or "logs-*")

    def in_estate(self, address: str) -> bool:
        """Whether an address belongs to the estate. Fails OPEN with no census and no CIDR."""
        if not self.census and not self.cidrs:
            return True
        if address in self.census:
            return True
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in net for net in self.cidrs if getattr(net, "version", 0) == ip.version)


Detector = Callable[[Any, DetectorContext], Awaitable[DetectorRun]]


def hour_floor(at: datetime) -> datetime:
    """The UTC start of the hour that holds ``at``."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def complete_hours(*, hours: int, end: datetime) -> list[datetime]:
    """The UTC starts of the whole hours inside the last ``hours`` before ``end``.

    The hour that holds ``end`` is still filling. It would read as a silence.
    """
    last = hour_floor(end)
    first = last - timedelta(hours=max(1, hours))
    out: list[datetime] = []
    at = first
    while at < last:
        out.append(at)
        at += timedelta(hours=1)
    return out


def iso(at: datetime) -> str:
    """An aware UTC timestamp as Elasticsearch reads it."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.astimezone(UTC).isoformat()


def oql_stamp(at: datetime) -> str:
    """A timestamp as an OQL range writes it."""
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def plain_address(value: Any) -> str | None:
    """A unicast address a machine can own, or None.

    Loopback, link-local, multicast and the unspecified address belong to no
    machine. Every host reports ``127.0.0.1``, and a join on it would make
    the whole estate one machine.
    """
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return None
    return str(ip)
