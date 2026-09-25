"""What an observation is worth, now.

Live weight is computed on READ from the half-life. There is deliberately no
decay job: one that misses a night leaves every weight in the system overstated
and nothing anywhere says so, which is the shape of defect this project keeps
finding.

Three behaviours here are load-bearing and easy to get subtly wrong.

**Stacking is sub-linear and capped.** A repeat of the same spec and content on
the same entity refreshes the observation rather than adding a new one, and the
weight grows as ``w · (1 + ln n)`` to a ceiling of 1.0. A campaign of identical
steps should be louder than a single step; uncapped, one repeated observation
alone clears any threshold on its own and the two-kind requirement becomes
decorative.

**The floor is a cliff, not a clamp.** Below it an observation is history —
kept for the dossier timeline, never summed. Clamping to the floor instead
would let ten thousand dead observations quietly add up to a lead.

**Birth weights are inverted from the first draft.** A novel destination or
process for a host is the strongest single statistical signal. "Outside active
hours" is the weakest, because it is the clause most exposed to clock changes,
shift patterns and daylight saving — the things that move without anything
happening.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

__all__ = [
    "ALERT_WEIGHT_BY_VERDICT",
    "DEFAULT_FLOOR",
    "DEFAULT_HALF_LIFE_HOURS",
    "DEFAULT_LEAD_THRESHOLD",
    "DEFAULT_MIN_KINDS",
    "KIND_FOR_DIMENSION",
    "KIND_WEIGHT_CAP",
    "Kind",
    "KindWeight",
    "alert_weight",
    "birth_weight",
    "decay_horizon_hours",
    "is_finding_grade",
    "kind_for_dimension",
    "lead_total",
    "live_weight",
    "stacked",
    "weight_by_kind",
]

# Chosen to be MOVED. The design is explicit that the half-life, floor and
# threshold are picked in shadow to satisfy the geometry requirement, not the
# other way round — as first drafted the numbers made accumulation impossible
# and leads would have been priors plus alerts and nothing else.
DEFAULT_HALF_LIFE_HOURS = 48.0
DEFAULT_FLOOR = 0.05

# 0.85, not the 1.0 the design first wrote down, and the reason is arithmetic
# rather than taste. The design requires that two observations of the strongest
# kind inside one working day form a lead. Two at 0.5 sum to exactly 1.0 only
# with ZERO decay; eight hours apart at a 48-hour half-life they sum to 0.945,
# so at a threshold of 1.0 that case can never pass. Three of the weakest kind
# across a working day reach 0.850.
#
# 0.850 is the largest threshold both required cases clear while keeping the
# birth weights the design argued for. Moving the threshold rather than the
# weights is deliberate: the weights encode which signals matter, and the
# design named the threshold as the thing to choose in shadow.
#
# tests/test_lead_geometry.py pins this. Change it and that test says so.
DEFAULT_LEAD_THRESHOLD = 0.85
"""Derived, on 2026-09-15, from the two cases the design requires a lead for.

Two observations of the strongest kind eight hours apart sum to 0.945, and
three of the weakest kind across a working day sum to 0.850, so 0.850 is the
largest threshold both cases clear. It has not yet been validated against a
miss: read `GET /api/v1/leads/quality` for a week before moving it."""

DEFAULT_MIN_KINDS = 2


class Kind(Enum):
    """What sort of observation this is. The kind carries the birth weight.

    These follow the design's LAYER 2 CLAUSE VOCABULARY, one kind per clause.
    That matters more than it looks. The first cut collapsed every "a member
    this baseline does not hold" clause into a single ``novel_member`` kind,
    and since a lead needs two different kinds, that made the whole novelty
    half of the design unable to form a lead by itself — including the exact
    scenario it was designed around: a workstation that visits a new external
    destination one evening and opens a connection to a new internal port the
    next day.

    The birth-weight paragraph in the design says "a novel destination OR
    process … ≈ 0.5". That assigns them the same WEIGHT. It does not make them
    the same KIND, and reading it that way is what broke the layer.
    """

    # --- the novelty clauses, one kind each -------------------------------
    # A destination this host has not talked to. Covers both the address and
    # the name: they describe ONE connection, and separating them would let a
    # single outbound flow contribute two kinds and form a lead on its own.
    NOVEL_DESTINATION = "novel_destination"
    # A port this host has not served before.
    NOVEL_SERVED_PORT = "novel_served_port"
    # A port this host has not connected out on before.
    NOVEL_CONSUMED_PORT = "novel_consumed_port"
    # An executable this host has not run.
    NOVEL_PROCESS = "novel_process"
    # A (parent, child) pair this host has not produced — the shape that
    # catches a familiar binary launched from an unfamiliar place.
    NOVEL_PROCESS_PAIR = "novel_process_pair"
    # This principal on this host for the first time.
    NOVEL_BINDING = "novel_binding"

    # --- the other clauses ------------------------------------------------
    # A member that is rare across the entity's peer group.
    RARE_FOR_PEERS = "rare_for_peers"
    # Activity outside the entity's own measured active hours.
    OFF_HOURS = "off_hours"
    # A numeric dimension far below its own median — a backup that stopped.
    BELOW_BASELINE = "below_baseline"
    # ...and far above it.
    ABOVE_BASELINE = "above_baseline"
    # One spec touched many distinct scopes inside the window. A sweep across
    # forty hosts is a second KIND, not forty refreshes of one observation.
    SCOPE_COUNT = "scope_count"
    # A triaged alert, weighted by its verdict elsewhere.
    ALERT = "alert"
    # A catalog query analytic matched, and the analytic has a benign
    # population. It needs a second kind. A no-baseline analytic writes
    # PRIOR_NO_BASELINE instead.
    CATALOG_MATCH = "catalog_match"
    # An analyst promoted a hunt finding or marked it as a threat.
    HUNT_FINDING = "hunt_finding"
    # A prior that declares no benign population. Born a finding.
    PRIOR_NO_BASELINE = "prior_no_baseline"


# The novelty kinds all share the strongest weight, per the design: "a novel
# destination or process for a host is the strongest single statistical signal".
_NOVELTY = 0.5

_BIRTH_WEIGHTS: dict[Kind, float] = {
    Kind.PRIOR_NO_BASELINE: 1.0,
    # A catalog hit from an analytic that has a benign population. It is worth
    # more than a novelty and less than a finding, so it needs a second kind.
    Kind.CATALOG_MATCH: 0.7,
    # An analyst read this and promoted it, so it carries the same weight.
    Kind.HUNT_FINDING: 0.7,
    Kind.NOVEL_DESTINATION: _NOVELTY,
    Kind.NOVEL_SERVED_PORT: _NOVELTY,
    Kind.NOVEL_CONSUMED_PORT: _NOVELTY,
    Kind.NOVEL_PROCESS: _NOVELTY,
    Kind.NOVEL_PROCESS_PAIR: _NOVELTY,
    Kind.NOVEL_BINDING: _NOVELTY,
    Kind.RARE_FOR_PEERS: 0.45,
    Kind.SCOPE_COUNT: 0.4,
    Kind.BELOW_BASELINE: 0.35,
    Kind.ABOVE_BASELINE: 0.35,
    Kind.ALERT: 0.35,
    # The weakest, because it is the clause most exposed to clock changes,
    # shift patterns and daylight saving — things that move without anything
    # happening.
    Kind.OFF_HOURS: 0.3,
}

# Which profile dimension produces which kind.
#
# peers_out and dns_names deliberately share NOVEL_DESTINATION: a new address
# and the name that resolved to it are one connection, and giving them separate
# kinds would let a single outbound flow satisfy the two-kind rule on its own.
KIND_FOR_DIMENSION: dict[str, Kind] = {
    "peers_out": Kind.NOVEL_DESTINATION,
    "dns_names": Kind.NOVEL_DESTINATION,
    "served_ports": Kind.NOVEL_SERVED_PORT,
    "consumed_ports": Kind.NOVEL_CONSUMED_PORT,
    "process_names": Kind.NOVEL_PROCESS,
    "process_parents": Kind.NOVEL_PROCESS_PAIR,
    "logon_users": Kind.NOVEL_BINDING,
}


def kind_for_dimension(dimension: str) -> Kind:
    """The observation kind a profile dimension produces.

    Falls back to NOVEL_DESTINATION for an unmapped dimension rather than
    raising: a dimension added without a mapping should still contribute
    something, and the strongest-weight default makes the omission visible in
    the numbers rather than silently dropping the observation.
    """
    return KIND_FOR_DIMENSION.get(dimension, Kind.NOVEL_DESTINATION)


def birth_weight(kind: Kind) -> float:
    """What an observation of this kind is worth when it is new."""
    return _BIRTH_WEIGHTS[kind]


# An alert observation is weighted by its triage verdict. A false positive is
# not recorded. The base weight of Kind.ALERT stays for callers that have no
# verdict.
ALERT_WEIGHT_BY_VERDICT: dict[str, float] = {
    "true_positive": 1.0,
    "needs_more_info": 0.5,
}


def alert_weight(verdict: str | None) -> float | None:
    """The birth weight for an alert with this verdict, or None to not record."""
    return ALERT_WEIGHT_BY_VERDICT.get(str(verdict or ""))


def is_finding_grade(kind: Kind, weight: float) -> bool:
    """True if one observation of this kind and weight forms a lead alone.

    A no-baseline prior is a finding. A true-positive alert is a finding. A
    catalog hit from a no-baseline analytic is recorded as PRIOR_NO_BASELINE,
    so it is covered by the first rule.
    """
    if kind is Kind.PRIOR_NO_BASELINE:
        return True
    return kind is Kind.ALERT and weight >= 1.0


def stacked(weight: float, *, count: float, cap: float | None = 1.0) -> float:
    """``w · (1 + ln n)``, capped at 1.0.

    ``cap=None`` returns the raw stack. The single-signal rule reads it: at the
    cap, a 0.7 kind seen twice reads 1.0 and so does a 0.7 kind seen fifty
    times, and a rule that fires at 1.0 cannot tell them apart.

    Worth knowing before tuning in shadow: at a birth weight of 0.5 the ceiling
    is reached at ``n = e`` — about 2.7. Stacking therefore separates "once"
    from "more than twice" for the strongest kind and nothing finer. If a
    campaign should outrank a pair, the birth weight has to come down or the
    cap has to go up; the logarithm cannot do it alone.

    A count below one is treated as one. ``ln(0)`` is negative infinity and
    ``ln(0.5)`` is negative, either of which would turn an observation into a
    negative weight that SUBTRACTS from the lead it belongs to.
    """
    n = max(1.0, float(count))
    value = weight * (1.0 + math.log(n))
    return value if cap is None else min(cap, value)


def live_weight(
    weight: float,
    *,
    born_at: datetime,
    count: float = 1.0,
    now: datetime | None = None,
    half_life_hours: float = DEFAULT_HALF_LIFE_HOURS,
    floor: float = DEFAULT_FLOOR,
    cap: float | None = 1.0,
) -> float:
    """What this observation is worth at ``now``. Zero once below the floor.

    ``cap=None`` decays the uncapped stack, which is what the single-signal
    rule reads. Everything that SUMS observations reads the capped value.

    A naive ``born_at`` is read as UTC. The store hands back naive datetimes,
    and reading them as local time shifts every weight in the system by the
    deployment's offset — up to five hours of decay applied or skipped.

    An observation born in the future decays by nothing rather than gaining
    weight: clock skew between a grid and its reader is routine, and a negative
    age multiplies the weight UP.
    """
    at = now or datetime.now(UTC)
    if born_at.tzinfo is None:
        born_at = born_at.replace(tzinfo=UTC)
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)

    age_hours = max(0.0, (at - born_at).total_seconds() / 3600.0)
    value = stacked(weight, count=count, cap=cap)
    if half_life_hours > 0:
        value *= 0.5 ** (age_hours / half_life_hours)

    # A cliff. Below the floor this is history, and history is never summed.
    return value if value >= floor else 0.0


def decay_horizon_hours(
    half_life_hours: float = DEFAULT_HALF_LIFE_HOURS, floor: float = DEFAULT_FLOOR
) -> float:
    """The age at which a full-weight observation drops below the floor.

    Derived from the two constants :func:`live_weight` floors on, not a third
    number: ``half_life * log2(1 / floor)``. With the defaults that is 207.4
    hours. The lead layer reads it as the span in which a closed lead still
    answers for a repeat of the types it held.
    """
    if half_life_hours <= 0 or floor <= 0 or floor >= 1:
        return 0.0
    return half_life_hours * math.log2(1.0 / floor)


# What one kind can contribute to a lead's total. Two thresholds: one kind at
# the cap is a lead-and-a-half worth of one story, and a second kind at any
# weight is what turns it into a chain. Production summed 45 novel served
# ports to 25 against a threshold of 0.85, and 25 ranked nothing, because
# the one thing it measured was how many rows the sweep had written.
KIND_WEIGHT_CAP = 2.0 * DEFAULT_LEAD_THRESHOLD


@dataclass(frozen=True)
class KindWeight:
    """The live weight of one kind on a lead, against the cap one kind can reach."""

    kind: str
    weight: float
    cap: float
    saturated: bool


def weight_by_kind(
    pairs: Iterable[tuple[Kind | str, float]], *, cap: float = KIND_WEIGHT_CAP
) -> list[KindWeight]:
    """Sum live weights per kind, each kind capped, kinds in name order.

    A negative weight counts as zero. Nothing here subtracts from a lead.
    """
    sums: dict[str, float] = {}
    for kind, weight in pairs:
        key = kind.value if isinstance(kind, Kind) else str(kind)
        sums[key] = sums.get(key, 0.0) + max(0.0, float(weight))
    return [
        KindWeight(kind=key, weight=min(cap, total), cap=cap, saturated=total >= cap)
        for key, total in sorted(sums.items())
    ]


def lead_total(pairs: Iterable[tuple[Kind | str, float]], *, cap: float = KIND_WEIGHT_CAP) -> float:
    """A lead's total: the capped sum of each kind.

    Formation writes this as ``weight_at_formation`` and the lead page reads
    it as ``weight_now``, so the two agree.
    """
    return sum(row.weight for row in weight_by_kind(pairs, cap=cap))
