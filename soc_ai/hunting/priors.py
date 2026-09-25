"""The ``profile`` evaluator: a spec that reads a baseline instead of a document.

A prior asks "is this ordinary for this entity, given its role?". It produces
value on day one, before any entity has enough history to score against,
because the question it asks of a role does not need a baseline — a domain
controller originating RDP to a workstation is worth a look on the first day
the sensor is plugged in.

**Three answers, not two.** Every result carries a coverage state, and the
three non-firing ones mean different things that a single "clean" would erase:

``measured``          the baseline is real and was compared against
``learning``          the entity exists but has under seven days of history
``blind``             nothing could be measured — no plane, no profile, or an
                      unconfident role
``not_applicable``    the prior is scoped to roles this entity is not in

Reporting any of the last three as clean is the false all-clear this whole
layer exists to prevent, and it is worse than reporting nothing at all, because
it counts as coverage that was never given.

**The confidence gate is inverted.** A prior evaluates only where the dossier
is confident about the role. Below the threshold it is blind and says so; it is
never demoted to a weak observation. Demotion sounds conservative and is the
opposite: it turns every host the dossier cannot classify into a safe harbour,
and a host nobody can classify is exactly where a careful attacker lives.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from soc_ai.dossier.profile_math import (
    GUARDED_PORT_DIMENSIONS,
    LINUX_EPHEMERAL_START,
    robust_z,
    served_port_counts,
)
from soc_ai.hunting.spec import HuntSpec
from soc_ai.hunting.weight import Kind, kind_for_dimension
from soc_ai.hunting.window import DEFAULT_RECENT_HOURS
from soc_ai.hunting.wording import plural, result_note
from soc_ai.store.entity_profiles import ProfileRow

__all__ = [
    "COVERAGE_BLIND",
    "COVERAGE_LEARNING",
    "COVERAGE_MEASURED",
    "COVERAGE_NOT_APPLICABLE",
    "GUARDED_PORT_DIMENSIONS",
    "LINUX_EPHEMERAL_START",
    "Departure",
    "PriorResult",
    "evaluate_prior",
    "served_port_counts",
]

COVERAGE_MEASURED = "measured"
COVERAGE_LEARNING = "learning"
COVERAGE_BLIND = "blind"
COVERAGE_NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class Departure:
    """One member of a dimension that the entity's baseline does not hold.

    ``baseline_size`` and ``support_days`` travel with it because the finding
    is unreadable without them. "445 is new on this switch" means one thing
    when the switch has served exactly one port for thirty days and another
    when it has served two hundred for three.
    """

    dimension: str
    member: str
    observed: Any
    baseline_size: int
    support_days: int
    # How many times it was seen in the recent window. An analyst reading
    # "port 3389 is new here" needs to know whether that happened twice or two
    # thousand times.
    observed_count: int = 0
    # The three numbers a rate departure is made of. The summary said "far
    # above" for a 13 % move and named a median of its own, while the profile
    # panel showed the baseline median for the same cell. All three travel with
    # the departure so that one sentence can state them together.
    observed_value: float | None = None
    baseline_median: float | None = None
    ratio: float | None = None
    # The documents the recent read saw this member in, up to three of them.
    # A departure without them is a claim an analyst cannot open: the range
    # formed a lead whose objective said "no document ids recorded" against
    # every observation in it, and the hunt re-queried the grid rather than
    # read the evidence that formed the lead.
    sample_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class PriorResult:
    """What one prior concluded about one entity."""

    spec_id: str
    entity_kind: str
    entity_key: str
    coverage: str
    departures: tuple[Departure, ...] = ()
    note: str = ""
    # Which observation kind these departures are worth. Taken from the SPEC,
    # because a prior that declares no benign population is a finding in its
    # own right while an ordinary novel member is a contribution toward one --
    # reading it off the departure would make every prior equally loud.
    kind: Kind = Kind.NOVEL_DESTINATION

    @property
    def fired(self) -> bool:
        return bool(self.departures)


def _observed_count(value: Any) -> int:
    """How many times the caller says it saw this member.

    Zero for anything unreadable. Callers hand this whatever they measured, and
    an odd shape must neither crash the sweep nor sail past the recurrence
    floor — both of which a permissive default would allow.
    """
    return (
        _observed_int(value, "count")
        if isinstance(value, Mapping)
        else _observed_int({"count": value}, "count")
    )


def _observed_int(value: Any, key: str) -> int:
    """One integer the caller measured for this member. Zero when unreadable.

    Zero is the reading that does NOT count. A member the recent read could
    not describe must not pass a guard that asks how many peers reached it.
    """
    raw = value.get(key) if isinstance(value, Mapping) else None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return 0
    return int(raw)


def _sample_ids(value: Any) -> tuple[str, ...]:
    """The document ids the caller sampled for this member.

    Empty for anything unreadable, and for the plain counts an older caller
    hands in. A dimension whose plane returns no hits still has to produce a
    readable departure.
    """
    if not isinstance(value, Mapping):
        return ()
    raw = value.get("sample_ids")
    if isinstance(raw, (str, bytes)) or not isinstance(raw, (list, tuple, set, frozenset)):
        return ()
    out: list[str] = []
    for item in raw:
        text = str(item)
        if text and text not in out:
            out.append(text)
    return tuple(out)


def _kind_for(spec: HuntSpec) -> Kind:
    """A no-baseline prior is born a finding; everything else takes its kind
    from the dimension it read.

    The dimension matters because a lead needs two different kinds. Returning
    one flat "novel member" for every dimension is what made the novelty half
    of this design unable to form a lead on its own — see
    tests/test_lead_geometry.py.
    """
    if spec.no_benign_baseline:
        return Kind.PRIOR_NO_BASELINE
    if spec.profile is None:
        return Kind.NOVEL_DESTINATION
    if spec.profile.test == "outside_active_hours":
        return Kind.OFF_HOURS
    if spec.profile.test == "above":
        return Kind.ABOVE_BASELINE
    if spec.profile.test == "below":
        return Kind.BELOW_BASELINE
    return kind_for_dimension(spec.profile.dimension)


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _observed_value(value: Any) -> float | None:
    """The measured magnitude for a rate test, or None if unreadable."""
    raw = value.get("value") if isinstance(value, Mapping) else value
    return _as_float(raw)


def _blank(spec: HuntSpec, profile: ProfileRow | None, coverage: str, note: str) -> PriorResult:
    return PriorResult(
        spec_id=spec.id,
        entity_kind=profile.entity_kind if profile else "host",
        entity_key=profile.entity_key if profile else "*",
        coverage=coverage,
        departures=(),
        note=note,
        kind=_kind_for(spec),
    )


def evaluate_prior(  # noqa: PLR0912, PLR0915 - one function reads as one procedure
    spec: HuntSpec,
    *,
    profile: ProfileRow | None,
    observed: Mapping[Any, Any],
    role: str | None,
    role_confidence: float | None,
    window_hours: int = DEFAULT_RECENT_HOURS,
) -> PriorResult:
    """Compare what was just seen against what this entity's baseline holds.

    ``observed`` is a mapping of member -> whatever the caller measured for it;
    only the keys are read for ``novel_for``. Keys are compared as strings,
    because ports arrive as integers from one plane and strings from another,
    and comparing by type makes every port on the second plane novel forever.
    """
    test = spec.profile
    if test is None:
        return _blank(spec, profile, COVERAGE_BLIND, "spec carries no profile block")

    # The inverted gate applies ONLY to specs that read the role.
    #
    # The design's wording is "cannot apply ROLE PRIORS: role unknown". A prior
    # that reasons from a role cannot reason without one. A layer-2 clause --
    # hour outside active_hours, rate_of above/below -- compares a host to its
    # OWN baseline and never consults its role, so gating it on role confidence
    # produces the same safe harbour the inversion exists to close, arriving
    # from the other side: on a grid where most hosts are unclassified, those
    # clauses never fire, so no second kind ever appears and no chain can form
    # on exactly the machines nobody can identify.
    #
    # ``roles`` being non-empty is the signal, because it is the only thing in
    # a spec that makes it role-dependent.
    if test.roles:
        # Gate BEFORE scoping, and the order matters. "Not applicable" is a
        # claim that this prior has nothing to say about this entity, which can
        # only be made once the role is known. Scoping first would answer "not
        # applicable" to every role-scoped prior on an unclassified host, and a
        # host that no prior applies to reads as covered.
        confidence = role_confidence if role_confidence is not None else 0.0
        if role is None or confidence < test.min_role_confidence:
            return _blank(
                spec,
                profile,
                COVERAGE_BLIND,
                "cannot apply role priors: role unknown or below the confidence "
                f"gate ({confidence:.2f} < {test.min_role_confidence:.2f})",
            )
        if role not in test.roles:
            return _blank(
                spec,
                profile,
                COVERAGE_NOT_APPLICABLE,
                f"prior applies to {', '.join(test.roles)}; this entity is {role}",
            )

    if profile is None:
        return _blank(
            spec,
            profile,
            COVERAGE_BLIND,
            f"no {test.dimension} profile has been built for this entity",
        )

    if profile.coverage == COVERAGE_LEARNING:
        return _blank(
            spec,
            profile,
            COVERAGE_LEARNING,
            f"learning: {plural(profile.support_days, 'day')} of history. "
            "Everything is novel below the floor.",
        )

    if not profile.is_scorable:
        return _blank(
            spec,
            profile,
            COVERAGE_BLIND,
            f"{test.dimension} is {profile.coverage} for this entity",
        )

    baseline = profile.vector if isinstance(profile.vector, Mapping) else {}
    known = {str(k) for k in baseline}

    departures: list[Departure] = []

    if test.test == "outside_active_hours":
        # An EMPTY hour set means this entity was never seen active at all,
        # which is a coverage problem wearing the clothes of a 24-hour anomaly.
        # Firing here would make every hour of every quiet host a departure.
        if known:
            for raw_member, value in observed.items():
                member = str(raw_member)
                if member in known:
                    continue
                count = _observed_count(value)
                if count < test.min_observations:
                    continue
                departures.append(
                    Departure(
                        dimension=test.dimension,
                        member=member,
                        observed=value,
                        baseline_size=len(known),
                        support_days=profile.support_days,
                        observed_count=count,
                        sample_ids=_sample_ids(value),
                    )
                )

    elif test.test in {"above", "below"}:
        for raw_cell, value in observed.items():
            cell = str(raw_cell)
            summary = baseline.get(cell)
            if not isinstance(summary, Mapping):
                continue
            current = _observed_value(value)
            if current is None:
                continue
            med = _as_float(summary.get("median"))
            z = robust_z(
                value=current,
                med=med,
                dispersion=_as_float(summary.get("dispersion")),
            )
            # None means the cell has no dispersion to measure against.
            # Treating that as "very far from the median" makes every cell
            # whose samples happen to be identical fire on anything.
            if z is None:
                continue
            # Nothing is a multiple of zero, and a departure that cannot say
            # how far it travelled is not one an analyst can read.
            if med is None or med <= 0.0:
                continue
            ratio = current / med
            crossed = z >= test.threshold if test.test == "above" else z <= -test.threshold
            # The SAME threshold, applied to the multiple of the median.
            #
            # A robust z is a distance in dispersions. On a cell whose samples
            # sit close together it reaches 7.8 for a 13 % move, and the range
            # reported 2446 per hour against a median of 2216 as a rate far
            # above its own baseline. The threshold reads as "3 times" to
            # everyone who opens the analytic, so it is applied that way too.
            far = ratio >= test.threshold if test.test == "above" else ratio <= 1.0 / test.threshold
            if not (crossed and far):
                continue
            departures.append(
                Departure(
                    dimension=test.dimension,
                    member=cell,
                    observed=value,
                    baseline_size=len(known),
                    support_days=profile.support_days,
                    observed_count=int(current),
                    observed_value=current,
                    baseline_median=med,
                    ratio=ratio,
                    sample_ids=_sample_ids(value),
                )
            )

    elif test.test == "novel_for":
        guarded = test.dimension in GUARDED_PORT_DIMENSIONS
        for raw_member, value in observed.items():
            member = str(raw_member)
            if member in known:
                continue
            count = _observed_count(value)
            # Recurrence floor. One sighting is not a pattern, and the whole
            # ephemeral-port false-positive class is exactly one sighting.
            if count < test.min_observations:
                continue
            # The peers-or-days guard, on served ports. The floor counts
            # documents, and an endpoint sensor writes one DNS lookup as two
            # documents with the entity on the receiving side. The guard asks
            # who reached the port and on how many days, which no sensor
            # mirrors.
            if guarded and not served_port_counts(
                member,
                count=count,
                peers=_observed_int(value, "peers"),
                days=_observed_int(value, "days"),
            ):
                continue
            departures.append(
                Departure(
                    dimension=test.dimension,
                    member=member,
                    observed=value,
                    baseline_size=len(known),
                    support_days=profile.support_days,
                    observed_count=count,
                    sample_ids=_sample_ids(value),
                )
            )

    # The note reads in the analyst's words, from the same module the stored
    # summary and the CLI read. It said "9 novel consumed_ports against a
    # baseline of 15 over 30 day(s)", which is the column name and a count.
    note = result_note(
        _kind_for(spec),
        departures,
        baseline_size=len(known),
        support_days=profile.support_days,
        window_hours=window_hours,
    )
    return PriorResult(
        spec_id=spec.id,
        entity_kind=profile.entity_kind,
        entity_key=profile.entity_key,
        coverage=COVERAGE_MEASURED,
        departures=tuple(departures),
        note=note,
        kind=_kind_for(spec),
    )
