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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from soc_ai.dossier.profile_math import (
    GUARDED_PORT_DIMENSIONS,
    LINUX_EPHEMERAL_START,
    SET_CAP,
    Seasonal,
    cell_for,
    hour_of_week,
    seasonal_baseline,
    served_port_counts,
)
from soc_ai.hunting.spec import HuntSpec
from soc_ai.hunting.weight import Kind, kind_for_dimension
from soc_ai.hunting.window import DEFAULT_RECENT_HOURS
from soc_ai.hunting.wording import baseline_noun, plural, result_note
from soc_ai.store.entity_profiles import ProfileRow

if TYPE_CHECKING:
    from soc_ai.hunting.detectors.base import ModelHit
    from soc_ai.hunting.estate import EstateView, PeerView

__all__ = [
    "COVERAGE_BLIND",
    "COVERAGE_LEARNING",
    "COVERAGE_MEASURED",
    "COVERAGE_NOT_APPLICABLE",
    "DEFAULT_MIN_KNOWN_DAYS",
    "GUARDED_PORT_DIMENSIONS",
    "LINUX_EPHEMERAL_START",
    "STATISTIC_DOCUMENTS",
    "STATISTIC_ESTATE_HOSTS",
    "STATISTIC_HOUR_DOCUMENTS",
    "STATISTIC_PEER_SHARE",
    "STATISTIC_RESIDUAL_Z",
    "STATISTIC_ROBUST_Z",
    "Departure",
    "PriorResult",
    "evaluate_prior",
    "known_members",
    "member_days",
    "served_port_counts",
]

COVERAGE_MEASURED = "measured"
COVERAGE_LEARNING = "learning"
COVERAGE_BLIND = "blind"
COVERAGE_NOT_APPLICABLE = "not_applicable"

# The four states the sweep trail has a column for.
_TRAIL_STATES = frozenset(
    {COVERAGE_MEASURED, COVERAGE_LEARNING, COVERAGE_BLIND, COVERAGE_NOT_APPLICABLE}
)

# The names of the statistics a departure records. The console formats each
# one in words, so a name is part of the API and does not change.
STATISTIC_DOCUMENTS = "documents"
STATISTIC_ESTATE_HOSTS = "estate_hosts"
STATISTIC_HOUR_DOCUMENTS = "hour_documents"
STATISTIC_PEER_SHARE = "peer_share"
STATISTIC_RESIDUAL_Z = "residual_z"
# The name a rate departure carried before the hourly test. Rows written then
# keep it, and the console still reads it.
STATISTIC_ROBUST_Z = "robust_z"

# The key of the hourly series inside a rate vector. The same string as
# soc_ai.dossier.profile.HOURLY_KEY, which this pure module does not import.
HOURLY_KEY = "hourly"


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
    # The newest timestamp among those documents. The observation decays from
    # it. Without it the observation decayed from the sweep that recorded it,
    # and an event a day old read as fresh. None when no document carries one.
    observed_at: datetime | None = None
    # The statistic that departed, its value, and the value of the baseline it
    # departed from. The observation stores the three in columns, and the lead
    # hunt reads them as numbers. They lived only in the summary sentence.
    statistic: str | None = None
    statistic_value: float | None = None
    baseline_value: float | None = None
    # How many hosts in the estate hold the member, and how many hosts hold a
    # set on the dimension at all. None when the sweep read no prevalence.
    estate_hosts: int | None = None
    estate_measured: int | None = None
    # Fewer hosts than the rare bar hold it. The observation is born heavier.
    estate_rare: bool = False
    # A rate departure is a run of hours. How many, where it starts and ends
    # in UTC, and the local hour of the week of its furthest hour.
    run_hours: int = 0
    run_start: datetime | None = None
    run_end: datetime | None = None
    peak_label: str | None = None
    # The peer group a peer test read: the role, how many peers, and how many
    # of them hold the member. None when no peer group was read.
    peer_role: str | None = None
    peer_count: int | None = None
    peer_holders: int | None = None


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
    # New members that most of the estate already holds. They are traits of
    # the estate and form no observation. The note states how many.
    suppressed: int = 0
    # New members that most peers in the role already hold: traits of the
    # role. They form no observation either.
    role_traits: int = 0
    # The hits of a ``model`` spec, each with its documents. A profile result
    # holds none. See soc_ai.hunting.detectors.base.
    hits: tuple[ModelHit, ...] = ()
    # The hits a detector returned with no cited document. They are dropped
    # before this result is built and form no observation.
    dropped: int = 0

    @property
    def fired(self) -> bool:
        return bool(self.departures or self.hits)

    @property
    def trail_state(self) -> str:
        """The state the sweep trail counts this result under.

        The trail holds four columns. A detector state outside them folds
        into the nearest one: ``held`` was measured, and ``unmeasurable``,
        ``stale`` and ``drifted`` could not be scored, which is blind.
        """
        if self.coverage in _TRAIL_STATES:
            return self.coverage
        return COVERAGE_MEASURED if self.coverage == "held" else COVERAGE_BLIND


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


def _observed_at(value: Any) -> datetime | None:
    """The newest document time the caller read for this member, or None.

    The recent read writes it as ``newest``, an ISO 8601 string, beside the
    sample ids. Anything unreadable is None: the observation then decays from
    the time it was recorded, which is the clock it had before.
    """
    if not isinstance(value, Mapping):
        return None
    raw = value.get("newest")
    if isinstance(raw, datetime):
        stamp = raw
    elif isinstance(raw, str) and raw:
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return stamp if stamp.tzinfo is not None else stamp.replace(tzinfo=UTC)


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
    if spec.profile.test == "rare_for_peers":
        return Kind.RARE_FOR_PEERS
    return kind_for_dimension(spec.profile.dimension)


# A member counts as known after this many days of sightings, by default. The
# spec can raise it. One sighting a month ago made a member known for good:
# the range DC logon set held the attacker's three accounts.
DEFAULT_MIN_KNOWN_DAYS = 2


def member_days(entry: Any) -> int | None:
    """On how many calendar days a stored member was seen, first to last.

    A served port stores it. Every other member stores its first and last
    sighting, and the days run from the date of the one to the date of the
    other. None when the entry says neither: a set from an older build.
    """
    if not isinstance(entry, Mapping):
        return None
    days = entry.get("days")
    if isinstance(days, int) and not isinstance(days, bool) and days > 0:
        return days
    first, last = _stamp(entry.get("first_seen")), _stamp(entry.get("last_seen"))
    if first is None or last is None:
        return None
    return abs((last.astimezone(UTC).date() - first.astimezone(UTC).date()).days) + 1


def known_members(
    vector: Any,
    *,
    min_days: int = DEFAULT_MIN_KNOWN_DAYS,
    exclude: Sequence[tuple[datetime, datetime]] = (),
) -> set[str]:
    """The members of a stored set the baseline knows.

    A member is known when it was seen on ``min_days`` days or more. A member
    first seen inside an ``exclude`` window is not known: it entered the set
    during an attack an investigation confirmed. A member whose entry states
    no days is known, as every member was before the rule: a set from an
    older build must not make every member new at once.
    """
    if not isinstance(vector, Mapping):
        return set()
    windows = [(_aware(a), _aware(b)) for a, b in exclude]
    out: set[str] = set()
    for raw, entry in vector.items():
        member = str(raw)
        days = member_days(entry)
        if days is not None and days < min_days:
            continue
        first = _stamp(entry.get("first_seen")) if isinstance(entry, Mapping) else None
        if first is not None and any(lo <= first < hi for lo, hi in windows):
            continue
        out.add(member)
    return out


def _aware(at: datetime) -> datetime:
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


def _seasonal_of(
    baseline: Mapping[Any, Any], *, tz: str, exclude: Sequence[tuple[datetime, datetime]]
) -> Seasonal | None:
    """The expected count per hour of the week, from the series a rate vector holds."""
    block = baseline.get(HOURLY_KEY)
    if not isinstance(block, Mapping):
        return None
    counts = block.get("counts")
    start = _stamp(block.get("start"))
    if start is None or not isinstance(counts, list) or not counts:
        return None
    values = [
        float(c) if isinstance(c, (int, float)) and not isinstance(c, bool) else 0.0 for c in counts
    ]
    return seasonal_baseline(start, values, tz=tz, exclude=exclude)


def _stamp(raw: Any) -> datetime | None:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo is not None else raw.replace(tzinfo=UTC)
    if not isinstance(raw, str) or not raw:
        return None
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo is not None else stamp.replace(tzinfo=UTC)


@dataclass(frozen=True)
class _Hour:
    """One recent hour that crossed the bar."""

    at: datetime
    count: float
    expected: float
    z: float
    entry: Any


_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")

# How many document ids a rate departure keeps across the hours of its run.
_RUN_SAMPLE_IDS = 10


def _zone_of(tz: str) -> Any:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415 - lazy

    try:
        return ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def _runs(
    hours: list[tuple[datetime, Any]], *, seasonal: Seasonal, above: bool, bar: float, tz: str
) -> list[list[_Hour]]:
    """The runs of consecutive recent hours that cross the bar."""
    runs: list[list[_Hour]] = []
    current: list[_Hour] = []
    previous: datetime | None = None
    for at, entry in hours:
        how = hour_of_week(at, tz=tz)
        expected = seasonal.expected[how]
        sigma = seasonal.sigma(how)
        hit: _Hour | None = None
        if expected is not None and sigma is not None:
            count = float(_observed_count(entry))
            z = (count - expected) / sigma
            far = count >= bar * max(expected, 1.0) if above else count <= expected / bar
            crossed = z >= bar if above else z <= -bar
            if far and crossed:
                hit = _Hour(at=at, count=count, expected=expected, z=z, entry=entry)
        follows = previous is not None and at - previous == timedelta(hours=1)
        if current and (hit is None or not follows):
            runs.append(current)
            current = []
        if hit is not None:
            current.append(hit)
        previous = at
    if current:
        runs.append(current)
    return runs


def _rate_departures(
    test: Any,
    seasonal: Seasonal,
    observed: Mapping[Any, Any],
    *,
    support_days: int,
    tz: str,
) -> list[Departure]:
    """Each run of recent hours that sits far from the expected count of its hour.

    An hour crosses the bar when it sits ``threshold`` dispersions from the
    expected count of its hour of the week, and the count is ``threshold``
    times that expectation, or a ``threshold``-th of it. The dispersion is the
    larger of the pooled MAD and the square root of the expected count, so a
    burst of one hour moves the test. The median of the recent hours did not.

    A departure is a run of ``min_hours`` hours in a row that cross the bar,
    or one hour twice as far out. An hour with no expectation, or with no
    dispersion at an expected count of zero, is unmeasurable. It breaks a run
    and is never a departure. One departure per cell: the run that went
    furthest. Its member is the cell of its furthest hour, so a repeat in the
    same cell refreshes the same observation.
    """
    bar = float(test.threshold)
    hours = sorted(
        (stamp, entry) for key, entry in observed.items() if (stamp := _stamp(key)) is not None
    )
    runs = _runs(hours, seasonal=seasonal, above=test.test == "above", bar=bar, tz=tz)

    best: dict[str, tuple[list[_Hour], _Hour]] = {}
    for run in runs:
        peak = max(run, key=lambda h: abs(h.z))
        if len(run) < test.min_hours and abs(peak.z) < 2.0 * bar:
            continue
        cell = cell_for(peak.at, tz=tz).value
        held = best.get(cell)
        if held is None or abs(peak.z) > abs(held[1].z):
            best[cell] = (run, peak)

    measured = sum(1 for e in seasonal.expected if e is not None)
    out: list[Departure] = []
    for cell, (run, peak) in best.items():
        ids: list[str] = []
        newest: datetime | None = None
        for hour in run:
            for one in _sample_ids(hour.entry):
                if one not in ids and len(ids) < _RUN_SAMPLE_IDS:
                    ids.append(one)
            stamp = _observed_at(hour.entry)
            if stamp is not None and (newest is None or stamp > newest):
                newest = stamp
        local = peak.at.astimezone(_zone_of(tz))
        out.append(
            Departure(
                dimension=test.dimension,
                member=cell,
                observed=peak.entry,
                baseline_size=measured,
                support_days=support_days,
                observed_count=int(peak.count),
                observed_value=peak.count,
                baseline_median=peak.expected,
                ratio=peak.count / peak.expected if peak.expected > 0 else None,
                sample_ids=tuple(ids),
                observed_at=newest,
                statistic=STATISTIC_RESIDUAL_Z,
                statistic_value=round(peak.z, 2),
                baseline_value=peak.expected,
                run_hours=len(run),
                run_start=run[0].at,
                run_end=run[-1].at + timedelta(hours=1),
                peak_label=f"{_WEEKDAYS[local.weekday()]} {local.hour:02d}:00",
            )
        )
    return out


def _role_words(role: str) -> str:
    """A role id as the console writes it: "domain controller"."""
    return role.replace("_", " ")


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
    estate: EstateView | None = None,
    tz: str = "UTC",
    exclude: Sequence[tuple[datetime, datetime]] = (),
    peers: PeerView | None = None,
) -> PriorResult:
    """Compare what was just seen against what this entity's baseline holds.

    ``observed`` is a mapping of member -> whatever the caller measured for it;
    only the keys are read for ``novel_for``. Keys are compared as strings,
    because ports arrive as integers from one plane and strings from another,
    and comparing by type makes every port on the second plane novel forever.

    ``estate`` says how many hosts hold each new member. An estate-common
    member forms no departure. An estate-rare one is marked. None leaves every
    novelty as it was: the sweep read no prevalence.

    ``tz`` is the deployment's zone: the hour of the week is local. ``exclude``
    names windows the baseline must not learn from, such as an attack an
    investigation confirmed.

    ``peers`` is the entity's peer group in its confident role. A new member
    most peers hold is a role trait and forms no departure. ``rare_for_peers``
    reads it to find a new member the peers do not hold either.
    """
    # The notes below reach the console as the blind reason of the analytic.
    # The operator reads them, so they name the dimension in words and the
    # role in plain terms. No code reads their text: the coverage state is the
    # machine-readable part.
    test = spec.profile
    if test is None:
        return _blank(
            spec, profile, COVERAGE_BLIND, "the analytic has no profile section to evaluate."
        )

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
                "the role of this host is not known well enough. The confidence is "
                f"{confidence:.2f} and the gate is {test.min_role_confidence:.2f}.",
            )
        if role not in test.roles:
            return _blank(
                spec,
                profile,
                COVERAGE_NOT_APPLICABLE,
                f"the analytic applies to the role {' or '.join(map(_role_words, test.roles))}. "
                f"This host has the role {_role_words(role)}.",
            )

    if profile is None:
        return _blank(
            spec,
            profile,
            COVERAGE_BLIND,
            f"no {baseline_noun(test.dimension)} baseline exists for this host yet.",
        )

    if profile.coverage == COVERAGE_LEARNING:
        return _blank(
            spec,
            profile,
            COVERAGE_LEARNING,
            f"learning: the baseline holds {plural(profile.support_days, 'day')} of history. "
            "The analytic does not score this host until the baseline holds enough days.",
        )

    if not profile.is_scorable:
        return _blank(
            spec,
            profile,
            COVERAGE_BLIND,
            f"the {baseline_noun(test.dimension)} baseline of this host is {profile.coverage}.",
        )

    baseline = profile.vector if isinstance(profile.vector, Mapping) else {}
    known = {str(k) for k in baseline}
    # The members the baseline knows: seen on enough days, and not first
    # seen inside a confirmed attack. ``known`` stays every stored member,
    # for the cap and for the sentence that states the size of the set.
    familiar = known_members(baseline, min_days=test.min_known_days, exclude=exclude)

    departures: list[Departure] = []
    suppressed = 0
    role_traits = 0

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
                        observed_at=_observed_at(value),
                        # The documents in an hour the baseline holds none in.
                        statistic=STATISTIC_HOUR_DOCUMENTS,
                        statistic_value=float(count),
                        baseline_value=0.0,
                    )
                )

    elif test.test in {"above", "below"}:
        seasonal = _seasonal_of(baseline, tz=tz, exclude=exclude)
        if seasonal is None:
            # A rate baseline built before the hourly series existed holds the
            # three cells only. The next build writes the series. Until then
            # the prior cannot say what an hour should hold.
            return _blank(
                spec,
                profile,
                COVERAGE_BLIND,
                "the baseline holds no hourly series yet. The next profile build writes one.",
            )
        departures.extend(
            _rate_departures(test, seasonal, observed, support_days=profile.support_days, tz=tz)
        )

    elif test.test == "novel_for":
        # A set at the cap holds the top members by document count. A member
        # past the cut reads as new on every sweep, so nothing new can be told
        # from it. The prior says so and stays blind on this entity.
        if len(known) >= SET_CAP:
            return _blank(
                spec,
                profile,
                COVERAGE_BLIND,
                f"the baseline is full. It holds {len(known)} values, the most it can hold. "
                "soc-ai cannot tell a new value from a value past that limit.",
            )
        guarded = test.dimension in GUARDED_PORT_DIMENSIONS
        for raw_member, value in observed.items():
            member = str(raw_member)
            if member in familiar:
                continue
            # A prior about a named class of tool reads only those names. An
            # updater's new file name is new and is not remote execution.
            if not test.reads_member(member):
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
            # A member most of the estate holds is a trait of the estate. A
            # no-baseline prior is a finding however common the member is.
            if estate is not None and not spec.no_benign_baseline and estate.common(member):
                suppressed += 1
                continue
            # A member most peers in the same confident role hold is what the
            # role does. A server that gains the port every server serves has
            # joined its role, not left it.
            if peers is not None and not spec.no_benign_baseline and peers.trait(member):
                role_traits += 1
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
                    observed_at=_observed_at(value),
                    # With prevalence, the statistic is the hosts that hold the
                    # member against the hosts profiled. Without it, the
                    # documents in the window against the set it is new to.
                    statistic=STATISTIC_ESTATE_HOSTS if estate is not None else STATISTIC_DOCUMENTS,
                    statistic_value=float(estate.holders(member) if estate is not None else count),
                    baseline_value=float(estate.measured if estate is not None else len(known)),
                    estate_hosts=estate.holders(member) if estate is not None else None,
                    estate_measured=estate.measured if estate is not None else None,
                    estate_rare=estate is not None and estate.rare(member),
                )
            )

    elif test.test == "rare_for_peers":
        if len(known) >= SET_CAP:
            return _blank(
                spec,
                profile,
                COVERAGE_BLIND,
                f"the baseline is full. It holds {len(known)} values, the most it can hold. "
                "soc-ai cannot tell a new value from a value past that limit.",
            )
        # Without a group of confident peers the test has nothing to compare
        # against. Blind, and the note says which part is missing.
        if peers is None:
            return _blank(
                spec,
                profile,
                COVERAGE_BLIND,
                "no peer group: the role of this host is not known well enough. "
                f"The test needs {test.min_peers} hosts in one role.",
            )
        if not peers.measurable:
            return _blank(
                spec,
                profile,
                COVERAGE_BLIND,
                f"the peer group is too small. The role {_role_words(peers.role)} has "
                f"{plural(peers.peers, 'peer')}. The test needs {test.min_peers}.",
            )
        for raw_member, value in observed.items():
            member = str(raw_member)
            if member in familiar or not test.reads_member(member):
                continue
            count = _observed_count(value)
            if count < test.min_observations:
                continue
            held = peers.held_by(member)
            if held > test.max_peer_share * peers.peers:
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
                    observed_at=_observed_at(value),
                    statistic=STATISTIC_PEER_SHARE,
                    statistic_value=float(held),
                    baseline_value=float(peers.peers),
                    peer_role=peers.role,
                    peer_count=peers.peers,
                    peer_holders=held,
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
    if suppressed:
        note += (
            f" {plural(suppressed, 'new member')} common across the estate formed no observation."
        )
    if role_traits:
        note += (
            f" {plural(role_traits, 'new member')} that most peers in the role hold "
            "formed no observation."
        )
    return PriorResult(
        spec_id=spec.id,
        entity_kind=profile.entity_kind,
        entity_key=profile.entity_key,
        coverage=COVERAGE_MEASURED,
        departures=tuple(departures),
        note=note,
        kind=_kind_for(spec),
        suppressed=suppressed,
        role_traits=role_traits,
    )
