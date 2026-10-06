"""The `profile` evaluator and the role priors it runs.

The behaviour most likely to be implemented backwards is the confidence gate,
so most of these tests are planted against that defect. The design inverts it:
a prior on a low-confidence role is BLIND and says so. It is never demoted to a
weak observation, because that turns a quiet host into a safe harbour, and a
quiet host is exactly where a careful attacker lives.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.dossier.profile_math import HOURS_PER_WEEK
from soc_ai.hunting.priors import (
    COVERAGE_BLIND,
    COVERAGE_LEARNING,
    COVERAGE_MEASURED,
    COVERAGE_NOT_APPLICABLE,
    LINUX_EPHEMERAL_START,
    evaluate_prior,
    known_members,
    member_days,
    served_port_counts,
)
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog
from soc_ai.store.entity_profiles import ProfileRow


def _spec(**profile: Any) -> HuntSpec:
    block = {"dimension": "served_ports", "test": "novel_for"}
    block.update(profile)
    return HuntSpec.model_validate(
        {
            "id": "prior-test",
            "title": "A prior under test",
            "evaluator": "profile",
            "profile": block,
            "scope_field": "host.name",
        }
    )


def _profile(
    *,
    vector: Any = None,
    coverage: str = "measured",
    support_days: int = 30,
    dimension: str = "served_ports",
) -> ProfileRow:
    return ProfileRow(
        entity_kind="host",
        entity_key="10.1.10.254",
        dimension=dimension,
        shape="categorical",
        vector={"22": {"count": 40}} if vector is None else vector,
        coverage=coverage,
        coverage_reason=None,
        support_days=support_days,
        role="network_device",
        role_confidence=0.9,
        identity_fingerprint=None,
        window_days=30,
        first_seen=None,
        last_seen=None,
        built_at=None,
    )


def _seen(count: int, *, peers: int = 2, days: int = 2, **extra: Any) -> dict[str, Any]:
    """One observed member with what the recent read now carries.

    Two peers and two days by default, so a member counts as a served port
    unless the test says otherwise.
    """
    return {"count": count, "peers": peers, "days": days, **extra}


# ---------------------------------------------------------------------------
# The inverted confidence gate
# ---------------------------------------------------------------------------


def test_a_low_confidence_role_is_blind_not_weakly_firing() -> None:
    result = evaluate_prior(
        _spec(roles=["network_device"]),
        profile=_profile(),
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.5,
    )
    assert result.coverage == COVERAGE_BLIND
    assert result.departures == ()
    assert "role" in result.note.lower()


def test_an_unknown_role_is_blind_not_a_free_pass() -> None:
    result = evaluate_prior(
        _spec(roles=["network_device"]),
        profile=_profile(),
        observed={"445": _seen(4)},
        role=None,
        role_confidence=None,
    )
    assert result.coverage == COVERAGE_BLIND
    assert result.departures == ()


# N2 of the 2026-10-05 verification. The blind notes reach the console as the
# reason under the coverage count. They read "cannot apply role priors: role
# unknown or below the confidence gate (0.50 < 0.90)" and "no connection_rate
# profile has been built for this entity". The operator read the data model.
_INTERNAL_WORDS = ("role priors", "confidence gate", "<", "_", "entity", "spec ", "profile block")


def _plain(note: str) -> None:
    for word in _INTERNAL_WORDS:
        assert word not in note, (word, note)


def test_the_role_gate_note_states_the_confidence_and_the_gate_in_words() -> None:
    result = evaluate_prior(
        _spec(roles=["network_device"]),
        profile=_profile(),
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.5,
    )
    assert result.note == (
        "the role of this host is not known well enough. The confidence is 0.50 and the gate "
        "is 0.90."
    )
    _plain(result.note)


def test_the_unknown_role_note_states_a_confidence_of_zero() -> None:
    result = evaluate_prior(
        _spec(roles=["network_device"]),
        profile=_profile(),
        observed={"445": _seen(4)},
        role=None,
        role_confidence=None,
    )
    assert "The confidence is 0.00 and the gate is 0.90." in result.note
    _plain(result.note)


@pytest.mark.parametrize(
    ("dimension", "words"),
    [
        ("connection_rate", "connection rate"),
        ("active_hours", "active hours"),
        ("served_ports", "served port"),
        ("dns_names", "DNS name"),
    ],
)
def test_the_no_baseline_note_names_the_dimension_in_words(dimension: str, words: str) -> None:
    result = evaluate_prior(
        _spec(dimension=dimension),
        profile=None,
        observed={"445": _seen(4)},
        role=None,
        role_confidence=None,
    )
    assert result.coverage == COVERAGE_BLIND
    assert result.note == f"no {words} baseline exists for this host yet."
    _plain(result.note)


def test_the_unscorable_baseline_note_names_the_dimension_in_words() -> None:
    result = evaluate_prior(
        _spec(dimension="connection_rate"),
        profile=_profile(coverage="stale", dimension="connection_rate"),
        observed={"work": _seen(4)},
        role=None,
        role_confidence=None,
    )
    assert result.coverage == COVERAGE_BLIND
    assert result.note == "the connection rate baseline of this host is stale."
    _plain(result.note)


def test_the_not_applicable_note_names_both_roles() -> None:
    result = evaluate_prior(
        _spec(roles=["domain_controller", "server"]),
        profile=_profile(),
        observed={"445": _seen(4)},
        role="workstation",
        role_confidence=0.9,
    )
    assert result.coverage == COVERAGE_NOT_APPLICABLE
    assert result.note == (
        "the analytic applies to the role domain controller or server. "
        "This host has the role workstation."
    )
    _plain(result.note)


def test_a_high_confidence_role_evaluates_normally() -> None:
    result = evaluate_prior(
        _spec(roles=["network_device"]),
        profile=_profile(),
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.coverage == COVERAGE_MEASURED
    assert [d.member for d in result.departures] == ["445"]


def test_a_prior_scoped_to_other_roles_does_not_apply() -> None:
    # Not applicable is a third answer, distinct from blind and from clean.
    # A domain-controller prior on a workstation has nothing to say, and
    # reporting that as "clean" would let it count as coverage it never gave.
    result = evaluate_prior(
        _spec(roles=["domain_controller"]),
        profile=_profile(),
        observed={"445": _seen(4)},
        role="workstation",
        role_confidence=0.9,
    )
    assert result.coverage == COVERAGE_NOT_APPLICABLE
    assert result.departures == ()


def test_a_prior_with_no_roles_applies_to_every_role() -> None:
    result = evaluate_prior(
        _spec(),
        profile=_profile(),
        observed={"445": _seen(4)},
        role="workstation",
        role_confidence=0.9,
    )
    assert result.coverage == COVERAGE_MEASURED
    assert [d.member for d in result.departures] == ["445"]


# ---------------------------------------------------------------------------
# Coverage before conclusions
# ---------------------------------------------------------------------------


def test_a_blind_profile_produces_no_departures() -> None:
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector=None, coverage="blind"),
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.coverage == COVERAGE_BLIND
    assert result.departures == ()


def test_a_learning_profile_produces_no_departures() -> None:
    # Below the support floor an entity has not earned the right to call
    # anything unusual. Everything is novel on day one.
    result = evaluate_prior(
        _spec(),
        profile=_profile(coverage="learning", support_days=3),
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.coverage == "learning"
    assert result.departures == ()
    assert "3" in result.note


def test_a_missing_profile_is_blind_not_clean() -> None:
    # The entity has never been profiled. That is a coverage gap, and calling
    # it clean is the false all-clear this layer exists to prevent.
    result = evaluate_prior(
        _spec(),
        profile=None,
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.coverage == COVERAGE_BLIND
    assert result.departures == ()


def test_a_measured_but_empty_baseline_still_scores() -> None:
    # The mirror image, and the reason coverage is not just emptiness: a device
    # that has genuinely served no ports in 30 days has an empty set that MEANS
    # something, and the first port on it is a real departure.
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={}),
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.coverage == COVERAGE_MEASURED
    assert [d.member for d in result.departures] == ["445"]


# ---------------------------------------------------------------------------
# novel_for
# ---------------------------------------------------------------------------


def test_a_member_already_in_the_baseline_is_not_a_departure() -> None:
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}, "445": {"count": 5}}),
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures == ()


def test_several_novel_members_each_produce_a_departure() -> None:
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={"445": _seen(4), "3389": _seen(2), "22": _seen(9)},
        role="network_device",
        role_confidence=0.9,
    )
    assert {d.member for d in result.departures} == {"445", "3389"}


def test_a_departure_carries_what_the_baseline_held_for_context() -> None:
    # An analyst reading "445 is new on this switch" needs to know the switch
    # has served exactly one port for thirty days, not that it serves hundreds.
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.9,
    )
    departure = result.departures[0]
    assert departure.baseline_size == 1
    assert departure.support_days == 30


def test_member_keys_are_compared_as_strings_not_by_type() -> None:
    # Ports arrive as ints from one plane and strings from another. Comparing
    # by type makes every port on the second plane novel forever.
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={22: {"count": 9}},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures == ()


# ---------------------------------------------------------------------------
# The shipped priors
# ---------------------------------------------------------------------------


def test_every_shipped_prior_loads_and_declares_false_positives() -> None:
    catalog = load_catalog(CATALOG_DIR)
    priors = {k: v for k, v in catalog.items() if v.evaluator == "profile"}
    assert priors, "the catalog ships no priors"
    for spec_id, spec in priors.items():
        assert spec.profile is not None
        assert spec.false_positives, f"{spec_id} declares no false positives"
        assert spec.description.strip(), f"{spec_id} has no description"


def test_the_single_shot_events_declare_no_benign_baseline() -> None:
    # The design's last three: they never accumulate, and they are how the
    # highest-impact events are covered at all. A triage must not close them
    # on how often they fire. They shipped as priors that read the wrong
    # dimension; they are now match analytics over the events they name.
    catalog = load_catalog(CATALOG_DIR)
    single_shot = {
        "identity-defender-detection",
        "identity-4719-audit-policy-change",
        "identity-privileged-group-change",
    }
    for spec_id in single_shot:
        assert spec_id in catalog, f"{spec_id} is not in the catalog"
        assert catalog[spec_id].no_benign_baseline, f"{spec_id} must declare no baseline"
        assert catalog[spec_id].evaluator == "match", f"{spec_id} must read its event"
        assert catalog[spec_id].roles, f"{spec_id} lost its role gate"


def test_every_prior_role_is_in_the_dossier_vocabulary() -> None:
    from soc_ai.dossier.infer import ROLE_VOCABULARY

    catalog = load_catalog(CATALOG_DIR)
    for spec_id, spec in catalog.items():
        if spec.evaluator != "profile" or spec.profile is None:
            continue
        for role in spec.profile.roles:
            assert role in ROLE_VOCABULARY, f"{spec_id} names unknown role {role!r}"


# ---------------------------------------------------------------------------
# Recurrence: a single stray connection is not a pattern
# ---------------------------------------------------------------------------


def test_a_member_seen_once_is_not_a_departure() -> None:
    """The ephemeral-port floor alone is the wrong instrument.

    Against the range it let port 47908 through: above Linux's ephemeral start
    of 32768 but below the IANA dynamic floor of 49152. Raising the floor to
    32768 would kill the noise and also blind the layer to a C2 listener parked
    on a high port, which is a real thing attackers do.

    Recurrence separates them without guessing about numbers. An ephemeral port
    is used once and never again; a service -- legitimate or hostile -- is used
    repeatedly. One observation is not a pattern.
    """
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={"47908": {"count": 1}},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures == ()
    assert result.coverage == COVERAGE_MEASURED


def test_a_member_that_recurs_is_a_departure_however_high_the_port() -> None:
    # The case the floor would have destroyed: a listener on a high port that
    # is actually being used.
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={"47908": _seen(12)},
        role="network_device",
        role_confidence=0.9,
    )
    assert [d.member for d in result.departures] == ["47908"]


def test_the_recurrence_floor_is_declarable_per_prior() -> None:
    # A single-shot prior covers events where one occurrence IS the finding,
    # so it must be able to set the floor to one.
    result = evaluate_prior(
        _spec(min_observations=1),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={"47908": _seen(1)},
        role="network_device",
        role_confidence=0.9,
    )
    assert [d.member for d in result.departures] == ["47908"]


def test_an_unparseable_observation_count_does_not_crash_the_prior() -> None:
    # Callers hand this whatever they measured. A missing or odd count must
    # not take the sweep down, and must not silently pass the floor either.
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={"47908": {}, "47909": "nonsense", "47910": None},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures == ()


def test_the_departure_carries_the_observed_count() -> None:
    # An analyst reading "port 47908 is new" needs to know whether it happened
    # twice or two thousand times.
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={"3389": _seen(57)},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures[0].observed_count == 57


# ---------------------------------------------------------------------------
# outside_active_hours and the rate tests
# ---------------------------------------------------------------------------


def _hours_profile(hours: dict[str, Any], **kw: Any) -> ProfileRow:
    return _profile(vector=hours, dimension="active_hours", **kw)


def _rate_profile(cells: dict[str, Any], **kw: Any) -> ProfileRow:
    return _profile(vector=cells, dimension="connection_rate", **kw)


def test_activity_in_an_hour_the_host_has_never_used_is_a_departure() -> None:
    # The clause that gives the GitHub-at-7PM step its second kind. Without it
    # that whole chain is one kind and forms nothing.
    spec = _spec(dimension="active_hours", test="outside_active_hours")
    result = evaluate_prior(
        spec,
        profile=_hours_profile({"9": {"count": 200}, "10": {"count": 300}}),
        observed={"19": {"count": 12}},
        role="workstation",
        role_confidence=0.9,
    )
    assert [d.member for d in result.departures] == ["19"]


def test_activity_in_a_familiar_hour_is_not_a_departure() -> None:
    spec = _spec(dimension="active_hours", test="outside_active_hours")
    result = evaluate_prior(
        spec,
        profile=_hours_profile({"9": {"count": 200}, "19": {"count": 300}}),
        observed={"19": {"count": 12}},
        role="workstation",
        role_confidence=0.9,
    )
    assert result.departures == ()


def test_a_host_with_no_measured_active_hours_is_not_departing_from_nothing() -> None:
    # An empty hour set means this host was never seen active at all, which is
    # a coverage problem wearing the clothes of a 24-hour anomaly. Firing here
    # would mean every hour of every quiet host is a departure.
    spec = _spec(dimension="active_hours", test="outside_active_hours")
    result = evaluate_prior(
        spec,
        profile=_hours_profile({}),
        observed={"19": {"count": 12}},
        role="workstation",
        role_confidence=0.9,
    )
    assert result.departures == ()


# The rate tests read an hourly series. Four weeks of it, from a Monday.
_SERIES_START = datetime(2026, 8, 3, tzinfo=UTC)
assert _SERIES_START.weekday() == 0


def _series_profile(
    count_at: Callable[[datetime], float], *, weeks: int = 4, **kw: Any
) -> ProfileRow:
    """A rate profile whose hourly series is ``count_at`` for every hour."""
    counts = [count_at(_SERIES_START + timedelta(hours=n)) for n in range(weeks * HOURS_PER_WEEK)]
    return _rate_profile(
        {
            "work": {"median": 100.0, "dispersion": 0.0, "samples": 200},
            "hourly": {"start": _SERIES_START.isoformat(), "counts": counts},
        },
        **kw,
    )


def _recent(start: datetime, counts: list[float], **extra: Any) -> dict[str, Any]:
    """Recent hours from ``start``, one entry per hour, keyed by its UTC start."""
    return {
        (start + timedelta(hours=n)).isoformat(): {
            "count": c,
            "sample_ids": [f"h{n}"],
            **extra,
        }
        for n, c in enumerate(counts)
    }


def _flat(_at: datetime) -> float:
    return 100.0


def _monday_morning(at: datetime) -> float:
    """1000 every Monday from 09:00 to 12:59 UTC, 100 at every other hour."""
    return 1000.0 if at.weekday() == 0 and 9 <= at.hour < 13 else 100.0


# The week after the series: a Monday, then a Wednesday.
_MONDAY = _SERIES_START + timedelta(weeks=4)
_WEDNESDAY = _MONDAY + timedelta(days=2)


def _day(base: datetime, burst: dict[int, float], *, usual: float = 100.0) -> dict[str, Any]:
    """24 recent hours from midnight of ``base``: ``usual`` an hour, or the burst."""
    return _recent(base, [burst.get(h, usual) for h in range(24)])


def _rate(test: str, profile: ProfileRow, observed: dict[str, Any], **kw: Any) -> Any:
    return evaluate_prior(
        _spec(dimension="connection_rate", test=test, threshold=3.0),
        profile=profile,
        observed=observed,
        role="server",
        role_confidence=0.9,
        **kw,
    )


def test_a_four_hour_burst_on_a_flat_host_departs() -> None:
    """The recent median of 24 hours did not move for a burst of four. Each
    hour is tested now, against the expected count of its hour of the week,
    with a dispersion of at least the square root of that count."""
    result = _rate(
        "above",
        _series_profile(_flat),
        _day(_WEDNESDAY, {14: 1000.0, 15: 1000.0, 16: 1000.0, 17: 1000.0}),
    )
    (departure,) = result.departures
    assert departure.member == "work"
    assert departure.run_hours == 4
    assert departure.observed_value == 1000.0
    assert departure.baseline_median == 100.0
    assert departure.ratio == 10.0
    assert departure.statistic == "residual_z"
    # A flat host has a pooled MAD of zero. The floor is the square root of
    # the expected count: (1000 - 100) / 10.
    assert departure.statistic_value == 90.0
    assert departure.run_start == _WEDNESDAY + timedelta(hours=14)
    assert departure.run_end == _WEDNESDAY + timedelta(hours=18)
    assert departure.peak_label == "Wednesday 14:00"
    assert departure.sample_ids == ("h14", "h15", "h16", "h17")
    assert "on Wednesday 14:00 is 1000 per hour" in result.note
    assert "The baseline expects 100 per hour at that hour of the week" in result.note
    assert "The departure lasted 4 hours" in result.note


def test_the_same_burst_on_a_host_whose_monday_morning_is_like_that_does_not() -> None:
    """Negative control: the same four hours of 1000, on the Monday morning
    this host always spends at 1000. The expected count of that hour of the
    week is 1000, and nothing departed."""
    burst = {9: 1000.0, 10: 1000.0, 11: 1000.0, 12: 1000.0}
    profile = _series_profile(_monday_morning)
    assert _rate("above", profile, _day(_MONDAY, burst)).departures == ()
    # The same burst on the Wednesday is a departure for the same host.
    assert _rate("above", profile, _day(_WEDNESDAY, burst)).departures != ()


def test_the_hour_of_the_week_is_named_in_the_deployment_zone() -> None:
    """A burst from 20:00 to 23:59 UTC on a Wednesday starts at 16:00 in New
    York, inside working hours there. The cell and the label are local."""
    burst = {20: 1000.0, 21: 1000.0, 22: 1000.0, 23: 1000.0}
    profile = _series_profile(_flat)
    local = _rate("above", profile, _day(_WEDNESDAY, burst), tz="America/New_York")
    utc = _rate("above", profile, _day(_WEDNESDAY, burst), tz="UTC")
    assert [(d.member, d.peak_label) for d in local.departures] == [("work", "Wednesday 16:00")]
    assert [(d.member, d.peak_label) for d in utc.departures] == [("off", "Wednesday 20:00")]


def test_one_hour_just_over_the_bar_needs_a_second_hour() -> None:
    """A run of two hours, or one hour twice as far out. One odd hour at
    the bar stays quiet."""
    profile = _series_profile(lambda _at: 1.0)
    one = _rate("above", profile, _day(_WEDNESDAY, {14: 4.0}, usual=1.0))
    two = _rate("above", profile, _day(_WEDNESDAY, {14: 4.0, 15: 4.0}, usual=1.0))
    far = _rate("above", profile, _day(_WEDNESDAY, {14: 40.0}, usual=1.0))
    # z of 3 and four times the expected count: over the bar, but alone.
    assert one.departures == ()
    assert [d.run_hours for d in two.departures] == [2]
    assert [d.run_hours for d in far.departures] == [1]


def test_a_small_move_against_a_tight_baseline_is_not_far_above() -> None:
    """13 % is not "far above", whatever the dispersion says. The range read
    2446 per hour against 2216 as a departure. The count must also clear the
    threshold as a multiple of the expected count."""
    profile = _series_profile(lambda _at: 2216.0)
    observed = _recent(_WEDNESDAY, [2446.0] * 24)
    assert _rate("above", profile, observed).departures == ()
    assert _rate("below", profile, _recent(_WEDNESDAY, [1900.0] * 24)).departures == ()


def test_an_hour_with_no_count_and_no_spread_is_unmeasurable() -> None:
    """An hour of the week the host never used, on a host whose hours never
    vary: the expected count is zero and the pooled MAD is zero. The hour
    cannot say how surprising a count is. It is unmeasurable, never a
    departure."""

    def office(at: datetime) -> float:
        return 100.0 if 8 <= at.hour < 18 else 0.0

    profile = _series_profile(office)
    night_burst = {h: office(_WEDNESDAY + timedelta(hours=h)) for h in range(24)}
    night_burst.update({2: 500.0, 3: 500.0, 4: 500.0})
    night = _rate("above", profile, _recent(_WEDNESDAY, [night_burst[h] for h in range(24)]))
    assert night.coverage == COVERAGE_MEASURED
    assert night.departures == ()
    # The same hours on a host whose counts vary have a dispersion to read.
    varied = _series_profile(lambda at: office(at) + at.day % 3)
    departures = _rate(
        "above", varied, _recent(_WEDNESDAY, [night_burst[h] for h in range(24)])
    ).departures
    assert [(d.member, d.run_hours) for d in departures] == [("off", 3)]


def test_a_host_that_stops_departs_below() -> None:
    """A backup that stops is as interesting as one that doubles."""
    result = _rate("below", _series_profile(_flat), _day(_WEDNESDAY, {10: 0.0, 11: 0.0, 12: 0.0}))
    (departure,) = result.departures
    assert departure.member == "work"
    assert departure.run_hours == 3
    assert departure.observed_value == 0.0
    assert departure.ratio == 0.0
    assert departure.statistic_value == -10.0


def test_above_does_not_fire_on_a_drop_and_below_does_not_fire_on_a_spike() -> None:
    profile = _series_profile(_flat)
    high = _day(_WEDNESDAY, {14: 1000.0, 15: 1000.0})
    low = _day(_WEDNESDAY, {14: 0.0, 15: 0.0})
    assert _rate("above", profile, low).departures == ()
    assert _rate("below", profile, high).departures == ()


def test_a_rate_baseline_with_no_hourly_series_is_blind_until_the_next_build() -> None:
    """A baseline built before the hourly series holds the three cells only.
    The prior says so. It does not fall back to a median it no longer
    trusts, and it does not read as clean."""
    result = _rate(
        "above",
        _rate_profile({"work": {"median": 40.0, "dispersion": 2.0, "samples": 200}}),
        _day(_WEDNESDAY, {14: 1000.0, 15: 1000.0}),
    )
    assert result.coverage == COVERAGE_BLIND
    assert "no hourly series yet" in result.note


def test_a_host_with_no_history_stays_learning() -> None:
    result = _rate(
        "above",
        _series_profile(_flat, weeks=1, coverage="learning", support_days=3),
        _day(_WEDNESDAY, {14: 1000.0, 15: 1000.0}),
    )
    assert result.coverage == COVERAGE_LEARNING
    assert result.departures == ()


def test_a_window_an_investigation_confirmed_stays_out_of_the_rate_baseline() -> None:
    """The baseline learnt a burst on the Wednesday of week two. That window
    was an attack. Left in, the next Wednesday burst reads as half usual."""

    def poisoned(at: datetime) -> float:
        return 1000.0 if at.weekday() == 2 and 14 <= at.hour < 18 and at.day in (12, 19) else 100.0

    profile = _series_profile(poisoned)
    burst = _day(_WEDNESDAY, {14: 1000.0, 15: 1000.0, 16: 1000.0, 17: 1000.0})
    windows = [
        (datetime(2026, 8, 12, 13, tzinfo=UTC), datetime(2026, 8, 12, 19, tzinfo=UTC)),
        (datetime(2026, 8, 19, 13, tzinfo=UTC), datetime(2026, 8, 19, 19, tzinfo=UTC)),
    ]
    # With the attack in the baseline, two of four Wednesdays held the burst
    # and the expected count sits between them.
    learnt = _rate("above", profile, burst)
    clean = _rate("above", profile, burst, exclude=windows)
    assert learnt.departures == ()
    assert [d.run_hours for d in clean.departures] == [4]


# ---------------------------------------------------------------------------
# The gate applies to role priors, not to role-independent clauses
# ---------------------------------------------------------------------------


def test_a_role_independent_clause_fires_on_an_unclassified_host() -> None:
    """The other side of the safe harbour.

    A clause that compares a host to its OWN baseline never reads the role.
    Gating it on role confidence means that on a grid where most hosts are
    unclassified -- which is most grids -- no second observation kind ever
    appears, so no chain can form on exactly the machines nobody can identify.

    The design's wording is "cannot apply ROLE PRIORS", and this is not one.
    """
    spec = _spec(dimension="active_hours", test="outside_active_hours")
    assert spec.profile is not None and spec.profile.roles == []
    result = evaluate_prior(
        spec,
        profile=_hours_profile({"9": {"count": 200}}),
        observed={"19": {"count": 12}},
        role=None,
        role_confidence=None,
    )
    assert result.coverage == COVERAGE_MEASURED
    assert [d.member for d in result.departures] == ["19"]


def test_a_role_scoped_prior_is_still_blind_on_an_unclassified_host() -> None:
    # The inversion itself is unchanged: a prior that reasons from a role
    # cannot reason without one, and must say so rather than stay quiet.
    result = evaluate_prior(
        _spec(roles=["network_device"]),
        profile=_profile(),
        observed={"445": _seen(4)},
        role=None,
        role_confidence=None,
    )
    assert result.coverage == COVERAGE_BLIND


def test_only_role_scoped_specs_are_required_to_hold_the_gate_high() -> None:
    # Replaces the blanket assertion. A role-independent clause has no gate to
    # relax, and requiring one of it is what created the second safe harbour.
    catalog = load_catalog(CATALOG_DIR)
    for spec_id, spec in catalog.items():
        if spec.evaluator != "profile" or spec.profile is None:
            continue
        if not spec.profile.roles:
            continue
        assert spec.profile.min_role_confidence >= 0.9, (
            f"{spec_id} relaxes the role-confidence gate"
        )


# ---------------------------------------------------------------------------
# The documents behind a departure
# ---------------------------------------------------------------------------


def test_a_novel_member_carries_the_documents_it_was_seen_in() -> None:
    """A departure an analyst cannot open is a claim, not evidence.

    The sweep samples up to three documents per member and hands them here.
    They travel with the departure so the observation can name them, and the
    lead hunt can read them before it queries anything.
    """
    result = evaluate_prior(
        _spec(),
        profile=_profile(),
        observed={"445": _seen(4, sample_ids=("d1", "d2", "d3"))},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures[0].sample_ids == ("d1", "d2", "d3")


def test_a_departure_with_no_sample_carries_an_empty_list_not_a_crash() -> None:
    # The older recent read hands plain counts. A dimension whose plane returns
    # no hits must still produce a readable departure.
    result = evaluate_prior(
        _spec(),
        profile=_profile(),
        observed={"445": _seen(4)},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures[0].sample_ids == ()


def test_an_hour_departure_carries_the_documents_seen_in_that_hour() -> None:
    spec = _spec(dimension="active_hours", test="outside_active_hours")
    result = evaluate_prior(
        spec,
        profile=_hours_profile({"9": {"count": 200}, "10": {"count": 300}}),
        observed={"19": {"count": 12, "sample_ids": ["h1", "h2"]}},
        role="workstation",
        role_confidence=0.9,
    )
    assert result.departures[0].sample_ids == ("h1", "h2")


# ---------------------------------------------------------------------------
# The peers-or-days guard on served ports
# ---------------------------------------------------------------------------


def test_a_port_reached_from_one_peer_on_one_day_does_not_count() -> None:
    # The production case. Postfix on a hypervisor looked up a name. The
    # endpoint sensor wrote the reply with the hypervisor as the destination
    # and the ephemeral source port of the lookup as the destination port.
    # One peer, one day, nineteen documents across nineteen sweeps.
    assert served_port_counts("33897", count=19, peers=1, days=1) is False


def test_a_port_two_peers_reach_counts() -> None:
    assert served_port_counts("445", count=2, peers=2, days=1) is True


def test_a_port_reached_on_two_days_counts() -> None:
    assert served_port_counts("445", count=2, peers=1, days=2) is True


def test_a_high_port_needs_two_peers_and_two_days() -> None:
    # Linux hands out 32768 and up per connection. A listener parked up there
    # is real when several machines reach it across several days.
    assert served_port_counts("33897", count=6, peers=2, days=1) is False
    assert served_port_counts("33897", count=6, peers=1, days=2) is False
    assert served_port_counts("33897", count=6, peers=2, days=2) is True
    assert served_port_counts(str(LINUX_EPHEMERAL_START), count=6, peers=2, days=1) is False
    assert served_port_counts(str(LINUX_EPHEMERAL_START - 1), count=6, peers=2, days=1) is True


def test_a_port_with_no_documents_never_counts() -> None:
    assert served_port_counts("445", count=0, peers=5, days=5) is False


def test_a_member_that_is_not_a_port_number_does_not_count() -> None:
    assert served_port_counts("http", count=4, peers=3, days=3) is False
    assert served_port_counts(None, count=4, peers=3, days=3) is False


def test_a_novel_port_from_one_peer_on_one_day_is_not_a_departure() -> None:
    # Nineteen documents cleared the recurrence floor nineteen times on
    # production. The floor counts documents. The guard counts peers and days.
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": _seen(40)}),
        observed={"33897": _seen(19, peers=1, days=1)},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures == ()
    assert result.coverage == COVERAGE_MEASURED


def test_a_novel_port_two_peers_reach_is_a_departure() -> None:
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": _seen(40)}),
        observed={"8443": _seen(2, peers=2, days=1)},
        role="network_device",
        role_confidence=0.9,
    )
    assert [d.member for d in result.departures] == ["8443"]


def test_a_recent_read_without_peers_or_days_does_not_fire_on_a_served_port() -> None:
    # An older shape, or a plane that carries no source address. Zero is
    # what the reader hands back, and zero does not count. A permissive
    # default here is how the ephemeral-port stream got in the first time.
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": _seen(40)}),
        observed={"8443": {"count": 12}},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures == ()


def test_the_guard_applies_to_served_ports_and_not_to_outbound_ports() -> None:
    # consumed_ports is keyed on the source. A peer count there would count
    # the entity itself, so the dimension keeps the recurrence floor alone.
    result = evaluate_prior(
        _spec(dimension="consumed_ports"),
        profile=_profile(vector={"443": {"count": 90}}, dimension="consumed_ports"),
        observed={"8220": {"count": 3}},
        role="network_device",
        role_confidence=0.9,
    )
    assert [d.member for d in result.departures] == ["8220"]


def test_the_note_states_documents_in_the_window_not_sweeps() -> None:
    # "The sweep saw it 2 times" sat beside "seen 19 times" on one row, and
    # the two numbers measured different things. The note says what the
    # count is: documents, in the window the sweep read.
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": _seen(40)}),
        observed={"8443": _seen(4)},
        role="network_device",
        role_confidence=0.9,
        window_hours=12,
    )
    assert "4 documents in the last 12 h" in result.note
    assert "saw it" not in result.note


def test_one_document_reads_in_the_singular() -> None:
    result = evaluate_prior(
        _spec(min_observations=1),
        profile=_profile(vector={"22": _seen(40)}),
        observed={"8443": _seen(1)},
        role="network_device",
        role_confidence=0.9,
        window_hours=24,
    )
    assert "1 document in the last 24 h" in result.note


# ---------------------------------------------------------------------------
# Member patterns: a prior that names the members it is about
# ---------------------------------------------------------------------------

_REMOTE_TOOLING_ID = "prior-workstation-remote-execution-tooling"


def _remote_tooling_members(observed: dict[str, Any]) -> list[str]:
    """The members the shipped remote-tooling prior fires on, for a measured
    workstation whose process baseline holds two ordinary names."""
    spec = load_catalog(CATALOG_DIR)[_REMOTE_TOOLING_ID]
    result = evaluate_prior(
        spec,
        profile=_profile(
            dimension="process_names",
            vector={"explorer.exe": {"count": 50}, "svchost.exe": {"count": 50}},
        ),
        observed=observed,
        role="workstation",
        role_confidence=0.95,
    )
    assert result.coverage == COVERAGE_MEASURED
    return [d.member for d in result.departures]


def test_remote_tooling_prior_ignores_updater_names() -> None:
    """Negative control: the range wrote five observations in three days, all
    Edge and Defender updater names. Each is a new process name, so a prior
    that reads any new name fires on every update. These are the shapes the
    range saw, each seen often enough to pass the recurrence floor."""
    updaters = {
        "MicrosoftEdgeUpdate.exe": {"count": 6},
        "MicrosoftEdgeUpdateSetup_X86_1.3.275.13.exe": {"count": 4},
        "MicrosoftEdge_X64_154.0.4258.53_154.0.4258.48.exe": {"count": 3},
        "mpam-d_bd_1.459.428.0.exe": {"count": 5},
        "AM_Delta_Patch_1.459.498.0.exe": {"count": 3},
    }
    assert _remote_tooling_members(updaters) == []


def test_remote_tooling_prior_fires_on_the_psexec_service() -> None:
    """The positive: the PsExec service on the target is remote execution, in
    the case the sensor writes it. An updater beside it still does not fire."""
    members = _remote_tooling_members(
        {
            "PSEXESVC.exe": {"count": 2},
            "MicrosoftEdgeUpdate.exe": {"count": 6},
        }
    )
    assert members == ["PSEXESVC.exe"]


def test_remote_tooling_prior_names_its_tools() -> None:
    """Each tool the description names is in the list: PsExec on both ends,
    WMIC, the WinRM shell, and the PowerShell remoting host."""
    for name in (
        "psexesvc.exe",
        "PsExec.exe",
        "PsExec64.exe",
        "WMIC.exe",
        "winrs.exe",
        "winrshost.exe",
        "wsmprovhost.exe",
    ):
        assert _remote_tooling_members({name: {"count": 2}}) == [name], name


def test_member_patterns_read_the_base_name_of_a_path() -> None:
    """A plane that writes the image path still matches on the file name."""
    spec = _spec(dimension="process_names", member_patterns=["psexesvc*.exe"])
    result = evaluate_prior(
        spec,
        profile=_profile(dimension="process_names", vector={"explorer.exe": {"count": 9}}),
        observed={
            "C:\\Windows\\PSEXESVC.exe": {"count": 2},
            "/opt/psexesvc.exe.bak": {"count": 2},
        },
        role=None,
        role_confidence=None,
    )
    assert [d.member for d in result.departures] == ["C:\\Windows\\PSEXESVC.exe"]


def test_a_prior_without_member_patterns_still_reads_every_member() -> None:
    """The list is opt-in. A prior that declares none keeps reading any new
    member, so the port priors do not go quiet."""
    result = evaluate_prior(
        _spec(),
        profile=_profile(),
        observed={"4444": _seen(3), "8443": _seen(3)},
        role=None,
        role_confidence=None,
    )
    assert sorted(d.member for d in result.departures) == ["4444", "8443"]


def test_member_patterns_belong_to_the_novelty_test_only() -> None:
    """A list on an hour or rate test would be ignored, and an ignored list
    reads like a narrowed prior. The spec refuses it, and an empty pattern."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="member_patterns"):
        _spec(dimension="active_hours", test="outside_active_hours", member_patterns=["1*"])
    with pytest.raises(ValidationError, match="member_patterns"):
        _spec(dimension="process_names", member_patterns=["  "])


# ---------------------------------------------------------------------------
# Baseline hygiene: known after two days, and never from a confirmed attack
# ---------------------------------------------------------------------------


def _logon(first: str, last: str, count: int = 3) -> dict[str, Any]:
    return {"count": count, "first_seen": first, "last_seen": last}


_LOGONS = {
    # Seen through the whole window: a real user of this host.
    "administrator": _logon("2026-08-01T08:00:00Z", "2026-08-30T17:00:00Z", 900),
    # Seen once, twenty days before the sweep, inside one hour.
    "svc_legacy": _logon("2026-08-10T02:00:00Z", "2026-08-10T02:40:00Z", 2),
}


def _logon_prior(**kw: Any) -> Any:
    return _spec(dimension="logon_users", test="novel_for", **kw)


def test_a_member_the_baseline_saw_on_one_day_is_still_new() -> None:
    """One sighting a month ago made a member known for good. The range DC
    logon set held the three accounts the attack created, and their next
    logon read as ordinary."""
    result = evaluate_prior(
        _logon_prior(),
        profile=_profile(vector=_LOGONS, dimension="logon_users"),
        observed={"svc_legacy": _seen(4), "administrator": _seen(40)},
        role="domain_controller",
        role_confidence=1.0,
    )
    assert [d.member for d in result.departures] == ["svc_legacy"]


def test_the_known_bar_is_declarable_per_prior() -> None:
    """Negative control: at one day the old rule holds, and nothing departs."""
    result = evaluate_prior(
        _logon_prior(min_known_days=1),
        profile=_profile(vector=_LOGONS, dimension="logon_users"),
        observed={"svc_legacy": _seen(4)},
        role="domain_controller",
        role_confidence=1.0,
    )
    assert result.departures == ()


def test_a_member_with_no_dates_stays_known() -> None:
    """A set from an older build states no dates. Its members stay known, so
    an upgrade does not make every member new at once."""
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={"22": _seen(6)},
        role="network_device",
        role_confidence=1.0,
    )
    assert result.departures == ()
    assert member_days({"count": 40}) is None
    assert member_days({"days": 3}) == 3
    assert member_days(_LOGONS["svc_legacy"]) == 1


def test_a_member_first_seen_inside_a_confirmed_attack_is_not_known() -> None:
    """The account entered the set during an attack an investigation confirmed.
    Seen on two days, it still is not what this host does."""
    vector = {
        **_LOGONS,
        "domainadmin": _logon("2026-08-10T02:10:00Z", "2026-08-11T03:00:00Z"),
    }
    window = [(datetime(2026, 8, 9, tzinfo=UTC), datetime(2026, 8, 12, tzinfo=UTC))]
    kw = dict(role="domain_controller", role_confidence=1.0)
    clean = evaluate_prior(
        _logon_prior(),
        profile=_profile(vector=vector, dimension="logon_users"),
        observed={"domainadmin": _seen(4), "administrator": _seen(40)},
        exclude=window,
        **kw,
    )
    learnt = evaluate_prior(
        _logon_prior(),
        profile=_profile(vector=vector, dimension="logon_users"),
        observed={"domainadmin": _seen(4), "administrator": _seen(40)},
        **kw,
    )
    assert [d.member for d in clean.departures] == ["domainadmin"]
    assert learnt.departures == ()
    assert known_members(vector, exclude=window) == {"administrator"}


def test_a_peer_test_reads_member_patterns_and_bounds_its_group() -> None:
    """The peer test reads names like the novelty test. A peer group of one
    is no group, and a share above one is no share."""
    import pytest
    from pydantic import ValidationError

    spec = _spec(dimension="process_names", test="rare_for_peers", member_patterns=["psexe*"])
    assert spec.profile is not None and spec.profile.reads_member("PSEXESVC.exe")
    assert spec.profile.min_peers == 5 and spec.profile.max_peer_share == 0.0
    with pytest.raises(ValidationError, match="min_peers"):
        _spec(test="rare_for_peers", min_peers=1)
    with pytest.raises(ValidationError, match="max_peer_share"):
        _spec(test="rare_for_peers", max_peer_share=1.5)


def test_a_peer_test_without_a_peer_group_is_blind() -> None:
    """No confident role, no group. The test never reads a member as rare
    against peers it could not read."""
    result = evaluate_prior(
        _spec(test="rare_for_peers"),
        profile=_profile(),
        observed={"4444": _seen(6)},
        role=None,
        role_confidence=None,
    )
    assert result.coverage == COVERAGE_BLIND
    assert result.note.startswith("no peer group:")
