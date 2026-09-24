"""The `profile` evaluator and the role priors it runs.

The behaviour most likely to be implemented backwards is the confidence gate,
so most of these tests are planted against that defect. The design inverts it:
a prior on a low-confidence role is BLIND and says so. It is never demoted to a
weak observation, because that turns a quiet host into a safe harbour, and a
quiet host is exactly where a careful attacker lives.
"""

from __future__ import annotations

from typing import Any

from soc_ai.hunting.priors import (
    COVERAGE_BLIND,
    COVERAGE_MEASURED,
    COVERAGE_NOT_APPLICABLE,
    evaluate_prior,
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
        support_days=support_days,
        role="network_device",
        role_confidence=0.9,
        identity_fingerprint=None,
        window_days=30,
        first_seen=None,
        last_seen=None,
        built_at=None,
    )


# ---------------------------------------------------------------------------
# The inverted confidence gate
# ---------------------------------------------------------------------------


def test_a_low_confidence_role_is_blind_not_weakly_firing() -> None:
    result = evaluate_prior(
        _spec(roles=["network_device"]),
        profile=_profile(),
        observed={"445": {"count": 4}},
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
        observed={"445": {"count": 4}},
        role=None,
        role_confidence=None,
    )
    assert result.coverage == COVERAGE_BLIND
    assert result.departures == ()


def test_a_high_confidence_role_evaluates_normally() -> None:
    result = evaluate_prior(
        _spec(roles=["network_device"]),
        profile=_profile(),
        observed={"445": {"count": 4}},
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
        observed={"445": {"count": 4}},
        role="workstation",
        role_confidence=0.9,
    )
    assert result.coverage == COVERAGE_NOT_APPLICABLE
    assert result.departures == ()


def test_a_prior_with_no_roles_applies_to_every_role() -> None:
    result = evaluate_prior(
        _spec(),
        profile=_profile(),
        observed={"445": {"count": 4}},
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
        observed={"445": {"count": 4}},
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
        observed={"445": {"count": 4}},
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
        observed={"445": {"count": 4}},
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
        observed={"445": {"count": 4}},
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
        observed={"445": {"count": 4}},
        role="network_device",
        role_confidence=0.9,
    )
    assert result.departures == ()


def test_several_novel_members_each_produce_a_departure() -> None:
    result = evaluate_prior(
        _spec(),
        profile=_profile(vector={"22": {"count": 40}}),
        observed={"445": {"count": 4}, "3389": {"count": 2}, "22": {"count": 9}},
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
        observed={"445": {"count": 4}},
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


def test_the_single_shot_priors_declare_no_benign_baseline() -> None:
    # The design's last three: they never accumulate, and they are how the
    # highest-impact events are covered at all. A triage must not close them
    # on how often they fire.
    catalog = load_catalog(CATALOG_DIR)
    single_shot = {
        "prior-defender-adjudication-on-server",
        "prior-audit-policy-changed-on-dc",
        "prior-privileged-group-membership-changed",
    }
    for spec_id in single_shot:
        assert spec_id in catalog, f"{spec_id} is not in the catalog"
        assert catalog[spec_id].no_benign_baseline, f"{spec_id} must declare no baseline"


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
        observed={"47908": {"count": 12}},
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
        observed={"47908": {"count": 1}},
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
        observed={"3389": {"count": 57}},
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


def test_a_rate_far_above_its_own_median_is_a_departure() -> None:
    spec = _spec(dimension="connection_rate", test="above", threshold=3.0)
    result = evaluate_prior(
        spec,
        profile=_rate_profile({"work": {"median": 40.0, "dispersion": 2.0, "samples": 200}}),
        observed={"work": {"value": 400.0}},
        role="server",
        role_confidence=0.9,
    )
    assert [d.member for d in result.departures] == ["work"]


def test_a_rate_departure_carries_the_numbers_behind_it() -> None:
    """The observation said one median and the host page said another.

    The summary read "far above" over a median of its own, while the profile
    panel showed the baseline median for the same cell. Two numbers for one
    thing, and neither said how far apart they were.
    """
    spec = _spec(dimension="connection_rate", test="above", threshold=3.0)
    result = evaluate_prior(
        spec,
        profile=_rate_profile({"work": {"median": 40.0, "dispersion": 2.0, "samples": 200}}),
        observed={"work": {"value": 400.0}},
        role="server",
        role_confidence=0.9,
    )
    departure = result.departures[0]
    assert departure.observed_value == 400.0
    assert departure.baseline_median == 40.0
    assert departure.ratio == 10.0
    assert "400 per hour" in result.note
    assert "The median is 40 per hour" in result.note
    assert "10.0 times the median" in result.note


def test_a_small_move_against_a_tight_baseline_is_not_far_above() -> None:
    """13 % is not "far above", whatever the dispersion says.

    The range read 2446 per hour against a median of 2216 as a departure,
    because the cell's samples sat close together and the robust z was 7.8. A
    distance in dispersions is not a distance an analyst can read, so the ratio
    must clear the spec's threshold as well.
    """
    spec = _spec(dimension="connection_rate", test="above", threshold=3.0)
    result = evaluate_prior(
        spec,
        profile=_rate_profile({"work": {"median": 2216.0, "dispersion": 20.0, "samples": 200}}),
        observed={"work": {"value": 2446.0}},
        role="server",
        role_confidence=0.9,
    )
    assert result.coverage == COVERAGE_MEASURED
    assert result.departures == ()


def test_a_small_drop_against_a_tight_baseline_is_not_far_below() -> None:
    spec = _spec(dimension="connection_rate", test="below", threshold=3.0)
    result = evaluate_prior(
        spec,
        profile=_rate_profile({"work": {"median": 2216.0, "dispersion": 20.0, "samples": 200}}),
        observed={"work": {"value": 1900.0}},
        role="server",
        role_confidence=0.9,
    )
    assert result.departures == ()


def test_a_median_of_zero_cannot_produce_a_ratio_or_a_departure() -> None:
    # Nothing is a multiple of zero. A departure that cannot say how far it
    # travelled is not one an analyst can read.
    spec = _spec(dimension="connection_rate", test="above", threshold=3.0)
    result = evaluate_prior(
        spec,
        profile=_rate_profile({"work": {"median": 0.0, "dispersion": 2.0, "samples": 200}}),
        observed={"work": {"value": 400.0}},
        role="server",
        role_confidence=0.9,
    )
    assert result.departures == ()


def test_a_rate_far_below_its_own_median_is_a_departure() -> None:
    # A backup that stops is as interesting as one that doubles. The clean
    # state must not be the attacker's goal state.
    spec = _spec(dimension="connection_rate", test="below", threshold=3.0)
    result = evaluate_prior(
        spec,
        profile=_rate_profile({"work": {"median": 40.0, "dispersion": 2.0, "samples": 200}}),
        observed={"work": {"value": 0.0}},
        role="server",
        role_confidence=0.9,
    )
    assert [d.member for d in result.departures] == ["work"]


def test_above_does_not_fire_on_a_drop_and_below_does_not_fire_on_a_spike() -> None:
    # The z is signed; reading its absolute value would make the two tests
    # identical and 'below' would stop meaning anything.
    high = {"work": {"value": 400.0}}
    low = {"work": {"value": 0.0}}
    cells = _rate_profile({"work": {"median": 40.0, "dispersion": 2.0, "samples": 200}})
    kw = dict(role="server", role_confidence=0.9)
    assert (
        evaluate_prior(
            _spec(dimension="connection_rate", test="above"), profile=cells, observed=low, **kw
        ).departures
        == ()
    )
    assert (
        evaluate_prior(
            _spec(dimension="connection_rate", test="below"), profile=cells, observed=high, **kw
        ).departures
        == ()
    )


def test_a_cell_with_no_dispersion_cannot_produce_a_departure() -> None:
    # robust_z returns None there. Treating None as "very far from the median"
    # makes every cell whose samples happen to be identical fire on anything.
    spec = _spec(dimension="connection_rate", test="above")
    result = evaluate_prior(
        spec,
        profile=_rate_profile({"work": {"median": 40.0, "dispersion": 0.0, "samples": 200}}),
        observed={"work": {"value": 4000.0}},
        role="server",
        role_confidence=0.9,
    )
    assert result.departures == ()


def test_a_cell_the_profile_never_measured_cannot_produce_a_departure() -> None:
    spec = _spec(dimension="connection_rate", test="above")
    result = evaluate_prior(
        spec,
        profile=_rate_profile({"work": {"median": None, "dispersion": None, "samples": 0}}),
        observed={"work": {"value": 4000.0}},
        role="server",
        role_confidence=0.9,
    )
    assert result.departures == ()


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
        observed={"445": {"count": 4}},
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
        observed={"445": {"count": 4, "sample_ids": ("d1", "d2", "d3")}},
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
        observed={"445": {"count": 4}},
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


def test_a_rate_departure_carries_the_documents_of_its_cell() -> None:
    spec = _spec(dimension="connection_rate", test="above", threshold=3.0)
    result = evaluate_prior(
        spec,
        profile=_rate_profile({"work": {"median": 40.0, "dispersion": 2.0, "samples": 200}}),
        observed={"work": {"value": 400.0, "sample_ids": ["r1", "r2", "r3"]}},
        role="server",
        role_confidence=0.9,
    )
    assert result.departures[0].sample_ids == ("r1", "r2", "r3")
