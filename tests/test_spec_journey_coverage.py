"""Every spec_journey scenario is checked against the spec it names, in CI.

This is the gate that makes the declarative catalog measurable. Before it, the
only evidence a spec worked was a transcript of somebody running queries against
a lab grid by hand, which proves nothing the day the grid is switched off.

It runs with no Elasticsearch and no model. A scenario declares which spec should
fire and on which entity; the rendered fixture is evaluated against that spec's
clause tree in memory. If a spec is edited so it no longer catches the attack its
fixture describes, the suite fails on the next commit rather than the next
incident.

Two things this deliberately does NOT claim:

- It is not proof the compiled Elasticsearch query behaves identically. That is
  tested per clause in ``test_hunt_spec`` and end to end against a live grid.
  Three independent checks, none standing in for another.
- A passing scenario does not mean the spec is well tuned on a real network.
  A fixture contains what its author put in it, and a benign twin is only as
  adversarial as whoever wrote it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from soc_ai.eval.journey import JourneyStage
from soc_ai.eval.spec_journey import score_spec_journey
from soc_ai.eval.synth_loader import Scenario, load_all_scenarios
from soc_ai.hunting.execute import Candidate, SpecRun
from soc_ai.hunting.match import (
    clause_matches,
    detection_matches,
    detection_undecided,
    get_field,
    precondition_matches,
)
from soc_ai.hunting.spec import HuntSpec, load_catalog

REPO = Path(__file__).resolve().parents[1]
CATALOG = load_catalog(REPO / "soc_ai/hunting/catalog")
SCENARIOS = load_all_scenarios(REPO / "soc_ai/eval/synth_scenarios")
WITH_SPEC = [s for s in SCENARIOS if s.spec_journey is not None]


def _simulate(spec: HuntSpec, scenario: Scenario) -> SpecRun:
    """Run the spec over the scenario's events the way the executor would.

    Same two questions in the same order: does the precondition see anything,
    then which scopes does the detection surface. Grouping by ``scope_field`` is
    what turns documents into candidates, and reproducing it here is what lets
    this catch an over-grouping or under-grouping regression.

    ``precondition_docs`` is the count of documents that satisfy the
    precondition, not the count of documents planted. It used to be the latter,
    which meant the harness reported a number the executor never would and
    could not have noticed a spec counting a copy of the event it cannot read.

    ``undecided_docs`` is the third question the executor asks, in the same
    order: which documents satisfy the positive clauses and are missing a field
    an exclusion reads. A harness that skipped it would score a fixture clean
    over documents a live run reports, which is the divergence that made the
    presence rule shippable in the first place.
    """
    docs: list[dict[str, Any]] = [dict(e.fields) for e in scenario.events]

    examined = [d for d in docs if precondition_matches(spec, d)] if spec.precondition else docs
    if spec.precondition is not None and not examined:
        return SpecRun(spec.id, "a", "b", blind=True, precondition_docs=0, matched_docs=0)

    undecided = [d for d in docs if detection_undecided(spec.detection, d)]
    matched = [d for d in docs if detection_matches(spec.detection, d)]
    by_scope: dict[str, int] = {}
    for doc in matched:
        key = get_field(doc, spec.scope_field)
        if isinstance(key, list):
            key = key[0] if key else None
        if key is not None:
            by_scope[str(key)] = by_scope.get(str(key), 0) + 1

    return SpecRun(
        spec.id,
        "a",
        "b",
        blind=False,
        precondition_docs=len(examined),
        matched_docs=len(matched),
        undecided_docs=len(undecided),
        candidates=[
            Candidate(spec.id, k, spec.scope_kind, n, ("synthetic",), "synthetic", None, None, None)
            for k, n in sorted(by_scope.items(), key=lambda kv: -kv[1])
        ],
    )


def test_there_is_at_least_one_spec_journey_scenario() -> None:
    """Without this the parametrised gate below would vacuously pass on zero cases."""
    assert WITH_SPEC, (
        "no scenario declares a spec_journey, so the declarative catalog has no "
        "coverage at all and every test in this module is a no-op"
    )


@pytest.mark.parametrize("scenario", WITH_SPEC, ids=lambda s: s.id)
def test_the_named_spec_exists(scenario: Scenario) -> None:
    assert scenario.spec_journey is not None
    assert scenario.spec_journey.spec_id in CATALOG, (
        f"{scenario.id} names spec {scenario.spec_journey.spec_id!r}, which is not in "
        f"the catalog: {sorted(CATALOG)}"
    )


@pytest.mark.parametrize("scenario", WITH_SPEC, ids=lambda s: s.id)
def test_the_spec_fires_on_its_scenario(scenario: Scenario) -> None:
    """The gate. A spec that stops catching its own fixture fails the build."""
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]
    result = score_spec_journey(scenario.id, scenario.spec_journey, _simulate(spec, scenario))
    assert result.reached is JourneyStage.COMPLETE, result.detail


@pytest.mark.parametrize("scenario", WITH_SPEC, ids=lambda s: s.id)
def test_a_spec_journey_scenario_carries_no_alert(scenario: Scenario) -> None:
    """The premise of the whole arc: this telemetry never becomes an alert.

    A fixture that quietly planted an alert-tagged document would be measuring
    the thing the alert queue already catches, and the scenario would prove
    nothing about hunting beyond it.
    """
    for event in scenario.events:
        fields = event.fields
        assert not event.is_triage_target, f"{scenario.id} plants a triage target"
        assert get_field(fields, "event.kind") != "alert", (
            f"{scenario.id} plants an alert-kind document"
        )
        tags = get_field(fields, "tags") or []
        assert "alert" not in (tags if isinstance(tags, list) else [tags])


@pytest.mark.parametrize("scenario", WITH_SPEC, ids=lambda s: s.id)
def test_every_exclusion_clause_is_individually_load_bearing(scenario: Scenario) -> None:
    """Deleting any single ``none`` clause must break the scenario.

    "Some document is unmatched" is too weak a control. s2's twin originally
    shared the attack document's ServiceName, so it could never surface as a
    second candidate: a mutation sweep showed the ENTIRE ``none`` block could be
    deleted with the suite still green. That block holds the krbtgt exclusion,
    which is the only thing stopping every domain controller's own
    ticket-granting ticket from being reported as Kerberoasting.

    This is the mutation test done properly: drop one clause at a time and
    require the scenario to notice.
    """
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]
    if not spec.detection.none:
        pytest.skip(f"{spec.id} has no exclusion clauses")

    for i, clause in enumerate(spec.detection.none):
        weakened = spec.model_copy(
            update={
                "detection": spec.detection.model_copy(
                    update={"none": [c for j, c in enumerate(spec.detection.none) if j != i]}
                )
            }
        )
        result = score_spec_journey(
            scenario.id, scenario.spec_journey, _simulate(weakened, scenario)
        )
        assert result.reached is not JourneyStage.COMPLETE, (
            f"{scenario.id} still passes with `{clause.field} {clause.op} "
            f"{clause.value!r}` deleted from {spec.id}, so that exclusion could be "
            "dropped in review with a green suite"
        )


@pytest.mark.parametrize("scenario", WITH_SPEC, ids=lambda s: s.id)
def test_the_scenario_contains_a_benign_twin_the_spec_must_reject(
    scenario: Scenario,
) -> None:
    """A fixture of nothing but the attack cannot show the discriminator works.

    The DCSync spec's whole detection is the machine-account exclusion: on the
    range on 2026-09-04, counted with the narrower Get-Changes-only clause, 36
    of 38 documents carrying the replication right were the DC's own computer
    account. A scenario without one of those would pass against a spec that
    had dropped the exclusion entirely.
    """
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]
    docs = [dict(e.fields) for e in scenario.events]
    unmatched = [d for d in docs if not detection_matches(spec.detection, d)]
    assert unmatched, (
        f"{scenario.id} has no event the spec rejects. Every planted document matches, "
        "so the scenario cannot distinguish a working discriminator from a missing one."
    )


def _expected_actor_docs(scenario: Scenario, spec: HuntSpec) -> list[dict[str, Any]]:
    """The planted documents the scenario attributes to the actor it expects surfaced."""
    assert scenario.spec_journey is not None
    expected = set(scenario.spec_journey.expected_scope_keys)
    docs = [dict(e.fields) for e in scenario.events]
    return [d for d in docs if str(get_field(d, spec.scope_field)) in expected]


@pytest.mark.parametrize("scenario", WITH_SPEC, ids=lambda s: s.id)
def test_every_document_from_the_expected_actor_matches_the_spec(scenario: Scenario) -> None:
    """A candidate that fires can hide a document the spec cannot see.

    The journey score asks whether the actor surfaced. It cannot tell two
    matching documents from three, so a spec that misses one of the actor's
    documents passes as long as a sibling carries the candidate. That is how
    the DCSync spec shipped blind to Get-Changes-All: its fixture planted only
    the right the clause matched, and the scenario was green. Every document
    the fixture attributes to the expected actor has to match on its own.
    """
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]
    actor_docs = _expected_actor_docs(scenario, spec)
    assert actor_docs, f"{scenario.id} plants nothing for its expected actor"
    missed = [d for d in actor_docs if not detection_matches(spec.detection, d)]
    assert not missed, (
        f"{scenario.id}: {len(missed)} of {len(actor_docs)} documents from the expected "
        f"actor do not match {spec.id}; the candidate still fires off the others, which is "
        "exactly the miss the journey score cannot see"
    )


@pytest.mark.parametrize("scenario", WITH_SPEC, ids=lambda s: s.id)
def test_every_any_clause_is_individually_load_bearing(scenario: Scenario) -> None:
    """Deleting any single ``any`` clause must leave an actor document unmatched.

    The ``none`` mutation test above has a twin problem in the other direction:
    an ``any`` block is a floor of one, so a clause nothing in the fixture
    exercises can be deleted with the suite still green. Each alternative has
    to be the only way some planted document matches.
    """
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]
    if not spec.detection.any:
        pytest.skip(f"{spec.id} has no any clauses")

    actor_docs = _expected_actor_docs(scenario, spec)
    for i, clause in enumerate(spec.detection.any):
        remaining = [c for j, c in enumerate(spec.detection.any) if j != i]
        weakened = spec.model_copy(
            update={"detection": spec.detection.model_copy(update={"any": remaining})}
        )
        assert any(not detection_matches(weakened.detection, d) for d in actor_docs), (
            f"{scenario.id} plants no document that only `{clause.field} {clause.op} "
            f"{clause.value!r}` matches, so that clause could be dropped from {spec.id} "
            "in review with a green suite"
        )


def test_removing_the_dcsync_discriminator_breaks_its_scenario() -> None:
    """A negative control on the gate itself.

    The tests above pass when spec and fixture agree. This one proves they would
    NOTICE a real regression, by making one: drop the machine-account exclusion
    and the benign twin is surfaced as a second candidate, which the scenario's
    expected count catches.
    """
    scenario = next(s for s in WITH_SPEC if s.id == "s1-dcsync-no-alert")
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]

    broken = spec.model_copy(update={"detection": spec.detection.model_copy(update={"none": []})})
    result = score_spec_journey(scenario.id, scenario.spec_journey, _simulate(broken, scenario))

    assert result.reached is JourneyStage.TRIGGER_DID_NOT_FIRE
    assert "SYNTH-DC02$" in result.actual_scope_keys, (
        "the benign twin should now be surfaced, which is exactly the regression"
    )


def test_the_second_copy_of_a_windows_event_is_never_surfaced_as_a_candidate() -> None:
    """A host running winlog and Elastic Defend ships every security event twice.

    The endpoint copy carries the same ``event.code`` and none of the
    ``winlog.event_data`` tree, so an exclusion written against that tree
    excludes nothing on it. s1 plants one, and the detection has to reject it.
    That is the half of this that must never move: on the range on 2026-09-05 a
    4648 spec returned 78 candidates, 74 of them the machine accounts its
    exclusions exist to remove.

    The denominator is the half that did move, deliberately. It used to be
    narrowed by every field the detection read, exclusions included, which
    kept this copy out. That same rule also deletes a field Windows leaves
    unpopulated inside the right dataset, and on the live grid it took a 4624
    spec from 5,240 matching documents to a clean result over a precondition of
    182. The precondition is now the population the ``all`` block anchors, and
    what the detection cannot decide is counted rather than subtracted.

    This copy is not counted, because it fails a POSITIVE clause: it carries no
    ``Properties`` leaf, and a term or wildcard query cannot match a field that
    is not there, in either engine. Known and not addressed here: that makes a
    spec whose whole discriminator lives in ``any`` blind to the second copy
    without saying so. Extending the undecided reading to positive alternatives
    is a separate change with its own noise profile.
    """
    scenario = next(s for s in WITH_SPEC if s.id == "s1-dcsync-no-alert")
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]

    docs = [dict(e.fields) for e in scenario.events]
    duplicates = [d for d in docs if get_field(d, "event.dataset") == "endpoint.events.security"]
    assert duplicates, "s1 no longer plants the second copy, so this gate is vacuous"

    for doc in duplicates:
        assert get_field(doc, "winlog.event_data.SubjectUserName") is None, (
            "the plant has to be on the path the old compilation missed: a document "
            "carrying the code and NOT the field the exclusion reads"
        )
        assert not detection_matches(spec.detection, doc)

    run = _simulate(spec, scenario)
    assert run.candidates and all(c.scope_key != "SYNTH-DC02$" for c in run.candidates), (
        "the machine account the exclusion exists to remove is back in the candidates"
    )


@pytest.mark.parametrize("scenario", WITH_SPEC, ids=lambda s: s.id)
def test_no_planted_document_is_discarded_without_being_counted(scenario: Scenario) -> None:
    """The gate the presence rule needed and did not have.

    A document that satisfies the positive clauses and fires no exclusion it
    carries the field for either matches or is reported undecided. Nothing may
    fall between the two. Read against the tree as it behaved before the
    presence rule, which is the set of documents that used to be returned, so a
    narrowing that quietly deleted any of them fails here.
    """
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]
    tree = spec.detection
    for doc in (dict(e.fields) for e in scenario.events):
        if not all(clause_matches(c, doc) for c in tree.all):
            continue
        if tree.any and not any(clause_matches(c, doc) for c in tree.any):
            continue
        if any(clause_matches(c, doc) for c in tree.none):
            continue
        assert detection_matches(tree, doc) or detection_undecided(tree, doc), (
            f"{scenario.id} plants a document the tree returned before the presence "
            "rule and now neither matches nor counts"
        )


def test_a_sparse_field_inside_the_right_dataset_is_reported_not_deleted() -> None:
    """The negative control for the defect this change fixes, on a fixture.

    Take s1's attack document and remove only the field its exclusion reads,
    which is what Windows does to ``SubjectUserName`` on a network logon. The
    document is still in the dataset the spec is written against and still
    satisfies every positive clause. The run has to report it rather than lose
    it, and it must not become a candidate: nothing here knows whether that
    account was a machine account.
    """
    scenario = next(s for s in WITH_SPEC if s.id == "s1-dcsync-no-alert")
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]

    attack = next(
        dict(e.fields)
        for e in scenario.events
        if get_field(e.fields, "winlog.event_data.SubjectUserName") == "svc-replicator"
    )
    sparse = {k: v for k, v in attack.items() if k != "winlog.event_data.SubjectUserName"}

    assert detection_matches(spec.detection, attack), "the unmodified document must match"
    assert not detection_matches(spec.detection, sparse)
    assert detection_undecided(spec.detection, sparse)
    assert precondition_matches(spec, sparse), (
        "removing it from the denominator as well is what let the run read clean"
    )


def test_a_missing_telemetry_plane_reports_blind_not_clean() -> None:
    """The other negative control: an absent plane must not read as an all-clear."""
    scenario = next(s for s in WITH_SPEC if s.id == "s1-dcsync-no-alert")
    assert scenario.spec_journey is not None
    spec = CATALOG[scenario.spec_journey.spec_id]

    empty = Scenario.model_validate(
        {
            **scenario.model_dump(),
            "events": [
                {**scenario.events[0].model_dump(), "fields": {"event.dataset": "zeek.conn"}}
            ],
        }
    )
    result = score_spec_journey(scenario.id, scenario.spec_journey, _simulate(spec, empty))

    assert result.reached is JourneyStage.TRIGGER_BLIND
    assert "blind" in result.detail
    assert "absent rather than clean" in result.detail


def test_the_triage_batch_cannot_be_handed_a_no_alert_scenario() -> None:
    """The population split has to hold at the CLI, not only in select_scenarios.

    `select_scenarios` excludes the declarative population from the tier and
    `all` selectors, but an explicit id still resolves either — deliberately.
    The triage harness is the one caller for which that is never right: a
    scenario with no alert has nothing to sample, so it would plant its
    documents and then raise from the ingester, leaving litter behind.
    """
    import soc_ai.cli as cli_mod

    source = Path(cli_mod.__file__).read_text()
    assert "not_triageable" in source, (
        "validate-batch no longer rejects spec_journey scenarios; an explicit "
        "--synth-set of one would plant documents and then fail in the ingester"
    )


def test_the_ingester_names_the_right_population_when_it_refuses() -> None:
    """Its old message blamed the renderer for something now legal by design."""
    from soc_ai.eval import synth_ingest

    source = Path(synth_ingest.__file__).read_text()
    assert "render_scenario enforces exactly-one triage target" not in source, (
        "the ingester still claims the renderer enforces one triage target, which "
        "stopped being true when the second population landed"
    )
    assert "declarative population" in source
