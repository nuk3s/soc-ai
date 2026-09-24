"""A planted fixture must not reach a real queue, whatever shape it arrives in.

The numbers behind this module were measured on the development range on
2026-09-06, on the ``tags:alert`` population:

- 56,162 alert-tagged documents survived the top-level-only exclusion;
- 2 of them were a planted DCSync fixture whose marker sat one level down,
  presenting as a critical Sigma detection in the live queue;
- adding the envelope position took the survivors to 56,160 and the
  ``sigma.alert`` class from 55 to 53. ``suricata.alert`` did not move
  (56,107 before and after), and the three genuine DCSync alerts on the real
  domain controller were all still there.

Security Onion's Sigma pipeline re-nests the whole originating document under
``event_data``, so a marker the ingest wrote at the top level of the source
event lands under that envelope on the alert the pipeline emits. The event
itself is still excluded, which is the part that turns a leak into a wrong
answer: the alert is visible and everything that would explain it is not.
"""

from __future__ import annotations

from typing import Any

from soc_ai.tools._synth_scope import MARKER_PATHS, scope_hidden_scenario, synth_scope_must_not

# The document as Elasticsearch returns it: the envelope is a nested object and
# the source document's own dotted field names are written flat inside it.
# Neither a pure-nested nor a pure-flat reader reaches the marker in this shape.
_SIGMA_ALERT_SOURCE = {
    "rule": {"name": "Active Directory Replication from Non Machine Account"},
    "event": {"dataset": "sigma.alert", "severity_label": "critical"},
    "event_data": {
        "synth.scenario_id": "s1-dcsync-no-alert",
        "host.hostname": "SYNTH-DC01",
    },
}

# A document, keyed the way Elasticsearch addresses its fields, so the tests
# assert which documents a query can RETURN rather than how a clause is spelt.
_TOP_LEVEL_PLANT = {"synth.scenario_id": "s1-dcsync-no-alert"}
_ENVELOPE_PLANT = {
    "rule.name": "Active Directory Replication from Non Machine Account",
    "event.dataset": "sigma.alert",
    "event_data.synth.scenario_id": "s1-dcsync-no-alert",
    "event_data.host.hostname": "SYNTH-DC01",
}
_ENVELOPE_SIBLING = {"event_data.synth.scenario_id": "s2-other-scenario"}
# The negative control: the real thing. Same rule, same envelope, same critical
# severity, no marker in either position. Shape taken from the three genuine
# detections on the range's domain controller.
_GENUINE_ALERT = {
    "rule.name": "Active Directory Replication from Non Machine Account",
    "event.dataset": "sigma.alert",
    "event.severity_label": "critical",
    "event_data.host.name": "sr-dc01",
    "event_data.winlog.event_data.SubjectUserName": "localuser",
    "tags": "alert",
}


def _clause_matches(clause: dict[str, Any], doc: dict[str, Any]) -> bool:
    """Evaluate one ``must_not`` clause shape against a field-path-keyed doc."""
    if "exists" in clause:
        return clause["exists"]["field"] in doc
    if "term" in clause:
        ((field, value),) = clause["term"].items()
        return doc.get(field.removesuffix(".keyword")) == value
    if "bool" in clause:
        inner = clause["bool"]
        return all(_clause_matches(m, doc) for m in inner.get("must", [])) and not any(
            _clause_matches(m, doc) for m in inner.get("must_not", [])
        )
    return False


def _excluded(scope: bool | str, doc: dict[str, Any]) -> bool:
    return any(_clause_matches(c, doc) for c in synth_scope_must_not(scope))


def test_the_envelope_position_is_one_of_the_marker_paths() -> None:
    """The pipeline decides where the marker lands, so the guard names both."""
    assert "synth.scenario_id" in MARKER_PATHS
    assert "event_data.synth.scenario_id" in MARKER_PATHS


def test_prod_excludes_a_plant_nested_under_the_sigma_envelope() -> None:
    """The leak. Two of these presented as a critical alert in the live queue."""
    assert _excluded(False, _ENVELOPE_PLANT)


def test_prod_still_excludes_a_plant_at_the_top_level() -> None:
    assert _excluded(False, _TOP_LEVEL_PLANT)


def test_a_genuine_alert_with_no_marker_anywhere_still_reaches_the_queue() -> None:
    """The negative control, and the only one that matters.

    A guard that catches the fixture by hiding the alert class it wore is not a
    fix. This document is the same rule, the same envelope and the same critical
    severity as the plant, and it must survive every scope.
    """
    assert not _excluded(False, _GENUINE_ALERT)
    assert not _excluded("s1-dcsync-no-alert", _GENUINE_ALERT)
    assert not _excluded(True, _GENUINE_ALERT)


def test_a_scenario_scope_sees_its_own_plant_in_the_envelope() -> None:
    """A batch-eval run triaging a Sigma-shaped plant has to be able to read it."""
    assert not _excluded("s1-dcsync-no-alert", _ENVELOPE_PLANT)


def test_a_scenario_scope_excludes_a_sibling_plant_in_the_envelope() -> None:
    """The cross-contamination rule holds at the nested position too: the
    catalogue is ingested as one batch and its scenarios share endpoints."""
    assert _excluded("s1-dcsync-no-alert", _ENVELOPE_SIBLING)


def test_a_scenario_scope_excludes_a_sibling_plant_at_the_top_level() -> None:
    assert _excluded("s1-dcsync-no-alert", {"synth.scenario_id": "s2-other-scenario"})


def test_the_hunt_journey_scope_excludes_nothing() -> None:
    assert synth_scope_must_not(True) == []


def test_a_hidden_anchor_is_named_by_the_scenario_it_belongs_to() -> None:
    """The refusal has to say what it refused, so the answer is the id, not a
    bare yes. Read off the document layout the grid actually returns."""
    assert scope_hidden_scenario(False, _SIGMA_ALERT_SOURCE) == "s1-dcsync-no-alert"


def test_a_scope_that_owns_the_anchor_hides_nothing() -> None:
    assert scope_hidden_scenario("s1-dcsync-no-alert", _SIGMA_ALERT_SOURCE) is None
    assert scope_hidden_scenario(True, _SIGMA_ALERT_SOURCE) is None


def test_a_scope_that_owns_a_different_scenario_hides_the_anchor() -> None:
    """A scoped run handed a sibling's alert id would pivot with every one of
    that sibling's supporting documents excluded."""
    assert scope_hidden_scenario("s2-other-scenario", _SIGMA_ALERT_SOURCE) == "s1-dcsync-no-alert"


def test_a_genuine_anchor_is_never_hidden() -> None:
    """The negative control again, on the read side: no marker, no refusal, at
    any scope. A refusal on a real alert is a worse bug than the leak."""
    for scope in (False, True, "s1-dcsync-no-alert"):
        assert scope_hidden_scenario(scope, _GENUINE_ALERT) is None


def test_the_marker_is_read_in_every_layout_the_grid_writes_it() -> None:
    """Flat-dotted, nested, and the mix a Sigma alert arrives in."""
    assert scope_hidden_scenario(False, {"synth.scenario_id": "s1"}) == "s1"
    assert scope_hidden_scenario(False, {"synth": {"scenario_id": "s1"}}) == "s1"
    assert scope_hidden_scenario(False, {"event_data": {"synth.scenario_id": "s1"}}) == "s1"
    assert scope_hidden_scenario(False, {"event_data": {"synth": {"scenario_id": "s1"}}}) == "s1"


def test_the_clauses_are_valid_elasticsearch_must_not_shape() -> None:
    """Spliced straight into a bool query, so every clause is a single-key dict."""
    for scope in (False, "s1-dcsync-no-alert"):
        for clause in synth_scope_must_not(scope):
            assert isinstance(clause, dict)
            assert len(clause) == 1
            assert next(iter(clause)) in {"exists", "bool"}
