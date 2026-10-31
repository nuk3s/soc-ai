"""The subject rule: which hunt findings the hunt investigates.

A finding is a subject when it is a threat and names an entity. A visibility
gap, a failed run and an observation are never subjects. A citation is not required:
the anchor rule of the promotion finds a document, or says that it cannot.
Each case below pairs the positive shape with the one field that turns it
off.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.hunting.findings import (
    finding_document_ids,
    finding_entities,
    finding_is_subject,
    subject_fingerprint,
    subject_ordinals,
)

_DOC = "tel-doc-000001"
_DOC2 = "tel-doc-000002"


def _threat(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "title": "Beaconing to a rare external address",
        "detail": "The host calls out every 60 s.",
        "severity": "high",
        "category": "threat",
        "hosts": ["10.0.0.5"],
        "citations": [_DOC],
    }
    base.update(over)
    return base


def test_a_threat_on_a_host_with_a_document_is_a_subject() -> None:
    assert finding_is_subject(_threat()) is True


@pytest.mark.parametrize(
    "entity_fields",
    [
        {"hosts": ["ws-17"]},
        {"hosts": [], "entities": [{"kind": "user", "value": "svc-backup"}]},
        {"hosts": [], "entities": [["cloud_identity", "ops@example.org"]]},
        {"hosts": [], "users": ["alice"]},
        {"hosts": [], "domains": ["corp.example"]},
    ],
)
def test_each_entity_type_makes_a_subject(entity_fields: dict[str, Any]) -> None:
    assert finding_is_subject(_threat(**entity_fields)) is True


def test_a_finding_that_names_no_entity_is_not_a_subject() -> None:
    assert finding_is_subject(_threat(hosts=[])) is False
    # A rule or a dataset scope names no entity to investigate.
    rule_scope = _threat(hosts=[], entities=[{"kind": "rule", "value": "R1"}])
    assert finding_is_subject(rule_scope) is False


def test_a_finding_that_cites_no_document_is_still_a_subject() -> None:
    # A threat the model named without a citation is the one to check. The
    # range re-hunt of 2026-10-07 reported "Internal host nmap RDP scan" with
    # two hosts and no citation, and the hunt investigated nothing.
    assert finding_is_subject(_threat(citations=[])) is True
    # Prose and a tool call are citations. They are not documents, and the
    # finding is a subject all the same.
    tool_and_prose = ["t_origin_chain(10.0.0.5)", "the conn log"]
    assert finding_is_subject(_threat(citations=tool_and_prose)) is True
    assert finding_document_ids(_threat(citations=tool_and_prose)) == []
    # Control: the entity is what makes the subject. None, and no document
    # count brings it back.
    assert finding_is_subject(_threat(hosts=[], citations=[_DOC])) is False


def test_a_visibility_gap_is_not_a_subject() -> None:
    assert finding_is_subject(_threat(category="visibility_gap")) is False


def test_a_legacy_gap_with_no_category_is_not_a_subject() -> None:
    legacy = _threat(title="No process telemetry on ws-17")
    del legacy["category"]
    assert finding_is_subject(legacy) is False


def test_a_run_failure_is_not_a_subject() -> None:
    failure = _threat(category="visibility_gap", title="DCSync by a non-machine: could not run")
    assert finding_is_subject(failure) is False


def test_a_clean_observation_is_not_a_subject() -> None:
    clean = _threat(category="observation", title="No beaconing observed on 10.0.0.5")
    assert finding_is_subject(clean) is False
    assert finding_is_subject(_threat(category="observation", title="Nothing unusual")) is False


def test_an_observation_is_never_a_subject() -> None:
    """An observation claims no threat, so the hunt opens no investigation on it.

    The range hunt of lead 5 (2026-10-19) linked the observation "All abuse is
    historical, no 30-day recurrence" to the investigation of a threat on the
    same hosts. The card then read "True positive 0.72" and the label counted
    it as a threat.
    """
    seen = _threat(category="observation", title="Nightly backup job writes to a share")
    assert finding_is_subject(seen) is False
    historical = _threat(category="observation", title="All abuse is historical")
    assert finding_is_subject(historical) is False
    # Control: the same finding as a threat is a subject.
    assert finding_is_subject({**seen, "category": "threat"}) is True


def test_a_threat_title_that_starts_with_no_is_still_a_subject() -> None:
    """The clean rule reads the title of an observation only."""
    assert finding_is_subject(_threat(title="No MFA on an admin logon from 10.0.0.5")) is True


@pytest.mark.parametrize("value", [None, "finding", 3, ["a"]])
def test_a_non_mapping_is_not_a_subject(value: Any) -> None:
    assert finding_is_subject(value) is False


def test_entities_and_documents_are_normalised() -> None:
    finding = _threat(
        hosts=["WS-17", "10.0.0.5", True, None],
        entities=[{"kind": "ip", "value": "10.0.0.5"}, {"kind": "user", "value": " Alice "}],
        citations=[_DOC, _DOC, 7, "short"],
    )
    assert finding_entities(finding) == [
        ("host", "ws-17"),
        ("address", "10.0.0.5"),
        ("user", "alice"),
    ]
    assert finding_document_ids(finding) == [_DOC]


def test_the_fingerprint_ignores_order_case_and_the_hunt() -> None:
    a = _threat(hosts=["10.0.0.5", "WS-17"], citations=[_DOC, _DOC2])
    b = _threat(
        title="Another wording from a second hunt",
        hosts=["ws-17", "10.0.0.5"],
        citations=[_DOC2, _DOC],
    )
    assert subject_fingerprint(a) == subject_fingerprint(b)


def test_the_fingerprint_changes_with_the_subject() -> None:
    base = subject_fingerprint(_threat())
    assert base is not None
    assert subject_fingerprint(_threat(citations=[_DOC2])) != base
    assert subject_fingerprint(_threat(hosts=["10.0.0.6"])) != base
    assert subject_fingerprint(_threat(hosts=[], citations=[])) is None


@pytest.mark.parametrize(
    "citations",
    [
        [],
        ["the conn log shows the login", "t_origin_chain(192.0.2.10)"],
        ["1:YDPTyOYjiAM6SPNKuaVlT1H+k7A="],
        ["t_origin_chain:192.0.2.10"],
        ["t_host_summary:192.0.2.11"],
    ],
)
def test_a_finding_that_cites_no_document_has_no_fingerprint(citations: list[str]) -> None:
    """Change E. A finding with no document has only its claim as identity.
    The entity set alone made two different claims on one host pair share an
    investigation (lead 49, 2026-10-24). A tool call is not a document."""
    finding = _threat(hosts=["192.0.2.10", "192.0.2.11"], citations=citations)
    assert subject_fingerprint(finding) is None
    # The owner rule holds: the finding is still a subject.
    assert finding_is_subject(finding) is True


def test_a_tool_call_citation_is_not_a_document() -> None:
    assert finding_document_ids(_threat(citations=["t_host_summary:192.0.2.11", _DOC])) == [_DOC]


def test_subjects_come_in_severity_then_report_order() -> None:
    findings = [
        _threat(severity="low"),
        _threat(category="visibility_gap"),
        _threat(severity="critical"),
        _threat(severity="low"),
        _threat(severity="high"),
        "not a finding",
    ]
    assert subject_ordinals(findings) == [2, 4, 0, 3]
    assert subject_ordinals("not a list") == []


def test_a_user_scoped_catalog_candidate_is_a_subject() -> None:
    """The catalog composer names the scope entity, so a user-scoped match qualifies."""
    from pathlib import Path

    from soc_ai.hunting.execute import Candidate, SpecRun
    from soc_ai.hunting.findings import candidate_findings
    from soc_ai.hunting.spec import load_catalog

    catalog = load_catalog(Path(__file__).resolve().parents[1] / "soc_ai/hunting/catalog")
    spec = catalog["identity-4662-dcsync-nonmachine"]
    assert spec.scope_kind == "user"
    candidate = Candidate(spec.id, "svc-backup", "user", 1, (_DOC,), _DOC, ".ds-x", None, None)
    run = SpecRun(
        spec_id=spec.id,
        since="2026-09-03T00:00:00Z",
        until="2026-09-06T00:00:00Z",
        blind=False,
        precondition_docs=5,
        matched_docs=1,
        candidates=[candidate],
    )
    (finding,) = candidate_findings(spec, run)
    assert finding["hosts"] == []
    assert finding["entities"] == [{"kind": "user", "value": "svc-backup"}]
    assert finding_is_subject(finding) is True
    # Control: the same match without the entity names nothing.
    assert finding_is_subject({**finding, "entities": []}) is False
