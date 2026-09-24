"""A candidate becomes a finding without a model, and without inventing anything.

The whole cost argument for the declarative catalog is that nothing generative
runs. These tests hold that line: the narrative is composed from the spec's own
reviewed prose, the citations are real document ids, and nothing asserts a
number the detection did not compute.
"""

from __future__ import annotations

from pathlib import Path

from soc_ai.hunting.execute import Candidate, SpecRun
from soc_ai.hunting.findings import candidate_findings, spec_report
from soc_ai.hunting.spec import HuntSpec, load_catalog

CATALOG = load_catalog(Path(__file__).resolve().parents[1] / "soc_ai/hunting/catalog")
DCSYNC = CATALOG["identity-4662-dcsync-nonmachine"]


def _run(**over) -> SpecRun:
    base = {
        "spec_id": DCSYNC.id,
        "since": "2026-09-03T00:00:00Z",
        "until": "2026-09-06T00:00:00Z",
        "blind": False,
        "precondition_docs": 47,
        "matched_docs": 2,
        "candidates": [
            Candidate(
                DCSYNC.id,
                "localuser",
                "user",
                2,
                ("idA", "idB"),
                "idA",
                ".ds-x",
                "2026-09-04T16:35:51Z",
                "2026-09-04T16:35:51Z",
            )
        ],
    }
    return SpecRun(**{**base, **over})


def test_a_candidate_becomes_a_finding_with_real_citations() -> None:
    """The promotion route resolves a citation to an anchor, so ids must be real."""
    (finding,) = candidate_findings(DCSYNC, _run())
    assert finding["citations"] == ["idA", "idB"]
    assert finding["severity"] == "critical"
    assert finding["category"] == "threat"
    assert "localuser" in finding["title"]
    assert "T1003.006" in finding["mitre_techniques"]


def test_the_title_stays_within_the_analyst_scannable_budget() -> None:
    """HuntFinding's own style rule: ~60 characters, scannable in a list."""
    (finding,) = candidate_findings(DCSYNC, _run())
    assert len(finding["title"]) <= 60


def test_the_detail_is_the_spec_authors_prose_not_a_generated_sentence() -> None:
    """Nothing generative runs, so every sentence was written and reviewed by a human."""
    (finding,) = candidate_findings(DCSYNC, _run())
    opening = " ".join(DCSYNC.description.split())[:60]
    assert opening in finding["detail"]


def test_a_blind_run_reports_a_visibility_gap_not_silence() -> None:
    """An empty findings list would render as "nothing found" while meaning "could not see"."""
    findings = candidate_findings(DCSYNC, _run(blind=True, candidates=[], matched_docs=0))
    (gap,) = findings
    assert gap["category"] == "visibility_gap"
    assert "coverage gap" in gap["detail"]
    assert "not an all-clear" in gap["detail"]


def test_an_errored_run_is_unknown_rather_than_clean() -> None:
    findings = candidate_findings(
        DCSYNC, _run(candidates=[], matched_docs=0, error="field has no mapping")
    )
    (err,) = findings
    assert err["category"] == "visibility_gap"
    assert "The result is unknown." in err["detail"]
    assert "mapping" in err["detail"]


def test_a_clean_run_says_it_could_see() -> None:
    """ "Nothing matched" is only meaningful alongside "and it was looking"."""
    report = spec_report(DCSYNC, _run(candidates=[], matched_docs=0))
    assert report["findings"] == []
    assert "This is a clean result." in report["narrative"]
    assert "47" in report["narrative"]


def test_the_report_carries_no_invented_confidence() -> None:
    """A predicate matched or it did not; a probability would be fabricated."""
    report = spec_report(DCSYNC, _run())
    assert "confidence" not in report


def test_the_narrative_names_query_truncation_specifically() -> None:
    """Not "held back by the budget" — three different facts used to share that phrase.

    Query truncation, budget pressure and already-handled conditions were summed
    into one number and labelled budget, so a run that held back nothing could
    report three.
    """
    report = spec_report(DCSYNC, _run(truncated_docs=9))
    assert "The bucket ceiling left 9 document(s) out of the grouping" in report["narrative"]
    assert "budget" not in report["narrative"]


def test_documents_that_matched_but_grouped_nowhere_are_a_gap_not_silence() -> None:
    """The DCSync event with no attributable principal is the one worth reading.

    ``clean`` used to ignore ``matched_docs`` entirely, so twelve matching
    documents that produced no scope bucket reported an all-clear.
    """
    findings = candidate_findings(
        DCSYNC, _run(candidates=[], matched_docs=12, unattributed_docs=12)
    )
    (gap,) = findings
    assert gap["category"] == "visibility_gap"
    assert "12 document(s) matched" in gap["detail"]
    assert DCSYNC.scope_field in gap["detail"]
    assert "not a clean result" in gap["detail"]


def test_documents_no_verdict_was_reached_on_are_a_gap_not_silence() -> None:
    """Neither matched nor ruled out, so neither a candidate nor an all-clear.

    The population is real: over 2026-09-05 the reconstructed 4624 spec had
    5,240 documents that satisfied its positive clauses and carried no
    ``SubjectUserName``, because Windows does not write one on a network logon.
    The detection returned zero and the run reported clean.
    """
    findings = candidate_findings(DCSYNC, _run(candidates=[], matched_docs=0, undecided_docs=5240))
    (gap,) = findings
    assert gap["category"] == "visibility_gap"
    assert "5240 document(s) matched this detection's positive clauses" in gap["detail"]
    assert "winlog.event_data.SubjectUserName" in gap["detail"]
    assert "not a clean result" in gap["detail"]
    assert "event.dataset" in gap["detail"] and "absent: match" in gap["detail"], (
        "a gap an analyst cannot act on becomes one they learn to scroll past"
    )


TWO_EXCLUSIONS = HuntSpec.model_validate(
    {
        "id": "identity-4624-two-exclusions",
        "title": "Logon by a non-machine account",
        "description": "Windows 4624 logons, machine accounts excluded.",
        "scope_field": "user.name",
        "detection": {
            "all": [{"field": "event.code", "value": "4624"}],
            "none": [
                {"field": "winlog.event_data.SubjectUserName", "op": "wildcard", "value": "*$"},
                {"field": "user.name", "op": "wildcard", "value": "*$"},
            ],
        },
        "precondition": {"all": [{"field": "event.code", "value": "4624"}]},
    }
)


def _two_exclusion_run(**over) -> SpecRun:
    base = {
        "spec_id": TWO_EXCLUSIONS.id,
        "since": "2026-09-05T00:00:00Z",
        "until": "2026-09-06T00:00:00Z",
        "blind": False,
        "precondition_docs": 5422,
        "matched_docs": 0,
        "candidates": [],
        "undecided_docs": 52,
    }
    return SpecRun(**{**base, **over})


def test_the_undecided_finding_names_only_the_field_that_was_missing() -> None:
    """The sentence said the documents carry no value for EVERY exclusion field.

    The compiled query requires only that at least one is missing. Measured on
    a range with a reconstructed two-exclusion spec: 52 undecided documents,
    all 52 carrying the first field named and none carrying the second, so the
    first field in the sentence was present on every document it described.
    That is not only wrong, it misdirects the remedy: the fix the product
    offers is a per-clause declaration, so an analyst told the documents lack a
    field adds it to the wrong clause, sees nothing change, and concludes the
    gap is handled.
    """
    (gap,) = candidate_findings(
        TWO_EXCLUSIONS,
        _two_exclusion_run(
            undecided_by_field=(("winlog.event_data.SubjectUserName", 0), ("user.name", 52))
        ),
    )
    assert "52 document(s) matched this detection's positive clauses" in gap["detail"]
    assert "carry no value for user.name" in gap["detail"]
    assert "SubjectUserName" not in gap["detail"], (
        "every one of those 52 documents carries that field"
    )


def test_the_undecided_finding_counts_each_field_it_names() -> None:
    """Two fields genuinely missing, on overlapping populations.

    A document can lack both, so the counts are not a partition and the
    sentence must not read as one: each number is how many of the undecided
    documents lack THAT field.
    """
    (gap,) = candidate_findings(
        TWO_EXCLUSIONS,
        _two_exclusion_run(
            undecided_docs=60,
            undecided_by_field=(("winlog.event_data.SubjectUserName", 52), ("user.name", 14)),
        ),
    )
    assert "at least one" in gap["detail"]
    assert "winlog.event_data.SubjectUserName on 52" in gap["detail"]
    assert "user.name on 14" in gap["detail"]


def test_without_a_breakdown_the_finding_claims_only_what_the_query_required() -> None:
    """No per-field answer from the grid: say the weaker true thing.

    "At least one of these" is what the undecided query asks for, so it is safe
    with no breakdown to narrow it. Naming a field as absent on no evidence is
    the defect pointed the other way.
    """
    (gap,) = candidate_findings(TWO_EXCLUSIONS, _two_exclusion_run())
    assert "at least one" in gap["detail"]
    assert "carry no value for user.name" not in gap["detail"]


def test_a_single_exclusion_field_still_reads_as_the_plain_sentence() -> None:
    """The negative control on the wording: with one exclusion field, "at least
    one of them missing" IS that field missing, so the plain sentence is true
    and the shipped specs' findings do not grow hedging they do not need."""
    (gap,) = candidate_findings(DCSYNC, _run(candidates=[], matched_docs=0, undecided_docs=5240))
    assert "carry no value for winlog.event_data.SubjectUserName" in gap["detail"]
    assert "at least one" not in gap["detail"]


def test_a_spec_with_no_detection_block_still_renders_a_sentence() -> None:
    """A profile spec has no detection and names no exclusion.

    The sweep answers it from a stored baseline, so it produces no undecided
    document and this path is not reached on the live route. The builder still
    has to survive it: an attribute error here fails the whole sweep, and the
    old sentence ended on a colon with no field after it.
    """
    prior = HuntSpec.model_validate(
        {
            "id": "test-prior",
            "title": "A prior with no detection",
            "description": "For the findings builder.",
            "evaluator": "profile",
            "profile": {"dimension": "served_ports", "test": "novel_for", "roles": ["server"]},
        }
    )
    assert prior.detection is None

    (gap,) = candidate_findings(
        prior,
        SpecRun(
            spec_id=prior.id,
            since="2026-09-03T00:00:00Z",
            until="2026-09-06T00:00:00Z",
            blind=False,
            precondition_docs=47,
            matched_docs=0,
            candidates=[],
            undecided_docs=5240,
        ),
    )
    assert gap["category"] == "visibility_gap"
    assert "are each missing a field one of the spec's exclusions reads" in gap["detail"]
    assert not gap["detail"].rstrip().endswith(":")


# ---------------------------------------------------------------------------
# The two halves of a finding's detail, separable in the data
# ---------------------------------------------------------------------------


def test_every_composed_finding_carries_the_spec_prose_as_its_own_field() -> None:
    """The detail is the author's prose and then this run's result, in one
    string, and the reader has no way to tell them apart. The detail page split
    them by matching the sentence a CANDIDATE finding ends with, so it never
    fired on a visibility-gap finding, which is the case where the author's
    measurements mislead most: the run saw nothing and the prose describes what
    the author once measured. The seam is now carried rather than guessed."""
    runs = {
        "candidate": _run(),
        "undecided": _run(candidates=[], matched_docs=0, undecided_docs=5240),
        "unattributed": _run(candidates=[], matched_docs=12, unattributed_docs=12),
        "truncated": _run(candidates=[], matched_docs=500, truncated_docs=460),
        "blind": _run(candidates=[], matched_docs=0, blind=True, precondition_docs=0),
    }
    for name, run in runs.items():
        for finding in candidate_findings(DCSYNC, run):
            rationale = finding["spec_rationale"]
            assert rationale, f"{name}: no rationale to set apart"
            assert finding["detail"].startswith(rationale), (
                f"{name}: the detail does not begin with the prose the field claims"
            )
            assert finding["detail"] != rationale, f"{name}: nothing left to say about the run"


def test_a_run_that_failed_claims_no_authoring_prose() -> None:
    """Its detail is entirely about this run, so there is no half to set apart
    and a rationale field would have the page label a live error as something
    written when the detection was authored."""
    (finding,) = candidate_findings(DCSYNC, _run(error="ConnectionError: grid down"))
    assert finding.get("spec_rationale") is None
    assert "could not run" in finding["title"]


def test_a_candidate_finding_carries_its_document_count_as_a_number() -> None:
    """The card says "3 of 4 matching documents" and read the 4 out of the
    prose. A number the composer already has does not need parsing back out of
    the sentence it wrote."""
    (finding,) = candidate_findings(DCSYNC, _run())
    assert finding["matched_docs"] == 2
    assert (
        candidate_findings(DCSYNC, _run(candidates=[], matched_docs=0, undecided_docs=1))[0].get(
            "matched_docs"
        )
        is None
    ), "a gap finding counts no candidate documents"


def test_the_narrative_says_the_run_could_not_decide_rather_than_found_nothing() -> None:
    report = spec_report(DCSYNC, _run(candidates=[], matched_docs=0, undecided_docs=5240))
    assert "could not evaluate its exclusions against 5240 document(s)" in report["narrative"]
    assert "clean result" not in report["narrative"]


def test_query_truncation_is_its_own_visibility_gap() -> None:
    findings = candidate_findings(DCSYNC, _run(candidates=[], matched_docs=500, truncated_docs=460))
    assert any(f["category"] == "visibility_gap" for f in findings)
    assert any("This run did not read every document." in f["detail"] for f in findings)


def test_a_gated_run_does_not_invent_a_coverage_gap() -> None:
    """The gate removes candidates; it does not make their documents unattributable.

    A first version derived ``unattributed_docs`` from
    ``matched_docs - sum(candidate.doc_count)``, so every already-handled
    candidate was reported as an unattributable document and a healthy sweep
    grew a spurious visibility_gap finding.
    """
    gated = _run(matched_docs=2, unattributed_docs=0)  # 2 matched, 1 survived the gate
    findings = candidate_findings(DCSYNC, gated)
    assert all(f["category"] != "visibility_gap" for f in findings)


def test_a_user_scoped_finding_does_not_claim_the_account_is_a_host() -> None:
    """``hosts`` feeds host pivots and the entity page; an account there is wrong."""
    (finding,) = candidate_findings(DCSYNC, _run())
    assert finding["hosts"] == []


def test_an_ip_scoped_finding_does_populate_hosts() -> None:
    decoy = CATALOG["decoy-opencanary-interaction"]
    run = SpecRun(
        decoy.id,
        "a",
        "b",
        blind=False,
        precondition_docs=14,
        matched_docs=6,
        candidates=[Candidate(decoy.id, "10.0.0.66", "ip", 4, ("i1",), "i1", ".ds", None, None)],
    )
    (finding,) = candidate_findings(decoy, run)
    assert finding["hosts"] == ["10.0.0.66"]


def test_every_shipped_spec_produces_a_renderable_finding() -> None:
    """Guards against a spec whose prose or level breaks the finding shape."""
    for spec in CATALOG.values():
        run = SpecRun(
            spec.id,
            "a",
            "b",
            blind=False,
            precondition_docs=10,
            matched_docs=1,
            candidates=[
                Candidate(spec.id, "x", spec.scope_kind, 1, ("i",), "i", ".ds", None, None)
            ],
        )
        (finding,) = candidate_findings(spec, run)
        assert finding["title"] and len(finding["title"]) <= 60
        assert len(finding["detail"]) > 40
        assert finding["severity"] in {"info", "low", "medium", "high", "critical"}


# ---------------------------------------------------------------------------
# Naming the window the precondition actually used
# ---------------------------------------------------------------------------

# A spec shaped like the decoy: its sensor writes when something happens, so its
# precondition asks about ninety days rather than about the sweep window.
NO_HEARTBEAT = HuntSpec.model_validate(
    {
        "id": "t-no-heartbeat",
        "title": "Something connected to a decoy service",
        "description": "An OpenCanary honeypot recorded an inbound interaction.",
        "scope_field": "source.ip",
        "scope_kind": "ip",
        "precondition": {"all": [{"field": "event.dataset", "value": "opencanary.events"}]},
        "precondition_lookback_minutes": 90 * 24 * 60,
        "detection": {
            "all": [
                {"field": "event.dataset", "value": "opencanary.events"},
                {"field": "source.ip", "op": "exists"},
            ]
        },
    }
)


def _quiet_run(**over) -> SpecRun:
    base = {
        "spec_id": NO_HEARTBEAT.id,
        "since": "now-61m",
        "until": "now",
        "blind": True,
        "precondition_docs": 0,
        "matched_docs": 0,
        "candidates": [],
        "precondition_since": "now-61m-129600m",
    }
    return SpecRun(**{**base, **over})


def test_a_blind_report_names_the_window_the_precondition_asked_about() -> None:
    """The wrong sentence is the harm, not the boolean.

    A spec that asked about ninety days and reported "nothing between now-61m
    and now" states something false in the one finding an operator reads about
    the marker they are meant to believe.
    """
    report = spec_report(NO_HEARTBEAT, _quiet_run())
    assert "in the 90 days to now" in report["narrative"]
    assert "now-61m and now" not in report["narrative"]

    (gap,) = candidate_findings(NO_HEARTBEAT, _quiet_run())
    assert "in the 90 days to now" in gap["detail"]
    assert "coverage gap" in gap["detail"]


def test_the_window_comes_from_the_run_and_not_from_the_catalog_file() -> None:
    """A run that did not widen says so, whatever the spec says today.

    The trail outlives the file. Composed from the current spec, the sentence
    would describe a window that run never asked about the moment somebody edits
    the look-back.
    """
    report = spec_report(NO_HEARTBEAT, _quiet_run(precondition_since=""))
    assert "between now-61m and now" in report["narrative"]
    assert "90 days" not in report["narrative"]


def test_a_clean_run_under_a_look_back_says_which_window_it_could_see_over() -> None:
    """ "It could see" is a claim about a window, so the window belongs in it."""
    report = spec_report(NO_HEARTBEAT, _quiet_run(blind=False, precondition_docs=8, matched_docs=0))
    assert "This is a clean result." in report["narrative"]
    assert "8 document(s) in the 90 days to now" in report["narrative"]


def test_a_spec_with_no_look_back_reports_exactly_as_it_did() -> None:
    """Three of the four shipped specs are this case."""
    blind = spec_report(DCSYNC, _run(blind=True, candidates=[], matched_docs=0))
    assert (
        "precondition matched nothing between 2026-09-03T00:00:00Z and 2026-09-06T00:00:00Z"
        in blind["narrative"]
    )
    clean = spec_report(DCSYNC, _run(candidates=[], matched_docs=0))
    assert (
        "Its precondition matched 47 document(s). This is a clean result." in (clean["narrative"])
    )
