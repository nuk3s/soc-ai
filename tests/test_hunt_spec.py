"""The HuntSpec document, its compiler, and the shipped catalog.

The acceptance evidence behind these tests, run against the development range on
2026-09-04 over 2026-09-03T00:00Z to 2026-09-06T00:00Z:

    identity-4662-dcsync-nonmachine   2 docs  -> localuser    16:35:51
    identity-4768-preauth-disabled    1 doc   -> svc_legacy   16:34:41
    identity-4769-rc4-service-ticket  1 doc   -> svc_sql      16:34:17

Three predicates, no model, no statistics, no false positives, and the chain
recovered in order across 94 seconds. Security Onion's own rules produced
nothing for two of the three, and were 22 to 60 minutes late on the other.

The DCSync line was produced by the clause as it then shipped, matching
DS-Replication-Get-Changes only. The spec has since widened to all three
replication rights; the tests under "The shipped catalog" say why.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from soc_ai.hunting.match import (
    clause_matches,
    detection_matches,
    detection_undecided,
    field_is_present,
    precondition_matches,
)
from soc_ai.hunting.spec import (
    MAX_CLAUSES,
    MAX_PRECONDITION_LOOKBACK_MINUTES,
    Clause,
    Detection,
    HuntSpec,
    load_catalog,
    load_spec,
)

CATALOG = Path(__file__).resolve().parents[1] / "soc_ai/hunting/catalog"

# The three AD control-access rights that together make an account DCSync
# capable. PowerView's `-Rights DCSync` grants exactly these three and nothing
# else. The DC writes one 4662 per right it checks, so a detection has to
# accept any one of them on its own.
DS_REPLICATION_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"
REPLICATION_RIGHTS = (
    DS_REPLICATION_GET_CHANGES,
    DS_REPLICATION_GET_CHANGES_ALL,
    DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET,
)
# Sigma's non-machine replication rule also matches this one. It is left out of
# the spec on purpose; the test that pins its absence says why.
DS_REPLICATION_SYNCHRONIZE = "9923a32a-3607-11d2-b9be-0000f87a36b2"
# The domainDNS class GUID that trails every one of these documents.
DOMAIN_DNS_CLASS = "19195a5b-6da0-11d0-afd3-00c04fd930c9"


def _spec(**over) -> HuntSpec:
    base = {
        "id": "test-spec",
        "title": "t",
        "detection": {"all": [{"field": "event.code", "value": "4662"}]},
    }
    return HuntSpec.model_validate({**base, **over})


def _4662(subject: str, *rights: str) -> dict[str, str]:
    """A Directory Service Access document the way the DC writes it.

    ``Properties`` is one multi-line composite string: the access kind, then
    each control-access right the DC checked, then the object class. A real
    DCSync run splits one act across documents that each carry one right.
    """
    checked = "".join(f"\t\t{{{right}}}\n" for right in rights)
    return {
        "event.code": "4662",
        "winlog.event_data.SubjectUserName": subject,
        "winlog.event_data.Properties": f"Control Access\n{checked}\t{{{DOMAIN_DNS_CLASS}}}",
    }


# ---------------------------------------------------------------------------
# Clause compilation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("op", "value", "expected"),
    [
        ("equals", "4662", {"term": {"event.code": "4662"}}),
        ("one_of", ["4662", "4769"], {"terms": {"event.code": ["4662", "4769"]}}),
        ("exists", None, {"exists": {"field": "event.code"}}),
        ("prefix", "46", {"prefix": {"event.code": "46"}}),
        ("wildcard", "46*", {"wildcard": {"event.code": "46*"}}),
        ("contains", "66", {"wildcard": {"event.code": "*66*"}}),
        ("gte", 10, {"range": {"event.code": {"gte": 10}}}),
    ],
)
def test_each_op_compiles(op, value, expected) -> None:
    assert Clause(field="event.code", op=op, value=value).to_es() == expected


def test_a_spec_cannot_query_a_field_the_query_language_forbids() -> None:
    """One reviewed decision per field, not two that can disagree.

    A spec reading a field OQL does not admit would route around the whitelist
    and, with it, around the Oracle-egress classification that lands in the same
    change.
    """
    with pytest.raises(ValidationError, match="not on the OQL whitelist"):
        Clause(field="winlog.event_data.NobodyClassifiedThis", value="x")


def test_exists_takes_no_value_and_the_others_require_one() -> None:
    with pytest.raises(ValidationError, match="takes no value"):
        Clause(field="event.code", op="exists", value="4662")
    with pytest.raises(ValidationError, match="requires a value"):
        Clause(field="event.code", op="equals")
    with pytest.raises(ValidationError, match="requires a list"):
        Clause(field="event.code", op="one_of", value="4662")
    with pytest.raises(ValidationError, match="scalar, not a list"):
        Clause(field="event.code", op="equals", value=["a", "b"])


# ---------------------------------------------------------------------------
# Detection shape
# ---------------------------------------------------------------------------


def test_a_detection_needs_at_least_one_clause() -> None:
    with pytest.raises(ValidationError, match="at least one clause"):
        Detection()


def test_a_detection_of_only_exclusions_is_a_grid_sweep_not_a_detection() -> None:
    """``none`` alone matches every document that is not excluded."""
    with pytest.raises(ValidationError, match="sweep of the whole grid"):
        Detection(none=[Clause(field="event.code", value="4662")])


def test_the_clause_ceiling_holds() -> None:
    with pytest.raises(ValidationError, match=f"ceiling is {MAX_CLAUSES}"):
        Detection(all=[Clause(field="event.code", value=str(i)) for i in range(MAX_CLAUSES + 1)])


# ---------------------------------------------------------------------------
# Query compilation
# ---------------------------------------------------------------------------


def test_the_query_carries_provenance_and_synth_scope() -> None:
    """Both scopes are threaded, not optional.

    85% of the development grid is imported. A spec compiled without the
    provenance clause is measuring somebody else's network.
    """
    q = _spec().to_query(since="2026-09-03T00:00:00Z", until="2026-09-06T00:00:00Z")
    must_not = q["bool"]["must_not"]
    assert {"exists": {"field": "import.id"}} in must_not
    assert {"term": {"tags": "replayed-corpus"}} in must_not
    assert {"exists": {"field": "synth.scenario_id"}} in must_not


def test_provenance_any_admits_history_for_a_retro_hunt() -> None:
    q = _spec(provenance="any").to_query(since="a", until="b")
    assert {"exists": {"field": "import.id"}} not in q["bool"].get("must_not", [])


def test_the_time_window_is_always_a_filter() -> None:
    q = _spec().to_query(since="2026-09-03T00:00:00Z", until="2026-09-06T00:00:00Z")
    assert {
        "range": {"@timestamp": {"gte": "2026-09-03T00:00:00Z", "lte": "2026-09-06T00:00:00Z"}}
    } in q["bool"]["filter"]


def test_the_precondition_compiles_over_the_same_population() -> None:
    """A precondition scoped differently to the detection answers a different question."""
    spec = _spec(precondition={"all": [{"field": "event.code", "value": "4662"}]})
    det = spec.to_query(since="a", until="b")
    pre = spec.to_query(since="a", until="b", precondition=True)
    assert det["bool"]["must_not"] == pre["bool"]["must_not"]
    assert {"range": {"@timestamp": {"gte": "a", "lte": "b"}}} in pre["bool"]["filter"]


def test_asking_for_a_precondition_that_does_not_exist_is_an_error() -> None:
    with pytest.raises(ValueError, match="no precondition"):
        _spec().to_query(since="a", until="b", precondition=True)


def test_any_clauses_become_a_should_with_minimum_one() -> None:
    spec = _spec(
        detection={
            "any": [
                {"field": "event.code", "value": "4768"},
                {"field": "event.code", "value": "4769"},
            ]
        }
    )
    q = spec.to_query(since="a", until="b")
    assert q["bool"]["minimum_should_match"] == 1
    assert len(q["bool"]["should"]) == 2


def test_an_all_only_detection_compiles_without_a_should_block() -> None:
    """Widening one spec to ``any`` must not change how every other spec compiles."""
    q = _spec().to_query(since="a", until="b")
    assert "should" not in q["bool"]
    assert "minimum_should_match" not in q["bool"]


def test_the_matcher_and_the_compiler_agree_on_any() -> None:
    """``any`` is a floor of one in both engines, and absent ``any`` is no floor.

    The compiler says ``should`` with ``minimum_should_match: 1``. The matcher
    has to say the same thing in memory, or the coverage gate would certify a
    spec that behaves differently live.
    """
    tree = Detection(
        all=[Clause(field="event.code", value="4662")],
        any=[
            Clause(field="winlog.event_data.Properties", op="contains", value="aaa"),
            Clause(field="winlog.event_data.Properties", op="contains", value="bbb"),
        ],
        none=[Clause(field="winlog.event_data.SubjectUserName", op="wildcard", value="*$")],
    )
    doc = {"event.code": "4662", "winlog.event_data.SubjectUserName": "u"}
    assert detection_matches(tree, {**doc, "winlog.event_data.Properties": "x bbb"})
    assert detection_matches(tree, {**doc, "winlog.event_data.Properties": "aaa bbb"})
    assert not detection_matches(tree, {**doc, "winlog.event_data.Properties": "ccc"}), (
        "no any-clause held, so the floor of one is not met"
    )
    assert not detection_matches(tree, {**doc, "winlog.event_data.Properties": ""})

    without_any = Detection(all=tree.all, none=tree.none)
    assert detection_matches(without_any, {**doc, "winlog.event_data.Properties": "ccc"}), (
        "an empty any block is no constraint, matching the compiler's absent should"
    )


# ---------------------------------------------------------------------------
# Exclusions over a field the document does not carry
# ---------------------------------------------------------------------------

# The shape that exposed the defect. It is written out here rather than shipped
# because it is the NEXT spec on the roadmap, and the four in the catalog only
# escape by luck of which event codes Elastic Defend subscribes to.
#
# Windows security events arrive twice on a host running both the winlog
# integration and Elastic Defend. Measured on the development range on
# 2026-09-05:
#
#     event.code 4624: 2,858 total = 1,429 endpoint.events.security
#                                    (0 with winlog.event_data.SubjectUserName)
#                                  + 1,429 system.security
#     event.code 4648:   154 total =    77 endpoint.events.security
#                                    (0 with winlog.event_data.SubjectUserName)
#                                  +    77 system.security
#
# Compiled as the clause form then was, the 4648 spec produced 78 candidates:
# 77 from endpoint.events.security and 1 from system.security, of which 74 were
# the machine accounts the exclusions exist to remove. 98.7% false positives
# from a clause written correctly.
DUAL_SOURCED_CODE = "4648"

# The copy that carries the event data, and the copy that carries only the code.
WINLOG_MACHINE_ACCOUNT = {
    "event.code": DUAL_SOURCED_CODE,
    "event.dataset": "system.security",
    "winlog.event_data.SubjectUserName": "SYNTH-WS07$",
    "winlog.event_data.TargetUserName": "SYNTH-WS07$",
}
WINLOG_HUMAN = {
    "event.code": DUAL_SOURCED_CODE,
    "event.dataset": "system.security",
    "winlog.event_data.SubjectUserName": "j.hollis",
    "winlog.event_data.TargetUserName": "svc_reporting",
}
ENDPOINT_COPY = {
    "event.code": DUAL_SOURCED_CODE,
    "event.dataset": "endpoint.events.security",
}


def _dual_sourced_spec() -> HuntSpec:
    """A spec whose precision comes entirely from its exclusions."""
    return _spec(
        precondition={"all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}]},
        detection={
            "all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}],
            "none": [
                {"field": "winlog.event_data.SubjectUserName", "op": "wildcard", "value": "*$"},
                {"field": "winlog.event_data.TargetUserName", "op": "wildcard", "value": "*$"},
            ],
        },
    )


def test_an_exclusion_holds_on_a_document_that_does_not_carry_the_field() -> None:
    """An exclusion is a statement about documents that carry the field.

    A ``must_not`` on a wildcard over a field a document does not have excludes
    nothing, so the moment the same event code arrives from a second dataset
    with a different schema, the exclusion silently stops working on that copy
    and the spec keeps every document it was written to drop.

    The first two assertions are the negative control, and the reason this
    fixture is on the missed path rather than the easy one: the endpoint copy
    satisfies every positive clause and fires NO exclusion clause, which is
    exactly the state in which the old rule kept it. A fixture whose planted
    document failed a positive clause would have been rejected either way and
    would have proved nothing.
    """
    tree = _dual_sourced_spec().detection

    assert all(clause_matches(c, ENDPOINT_COPY) for c in tree.all), (
        "the endpoint copy must satisfy the positive clauses, or it never reaches "
        "the exclusion and this fixture tests nothing"
    )
    assert not any(clause_matches(c, ENDPOINT_COPY) for c in tree.none), (
        "no exclusion clause fires on the endpoint copy; `not any(...)` over those "
        "clauses is the old rule, and it admitted this document"
    )

    assert not detection_matches(tree, ENDPOINT_COPY)
    assert not detection_matches(tree, WINLOG_MACHINE_ACCOUNT)
    assert detection_matches(tree, WINLOG_HUMAN), (
        "the population the spec is actually about must still match"
    )


def test_the_compiled_exclusion_requires_the_field_it_reads() -> None:
    """Same statement in the other engine: has the field AND does not match it."""
    q = _dual_sourced_spec().to_query(since="a", until="b")
    for field in ("winlog.event_data.SubjectUserName", "winlog.event_data.TargetUserName"):
        assert {"exists": {"field": field}} in q["bool"]["filter"], (
            f"nothing requires {field} to be present, so the must_not below is a no-op "
            "on every document that lacks it"
        )
        assert {"wildcard": {field: "*$"}} in q["bool"]["must_not"]


def test_the_matcher_and_the_compiler_agree_on_an_absent_field_in_none() -> None:
    """The agreement discipline, extended to the case that broke it.

    Before this change the two engines agreed, and agreed on the wrong answer:
    ``clause_matches`` returns False for a missing field, so ``not any(...)``
    let the document through in memory exactly as ``must_not`` let it through
    in Elasticsearch. That is why the coverage gate could not have caught this
    — it faithfully reproduced the defect.
    """
    spec = _dual_sourced_spec()
    q = spec.to_query(since="a", until="b")
    excluded_fields = [
        c["exists"]["field"]
        for c in q["bool"]["filter"]
        if "exists" in c  # type: ignore[index]
    ]
    assert excluded_fields == [
        "winlog.event_data.SubjectUserName",
        "winlog.event_data.TargetUserName",
    ]
    for field in excluded_fields:
        partial = {k: v for k, v in WINLOG_HUMAN.items() if k != field}
        assert not detection_matches(spec.detection, partial), (
            f"the compiler requires {field} to exist and the matcher does not; a spec "
            "would score one way in CI and behave another way live"
        )


def test_a_none_clause_on_exists_still_means_the_field_must_be_absent() -> None:
    """The carve-out, and it is not a special case so much as the same rule.

    ``none: [{field: f, op: exists}]`` says f must NOT be there. Requiring f to
    be present would make the clause unsatisfiable, so a presence requirement is
    derived only from clauses that read a value.
    """
    tree = Detection(
        all=[Clause(field="event.code", value=DUAL_SOURCED_CODE)],
        none=[Clause(field="winlog.event_data.SubjectUserName", op="exists")],
    )
    assert tree.to_es() == {
        "bool": {
            "filter": [{"term": {"event.code": DUAL_SOURCED_CODE}}],
            "must_not": [{"exists": {"field": "winlog.event_data.SubjectUserName"}}],
        }
    }
    assert detection_matches(tree, ENDPOINT_COPY)
    assert not detection_matches(tree, WINLOG_HUMAN)


def test_an_exclusion_on_a_field_the_all_block_already_pins_adds_nothing() -> None:
    """A value-bearing positive clause already requires the field to be there."""
    tree = Detection(
        all=[Clause(field="winlog.event_data.ServiceName", op="prefix", value="svc")],
        none=[Clause(field="winlog.event_data.ServiceName", op="wildcard", value="*$")],
    )
    assert tree.to_es()["bool"]["filter"] == [{"prefix": {"winlog.event_data.ServiceName": "svc"}}]


# ---------------------------------------------------------------------------
# The precondition and the second copy of the same event
# ---------------------------------------------------------------------------


def test_the_precondition_does_not_inherit_the_exclusion_fields() -> None:
    """The correction. An undecidable document is examined, not excluded.

    The first version of this rule required every field the detection read by
    value, exclusions included, on the argument that a copy of the event
    carrying none of them is not a document the spec can read. That is true of
    a second dataset and false of a sparse field, and nothing in a document
    says which it is. Requiring them removed from the denominator exactly the
    documents the detection had discarded, which is how a spec reports a small
    non-zero precondition and a clean result over thousands of dropped
    documents.

    They are counted instead, by the undecided query, so the population the
    precondition describes is the one the run reports on.
    """
    spec = _dual_sourced_spec()
    pre = spec.to_query(since="a", until="b", precondition=True)
    det = spec.to_query(since="a", until="b")
    for field in ("winlog.event_data.SubjectUserName", "winlog.event_data.TargetUserName"):
        assert {"exists": {"field": field}} not in pre["bool"]["filter"], (
            f"the precondition requires {field}, so the documents the detection "
            "discards for lacking it are missing from the count that decides whether "
            "the run was blind"
        )
        assert {"exists": {"field": field}} in det["bool"]["filter"]
        assert {"wildcard": {field: "*$"}} in det["bool"]["must_not"]
        assert {"wildcard": {field: "*$"}} not in pre["bool"]["must_not"], (
            "the precondition inherits which copy of the document to look at, not the "
            "exclusion; it stays the broader question of whether the spec can see"
        )


def test_the_precondition_inherits_the_fields_the_detection_reads_by_value() -> None:
    """Not only the exclusions: any field whose VALUE is the discriminator.

    A detection of ``PreAuthType == 0`` cannot fire on a copy that has no
    PreAuthType, so counting those copies inflates the denominator the same way.
    An ``op: exists`` clause is left out, because there the presence IS the
    detection and inheriting it would collapse the precondition into the
    detection and turn every clean run blind.
    """
    spec = _spec(
        precondition={"all": [{"field": "event.code", "value": "4768"}]},
        detection={
            "all": [
                {"field": "event.code", "value": "4768"},
                {"field": "winlog.event_data.PreAuthType", "value": "0"},
            ]
        },
    )
    pre = spec.to_query(since="a", until="b", precondition=True)
    assert {"exists": {"field": "winlog.event_data.PreAuthType"}} in pre["bool"]["filter"]

    interaction = _spec(
        precondition={"all": [{"field": "event.dataset", "value": "opencanary.events"}]},
        detection={
            "all": [
                {"field": "event.dataset", "value": "opencanary.events"},
                {"field": "source.ip", "op": "exists"},
            ]
        },
    )
    pre = interaction.to_query(since="a", until="b", precondition=True)
    assert {"exists": {"field": "source.ip"}} not in pre["bool"]["filter"], (
        "the decoy's precondition would become its detection, and a grid where the "
        "honeypot only ever booted would read blind instead of clean"
    )


# ---------------------------------------------------------------------------
# The alternatives block, which is the door the presence scope left open
#
# ``required_fields`` scopes the precondition by the ``all`` block, and ``all``
# is a conjunction, so every field it reads by value must be present. ``any`` is
# a disjunction and was left out entirely on the reasoning that requiring all of
# its fields would be the opposite of what the block says — true, and it skipped
# past what the block DOES say, which is that at least one of them must be
# there. A document carrying none of them satisfies no branch, so the detection
# is a decided non-match on it, silently.
#
# That is not a hypothetical shape. The shipped DCSync spec is written exactly
# that way: its ``all`` block is the bare event code 4662 and its whole
# discriminator, the three directory replication rights, is an ``any`` of three
# ``contains`` clauses on winlog.event_data.Properties. On a host running both
# the winlog integration and Elastic Defend the endpoint copy carries the code
# and none of the winlog tree, so it entered the denominator, matched nothing,
# and was reported nowhere.
# ---------------------------------------------------------------------------


ALTERNATIVES_ONLY_DISCRIMINATOR = {
    "precondition": {"all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}]},
    "detection": {
        "all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}],
        # The whole detection lives here, on a field only one copy carries.
        "any": [
            {"field": "winlog.event_data.SubjectUserName", "op": "prefix", "value": "adm-"},
            {"field": "winlog.event_data.SubjectUserName", "op": "prefix", "value": "svc-"},
        ],
    },
}


def test_the_precondition_requires_one_of_the_fields_the_any_block_reads() -> None:
    """The defect. A spec with no exclusion clause at all, whose precision is
    entirely in ``any``, counted both copies of a double-shipped event."""
    spec = _spec(**ALTERNATIVES_ONLY_DISCRIMINATOR)
    assert spec.detection.exclusion_fields() == (), "this spec has no exclusion to lean on"

    pre = spec.to_query(since="a", until="b", precondition=True)
    assert {
        "bool": {
            "should": [{"exists": {"field": "winlog.event_data.SubjectUserName"}}],
            "minimum_should_match": 1,
        }
    } in pre["bool"]["filter"], (
        "the precondition counts a copy of the event that satisfies no branch of "
        "the detection, so the run reports having examined documents it could "
        "never have matched"
    )


def test_the_any_scope_is_at_least_one_field_and_never_all_of_them() -> None:
    """The shape matters as much as the presence. ``any`` names alternatives, so
    requiring every field its branches read would demand a document carry all of
    them at once and delete the population the block is about."""
    spec = _spec(
        precondition={"all": [{"field": "event.code", "value": "4662"}]},
        detection={
            "all": [{"field": "event.code", "value": "4662"}],
            "any": [
                {"field": "winlog.event_data.SubjectUserName", "op": "prefix", "value": "adm-"},
                {"field": "winlog.event_data.TargetUserName", "op": "prefix", "value": "svc-"},
            ],
        },
    )
    filters = spec.to_query(since="a", until="b", precondition=True)["bool"]["filter"]
    for field in ("winlog.event_data.SubjectUserName", "winlog.event_data.TargetUserName"):
        assert {"exists": {"field": field}} not in filters, (
            f"{field} is required outright, so a document carrying only the other "
            "alternative is counted out of its own denominator"
        )
    assert {
        "bool": {
            "should": [
                {"exists": {"field": "winlog.event_data.SubjectUserName"}},
                {"exists": {"field": "winlog.event_data.TargetUserName"}},
            ],
            "minimum_should_match": 1,
        }
    } in filters


def test_an_any_block_of_exists_clauses_does_not_scope_the_precondition() -> None:
    """NEGATIVE CONTROL. ``op: exists`` reads presence rather than a value, so it
    reaches a verdict on a document with no field at all and is never the reason
    one is unexaminable. Scoping on it would collapse the precondition into the
    detection, which is the decoy spec's failure mode: a grid where the honeypot
    only ever booted would read blind instead of clean."""
    spec = _spec(
        precondition={"all": [{"field": "event.dataset", "value": "opencanary.events"}]},
        detection={
            "all": [{"field": "event.dataset", "value": "opencanary.events"}],
            "any": [
                {"field": "source.ip", "op": "exists"},
                {"field": "source.port", "op": "exists"},
            ],
        },
    )
    assert spec.detection.alternative_fields() == ()
    filters = spec.to_query(since="a", until="b", precondition=True)["bool"]["filter"]
    assert not any("should" in f.get("bool", {}) for f in filters)


def test_an_any_field_the_precondition_already_pins_needs_no_second_filter() -> None:
    """NEGATIVE CONTROL. A precondition clause that pins one of the alternatives
    by value satisfies the disjunction on its own. Dropping that field and
    requiring the rest would turn "at least one of these" into "one of the
    others", which is narrower than either block asks."""
    spec = _spec(
        precondition={
            "all": [
                {"field": "event.code", "value": "4662"},
                {"field": "winlog.event_data.SubjectUserName", "op": "prefix", "value": "a"},
            ]
        },
        detection={
            "all": [{"field": "event.code", "value": "4662"}],
            "any": [
                {"field": "winlog.event_data.SubjectUserName", "op": "prefix", "value": "adm-"},
                {"field": "winlog.event_data.TargetUserName", "op": "prefix", "value": "svc-"},
            ],
        },
    )
    filters = spec.to_query(since="a", until="b", precondition=True)["bool"]["filter"]
    assert not any("should" in f.get("bool", {}) for f in filters)


def test_the_matcher_agrees_the_impoverished_copy_is_out_of_the_any_denominator() -> None:
    """The in-memory twin has to move with the compiler, or a fixture passes the
    coverage gate over a population the live query does not have."""
    spec = _spec(**ALTERNATIVES_ONLY_DISCRIMINATOR)

    assert precondition_matches(spec, WINLOG_HUMAN), (
        "the copy that carries the discriminator is exactly what the spec examines"
    )
    assert not precondition_matches(spec, ENDPOINT_COPY), (
        "the endpoint copy satisfies no branch of the any block, so it is a decided "
        "non-match the denominator must not claim to have examined"
    )


def test_the_matcher_keeps_a_document_carrying_one_of_several_alternatives() -> None:
    """NEGATIVE CONTROL for the matcher. One alternative present is enough; a
    rule that demanded all of them would empty the denominator instead."""
    spec = _spec(
        precondition={"all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}]},
        detection={
            "all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}],
            "any": [
                {"field": "winlog.event_data.SubjectUserName", "op": "prefix", "value": "adm-"},
                {"field": "winlog.event_data.TargetUserName", "op": "prefix", "value": "svc-"},
            ],
        },
    )
    only_one = {
        "event.code": DUAL_SOURCED_CODE,
        "event.dataset": "system.security",
        "winlog.event_data.TargetUserName": "svc_reporting",
    }
    assert precondition_matches(spec, only_one)


def test_the_matcher_and_the_compiler_agree_on_the_precondition_scope() -> None:
    """``precondition_matches`` is the in-memory half of the same scope."""
    spec = _dual_sourced_spec()
    assert precondition_matches(spec, WINLOG_HUMAN)
    assert precondition_matches(spec, WINLOG_MACHINE_ACCOUNT), (
        "a machine account is in the population the spec examined; the exclusion "
        "removes it from the detection, not from the denominator"
    )
    assert precondition_matches(spec, ENDPOINT_COPY), (
        "the endpoint copy is examined and reported undecidable, so leaving it out "
        "of the denominator hides the documents the run could not decide"
    )


def test_a_grid_carrying_only_the_impoverished_copy_cannot_report_clean() -> None:
    """What stops the presence rule from becoming a silent miss.

    Requiring the field narrows the detection, and a narrowing that nothing
    reports is how an all-clear gets invented. The first answer was to narrow
    the precondition the same way, so a grid holding only the impoverished copy
    read as blind. It only fired on TOTAL absence: at one document with the
    field the precondition is non-zero, the run is not blind, and every other
    document is gone.

    The replacement does not depend on the count. Every document the detection
    discards for a missing field is undecided, one is enough, and the run says
    so whether there are 5,240 of them or one.
    """
    spec = _dual_sourced_spec()
    tree = spec.detection

    assert precondition_matches(spec, ENDPOINT_COPY)
    assert not detection_matches(tree, ENDPOINT_COPY)
    assert detection_undecided(tree, ENDPOINT_COPY), (
        "the copy is dropped from the detection and counted nowhere, which is the "
        "all-clear this rule exists to prevent"
    )

    # The case the old net could not see: one readable document alongside the
    # impoverished ones is enough to make the precondition non-zero.
    assert precondition_matches(spec, WINLOG_HUMAN)
    assert detection_matches(tree, WINLOG_HUMAN)
    assert not detection_undecided(tree, WINLOG_HUMAN)


def _matched_before_the_presence_rule(tree: Detection, doc: dict[str, object]) -> bool:
    """The clause tree read as it was before 2026-09-05: no presence requirement.

    A ``must_not`` over an absent field excluded nothing, so this is every
    document the detection USED to return. It is the yardstick for the one
    property that matters: none of them may now disappear without being
    counted.
    """
    if not all(clause_matches(c, doc) for c in tree.all):
        return False
    if tree.any and not any(clause_matches(c, doc) for c in tree.any):
        return False
    return not any(clause_matches(c, doc) for c in tree.none)


def test_no_document_the_detection_used_to_return_is_dropped_without_a_count() -> None:
    """The invariant, stated against the behaviour the presence rule replaced.

    Every document the pre-2026-09-05 tree returned is now either matched or
    undecided, and never both. That is what makes the presence filter a
    narrowing the run reports rather than a deletion it hides, and it is the
    property the live-grid arithmetic shows: over 2026-09-05 the reconstructed
    4624 spec returned 5,240 documents before the rule and 0 + 5,240 after.
    """
    docs = [
        ENDPOINT_COPY,
        WINLOG_MACHINE_ACCOUNT,
        WINLOG_HUMAN,
        # One exclusion field present, the other not.
        {k: v for k, v in WINLOG_HUMAN.items() if k != "winlog.event_data.TargetUserName"},
        {
            k: v
            for k, v in WINLOG_MACHINE_ACCOUNT.items()
            if k != "winlog.event_data.SubjectUserName"
        },
    ]
    tree = _dual_sourced_spec().detection
    for doc in docs:
        matched = detection_matches(tree, doc)
        undecided = detection_undecided(tree, doc)
        assert not (matched and undecided), doc
        if _matched_before_the_presence_rule(tree, doc):
            assert matched or undecided, (
                f"{doc} was returned before the presence rule and is now neither "
                "matched nor counted, which is the silent deletion"
            )


def test_the_undecided_query_is_the_documents_the_presence_filter_removes() -> None:
    """The compiled half of the same partition, clause by clause.

    Detection and undecided are the same tree over the same window with the
    same exclusions; they differ only in requiring the exclusion fields present
    or requiring one of them absent. Anything else diverging between the two
    would put documents in neither.
    """
    spec = _dual_sourced_spec()
    det = spec.to_query(since="a", until="b")["bool"]
    und = spec.to_query(since="a", until="b", undecided=True)["bool"]
    fields = ("winlog.event_data.SubjectUserName", "winlog.event_data.TargetUserName")

    assert det["must_not"] == und["must_not"], (
        "an exclusion dropped from one side would let documents through it in the "
        "other, and the two counts would stop adding up"
    )
    presence = [{"exists": {"field": f}} for f in fields]
    assert [f for f in det["filter"] if f not in presence] == [
        f for f in und["filter"] if "should" not in f.get("bool", {})
    ]
    assert {
        "bool": {
            "should": [{"bool": {"must_not": [{"exists": {"field": f}}]}} for f in fields],
            "minimum_should_match": 1,
        }
    } in und["filter"], "one unevaluated exclusion is enough; it is not an AND"


def test_an_undecided_query_is_refused_where_nothing_can_be_undecided() -> None:
    """A spec with no absence to report would count its own matches twice."""
    spec = _spec(detection={"all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}]})
    with pytest.raises(ValueError, match="no exclusion that can go unevaluated"):
        spec.to_query(since="a", until="b", undecided=True)


def test_the_two_questions_cannot_be_compiled_into_one_query() -> None:
    with pytest.raises(ValueError, match="different questions"):
        _dual_sourced_spec().to_query(since="a", until="b", precondition=True, undecided=True)


# ---------------------------------------------------------------------------
# Declaring what an absent field means
# ---------------------------------------------------------------------------


def test_absent_match_says_the_exclusion_does_not_apply_and_the_document_matches() -> None:
    """The sparse-field case, stated by the author instead of guessed at.

    Windows writes no ``SubjectUserName`` on a network logon: the subject there
    is the null SID. Measured on the development range over 2026-09-05, 5,240 of
    the 5,422 documents carrying event code 4624 and a LogonType had no
    SubjectUserName, and every one of the 5,240 was a network logon. A null subject
    is definitively not a machine account, so the right answer for that spec is
    that the exclusion does not apply and the document matches.
    """
    tree = Detection(
        all=[Clause(field="event.code", value=DUAL_SOURCED_CODE)],
        none=[
            Clause(
                field="winlog.event_data.SubjectUserName",
                op="wildcard",
                value="*$",
                absent="match",
            )
        ],
    )
    assert tree.exclusion_fields() == (), "nothing is undecided once absence is declared"
    assert tree.to_es()["bool"]["filter"] == [{"term": {"event.code": DUAL_SOURCED_CODE}}]
    assert detection_matches(tree, ENDPOINT_COPY)
    assert not detection_undecided(tree, ENDPOINT_COPY)
    assert not detection_matches(tree, WINLOG_MACHINE_ACCOUNT), (
        "the exclusion still removes the accounts it can read"
    )


def test_absent_is_refused_where_it_would_be_parsed_and_ignored() -> None:
    """A positive clause cannot match a missing field in either engine."""
    for block in ("all", "any"):
        with pytest.raises(ValidationError, match="only means something on a 'none'"):
            Detection.model_validate(
                {
                    "all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}],
                    block: [
                        {
                            "field": "winlog.event_data.SubjectUserName",
                            "op": "wildcard",
                            "value": "svc*",
                            "absent": "match",
                        }
                    ],
                }
            )


def test_absent_is_refused_on_a_none_clause_that_already_demands_absence() -> None:
    with pytest.raises(ValidationError, match="already says the field must be absent"):
        Detection.model_validate(
            {
                "all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}],
                "none": [
                    {
                        "field": "winlog.event_data.SubjectUserName",
                        "op": "exists",
                        "absent": "match",
                    }
                ],
            }
        )


def test_two_clauses_on_one_field_may_not_disagree_about_absence() -> None:
    """Whichever the compiler picked would silently be the other one's opposite."""
    with pytest.raises(ValidationError, match="disagree about what an absent value means"):
        Detection.model_validate(
            {
                "all": [{"field": "event.code", "value": DUAL_SOURCED_CODE}],
                "none": [
                    {
                        "field": "winlog.event_data.ServiceName",
                        "op": "wildcard",
                        "value": "*$",
                    },
                    {
                        "field": "winlog.event_data.ServiceName",
                        "value": "krbtgt",
                        "absent": "match",
                    },
                ],
            }
        )


# ---------------------------------------------------------------------------
# The case the presence rule broke: a field that is sparse inside its own
# dataset. Reconstructed from the live development range, counted 2026-09-06
# over 2026-09-05T00:00:00Z to 2026-09-06T00:00:00Z, one query per row:
#
#   before the presence rule   precondition 10844   detection 5240
#   with it                    precondition   182   detection    0   -> CLEAN
#   with this change           precondition  5422   detection    0   undecided 5240
#
# 182 is greater than zero, so the middle row was not blind. It reported a
# clean grid while deleting 5,240 documents that matched its positive clauses.
# ---------------------------------------------------------------------------

NETWORK_LOGON_CODE = "4624"

# A network logon. Windows populates no SubjectUserName at all here, because the
# subject is the null SID; the same document in the endpoint copy carries
# neither field.
NETWORK_LOGON = {
    "event.code": NETWORK_LOGON_CODE,
    "event.dataset": "system.security",
    "winlog.event_data.LogonType": "3",
    "winlog.event_data.TargetUserName": "j.hollis",
}
INTERACTIVE_MACHINE_LOGON = {
    "event.code": NETWORK_LOGON_CODE,
    "event.dataset": "system.security",
    "winlog.event_data.LogonType": "3",
    "winlog.event_data.SubjectUserName": "SYNTH-WS07$",
    "winlog.event_data.TargetUserName": "SYNTH-WS07$",
}


def _sparse_field_spec() -> HuntSpec:
    """The reconstruction: precision from an exclusion on a field Windows omits."""
    return _spec(
        scope_field="winlog.event_data.TargetUserName",
        scope_kind="user",
        precondition={"all": [{"field": "event.code", "value": NETWORK_LOGON_CODE}]},
        detection={
            "all": [
                {"field": "event.code", "value": NETWORK_LOGON_CODE},
                {"field": "winlog.event_data.LogonType", "value": "3"},
            ],
            "none": [
                {"field": "winlog.event_data.SubjectUserName", "op": "wildcard", "value": "*$"}
            ],
        },
    )


def test_a_field_sparse_inside_its_own_dataset_is_reported_not_deleted() -> None:
    """The negative control on the fix that shipped on 2026-09-05.

    This document is not a second copy of the event. It is in the dataset the
    spec is written against, it carries every field the detection reads by
    value, and it satisfies both positive clauses. Windows simply does not
    populate the field the exclusion reads for this kind of logon.

    The presence rule deleted it and the precondition, carrying the same rule,
    did not notice. The requirement is that it is either matched or reported,
    never dropped in silence.
    """
    spec = _sparse_field_spec()
    tree = spec.detection

    assert all(clause_matches(c, NETWORK_LOGON) for c in tree.all), (
        "the document has to satisfy the positive clauses or it proves nothing"
    )
    assert not field_is_present(NETWORK_LOGON, "winlog.event_data.SubjectUserName")

    assert not detection_matches(tree, NETWORK_LOGON)
    assert detection_undecided(tree, NETWORK_LOGON), (
        "5,240 documents on the live grid took this path and were counted nowhere"
    )
    assert precondition_matches(spec, NETWORK_LOGON), (
        "dropping it from the denominator too is what let the run read as clean"
    )


def test_the_sparse_field_case_and_the_duplicate_copy_case_compile_the_same_way() -> None:
    """One rule, and the reason a per-clause declaration is the only way out.

    Both documents satisfy the positive clauses and lack the field an exclusion
    reads. Nothing in either says which of the two situations it is, so the
    compiler treats them identically and reports both. The author resolves it
    with ``absent: match`` where they know, and by pinning ``event.dataset``
    where they want one copy.
    """
    sparse = _sparse_field_spec().detection
    duplicated = _dual_sourced_spec().detection
    assert detection_undecided(sparse, NETWORK_LOGON)
    assert detection_undecided(duplicated, ENDPOINT_COPY)


def test_the_machine_account_exclusion_still_removes_machine_accounts() -> None:
    """The other negative control: the 74 false positives have not come back.

    On 2026-09-05 a spec on event code 4648 returned 78 candidates, 74 of them
    the machine accounts its exclusions exist to remove, because the exclusion
    was a no-op on the copy that carries no ``winlog.event_data``. Nothing in
    this change relaxes that. Both the copy and the machine account are kept out
    of the candidates, in both engines.
    """
    for spec, machine, impoverished in (
        (_dual_sourced_spec(), WINLOG_MACHINE_ACCOUNT, ENDPOINT_COPY),
        (_sparse_field_spec(), INTERACTIVE_MACHINE_LOGON, NETWORK_LOGON),
    ):
        tree = spec.detection
        assert not detection_matches(tree, machine)
        assert not detection_undecided(tree, machine), (
            "a machine account the exclusion CAN read is decided, not undecided"
        )
        assert not detection_matches(tree, impoverished)

        det = spec.to_query(since="a", until="b")["bool"]
        for field in tree.exclusion_fields():
            assert {"exists": {"field": field}} in det["filter"]
        und = spec.to_query(since="a", until="b", undecided=True)["bool"]
        assert und["must_not"] == det["must_not"], (
            "the undecided query drops the presence filter and nothing else, so it "
            "cannot become a back door for the documents the exclusions remove"
        )


def test_asking_for_a_precondition_that_does_not_exist_is_an_error_in_memory_too() -> None:
    with pytest.raises(ValueError, match="no precondition"):
        precondition_matches(_spec(), WINLOG_HUMAN)


def test_asking_a_profile_spec_about_a_document_is_an_error() -> None:
    """A profile spec has no detection block and no document to read.

    It is answered from a stored baseline. Returning False for it would count
    the whole population as examined and report a false all-clear, which is
    the reverse of the reading the precondition exists to give.
    """
    prior = HuntSpec.model_validate(
        {
            "id": "test-prior",
            "title": "t",
            "evaluator": "profile",
            "profile": {"dimension": "served_ports", "test": "novel_for", "roles": ["server"]},
            "precondition": {"all": [{"field": "event.code", "value": "4624"}]},
        }
    )
    assert prior.detection is None
    with pytest.raises(ValueError, match="no detection"):
        precondition_matches(prior, WINLOG_HUMAN)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_the_id_must_be_a_slug() -> None:
    with pytest.raises(ValidationError, match="kebab-case"):
        _spec(id="Not A Slug")


def test_the_id_must_match_the_filename(tmp_path: Path) -> None:
    """A finding's spec_id names the file that produced it, with no lookup."""
    p = tmp_path / "wrong-name.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "id": "right-name",
                "title": "t",
                "detection": {"all": [{"field": "event.code", "value": "1"}]},
            }
        )
    )
    with pytest.raises(ValueError, match="does not match the filename"):
        load_spec(p)


def test_yaml_that_does_not_parse_is_a_value_error_with_the_place(tmp_path: Path) -> None:
    """The analytics route answered 500 on a typo in an analyst's YAML.

    yaml.YAMLError is not a ValueError, so the route's own handler never saw
    it. The parser knows the line and the column, and the analyst needs both.
    """
    from soc_ai.hunting.spec import parse_spec

    with pytest.raises(ValueError) as caught:
        parse_spec("id: local-x\ntitle: [unclosed\n")
    text = str(caught.value)
    assert text.startswith("the YAML does not parse: ")
    assert "line 3" in text and "column" in text
    assert not isinstance(caught.value, yaml.YAMLError)


def test_an_invalid_spec_fails_the_catalog_rather_than_being_skipped(tmp_path: Path) -> None:
    """A catalog that quietly drops a spec reports a clean sweep it never ran."""
    (tmp_path / "good.yaml").write_text(
        yaml.safe_dump(
            {
                "id": "good",
                "title": "t",
                "detection": {"all": [{"field": "event.code", "value": "1"}]},
            }
        )
    )
    (tmp_path / "bad.yaml").write_text(yaml.safe_dump({"id": "bad", "title": "t", "detection": {}}))
    with pytest.raises(ValidationError):
        load_catalog(tmp_path)


# ---------------------------------------------------------------------------
# The shipped catalog
# ---------------------------------------------------------------------------


def test_the_shipped_catalog_loads() -> None:
    catalog = load_catalog(CATALOG)
    # Pinned per evaluator rather than as one set, so that adding a prior does
    # not quietly edit the list of match specs, and the reverse.
    assert {k for k, v in catalog.items() if v.evaluator == "match"} == {
        "identity-4662-dcsync-nonmachine",
        "identity-4768-preauth-disabled",
        "identity-4769-rc4-service-ticket",
        "decoy-opencanary-interaction",
    }
    assert {k for k, v in catalog.items() if v.evaluator == "profile"} == {
        "prior-audit-policy-changed-on-dc",
        "prior-dc-originates-rdp-or-smb-to-workstation",
        "prior-defender-adjudication-on-server",
        "prior-hypervisor-novel-served-port",
        "prior-privileged-group-membership-changed",
        "prior-server-internet-nonweb-novel-port",
        "prior-workstation-account-first-logon-to-dc",
        "prior-workstation-remote-execution-tooling",
        "prior-workstation-to-network-device-novel-port",
        # The unscoped clause specs: they apply to every role and carry the
        # kinds a chain needs besides novelty.
        "profile-activity-outside-measured-hours",
        "profile-connection-rate-collapsed",
        "profile-connection-rate-spiked",
    }


def test_every_shipped_spec_has_a_precondition() -> None:
    """Zero findings from a blind spec is a coverage gap, not an all-clear.

    Without a precondition the two are indistinguishable, and reporting the
    first as the second is the false all-clear this project ranks above any
    loud error.
    """
    for spec in load_catalog(CATALOG).values():
        if spec.evaluator == "profile":
            # A prior answers from a stored baseline, not from a query, so it
            # has no precondition to run. It tells blind from clean through the
            # profile's own coverage column instead, which carries the same
            # distinction — see tests/test_hunting_priors.py.
            continue
        assert spec.precondition is not None, f"{spec.id} cannot tell blind from clean"


def test_every_shipped_spec_documents_its_false_positives_and_attack_mapping() -> None:
    for spec in load_catalog(CATALOG).values():
        assert spec.false_positives, f"{spec.id} claims no false positives, which is never true"
        assert spec.attack, f"{spec.id} has no ATT&CK mapping"
        assert spec.references, f"{spec.id} cites nothing"


def test_the_dcsync_spec_excludes_machine_accounts() -> None:
    """The exclusion IS the detection.

    Measured on the development range on 2026-09-04, with the clause then
    matching only DS-Replication-Get-Changes: 38 documents carried the right
    and 36 were the DC's own machine account replicating legitimately. Without
    this clause the spec is 95% noise; with it, precision is total. The widened
    clause has not been re-counted, and its benign population is the same
    machine-account replication this clause removes.
    """
    spec = load_catalog(CATALOG)["identity-4662-dcsync-nonmachine"]
    q = spec.to_query(since="a", until="b")
    assert {"wildcard": {"winlog.event_data.SubjectUserName": "*$"}} in q["bool"]["must_not"]


def test_the_dcsync_spec_compiles_the_replication_rights_as_any_of_three() -> None:
    """One of three rights, not the first right only.

    As shipped in 1.5.0 the clause was a single ``contains`` on
    DS-Replication-Get-Changes. The DC writes one document per right it checks,
    and the two ``1131f6a*`` GUIDs differ in their last character, so a document
    carrying only Get-Changes-All, the right that actually releases secrets,
    could never match. The rights now compile to a ``should`` block with a
    floor of one; ``event.code`` stays a hard filter and no ``Properties``
    clause remains in the filter to AND one right back in.
    """
    spec = load_catalog(CATALOG)["identity-4662-dcsync-nonmachine"]
    q = spec.to_query(since="a", until="b")
    assert {"term": {"event.code": "4662"}} in q["bool"]["filter"]
    assert q["bool"]["minimum_should_match"] == 1
    assert q["bool"]["should"] == [
        {"wildcard": {"winlog.event_data.Properties": f"*{right}*"}} for right in REPLICATION_RIGHTS
    ]
    assert not any("winlog.event_data.Properties" in str(c) for c in q["bool"]["filter"])


@pytest.mark.parametrize("right", REPLICATION_RIGHTS)
def test_the_dcsync_spec_matches_a_document_carrying_one_right_alone(right: str) -> None:
    """Each right on its own is the act; the exclusion still holds across all of them."""
    spec = load_catalog(CATALOG)["identity-4662-dcsync-nonmachine"]
    assert detection_matches(spec.detection, _4662("svc-replicator", right))
    assert not detection_matches(spec.detection, _4662("SYNTH-DC02$", right)), (
        "a machine account carrying this right is a domain controller doing its job"
    )


def test_the_narrower_clause_missed_get_changes_all_on_its_own() -> None:
    """Negative control on the fix itself.

    Rebuild the detection as 1.5.0 shipped it and show that a document carrying
    only Get-Changes-All does not match it, while one carrying Get-Changes
    does. Without this the parametrised test above could pass because
    ``contains`` happened to match a shared prefix, rather than because the
    clause was widened.
    """
    shipped = Detection(
        all=[
            Clause(field="event.code", value="4662"),
            Clause(
                field="winlog.event_data.Properties",
                op="contains",
                value=DS_REPLICATION_GET_CHANGES,
            ),
        ],
        none=[Clause(field="winlog.event_data.SubjectUserName", op="wildcard", value="*$")],
    )
    assert not detection_matches(shipped, _4662("svc-replicator", DS_REPLICATION_GET_CHANGES_ALL))
    assert detection_matches(shipped, _4662("svc-replicator", DS_REPLICATION_GET_CHANGES))


def test_the_dcsync_spec_leaves_out_the_right_that_reads_nothing() -> None:
    """DS-Replication-Synchronize is not in the spec, on purpose.

    Sigma's non-machine replication rule matches it. The right lets a caller
    ask a DC to replicate now, which is what ``repadmin /syncall`` does, and it
    reads no directory data itself. An administrator exercises it under a human
    account, which the machine-account exclusion cannot separate from an
    attacker, so matching it would import a false-positive class the spec does
    not have today in exchange for no secret it could catch.
    """
    spec = load_catalog(CATALOG)["identity-4662-dcsync-nonmachine"]
    assert not detection_matches(
        spec.detection, _4662("svc-replicator", DS_REPLICATION_SYNCHRONIZE)
    )
    assert not detection_matches(spec.detection, _4662("svc-replicator")), (
        "a 4662 carrying no replication right at all is not this detection"
    )


def test_each_shipped_spec_scopes_to_the_actor_not_the_document() -> None:
    """One condition is one candidate, not one per document.

    The DCSync run produced two documents for a single act by a single account;
    grouping by the principal is what stops that being two findings.
    """
    catalog = load_catalog(CATALOG)
    assert catalog["identity-4662-dcsync-nonmachine"].scope_field == (
        "winlog.event_data.SubjectUserName"
    )
    assert catalog["identity-4768-preauth-disabled"].scope_field == (
        "winlog.event_data.TargetUserName"
    )
    assert catalog["identity-4769-rc4-service-ticket"].scope_field == (
        "winlog.event_data.ServiceName"
    )
    # The decoy's actor is whoever touched it, not an account.
    assert catalog["decoy-opencanary-interaction"].scope_field == "source.ip"
    assert catalog["decoy-opencanary-interaction"].scope_kind == "ip"


def test_the_decoy_spec_requires_an_interaction_not_merely_a_document() -> None:
    """OpenCanary writes a boot record every time the service starts.

    On the development range 8 of 14 documents in the dataset are exactly that,
    so a spec matching the dataset alone would have been 57% boot messages while
    advertising perfect precision. The interaction test is the presence of a
    source address, which the boot record does not carry: 6 documents have one,
    8 do not, and the overlap with logtype 1001 is zero.
    """
    spec = load_catalog(CATALOG)["decoy-opencanary-interaction"]
    q = spec.to_query(since="a", until="b")
    assert {"exists": {"field": "source.ip"}} in q["bool"]["filter"], (
        "without this the spec fires on the honeypot starting up"
    )


# Every ``exists`` clause in each shipped spec's compiled filter, detection then
# precondition, plus the fields its undecided query asks about. Written out so a
# change to any of them is a reviewed edit rather than a side effect. The decoy's
# ``source.ip`` entry is authored in the spec; the rest are derived.
#
# Counted against the live development range on 2026-09-06 over the whole
# retention, one query per column, to show the compiled change moves no number
# on the shipped catalog:
#
#   identity-4662-dcsync-nonmachine    precondition 86    detection 3  undecided 0
#   identity-4769-rc4-service-ticket   precondition 5393  detection 1  undecided 0
#
# Both preconditions read the same with and without the exclusion field, because
# every 4662 and 4769 document on that grid carries the field its exclusions
# read. That is why the defect this table records was latent rather than live.
SHIPPED_PRESENCE: dict[str, tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = {
    "identity-4662-dcsync-nonmachine": (
        ("winlog.event_data.SubjectUserName",),
        (),
        ("winlog.event_data.SubjectUserName",),
    ),
    "identity-4768-preauth-disabled": ((), ("winlog.event_data.PreAuthType",), ()),
    "identity-4769-rc4-service-ticket": (
        ("winlog.event_data.ServiceName",),
        ("winlog.event_data.TicketEncryptionType",),
        ("winlog.event_data.ServiceName",),
    ),
    "decoy-opencanary-interaction": (("source.ip",), (), ()),
}


@pytest.mark.parametrize("spec_id", sorted(SHIPPED_PRESENCE))
def test_what_the_absent_field_rule_changed_for_each_shipped_spec(spec_id: str) -> None:
    """Detection content, so it is pinned rather than described.

    None of the four was exposed to the false-positive half of the defect: each
    reads at least one ``winlog.event_data`` field in a POSITIVE clause, and a
    positive clause cannot match a document that lacks the field. Nor is any of
    them exposed to the silent-deletion half today, since on the grid they were
    written against the fields their exclusions read are present on every
    document their positive clauses match.

    What moved is the denominator, twice. The presence rule first narrowed it to
    one copy of a double-shipped event, which was right, and then narrowed it
    again by the exclusion fields, which is the deletion this change undoes. The
    two specs with exclusions have those fields back in the population and their
    absence reported instead.
    """
    spec = load_catalog(CATALOG)[spec_id]
    detection_presence, precondition_presence, undecidable = SHIPPED_PRESENCE[spec_id]

    det = spec.to_query(since="a", until="b")["bool"]["filter"]
    pre = spec.to_query(since="a", until="b", precondition=True)["bool"]["filter"]
    assert [c for c in det if "exists" in c] == [
        {"exists": {"field": f}} for f in detection_presence
    ]
    assert [c for c in pre if "exists" in c] == [
        {"exists": {"field": f}} for f in precondition_presence
    ]
    assert spec.detection.exclusion_fields() == undecidable


# ---------------------------------------------------------------------------
# A precondition that looks back further than the run
# ---------------------------------------------------------------------------


def _decoy_shaped(**over) -> HuntSpec:
    """A spec whose sensor reports on an event rather than on a schedule."""
    base = {
        "precondition": {"all": [{"field": "event.dataset", "value": "opencanary.events"}]},
        "detection": {
            "all": [
                {"field": "event.dataset", "value": "opencanary.events"},
                {"field": "source.ip", "op": "exists"},
            ]
        },
    }
    return _spec(**{**base, **over})


def test_a_precondition_can_look_back_further_than_the_run_window() -> None:
    """A sensor with no heartbeat cannot be asked "did you report in the last hour".

    OpenCanary writes a record when its service starts and then nothing at all
    until something touches the honeypot. Over one sweep window its precondition
    measures "was the decoy touched recently", not "is the decoy reporting", so
    a quiet day reports a coverage gap on a healthy decoy and trains an analyst
    to ignore the one marker that exists to be believed.
    """
    spec = _decoy_shaped(precondition_lookback_minutes=129_600)
    pre = spec.to_query(since="now-61m", until="now", precondition=True)
    det = spec.to_query(since="now-61m", until="now")

    assert {"range": {"@timestamp": {"gte": "now-61m-129600m", "lte": "now"}}} in pre["bool"][
        "filter"
    ]
    assert {"range": {"@timestamp": {"gte": "now-61m", "lte": "now"}}} in det["bool"]["filter"], (
        "only the precondition widens; a detection over ninety days would report "
        "ninety days of findings on every sweep"
    )


def test_the_look_back_is_per_spec_and_defaults_to_the_run_window() -> None:
    """Zero is the default, so a spec that says nothing compiles as it always did.

    It is per spec because the opposite case is real and shipped: a domain
    controller with Directory Service Access auditing on writes 4662s
    continuously, so silence in the window there genuinely means the auditing
    was switched off. Widening every precondition would trade a false gap for a
    false all-clear.
    """
    spec = _decoy_shaped()
    assert spec.precondition_lookback_minutes == 0
    pre = spec.to_query(since="now-61m", until="now", precondition=True)
    det = spec.to_query(since="now-61m", until="now")
    assert [f for f in pre["bool"]["filter"] if "range" in f] == [
        f for f in det["bool"]["filter"] if "range" in f
    ]


def test_the_look_back_shifts_the_window_start_so_it_can_only_widen() -> None:
    """Computed from the run's start, not from its end, which could narrow it.

    A retro sweep over three days with a short look-back would otherwise ask the
    precondition about less ground than the detection covers, and a spec that
    matched documents its own precondition could not see would report blind over
    evidence it was holding.
    """
    spec = _decoy_shaped(precondition_lookback_minutes=5)
    pre = spec.to_query(since="now-4320m", until="now", precondition=True)
    assert {"range": {"@timestamp": {"gte": "now-4320m-5m", "lte": "now"}}} in pre["bool"]["filter"]


def test_an_absolute_window_start_takes_the_date_math_separator() -> None:
    """``now`` chains directly; a literal timestamp needs ``||`` before the math.

    Both reach this code: the sweep passes ``now-61m`` and ``soc-ai spec-sweep``
    passes whatever ``--since`` was given, which it documents as either form.
    """
    spec = _decoy_shaped(precondition_lookback_minutes=1440)
    absolute = spec.to_query(
        since="2026-09-03T00:00:00Z", until="2026-09-06T00:00:00Z", precondition=True
    )
    assert {
        "range": {
            "@timestamp": {"gte": "2026-09-03T00:00:00Z||-1440m", "lte": "2026-09-06T00:00:00Z"}
        }
    } in absolute["bool"]["filter"]

    already_math = spec.to_query(
        since="2026-09-03T00:00:00Z||/d", until="2026-09-06T00:00:00Z", precondition=True
    )
    window = next(f for f in already_math["bool"]["filter"] if "range" in f)
    assert window["range"]["@timestamp"]["gte"] == "2026-09-03T00:00:00Z||/d-1440m", (
        "a second separator would make the expression unparseable to Elasticsearch"
    )


def test_the_look_back_is_bounded() -> None:
    """Past a year the precondition asks whether the sensor was ever installed.

    No grid this runs against keeps a year of indices to answer with, and the
    query is an exact count over whatever window it is given.
    """
    with pytest.raises(ValidationError, match="precondition_lookback_minutes"):
        _decoy_shaped(precondition_lookback_minutes=-1)
    with pytest.raises(ValidationError, match="precondition_lookback_minutes"):
        _decoy_shaped(precondition_lookback_minutes=MAX_PRECONDITION_LOOKBACK_MINUTES + 1)
    at_ceiling = _decoy_shaped(precondition_lookback_minutes=MAX_PRECONDITION_LOOKBACK_MINUTES)
    assert at_ceiling.precondition_lookback_minutes == MAX_PRECONDITION_LOOKBACK_MINUTES


def test_a_look_back_with_no_precondition_to_widen_is_refused() -> None:
    """Otherwise the key is parsed, validated and silently ignored."""
    with pytest.raises(ValidationError, match="no precondition"):
        _spec(precondition_lookback_minutes=1440)


def test_only_the_decoy_looks_back_past_the_run_window() -> None:
    """The catalog's own acceptance test is why this is not a blanket widening.

    Turning Directory Service Access auditing off on a domain controller must
    make the DCSync spec report blind rather than clean. That DC reports
    continuously, so silence in the window is the gap. The honeypot has no
    heartbeat, so silence in the window is the good outcome.
    """
    catalog = load_catalog(CATALOG)
    assert catalog["decoy-opencanary-interaction"].precondition_lookback_minutes == 90 * 24 * 60
    for spec_id in (
        "identity-4662-dcsync-nonmachine",
        "identity-4768-preauth-disabled",
        "identity-4769-rc4-service-ticket",
    ):
        assert catalog[spec_id].precondition_lookback_minutes == 0, (
            f"{spec_id} reports continuously, so silence in the window is a real gap"
        )


# ---------------------------------------------------------------------------
# no_benign_baseline — the doctrine a triage gate reads off the catalog
# ---------------------------------------------------------------------------


def test_no_benign_baseline_defaults_false() -> None:
    """A spec that says nothing has a benign population, like everything did before."""
    spec = HuntSpec(
        id="x", title="x", detection=Detection(all=[Clause(field="event.code", value="1")])
    )
    assert spec.no_benign_baseline is False


def test_exactly_the_specs_whose_exceptions_are_identities_declare_no_baseline() -> None:
    """Which shipped specs carry the flag, and why the third does not.

    DCSync's and AS-REP's false-positive lists are identity exceptions — the
    sync appliance's account, the one legacy account configured without
    pre-authentication. A volume argument cannot clear either: an attacker's
    persistent DCSync is exactly "this account replicates every hour", and a
    pre-auth-disabled account appearing at every logon is the exposure, not a
    baseline. Kerberoast's list names a real benign population — Windows 7 and
    2008 R2 clients and default-encryption accounts negotiate RC4 routinely —
    so a rate CAN clear it, and it keeps its baseline. Pinned so a spec added
    later has to decide, out loud, which kind it is.
    """
    catalog = load_catalog(CATALOG)
    flagged = sorted(
        s.id for s in catalog.values() if s.no_benign_baseline and s.evaluator == "match"
    )
    assert flagged == ["identity-4662-dcsync-nonmachine", "identity-4768-preauth-disabled"]

    # The priors make the same declaration for the same reason, and are pinned
    # separately so adding one to either list stays a deliberate decision.
    flagged_priors = sorted(
        s.id for s in catalog.values() if s.no_benign_baseline and s.evaluator == "profile"
    )
    assert flagged_priors == [
        "prior-audit-policy-changed-on-dc",
        "prior-defender-adjudication-on-server",
        "prior-privileged-group-membership-changed",
    ]


# ---------------------------------------------------------------------------
# The `profile` evaluator
#
# A prior reads an entity's profile; it has no document pattern to match. The
# first cut required a detection block anyway, so every prior carried a dummy
# clause that then had to be excluded from every query path — and a spec
# carrying both was ambiguous about which one decided, an ambiguity the query
# builder and the evaluator resolved differently.
# ---------------------------------------------------------------------------


def test_a_profile_spec_needs_no_detection_block() -> None:
    spec = HuntSpec.model_validate(
        {
            "id": "prior-example",
            "title": "Example prior",
            "evaluator": "profile",
            "profile": {
                "dimension": "served_ports",
                "test": "novel_for",
                "roles": ["network_device"],
            },
            "scope_field": "host.name",
        }
    )
    assert spec.evaluator == "profile"
    assert spec.detection is None
    assert spec.profile is not None
    assert spec.profile.dimension == "served_ports"


def test_a_match_spec_still_requires_a_detection_block() -> None:
    with pytest.raises(ValidationError):
        HuntSpec.model_validate(
            {"id": "x", "title": "x", "evaluator": "match", "scope_field": "host.name"}
        )


def test_a_profile_spec_rejects_a_detection_block() -> None:
    with pytest.raises(ValidationError):
        HuntSpec.model_validate(
            {
                "id": "x",
                "title": "x",
                "evaluator": "profile",
                "profile": {"dimension": "served_ports", "test": "novel_for"},
                "detection": {"all": [{"field": "event.code", "value": "1"}]},
            }
        )


def test_a_match_spec_rejects_a_profile_block() -> None:
    # Same reasoning in the other direction: a profile block on a match spec is
    # parsed, validated, and then silently ignored by the query path.
    with pytest.raises(ValidationError):
        HuntSpec.model_validate(
            {
                "id": "x",
                "title": "x",
                "evaluator": "match",
                "detection": {"all": [{"field": "event.code", "value": "1"}]},
                "profile": {"dimension": "served_ports", "test": "novel_for"},
            }
        )


def test_a_profile_spec_without_a_profile_block_is_refused() -> None:
    with pytest.raises(ValidationError):
        HuntSpec.model_validate(
            {"id": "x", "title": "x", "evaluator": "profile", "scope_field": "host.name"}
        )


def test_the_role_confidence_gate_defaults_high_not_permissive() -> None:
    # The design inverts this gate: a prior on a low-confidence role is BLIND,
    # never weakly firing. A permissive default would quietly restore the
    # behaviour the inversion exists to remove.
    spec = HuntSpec.model_validate(
        {
            "id": "prior-example",
            "title": "Example prior",
            "evaluator": "profile",
            "profile": {"dimension": "served_ports", "test": "novel_for"},
        }
    )
    assert spec.profile is not None
    assert spec.profile.min_role_confidence >= 0.9


def test_an_unknown_profile_test_is_refused() -> None:
    with pytest.raises(ValidationError):
        HuntSpec.model_validate(
            {
                "id": "x",
                "title": "x",
                "evaluator": "profile",
                "profile": {"dimension": "served_ports", "test": "vibes"},
            }
        )


def test_a_profile_spec_rejects_a_role_outside_the_vocabulary() -> None:
    # A typo'd role silently matches nothing, and a prior that matches nothing
    # is indistinguishable from a clean network.
    with pytest.raises(ValidationError):
        HuntSpec.model_validate(
            {
                "id": "x",
                "title": "x",
                "evaluator": "profile",
                "profile": {
                    "dimension": "served_ports",
                    "test": "novel_for",
                    "roles": ["workstaton"],
                },
            }
        )


def test_a_title_loses_its_trailing_full_stop() -> None:
    from soc_ai.hunting.spec import parse_spec

    spec = parse_spec(
        "id: local-x\ntitle: A title with a full stop.\nscope_field: source.ip\nscope_kind: host\n"
        'precondition:\n  all:\n    - field: event.code\n      value: "1"\n'
        'detection:\n  all:\n    - field: event.code\n      value: "1"\n'
    )
    assert spec.title == "A title with a full stop"
