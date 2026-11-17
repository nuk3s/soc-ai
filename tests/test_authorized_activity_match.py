"""The match of one run against the authorized scopes. Pure, no store.

A wrong match hides an attack. Each negative control below is activity that
is close to the authorized test and is not the test: a new source, a second
address of a source machine, a new target, a rule that is not on the list, a
later attack stage, a decoy hit, the reverse direction, a time outside the
window, a revoked record, an address that the Hosts data maps to another
machine, a report that cites activity beyond the pair, and a hunt finding.
None of them may match.

The fixtures follow the production shape of 2026-11: the sources are agent
machines with more than one address, and the target is a machine that the
Hosts data knows only by its address.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from soc_ai.agent import authorized_activity as aam
from soc_ai.agent.authorized_activity import CitedDocument, Matched, Outside, RunFlags
from soc_ai.so_client.models import SoAlert
from soc_ai.store.authorized_activity import Scope, ScopeEntry

TARGET = "10.40.0.164"
SOURCE_A = "10.50.0.26"
SOURCE_A_SECOND = "10.50.0.27"
SOURCE_B = "10.50.0.52"
STRANGER = "10.50.0.200"
OTHER_TARGET = "10.40.0.9"
THIRD_HOST = "203.0.113.9"
RULE = "ET EXPLOIT PHP php2shell Chunked Multipart Request without Content-Length (CVE-2026-109618)"
RULE_NESTED = "ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)"
# The two other true positives of the same pair in production. Not on the list.
HUNTING_UPLOAD = "ET HUNTING PHP Generic Upload Progress Session Manipulation"
HUNTING_POST = (
    "ET HUNTING Generic POST with Common Control/Escape Character in Filename "
    "Parameter - Possible Command Injection Attempt"
)

NOW = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
START = NOW - timedelta(days=1)
END = NOW + timedelta(days=6)

# What the Hosts data says today: address -> machine key.
MEMBERS: dict[str, str | None] = {
    SOURCE_A: "agent:a-1",
    SOURCE_A_SECOND: "agent:a-1",
    SOURCE_B: "agent:b-2",
    TARGET: f"ip:{TARGET}",
    STRANGER: "agent:z-9",
    OTHER_TARGET: f"ip:{OTHER_TARGET}",
}


def _scope(**overrides: object) -> Scope:
    fields: dict[str, object] = {
        "id": 1,
        "label": "php2shell test",
        "sources": (
            ScopeEntry(SOURCE_A, "agent:a-1", "agent-a"),
            ScopeEntry(SOURCE_B, "agent:b-2", "agent-b"),
        ),
        "target": ScopeEntry(TARGET, f"ip:{TARGET}"),
        "rule_names": (RULE, RULE_NESTED),
        "rule_class": "exploit_attempt",
        "starts_at": START,
        "expires_at": END,
        "created_by": "casey",
    }
    fields.update(overrides)
    return Scope(**fields)  # type: ignore[arg-type]


def _alert(**overrides: object) -> SoAlert:
    fields: dict[str, object] = {
        "id": "alert-1",
        "timestamp": NOW.replace(tzinfo=UTC),
        "rule_name": RULE,
        "source_ip": SOURCE_A,
        "destination_ip": TARGET,
        "classtype": "web-application-attack",
        "event_dataset": "suricata.alert",
        "event_module": "suricata",
    }
    fields.update(overrides)
    return SoAlert(**fields)  # type: ignore[arg-type]


def _match(
    alert: SoAlert | None,
    *,
    verdict: str | None = "true_positive",
    flags: RunFlags | None = None,
    scopes: list[Scope] | None = None,
    members: dict[str, str | None] | None = None,
    documents: list[SoAlert] | None = None,
) -> Matched | Outside | None:
    return aam.match(
        alert,
        documents or [],
        verdict=verdict,
        run_flags=flags or RunFlags(),
        authorizations=scopes if scopes is not None else [_scope()],
        memberships=members if members is not None else MEMBERS,
    )


def _outside(answer: Matched | Outside | None) -> tuple[str, ...]:
    assert isinstance(answer, Outside), answer
    return answer.parts


# ── The activity the analyst authorized ────────────────────────────────────


def test_a_listed_rule_from_a_stored_source_to_the_target_matches() -> None:
    answer = _match(_alert())
    assert isinstance(answer, Matched)
    assert answer.scope.id == 1
    assert isinstance(_match(_alert(rule_name=RULE_NESTED)), Matched)
    assert isinstance(_match(_alert(source_ip=SOURCE_B)), Matched)


def test_the_window_includes_its_two_ends() -> None:
    assert isinstance(_match(_alert(timestamp=START.replace(tzinfo=UTC))), Matched)
    assert isinstance(_match(_alert(timestamp=END.replace(tzinfo=UTC))), Matched)


def test_the_oldest_scope_takes_a_run_that_two_scopes_match() -> None:
    answer = _match(_alert(), scopes=[_scope(id=7, label="newer"), _scope(id=3, label="older")])
    assert isinstance(answer, Matched)
    assert answer.scope.id == 3


# ── Negative controls: close to the test, and not the test ─────────────────


def test_a_second_address_of_a_source_machine_is_outside() -> None:
    """The record stores addresses. The Hosts data joins this one to the same
    agent machine, and a join by a DNS name or a lease proves no machine."""
    assert _outside(_match(_alert(source_ip=SOURCE_A_SECOND))) == (aam.PART_SOURCE,)


def test_a_new_source_is_outside() -> None:
    assert _outside(_match(_alert(source_ip=STRANGER))) == (aam.PART_SOURCE,)


def test_a_new_target_is_outside() -> None:
    assert _outside(_match(_alert(destination_ip=OTHER_TARGET))) == (aam.PART_TARGET,)


@pytest.mark.parametrize(
    "rule",
    [
        HUNTING_UPLOAD,
        HUNTING_POST,
        # A rule of the same family that the list does not hold.
        "ET EXPLOIT PHP php2shell Multipart Header Amplification OOM (CVE-2026-109618)",
        # No prefix: a longer name and a shorter name are other rules.
        RULE + " variant 2",
        "ET EXPLOIT PHP php2shell",
        # The case stays.
        RULE.lower(),
    ],
)
def test_a_rule_that_is_not_on_the_list_is_outside(rule: str) -> None:
    assert _outside(_match(_alert(rule_name=rule))) == (aam.PART_RULE,)


def test_a_short_listed_rule_name_is_no_prefix_for_longer_rules() -> None:
    """Review scenario s1: a record on a rule name of three words."""
    scope = _scope(rule_names=("ET SCAN NMAP",), rule_class="recon")
    scan = {"classtype": "attempted-recon"}
    assert isinstance(_match(_alert(rule_name="ET SCAN NMAP", **scan), scopes=[scope]), Matched)
    for longer in (
        "ET SCAN NMAP -sS window 1024",
        "ET SCAN Nmap Scripting Engine User-Agent Detected",
    ):
        answer = _match(_alert(rule_name=longer, **scan), scopes=[scope])
        assert _outside(answer) == (aam.PART_RULE,), longer


def test_a_listed_rule_name_with_another_alert_class_is_outside() -> None:
    """The name is on the list, and the alert reports a later stage."""
    alert = _alert(classtype="successful-admin")
    assert _outside(_match(alert)) == (aam.PART_RULE,)


def test_a_decoy_hit_inside_the_scope_is_outside() -> None:
    """The needle sits on the path the other parts would pass."""
    by_dataset = _alert(event_dataset="opencanary", event_module="opencanary")
    assert _outside(_match(by_dataset)) == (aam.PART_DECOY,)
    named = "ET EXPLOIT PHP php2shell honeypot probe"
    scope = _scope(rule_names=(named,))
    assert _outside(_match(_alert(rule_name=named), scopes=[scope])) == (aam.PART_DECOY,)


def test_the_reverse_direction_is_outside() -> None:
    """The target that connects back to a source is a later attack stage."""
    alert = _alert(source_ip=TARGET, destination_ip=SOURCE_A)
    assert _outside(_match(alert)) == (aam.PART_DIRECTION,)


def test_one_second_outside_the_window_is_outside() -> None:
    late = _alert(timestamp=(END + timedelta(seconds=1)).replace(tzinfo=UTC))
    early = _alert(timestamp=(START - timedelta(seconds=1)).replace(tzinfo=UTC))
    assert _outside(_match(late)) == (aam.PART_TIME,)
    assert _outside(_match(early)) == (aam.PART_TIME,)
    assert _outside(_match(_alert(timestamp=None))) == (aam.PART_TIME,)


def test_a_revoked_scope_matches_nothing() -> None:
    assert _match(_alert(), scopes=[_scope(revoked_at=NOW)]) is None


def test_a_target_address_that_an_agent_or_a_mac_claimed_is_outside() -> None:
    """The production target is known only by its address. The record follows
    the address until the Hosts data gives it another identity."""
    for key in ("agent:new-1", "mac:aa:bb:cc:dd:ee:ff"):
        members = {**MEMBERS, TARGET: key}
        assert _outside(_match(_alert(), members=members)) == (aam.PART_TARGET,), key


def test_a_target_with_no_agent_follows_the_address() -> None:
    assert isinstance(_match(_alert(), members={**MEMBERS, TARGET: None}), Matched)
    bare = _scope(target=ScopeEntry(TARGET, None))
    assert isinstance(_match(_alert(), scopes=[bare]), Matched)
    assert isinstance(_match(_alert(), scopes=[bare], members={**MEMBERS, TARGET: None}), Matched)


def test_a_source_address_that_the_hosts_data_maps_to_another_machine_is_outside() -> None:
    """The stored address is not enough. The mapping of today must be the same."""
    for key in (None, "agent:z-9", f"ip:{SOURCE_A}"):
        members = {**MEMBERS, SOURCE_A: key}
        assert _outside(_match(_alert(), members=members)) == (aam.PART_SOURCE,), key


def test_a_target_with_an_agent_must_keep_that_agent() -> None:
    scope = _scope(target=ScopeEntry(TARGET, "agent:t-1", "web"))
    assert isinstance(
        _match(_alert(), scopes=[scope], members={**MEMBERS, TARGET: "agent:t-1"}), Matched
    )
    for key in (None, f"ip:{TARGET}", "agent:t-2"):
        answer = _match(_alert(), scopes=[scope], members={**MEMBERS, TARGET: key})
        assert _outside(answer) == (aam.PART_TARGET,), key


def test_an_alert_with_no_source_is_outside() -> None:
    assert _outside(_match(_alert(source_ip=None))) == (aam.PART_FLOW,)


@pytest.mark.parametrize("verdict", ["needs_more_info", "false_positive", "inconclusive", None])
def test_only_a_true_positive_is_judged(verdict: str | None) -> None:
    assert _match(_alert(), verdict=verdict) is None


@pytest.mark.parametrize(
    "flags", [RunFlags(replay=True), RunFlags(synthetic=True), RunFlags(promoted="lead")]
)
def test_a_measurement_and_a_lead_run_get_no_answer(flags: RunFlags) -> None:
    assert _match(_alert(), flags=flags) is None


def test_a_run_between_other_machines_has_no_answer() -> None:
    assert _match(_alert(source_ip=STRANGER, destination_ip=OTHER_TARGET)) is None


def test_a_run_that_fails_the_time_and_another_part_has_no_answer() -> None:
    """An ended scope says nothing about new activity of one of its machines."""
    late = (END + timedelta(days=2)).replace(tzinfo=UTC)
    assert _match(_alert(source_ip=STRANGER, timestamp=late)) is None
    assert _match(_alert(rule_name=HUNTING_UPLOAD, timestamp=late)) is None


def test_no_scope_and_no_alert_give_no_answer() -> None:
    assert _match(_alert(), scopes=[]) is None
    assert _match(None) is None


def test_the_closest_scope_names_the_outside_run() -> None:
    far = _scope(id=1, label="far", rule_names=("ET SCAN Nmap Scripting Engine",))
    near = _scope(id=2, label="near")
    answer = _match(_alert(source_ip=STRANGER), scopes=[far, near])
    assert isinstance(answer, Outside)
    assert (answer.scope.label, answer.parts) == ("near", (aam.PART_SOURCE,))


# ── A hunt finding never matches ───────────────────────────────────────────

FINDING = RunFlags(promoted="finding")


def _document(**overrides: object) -> SoAlert:
    fields: dict[str, object] = {
        "id": "zeek-http-doc-0001",
        "timestamp": NOW.replace(tzinfo=UTC),
        "rule_name": None,
        "source_ip": SOURCE_A,
        "destination_ip": TARGET,
        "event_dataset": "zeek.http",
        "event_module": "zeek",
        "network_community_id": "1:session-a",
    }
    fields.update(overrides)
    return SoAlert(**fields)  # type: ignore[arg-type]


def test_a_finding_on_the_machines_of_a_scope_is_outside_and_never_matches() -> None:
    """soc-ai always judges a finding on its own. Every document of this one
    is inside the pair, the rule list and the time, and it still does not match."""
    answer = _match(_document(), flags=FINDING, documents=[_document()])
    assert _outside(answer) == (aam.PART_FINDING,)
    # The anchor is elsewhere, and one document of the hunt touches the target.
    elsewhere = _document(source_ip=STRANGER, destination_ip=OTHER_TARGET)
    answer = _match(elsewhere, flags=FINDING, documents=[_document(source_ip=TARGET)])
    assert _outside(answer) == (aam.PART_FINDING,)


def test_a_finding_between_other_machines_has_no_answer() -> None:
    elsewhere = _document(source_ip=STRANGER, destination_ip=OTHER_TARGET)
    assert _match(elsewhere, flags=FINDING, documents=[elsewhere]) is None
    assert _match(_document(), flags=FINDING, scopes=[_scope(revoked_at=NOW)]) is None


# ── The cited evidence ─────────────────────────────────────────────────────


def _index(*documents: dict[str, object]) -> dict[str, list[CitedDocument]]:
    index = aam.index_documents([{"alert": _alert().model_dump(mode="json")}, list(documents)])
    assert index is not None
    return index


PAIR_DOC = {"id": "zeek-http-doc-0001", "source_ip": SOURCE_A, "destination_ip": TARGET}
REPLY_DOC = {"id": "zeek-conn-doc-0002", "source_ip": TARGET, "destination_ip": SOURCE_B}
BEACON_DOC = {"id": "zeek-conn-doc-0201", "source_ip": TARGET, "destination_ip": THIRD_HOST}
HOST_LOG = {"id": "sysmon-doc-0301", "host_name": "web", "process_name": "sh"}
ES_HIT = {
    "_id": "es-hit-0401",
    "_source": {
        "source": {"ip": TARGET},
        "destination": {"ip": THIRD_HOST},
        "hash": {"ja3": "e7d705a3286e19ea42f587b344ee6865"},
    },
}


def test_a_report_that_cites_only_documents_of_the_pair_is_inside() -> None:
    index = _index(PAIR_DOC, REPLY_DOC, BEACON_DOC)
    cited = ["alert-1", "zeek-http-doc-0001", "ZEEK-CONN-DOC-0002"]
    assert aam.cited_beyond(_scope(), cited, index) is False
    assert aam.cited_beyond(_scope(), [], index) is False
    assert aam.cited_beyond(_scope(), None, index) is False


@pytest.mark.parametrize(
    ("cited", "why"),
    [
        (["alert-1", "zeek-conn-doc-0201"], "a flow from the target to a third host"),
        (["sysmon-doc-0301"], "a host log names no pair"),
        (["es-hit-0401"], "a raw grid hit to a third host"),
        (["e7d705a3286e19ea42f587b344ee6865"], "a cited hash of a document beyond the pair"),
        (["zeek-http-doc-9999"], "a document the run did not record"),
        (["t_host_summary:10.40.0.164"], "a tool call is not a document of the pair"),
    ],
)
def test_a_report_that_cites_activity_beyond_the_scope_is_outside(
    cited: list[str], why: str
) -> None:
    index = _index(PAIR_DOC, REPLY_DOC, BEACON_DOC, HOST_LOG, ES_HIT)
    assert aam.cited_beyond(_scope(), cited, index) is True, why


def test_a_document_inside_a_json_text_result_is_read() -> None:
    import json

    result = json.dumps({"hits": [BEACON_DOC]})
    index = aam.index_documents([{"tool_name": "t", "result": result}])
    assert index is not None
    assert aam.cited_beyond(_scope(), ["zeek-conn-doc-0201"], index) is True


# ── The report of a production run ─────────────────────────────────────────
#
# The nine true positive runs of the 2026-11 campaign cite fields of the
# focus alert, events on its session, tool calls, the alert history of the
# hosts, one grid document id and one investigation id. Their text names the
# sources and the target only. Each such run must stay inside.

GRID_ID = "8IKUzKEBLWkWRQIwPbm-"
SESSION_DOC_ID = "Qm3xzKEBLWkWRQIwPbn0"
BEACON_ID = "Zt9qzKEBLWkWRQIwPc1a"
INVESTIGATION_ID = "01M6Y98DBWJ8JHFJJ4KSTC15EP"
PRODUCTION_CITATIONS = [
    "alert.payload_printable",
    "alert.rule_name",
    "alert.id",
    "alert.rule_metadata.signature_severity",
    "alert.network_community_id",
    "alert.alert_action",
    "community_id_events.0.zeek_http_status",
    "community_id_events.0.rule_name",
    "tool t_origin_chain",
    "tool t_rule_prevalence",
    "tool t_prevalence",
    "tool t_query_cases",
    "tool t_query_events_oql",
    "host_alert_profile",
    "host_alert_profiles.0.alert_count",
    f"host_alert_profile.{RULE}",
    GRID_ID,
    INVESTIGATION_ID,
]
PRODUCTION_TEXTS = [
    f"agent-a at {SOURCE_A} sent php2shell exploit requests to {TARGET}.",
    f"The target {TARGET} answered with HTTP 500. Agent-B at {SOURCE_B} sent the same requests.",
    f"Open a case for the exploit requests from {SOURCE_A} to {TARGET}.",
]
# The machine names of the Hosts data, lower case, with the keys of their machines.
HOST_NAMES: dict[str, frozenset[str]] = {
    "agent-a": frozenset({"agent:a-1"}),
    "agent-b": frozenset({"agent:b-2"}),
    "agent-z": frozenset({"agent:z-9"}),
    "mainsrv": frozenset({"agent:h-7"}),
    "blue": frozenset({"agent:bl-3"}),
}


def _production_index() -> dict[str, list[CitedDocument]]:
    alert = _alert(id=GRID_ID).model_dump(mode="json")
    session_doc = {"id": SESSION_DOC_ID, "source_ip": TARGET, "destination_ip": SOURCE_A}
    beacon = {"_id": BEACON_ID, "_source": {"source_ip": TARGET, "destination_ip": THIRD_HOST}}
    index = aam.index_documents(
        [
            {
                "alert": alert,
                "community_id_events": [session_doc],
                "host_alert_profiles": [{"host": TARGET, "alert_count": 9}],
            },
            {"tool_name": "t_query_events_oql", "result": {"hits": [beacon]}},
        ]
    )
    assert index is not None
    return index


def _report_answer(
    citations: list[str] | None = None,
    texts: list[str] | None = None,
    names: dict[str, frozenset[str]] | None = HOST_NAMES,
) -> Outside | None:
    return aam.report_beyond(
        _scope(),
        citations=PRODUCTION_CITATIONS if citations is None else citations,
        texts=PRODUCTION_TEXTS if texts is None else texts,
        documents=_production_index(),
        host_names=names,
    )


def _line(answer: Outside | None) -> str:
    assert isinstance(answer, Outside), answer
    assert answer.parts == (aam.PART_CITED,)
    return aam.outside_mark(answer.scope, answer.parts, answer.named)["line"]


def test_a_run_with_the_production_citation_shapes_is_inside() -> None:
    assert isinstance(_match(_alert(id=GRID_ID)), Matched)
    assert _report_answer() is None
    assert _report_answer([GRID_ID, SESSION_DOC_ID.lower()]) is None


def test_a_report_that_names_another_address_is_outside() -> None:
    texts = [*PRODUCTION_TEXTS, f"The target {TARGET} then connected to {THIRD_HOST}:443."]
    assert _line(_report_answer(texts=texts)) == (
        "This activity is outside the authorized scope of php2shell test: "
        f"the report names {THIRD_HOST}, which is beyond the scope."
    )
    ipv6 = [f"The target answered 2001:db8::7 on {TARGET}."]
    assert "names 2001:db8::7," in _line(_report_answer(texts=ipv6))


def test_a_report_that_names_another_known_machine_is_outside() -> None:
    texts = [*PRODUCTION_TEXTS, "The target then fetched a file from Mainsrv."]
    assert _line(_report_answer(texts=texts)).endswith(
        "the report names Mainsrv, which is beyond the scope."
    )
    fqdn = ["The target resolved mainsrv.example.test first."]
    assert _line(_report_answer(texts=fqdn)).endswith("names mainsrv, which is beyond the scope.")


def test_a_cited_document_between_the_target_and_a_third_host_is_outside() -> None:
    answer = _report_answer([*PRODUCTION_CITATIONS, BEACON_ID])
    assert _line(answer).endswith("the report cites activity beyond the scope.")


def test_a_cited_document_id_that_does_not_resolve_is_outside() -> None:
    answer = _report_answer([*PRODUCTION_CITATIONS, "Xx0qzKEBLWkWRQIwPzzz"])
    assert _line(answer).endswith("the report cites activity beyond the scope.")


def test_a_machine_name_inside_a_longer_word_does_not_count() -> None:
    texts = [
        *PRODUCTION_TEXTS,
        "The blueprint of the exploit matches the sky-blue lab and blue_team notes.",
    ]
    assert _report_answer(texts=texts) is None
    assert _line(_report_answer(texts=["The blue host replied."])).endswith(
        "the report names blue, which is beyond the scope."
    )


def test_a_report_with_no_machine_name_data_is_outside() -> None:
    assert _line(_report_answer(names=None)).endswith("the report cites activity beyond the scope.")


def test_a_time_or_a_mac_in_the_text_is_no_address() -> None:
    texts = [f"At 10:32:05 the target {TARGET} with MAC 00:1a:2b:3c:4d:5e answered."]
    assert _report_answer(texts=texts) is None


# ── The words ──────────────────────────────────────────────────────────────


def test_the_outside_line_names_the_part_that_failed() -> None:
    line = "This activity is outside the authorized scope of php2shell test: "
    assert aam.outside_sentence("php2shell test", [aam.PART_SOURCE]) == line + "the source is new."
    assert aam.outside_sentence("php2shell test", [aam.PART_RULE]) == line + "the rule is new."
    assert aam.outside_sentence("php2shell test", [aam.PART_CITED]) == (
        line + "the report cites activity beyond the scope."
    )
    assert aam.outside_sentence("php2shell test", [aam.PART_FINDING]) == (
        line + "a finding is always judged on its own."
    )
    assert aam.outside_sentence("php2shell test", [aam.PART_RULE, aam.PART_SOURCE]) == (
        line + "the source is new and the rule is new."
    )


def test_the_marks_hold_the_display_copy() -> None:
    scope = _scope()
    matched = aam.matched_mark(scope, at=NOW)
    assert matched["state"] == "matched"
    assert (matched["id"], matched["label"], matched["by"]) == (1, "php2shell test", "casey")
    assert matched["expires_at"].endswith("Z")
    assert "earlier" not in matched
    assert aam.matched_mark(scope, at=NOW, earlier=True)["earlier"] is True
    outside = aam.outside_mark(scope, [aam.PART_TARGET])
    assert outside["state"] == "outside"
    assert outside["parts"] == ["target"]
    assert outside["line"].endswith("the target is new.")
