"""The campaign engine: membership by proven links, roles, stages and evidence.

Every machine key, address and name here is a placeholder. The last test
holds the structure of the case that the design names as its reference.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

from soc_ai.campaigns.engine import build_campaigns
from soc_ai.campaigns.types import CampaignDraft, DocFacts, Member, RunFacts, jsonable

T0 = datetime(2026, 1, 10, 0, 0, 0)
A1, A2, A3 = "agent:a1", "agent:a2", "agent:a3"
T1, T2, T3, X1 = "ip:198.51.100.10", "ip:198.51.100.11", "ip:198.51.100.12", "ip:198.51.100.99"
ADDRESS = {
    A1: "192.0.2.1",
    A2: "192.0.2.2",
    A3: "192.0.2.3",
    T1: "198.51.100.10",
    T2: "198.51.100.11",
    T3: "198.51.100.12",
    X1: "198.51.100.99",
}
NAME = {A1: "actor-a", A2: "actor-b", A3: "actor-c", T1: "web-1"}
FP = "false_positive"


def at(hours: float) -> datetime:
    return T0 + timedelta(hours=hours)


def run(
    run_id: str, hours: float = 0.0, src: str | None = A1, dst: str | None = T1, **over: Any
) -> RunFacts:
    """One alert run: a true positive of the class exploit_attempt on RULE A."""
    base: dict[str, Any] = {
        "run_id": run_id,
        "event_time": at(hours),
        "finished_at": at(hours) + timedelta(minutes=5),
        "source": src,
        "target": dst,
        "source_address": ADDRESS.get(src or ""),
        "target_address": ADDRESS.get(dst or ""),
        "source_name": NAME.get(src or ""),
        "target_name": NAME.get(dst or ""),
        "source_join": "agent" if src else None,
        "target_join": "network" if dst else None,
        "attack_class": "exploit_attempt",
        "label": "RULE A",
        "rules": frozenset({"RULE A"}),
    }
    base.update(over)
    return RunFacts(**base)


def finding(
    run_id: str, hours: float = 0.0, src: str | None = A1, dst: str | None = T1, **over: Any
) -> RunFacts:
    base: dict[str, Any] = {
        "kind": "finding",
        "attack_class": "finding",
        "label": "A finding",
        "rules": frozenset(),
        "tier": "scheduled_hunt",
    }
    base.update(over)
    return run(run_id, hours, src, dst, **base)


def doc(
    doc_id: str, hours: float = 0.0, src: str | None = A1, dst: str | None = T1, **over: Any
) -> DocFacts:
    base: dict[str, Any] = {
        "id": doc_id,
        "at": at(hours),
        "source": src,
        "target": dst,
        "source_address": ADDRESS.get(src or ""),
        "target_address": ADDRESS.get(dst or ""),
        "target_port": 80,
        "dataset": "zeek.http",
    }
    base.update(over)
    return DocFacts(**base)


def only(drafts: list[CampaignDraft]) -> CampaignDraft:
    assert len(drafts) == 1, [d.run_ids for d in drafts]
    return drafts[0]


def member(draft: CampaignDraft, run_id: str) -> Member:
    return next(m for m in draft.members if m.run.run_id == run_id)


def roles(draft: CampaignDraft) -> dict[str, str]:
    return {p.machine_key: p.role for p in draft.parties}


# ── Seeds ────────────────────────────────────────────────────────────────


def test_one_seed_is_one_campaign() -> None:
    draft = only(build_campaigns([run("r1")]))
    assert draft.run_ids == ("r1",)
    assert member(draft, "r1").link.type == "seed"
    assert roles(draft) == {A1: "actor", T1: "target"}
    assert draft.stage == "attempt"
    assert draft.first_event == draft.last_event == T0
    assert draft.pairs == frozenset({(A1, T1)})


def test_a_true_positive_with_no_impact_starts_no_campaign() -> None:
    assert build_campaigns([run("r1", impact="none")]) == []


def test_a_true_positive_with_no_impact_joins_a_campaign() -> None:
    draft = only(build_campaigns([run("r1"), run("r2", 1, impact="none")]))
    assert draft.run_ids == ("r1", "r2")
    assert member(draft, "r2").link.type == "actor"


def test_a_true_positive_of_no_attack_class_starts_no_campaign() -> None:
    assert build_campaigns([run("r1", attack_class="")]) == []


def test_a_run_with_no_event_time_is_in_no_campaign() -> None:
    assert build_campaigns([run("r1", event_time=None)]) == []


def test_a_run_with_one_machine_at_both_ends_starts_no_campaign() -> None:
    assert build_campaigns([run("r1", dst=A1)]) == []


# ── Actor and Artifact ───────────────────────────────────────────────────


def test_the_actor_link_adds_a_target() -> None:
    draft = only(build_campaigns([run("r1"), run("r2", 1, dst=T2, rules=frozenset({"RULE B"}))]))
    assert roles(draft) == {A1: "actor", T1: "target", T2: "target"}
    link = member(draft, "r2").link
    assert (link.type, link.member_run_id, link.machine) == ("actor", "r1", A1)


def test_the_actor_link_ends_at_the_horizon() -> None:
    drafts = build_campaigns([run("r1"), run("r2", 208, rules=frozenset({"RULE B"}))])
    assert [d.run_ids for d in drafts] == [("r1",), ("r2",)]


def test_a_chain_of_the_actor_link_can_be_longer_than_one_horizon() -> None:
    facts = [
        run("r1"),
        run("r2", 150, dst=T2, rules=frozenset({"RULE B"})),
        run("r3", 300, dst=T3, rules=frozenset({"RULE C"})),
    ]
    draft = only(build_campaigns(facts))
    assert [m.link.type for m in draft.members] == ["seed", "actor", "actor"]
    assert member(draft, "r3").link.member_run_id == "r2"


def test_a_true_positive_with_a_hostile_impact_is_an_attack_with_no_class() -> None:
    """A Sigma rule and a Zeek notice have no Suricata class."""
    draft = only(build_campaigns([run("r1", attack_class="", impact="succeeded")]))
    assert member(draft, "r1").stage == "access"
    assert build_campaigns([run("r1", attack_class="", impact="unknown")]) == []


def test_the_same_actor_target_and_rule_have_no_time_limit() -> None:
    draft = only(build_campaigns([run("r1"), run("r2", 235)]))
    link = member(draft, "r2").link
    assert (link.type, link.member_run_id, link.artifact) == ("artifact", "r1", "rule: RULE A")


def test_a_shared_cve_id_or_http_key_is_an_artifact() -> None:
    by_cve = [
        run("r1", cves=frozenset({"CVE-2026-10000"})),
        run("r2", 300, rules=frozenset({"RULE B"}), cves=frozenset({"CVE-2026-10000"})),
    ]
    assert member(only(build_campaigns(by_cve)), "r2").link.artifact == "cve: CVE-2026-10000"
    by_http = [
        run("r1", http_keys=frozenset({"POST /upload.php"})),
        run("r2", 300, rules=frozenset(), http_keys=frozenset({"POST /upload.php"})),
    ]
    assert member(only(build_campaigns(by_http)), "r2").link.artifact == "http: POST /upload.php"


def test_the_artifact_link_adds_an_actor_inside_the_horizon() -> None:
    draft = only(build_campaigns([run("r1"), run("r2", 2, src=A2)]))
    assert roles(draft) == {A1: "actor", A2: "actor", T1: "target"}
    assert member(draft, "r2").link.type == "artifact"


def test_a_new_actor_after_the_horizon_is_a_new_campaign() -> None:
    drafts = build_campaigns([run("r1"), run("r2", 208, src=A2)])
    assert [d.run_ids for d in drafts] == [("r1",), ("r2",)]


def test_a_true_positive_of_no_attack_class_joins_by_an_artifact_only() -> None:
    by_actor = [run("r1"), run("r2", 1, dst=T2, attack_class="", rules=frozenset({"RULE B"}))]
    assert only(build_campaigns(by_actor)).run_ids == ("r1",)
    by_artifact = [run("r1"), run("r2", 1, attack_class="")]
    draft = only(build_campaigns(by_artifact))
    assert member(draft, "r2").link.type == "artifact"
    assert member(draft, "r2").stage is None


def test_a_source_with_no_machine_joins_no_campaign_of_another_actor() -> None:
    draft = only(build_campaigns([run("r1"), run("r2", 1, src=None)]))
    assert draft.run_ids == ("r1",)


def test_an_actor_run_with_no_target_machine_is_a_member_and_adds_no_party() -> None:
    draft = only(build_campaigns([run("r1"), run("r2", 1, dst=None, rules=frozenset({"RULE B"}))]))
    assert member(draft, "r2").link.type == "actor"
    assert roles(draft) == {A1: "actor", T1: "target"}


# ── Session ──────────────────────────────────────────────────────────────


def test_a_false_positive_on_a_member_session_is_a_member_with_another_verdict() -> None:
    seed = run("r1", sessions=(("1:abc=", at(0)),))
    other = run("r2", 0.2, verdict=FP, sessions=(("1:abc=", at(0.2)),))
    draft = only(build_campaigns([seed, other]))
    found = member(draft, "r2")
    assert (found.link.type, found.link.member_run_id, found.link.community_id) == (
        "session",
        "r1",
        "1:abc=",
    )
    assert found.verdict_differs is True
    assert found.stage is None
    assert roles(draft) == {A1: "actor", T1: "target"}
    assert draft.last_event == T0


def test_a_false_positive_from_a_new_source_on_a_member_session_adds_no_party() -> None:
    seed = run("r1", sessions=(("1:abc=", at(0)),))
    other = run("r2", 0.2, src=A2, dst=T2, verdict=FP, sessions=(("1:abc=", at(0.2)),))
    assert roles(only(build_campaigns([seed, other]))) == {A1: "actor", T1: "target"}


def test_a_false_positive_from_the_target_on_a_member_session_reads_the_session_link() -> None:
    """The alert on the answer of the server has the target as its source. Its
    run is a false positive. It joins by the session, and its link says so."""
    seed = run("r1", sessions=(("1:abc=", at(0)),))
    answer = run("r2", 0.01, src=T1, dst=A1, verdict=FP, sessions=(("1:abc=", at(0.01)),))
    draft = only(build_campaigns([seed, run("r0", -1), answer]))
    found = member(draft, "r2")
    assert (found.link.type, found.link.member_run_id) == ("session", "r1")
    assert (found.direction, found.stage, found.verdict_differs) == ("forward", None, True)


def test_a_run_with_another_verdict_joins_no_two_campaigns() -> None:
    """One false positive run holds a session of each of two campaigns. It
    joins the nearer one. The two campaigns stay apart."""
    first = run("s1", sessions=(("1:c1=", at(0)),))
    second = run("s2", 300, rules=frozenset({"RULE B"}), sessions=(("1:c2=", at(300)),))
    bridge = run("fp", 300.1, verdict=FP, sessions=(("1:c1=", at(0.1)), ("1:c2=", at(300.1))))
    drafts = build_campaigns([first, second, bridge])
    assert [d.run_ids for d in drafts] == [("s1",), ("s2", "fp")]
    assert member(drafts[1], "fp").link.member_run_id == "s2"


def test_a_run_with_another_verdict_passes_no_link_on() -> None:
    """A true positive shares a session with a false positive member only. It
    is no member."""
    seed = run("s1", sessions=(("1:c1=", at(0)),))
    other = run("fp", 0.1, verdict=FP, sessions=(("1:c1=", at(0.1)), ("1:c9=", at(0.1))))
    far = run(
        "r9",
        0.2,
        src=A2,
        dst=T2,
        attack_class="",
        rules=frozenset(),
        sessions=(("1:c9=", at(0.2)),),
    )
    draft = only(build_campaigns([seed, other, far]))
    assert draft.run_ids == ("s1", "fp")


def test_a_community_id_five_days_later_is_another_session() -> None:
    seed = run("r1", sessions=(("1:abc=", at(0)),))
    other = run("r2", 120, verdict=FP, sessions=(("1:abc=", at(120)),))
    assert only(build_campaigns([seed, other])).run_ids == ("r1",)


def test_a_false_positive_with_no_shared_session_is_no_member() -> None:
    assert only(build_campaigns([run("r1"), run("r2", 0.1, verdict=FP)])).run_ids == ("r1",)


# ── Documents ────────────────────────────────────────────────────────────


def _cited_finding(**over: Any) -> RunFacts:
    base: dict[str, Any] = {
        "cited_ids": ("d1", "d2"),
        "documents": (doc("d1", 1, cited=True), doc("d2", 1.1, cited=True)),
    }
    base.update(over)
    return finding("f1", 1, src=None, dst=None, **base)


def test_a_finding_joins_by_its_cited_documents() -> None:
    draft = only(build_campaigns([run("r1"), _cited_finding()]))
    link = member(draft, "f1").link
    assert (link.type, link.document_ids) == ("documents", ("d1", "d2"))


def test_a_cited_document_that_the_store_does_not_hold_proves_nothing() -> None:
    draft = only(build_campaigns([run("r1"), _cited_finding(cited_unresolved=1)]))
    assert draft.run_ids == ("r1",)


def test_a_cited_document_with_an_end_that_is_no_party_proves_nothing() -> None:
    documents = (doc("d1", 1, cited=True), doc("d2", 1.1, dst=X1, cited=True))
    draft = only(build_campaigns([run("r1"), _cited_finding(documents=documents)]))
    assert draft.run_ids == ("r1",)


def test_a_finding_that_cites_no_document_does_not_join_by_documents() -> None:
    draft = only(
        build_campaigns([run("r1"), _cited_finding(cited_ids=(), documents=(doc("d1", 1),))])
    )
    assert draft.run_ids == ("r1",)


def test_the_documents_link_ends_at_the_horizon() -> None:
    late = _cited_finding(event_time=at(300))
    assert only(build_campaigns([run("r1"), late])).run_ids == ("r1",)


def test_a_false_positive_finding_does_not_join_by_documents() -> None:
    assert only(build_campaigns([run("r1"), _cited_finding(verdict=FP)])).run_ids == ("r1",)


# ── Target as source ─────────────────────────────────────────────────────


def test_a_target_that_acts_on_a_third_host_is_movement() -> None:
    facts = [
        run("r1", impact="succeeded"),
        run("r2", 1, src=T1, dst=X1, rules=frozenset({"RULE B"})),
    ]
    draft = only(build_campaigns(facts))
    found = member(draft, "r2")
    assert (found.link.type, found.link.member_run_id, found.link.machine) == (
        "target_source",
        "r1",
        T1,
    )
    assert (found.direction, found.stage) == ("beyond", "movement")
    assert roles(draft) == {A1: "actor", T1: "target", X1: "target"}
    beyond = {p.machine_key: p.beyond for p in draft.parties}
    assert beyond == {A1: False, T1: False, X1: True}
    assert draft.stage == "movement"
    assert draft.beyond_runs == 1
    assert draft.pairs == frozenset({(A1, T1)})
    assert member(draft, "r1").link.type == "seed"


def test_a_target_that_acted_before_the_attack_is_another_campaign() -> None:
    facts = [
        run("r1", impact="succeeded"),
        run("r0", -2, src=T1, dst=X1, rules=frozenset({"RULE B"})),
    ]
    assert [d.run_ids for d in build_campaigns(facts)] == [("r0",), ("r1",)]


def test_a_target_that_answers_its_actor_is_no_movement() -> None:
    answer = run("r2", 0.02, src=T1, dst=A1, rules=frozenset({"RULE B"}))
    draft = only(build_campaigns([run("r1", impact="succeeded"), answer]))
    found = member(draft, "r2")
    assert (found.link.type, found.direction, found.stage) == (
        "target_source",
        "reverse",
        "attempt",
    )
    assert roles(draft) == {A1: "actor", T1: "target"}
    assert draft.beyond_runs == 0


def test_a_target_stays_a_target_however_many_runs_it_makes() -> None:
    """The target is the source of three runs and the target of two. A count
    of its runs would read it as an actor and lose the movement."""
    facts = [
        run("r1", impact="succeeded"),
        run("r2", 1),
        run("r3", 2, src=T1, dst=X1, rules=frozenset({"RULE B"})),
        run("r4", 3, src=T1, dst=T2, rules=frozenset({"RULE B"})),
        run("r5", 4, src=T1, dst=X1, rules=frozenset({"RULE B"})),
    ]
    draft = only(build_campaigns(facts))
    assert roles(draft) == {A1: "actor", T1: "target", X1: "target", T2: "target"}
    assert [m.direction for m in draft.members] == [
        "forward",
        "forward",
        "beyond",
        "beyond",
        "beyond",
    ]
    assert [m.link.type for m in draft.members[2:]] == ["target_source"] * 3
    assert draft.stage == "movement"
    assert draft.beyond_runs == 3


def test_a_target_of_an_attack_with_no_proof_carries_nothing_on() -> None:
    """The attack on the target shows no effect. A later attack from that
    target is its own activity: a host that was probed and that later acts
    must not join the campaign of the prober."""
    later = run("r2", 1, src=T1, dst=X1, rules=frozenset({"RULE B"}))
    assert [d.run_ids for d in build_campaigns([run("r1"), later])] == [("r1",), ("r2",)]
    scan = run("r1", attack_class="recon", impact="attempted")
    assert [d.run_ids for d in build_campaigns([scan, later])] == [("r1",), ("r2",)]


def test_an_alert_on_the_answer_of_the_server_that_comes_first_inverts_no_role() -> None:
    facts = [
        run("r0", 0, src=T1, dst=A1, rules=frozenset({"RULE B"}), sessions=(("1:abc=", at(0)),)),
        run("r1", 0.001, sessions=(("1:abc=", at(0.001)),)),
        run("r2", 0.002),
        run("r3", 0.003),
    ]
    draft = only(build_campaigns(facts))
    assert roles(draft) == {A1: "actor", T1: "target"}
    assert member(draft, "r0").direction == "reverse"
    assert draft.beyond_runs == 0
    assert draft.pairs == frozenset({(A1, T1)})


def test_an_actor_that_is_attacked_later_stays_an_actor() -> None:
    """Actor b attacks actor a with effect. The later runs of actor a moved on
    from that attack: they read movement. Actor a stays an actor."""
    facts = [
        run("r1"),
        run("r2", 5, src=A2, dst=A1, rules=frozenset({"RULE B"}), impact="succeeded"),
        run("r3", 6),
    ]
    draft = only(build_campaigns(facts))
    assert roles(draft) == {A1: "actor", A2: "actor", T1: "target"}
    assert [m.direction for m in draft.members] == ["forward", "forward", "beyond"]


# ── Merge and order ──────────────────────────────────────────────────────


def _two_seeds() -> list[RunFacts]:
    return [run("s1"), run("s2", 1, src=A2, dst=T2, rules=frozenset({"RULE B"}))]


def test_two_seeds_with_no_link_are_two_campaigns() -> None:
    assert [d.run_ids for d in build_campaigns(_two_seeds())] == [("s1",), ("s2",)]


def test_a_run_that_links_two_campaigns_merges_them() -> None:
    bridge = run("r3", 2, src=A1, dst=T2, rules=frozenset({"RULE B"}))
    draft = only(build_campaigns([*_two_seeds(), bridge]))
    assert draft.run_ids == ("s1", "s2", "r3")
    assert draft.seed_run_id == "s1"
    assert member(draft, "s2").link.type == "artifact"
    assert roles(draft) == {A1: "actor", A2: "actor", T1: "target", T2: "target"}


def test_the_order_of_the_input_does_not_change_the_result() -> None:
    facts = [
        *_two_seeds(),
        run("r3", 2, src=A1, dst=T2, rules=frozenset({"RULE B"}), impact="succeeded"),
        run("r4", 3, src=T2, dst=X1, rules=frozenset({"RULE C"})),
        run("r5", 0.1, verdict=FP, sessions=(("1:abc=", at(0.1)),)),
        run("s1b", 0.05, sessions=(("1:abc=", at(0.05)),)),
        _cited_finding(),
        run("r9", 500, src=A3, dst=T3),
    ]
    expected = jsonable(build_campaigns(facts))
    assert len(expected) == 2
    rng = random.Random(7)
    for _ in range(20):
        shuffled = facts[:]
        rng.shuffle(shuffled)
        assert jsonable(build_campaigns(shuffled)) == expected


# ── Stages ───────────────────────────────────────────────────────────────


def test_the_ladder_states_each_stage_with_its_proof() -> None:
    facts = [
        run("r1"),
        run("r2", 1, impact="succeeded", documents=(doc("d-alert", 1, is_alert=True),)),
        finding("f3", 2, impact="succeeded", stage_claim="action", cited_ids=("d9",)),
        run("r4", 3),
    ]
    draft = only(build_campaigns(facts))
    ladder = {s.stage: s for s in draft.ladder}
    assert [s.stage for s in draft.ladder] == [
        "reconnaissance",
        "attempt",
        "access",
        "action",
        "movement",
    ]
    assert [s.reached for s in draft.ladder] == [False, True, True, True, False]
    assert (
        ladder["attempt"].members,
        ladder["attempt"].first_at,
        ladder["attempt"].proof_run_id,
    ) == (2, at(0), "r1")
    assert (ladder["access"].proof_run_id, ladder["access"].proof_document_id) == ("r2", "d-alert")
    assert (ladder["action"].proof_run_id, ladder["action"].proof_document_id) == ("f3", "d9")
    assert ladder["reconnaissance"].first_at is None
    assert draft.stage == "action"


def test_a_stage_states_the_label_and_the_time_of_its_proof_document() -> None:
    proof = doc("d-alert", 1.5, is_alert=True, label="EXPLOIT RULE 9")
    facts = [
        run("r1"),
        run(
            "r2",
            1,
            impact="succeeded",
            documents=(doc("d-other", 1), proof),
            cited_ids=("d-alert",),
        ),
        finding("f3", 2, impact="succeeded", stage_claim="action", cited_ids=("d9",)),
    ]
    ladder = {s.stage: s for s in only(build_campaigns(facts)).ladder}
    access = ladder["access"]
    assert (access.proof_document_id, access.proof_label, access.proof_at) == (
        "d-alert",
        "EXPLOIT RULE 9",
        at(1.5),
    )
    # NEGATIVE CONTROL: a proof id that the run holds no document for has no label and no time.
    action = ladder["action"]
    assert (action.proof_document_id, action.proof_label, action.proof_at) == ("d9", "", None)
    # A stage that no member reaches has no proof.
    assert (ladder["movement"].proof_label, ladder["movement"].proof_at) == ("", None)


def test_a_scan_is_reconnaissance_also_when_it_got_answers() -> None:
    draft = only(build_campaigns([run("r1", attack_class="recon", impact="succeeded")]))
    assert member(draft, "r1").stage == "reconnaissance"
    assert draft.stage == "reconnaissance"


def test_a_post_compromise_alert_is_an_attempt_until_its_impact_reads_succeeded() -> None:
    plain = only(build_campaigns([run("r1", attack_class="post_compromise")]))
    assert member(plain, "r1").stage == "attempt"
    proven = only(build_campaigns([run("r1", attack_class="post_compromise", impact="succeeded")]))
    assert member(proven, "r1").stage == "access"


def test_a_claim_of_movement_needs_the_structure() -> None:
    draft = only(build_campaigns([finding("f1", impact="succeeded", stage_claim="movement")]))
    assert member(draft, "f1").stage == "action"


def test_a_finding_with_no_claim_reads_its_impact() -> None:
    facts = [
        finding("f1"),
        finding("f2", 1, impact="attempted"),
        finding("f3", 2, impact="succeeded"),
    ]
    draft = only(build_campaigns(facts))
    assert [m.stage for m in draft.members] == [None, "attempt", "access"]


def test_a_campaign_with_no_proven_stage() -> None:
    assert only(build_campaigns([finding("f1")])).stage is None


# ── Parties, waves and evidence ──────────────────────────────────────────


def test_the_alert_documents_of_a_finding_add_its_targets() -> None:
    documents = (
        doc("d1", 0, dst=T2, is_alert=True),
        doc("d2", 0, dst=T3, is_alert=True),
        doc("d3", 0, src=T1, dst=X1, is_alert=True),
        doc("d4", 0, dst=X1, dataset="zeek.dns", target_port=53),
    )
    draft = only(build_campaigns([finding("f1", documents=documents)]))
    # A name lookup of the actor names no target, and a document of another
    # source machine names none.
    assert roles(draft) == {A1: "actor", T1: "target", T2: "target", T3: "target"}
    party = {p.machine_key: p for p in draft.parties}
    assert party[T2].addresses == ("198.51.100.11",)
    assert (party[A1].name, party[A1].join, party[A1].member_runs) == ("actor-a", "agent", 1)
    assert (party[T1].name, party[T1].join) == ("web-1", "network")


def test_the_parties_are_the_actors_first() -> None:
    draft = only(build_campaigns([run("r1"), run("r2", 2, src=A2)]))
    assert [p.machine_key for p in draft.parties] == [A1, A2, T1]
    assert [(p.first_event, p.last_event) for p in draft.parties] == [
        (at(0), at(0)),
        (at(2), at(2)),
        (at(0), at(2)),
    ]


def test_the_waves_of_an_actor() -> None:
    facts = [run("r1"), run("r2", 5 / 60), run("r3", 125 / 60), run("r4", 1, src=A2)]
    draft = only(build_campaigns(facts))
    by_actor = {w.machine_key: w.waves for w in draft.waves}
    assert [(w.n, w.start, w.end, w.events) for w in by_actor[A1]] == [
        (1, at(0), at(5 / 60), 2),
        (2, at(125 / 60), at(125 / 60), 1),
    ]
    assert [(w.n, w.events) for w in by_actor[A2]] == [(1, 1)]


def test_the_sessions_between_parties_on_a_port_with_no_alert() -> None:
    documents = (
        doc("d-alert", 0, is_alert=True, dataset="suricata.alert"),
        doc("d-http", 0.01),
        doc("d-ssh1", -22, target_port=22, dataset="zeek.conn"),
        doc("d-ssh2", 0.1, target_port=22, dataset="zeek.ssh"),
        doc("d-out", 0.2, src=T1, dst=X1, target_port=443),
        doc("d-untimed", 0, target_port=22, at=None),
    )
    draft = only(build_campaigns([finding("f1", documents=documents)]))
    assert len(draft.sessions) == 1
    group = draft.sessions[0]
    assert (group.source, group.target, group.port, group.dataset) == (A1, T1, 22, "zeek.conn")
    assert (group.documents, group.first_at, group.last_at) == (2, at(-22), at(0.1))
    assert group.document_ids == ("d-ssh1", "d-ssh2")


def test_a_named_host_that_is_no_end_of_the_campaign() -> None:
    documents = (
        doc("d1", 0, named=("files.example.test", "198.51.100.10", "web-1", "192.0.2.1")),
        doc("d2", 0.1, named=("files.example.test",)),
    )
    draft = only(build_campaigns([run("r1", documents=documents)]))
    assert [(n.value, n.documents, n.document_ids) for n in draft.named] == [
        ("files.example.test", 2, ("d1", "d2"))
    ]


def test_a_document_of_other_hosts_names_no_host_for_the_campaign() -> None:
    documents = (
        doc("d1", 0, src=A2, dst=X1, named=("mirror.example.test",)),
        doc("d2", 0, dst=None, named=("mirror.example.test",)),
    )
    assert only(build_campaigns([finding("f1", documents=documents)])).named == ()


def test_the_detection_record_names_the_first_verdict_of_each_stage() -> None:
    facts = [
        run("r1", finished_at=at(0) + timedelta(hours=30)),
        finding("f2", 1, impact="attempted", finished_at=at(1) + timedelta(minutes=10)),
        finding(
            "f3", 2, impact="succeeded", finished_at=at(2) + timedelta(seconds=90), tier="lead_hunt"
        ),
    ]
    draft = only(build_campaigns(facts))
    assert [(d.stage, d.tier, d.run_id, d.seconds) for d in draft.detection] == [
        ("attempt", "scheduled_hunt", "f2", 600),
        ("access", "lead_hunt", "f3", 90),
    ]


# ── The arrows of the attack graph ───────────────────────────────────────


def edges(draft: CampaignDraft) -> list[tuple[str, str, int, str | None, bool, bool]]:
    return [(e.source, e.target, e.runs, e.stage, e.beyond, e.from_documents) for e in draft.edges]


def test_an_arrow_counts_the_runs_of_two_machines_and_states_their_highest_stage() -> None:
    facts = [
        run("r1"),
        run("r2", 1, impact="succeeded"),
        run("r3", 2, src=A2),
        run("r4", 3, verdict=FP, sessions=(("1:abc=", at(3)),)),
        run("r5", 3, sessions=(("1:abc=", at(3)),)),
    ]
    draft = only(build_campaigns(facts))
    assert edges(draft) == [
        (A1, T1, 3, "access", False, False),
        (A2, T1, 1, "attempt", False, False),
    ]
    first = draft.edges[0]
    assert (first.first_at, first.last_at) == (at(0), at(3))


def test_a_run_on_the_answer_of_the_server_counts_on_the_arrow_of_its_actor() -> None:
    answer = run("r2", 0.02, src=T1, dst=A1, rules=frozenset({"RULE B"}))
    draft = only(build_campaigns([run("r1", impact="succeeded"), answer]))
    assert edges(draft) == [(A1, T1, 2, "access", False, False)]


def test_an_arrow_from_a_target_that_an_attack_worked_on_reads_beyond() -> None:
    facts = [
        run("r1", impact="succeeded"),
        run("r2", 1, src=T1, dst=X1, rules=frozenset({"RULE B"})),
    ]
    draft = only(build_campaigns(facts))
    assert edges(draft) == [
        (A1, T1, 1, "access", False, False),
        (T1, X1, 1, "movement", True, False),
    ]


def test_a_target_that_only_an_alert_document_shows_gets_an_arrow_with_no_stage() -> None:
    documents = (
        doc("d1", 0, dst=T2, is_alert=True),
        doc("d2", 0, dst=T2, is_alert=True),
        doc("d3", 0, dst=T1, is_alert=True),
        doc("d4", 0, dst=T3, dataset="zeek.dns"),
    )
    draft = only(build_campaigns([finding("f1", impact="attempted", documents=documents)]))
    assert edges(draft) == [(A1, T1, 1, "attempt", False, False), (A1, T2, 1, None, False, True)]
    # Each target party has an arrow into it.
    targets = {p.machine_key for p in draft.parties if p.role == "target"}
    assert {e.target for e in draft.edges} == targets


def test_a_run_with_no_target_machine_draws_no_arrow() -> None:
    draft = only(build_campaigns([run("r1"), run("r2", 1, dst=None, rules=frozenset({"RULE B"}))]))
    assert edges(draft) == [(A1, T1, 1, "attempt", False, False)]


# ── The reference case ───────────────────────────────────────────────────


def _reference_case() -> list[RunFacts]:
    """Three actors test one web application for 19 days.

    Actor c opens with three alerts and a finding. Actor b follows in hour
    20, actor a from hour 21. On day 4 a finding proves a command through a
    web shell. Then 235 hours pass, more than one horizon. Actor a uses the
    same rule again, and a finding on day 19 proves a file read. The target
    also fetches package updates: twelve false positive runs.
    """
    cve = frozenset({"CVE-2026-10000"})
    rules = [frozenset({f"EXPLOIT RULE {n}"}) for n in (1, 2, 3)]
    facts: list[RunFacts] = []
    for i, rule in enumerate(rules):
        facts.append(
            run(f"c{i}", 0.01 * i, src=A3, rules=rule, cves=cve, sessions=((f"1:c{i}=", at(0)),))
        )
    ssh = (
        doc("ssh-day-before", -22, src=A3, target_port=22, dataset="zeek.conn"),
        doc("ssh-c", 0.08, src=A3, target_port=22, dataset="zeek.ssh"),
        doc("alert-c", 0, src=A3, is_alert=True, dataset="suricata.alert"),
    )
    facts.append(finding("c-finding", 0.1, src=A3, documents=ssh))
    for i, rule in enumerate(rules):
        facts.append(run(f"b{i}", 20 + 0.01 * i, src=A2, rules=rule, cves=cve))
    for i, rule in enumerate(rules):
        facts.append(run(f"a{i}", 21 + 0.01 * i, src=A1, rules=rule, cves=cve))
    shell = (doc("shell-get", 96, cited=True, named=("198.51.100.10",)),)
    facts.append(
        finding(
            "a-shell",
            96,
            impact="succeeded",
            stage_claim="action",
            cited_ids=("shell-get",),
            documents=shell,
        )
    )
    facts.append(run("a-again", 96 + 235, rules=rules[2], cves=cve))
    facts.append(run("b-again", 96 + 260, src=A2, rules=rules[0], cves=cve))
    facts.append(finding("a-read", 19 * 24, impact="succeeded", cited_ids=("read-get",)))
    for i in range(12):
        facts.append(
            run(
                f"update{i}",
                30 + i,
                src=T1,
                dst=None,
                verdict=FP,
                attack_class="",
                rules=frozenset({"PACKAGE RULE"}),
                sessions=((f"1:u{i}=", at(30 + i)),),
            )
        )
    facts.append(
        run("needs-info", 97, verdict="needs_more_info", attack_class="finding", kind="finding")
    )
    return facts


def test_the_reference_case_is_one_campaign() -> None:
    draft = only(build_campaigns(_reference_case()))
    assert roles(draft) == {A3: "actor", A2: "actor", A1: "actor", T1: "target"}
    assert [p.machine_key for p in draft.parties] == [A3, A2, A1, T1]
    assert len(draft.members) == 14
    assert not any(m.run.run_id.startswith("update") for m in draft.members)
    assert "needs-info" not in draft.run_ids
    assert draft.seed_run_id == "c0"
    assert (draft.first_event, draft.last_event) == (at(0), at(19 * 24))

    assert [s.reached for s in draft.ladder] == [False, True, True, True, False]
    ladder = {s.stage: s for s in draft.ladder}
    assert (ladder["action"].proof_run_id, ladder["action"].proof_document_id) == (
        "a-shell",
        "shell-get",
    )
    assert (ladder["access"].proof_run_id, ladder["access"].first_at) == ("a-read", at(19 * 24))
    assert draft.stage == "action"
    assert draft.beyond_runs == 0

    # The run after the gap of 235 hours joins by its rule.
    again = member(draft, "a-again").link
    assert (again.type, again.artifact) == ("artifact", "rule: EXPLOIT RULE 3")
    # The nearest earlier member with a shared artifact is the evidence.
    late = member(draft, "b-again").link
    assert (late.type, late.member_run_id, late.artifact) == (
        "artifact",
        "a-again",
        "cve: CVE-2026-10000",
    )
    assert member(draft, "a-read").link.type == "actor"
    assert member(draft, "b0").link.type == "artifact"

    # The administration sessions are related, and are no part of the waves.
    assert [(s.source, s.port, s.documents, s.first_at) for s in draft.sessions] == [
        (A3, 22, 2, at(-22))
    ]
    assert draft.named == ()
    waves = {w.machine_key: [(x.start, x.events) for x in w.waves] for w in draft.waves}
    assert waves[A3] == [(at(0), 4)]
    assert [start for start, _ in waves[A1]] == [at(21), at(96), at(96 + 235), at(19 * 24)]


# ── A finding that names the two machines of a campaign ───────────────────────


def named(run_id: str, hours: float, machines: tuple[str, ...], **over: Any) -> RunFacts:
    """A finding run that cites summary queries: a target, no source, and the
    machines that its finding names."""
    base: dict[str, Any] = {
        "kind": "finding",
        "src": None,
        "attack_class": "finding",
        "impact": "attempted",
        "rules": frozenset(),
        "label": "File read on web-1",
        "named_machines": machines,
    }
    base.update(over)
    return run(run_id, hours, **base)


def test_a_finding_that_names_the_pair_of_a_campaign_joins_it() -> None:
    seed = run("r1")
    finding = named("f1", 50, (A1, T1))
    draft = only(build_campaigns([seed, finding]))
    found = member(draft, "f1")
    assert (found.link.type, found.link.member_run_id, found.link.machine) == (
        "named_pair",
        "r1",
        A1,
    )
    assert (found.run.source, found.run.source_join) == (A1, "named")
    assert (found.run.source_address, found.run.source_name) == (ADDRESS[A1], NAME[A1])
    assert found.verdict_differs is False
    assert roles(draft) == {A1: "actor", T1: "target"}
    assert draft.last_event == at(50)


def test_a_finding_that_names_a_pair_starts_no_campaign() -> None:
    """The names prove no direction. With no proven attack of the pair, the
    finding forms no campaign and joins none."""
    assert build_campaigns([named("f1", 0, (A1, T1))]) == []
    other = run("r1", src=A2, dst=T1)
    draft = only(build_campaigns([other, named("f1", 1, (A1, T1))]))
    assert [m.run.run_id for m in draft.members] == ["r1"]
    assert roles(draft) == {A2: "actor", T1: "target"}


def test_a_finding_that_names_the_pair_in_the_other_direction_stays_out() -> None:
    """The campaign proves an attack of A1 on T1. A finding whose target is A1
    and that names T1 states the other direction, which no member proves."""
    seed = run("r1")
    back = named("f1", 1, (A1, T1), dst=A1)
    draft = only(build_campaigns([seed, back]))
    assert [m.run.run_id for m in draft.members] == ["r1"]


def test_a_finding_that_names_three_machines_stays_out() -> None:
    seed = run("r1")
    wide = named("f1", 1, (A1, A2, T1))
    assert [m.run.run_id for m in only(build_campaigns([seed, wide])).members] == ["r1"]


def test_a_finding_that_names_the_pair_after_one_horizon_stays_out() -> None:
    seed = run("r1")
    late = named("f1", 300, (A1, T1))
    assert [
        m.run.run_id for m in only(build_campaigns([seed, late], horizon_hours=200)).members
    ] == ["r1"]


def test_a_named_finding_with_another_verdict_stays_out() -> None:
    """A finding that its investigation refuted names the pair. It has no
    session, so it joins nothing."""
    seed = run("r1")
    refuted = named("f1", 2, (A1, T1), verdict=FP)
    assert [m.run.run_id for m in only(build_campaigns([seed, refuted])).members] == ["r1"]


def test_a_named_finding_with_the_target_only_stays_out() -> None:
    """The finding names the target and no other machine."""
    seed = run("r1")
    alone = named("f1", 1, (T1,))
    assert [m.run.run_id for m in only(build_campaigns([seed, alone])).members] == ["r1"]


def test_a_named_finding_passes_no_link_on() -> None:
    """A second campaign has the same target. The named finding is near both.
    It joins the campaign of its pair, and the two campaigns stay apart."""
    first = run("r1")
    second = run("s1", 400, src=A2, rules=frozenset({"RULE B"}))
    finding = named("f1", 100, (A1, T1))
    drafts = build_campaigns([first, second, finding], horizon_hours=150)
    assert len(drafts) == 2
    holder = next(d for d in drafts if "f1" in d.run_ids)
    assert set(holder.run_ids) == {"r1", "f1"}


def test_a_named_finding_gives_the_same_campaign_in_each_order() -> None:
    runs = [run("r1"), run("r2", 2), named("f1", 50, (A1, T1)), named("f2", 60, (A1, T1))]
    expect = jsonable(build_campaigns(runs))
    rng = random.Random(7)
    for _ in range(6):
        mixed = runs[:]
        rng.shuffle(mixed)
        assert jsonable(build_campaigns(mixed)) == expect


# ── Exclude and Include by an analyst ─────────────────────────────────────────


def test_an_excluded_run_joins_no_campaign_and_passes_no_link_on() -> None:
    """r2 links r1 and r3 by its session and its actor. With r2 out, r3 has no
    link to r1 inside one horizon, so two campaigns form."""
    r1 = run("r1", sessions=(("1:a=", at(0)),))
    r2 = run("r2", 150, sessions=(("1:a=", at(0.1)),))
    r3 = run("r3", 300, rules=frozenset({"RULE B"}))
    assert [set(d.run_ids) for d in build_campaigns([r1, r2, r3], horizon_hours=200)] == [
        {"r1", "r2", "r3"}
    ]
    drafts = build_campaigns([r1, r2, r3], horizon_hours=200, excluded={"r2"})
    assert [set(d.run_ids) for d in drafts] == [{"r1"}, {"r3"}]


def test_an_excluded_seed_leaves_the_other_runs_their_own_campaign() -> None:
    drafts = build_campaigns([run("r1"), run("r2", 1)], excluded={"r1"})
    assert [d.run_ids for d in drafts] == [("r2",)]


def test_an_included_run_joins_the_campaign_of_its_anchor() -> None:
    """A run with a verdict that needs more information has no session of the
    campaign. The analyst joins it to the campaign of r1."""
    seed = run("r1")
    other = run("n1", 5, src=A2, dst=T2, verdict="needs_more_info")
    draft = only(build_campaigns([seed, other], included={"n1": "r1"}))
    found = member(draft, "n1")
    assert (found.link.type, found.link.member_run_id) == ("included", "r1")
    assert found.verdict_differs is True
    assert roles(draft) == {A1: "actor", T1: "target"}


def test_an_included_run_with_no_anchor_in_a_campaign_joins_nothing() -> None:
    seed = run("r1")
    other = run("n1", 5, src=A2, dst=T2, verdict="needs_more_info")
    draft = only(build_campaigns([seed, other], included={"n1": "gone"}))
    assert draft.run_ids == ("r1",)


def test_an_exclusion_wins_over_an_inclusion() -> None:
    seed = run("r1")
    other = run("n1", 5, src=A2, dst=T2, verdict="needs_more_info")
    drafts = build_campaigns([seed, other], included={"n1": "r1"}, excluded={"n1"})
    assert only(drafts).run_ids == ("r1",)
    assert build_campaigns([seed, other], included={"n1": "r1"}, excluded={"r1"}) == []


def test_an_included_run_that_a_link_proves_reads_the_proven_link() -> None:
    seed = run("r1")
    later = run("r2", 2)
    draft = only(build_campaigns([seed, later], included={"r2": "r1"}))
    assert member(draft, "r2").link.type == "actor"


def test_an_included_run_starts_no_campaign_and_merges_no_two() -> None:
    first = run("r1")
    second = run("s1", 400, src=A2, dst=T2, rules=frozenset({"RULE B"}))
    other = run("n1", 5, src=A3, dst=T3, verdict="needs_more_info")
    drafts = build_campaigns([first, second, other], horizon_hours=100, included={"n1": "r1"})
    assert len(drafts) == 2
    assert next(set(d.run_ids) for d in drafts if "n1" in d.run_ids) == {"r1", "n1"}
