"""The facts that the page of a rule states (round 3, part 2: F1 to F4).

The page of a rule prepares one decision, so each fact on it must hold on the
stored data. The plants sit on the paths that a careless read would miss: an
automatic acknowledge that a rule decision allowed, a hold after the newest
acknowledge, the acknowledges of another rule. The grid and the Security Onion
write are fakes, and the data is synthetic.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from soc_ai.webui import rule_decisions as rd

from tests.test_rule_decision_api import (  # noqa: F401 - the shared fixtures
    KEY,
    client,
    client_auto_ack_off,
    decide,
    grid,
    seed,
    writer,
)
from tests.test_rule_decision_selection import OTHER_RULE

ACKED = [("auto_ack", {"success": True})]


def page(client: TestClient) -> dict[str, Any]:  # noqa: F811
    answer = client.get(f"/api/v1/rule-decisions/{KEY}")
    assert answer.status_code == 200
    found: dict[str, Any] = answer.json()
    return found


# ── F1: a rule that soc-ai acknowledges by itself ──────────────────────────


def test_a_rule_that_soc_ai_acknowledges_by_itself_states_it(client: TestClient) -> None:  # noqa: F811
    """Holds from before a change of the guard, then acknowledges with no decision."""
    for alert in ("ev-old-1", "ev-old-2"):
        grid(client).add(alert)
        seed(client, alert, reason="high_stakes")
    for alert in ("ev-new-1", "ev-new-2", "ev-new-3"):
        seed(client, alert, reason=None, events=ACKED)

    facts = page(client)

    alone = facts["selfAcknowledging"]
    assert alone is not None
    assert alone["acknowledged"] == 3 and alone["before"] == 2
    day = alone["since"][:10]
    assert alone["sentence"] == (
        f"soc-ai acknowledges the false positives of this rule by itself since {day} UTC. "
        "The 2 here are from before that date."
    )
    # The standing choice adds nothing for the rule, and the hold reads in the past.
    assert facts["canStanding"] is False
    assert facts["canStandingWhy"].startswith("soc-ai acknowledges the false positives")
    assert facts["confident"]["reasons"] == [
        {
            "code": "high_stakes",
            "label": rd.hold_label("high_stakes", past=True),
            "count": 2,
        }
    ]
    assert rd.hold_label("high_stakes", past=True) != rd.hold_label("high_stakes")
    refused = decide(client, writer(client), decision="standing")
    assert refused.status_code == 409
    assert refused.json()["detail"]["reason"] == "rule_acknowledges_alone"


def test_an_acknowledge_under_a_rule_decision_is_no_change_of_the_guard(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: the acknowledges of a standing decision rest on the analyst."""
    grid(client).add("ev-old")
    seed(client, "ev-old", reason="high_stakes")
    seed(
        client, "ev-new", reason=None, events=[("auto_ack", {"success": True, "rule_decision": 7})]
    )

    facts = page(client)

    assert facts["selfAcknowledging"] is None
    assert facts["canStanding"] is True
    assert facts["confident"]["reasons"][0]["label"] == rd.hold_label("high_stakes")


def test_a_hold_after_the_acknowledge_keeps_the_present_tense(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL: the guard held the rule again after the acknowledge."""
    seed(client, "ev-new", reason=None, events=ACKED)
    grid(client).add("ev-later")
    seed(client, "ev-later", reason="high_stakes")

    facts = page(client)

    assert facts["selfAcknowledging"] is None and facts["canStanding"] is True


def test_a_failed_acknowledge_and_another_rule_state_nothing(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL: a failed write and the acknowledges of another rule."""
    grid(client).add("ev-old")
    seed(client, "ev-old", reason="high_stakes")
    seed(client, "ev-fail", reason=None, events=[("auto_ack", {"success": False})])
    seed(client, "ev-other", rule=OTHER_RULE, reason=None, events=ACKED)

    facts = page(client)

    assert facts["selfAcknowledging"] is None and facts["canStanding"] is True


def test_with_auto_ack_off_soc_ai_acknowledges_nothing_by_itself(
    client_auto_ack_off: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: the stored acknowledges are history once the setting is off."""
    off = client_auto_ack_off
    grid(off).add("ev-old")
    seed(off, "ev-old", reason="high_stakes")
    seed(off, "ev-new", reason=None, events=ACKED)

    facts = page(off)

    assert facts["selfAcknowledging"] is None
    assert "Automatic acknowledge is off" in facts["canStandingWhy"]


# ── F3: the window of the grid count and the plan of each choice ───────────


def _plan(facts: dict[str, Any], *, weak: bool) -> dict[str, Any]:
    (found,) = [p for p in facts["plans"] if p["includeWeak"] is weak]
    return found


def test_the_page_states_what_each_choice_writes_and_the_decision_writes_it(
    client: TestClient,  # noqa: F811
) -> None:
    g = grid(client)
    for alert in ("ev-1", "ev-2", "ev-weak", "ev-sib"):
        g.add(alert)
    seed(client, "ev-1")
    seed(client, "ev-2", reason=None)
    # The weak verdict of its own holds this alert open in the first choice.
    seed(client, "ev-weak", reason="below_threshold", confidence=0.5)

    facts = page(client)

    assert facts["openAlertsDays"] == 30 and facts["planKnown"] is True
    checked = _plan(facts, weak=False)
    assert checked == {
        "includeWeak": False,
        "investigations": 2,
        "alerts": 2,
        "inherit": 1,
        "held": 1,
        "capped": False,
        "includeTruePositivePairs": False,
    }
    both = _plan(facts, weak=True)
    assert (both["investigations"], both["alerts"], both["inherit"], both["held"]) == (3, 3, 1, 0)
    # The decision writes what the page stated for its choice.
    write = writer(client)
    assert decide(client, write).status_code == 202
    written = sorted(call.args[1]["alert_id"] for call in write.await_args_list)
    assert written == ["ev-1", "ev-2", "ev-sib"]
    assert len(written) == checked["alerts"] + checked["inherit"]
    assert not g.acked("ev-weak")


def test_the_page_reads_the_plan_once_while_the_selection_stays(client: TestClient) -> None:  # noqa: F811
    g = grid(client)
    g.add("ev-1")
    seed(client, "ev-1")
    scans: list[int] = []
    search = g.search

    async def counted(index: str, query: dict[str, Any], **kw: Any) -> Any:
        if "ids" not in query and kw.get("size"):
            scans.append(1)
        return await search(index, query, **kw)

    g.search = counted  # type: ignore[method-assign]
    page(client)
    first = len(scans)
    page(client)

    assert first >= 1 and len(scans) == first


def test_with_the_grid_down_the_count_of_the_alerts_is_unknown(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL: no plan from a grid that did not answer."""
    grid(client).add("ev-1")
    seed(client, "ev-1")
    grid(client).down = True

    facts = page(client)

    assert facts["planKnown"] is False and facts["plans"] == []


def test_a_scan_that_hits_its_limit_states_it(
    client: TestClient,  # noqa: F811
    monkeypatch: Any,
) -> None:
    from soc_ai.webui import alerts_query as aq

    monkeypatch.setattr(aq, "MAX_EVENTS", 2)
    monkeypatch.setattr(rd, "CLUSTER_SCAN_MAX", 2)
    g = grid(client)
    for alert in ("ev-1", "ev-a", "ev-b", "ev-c"):
        g.add(alert)
    seed(client, "ev-1")

    assert _plan(page(client), weak=False)["capped"] is True


# ── F4: the false positives on the machines of a true positive ─────────────

PAIR_SRC, PAIR_DST = "192.0.2.10", "203.0.113.5"
OTHER_SRC = "198.51.100.7"


def _seed_true_positive_rule(client: TestClient) -> dict[str, str]:  # noqa: F811
    g = grid(client)
    for alert in (
        "ev-pair",
        "ev-back",
        "ev-other",
        "ev-weak",
        "ev-sib-pair",
        "ev-sib-other",
        "ev-tp",
    ):
        g.add(alert)
    g.docs["ev-other"]["source"]["ip"] = OTHER_SRC
    g.docs["ev-sib-other"]["source"]["ip"] = OTHER_SRC
    # The same two machines in the other direction are the same pair.
    g.docs["ev-back"]["source"]["ip"], g.docs["ev-back"]["destination"]["ip"] = PAIR_DST, PAIR_SRC
    return {
        "pair": seed(client, "ev-pair"),
        "back": seed(client, "ev-back", src_ip=PAIR_DST, dest_ip=PAIR_SRC),
        "other": seed(client, "ev-other", src_ip=OTHER_SRC),
        "weak": seed(client, "ev-weak", reason="below_threshold", confidence=0.5),
        "tp": seed(client, "ev-tp", verdict="true_positive", reason=None),
    }


def test_the_default_decision_acknowledges_no_alert_on_the_machines_of_a_true_positive(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL of F4: the default body leaves the pair of a true positive open."""
    _seed_true_positive_rule(client)
    g = grid(client)
    write = writer(client)

    assert decide(client, write).status_code == 202

    written = sorted(call.args[1]["alert_id"] for call in write.await_args_list)
    assert written == ["ev-other", "ev-sib-other"]
    for alert in ("ev-pair", "ev-back", "ev-sib-pair", "ev-tp"):
        assert not g.acked(alert), alert


def test_the_third_choice_adds_the_machines_of_the_true_positive(client: TestClient) -> None:  # noqa: F811
    _seed_true_positive_rule(client)
    write = writer(client)

    answer = decide(client, write, includeTruePositivePairs=True)

    assert answer.status_code == 202
    assert answer.json()["includeTruePositivePairs"] is True
    written = sorted(call.args[1]["alert_id"] for call in write.await_args_list)
    assert written == ["ev-back", "ev-other", "ev-pair", "ev-sib-other"]
    # NEGATIVE CONTROL: the true positive keeps its own alert open whatever the
    # choice, and a sibling with no run of its own inherits that true positive.
    assert not grid(client).acked("ev-tp") and not grid(client).acked("ev-sib-pair")


def test_the_page_states_the_false_positives_on_the_machines_of_a_true_positive(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_true_positive_rule(client)

    facts = page(client)

    # The weak one sits on the pair too: the seed gives it the same ends.
    assert facts["truePositivePairs"] == {"confident": 2, "weak": 1}
    marked = {m["key"]: m["truePositive"] for m in facts["machines"]}
    assert marked[PAIR_SRC] is True and marked[PAIR_DST] is True
    assert marked[OTHER_SRC] is False
    main = [p for p in facts["plans"] if not p["includeWeak"] and not p["includeTruePositivePairs"]]
    third = [p for p in facts["plans"] if not p["includeWeak"] and p["includeTruePositivePairs"]]
    assert main[0]["investigations"] == 1 and main[0]["inherit"] == 1
    assert third[0]["investigations"] == 3


def test_a_rule_with_no_true_positive_offers_no_third_choice(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL: no pair of a true positive, no third choice."""
    grid(client).add("ev-1")
    seed(client, "ev-1")

    facts = page(client)

    assert facts["truePositivePairs"] == {"confident": 0, "weak": 0}
    assert all(p["includeTruePositivePairs"] is False for p in facts["plans"])
    assert all(m["truePositive"] is False for m in facts["machines"])


# ── F7: the refusal names its cause once ───────────────────────────────────


def test_the_refusal_of_a_rule_with_a_true_positive_states_its_cause_once(
    client: TestClient,  # noqa: F811
) -> None:
    """The console puts "soc-ai offers no standing decision" before the cause."""
    grid(client).add("ev-1")
    seed(client, "ev-1")
    seed(client, "ev-tp", verdict="true_positive", src_ip=OTHER_SRC)

    why = page(client)["canStandingWhy"]

    assert why == "This rule holds a true positive verdict that stands."
    assert "standing decision" not in why
