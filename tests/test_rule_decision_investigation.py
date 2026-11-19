"""The investigation page and the rule decision (round 3, RS6).

The payload of an investigation gains ``ruleDecision``: null, or the page of
its rule, the count of the open false positives of the rule and the group of
this one, when the investigation is an open false positive. Each recommended
action gains ``ruleDecisionReceipt`` when a rule decision carried out its
acknowledge. The sentence of the hold (``_ack_pending_note``) keeps its words.

The grid is a fake, and the data is synthetic.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient
from soc_ai.api.webui._timeline import _ack_pending_note, _build_actions
from soc_ai.webui import rule_decisions as rd

from tests.test_rule_decision_api import client, decide, grid, seed, writer  # noqa: F401
from tests.test_rule_decision_selection import RULE, ack_action

KEY = rd.rule_key(RULE)


def _event(kind: str, payload: dict[str, Any], sequence: int = 1) -> Any:
    return SimpleNamespace(kind=kind, payload=payload, sequence=sequence)


def test_a_receipt_of_a_rule_decision_names_the_decision() -> None:
    action = ack_action("ev-1")
    report = {"recommended_actions": [action]}
    row = SimpleNamespace(action_index=0, action=action, rule_name=RULE)
    receipt = rd.receipt(
        row, decision_id=7, by="analyst1", at="2026-11-18T10:00:00+00:00", already=False
    )  # type: ignore[arg-type]

    (card,) = _build_actions([_event("action_executed", receipt)], report)

    assert card.applied is True
    assert card.ruleDecisionReceipt is not None
    assert card.ruleDecisionReceipt.model_dump() == {
        "id": 7,
        "at": "2026-11-18T10:00:00+00:00",
        "href": f"/needs-you/rule/{KEY}",
    }


def test_an_acknowledge_under_a_standing_decision_names_it_too() -> None:
    report = {"recommended_actions": [ack_action("ev-1")]}
    auto = _event("auto_ack", {"success": True, "rule_decision": 3, "rule_key": KEY})

    (card,) = _build_actions([auto], report, ran_at="2026-11-18T09:00:00+00:00")

    assert card.ruleDecisionReceipt is not None
    assert (card.ruleDecisionReceipt.id, card.ruleDecisionReceipt.at) == (
        3,
        "2026-11-18T09:00:00+00:00",
    )


def test_an_acknowledge_with_no_rule_decision_has_no_receipt() -> None:
    """NEGATIVE CONTROL: an analyst press and a plain automatic acknowledge."""
    report = {"recommended_actions": [ack_action("ev-1")]}
    press = _event("action_executed", {"tool_name": "ack_alert", "success": True, "index": 0})
    auto = _event("auto_ack", {"success": True})
    for events in ([press], [auto], []):
        (card,) = _build_actions(events, report)
        assert card.ruleDecisionReceipt is None


def test_the_sentence_of_the_hold_states_one_reason() -> None:
    held = _event("auto_ack_skipped", {"reason": "high_stakes"})
    assert _ack_pending_note([held]) == (
        "soc-ai holds this acknowledge. The alert is high or critical, or a malware or "
        "exploit alert."
    )
    # The card and the page of the rule read the same label.
    from soc_ai.webui.rule_decisions import hold_label

    assert hold_label("high_stakes") in str(_ack_pending_note([held]))


def test_the_page_of_an_open_false_positive_links_its_rule(client: TestClient) -> None:  # noqa: F811
    for alert in ("ev-1", "ev-2", "ev-tp"):
        grid(client).add(alert)
    first = seed(client, "ev-1")
    weak = seed(client, "ev-2", reason="below_threshold", confidence=0.5)
    # The true positive is on another machine pair: the default decision
    # leaves the pair of a true positive open (F4).
    tp = seed(client, "ev-tp", verdict="true_positive", src_ip="198.51.100.20")

    page = client.get(f"/api/v1/investigations/{first}").json()
    assert page["ruleDecision"] == {
        "href": f"/needs-you/rule/{KEY}",
        "count": 2,
        "group": "confident",
    }
    assert client.get(f"/api/v1/investigations/{weak}").json()["ruleDecision"]["group"] == "weak"
    # NEGATIVE CONTROL: a true positive waits on no rule decision.
    assert client.get(f"/api/v1/investigations/{tp}").json()["ruleDecision"] is None

    decide(client, writer(client))

    after = client.get(f"/api/v1/investigations/{first}").json()
    assert after["ruleDecision"] is None
    (card,) = after["actions"]
    assert card["applied"] is True
    assert card["ruleDecisionReceipt"]["href"] == f"/needs-you/rule/{KEY}"


def test_an_alert_that_the_grid_states_as_acknowledged_has_no_rule_decision(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: Security Onion acknowledged the alert outside soc-ai."""
    grid(client).add("ev-1", acked=True)
    first = seed(client, "ev-1")

    assert client.get(f"/api/v1/investigations/{first}").json()["ruleDecision"] is None


def test_the_page_of_a_rule_states_the_term_of_a_standing_decision(
    client: TestClient,  # noqa: F811
) -> None:
    client.app.state.settings.rule_decision_days = 14  # type: ignore[attr-defined]

    page = client.get(f"/api/v1/rule-decisions/{KEY}").json()

    assert page["standingDays"] == 14
