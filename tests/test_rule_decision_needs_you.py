"""The rules with open false positives in Needs you (round 3, RS3).

``GET /needs-you`` gains ``rules_waiting``, and ``decisions`` adds it.
``GET /needs-you/items`` gains one item for each rule with one or more open
false positives, after the other investigations and before the alert groups.
Inside the group the count of the group confident decides first, then the
newest event. The count and the list read one summary, so they agree.

The data is synthetic.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui import needs_you_facts as ny_facts
from soc_ai.api.webui import routes_meta
from soc_ai.store import rule_decisions as rd_store
from soc_ai.store.auth import utcnow
from soc_ai.webui import rule_decisions as rd

from tests.test_rule_decision_api import client, run, seed  # noqa: F401 - the shared fixture
from tests.test_rule_decision_selection import OTHER_RULE, RULE

THIRD_RULE = "ET SCAN ws-1 port sweep"


@pytest.fixture
def groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """The alert part, fixed: the fake grid answers no aggregation."""

    async def two(_request: Any) -> tuple[int, bool]:
        return 2, False

    monkeypatch.setattr(routes_meta, "_cached_untriaged_groups", two)


def _seed_mix(c: TestClient) -> None:
    for n in range(3):
        seed(c, f"ev-a{n}", confidence=0.8 + n / 100, src_ip=f"192.0.2.{20 + n}")
    seed(c, "ev-a-weak", reason="below_threshold", confidence=0.4)
    seed(c, "ev-b1", rule=OTHER_RULE, reason="uncited", confidence=0.6)
    seed(c, "ev-c1", rule=THIRD_RULE)
    seed(c, "ev-tp", rule=RULE, verdict="true_positive", actions=[])

    async def acked(maker: Any) -> None:
        async with maker() as db:
            await rd_store.record_states(db, {"ev-c1": "acknowledged"}, at=utcnow())

    run(c, acked)


def test_the_count_and_the_list_state_the_same_rules(
    client: TestClient,  # noqa: F811
    groups: None,
) -> None:
    """NEGATIVE CONTROL: the count of Needs you equals the list for a seeded mix,
    and an alert that the grid states as acknowledged is in no count."""
    _seed_mix(client)

    count = client.get("/api/v1/needs-you").json()
    items = client.get("/api/v1/needs-you/items").json()

    assert count["unknown"] == [] and items["unknown"] == []
    assert count["rules_waiting"] == 2
    assert count["decisions"] == items["total"]
    assert count["decisions"] == (
        count["campaigns"]
        + count["investigations_waiting"]
        + count["leads_needing_decision"]
        + count["untriaged_groups"]
        + count["rules_waiting"]
    )
    rules = [i for i in items["items"] if i["type"] == "rule"]
    assert [r["title"] for r in rules] == [RULE, OTHER_RULE]
    first = rules[0]
    assert first["id"] == rd.rule_key(RULE)
    assert first["href"] == f"/needs-you/rule/{rd.rule_key(RULE)}"
    assert (first["count"], first["confident"], first["weak"]) == (4, 3, 1)
    assert first["verdict"] == "false_positive" and first["impact"] is None
    assert first["confidence"] == pytest.approx(0.81)
    assert first["severity"] is None
    assert first["since"] is not None and first["eventAt"] is not None
    assert first["why"] == (
        "soc-ai holds the acknowledge of 4 false positives of this rule. "
        "3 have checked evidence, and 1 has weak evidence."
    )
    assert first["action"]["label"] == "Decide on the rule"
    assert first["machines"][0]["address"] == "203.0.113.5"
    assert first["machinesMore"] == 2
    # After the other investigations and before the alert groups.
    order = [i["type"] for i in items["items"]]
    assert order.index("rule") > max(
        (n for n, t in enumerate(order) if t == "investigation"), default=-1
    )
    assert order[-1] == "alerts"


def test_the_row_of_a_rule_states_the_end_of_its_standing_decision(
    client: TestClient,  # noqa: F811
    groups: None,
) -> None:
    seed(client, "ev-b1", rule=OTHER_RULE, reason="high_stakes")

    async def ended(maker: Any) -> None:
        async with maker() as db:
            row = rd_store.new_decision(
                rule_name=OTHER_RULE,
                decision="standing",
                include_weak=False,
                note="",
                by="analyst1",
                at=utcnow() - timedelta(days=2),
                ends_at=utcnow() + timedelta(days=28),
            )
            rd_store.end_decision(row, cause="true_positive", at=utcnow() - timedelta(days=1))
            db.add(row)
            await db.commit()

    run(client, ended)

    items = client.get("/api/v1/needs-you/items").json()

    (rule,) = [i for i in items["items"] if i["type"] == "rule"]
    assert rule["why"] == (
        "soc-ai holds the acknowledge of 1 false positive of this rule. It has checked evidence. "
        "The standing decision of this rule ended, because an investigation of the rule "
        "gave a true positive verdict."
    )


def test_a_decision_takes_the_rule_out_of_the_count(
    client: TestClient,  # noqa: F811
    groups: None,
) -> None:
    from tests.test_rule_decision_api import decide, grid, writer

    grid(client).add("ev-a0")
    seed(client, "ev-a0")
    assert client.get("/api/v1/needs-you").json()["rules_waiting"] == 1

    assert decide(client, writer(client)).status_code == 202

    count = client.get("/api/v1/needs-you").json()
    assert count["rules_waiting"] == 0
    assert all(i["type"] != "rule" for i in client.get("/api/v1/needs-you/items").json()["items"])


def test_inside_the_group_the_confident_count_decides_then_the_newest_event() -> None:
    def item(rule_id: str, confident: int, at: str) -> Any:
        return SimpleNamespace(
            type="rule", id=rule_id, confident=confident, eventAt=at, verdict="false_positive"
        )

    lead = SimpleNamespace(type="lead", id="7", eventAt=None, verdict=None)
    other = SimpleNamespace(type="investigation", id="9", eventAt=None, verdict="needs_more_info")
    alerts = SimpleNamespace(type="alerts", id="alerts", eventAt=None, verdict="untriaged")
    rows = [
        alerts,
        item("small-new", 1, "2026-11-18T10:00:00+00:00"),
        item("big", 470, "2026-11-01T10:00:00+00:00"),
        item("small-old", 1, "2026-11-10T10:00:00+00:00"),
        other,
        lead,
    ]
    ordered = [r.id for r in sorted(rows, key=ny_facts.order_key)]
    assert ordered == ["7", "9", "big", "small-new", "small-old", "alerts"]
