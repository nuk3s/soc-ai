"""One rule decides whether the console may execute a recommended action (V3-N2).

The verify of 2026-10-20 found the surfaces apart. On a lead run, and on an
alert run that a promoted lead anchors, the row of the pending-action list and
the execute route refused "Escalate to case". The action card of the run page
offered the same write enabled, because it read the kind of the run and
nothing else. The row then gave the reason of a promoted finding for a real
alert (V3-N3). On the range 8 of the 9 actions in the needs-you count were on
promoted findings, and no person could execute one of them.

:func:`soc_ai.api.webui.action_rules.action_block` now decides for the card,
the row, the needs-you count and the execute route. The negative controls
plant each case on the path a surface missed:

* A lead run has kind "lead". The card read kind "hunt" only.
* An alert run has kind "suricata". A promoted lead anchors its alert, and
  only an anchor read sees that. The anchor rule refuses the write only when
  the anchor is not in the alert feed (tests/test_anchor_real_alert.py), so
  these tests plant the anchor as telemetry.
* A standing alert run with an executable escalate still counts, so the test
  fails if the count drops every action.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui import action_rules
from soc_ai.api.webui.action_rules import ActionFacts, action_block, block_reason

from tests.anchor_grid import install
from tests.test_needs_you_count import client  # noqa: F401 - the shared fixture
from tests.test_pending_action_rows import _ESCALATE, _pending_rows, _seed, _waiting

# The anchor is not a Security Onion alert, so the sentence names a document.
_ANCHORED_BY_LEAD = (
    "A promoted lead uses this document as its anchor. The document is not a Security Onion alert."
)
_ANCHORED_BY_FINDING = (
    "A promoted finding uses this document as its anchor. "
    "The document is not a Security Onion alert."
)


def _hunt_subject(client: TestClient, run_id: str) -> None:  # noqa: F811
    """Make a seeded run a hunt subject, the way a lead promotion lands it."""
    from soc_ai.store.models import Investigation

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            inv = await db.get(Investigation, run_id)
            assert inv is not None
            inv.subject_json = {"type": "hunt", "hunt_id": "H-1"}
            await db.commit()

    asyncio.run(go())


def _detail(client: TestClient, run_id: str) -> dict[str, Any]:  # noqa: F811
    res = client.get(f"/api/v1/investigations/{run_id}")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _needs_you_actions(client: TestClient) -> int:  # noqa: F811
    with patch(
        "soc_ai.api.webui.routes_meta._cached_untriaged_groups",
        AsyncMock(return_value=(0, False)),
    ):
        res = client.get("/api/v1/needs-you")
    assert res.status_code == 200, res.text
    count: int = res.json()["pending_actions"]
    return count


def _execute(client: TestClient, run_id: str) -> Any:  # noqa: F811
    calls: list[str] = []

    async def fn(alert_id: str, **_: Any) -> dict[str, Any]:
        calls.append(alert_id)
        return {"id": "case-1", "alert_linked": True, "marked_escalated": True}

    from soc_ai.tools._registry import ToolSpec

    tool = ToolSpec(name="escalate_to_case", read_only=False, description="", func=fn)
    with (
        patch("soc_ai.tools.write_exec.get_tool", return_value=tool),
        patch("soc_ai.api.webui.routes_actions._reserve_escalate", AsyncMock(return_value=None)),
    ):
        res = client.post(f"/api/v1/investigations/{run_id}/actions/0/execute")
    return res, calls


# ── The card, the row and the route agree ──────────────────────────────────


def test_a_lead_run_offers_no_write_on_the_card(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL on the path the card missed: kind "lead".

    The card turned the write off for kind "hunt" only. A lead run lands kind
    "lead" with the hunt as its subject. The card, the route and the count
    now read one rule, with the sentence of a lead.
    """
    _seed(client, "INV-LEAD", alert_id="es-lead-anchor", actions=[_ESCALATE], kind="lead")
    _hunt_subject(client, "INV-LEAD")
    detail = _detail(client, "INV-LEAD")
    assert [a["blockedReason"] for a in detail["actions"]] == [action_rules.PROMOTED_LEAD]
    assert detail["writeBlockedReason"] == action_rules.PROMOTED_LEAD
    refused, calls = _execute(client, "INV-LEAD")
    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"]["reason"] == "hunt_kind_no_so_target"
    assert refused.json()["detail"]["hint"] == action_rules.PROMOTED_LEAD
    assert calls == []


def test_an_alert_a_promoted_lead_anchors_states_the_anchor(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL on the path the card missed: an ordinary alert run.

    The alert run has kind "suricata". A promoted lead uses its alert as the
    anchor, and the alert feed does not hold the document. The execute route
    refuses the write for that reason. The card offered the write, and the
    row read "A promoted finding has no Security Onion alert to act on." Each
    surface now states the anchor.
    """
    install(client, telemetry={"es-wmi"})
    _seed(client, "INV-WMI", alert_id="es-wmi", actions=[_ESCALATE], hours_ago=2)
    _seed(client, "INV-LEAD-17", alert_id="es-wmi", kind="lead", verdict="true_positive")
    _hunt_subject(client, "INV-LEAD-17")
    detail = _detail(client, "INV-WMI")
    assert [a["blockedReason"] for a in detail["actions"]] == [_ANCHORED_BY_LEAD]
    assert detail["writeBlockedReason"] == _ANCHORED_BY_LEAD
    refused, calls = _execute(client, "INV-WMI")
    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"]["hint"] == _ANCHORED_BY_LEAD
    assert calls == []
    # The row builder agrees, and it does not offer the action at all.
    assert _waiting(client, ["INV-WMI"]).get("INV-WMI", []) == []


def test_an_alert_a_promoted_finding_anchors_names_the_finding(client: TestClient) -> None:  # noqa: F811
    install(client, telemetry={"es-cited"})
    _seed(client, "INV-ALERT", alert_id="es-cited", actions=[_ESCALATE], hours_ago=2)
    _seed(client, "INV-FINDING", alert_id="es-cited", kind="hunt")
    _hunt_subject(client, "INV-FINDING")
    detail = _detail(client, "INV-ALERT")
    assert [a["blockedReason"] for a in detail["actions"]] == [_ANCHORED_BY_FINDING]


def test_a_promoted_finding_keeps_its_own_sentence(client: TestClient) -> None:  # noqa: F811
    _seed(client, "INV-HUNT", alert_id="es-telemetry", actions=[_ESCALATE], kind="hunt")
    detail = _detail(client, "INV-HUNT")
    assert [a["blockedReason"] for a in detail["actions"]] == [action_rules.PROMOTED_FINDING]


def test_a_standing_alert_run_offers_its_write_on_the_card(client: TestClient) -> None:  # noqa: F811
    """Control for the three refusals above: no rule fires, the write is on."""
    _seed(client, "INV-PLAIN", alert_id="es-plain", actions=[_ESCALATE])
    detail = _detail(client, "INV-PLAIN")
    assert [a["blockedReason"] for a in detail["actions"]] == [None]
    assert detail["writeBlockedReason"] is None


def test_the_execute_route_refuses_a_write_against_the_analyst(client: TestClient) -> None:  # noqa: F811
    """The card and the row turned the write off. The route wrote it anyway.

    An analyst set the alert to false positive on an earlier run. The newer
    model run recommends an escalate. The route now refuses it with the
    sentence of the card, and nothing reaches Security Onion.
    """
    _seed(
        client,
        "INV-ANALYST",
        alert_id="es-disputed",
        verdict="false_positive",
        analyst="ana",
        hours_ago=5,
    )
    _seed(client, "INV-MODEL", alert_id="es-disputed", actions=[_ESCALATE], hours_ago=1)
    refused, calls = _execute(client, "INV-MODEL")
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"]["reason"] == "analyst_verdict"
    assert refused.json()["detail"]["hint"].startswith(
        "ana set the verdict of this alert to false positive."
    )
    assert calls == []


# ── The needs-you count ─────────────────────────────────────────────────────


def test_an_action_no_one_can_execute_does_not_count(client: TestClient) -> None:  # noqa: F811
    """8 of 9 counted actions were on promoted findings. None of them waits.

    NEGATIVE CONTROL: the executable escalate on a standing alert run still
    counts, and its run stays on the pending list. The test fails if the
    count drops every action.
    """
    install(client, telemetry={"es-l1"})
    _seed(client, "INV-FINDING", alert_id="es-f1", actions=[_ESCALATE], kind="hunt")
    _seed(client, "INV-LEAD", alert_id="es-l1", actions=[_ESCALATE], kind="lead")
    _hunt_subject(client, "INV-LEAD")
    _seed(client, "INV-ANCHORED", alert_id="es-l1", actions=[_ESCALATE], hours_ago=3)
    _seed(client, "INV-REAL", alert_id="es-real", actions=[_ESCALATE], hours_ago=2)
    assert _needs_you_actions(client) == 1
    assert [r["id"] for r in _pending_rows(client)] == ["INV-REAL"]


def test_a_blocked_action_beside_a_waiting_one_counts_nothing(client: TestClient) -> None:  # noqa: F811
    """A run with a blocked ack and an executable escalate counts one action.

    soc-ai does not acknowledge an alert that an analyst set to true
    positive. The row carries the escalate alone. The card keeps the ack with
    its reason.
    """
    ack = {"tool_name": "ack_alert", "tool_args": {}, "rationale": "Close the noise."}
    _seed(client, "INV-TP", alert_id="es-tp", actions=[ack, _ESCALATE], analyst="ana")
    assert _needs_you_actions(client) == 1
    rows = _pending_rows(client)
    assert [(a["type"], a["executable"]) for a in rows[0]["waitingActions"]] == [("escalate", True)]
    assert rows[0]["pendingActions"] == 1
    reasons = [a["blockedReason"] for a in _detail(client, "INV-TP")["actions"]]
    assert reasons[0] is not None and reasons[1] is None


# ── The rule itself ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("facts", "tool", "code", "reason"),
    [
        (ActionFacts(replay=True), "escalate_to_case", "backtest_replay", None),
        (ActionFacts(superseded_by="INV-9"), "escalate_to_case", "superseded", None),
        (ActionFacts(alert_id="a"), "isolate_host", "not_executable", None),
        (
            ActionFacts(promoted="finding", alert_id="a"),
            "ack_alert",
            "hunt_kind_no_so_target",
            action_rules.PROMOTED_FINDING,
        ),
        (
            ActionFacts(promoted="lead", alert_id="a"),
            "ack_alert",
            "hunt_kind_no_so_target",
            action_rules.PROMOTED_LEAD,
        ),
        (
            ActionFacts(anchor="lead", alert_id="a"),
            "escalate_to_case",
            "hunt_kind_no_so_target",
            _ANCHORED_BY_LEAD,
        ),
        (ActionFacts(), "escalate_to_case", "missing_alert_id", action_rules.NO_ALERT),
        (ActionFacts(alert_id="a"), "add_case_comment", "no_case_for_comment", None),
        (ActionFacts(alert_id="a", demo=True), "escalate_to_case", "demo_mode", None),
    ],
)
def test_each_rule_has_its_own_code_and_sentence(
    facts: ActionFacts, tool: str, code: str, reason: str | None
) -> None:
    block = action_block(facts, tool)
    assert block is not None
    assert block.code == code
    if reason is not None:
        assert block.reason == reason


def test_the_sentences_are_distinct() -> None:
    """V3-N3: one sentence for two rules said a false thing about one of them."""
    sentences = [
        block_reason(ActionFacts(replay=True), "ack_alert"),
        block_reason(ActionFacts(superseded_by="INV-9"), "ack_alert"),
        block_reason(ActionFacts(alert_id="a"), "isolate_host"),
        block_reason(ActionFacts(promoted="finding"), "ack_alert"),
        block_reason(ActionFacts(promoted="lead"), "ack_alert"),
        block_reason(ActionFacts(anchor="finding", alert_id="a"), "ack_alert"),
        block_reason(ActionFacts(anchor="lead", alert_id="a"), "ack_alert"),
        block_reason(
            ActionFacts(anchor="lead", anchor_status="unknown", alert_id="a"), "ack_alert"
        ),
        block_reason(ActionFacts(), "ack_alert"),
        block_reason(ActionFacts(alert_id="a"), "add_case_comment"),
        block_reason(ActionFacts(alert_id="a", demo=True), "ack_alert"),
        block_reason(
            ActionFacts(
                alert_id="a", run_verdict="true_positive", analyst_verdict="false_positive"
            ),
            "ack_alert",
        ),
    ]
    assert all(sentences)
    assert len(set(sentences)) == len(sentences)


def test_a_comment_with_its_case_and_no_other_rule_may_run() -> None:
    assert action_block(ActionFacts(alert_id="a", case_id="case-7"), "add_case_comment") is None


# ── What the row names as the target (V3-N4) ────────────────────────────────


def test_the_row_names_the_real_target() -> None:
    """The row called a finding or a lead "The alert of ...". The type now
    names what the action acts on."""
    from types import SimpleNamespace

    from soc_ai.api.webui.routes_meta import _target_type

    alert = SimpleNamespace(kind="suricata", subject_json=None)
    finding = SimpleNamespace(kind="hunt", subject_json={"type": "hunt"})
    lead = SimpleNamespace(kind="lead", subject_json={"type": "hunt"})
    assert _target_type(alert, "escalate_to_case") == "alert"
    assert _target_type(alert, "ack_alert") == "alert"
    assert _target_type(alert, "add_case_comment") == "case"
    assert _target_type(finding, "escalate_to_case") == "finding"
    assert _target_type(lead, "escalate_to_case") == "lead"
