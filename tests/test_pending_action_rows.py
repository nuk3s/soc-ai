"""The waiting actions on the rows of the pending-action list (dogfood 2026-10-19, R1-I1).

The needs-you line "N recommended actions wait for you" opens the
Investigations list filtered to the runs with a waiting action. To act, the
analyst opened each run and came back: two page changes per run, 32 for 16
runs. Each row of that list now carries its waiting actions, and the console
offers Execute and Dismiss on the row. The row carries an action only when
the console can execute it, under the rule the action card follows
(:mod:`soc_ai.api.webui.action_rules`), and the write goes through the same
action routes.

The negative controls plant each case on the path a guard would miss:

* The list filter drops a superseded run in SQL. A caller that picks its own
  runs (the hunt page does) skips that filter, so the row builder must apply
  the rule itself.
* A list read before a newer run started still shows the old row. The write
  route must refuse the superseded run.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from soc_ai.webui.alerts_query import GroupPage

from tests.test_needs_you_count import client  # noqa: F401 - the shared fixture

_ESCALATE = {
    "tool_name": "escalate_to_case",
    "tool_args": {"case_title": "t", "case_description": "d"},
    "rationale": "The beacon matches a known C2 address.",
}
_ESCALATE_2 = {
    "tool_name": "escalate_to_case",
    "tool_args": {"case_title": "t2", "case_description": "d2"},
    "rationale": "A second host shows the same beacon.",
}
_ACK = {"tool_name": "ack_alert", "tool_args": {}, "rationale": "Close the noise of this rule."}
_COMMENT = {
    "tool_name": "add_case_comment",
    "tool_args": {"comment": "more evidence"},
    "rationale": "Add the second beacon to the case.",
}


def _ago(hours: float) -> datetime:
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _seed(
    client: TestClient,  # noqa: F811 - the fixture
    run_id: str,
    *,
    alert_id: str,
    verdict: str = "true_positive",
    actions: list[dict[str, Any]] | None = None,
    hours_ago: float = 1.0,
    events: list[tuple[str, dict[str, Any]]] | None = None,
    started_by: str | None = None,
    kind: str = "suricata",
    analyst: str | None = None,
    status: str = "complete",
) -> None:
    """One investigation, and the events the action card reads.

    ``analyst`` names the person who set the verdict of the run. The run then
    carries an analyst resolution, the way an override stores it.
    """
    from soc_ai.store.models import Investigation, InvestigationEvent

    report: dict[str, Any] = {"verdict": verdict, "recommended_actions": actions or []}
    if analyst is not None:
        report["resolution"] = {
            "resolved_via": "manual",
            "resolved_by": analyst,
            "resolved_at": datetime.now(UTC).isoformat(),
        }

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id=run_id,
                    alert_es_id=alert_id,
                    kind=kind,
                    rule_name=f"ET TEST {run_id}",
                    status=status,
                    verdict=verdict if status == "complete" else None,
                    confidence=0.8,
                    report=report,
                    created_at=_ago(hours_ago),
                    finished_at=_ago(hours_ago) if status == "complete" else None,
                    started_by=started_by or "scheduler",
                )
            )
            await db.flush()
            for seq, (event_kind, payload) in enumerate(events or []):
                db.add(
                    InvestigationEvent(
                        investigation_id=run_id, sequence=seq, kind=event_kind, payload=payload
                    )
                )
            await db.commit()

    asyncio.run(go())


def _pending_rows(client: TestClient, **params: Any) -> list[dict[str, Any]]:  # noqa: F811
    res = client.get("/api/v1/investigations", params={"pending_action": "true", **params})
    assert res.status_code == 200, res.text
    rows: list[dict[str, Any]] = res.json()["rows"]
    return rows


def _waiting(client: TestClient, run_ids: list[str]) -> dict[str, Any]:  # noqa: F811
    """The row builder on runs the caller picked, with no list filter in front."""
    from soc_ai.api.webui.routes_meta import waiting_actions_by_run
    from soc_ai.store.models import Investigation
    from sqlalchemy import select

    async def go() -> dict[str, Any]:
        async with client.app.state.db_sessionmaker() as db:
            runs = (
                await db.scalars(select(Investigation).where(Investigation.id.in_(run_ids)))
            ).all()
            return await waiting_actions_by_run(db, runs)

    return asyncio.run(go())


# ── The row field ───────────────────────────────────────────────────────────


def test_a_pending_row_carries_its_waiting_action(client: TestClient) -> None:  # noqa: F811
    _seed(client, "INV-WAITS", alert_id="es-tp", actions=[_ESCALATE])
    rows = _pending_rows(client)
    assert [r["id"] for r in rows] == ["INV-WAITS"]
    assert rows[0]["waitingActions"] == [
        {
            "id": "a0",
            "index": 0,
            "type": "escalate",
            "label": "Escalate to case",
            "target": "ET TEST INV-WAITS",
            "targetType": "alert",
            "rationale": "The beacon matches a known C2 address.",
            "executable": True,
            "reason": None,
        }
    ]


def test_a_dismissed_or_executed_action_is_not_listed(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. Only the action that still waits is on the row.

    The first run has one action executed and one dismissed: nothing waits, so
    the run is not on the list. The second run has its first action dismissed:
    only the second action is on the row, with its own index.
    """
    _seed(
        client,
        "INV-DONE",
        alert_id="es-done",
        actions=[_ESCALATE, _ESCALATE_2],
        events=[
            ("action_executed", {"index": 0, "success": True, "by": "ana"}),
            ("action_dismissed", {"index": 1, "by": "ana"}),
        ],
    )
    _seed(
        client,
        "INV-HALF",
        alert_id="es-half",
        actions=[_ESCALATE, _ESCALATE_2],
        events=[("action_dismissed", {"index": 0, "by": "ana"})],
    )
    rows = _pending_rows(client)
    assert [r["id"] for r in rows] == ["INV-HALF"]
    waiting = rows[0]["waitingActions"]
    assert [(a["id"], a["index"]) for a in waiting] == [("a1", 1)]
    assert rows[0]["pendingActions"] == len(waiting)


def test_the_plain_list_carries_no_waiting_actions(client: TestClient) -> None:  # noqa: F811
    """Backward compatible: the field is filled only under the filter."""
    _seed(client, "INV-WAITS", alert_id="es-tp", actions=[_ESCALATE])
    rows = client.get("/api/v1/investigations").json()["rows"]
    assert [r["id"] for r in rows] == ["INV-WAITS"]
    assert rows[0].get("waitingActions") in (None, [])


def test_a_replay_offers_no_executable_action(client: TestClient) -> None:  # noqa: F811
    """A backtest replay offers no Execute, through the list or the row builder."""
    _seed(client, "INV-REPLAY", alert_id="es-replay", actions=[_ESCALATE], started_by="backtest")
    _seed(client, "INV-LIVE", alert_id="es-live", actions=[_ESCALATE])
    rows = _pending_rows(client, include_backtest="true")
    assert [r["id"] for r in rows] == ["INV-LIVE"]
    by_run = _waiting(client, ["INV-REPLAY", "INV-LIVE"])
    assert not [a for a in by_run.get("INV-REPLAY", []) if a.executable]
    assert by_run.get("INV-REPLAY", []) == []
    # Control: the live run beside it offers its action.
    assert [a.executable for a in by_run["INV-LIVE"]] == [True]


# ── A superseded run offers nothing ─────────────────────────────────────────


def test_the_row_builder_offers_nothing_on_a_superseded_run(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL on the path the list filter misses.

    The list filter leaves a superseded run out in SQL. The hunt page picks
    its own runs and calls the shared rule with no such filter. The row
    builder must apply the supersede rule on its own.
    """
    _seed(client, "INV-OLD", alert_id="es-swap", actions=[_ESCALATE], hours_ago=5)
    _seed(client, "INV-NEW", alert_id="es-swap", actions=[_ESCALATE_2], hours_ago=1)
    by_run = _waiting(client, ["INV-OLD", "INV-NEW"])
    assert by_run.get("INV-OLD", []) == []
    # Control: the newer run of the same alert offers its action.
    assert [a.index for a in by_run["INV-NEW"]] == [0]
    assert [r["id"] for r in _pending_rows(client)] == ["INV-NEW"]


def test_a_run_answered_by_a_follow_up_offers_nothing(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. The page reads a recorded follow-up as a newer run.

    A hunt-subject run stands alone, so no alert group links it to a newer
    run, and the SQL rule cannot see the follow-up on its report. The page
    calls the run superseded. The row builder agrees with the page.
    """
    from soc_ai.store.models import Investigation

    _seed(client, "INV-ASKED", alert_id="es-asked", actions=[_ESCALATE], hours_ago=5)
    _seed(client, "INV-ANSWER", alert_id="es-other", status="running", hours_ago=1)

    async def link() -> None:
        async with client.app.state.db_sessionmaker() as db:
            inv = await db.get(Investigation, "INV-ASKED")
            assert inv is not None
            inv.subject_json = {"type": "hunt", "hunt_id": "H1"}
            inv.report = {**(inv.report or {}), "follow_up": {"id": "INV-ANSWER"}}
            await db.commit()

    asyncio.run(link())
    assert _waiting(client, ["INV-ASKED"]).get("INV-ASKED", []) == []


def _escalate_tool(calls: list[str]) -> Any:
    from soc_ai.tools._registry import ToolSpec

    async def fn(alert_id: str, *, auth: Any, settings: Any = None, **_: Any) -> dict[str, Any]:
        calls.append(alert_id)
        return {"id": "case-1", "alert_linked": True, "marked_escalated": True}

    return ToolSpec(name="escalate_to_case", read_only=False, description="", func=fn)


def test_the_write_routes_refuse_a_run_a_newer_run_replaced(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL on the path the read guard misses: a stale row.

    The list was read while the run waited. A newer run of the alert then
    started. The row on screen still offers Execute, so the write route must
    refuse the superseded run. Nothing reaches Security Onion.
    """
    _seed(client, "INV-STALE", alert_id="es-stale", actions=[_ESCALATE], hours_ago=5)
    assert [r["id"] for r in _pending_rows(client)] == ["INV-STALE"]
    _seed(client, "INV-NEWER", alert_id="es-stale", status="running", hours_ago=0.1)
    calls: list[str] = []
    with (
        patch("soc_ai.tools.write_exec.get_tool", return_value=_escalate_tool(calls)),
        patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=GroupPage([], 0))),
    ):
        refused = client.post("/api/v1/investigations/INV-STALE/actions/0/execute")
        assert refused.status_code == 409, refused.text
        assert refused.json()["detail"]["reason"] == "superseded"
        assert refused.json()["detail"]["invId"] == "INV-NEWER"
        assert calls == []
        dismissed = client.post("/api/v1/investigations/INV-STALE/actions/0/dismiss")
        assert dismissed.status_code == 409, dismissed.text
        assert dismissed.json()["detail"]["reason"] == "superseded"


def test_the_execute_route_writes_for_a_standing_run(client: TestClient) -> None:  # noqa: F811
    """Control for the refusal above: the same press on a standing run writes."""
    _seed(client, "INV-STANDS", alert_id="es-stands", actions=[_ESCALATE])
    calls: list[str] = []
    with (
        patch("soc_ai.tools.write_exec.get_tool", return_value=_escalate_tool(calls)),
        patch("soc_ai.api.webui.routes_actions._reserve_escalate", AsyncMock(return_value=None)),
    ):
        done = client.post("/api/v1/investigations/INV-STANDS/actions/0/execute")
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "executed"
    assert calls == ["es-stands"]
    # The row leaves the pending list: the receipt closes the action.
    assert _pending_rows(client) == []


# ── The rules the card follows ──────────────────────────────────────────────


_DISPUTED = (
    "ana set the verdict of this alert to false positive. This run reached true positive. "
    "Override the verdict of this run to act."
)
_NO_ACK = (
    "ana set the verdict of this alert to true positive. soc-ai does not acknowledge an "
    "alert with that verdict."
)


def _card_reasons(client: TestClient, run_id: str) -> list[Any]:  # noqa: F811
    """The reason each action card of the run page states for a write that is off."""
    res = client.get(f"/api/v1/investigations/{run_id}")
    assert res.status_code == 200, res.text
    return [a.get("blockedReason") for a in res.json()["actions"]]


def test_an_analyst_verdict_on_another_run_turns_off_the_write(client: TestClient) -> None:  # noqa: F811
    """A write never acts against an analyst verdict, on the row or on the card.

    An analyst set the alert to false positive on an earlier run. A newer
    model run reached true positive and recommends an escalate. The action
    card of the run page states the reason and keeps Dismiss. The action
    waits for nobody, so the pending list leaves the run out (2026-10-20).
    """
    _seed(
        client,
        "INV-ANALYST-FP",
        alert_id="es-disputed",
        verdict="false_positive",
        analyst="ana",
        hours_ago=5,
    )
    _seed(client, "INV-MODEL-TP", alert_id="es-disputed", actions=[_ESCALATE], hours_ago=1)
    assert _pending_rows(client) == []
    assert _waiting(client, ["INV-MODEL-TP"]).get("INV-MODEL-TP", []) == []
    assert _card_reasons(client, "INV-MODEL-TP") == [_DISPUTED]


def test_an_analyst_true_positive_turns_off_the_ack(client: TestClient) -> None:  # noqa: F811
    """soc-ai does not acknowledge an alert that an analyst set to true positive.

    The escalate of the same run stays on, on the row and on the card: it
    agrees with the analyst. The row carries the escalate alone. The card
    keeps the ack with its reason.
    """
    _seed(client, "INV-TP", alert_id="es-tp", actions=[_ACK, _ESCALATE], analyst="ana")
    waiting = _pending_rows(client)[0]["waitingActions"]
    assert [(a["type"], a["executable"]) for a in waiting] == [("escalate", True)]
    assert waiting[0]["label"] == "Escalate to case"
    assert _card_reasons(client, "INV-TP") == [_NO_ACK, None]


def test_an_analyst_verdict_equal_to_the_run_verdict_keeps_the_write(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL. The rule fires on a disagreement only.

    An analyst set true positive on an earlier run of the alert, and the newer
    run reached true positive too. The escalate agrees with both verdicts. The
    row and the card keep the write on, so the test fails if the rule fires on
    any analyst verdict.
    """
    _seed(
        client,
        "INV-ANALYST-TP",
        alert_id="es-agreed",
        verdict="true_positive",
        analyst="ana",
        hours_ago=5,
    )
    _seed(client, "INV-MODEL-TP", alert_id="es-agreed", actions=[_ESCALATE], hours_ago=1)
    action = _pending_rows(client)[0]["waitingActions"][0]
    assert (action["executable"], action["reason"]) == (True, None)
    assert _card_reasons(client, "INV-MODEL-TP") == [None]


def test_the_rule_is_one_helper() -> None:
    """The row and the card call one function, so the two cannot drift."""
    from soc_ai.api.webui._timeline import analyst_verdict_block

    assert analyst_verdict_block("escalate", "true_positive", None, None) is None
    assert analyst_verdict_block("ack", "true_positive", "true_positive", None) == (
        "An analyst set the verdict of this alert to true positive. soc-ai does not "
        "acknowledge an alert with that verdict."
    )
    assert analyst_verdict_block("ack", "false_positive", "false_positive", "ana") is None


def test_a_promoted_lead_offers_no_execute(client: TestClient) -> None:  # noqa: F811
    """The card states the reason of a lead. The pending list leaves the run out."""
    _seed(client, "INV-LEAD", alert_id="es-anchor", actions=[_ESCALATE], kind="lead")
    assert _pending_rows(client) == []
    assert _card_reasons(client, "INV-LEAD") == [
        "A promoted lead has no Security Onion alert to act on."
    ]


def test_a_comment_needs_the_case_this_run_opened(client: TestClient) -> None:  # noqa: F811
    """The write route binds a comment to a case this run opened, or refuses it."""
    _seed(client, "INV-NOCASE", alert_id="es-nocase", actions=[_COMMENT])
    _seed(
        client,
        "INV-CASE",
        alert_id="es-case",
        actions=[_ESCALATE, _COMMENT],
        events=[
            (
                "action_executed",
                {
                    "index": 0,
                    "success": True,
                    "by": "ana",
                    "tool_name": "escalate_to_case",
                    "case_id": "case-7",
                },
            )
        ],
    )
    rows = {r["id"]: r for r in _pending_rows(client)}
    assert "INV-NOCASE" not in rows
    assert _card_reasons(client, "INV-NOCASE") == [
        "This investigation opened no Security Onion case. Escalate the alert first."
    ]
    with_case = rows["INV-CASE"]["waitingActions"]
    assert [(a["type"], a["target"], a["targetType"], a["executable"]) for a in with_case] == [
        ("comment", "case-7", "case", True)
    ]
