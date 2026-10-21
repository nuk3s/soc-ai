"""The escalate of a run names the cases its alert is already on (V3-N2).

The alert of the range was on two Security Onion cases. The action card of
its run read "Open one Security Onion case for this alert.", and the execute
route then opened no case, because the alert was already on one. The Alerts
escalate confirm names and links the cases. The card and the row of the
pending-action list now do the same, from the same two sources the execute
route asks: the escalation ledger first, then the case links of Security
Onion.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from tests.anchor_grid import install
from tests.test_action_rule import _ANCHORED_BY_LEAD, _hunt_subject
from tests.test_needs_you_count import client  # noqa: F401 - the shared fixture
from tests.test_pending_action_rows import _ACK, _ESCALATE, _seed

_GRID = "soc_ai.webui.case_links.all_case_ids_for_alert"


def _ledger(client: TestClient, alert_id: str, case_id: str) -> None:  # noqa: F811
    from soc_ai.store.models import AlertEscalation

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(AlertEscalation(alert_id=alert_id, case_id=case_id, escalated_by="ana"))
            await db.commit()

    asyncio.run(go())


def _detail(client: TestClient, run_id: str) -> dict[str, Any]:  # noqa: F811
    res = client.get(f"/api/v1/investigations/{run_id}")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_the_card_names_every_case_of_the_alert(client: TestClient) -> None:  # noqa: F811
    """An anchor outside the alert feed: the write is off, and the cases show."""
    install(client, telemetry={"es-wmi"})
    _seed(client, "INV-WMI", alert_id="es-wmi", actions=[_ESCALATE], hours_ago=2)
    _seed(client, "INV-LEAD-17", alert_id="es-wmi", kind="lead")
    _hunt_subject(client, "INV-LEAD-17")
    grid = AsyncMock(return_value=["case-a", "case-b"])
    with patch(_GRID, grid):
        detail = _detail(client, "INV-WMI")
    assert detail["actions"][0]["blockedReason"] == _ANCHORED_BY_LEAD
    assert [c["id"] for c in detail["alertCases"]] == ["case-a", "case-b"]
    assert all(
        c["url"] is None or c["url"].endswith(f"/#/case/{c['id']}") for c in detail["alertCases"]
    )
    assert detail["alertCasesComplete"] is True
    assert grid.await_args is not None and grid.await_args.args[2] == "es-wmi"


def test_a_failed_grid_read_keeps_the_ledger_case(client: TestClient) -> None:  # noqa: F811
    """The ledger answers when the grid does not. The list is then partial."""
    _seed(client, "INV-ESC", alert_id="es-esc", actions=[_ESCALATE])
    _ledger(client, "es-esc", "case-ledger")
    with patch(_GRID, AsyncMock(side_effect=TimeoutError())):
        detail = _detail(client, "INV-ESC")
    assert [c["id"] for c in detail["alertCases"]] == ["case-ledger"]
    assert detail["alertCasesComplete"] is False


def test_a_run_with_no_waiting_escalate_asks_the_grid_nothing(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL. One grid read per page load, only when it can matter."""
    _seed(client, "INV-ACK", alert_id="es-ack", actions=[_ACK])
    _seed(client, "INV-FINDING", alert_id="es-telemetry", actions=[_ESCALATE], kind="hunt")
    grid = AsyncMock(return_value=["case-a"])
    with patch(_GRID, grid):
        assert _detail(client, "INV-ACK")["alertCases"] == []
        assert _detail(client, "INV-FINDING")["alertCases"] == []
    grid.assert_not_awaited()


def test_the_scope_of_an_escalate_names_the_cases(client: TestClient) -> None:  # noqa: F811
    """The row of the pending-action list reads the scope before its confirm."""
    _seed(client, "INV-ON-CASE", alert_id="es-on-case", actions=[_ESCALATE])
    with patch(_GRID, AsyncMock(return_value=["case-a", "case-b"])):
        scope = client.get("/api/v1/investigations/INV-ON-CASE/actions/0/scope").json()
    assert scope["count"] == 0
    assert [c["id"] for c in scope["cases"]] == ["case-a", "case-b"]
    assert scope["sentence"] == (
        "The alert is already on cases case-a, case-b. soc-ai opens no second case."
    )


def test_the_scope_of_an_escalate_with_no_case_opens_one(client: TestClient) -> None:  # noqa: F811
    """Control: no case on the grid and none in the ledger. The press opens one."""
    _seed(client, "INV-NEW-CASE", alert_id="es-new", actions=[_ESCALATE])
    with patch(_GRID, AsyncMock(return_value=[])):
        scope = client.get("/api/v1/investigations/INV-NEW-CASE/actions/0/scope").json()
    assert scope["count"] == 1
    assert scope["cases"] == []
    assert scope["sentence"] == "Open one Security Onion case for this alert."


def test_a_partial_case_list_says_found(client: TestClient) -> None:  # noqa: F811
    """A list the grid did not confirm names the case as a finding."""
    _seed(client, "INV-PART", alert_id="es-part", actions=[_ESCALATE])
    _ledger(client, "es-part", "case-ledger")
    with patch(_GRID, AsyncMock(side_effect=TimeoutError())):
        scope = client.get("/api/v1/investigations/INV-PART/actions/0/scope").json()
    assert scope["sentence"] == (
        "soc-ai found the alert on case case-ledger. soc-ai opens no second case."
    )
