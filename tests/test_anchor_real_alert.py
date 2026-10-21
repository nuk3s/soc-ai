"""The anchor rule refuses a write only when the anchor is not an alert.

The anchor rule refuses a Security Onion write on a document that a promoted
finding or lead uses as its anchor. An anchor is often plain telemetry, a Zeek
or host-log record with no alert behind it, and a later run on the same
document must not turn it into a write. The rule refused too much: on the range
lead 17 cites the real Suricata alert WMIExec, and "Escalate to case" on the
investigation of that alert was refused (dogfood 2026-10-21).

The rule now asks the grid whether the alert feed holds the anchor document,
with the filter of the Alerts page. A real alert takes the write. A document
outside the feed keeps the refusal and its sentence. A grid that does not
answer keeps the refusal, with a sentence that says soc-ai could not read the
document.

The negative controls plant each case on the path a loose rule would miss:

* The telemetry document is on the grid. A lookup by id alone finds it, and
  only the alert filter keeps it out of the feed.
* The promoted lead run of a real alert still writes nothing: its subject is
  the lead.
* A grid failure is not a "no". It refuses with its own sentence.

tests/test_anchor_check.py holds the tests of the check itself.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui import action_rules

from tests.anchor_grid import install
from tests.test_action_rule import (
    _ANCHORED_BY_FINDING,
    _ANCHORED_BY_LEAD,
    _detail,
    _execute,
    _hunt_subject,
    _needs_you_actions,
)
from tests.test_needs_you_count import client  # noqa: F401 - the shared fixture
from tests.test_pending_action_rows import _ESCALATE, _pending_rows, _seed

_UNREAD_BY_LEAD = (
    "A promoted lead uses this document as its anchor. "
    "soc-ai could not read the anchor document. Try again when the grid answers."
)


def _lead_on(client: TestClient, run_id: str, alert_id: str) -> None:  # noqa: F811
    """A promoted lead that uses ``alert_id`` as its anchor."""
    _seed(client, run_id, alert_id=alert_id, kind="lead", verdict="true_positive")
    _hunt_subject(client, run_id)


def _finding_on(client: TestClient, run_id: str, alert_id: str) -> None:  # noqa: F811
    """A promoted finding that uses ``alert_id`` as its anchor."""
    _seed(client, run_id, alert_id=alert_id, kind="hunt", verdict="true_positive")
    _hunt_subject(client, run_id)


# ── The card, the row, the count and the execute route ─────────────────────


def test_a_real_alert_a_lead_anchors_takes_the_write(client: TestClient) -> None:  # noqa: F811
    """Lead 17 cites the WMIExec alert. The write on the alert run is on."""
    grid = install(client, alerts={"es-wmi"})
    _seed(client, "INV-WMI", alert_id="es-wmi", actions=[_ESCALATE], hours_ago=2)
    _lead_on(client, "INV-LEAD-17", "es-wmi")

    detail = _detail(client, "INV-WMI")
    assert [a["blockedReason"] for a in detail["actions"]] == [None]
    assert detail["writeBlockedReason"] is None
    rows = _pending_rows(client)
    assert [r["id"] for r in rows] == ["INV-WMI"]
    assert [(a["type"], a["executable"]) for a in rows[0]["waitingActions"]] == [("escalate", True)]
    assert _needs_you_actions(client) == 1
    done, calls = _execute(client, "INV-WMI")
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "executed"
    assert calls == ["es-wmi"]
    assert grid.feed_reads >= 1


def test_a_telemetry_document_a_finding_anchors_is_still_refused(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL: the grid holds the document, and the feed does not.

    A check by id alone finds the Zeek record and calls it an alert. The
    alert filter keeps it out, and every surface keeps today's sentence.
    """
    install(client, telemetry={"es-zeek-conn"})
    _seed(client, "INV-ALERT", alert_id="es-zeek-conn", actions=[_ESCALATE], hours_ago=2)
    _finding_on(client, "INV-FINDING", "es-zeek-conn")

    detail = _detail(client, "INV-ALERT")
    assert [a["blockedReason"] for a in detail["actions"]] == [_ANCHORED_BY_FINDING]
    assert detail["writeBlockedReason"] == _ANCHORED_BY_FINDING
    assert _pending_rows(client) == []
    assert _needs_you_actions(client) == 0
    refused, calls = _execute(client, "INV-ALERT")
    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"]["reason"] == "hunt_kind_no_so_target"
    assert refused.json()["detail"]["hint"] == _ANCHORED_BY_FINDING
    assert calls == []


def test_a_document_no_one_holds_keeps_the_lead_sentence(client: TestClient) -> None:  # noqa: F811
    """A document that aged out of the grid is no alert to write to."""
    install(client)
    _seed(client, "INV-GONE", alert_id="es-aged-out", actions=[_ESCALATE], hours_ago=2)
    _lead_on(client, "INV-LEAD-GONE", "es-aged-out")
    detail = _detail(client, "INV-GONE")
    assert [a["blockedReason"] for a in detail["actions"]] == [_ANCHORED_BY_LEAD]


def test_a_grid_failure_refuses_with_the_unread_sentence(client: TestClient) -> None:  # noqa: F811
    """A grid that does not answer is not a "no" and not a "yes"."""
    install(client, alerts={"es-wmi"}, down=True)
    _seed(client, "INV-WMI", alert_id="es-wmi", actions=[_ESCALATE], hours_ago=2)
    _lead_on(client, "INV-LEAD-17", "es-wmi")

    detail = _detail(client, "INV-WMI")
    assert [a["blockedReason"] for a in detail["actions"]] == [_UNREAD_BY_LEAD]
    assert detail["writeBlockedReason"] == _UNREAD_BY_LEAD
    assert _needs_you_actions(client) == 0
    refused, calls = _execute(client, "INV-WMI")
    assert refused.status_code == 503, refused.text
    assert refused.json()["detail"]["reason"] == "anchor_unread"
    assert refused.json()["detail"]["hint"] == _UNREAD_BY_LEAD
    assert calls == []


def test_the_promoted_run_of_a_real_alert_still_writes_nothing(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL: the anchor is a real alert, and the subject is the lead.

    A rule that asks only "is the anchor an alert" would let the lead run
    escalate. The run of a promotion never writes.
    """
    install(client, alerts={"es-wmi"})
    _seed(client, "INV-LEAD-17", alert_id="es-wmi", kind="lead", actions=[_ESCALATE])
    _hunt_subject(client, "INV-LEAD-17")

    detail = _detail(client, "INV-LEAD-17")
    assert [a["blockedReason"] for a in detail["actions"]] == [action_rules.PROMOTED_LEAD]
    assert _needs_you_actions(client) == 0
    refused, calls = _execute(client, "INV-LEAD-17")
    assert refused.status_code == 400, refused.text
    assert refused.json()["detail"]["hint"] == action_rules.PROMOTED_LEAD
    assert calls == []


# ── The cost of the check ───────────────────────────────────────────────────


def test_one_search_checks_a_page_of_thirty_rows(client: TestClient) -> None:  # noqa: F811
    """30 alert runs, each one anchored by a lead: one grid search, then none."""
    alerts = {f"es-wmi-{n:02d}" for n in range(30)}
    grid = install(client, alerts=alerts)
    for n in range(30):
        _seed(client, f"INV-A{n:02d}", alert_id=f"es-wmi-{n:02d}", actions=[_ESCALATE], hours_ago=2)
        _lead_on(client, f"INV-L{n:02d}", f"es-wmi-{n:02d}")

    rows = _pending_rows(client, limit=50)
    assert len(rows) == 30
    assert all(r["waitingActions"][0]["executable"] for r in rows)
    assert grid.feed_reads == 1
    # The second page read and the needs-you count ask the cache.
    assert len(_pending_rows(client, limit=50)) == 30
    assert _needs_you_actions(client) == 30
    assert grid.feed_reads == 1


# ── Acknowledge selected events ─────────────────────────────────────────────


def _ack_events(client: TestClient, ids: list[str]) -> tuple[Any, AsyncMock]:  # noqa: F811
    with patch(
        "soc_ai.api.webui.routes_alert_actions.execute_write_tool",
        new=AsyncMock(return_value=({}, None)),
    ) as write_spy:
        res = client.post("/api/v1/alerts/ack-events", json={"es_ids": ids})
    return res, write_spy


def test_ack_events_acks_a_real_alert_a_lead_anchors(client: TestClient) -> None:  # noqa: F811
    install(client, alerts={"es-wmi"})
    _lead_on(client, "INV-LEAD-17", "es-wmi")
    res, write_spy = _ack_events(client, ["es-wmi"])
    assert res.status_code == 200, res.text
    assert res.json()["acked"] == 1
    write_spy.assert_awaited_once()


def test_ack_events_refuses_a_telemetry_anchor(client: TestClient) -> None:  # noqa: F811
    install(client, alerts={"es-wmi"}, telemetry={"es-zeek-conn"})
    _finding_on(client, "INV-FINDING", "es-zeek-conn")
    res, write_spy = _ack_events(client, ["es-wmi", "es-zeek-conn"])
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["reason"] == "hunt_kind_no_so_target"
    assert res.json()["detail"]["ids"] == ["es-zeek-conn"]
    assert res.json()["detail"]["hint"] == _ANCHORED_BY_FINDING
    write_spy.assert_not_awaited()


def test_ack_events_names_every_telemetry_anchor(client: TestClient) -> None:  # noqa: F811
    install(client, telemetry={"es-zeek-conn", "es-zeek-dns"})
    _finding_on(client, "INV-FINDING", "es-zeek-conn")
    _lead_on(client, "INV-LEAD", "es-zeek-dns")
    res, write_spy = _ack_events(client, ["es-zeek-conn", "es-zeek-dns"])
    assert res.status_code == 400, res.text
    assert res.json()["detail"]["ids"] == ["es-zeek-conn", "es-zeek-dns"]
    assert res.json()["detail"]["hint"] == (
        "A promoted finding or lead uses each of these documents as its anchor. "
        "The documents are not Security Onion alerts."
    )
    write_spy.assert_not_awaited()


def test_ack_events_refuses_when_the_grid_does_not_answer(client: TestClient) -> None:  # noqa: F811
    install(client, alerts={"es-wmi"}, down=True)
    _lead_on(client, "INV-LEAD-17", "es-wmi")
    res, write_spy = _ack_events(client, ["es-wmi"])
    assert res.status_code == 503, res.text
    assert res.json()["detail"]["reason"] == "anchor_unread"
    assert res.json()["detail"]["ids"] == ["es-wmi"]
    assert res.json()["detail"]["hint"] == (
        "soc-ai could not read the anchor document. Try again when the grid answers."
    )
    write_spy.assert_not_awaited()


# ── A new run over an anchor ────────────────────────────────────────────────


def _investigate(client: TestClient, alert_id: str) -> dict[str, Any]:  # noqa: F811
    captured: dict[str, Any] = {}

    def fake(alert_id: str, **kwargs: Any) -> Any:
        async def gen() -> Any:
            captured["kwargs"] = kwargs
            return
            yield  # pragma: no cover - an async generator

        return gen()

    with (
        patch("soc_ai.api.routes.investigate", fake),
        patch("soc_ai.api.routes.resolve_alert_for_hunt", AsyncMock(return_value=(True, None))),
    ):
        res = client.post("/investigate", json={"alert_id": alert_id})
    assert res.status_code == 200, res.text
    assert captured, "the route never ran the investigation"
    return captured["kwargs"]


@pytest.mark.parametrize(
    ("grid", "writes"),
    [
        ({"alerts": {"es-wmi"}}, True),
        ({"telemetry": {"es-wmi"}}, False),
        ({"alerts": {"es-wmi"}, "down": True}, False),
    ],
)
def test_investigate_keeps_writes_on_for_a_real_alert_only(
    client: TestClient,  # noqa: F811
    grid: dict[str, Any],
    writes: bool,
) -> None:
    install(client, **grid)
    _lead_on(client, "INV-LEAD-17", "es-wmi")
    assert _investigate(client, "es-wmi").get("allow_so_writes") is writes


def _manager() -> AsyncMock:
    mgr = AsyncMock()
    mgr.start = AsyncMock(return_value="INV-NEW")
    return mgr


@pytest.mark.parametrize(
    ("grid", "reason"),
    [
        ({"alerts": {"es-wmi"}}, None),
        ({"telemetry": {"es-wmi"}}, "hunt_kind"),
        ({"alerts": {"es-wmi"}, "down": True}, "anchor_unread"),
    ],
)
def test_rehunt_reruns_the_alert_run_of_a_real_alert(
    client: TestClient,  # noqa: F811
    grid: dict[str, Any],
    reason: str | None,
) -> None:
    install(client, **grid)
    _seed(client, "INV-WMI", alert_id="es-wmi", verdict="needs_more_info", hours_ago=2)
    _lead_on(client, "INV-LEAD-17", "es-wmi")
    mgr = _manager()
    with patch("soc_ai.webui.hunt_manager.get_manager", return_value=mgr):
        res = client.post("/api/v1/investigations/rehunt", json={"inv_ids": ["INV-WMI"]})
    assert res.status_code == 200, res.text
    body = res.json()
    if reason is None:
        assert [s["invId"] for s in body["started"]] == ["INV-WMI"]
        assert mgr.start.await_args.kwargs.get("allow_so_writes", True) is True
    else:
        assert body["started"] == []
        assert body["skipped"] == [{"invId": "INV-WMI", "reason": reason}]
        mgr.start.assert_not_awaited()


@pytest.mark.parametrize(
    ("grid", "status", "reason"),
    [
        ({"alerts": {"es-wmi"}}, 200, None),
        ({"telemetry": {"es-wmi"}}, 409, "hunt_kind_no_rerun"),
        ({"alerts": {"es-wmi"}, "down": True}, 503, "anchor_unread"),
    ],
)
def test_request_more_info_reruns_the_alert_run_of_a_real_alert(
    client: TestClient,  # noqa: F811
    grid: dict[str, Any],
    status: int,
    reason: str | None,
) -> None:
    install(client, **grid)
    _seed(client, "INV-WMI", alert_id="es-wmi", verdict="needs_more_info", hours_ago=2)
    _lead_on(client, "INV-LEAD-17", "es-wmi")
    mgr = _manager()
    with patch("soc_ai.webui.hunt_manager.get_manager", return_value=mgr):
        res = client.post("/api/v1/investigations/INV-WMI/request-more-info")
    assert res.status_code == status, res.text
    if reason is None:
        assert res.json() == {"investigation_id": "INV-NEW"}
    else:
        assert res.json()["detail"]["reason"] == reason
        mgr.start.assert_not_awaited()


def _start_hunt(client: TestClient, alert_id: str) -> tuple[Any, AsyncMock]:  # noqa: F811
    mgr = _manager()
    with (
        patch(
            "soc_ai.api.webui.routes_hunts.resolve_alert_for_hunt",
            AsyncMock(return_value=(True, "ET TEST rule")),
        ),
        patch("soc_ai.webui.hunt_manager.get_manager", return_value=mgr),
    ):
        res = client.post("/api/v1/hunt", json={"alert_id": alert_id})
    return res, mgr


def _old_finding_on(client: TestClient, run_id: str, alert_id: str) -> None:  # noqa: F811
    """A promoted finding of the older shape: kind "hunt" and no hunt subject."""
    _seed(client, run_id, alert_id=alert_id, kind="hunt", verdict="true_positive")


def test_start_hunt_reruns_a_real_alert_an_old_finding_anchors(client: TestClient) -> None:  # noqa: F811
    install(client, alerts={"es-wmi"})
    _old_finding_on(client, "INV-FINDING", "es-wmi")
    res, mgr = _start_hunt(client, "es-wmi")
    assert res.status_code == 200, res.text
    assert mgr.start.await_args.kwargs.get("allow_so_writes", True) is True


def test_start_hunt_still_refuses_a_telemetry_anchor(client: TestClient) -> None:  # noqa: F811
    install(client, telemetry={"es-zeek-conn"})
    _old_finding_on(client, "INV-FINDING", "es-zeek-conn")
    res, mgr = _start_hunt(client, "es-zeek-conn")
    assert res.status_code == 409, res.text
    assert res.json()["detail"]["reason"] == "hunt_kind_no_rerun"
    mgr.start.assert_not_awaited()


def test_start_hunt_refuses_an_old_finding_anchor_the_grid_cannot_check(
    client: TestClient,  # noqa: F811
) -> None:
    install(client, alerts={"es-wmi"}, down=True)
    _old_finding_on(client, "INV-FINDING", "es-wmi")
    res, mgr = _start_hunt(client, "es-wmi")
    assert res.status_code == 503, res.text
    assert res.json()["detail"]["reason"] == "anchor_unread"
    mgr.start.assert_not_awaited()


def test_start_hunt_turns_writes_off_over_a_telemetry_lead_anchor(client: TestClient) -> None:  # noqa: F811
    """NEGATIVE CONTROL on the path the old guard missed: a lead anchor.

    The latest-row read leaves the lead run out, so the kind "hunt" guard
    never fired, and the new run wrote to Security Onion over telemetry.
    """
    install(client, telemetry={"es-zeek-conn"})
    _lead_on(client, "INV-LEAD", "es-zeek-conn")
    res, mgr = _start_hunt(client, "es-zeek-conn")
    assert res.status_code == 200, res.text
    assert mgr.start.await_args.kwargs.get("allow_so_writes") is False


# ── The rule ────────────────────────────────────────────────────────────────


def test_the_rule_reads_the_anchor_status() -> None:
    from soc_ai.api.webui.action_rules import ActionFacts, action_block
    from soc_ai.webui import anchor_check

    alert = ActionFacts(anchor="lead", anchor_status=anchor_check.ALERT, alert_id="a")
    telemetry = ActionFacts(anchor="lead", anchor_status=anchor_check.NOT_ALERT, alert_id="a")
    unread = ActionFacts(anchor="lead", anchor_status=anchor_check.UNKNOWN, alert_id="a")
    assert action_block(alert, "escalate_to_case") is None
    block = action_block(telemetry, "escalate_to_case")
    assert block is not None and block.reason == _ANCHORED_BY_LEAD
    block = action_block(unread, "escalate_to_case")
    assert block is not None
    assert (block.code, block.reason) == ("anchor_unread", _UNREAD_BY_LEAD)
    # A fact with no status keeps today's refusal.
    block = action_block(ActionFacts(anchor="lead", alert_id="a"), "escalate_to_case")
    assert block is not None and block.reason == _ANCHORED_BY_LEAD
