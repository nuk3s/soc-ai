"""A second press of group escalate must not open a second case.

The first repair read ``event.acknowledged``/``event.escalated`` off the hit and
skipped anything that carried them. On the Elastic Defend endpoint alert index
that guard is inert for the case it exists to stop: the attach Security Onion
performs when soc-ai calls ``POST /api/case/events`` writes neither flag, so a
genuinely unescalated alert is never skipped. Measured on the range against an
18-event group holding exactly one unwritten alert:

    press 1 -> {"escalated": 1, "already_escalated": 17, "remaining": 0}
    press 2 -> {"escalated": 1, "already_escalated": 17, "remaining": 0}

Two cases, one alert. The guard held only for events something else had already
acknowledged, which is the case where a duplicate case was never in question.

The tests below fix the truth at both ends: what a second press writes, and
what the operator is told about it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui.alerts_query import AlertEvent

_RULE = "Execution via Interactive Secondary Logon"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _event(idx: int, *, acknowledged: bool = False, escalated: bool = False) -> AlertEvent:
    return AlertEvent(
        es_id=f"ev-{idx}",
        timestamp="t",
        src="host-a",
        dst="host-b",
        severity="high",
        host="wks-1",
        acknowledged=acknowledged,
        escalated=escalated,
    )


class _Grid:
    """A grid that records neither flag when soc-ai attaches an alert to a case.

    This is the Elastic Defend endpoint alert index: the group keeps serving the
    same events with the same empty ``_source`` flags no matter how many cases
    reference them, so nothing about the alert itself can tell a second press
    that the first one already happened.
    """

    def __init__(self, events: list[AlertEvent], *, link_lag: bool = False) -> None:
        self.events = events
        self.escalated: list[str] = []
        self.case_links: dict[str, list[str]] = {}
        # The case index is a refreshed read. Within the refresh window a case
        # opened seconds ago is not visible yet, so a press that close behind
        # another gets nothing back from it. Set this and the ledger is the only
        # thing standing between the operator and a duplicate case.
        self.link_lag = link_lag

    async def fetch(self, *_args: Any, **kwargs: Any) -> list[AlertEvent]:
        if int(kwargs.get("offset", 0)):
            return []
        return list(self.events)

    async def count(self, *_args: Any, **_kwargs: Any) -> int:
        return len(self.events)

    async def write(
        self, tool: str, tool_args: dict[str, Any], **_kwargs: Any
    ) -> tuple[dict[str, Any], None]:
        assert tool == "escalate_to_case"
        alert_id = tool_args["alert_id"]
        case_id = f"case-{len(self.escalated) + 1}"
        self.escalated.append(alert_id)
        self.case_links.setdefault(alert_id, []).append(case_id)
        return {"case_id": case_id, "case_created": True, "alert_linked": True}, None

    async def links(self, _elastic: Any, _settings: Any, alert_ids: list[str]) -> dict[str, str]:
        if self.link_lag:
            return {}
        return {a: self.case_links[a][0] for a in alert_ids if a in self.case_links}

    def press(self, client: TestClient) -> Any:
        with (
            patch("soc_ai.api.webui_api.aq.fetch_group_events", self.fetch),
            patch("soc_ai.api.webui_api.aq.count_group_events", self.count),
            patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", self.write),
            patch(
                "soc_ai.api.webui.routes_alert_actions.case_ids_for_alerts",
                self.links,
            ),
        ):
            return client.post(
                "/api/v1/alerts/escalate-group", json={"rule_name": _RULE, "range": "7d"}
            )


def _live_group() -> list[AlertEvent]:
    """The group as the range served it: 18 events, 17 acknowledged by something
    else, exactly one never written to at all."""
    return [_event(0)] + [_event(i, acknowledged=True) for i in range(1, 18)]


def test_a_second_press_opens_no_second_case(client: TestClient) -> None:
    """The defect itself. Two presses of the same group, one case.

    Driven with the case index lagging, because that is what a second press
    seconds behind the first actually meets, and because a test that let the
    grid answer would pass on the grid lookup alone and prove nothing about the
    ledger. The two presses this reproduces were six seconds apart on the range,
    and the case index had not caught up when it was read.
    """
    grid = _Grid(_live_group(), link_lag=True)

    first = grid.press(client)
    second = grid.press(client)

    assert first.status_code == 200
    assert second.status_code == 200
    assert grid.escalated == ["ev-0"], "the second press escalated ev-0 again"
    assert grid.case_links["ev-0"] == ["case-1"], "one alert, one case"
    assert first.json()["escalated"] == 1
    assert second.json()["escalated"] == 0


def test_the_message_counts_only_alerts_a_second_case_was_withheld_from(
    client: TestClient,
) -> None:
    """``already_escalated`` claimed 17 duplicates prevented on a first press
    where no case existed for any of them, and said nothing about the one alert
    that really did get a second case. It was false in both directions at once.

    Acknowledged-not-escalated events are skipped, but they are skipped because
    Security Onion already acknowledged them, which is a different sentence.
    """
    grid = _Grid(_live_group(), link_lag=True)

    first = grid.press(client).json()
    second = grid.press(client).json()

    # Nothing had a case before the first press, so nothing was withheld.
    assert first["already_escalated"] == 0
    assert first["already_acked"] == 17
    # The second press is the one that withheld a case, from exactly one alert.
    assert second["already_escalated"] == 1
    assert second["already_acked"] == 17
    assert second["escalated"] == 0
    assert second["remaining"] == 0


def test_an_alert_security_onion_already_escalated_is_counted_as_escalated(
    client: TestClient,
) -> None:
    """An analyst escalating from Security Onion's own console stamps
    ``event.escalated`` on the alert. soc-ai did not open that case and has no
    ledger row for it, but it must still not open a second one, and must not
    file the alert under "already acknowledged"."""
    grid = _Grid([_event(0, acknowledged=True, escalated=True), _event(1)])

    body = grid.press(client).json()

    assert grid.escalated == ["ev-1"]
    assert body["escalated"] == 1
    assert body["already_escalated"] == 1
    assert body["already_acked"] == 0


def test_a_case_opened_outside_this_instance_is_not_duplicated(client: TestClient) -> None:
    """Security Onion's case-to-event links are the cross-operator truth: a
    related document exists for the alert even though this instance's ledger is
    empty and the alert carries no flag."""
    grid = _Grid([_event(0), _event(1)])
    grid.case_links["ev-0"] = ["case-from-elsewhere"]

    body = grid.press(client).json()

    assert grid.escalated == ["ev-1"]
    assert body["escalated"] == 1
    assert body["already_escalated"] == 1


def test_a_grid_that_records_the_escalation_still_escalates_once(client: TestClient) -> None:
    """Negative control. On an index that DOES carry the flags, Security Onion
    hides an escalated alert from the next fetch, so the group arrives empty and
    the guard has nothing to do. The fix must not turn that into a refusal to
    escalate anything.
    """
    grid = _Grid([_event(i) for i in range(5)])
    first = grid.press(client).json()

    # Second press: the grid now hides them, exactly as a mapped index would.
    grid.events = []
    second = grid.press(client).json()

    assert sorted(grid.escalated) == [f"ev-{i}" for i in range(5)]
    assert first["escalated"] == 5
    assert first["already_escalated"] == 0
    assert first["already_acked"] == 0
    assert second["escalated"] == 0
    assert second["total"] == 0


def test_an_alert_escalated_from_an_investigation_is_not_escalated_again(
    client: TestClient,
) -> None:
    """The two escalate paths have to share one record.

    An analyst escalates a single alert from its investigation, then somebody
    presses escalate on the group that alert belongs to. Security Onion's case
    links would catch it, but only on a deployment whose case index this
    instance can read, so the group press is driven here with that lookup
    failing. The ledger the single-alert path writes is what is left.
    """
    import asyncio

    from soc_ai.store import investigations as inv_svc
    from soc_ai.tools._registry import ToolSpec

    async def seed() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(
                db, alert_es_id="ev-0", started_by="analyst", rule_name=_RULE
            )
            inv.report = {
                "recommended_actions": [
                    {
                        "tool_name": "escalate_to_case",
                        "tool_args": {"case_title": "t", "case_description": "d"},
                    }
                ]
            }
            await db.commit()
            return str(inv.id)

    inv_id = asyncio.run(seed())

    async def fake_escalate(
        alert_id: str, case_title: str = "", case_description: str = "", *, auth: Any
    ) -> dict[str, Any]:
        return {
            "case_id": "case-from-investigation",
            "alert_id": alert_id,
            "alert_linked": True,
            "events_attached": 1,
            "marked_escalated": True,
        }

    with patch(
        "soc_ai.tools.write_exec.get_tool",
        return_value=ToolSpec(
            name="escalate_to_case", read_only=False, description="", func=fake_escalate
        ),
    ):
        assert (
            client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()["status"]
            == "executed"
        )

    grid = _Grid([_event(0), _event(1)])

    async def unreadable(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        raise RuntimeError("this deployment cannot read the case index")

    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", grid.fetch),
        patch("soc_ai.api.webui_api.aq.count_group_events", grid.count),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", grid.write),
        patch("soc_ai.api.webui.routes_alert_actions.case_ids_for_alerts", unreadable),
    ):
        body = client.post(
            "/api/v1/alerts/escalate-group", json={"rule_name": _RULE, "range": "7d"}
        ).json()

    assert grid.escalated == ["ev-1"], "ev-0 was escalated a second time"
    assert body["escalated"] == 1
    assert body["already_escalated"] == 1


def test_a_failed_escalate_is_not_reported_as_a_withheld_duplicate(client: TestClient) -> None:
    """A write that never opened a case must not leave the alert counted as
    already escalated on the next press. That would strand it, reporting a
    duplicate prevented where no case was ever created."""
    grid = _Grid([_event(0)])

    async def failing(_tool: str, _args: dict[str, Any], **_kw: Any) -> tuple[None, str]:
        return None, "escalate_to_case returned 500"

    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", grid.fetch),
        patch("soc_ai.api.webui_api.aq.count_group_events", grid.count),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", failing),
        patch("soc_ai.api.webui.routes_alert_actions.case_ids_for_alerts", grid.links),
    ):
        first = client.post(
            "/api/v1/alerts/escalate-group", json={"rule_name": _RULE, "range": "7d"}
        ).json()

    assert first["escalated"] == 0
    assert first["failed"] == 1

    # The grid confirms no case exists, so the next press may try again.
    second = grid.press(client).json()
    assert second["escalated"] == 1
    assert second["already_escalated"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# A case created with nothing attached is not an escalation
#
# On the range an escalate answered {"status": "executed", "detail": "Case
# created: ..."} for an alert that was not on the grid at all. Security Onion
# created the case, answered the attach 200, attached nothing, and soc-ai wrote
# the alert into the escalation ledger as escalated. Two lies for the price of
# one: an empty case in the queue wearing an incident's title, and a ledger row
# that will refuse the case actually needed.
# ─────────────────────────────────────────────────────────────────────────────


def _seed_escalate_investigation(client: TestClient, alert_id: str = "ev-0") -> str:
    """A complete investigation whose action 0 is a pressable escalate."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def seed() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(
                db, alert_es_id=alert_id, started_by="analyst", rule_name=_RULE
            )
            inv.report = {
                "recommended_actions": [
                    {
                        "tool_name": "escalate_to_case",
                        "tool_args": {"case_title": "t", "case_description": "d"},
                    }
                ]
            }
            await db.commit()
            return str(inv.id)

    return asyncio.run(seed())


def _ledger(client: TestClient, alert_id: str) -> tuple[bool, str | None]:
    """``(claimed, case_id)`` for ``alert_id`` in soc-ai's escalation ledger."""
    import asyncio

    from soc_ai.store import escalations as esc_svc

    async def read() -> tuple[bool, str | None]:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            claims = await esc_svc.cases_for_alerts(db, [alert_id])
        return alert_id in claims, claims.get(alert_id)

    return asyncio.run(read())


def _press_action(client: TestClient, inv_id: str, result: dict[str, Any]) -> dict[str, Any]:
    """Press the investigation's escalate card with a tool that returns ``result``."""
    from soc_ai.tools._registry import ToolSpec

    async def fake_escalate(
        alert_id: str, case_title: str = "", case_description: str = "", *, auth: Any
    ) -> dict[str, Any]:
        return {**result, "alert_id": alert_id}

    with patch(
        "soc_ai.tools.write_exec.get_tool",
        return_value=ToolSpec(
            name="escalate_to_case", read_only=False, description="", func=fake_escalate
        ),
    ):
        out = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()
    return dict(out)


_EMPTY_CASE = {
    "case_id": "case-empty",
    "case_created": True,
    "alert_linked": False,
    "events_attached": 0,
    "marked_escalated": False,
    "link_error": (
        "case case-empty was created but Security Onion attached no event for "
        "alert ev-0: the alert is not on the grid, and the case is empty"
    ),
}


def test_a_case_that_attached_nothing_is_not_reported_as_an_escalate(
    client: TestClient,
) -> None:
    """The defect. The alert is on no case, so the press did not do the thing
    the operator asked for, and must not say it did. The case id belongs in the
    answer: there is now an empty case in Security Onion's queue and only the
    operator can deal with it."""
    inv_id = _seed_escalate_investigation(client)

    out = _press_action(client, inv_id, _EMPTY_CASE)

    assert out["status"] == "error"
    assert "case-empty" in (out["error"] or "")
    assert "not attached" in (out["error"] or "") or "attached no event" in (out["error"] or "")


def test_a_case_that_attached_nothing_leaves_the_ledger_claim_open(
    client: TestClient,
) -> None:
    """The second half of the defect. The ledger recorded the alert as escalated
    to a case that does not hold it, so the duplicate-prevention machinery would
    refuse to open the case actually needed. A claim with no case id on it is
    the honest record: soc-ai tried, nobody knows what Security Onion ended up
    with, and the next press reconciles it against the grid."""
    inv_id = _seed_escalate_investigation(client)

    _press_action(client, inv_id, _EMPTY_CASE)

    claimed, case_id = _ledger(client, "ev-0")
    assert claimed, "nothing recorded at all leaves the attempt invisible"
    assert case_id is None, "an unattached case was recorded as the alert's case"


def test_the_next_group_press_reconciles_an_unattached_escalate(client: TestClient) -> None:
    """What the open claim is for. The grid can be asked whether a case really
    holds the alert; it says no, so the claim is released and the alert is
    escalated for real rather than stranded behind a claim nobody can settle."""
    inv_id = _seed_escalate_investigation(client)
    _press_action(client, inv_id, _EMPTY_CASE)

    grid = _Grid([_event(0), _event(1)])
    body = grid.press(client).json()

    assert sorted(grid.escalated) == ["ev-0", "ev-1"], "ev-0 stayed stranded"
    assert body["escalated"] == 2
    assert body["already_escalated"] == 0


def test_a_linked_escalate_is_still_reported_and_still_recorded(client: TestClient) -> None:
    """Negative control. An escalate Security Onion really did attach must still
    answer executed, still name the case, and still take the ledger row that
    stops a second case. A fix that failed every escalate would satisfy the
    three tests above and destroy the feature."""
    inv_id = _seed_escalate_investigation(client)

    out = _press_action(
        client,
        inv_id,
        {
            "case_id": "case-real",
            "case_created": True,
            "alert_linked": True,
            "events_attached": 1,
            "marked_escalated": True,
        },
    )

    assert out["status"] == "executed"
    assert "case-real" in out["detail"]
    assert _ledger(client, "ev-0") == (True, "case-real")


def test_an_escalate_security_onion_did_not_stamp_says_so(client: TestClient) -> None:
    """The alert IS on the case, so this is not a failed escalate and pressing
    again would only open a duplicate. But Security Onion did not stamp the
    flag, so the alert still reads as untriaged in its own alert list, and the
    operator finding it there deserves to have been told."""
    inv_id = _seed_escalate_investigation(client)

    out = _press_action(
        client,
        inv_id,
        {
            "case_id": "case-real",
            "case_created": True,
            "alert_linked": True,
            "events_attached": 1,
            "marked_escalated": False,
            "mark_error": "case case-real holds the alert but marking it escalated returned 400",
        },
    )

    assert out["status"] == "executed"
    assert "case-real" in out["detail"]
    assert "not" in out["detail"] and "escalated" in out["detail"]
    # The alert is genuinely on the case, so the ledger row is correct.
    assert _ledger(client, "ev-0") == (True, "case-real")


def test_the_group_escalate_does_not_count_a_case_that_attached_nothing(
    client: TestClient,
) -> None:
    """Same defect on the group press. An empty case is a failed escalate, the
    claim stays open rather than being resolved to it, and the case id reaches
    the operator so the empty case can be dealt with."""
    grid = _Grid([_event(0)])

    async def attaches_nothing(
        _tool: str, tool_args: dict[str, Any], **_kw: Any
    ) -> tuple[dict[str, Any], None]:
        return {
            "alert_id": tool_args["alert_id"],
            "case_id": "case-empty",
            "case_created": True,
            "alert_linked": False,
            "events_attached": 0,
        }, None

    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", grid.fetch),
        patch("soc_ai.api.webui_api.aq.count_group_events", grid.count),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", attaches_nothing),
        patch("soc_ai.api.webui.routes_alert_actions.case_ids_for_alerts", grid.links),
    ):
        body = client.post(
            "/api/v1/alerts/escalate-group", json={"rule_name": _RULE, "range": "7d"}
        ).json()

    assert body["escalated"] == 0
    assert body["failed"] == 1
    assert body["empty_cases"] == ["case-empty"]
    assert _ledger(client, "ev-0") == (True, None)


# ---------------------------------------------------------------------------
# GET /escalations/stranded — the ledger's first operator surface.
#
# Every reader in the store is keyed by an explicit list of alert ids, which is
# what the press path needs and useless for "what is stuck". So the claim the
# test above leaves open — an escalate whose outcome nobody will ever learn,
# refusing every future escalate of ev-0 — could be seen only by opening the
# database.


def _backdate(client: TestClient, alert_id: str, *, minutes: int) -> None:
    """Age a claim past the settling window, since a claim is stamped now."""
    import asyncio

    from sqlalchemy import text

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            await db.execute(
                text(
                    "UPDATE alert_escalations "
                    "SET created_at = datetime('now', :d) WHERE alert_id = :a"
                ),
                {"d": f"-{minutes} minutes", "a": alert_id},
            )
            await db.commit()

    asyncio.run(go())


# ─────────────────────────────────────────────────────────────────────────────
# The two escalate paths racing
#
# The ledger made a repeated GROUP press safe, but only the group press ever
# reserved anything. The single-alert escalate an analyst runs from an
# investigation opened its case first and wrote the ledger row afterwards, which
# is a report rather than a reservation. Its own defences are the persisted
# ``action_executed`` marker, keyed to one investigation and one action, and a
# process-local lock on the same key: neither can see a group escalate over the
# same alert, and the group escalate could not see the single press either,
# because nothing named the alert until the case was already open. Both presses
# pass their own check and Security Onion ends with two cases on one alert.
#
# The tests below fix both halves of the reservation: that the single press
# holds the claim BEFORE it writes, which is what makes a concurrent group press
# collide, and that it honours a claim somebody else already holds.
# ─────────────────────────────────────────────────────────────────────────────


def _escalate_tool(result: dict[str, Any], *, seen: list[Any] | None = None) -> Any:
    """A patch of the write registry whose escalate returns ``result``.

    When ``seen`` is given, each call appends the alert id, so a test can assert
    whether Security Onion was written to at all.
    """
    from soc_ai.tools._registry import ToolSpec

    async def fake_escalate(
        alert_id: str, case_title: str = "", case_description: str = "", *, auth: Any
    ) -> dict[str, Any]:
        if seen is not None:
            seen.append(alert_id)
        return {**result, "alert_id": alert_id}

    return patch(
        "soc_ai.tools.write_exec.get_tool",
        return_value=ToolSpec(
            name="escalate_to_case", read_only=False, description="", func=fake_escalate
        ),
    )


_LINKED_CASE = {
    "case_id": "case-single",
    "case_created": True,
    "alert_linked": True,
    "events_attached": 1,
    "marked_escalated": True,
}


def _grid_holds_no_case() -> Any:
    async def none(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        return {}

    return patch("soc_ai.api.webui.routes_alert_actions.case_ids_for_alerts", none)


def _grid_cannot_be_read() -> Any:
    async def unreadable(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        raise RuntimeError("this deployment cannot read the case index")

    return patch("soc_ai.api.webui.routes_alert_actions.case_ids_for_alerts", unreadable)


def _hold(client: TestClient, alert_id: str, case_id: str | None) -> None:
    """Take a ledger claim on ``alert_id`` the way a group press would."""
    import asyncio

    from soc_ai.store import escalations as esc_svc

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            await esc_svc.claim(db, [alert_id], actor="group")
            if case_id:
                await esc_svc.record_case(db, alert_id, case_id)

    asyncio.run(go())


def test_a_stranded_claim_reaches_an_operator_surface(client: TestClient) -> None:
    """The claim the empty-case press leaves behind, on a route rather than in
    the database. It names the alert, who pressed, and when — the age being the
    fact that separates a request in flight from a permanently stuck alert."""
    grid = _Grid([_event(0)])

    async def attaches_nothing(
        _tool: str, tool_args: dict[str, Any], **_kw: Any
    ) -> tuple[dict[str, Any], None]:
        return {
            "alert_id": tool_args["alert_id"],
            "case_id": "case-empty",
            "case_created": True,
            "alert_linked": False,
            "events_attached": 0,
        }, None

    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", grid.fetch),
        patch("soc_ai.api.webui_api.aq.count_group_events", grid.count),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", attaches_nothing),
        patch("soc_ai.api.webui.routes_alert_actions.case_ids_for_alerts", grid.links),
    ):
        client.post("/api/v1/alerts/escalate-group", json={"rule_name": _RULE, "range": "7d"})

    # Fresh, the claim is a request in flight and the route says nothing —
    # which is the control that keeps the surface worth reading.
    assert client.get("/api/v1/escalations/stranded").json()["total"] == 0

    _backdate(client, "ev-0", minutes=90)
    body = client.get("/api/v1/escalations/stranded").json()
    assert body["total"] == 1
    assert [c["alert_id"] for c in body["claims"]] == ["ev-0"]
    assert body["claims"][0]["claimed_at"].endswith("Z")
    assert body["settling_minutes"] == 15, (
        "zero claims mean nothing without the window that was checked"
    )


def test_a_settled_escalate_leaves_the_stranded_list_empty(client: TestClient) -> None:
    """NEGATIVE CONTROL. A press that opened a case and attached the alert is a
    working escalate, and a panel that flagged it would be ignored within a
    day. Backdated well past the window, so only the case id can be the reason
    it is absent."""
    grid = _Grid([_event(0)])
    body = grid.press(client).json()
    assert body["escalated"] == 1
    _backdate(client, "ev-0", minutes=90)

    stranded = client.get("/api/v1/escalations/stranded").json()
    assert (stranded["total"], stranded["claims"]) == (0, [])


def test_the_single_alert_escalate_claims_the_alert_before_it_opens_the_case(
    client: TestClient,
) -> None:
    """The defect, read at the instant it matters.

    The window a group press lands in is the one between this press deciding to
    write and the case existing. The ledger is read from inside the write tool,
    which is exactly that instant: an empty ledger there means a group press
    arriving now finds nothing, claims the alert and opens its own case.
    """
    from soc_ai.store import escalations as esc_svc
    from soc_ai.tools._registry import ToolSpec

    inv_id = _seed_escalate_investigation(client)
    held_at_write: list[bool] = []

    async def fake_escalate(
        alert_id: str, case_title: str = "", case_description: str = "", *, auth: Any
    ) -> dict[str, Any]:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            claims = await esc_svc.cases_for_alerts(db, [alert_id])
        held_at_write.append(alert_id in claims)
        return {**_LINKED_CASE, "alert_id": alert_id}

    with (
        patch(
            "soc_ai.tools.write_exec.get_tool",
            return_value=ToolSpec(
                name="escalate_to_case", read_only=False, description="", func=fake_escalate
            ),
        ),
        _grid_holds_no_case(),
    ):
        out = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()

    assert out["status"] == "executed"
    assert held_at_write == [True], (
        "the case was opened while nothing in the ledger named the alert, so a "
        "group press in that window would have opened a second one"
    )
    assert _ledger(client, "ev-0") == (True, "case-single")


def test_the_single_alert_escalate_will_not_open_a_second_case_over_a_held_claim(
    client: TestClient,
) -> None:
    """The other half. A group press that got there first holds the alert and
    has a case for it, so this press must answer rather than write."""
    inv_id = _seed_escalate_investigation(client)
    _hold(client, "ev-0", "case-from-the-group")
    written: list[Any] = []

    with _escalate_tool({"case_id": "case-duplicate", "alert_linked": True}, seen=written):
        out = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()

    assert written == [], "a second case was opened for an alert already on one"
    assert out["status"] == "executed"
    assert "already" in out["detail"].lower()
    # The first case an alert reached is the one the ledger keeps.
    assert _ledger(client, "ev-0") == (True, "case-from-the-group")


def test_an_unsettled_claim_the_grid_cannot_answer_for_stops_the_escalate(
    client: TestClient,
) -> None:
    """An earlier escalate claimed the alert and never came back with a case id,
    and the case index cannot be read. Opening a case now might duplicate one
    that already exists; refusing leaves the alert where it is, and only the
    second of those is reversible. Answered as an error, not an execution, so
    the card stays pressable once the grid is readable again."""
    inv_id = _seed_escalate_investigation(client)
    _hold(client, "ev-0", None)
    written: list[Any] = []

    with (
        _escalate_tool({"case_id": "case-duplicate", "alert_linked": True}, seen=written),
        _grid_cannot_be_read(),
    ):
        out = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()

    assert written == []
    assert out["status"] == "error"
    assert "case index" in (out["error"] or "")


def test_a_claim_the_grid_disproves_does_not_strand_the_alert(client: TestClient) -> None:
    """NEGATIVE CONTROL. A reservation that never released anything would turn
    every failed escalate into an alert nobody could escalate again. The stale
    claim is released and retaken, and the case is opened."""
    inv_id = _seed_escalate_investigation(client)
    _hold(client, "ev-0", None)
    written: list[Any] = []

    with (
        _escalate_tool({**_LINKED_CASE, "case_id": "case-retried"}, seen=written),
        _grid_holds_no_case(),
    ):
        out = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()

    assert out["status"] == "executed"
    assert written == ["ev-0"]
    assert _ledger(client, "ev-0") == (True, "case-retried")
