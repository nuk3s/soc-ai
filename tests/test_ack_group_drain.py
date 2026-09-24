"""Bulk acknowledge has to drain the group it is pointed at.

``ack_group`` fetched one page of not-yet-acknowledged events and acknowledged
up to ``_ACK_CAP`` of them. That relies on Security Onion dropping an
acknowledged event out of the next fetch, which needs ``event.acknowledged`` to
be a searchable field. On a live SO 3.2.0 grid it is not, for Elastic Defend
endpoint alerts: ``.ds-logs-endpoint.alerts-default-*`` is mapped
``dynamic: false`` without that field, so Security Onion writes the flag into
``_source`` and no query can ever see it. Measured on 2026-09-06 against a
16-event endpoint group: all 16 acknowledged (SO answered 200 each time), and
the very next fetch with the hide-acknowledged filter returned the same 16 ids.
Every press re-acknowledged the same events and reported success.

The flag is still in ``_source`` on every hit, so these tests pin the behaviour
that reads it there: skip what Security Onion already records as acknowledged,
page past it, and report what is left.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui import alerts_query as aq
from soc_ai.webui.alerts_query import AlertEvent

_RULE = "Ingress Tool Transfer via CURL"


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


def _event(idx: int, *, acknowledged: bool = False) -> AlertEvent:
    return AlertEvent(
        es_id=f"ev-{idx}",
        timestamp="t",
        src="host-a",
        dst="host-b",
        severity="high",
        host="wks-1",
        acknowledged=acknowledged,
    )


def _post(client: TestClient) -> Any:
    return client.post("/api/v1/alerts/ack-group", json={"rule_name": _RULE, "range": "24h"})


def _run(
    client: TestClient,
    pages: dict[int, list[AlertEvent]],
    *,
    matched: int,
) -> tuple[Any, list[str], list[int]]:
    """Drive ack-group against a grid that serves ``pages`` keyed by offset."""
    acked: list[str] = []
    offsets: list[int] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> list[AlertEvent]:
        offset = int(kwargs.get("offset", 0))
        offsets.append(offset)
        return pages.get(offset, [])

    async def fake_count(*_args: Any, **_kwargs: Any) -> int:
        return matched

    async def fake_write(
        _tool: str, tool_args: dict[str, Any], **_kwargs: Any
    ) -> tuple[dict[str, Any], None]:
        acked.append(tool_args["alert_id"])
        return {"acknowledged": True}, None

    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", fake_fetch),
        patch("soc_ai.api.webui_api.aq.count_group_events", fake_count),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", fake_write),
    ):
        resp = _post(client)
    return resp, acked, offsets


def test_events_the_grid_still_lists_as_acknowledged_are_not_acknowledged_again(
    client: TestClient,
) -> None:
    """The defect, at its smallest: a whole page Security Onion already records
    as acknowledged must produce no writes at all, not a page of duplicates."""
    pages = {0: [_event(i, acknowledged=True) for i in range(16)]}
    resp, acked, _offsets = _run(client, pages, matched=16)

    assert resp.status_code == 200
    body = resp.json()
    assert acked == []
    assert body["acked"] == 0
    assert body["already_acked"] == 16
    assert body["remaining"] == 0
    assert body["capped"] is False


def test_ack_group_pages_past_events_the_grid_will_not_hide(client: TestClient) -> None:
    """A press must reach the events below the ones it already acknowledged.

    Offset 0 is a full page Security Onion still lists as acknowledged; the
    fresh events start at offset 200. Before the fix the fetch stopped at offset
    0 and the group could never empty.
    """
    pages = {
        0: [_event(i, acknowledged=True) for i in range(aq.MAX_EVENTS)],
        aq.MAX_EVENTS: [_event(1000 + i) for i in range(5)],
    }
    resp, acked, offsets = _run(client, pages, matched=aq.MAX_EVENTS + 5)

    assert resp.status_code == 200
    body = resp.json()
    assert aq.MAX_EVENTS in offsets, "ack-group never looked past the first page"
    assert sorted(acked) == sorted(f"ev-{1000 + i}" for i in range(5))
    assert body["acked"] == 5
    assert body["already_acked"] == aq.MAX_EVENTS
    assert body["remaining"] == 0
    assert body["capped"] is False


def test_ack_group_reports_how_many_are_left(client: TestClient) -> None:
    """Over the cap, the operator gets the real number left, not just a flag."""
    from soc_ai.api.webui.routes_alert_actions import _ACK_CAP

    pages = {
        0: [_event(i) for i in range(aq.MAX_EVENTS)],
        aq.MAX_EVENTS: [_event(aq.MAX_EVENTS + i) for i in range(aq.MAX_EVENTS)],
    }
    resp, acked, _offsets = _run(client, pages, matched=500)

    assert resp.status_code == 200
    body = resp.json()
    assert len(acked) == _ACK_CAP
    assert body["acked"] == _ACK_CAP
    assert body["capped"] is True
    assert body["remaining"] == 500 - _ACK_CAP


def test_a_grid_that_hides_acknowledged_events_still_drains_in_one_press(
    client: TestClient,
) -> None:
    """Negative control: on a grid whose index DOES carry the field, nothing is
    skipped and nothing is paged past. Suricata alerts behaved this way in the
    same measurement, so the fix must not change them."""
    pages = {0: [_event(i) for i in range(12)]}
    resp, acked, offsets = _run(client, pages, matched=12)

    assert resp.status_code == 200
    body = resp.json()
    assert len(acked) == 12
    assert body["already_acked"] == 0
    assert body["remaining"] == 0
    assert body["capped"] is False
    assert offsets == [0], "a short first page needs no second fetch"


def test_ack_group_stops_scanning_at_the_bound(client: TestClient) -> None:
    """A group of nothing but already-acknowledged events cannot be scanned
    forever. The scan stops at ``_ACK_MAX_SCAN`` and says so by reporting what
    is still outstanding rather than a false all-clear."""
    from soc_ai.api.webui.routes_alert_actions import _ACK_MAX_SCAN

    pages = {
        offset: [_event(offset + i, acknowledged=True) for i in range(aq.MAX_EVENTS)]
        for offset in range(0, _ACK_MAX_SCAN + 2 * aq.MAX_EVENTS, aq.MAX_EVENTS)
    }
    resp, acked, offsets = _run(client, pages, matched=_ACK_MAX_SCAN + aq.MAX_EVENTS)

    assert resp.status_code == 200
    body = resp.json()
    assert acked == []
    assert len(offsets) <= _ACK_MAX_SCAN // aq.MAX_EVENTS + 1
    assert body["capped"] is True
    assert body["remaining"] > 0


def test_escalate_group_does_not_open_a_second_case_for_an_escalated_alert(
    client: TestClient,
) -> None:
    """Same class, worse outcome: on that index an escalated alert also stays
    visible, and escalating it again opens a DUPLICATE Security Onion case."""
    escalated: list[str] = []

    async def fake_fetch(*_args: Any, **kwargs: Any) -> list[AlertEvent]:
        if int(kwargs.get("offset", 0)):
            return []
        return [_event(i, acknowledged=True) for i in range(4)]

    async def fake_count(*_args: Any, **_kwargs: Any) -> int:
        return 4

    async def fake_write(
        _tool: str, tool_args: dict[str, Any], **_kwargs: Any
    ) -> tuple[dict[str, Any], None]:
        escalated.append(tool_args["alert_id"])
        return {"case_created": True}, None

    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", fake_fetch),
        patch("soc_ai.api.webui_api.aq.count_group_events", fake_count),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", fake_write),
    ):
        resp = client.post(
            "/api/v1/alerts/escalate-group", json={"rule_name": _RULE, "range": "24h"}
        )

    assert resp.status_code == 200
    assert escalated == []
    assert resp.json()["escalated"] == 0
