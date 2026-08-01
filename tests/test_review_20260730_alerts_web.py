"""Regression tests for the 2026-07-30 alerts-web review bucket (B03).

Covers:
* F04 — advisory-action idempotency markers key on stable identity, not list
  position, so a chat-resolve that REPLACES recommended_actions can't bind a
  stale "executed" marker to a different action.
* F06 — Phase-D `targeted_dispatch` events count toward toolCalls/pivots so a
  tool-grounded synth-first run isn't badged "heuristic · no tools".
* F21 — `ack_group` can actually observe capping (a >cap group reports capped).
* F22 — `/alerts/events` and `/alerts/representative` forward the `hide_acked`
  filter the console sends.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui._timeline import _action_identity, _build_actions, _build_timeline
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui import alerts_query as aq
from soc_ai.webui.alerts_query import AlertEvent


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


# ── F04: identity-keyed action idempotency ─────────────────────────────────


def _exec_marker(action: dict, *, index: int, by: str = "alice") -> SimpleNamespace:
    """A NEW-format action_executed marker (carries action_key)."""
    return SimpleNamespace(
        kind="action_executed",
        payload={
            "index": index,
            "action_key": _action_identity(action),
            "tool_name": action.get("tool_name", ""),
            "success": True,
            "by": by,
        },
    )


def test_executed_marker_does_not_bind_to_replaced_action() -> None:
    """F04: after a chat-resolve REPLACES recommended_actions, the ack marker at
    the old index 0 must NOT mark the escalate that now occupies index 0 applied
    (that would render an unopened SO case as "Executed" and non-actionable)."""
    ack = {"tool_name": "ack_alert", "rationale": "benign"}
    marker = _exec_marker(ack, index=0)
    # Resolve replaced the list: an escalate now sits where the ack was.
    report_v2 = {"recommended_actions": [{"tool_name": "escalate_to_case", "rationale": "case it"}]}
    actions = _build_actions([marker], report_v2)
    assert actions[0].applied is False  # escalate stays actionable — no false "Executed"


def test_executed_marker_follows_action_across_reindex() -> None:
    """F04: identity-keying means the executed ack stays marked applied even when
    a resolve re-indexes it (here the ack moves from index 0 to index 1)."""
    ack = {"tool_name": "ack_alert", "rationale": "benign"}
    marker = _exec_marker(ack, index=0)
    report_v2 = {
        "recommended_actions": [
            {"tool_name": "escalate_to_case", "rationale": "new"},
            ack,  # the executed ack, now at index 1
        ]
    }
    actions = _build_actions([marker], report_v2)
    assert actions[0].applied is False  # the new escalate is untouched
    assert actions[1].applied is True  # the executed ack is still applied
    assert actions[1].appliedNote == "Executed · alice"


# ── F06: Phase-D dispatches count as tool calls ────────────────────────────


def test_build_timeline_counts_targeted_dispatch() -> None:
    """F06: targeted_dispatch (Phase-D real-tool runs) count toward toolCalls and,
    for query/zeek/pcap tools, pivots — so the run isn't badged 'no tools'."""
    events = [
        SimpleNamespace(
            kind="targeted_dispatch",
            sequence=1,
            payload={"tool_name": "t_get_event_raw", "question": "q", "tool_args": {}},
        ),
        SimpleNamespace(
            kind="targeted_dispatch",
            sequence=2,
            payload={"tool_name": "t_query_events_oql", "question": "q2", "tool_args": {}},
        ),
    ]
    _timeline, tool_calls, pivots, _has_oracle = _build_timeline(events)
    assert tool_calls == 2  # both dispatches counted (was 0 before the fix)
    assert pivots == 1  # only the query dispatch is a pivot


# ── F21: ack-group capping is observable ───────────────────────────────────


def test_ack_group_reports_capped_when_group_exceeds_cap(client: TestClient) -> None:
    """F21: a group at the fetch ceiling must report capped=True (was always
    False because the cap equalled the fetch clamp, silently part-acking)."""
    from soc_ai.api.webui.routes_alert_actions import _ACK_CAP

    # The real fetch clamps to aq.MAX_EVENTS; simulate a group that fills it.
    fake_events = [
        AlertEvent(
            es_id=f"ev-{i}",
            timestamp="t",
            src="1.1.1.1:5",
            dst="2.2.2.2:443",
            severity="high",
            host="wks-1",
        )
        for i in range(aq.MAX_EVENTS)
    ]

    async def fake_write(tool_name, tool_args, *, auth, settings, **_kwargs):
        return {"acknowledged": True}, None

    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", AsyncMock(return_value=fake_events)),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", fake_write),
    ):
        resp = client.post(
            "/api/v1/alerts/ack-group", json={"rule_name": "NOISY RULE", "range": "24h"}
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["capped"] is True
    assert body["acked"] == _ACK_CAP  # acked up to the cap, the rest left for a re-run


def test_ack_cap_below_fetch_clamp_invariant() -> None:
    """F21: the cap MUST sit below the fetch clamp or capping is undetectable."""
    from soc_ai.api.webui.routes_alert_actions import _ACK_CAP

    assert _ACK_CAP < aq.MAX_EVENTS


# ── F22: hide_acked is forwarded ───────────────────────────────────────────


def test_alerts_events_forwards_hide_acked(client: TestClient) -> None:
    """F22: GET /alerts/events?hide_acked=true forwards hide_acked into
    fetch_group_events (it was silently dropped, showing acked events)."""
    mock_fetch = AsyncMock(return_value=[])
    with patch("soc_ai.api.webui_api.aq.fetch_group_events", mock_fetch):
        resp = client.get(
            "/api/v1/alerts/events",
            params={"rule_name": "ET X", "kind": "suricata", "hide_acked": "true"},
        )
    assert resp.status_code == 200
    _args, kwargs = mock_fetch.call_args
    assert kwargs.get("hide_acked") is True


def test_representative_forwards_hide_acked(client: TestClient) -> None:
    """F22: GET /alerts/representative?hide_acked=true forwards the filter too."""
    events = [
        AlertEvent(
            es_id="e1",
            timestamp="2026-01-01T00:00:00Z",
            src="1.1.1.1",
            dst="2.2.2.2",
            severity="low",
            host="h",
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            dst_port=443,
        )
    ]
    mock_fetch = AsyncMock(return_value=events)
    with patch("soc_ai.api.webui_api.aq.fetch_group_events", mock_fetch):
        resp = client.get(
            "/api/v1/alerts/representative",
            params={"rule_name": "ET X", "kind": "suricata", "hide_acked": "true"},
        )
    assert resp.status_code == 200
    _args, kwargs = mock_fetch.call_args
    assert kwargs.get("hide_acked") is True
