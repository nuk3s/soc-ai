"""The needs-you count: one total for the Dashboard tile, the sidebar and the bell.

Dogfood 2026-10-06: the landing page said "queue clear" while 11 leads waited,
and the bell said "None need attention". ``GET /needs-you`` states every part of
the work that waits on the analyst and the total, and the three surfaces read it.
The first test seeds one item of each part and reads a total of five.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import ConnectionError as EsConnectionError
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui.alerts_query import AlertGroup, GroupPage

from tests.test_analytics_api import _seed_shadow_hit

_ESCALATE = {
    "tool_name": "escalate_to_case",
    "tool_args": {"alert_id": "es-tp", "case_title": "t", "case_description": "d"},
    "rationale": "The beacon matches a known C2 address.",
}
_ACK = {
    "tool_name": "ack_alert",
    "tool_args": {"alert_id": "es-fp"},
    "rationale": "Benign scanner.",
}


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
        with TestClient(app) as test_client:
            yield test_client


def _ago(hours: float) -> datetime:
    """A stored (naive UTC) timestamp that many hours back from now."""
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _seed_lead(client: TestClient, *, formed_hours_ago: float = 1.0, idx: int = 0) -> int:
    """A lead whose hunt has finished: it waits on a decision."""
    from soc_ai.store.models import Hunt, Lead

    async def go() -> int:
        async with client.app.state.db_sessionmaker() as db:
            hunt = Hunt(
                id=f"needs-you-hunt-{idx}",
                objective="look at this lead",
                objective_hash=f"x{idx}",
                started_by="auto-hunt",
                kind="lead",
                status="complete",
            )
            db.add(hunt)
            await db.flush()
            lead = Lead(
                status="hunting",
                entities_json=[["host", "10.1.2.3"]],
                kinds_json=["catalog_match"],
                hunt_id=hunt.id,
                formed_at=_ago(formed_hours_ago),
            )
            db.add(lead)
            await db.commit()
            return int(lead.id)

    return asyncio.run(go())


def _seed_run(
    client: TestClient,
    run_id: str,
    *,
    alert_id: str,
    verdict: str,
    actions: list[dict[str, Any]] | None = None,
    hours_ago: float = 1.0,
    events: list[tuple[str, dict[str, Any]]] | None = None,
) -> None:
    """One complete investigation, and the events the action card reads."""
    from soc_ai.store.models import Investigation, InvestigationEvent

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id=run_id,
                    alert_es_id=alert_id,
                    kind="suricata",
                    rule_name=f"ET TEST {run_id}",
                    status="complete",
                    verdict=verdict,
                    confidence=0.8,
                    report={"verdict": verdict, "recommended_actions": actions or []},
                    created_at=_ago(hours_ago),
                    finished_at=_ago(hours_ago),
                )
            )
            await db.flush()
            for seq, (kind, payload) in enumerate(events or []):
                db.add(
                    InvestigationEvent(
                        investigation_id=run_id, sequence=seq, kind=kind, payload=payload
                    )
                )
            await db.commit()

    asyncio.run(go())


def _one_untriaged_group() -> GroupPage:
    """One alert group no investigation names: it has no verdict."""
    return GroupPage(
        [
            AlertGroup(
                rule_name="ET TEST untriaged",
                count=3,
                severity="high",
                latest_ts=datetime.now(UTC).isoformat(),
                latest_id="es-untriaged",
            )
        ],
        3,
    )


def _needs_you(client: TestClient) -> dict[str, Any]:
    res = client.get("/api/v1/needs-you")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_one_item_of_each_part_reads_a_total_of_five(client: TestClient) -> None:
    _seed_lead(client)
    _seed_shadow_hit(client, complete=True)
    _seed_run(client, "INV-NMI", alert_id="es-nmi", verdict="needs_more_info")
    _seed_run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", actions=[_ESCALATE])
    with patch(
        "soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=_one_untriaged_group())
    ):
        body = _needs_you(client)
    assert body["leads_needing_decision"] == 1
    assert body["unread_shadow_hits"] == 1
    assert body["untriaged_groups"] == 1
    assert body["needs_more_info"] == 1
    assert body["pending_actions"] == 1
    assert body["total"] == 5
    assert body["unknown"] == []
    assert body["alert_window"] == "7d"
    assert body["verdict_window"] == "30d"
    # The hunting half is the Hunts page count, read through its own route.
    hunting = client.get("/api/v1/hunts/needs-you").json()
    assert hunting["leads_needing_decision"] == body["leads_needing_decision"]
    assert hunting["unread_shadow_hits"] == body["unread_shadow_hits"]
    # The needs-more-info part is the count the Investigations list shows for
    # the link the console builds.
    since = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    listed = client.get(
        "/api/v1/investigations", params={"verdict": "needs_more_info", "since": since}
    ).json()
    assert listed["total"] == body["needs_more_info"]


def test_an_empty_store_needs_nothing(client: TestClient) -> None:
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=GroupPage([], 0))):
        body = _needs_you(client)
    assert body["total"] == 0
    assert body["unknown"] == []


def test_a_grid_outage_takes_the_alert_part_and_leaves_the_rest(client: TestClient) -> None:
    """A failed read is not a zero. The four database parts still answer."""
    _seed_lead(client)
    _seed_run(client, "INV-NMI", alert_id="es-nmi", verdict="needs_more_info")
    with patch(
        "soc_ai.webui.alerts_query.fetch_groups",
        AsyncMock(side_effect=EsConnectionError("refused")),
    ):
        body = _needs_you(client)
    assert body["untriaged_groups"] is None
    assert body["unknown"] == ["untriaged_groups"]
    assert body["leads_needing_decision"] == 1
    assert body["needs_more_info"] == 1
    assert body["total"] == 2


def test_the_alert_part_hides_a_group_with_a_verdict(client: TestClient) -> None:
    """NEGATIVE CONTROL. A group whose rule has a verdict is not waiting."""
    _seed_run(client, "INV-FP", alert_id="es-untriaged", verdict="false_positive")
    page = _one_untriaged_group()
    page.groups[0].rule_name = "ET TEST INV-FP"
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=page)):
        body = _needs_you(client)
    assert body["untriaged_groups"] == 0


def test_one_grid_read_serves_the_alert_part_for_its_ttl(client: TestClient) -> None:
    fetch = AsyncMock(return_value=_one_untriaged_group())
    with patch("soc_ai.webui.alerts_query.fetch_groups", fetch):
        _needs_you(client)
        _needs_you(client)
    assert fetch.await_count == 1


def test_an_executed_action_is_not_pending(client: TestClient) -> None:
    """NEGATIVE CONTROL. The execution receipt the card reads takes it off."""
    receipt = {
        "success": True,
        "by": "ana",
        "action_key": json.dumps(
            {
                "tool_name": _ESCALATE["tool_name"],
                "tool_args": _ESCALATE["tool_args"],
                "rationale": _ESCALATE["rationale"],
            },
            sort_keys=True,
            default=str,
        ),
    }
    _seed_run(
        client,
        "INV-TP",
        alert_id="es-tp",
        verdict="true_positive",
        actions=[_ESCALATE],
        events=[("action_executed", receipt)],
    )
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=GroupPage([], 0))):
        assert _needs_you(client)["pending_actions"] == 0


def test_a_dismissed_action_is_not_pending_and_an_undo_counts_it_again(
    client: TestClient,
) -> None:
    """The action card stores a dismissal, and the count follows it.

    The investigation page branch made a dismissal persist as an event. The
    count read the execute receipts only, so a dismissed recommendation kept
    the needs-you total up after the card said it was handled.
    """
    _seed_run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", actions=[_ESCALATE])
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=GroupPage([], 0))):
        assert _needs_you(client)["pending_actions"] == 1
        res = client.post("/api/v1/investigations/INV-TP/actions/0/dismiss")
        assert res.status_code == 200, res.text
        assert _needs_you(client)["pending_actions"] == 0
        res = client.post("/api/v1/investigations/INV-TP/actions/0/restore")
        assert res.status_code == 200, res.text
        assert _needs_you(client)["pending_actions"] == 1


def test_a_false_positive_acknowledgement_is_not_counted(client: TestClient) -> None:
    """NEGATIVE CONTROL. The housekeeping ack on a false positive would drown the count."""
    _seed_run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", actions=[_ACK])
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=GroupPage([], 0))):
        assert _needs_you(client)["pending_actions"] == 0


def test_a_replaced_run_is_not_counted(client: TestClient) -> None:
    """NEGATIVE CONTROL. A later run of the same alert stands in its place."""
    _seed_run(
        client,
        "INV-OLD",
        alert_id="es-tp",
        verdict="true_positive",
        actions=[_ESCALATE],
        hours_ago=5,
    )
    _seed_run(client, "INV-NEW", alert_id="es-tp", verdict="false_positive", hours_ago=1)
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=GroupPage([], 0))):
        assert _needs_you(client)["pending_actions"] == 0


def test_a_run_outside_the_window_is_not_counted(client: TestClient) -> None:
    _seed_run(
        client,
        "INV-TP",
        alert_id="es-tp",
        verdict="true_positive",
        actions=[_ESCALATE],
        hours_ago=31 * 24,
    )
    _seed_run(client, "INV-NMI", alert_id="es-nmi", verdict="needs_more_info", hours_ago=31 * 24)
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=GroupPage([], 0))):
        body = _needs_you(client)
    assert body["pending_actions"] == 0
    assert body["needs_more_info"] == 0


# ── The bell ────────────────────────────────────────────────────────────────


def test_the_bell_lists_an_old_lead_and_marks_it_warn(client: TestClient) -> None:
    """The feed read the last 24 h only and marked only a shadow lead warn.

    The bell then said "None need attention" while 10 leads waited on Hunts.
    """
    lead_id = _seed_lead(client, formed_hours_ago=72)
    rows = client.get("/api/v1/notifications").json()
    row = next(r for r in rows if r["id"] == f"lead:{lead_id}")
    assert row["tone"] == "warn"
    assert row["group"] == "hunting"


def test_the_bell_folds_the_leads_past_five_into_one_row(client: TestClient) -> None:
    ids = [_seed_lead(client, formed_hours_ago=1 + i, idx=i) for i in range(7)]
    rows = client.get("/api/v1/notifications").json()
    lead_rows = [r for r in rows if r["id"].startswith("lead:")]
    assert [r["id"] for r in lead_rows] == [f"lead:{i}" for i in ids[:5]]
    more = next(r for r in rows if r["id"] == "lead-more")
    assert more["title"] == "2 more leads are open. Open Hunts to decide."
    assert more["dismissible"] is False
    assert more["href"] == "/hunts#leads"


def test_the_bell_adds_no_fold_row_for_five_leads(client: TestClient) -> None:
    """NEGATIVE CONTROL. Five leads fit, so no row states a count of zero."""
    for i in range(5):
        _seed_lead(client, formed_hours_ago=1 + i, idx=i)
    rows = client.get("/api/v1/notifications").json()
    assert not [r for r in rows if r["id"] == "lead-more"]
    assert len([r for r in rows if r["id"].startswith("lead:")]) == 5
