"""An alert group row carries its waiting actions and its reason (J1, 2026-11-13).

The Alerts view "Needs decision" counted one needs-more-info group. The nine
true positive groups with a waiting Escalate were not in it, because the row
carried nothing about an action. The row also showed no reason: the analyst
opened each report to learn why a group was a true positive.

Each group now carries ``waitingActions``, the actions that wait for a person
on its true positive runs, under the needs-you rule. It carries the headline of
the run behind the standing verdict and of the run behind the window verdict.

The negative controls: a false positive recommends an acknowledgement, and
that housekeeping is not a decision, so it counts nothing. An action that an
analyst dismissed waits for nobody.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui.alerts_query import AlertGroup, GroupPage

_RULE = "ET EXPLOIT Example Chunked Request"
_ESCALATE = {
    "tool_name": "escalate_to_case",
    "tool_args": {"case_title": "t", "case_description": "d"},
    "rationale": "The payload matches the exploit.",
}
_ACK = {"tool_name": "ack_alert", "tool_args": {}, "rationale": "Close the noise of this rule."}


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _ago(hours: float) -> datetime:
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _run(
    client: TestClient,
    run_id: str,
    *,
    alert_id: str,
    verdict: str,
    hours_ago: float,
    actions: list[dict[str, Any]] | None = None,
    rationale: str = "",
    events: list[tuple[str, dict[str, Any]]] | None = None,
) -> None:
    from soc_ai.store.models import Investigation, InvestigationEvent

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id=run_id,
                    alert_es_id=alert_id,
                    rule_name=_RULE,
                    status="complete",
                    verdict=verdict,
                    confidence=0.8,
                    src_ip="10.20.30.5",
                    dest_ip="10.40.50.7",
                    rationale=rationale,
                    report={"verdict": verdict, "recommended_actions": actions or []},
                    started_by="scheduler",
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


def _group(client: TestClient, range_: str = "24h") -> dict[str, Any]:
    page = GroupPage(
        [
            AlertGroup(
                rule_name=_RULE,
                count=4,
                severity="medium",
                latest_ts=datetime.now(UTC).isoformat(),
                latest_id="es-latest",
            )
        ],
        4,
    )
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=page)):
        res = client.get("/api/v1/alerts", params={"range": range_})
    assert res.status_code == 200, res.text
    groups: list[dict[str, Any]] = res.json()["groups"]
    assert len(groups) == 1
    return groups[0]


def test_a_true_positive_group_carries_its_waiting_escalate(client: TestClient) -> None:
    _run(
        client,
        "INV-TP",
        alert_id="es-tp",
        verdict="true_positive",
        hours_ago=2,
        actions=[_ESCALATE],
        rationale="The request body holds a web shell upload.",
    )

    g = _group(client)

    assert g["waitingActions"] == 1
    assert g["headline"] == "The request body holds a web shell upload."
    assert g["windowHeadline"] == "The request body holds a web shell upload."


def test_a_false_positive_acknowledgement_is_no_decision(client: TestClient) -> None:
    # Negative control: the false positive recommends an acknowledgement. It
    # waits too, but it is housekeeping, and the needs-you rule counts only a
    # true positive.
    _run(
        client,
        "INV-FP",
        alert_id="es-fp",
        verdict="false_positive",
        hours_ago=2,
        actions=[_ACK],
        rationale="The traffic is a known updater.",
    )

    g = _group(client)

    assert g["waitingActions"] == 0
    assert g["headline"] == "The traffic is a known updater."


def test_a_dismissed_escalate_waits_for_nobody(client: TestClient) -> None:
    _run(
        client,
        "INV-TP-DONE",
        alert_id="es-tp",
        verdict="true_positive",
        hours_ago=2,
        actions=[_ESCALATE],
        events=[("action_dismissed", {"index": 0, "by": "analyst"})],
    )

    assert _group(client)["waitingActions"] == 0


def test_a_true_positive_run_in_the_window_counts_under_a_newer_verdict(
    client: TestClient,
) -> None:
    # Two alerts of one rule: the true positive with the waiting Escalate is in
    # the window, and the newest run of the rule is a false positive. The row
    # counts the action of the true positive run, and it names both headlines.
    _run(
        client,
        "INV-TP-OLD",
        alert_id="es-a",
        verdict="true_positive",
        hours_ago=6,
        actions=[_ESCALATE],
        rationale="The host ran the dropped payload.",
    )
    _run(
        client,
        "INV-FP-NEW",
        alert_id="es-b",
        verdict="false_positive",
        hours_ago=1,
        rationale="The scanner is an approved asset.",
    )

    g = _group(client)

    assert g["invId"] == "INV-FP-NEW"
    assert g["windowInvId"] == "INV-TP-OLD"
    assert g["waitingActions"] == 1
    assert g["headline"] == "The scanner is an approved asset."
    assert g["windowHeadline"] == "The host ran the dropped payload."


def test_an_untriaged_group_has_no_reason_and_no_action(client: TestClient) -> None:
    g = _group(client)

    assert g["waitingActions"] == 0
    assert g["headline"] is None
    assert g["windowHeadline"] is None
