"""One rule for "waits for you": the run page states only work that Needs you lists (NY5).

The macro review of 2026-11-17 (m14) found that at 24 hours 10 of 19 open
detections stated "1 action waits for you" on their investigation page, and
the agent found them in no queue. A read-only count of production gave the
cause: each of the 10 is a false positive with an open acknowledge. The
needs-you rule leaves the acknowledge of a false positive out
(:func:`soc_ai.api.webui.action_rules.run_requests`), and the run page counted
every open action.

Each action card now carries ``waits`` from the one rule, and the page counts
those. The test holds, for every investigation it seeds: an action waits on
the page exactly when the investigation is an item of Needs you.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui import action_rules
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui.alerts_query import GroupPage

from tests.test_campaign_facts import LEASED, OUTSIDE, seed_hosts, seed_run

_NO_GROUPS = "soc_ai.webui.alerts_query.fetch_groups"


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


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _action(tool: str, alert_id: str) -> dict[str, Any]:
    args: dict[str, Any] = {"alert_id": alert_id}
    if tool == "escalate_to_case":
        args.update(case_title="t", case_description="d")
    return {"tool_name": tool, "tool_args": args, "rationale": "The model recommends it."}


def _seed(client: TestClient) -> dict[str, str]:
    """A false positive with an open acknowledge, a true positive with an open
    escalate, and a true positive whose escalate an analyst dismissed."""

    async def work(db: Any) -> dict[str, str]:
        await seed_hosts(db)
        return {
            "fp_ack": await seed_run(
                db,
                "alert-f1",
                src=OUTSIDE,
                dst=OUTSIDE,
                verdict="false_positive",
                report={"recommended_actions": [_action("ack_alert", "alert-f1")]},
            ),
            "tp_escalate": await seed_run(
                db,
                "alert-t1",
                src=LEASED,
                dst=OUTSIDE,
                report={"recommended_actions": [_action("escalate_to_case", "alert-t1")]},
            ),
            "tp_dismissed": await seed_run(
                db,
                "alert-t2",
                src=LEASED,
                dst=OUTSIDE,
                report={"recommended_actions": [_action("escalate_to_case", "alert-t2")]},
            ),
        }

    runs: dict[str, str] = _do(client, work)
    res = client.post(f"/api/v1/investigations/{runs['tp_dismissed']}/actions/0/dismiss", json={})
    assert res.status_code == 200, res.text
    return runs


def _page_waits(client: TestClient, run_id: str) -> list[bool]:
    res = client.get(f"/api/v1/investigations/{run_id}")
    assert res.status_code == 200, res.text
    return [bool(a["waits"]) for a in res.json()["actions"]]


def _items(client: TestClient) -> set[str]:
    with patch(_NO_GROUPS, AsyncMock(return_value=GroupPage([], 0))):
        body = client.get("/api/v1/needs-you/items").json()
    return {i["id"] for i in body["items"] if i["type"] == "investigation"}


def test_an_action_waits_on_the_page_only_when_needs_you_lists_its_investigation(
    client: TestClient,
) -> None:
    runs = _seed(client)
    listed = _items(client)
    for name, run_id in runs.items():
        waits = _page_waits(client, run_id)
        assert any(waits) == (run_id in listed), name
    assert listed == {runs["tp_escalate"]}


def test_the_acknowledge_of_a_false_positive_stays_open_and_waits_for_no_one(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL. The card keeps its Acknowledge. Only the count changes."""
    runs = _seed(client)
    page = client.get(f"/api/v1/investigations/{runs['fp_ack']}").json()
    (card,) = page["actions"]
    assert card["applied"] is False and card["dismissed"] is False
    assert card["blockedReason"] is None, "the analyst can still press it"
    assert card["waits"] is False
    # The count of the top bar holds no part of it either.
    with patch(_NO_GROUPS, AsyncMock(return_value=GroupPage([], 0))):
        count = client.get("/api/v1/needs-you").json()
    assert count["pending_actions"] == 1
    assert count["investigations_waiting"] == 1


def test_a_dismissed_action_of_a_true_positive_waits_no_more(client: TestClient) -> None:
    """NEGATIVE CONTROL. The guard keeps a true positive with an open action."""
    runs = _seed(client)
    assert _page_waits(client, runs["tp_escalate"]) == [True]
    assert _page_waits(client, runs["tp_dismissed"]) == [False]


def test_the_run_half_of_the_rule() -> None:
    from types import SimpleNamespace

    def run(**over: Any) -> Any:
        return SimpleNamespace(**{"status": "complete", "verdict": "true_positive", **over})

    assert action_rules.run_requests(run())
    assert action_rules.run_requests(run(is_fallback=False))
    # A false positive, a needs-more-info verdict, a fallback and a run that
    # has not ended request nothing.
    assert not action_rules.run_requests(run(verdict="false_positive"))
    assert not action_rules.run_requests(run(verdict="needs_more_info"))
    assert not action_rules.run_requests(run(is_fallback=True))
    assert not action_rules.run_requests(run(status="running"))
