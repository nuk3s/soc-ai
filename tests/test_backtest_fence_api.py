"""The API half of the backtest fence: the list, the page and the execute route.

A backtest replay is a measurement on an alert an analyst already closed. The
list and its figures leave replays out by default and put them back on
request. A replay stands alone in the list. The page of a replay closes every
recommended action, and the execute route refuses them. Each refusal has its
negative control: the same request about a live run does the thing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store.models import Investigation

from tests.test_backtest_fence import _inv


def _seed(client: TestClient, rows: list[Investigation]) -> None:
    async def _run() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add_all(rows)
            await db.commit()

    asyncio.run(_run())


@pytest.fixture
def api_client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


# One live true positive, a NEWER replay of the same alert, a replay of a
# second alert, and a live false positive.
LIVE_TP, REPLAY_SAME, REPLAY_OTHER, LIVE_FP = (f"{n:026d}" for n in (1, 2, 3, 4))


def _seed_mixed(client: TestClient) -> None:
    _seed(
        client,
        [
            _inv(1, alert="al-1", started_by="analyst", minutes_ago=30),
            _inv(2, alert="al-1", started_by="backtest", minutes_ago=5),
            _inv(3, alert="al-2", started_by="backtest", minutes_ago=4),
            _inv(4, alert="al-3", started_by="scheduler", verdict="false_positive", minutes_ago=3),
        ],
    )


class TestTheInvestigationsList:
    def test_the_list_leaves_replays_out_by_default(self, api_client: TestClient) -> None:
        _seed_mixed(api_client)
        body = api_client.get("/api/v1/investigations").json()
        by_id = {r["id"]: r for r in body["rows"]}
        assert set(by_id) == {LIVE_TP, LIVE_FP}
        assert body["total"] == 2
        assert body["truePositives"] == 1
        # The count the header names beside the figures.
        assert body["backtestReplays"] == 2
        assert body["includesBacktest"] is False
        assert by_id[LIVE_TP]["ranBy"] == "analyst"
        # A newer replay of the same alert does not take primacy from the
        # live run: the replay is not that alert's run.
        assert by_id[LIVE_TP]["isPrimary"] is True
        assert by_id[LIVE_TP]["latestRunId"] == LIVE_TP

    def test_the_parameter_puts_the_replays_back(self, api_client: TestClient) -> None:
        _seed_mixed(api_client)
        body = api_client.get("/api/v1/investigations?include_backtest=true").json()
        by_id = {r["id"]: r for r in body["rows"]}
        assert set(by_id) == {LIVE_TP, REPLAY_SAME, REPLAY_OTHER, LIVE_FP}
        assert body["total"] == 4
        assert body["truePositives"] == 3
        assert body["backtestReplays"] == 2
        assert body["includesBacktest"] is True
        assert by_id[REPLAY_SAME]["ranBy"] == "backtest"
        # The replay stands alone: its own group, and the live run keeps its.
        assert by_id[REPLAY_SAME]["alertId"] == REPLAY_SAME
        assert by_id[REPLAY_SAME]["isPrimary"] is True
        assert by_id[LIVE_TP]["isPrimary"] is True

    def test_control_a_newer_live_run_still_takes_primacy(self, api_client: TestClient) -> None:
        """The primacy rule still works for live runs. Without this, a change
        that made every run primary would pass the two tests above."""
        _seed_mixed(api_client)
        _seed(api_client, [_inv(9, alert="al-1", started_by="analyst", minutes_ago=1)])
        body = api_client.get("/api/v1/investigations").json()
        by_id = {r["id"]: r for r in body["rows"]}
        assert by_id[f"{9:026d}"]["isPrimary"] is True
        assert by_id[LIVE_TP]["isPrimary"] is False

    def test_the_replay_count_follows_the_other_filters(self, api_client: TestClient) -> None:
        _seed_mixed(api_client)
        body = api_client.get("/api/v1/investigations?verdict=false_positive").json()
        assert body["total"] == 1
        # No replay is a false positive, so the filter set hides none.
        assert body["backtestReplays"] == 0


class TestTheReplayActions:
    def test_a_replay_shows_its_actions_closed(self, api_client: TestClient) -> None:
        from soc_ai.api.webui._timeline import REPLAY_ACTION_NOTE

        _seed_mixed(api_client)
        replay = api_client.get(f"/api/v1/investigations/{REPLAY_SAME}").json()
        assert replay["meta"]["ranBy"] == "backtest"
        assert replay["actions"], "the page still shows what the model recommended"
        for action in replay["actions"]:
            assert action["applied"] is True
            assert action["appliedNote"] == REPLAY_ACTION_NOTE
        # Control: the live run's action stays open for the analyst.
        live = api_client.get(f"/api/v1/investigations/{LIVE_TP}").json()
        assert [a["applied"] for a in live["actions"]] == [False]

    def test_the_execute_route_refuses_a_replay(self, api_client: TestClient) -> None:
        from soc_ai.tools._registry import ToolSpec

        _seed_mixed(api_client)
        calls: list[str] = []

        async def fn(
            alert_id: str, comment: str | None = None, *, auth: Any, settings: Any = None
        ) -> dict[str, Any]:
            calls.append(alert_id)
            return {"acknowledged": True}

        tool = ToolSpec(name="ack_alert", read_only=False, description="", func=fn)
        with patch("soc_ai.tools.write_exec.get_tool", return_value=tool):
            refused = api_client.post(f"/api/v1/investigations/{REPLAY_SAME}/actions/0/execute")
            assert refused.status_code == 400
            assert refused.json()["detail"]["reason"] == "backtest_replay"
            assert calls == []
            # Control: the same action on the live run reaches the write.
            done = api_client.post(f"/api/v1/investigations/{LIVE_TP}/actions/0/execute")
        assert done.status_code == 200
        assert done.json()["status"] == "executed"
