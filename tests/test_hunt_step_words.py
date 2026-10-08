"""A running hunt says what it does now and names each search (dogfood 2026-10-06 W10).

The page showed the elapsed time and one fixed sentence. Four steps read
"Event search: 0 matches", and a tool error read "time_range_minutes must be
<= 43200, got 100000".
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_hunts import _build_hunt_timeline, _typical_run
from soc_ai.config import Settings
from soc_ai.hunting.step_words import current_activity, search_title, translate_tool_error
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Hunt, HuntEvent

_CAP_ERROR = "time_range_minutes must be <= 43200, got 100000"


def test_a_cap_error_reads_as_two_sentences() -> None:
    assert translate_tool_error(_CAP_ERROR, retried=True) == (
        "The query asked for 69 days. The grid answers 30 days. The agent tried again."
    )
    assert translate_tool_error("lookback_days must be <= 30, got 60") == (
        "The query asked for 60 days. The grid answers 30 days."
    )
    # Negative control: an error of no known shape is left to the raw formatter.
    assert translate_tool_error("connection reset by peer") is None


def test_a_search_names_what_it_looked_for() -> None:
    args = {"query": 'destination.ip:"10.99.0.30"', "time_range_minutes": 43200}
    assert search_title("t_query_events_oql", args, {"total": 0}, running=False) == (
        "Searched for traffic to 10.99.0.30 over 30 days: 0 events"
    )
    both = {"query": "source.ip:10.0.0.5 AND destination.ip:203.0.113.9 | head 5"}
    assert search_title("t_query_events_oql", both, {"total": 1}, running=False) == (
        "Searched for traffic from 10.0.0.5 to 203.0.113.9: 1 event"
    )
    dataset = {"query": "event.dataset:zeek.conn AND host.name:sr-dc01", "time_range_minutes": 1440}
    assert search_title("t_query_events_oql", dataset, {"total": 12}, running=False) == (
        "Searched for events on sr-dc01 in zeek.conn over 24 h: 12 events"
    )
    assert search_title("t_query_events_oql", args, None, running=True) == (
        "Searching for traffic to 10.99.0.30 over 30 days"
    )
    failed = {"error": True, "message": _CAP_ERROR}
    assert search_title("t_query_events_oql", args, failed, running=False, retried=True) == (
        "Search for traffic to 10.99.0.30 over 30 days failed. The query asked for 69 days. "
        "The grid answers 30 days. The agent tried again."
    )
    only_dataset = {"query": "event.dataset:zeek.dns"}
    assert search_title("t_query_events_oql", only_dataset, {"total": 4}, running=False) == (
        "Searched for zeek.dns events: 4 events"
    )
    # Negative controls: another tool is no search, and a finished hunt's
    # search with no result keeps the shared wording.
    assert search_title("t_host_summary", {}, {"total": 1}, running=False) is None
    assert search_title("t_query_events_oql", args, None, running=False) is None


def _ev(seq: int, kind: str, payload: dict[str, Any]) -> HuntEvent:
    return HuntEvent(hunt_id="h", sequence=seq, kind=kind, payload=payload)


def _trace() -> list[HuntEvent]:
    big = {"query": 'destination.ip:"10.99.0.30"', "time_range_minutes": 100000}
    ok = {"query": 'destination.ip:"10.99.0.30"', "time_range_minutes": 43200}
    return [
        _ev(1, "hunt_started", {"objective": "o"}),
        _ev(2, "tool_call", {"tool_name": "t_query_events_oql", "args": big, "tool_call_id": "a"}),
        _ev(
            3,
            "tool_result",
            {"tool_call_id": "a", "result": {"error": True, "message": _CAP_ERROR}},
        ),
        _ev(4, "tool_call", {"tool_name": "t_query_events_oql", "args": ok, "tool_call_id": "b"}),
        _ev(5, "tool_result", {"tool_call_id": "b", "result": {"total": 0}}),
    ]


def test_the_timeline_names_the_searches_and_translates_the_error() -> None:
    titles = [s.title for s in _build_hunt_timeline(_trace(), "complete")]
    assert titles[1] == (
        "Search for traffic to 10.99.0.30 over 69 days failed. The query asked for 69 days. "
        "The grid answers 30 days. The agent tried again."
    )
    assert titles[2] == "Searched for traffic to 10.99.0.30 over 30 days: 0 events"
    assert not any("must be <=" in t for t in titles)


def test_the_current_activity_follows_the_newest_event() -> None:
    trace = _trace()
    assert current_activity(trace) == "the model reads the results"
    assert current_activity(trace[:4]) == "the agent searches the events"
    assert current_activity(trace[:1]) == "the model plans the hunt"
    assert current_activity([]) is None


def test_the_typical_run_is_the_middle_half_in_minutes() -> None:
    typical = _typical_run([300, 360, 420, 480])
    assert typical is not None
    assert (typical.lowMin, typical.highMin, typical.samples) == (5, 8, 4)
    # Negative control: two runs say little about a grid.
    assert _typical_run([300, 400]) is None


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def test_a_running_hunt_carries_its_step_and_the_typical_run(client: TestClient) -> None:
    async def seed() -> tuple[str, str]:
        now = datetime.now(UTC).replace(tzinfo=None)
        async with client.app.state.db_sessionmaker() as db:
            for minutes in (5, 6, 7, 8):
                done = await hunt_svc.create(db, objective=f"done {minutes}", started_by="t")
                await hunt_svc.finalize(db, done.id, status="complete", report={"findings": []})
                row = await db.get(Hunt, done.id)
                assert row is not None
                row.created_at = now - timedelta(minutes=minutes)
                row.finished_at = now
            # A catalog run is one query. It is no part of the estimate.
            fast = await hunt_svc.create(db, objective="c", started_by="t", kind="triggered")
            await hunt_svc.finalize(db, fast.id, status="complete", report={"findings": []})
            await db.commit()
            running = await hunt_svc.create(db, objective="hunt for beacons", started_by="t")
            await hunt_svc.append_events(
                db,
                running.id,
                [
                    {"sequence": 1, "kind": "hunt_started", "payload": {"objective": "o"}},
                    {
                        "sequence": 2,
                        "kind": "tool_call",
                        "payload": {
                            "tool_name": "t_query_events_oql",
                            "args": {"query": "source.ip:10.0.0.5"},
                            "tool_call_id": "c",
                        },
                    },
                ],
            )
            await db.commit()
            return running.id, done.id

    running_id, done_id = asyncio.run(seed())
    detail = client.get(f"/api/v1/hunts/{running_id}").json()
    assert detail["currentStep"] == "the agent searches the events"
    assert detail["typicalRun"] == {"lowMin": 5, "highMin": 8, "medianMin": 6, "samples": 4}
    assert detail["timeline"][-1]["title"] == "Searching for traffic from 10.0.0.5"
    # Negative control: a finished hunt carries neither.
    finished = client.get(f"/api/v1/hunts/{done_id}").json()
    assert finished["currentStep"] is None and finished["typicalRun"] is None
