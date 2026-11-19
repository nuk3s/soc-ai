"""The grid state of the alert of an open false positive (round 3, RS2, migration 0075).

The store cannot tell if an alert is still open: an acknowledge from another
investigation, from the inherited fan-out or from Security Onion leaves no row.
A background step asks the grid for the alerts of the selection in bounded
batches and stores the answer. The selection leaves out an alert that the grid
states as acknowledged or gone. When the grid does not answer, the last state
stays. An alert with no stored state counts as open.

The grid is a fake. The data is synthetic.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import rule_decisions as rd_store
from soc_ai.store.auth import utcnow
from soc_ai.webui import rule_decisions as rd

from tests.test_rule_decision_selection import maker_for, seed_fp, select_all


class Grid:
    """The grid: the acknowledged flag of each alert it holds, or down."""

    def __init__(self, held: dict[str, bool] | None = None) -> None:
        self.held = held
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"index": index, "query": query, **kwargs})
        if self.held is None:
            raise ConnectionError("the grid refused the connection")
        ids = query.get("ids", {}).get("values", [])
        hits = [
            {"_id": i, "_source": {"event": {"acknowledged": True}} if self.held[i] else {}}
            for i in ids
            if i in self.held
        ]
        return EsSearchResult(total=len(hits), took_ms=1, hits=hits)


def app_state(settings: Settings, maker: Any, grid: Grid) -> Any:
    return SimpleNamespace(settings=settings, db_sessionmaker=maker, elastic=grid)


@pytest.mark.asyncio
async def test_the_step_stores_each_state_and_the_selection_leaves_out_the_closed_ones(
    settings_kratos: Settings,
) -> None:
    maker = await maker_for(settings_kratos)
    await seed_fp(maker, "ev-acked")
    kept = await seed_fp(maker, "ev-open")
    await seed_fp(maker, "ev-gone")
    grid = Grid({"ev-acked": True, "ev-open": False})

    assert await rd.background_step(app_state(settings_kratos, maker, grid)) is True

    rows = await select_all(maker)
    assert [r.id for r in rows] == [kept]
    assert rows[0].grid_state == rd_store.STATE_OPEN
    assert rows[0].grid_read_at is not None
    async with maker() as db:
        states = await rd_store.states_for(db, ["ev-acked", "ev-open", "ev-gone"])
    assert {a: s for a, (s, _at) in states.items()} == {
        "ev-acked": "acknowledged",
        "ev-open": "open",
        "ev-gone": "gone",
    }
    # One search, by id, for the flag of the document, and no partial answer.
    (call,) = grid.calls
    assert call["source"] == ["event.acknowledged"]
    assert call["require_complete"] is True
    assert sorted(call["query"]["ids"]["values"]) == ["ev-acked", "ev-gone", "ev-open"]


@pytest.mark.asyncio
async def test_a_grid_that_does_not_answer_keeps_the_last_state(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL: a failed read is no answer. Nothing leaves the selection."""
    maker = await maker_for(settings_kratos)
    first = await seed_fp(maker, "ev-1")
    second = await seed_fp(maker, "ev-2")

    assert await rd.background_step(app_state(settings_kratos, maker, Grid(None))) is False
    rows = await select_all(maker)
    assert {r.id for r in rows} == {first, second}
    # Never read: each alert counts as open, and the read time is unknown.
    assert all(r.grid_state is None for r in rows)
    assert rd.read_at(rows) is None

    # A read that answered, then a grid that is down: the last state stays.
    old = utcnow() - timedelta(minutes=20)
    async with maker() as db:
        await rd_store.record_states(db, {"ev-1": "open", "ev-2": "open"}, at=old)
    assert await rd.background_step(app_state(settings_kratos, maker, Grid(None))) is False
    rows = await select_all(maker)
    assert {r.id for r in rows} == {first, second}
    assert {r.grid_state for r in rows} == {"open"}
    assert rd.read_at(rows) == old


@pytest.mark.asyncio
async def test_the_step_reads_in_bounded_batches_and_only_what_is_due(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rd, "GRID_BATCH", 2)
    maker = await maker_for(settings_kratos)
    for n in range(5):
        await seed_fp(maker, f"ev-{n}")
    grid = Grid({f"ev-{n}": False for n in range(5)})
    state = app_state(settings_kratos, maker, grid)

    assert await rd.background_step(state, limit=4) is True
    assert [len(c["query"]["ids"]["values"]) for c in grid.calls] == [2, 2]
    # The alert with no read comes first in the next step.
    grid.calls.clear()
    assert await rd.background_step(state) is True
    assert [c["query"]["ids"]["values"] for c in grid.calls] == [["ev-4"]]
    # A state younger than 5 minutes is not due.
    grid.calls.clear()
    assert await rd.background_step(state) is None
    assert await rd.refresh_rule(state, "ET POLICY actor-a outbound check") is None
    assert grid.calls == []


def test_the_oldest_read_is_due_first() -> None:
    now = utcnow()

    def row(alert: str, read: Any) -> Any:
        return SimpleNamespace(alert_es_id=alert, grid_read_at=read)

    rows = [
        row("fresh", now - timedelta(minutes=1)),
        row("old", now - timedelta(minutes=30)),
        row("older", now - timedelta(hours=2)),
        row("never", None),
    ]
    assert rd.stale_alerts(rows, now=now) == ["never", "older", "old"]  # type: ignore[arg-type]
