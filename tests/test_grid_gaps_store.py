"""The grid-gap ledger: open, close, grow and read the hours the grid held no data.

The range sensor was down for about 90 hours. soc-ai saw it and kept no
record, so every surface read the hole as a quiet grid after the recovery.
These tests pin the ledger that keeps the record.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from soc_ai.config import Settings
from soc_ai.store import grid_gaps
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect


async def _maker(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


async def test_the_migration_creates_the_table(settings_kratos: Settings) -> None:
    engine, _ = await _maker(settings_kratos)
    async with engine.connect() as conn:
        cols = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("grid_gaps")}
        )
    await engine.dispose()
    assert {"id", "source", "plane", "started_at", "ended_at", "detail", "created_at"} <= cols


async def test_one_outage_is_one_open_row_and_the_first_good_probe_closes_it(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _maker(settings_kratos)
    start = _now() - timedelta(hours=5)
    async with maker() as db:
        first = await grid_gaps.open_probe_gap(db, started_at=start, detail="refused")
        # A restart in the middle of the outage opens nothing new.
        again = await grid_gaps.open_probe_gap(
            db, started_at=start + timedelta(hours=1), detail="refused"
        )
        assert again.id == first.id
        assert len(await grid_gaps.open_probe_gaps(db)) == 1

        end = _now()
        assert await grid_gaps.close_probe_gaps(db, ended_at=end) == 1
        assert await grid_gaps.open_probe_gaps(db) == []
        rows = await grid_gaps.overlapping(db, since=start - timedelta(hours=1), until=end)
    await engine.dispose()
    assert len(rows) == 1
    assert rows[0].ended_at == end.replace(tzinfo=None)
    assert rows[0].source == grid_gaps.SOURCE_PROBE


async def test_overlapping_reads_only_the_gaps_inside_the_window(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _maker(settings_kratos)
    now = _now()
    async with maker() as db:
        await grid_gaps.record_sweep_gap(
            db,
            plane="connection_rate",
            started_at=now - timedelta(days=10),
            ended_at=now - timedelta(days=9),
            detail="old",
        )
        await grid_gaps.record_sweep_gap(
            db,
            plane="connection_rate",
            started_at=now - timedelta(hours=30),
            ended_at=now - timedelta(hours=20),
            detail="recent",
        )
        await grid_gaps.open_probe_gap(db, started_at=now - timedelta(hours=2), detail="down")
        week = await grid_gaps.overlapping(db, since=now - timedelta(days=7), until=now)
        day = await grid_gaps.overlapping(db, since=now - timedelta(hours=12), until=now)
    await engine.dispose()
    assert [g.detail for g in week] == ["recent", "down"]
    # The open gap runs to now, so a window that ends now holds it.
    assert [g.detail for g in day] == ["down"]


async def test_a_sweep_gap_on_the_same_plane_grows_and_stays_one_row(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _maker(settings_kratos)
    now = _now().replace(minute=0, second=0)
    async with maker() as db:
        first = await grid_gaps.record_sweep_gap(
            db,
            plane="connection_rate",
            started_at=now - timedelta(hours=10),
            ended_at=now - timedelta(hours=6),
            detail="a",
        )
        grown = await grid_gaps.record_sweep_gap(
            db,
            plane="connection_rate",
            started_at=now - timedelta(hours=6),
            ended_at=now - timedelta(hours=2),
            detail="b",
        )
        other = await grid_gaps.record_sweep_gap(
            db,
            plane="active_hours",
            started_at=now - timedelta(hours=6),
            ended_at=now - timedelta(hours=2),
            detail="c",
        )
    await engine.dispose()
    assert grown.id == first.id
    assert grown.started_at == (now - timedelta(hours=10)).replace(tzinfo=None)
    assert grown.ended_at == (now - timedelta(hours=2)).replace(tzinfo=None)
    assert other.id != first.id


async def test_closed_since_reads_the_gaps_that_ended_in_the_window(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _maker(settings_kratos)
    now = _now()
    async with maker() as db:
        await grid_gaps.record_sweep_gap(
            db,
            plane="connection_rate",
            started_at=now - timedelta(hours=50),
            ended_at=now - timedelta(hours=30),
            detail="old",
        )
        await grid_gaps.open_probe_gap(db, started_at=now - timedelta(hours=8), detail="x")
        await grid_gaps.close_probe_gaps(db, ended_at=now - timedelta(hours=1))
        rows = await grid_gaps.closed_since(db, since=now - timedelta(hours=24))
    await engine.dispose()
    assert [g.source for g in rows] == [grid_gaps.SOURCE_PROBE]


def test_a_window_adds_the_settle_margin_and_an_open_gap_runs_to_now() -> None:
    now = _now()
    closed = SimpleNamespace(
        started_at=(now - timedelta(hours=10)).replace(tzinfo=None),
        ended_at=(now - timedelta(hours=5)).replace(tzinfo=None),
    )
    open_ = SimpleNamespace(
        started_at=(now - timedelta(hours=1)).replace(tzinfo=None), ended_at=None
    )
    windows = grid_gaps.windows_of(
        [closed, open_],  # type: ignore[list-item]
        settle=timedelta(minutes=60),
        now=now,
    )
    assert windows[0].end == now - timedelta(hours=4)
    assert grid_gaps.covered(now - timedelta(hours=4, minutes=30), windows)
    assert not grid_gaps.covered(now - timedelta(hours=3), windows)
    assert windows[1].end == now + timedelta(hours=1)


def test_the_settle_margin_reads_the_setting_and_survives_a_bad_value() -> None:
    assert grid_gaps.settle_of(SimpleNamespace(grid_gap_settle_minutes=90)) == timedelta(minutes=90)
    assert grid_gaps.settle_of(SimpleNamespace(grid_gap_settle_minutes="x")) == timedelta(
        minutes=grid_gaps.DEFAULT_SETTLE_MINUTES
    )
    assert grid_gaps.settle_of(object()) == timedelta(minutes=grid_gaps.DEFAULT_SETTLE_MINUTES)


def test_the_fact_line_states_the_hours_and_that_a_zero_is_unknown() -> None:
    start = datetime(2026, 10, 15, 13, 36)
    end = datetime(2026, 10, 19, 10, 15)
    lines = grid_gaps.fact_lines(
        [
            SimpleNamespace(started_at=start, ended_at=end),  # type: ignore[list-item]
            SimpleNamespace(started_at=end + timedelta(hours=2), ended_at=None),  # type: ignore[list-item]
        ]
    )
    assert lines == [
        "The grid held no data from 2026-10-15 13:36 UTC to 2026-10-19 10:15 UTC. "
        "A zero count over these hours means unknown.",
        "The grid has held no data since 2026-10-19 12:15 UTC. "
        "A zero count over these hours means unknown.",
    ]


def test_the_settle_setting_is_in_settings_and_applies_live(settings_kratos: Settings) -> None:
    from soc_ai.store.config_overrides import WHITELIST_BY_KEY, apply_to_settings, coerce

    assert settings_kratos.grid_gap_settle_minutes == grid_gaps.DEFAULT_SETTLE_MINUTES
    spec = WHITELIST_BY_KEY["grid_gap_settle_minutes"]
    assert spec.type == "int"
    assert spec.hot is True
    assert spec.min_value == 0
    assert "grid_gap_settle_minutes" in apply_to_settings(
        settings_kratos, {"grid_gap_settle_minutes": coerce("grid_gap_settle_minutes", "120")}
    )
    assert grid_gaps.settle_of(settings_kratos) == timedelta(minutes=120)
