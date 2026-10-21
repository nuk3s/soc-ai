"""The self-healing hold does not count a hit the grid gap wrote.

After the range outage the sweep wrote five collapse hits for hours inside
the outage, and the hold moved the live analytic to shadow on them (dogfood
2026-10-19, R3-D2, R1-D3). A hit whose event window lies inside a grid gap
says more about the grid than about the analytic.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.config import Settings
from soc_ai.hunting import self_heal
from soc_ai.store import grid_gaps

from tests.test_analytic_self_heal import _ID, _db, _hit, _live, _spec_text


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def _iso(at: datetime) -> str:
    return at.replace(tzinfo=UTC).isoformat()


async def _gap(db: Any, start: datetime, end: datetime) -> None:
    await grid_gaps.open_probe_gap(db, started_at=start, detail="refused")
    await grid_gaps.close_probe_gaps(db, ended_at=end)


async def _rate_hits(
    db: Any, count: int, *, born: datetime, start: datetime, end: datetime
) -> None:
    rows = []
    for _ in range(count):
        row = _hit(born)
        row.evidence_json = {"window": {"start": _iso(start), "end": _iso(end)}}
        rows.append(row)
    db.add_all(rows)
    await db.commit()


async def test_hits_inside_a_gap_do_not_count_toward_the_limit(settings_kratos: Settings) -> None:
    now = _now()
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=3), at=now - timedelta(days=5))
        await _gap(db, now - timedelta(days=4), now - timedelta(hours=1))
        await _rate_hits(
            db,
            5,
            born=now - timedelta(minutes=50),
            start=now - timedelta(hours=24),
            end=now - timedelta(hours=1),
        )
        result = await self_heal.run_self_heal(db, now=now)
    await engine.dispose()
    assert result.demoted == []


async def test_the_same_hits_with_no_gap_still_demote(settings_kratos: Settings) -> None:
    """The control: the window on the row is not what excuses the hit."""
    now = _now()
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=3), at=now - timedelta(days=5))
        await _rate_hits(
            db,
            5,
            born=now - timedelta(minutes=50),
            start=now - timedelta(hours=24),
            end=now - timedelta(hours=1),
        )
        result = await self_heal.run_self_heal(db, now=now)
    await engine.dispose()
    assert [d.analytic_id for d in result.demoted] == [_ID]


async def test_a_hit_that_starts_before_the_gap_still_counts(settings_kratos: Settings) -> None:
    now = _now()
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=3), at=now - timedelta(days=5))
        await _gap(db, now - timedelta(hours=10), now - timedelta(hours=2))
        await _rate_hits(
            db,
            5,
            born=now - timedelta(minutes=50),
            start=now - timedelta(hours=14),
            end=now - timedelta(hours=8),
        )
        result = await self_heal.run_self_heal(db, now=now)
    await engine.dispose()
    assert [d.analytic_id for d in result.demoted] == [_ID]


def test_the_event_window_reads_each_shape_a_hit_stores() -> None:
    start = datetime(2026, 10, 18, 11, tzinfo=UTC)
    end = datetime(2026, 10, 19, 10, tzinfo=UTC)
    rate = {"window": {"start": start.isoformat(), "end": end.isoformat()}}
    model = {
        "baseline": {
            "features": {
                "silent_from": "2026-10-18T11:00:00Z",
                "silent_until": "2026-10-19T10:00:00Z",
            }
        }
    }
    assert self_heal.event_window(None, rate) == (start, end)
    assert self_heal.event_window(None, model) == (start, end)
    point = datetime(2026, 10, 18, 12)
    assert self_heal.event_window(point, {}) == (
        point.replace(tzinfo=UTC),
        point.replace(tzinfo=UTC),
    )
    assert self_heal.event_window(None, None) is None
