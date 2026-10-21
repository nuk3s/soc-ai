"""The rate baseline reads the hours of a grid gap as missing, never as zero.

The profile build fills every empty hour between a host's first and last
active hour with zero. After the range outage of 2026-10-15 the rebuild added
about 90 hole hours to each connection rate as zeros, and the expected counts
of those hours of the week stayed low for four weeks (dogfood 2026-10-19,
R4-D4).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from scripts.scale import estate as estate_mod
from scripts.scale.grid import Grid
from soc_ai.config import Settings
from soc_ai.dossier import profile_job
from soc_ai.dossier.profile import _rate_vector
from soc_ai.store import grid_gaps
from soc_ai.store.models import EntityProfile
from sqlalchemy import select

from tests.test_profile_job_batches import _census, _cidrs, _settings, _store


def _bucket(hours: dict[datetime, int]) -> dict[str, Any]:
    return {
        "hours": {
            "buckets": [
                {"key_as_string": at.isoformat().replace("+00:00", "Z"), "doc_count": n}
                for at, n in sorted(hours.items())
            ]
        }
    }


def test_an_hour_inside_a_gap_is_null_in_the_series_and_out_of_the_cells() -> None:
    start = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(days=3)
    hours = {start + timedelta(hours=n): 100 for n in range(72)}
    # The grid held nothing from hour 24 to hour 48. An agent back-filled one hour.
    for n in range(24, 48):
        hours.pop(start + timedelta(hours=n))
    hours[start + timedelta(hours=30)] = 7
    gap = (start + timedelta(hours=24), start + timedelta(hours=48))

    plain = _rate_vector(_bucket(hours), tz="UTC")
    vector = _rate_vector(_bucket(hours), tz="UTC", gaps=[gap])

    counts = vector["hourly"]["counts"]
    assert len(counts) == 72
    assert counts[:24] == [100] * 24
    assert counts[24:48] == [None] * 24
    assert counts[48:] == [100] * 24
    # Without the ledger the series zero-fills the dark hours, and every one of
    # them enters a cell. With the gap the 24 hours stay out of the cells. The
    # median of a day-of-week cell drops below 100 only on the weekdays where
    # the zeros are the majority of that cell, so the test counts samples: a
    # median check failed on 2026-10-20 and passed the day before.
    assert plain["hourly"]["counts"][24:48].count(0) == 23

    def cell_samples(v: dict[str, Any]) -> int:
        return sum(int(c["samples"]) for k, c in v.items() if k != "hourly")

    assert cell_samples(plain) == 72
    assert cell_samples(vector) == 48
    assert all(c["median"] == 100 for k, c in vector.items() if k != "hourly" and c["samples"])


async def test_the_build_reads_the_ledger_and_stores_the_gap_hours_as_null(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    estate = estate_mod.build(20)
    grid = Grid(estate)
    settings = _settings(settings_kratos, tmp_path / "store")
    engine, maker = await _store(settings)
    await _census(grid, maker, settings)
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    gap_start, gap_end = now - timedelta(days=6), now - timedelta(days=4)
    async with maker() as db:
        await grid_gaps.open_probe_gap(db, started_at=gap_start, detail="refused")
        await grid_gaps.close_probe_gaps(db, ended_at=gap_end)

    build = await profile_job.build_profiles(grid, maker, settings, _cidrs(settings))
    assert build.errors == []
    async with maker() as db:
        vectors = (
            await db.scalars(
                select(EntityProfile.vector_json).where(
                    EntityProfile.dimension == "connection_rate"
                )
            )
        ).all()
    await engine.dispose()

    settle = grid_gaps.settle_of(settings)
    checked = 0
    for vector in vectors:
        hourly = (vector or {}).get("hourly")
        if not hourly:
            continue
        first = datetime.fromisoformat(hourly["start"])
        for n, count in enumerate(hourly["counts"]):
            at = first + timedelta(hours=n)
            inside = gap_start <= at < gap_end + settle
            assert (count is None) == inside, (at, count)
            checked += inside
    assert checked > 0, "no stored series reaches the gap"
