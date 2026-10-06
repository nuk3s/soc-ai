"""The dossier sweep at scale: stage timings, the census past its cap, the build order.

Runs against the scale harness's grid over a synthetic estate. The sweep's
per-host build is held to one host, so each test reads the network-wide
stages.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from scripts.scale import estate as estate_mod
from scripts.scale.grid import Grid
from soc_ai.config import Settings
from soc_ai.dossier.stages import CountingGrid, StageClock, counting
from soc_ai.enrichment import host_dossier as job
from soc_ai.so_client import fields, inventory
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import DossierRun
from sqlalchemy import select


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    fields._clear_agg_field_cache()
    inventory._clear_cache()
    yield
    fields._clear_agg_field_cache()
    inventory._clear_cache()


def _settings(base: Settings, data_dir: Path, **overrides: Any) -> Settings:
    settings = base.model_copy()
    settings.soc_ai_data_dir = data_dir
    settings.dossier_enabled = True
    settings.dossier_max_hosts_per_run = 1
    settings.internal_cidrs = [ipaddress.ip_network(c) for c in estate_mod.CIDRS]
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


async def _sweep(
    settings: Settings, estate: estate_mod.Estate
) -> tuple[job.DossierSummary, Grid, Any]:
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    grid = Grid(estate)
    summary = await job.run_dossier_refresh(grid, maker, settings)
    async with maker() as db:
        run = (await db.scalars(select(DossierRun))).one()
    await engine.dispose()
    return summary, grid, run


def _stage(summary: job.DossierSummary, name: str) -> dict[str, Any]:
    return next(s for s in summary.stages if s["name"] == name)


# ---------------------------------------------------------------------------
# Stage timings
# ---------------------------------------------------------------------------


async def test_the_sweep_logs_one_line_per_stage_with_its_searches(
    settings_kratos: Settings, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    estate = estate_mod.build(120)
    settings = _settings(settings_kratos, tmp_path / "store", entity_profiles_enabled=True)
    with caplog.at_level(logging.INFO, logger="soc_ai"):
        summary, grid, _run = await _sweep(settings, estate)

    names = [s["name"] for s in summary.stages]
    assert names == [
        "agent inventory",
        "dns names",
        "dhcp leases",
        "census",
        "census record",
        "host builds",
        "prune",
        "machines",
        "profile build",
    ]
    # Every search the sweep made is counted in exactly one stage.
    assert sum(s["searches"] for s in summary.stages) == grid.searches
    assert _stage(summary, "census")["searches"] == 1
    assert _stage(summary, "census record")["searches"] == 0
    assert _stage(summary, "profile build")["searches"] > 0
    lines = [r.getMessage() for r in caplog.records if " stage " in r.getMessage()]
    assert any(line.startswith("dossier sweep stage census: ") for line in lines)
    assert any(line.startswith("profile build stage batches: ") for line in lines)
    assert any("1 search," in line or line.endswith("1 search") for line in lines)


def test_the_counting_grid_passes_everything_else_through() -> None:
    class _Inner:
        async def max_buckets(self) -> int:
            return 7

    wrapped = counting(_Inner())
    assert isinstance(wrapped, CountingGrid)
    assert counting(wrapped) is wrapped
    assert getattr(wrapped, "nothing_here", None) is None
    assert wrapped.inner.__class__ is _Inner


def test_a_stage_that_raises_is_still_timed_and_logged(caplog: pytest.LogCaptureFixture) -> None:
    clock = StageClock(label="test run")
    with caplog.at_level(logging.INFO), pytest.raises(RuntimeError), clock.stage("boom"):
        raise RuntimeError("the grid is gone")
    assert [s.name for s in clock.stages] == ["boom"]
    assert any("test run stage boom:" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# The build reads this sweep's census
# ---------------------------------------------------------------------------


async def test_the_profile_build_batches_this_sweeps_census(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """On a fresh store the build runs after the census, so it has hosts to batch.

    Run before the census, the build found an empty table, sent every host
    through the one capped read, and dated nothing.
    """
    estate = estate_mod.build(120)
    settings = _settings(settings_kratos, tmp_path / "store", entity_profiles_enabled=True)
    summary, _grid, run = await _sweep(settings, estate)
    line = next(n for n in summary.notes if n.startswith("entity profiles: wrote"))
    assert "in 1 batch" in line
    assert "Built 0 hosts" not in line
    # The run row carries the same line.
    assert line in (run.notes or [])


# ---------------------------------------------------------------------------
# The census past the one-search cap
# ---------------------------------------------------------------------------


async def test_the_census_pages_past_the_one_search_cap(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """1,300 hosts against a census search that holds 1,000 addresses.

    ``dossier_max_hosts`` allows 5,000, so the census reads the rest in
    composite pages. Before, it kept the 1,000 busiest and told the operator
    to raise a setting that could not raise the cap.
    """
    monkeypatch.setattr(job, "_MAX_CENSUS_AGG_SIZE", 1000)
    estate = estate_mod.build(1300)
    settings = _settings(settings_kratos, tmp_path / "store", dossier_max_hosts=5000)
    summary, _grid, _run = await _sweep(settings, estate)

    assert summary.hosts_seen >= 1300
    assert not any("census truncated" in n for n in summary.notes)
    assert not any("census stopped" in n for n in summary.notes)
    assert _stage(summary, "census")["searches"] > 1


async def test_without_room_to_page_the_census_keeps_its_note(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: a table cap equal to the search cap leaves nothing to page."""
    monkeypatch.setattr(job, "_MAX_CENSUS_AGG_SIZE", 1000)
    estate = estate_mod.build(1300)
    settings = _settings(settings_kratos, tmp_path / "store", dossier_max_hosts=1000)
    summary, _grid, _run = await _sweep(settings, estate)

    assert any("census truncated at 1000 address buckets" in n for n in summary.notes)
    assert _stage(summary, "census")["searches"] == 1


async def test_the_census_pages_stop_at_the_table_cap_and_say_so(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(job, "_MAX_CENSUS_AGG_SIZE", 1000)
    monkeypatch.setattr(job, "_CENSUS_PAGE", 500)
    estate = estate_mod.build(1300)
    settings = _settings(settings_kratos, tmp_path / "store", dossier_max_hosts=1100)
    summary, _grid, _run = await _sweep(settings, estate)

    assert any("census stopped at 1100 addresses" in n for n in summary.notes)
