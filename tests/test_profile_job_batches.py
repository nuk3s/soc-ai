"""The profile build: batches, the skip rule and the per-host fallback.

Everything here runs against the scale harness's grid (``scripts/scale/grid.py``)
over a small synthetic estate (``scripts/scale/estate.py``), so the lane builds
real profiles from real query semantics. The properties:

* a host whose profile is fresh and whose activity predates its build's
  window is skipped, and its rows survive the expiry;
* a batch of 50 hosts costs one search per dimension, not 50;
* a batch the grid refuses for its bucket count is read one host at a time,
  and the rows come out the same;
* the batched build writes exactly the rows the per-host build writes;
* the read outside the census pages every host, 1,000 a page, up to a
  ceiling of 20,000. A host past the old cap of 500 gets a profile;
* a read outside the census that stops at its ceiling says so with the
  number, and writes no "measured, none observed" row for a host past it;
* the bulk writer writes what ``upsert_profile`` writes;
* a host whose rows hold an older profile shape is built whatever its age,
  and a store whose newest shape is older than the code's makes a build due.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from scripts.scale import estate as estate_mod
from scripts.scale.grid import Grid
from soc_ai.config import Settings
from soc_ai.dossier import profile_job
from soc_ai.dossier.profile import PROFILE_SHAPE, collect_entity_profiles
from soc_ai.enrichment.host_dossier import run_dossier_refresh
from soc_ai.so_client import fields, inventory
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import entity_profiles
from soc_ai.store.config_overrides import WHITELIST_BY_KEY
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityProfile, HostDossier
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from tests.es_doubles import composite_page

_CATEGORICAL = (
    "peers_out",
    "consumed_ports",
    "served_ports",
    "process_names",
    "process_parents",
    "dns_names",
    "logon_users",
)


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    """Both resolvers are process-cached; a stale entry from another estate would leak in."""
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
    settings.entity_profiles_enabled = False
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


async def _store(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[Any]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _census(grid: Grid, maker: async_sessionmaker[Any], settings: Settings) -> None:
    """One dossier sweep with the build off: the census and the machines only."""
    settings.entity_profiles_enabled = False
    summary = await run_dossier_refresh(grid, maker, settings)
    assert not [e for e in summary.errors if "census" in e], summary.errors
    settings.entity_profiles_enabled = True


async def _rows(maker: async_sessionmaker[Any]) -> dict[tuple[str, str], tuple[Any, ...]]:
    async with maker() as db:
        models = (await db.scalars(select(EntityProfile))).all()
    return {
        (m.entity_key, m.dimension): (
            m.shape,
            json.dumps(m.vector_json, sort_keys=True),
            m.coverage,
            m.coverage_reason,
            m.support_days,
        )
        for m in models
    }


def _cidrs(settings: Settings) -> list[Any]:
    return list(settings.internal_cidrs)


def _agg_name(aggs: Mapping[str, Any] | None) -> str | None:
    return next(iter(aggs)) if aggs else None


def _batch_keys(query: Any) -> int | None:
    """How many keys the build's batch filter carries, or None for an unscoped read."""
    node = query.get("bool") if isinstance(query, Mapping) else None
    if not isinstance(node, Mapping) or "must_not" in node:
        return None
    for clause in node.get("filter") or ():
        terms = clause.get("terms") if isinstance(clause, Mapping) else None
        if isinstance(terms, Mapping) and len(terms) == 1:
            ((_field, values),) = terms.items()
            if isinstance(values, list):
                return len(values)
    return None


# ---------------------------------------------------------------------------
# The skip rule
# ---------------------------------------------------------------------------


async def test_a_fresh_quiet_host_is_skipped_and_keeps_its_rows(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """A dormant workstation sent nothing for three days. The second build skips it.

    Three negative controls ride on the same run, each on the path a looser
    rule would miss:

    * a dormant host whose census shows activity after its build is built;
    * a dormant host whose activity falls inside the lag before its build is
      built. "Older than the build" alone would skip it, and its baseline
      would never read that activity;
    * a dormant host whose profile is older than the refresh interval is built.
    """
    estate = estate_mod.build(150)
    grid = Grid(estate)
    settings = _settings(settings_kratos, tmp_path / "store")
    engine, maker = await _store(settings)
    await _census(grid, maker, settings)

    first = await profile_job.build_profiles(grid, maker, settings, _cidrs(settings))
    assert first.errors == []
    assert first.skipped == 0

    # A lease document dates a host on the per-host build, so the test keeps
    # to dormant hosts without one.
    burst = next(h for h in estate.hosts if h.ip in estate.planted["burst_and_night"])
    dormant = sorted(
        h.ip for h in estate.hosts if estate_mod.dormant(h) and h is not burst and not h.leased
    )
    assert len(dormant) >= 4, "the estate must hold dormant workstations"
    woke, lagged, stale, quiet = dormant[0], dormant[1], dormant[2], dormant[3:]
    async with maker() as db:
        built = {
            key: stamp
            for key, stamp in (
                await db.execute(
                    select(EntityProfile.entity_key, EntityProfile.built_at).where(
                        EntityProfile.entity_key.in_(dormant)
                    )
                )
            ).all()
        }
        now = datetime.now(UTC).replace(tzinfo=None)
        await db.execute(
            update(HostDossier).where(HostDossier.host_key == woke).values(last_seen=now)
        )
        await db.execute(
            update(HostDossier)
            .where(HostDossier.host_key == lagged)
            .values(last_seen=built[lagged] - timedelta(hours=1))
        )
        await db.execute(
            update(EntityProfile)
            .where(EntityProfile.entity_key == stale)
            .values(built_at=now - timedelta(days=2))
        )
        await db.commit()

    second = await profile_job.build_profiles(grid, maker, settings, _cidrs(settings))
    assert second.errors == []
    async with maker() as db:
        after = {
            key: stamp
            for key, stamp in (
                await db.execute(
                    select(EntityProfile.entity_key, EntityProfile.built_at).where(
                        EntityProfile.entity_key.in_(dormant)
                    )
                )
            ).all()
        }
    # The quiet dormant hosts kept their rows and their build stamp.
    for ip in quiet:
        assert ip in after, f"{ip} lost its rows to the expiry"
        assert after[ip] == built[ip], f"{ip} was rebuilt"
    # The three controls were rebuilt.
    for ip in (woke, lagged, stale):
        assert after[ip] > built[ip], f"{ip} was skipped"
    assert second.skipped >= len(quiet)
    assert any(f"Skipped {second.skipped} fresh hosts" in n for n in second.notes)
    await engine.dispose()


async def test_a_fresh_host_that_holds_an_older_shape_is_built(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """The upgrade of 2026-10-04 added the hourly series to the rate baseline.

    The rows of the morning build were fresh by age, and the skip rule kept
    them. The rate analytics read them as blind until the next daily build. A
    host whose rows hold an older shape is now built whatever their age.

    Negative control on the same run: a quiet host whose rows hold the
    current shape is skipped, as before.
    """
    estate = estate_mod.build(150)
    grid = Grid(estate)
    settings = _settings(settings_kratos, tmp_path / "store")
    engine, maker = await _store(settings)
    await _census(grid, maker, settings)

    first = await profile_job.build_profiles(grid, maker, settings, _cidrs(settings))
    assert first.errors == []
    async with maker() as db:
        shapes = set((await db.scalars(select(EntityProfile.shape_version))).all())
    # Every row a build writes carries the shape of this release.
    assert shapes == {PROFILE_SHAPE}

    burst = next(h for h in estate.hosts if h.ip in estate.planted["burst_and_night"])
    dormant = sorted(
        h.ip for h in estate.hosts if estate_mod.dormant(h) and h is not burst and not h.leased
    )
    assert len(dormant) >= 2, "the estate must hold dormant workstations"
    old, current = dormant[0], dormant[1]
    async with maker() as db:
        built = dict(
            (
                await db.execute(
                    select(EntityProfile.entity_key, EntityProfile.built_at).where(
                        EntityProfile.entity_key.in_([old, current])
                    )
                )
            ).all()
        )
        # A row written before the stamp existed holds no shape: shape 1.
        await db.execute(
            update(EntityProfile).where(EntityProfile.entity_key == old).values(shape_version=None)
        )
        await db.commit()

    second = await profile_job.build_profiles(grid, maker, settings, _cidrs(settings))
    assert second.errors == []
    async with maker() as db:
        after = {
            key: (stamp, shape)
            for key, stamp, shape in (
                await db.execute(
                    select(
                        EntityProfile.entity_key,
                        EntityProfile.built_at,
                        EntityProfile.shape_version,
                    ).where(EntityProfile.entity_key.in_([old, current]))
                )
            ).all()
        }
    assert after[old][0] > built[old], "the host with the older shape was skipped"
    assert after[old][1] == PROFILE_SHAPE
    assert after[current][0] == built[current], "a fresh host of the current shape was rebuilt"
    assert second.reshaped == 1
    assert (
        "entity profiles: 1 host held the profile shape 1. This release writes shape "
        f"{PROFILE_SHAPE}. The build read them whatever their age."
    ) in second.notes
    # A build with nothing reshaped says nothing about shapes.
    assert first.reshaped == 0
    assert not [n for n in first.notes if "profile shape" in n]
    await engine.dispose()


async def test_a_store_with_no_row_of_the_current_shape_makes_a_build_due(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """The prior sweep loop asks :func:`profile_job.shape_due` beside its age rule.

    Negative controls: a store whose newest row holds the current shape, and
    an empty store, make no build due for the shape. A user row of an older
    shape counts for nothing: the build never rewrites it, and a build due on
    every wake would rebuild the estate every hour.
    """
    settings = _settings(settings_kratos, tmp_path / "store")
    engine, maker = await _store(settings)

    empty = await profile_job.freshness(maker)
    assert empty.newest_shape is None and empty.outdated == 0
    assert profile_job.shape_due(empty) is None

    async with maker() as db:
        for key in ("192.0.2.1", "192.0.2.2"):
            await entity_profiles.upsert_profile(
                db,
                entity_kind="host",
                entity_key=key,
                dimension="connection_rate",
                shape="numeric",
                vector={"work": {"median": 4.0}},
            )
        await entity_profiles.upsert_profile(
            db,
            entity_kind="user",
            entity_key="alice",
            dimension="logon_hosts",
            shape="categorical",
            vector={},
        )

    before = await profile_job.freshness(maker)
    assert before.newest_shape == 1
    assert before.outdated == 2
    assert profile_job.shape_due(before) == (
        f"the stored profiles hold shape 1. This release reads shape {PROFILE_SHAPE}. "
        "A profile build is due now."
    )

    # One host row of the current shape: a build of this release ran. The
    # other row stays outdated, and the next build reads that host.
    async with maker() as db:
        await db.execute(
            update(EntityProfile)
            .where(EntityProfile.entity_key == "192.0.2.1")
            .values(shape_version=PROFILE_SHAPE)
        )
        await db.commit()
    after = await profile_job.freshness(maker)
    assert after.newest_shape == PROFILE_SHAPE
    assert after.outdated == 1
    assert profile_job.shape_due(after) is None
    await engine.dispose()


# ---------------------------------------------------------------------------
# Searches per batch
# ---------------------------------------------------------------------------


async def _batch_searches(
    settings_kratos: Settings, tmp_path: Path, *, hosts: int
) -> dict[str, list[int]]:
    """Per aggregation name, the key count of every batch search the build made."""
    estate = estate_mod.build(hosts)
    seen: dict[str, list[int]] = {}

    def spy(query: Any, aggs: Mapping[str, Any] | None) -> bool:
        keys = _batch_keys(query)
        name = _agg_name(aggs)
        if keys is not None and name is not None:
            seen.setdefault(name, []).append(keys)
        return False

    grid = Grid(estate)
    settings = _settings(settings_kratos, tmp_path / f"store-{hosts}")
    engine, maker = await _store(settings)
    await _census(grid, maker, settings)
    grid.refuse = spy
    build = await profile_job.build_profiles(grid, maker, settings, _cidrs(settings))
    assert build.errors == []
    await engine.dispose()
    return seen


async def test_a_batch_of_50_hosts_costs_one_search_per_dimension(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    seen = await _batch_searches(settings_kratos, tmp_path, hosts=50)
    for dimension in _CATEGORICAL:
        assert len(seen.get(dimension, [])) == 1, (dimension, seen.get(dimension))
    # The one search held every address of the batch, 50 hosts and more.
    assert max(seen["served_ports"]) >= 50


async def test_a_batch_of_one_host_costs_one_search_per_host(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control: with a batch of one the count grows with the hosts.

    Without it the test above could pass on a build that never batched.
    """
    monkeypatch.setattr(profile_job, "_BATCH_KEYS", 1)
    seen = await _batch_searches(settings_kratos, tmp_path, hosts=50)
    assert len(seen["served_ports"]) >= 50


# ---------------------------------------------------------------------------
# The per-host fallback, and the equality of the paths
# ---------------------------------------------------------------------------


async def _build_rows(
    settings_kratos: Settings,
    path: Path,
    estate: estate_mod.Estate,
    *,
    refuse: Any = None,
) -> tuple[dict[tuple[str, str], tuple[Any, ...]], profile_job.ProfileBuild]:
    grid = Grid(estate)
    settings = _settings(settings_kratos, path)
    engine, maker = await _store(settings)
    await _census(grid, maker, settings)
    grid.refuse = refuse
    build = await profile_job.build_profiles(grid, maker, settings, _cidrs(settings))
    rows = await _rows(maker)
    await engine.dispose()
    return rows, build


async def test_a_refused_batch_is_read_one_host_at_a_time(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """The grid refuses every served-port read of more than one host.

    The build splits the batch down to single hosts, says how many it read
    alone, and writes the same rows as a build the grid did not refuse.
    """
    estate = estate_mod.build(80)

    def refuse(query: Any, aggs: Mapping[str, Any] | None) -> bool:
        keys = _batch_keys(query)
        return _agg_name(aggs) == "served_ports" and keys is not None and keys > 1

    refused, split = await _build_rows(settings_kratos, tmp_path / "split", estate, refuse=refuse)
    plain, whole = await _build_rows(settings_kratos, tmp_path / "plain", estate)

    assert split.errors == []
    assert whole.single == 0
    assert split.single > 0
    assert any("alone" in n for n in split.notes)
    assert refused == plain


async def test_the_batched_build_writes_the_per_host_build_rows(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same members, same counts, same coverage: a batch of 500 against batches of one."""
    estate = estate_mod.build(120)
    batched, _ = await _build_rows(settings_kratos, tmp_path / "batched", estate)
    monkeypatch.setattr(profile_job, "_BATCH_KEYS", 1)
    single, build = await _build_rows(settings_kratos, tmp_path / "single", estate)
    assert build.batches > 100
    assert len(batched) > 1000
    assert batched == single


async def test_the_batched_build_writes_the_estate_wide_lane_rows(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """Below 500 hosts the lane's own estate-wide read and the batches agree."""
    estate = estate_mod.build(120)
    batched, _ = await _build_rows(settings_kratos, tmp_path / "batched", estate)

    grid = Grid(estate)
    settings = _settings(settings_kratos, tmp_path / "lane")
    sweep = await collect_entity_profiles(
        elastic=grid,  # type: ignore[arg-type]
        settings=settings,
        window_hours=30 * 24,
        lag_hours=24,
        cidrs=_cidrs(settings),
    )
    lane = {
        (r.key, r.dimension): (
            r.shape,
            json.dumps(r.vector, sort_keys=True),
            r.coverage,
            r.coverage_reason,
            r.support_days,
        )
        for r in profile_job._rows_of(sweep)
    }
    assert batched == lane


# ---------------------------------------------------------------------------
# The read outside the census
# ---------------------------------------------------------------------------


class _PagedGrid:
    """Answers the paged read outside the census over ``count`` hosts, one page per search.

    ``sizes`` holds the page size of every search, ``bodies`` the aggregation
    body and ``queries`` the query. A terms read gets the busiest 500, the
    answer the read got before it paged.
    """

    def __init__(self, count: int) -> None:
        self.buckets = [
            {"key": f"10.0.{n // 256}.{n % 256}", "doc_count": count - n} for n in range(count)
        ]
        self.sizes: list[int] = []
        self.bodies: list[Mapping[str, Any]] = []
        self.queries: list[Any] = []

    async def search(self, index: str, query: Any, **kwargs: Any) -> EsSearchResult:
        ((name, body),) = kwargs["aggs"].items()
        self.bodies.append(body)
        self.queries.append(query)
        if "composite" not in body:
            size = int(body["terms"]["size"])
            self.sizes.append(size)
            return EsSearchResult(
                total=0,
                took_ms=1,
                aggregations={
                    name: {
                        "buckets": self.buckets[:size],
                        "sum_other_doc_count": len(self.buckets[size:]),
                    }
                },
            )
        self.sizes.append(int(body["composite"]["size"]))
        page = composite_page(body, self.buckets)
        return EsSearchResult(total=0, took_ms=1, aggregations={name: page})


# The lane's categorical read, as collect_entity_profiles sends it for peers_out.
_PEERS_OUT_AGGS: dict[str, Any] = {
    "peers_out": {
        "terms": {"field": "source.ip", "size": 500},
        "aggs": {"members": {"terms": {"field": "destination.ip", "size": 200}}},
    }
}
_KNOWN = "192.0.2.1"


async def _beyond_read(grid: _PagedGrid) -> tuple[Any, profile_job._Shared]:
    shared = profile_job._Shared(grid, [])
    beyond = profile_job._BatchGrid(shared, exclude={"address": frozenset({_KNOWN})})
    result = await beyond.search(
        "logs-*", {"match_all": {}}, size=0, aggs=copy.deepcopy(_PEERS_OUT_AGGS)
    )
    return result, shared


def test_the_read_outside_the_census_pages_1000_up_to_20000() -> None:
    assert profile_job._BEYOND_PAGE == 1000
    assert profile_job._BEYOND_CEILING == 20_000


async def test_a_2500_host_read_outside_the_census_reads_every_host() -> None:
    """Three pages of 1,000, every host in the answer, no ceiling, the known hosts excluded."""
    grid = _PagedGrid(2500)

    result, shared = await _beyond_read(grid)

    buckets = result.aggregations["peers_out"]["buckets"]
    assert len(buckets) == 2500
    assert {b["key"] for b in buckets} == {b["key"] for b in grid.buckets}
    assert grid.sizes == [1000, 1000, 1000]
    assert len(shared.beyond) == 2500
    assert shared.capped == set()
    assert shared.at_ceiling == set()
    # Every page carries the lane's member aggregation and the exclusion.
    for body in grid.bodies:
        assert body["aggs"] == _PEERS_OUT_AGGS["peers_out"]["aggs"]
    for query in grid.queries:
        assert query["bool"]["must_not"] == [{"terms": {"source.ip": [_KNOWN]}}]


async def test_a_read_past_the_ceiling_stops_at_20000_and_marks_the_dimension() -> None:
    grid = _PagedGrid(20_500)

    result, shared = await _beyond_read(grid)

    assert len(result.aggregations["peers_out"]["buckets"]) == 20_000
    assert grid.sizes == [1000] * 19 + [1001]
    assert shared.at_ceiling == {"peers_out"}
    assert shared.capped == {"peers_out"}


async def test_400_hosts_outside_the_census_cost_one_page_and_no_mark() -> None:
    """Negative control: a short first page ends the read, and nothing is marked."""
    grid = _PagedGrid(400)

    result, shared = await _beyond_read(grid)

    assert len(result.aggregations["peers_out"]["buckets"]) == 400
    assert grid.sizes == [1000]
    assert shared.capped == set()
    assert shared.at_ceiling == set()


async def test_the_partitioned_shaped_read_is_not_paged() -> None:
    """Negative control: a terms read with a partition keeps its own ladder, as one search."""
    grid = _PagedGrid(700)
    shared = profile_job._Shared(grid, [])
    beyond = profile_job._BatchGrid(shared, exclude={"address": frozenset()})
    shaped = {
        "shaped": {
            "terms": {
                "field": "source.ip",
                "size": 500,
                "include": {"partition": 0, "num_partitions": 1},
            }
        }
    }

    result = await beyond.search("logs-*", {"match_all": {}}, size=0, aggs=shaped)

    assert len(grid.bodies) == 1
    assert "composite" not in grid.bodies[0]
    assert len(result.aggregations["shaped"]["buckets"]) == 500
    assert shared.capped == {"shaped"}
    assert shared.at_ceiling == set()


async def _beyond_build(
    settings_kratos: Settings, path: Path, estate: estate_mod.Estate, spy: Any = None
) -> tuple[dict[tuple[str, str], tuple[Any, ...]], profile_job.ProfileBuild]:
    """A build on an empty census: every host goes through the read outside the census."""
    grid = Grid(estate, refuse=spy)
    settings = _settings(settings_kratos, path, entity_profiles_enabled=True)
    engine, maker = await _store(settings)
    build = await profile_job.build_profiles(grid, maker, settings, _cidrs(settings))
    rows = await _rows(maker)
    await engine.dispose()
    return rows, build


def _hosts_on(rows: Mapping[tuple[str, str], Any], dimension: str) -> set[str]:
    return {key for key, dim in rows if dim == dimension}


async def test_a_host_past_the_old_500_cap_now_gets_a_profile(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """600 hosts and an empty census. The terms read held the busiest 500 on each dimension.

    The paged read gives every host its row, the same rows a build with the
    census writes in batches, and the build writes no ceiling note.
    """
    estate = estate_mod.build(600)
    beyond, build = await _beyond_build(settings_kratos, tmp_path / "beyond", estate)

    assert build.errors == []
    assert build.batches == 0
    assert len(_hosts_on(beyond, "peers_out")) > 500
    assert not [n for n in build.notes if "ceiling" in n or "entity cap" in n], build.notes

    batched, batched_build = await _build_rows(settings_kratos, tmp_path / "census", estate)
    assert batched_build.batches > 0
    assert beyond == batched


async def test_400_hosts_outside_the_census_cost_one_page_per_dimension(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """Negative control: below one page, each dimension reads once and the build adds no note."""
    pages: dict[str, list[int]] = {}

    def spy(query: Any, aggs: Mapping[str, Any] | None) -> bool:
        for name, body in (aggs or {}).items():
            if isinstance(body, Mapping) and "composite" in body:
                pages.setdefault(name, []).append(int(body["composite"]["size"]))
        return False

    _rows_400, build = await _beyond_build(
        settings_kratos, tmp_path / "store", estate_mod.build(400), spy
    )

    assert build.errors == []
    assert build.beyond > 400
    for dimension in _CATEGORICAL:
        assert pages.get(dimension) == [1000], (dimension, pages.get(dimension))
    assert not [n for n in build.notes if "ceiling" in n or "entity cap" in n], build.notes


async def test_a_read_at_the_ceiling_says_so_and_writes_no_measured_empty_row(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty census sends every host through the paged read, here with a ceiling of 300.

    The note names the ceiling and the dimensions. A host can sit past the
    ceiling on ``peers_out`` and inside it on ``dns_names``. The fill used to
    write it a "measured, none observed" ``peers_out`` row: a claim about a
    read that never reached the host.
    """
    monkeypatch.setattr(profile_job, "_BEYOND_CEILING", 300)
    monkeypatch.setattr(profile_job, "_BEYOND_PAGE", 100)
    rows, build = await _beyond_build(settings_kratos, tmp_path / "store", estate_mod.build(600))

    assert build.batches == 0
    ceiling = [n for n in build.notes if "stopped at the ceiling of 300 hosts" in n]
    assert len(ceiling) == 1, build.notes
    assert "peers_out" in ceiling[0]
    keyed: dict[str, set[str]] = {}
    for key, dim in rows:
        keyed.setdefault(key, set()).add(dim)
    past_the_ceiling = [
        k for k, dims in keyed.items() if "dns_names" in dims and "peers_out" not in dims
    ]
    assert past_the_ceiling, "the estate must put a host past the peers_out ceiling"
    empty_measured = [
        key
        for (key, dim), (_shape, vector, coverage, _reason, _days) in rows.items()
        if dim == "peers_out" and coverage == "measured" and vector == "{}"
    ]
    assert empty_measured == []


# ---------------------------------------------------------------------------
# The writer, the workers, the setting
# ---------------------------------------------------------------------------


async def test_the_bulk_writer_writes_what_upsert_profile_writes(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """Insert and update, row for row, against the per-row store function."""
    estate = estate_mod.build(60)
    grid = Grid(estate)
    base = _settings(settings_kratos, tmp_path / "lane")
    sweep = await collect_entity_profiles(
        elastic=grid,  # type: ignore[arg-type]
        settings=base,
        window_hours=30 * 24,
        lag_hours=24,
        cidrs=_cidrs(base),
    )
    rows = profile_job._rows_of(sweep)
    assert len(rows) > 100
    # The second pass changes every value the first wrote.
    changed = [
        profile_job._Row(
            key=r.key,
            dimension=r.dimension,
            shape=r.shape,
            vector={"changed": {"count": 1}},
            coverage="learning",
            support_days=r.support_days + 1,
            coverage_reason="x",
        )
        for r in rows
    ]

    bulk_settings = _settings(settings_kratos, tmp_path / "bulk")
    one_settings = _settings(settings_kratos, tmp_path / "one")
    bulk_engine, bulk = await _store(bulk_settings)
    one_engine, one = await _store(one_settings)
    for batch in (rows, changed):
        async with bulk() as db:
            await profile_job._write_rows(db, batch, window_days=30)
        async with one() as db:
            for r in batch:
                await entity_profiles.upsert_profile(
                    db,
                    entity_kind="host",
                    entity_key=r.key,
                    dimension=r.dimension,
                    shape=r.shape,
                    vector=r.vector,
                    coverage=r.coverage,
                    coverage_reason=r.coverage_reason,
                    support_days=r.support_days,
                    window_days=30,
                    shape_version=PROFILE_SHAPE,
                )
        assert await _full(bulk) == await _full(one)
    await bulk_engine.dispose()
    await one_engine.dispose()


async def _full(maker: async_sessionmaker[Any]) -> list[tuple[Any, ...]]:
    """Every column of every row but the id and the build stamp."""
    async with maker() as db:
        models = (await db.scalars(select(EntityProfile))).all()
    skip = {"id", "built_at"}
    columns = [c.key for c in EntityProfile.__table__.columns if c.key not in skip]
    return sorted(
        tuple(json.dumps(getattr(m, c), sort_keys=True, default=str) for c in columns)
        for m in models
    )


async def test_profile_build_workers_bounds_the_batches_in_flight(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The setting is read on every build, and it caps concurrent batch reads."""
    monkeypatch.setattr(profile_job, "_BATCH_KEYS", 20)
    estate = estate_mod.build(120)
    grid = Grid(estate, latency_ms=5)
    settings = _settings(settings_kratos, tmp_path / "store")
    engine, maker = await _store(settings)
    await _census(grid, maker, settings)

    in_flight = 0
    peak = 0
    inner = grid.search

    async def search(index: str, query: Any, **kwargs: Any) -> Any:
        nonlocal in_flight, peak
        scoped = _batch_keys(query) is not None
        if scoped:
            in_flight += 1
            peak = max(peak, in_flight)
        try:
            return await inner(index, query, **kwargs)
        finally:
            if scoped:
                in_flight -= 1

    grid.search = search  # type: ignore[method-assign]
    observed: dict[int, int] = {}
    for workers in (1, 3):
        settings.profile_build_workers = workers
        peak = 0
        build = await profile_job.build_profiles(grid, maker, settings, _cidrs(settings))
        assert build.errors == []
        assert build.batches >= 3
        observed[workers] = peak
    await engine.dispose()
    assert observed[1] == 1
    assert 1 < observed[3] <= 3


def test_profile_build_workers_is_a_hot_bounded_setting(settings_kratos: Settings) -> None:
    assert settings_kratos.profile_build_workers == 2
    spec = WHITELIST_BY_KEY["profile_build_workers"]
    assert spec.hot is True
    assert spec.type == "int"
    assert (spec.min_value, spec.max_value) == (1, 8)
    assert spec.section == "Behavioural profiles"


def test_the_batch_never_outgrows_the_lane_entity_terms() -> None:
    from soc_ai.dossier import profile

    assert profile_job._BATCH_KEYS <= profile._MAX_ENTITIES


async def test_the_wrapper_answers_an_empty_key_list_without_a_search() -> None:
    """A batch with names and no addresses sends no address read to the grid."""
    calls: list[Any] = []

    class _Grid:
        async def search(self, *args: Any, **kwargs: Any) -> Any:
            calls.append(args)
            raise AssertionError("no search expected")

    shared = profile_job._Shared(_Grid(), [])
    grid = profile_job._BatchGrid(shared, include={"address": (), "name": ("ws-1",)})
    result = await grid.search(
        "logs-*",
        {"match_all": {}},
        size=0,
        aggs={"served_ports": {"terms": {"field": "destination.ip", "size": 500}}},
    )
    assert result.aggregations == {"served_ports": {"buckets": [], "sum_other_doc_count": 0}}
    assert calls == []


async def test_a_read_every_batch_shares_runs_once() -> None:
    """The plane probes are the same for every batch. Two batches at once wait for one answer."""
    calls: list[Any] = []

    class _Grid:
        async def search(self, index: str, query: Any, **kwargs: Any) -> Any:
            calls.append(query)
            await asyncio.sleep(0.01)
            return {"probe": len(calls)}

    shared = profile_job._Shared(_Grid(), [])
    a = profile_job._BatchGrid(shared, include={"address": ("192.0.2.1",)})
    b = profile_job._BatchGrid(shared, include={"address": ("192.0.2.2",)})
    probe = {"plane_probe": {"filters": {"filters": {"x": {"match_all": {}}}}}}
    first, second = await asyncio.gather(
        a.search("logs-*", {"match_all": {}}, size=0, aggs=probe),
        b.search("logs-*", {"match_all": {}}, size=0, aggs=probe),
    )
    assert first == second == {"probe": 1}
    assert len(calls) == 1
