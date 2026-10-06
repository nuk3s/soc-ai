"""Run the sweep, the clustering, the profile build and the prior sweep at scale.

Usage::

    .venv/bin/python scripts/scale/run.py --hosts 2000
    .venv/bin/python scripts/scale/run.py --hosts 20000 --json /tmp/scale-20000.json

The runner boots the app's store and settings: a fresh SQLite file in a
temporary directory, migrated to head, and settings that point the internal
CIDRs at the estate. The grid is :class:`scripts.scale.grid.Grid` over a
synthetic estate from :mod:`scripts.scale.estate`. The runner then calls the
entry points the scheduler calls, in this order:

1. ``dossier sweep``: :func:`run_dossier_refresh`, with the profile build off.
   Its own stages print below it.
2. ``cluster machines``: the pure :func:`cluster_machines` over the store's
   census, timed alone.
3. ``profile build``: :func:`profile_job.build_profiles`.
4. ``profile build again``: the same build a minute later. Every host is
   fresh, so this measures the incremental path.
5. ``prior sweep``: :func:`run_prior_sweep` with ``record=True``.

Each stage prints its wall time, the searches it sent to the grid and the
peak resident memory of the process during the stage. The counts at the end
are machines, profile rows, observations and leads.

See ``docs/dev/scale-harness.md`` for the budgets and how to read a failure.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import resource
import sys
import tempfile
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pydantic import SecretStr  # noqa: E402
from scripts.scale import estate as estate_mod  # noqa: E402
from scripts.scale.grid import Grid  # noqa: E402
from soc_ai.config import Settings  # noqa: E402
from soc_ai.dossier import profile_job  # noqa: E402
from soc_ai.enrichment.host_dossier import run_dossier_refresh  # noqa: E402
from soc_ai.so_client import fields, inventory  # noqa: E402
from soc_ai.store import host_dossier as dossier_store  # noqa: E402
from soc_ai.store import host_machines  # noqa: E402
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations  # noqa: E402
from soc_ai.store.models import (  # noqa: E402
    EntityObservation,
    EntityProfile,
    HostDossier,
    HostMachine,
    Lead,
)
from sqlalchemy import func, select  # noqa: E402


@dataclass
class StageResult:
    name: str
    seconds: float
    searches: int
    peak_rss_mb: float | None = None
    # Seconds the mock grid spent answering. The app's own share is the rest.
    grid_seconds: float = 0.0
    detail: str = ""


@dataclass
class Report:
    hosts: int
    estate: dict[str, int]
    stages: list[StageResult] = field(default_factory=list)
    sweep_stages: list[dict[str, Any]] = field(default_factory=list)
    build_stages: list[dict[str, Any]] = field(default_factory=list)
    rebuild_stages: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    planted: dict[str, list[str]] = field(default_factory=dict)

    def stage(self, name: str) -> StageResult:
        for stage in self.stages:
            if stage.name == name:
                return stage
        raise KeyError(name)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Peak memory per stage
# ---------------------------------------------------------------------------

_CLEAR_REFS = Path("/proc/self/clear_refs")
_STATUS = Path("/proc/self/status")


def _reset_peak() -> bool:
    """Reset the kernel's high-water mark of resident memory. Linux only."""
    try:
        _CLEAR_REFS.write_text("5")
    except OSError:
        return False
    return True


def _peak_mb() -> float | None:
    try:
        for line in _STATUS.read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    # ru_maxrss is in KiB on Linux. It never resets, so it is the run's peak.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


@asynccontextmanager
async def _measure(report: Report, name: str, grid: Grid) -> AsyncIterator[StageResult]:
    result = StageResult(name=name, seconds=0.0, searches=0)
    resettable = _reset_peak()
    before = grid.searches
    grid_before = grid.seconds
    started = time.perf_counter()
    try:
        yield result
    finally:
        result.seconds = time.perf_counter() - started
        result.searches = grid.searches - before
        result.grid_seconds = grid.seconds - grid_before
        result.peak_rss_mb = _peak_mb() if resettable else None
        report.stages.append(result)


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def _settings(data_dir: Path, *, workers: int, max_hosts_per_run: int, hosts: int) -> Settings:
    return Settings(
        so_host="https://so.example.test",
        so_username="analyst",
        so_password=SecretStr("not-a-secret"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.test:9200"],
        litellm_base_url="http://localhost:4000",
        api_auth_required=False,
        soc_ai_data_dir=data_dir,
        internal_cidrs=list(estate_mod.CIDRS),
        dossier_enabled=True,
        dossier_max_hosts_per_run=max_hosts_per_run,
        dossier_max_hosts=max(5000, 2 * hosts),
        entity_profiles_enabled=False,
        profile_build_workers=workers,
    )


async def _seed_declarations(maker: Any, estate: estate_mod.Estate) -> int:
    """Write the operator's declared roles before the first sweep."""
    count = 0
    async with maker() as db:
        for host in estate.hosts:
            if not host.declared_role:
                continue
            await dossier_store.upsert_host(db, host.ip)
            await dossier_store.set_override(
                db, host.ip, "role", host.declared_role, actor="scale-harness"
            )
            count += 1
        await db.commit()
    return count


async def _count(maker: Any, model: Any) -> int:
    async with maker() as db:
        return int((await db.execute(select(func.count()).select_from(model))).scalar_one())


async def run(  # noqa: PLR0915 - one procedure, read top to bottom
    hosts: int,
    *,
    days: int = 8,
    seed: int = 20261004,
    workers: int = 2,
    max_hosts_per_run: int = 200,
    latency_ms: float = 0.0,
    data_dir: Path | None = None,
) -> Report:
    """Run every stage against a fresh estate of ``hosts`` hosts. Returns the report."""
    from soc_ai.hunting.prior_sweep import run_prior_sweep

    # Both resolvers cache per process. A run after another must read its own grid.
    fields._clear_agg_field_cache()
    inventory._clear_cache()
    started = time.perf_counter()
    estate = estate_mod.build(hosts, days=days, seed=seed, anchor=datetime.now(UTC))
    grid = Grid(estate, latency_ms=latency_ms)
    report = Report(hosts=hosts, estate=estate.summary(), planted=estate.planted)
    report.notes.append(f"estate built in {time.perf_counter() - started:.2f} s")

    with tempfile.TemporaryDirectory(prefix="soc-ai-scale-") as scratch:
        root = data_dir or Path(scratch)
        settings = _settings(
            root, workers=workers, max_hosts_per_run=max_hosts_per_run, hosts=hosts
        )
        async with _measure(report, "boot", grid):
            engine = make_engine(settings)
            await run_migrations(engine)
            maker = make_sessionmaker(engine)
            declared = await _seed_declarations(maker, estate)
        report.notes.append(f"{declared} declared roles seeded")
        try:
            async with _measure(report, "dossier sweep", grid) as stage:
                summary = await run_dossier_refresh(grid, maker, settings, trigger="manual")
                stage.detail = f"{summary.hosts_seen} seen, {summary.hosts_built} built"
            report.sweep_stages = summary.stages
            report.errors.extend(summary.errors)
            report.notes.extend(summary.notes)

            async with _measure(report, "cluster machines", grid) as stage:
                async with maker() as db:
                    facts = await host_machines.load_address_facts(
                        db,
                        now=datetime.now(UTC),
                        min_confidence=float(settings.dossier_min_confidence),
                        staleness_hours=int(settings.dossier_staleness_hours),
                    )
                    prior = await host_machines.load_prior(db)
                loaded = time.perf_counter()
                clustering = host_machines.cluster_machines(facts, prior=prior)
                stage.detail = (
                    f"{len(facts)} addresses, {len(clustering.machines)} machines, "
                    f"pure clustering {time.perf_counter() - loaded:.2f} s"
                )

            settings.entity_profiles_enabled = True
            cidrs = list(settings.internal_cidrs)
            async with _measure(report, "profile build", grid) as stage:
                build = await profile_job.build_profiles(grid, maker, settings, cidrs)
                stage.detail = (
                    f"{build.written} rows, {build.batches} batches, "
                    f"{build.skipped} skipped, {build.single} alone"
                )
            report.build_stages = build.stages
            report.errors.extend(build.errors)
            report.notes.extend(n for n in build.notes if not n.startswith("profile planes"))

            async with _measure(report, "profile build again", grid) as stage:
                again = await profile_job.build_profiles(grid, maker, settings, cidrs)
                stage.detail = (
                    f"{again.written} rows, {again.batches} batches, {again.skipped} skipped"
                )
            report.rebuild_stages = again.stages
            report.errors.extend(again.errors)

            async with _measure(report, "prior sweep", grid) as stage:
                async with maker() as db:
                    sweep = await run_prior_sweep(
                        elastic=grid, settings=settings, db=db, record=True, cidrs=cidrs
                    )
                leads = sweep.leads
                stage.detail = f"{len(sweep.results)} results"
            report.errors.extend(sweep.errors)
            report.notes.extend(n for n in sweep.notes if "cap" in n or "500" in n)
            if leads is not None:
                report.notes.append(f"prior sweep formed {len(leads.formed)} lead(s)")

            report.counts = {
                "addresses": await _count(maker, HostDossier),
                "machines": await _count(maker, HostMachine),
                "profile_rows": await _count(maker, EntityProfile),
                "observations": await _count(maker, EntityObservation),
                "leads": await _count(maker, Lead),
                "searches": grid.searches,
            }
            async with maker() as db:
                rows = await db.execute(
                    select(EntityObservation.spec_id, func.count()).group_by(
                        EntityObservation.spec_id
                    )
                )
                for spec_id, count in rows.all():
                    report.counts[f"observations {spec_id}"] = int(count)
        finally:
            await engine.dispose()
    return report


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _table(report: Report) -> str:
    lines = [
        f"scale harness: {report.hosts} hosts",
        "",
        f"{'stage':<28}{'wall s':>10}{'grid s':>10}{'searches':>10}{'peak MB':>10}  detail",
    ]
    for stage in report.stages:
        peak = f"{stage.peak_rss_mb:.0f}" if stage.peak_rss_mb is not None else "-"
        lines.append(
            f"{stage.name:<28}{stage.seconds:>10.2f}{stage.grid_seconds:>10.2f}"
            f"{stage.searches:>10}{peak:>10}  {stage.detail}"
        )
        nested = {
            "dossier sweep": report.sweep_stages,
            "profile build": report.build_stages,
            "profile build again": report.rebuild_stages,
        }.get(stage.name, [])
        for inner in nested:
            lines.append(
                f"  {inner['name']:<26}{inner['seconds']:>10.2f}{'':>10}{inner['searches']:>10}"
                f"{'':>10}  {inner.get('detail', '')}"
            )
    lines.append("")
    for key, value in report.counts.items():
        lines.append(f"{key:>16}: {value}")
    for key, value in report.estate.items():
        lines.append(f"{'estate ' + key:>16}: {value}")
    if report.errors:
        lines.append("")
        lines.append("errors:")
        lines.extend(f"  {e}" for e in report.errors[:20])
    if report.notes:
        lines.append("")
        lines.append("notes:")
        lines.extend(f"  {n}" for n in report.notes[:30])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run soc-ai's sweeps against a synthetic estate.")
    parser.add_argument("--hosts", type=int, default=2000)
    parser.add_argument("--days", type=int, default=8)
    parser.add_argument("--seed", type=int, default=20261004)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--max-hosts-per-run", type=int, default=200)
    parser.add_argument("--latency-ms", type=float, default=0.0)
    parser.add_argument("--json", type=Path, default=None, help="Write the report here too.")
    parser.add_argument("--verbose", action="store_true", help="Log the stage lines at INFO.")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    report = asyncio.run(
        run(
            args.hosts,
            days=args.days,
            seed=args.seed,
            workers=args.workers,
            max_hosts_per_run=args.max_hosts_per_run,
            latency_ms=args.latency_ms,
        )
    )
    print(_table(report))
    if args.json is not None:
        args.json.write_text(json.dumps(report.as_dict(), indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
