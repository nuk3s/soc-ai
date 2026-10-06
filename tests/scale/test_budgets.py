"""The scale harness under budget: wall time, searches and memory per stage.

One harness run per session (``scripts/scale/run.py``) over a synthetic estate
of ``--scale-hosts`` hosts. Each stage must stay inside its budget. A budget is
linear in the host count: ``base + per_k * hosts / 1000``. A stage that grows
faster than linear breaks its budget at 10,000 or 20,000 hosts, even when it
passes at 2,000.

The numbers come from the measurement of 2026-10-04 on the development box.
The search budgets carry about 20 percent of headroom: a search count does not
vary from run to run, so a change that adds searches fails here. The wall time
budgets carry about three times the measured slope: CI runners are slower and
shared. ``docs/dev/scale-harness.md`` holds the measurement and explains how
to read a failure.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import pytest
from scripts.scale import run as harness
from soc_ai.store import host_machines as hm

from tests.test_host_machines_indexed import _inputs, _prior

pytestmark = pytest.mark.scale


@dataclass(frozen=True)
class Budget:
    """A linear budget for one stage."""

    wall_base: float
    wall_per_k: float
    searches_base: int = 0
    searches_per_k: float = 0.0

    def wall(self, hosts: int) -> float:
        return self.wall_base + self.wall_per_k * hosts / 1000

    def searches(self, hosts: int) -> int:
        return int(self.searches_base + self.searches_per_k * hosts / 1000)


BUDGETS: dict[str, Budget] = {
    "boot": Budget(wall_base=10, wall_per_k=0.5),
    # 615 searches are the 200 per-host builds. The census adds two pages per
    # 2,000 addresses above 10,000. The batched census record took the wall
    # slope from about 3.0 s to 1.85 s per 1,000 hosts, so the budget is three
    # times the new slope.
    "dossier sweep": Budget(wall_base=10, wall_per_k=5.5, searches_base=650, searches_per_k=1.5),
    "cluster machines": Budget(wall_base=2, wall_per_k=0.25),
    "profile build": Budget(wall_base=5, wall_per_k=6, searches_base=30, searches_per_k=45),
    "profile build again": Budget(wall_base=5, wall_per_k=6, searches_base=30, searches_per_k=45),
    # The recent read pages the whole estate, 1,000 entities a page: 15
    # searches at 2,000 hosts, 75 at 20,000. It scores every entity it reads,
    # 103,504 results at 20,000 hosts in 41 s.
    "prior sweep": Budget(wall_base=5, wall_per_k=6, searches_base=20, searches_per_k=4),
}
# Peak resident memory of the whole process, the estate and the grid included.
PEAK_MB_BASE = 400
PEAK_MB_PER_K = 35
# The pure clustering on 20,000 hosts, with 6,780 machines to merge.
CLUSTER_20000_SECONDS = 10.0


@pytest.fixture(scope="module")
def report(scale_hosts: int) -> harness.Report:
    result = asyncio.run(harness.run(scale_hosts))
    print()
    print(harness._table(result))
    return result


@pytest.mark.parametrize("stage", sorted(BUDGETS))
def test_each_stage_stays_inside_its_budget(
    report: harness.Report, scale_hosts: int, stage: str
) -> None:
    budget = BUDGETS[stage]
    measured = report.stage(stage)
    assert measured.seconds <= budget.wall(scale_hosts), (
        f"{stage}: {measured.seconds:.1f} s against a budget of "
        f"{budget.wall(scale_hosts):.1f} s at {scale_hosts} hosts "
        f"(the grid answered for {measured.grid_seconds:.1f} s of it)"
    )
    assert measured.searches <= budget.searches(scale_hosts), (
        f"{stage}: {measured.searches} searches against a budget of "
        f"{budget.searches(scale_hosts)} at {scale_hosts} hosts"
    )


def test_the_process_stays_inside_its_memory_budget(
    report: harness.Report, scale_hosts: int
) -> None:
    peaks = [s.peak_rss_mb for s in report.stages if s.peak_rss_mb is not None]
    if not peaks:
        pytest.skip("this platform does not report the peak resident memory")
    budget = PEAK_MB_BASE + PEAK_MB_PER_K * scale_hosts / 1000
    assert max(peaks) <= budget, f"peak {max(peaks):.0f} MB against {budget:.0f} MB"


def test_the_run_is_clean_and_covers_the_estate(report: harness.Report, scale_hosts: int) -> None:
    assert report.errors == []
    # The census holds every host: the paging past the one-search cap works.
    assert report.counts["addresses"] >= scale_hosts
    assert report.counts["machines"] >= int(0.9 * scale_hosts)
    assert report.counts["profile_rows"] >= 5 * scale_hosts


def test_the_planted_departures_are_observed(report: harness.Report) -> None:
    """The burst at night is two observation types on one host, and so a lead."""
    assert report.counts.get("observations profile-connection-rate-spiked", 0) >= 1
    assert report.counts.get("observations profile-activity-outside-measured-hours", 0) >= 1
    assert report.counts["leads"] >= 1


def test_the_whole_estate_is_read_for_the_quiet_departures(report: harness.Report) -> None:
    """The silent server and the novel served port sit outside the busiest 500.

    A recent read of the busiest 500 entities missed both at 20,000 hosts, and
    it scored no silent host once it held 500. The paged read sees both.
    """
    assert report.counts.get("observations profile-connection-rate-collapsed", 0) >= 1
    assert report.counts.get("observations prior-hypervisor-novel-served-port", 0) >= 1
    assert not [n for n in report.notes if "stopped at the ceiling" in n], report.notes


def test_the_second_build_skips_the_quiet_hosts(report: harness.Report) -> None:
    first = report.stage("profile build")
    again = report.stage("profile build again")
    skipped = next(s for s in report.rebuild_stages if s["name"] == "plan")["detail"]
    assert " 0 skipped" not in skipped, skipped
    assert again.searches <= first.searches


def test_cluster_machines_on_20000_hosts_stays_under_its_budget() -> None:
    """The pure clustering, with a previous sweep that makes every agent a merge.

    The merge scanned every machine per earlier machine. At 20,000 hosts it
    took 102 s. The indexed merge takes about 1 s.
    """
    inputs = _inputs(20_000)
    first = hm.cluster_machines(**inputs)
    prior = _prior(first)
    started = time.perf_counter()
    second = hm.cluster_machines(**inputs, prior=prior)
    seconds = time.perf_counter() - started
    assert len(second.merged) > 6000
    assert seconds <= CLUSTER_20000_SECONDS, f"{seconds:.1f} s"
