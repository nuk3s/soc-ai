"""A completed investigation increments socai_investigations_total (dogfood 2026-10-01 RA2).

The orchestrator yielded its "done" event without passing it through
``_audit``, and ``_audit`` is the only feed into the /metrics counters. So the
counter stayed at 0 on every completed run. This drives a real pipeline run
through the golden harness and reads the counter.
"""

from __future__ import annotations

import pytest
from soc_ai import metrics

from tests.golden.harness import run_scenario
from tests.golden.scenarios import SCENARIOS


@pytest.mark.asyncio
async def test_a_completed_run_counts_once() -> None:
    saved = metrics._GLOBAL
    metrics._GLOBAL = metrics._Metrics()
    try:
        result = await run_scenario(SCENARIOS[0])
        assert "done" in result.event_kinds
        assert metrics.get_metrics().investigations_total == 1
        assert "socai_investigations_total 1" in metrics.render(version="test")
    finally:
        metrics._GLOBAL = saved
