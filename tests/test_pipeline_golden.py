"""E1.4 — Backtest golden-pipeline gate.

A DETERMINISTIC regression gate over the triage funnel's *deterministic* layers
(decision templates, evidence/citation gates, targeted downgrades, funnel
routing) — NOT the model's quality. Each golden scenario replays a realistic ES
``_source`` dict through :func:`soc_ai.agent.orchestrator.investigate` with a
mocked Elasticsearch and a SCRIPTED model double, then asserts the final verdict
plus which deterministic gate events fired.

A prompt or gate edit that silently flips a golden verdict — or stops a gate
firing — fails this gate with a clear diff.

Marked ``slow`` so it is grouped with the heavier suite, but it is fast
(<2 min total; no network, no real model). CI's default ``uv run pytest`` run
includes ``slow`` (there is no ``-m "not slow"`` in ``addopts``), so this gate
runs on every CI push under the coverage gate.
"""

from __future__ import annotations

import pytest

from tests.golden.harness import run_scenario
from tests.golden.scenarios import SCENARIOS, GoldenScenario

pytestmark = pytest.mark.slow


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
async def test_golden_pipeline(scenario: GoldenScenario) -> None:
    """Replay one golden scenario and assert its pinned deterministic outcome."""
    result = await run_scenario(scenario)
    exp = scenario.expected

    # 1. Final verdict.
    assert result.verdict == exp.verdict, (
        f"[{scenario.id}] verdict {result.verdict!r} != expected {exp.verdict!r}. "
        f"Event kinds seen: {sorted(result.event_kinds)}"
    )

    # 2. Confidence bounds (optional).
    if exp.min_confidence is not None:
        assert result.confidence is not None, f"[{scenario.id}] no confidence emitted"
        assert result.confidence >= exp.min_confidence, (
            f"[{scenario.id}] confidence {result.confidence} < min {exp.min_confidence}"
        )
    if exp.max_confidence is not None:
        assert result.confidence is not None, f"[{scenario.id}] no confidence emitted"
        assert result.confidence <= exp.max_confidence, (
            f"[{scenario.id}] confidence {result.confidence} > max {exp.max_confidence}"
        )

    # 3. Every named gate MUST have fired.
    for gate in exp.gates_fired:
        assert gate in result.event_kinds, (
            f"[{scenario.id}] expected gate {gate!r} to fire but it did not. "
            f"Event kinds seen: {sorted(result.event_kinds)}"
        )

    # 4. Every named gate MUST be absent.
    for gate in exp.gates_absent:
        assert gate not in result.event_kinds, (
            f"[{scenario.id}] gate {gate!r} fired but should have been absent. "
            f"Event kinds seen: {sorted(result.event_kinds)}"
        )


def test_golden_set_is_non_trivial() -> None:
    """Guard the harness against silent scenario loss (a mis-import that empties
    the set would otherwise make the parametrized gate vacuously pass)."""
    assert len(SCENARIOS) >= 6, "the golden set must keep at least 6 scenarios"
    assert len({s.id for s in SCENARIOS}) == len(SCENARIOS), "scenario ids must be unique"
