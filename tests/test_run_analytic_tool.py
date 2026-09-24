"""The hunt agent runs an analytic as a step."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.agent import toolset
from soc_ai.config import Settings
from soc_ai.hunting.execute import Candidate, SpecRun

pytestmark = pytest.mark.asyncio


def _run(spec_id: str) -> SpecRun:
    return SpecRun(
        spec_id=spec_id,
        since="now-30d",
        until="now",
        blind=False,
        precondition_docs=40,
        matched_docs=2,
        candidates=[
            Candidate(
                spec_id=spec_id,
                scope_key="198.51.100.7",
                scope_kind="host",
                doc_count=2,
                sample_ids=("d1", "d2"),
                anchor_id="d1",
                anchor_index="logs-x",
                first_seen="2026-09-17T10:00:00Z",
                last_seen="2026-09-17T11:00:00Z",
            )
        ],
    )


def _ctx(settings: Settings) -> SimpleNamespace:
    return SimpleNamespace(
        elastic=None, settings=settings, db_sessionmaker=None, include_synth=False
    )


async def test_the_tool_runs_a_live_analytic_and_returns_its_candidates(
    settings_kratos: Settings,
) -> None:
    fake_catalog = SimpleNamespace(
        specs={
            "identity-4662-dcsync-nonmachine": SimpleNamespace(
                id="identity-4662-dcsync-nonmachine", title="DCSync"
            )
        },
        shadow_ids=frozenset(),
        status_of=lambda sid: ("shipped", "live"),
    )
    with (
        patch("soc_ai.agent.toolset.effective_catalog", AsyncMock(return_value=fake_catalog)),
        patch(
            "soc_ai.agent.toolset.run_spec", AsyncMock(side_effect=lambda spec, **kw: _run(spec.id))
        ),
    ):
        out = await toolset.run_analytic_for_agent(
            ctx=_ctx(settings_kratos),
            analytic_id="identity-4662-dcsync-nonmachine",
            window_days=30,
        )
    assert out["analytic"] == "identity-4662-dcsync-nonmachine"
    assert out["status"] == "live"
    assert out["matched_docs"] == 2
    assert out["candidates"][0]["entity"] == "198.51.100.7"
    assert out["candidates"][0]["sample_ids"] == ["d1", "d2"]
    assert out["provenance"] == "live"


async def test_an_unknown_or_retired_analytic_is_refused_with_the_list(
    settings_kratos: Settings,
) -> None:
    fake_catalog = SimpleNamespace(
        specs={},
        shadow_ids=frozenset(),
        status_of=lambda sid: ("shipped", "retired"),
        listed={"identity-4662-dcsync-nonmachine": SimpleNamespace(title="DCSync")},
    )
    with patch("soc_ai.agent.toolset.effective_catalog", AsyncMock(return_value=fake_catalog)):
        out = await toolset.run_analytic_for_agent(
            ctx=_ctx(settings_kratos), analytic_id="nope", window_days=7
        )
    assert out["error"] == "unknown_analytic"
    assert "identity-4662-dcsync-nonmachine" in str(out["available"])


async def test_the_window_is_clamped(settings_kratos: Settings) -> None:
    calls: list[str] = []

    async def fake_run(spec: Any, **kw: Any) -> SpecRun:
        calls.append(kw["since"])
        return _run(spec.id)

    fake_catalog = SimpleNamespace(
        specs={"a": SimpleNamespace(id="a", title="A")},
        shadow_ids=frozenset(),
        status_of=lambda sid: ("local", "live"),
    )
    with (
        patch("soc_ai.agent.toolset.effective_catalog", AsyncMock(return_value=fake_catalog)),
        patch("soc_ai.agent.toolset.run_spec", fake_run),
    ):
        await toolset.run_analytic_for_agent(
            ctx=_ctx(settings_kratos), analytic_id="a", window_days=400
        )
    assert calls == ["now-90d"]


async def test_a_run_that_errored_is_reported_as_could_not_run(
    settings_kratos: Settings,
) -> None:
    """A grid error never reads as an empty result."""

    async def fake_run(spec: Any, **kw: Any) -> SpecRun:
        return SpecRun(
            spec_id=spec.id,
            since=kw["since"],
            until="now",
            blind=False,
            precondition_docs=0,
            matched_docs=0,
            error="mapping error on winlog.event_data.X",
        )

    fake_catalog = SimpleNamespace(
        specs={"a": SimpleNamespace(id="a", title="A")},
        shadow_ids=frozenset({"a"}),
        status_of=lambda sid: ("local", "shadow"),
    )
    with (
        patch("soc_ai.agent.toolset.effective_catalog", AsyncMock(return_value=fake_catalog)),
        patch("soc_ai.agent.toolset.run_spec", fake_run),
    ):
        out = await toolset.run_analytic_for_agent(
            ctx=_ctx(settings_kratos), analytic_id="a", window_days=7
        )
    assert out["error"] == "could_not_run"
    assert out["status"] == "shadow"
    assert "candidates" not in out


async def test_the_tool_is_registered_on_the_hunt_role_alone() -> None:
    assert "t_run_analytic" in toolset.HUNT_ONLY
