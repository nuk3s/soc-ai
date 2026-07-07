"""Unified tool-surface module: one registration site, one Phase-D source."""

from __future__ import annotations

import inspect
from typing import get_args
from unittest.mock import AsyncMock

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.agent.targeted_investigator import _dispatch_table
from soc_ai.agent.toolset import PHASE_D_TOOLS, register_read_tools
from soc_ai.config import Settings
from soc_ai.triage_models import TargetedGap

from tests.test_tool_surface import INVESTIGATOR_EXPECTED, _all_flags_on


def _agent_with(role: str, settings: Settings) -> Agent:
    agent: Agent = Agent(TestModel(call_tools=[]), output_type=str, system_prompt="x")
    ctx = InvestigationContext(settings=settings, auth=AsyncMock(), elastic=AsyncMock())
    register_read_tools(agent, ctx, role=role)  # type: ignore[arg-type]
    return agent


def _names(agent: Agent) -> set[str]:
    return set(agent._function_toolset.tools)


def test_roles_register_disjoint_extras(settings_kratos: Settings) -> None:
    inv = _names(_agent_with("investigator", settings_kratos))
    chat = _names(_agent_with("chat", settings_kratos))
    hunt = _names(_agent_with("hunt", settings_kratos))
    assert {"t_query_detections", "t_get_playbooks", "t_lookup_runbook"} <= inv - chat
    assert "t_suggest_rule_tuning" in chat and "t_suggest_rule_tuning" not in hunt
    assert hunt <= chat  # hunt is the minimal surface


def test_hunt_oql_default_window_is_wide(settings_kratos: Settings) -> None:
    hunt = _agent_with("hunt", settings_kratos)
    fn = hunt._function_toolset.tools["t_query_events_oql"].function
    assert inspect.signature(fn).parameters["time_range_minutes"].default == 1440
    inv = _agent_with("investigator", settings_kratos)
    fn = inv._function_toolset.tools["t_query_events_oql"].function
    assert inspect.signature(fn).parameters["time_range_minutes"].default == 60


def test_gated_tools_absent_when_flags_off(settings_kratos: Settings) -> None:
    """Registration-time gating in every role (normalized; investigator too)."""
    gated = {
        "t_shodan_internetdb",
        "t_greynoise",
        "t_shodan_host",
        "t_cve_lookup",
        "t_get_pcap",
        "t_web_search",
        "t_crawl_page",
    }
    for role in ("investigator", "chat", "hunt"):
        names = _names(_agent_with(role, settings_kratos))
        assert not (gated & names), (role, sorted(gated & names))


def test_investigator_flags_on_matches_golden_set(settings_kratos: Settings) -> None:
    """The unified module reproduces the investigator surface exactly.

    ``INVESTIGATOR_EXPECTED`` is the golden set captured from the live
    ``build_investigator`` at rewire time — it pins the unified module against
    the pre-rewire surface and will catch any unintended registration drift.
    """
    agent = _agent_with("investigator", _all_flags_on(settings_kratos))
    assert _names(agent) == INVESTIGATOR_EXPECTED


def test_targeted_gap_literal_matches_phase_d_tools() -> None:
    """The TargetedGap Literal is a GATED copy of the dispatch surface."""
    literal_names = set(get_args(TargetedGap.model_fields["tool_name"].annotation))
    assert literal_names == set(PHASE_D_TOOLS)


def test_phase_d_dispatch_table_matches_phase_d_tools() -> None:
    """Drift gate: the Phase-D dispatch table keys == PHASE_D_TOOLS exactly.

    _dispatch_named_tool validates tool_name against PHASE_D_TOOLS before the
    table lookup, so a table key missing from the tuple would be unreachable
    and a tuple entry missing from the table would KeyError — both are drift.
    """
    assert set(_dispatch_table()) == set(PHASE_D_TOOLS)


@pytest.mark.asyncio
async def test_dedup_wrapping_runs_through_registered_tool(settings_kratos: Settings) -> None:
    """Behavioral proof the house wrapping runs THROUGH the module (not just
    name parity): the second identical call to a registered tool short-circuits
    with the structured duplicate-hint dict instead of re-running the tool."""
    agent = _agent_with("investigator", settings_kratos)
    tool = agent._function_toolset.tools["t_query_cases"]

    first = await tool.function(query="ransomware")
    second = await tool.function(query="ransomware")

    # First call went through to the (mocked) elastic ctx — whatever it
    # returned, it is NOT the duplicate payload.
    assert not (isinstance(first, dict) and first.get("duplicate_call"))
    assert isinstance(second, dict)
    assert second["duplicate_call"] is True
    assert second["tool_name"] == "t_query_cases"
    assert "hint" in second
