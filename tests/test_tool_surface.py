"""Registration-surface tests: new-tool smoke tests + per-role parity oracle.

Asserts that ``t_get_rule_content`` and ``t_decode_payload`` are registered on
all three read agents, and that the investigator gained ``t_get_event_raw``
(parity with chat/hunt — its escape hatch when prefetch dropped a field).

The golden constants (``CORE``, ``INVESTIGATOR_EXPECTED``, ``CHAT_EXPECTED``,
``HUNT_EXPECTED``) are the per-role parity oracle: they document the EXACT tool
surface of each agent when all gated tools are enabled, and act as the
reference that ``tests/test_toolset.py`` pins the unified module against.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

from pydantic import SecretStr
from pydantic_ai.models.test import TestModel
from soc_ai.agent.chat_agent import build_chat_agent
from soc_ai.agent.hunt import HUNT_SYSTEM_PROMPT, build_hunt_agent
from soc_ai.agent.orchestrator import InvestigationContext, build_investigator
from soc_ai.config import Settings

NEW_TOOLS = {"t_get_rule_content", "t_decode_payload"}


def _ctx(settings: Settings) -> InvestigationContext:
    return InvestigationContext(settings=settings, auth=AsyncMock(), elastic=AsyncMock())


def _names(agent: Any) -> set[str]:
    return set(agent._function_toolset.tools.keys())  # type: ignore[attr-defined]


def test_investigator_registers_new_tools(settings_kratos: Settings) -> None:
    agent = build_investigator(TestModel(call_tools=[]), _ctx(settings_kratos))
    names = _names(agent)
    assert names >= NEW_TOOLS, sorted(NEW_TOOLS - names)
    assert "t_get_event_raw" in names  # parity with chat/hunt


def test_chat_agent_registers_new_tools(settings_kratos: Settings) -> None:
    agent = build_chat_agent(TestModel(call_tools=[]), _ctx(settings_kratos), system_prompt="chat")
    names = _names(agent)
    assert names >= NEW_TOOLS, sorted(NEW_TOOLS - names)


def test_hunt_agent_registers_new_tools(settings_kratos: Settings) -> None:
    agent = build_hunt_agent(
        TestModel(call_tools=[]),
        _ctx(settings_kratos),
        system_prompt=HUNT_SYSTEM_PROMPT.format(objective="hunt"),
    )
    names = _names(agent)
    assert names >= NEW_TOOLS, sorted(NEW_TOOLS - names)


# ---------------------------------------------------------------------------
# Golden per-role tool sets (parity oracle for toolset unification)
#
# These constants document the EXACT tool surface of each agent when ALL
# gated tools are enabled.  They act as a parity oracle: a refactor that
# moves registrations into a unified module must leave these sets unchanged.
# ---------------------------------------------------------------------------

CORE = {
    "t_query_events_oql",
    "t_query_zeek_logs",
    "t_describe_dataset",
    "t_field_values",
    "t_query_cases",
    "t_get_event_raw",
    "t_get_rule_content",
    "t_decode_payload",
    "t_enrich_ip",
    "t_enrich_domain",
    "t_enrich_hash",
    "t_host_summary",
    "t_prevalence",
    "t_rule_prevalence",
    "t_shodan_internetdb",
    "t_greynoise",
    "t_shodan_host",
    "t_cve_lookup",
    "t_get_pcap",
    "t_web_search",
    "t_crawl_page",
}
INVESTIGATOR_EXPECTED = CORE | {
    "t_query_detections",
    "t_get_playbooks",
    "t_lookup_runbook",
    "t_suggest_rule_tuning",
}
CHAT_EXPECTED = CORE | {"t_suggest_rule_tuning", "propose_verdict"}
HUNT_EXPECTED = CORE


def _all_flags_on(settings_kratos: Settings) -> Settings:
    return settings_kratos.model_copy(
        update={
            "allow_online_enrichment": True,
            "shodan_api_key": SecretStr("k"),
            "greynoise_api_key": SecretStr("k"),
            "pcap_enabled": True,
            "so_ssh_host": "sensor.local",
            "web_search_enabled": True,
            "searxng_url": "https://sx.local",
            "crawl4ai_enabled": True,
            "crawl4ai_url": "https://c4.local",
        }
    )


def test_golden_tool_sets_investigator(settings_kratos: Settings) -> None:
    agent = build_investigator(TestModel(call_tools=[]), _ctx(_all_flags_on(settings_kratos)))
    assert _names(agent) == INVESTIGATOR_EXPECTED


def test_golden_tool_sets_chat(settings_kratos: Settings) -> None:
    agent = build_chat_agent(
        TestModel(call_tools=[]),
        _ctx(_all_flags_on(settings_kratos)),
        system_prompt="chat",
        proposal_sink=[],
    )
    assert _names(agent) == CHAT_EXPECTED


def test_golden_tool_sets_hunt(settings_kratos: Settings) -> None:
    agent = build_hunt_agent(
        TestModel(call_tools=[]),
        _ctx(_all_flags_on(settings_kratos)),
        system_prompt=HUNT_SYSTEM_PROMPT.format(objective="hunt"),
    )
    assert _names(agent) == HUNT_EXPECTED


# ---------------------------------------------------------------------------
# Golden per-role tool sets with ALL gates OFF.
#
# This PINS the deliberate normalization the toolset unification made:
# settings-gated tools are absent from EVERY role's registered surface when
# their flag is off. (Pre-unification the investigator kept t_get_pcap /
# t_web_search / t_crawl_page registered even when disabled; now no role
# registers a tool the model can't use.)
# ---------------------------------------------------------------------------

GATED = {
    "t_shodan_internetdb",
    "t_greynoise",
    "t_shodan_host",
    "t_cve_lookup",
    "t_get_pcap",
    "t_web_search",
    "t_crawl_page",
}


def test_golden_tool_sets_flags_off_investigator(settings_kratos: Settings) -> None:
    assert settings_kratos.allow_online_enrichment is False  # fixture default: gates off
    agent = build_investigator(TestModel(call_tools=[]), _ctx(settings_kratos))
    assert _names(agent) == INVESTIGATOR_EXPECTED - GATED


def test_golden_tool_sets_flags_off_chat(settings_kratos: Settings) -> None:
    agent = build_chat_agent(
        TestModel(call_tools=[]),
        _ctx(settings_kratos),
        system_prompt="chat",
        proposal_sink=[],
    )
    assert _names(agent) == CHAT_EXPECTED - GATED


def test_golden_tool_sets_flags_off_hunt(settings_kratos: Settings) -> None:
    agent = build_hunt_agent(
        TestModel(call_tools=[]),
        _ctx(settings_kratos),
        system_prompt=HUNT_SYSTEM_PROMPT.format(objective="hunt"),
    )
    assert _names(agent) == HUNT_EXPECTED - GATED
