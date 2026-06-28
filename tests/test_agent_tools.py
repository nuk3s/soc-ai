"""Tests for the agent-tools capability introspection (config console)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pydantic import SecretStr
from soc_ai.api.agent_tools import catalog_tool_names, collect_agent_tools


def _settings(**over: Any) -> Any:
    base: dict[str, Any] = dict(
        es_hosts=["https://es:9200"],
        allow_online_enrichment=False,
        shodan_api_key=None,
        greynoise_api_key=None,
        pcap_enabled=False,
        so_ssh_host="",
        web_search_enabled=False,
        searxng_url="",
        crawl4ai_enabled=False,
        crawl4ai_url="",
        so_host="https://so.example",
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_catalog_covers_every_registered_tool() -> None:
    """No registered tool may be missing from the curated catalogue (drift guard)."""
    # Importing the agents force-registers every @tool (incl. chat-only ones).
    import soc_ai.agent.chat_agent
    import soc_ai.agent.orchestrator  # noqa: F401
    from soc_ai.tools._registry import list_tools

    registered = {s.name for s in list_tools()}
    assert registered <= catalog_tool_names(), registered - catalog_tool_names()


def test_online_tools_unavailable_by_default() -> None:
    tools = {t.name: t for t in collect_agent_tools(_settings())}
    assert tools["shodan_internetdb"].available is False
    assert "Online enrichment" in tools["shodan_internetdb"].missing
    assert tools["cve_lookup"].available is False
    assert tools["shodan_host"].available is False
    assert tools["greynoise"].available is False


def test_online_tools_available_when_enabled_and_keyed() -> None:
    s = _settings(
        allow_online_enrichment=True,
        shodan_api_key=SecretStr("k"),
        greynoise_api_key=SecretStr("k"),
    )
    tools = {t.name: t for t in collect_agent_tools(s)}
    assert tools["shodan_internetdb"].available is True  # no key required
    assert tools["cve_lookup"].available is True
    assert tools["shodan_host"].available is True
    assert tools["greynoise"].available is True


def test_online_master_on_but_no_key_flags_missing_key() -> None:
    s = _settings(allow_online_enrichment=True)  # keys unset
    tools = {t.name: t for t in collect_agent_tools(s)}
    assert tools["shodan_host"].available is False
    assert tools["shodan_host"].missing == ["Shodan API key"]
    assert tools["shodan_internetdb"].available is True  # keyless, master on


def test_es_tools_track_es_config() -> None:
    on = {t.name: t for t in collect_agent_tools(_settings(es_hosts=["x"]))}
    off = {t.name: t for t in collect_agent_tools(_settings(es_hosts=[]))}
    assert on["query_events_oql"].available is True
    assert off["query_events_oql"].available is False
    assert "Elasticsearch" in off["query_events_oql"].missing


def test_pcap_requires_flag_and_host() -> None:
    assert {t.name: t for t in collect_agent_tools(_settings())}["get_pcap"].available is False
    s = _settings(pcap_enabled=True, so_ssh_host="sensor.local")
    assert {t.name: t for t in collect_agent_tools(s)}["get_pcap"].available is True


def test_write_tools_flagged() -> None:
    tools = {t.name: t for t in collect_agent_tools(_settings())}
    assert tools["ack_alert"].read_only is False
    assert tools["query_events_oql"].read_only is True
