"""Tests for the agent-tools capability introspection (config console)."""

from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import SecretStr
from soc_ai.api.agent_tools import catalog_tool_names, collect_agent_tools

# A directory that holds no feed file. The enrichment tests below point the
# feed directories at their own tmp_path.
_NO_FEEDS = Path("/nonexistent/soc-ai-test-feeds")


def _settings(**over: Any) -> Any:
    base: dict[str, Any] = dict(
        blocklist_data_dir=_NO_FEEDS,
        maxmind_data_dir=_NO_FEEDS,
        cloud_prefix_data_dir=_NO_FEEDS,
        blocklist_sources=["urlhaus", "threatfox", "feodo", "tor", "internal_seed"],
        blocklist_stale_threshold_days=7,
        cloud_prefix_stale_threshold_days=45,
        misp_url=None,
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


# ---------------------------------------------------------------------------
# R5-D9: an enrichment tool with no local feed is not "Available" (2026-10-19)
# ---------------------------------------------------------------------------

_ENRICH = ("enrich_ip", "enrich_domain", "enrich_hash")


def _touch(path: Path, *, days_old: float = 0.0) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x\n")
    stamp = time.time() - days_old * 86400
    os.utime(path, (stamp, stamp))


def _feeds(tmp_path: Path, *, blocklist_days: float | None, maxmind: bool, cloud: bool) -> Any:
    bl, mm, cp = tmp_path / "bl", tmp_path / "mm", tmp_path / "cp"
    for d in (bl, mm, cp):
        d.mkdir(parents=True, exist_ok=True)
    if blocklist_days is not None:
        for name in ("urlhaus.csv", "threatfox.json", "feodo.csv", "tor_exits.txt"):
            _touch(bl / name, days_old=blocklist_days)
    if maxmind:
        _touch(mm / "GeoLite2-City.mmdb")
        _touch(mm / "GeoLite2-ASN.mmdb")
    if cloud:
        _touch(cp / "aws.json")
    return _settings(blocklist_data_dir=bl, maxmind_data_dir=mm, cloud_prefix_data_dir=cp)


@pytest.mark.parametrize("name", _ENRICH)
def test_an_enrich_tool_with_no_local_feed_is_unavailable(tmp_path: Path, name: str) -> None:
    """The dogfood saw "Available" with every feed missing. An empty answer then
    read as "no hit", where the tool had nothing to look in."""
    tool = {
        t.name: t
        for t in collect_agent_tools(
            _feeds(tmp_path, blocklist_days=None, maxmind=False, cloud=False)
        )
    }[name]
    assert tool.available is False
    assert "Local blocklists" in tool.missing
    assert tool.state_reason and "soc-ai finds no file for" in tool.state_reason


@pytest.mark.parametrize("name", _ENRICH)
def test_an_enrich_tool_with_fresh_feeds_is_available(tmp_path: Path, name: str) -> None:
    tool = {
        t.name: t
        for t in collect_agent_tools(_feeds(tmp_path, blocklist_days=1, maxmind=True, cloud=True))
    }[name]
    assert tool.available is True
    assert tool.missing == []
    assert tool.degraded == []
    assert tool.state_reason is None


def test_a_stale_blocklist_degrades_the_enrich_tools(tmp_path: Path) -> None:
    tools = {
        t.name: t
        for t in collect_agent_tools(_feeds(tmp_path, blocklist_days=88, maxmind=True, cloud=True))
    }
    for name in _ENRICH:
        assert tools[name].available is True, name
        assert tools[name].degraded == ["Local blocklists"], name
        assert "88 days old" in (tools[name].state_reason or ""), name


def test_enrich_ip_with_only_geoip_is_degraded_not_unavailable(tmp_path: Path) -> None:
    """enrich_ip reads three feeds. One present feed keeps it available."""
    tools = {
        t.name: t
        for t in collect_agent_tools(
            _feeds(tmp_path, blocklist_days=None, maxmind=True, cloud=False)
        )
    }
    ip = tools["enrich_ip"]
    assert ip.available is True
    assert ip.degraded == ["Local blocklists", "Cloud prefixes"]
    # enrich_hash reads the blocklists only, so it has nothing to look in.
    assert tools["enrich_hash"].available is False


def test_misp_keeps_an_enrich_tool_available_with_no_local_feed(tmp_path: Path) -> None:
    s = _feeds(tmp_path, blocklist_days=None, maxmind=False, cloud=False)
    s.misp_url = "https://misp.example.com"
    tool = {t.name: t for t in collect_agent_tools(s)}["enrich_hash"]
    assert tool.available is True
    assert tool.degraded == ["Local blocklists"]


def test_a_tool_with_no_feed_carries_no_degraded_state() -> None:
    """Negative control: the feed rule touches only the tools that read a feed."""
    tool = {t.name: t for t in collect_agent_tools(_settings())}["query_events_oql"]
    assert tool.degraded == []
    assert tool.state_reason is None
