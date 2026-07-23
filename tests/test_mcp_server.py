"""Tests for :mod:`soc_ai.mcp_server`."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.mcp_server.server import build_mcp
from soc_ai.so_client.elastic import ElasticClient


def _make_elastic(settings: Settings) -> ElasticClient:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        return ElasticClient(settings)


@pytest.mark.asyncio
async def test_build_mcp_registers_read_tools(settings_kratos: Settings) -> None:
    elastic = _make_elastic(settings_kratos)
    mcp = build_mcp(settings_kratos, elastic)

    tools = await mcp.list_tools()
    names = {t.name for t in tools}

    # Every read tool should be registered.
    expected = {
        "query_events",
        "alert_context",
        "cases",
        "detections",
        "zeek_logs",
        "playbooks",
        "enrich_indicator_ip",
        "enrich_indicator_domain",
        "enrich_indicator_hash",
        "runbook",
    }
    assert expected.issubset(names)


@pytest.mark.asyncio
async def test_build_mcp_excludes_write_tools(settings_kratos: Settings) -> None:
    """The MCP server MUST NOT expose write tools - the analyst write path is FastAPI-only."""
    elastic = _make_elastic(settings_kratos)
    mcp = build_mcp(settings_kratos, elastic)

    tools = await mcp.list_tools()
    names = {t.name for t in tools}

    forbidden = {"ack_alert", "escalate_to_case", "add_case_comment"}
    assert names.isdisjoint(forbidden)


@pytest.mark.asyncio
async def test_enrich_tools_receive_local_sources(settings_kratos: Settings) -> None:
    """The MCP enrich tools must pass the local blocklist/GeoIP/cloud sources
    through, not silently degrade to internal-CIDR + MISP only."""
    from soc_ai.enrichment.blocklists import BlocklistDB
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools.enrichment import EnrichmentContext, IndicatorEnrichment

    elastic = _make_elastic(settings_kratos)
    bl, mm, cl = BlocklistDB(), MaxmindReader(), CloudPrefixDB()
    mcp = build_mcp(
        settings_kratos,
        elastic,
        enrichment=EnrichmentContext(blocklist=bl, maxmind=mm, cloud=cl),
    )

    fake = AsyncMock(return_value=IndicatorEnrichment(indicator="1.2.3.4", indicator_type="ip"))
    with patch("soc_ai.mcp_server.server.enrich_ip", fake):
        await mcp.call_tool("enrich_indicator_ip", {"ip": "1.2.3.4"})

    kwargs = fake.call_args.kwargs
    assert kwargs["blocklist"] is bl
    assert kwargs["maxmind"] is mm
    assert kwargs["cloud"] is cl


@pytest.mark.asyncio
async def test_enrich_tools_degrade_without_enrichment(settings_kratos: Settings) -> None:
    """With no EnrichmentContext the enrich tools still work (sources = None)."""
    from soc_ai.tools.enrichment import IndicatorEnrichment

    elastic = _make_elastic(settings_kratos)
    mcp = build_mcp(settings_kratos, elastic)  # no enrichment

    fake = AsyncMock(return_value=IndicatorEnrichment(indicator="1.2.3.4", indicator_type="ip"))
    with patch("soc_ai.mcp_server.server.enrich_ip", fake):
        await mcp.call_tool("enrich_indicator_ip", {"ip": "1.2.3.4"})

    kwargs = fake.call_args.kwargs
    assert kwargs["blocklist"] is None
    assert kwargs["maxmind"] is None
    assert kwargs["cloud"] is None


@pytest.mark.asyncio
async def test_mcp_server_name(settings_kratos: Settings) -> None:
    elastic = _make_elastic(settings_kratos)
    mcp = build_mcp(settings_kratos, elastic)
    assert mcp.name == "soc-ai"


def _model_dump_stub() -> MagicMock:
    obj = MagicMock()
    obj.model_dump.return_value = {}
    return obj


@pytest.mark.asyncio
async def test_mcp_tools_clamp_absurd_caller_limits(settings_kratos: Settings) -> None:
    """An MCP client is an untrusted caller: it must not be able to push
    max_results / window_seconds / max_per_pivot / k straight through to
    Elasticsearch unclamped (unlike the agent's own tool wrappers in
    toolset.py, which cap every one of these before dispatch)."""
    elastic = _make_elastic(settings_kratos)
    mcp = build_mcp(settings_kratos, elastic)

    with (
        patch(
            "soc_ai.mcp_server.server.query_events_oql",
            AsyncMock(return_value=_model_dump_stub()),
        ) as fake_query_events,
        patch(
            "soc_ai.mcp_server.server.get_alert_context",
            AsyncMock(return_value=_model_dump_stub()),
        ) as fake_alert_context,
        patch("soc_ai.mcp_server.server.query_cases", AsyncMock(return_value=[])) as fake_cases,
        patch(
            "soc_ai.mcp_server.server.query_detections", AsyncMock(return_value=[])
        ) as fake_detections,
        patch("soc_ai.mcp_server.server.query_zeek_logs", AsyncMock(return_value=[])) as fake_zeek,
        patch(
            "soc_ai.mcp_server.server.get_playbooks", AsyncMock(return_value=[])
        ) as fake_playbooks,
        patch(
            "soc_ai.mcp_server.server.lookup_runbook", AsyncMock(return_value=[])
        ) as fake_runbook,
    ):
        await mcp.call_tool(
            "query_events", {"query": "*", "max_results": 1_000_000, "time_range_minutes": 60}
        )
        await mcp.call_tool(
            "alert_context",
            {"alert_id": "x", "window_seconds": 100_000_000, "max_per_pivot": 1_000_000},
        )
        await mcp.call_tool("cases", {"query": "*", "max_results": 1_000_000})
        await mcp.call_tool("detections", {"query": "*", "max_results": 1_000_000})
        await mcp.call_tool("zeek_logs", {"community_id": "c1", "max_results": 1_000_000})
        await mcp.call_tool("playbooks", {"max_results": 1_000_000})
        await mcp.call_tool("runbook", {"query": "*", "k": 1_000_000})

    assert fake_query_events.call_args.kwargs["max_results"] <= 25
    assert fake_alert_context.call_args.kwargs["window_seconds"] <= 14_400
    assert fake_alert_context.call_args.kwargs["max_per_pivot"] <= 50
    assert fake_cases.call_args.kwargs["max_results"] <= 10
    assert fake_detections.call_args.kwargs["max_results"] <= 10
    assert fake_zeek.call_args.kwargs["max_results"] <= 25
    assert fake_playbooks.call_args.kwargs["max_results"] <= 10
    assert fake_runbook.call_args.kwargs["k"] <= 5
