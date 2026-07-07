"""Tests for :mod:`soc_ai.mcp_server`."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

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
