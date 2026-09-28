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


def _audit_kinds(audit: AsyncMock) -> list[str]:
    return [c.args[1] for c in audit.log_kind.await_args_list]


@pytest.mark.asyncio
async def test_mcp_tool_calls_are_audited(settings_kratos: Settings) -> None:
    """Every MCP tool invocation lands in the audit trail as a tool_call /
    tool_result pair, attributed to the MCP surface rather than an analyst,
    and never as a mutating (fail-closed) write."""
    elastic = _make_elastic(settings_kratos)
    audit = AsyncMock()
    mcp = build_mcp(settings_kratos, elastic, audit=audit)

    with patch(
        "soc_ai.mcp_server.server.query_events_oql",
        AsyncMock(return_value=_model_dump_stub()),
    ):
        await mcp.call_tool("query_events", {"query": "*", "max_results": 5})

    assert _audit_kinds(audit) == ["tool_call", "tool_result"]
    call, result = audit.log_kind.await_args_list
    session_id = call.args[0]
    assert session_id.startswith("mcp-")
    assert result.args[0] == session_id
    assert call.args[2]["tool"] == "query_events"
    assert call.args[2]["args"]["query"] == "*"
    assert call.args[2]["args"]["max_results"] == 5
    assert result.args[2]["tool"] == "query_events"
    assert result.args[2]["ok"] is True
    for c in (call, result):
        assert c.kwargs["user"] == "mcp"
        assert c.kwargs.get("mutating", False) is False


@pytest.mark.asyncio
async def test_mcp_audit_covers_every_registered_tool(settings_kratos: Settings) -> None:
    from soc_ai.tools.enrichment import IndicatorEnrichment

    elastic = _make_elastic(settings_kratos)
    audit = AsyncMock()
    mcp = build_mcp(settings_kratos, elastic, audit=audit)

    enriched = AsyncMock(return_value=IndicatorEnrichment(indicator="1.2.3.4", indicator_type="ip"))
    with (
        patch(
            "soc_ai.mcp_server.server.query_events_oql",
            AsyncMock(return_value=_model_dump_stub()),
        ),
        patch(
            "soc_ai.mcp_server.server.get_alert_context",
            AsyncMock(return_value=_model_dump_stub()),
        ),
        patch("soc_ai.mcp_server.server.query_cases", AsyncMock(return_value=[])),
        patch("soc_ai.mcp_server.server.query_detections", AsyncMock(return_value=[])),
        patch("soc_ai.mcp_server.server.query_zeek_logs", AsyncMock(return_value=[])),
        patch("soc_ai.mcp_server.server.get_playbooks", AsyncMock(return_value=[])),
        patch("soc_ai.mcp_server.server.lookup_runbook", AsyncMock(return_value=[])),
        patch("soc_ai.mcp_server.server.enrich_ip", enriched),
        patch("soc_ai.mcp_server.server.enrich_domain", enriched),
        patch("soc_ai.mcp_server.server.enrich_hash", enriched),
    ):
        calls = [
            ("query_events", {"query": "*"}),
            ("alert_context", {"alert_id": "x"}),
            ("cases", {"query": "*"}),
            ("detections", {"query": "*"}),
            ("zeek_logs", {"community_id": "c1"}),
            ("playbooks", {}),
            ("runbook", {"query": "*"}),
            ("enrich_indicator_ip", {"ip": "1.2.3.4"}),
            ("enrich_indicator_domain", {"domain": "example.com"}),
            ("enrich_indicator_hash", {"hash_value": "a" * 32, "algo": "md5"}),
        ]
        for name, args in calls:
            await mcp.call_tool(name, args)

    logged = [c.args[2]["tool"] for c in audit.log_kind.await_args_list if c.args[1] == "tool_call"]
    assert logged == [name for name, _ in calls]
    assert _audit_kinds(audit).count("tool_result") == len(calls)


@pytest.mark.asyncio
async def test_mcp_audit_failure_is_fail_open(settings_kratos: Settings) -> None:
    """An audit write that fails must never block a read tool (the audit
    writes for a read stay fail-open, as SAFETY_MODEL.md promises)."""
    elastic = _make_elastic(settings_kratos)
    audit = AsyncMock()
    audit.log_kind.side_effect = RuntimeError("es down")
    mcp = build_mcp(settings_kratos, elastic, audit=audit)

    with patch("soc_ai.mcp_server.server.query_cases", AsyncMock(return_value=[])) as fake:
        await mcp.call_tool("cases", {"query": "*"})

    assert fake.await_count == 1
    assert audit.log_kind.await_count == 2


@pytest.mark.asyncio
async def test_mcp_audit_records_tool_error(settings_kratos: Settings) -> None:
    """A tool that raises still leaves a tool_result carrying the error, and
    the error itself still reaches the MCP client."""
    elastic = _make_elastic(settings_kratos)
    audit = AsyncMock()
    mcp = build_mcp(settings_kratos, elastic, audit=audit)

    with (
        patch(
            "soc_ai.mcp_server.server.query_cases",
            AsyncMock(side_effect=ValueError("bad query")),
        ),
        pytest.raises(Exception, match="bad query"),
    ):
        await mcp.call_tool("cases", {"query": "*"})

    assert _audit_kinds(audit) == ["tool_call", "tool_result"]
    result_payload = audit.log_kind.await_args_list[1].args[2]
    assert result_payload["ok"] is False
    assert "bad query" in result_payload["error"]


@pytest.mark.asyncio
async def test_mcp_without_audit_logger_still_serves(settings_kratos: Settings) -> None:
    """``audit`` is optional so a bare embedding (and the module docstring's
    example) keeps working; nothing is logged and nothing errors."""
    elastic = _make_elastic(settings_kratos)
    mcp = build_mcp(settings_kratos, elastic)

    with patch("soc_ai.mcp_server.server.query_cases", AsyncMock(return_value=[])) as fake:
        out = await mcp.call_tool("cases", {"query": "*"})

    assert fake.await_count == 1
    assert out is not None


def test_mcp_main_wires_audit_logger(settings_kratos: Settings) -> None:
    """``python -m soc_ai.mcp_server`` must hand build_mcp an AuditLogger so
    the stdio surface is not an unaudited path into the grid."""
    import asyncio

    from soc_ai.audit.logger import AuditLogger
    from soc_ai.mcp_server import __main__ as mcp_main

    fake_mcp = MagicMock()
    fake_mcp.run_stdio_async = AsyncMock()
    fake_engine = MagicMock()
    fake_engine.dispose = AsyncMock()
    with (
        patch.object(mcp_main, "get_settings", return_value=settings_kratos),
        patch.object(mcp_main, "ElasticClient") as fake_elastic_cls,
        patch.object(mcp_main, "build_local_enrichment_context", return_value=None),
        patch.object(mcp_main, "make_engine", return_value=fake_engine),
        patch.object(mcp_main, "make_sessionmaker", return_value=MagicMock()),
        patch.object(mcp_main, "build_mcp", return_value=fake_mcp) as fake_build,
    ):
        fake_elastic_cls.return_value.aclose = AsyncMock()
        asyncio.run(mcp_main._run())

    audit = fake_build.call_args.kwargs.get("audit")
    assert isinstance(audit, AuditLogger)
