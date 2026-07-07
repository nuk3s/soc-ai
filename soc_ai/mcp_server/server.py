"""FastMCP server exposing soc-ai's read-only tool subset.

**Read tools only.** Write tools (``ack_alert``, ``escalate_to_case``,
``add_case_comment``) require the explicit analyst-executed actions flow that
lives in the FastAPI layer; that human-in-the-loop step can't be enforced
through MCP, where clients typically auto-approve. See ``docs/SAFETY_MODEL.md``.

Run as a stdio MCP server::

    uv run python -m soc_ai.mcp_server

Or programmatically::

    from soc_ai.mcp_server.server import build_mcp
    mcp = build_mcp(settings, elastic, misp=misp, enrichment=enrichment)
    await mcp.run_stdio_async()
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.enrichment import (
    EnrichmentContext,
    MispClient,
    enrich_domain,
    enrich_hash,
    enrich_ip,
)
from soc_ai.tools.get_alert_context import get_alert_context
from soc_ai.tools.get_playbooks import get_playbooks
from soc_ai.tools.lookup_runbook import lookup_runbook
from soc_ai.tools.query_cases import query_cases
from soc_ai.tools.query_detections import query_detections
from soc_ai.tools.query_events import query_events_oql
from soc_ai.tools.query_zeek import query_zeek_logs


def build_mcp(
    settings: Settings,
    elastic: ElasticClient,
    misp: MispClient | None = None,
    enrichment: EnrichmentContext | None = None,
    db_sessionmaker: Any = None,
) -> FastMCP:
    """Construct a :class:`FastMCP` server with the read-only tool surface.

    The returned server has every read tool registered as a closure over
    the runtime ``elastic`` / ``settings`` / ``misp`` clients. ``enrichment``
    carries the local blocklist / MaxMind / cloud-prefix sources; when it is
    ``None`` the enrich tools degrade to internal-CIDR + MISP only (the caller
    — see ``__main__`` — normally builds and passes it so MCP clients get the
    same enrichment depth as the FastAPI path).
    """
    mcp: FastMCP = FastMCP("soc-ai")
    _blocklist = enrichment.blocklist if enrichment else None
    _maxmind = enrichment.maxmind if enrichment else None
    _cloud = enrichment.cloud if enrichment else None

    @mcp.tool()
    async def query_events(
        query: str,
        time_range_minutes: int = 1440,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """Run a validated OQL query against the SO events index."""
        result = await query_events_oql(
            query,
            elastic=elastic,
            settings=settings,
            time_range_minutes=time_range_minutes,
            max_results=max_results,
        )
        return result.model_dump(mode="json")

    @mcp.tool()
    async def alert_context(
        alert_id: str,
        window_seconds: int = 300,
        max_per_pivot: int = 50,
    ) -> dict[str, Any]:
        """Fetch a SOC alert and fan out via 5 typed pivots."""
        result = await get_alert_context(
            alert_id,
            elastic=elastic,
            settings=settings,
            window_seconds=window_seconds,
            max_per_pivot=max_per_pivot,
        )
        return result.model_dump(mode="json")

    @mcp.tool()
    async def cases(
        query: str,
        status: str | None = None,
        max_results: int = 25,
    ) -> list[dict[str, Any]]:
        """Search SOC cases by free-text + optional status filter."""
        out = await query_cases(
            query,
            elastic=elastic,
            settings=settings,
            status=status,
            max_results=max_results,
        )
        return [c.model_dump(mode="json") for c in out]

    @mcp.tool()
    async def detections(query: str, max_results: int = 25) -> list[dict[str, Any]]:
        """Search SOC detection rules by free-text."""
        out = await query_detections(
            query,
            elastic=elastic,
            settings=settings,
            max_results=max_results,
        )
        return [d.model_dump(mode="json") for d in out]

    @mcp.tool()
    async def zeek_logs(
        community_id: str,
        log_types: list[str] | None = None,
        time_range_minutes: int = 60,
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """Pivot into Zeek logs by network.community_id."""
        return await query_zeek_logs(
            community_id,
            elastic=elastic,
            settings=settings,
            log_types=log_types,
            time_range_minutes=time_range_minutes,
            max_results=max_results,
        )

    @mcp.tool()
    async def playbooks(alert_id: str | None = None, max_results: int = 25) -> list[dict[str, Any]]:
        """Pull playbooks; optionally scoped to a given alert's linked rule."""
        out = await get_playbooks(
            elastic=elastic,
            settings=settings,
            alert_id=alert_id,
            max_results=max_results,
        )
        return [p.model_dump(mode="json") for p in out]

    @mcp.tool()
    async def enrich_indicator_ip(ip: str) -> dict[str, Any]:
        """Enrich an IP via internal-CIDR + local blocklists/GeoIP/cloud + optional MISP."""
        return (
            await enrich_ip(
                ip,
                settings=settings,
                misp=misp,
                blocklist=_blocklist,
                maxmind=_maxmind,
                cloud=_cloud,
            )
        ).model_dump(mode="json")

    @mcp.tool()
    async def enrich_indicator_domain(domain: str) -> dict[str, Any]:
        """Enrich a domain via local blocklists + optional MISP lookup."""
        return (
            await enrich_domain(domain, settings=settings, misp=misp, blocklist=_blocklist)
        ).model_dump(mode="json")

    @mcp.tool()
    async def enrich_indicator_hash(hash_value: str, algo: str) -> dict[str, Any]:
        """Enrich a file hash via local blocklists + optional MISP lookup."""
        return (
            await enrich_hash(hash_value, algo, settings=settings, misp=misp, blocklist=_blocklist)
        ).model_dump(mode="json")

    @mcp.tool()
    async def runbook(query: str, k: int = 5) -> list[dict[str, Any]]:
        """Search the operator's runbooks (keyword/tag/rule-linked).

        Served from the local store when the caller passed a ``db_sessionmaker``
        (``__main__`` builds one over the app's SQLite DB). Without it — e.g. a
        bare embedding with no store — this degrades to ``[]`` exactly like the
        in-app tool does, rather than erroring.
        """
        return await lookup_runbook(query, k=k, db_sessionmaker=db_sessionmaker)

    return mcp
