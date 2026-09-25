"""FastMCP server exposing soc-ai's read-only tool subset.

**Read tools only.** Write tools (``ack_alert``, ``escalate_to_case``,
``add_case_comment``) require the explicit analyst-executed actions flow that
lives in the FastAPI layer; that human-in-the-loop step can't be enforced
through MCP, where clients typically auto-approve. See ``docs/SAFETY_MODEL.md``.

Run as a stdio MCP server::

    uv run python -m soc_ai.mcp_server

Or programmatically::

    from soc_ai.mcp_server.server import build_mcp
    mcp = build_mcp(settings, elastic, misp=misp, enrichment=enrichment, audit=audit)
    await mcp.run_stdio_async()

Pass an ``AuditLogger`` as ``audit`` (``__main__`` does) so each tool call an
MCP client makes lands in the tamper-evident audit index like every other
tool invocation; leaving it ``None`` runs the server unaudited.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from mcp.server.fastmcp import FastMCP

from soc_ai.audit.logger import AuditLogger
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

_LOGGER = logging.getLogger(__name__)

_T = TypeVar("_T")


def _result_summary(result: Any) -> dict[str, Any]:
    """A bounded description of a tool's return value for the audit record.

    The full body can be hundreds of events; the trail only needs to show
    that the call happened and roughly how much came back.
    """
    if isinstance(result, list):
        return {"count": len(result)}
    return {"type": type(result).__name__}


class _ToolAudit:
    """Writes a ``tool_call`` / ``tool_result`` pair around each MCP tool call.

    One instance per server process: stdio MCP has no per-client identity to
    attribute to, so the trail groups everything a given launch did under a
    single ``mcp-*`` session id and ``user="mcp"``. With ``audit=None`` every
    call is a no-op, so a bare embedding keeps working unaudited.
    """

    def __init__(self, audit: AuditLogger | None) -> None:
        self._audit = audit
        self._session_id = f"mcp-{uuid.uuid4().hex[:12]}"

    async def _record(self, kind: str, payload: dict[str, Any]) -> None:
        # Audit must never block a read tool: these are fail-open writes,
        # the same way the orchestrator's _audit swallows logger errors.
        if self._audit is None:
            return
        try:
            await self._audit.log_kind(self._session_id, kind, payload, user="mcp")
        except Exception as e:
            _LOGGER.warning("audit log_kind failed (kind=%s): %s", kind, e)

    async def __call__(
        self, name: str, args: dict[str, Any], call: Callable[[], Awaitable[_T]]
    ) -> _T:
        """Run ``call`` with a ``tool_call`` before and a ``tool_result`` after.

        ``args`` are the clamped values that actually reach the tool, not the
        raw caller input, so the record matches what hit Elasticsearch. A
        failing tool is still recorded (with the error) and then re-raised so
        the MCP client sees it.
        """
        await self._record("tool_call", {"tool": name, "args": args})
        try:
            result = await call()
        except Exception as e:
            await self._record(
                "tool_result",
                {"tool": name, "ok": False, "error": f"{type(e).__name__}: {e}"},
            )
            raise
        await self._record("tool_result", {"tool": name, "ok": True, **_result_summary(result)})
        return result


def build_mcp(
    settings: Settings,
    elastic: ElasticClient,
    misp: MispClient | None = None,
    enrichment: EnrichmentContext | None = None,
    db_sessionmaker: Any = None,
    audit: AuditLogger | None = None,
) -> FastMCP:
    """Construct a :class:`FastMCP` server with the read-only tool surface.

    The returned server has every read tool registered as a closure over
    the runtime ``elastic`` / ``settings`` / ``misp`` clients. ``enrichment``
    carries the local blocklist / MaxMind / cloud-prefix sources; when it is
    ``None`` the enrich tools degrade to internal-CIDR + MISP only (the caller
    — see ``__main__`` — normally builds and passes it so MCP clients get the
    same enrichment depth as the FastAPI path).

    ``audit`` is the tamper-evident ES audit logger. Every tool invocation an
    MCP client makes is written to it as a ``tool_call`` / ``tool_result``
    pair under a per-server ``mcp-*`` session id and ``user="mcp"``, so grid
    queries and IOC lookups made through this surface show up in
    ``soc-ai audit verify`` and the per-kind egress counters exactly like
    the agent's own tool calls do. ``__main__`` always passes one; a bare
    embedding may leave it ``None`` and runs unaudited.
    """
    mcp: FastMCP = FastMCP("soc-ai")
    _blocklist = enrichment.blocklist if enrichment else None
    _maxmind = enrichment.maxmind if enrichment else None
    _cloud = enrichment.cloud if enrichment else None
    _audited = _ToolAudit(audit)

    @mcp.tool()
    async def query_events(
        query: str,
        time_range_minutes: int = 1440,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """Run a validated OQL query against the SO events index."""
        # An MCP client is an untrusted caller (no prompt-mediated guidance the
        # way an agent's system prompt gives it), so clamp the same way the
        # agent's own t_query_events_oql wrapper does (toolset.py) -- without
        # this, a `head`-less query's max_results goes straight into the ES
        # request body with no ceiling (oql.py's _HARD_MAX_RESULTS only guards
        # an explicit `head` stage).
        max_results = min(max_results, 25)
        result = await _audited(
            "query_events",
            {"query": query, "time_range_minutes": time_range_minutes, "max_results": max_results},
            lambda: query_events_oql(
                query,
                elastic=elastic,
                settings=settings,
                time_range_minutes=time_range_minutes,
                max_results=max_results,
            ),
        )
        return result.model_dump(mode="json")

    @mcp.tool()
    async def alert_context(
        alert_id: str,
        window_seconds: int = 300,
        max_per_pivot: int = 50,
    ) -> dict[str, Any]:
        """Fetch a SOC alert and fan out via 5 typed pivots."""
        # Clamp: get_alert_context only rejects non-positive values, not
        # unbounded ones. 14_400s (4h) covers the widest legitimate pivot
        # window in the synth scenario catalogue; 50 matches this tool's
        # existing default.
        window_seconds = min(window_seconds, 14_400)
        max_per_pivot = min(max_per_pivot, 50)
        result = await _audited(
            "alert_context",
            {
                "alert_id": alert_id,
                "window_seconds": window_seconds,
                "max_per_pivot": max_per_pivot,
            },
            lambda: get_alert_context(
                alert_id,
                elastic=elastic,
                settings=settings,
                window_seconds=window_seconds,
                max_per_pivot=max_per_pivot,
            ),
        )
        return result.model_dump(mode="json")

    @mcp.tool()
    async def cases(
        query: str,
        status: str | None = None,
        max_results: int = 25,
    ) -> list[dict[str, Any]]:
        """Search SOC cases by free-text + optional status filter."""
        # Same clamp as the agent's t_query_cases wrapper (toolset.py):
        # query_cases only rejects non-positive max_results, not unbounded ones.
        max_results = min(max_results, 10)
        out = await _audited(
            "cases",
            {"query": query, "status": status, "max_results": max_results},
            lambda: query_cases(
                query,
                elastic=elastic,
                settings=settings,
                status=status,
                max_results=max_results,
            ),
        )
        return [c.model_dump(mode="json") for c in out]

    @mcp.tool()
    async def detections(query: str, max_results: int = 25) -> list[dict[str, Any]]:
        """Search SOC detection rules by free-text."""
        # Same clamp as the agent's t_query_detections wrapper (toolset.py).
        max_results = min(max_results, 10)
        out = await _audited(
            "detections",
            {"query": query, "max_results": max_results},
            lambda: query_detections(
                query,
                elastic=elastic,
                settings=settings,
                max_results=max_results,
            ),
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
        # Same clamp as the agent's t_query_zeek_logs wrapper (toolset.py).
        max_results = min(max_results, 25)
        return await _audited(
            "zeek_logs",
            {
                "community_id": community_id,
                "log_types": log_types,
                "time_range_minutes": time_range_minutes,
                "max_results": max_results,
            },
            lambda: query_zeek_logs(
                community_id,
                elastic=elastic,
                settings=settings,
                log_types=log_types,
                time_range_minutes=time_range_minutes,
                max_results=max_results,
            ),
        )

    @mcp.tool()
    async def playbooks(alert_id: str | None = None, max_results: int = 25) -> list[dict[str, Any]]:
        """Pull playbooks; optionally scoped to a given alert's linked rule."""
        # Same clamp as the agent's t_get_playbooks wrapper (toolset.py).
        max_results = min(max_results, 10)
        out = await _audited(
            "playbooks",
            {"alert_id": alert_id, "max_results": max_results},
            lambda: get_playbooks(
                elastic=elastic,
                settings=settings,
                alert_id=alert_id,
                max_results=max_results,
            ),
        )
        return [p.model_dump(mode="json") for p in out]

    @mcp.tool()
    async def enrich_indicator_ip(ip: str) -> dict[str, Any]:
        """Enrich an IP via internal-CIDR + local blocklists/GeoIP/cloud + optional MISP."""
        return (
            await _audited(
                "enrich_indicator_ip",
                {"ip": ip},
                lambda: enrich_ip(
                    ip,
                    settings=settings,
                    misp=misp,
                    blocklist=_blocklist,
                    maxmind=_maxmind,
                    cloud=_cloud,
                ),
            )
        ).model_dump(mode="json")

    @mcp.tool()
    async def enrich_indicator_domain(domain: str) -> dict[str, Any]:
        """Enrich a domain via local blocklists + optional MISP lookup."""
        return (
            await _audited(
                "enrich_indicator_domain",
                {"domain": domain},
                lambda: enrich_domain(domain, settings=settings, misp=misp, blocklist=_blocklist),
            )
        ).model_dump(mode="json")

    @mcp.tool()
    async def enrich_indicator_hash(hash_value: str, algo: str) -> dict[str, Any]:
        """Enrich a file hash via local blocklists + optional MISP lookup."""
        return (
            await _audited(
                "enrich_indicator_hash",
                {"hash_value": hash_value, "algo": algo},
                lambda: enrich_hash(
                    hash_value, algo, settings=settings, misp=misp, blocklist=_blocklist
                ),
            )
        ).model_dump(mode="json")

    @mcp.tool()
    async def runbook(query: str, k: int = 5) -> list[dict[str, Any]]:
        """Search the operator's runbooks (keyword/tag/rule-linked).

        Served from the local store when the caller passed a ``db_sessionmaker``
        (``__main__`` builds one over the app's SQLite DB). Without it — e.g. a
        bare embedding with no store — this degrades to ``[]`` exactly like the
        in-app tool does, rather than erroring.
        """
        # Same clamp as the agent's t_lookup_runbook wrapper (toolset.py).
        k = min(k, 5)
        return await _audited(
            "runbook",
            {"query": query, "k": k},
            lambda: lookup_runbook(query, k=k, db_sessionmaker=db_sessionmaker),
        )

    return mcp
