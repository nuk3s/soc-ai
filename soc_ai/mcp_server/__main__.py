"""``uv run python -m soc_ai.mcp_server`` - boot the FastMCP server over stdio.

Reuses the same Settings/auth/Elastic/MISP wiring as the FastAPI app, but
serves the read-only tool surface to MCP clients (e.g. Continue,
etc.) over stdio.
"""

from __future__ import annotations

import asyncio
import logging

from soc_ai.config import get_settings
from soc_ai.mcp_server.server import build_mcp
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store.db import make_engine, make_sessionmaker
from soc_ai.tools.enrichment import MispClient, build_local_enrichment_context


async def _run() -> None:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    elastic = ElasticClient(settings)
    misp = MispClient(settings) if settings.misp_url is not None else None
    # Load the same local blocklist / GeoIP / cloud-prefix sources the FastAPI
    # path uses, so MCP enrichment isn't silently degraded to CIDR + MISP only.
    enrichment = build_local_enrichment_context(settings)
    # Open the app's SQLite store read-only so the `runbook` tool actually
    # searches operator runbooks instead of always returning []. No migrations
    # here — the FastAPI app owns the schema; if the DB doesn't exist yet,
    # lookup_runbook degrades to [] on the first query.
    db_engine = make_engine(settings)
    db_sessionmaker = make_sessionmaker(db_engine)
    mcp = build_mcp(
        settings, elastic, misp=misp, enrichment=enrichment, db_sessionmaker=db_sessionmaker
    )
    try:
        await mcp.run_stdio_async()
    finally:
        await elastic.aclose()
        if misp is not None:
            await misp.aclose()
        await db_engine.dispose()


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
