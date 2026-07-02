"""SearXNG web-search tool — research EXTERNAL indicators (domains, IPs, hashes).

Read-only outbound HTTP to a self-hosted SearXNG instance so the agent can
research an external indicator: domain reputation, what a host/service is, known
abuse. Bounded by a timeout; never raises (returns a graceful ``{"ok": False,
"error": ...}`` dict).

PRIVACY: SearXNG fans the query out to public search engines, so a query MUST
contain only EXTERNAL indicators. A query referencing an INTERNAL identifier —
an internal IP (anything not globally routable, incl. RFC1918/CGNAT/benchmark/
loopback/link-local and IPv6), an internal FQDN on a configured suffix, or a
known internal hostname — is refused, so internal IPs/hostnames never leak to
public search engines.

Note: requires the SearXNG instance to expose the JSON API
(``search.formats: [json]`` in its settings.yml). If it doesn't, the probe
returns a graceful ``HTTP 403`` error.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from soc_ai.tools.online import first_internal_identifier

_LOGGER = logging.getLogger(__name__)


async def web_search(query: str, *, settings: Any) -> dict[str, Any]:
    """Search the configured SearXNG instance for *query*. Never raises.

    Returns ``{"ok": True, "query", "result_count", "results": [{title, url,
    content, engine}], "answers": [...]}`` on success, else
    ``{"ok": False, "error": ...}``.
    """
    query = (query or "").strip()
    if not query:
        return {"ok": False, "error": "empty query"}
    if not getattr(settings, "web_search_enabled", False):
        return {"ok": False, "error": "web search disabled (set WEB_SEARCH_ENABLED=true)"}
    base = str(getattr(settings, "searxng_url", "") or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "searxng_url not configured"}
    # PRIVACY GUARD: never leak an internal identifier to public search engines.
    # Covers internal IPs (RFC1918/CGNAT/benchmark/loopback/link-local + IPv6),
    # internal FQDNs on a configured suffix, and known internal hostnames — the
    # same predicate the crawl_page + online-enrichment egress paths use, so the
    # three can't drift.
    leaked = first_internal_identifier(query, settings)
    if leaked is not None:
        return {
            "ok": False,
            "error": (
                f"refused: query contains internal identifier {leaked!r}; "
                "web_search is for EXTERNAL indicators only"
            ),
        }
    timeout = float(getattr(settings, "searxng_timeout_s", 10))
    max_results = int(getattr(settings, "web_search_max_results", 5))
    verify = bool(getattr(settings, "searxng_verify_ssl", True))
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=verify) as client:
            resp = await client.get(
                f"{base}/search",
                params={"q": query, "format": "json"},
                headers={"Accept": "application/json"},
            )
        if resp.status_code != 200:
            return {"ok": False, "error": f"searxng HTTP {resp.status_code}"}
        data = resp.json()
    except Exception as e:  # graceful — a probe failure is a normal error result
        _LOGGER.warning("web_search failed: %s", type(e).__name__)
        return {"ok": False, "error": type(e).__name__}

    results = [
        {
            "title": str(r.get("title", ""))[:200],
            "url": str(r.get("url", ""))[:300],
            "content": str(r.get("content", ""))[:400],
            "engine": str(r.get("engine", ""))[:40],
        }
        for r in (data.get("results") or [])[:max_results]
    ]
    answers = [str(a)[:300] for a in (data.get("answers") or [])][:3]
    return {
        "ok": True,
        "query": query,
        "result_count": len(results),
        "results": results,
        "answers": answers,
    }
