"""Tests for the SearXNG web_search tool + its investigator wiring."""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from soc_ai.tools.web_search import web_search

_REAL = httpx.AsyncClient


def _settings(**over: Any) -> Any:
    base: dict[str, Any] = dict(
        web_search_enabled=True,
        searxng_url="https://search.lan",
        searxng_verify_ssl=False,
        searxng_timeout_s=5,
        web_search_max_results=5,
        internal_cidrs=[ipaddress.ip_network("10.0.0.0/8")],
        oracle_internal_suffixes=(".lan", ".local", ".internal", ".corp"),
        oracle_extra_hosts=["finance-pc"],
    )
    base.update(over)
    return SimpleNamespace(**base)


def _patch_httpx(handler: Any) -> Any:
    transport = httpx.MockTransport(handler)

    def _factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k["transport"] = transport
        return _REAL(*a, **k)

    return patch("soc_ai.tools.web_search.httpx.AsyncClient", _factory)


@pytest.mark.asyncio
async def test_disabled_returns_error_no_io() -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        r = await web_search("anything", settings=_settings(web_search_enabled=False))
    assert r["ok"] is False
    assert "disabled" in r["error"]
    assert calls["n"] == 0


@pytest.mark.asyncio
async def test_no_url_errors() -> None:
    r = await web_search("x", settings=_settings(searxng_url=""))
    assert r["ok"] is False
    assert "searxng_url" in r["error"]


@pytest.mark.asyncio
async def test_empty_query_errors() -> None:
    r = await web_search("   ", settings=_settings())
    assert r["ok"] is False


@pytest.mark.asyncio
async def test_privacy_guard_refuses_internal_ip() -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        r = await web_search("what is 10.4.4.4 doing", settings=_settings())
    assert r["ok"] is False
    assert "internal" in r["error"].lower()
    assert "10.4.4.4" in r["error"]
    assert calls["n"] == 0  # never reached the network


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query",
    [
        "research dc01.corp.local",  # internal FQDN on a configured suffix
        "look up FINANCE-PC in AD",  # known internal host (oracle_extra_hosts)
        "scanner behind 100.64.0.1",  # CGNAT — not is_global, not in internal_cidrs
        "traffic to 127.0.0.1 loopback",  # loopback
        "link-local 169.254.1.1",  # link-local
        "benchmark 198.18.0.1 route",  # benchmarking range
        "internal v6 fd00::1 host",  # IPv6 ULA
        "who is ::1",  # IPv6 loopback
    ],
)
async def test_privacy_guard_refuses_internal_identifiers(query: str) -> None:
    """The name/IP egress guard blocks internal FQDNs, known internal hosts, and
    every non-globally-routable IP class (incl. IPv6) — not just RFC1918 v4."""
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        r = await web_search(query, settings=_settings())
    assert r["ok"] is False
    assert "internal" in r["error"].lower()
    assert calls["n"] == 0  # never reached the network


@pytest.mark.asyncio
async def test_privacy_guard_allows_external_domain_query() -> None:
    """A normal external-indicator query (public domain, no internal tokens) is
    NOT over-refused and reaches the search backend."""
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"results": [], "answers": []})

    with _patch_httpx(h):
        r = await web_search("emotet c2 domains 2024 8.8.8.8 reputation", settings=_settings())
    assert r["ok"] is True
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_external_ip_allowed_and_results_parsed() -> None:
    payload = {
        "results": [
            {
                "title": "PushPlanet abuse report",
                "url": "https://x/y",
                "content": "flagged",
                "engine": "ddg",
            },
            {"title": "two", "url": "https://a/b", "content": "c", "engine": "bing"},
        ],
        "answers": ["parked domain"],
    }

    def h(req: httpx.Request) -> httpx.Response:
        assert req.url.path.endswith("/search")
        assert req.url.params.get("format") == "json"
        return httpx.Response(200, json=payload)

    with _patch_httpx(h):
        r = await web_search("pushplanet.azurewebsites.net", settings=_settings())
    assert r["ok"] is True
    assert r["result_count"] == 2
    assert r["results"][0]["title"].startswith("PushPlanet")
    assert r["answers"] == ["parked domain"]


@pytest.mark.asyncio
async def test_non_200_graceful() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="json format disabled")

    with _patch_httpx(h):
        r = await web_search("example.com", settings=_settings())
    assert r["ok"] is False
    assert "403" in r["error"]


@pytest.mark.asyncio
async def test_connect_error_graceful() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    with _patch_httpx(h):
        r = await web_search("example.com", settings=_settings())
    assert r["ok"] is False


def test_wiring_dispatch_and_literal() -> None:
    # dispatch table includes t_web_search → web_search
    from soc_ai.agent import targeted_investigator as ti

    assert ti._dispatch_table()["t_web_search"] is web_search
    # TargetedGap.tool_name Literal includes it
    from soc_ai.agent.triage import TargetedGap

    schema = TargetedGap.model_json_schema()
    # the Literal surfaces as an enum on tool_name
    tool_field = schema["properties"]["tool_name"]
    enum_vals = tool_field.get("enum") or []
    assert "t_web_search" in enum_vals
