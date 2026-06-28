"""Tests for the full Shodan host tool (online, API-key, egress-gated).

Every path is exercised with the network mocked out:

- gate OFF / missing key → clean disabled/not_configured dict, no I/O
- private / internal_cidrs IP (gate ON, key set) → ``private_ip`` skip, no I/O
- gate ON + 200 → compact projection (owner/geo/os/ports/vulns/services)
- the per-service projection is capped and never leaks raw banner text
- 404 → ``observed: False``; 401/other → clean error dict; network err → error
"""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from pydantic import SecretStr
from soc_ai.tools.shodan_host import _MAX_SERVICES, shodan_host

_REAL = httpx.AsyncClient


def _settings(**over: Any) -> Any:
    base: dict[str, Any] = dict(
        allow_online_enrichment=True,
        online_enrichment_timeout_s=8,
        online_enrichment_verify_ssl=True,
        shodan_api_key=SecretStr("test-key"),
        internal_cidrs=[],
    )
    base.update(over)
    return SimpleNamespace(**base)


def _patch_httpx(handler: Any) -> Any:
    transport = httpx.MockTransport(handler)

    def _factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k["transport"] = transport
        return _REAL(*a, **k)

    return patch("soc_ai.tools.online.httpx.AsyncClient", _factory)


@pytest.mark.asyncio
async def test_gate_off_returns_disabled_no_io() -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        out = await shodan_host("8.8.8.8", settings=_settings(allow_online_enrichment=False))

    assert out["available"] is False
    assert out["reason"] == "online_enrichment_disabled"
    assert calls["n"] == 0


@pytest.mark.asyncio
async def test_missing_key_returns_not_configured_no_io() -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        out = await shodan_host("8.8.8.8", settings=_settings(shodan_api_key=None))

    assert out["available"] is False
    assert out["reason"] == "not_configured"
    assert calls["n"] == 0


@pytest.mark.asyncio
async def test_private_ip_skipped_no_io() -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        out = await shodan_host("192.168.1.10", settings=_settings())

    assert out["available"] is False
    assert out["reason"] == "private_ip"
    assert calls["n"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["100.64.1.1", "100.127.255.254", "198.18.0.5", "169.254.1.1"])
async def test_non_global_ranges_skipped_no_io(ip: str) -> None:
    """CGNAT (100.64/10) and benchmarking (198.18/15) are NOT is_private but must
    still never leave the box — the is_global gate catches them."""

    def h(req: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError(f"network hit for non-routable IP {ip}")

    with _patch_httpx(h):
        out = await shodan_host(ip, settings=_settings())

    assert out["reason"] == "private_ip"


@pytest.mark.asyncio
async def test_internal_cidr_ip_skipped_no_io() -> None:
    """An internal-but-globally-routable host (operator internal_cidrs) is skipped.

    Uses a genuinely global block (8.8.8.0/24) so this exercises the
    internal_cidrs branch, not the is_global gate."""

    def h(req: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError("network hit for internal_cidrs IP")

    s = _settings(internal_cidrs=[ipaddress.ip_network("8.8.8.0/24")])
    with _patch_httpx(h):
        out = await shodan_host("8.8.8.8", settings=s)

    assert out["reason"] == "private_ip"


@pytest.mark.asyncio
async def test_success_200_projects_compact_fields() -> None:
    captured: dict[str, Any] = {}
    payload = {
        "ip_str": "1.1.1.1",
        "org": "Cloudflare",
        "isp": "Cloudflare",
        "asn": "AS13335",
        "country_name": "United States",
        "city": "San Francisco",
        "os": None,
        "last_update": "2026-06-01T00:00:00",
        "ports": [443, 80],
        "hostnames": ["one.one.one.one"],
        "domains": ["one.one"],
        "tags": ["cdn"],
        "vulns": {"CVE-2021-0001": {}},
        "data": [
            {
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.25",
                "_shodan": {"module": "https"},
                "vulns": {"CVE-2022-2222": {}},
                "banner": "RAW BANNER TEXT THAT MUST NOT LEAK",
            }
        ],
    }

    def h(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        return httpx.Response(200, json=payload)

    with _patch_httpx(h):
        out = await shodan_host("1.1.1.1", settings=_settings())

    assert "api.shodan.io/shodan/host/1.1.1.1" in captured["url"]
    assert "key=test-key" in captured["url"]
    assert out["observed"] is True
    assert out["org"] == "Cloudflare"
    assert out["asn"] == "AS13335"
    assert out["ports"] == [80, 443]  # sorted, ints only
    assert out["vulns"] == ["CVE-2021-0001", "CVE-2022-2222"]  # union, sorted
    assert out["services"] == [
        {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.25", "module": "https"}
    ]
    # raw banner text must never appear in the projection
    assert "BANNER" not in repr(out)


@pytest.mark.asyncio
async def test_services_capped() -> None:
    payload = {
        "ip_str": "1.1.1.1",
        "data": [{"port": p, "_shodan": {"module": "x"}} for p in range(_MAX_SERVICES + 10)],
    }

    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _patch_httpx(h):
        out = await shodan_host("1.1.1.1", settings=_settings())

    assert len(out["services"]) == _MAX_SERVICES


@pytest.mark.asyncio
async def test_404_is_no_data_not_error() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "No information available for that IP."})

    with _patch_httpx(h):
        out = await shodan_host("9.9.9.9", settings=_settings())

    assert out["observed"] is False
    assert "error" not in out


@pytest.mark.asyncio
async def test_401_bad_key_returns_error() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "Invalid API key"})

    with _patch_httpx(h):
        out = await shodan_host("8.8.8.8", settings=_settings())

    assert out["error"] is True
    assert "401" in out["message"]


@pytest.mark.asyncio
async def test_network_error_returns_clean_error_dict() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with _patch_httpx(h):
        out = await shodan_host("8.8.8.8", settings=_settings())

    assert out["error"] is True
    assert "ConnectError" in out["message"]


def test_registered_as_read_only_tool() -> None:
    from soc_ai.tools._registry import get_tool

    spec = get_tool("shodan_host")
    assert spec.read_only is True
    assert "SHODAN_API_KEY" in spec.description or "Shodan" in spec.description
