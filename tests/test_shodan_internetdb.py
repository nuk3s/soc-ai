"""Tests for the Shodan InternetDB online tool (free, no-key, egress-gated).

Every path is exercised with the network mocked out:

- gate OFF (``allow_online_enrichment=False``) → clean 'disabled' dict, no I/O
- gate ON + mocked HTTP 200 → parsed ports/cpes/hostnames/tags/vulns
- gate ON + mocked HTTP 404 → clean ``observed: False`` (a real "not seen" answer)
- a private / reserved IP (gate ON) → ``private_ip`` skip, no I/O
- a network/transport error → clean ``error: True`` dict, never an exception
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from soc_ai.tools.shodan_internetdb import shodan_internetdb

_REAL = httpx.AsyncClient


def _settings(**over: Any) -> Any:
    """A minimal stand-in for Settings: only the online-enrichment fields the
    tool (and the shared online helpers) read."""
    base: dict[str, Any] = dict(
        allow_online_enrichment=True,
        online_enrichment_timeout_s=8,
        online_enrichment_verify_ssl=True,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _patch_httpx(handler: Any) -> Any:
    """Route every httpx.AsyncClient request (created inside online_client) through
    a MockTransport calling ``handler`` — same convention as test_crawl_page."""
    transport = httpx.MockTransport(handler)

    def _factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k["transport"] = transport
        return _REAL(*a, **k)

    # online_client builds the AsyncClient in soc_ai.tools.online, so patch there.
    return patch("soc_ai.tools.online.httpx.AsyncClient", _factory)


@pytest.mark.asyncio
async def test_gate_off_returns_disabled_no_io() -> None:
    """Master flag off → the gate dict is returned verbatim and nothing is sent."""
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        out = await shodan_internetdb("8.8.8.8", settings=_settings(allow_online_enrichment=False))

    assert out["available"] is False
    assert out["reason"] == "online_enrichment_disabled"
    assert calls["n"] == 0  # no network I/O when disabled


@pytest.mark.asyncio
async def test_private_ip_skipped_no_io() -> None:
    """A private/reserved IP is never sent off-box — clean private_ip result."""
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        out = await shodan_internetdb("192.168.50.8", settings=_settings())

    assert out["available"] is False
    assert out["reason"] == "private_ip"
    assert out["ip"] == "192.168.50.8"
    assert calls["n"] == 0  # never reached the network


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.1.1", "192.168.1.10", "100.64.0.1"])
async def test_reserved_ranges_all_skipped(ip: str) -> None:
    """Loopback, link-local, RFC1918 and CGNAT are all treated as non-routable."""

    def h(req: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError(f"network hit for reserved IP {ip}")

    with _patch_httpx(h):
        out = await shodan_internetdb(ip, settings=_settings())

    assert out["reason"] == "private_ip"


@pytest.mark.asyncio
async def test_success_200_parses_fields() -> None:
    """A mocked 200 yields observed=True with the InternetDB lists surfaced."""
    captured = {"url": ""}
    payload = {
        "ip": "1.1.1.1",
        "ports": [80, 443],
        "cpes": ["cpe:/a:nginx:nginx"],
        "hostnames": ["one.one.one.one"],
        "tags": ["cdn"],
        "vulns": ["CVE-2021-1234"],
    }

    def h(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        return httpx.Response(200, json=payload)

    with _patch_httpx(h):
        out = await shodan_internetdb("1.1.1.1", settings=_settings())

    assert captured["url"] == "https://internetdb.shodan.io/1.1.1.1"
    assert out["observed"] is True
    assert out["ip"] == "1.1.1.1"
    assert out["ports"] == [80, 443]
    assert out["cpes"] == ["cpe:/a:nginx:nginx"]
    assert out["hostnames"] == ["one.one.one.one"]
    assert out["tags"] == ["cdn"]
    assert out["vulns"] == ["CVE-2021-1234"]


@pytest.mark.asyncio
async def test_success_200_missing_fields_default_to_empty_lists() -> None:
    """A sparse 200 (only ip) still returns the full, stable list-shape."""

    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ip": "1.1.1.1"})

    with _patch_httpx(h):
        out = await shodan_internetdb("1.1.1.1", settings=_settings())

    assert out["observed"] is True
    for field in ("ports", "cpes", "hostnames", "tags", "vulns"):
        assert out[field] == []


@pytest.mark.asyncio
async def test_404_is_no_data_not_error() -> None:
    """404 = InternetDB has never seen this IP → observed=False, no error flag."""

    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "No information available"})

    with _patch_httpx(h):
        out = await shodan_internetdb("9.9.9.9", settings=_settings())

    assert out["observed"] is False
    assert out["ip"] == "9.9.9.9"
    assert "error" not in out


@pytest.mark.asyncio
async def test_network_error_returns_clean_error_dict() -> None:
    """A transport/network failure becomes a clean error dict — never raises."""

    def h(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with _patch_httpx(h):
        out = await shodan_internetdb("8.8.8.8", settings=_settings())

    assert out["error"] is True
    assert "ConnectError" in out["message"]


@pytest.mark.asyncio
async def test_timeout_returns_clean_error_dict() -> None:
    """A read timeout is also caught (subclass of httpx.HTTPError)."""

    def h(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    with _patch_httpx(h):
        out = await shodan_internetdb("8.8.8.8", settings=_settings())

    assert out["error"] is True
    assert "ReadTimeout" in out["message"]


@pytest.mark.asyncio
async def test_invalid_ip_treated_as_non_routable() -> None:
    """An unparseable IP string is rejected up front (no network I/O)."""

    def h(req: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError("network hit for invalid IP")

    with _patch_httpx(h):
        out = await shodan_internetdb("not-an-ip", settings=_settings())

    assert out["available"] is False
    assert out["reason"] == "private_ip"


@pytest.mark.asyncio
async def test_500_returns_clean_error_dict() -> None:
    """A non-404 error status surfaces a clean error dict (raise_for_status path)."""

    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with _patch_httpx(h):
        out = await shodan_internetdb("8.8.8.8", settings=_settings())

    assert out["error"] is True


def test_registered_as_read_only_tool() -> None:
    """The @tool decorator registered it read-only under its function name."""
    from soc_ai.tools._registry import get_tool

    spec = get_tool("shodan_internetdb")
    assert spec.read_only is True
    assert "InternetDB" in spec.description
