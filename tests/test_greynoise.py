"""Tests for the GreyNoise online enrichment tool + its agent wiring.

Covers the egress/key gate (disabled, not_configured), the private-IP skip, a
mocked 200 hit, a mocked 404 (never observed), and a network-error path. All
HTTP is hermetic via an httpx.MockTransport patched into ``online_client``'s
AsyncClient factory; no test touches the real GreyNoise API.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from pydantic import SecretStr
from soc_ai.tools.greynoise import greynoise

_REAL = httpx.AsyncClient


def _settings(**over: Any) -> Any:
    base: dict[str, Any] = dict(
        allow_online_enrichment=True,
        greynoise_api_key=SecretStr("gn-test-key"),
        online_enrichment_timeout_s=8,
        online_enrichment_verify_ssl=True,
        internal_cidrs=[],
    )
    base.update(over)
    return SimpleNamespace(**base)


def _patch_httpx(handler: Any) -> Any:
    """Patch the AsyncClient that ``online_client`` builds with a MockTransport."""
    transport = httpx.MockTransport(handler)

    def _factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k["transport"] = transport
        return _REAL(*a, **k)

    return patch("soc_ai.tools.online.httpx.AsyncClient", _factory)


# --- gate: master egress switch off (no flag) ------------------------------


@pytest.mark.asyncio
async def test_gate_off_no_flag_disabled_no_io() -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        r = await greynoise("8.8.8.8", settings=_settings(allow_online_enrichment=False))
    assert r["available"] is False
    assert r["reason"] == "online_enrichment_disabled"
    assert calls["n"] == 0  # never reached the network


# --- gate: flag on but key missing -> not_configured -----------------------


@pytest.mark.asyncio
async def test_flag_on_but_no_key_not_configured_no_io() -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        r = await greynoise("8.8.8.8", settings=_settings(greynoise_api_key=None))
    assert r["available"] is False
    assert r["reason"] == "not_configured"
    assert "greynoise_api_key" in r["hint"].lower()
    assert calls["n"] == 0


@pytest.mark.asyncio
async def test_blank_secret_treated_as_unconfigured() -> None:
    r = await greynoise("8.8.8.8", settings=_settings(greynoise_api_key=SecretStr("")))
    assert r["available"] is False
    assert r["reason"] == "not_configured"


# --- private / internal IPs are skipped (no egress) ------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ip",
    ["10.4.4.4", "192.168.1.10", "172.16.0.1", "127.0.0.1", "169.254.1.1", "not-an-ip"],
)
async def test_private_or_bad_ip_skipped_no_io(ip: str) -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        r = await greynoise(ip, settings=_settings())
    assert r.get("skipped") is True
    assert calls["n"] == 0


# --- mocked 200 hit ---------------------------------------------------------


@pytest.mark.asyncio
async def test_observed_200_parsed_and_sends_key_header() -> None:
    payload = {
        "ip": "1.2.3.4",
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "unknown",
        "link": "https://viz.greynoise.io/ip/1.2.3.4",
        "last_seen": "2026-06-26",
        "message": "Success",
    }

    def h(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/v3/community/1.2.3.4"
        assert req.url.host == "api.greynoise.io"
        assert req.headers.get("key") == "gn-test-key"
        return httpx.Response(200, json=payload)

    with _patch_httpx(h):
        r = await greynoise("1.2.3.4", settings=_settings())
    assert r["observed"] is True
    assert r["noise"] is True
    assert r["riot"] is False
    assert r["classification"] == "malicious"
    assert r["name"] == "unknown"
    assert r["link"].endswith("/1.2.3.4")
    assert r["last_seen"] == "2026-06-26"
    assert "error" not in r


# --- mocked 404 = never observed -------------------------------------------


@pytest.mark.asyncio
async def test_404_never_observed() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"ip": "5.6.7.8", "message": "IP not observed"})

    with _patch_httpx(h):
        r = await greynoise("5.6.7.8", settings=_settings())
    assert r["observed"] is False
    assert r["summary"] == "not seen scanning the internet"
    assert "error" not in r


# --- other non-200 -> error -------------------------------------------------


@pytest.mark.asyncio
async def test_non_200_returns_error() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited")

    with _patch_httpx(h):
        r = await greynoise("1.2.3.4", settings=_settings())
    assert "error" in r
    assert "429" in r["error"]


# --- network error never raises --------------------------------------------


@pytest.mark.asyncio
async def test_connect_error_graceful() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    with _patch_httpx(h):
        r = await greynoise("1.2.3.4", settings=_settings())
    assert "error" in r
    assert r["error"] == "ConnectError"


@pytest.mark.asyncio
async def test_empty_ip_errors_no_io() -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        r = await greynoise("   ", settings=_settings())
    assert "error" in r
    assert calls["n"] == 0


# --- registry: greynoise module is force-imported --------------------------


def test_force_imported_in_tools_package() -> None:
    import soc_ai.tools as tools_pkg

    assert hasattr(tools_pkg, "greynoise")
