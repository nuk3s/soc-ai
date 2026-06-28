"""Tests for the CVEDB tool (online, free/no-key, egress-gated).

- gate OFF → clean disabled dict, no I/O
- malformed CVE id → ``error: invalid CVE id``, no I/O
- gate ON + 200 → cvss / epss / kev / refs surfaced, id upper-cased
- 404 → ``found: False``; non-200 / network err → clean error dict, never raises
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from soc_ai.tools.cvedb import cve_lookup

_REAL = httpx.AsyncClient


def _settings(**over: Any) -> Any:
    base: dict[str, Any] = dict(
        allow_online_enrichment=True,
        online_enrichment_timeout_s=8,
        online_enrichment_verify_ssl=True,
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
        out = await cve_lookup("CVE-2021-44228", settings=_settings(allow_online_enrichment=False))

    assert out["available"] is False
    assert out["reason"] == "online_enrichment_disabled"
    assert calls["n"] == 0


@pytest.mark.asyncio
async def test_invalid_cve_id_rejected_no_io() -> None:
    def h(req: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError("network hit for malformed CVE id")

    with _patch_httpx(h):
        out = await cve_lookup("not-a-cve", settings=_settings())

    assert out["error"] == "invalid CVE id"


@pytest.mark.asyncio
async def test_success_200_surfaces_scores() -> None:
    captured: dict[str, Any] = {}
    payload = {
        "cve_id": "CVE-2021-44228",
        "summary": "Log4Shell",
        "cvss": 10.0,
        "cvss_version": 3,
        "epss": 0.97,
        "ranking_epss": 0.999,
        "kev": True,
        "propose_action": "patch now",
        "ransomware_campaign": "Known",
        "references": ["https://example/1"],
        "published_time": "2021-12-10",
    }

    def h(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        return httpx.Response(200, json=payload)

    with _patch_httpx(h):
        # lower-case input must be upper-cased into the request + result
        out = await cve_lookup("cve-2021-44228", settings=_settings())

    assert captured["url"] == "https://cvedb.shodan.io/cve/CVE-2021-44228"
    assert out["found"] is True
    assert out["cve_id"] == "CVE-2021-44228"
    assert out["cvss"] == 10.0
    assert out["epss"] == 0.97
    assert out["kev"] is True
    assert out["references"] == ["https://example/1"]


@pytest.mark.asyncio
async def test_404_is_not_found_not_error() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "not found"})

    with _patch_httpx(h):
        out = await cve_lookup("CVE-1999-0001", settings=_settings())

    assert out["found"] is False
    assert "error" not in out


@pytest.mark.asyncio
async def test_network_error_returns_clean_error_dict() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with _patch_httpx(h):
        out = await cve_lookup("CVE-2021-44228", settings=_settings())

    assert out["error"] == "ConnectError"


def test_registered_as_read_only_tool() -> None:
    from soc_ai.tools._registry import get_tool

    spec = get_tool("cve_lookup")
    assert spec.read_only is True
    assert "CVE" in spec.description
