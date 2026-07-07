"""Tests for the crawl4ai crawl_page tool + its investigator wiring."""

from __future__ import annotations

import ipaddress
import json
import socket
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from soc_ai.tools.crawl_page import crawl_page

_REAL = httpx.AsyncClient


def _settings(**over: Any) -> Any:
    base: dict[str, Any] = dict(
        crawl4ai_enabled=True,
        crawl4ai_url="https://crawl.lan",
        crawl4ai_verify_ssl=False,
        crawl4ai_timeout_s=10,
        crawl_max_chars=6000,
        crawl4ai_token=None,
        internal_cidrs=[ipaddress.ip_network("10.0.0.0/8")],
        oracle_internal_suffixes=(".corp", ".lan"),
    )
    base.update(over)
    return SimpleNamespace(**base)


def _patch_httpx(handler: Any) -> Any:
    transport = httpx.MockTransport(handler)

    def _factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k["transport"] = transport
        return _REAL(*a, **k)

    return patch("soc_ai.tools.crawl_page.httpx.AsyncClient", _factory)


def _patch_resolve(addr: str = "93.184.216.34") -> Any:
    """Make DNS resolution hermetic: every host resolves to *addr* (a public IP
    by default) so SSRF-guard tests don't touch the network."""

    def _fake_getaddrinfo(host: str, *a: Any, **k: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]

    return patch("soc_ai.tools.crawl_page.socket.getaddrinfo", _fake_getaddrinfo)


@pytest.mark.asyncio
async def test_disabled_no_io() -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        r = await crawl_page("https://evil.example.com", settings=_settings(crawl4ai_enabled=False))
    assert r["ok"] is False
    assert "disabled" in r["error"]
    assert calls["n"] == 0


@pytest.mark.asyncio
async def test_no_url_configured() -> None:
    r = await crawl_page("https://x.com", settings=_settings(crawl4ai_url=""))
    assert r["ok"] is False
    assert "crawl4ai_url" in r["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "https://10.4.4.4/page",  # internal CIDR
        "http://127.0.0.1/x",  # loopback
        "https://localhost/x",  # localhost
        "https://intranet/x",  # bare hostname
        "https://wiki.corp/x",  # internal suffix
        "ftp://example.com/x",  # bad scheme
    ],
)
async def test_internal_or_unsafe_urls_refused(url: str) -> None:
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h):
        r = await crawl_page(url, settings=_settings())
    assert r["ok"] is False
    assert "refused" in r["error"] or "not allowed" in r["error"]
    assert calls["n"] == 0  # never reached the network


@pytest.mark.asyncio
async def test_md_endpoint_flat_response_parsed() -> None:
    """The real crawl4ai 0.8.x /md shape: flat {markdown: str, success: bool}."""
    payload = {
        "url": "https://abuse.example.com/report",
        "filter": "fit",
        "markdown": "# Report\nPushPlanet is a legit SaaS, no malware/phishing flags.",
        "success": True,
    }

    def h(req: httpx.Request) -> httpx.Response:
        if req.method == "HEAD":  # the SSRF redirect-preflight on the page itself
            return httpx.Response(200)  # terminal (no redirect)
        assert req.url.path.endswith("/md")  # crawl4ai 0.8.x markdown endpoint
        assert req.url.path != "/crawl"
        return httpx.Response(200, json=payload)

    with _patch_httpx(h), _patch_resolve():
        r = await crawl_page("https://abuse.example.com/report", settings=_settings())
    assert r["ok"] is True
    assert "legit SaaS" in r["content"]
    assert r["truncated"] is False


@pytest.mark.asyncio
async def test_results_array_markdown_object_tolerated() -> None:
    """Tolerance: also parse a results-array shape with a markdown OBJECT."""
    payload = {
        "results": [
            {
                "success": True,
                "title": "Abuse report",
                "markdown": {"fit_markdown": "legit SaaS, no flags."},
            }
        ]
    }

    with _patch_httpx(lambda req: httpx.Response(200, json=payload)), _patch_resolve():
        r = await crawl_page("https://abuse.example.com/report", settings=_settings())
    assert r["ok"] is True
    assert "legit SaaS" in r["content"]
    assert r["title"] == "Abuse report"


@pytest.mark.asyncio
async def test_markdown_string_and_truncation() -> None:
    big = "x" * 9000
    payload = {"results": [{"success": True, "markdown": big}]}

    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _patch_httpx(h), _patch_resolve():
        r = await crawl_page("https://e.com", settings=_settings(crawl_max_chars=100))
    assert r["ok"] is True
    assert len(r["content"]) == 100
    assert r["truncated"] is True


@pytest.mark.asyncio
async def test_success_false_and_empty_and_non200() -> None:
    with (
        _patch_httpx(lambda req: httpx.Response(200, json={"results": [{"success": False}]})),
        _patch_resolve(),
    ):
        assert (await crawl_page("https://e.com", settings=_settings()))["ok"] is False
    with (
        _patch_httpx(lambda req: httpx.Response(200, json={"results": [{"success": True}]})),
        _patch_resolve(),
    ):
        r = await crawl_page("https://e.com", settings=_settings())
        assert r["ok"] is False
        assert "no readable content" in r["error"]
    with _patch_httpx(lambda req: httpx.Response(502, text="bad gateway")), _patch_resolve():
        r = await crawl_page("https://e.com", settings=_settings())
        assert r["ok"] is False
        assert "502" in r["error"]


@pytest.mark.asyncio
async def test_connect_error_graceful() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    with _patch_httpx(h), _patch_resolve():
        r = await crawl_page("https://e.com", settings=_settings())
    assert r["ok"] is False


@pytest.mark.asyncio
async def test_public_host_resolving_to_internal_ip_refused() -> None:
    """SSRF: an external NAME whose A record points at a private/loopback/
    link-local/metadata IP must be refused — never reach the network."""
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    for bad_ip in ("169.254.169.254", "10.0.0.253", "127.0.0.1", "192.168.1.5"):
        with _patch_httpx(h), _patch_resolve(bad_ip):
            r = await crawl_page("https://evil.example.com/x", settings=_settings())
        assert r["ok"] is False
        assert "internal IP" in r["error"]
    assert calls["n"] == 0  # never reached the network


@pytest.mark.asyncio
async def test_public_host_resolving_to_public_ip_allowed() -> None:
    """A genuinely external host (resolves to a public IP) is allowed through."""
    payload = {"markdown": "public threat-intel page", "success": True}

    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _patch_httpx(h), _patch_resolve("93.184.216.34"):
        r = await crawl_page("https://abuse.example.com/report", settings=_settings())
    assert r["ok"] is True
    assert "threat-intel" in r["content"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location",
    [
        "https://169.254.169.254/latest/meta-data/",  # cloud metadata IP literal
        "http://127.0.0.1:8080/admin",  # loopback
        "https://10.0.0.253/secret",  # internal CIDR
        "https://intranet/wiki",  # bare internal hostname
        "https://api.corp/keys",  # internal DNS suffix
        "/admin",  # RELATIVE redirect back onto an internal host (see below)
    ],
)
async def test_redirect_to_internal_target_refused(location: str) -> None:
    """SSRF/TOCTOU: a 30x whose target is internal must be refused at preflight,
    BEFORE crawl4ai is ever handed a url to fetch server-side."""
    md_calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/md"):  # crawl4ai must never be reached
            md_calls["n"] += 1
            return httpx.Response(200, json={"markdown": "leaked", "success": True})
        # The external page 302s to an internal target.
        return httpx.Response(302, headers={"location": location})

    # The relative-redirect case only resolves to an internal host if the ORIGIN
    # host itself resolves internal; point the resolver at a loopback for it.
    resolve_to = "127.0.0.1" if location == "/admin" else "93.184.216.34"
    with _patch_httpx(h), _patch_resolve(resolve_to):
        r = await crawl_page("https://evil.example.com/start", settings=_settings())
    assert r["ok"] is False
    assert "refused" in r["error"]
    assert md_calls["n"] == 0  # crawl4ai never fetched anything


@pytest.mark.asyncio
async def test_redirect_to_name_resolving_internal_refused() -> None:
    """A 30x to an EXTERNAL name whose A record points at an internal IP is also
    refused — the per-hop guard re-resolves each redirect host."""
    md_calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/md"):
            md_calls["n"] += 1
            return httpx.Response(200, json={"markdown": "leaked", "success": True})
        return httpx.Response(302, headers={"location": "https://rebind.example.net/x"})

    # Every name resolves to an internal IP here, so the redirect hop is rejected.
    with _patch_httpx(h), _patch_resolve("10.0.0.5"):
        r = await crawl_page("https://evil.example.com/start", settings=_settings())
    assert r["ok"] is False
    assert "refused" in r["error"]
    assert md_calls["n"] == 0


@pytest.mark.asyncio
async def test_external_redirect_chain_followed_then_crawled() -> None:
    """A redirect chain that stays external is followed and the FINAL url (not the
    original) is what crawl4ai is asked to fetch."""
    fetched = {"url": None}

    def h(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/md"):
            body = json.loads(req.read().decode())
            assert body["follow_redirects"] is False  # defence-in-depth hint
            assert body["url"].endswith("/final")  # the FINAL url, not the original
            fetched["url"] = str(req.url)
            return httpx.Response(200, json={"markdown": "final external page", "success": True})
        if req.url.path == "/start":
            return httpx.Response(301, headers={"location": "https://abuse.example.com/final"})
        return httpx.Response(200)  # /final is terminal

    with _patch_httpx(h), _patch_resolve("93.184.216.34"):
        r = await crawl_page("https://abuse.example.com/start", settings=_settings())
    assert r["ok"] is True
    assert "final external page" in r["content"]
    assert fetched["url"].endswith("/md")


@pytest.mark.asyncio
async def test_redirect_loop_refused() -> None:
    """An over-long redirect chain (loop / evasion) is refused, not crawled."""
    md_calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/md"):
            md_calls["n"] += 1
            return httpx.Response(200, json={"markdown": "x", "success": True})
        return httpx.Response(302, headers={"location": "https://abuse.example.com/next"})

    with _patch_httpx(h), _patch_resolve("93.184.216.34"):
        r = await crawl_page("https://abuse.example.com/loop", settings=_settings())
    assert r["ok"] is False
    assert "redirect" in r["error"]
    assert md_calls["n"] == 0


@pytest.mark.asyncio
async def test_octal_ip_literal_refused() -> None:
    """A non-canonical (octal) loopback literal must not bypass the IP check.

    ``0177.0.0.1`` parses as 127.0.0.1; ipaddress.ip_address rejects the octal
    form, so it falls to the resolver path which also resolves it to loopback.
    Either way it must be refused without hitting the network."""
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    # Resolver returns loopback for the octal-looking host.
    with _patch_httpx(h), _patch_resolve("127.0.0.1"):
        r = await crawl_page("http://0177.0.0.1/x", settings=_settings())
    assert r["ok"] is False
    assert calls["n"] == 0


@pytest.mark.asyncio
async def test_unresolvable_host_refused() -> None:
    """A host that does not resolve cannot be proven external → refused."""

    def fail_resolve(host: str, *a: Any, **k: Any) -> list[Any]:
        raise OSError("name resolution failed")

    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_httpx(h), patch("soc_ai.tools.crawl_page.socket.getaddrinfo", fail_resolve):
        r = await crawl_page("https://nonexistent.example.org/x", settings=_settings())
    assert r["ok"] is False
    assert "did not resolve" in r["error"]
    assert calls["n"] == 0


def test_wiring_dispatch_and_literal() -> None:
    from soc_ai.agent import targeted_investigator as ti

    assert ti._dispatch_table()["t_crawl_page"] is crawl_page
    from soc_ai.agent.triage import TargetedGap

    enum_vals = TargetedGap.model_json_schema()["properties"]["tool_name"].get("enum") or []
    assert "t_crawl_page" in enum_vals
