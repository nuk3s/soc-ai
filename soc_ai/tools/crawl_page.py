"""crawl4ai page-read tool — deep-read an EXTERNAL web page's content.

Complements ``web_search``: search (SearXNG) finds candidate pages; this fetches
+ extracts the readable content (markdown) of one of them via a self-hosted
crawl4ai instance, so the agent can read an actual reputation / abuse /
threat-intel page instead of a snippet.

Read-only outbound HTTP to the crawl4ai service. Bounded by a timeout; never
raises (returns a graceful ``{"ok": False, "error": ...}`` dict).

SAFETY (SSRF): crawl4ai fetches whatever URL it's handed server-side, so a URL
pointing at an INTERNAL host (an internal IP, localhost, a bare hostname, or a
configured internal suffix) is refused — the agent must only deep-read external
indicators, never be steered (e.g. via a poisoned alert field) into pulling an
internal service's content.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from soc_ai.demo.guard import assert_egress_allowed

_LOGGER = logging.getLogger(__name__)

# Cap on redirect hops we will follow + revalidate before giving up. A chain
# longer than this is treated as hostile (redirect loop / evasion) and refused.
_MAX_REDIRECT_HOPS = 8


def _ip_is_internal(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, settings: Any) -> bool:
    """True iff *ip* is loopback/link-local/private/reserved/multicast/unspecified
    or falls inside a configured ``internal_cidrs`` network."""
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    for net in getattr(settings, "internal_cidrs", []) or []:
        try:
            if ip in net:
                return True
        except TypeError:
            continue
    return False


def _resolve_addrs(host: str) -> list[str]:
    """Resolve *host* to every A/AAAA address. Returns [] if resolution fails.

    A resolution failure is itself a refusal reason (we cannot prove the host
    is external), handled by the caller.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return []
    addrs: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            addrs.append(sockaddr[0])
    return addrs


def _host_is_internal(url: str, settings: Any) -> str | None:
    """Return a reason string if *url*'s host is internal/unsafe, else None.

    The host is DNS-resolved and EVERY resolved address (v4 + v6) is checked
    against the internal-IP reject set, so an external name whose A record points
    at a private/loopback/link-local address (DNS-rebinding / SSRF) is refused,
    and non-canonical IP encodings (octal/hex ``0177.0.0.1``) cannot bypass the
    parse because we validate the RESOLVED canonical addresses.

    This guard checks ONE url. A 30x redirect can still send the fetch to an
    internal target, so :func:`_preflight_redirects` re-applies this same guard
    to every redirect hop before crawl4ai is handed a (terminal) url. Operators
    should still egress-restrict the crawl4ai service as defence in depth.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return "unparseable URL"
    if parsed.scheme not in ("http", "https"):
        return f"scheme {parsed.scheme!r} not allowed (http/https only)"
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return "no host in URL"
    if host in ("localhost", "ip6-localhost"):
        return "localhost is not crawlable"

    # 1. IP-literal host → check directly (covers 0.0.0.0, ::, link-local, IPv6).
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None
    if literal_ip is not None:
        if _ip_is_internal(literal_ip, settings):
            return f"internal IP {host}"
        # A public IP literal still bypasses suffix checks — that's fine.
        return None

    # 2. Bare single-label hostname (no dot) → almost certainly internal.
    if "." not in host:
        return f"bare hostname {host!r} (likely internal)"

    # 3. Configured internal DNS suffix.
    for suffix in getattr(settings, "oracle_internal_suffixes", ()) or ():
        if host.endswith(suffix):
            return f"internal suffix {suffix}"

    # 4. Resolve the name and reject if ANY resolved address is internal. This
    #    closes the SSRF hole where ``evil.com`` resolves to 169.254.169.254 /
    #    10.x and the octal/hex-literal bypass (we check canonical resolved IPs).
    addrs = _resolve_addrs(host)
    if not addrs:
        return f"host {host!r} did not resolve (cannot verify it is external)"
    for addr in addrs:
        try:
            resolved = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _ip_is_internal(resolved, settings):
            return f"host {host!r} resolves to internal IP {addr}"
    return None


async def _preflight_redirects(
    url: str, *, settings: Any, client: httpx.AsyncClient
) -> tuple[str | None, str | None]:
    """Walk *url*'s redirect chain ourselves, revalidating every hop's host.

    crawl4ai fetches server-side and follows 30x redirects we never see, so a
    page that 302s to ``169.254.169.254`` / an RFC1918 host would slip past the
    single :func:`_host_is_internal` check on the original url (redirect-SSRF /
    TOCTOU). We close that by NOT delegating redirect-following blindly: with
    ``follow_redirects=False`` we resolve the chain hop-by-hop, run the SAME
    internal-host guard on each ``Location``, and hand crawl4ai only the final,
    non-redirecting url (so its server-side fetch returns 200 with no 30x left
    to chase into an internal target).

    Returns ``(final_url, None)`` on success, else ``(None, reason)``.
    """
    current = url
    for _ in range(_MAX_REDIRECT_HOPS):
        try:
            # HEAD is cheap and enough to read a Location; some servers reject
            # HEAD, so fall back to a GET (still no body streamed — we close it).
            resp = await client.head(current, follow_redirects=False)
            if resp.status_code == 405:  # method not allowed → retry with GET
                resp = await client.get(current, follow_redirects=False)
        except Exception as e:
            # A preflight failure is non-fatal: the host already passed the
            # internal-IP guard, so let crawl4ai attempt the original url. We
            # only *gain* safety from the chain we did manage to validate.
            _LOGGER.debug("redirect preflight stopped early (%s)", type(e).__name__)
            return current, None
        if not resp.is_redirect:
            return current, None  # terminal: hand THIS url to crawl4ai
        location = resp.headers.get("location")
        if not location:
            return current, None  # 30x with no target — let crawl4ai handle it
        # Resolve relative redirects against the current url, then revalidate.
        next_url = urljoin(current, location)
        bad = _host_is_internal(next_url, settings)
        if bad is not None:
            return None, f"redirect to internal target ({bad})"
        current = next_url
    return None, f"too many redirects (> {_MAX_REDIRECT_HOPS} hops)"


def _extract_content(result: Any) -> str:
    """Pull the readable text from a crawl4ai result, tolerant of shape drift."""
    if not isinstance(result, dict):
        return ""
    md = result.get("markdown")
    if isinstance(md, dict):  # newer crawl4ai: {raw_markdown, fit_markdown, ...}
        return str(md.get("fit_markdown") or md.get("raw_markdown") or "")
    if isinstance(md, str) and md:
        return md
    for key in ("extracted_content", "cleaned_html", "text", "html"):
        val = result.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


async def crawl_page(url: str, *, settings: Any) -> dict[str, Any]:
    """Fetch + extract the content of *url* via crawl4ai. Never raises.

    Returns ``{"ok": True, "url", "title", "content", "truncated"}`` on success,
    else ``{"ok": False, "error": ...}``.
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "error": "empty url"}
    if not getattr(settings, "crawl4ai_enabled", False):
        return {"ok": False, "error": "crawl4ai disabled (set CRAWL4AI_ENABLED=true)"}
    base = str(getattr(settings, "crawl4ai_url", "") or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "crawl4ai_url not configured"}
    bad = _host_is_internal(url, settings)
    if bad is not None:
        return {"ok": False, "error": f"refused: {bad}; crawl_page is for EXTERNAL pages only"}

    timeout = float(getattr(settings, "crawl4ai_timeout_s", 30))
    verify = bool(getattr(settings, "crawl4ai_verify_ssl", True))
    max_chars = int(getattr(settings, "crawl_max_chars", 6000))
    headers = {"Accept": "application/json"}
    token = getattr(settings, "crawl4ai_token", None)
    if token is not None:
        raw = token.get_secret_value() if hasattr(token, "get_secret_value") else str(token)
        if raw:
            headers["Authorization"] = f"Bearer {raw}"
    try:
        # Demo guard inside the try: blocked egress becomes a normal error
        # result (this function never raises), before any client exists.
        assert_egress_allowed(settings, "page crawl")
        async with httpx.AsyncClient(timeout=timeout, verify=verify) as client:
            # Resolve+revalidate the redirect chain BEFORE handing crawl4ai a
            # url, so a 30x to an internal host can't slip past the SSRF guard
            # server-side. We pass crawl4ai the final non-redirecting url.
            fetch_url, redir_bad = await _preflight_redirects(url, settings=settings, client=client)
            if redir_bad is not None:
                return {
                    "ok": False,
                    "error": f"refused: {redir_bad}; crawl_page is for EXTERNAL pages only",
                }
            assert fetch_url is not None  # (redir_bad is None) ⇒ fetch_url is set
            # crawl4ai's /md endpoint fetches + extracts clean ("fit") markdown
            # synchronously. Body is {"url": ...}; response is a flat dict with a
            # "markdown" string + "success" bool (crawl4ai 0.8.x). We also ask it
            # not to follow redirects (defence in depth — the chain is already
            # resolved to a terminal url above).
            resp = await client.post(
                f"{base}/md",
                json={"url": fetch_url, "follow_redirects": False},
                headers=headers,
            )
        if resp.status_code != 200:
            return {"ok": False, "error": f"crawl4ai HTTP {resp.status_code}"}
        data = resp.json()
    except Exception as e:  # graceful — a fetch failure is a normal error result
        _LOGGER.warning("crawl_page failed: %s", type(e).__name__)
        return {"ok": False, "error": type(e).__name__}

    # Response may be {"results": [..]}, a bare list, or a single dict.
    results = data.get("results") if isinstance(data, dict) else data
    result = results[0] if isinstance(results, list) and results else data
    if isinstance(result, dict) and result.get("success") is False:
        return {"ok": False, "error": "crawl4ai reported success=false for this url"}
    content = _extract_content(result)
    if not content:
        return {"ok": False, "error": "crawl4ai returned no readable content"}
    truncated = len(content) > max_chars
    title = str(result.get("title", "")) if isinstance(result, dict) else ""
    return {
        "ok": True,
        "url": url,
        "title": title[:200],
        "content": content[:max_chars],
        "truncated": truncated,
    }
