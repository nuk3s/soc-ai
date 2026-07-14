"""Shared helpers for the opt-in ONLINE enrichment tools (GreyNoise, Shodan
InternetDB, …).

Unlike the rest of soc-ai's enrichment — which is strictly local-mirror with no
runtime egress (see :mod:`soc_ai.enrichment`) — these tools reach OUT to
third-party APIs. They are therefore OFF by default (``allow_online_enrichment``)
and each returns a clean, NON-RAISING result dict whether or not it is
configured, so the agent reads the dict and moves on (same contract as the other
read tools).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import httpx

from soc_ai.config import Settings
from soc_ai.demo.guard import assert_egress_allowed

# Host/IP-ish tokens in a free-text query (FQDNs, bare hostnames, IPv4, IPv6).
# Leading ':' is allowed so IPv6 literals written with a leading '::' (e.g. ``::1``)
# are captured, not just those starting with a hextet.
_IDENTIFIER_TOKEN_RE = re.compile(r"[A-Za-z0-9:][A-Za-z0-9_.:-]*")


def online_unavailable(
    settings: Settings, *, requires_key: str | None = None
) -> dict[str, Any] | None:
    """Return a clean result dict if online enrichment can't run, else ``None``.

    Two gates: the master ``allow_online_enrichment`` flag (off by default), and
    an optional per-provider key. Returning a dict (rather than raising) lets the
    tool short-circuit with something the model can read and reason around.
    """
    if not settings.allow_online_enrichment:
        return {
            "available": False,
            "reason": "online_enrichment_disabled",
            "hint": (
                "online enrichment is off (preserves zero-egress default) — set "
                "ALLOW_ONLINE_ENRICHMENT=true to enable these tools"
            ),
        }
    if requires_key is not None:
        val: Any = getattr(settings, requires_key, None)
        # Unwrap a SecretStr; treat None / blank as not-configured.
        secret = val.get_secret_value() if hasattr(val, "get_secret_value") else val
        if not secret:
            return {
                "available": False,
                "reason": "not_configured",
                "hint": f"set {requires_key.upper()} in .env to enable this provider",
            }
    return None


def is_internal_ip(ip: str, settings: Any) -> bool:
    """True iff *ip* must NOT be sent to a third party (skip the online lookup).

    Anything that is not GLOBALLY ROUTABLE is treated as internal: RFC1918
    private space, loopback, link-local, CGNAT (``100.64.0.0/10``), benchmarking
    (``198.18.0.0/15``), TEST-NET / documentation, multicast, reserved and
    unspecified. ``ipaddress.is_global`` captures all of those in one check —
    notably the per-flag approach misses CGNAT and benchmarking (neither is
    ``is_private``), which would leak ISP/topology addresses off-box. Also
    rejects any operator-configured ``internal_cidrs`` network (an internal-but-
    globally-routable host). An unparseable value is treated as internal too: we
    never send garbage (or a hostname that could leak) to a third party.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return True
    if not addr.is_global:
        return True
    for net in getattr(settings, "internal_cidrs", []) or []:
        try:
            if addr in net:
                return True
        except TypeError:
            continue
    return False


def first_internal_identifier(text: str, settings: Any) -> str | None:
    """Return the first token in *text* that is an INTERNAL identifier (and so must
    NOT be sent to a third party), else ``None``.

    Catches three leak classes that an IPv4-only, ``internal_cidrs``-membership
    guard misses:

    * internal IPs — via :func:`is_internal_ip`, which treats anything not
      globally routable as internal (RFC1918, loopback, link-local, CGNAT,
      benchmarking) and understands IPv6, plus operator ``internal_cidrs``;
    * FQDNs on a configured internal DNS suffix (``oracle_internal_suffixes``,
      e.g. ``dc01.corp.local``);
    * a bare/known internal hostname configured in ``oracle_extra_hosts``.

    Bare single-label tokens are refused ONLY when they exactly match a configured
    internal host, so ordinary English/query words are never over-refused.
    """
    suffixes = tuple(s.lower() for s in (getattr(settings, "oracle_internal_suffixes", ()) or ()))
    extra_hosts = {str(h).lower() for h in (getattr(settings, "oracle_extra_hosts", ()) or ())}
    for raw in _IDENTIFIER_TOKEN_RE.findall(text or ""):
        # Strip only dot/hyphen punctuation from the ends — NOT colons, which are
        # part of an IPv6 literal (``::1``) or an IPv4 ``host:port``.
        tok = str(raw).strip(".-")
        if not tok:
            continue
        # IP candidates: the token itself, plus the host part of an IPv4 host:port.
        candidates = [tok]
        if tok.count(":") == 1:
            candidates.append(tok.rsplit(":", 1)[0])
        is_ip = False
        for cand in candidates:
            try:
                ipaddress.ip_address(cand)
            except ValueError:
                continue
            is_ip = True
            if is_internal_ip(cand, settings):  # not globally routable / in internal_cidrs
                return tok
        if is_ip:
            continue  # an external IP literal — not a leak
        low = tok.lower()
        if any(low.endswith(sfx) for sfx in suffixes) or low in extra_hosts:
            return tok
    return None


def online_client(settings: Settings) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` with the shared online-enrichment timeout + TLS policy."""
    assert_egress_allowed(settings, "online enrichment")
    return httpx.AsyncClient(
        timeout=settings.online_enrichment_timeout_s,
        verify=settings.online_enrichment_verify_ssl,
        headers={"User-Agent": "soc-ai (+https://github.com/nuk3s/soc-ai)"},
    )
