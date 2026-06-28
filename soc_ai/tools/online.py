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
from typing import Any

import httpx

from soc_ai.config import Settings


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


def online_client(settings: Settings) -> httpx.AsyncClient:
    """An ``httpx.AsyncClient`` with the shared online-enrichment timeout + TLS policy."""
    return httpx.AsyncClient(
        timeout=settings.online_enrichment_timeout_s,
        verify=settings.online_enrichment_verify_ssl,
        headers={"User-Agent": "soc-ai (+https://github.com/nuk3s/soc-ai)"},
    )
