"""GreyNoise Community lookup — is this IP indiscriminately scanning the internet?

ONLINE, API-KEY enrichment tool. Given an external IP, asks the GreyNoise
Community API whether GreyNoise has seen that address scanning/crawling the
internet (``noise``), whether it belongs to a known-benign service (``riot``),
plus a one-word ``classification`` (benign / malicious / unknown). This is a
high-signal "is this a mass-scanner vs. a targeted actor?" check that an analyst
would otherwise run by hand.

Egress discipline (the only way this tool ever touches the network):

1. :func:`online_unavailable` is consulted FIRST. When the master egress switch
   ``ALLOW_ONLINE_ENRICHMENT`` is off, or the ``greynoise_api_key`` isn't
   configured, the tool returns that clean disabled/not-configured dict and makes
   NO request.
2. Private / loopback / link-local / reserved IPs are skipped locally —
   GreyNoise only tracks public internet scanners, and an internal IP must never
   be sent to a third party.
3. A 404 from the Community API means "GreyNoise has never observed this IP" —
   reported as ``{observed: False}``, not an error.
4. Any network/HTTP/parse failure returns ``{error: ...}``. The function NEVER
   raises — online enrichment is a soft signal, never a triage blocker.
"""

from __future__ import annotations

import logging
from typing import Any

from soc_ai.tools._registry import tool
from soc_ai.tools.online import is_internal_ip, online_client, online_unavailable

_LOGGER = logging.getLogger(__name__)

_GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"


def _is_internal(ip: str, settings: Any) -> bool:
    """True iff *ip* is non-routable / internal (skip the lookup), or unparseable.

    Delegates to the shared :func:`soc_ai.tools.online.is_internal_ip`, which
    gates on ``is_global`` so CGNAT / benchmarking ranges are also skipped (the
    per-flag approach used to miss those), and honours ``internal_cidrs``.
    """
    return is_internal_ip(ip, settings)


@tool(
    read_only=True,
    description=(
        "GreyNoise lookup: is this external IP indiscriminately scanning the "
        "internet (benign mass-scanner noise) or a targeted actor? Online, opt-in."
    ),
)
async def greynoise(ip: str, *, settings: Any) -> dict[str, Any]:
    """Look up *ip* in the GreyNoise Community API. Never raises.

    Returns one of:

    - disabled / not-configured gate dict (no network I/O) — see
      :func:`online_unavailable`;
    - ``{"skipped": True, ...}`` for a private/internal IP (no network I/O);
    - ``{"observed": False, "summary": "not seen scanning the internet"}`` on a
      404 (GreyNoise has never seen this IP);
    - ``{"noise", "riot", "classification", "name", "link", "last_seen"}`` on a
      200 hit;
    - ``{"error": ...}`` on any network / HTTP / decode failure.
    """
    # 1. Egress + key gate FIRST — no network I/O when disabled/unconfigured.
    gate = online_unavailable(settings, requires_key="greynoise_api_key")
    if gate is not None:
        return gate

    ip = (ip or "").strip()
    if not ip:
        return {"error": "empty ip"}

    # 2. Never send an internal / non-routable address to GreyNoise.
    if _is_internal(ip, settings):
        return {
            "skipped": True,
            "ip": ip,
            "summary": "private/internal IP — GreyNoise only tracks public scanners",
        }

    key = settings.greynoise_api_key.get_secret_value()
    url = _GREYNOISE_COMMUNITY_URL.format(ip=ip)
    try:
        async with online_client(settings) as client:
            resp = await client.get(url, headers={"key": key, "Accept": "application/json"})
        # 3. 404 = never observed — a real answer, not an error.
        if resp.status_code == 404:
            return {
                "ip": ip,
                "observed": False,
                "summary": "not seen scanning the internet",
            }
        if resp.status_code != 200:
            return {"error": f"greynoise HTTP {resp.status_code}", "ip": ip}
        data = resp.json()
    except Exception as e:  # graceful — a lookup failure is a normal error result
        _LOGGER.warning("greynoise lookup failed for %s: %s", ip, type(e).__name__)
        return {"error": type(e).__name__, "ip": ip}

    if not isinstance(data, dict):
        return {"error": "greynoise returned a non-object body", "ip": ip}

    return {
        "ip": ip,
        "observed": True,
        "noise": bool(data.get("noise", False)),
        "riot": bool(data.get("riot", False)),
        "classification": data.get("classification"),
        "name": data.get("name"),
        "link": data.get("link"),
        "last_seen": data.get("last_seen"),
    }
