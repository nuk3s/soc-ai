"""``shodan_internetdb`` tool — free, no-key external-asset lookup for a PUBLIC IP.

Shodan's InternetDB (https://internetdb.shodan.io/<ip>) is the no-auth, no-cost
slice of Shodan: a single GET returns the open ``ports``, software ``cpes``,
reverse-DNS ``hostnames``, classification ``tags`` (e.g. ``cdn``, ``cloud``,
``self-signed``), and known ``vulns`` (CVE ids) Shodan last observed on that
address. It answers "what is this external host, from the outside?" — strong
corroboration for an alert against an unknown public IP without spending a key.

ONLINE, OFF BY DEFAULT. Like every tool in :mod:`soc_ai.tools.online`, this
reaches the public internet, so it is gated behind the master
``allow_online_enrichment`` flag and returns a clean, NON-RAISING result dict in
every path (disabled / private-IP / no-data / network-error) — the agent reads
the dict and reasons around it, exactly like the local read tools.

Guard rails baked in:

- **Gate first** via :func:`soc_ai.tools.online.online_unavailable` — no
  per-provider key is required (InternetDB is unauthenticated), so the gate is
  the master flag only. If it returns a dict, that dict is returned verbatim and
  no network I/O happens.
- **Skip private / reserved IPs** (RFC1918, loopback, link-local, CGNAT, …) —
  there is nothing for a *public* asset DB to know about an internal host, and
  sending an internal address to a third party would be a leak. Detected with the
  stdlib :mod:`ipaddress` module; returns ``{"available": False, "reason":
  "private_ip"}``.
- **404 → no data** (``observed: False``) — InternetDB returns 404 when it has
  never seen the IP, which is a real answer ("not an internet-exposed host"),
  not an error.
- **Any httpx / network error → ``{"error": True, "message": ...}``** — never an
  exception across the LLM tool boundary.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

import httpx

from soc_ai.config import Settings
from soc_ai.tools._registry import tool
from soc_ai.tools.online import online_client, online_unavailable

_LOGGER = logging.getLogger(__name__)

_BASE_URL = "https://internetdb.shodan.io"

# Fields InternetDB returns; we surface them with stable defaults so the agent
# always sees the same shape whether the host is richly described or sparse.
_LIST_FIELDS: tuple[str, ...] = ("ports", "cpes", "hostnames", "tags", "vulns")


def _is_routable_public_ip(ip: str) -> bool:
    """True iff ``ip`` is a valid GLOBAL (internet-routable) address.

    Everything else — RFC1918 private space, loopback, link-local, CGNAT
    (100.64/10), multicast, reserved, unspecified — is *not* something a public
    asset DB can describe, and must never be sent to a third party. ``is_global``
    captures all of those exclusions in one check; an unparseable string is
    likewise rejected.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _as_str_list(value: Any) -> list[Any]:
    """Coerce a JSON value to a list (InternetDB returns arrays; be defensive)."""
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


@tool(
    read_only=True,
    description=(
        "Look up a PUBLIC IP in Shodan InternetDB (free, no API key): open ports,"
        " CPEs, reverse-DNS hostnames, tags (cdn/cloud/self-signed), and known"
        " CVEs Shodan last observed. Opt-in online tool; skips private IPs."
    ),
)
async def shodan_internetdb(ip: str, *, settings: Settings) -> dict[str, Any]:
    """Fetch Shodan InternetDB's free, no-auth view of a public IP.

    Args:
        ip: the IP to look up. Must be a public, internet-routable address —
            private / reserved / loopback IPs are skipped (nothing for a public
            asset DB to know, and sending one out would leak internal topology).
        settings: app settings. Reads the ``allow_online_enrichment`` gate and
            the shared online-enrichment timeout / TLS policy.

    Returns:
        On success: ``{"ip", "observed": True, "ports", "cpes", "hostnames",
        "tags", "vulns"}`` — the lists InternetDB reports (empty when absent).
        When online enrichment is disabled: the gate's clean ``available: False``
        dict (no network I/O). For a private/reserved IP: ``{"available": False,
        "reason": "private_ip", ...}``. When Shodan has no record (HTTP 404):
        ``{"ip", "observed": False, ...}``. On any HTTP / network failure:
        ``{"error": True, "message": ...}``. NEVER raises — the caller is an LLM
        tool boundary.
    """
    # Gate FIRST — no per-provider key required (InternetDB is unauthenticated),
    # so this is the master allow_online_enrichment flag only. A returned dict
    # short-circuits with no network I/O.
    gate = online_unavailable(settings)
    if gate is not None:
        return gate

    # Never send an internal / reserved address to a third-party asset DB.
    if not _is_routable_public_ip(ip):
        return {
            "ip": ip,
            "available": False,
            "reason": "private_ip",
            "hint": (
                "Shodan InternetDB only knows internet-routable hosts; private,"
                " reserved or loopback IPs are skipped (and never sent off-box)."
            ),
        }

    url = f"{_BASE_URL}/{ip}"
    try:
        async with online_client(settings) as client:
            resp = await client.get(url)
    except httpx.HTTPError as e:
        _LOGGER.warning("shodan_internetdb request failed for %s: %s", ip, e)
        return {"error": True, "message": f"{type(e).__name__}: {e}"}
    except Exception as e:  # pragma: no cover - belt-and-suspenders, never raise
        _LOGGER.warning("shodan_internetdb unexpected error for %s: %s", ip, e)
        return {"error": True, "message": f"{type(e).__name__}: {e}"}

    # 404 = InternetDB has never seen this IP. That's a real answer (not exposed),
    # not an error.
    if resp.status_code == 404:
        return {
            "ip": ip,
            "observed": False,
            "summary": "no Shodan InternetDB record for this IP (not seen exposed)",
        }

    try:
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        _LOGGER.warning("shodan_internetdb bad response for %s: %s", ip, e)
        return {"error": True, "message": f"{type(e).__name__}: {e}"}

    if not isinstance(data, dict):
        return {"error": True, "message": f"unexpected response shape: {type(data).__name__}"}

    out: dict[str, Any] = {"ip": str(data.get("ip") or ip), "observed": True}
    for f in _LIST_FIELDS:
        out[f] = _as_str_list(data.get(f))
    return out
