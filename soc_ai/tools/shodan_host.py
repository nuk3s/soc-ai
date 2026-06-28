"""``shodan_host`` tool — the FULL, authenticated Shodan host lookup (API key).

Where :mod:`soc_ai.tools.shodan_internetdb` is the free, keyless slice (ports /
cpes / vulns only), this is the paid ``/shodan/host/{ip}`` endpoint: it adds the
network owner (``org`` / ``isp`` / ``asn``), geolocation, the guessed ``os``,
and — most usefully — the per-service BANNERS Shodan last collected (product +
version + module per open port). It answers "what is this external host running,
who owns it, and is any of it known-vulnerable?" with far more depth than the
keyless tool, for the cost of an operator-supplied ``SHODAN_API_KEY``.

ONLINE + API-KEY, OFF BY DEFAULT. Same egress discipline as every tool in
:mod:`soc_ai.tools.online`:

1. :func:`online_unavailable` is consulted FIRST with ``requires_key=
   "shodan_api_key"`` — when the master ``allow_online_enrichment`` switch is off
   OR the key is unset, the tool returns that clean dict and makes NO request.
2. Private / reserved / internal IPs (incl. operator ``internal_cidrs``) are
   skipped locally — a public asset DB knows nothing about an internal host, and
   sending one out would leak internal topology. ``{available: False, reason:
   "private_ip"}``.
3. The raw response is huge (full banner text, TLS certs, HTTP bodies); we
   return a COMPACT projection — owner/geo/os, the open-port set, hostnames,
   the union of known CVEs, and a capped list of {port, product, version,
   module} service summaries — never the raw banners.
4. A 404 means Shodan has no record (``observed: False``), not an error. Any
   other HTTP / network / parse failure returns ``{error: ...}``. NEVER raises.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from soc_ai.config import Settings
from soc_ai.tools._registry import tool
from soc_ai.tools.online import is_internal_ip, online_client, online_unavailable

_LOGGER = logging.getLogger(__name__)

_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"

# Cap the per-service projection so a host with hundreds of banners can't blow
# up the tool result / context window.
_MAX_SERVICES = 25


def _collect_vulns(data: dict[str, Any]) -> list[str]:
    """Union of CVE ids from the top-level ``vulns`` and every service banner."""
    found: set[str] = set()

    def _add(v: Any) -> None:
        # Shodan reports vulns as either a {cve: detail} dict or a [cve] list;
        # iterating both yields the CVE ids.
        if isinstance(v, (dict, list)):
            found.update(str(k) for k in v)

    _add(data.get("vulns"))
    for svc in data.get("data") or []:
        if isinstance(svc, dict):
            _add(svc.get("vulns"))
    return sorted(found)


def _service_summaries(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Compact {port, transport, product, version, module} per banner (no raw text)."""
    out: list[dict[str, Any]] = []
    for svc in data.get("data") or []:
        if not isinstance(svc, dict):
            continue
        raw_meta = svc.get("_shodan")
        shodan_meta = raw_meta if isinstance(raw_meta, dict) else {}
        out.append(
            {
                "port": svc.get("port"),
                "transport": svc.get("transport"),
                "product": svc.get("product"),
                "version": svc.get("version"),
                "module": shodan_meta.get("module"),
            }
        )
        if len(out) >= _MAX_SERVICES:
            break
    return out


@tool(
    read_only=True,
    description=(
        "Full Shodan host lookup for a PUBLIC IP (needs SHODAN_API_KEY): network"
        " owner (org/isp/asn), geo, guessed OS, open ports, per-service banners"
        " (product/version), and known CVEs. Online opt-in; skips private IPs."
    ),
)
async def shodan_host(ip: str, *, settings: Settings) -> dict[str, Any]:
    """Authenticated Shodan ``/shodan/host`` lookup for a public IP. Never raises.

    Args:
        ip: a PUBLIC, internet-routable address. Private / reserved / internal
            IPs (incl. ``internal_cidrs``) are skipped — nothing for a public
            asset DB to know, and an internal IP must never be sent off-box.
        settings: app settings — the ``allow_online_enrichment`` gate, the
            ``shodan_api_key``, and the shared online timeout / TLS policy.

    Returns:
        On success a COMPACT projection: ``{"ip", "observed": True, "org",
        "isp", "asn", "country", "city", "os", "last_update", "ports",
        "hostnames", "domains", "tags", "vulns", "services"}`` (services capped,
        no raw banners). Gate dict when disabled/unkeyed (no I/O); ``{available:
        False, reason: "private_ip"}`` for an internal IP; ``{observed: False}``
        on 404; ``{error: ...}`` on any other failure.
    """
    # 1. Egress + key gate FIRST — no network I/O when disabled / unkeyed.
    gate = online_unavailable(settings, requires_key="shodan_api_key")
    if gate is not None:
        return gate

    ip = (ip or "").strip()
    if not ip:
        return {"error": "empty ip"}

    # 2. Never send an internal / non-routable address to Shodan.
    if is_internal_ip(ip, settings):
        return {
            "ip": ip,
            "available": False,
            "reason": "private_ip",
            "hint": (
                "Shodan only knows internet-routable hosts; private, reserved or"
                " internal IPs are skipped (and never sent off-box)."
            ),
        }

    assert settings.shodan_api_key is not None  # guaranteed by the gate above
    key = settings.shodan_api_key.get_secret_value()
    url = _HOST_URL.format(ip=ip)
    try:
        async with online_client(settings) as client:
            # Fetch the full record (minify=false) so the structured per-service
            # fields we DO surface (product/version/module) are never stripped;
            # the bulky raw banner / cert / http blobs are dropped in our own
            # _service_summaries projection, so they never cross the tool boundary.
            resp = await client.get(url, params={"key": key, "minify": "false"})
    except httpx.HTTPError as e:
        _LOGGER.warning("shodan_host request failed for %s: %s", ip, e)
        return {"error": True, "message": f"{type(e).__name__}: {e}"}
    except Exception as e:  # pragma: no cover - belt-and-suspenders, never raise
        _LOGGER.warning("shodan_host unexpected error for %s: %s", ip, e)
        return {"error": True, "message": f"{type(e).__name__}: {e}"}

    # 404 = Shodan has no record for this IP. A real answer, not an error.
    if resp.status_code == 404:
        return {
            "ip": ip,
            "observed": False,
            "summary": "no Shodan record for this IP (not seen exposed)",
        }
    if resp.status_code == 401:
        return {"error": True, "message": "shodan rejected the API key (HTTP 401)"}
    if resp.status_code != 200:
        return {"error": True, "message": f"shodan HTTP {resp.status_code}", "ip": ip}

    try:
        data = resp.json()
    except ValueError as e:
        _LOGGER.warning("shodan_host bad response for %s: %s", ip, e)
        return {"error": True, "message": f"{type(e).__name__}: {e}"}
    if not isinstance(data, dict):
        return {"error": True, "message": f"unexpected response shape: {type(data).__name__}"}

    return {
        "ip": str(data.get("ip_str") or ip),
        "observed": True,
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "country": data.get("country_name"),
        "city": data.get("city"),
        "os": data.get("os"),
        "last_update": data.get("last_update"),
        "ports": sorted({p for p in (data.get("ports") or []) if isinstance(p, int)}),
        "hostnames": list(data.get("hostnames") or []),
        "domains": list(data.get("domains") or []),
        "tags": list(data.get("tags") or []),
        "vulns": _collect_vulns(data),
        "services": _service_summaries(data),
    }
