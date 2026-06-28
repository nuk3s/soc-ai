"""``cve_lookup`` tool — free CVE scoring from Shodan's CVEDB (no API key).

Shodan's CVEDB (https://cvedb.shodan.io/cve/<id>) is a free, unauthenticated
lookup that returns the data an analyst actually needs to PRIORITISE a CVE:
the CVSS base score, the EPSS exploit-probability (and its percentile ranking),
and whether the CVE is in CISA's Known-Exploited-Vulnerabilities (KEV) catalog
— plus a short summary and references. When an alert (or a Shodan host result)
names a CVE, this turns the bare id into "how bad / how likely-exploited / is it
actively-exploited in the wild".

ONLINE, NO KEY. It reaches the public internet, so — like the other online
tools — it is gated behind the master ``allow_online_enrichment`` switch and
returns a clean, NON-RAISING dict on every path. No per-provider key is needed.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from soc_ai.config import Settings
from soc_ai.tools._registry import tool
from soc_ai.tools.online import online_client, online_unavailable

_LOGGER = logging.getLogger(__name__)

_CVE_URL = "https://cvedb.shodan.io/cve/{cve}"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@tool(
    read_only=True,
    description=(
        "Look up a CVE in Shodan CVEDB (free, no key): CVSS base score, EPSS"
        " exploit-probability + ranking, CISA KEV (actively-exploited) flag,"
        " summary and references. Online opt-in. Use to PRIORITISE a named CVE."
    ),
)
async def cve_lookup(cve_id: str, *, settings: Settings) -> dict[str, Any]:
    """Fetch CVSS / EPSS / KEV scoring for *cve_id* from CVEDB. Never raises.

    Args:
        cve_id: a CVE identifier, e.g. ``CVE-2021-44228``. Validated against the
            ``CVE-YYYY-N+`` shape and upper-cased before the request.
        settings: app settings — reads the ``allow_online_enrichment`` gate and
            the shared online-enrichment timeout / TLS policy. No key required.

    Returns:
        On a hit: ``{"cve_id", "found": True, "summary", "cvss", "cvss_version",
        "epss", "ranking_epss", "kev", "propose_action", "ransomware_campaign",
        "references", "published_time"}``. The gate dict when online enrichment
        is disabled (no I/O). ``{"error": "invalid CVE id"}`` for a malformed id.
        ``{"cve_id", "found": False}`` on a 404 (CVEDB has no such record). Any
        HTTP / network / parse failure → ``{"error": ...}``.
    """
    # Gate FIRST — no key required (CVEDB is unauthenticated), so this is the
    # master allow_online_enrichment flag only. A returned dict skips network I/O.
    gate = online_unavailable(settings)
    if gate is not None:
        return gate

    cve = (cve_id or "").strip().upper()
    if not _CVE_RE.match(cve):
        return {
            "error": "invalid CVE id",
            "hint": "expected the form CVE-YYYY-NNNN",
            "cve_id": cve_id,
        }

    url = _CVE_URL.format(cve=cve)
    try:
        async with online_client(settings) as client:
            resp = await client.get(url)
        if resp.status_code == 404:
            return {"cve_id": cve, "found": False, "summary": "no CVEDB record for this CVE"}
        if resp.status_code != 200:
            return {"error": f"cvedb HTTP {resp.status_code}", "cve_id": cve}
        data = resp.json()
    except Exception as e:  # graceful — a lookup failure is a normal error result
        _LOGGER.warning("cve_lookup failed for %s: %s", cve, type(e).__name__)
        return {"error": type(e).__name__, "cve_id": cve}

    if not isinstance(data, dict):
        return {"error": "cvedb returned a non-object body", "cve_id": cve}

    return {
        "cve_id": str(data.get("cve_id") or cve),
        "found": True,
        "summary": data.get("summary"),
        "cvss": data.get("cvss"),
        "cvss_version": data.get("cvss_version"),
        "epss": data.get("epss"),
        "ranking_epss": data.get("ranking_epss"),
        "kev": bool(data.get("kev", False)),
        "propose_action": data.get("propose_action"),
        "ransomware_campaign": data.get("ransomware_campaign"),
        "references": list(data.get("references") or [])[:20],
        "published_time": data.get("published_time"),
    }
