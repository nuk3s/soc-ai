"""``host_summary`` tool — "what host is this?" from data Security Onion already has.

The chat/investigator agent repeatedly mis-identifies hosts (it has called an
iPhone a "Mac" by anchoring on the ``like Mac OS X`` substring every mobile
Safari User-Agent carries). This READ-ONLY tool answers the identity question
directly from Zeek/ECS observations in the events index, and — critically —
returns the *evidence* string behind every guess so the agent (and the analyst)
can see what the call was made from instead of inferring it.

What it derives for one IP over a lookback window:

- ``hostname`` — from Zeek DHCP (``host_name``), DCE-RPC/SMB host announcements,
  or a reverse-DNS (PTR) answer, with the source noted in ``evidence``.
- ``device_os_guess`` — PARSED from HTTP ``user_agent`` strings (and Zeek
  ``software.log`` when present). The parser is **ordered most-specific-first**
  so ``iPhone`` / ``iPad`` / ``Android`` win over the generic ``Macintosh`` /
  ``Windows`` tokens (the iPhone-vs-Mac fix). The backing UA string is returned
  in ``evidence`` so the call is auditable.
- ``role_guess`` — server vs workstation, inferred from whether the host appears
  as a *responder* on well-known service ports (it offers services → server) vs
  only as an *originator* (it consumes services → workstation).
- ``first_seen`` / ``last_seen`` within the window; ``top_peers``; ``top_ports``;
  ``top_dns`` — small terms aggregations, capped tight.

Robustness contract (mirrors the other read tools):

- **Empty data** → a clean ``{"observations": False, "summary": "no
  observations for <ip> ..."}`` result, never an exception.
- **ES error / bad input** → a clean ``{"error": True, "message": ...}`` dict,
  never a raised exception (the agent reads the dict and moves on).
- Field names are resolved **ECS-first** via :mod:`soc_ai.so_client.fields`
  exactly like ``query_zeek`` / discovery: a modern grid populates ECS names
  (``user_agent.original``, ``dns.query.name``), older SO and the synth fixtures
  populate ``zeek.*`` — both resolve to the same logical value here.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections import Counter
from datetime import datetime
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client import fields
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import first_present, get_dotted
from soc_ai.tools._registry import tool
from soc_ai.tools.query_events import _build_time_filter

_LOGGER = logging.getLogger(__name__)

# How many sample docs to pull per signal. The aggregations carry the volume
# numbers; the hits are only for hostname/UA evidence + first/last timestamps,
# so a small page is plenty and keeps the next-turn context small.
_SAMPLE_SIZE = 200
# Cap distinct buckets per terms aggregation.
_AGG_SIZE = 10

# Well-known service ports — a host seen RESPONDING on one of these is offering a
# service (server signal). Originating a connection TO one is consuming it
# (workstation signal). Kept deliberately small + classic; the role guess is a
# hint, not a verdict.
_SERVER_PORTS: frozenset[int] = frozenset(
    {22, 53, 80, 88, 110, 143, 389, 443, 445, 636, 993, 995, 3306, 3389, 5432, 8080, 8443}
)

# ---------------------------------------------------------------------------
# Device / OS fingerprinting from a User-Agent (or software.log) string.
#
# ORDER MATTERS. Every mobile-Safari UA contains "like Mac OS X", and iPadOS
# Safari now reports "Macintosh" in desktop-mode — so the generic Mac/Windows/
# Linux tokens MUST be tried LAST, after the specific device tokens. This
# ordering is the whole point of the tool: it is the iPhone-vs-Mac fix.
# ---------------------------------------------------------------------------
_OS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # --- specific devices first ---
    ("iPhone", re.compile(r"\biPhone\b", re.IGNORECASE)),
    ("iPad", re.compile(r"\biPad\b", re.IGNORECASE)),
    ("iPod", re.compile(r"\biPod\b", re.IGNORECASE)),
    # Android must beat "Linux" (Android UAs say "Linux; Android 14").
    ("Android", re.compile(r"\bAndroid\b", re.IGNORECASE)),
    # Windows Phone before generic Windows.
    ("Windows Phone", re.compile(r"\bWindows Phone\b", re.IGNORECASE)),
    ("Chrome OS", re.compile(r"\bCrOS\b", re.IGNORECASE)),
    ("PlayStation", re.compile(r"\bPlayStation\b", re.IGNORECASE)),
    ("Smart TV", re.compile(r"\b(SmartTV|SMART-TV|AppleTV|BRAVIA|GoogleTV)\b", re.IGNORECASE)),
    # --- generic desktop OSes last ---
    ("Windows", re.compile(r"\bWindows NT\b", re.IGNORECASE)),
    ("macOS", re.compile(r"\bMacintosh\b", re.IGNORECASE)),
    ("Linux", re.compile(r"\bLinux\b", re.IGNORECASE)),
)


def classify_user_agent(ua: str) -> str | None:
    """Map a User-Agent (or software) string to a device/OS label, or ``None``.

    The patterns are tried in :data:`_OS_PATTERNS` order — specific device
    tokens (``iPhone``/``iPad``/``Android``) BEFORE the generic desktop tokens
    (``Macintosh``/``Windows``/``Linux``) — so a mobile-Safari UA that contains
    ``like Mac OS X`` is correctly classified as ``iPhone``, NOT ``macOS``. This
    ordering is the iPhone-vs-Mac defect fix.

    Returns ``None`` when nothing matches (e.g. a bare ``curl/8.4`` or empty
    string) so the caller can report the device as genuinely unknown rather than
    backfilling a guess.
    """
    if not ua:
        return None
    for label, pattern in _OS_PATTERNS:
        if pattern.search(ua):
            return label
    return None


# Candidate field tables for signals query_zeek's _COALESCE_FIELDS doesn't cover.
# ECS-first, zeek.* fallback — same convention as soc_ai.so_client.fields.
_DHCP_HOSTNAME: tuple[str, ...] = ("zeek.dhcp.host_name", "dhcp.host_name", "host.hostname")
_SMB_HOSTNAME: tuple[str, ...] = (
    "zeek.dce_rpc.named_pipe",  # weak; real announcement is below
    "zeek.smb.host_name",
    "smb.host_name",
)
_PTR_ANSWER: tuple[str, ...] = fields.DNS_RESOLVED_IP
_SOFTWARE: tuple[str, ...] = (
    "zeek.software.unparsed_version",
    "software.unparsed_version",
    "zeek.software.name",
    "software.name",
)


def _to_int_port(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _terms_agg(field_name: str, size: int = _AGG_SIZE) -> dict[str, Any]:
    """A plain terms aggregation on ``field_name``."""
    return {"terms": {"field": field_name, "size": size}}


def _bucket_pairs(agg: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Normalise a terms agg into ``[{value, count}]`` (or ``[]``)."""
    if not agg:
        return []
    out: list[dict[str, Any]] = []
    for b in agg.get("buckets") or []:
        key = b.get("key")
        if key is None or key == "":
            continue
        out.append({"value": key, "count": int(b.get("doc_count", 0))})
    return out


def _base_host_query(
    ip: str, time_range_minutes: int, time_anchor: datetime | None
) -> dict[str, Any]:
    """Events in the window where ``ip`` is either endpoint, excluding synth docs."""
    return {
        "bool": {
            "must": [
                {
                    "bool": {
                        "should": [
                            {"term": {"source.ip": ip}},
                            {"term": {"destination.ip": ip}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            ],
            "filter": [_build_time_filter(time_range_minutes, time_anchor)],
            # Synthetic-eval kill-switch — same as query_events_oql: never let a
            # synth fixture leak into a real host summary.
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }


def _empty_result(ip: str) -> dict[str, Any]:
    """The clean no-data result (NOT an error — absence is a real answer)."""
    return {
        "ip": ip,
        "observations": False,
        "summary": f"no observations for {ip} in the lookback window",
        "hostname": None,
        "device_os_guess": None,
        "role_guess": "unknown",
        "first_seen": None,
        "last_seen": None,
        "top_peers": [],
        "top_ports": [],
        "top_dns": [],
        "evidence": {},
    }


def _guess_role(ip: str, hits: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """server vs workstation from connection direction on well-known ports.

    Responding (``destination.ip == ip``) on a well-known service port means the
    host OFFERS that service → server signal. Only ORIGINATING (``source.ip ==
    ip``) connections to service ports → workstation signal. Returns
    ``(role, evidence)`` where role is ``server`` / ``workstation`` / ``unknown``.
    """
    server_ev: list[str] = []
    client_ev: list[str] = []
    for hit in hits:
        # CONNECTION-direction signal only — Suricata alert docs also carry
        # source/destination.ip + destination.port, so an inbound IDS alert
        # against a workstation (host == destination.ip on 443/445/3389) would
        # otherwise flip its role to "server". Restrict to Zeek conn records.
        if get_dotted(hit, "event.dataset") != "zeek.conn":
            continue
        src = get_dotted(hit, "source.ip")
        dst = get_dotted(hit, "destination.ip")
        dport = _to_int_port(get_dotted(hit, "destination.port"))
        if dport is None or dport not in _SERVER_PORTS:
            continue
        if dst == ip and len(server_ev) < 5:
            server_ev.append(f"responds on port {dport} (server)")
        elif src == ip and len(client_ev) < 5:
            client_ev.append(f"connects out to port {dport} (client)")
    if server_ev:
        return "server", server_ev
    if client_ev:
        return "workstation", client_ev
    return "unknown", []


def _resolve_hostname(hits: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    """Best hostname for the IP + the evidence string, or ``(None, None)``.

    Preference order: Zeek DHCP ``host_name`` > SMB/DCE-RPC host announcement >
    ECS ``host.name`` > a reverse-DNS (PTR) answer. A field carrying an IP rather
    than a name is rejected (``host.name`` sometimes holds the address).
    """
    for hit in hits:
        for source_label, candidates in (
            ("dhcp", _DHCP_HOSTNAME),
            ("smb/dce_rpc", _SMB_HOSTNAME),
            ("host.name", ("host.name",)),
        ):
            value = first_present(hit, candidates)
            if isinstance(value, str) and value and not _looks_like_ip(value):
                return value, f"{value} (from {source_label})"
    # PTR fallback: a reverse-DNS answer naming this IP (only if nothing better).
    for hit in hits:
        qname = first_present(hit, fields.DNS_QUERY)
        if isinstance(qname, str) and qname.lower().rstrip(".").endswith(
            (".in-addr.arpa", ".ip6.arpa")
        ):
            ans_str = _first_str(first_present(hit, _PTR_ANSWER))
            if ans_str and not _looks_like_ip(ans_str):
                return ans_str, f"{ans_str} (from DNS PTR)"
    return None, None


def _resolve_device_os(hits: list[dict[str, Any]]) -> tuple[str | None, list[str]]:
    """Device/OS guess + the UA evidence strings backing it.

    Parses each distinct HTTP User-Agent (or ``software.log`` string) via
    :func:`classify_user_agent`, whose ordering makes ``iPhone`` win over the
    generic ``Macintosh`` token. The FIRST classified UA sets the guess; up to 5
    backing strings are returned as evidence so the call is auditable.
    """
    device_os_guess: str | None = None
    ua_evidence: list[str] = []
    seen_uas: set[str] = set()
    for hit in hits:
        ua_str = _first_str(first_present(hit, fields.HTTP_USER_AGENT)) or _first_str(
            first_present(hit, _SOFTWARE)
        )
        if not ua_str or ua_str in seen_uas:
            continue
        seen_uas.add(ua_str)
        label = classify_user_agent(ua_str)
        if label is not None:
            if device_os_guess is None:
                device_os_guess = label
            if len(ua_evidence) < 5:
                ua_evidence.append(f"{label}: {ua_str[:200]}")
    return device_os_guess, ua_evidence


def _collect_top_peers(ip: str, aggregations: dict[str, Any]) -> list[dict[str, Any]]:
    """Top peer IPs (the OTHER endpoint) across both source/destination aggs.

    Self (``ip``) is dropped so a host doesn't list itself as a peer.
    """
    peer_counts: Counter[str] = Counter()
    for agg_name in ("peers_src", "peers_dst"):
        for pair in _bucket_pairs(aggregations.get(agg_name)):
            peer = str(pair["value"])
            if peer and peer != ip:
                peer_counts[peer] += int(pair["count"])
    return [{"value": peer, "count": count} for peer, count in peer_counts.most_common(_AGG_SIZE)]


@tool(
    read_only=True,
    description=(
        "Identify an internal host by IP from Security Onion data: hostname,"
        " device/OS (parsed from HTTP User-Agent — fixes iPhone-vs-Mac),"
        " server/workstation role, first/last seen, top peers/ports/DNS."
    ),
)
async def host_summary(
    ip: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    lookback_hours: int = 24,
    time_anchor: datetime | None = None,
) -> dict[str, Any]:
    """Summarise what host an IP is, from Zeek/ECS observations in the window.

    Args:
        ip: the host IP to characterise (internal IPs are fully supported — OQL/
            Zeek queries work across RFC1918 too).
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        lookback_hours: window size in hours. Default 24.
        time_anchor: when set, center the window on this timestamp instead of the
            now-relative default. The chat/investigator threads ``alert.timestamp``
            here so it finds evidence for an old alert.

    Returns:
        A dict with ``hostname`` / ``device_os_guess`` / ``role_guess`` /
        ``first_seen`` / ``last_seen`` / ``top_peers`` / ``top_ports`` /
        ``top_dns`` and an ``evidence`` sub-dict holding the raw strings backing
        each guess. On no data: a clean ``observations: False`` result. On an ES
        error or bad IP: a clean ``{"error": True, "message": ...}`` dict. NEVER
        raises — the caller is an LLM tool boundary.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": True, "type": "ValueError", "message": f"invalid IP: {ip}"}

    if lookback_hours <= 0:
        return {
            "error": True,
            "type": "ValueError",
            "message": f"lookback_hours must be positive, got {lookback_hours}",
        }

    index = settings.events_index_pattern
    time_range_minutes = lookback_hours * 60
    query = _base_host_query(ip, time_range_minutes, time_anchor)

    # Aggregations: peers (the OTHER endpoint), service ports the host responds
    # on, and DNS names it queried. Built as a single search so it's one round
    # trip. The peer aggs intentionally bucket BOTH endpoints; we drop self below.
    aggs: dict[str, Any] = {
        "peers_src": _terms_agg("source.ip"),
        "peers_dst": _terms_agg("destination.ip"),
        "resp_ports": {
            # Only Zeek conn records — alert docs carry destination.port too and
            # would inflate "ports this host serves" with IDS-targeted ports.
            "filter": {
                "bool": {
                    "must": [
                        {"term": {"destination.ip": ip}},
                        {"term": {"event.dataset": "zeek.conn"}},
                    ]
                }
            },
            "aggs": {"ports": _terms_agg("destination.port")},
        },
        "first_seen": {"min": {"field": "@timestamp"}},
        "last_seen": {"max": {"field": "@timestamp"}},
    }

    # Project the identity-bearing fields plus every UA/DNS candidate so we read
    # real values whether the grid is ECS or legacy zeek.*. Order-stable + dedup.
    source_fields: dict[str, None] = {}
    for f in (
        "@timestamp",
        "event.dataset",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "host.name",
    ):
        source_fields.setdefault(f, None)
    for candidates in (
        fields.HTTP_USER_AGENT,
        fields.DNS_QUERY,
        _DHCP_HOSTNAME,
        _SMB_HOSTNAME,
        _PTR_ANSWER,
        _SOFTWARE,
    ):
        for c in candidates:
            source_fields.setdefault(c, None)

    try:
        result = await elastic.search(
            index,
            query,
            size=_SAMPLE_SIZE,
            sort=[{"@timestamp": {"order": "asc"}}],
            source=list(source_fields),
            aggs=aggs,
            track_total_hits=True,
        )
    except Exception as e:
        _LOGGER.warning("host_summary ES search failed for %s: %s", ip, e)
        return {"error": True, "type": type(e).__name__, "message": str(e)}

    if result.total == 0 and not result.hits:
        return _empty_result(ip)

    hits = [h.get("_source", {}) for h in result.hits]
    aggregations = result.aggregations or {}
    evidence: dict[str, Any] = {}

    # --- hostname (DHCP host_name > SMB/DCE-RPC announcement > host.name > PTR) ---
    hostname, hostname_evidence = _resolve_hostname(hits)
    if hostname_evidence:
        evidence["hostname"] = hostname_evidence

    # --- device / OS guess (parse User-Agents — the iPhone-vs-Mac fix) ---
    device_os_guess, ua_evidence = _resolve_device_os(hits)
    if ua_evidence:
        evidence["device_os_guess"] = ua_evidence

    # --- role guess (server vs workstation from connection direction) ---
    role_guess, role_evidence = _guess_role(ip, hits)
    if role_evidence:
        evidence["role_guess"] = role_evidence

    # --- top peers (the OTHER endpoint), top ports, top dns ---
    top_peers = _collect_top_peers(ip, aggregations)
    top_ports = _bucket_pairs((aggregations.get("resp_ports") or {}).get("ports"))
    top_dns = _collect_top_dns(hits)

    # first/last seen — prefer the min/max aggregation; fall back to the sorted hits.
    first_seen = _agg_time(aggregations.get("first_seen")) or (
        get_dotted(hits[0], "@timestamp") if hits else None
    )
    last_seen = _agg_time(aggregations.get("last_seen")) or (
        get_dotted(hits[-1], "@timestamp") if hits else None
    )

    return {
        "ip": ip,
        "observations": True,
        "event_count": result.total,
        "hostname": hostname,
        "device_os_guess": device_os_guess,
        "role_guess": role_guess,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "top_peers": top_peers,
        "top_ports": top_ports,
        "top_dns": top_dns,
        "evidence": evidence,
    }


def _looks_like_ip(value: str) -> bool:
    """True iff ``value`` parses as an IP — a hostname field carrying an IP is
    not a real hostname, so we skip it."""
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _first_str(value: Any) -> str | None:
    """Coerce a field value (str or list-of-str) to a single non-empty string."""
    if isinstance(value, str):
        return value or None
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str) and item:
                return item
    return None


def _agg_time(agg: dict[str, Any] | None) -> str | None:
    """Read a min/max date aggregation's value (prefer the ISO string form)."""
    if not agg:
        return None
    as_string = agg.get("value_as_string")
    if isinstance(as_string, str) and as_string:
        return as_string
    value = agg.get("value")
    return str(value) if value is not None else None


def _collect_top_dns(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Top DNS query names seen in the sample (forward records only).

    Pulled from the sampled hits rather than a dedicated aggregation: DNS query
    names live on ``zeek.dns`` events and the sample already carries them, so a
    Counter over the projected field avoids a second round trip. Reverse-zone
    (PTR) names are excluded — they describe IPs, not what the host browsed.
    """
    counts: Counter[str] = Counter()
    for hit in hits:
        qname = _first_str(first_present(hit, fields.DNS_QUERY))
        if not qname:
            continue
        low = qname.lower().rstrip(".")
        if low.endswith((".in-addr.arpa", ".ip6.arpa")):
            continue
        counts[qname] += 1
    return [{"value": name, "count": count} for name, count in counts.most_common(_AGG_SIZE)]
