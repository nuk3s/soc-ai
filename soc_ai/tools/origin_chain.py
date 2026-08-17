"""``origin_chain`` tool — "who was driving this host?"

The question an entry-level analyst asks on reflex when an INTERNAL host is the
apparent source of hostile activity: *is someone on that box?* soc-ai did not
ask it during the 2026-08-05 incident. It attributed SSH username-probing to
internal host 192.168.10.202 and stopped — while holding, in the indices it was
already querying, fifteen events (including a ``zeek.ssh`` record) showing
192.168.20.226 opening an SSH session TO .202 ninety seconds earlier. The real
actor was one pivot away and never got named.

``host_summary`` cannot answer this, by construction: its ``top_peers`` is a
volume-ranked terms aggregation over a 24-hour window, so a two-second SSH
session is statistically invisible beside thousands of routine events, and an
aggregation carries no ordering — "immediately before" is not expressible in it.

This tool answers exactly one question, narrowly: which remote-access sessions
arrived AT this host, in the window preceding the activity, in time order. Both
answers are load-bearing for a verdict:

- **Sessions found** → the host is a waypoint, not the origin. Attribute the
  behavior upstream and pivot again on that source.
- **No sessions** → the host acted autonomously. That is a genuinely different
  (and usually worse) finding, so absence is reported as a result, never as an
  empty shrug.

Read-only. Robustness contract mirrors the other read tools: empty data is a
clean result, any ES/input failure is a clean ``{"error": True, ...}`` dict, and
nothing raises into the agent loop.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from soc_ai.tools.query_events import _build_time_filter

_LOGGER = logging.getLogger(__name__)

# Datasets that carry an interactive / remote-access session. These are the
# protocols by which one host comes to be DRIVING another — the only inbound
# traffic that explains subsequent outbound behavior. Deliberately narrow: a
# host receiving HTTP is not thereby being operated.
_REMOTE_ACCESS_DATASETS: tuple[str, ...] = (
    "zeek.ssh",
    "zeek.rdp",
    "zeek.ntlm",
    "zeek.smb_mapping",
    "system.auth",
)
# Ports that mean the same thing when the dataset is a bare flow record
# (zeek.conn), which is what a short session often lands as.
_REMOTE_ACCESS_PORTS: tuple[int, ...] = (22, 3389, 5985, 5986, 5900, 23)

# How far back to look for the driving session, by default. An operator SSHes in
# and acts within minutes; a wider window buries the signal in unrelated
# sessions. The incident's gap was 96 seconds.
DEFAULT_LOOKBACK_MINUTES = 30

_MAX_SESSIONS = 25


def _parse_ts(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _empty(ip: str, lookback_minutes: int) -> dict[str, Any]:
    """No inbound session — a REAL finding: the host acted on its own."""
    return {
        "ip": ip,
        "observations": False,
        "inbound_sessions": [],
        "closest_preceding": None,
        "lookback_minutes": lookback_minutes,
        "summary": (
            f"no inbound remote-access sessions to {ip} in the {lookback_minutes} "
            "minutes before the activity — nothing was observed driving this host, "
            "so its behavior appears self-originated (or the driving session is not "
            "covered by current telemetry)"
        ),
    }


def _tool_error(exc: BaseException) -> dict[str, Any]:
    return {"error": True, "type": type(exc).__name__, "message": str(exc)}


def _build_query(ip: str, lookback_minutes: int, time_anchor: datetime | None) -> dict[str, Any]:
    """Inbound (destination == ip) remote-access traffic in the window.

    Matched either by remote-access DATASET or by well-known remote-access PORT,
    because a brief session frequently only lands as a bare ``zeek.conn`` flow.
    """
    return {
        "bool": {
            "must": [
                {"term": {"destination.ip": ip}},
                {
                    "bool": {
                        "should": [
                            {"terms": {"event.dataset": list(_REMOTE_ACCESS_DATASETS)}},
                            {"terms": {"destination.port": list(_REMOTE_ACCESS_PORTS)}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            ],
            "filter": [_build_time_filter(lookback_minutes, time_anchor)],
            # Never let a synthetic eval fixture masquerade as a real session
            # (same kill-switch as query_events_oql / host_summary).
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }


async def origin_chain(
    ip: str,
    *,
    elastic: Any,
    settings: Any,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    time_anchor: datetime | None = None,
) -> dict[str, Any]:
    """Remote-access sessions INBOUND to *ip* before the activity, time-ordered.

    ``time_anchor`` should be the alert's timestamp; ``closest_preceding`` is
    then the session that ended nearest before it — the most likely driver.
    """
    if not ip or not str(ip).strip():
        return {"error": True, "type": "ValueError", "message": "ip is required"}
    ip = str(ip).strip()

    try:
        response = await elastic.search(
            index=settings.events_index_pattern,
            query=_build_query(ip, lookback_minutes, time_anchor),
            size=_MAX_SESSIONS,
            sort=[{"@timestamp": "asc"}],
        )
    except Exception as exc:  # ES down / bad pattern → clean dict, never a raise
        _LOGGER.warning("origin_chain failed for %s: %s", ip, exc)
        return _tool_error(exc)

    sessions: list[dict[str, Any]] = []
    for hit in getattr(response, "hits", None) or []:
        src = hit.get("_source", {}) if isinstance(hit, dict) else {}
        source_ip = (src.get("source") or {}).get("ip")
        # Guard the direction invariant: a hit where the host is the SOURCE is
        # its own outbound activity, which must never be read as its driver.
        if not source_ip or source_ip == ip:
            continue
        ts = src.get("@timestamp")
        sessions.append(
            {
                "timestamp": ts,
                "source_ip": source_ip,
                "destination_port": (src.get("destination") or {}).get("port"),
                "dataset": (src.get("event") or {}).get("dataset"),
            }
        )

    if not sessions:
        return _empty(ip, lookback_minutes)

    closest: dict[str, Any] | None = None
    if time_anchor is not None:
        # Sessions at or before the anchor, newest last — the nearest one is the
        # likeliest driver (an operator acts shortly after logging in).
        preceding: list[tuple[dict[str, Any], datetime]] = []
        for s in sessions:
            parsed = _parse_ts(s["timestamp"])
            if parsed is not None and parsed <= time_anchor:
                preceding.append((s, parsed))
        if preceding:
            session, ts = max(preceding, key=lambda pair: pair[1])
            closest = {**session, "seconds_before": (time_anchor - ts).total_seconds()}
    if closest is None:
        closest = {**sessions[-1], "seconds_before": None}

    peers = sorted({s["source_ip"] for s in sessions})
    return {
        "ip": ip,
        "observations": True,
        "inbound_sessions": sessions,
        "closest_preceding": closest,
        "lookback_minutes": lookback_minutes,
        "summary": (
            f"{len(sessions)} inbound remote-access session(s) to {ip} from "
            f"{', '.join(peers)} in the {lookback_minutes} minutes before the "
            f"activity; closest was {closest['source_ip']}"
            + (
                f" {closest['seconds_before']:.0f}s before"
                if closest.get("seconds_before") is not None
                else ""
            )
            + f" ({closest.get('dataset')}). This host may be a WAYPOINT rather than "
            "the origin — attribute upstream and pivot on that source before "
            "blaming this host."
        ),
    }
