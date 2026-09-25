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
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.tools._synth_scope import SynthScope, synth_scope_must_not

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

# A Windows host records who logged an account on, and from where, in its own
# security log: event 4624 with a network (3) or remote-interactive (10) logon
# type and a ``source.ip``. That record names the driver when no sensor saw the
# session as a flow. The range's DCSync landed as exactly this: an NTLM logon
# from the attacker box 70 ms before the replication events, under the same
# logon id, while the only flow-shaped session in the window was the lab's
# WinRM management plane. Service and local logons carry no origin address and
# are not sessions in this sense.
_LOGON_EVENT_CODE = "4624"
_NETWORK_LOGON_TYPES: tuple[str, ...] = ("3", "10")

# A host talking to itself is not a driver, whatever the spelling.
_SELF_ADDRESSES: tuple[str, ...] = ("127.0.0.1", "::1")

# How far back to look for the driving session, by default. An operator SSHes in
# and acts within minutes; a wider window buries the signal in unrelated
# sessions. The incident's gap was 96 seconds.
DEFAULT_LOOKBACK_MINUTES = 30

# Ceiling on ``lookback_minutes`` (30 days), the bound the other windowed read
# tools enforce. A non-positive lookback would put the window's start after its
# end: empty by construction, which the empty branch below would then report as
# the host having acted on its own. Refused instead, before ES is asked.
_MAX_LOOKBACK_MINUTES = 43_200

_MAX_SESSIONS = 25

# How many raw hits to read before collapsing them. A domain controller logs
# hundreds of network logons in half an hour, nearly all of them one machine
# account re-authenticating. One page of 25 raw hits then covers a few seconds
# and hides every other driver, so the tool reads wider and reports each
# distinct driver once.
_MAX_HITS = 200

# Sort key floor for a session whose timestamp did not parse.
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _parse_ts(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _preceding_window(lookback_minutes: int, time_anchor: datetime | None) -> dict[str, Any]:
    """``[anchor - lookback, anchor]`` — the window this tool actually claims.

    It used to borrow ``query_events._build_time_filter``, which CENTERS an
    anchored window on the anchor. Centering is right there, where the caller
    asked for context around an alert. It is wrong here: every sentence this
    tool produces says "in the N minutes BEFORE the activity", and at the default
    30 it was reading 15 minutes before and 15 minutes after. A driving session
    20 minutes earlier fell outside the window while sessions that happened after
    the alert were counted, named as peers, and offered as the closest preceding
    one. The empty branch is the sentence "nothing was observed driving this
    host, so its behavior appears self-originated", which is the kind of claim
    that has to be true.

    With no anchor (live callers with no alert to hang the question on) the
    window stays ``[now - lookback, now]``, which is already a preceding window.
    """
    if time_anchor is not None:
        gte = (time_anchor - timedelta(minutes=lookback_minutes)).isoformat()
        return {"range": {"@timestamp": {"gte": gte, "lte": time_anchor.isoformat()}}}
    return {"range": {"@timestamp": {"gte": f"now-{lookback_minutes}m", "lte": "now"}}}


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


def _build_query(
    ip: str,
    lookback_minutes: int,
    time_anchor: datetime | None,
    include_synth: SynthScope = False,
) -> dict[str, Any]:
    """Inbound (destination == ip) remote-access traffic in the window.

    Matched either by remote-access DATASET or by well-known remote-access PORT,
    because a brief session frequently only lands as a bare ``zeek.conn`` flow.

    The second branch reads the host's own Windows security log: a 4624 with
    a network or remote-interactive logon type and a ``source.ip``. The host
    sits in ``host.ip`` there, so the destination term cannot cover it.
    """
    inbound_flow = {
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
            ]
        }
    }
    network_logon = {
        "bool": {
            "must": [
                {"term": {"host.ip": ip}},
                {"term": {"event.code": _LOGON_EVENT_CODE}},
                {"terms": {"winlog.event_data.LogonType": list(_NETWORK_LOGON_TYPES)}},
                {"exists": {"field": "source.ip"}},
            ]
        }
    }
    return {
        "bool": {
            "must": [
                {
                    "bool": {
                        "should": [inbound_flow, network_logon],
                        "minimum_should_match": 1,
                    }
                },
            ],
            "filter": [_preceding_window(lookback_minutes, time_anchor)],
            # Synth scope, threaded (not a hardcoded blanket exclude): prod
            # excludes every planted doc, a batch eval scopes to its own scenario
            # so the tool can see the plants it is being graded on. The host
            # logging an account on from its own address did not drive itself,
            # and a loopback address is the same statement in another spelling;
            # the loop below guards the direction invariant on the data too.
            "must_not": [
                *synth_scope_must_not(include_synth),
                {"terms": {"source.ip": [ip, *_SELF_ADDRESSES]}},
            ],
        }
    }


async def origin_chain(  # noqa: PLR0915 - one function reads as one procedure
    ip: str,
    *,
    elastic: Any,
    settings: Any,
    lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    time_anchor: datetime | None = None,
    include_synth: SynthScope = False,
) -> dict[str, Any]:
    """Remote-access sessions INBOUND to *ip* before the activity, time-ordered.

    ``time_anchor`` should be the alert's timestamp; ``closest_preceding`` is
    then the session that ended nearest before it — the most likely driver.
    """
    if not ip or not str(ip).strip():
        return {"error": True, "type": "ValueError", "message": "ip is required"}
    ip = str(ip).strip()
    if lookback_minutes <= 0 or lookback_minutes > _MAX_LOOKBACK_MINUTES:
        return {
            "error": True,
            "type": "ValueError",
            "message": (
                f"lookback_minutes must be between 1 and {_MAX_LOOKBACK_MINUTES}, "
                f"got {lookback_minutes}"
            ),
        }

    try:
        response = await elastic.search(
            index=settings.events_index_pattern,
            query=_build_query(ip, lookback_minutes, time_anchor, include_synth),
            size=_MAX_HITS,
            # Newest first. A busy host holds more sessions in the window than
            # the page returns, and the newest ones are the ones that can have
            # driven the activity; the page is put back in time order below.
            sort=[{"@timestamp": "desc"}],
        )
    except Exception as exc:  # ES down / bad pattern → clean dict, never a raise
        _LOGGER.warning("origin_chain failed for %s: %s", ip, exc)
        return _tool_error(exc)

    # One entry per driver: the (source, account) pair, newest first, so a
    # machine account re-authenticating 300 times in the window takes one slot
    # and every other driver keeps one of its own.
    collapsed: dict[tuple[str, str | None], dict[str, Any]] = {}
    for hit in getattr(response, "hits", None) or []:
        src = hit.get("_source", {}) if isinstance(hit, dict) else {}
        source_ip = (src.get("source") or {}).get("ip")
        # Guard the direction invariant: a hit where the host is the SOURCE is
        # its own outbound activity, which must never be read as its driver.
        # A loopback address is the same statement in another spelling.
        if not source_ip or source_ip == ip or source_ip in _SELF_ADDRESSES:
            continue
        ts = src.get("@timestamp")
        # Guard the time invariant the way the direction invariant above is
        # guarded. A session AFTER the activity did not drive it, and every
        # sentence this tool emits says "before". The range filter already
        # excludes them; this makes the claim true of the data, not of the query.
        parsed_ts = _parse_ts(ts)
        if time_anchor is not None and parsed_ts is not None and parsed_ts > time_anchor:
            continue
        session: dict[str, Any] = {
            "timestamp": ts,
            "source_ip": source_ip,
            "destination_port": (src.get("destination") or {}).get("port"),
            "dataset": (src.get("event") or {}).get("dataset"),
        }
        if str((src.get("event") or {}).get("code") or "") == _LOGON_EVENT_CODE:
            # A Windows logon names the account and the logon id, and the logon
            # id is what ties the session to the events it then performed.
            event_data = (src.get("winlog") or {}).get("event_data") or {}
            session["user"] = (src.get("user") or {}).get("name")
            session["logon_type"] = event_data.get("LogonType")
            session["logon_id"] = event_data.get("TargetLogonId")
            session["auth_package"] = event_data.get("AuthenticationPackageName")
        key = (source_ip, session.get("user"))
        seen = collapsed.get(key)
        if seen is None:
            session["events_in_window"] = 1
            collapsed[key] = session
            continue
        # Keep the NEWEST event of the pair, whatever order the page arrived
        # in: the question is which session could have driven the activity,
        # and that is the last one before it.
        session["events_in_window"] = seen["events_in_window"] + 1
        seen_ts, this_ts = _parse_ts(seen["timestamp"]), _parse_ts(session["timestamp"])
        if this_ts is not None and (seen_ts is None or this_ts > seen_ts):
            collapsed[key] = session
        else:
            seen["events_in_window"] = session["events_in_window"]

    sessions = list(collapsed.values())
    if not sessions:
        return _empty(ip, lookback_minutes)

    sessions.sort(
        key=lambda s: (_parse_ts(s["timestamp"]) is None, _parse_ts(s["timestamp"]) or _EPOCH)
    )
    sessions = sessions[-_MAX_SESSIONS:]

    closest: dict[str, Any] | None = None
    if time_anchor is not None:
        # Every surviving session is at or before the anchor, so the newest is
        # the likeliest driver (an operator acts shortly after logging in).
        preceding: list[tuple[dict[str, Any], datetime]] = []
        for s in sessions:
            parsed = _parse_ts(s["timestamp"])
            if parsed is not None:
                preceding.append((s, parsed))
        if preceding:
            session, ts = max(preceding, key=lambda pair: pair[1])
            closest = {**session, "seconds_before": (time_anchor - ts).total_seconds()}
    if closest is None:
        closest = {**sessions[-1], "seconds_before": None}

    peers = sorted({s["source_ip"] for s in sessions})
    closest_who = (
        f" logging on {closest['user']} (logon type {closest.get('logon_type')}, "
        f"logon id {closest.get('logon_id')})"
        if closest.get("user")
        else ""
    )
    return {
        "ip": ip,
        "observations": True,
        "inbound_sessions": sessions,
        "closest_preceding": closest,
        "lookback_minutes": lookback_minutes,
        "summary": (
            f"{len(sessions)} inbound remote-access session(s) to {ip} from "
            f"{', '.join(peers)} in the {lookback_minutes} minutes before the "
            f"activity; closest was {closest['source_ip']}{closest_who}"
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
