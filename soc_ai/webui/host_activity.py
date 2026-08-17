"""Live host activity: who a host talks to, how much, and over what ports.

The host page runs a SPLIT freshness contract. Identity — hostname, role, OS,
criticality — comes out of the dossier: swept on a schedule, resolver-computed,
and still answerable when the Security Onion grid is unreachable. Activity is the
other half, and it cannot be served that way. A cached peer list would show a
host as quiet while it is beaconing, which is the one reading the page exists to
prevent, so everything here is read off the grid on the request that renders it.

That makes query cost the design constraint. Peers AND volume come out of ONE
``size=0`` search: the two directions are filter sub-aggregations of the same
pass, because a host's peer list is meaningless without knowing which side it
was on — a port this host ANSWERS on is a service it offers, the same port
outbound is one it consumes (the distinction :mod:`soc_ai.dossier.observe` draws
for the same reason).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.webui.alerts_query import (
    # Module-private on the sibling, imported anyway: it is the ONE spelling of
    # where Security Onion nests an endpoint detection's agent address, and a
    # second copy here would drift the moment that path changes.
    _NESTED_HOST_IP,
    NOTICE_SOURCE_OQL,
    SIGMA_SOURCE_OQL,
    TIME_RANGES,
    build_filter,
)

_LOGGER = logging.getLogger(__name__)

# The ranges the host page offers. Deliberately two: this is a "what is it doing
# lately" panel, not the alerts console's time picker, and each range has a
# histogram interval chosen to keep the volume chart readable.
ACTIVITY_RANGES: tuple[str, ...] = ("24h", "7d")
DEFAULT_RANGE = "24h"
_VOLUME_INTERVAL: dict[str, str] = {"24h": "hour", "7d": "day"}

# Rows the peer table shows. A busy server talks to hundreds of addresses; past
# a dozen the panel stops being a summary and the analyst should be in the
# alerts console or a hunt instead.
MAX_PEERS = 12

# Terms-agg width PER DIRECTION, wider than MAX_PEERS on purpose: the two
# directional buckets are merged and re-sorted here, so cutting each side at 12
# would let a peer that is 7th inbound and 7th outbound — 14th by neither
# measure, but 2nd once summed — fall out of a list it belongs at the top of.
_PEER_AGG_SIZE = 25

# Ports per peer — the terms width on EACH direction, and the cap on the merged
# set the row renders. Deliberately small: a peer reached on more than a handful
# of ports is a scan, and what makes that legible is the connection count, not a
# longer list of ports.
_PORTS_PER_PEER = 5

# ``alerts_7d`` is SEVEN DAYS whatever the peer table is showing. The number
# answers "has anything fired on this machine lately", which a 24h view would
# keep resetting to zero; the alerted-edge FLAG is scoped to the chosen range
# instead, since a peer that fired last Tuesday is not what a 24h table is about.
ALERT_WINDOW = "7d"

# Peer addresses pulled from the detection pass. This is an INTERSECTION set,
# not a display list, and it fails in the unsafe direction: a peer that really
# did alert but falls outside these buckets renders `alerted: False`, turning a
# security signal into "nothing here". A scanned host — precisely the host
# someone opens this page for — can carry hundreds of distinct alerting peers
# over seven days, so this is deliberately far wider than the twelve peers that
# can possibly be displayed. Buckets are cheap; a quietly unflagged peer is not.
#
# Residual, and unavoidable with a terms agg: a host with more than this many
# distinct alerting peers can still have a displayed peer come back unflagged.
# At that point the count itself (`alerts_7d`) is the signal, not the per-row flag.
_ALERT_PEER_AGG_SIZE = 500

# Accounts listed for a host, with one bucket of headroom. Documents MISSING
# user.name are omitted by a terms agg and cost nothing — but a document that
# literally stores an empty string DOES get its own bucket (measured: a real
# grid carries a small number of both), and so does a name whose only difference
# is surrounding whitespace. Both are discarded or folded on the way out, so the
# spare bucket keeps that from costing a genuine account its slot.
MAX_USERS = 10
_USER_AGG_SIZE = MAX_USERS + 1

# The host-log datasets the user lane reads. Linux only today: Windows logon
# events land in `system.security`/`winlog.*` under different field names, and
# aggregating those as-is would list machine accounts (`HOST$`) as users.
_AUTH_DATASETS: tuple[str, ...] = ("system.auth",)

# Agent-name buckets on the auth pass. TWO is the whole requirement: the gate
# asks "did more than one machine write these documents", and one bucket of
# headroom over the answer it wants is enough to tell 1 from many.
_AGENT_AGG_SIZE = 2


@dataclass
class HostPeer:
    """One address this host exchanged traffic with, and how.

    ``direction`` is from THIS host's point of view: "out" = it originated,
    "in" = it answered, "both" = each. ``ports`` are the conversation's
    destination ports across both directions — for an inbound peer that is a
    service this host offers, for an outbound one a service it consumes.

    ``events`` is APPROXIMATE. It is the sum of two terms-aggregation doc
    counts, which Elasticsearch computes per shard and merges, so on a sharded
    index it can be slightly off. It is sound for ranking peers against each
    other — which is all this list uses it for — but it is not an exact count,
    and a surface that renders it should not invite one to be reconciled
    against the alerts console.
    """

    ip: str
    hostname: str | None = None
    direction: str = "out"
    ports: list[int] = field(default_factory=list)
    events: int = 0
    alerted: bool = False


@dataclass
class VolumePoint:
    """One histogram bucket: connections in the interval starting at ``ts``.

    The list length is NOT fixed and does not necessarily span the whole range.
    Elasticsearch fills interior gaps but not the edges, so a host that was
    silent until this morning returns buckets starting this morning. Render from
    the timestamps; do not index by position or assume 24 of them.
    """

    ts: str
    events: int


@dataclass
class UserSeen:
    """An account seen authenticating on this host, from its own auth log."""

    name: str
    events: int
    last_seen: str


@dataclass
class LatestInvestigation:
    """The newest investigation soc-ai has run involving this address."""

    id: str
    verdict: str | None
    ts: str


@dataclass
class HostActivity:
    """One host's live activity panel.

    ``users`` is ``None``, not ``[]``, when the grid holds no host-log
    authentication documents for this address. The two states read very
    differently — "nobody logged in" is a finding, "no auth telemetry" is a gap
    in coverage — and collapsing them into an empty list would state the first
    while meaning the second.

    ``None`` is WINDOW-scoped, and the page copy must not claim more than that.
    It means "no auth documents in the selected range", which a host that ships
    auth logs but was idle for 24h will also return. Word it as "no host auth
    logs in the last 24h" and never as "this machine ships no host logs" — the
    query cannot tell those apart and neither can the page.

    ``None`` covers a third case, rarer and deliberately folded in: an address
    SEVERAL agents claim (a docker or hypervisor bridge, an address DHCP
    recycled inside the window). The auth documents exist, but they were written
    by several machines, so no account list can be attributed to this address —
    see :func:`_uniquely_claimed`. Folded in because the alternative is listing
    another machine's logins as this host's, and because distinguishing it on
    the wire would be a field the page has nowhere to say. If the users card
    ever needs to explain that state, this is the discriminant to add.

    ``peers_truncated`` / ``users_truncated`` are set by the fold that CUT the
    list, from the pre-cut length — never re-derived downstream. The frontend
    used to infer truncation by comparing list lengths against copied cap
    constants, which reads a host with exactly-cap entries as a cut list and
    goes quietly wrong the day a cap moves.
    """

    peers: list[HostPeer] = field(default_factory=list)
    volume: list[VolumePoint] = field(default_factory=list)
    users: list[UserSeen] | None = None
    alerts_7d: int = 0
    latest_investigation: LatestInvestigation | None = None
    # The ranked fold held more than MAX_PEERS peers, so rows fell off the end.
    peers_truncated: bool = False
    # The folded account list held more than MAX_USERS names. Always False when
    # ``users`` is None: an absent list is not a cut one.
    users_truncated: bool = False


# Both lookups are INJECTED rather than imported. This module sits in the query
# layer and knows only Elasticsearch; the route owns the database session, so
# handing it two callables keeps host_activity testable without a DB and keeps a
# store import out of a module the CLI and the dossier prompt also reach for.
PeerNameLookup = Callable[[list[str]], Awaitable[dict[str, str]]]
InvestigationLookup = Callable[[str], Awaitable[LatestInvestigation | None]]


def _unwrap[T](outcome: T | BaseException) -> T:
    """Return a gathered result, or re-raise its failure UNWRAPPED.

    ``asyncio.gather(..., return_exceptions=True)`` rather than a TaskGroup, and
    rather than letting the first failure propagate on its own. Two different
    reasons:

    * A TaskGroup raises an ``ExceptionGroup``, which no longer matches the
      ``TransportError`` / ``OqlValidationError`` arms every other console route
      degrades on — the route would answer 500 where the console answers 503.
    * A bare ``gather`` propagates the first failure but does NOT cancel its
      siblings. The route raises while two ES searches are still in flight,
      outliving the request that asked for them and escaping the accounting of
      the ``asyncio.timeout`` wrapped around the call. ``return_exceptions=True``
      waits for every child, so nothing outlives the request and the timeout
      supervises all three.

    (Sibling exceptions are retrieved either way — ``gather`` marks them
    retrieved in its done-callback, so this is NOT about "never retrieved"
    warnings. Verified against the interpreter, under a loop exception handler.)
    """
    if isinstance(outcome, BaseException):
        raise outcome
    return outcome


async def _latest_investigation(
    lookup: InvestigationLookup | None, ip: str
) -> LatestInvestigation | None:
    """The investigation lookup as an awaitable, so it can join the fan-out.

    DEGRADED, not propagated. This lookup reads the DATABASE, and the route
    above only knows how to answer an ``OqlValidationError`` or an
    Elasticsearch ``TransportError`` / ``TimeoutError`` — so a SQLAlchemy error
    here used to turn a fully successful grid read into a bare 500, which the
    page renders as its grid-unavailable card ("Everything below comes from the
    network sweep and is unaffected"). That blames Security Onion for a database
    problem, at exactly the moment somebody is debugging one.

    What it costs is a LINK to the newest investigation. The peers, the volume,
    the users and the alert count all came back; charging the analyst for those
    to report a missing hyperlink is the wrong trade.

    ``Exception``, deliberately not ``BaseException``: the route wraps this call
    in ``asyncio.timeout``, which works by CANCELLING it, and a degrade that
    swallowed the cancellation would return a partial panel where the endpoint
    owes a 503.
    """
    if lookup is None:
        return None
    try:
        return await lookup(ip)
    except Exception as exc:
        _LOGGER.warning("host activity: investigation lookup failed for %s: %s", ip, exc)
        return None


def _supported(time_range: str) -> str:
    """A range this module can bucket, falling back to the default."""
    return time_range if time_range in ACTIVITY_RANGES else DEFAULT_RANGE


def _window(time_range: str) -> str:
    """The ``now-N`` anchor for a range, falling back to the default."""
    return TIME_RANGES[_supported(time_range)]


def _either_endpoint(ip: str) -> dict[str, Any]:
    """Match documents where ``ip`` is on EITHER side of the flow."""
    return {
        "bool": {
            "should": [{"term": {"source.ip": ip}}, {"term": {"destination.ip": ip}}],
            "minimum_should_match": 1,
        }
    }


def _conn_query(ip: str, window: str) -> dict[str, Any]:
    """zeek.conn only: an alert document also carries source/destination.ip, and
    counting one would inflate a peer's connection total with the detections that
    describe those same connections."""
    return {
        "bool": {
            "filter": [
                {"term": {"event.dataset": "zeek.conn"}},
                {"range": {"@timestamp": {"gte": window}}},
                _either_endpoint(ip),
            ],
            # The same kill-switch every dossier query carries: a synthetic-eval
            # fixture must never be able to describe a real machine's traffic.
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }


def _peer_aggs(peer_field: str) -> dict[str, Any]:
    return {
        "peers": {
            "terms": {"field": peer_field, "size": _PEER_AGG_SIZE},
            "aggs": {"ports": {"terms": {"field": "destination.port", "size": _PORTS_PER_PEER}}},
        }
    }


def _conn_aggs(ip: str, interval: str) -> dict[str, Any]:
    return {
        # "out" keys on destination.ip because the OTHER endpoint is the peer;
        # "in" mirrors it. Both read destination.port, which is the service port
        # of the conversation whichever side this host was on.
        "out": {
            "filter": {"term": {"source.ip": ip}},
            "aggs": _peer_aggs("destination.ip"),
        },
        "in": {
            "filter": {"term": {"destination.ip": ip}},
            "aggs": _peer_aggs("source.ip"),
        },
        # min_doc_count 0 so an idle hour renders as a zero in the chart rather
        # than closing up and making a quiet host look continuously busy. No
        # extended_bounds: ES fills interior gaps but not the edges, so the
        # series starts at the host's first activity and the bucket COUNT is not
        # fixed. Padding it would mean anchoring "now" here, and this module
        # deliberately leaves the clock to Elasticsearch.
        "volume": {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": interval,
                "min_doc_count": 0,
            }
        },
    }


def _buckets(agg: Any, *path: str) -> list[dict[str, Any]]:
    """Walk a nested aggregation to its bucket list, tolerating absence.

    An aggregation the grid did not return (a mapping it refused, a filter that
    matched nothing) reads as no buckets, so one missing sub-agg costs its own
    row and not the whole panel.
    """
    node: Any = agg
    for key in path:
        if not isinstance(node, dict):
            return []
        node = node.get(key)
    buckets = (node or {}).get("buckets") if isinstance(node, dict) else None
    return list(buckets) if isinstance(buckets, list) else []


def _merge_direction(peer: HostPeer, direction: str) -> str:
    return "both" if peer.direction != direction else direction


def _fold_peers(aggregations: dict[str, Any], host_ip: str) -> tuple[list[HostPeer], bool]:
    """Merge the two directional peer aggregations into one ranked list.

    Ports accumulate across directions rather than replacing: a NAS this host
    both mounts and ssh's into offers 445 AND 22, and a fold that kept only the
    second pass's ports would describe half the relationship.

    Returns ``(peers, truncated)`` — the flag compares the PRE-cut merged size
    against :data:`MAX_PEERS`, because this is the one place that size is still
    known. (Approximate in the direction of modesty: the merged set is itself
    bounded by the two terms-agg widths, so a host with more peers than
    ``2 * _PEER_AGG_SIZE`` still reads simply "truncated".)
    """
    merged: dict[str, HostPeer] = {}
    port_counts: dict[str, dict[int, int]] = {}
    # The two filter sub-aggs are NAMED for the direction they describe, so the
    # bucket path and the value written onto the peer are the same string.
    for direction in ("out", "in"):
        for bucket in _buckets(aggregations, direction, "peers"):
            ip = str(bucket.get("key") or "")
            # A flow whose two endpoints are the same address buckets the host
            # itself in BOTH sub-aggs. Dropped for the same reason the alert
            # lane discards it: "this host talks to this host" is not a peer
            # relationship, and as the busiest bucket it would open the table.
            if not ip or ip == host_ip:
                continue
            peer = merged.get(ip)
            if peer is None:
                peer = HostPeer(ip=ip, direction=direction)
                merged[ip] = peer
                port_counts[ip] = {}
            else:
                peer.direction = _merge_direction(peer, direction)
            peer.events += int(bucket.get("doc_count") or 0)
            counts = port_counts[ip]
            for port_bucket in _buckets(bucket, "ports"):
                port = port_bucket.get("key")
                if port is None:
                    continue
                seen = int(port_bucket.get("doc_count") or 0)
                counts[int(port)] = counts.get(int(port), 0) + seen

    for ip, peer in merged.items():
        ranked = sorted(port_counts[ip].items(), key=lambda kv: (-kv[1], kv[0]))
        peer.ports = [port for port, _count in ranked[:_PORTS_PER_PEER]]
    # Busiest first, then by address so a tie is stable across reloads.
    ordered = sorted(merged.values(), key=lambda p: (-p.events, p.ip))
    return ordered[:MAX_PEERS], len(ordered) > MAX_PEERS


def _fold_volume(aggregations: dict[str, Any]) -> list[VolumePoint]:
    points: list[VolumePoint] = []
    for bucket in _buckets(aggregations, "volume"):
        ts = bucket.get("key_as_string")
        if not ts:
            continue
        points.append(VolumePoint(ts=str(ts), events=int(bucket.get("doc_count") or 0)))
    return points


def _detection_scope(ip: str) -> dict[str, Any]:
    """Detections that involve THIS machine — flow endpoints, or its own agent.

    The nested agent address is included because host-shaped detections (Sigma
    process/file rules built from endpoint events) carry no flow at all, and an
    alert count that skipped them would read zero on exactly the detection class
    host-log shipping produces most of.

    Top-level ``host.ip`` is deliberately NOT matched: on a Suricata alert that
    is the SENSOR's address, so a host page for the sensor would claim every
    alert on the grid.
    """
    return {
        "bool": {
            "should": [
                {"term": {"source.ip": ip}},
                {"term": {"destination.ip": ip}},
                {"term": {_NESTED_HOST_IP: ip}},
            ],
            "minimum_should_match": 1,
        }
    }


async def _fetch_alert_edges(
    elastic: ElasticClient, settings: Settings, *, ip: str, window: str
) -> tuple[int, set[str]]:
    """``(alerts over 7d, peers that alerted within the chosen range)``.

    One search for both. The 7-day count is the query's total; the in-range peers
    come out of a filter sub-aggregation, so narrowing the flag to the visible
    window costs no extra round trip. Scoped to the SAME detection sources as the
    alerts console (Suricata, plus Sigma and ATTACK notices when the extra-source
    switch is on) — a host page and the console disagreeing about how many alerts
    a machine has is a bug report waiting to happen.
    """
    sources = [settings.webui_alerts_query]
    if settings.webui_extra_detections:
        sources += [SIGMA_SOURCE_OQL, NOTICE_SOURCE_OQL]
    query = build_filter(
        settings, time_range=ALERT_WINDOW, severity=None, oql=None, dataset_oqls=sources
    )
    query["bool"]["filter"].append(_detection_scope(ip))
    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=0,
        track_total_hits=True,
        aggs={
            "recent": {
                "filter": {"range": {"@timestamp": {"gte": window}}},
                "aggs": {
                    "src": {"terms": {"field": "source.ip", "size": _ALERT_PEER_AGG_SIZE}},
                    "dst": {"terms": {"field": "destination.ip", "size": _ALERT_PEER_AGG_SIZE}},
                },
            }
        },
    )
    aggregations = result.aggregations or {}
    # Every matched document already has this host on one side, so the OTHER
    # addresses in the two buckets are exactly its alerted peers.
    alerted = {
        str(bucket.get("key"))
        for side in ("src", "dst")
        for bucket in _buckets(aggregations, "recent", side)
        if bucket.get("key")
    }
    alerted.discard(ip)
    return result.total, alerted


def _uniquely_claimed(aggregations: dict[str, Any]) -> bool:
    """Did ONE machine write this address's auth documents, or several?

    THE UNIQUE-CLAIM RULE, applied to the user lane.
    :class:`~soc_ai.dossier.types.AgentInventory` states it in full: ``host.ip``
    is an array of every address a machine can see on itself, and on a real
    network those arrays overlap — Docker's default bridge gateway
    ``172.17.0.1`` is reported by every host running Docker (four of them on the
    network this was built against), a hypervisor bridge recurs the same way,
    and an address DHCP recycled inside the window is claimed by both holders.
    Filtering auth documents on ``host.ip`` alone therefore folds several
    machines' accounts into one list and calls the result this host's users.

    The dossier already refuses to name a contested address (``for_ip`` returns
    no self-report at all, by construction), so the identity half of this page
    goes quiet on exactly the hosts the user half was answering confidently
    about. This is the two halves agreeing.

    The RULE is reused; the network-wide inventory that normally computes it is
    not. ``collect_agent_inventory`` is a dataset probe plus a grid-wide
    ``host.name`` aggregation carrying a ``top_hits`` document per machine —
    two more searches on a page that runs three, sized to the whole network, to
    answer one question about one address. The auth documents already being
    aggregated here carry the same answer for free: the machines that wrote them
    are precisely the machines whose accounts would be mixed in.

    FAILS OPEN, and this is the one thing to know about it: a grid whose auth
    documents carry no ``host.name`` at all returns no buckets, which reads as
    "not contested" and lists the users. That is the pre-existing behaviour, and
    it is the honest one — no ``host.name`` means the claim question is
    unanswerable here rather than answered "several".
    """
    return len(_buckets(aggregations, "agents")) <= 1


async def _fetch_users(
    elastic: ElasticClient, settings: Settings, *, ip: str, window: str
) -> tuple[list[UserSeen] | None, bool]:
    """``(accounts seen on this host's own auth log or None, list was cut)``.

    Keyed on ``host.ip`` — the agent's self-reported addresses — because an auth
    document describes the machine it was written on, not a flow. ``None`` when
    the window holds no auth documents for this address at all; an empty list
    when it holds some that name nobody.

    That ``None`` is scoped to the WINDOW, not to the host's lifetime: an
    agent-carrying machine nobody touched for 24h is indistinguishable here from
    one that ships no auth logs. Widening the absence test to a lifetime probe
    would be a fourth search to answer a question the panel does not ask, so the
    ambiguity is left in place and named for the caller instead (see
    :class:`HostActivity`).

    ``None`` ALSO covers a second absence: an address several agents claim. See
    :func:`_uniquely_claimed`. Both are "this page has no account list for this
    address", which is what the field can say; the page copy is written for the
    common one.

    The second element compares the folded (pre-cut) account count against
    :data:`MAX_USERS` — decided here because only this fold still holds the
    pre-cut length. Always ``False`` beside a ``None`` list.
    """
    query = {
        "bool": {
            "filter": [
                {"terms": {"event.dataset": list(_AUTH_DATASETS)}},
                {"term": {"host.ip": ip}},
                {"range": {"@timestamp": {"gte": window}}},
            ],
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }
    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=0,
        track_total_hits=True,
        aggs={
            # Who WROTE these documents, beside what they say. One pass: see
            # `_uniquely_claimed` for why the answer gates the whole list.
            "agents": {"terms": {"field": "host.name", "size": _AGENT_AGG_SIZE}},
            "users": {
                "terms": {"field": "user.name", "size": _USER_AGG_SIZE},
                "aggs": {"last": {"max": {"field": "@timestamp"}}},
            },
        },
    )
    if not result.total:
        return None, False
    if not _uniquely_claimed(result.aggregations or {}):
        return None, False
    # Trimmed names are FOLDED, not just trimmed. Real grids carry a few auth
    # lines whose user.name has a leading space, and ES buckets those separately
    # — so trimming each in isolation renders one account as two rows with two
    # different counts, which reads as two accounts.
    folded: dict[str, UserSeen] = {}
    for bucket in _buckets(result.aggregations or {}, "users"):
        name = str(bucket.get("key") or "").strip()
        if not name:
            continue
        last = str((bucket.get("last") or {}).get("value_as_string") or "")
        seen = folded.get(name)
        if seen is None:
            folded[name] = UserSeen(
                name=name, events=int(bucket.get("doc_count") or 0), last_seen=last
            )
            continue
        seen.events += int(bucket.get("doc_count") or 0)
        seen.last_seen = max(seen.last_seen, last)  # ISO-8601 sorts lexically
    ordered = sorted(folded.values(), key=lambda u: (-u.events, u.name))
    return ordered[:MAX_USERS], len(ordered) > MAX_USERS


async def fetch_host_activity(
    elastic: ElasticClient,
    settings: Settings,
    ip: str,
    *,
    # Shadows the builtin deliberately and only here: this is the query-string
    # name the wire uses, and the route spells it `range_` solely because
    # FastAPI needs an alias. Helpers below take `time_range` instead.
    range: str = DEFAULT_RANGE,
    dossier_lookup: PeerNameLookup | None = None,
    investigation_lookup: InvestigationLookup | None = None,
) -> HostActivity:
    """One host's live activity over ``range``, read straight off the grid.

    Args:
        elastic: client for the Security Onion ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        ip: the host to describe. Callers validate this is an address; an
            unknown one is a legitimate empty answer, not an error.
        range: one of :data:`ACTIVITY_RANGES`. Anything else falls back to the
            default rather than raising — the route already rejects a bad value
            with a 422, and this module is also called from tests and the CLI.
        dossier_lookup: batch ``(ips) -> {ip: hostname}``. Called ONCE with the
            whole peer list; the route backs it with the dossier store's
            resolver, so a peer row names the same machine the host list does.
            A failure DEGRADES to unnamed peers.
        investigation_lookup: ``(ip) -> LatestInvestigation | None``, the
            investigations store's per-IP lookup. Omitted — or failing — the
            field stays null.

    Returns:
        A :class:`HostActivity`. The three Elasticsearch failures PROPAGATE: the
        caller maps them to the grid-unavailable response the rest of the console
        uses, and an empty panel returned for a down grid would read as "this
        host did nothing", which is exactly the wrong thing to tell an analyst.
        The two injected lookups are the other way round — they are DATABASE
        reads behind cosmetic fields, the route has no degraded answer for a
        database error, and reporting one as a down grid would send an operator
        to the wrong system.
    """
    window = _window(range)
    interval = _VOLUME_INTERVAL[_supported(range)]

    # Three searches, fanned out. THREE and not one because the alert pass takes
    # its scoping from ``alerts_query.build_filter`` — the same call the alerts
    # console makes — and that returns a finished ``bool`` query, not a clause a
    # union query could nest. Folding the passes together would mean hand-rolling
    # the detection-source scoping here, and the moment those two spellings can
    # drift, a host page and the console can disagree about how many alerts a
    # machine has. (The cost argument for splitting is weaker than it looks: a
    # union top-level query with three filter sub-aggs scans the same documents.
    # Source-of-truth is the reason; doc count is not.)
    #
    # Fanned out because they are independent and the route runs all of them
    # under ONE ``webui_grid_timeout_s``. In series that budget is spent
    # serially, so a slow first pass eats the allowance of the two behind it.
    # The investigation lookup joins them: it is a different datastore entirely,
    # so it is free concurrency and one less thing on the critical path.
    conn_out, edges_out, users_out, latest_out = await asyncio.gather(
        elastic.search(
            settings.events_index_pattern,
            _conn_query(ip, window),
            size=0,
            aggs=_conn_aggs(ip, interval),
        ),
        _fetch_alert_edges(elastic, settings, ip=ip, window=window),
        _fetch_users(elastic, settings, ip=ip, window=window),
        _latest_investigation(investigation_lookup, ip),
        return_exceptions=True,
    )
    # Unwrapped in priority order: the connection pass is the panel's spine, so
    # when the grid is down it is its error the analyst should be shown.
    aggregations = _unwrap(conn_out).aggregations or {}
    alerts_7d, alerted = _unwrap(edges_out)
    users, users_truncated = _unwrap(users_out)
    latest = _unwrap(latest_out)

    peers, peers_truncated = _fold_peers(aggregations, ip)
    for peer in peers:
        peer.alerted = peer.ip in alerted

    # The only lookup that CANNOT join the fan-out: it takes the peer list the
    # connection pass produces.
    #
    # Degraded like the investigation lookup above, and for the same reason: it
    # reads the DATABASE, the route can only translate Elasticsearch failures,
    # and a failed name lookup would otherwise answer 500 — which the page shows
    # as a down grid. A peer with no name still renders, as its address.
    if dossier_lookup is not None and peers:
        try:
            names = await dossier_lookup([peer.ip for peer in peers])
        except Exception as exc:
            _LOGGER.warning("host activity: peer name lookup failed for %s: %s", ip, exc)
            names = {}
        for peer in peers:
            peer.hostname = names.get(peer.ip)

    return HostActivity(
        peers=peers,
        volume=_fold_volume(aggregations),
        users=users,
        alerts_7d=alerts_7d,
        latest_investigation=latest,
        peers_truncated=peers_truncated,
        users_truncated=users_truncated,
    )
