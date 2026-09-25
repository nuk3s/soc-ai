"""Build a model of normal for every entity the grid can see.

One lane, run once per sweep, producing one row per (entity, dimension). It
follows the house lane contract exactly: keyword-only ``elastic``/``settings``,
a window in hours, an optional time anchor, and it never raises — failures land
in ``errors`` on the returned sweep.

**Planes are chosen by field presence, never by dataset name or volume.**

This is the one decision here that is not obvious, and it was bought expensively.
On the measured range ``zeek.conn`` held 885,000 documents across two weeks that
carried no ``destination.ip`` at all: Zeek had been reconfigured into
tab-separated output, and Security Onion's ingest pipeline parses ``message`` as
JSON with ``ignore_failure: true``, so every one of those documents indexed
clean and completely empty. Every surface reported the plane as the fifth
largest live dataset on the grid.

A profile builder that selects its flow plane by name would have built every
baseline on this grid out of nothing. One that selects by document count would
have preferred the empty plane to the working one. So the probe asks the only
question that matters — how many documents in this dataset actually carry the
field I am about to read — and a plane that cannot answer is not used.

The probe fails CLOSED, unlike :func:`soc_ai.dossier.observe._present_datasets`,
which treats an empty inventory as "unknown" and searches everything. The
asymmetry is deliberate. There, guessing wide costs a wasted query. Here it
costs a dimension that reports ``measured`` over a plane that answers nothing,
which is a confident all-clear from a measurement that never ran.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import UTC, date, datetime
from typing import Any

from soc_ai.dossier.profile_math import (
    GUARDED_PORT_DIMENSIONS,
    served_port_counts,
    summarise_cells,
)
from soc_ai.enrichment.discovery import _is_internal_ip
from soc_ai.so_client.elastic import DEFAULT_MAX_BUCKETS, ElasticClient
from soc_ai.so_client.fields import DATASET_NAME_FIELDS, EPHEMERAL_PORT_FLOOR, is_peer_address
from soc_ai.tools._provenance import LIVE, provenance_must_not
from soc_ai.tools._synth_scope import synth_scope_must_not

__all__ = [
    "DNS_CANDIDATES",
    "EPHEMERAL_PORT_FLOOR",
    "FLOW_CANDIDATES",
    "MIN_SUPPORT_DAYS",
    "PROCESS_CANDIDATES",
    "BuiltProfile",
    "ProfileSweep",
    "collect_entity_profiles",
    "resolve_plane",
    "served_direction_clauses",
]

_LOGGER = logging.getLogger(__name__)

# The design's floor: below this an entity has not earned the right to call
# anything unusual, and the profile reads "learning, day N of 7".
MIN_SUPPORT_DAYS = 7

# Candidate planes per logical role, most-specific first. Order is only a
# tie-break for reporting; every candidate that carries the field is used, so a
# membership seen by one sensor and not the other is still a membership.
FLOW_CANDIDATES: tuple[str, ...] = (
    "zeek.conn",
    "network_traffic.flow",
    "endpoint.events.network",
)
DNS_CANDIDATES: tuple[str, ...] = ("zeek.dns", "network_traffic.dns")
PROCESS_CANDIDATES: tuple[str, ...] = ("endpoint.events.process", "windows.sysmon_operational")
LOGON_CANDIDATES: tuple[str, ...] = ("system.security",)

# EPHEMERAL_PORT_FLOOR lives in so_client.fields so the dossier's own port
# inference can apply the same floor without importing this lane.


# How many entities and how many members per entity a single sweep will hold.
# A profile is a model of the ordinary, and the long tail of a terms agg is by
# definition not ordinary — but the bound is here because an unbounded nested
# terms agg on a 3.8M-document plane is how you take an Elasticsearch down.
_MAX_ENTITIES = 500
_MAX_MEMBERS = 200
# The most slices the shaped entity terms will be cut into. At 32 slices of
# 500 entities the ladder has tried 16,000 entity buckets per request down to
# 500, and a grid that still refuses is telling us its limit, not ours.
_MAX_PARTITIONS = 32
_TOO_MANY_BUCKETS = "too_many_buckets_exception"


@dataclass(frozen=True)
class BuiltProfile:
    """One dimension of one entity, as the lane produces it."""

    entity_kind: str
    entity_key: str
    dimension: str
    shape: str
    vector: Any | None
    coverage: str
    support_days: int = 0
    first_seen: str | None = None
    last_seen: str | None = None


@dataclass(frozen=True)
class ProfileSweep:
    """Everything one run of the lane produced.

    ``planes`` is reported so an operator can tell "no plane on this grid
    carries destination.ip" from "this host is quiet". Those look identical on
    a host page and have completely different answers.
    """

    profiles: tuple[BuiltProfile, ...] = ()
    planes: dict[str, tuple[str, ...]] = dc_field(default_factory=dict)
    errors: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    # Dimensions no plane on this grid can answer, by name. The ``*`` row says
    # the same thing per profile; this says it per dimension, which is what
    # the per-host coverage fill needs, since the fill skips ``*`` rows.
    unanswered: tuple[str, ...] = ()
    # Dimensions the grid refused to measure after every retry, with the
    # Elasticsearch reason. Not an error: the sweep finished, and the answer
    # is "this grid cannot answer this at this size".
    unmeasurable: dict[str, str] = dc_field(default_factory=dict)


def _dataset_clause(dataset: str) -> dict[str, Any]:
    """Select one dataset under either name field.

    ``data_stream.dataset`` is not optional here: on the measured grid the
    entire network-metadata plane — 4,040,237 documents — carries no
    ``event.dataset`` at all.
    """
    return {
        "bool": {
            "should": [{"term": {f: dataset}} for f in DATASET_NAME_FIELDS],
            "minimum_should_match": 1,
        }
    }


def _scope_must_not() -> list[dict[str, Any]]:
    """Live sensor telemetry only, and no planted eval documents.

    A profile is a claim about a population. Built over an import it describes
    somebody else's network, and built over synth plants it describes a fixture.
    """
    return [*provenance_must_not(LIVE), *synth_scope_must_not(False)]


def _window_filter(
    minutes: int, anchor: datetime | None, *, lag_minutes: int = 0
) -> dict[str, Any]:
    """The baseline window, optionally ending ``lag_minutes`` before the present.

    The lag is what makes novelty possible at all. A baseline built over the
    last thirty days CONTAINS the last twenty-four hours, so every member a
    recent read observes is already in the baseline it is compared against, and
    ``novel_for`` cannot fire — 656 evaluations on the range returned zero
    findings with no bug visible anywhere.

    The window therefore ENDS where the recent window BEGINS, the same shape
    :func:`soc_ai.tools.analytics._first_seen_windows` uses for the same reason.
    """
    if anchor is None:
        if lag_minutes > 0:
            return {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{minutes + lag_minutes}m",
                        "lte": f"now-{lag_minutes}m",
                    }
                }
            }
        return {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}

    end = f"{anchor.isoformat()}||-{lag_minutes}m" if lag_minutes > 0 else anchor.isoformat()
    return {
        "range": {
            "@timestamp": {
                "gte": f"{anchor.isoformat()}||-{minutes + lag_minutes}m",
                "lte": end,
            }
        }
    }


async def resolve_plane(
    elastic: ElasticClient,
    settings: Any,
    *,
    candidates: tuple[str, ...],
    field: str,
    minutes: int,
    time_anchor: datetime | None = None,
    lag_minutes: int = 0,
) -> tuple[str, ...] | None:
    """Which candidate datasets hold documents that actually carry ``field``.

    One filters aggregation, one bucket per candidate, each counting documents
    that both belong to the dataset and have the field. Cheap enough to run per
    dimension per sweep.

    Three return values, and the third is the point:

    ``("network_traffic.flow",)``  these planes can answer
    ``()``                         no plane on this grid can answer
    ``None``                       the probe itself failed — unknown

    The first cut collapsed the last two into ``()``, and a grid outage then
    rendered as "no plane carries destination.ip", which an operator reads as a
    fact about their estate rather than as a broken query. A dead grid must
    never be reportable as a quiet network.
    """
    if not candidates:
        return ()

    filters = {
        f"{dataset}|{field}": {
            "bool": {"filter": [_dataset_clause(dataset), {"exists": {"field": field}}]}
        }
        for dataset in candidates
    }
    query = {
        "bool": {
            "filter": [_window_filter(minutes, time_anchor, lag_minutes=lag_minutes)],
            "must_not": _scope_must_not(),
        }
    }
    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs={"plane_probe": {"filters": {"filters": filters}}},
        )
    except Exception as exc:
        _LOGGER.warning("profile: plane probe for %s failed: %s", field, exc)
        return None

    buckets = ((result.aggregations or {}).get("plane_probe") or {}).get("buckets") or {}
    usable: list[str] = []
    for dataset in candidates:
        bucket = buckets.get(f"{dataset}|{field}") or {}
        if int(bucket.get("doc_count") or 0) > 0:
            usable.append(dataset)
    return tuple(usable)


def _member_aggs(peer_field: str | None = None) -> dict[str, Any]:
    """Per-member sub-aggregations: when it was first and last seen.

    ``peer_field`` adds how many distinct peers reached the member. Asked for
    on the served-port dimension only. The outbound-port dimension is keyed
    on the source, so a peer count there would count the entity itself, and
    the address dimensions have no port to guard.

    The days the guard reads come from ``first`` and ``last``. Two metric
    aggregations cost no buckets. A day histogram under every member of
    every entity is 500 x 200 x 30 buckets on a busy grid, which is over
    ``search.max_buckets``.
    """
    aggs: dict[str, Any] = {
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}},
    }
    if peer_field:
        aggs["peers"] = {"cardinality": {"field": peer_field}}
    return aggs


def _peer_field(dimension: str) -> str | None:
    """The field that names the far end of a guarded port dimension."""
    return "source.ip" if dimension in GUARDED_PORT_DIMENSIONS else None


def _member_peers(member: dict[str, Any]) -> int:
    """Distinct peers behind one member bucket. Zero when the agg was not asked for."""
    raw = (member.get("peers") or {}).get("value")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return 0
    return int(raw)


def _member_days(member: dict[str, Any]) -> int:
    """Distinct UTC calendar dates from a member's first sighting to its last.

    Zero when either stamp is missing, and zero is the reading that does NOT
    count. One when both fall on the same date. Two when they fall on two
    dates, however close the stamps are.
    """
    first = _stamp_date(member, "first")
    last = _stamp_date(member, "last")
    if first is None or last is None:
        return 0
    return abs((last - first).days) + 1


def _stamp_date(bucket: dict[str, Any], key: str) -> date | None:
    """The UTC calendar date of one min/max stamp. None when unreadable."""
    raw = _stamp(bucket, key)
    if raw is None:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).date()


def _nested_terms(
    *, entity_field: str, member_field: str, peer_field: str | None = None
) -> dict[str, Any]:
    """One entity terms agg, each with its members and its own day count.

    ``active_days`` sits at the ENTITY level, not the member level, for two
    reasons. It is where the design puts it — the floor is "7 days of the
    entity's own data" — and putting a 30-bucket histogram under each of 200
    members of each of 500 entities is three million buckets for a number that
    is the same at every leaf.

    It is a daily ``date_histogram`` rather than a ``cardinality`` on
    ``@timestamp``. The first cut used cardinality, and against the live range
    a host reported 98,517 days of support over a 30-day window: cardinality
    counts distinct millisecond values, so the support floor was being cleared
    by volume rather than by persistence, and one busy afternoon read as a
    thousand days of history.

    ``peer_field`` adds the per-member peer count the served-port guard
    reads. The day count it also reads is derived from ``first`` and
    ``last``, which every member carries, so the guard adds one cardinality
    per member and no buckets.
    """
    return {
        "terms": {"field": entity_field, "size": _MAX_ENTITIES},
        "aggs": {
            "active_days": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "day",
                    "min_doc_count": 1,
                }
            },
            "members": {
                "terms": {"field": member_field, "size": _MAX_MEMBERS},
                "aggs": _member_aggs(peer_field),
            },
        },
    }


def _port_bound(member_field: str) -> list[dict[str, Any]]:
    """Exclude the dynamic port range, but only on port dimensions.

    Applied by MEMBER field rather than by dimension name, so a dimension added
    later gets the bound automatically if it aggregates a port and never gets it
    if it does not. Adding it unconditionally would drop every document with no
    ``destination.port`` from peers_out and the DNS dimensions.
    """
    if not member_field.endswith(".port"):
        return []
    return [{"range": {member_field: {"lt": EPHEMERAL_PORT_FLOOR}}}]


# Dimensions whose members are addresses, and so subject to the peer test.
_ADDRESS_DIMENSIONS = frozenset({"peers_out"})

# Dimensions that count only the traffic LEAVING the estate.
#
# consumed_ports feeds the analytic "a server connects to the internet on a
# port it has never used". The dimension took every destination port on every
# flow, so the range's first lead was 9 ports to internal hosts, every one of
# them the far end of a dynamically negotiated channel. A server talking to its
# own domain controller is not a server reaching the internet.
#
# served_ports is the other side of the same flow and stays estate-wide: the
# destination there IS the server, so the same exclusion would empty it.
_EXTERNAL_ONLY_DIMENSIONS = frozenset({"consumed_ports"})


def _outside_the_estate(dimension: str, *, cidrs: Sequence[Any]) -> list[dict[str, Any]]:
    """must_not clauses that drop flows whose destination is one of ours.

    Fails OPEN on an empty CIDR list, like every other scope test in this lane.
    An unconfigured estate means nobody has said what this network is, and
    dropping everything would report a healthy grid as silent.

    An ``ip`` field takes CIDR notation in a terms query, so the estate is one
    clause however many ranges it holds.
    """
    if dimension not in _EXTERNAL_ONLY_DIMENSIONS:
        return []
    nets = [str(c).strip() for c in cidrs if str(c).strip()]
    if not nets:
        return []
    return [{"terms": {"destination.ip": nets}}]


# The direction rule for served ports, keyed by plane.
#
# The generic clauses apply on every plane. DNS is never a served port: an
# endpoint sensor writes a lookup twice, once mirrored with the asking host
# as the destination and the lookup's ephemeral source port as the
# destination port. A flow a sensor marked as leaving the host is not one the
# host received. ``network.direction`` is optional in ECS and most planes
# omit it; ``internal`` and ``unknown`` say nothing about direction, so the
# clause drops the three outbound words and keeps everything else.
#
# The endpoint sensor names the inbound side. ``connection_accepted`` is the
# host answering; ``connection_attempted`` is the host calling out. A plane
# this table does not name gets the generic clauses only, so a grid with a
# flow plane nobody here has seen still builds a served-port set.
_ACCEPTED_ACTION_BY_PLANE: dict[str, str] = {"endpoint.events.network": "connection_accepted"}
_DNS_ACTIONS: tuple[str, ...] = ("lookup_requested", "lookup_result")
_OUTBOUND_DIRECTIONS: tuple[str, ...] = ("egress", "outbound", "external")


def served_direction_clauses(planes: Sequence[str]) -> dict[str, list[dict[str, Any]]]:
    """The bool clauses that keep a served-port read to connections the entity received.

    Returns ``{"filter": [...], "must_not": [...]}``. The baseline builder and
    the recent read both spread these into their query, so the two sides of
    the comparison agree on what a served port is.

    Each plane-specific filter is a choice: a document from any other plane,
    or the action that names an accepted connection. Written as a plain term
    it would drop every Zeek document from a read that spans both planes.
    """
    filters: list[dict[str, Any]] = []
    for plane in planes:
        action = _ACCEPTED_ACTION_BY_PLANE.get(plane)
        if action is None:
            continue
        filters.append(
            {
                "bool": {
                    "should": [
                        {"bool": {"must_not": [_dataset_clause(plane)]}},
                        {"term": {"event.action": action}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    must_not: list[dict[str, Any]] = [
        {"term": {"network.protocol": "dns"}},
        {"terms": {"event.action": list(_DNS_ACTIONS)}},
        {"terms": {"network.direction": list(_OUTBOUND_DIRECTIONS)}},
    ]
    return {"filter": filters, "must_not": must_not}


def _direction_for(dimension: str, *, planes: Sequence[str]) -> dict[str, list[dict[str, Any]]]:
    """The direction clauses for this dimension. Empty for every dimension but a guarded one."""
    if dimension not in GUARDED_PORT_DIMENSIONS:
        return {"filter": [], "must_not": []}
    return served_direction_clauses(planes)


def _entity_support_days(bucket: dict[str, Any], *, window_days: int) -> int:
    """How many distinct days this entity was seen on, bounded by the window.

    The bound is belt and braces against the defect above: whatever the
    aggregation returns, an entity cannot have more days of history than the
    window holds, and a support number larger than its own window is the kind
    of figure that clears every floor silently.
    """
    buckets = (bucket.get("active_days") or {}).get("buckets") or []
    return min(len(buckets), max(1, window_days))


def _stamp(bucket: dict[str, Any], key: str) -> str | None:
    node = bucket.get(key) or {}
    value = node.get("value_as_string")
    return value if isinstance(value, str) and value else None


def _ours(key: str, *, entity_kind: str, cidrs: Sequence[Any]) -> bool:
    """Whether this entity belongs to the estate.

    Only HOST entities are address-scoped. A user principal has no address, and
    running it through an address test would drop every user on the grid.
    """
    if entity_kind != "host" or not cidrs:
        return True
    return _is_internal_ip(key, list(cidrs))


def _profiles_from_buckets(
    buckets: list[dict[str, Any]],
    *,
    dimension: str,
    entity_kind: str,
    window_days: int,
    cidrs: Sequence[Any] = (),
) -> list[BuiltProfile]:
    """Turn one nested terms aggregation into one profile per entity."""
    out: list[BuiltProfile] = []
    for bucket in buckets:
        key = bucket.get("key")
        if not isinstance(key, str) or not key:
            continue
        if not _ours(key, entity_kind=entity_kind, cidrs=cidrs):
            continue
        members = ((bucket.get("members") or {}).get("buckets")) or []
        vector: dict[str, Any] = {}
        support = _entity_support_days(bucket, window_days=window_days)
        first: str | None = None
        last: str | None = None
        for member in members:
            name = member.get("key")
            if name is None:
                continue
            name = str(name)
            if dimension in _ADDRESS_DIMENSIONS and not is_peer_address(name):
                # mDNS to 224.0.0.251 and LLMNR to 224.0.0.252 are the host
                # talking to the LAN, not to a peer. Left in, every host's
                # peer set carries the same three multicast groups, and a
                # "novel destination" prior would fire on the first one seen.
                continue
            m_first = _stamp(member, "first")
            m_last = _stamp(member, "last")
            count = int(member.get("doc_count") or 0)
            entry: dict[str, Any] = {
                "count": count,
                "first_seen": m_first,
                "last_seen": m_last,
            }
            if dimension in GUARDED_PORT_DIMENSIONS:
                peers = _member_peers(member)
                days = _member_days(member)
                # The same guard the evaluator applies. A baseline that holds
                # ephemeral ports fills its 200 slots with noise, and every
                # real port outside them reads as new for ever.
                if not served_port_counts(name, count=count, peers=peers, days=days):
                    continue
                entry["peers"] = peers
                entry["days"] = days
            vector[name] = entry
            if m_first and (first is None or m_first < first):
                first = m_first
            if m_last and (last is None or m_last > last):
                last = m_last

        out.append(
            BuiltProfile(
                entity_kind=entity_kind,
                entity_key=key,
                dimension=dimension,
                shape="categorical",
                vector=vector,
                # An entity below the floor is LEARNING, not measured. The
                # profile exists and can be rendered; it just may not be scored
                # against, which the store enforces via is_scorable.
                coverage="measured" if support >= MIN_SUPPORT_DAYS else "learning",
                support_days=support,
                first_seen=first,
                last_seen=last,
            )
        )
    return out


def _blind(dimension: str, *, entity_kind: str = "host") -> BuiltProfile:
    """A dimension no plane on this grid can answer.

    Produced as a ROW rather than omitted. An absent row is indistinguishable
    from a dimension nobody thought to build, and the whole point of coverage
    is that a surface can say "blind for process on this host" instead of
    reporting nothing departed.
    """
    return BuiltProfile(
        entity_kind=entity_kind,
        entity_key="*",
        dimension=dimension,
        shape="categorical",
        vector=None,
        coverage="blind",
    )


# dimension -> (candidate planes, field probed, entity field, member field)
_CATEGORICAL: tuple[tuple[str, tuple[str, ...], str, str, str], ...] = (
    ("peers_out", FLOW_CANDIDATES, "destination.ip", "source.ip", "destination.ip"),
    ("consumed_ports", FLOW_CANDIDATES, "destination.port", "source.ip", "destination.port"),
    # Keyed on destination.ip on purpose: a switch never initiates anything, so
    # a source-keyed sweep gives it no history and every port it serves reads
    # as novel forever. Both endpoints of every connection are updated.
    ("served_ports", FLOW_CANDIDATES, "destination.port", "destination.ip", "destination.port"),
    ("process_names", PROCESS_CANDIDATES, "process.name", "host.name", "process.name"),
    (
        "process_parents",
        PROCESS_CANDIDATES,
        "process.parent.name",
        "host.name",
        "process.parent.name",
    ),
    ("dns_names", DNS_CANDIDATES, "dns.question.name", "source.ip", "dns.question.name"),
    ("logon_users", LOGON_CANDIDATES, "user.name", "host.name", "user.name"),
)

# The two dimensions that are not membership sets. They share one query.
#
# ``active_hours`` is a 24-bin SET test ("was this host ever active in this
# hour") and needs no dispersion. ``connection_rate`` is the three-cell
# summary. Both read the same hourly histogram of the same flow documents
# keyed by the same entity, so they are one aggregation read twice. Run as
# two aggregations the 700M-document grid refused both with the bucket limit.
#
# Both exist because without them there is exactly ONE observation kind
# available on a network-only grid, and a lead needs two.
_SHAPED: tuple[tuple[str, str], ...] = (
    ("active_hours", "active_hours"),
    ("connection_rate", "numeric"),
)
_SHAPED_DIMENSIONS: tuple[str, ...] = tuple(d for d, _ in _SHAPED)
_SHAPED_CANDIDATES = FLOW_CANDIDATES
_SHAPED_PROBE_FIELD = "destination.ip"
_SHAPED_ENTITY_FIELD = "source.ip"


def _shaped_aggs(*, entity_field: str, partition: int, num_partitions: int) -> dict[str, Any]:
    """The one aggregation both shaped dimensions read, for one partition.

    ``include.partition`` splits the entity terms into ``num_partitions``
    disjoint slices, so each request builds one slice's hour buckets and the
    total stays under ``search.max_buckets``. Every entity carries a day
    histogram and an hour histogram: over thirty days that is 751 buckets, and
    500 entities in one request is 375,000 against a limit of 65,536.

    Hour of DAY, not hour of week. On a 30-day window a 168-bin set holds four
    or five samples per bin; hour of day holds thirty. The weekday/weekend
    split is already carried by the three-cell rate dimension.
    """
    return {
        "shaped": {
            "terms": {
                "field": entity_field,
                "size": _MAX_ENTITIES,
                "include": {"partition": partition, "num_partitions": num_partitions},
            },
            "aggs": {
                "active_days": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "day",
                        "min_doc_count": 1,
                    }
                },
                "hours": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "hour",
                        "min_doc_count": 1,
                    }
                },
            },
        }
    }


def _estate_filter(entity_field: str, *, cidrs: Sequence[Any]) -> list[dict[str, Any]]:
    """Keep only entities inside the estate, in the query rather than after it.

    The lane already drops external entities in Python. Dropping them in the
    query is what keeps the bucket count honest: on the measured grid 774
    addresses reached the aggregation and 215 were ours, so three quarters
    of the bucket budget went to the internet. An ``ip`` field takes CIDR
    notation in a terms query. Fails OPEN on an empty CIDR list, like every
    scope test in this lane.
    """
    nets = [str(c).strip() for c in cidrs if str(c).strip()]
    if not nets:
        return []
    return [{"terms": {entity_field: nets}}]


def _partition_count(
    entities: int, *, window_hours: int, window_days: int, max_buckets: int
) -> int:
    """How many slices the entity terms need to fit under half the bucket limit.

    Half, because the estimate is a cardinality (approximate) times a ceiling
    (every hour of every day active), and a slice that lands exactly on the
    limit is a retry the ladder then has to pay for.
    """
    per_entity = max(1, window_hours) + max(1, window_days)
    budget = max(1, max_buckets // 2)
    needed = -(-(max(0, entities) * per_entity) // budget)
    return max(1, min(_MAX_PARTITIONS, needed))


def _too_many_buckets(exc: BaseException) -> bool:
    """Whether an Elasticsearch error is the bucket limit, read from its body.

    The top-level ``reason`` of a search_phase_execution_exception is an
    empty string; the cause sits under ``caused_by`` or ``root_cause``.
    """
    body = getattr(exc, "body", None)
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return False
    if (error.get("caused_by") or {}).get("type") == _TOO_MANY_BUCKETS:
        return True
    return any((rc or {}).get("type") == _TOO_MANY_BUCKETS for rc in error.get("root_cause") or [])


def _es_reason(exc: BaseException) -> str:
    """The sentence Elasticsearch gave, or the exception text when it gave none."""
    body = getattr(exc, "body", None)
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict):
        for node in (error.get("caused_by") or {}, error):
            reason = node.get("reason")
            if isinstance(reason, str) and reason.strip():
                return reason.strip()[:255]
    return str(exc)[:255]


async def _max_buckets(elastic: Any) -> int:
    """The grid's bucket limit. A client that cannot say gets the ES default."""
    reader = getattr(elastic, "max_buckets", None)
    if reader is None:
        return DEFAULT_MAX_BUCKETS
    try:
        return int(await reader())
    except Exception:
        return DEFAULT_MAX_BUCKETS


async def _entity_count(
    elastic: Any, settings: Any, query: dict[str, Any], *, entity_field: str
) -> int:
    """A cheap cardinality read, so the first partition count is an estimate."""
    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs={"entities": {"cardinality": {"field": entity_field}}},
        )
    except Exception:
        return 0
    value = ((result.aggregations or {}).get("entities") or {}).get("value")
    return int(value) if isinstance(value, (int, float)) else 0


async def _collect_shaped(
    elastic: Any,
    settings: Any,
    query: dict[str, Any],
    *,
    entity_field: str,
    window_hours: int,
    window_days: int,
) -> tuple[list[dict[str, Any]], str | None]:
    """Every entity bucket for the shaped dimensions, or the reason there are none.

    The ladder: start from the estimate, double on the bucket limit, stop at
    ``_MAX_PARTITIONS``. A refusal past the cap returns ``([], reason)`` so
    the caller can write the reason down. Any other failure raises: that is a
    broken query, not a fact about the grid's size.
    """
    max_buckets = await _max_buckets(elastic)
    entities = await _entity_count(elastic, settings, query, entity_field=entity_field)
    partitions = _partition_count(
        entities, window_hours=window_hours, window_days=window_days, max_buckets=max_buckets
    )
    while True:
        buckets: list[dict[str, Any]] = []
        refused: BaseException | None = None
        for partition in range(partitions):
            try:
                result = await elastic.search(
                    settings.events_index_pattern,
                    query,
                    size=0,
                    aggs=_shaped_aggs(
                        entity_field=entity_field,
                        partition=partition,
                        num_partitions=partitions,
                    ),
                )
            except Exception as exc:
                refused = exc
                break
            buckets.extend(((result.aggregations or {}).get("shaped") or {}).get("buckets") or [])
        if refused is None:
            return buckets, None
        if not _too_many_buckets(refused):
            raise refused
        if partitions >= _MAX_PARTITIONS:
            return [], _es_reason(refused)
        _LOGGER.info(
            "profile: %d partition(s) exceeded search.max_buckets=%d; retrying with %d",
            partitions,
            max_buckets,
            min(_MAX_PARTITIONS, partitions * 2),
        )
        partitions = min(_MAX_PARTITIONS, partitions * 2)


def _active_hours_vector(bucket: dict[str, Any], *, tz: str) -> dict[str, Any]:
    """Which local hours of the day this entity has ever been active in."""
    out: dict[str, Any] = {}
    for hour_bucket in ((bucket.get("hours") or {}).get("buckets")) or []:
        stamp = hour_bucket.get("key_as_string")
        count = int(hour_bucket.get("doc_count") or 0)
        if count <= 0:
            continue
        hour = _local_hour(stamp, tz=tz)
        if hour is None:
            # A pre-bucketed integer hour, which is what a terms agg returns.
            raw = hour_bucket.get("key")
            hour = int(raw) if isinstance(raw, (int, float)) else None
        if hour is None:
            continue
        entry = out.setdefault(str(hour), {"count": 0})
        entry["count"] += count
    return out


def _rate_vector(bucket: dict[str, Any], *, tz: str) -> dict[str, Any]:
    """The three local-time cells for a numeric dimension."""
    samples: list[tuple[datetime, float]] = []
    for hour_bucket in ((bucket.get("hours") or {}).get("buckets")) or []:
        stamp = _parse_stamp(hour_bucket.get("key_as_string"))
        if stamp is None:
            continue
        samples.append((stamp, float(hour_bucket.get("doc_count") or 0)))

    cells = summarise_cells(samples, tz=tz)
    return {
        cell.value: {
            "median": summary.median,
            "dispersion": summary.dispersion,
            "support_days": summary.support_days,
            "samples": summary.samples,
        }
        for cell, summary in cells.items()
    }


def _parse_stamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _local_hour(value: Any, *, tz: str) -> int | None:
    stamp = _parse_stamp(value)
    if stamp is None:
        return None
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415 - lazy, avoids a cycle

    try:
        zone = ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        zone = ZoneInfo("UTC")
    return stamp.astimezone(zone).hour


# Which logical plane each dimension draws on, for the sweep's ``planes`` report.
_PLANE_LABEL = {
    FLOW_CANDIDATES: "flow",
    PROCESS_CANDIDATES: "process",
    DNS_CANDIDATES: "dns",
    LOGON_CANDIDATES: "logon",
}


async def collect_entity_profiles(  # noqa: PLR0915 - one function reads as one procedure
    *,
    elastic: ElasticClient,
    settings: Any,
    window_hours: int,
    time_anchor: datetime | None = None,
    lag_hours: int = 0,
    cidrs: Sequence[Any] = (),
) -> ProfileSweep:
    """Build every entity's profile over ``window_hours``.

    ``cidrs`` scopes HOST entities to the estate's own address space. Without
    it the lane profiles every address it sees as a source, which on the range
    meant building baselines for a Microsoft server, the loopback address and
    the range router's upstream gateway, and then reporting findings about
    their behaviour. An empty list fails OPEN — it means nobody has told this
    deployment what its own network is, and treating that as "nothing is
    internal" would report a healthy grid as having no entities at all.

    ``lag_hours`` ends the window that many hours before the present, so the
    baseline does not contain the window it will be compared against. Pass the
    prior sweep's ``recent_hours``. Left at zero the window runs to now, which
    is what a host page wants — it renders what a machine does, including
    today — and which no novelty comparison should ever use.

    Never raises. A dimension whose query fails is reported in ``errors`` and
    produces no row, which is different from producing a blind row: the first
    means the sweep did not finish, the second means the grid cannot answer.
    """
    minutes = max(1, window_hours) * 60
    lag_minutes = max(0, lag_hours) * 60
    window_days = max(1, window_hours // 24)
    profiles: list[BuiltProfile] = []
    planes: dict[str, tuple[str, ...]] = {}
    errors: list[str] = []
    notes: list[str] = []
    unanswered: list[str] = []
    unmeasurable: dict[str, str] = {}

    # The cached probe answer, per (candidate list, field). ``None`` is one of
    # the three answers resolve_plane gives and it is the one that matters: the
    # probe itself failed. Typing the cache without it made both "the probe
    # failed" branches below read as dead code.
    resolved: dict[tuple[str, ...], dict[str, tuple[str, ...] | None]] = {}

    for dimension, candidates, probe_field, entity_field, member_field in _CATEGORICAL:
        cache = resolved.setdefault(candidates, {})
        if probe_field not in cache:
            cache[probe_field] = await resolve_plane(
                elastic,
                settings,
                candidates=candidates,
                field=probe_field,
                minutes=minutes,
                time_anchor=time_anchor,
                lag_minutes=lag_minutes,
            )
        usable = cache[probe_field]

        label = _PLANE_LABEL.get(candidates, dimension)
        usable_planes = usable or ()
        # Report the widest resolution seen for this logical plane, so the
        # summary says which datasets are carrying it at all.
        if usable_planes and len(usable_planes) >= len(planes.get(label, ())):
            planes[label] = usable_planes

        if usable is None:
            # The probe failed. That is a broken sweep, not a fact about the
            # estate, so it goes to errors and produces no row at all —
            # a blind row would claim we looked and could not see.
            errors.append(f"{dimension}: could not determine which plane carries {probe_field}")
            continue

        if not usable:
            unanswered.append(dimension)
            profiles.append(_blind(dimension))
            notes.append(
                f"{dimension}: no plane on this grid carries {probe_field}. "
                f"Tried {', '.join(candidates)}."
            )
            continue

        direction = _direction_for(dimension, planes=usable)
        query = {
            "bool": {
                "filter": [
                    _window_filter(minutes, time_anchor, lag_minutes=lag_minutes),
                    {
                        "bool": {
                            "should": [_dataset_clause(d) for d in usable],
                            "minimum_should_match": 1,
                        }
                    },
                    {"exists": {"field": entity_field}},
                    {"exists": {"field": member_field}},
                    *_port_bound(member_field),
                    *direction["filter"],
                ],
                "must_not": [
                    *_scope_must_not(),
                    *_outside_the_estate(dimension, cidrs=cidrs),
                    *direction["must_not"],
                ],
            }
        }
        aggs = {
            dimension: _nested_terms(
                entity_field=entity_field,
                member_field=member_field,
                peer_field=_peer_field(dimension),
            )
        }
        try:
            result = await elastic.search(settings.events_index_pattern, query, size=0, aggs=aggs)
        except Exception as exc:
            errors.append(f"{dimension}: {exc}")
            continue

        buckets = ((result.aggregations or {}).get(dimension) or {}).get("buckets") or []
        entity_kind = "user" if dimension == "logon_users" else "host"
        profiles.extend(
            _profiles_from_buckets(
                buckets,
                dimension=dimension,
                entity_kind=entity_kind,
                window_days=window_days,
                cidrs=cidrs,
            )
        )

    tz = str(getattr(settings, "so_timezone", "UTC") or "UTC")
    cache = resolved.setdefault(_SHAPED_CANDIDATES, {})
    if _SHAPED_PROBE_FIELD not in cache:
        cache[_SHAPED_PROBE_FIELD] = await resolve_plane(
            elastic,
            settings,
            candidates=_SHAPED_CANDIDATES,
            field=_SHAPED_PROBE_FIELD,
            minutes=minutes,
            time_anchor=time_anchor,
            lag_minutes=lag_minutes,
        )
    usable = cache[_SHAPED_PROBE_FIELD]
    if usable is None:
        for dimension in _SHAPED_DIMENSIONS:
            errors.append(
                f"{dimension}: could not determine which plane carries {_SHAPED_PROBE_FIELD}"
            )
    elif not usable:
        for dimension in _SHAPED_DIMENSIONS:
            profiles.append(_blind(dimension))
            unanswered.append(dimension)
    else:
        query = {
            "bool": {
                "filter": [
                    _window_filter(minutes, time_anchor, lag_minutes=lag_minutes),
                    {
                        "bool": {
                            "should": [_dataset_clause(d) for d in usable],
                            "minimum_should_match": 1,
                        }
                    },
                    {"exists": {"field": _SHAPED_ENTITY_FIELD}},
                    *_estate_filter(_SHAPED_ENTITY_FIELD, cidrs=cidrs),
                ],
                "must_not": _scope_must_not(),
            }
        }
        entity_buckets: list[dict[str, Any]] = []
        refusal: str | None = None
        try:
            entity_buckets, refusal = await _collect_shaped(
                elastic,
                settings,
                query,
                entity_field=_SHAPED_ENTITY_FIELD,
                window_hours=max(1, window_hours),
                window_days=window_days,
            )
        except Exception as exc:
            for dimension in _SHAPED_DIMENSIONS:
                errors.append(f"{dimension}: {exc}")
        if refusal is not None:
            for dimension in _SHAPED_DIMENSIONS:
                unmeasurable[dimension] = refusal
        for bucket in entity_buckets:
            key = bucket.get("key")
            if not isinstance(key, str) or not key:
                continue
            if not _ours(key, entity_kind="host", cidrs=cidrs):
                continue
            support = _entity_support_days(bucket, window_days=window_days)
            for dimension, shape in _SHAPED:
                vector = (
                    _active_hours_vector(bucket, tz=tz)
                    if shape == "active_hours"
                    else _rate_vector(bucket, tz=tz)
                )
                profiles.append(
                    BuiltProfile(
                        entity_kind="host",
                        entity_key=key,
                        dimension=dimension,
                        shape=shape,
                        vector=vector,
                        coverage="measured" if support >= MIN_SUPPORT_DAYS else "learning",
                        support_days=support,
                    )
                )

    return ProfileSweep(
        profiles=tuple(profiles),
        planes=planes,
        errors=tuple(errors),
        notes=tuple(notes),
        unanswered=tuple(unanswered),
        unmeasurable=unmeasurable,
    )
