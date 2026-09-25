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
from datetime import datetime
from typing import Any

from soc_ai.dossier.profile_math import summarise_cells
from soc_ai.enrichment.discovery import _is_internal_ip, _is_ip_literal
from soc_ai.so_client.elastic import ElasticClient
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


def _member_aggs() -> dict[str, Any]:
    """Per-member sub-aggregations: when it was first and last seen."""
    return {
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}},
    }


def _nested_terms(*, entity_field: str, member_field: str) -> dict[str, Any]:
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
                "aggs": _member_aggs(),
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

    A host keyed on its name rather than an address passes for the same
    reason. The process and logon dimensions key their rows on ``host.name``,
    which only an agent on the machine can ship, and a hostname fails the
    address test however local the machine is: with CIDRs configured every one
    of those rows was dropped as foreign.
    """
    if entity_kind != "host" or not cidrs or not _is_ip_literal(key):
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
            vector[name] = {
                "count": int(member.get("doc_count") or 0),
                "first_seen": m_first,
                "last_seen": m_last,
            }
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

# Dimensions that are not membership sets.
#
# ``active_hours`` is a 168-bin SET test — "was this host ever active in this
# hour of the week" — and needs no dispersion, which is why it does not go
# through the three-cell summary. ``connection_rate`` is the three-cell one.
#
# Both exist because without them there is exactly ONE observation kind
# available on a network-only grid, and a lead needs two. The chaining half of
# the design was inert on the range for precisely that reason.
_SHAPED: tuple[tuple[str, str, tuple[str, ...], str, str], ...] = (
    ("active_hours", "active_hours", FLOW_CANDIDATES, "destination.ip", "source.ip"),
    ("connection_rate", "numeric", FLOW_CANDIDATES, "destination.ip", "source.ip"),
)


def _shaped_aggs(dimension: str, shape: str, *, entity_field: str) -> dict[str, Any]:
    """The aggregation for a non-categorical dimension."""
    inner: dict[str, Any] = {
        "active_days": {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "day",
                "min_doc_count": 1,
            }
        }
    }
    if shape == "active_hours":
        # Hour of DAY, not hour of week. The design says 168 bins, and 168 is
        # right for a set test in principle — but on a 30-day window each bin
        # holds four or five samples, and "this host has never been active in
        # this hour" then rests on four observations. Hour of day gives thirty
        # per bin. The weekday/weekend split that 168 bins were carrying is
        # already held by the three-cell rate dimension.
        inner["hours"] = {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "hour",
                "min_doc_count": 1,
            }
        }
    else:
        inner["per_hour"] = {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "hour",
                "min_doc_count": 1,
            }
        }
    return {
        dimension: {
            "terms": {"field": entity_field, "size": _MAX_ENTITIES},
            "aggs": inner,
        }
    }


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
    for hour_bucket in ((bucket.get("per_hour") or {}).get("buckets")) or []:
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
            profiles.append(_blind(dimension))
            notes.append(
                f"{dimension}: no plane on this grid carries {probe_field}. "
                f"Tried {', '.join(candidates)}."
            )
            continue

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
                ],
                "must_not": [
                    *_scope_must_not(),
                    *_outside_the_estate(dimension, cidrs=cidrs),
                ],
            }
        }
        aggs = {dimension: _nested_terms(entity_field=entity_field, member_field=member_field)}
        try:
            result = await elastic.search(settings.events_index_pattern, query, size=0, aggs=aggs)
        except Exception as exc:
            errors.append(f"{dimension}: {exc}")
            continue

        buckets = ((result.aggregations or {}).get(dimension) or {}).get("buckets") or []
        # Every categorical dimension is a HOST profile, the logon one
        # included: its entity is the machine logged on to and the users are
        # its members. It was once labelled ``user``, and since every reader
        # loads a host's profile under ``host`` the stored logon set was
        # unreachable.
        profiles.extend(
            _profiles_from_buckets(
                buckets,
                dimension=dimension,
                entity_kind="host",
                window_days=window_days,
                cidrs=cidrs,
            )
        )

    tz = str(getattr(settings, "so_timezone", "UTC") or "UTC")
    for dimension, shape, candidates, probe_field, entity_field in _SHAPED:
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
        if usable is None:
            errors.append(f"{dimension}: could not determine which plane carries {probe_field}")
            continue
        if not usable:
            profiles.append(_blind(dimension))
            continue

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
                ],
                "must_not": _scope_must_not(),
            }
        }
        try:
            result = await elastic.search(
                settings.events_index_pattern,
                query,
                size=0,
                aggs=_shaped_aggs(dimension, shape, entity_field=entity_field),
            )
        except Exception as exc:
            errors.append(f"{dimension}: {exc}")
            continue

        buckets = ((result.aggregations or {}).get(dimension) or {}).get("buckets") or []
        for bucket in buckets:
            key = bucket.get("key")
            if not isinstance(key, str) or not key:
                continue
            if not _ours(key, entity_kind="host", cidrs=cidrs):
                continue
            support = _entity_support_days(bucket, window_days=window_days)
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
    )
