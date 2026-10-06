"""Detector 2: a host receives a session, then reaches a new host minutes later.

The pivot of 2026-08-05 on this lab is the case. A session landed on a host,
and seconds later that host tried SSH against a third host it had never
reached. A profile is per entity, so tier 2 cannot see an order in time
across two hosts.

**What it learns.** The edge set: which source address opened an accepted
session on which host, over ``learning_days`` before the recent window. The
sessions are Windows logons (4624 of logon type 3 or 10, with a source
address) and Linux accepted logons (``system.auth``, sshd Accepted). A host's
outbound edges are the edges whose source is one of its own addresses. Its
addresses are the ``host.ip`` values its own agent reports.

**When it fires.** A session lands on host B from another host. Within
``chain_minutes`` B makes its first attempt to a third host C: an accepted or
a failed logon on C from one of B's addresses. C is not in B's learned edge
set, B had not tried C earlier in the recent read, and the edge set is warm:
``warm_days`` of history for the estate and for B.

**What it does not read.** An attempt is read from the logon plane of C. An
attempt to a host that ships no logon plane, seen in the sensor's flows only,
is out of scope: the edge set learns from logons only, so every flow to such
a host would read as new.

**What a hit cites.** The session document on B and the attempt document on
C, the minutes between them and the number of outbound edges B had.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.dossier.profile import _dataset_clause, _scope_must_not
from soc_ai.hunting.detectors.base import (
    STATE_LEARNING,
    STATE_MEASURED,
    STATE_UNMEASURABLE,
    STATISTIC_CHAIN_MINUTES,
    DetectorContext,
    DetectorRun,
    EntityState,
    ModelHit,
    iso,
    oql_stamp,
    plain_address,
)
from soc_ai.hunting.detectors.params import LogonChainParams
from soc_ai.hunting.match import get_field
from soc_ai.hunting.rerun import oql_value
from soc_ai.hunting.weight import Kind
from soc_ai.hunting.wording import plural
from soc_ai.so_client.paging import CompositeRead

__all__ = ["DETECTOR_ID", "detect"]

DETECTOR_ID = "logon_chain"

# The Windows logon types that carry a session from another host: 3 is a
# network logon, 10 a remote interactive one. Winlogbeat writes the number,
# and some pipelines write the name.
_SESSION_TYPES = frozenset({"3", "10", "network", "remoteinteractive"})

# How many targets one page of the edge read holds, the most one read holds,
# and the most source addresses one target's edges keep.
_PAGE = 500
_MAX_TARGETS = 20_000
_MAX_SOURCES = 500
_MAX_ADDRESSES = 16

# The fields the recent read keeps of each logon document.
_FIELDS = [
    "@timestamp",
    "host.name",
    "host.ip",
    "source.ip",
    "event.code",
    "event.dataset",
    "data_stream.dataset",
    "event.outcome",
    "system.auth.ssh.event",
    "winlog.event_data.LogonType",
    "winlog.logon.type",
]


def _windows_session() -> dict[str, Any]:
    """A Windows logon that carries a session from another host."""
    return {
        "bool": {
            "filter": [
                {"term": {"event.code": "4624"}},
                {
                    "bool": {
                        "should": [
                            {"terms": {"winlog.event_data.LogonType": ["3", "10"]}},
                            {"terms": {"winlog.logon.type": ["Network", "RemoteInteractive"]}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            ]
        }
    }


def _accepted_clause() -> dict[str, Any]:
    """An accepted session: sshd Accepted, or a Windows network or remote logon.

    The ``system.auth`` clause is the profile builder's own scope of the plane,
    so the edge set and the logon-user baseline read the same accepted logons.
    """
    return {
        "bool": {
            "should": [_dataset_clause("system.auth"), _windows_session()],
            "minimum_should_match": 1,
        }
    }


def _attempt_clause() -> dict[str, Any]:
    """Any logon line with a source: accepted, failed or an invalid user."""
    return {
        "bool": {
            "should": [
                {"term": {"event.dataset": "system.auth"}},
                {"term": {"data_stream.dataset": "system.auth"}},
                {"terms": {"event.code": ["4624", "4625"]}},
            ],
            "minimum_should_match": 1,
        }
    }


def _loopback() -> dict[str, Any]:
    return {"terms": {"source.ip": ["127.0.0.1", "::1"]}}


def _fold(name: str) -> str:
    return name.strip().rstrip(".").casefold()


def _stamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value) / 1000.0, tz=UTC)
    if not isinstance(value, str) or not value:
        return None
    try:
        at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


def _metric_time(node: Any) -> datetime | None:
    if not isinstance(node, Mapping):
        return None
    return _stamp(node.get("value_as_string")) or _stamp(node.get("value"))


def _values(raw: Any) -> list[Any]:
    if raw is None:
        return []
    return list(raw) if isinstance(raw, (list, tuple)) else [raw]


@dataclass
class _Target:
    """One host that received accepted sessions in the learning window."""

    name: str
    first: datetime | None = None
    # source address -> first accepted session from it
    sources: dict[str, datetime] = field(default_factory=dict)
    addresses: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class _Logon:
    """One logon document of the recent read."""

    doc_id: str
    at: datetime
    target: str
    target_name: str
    source: str
    accepted: bool
    protocol: str


async def _read_edges(
    ctx: DetectorContext, *, since: datetime, until: datetime, notes: list[str]
) -> dict[str, _Target]:
    """The edge set: per target host, the sources of its accepted sessions."""
    query = {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": iso(since), "lt": iso(until)}}},
                _accepted_clause(),
                {"exists": {"field": "source.ip"}},
                {"exists": {"field": "host.name"}},
            ],
            "must_not": [*_scope_must_not(), _loopback()],
        }
    }
    aggs = {
        "first": {"min": {"field": "@timestamp"}},
        "sources": {
            "terms": {"field": "source.ip", "size": _MAX_SOURCES},
            "aggs": {"first": {"min": {"field": "@timestamp"}}},
        },
        "addresses": {"terms": {"field": "host.ip", "size": _MAX_ADDRESSES}},
    }
    reader = CompositeRead(
        ctx.elastic,
        ctx.index,
        query,
        name="logon_edges",
        field="host.name",
        aggs=aggs,
        page_size=_PAGE,
        ceiling=_MAX_TARGETS,
    )
    targets: dict[str, _Target] = {}
    capped_sources = 0
    async for page in reader.pages():
        for bucket in page:
            name = bucket.get("key")
            if not isinstance(name, str) or not name.strip():
                continue
            target = targets.setdefault(_fold(name), _Target(name=name))
            target.first = _metric_time(bucket.get("first")) or target.first
            sources = bucket.get("sources") or {}
            if int(sources.get("sum_other_doc_count") or 0) > 0:
                capped_sources += 1
            for row in sources.get("buckets") or ():
                address = plain_address(row.get("key")) if isinstance(row, dict) else None
                first = _metric_time(row.get("first")) if isinstance(row, dict) else None
                if address and first is not None:
                    held = target.sources.get(address)
                    target.sources[address] = first if held is None else min(held, first)
            for row in (bucket.get("addresses") or {}).get("buckets") or ():
                address = plain_address(row.get("key")) if isinstance(row, dict) else None
                if address and ctx.in_estate(address):
                    target.addresses.add(address)
    if reader.capped:
        notes.append(
            f"the edge read stopped at the ceiling of {_MAX_TARGETS:,} hosts. "
            "The detector did not score the hosts past the ceiling."
        )
    if capped_sources:
        notes.append(
            f"{plural(capped_sources, 'host')} received sessions from more than "
            f"{_MAX_SOURCES} sources. The edge set holds the busiest {_MAX_SOURCES} of each."
        )
    return targets


def _classify(source: Mapping[str, Any]) -> tuple[bool, str] | None:
    """Whether a logon document is an accepted session, and its protocol. None to skip."""
    code = str(get_field(source, "event.code") or "")
    if code == "4624":
        kind = {
            str(v).replace(" ", "").casefold()
            for v in (
                *_values(get_field(source, "winlog.event_data.LogonType")),
                *_values(get_field(source, "winlog.logon.type")),
            )
        }
        return (True, "Windows remote logon") if kind & _SESSION_TYPES else None
    if code == "4625":
        return False, "Windows remote logon"
    dataset = str(
        get_field(source, "event.dataset") or get_field(source, "data_stream.dataset") or ""
    )
    if dataset != "system.auth":
        return None
    event = str(get_field(source, "system.auth.ssh.event") or "")
    outcome = str(get_field(source, "event.outcome") or "")
    if event == "Accepted" or outcome == "success":
        return True, "SSH"
    if event in {"Failed", "Invalid"} or outcome == "failure":
        return False, "SSH"
    return None


async def _read_recent(
    ctx: DetectorContext,
    params: LogonChainParams,
    *,
    since: datetime,
    until: datetime,
    notes: list[str],
) -> tuple[list[_Logon], dict[str, set[str]]]:
    """The logon documents of the recent read, oldest first, and the addresses they name."""
    query = {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": iso(since), "lte": iso(until)}}},
                _attempt_clause(),
                {"exists": {"field": "source.ip"}},
                {"exists": {"field": "host.name"}},
            ],
            "must_not": [*_scope_must_not(), _loopback()],
        }
    }
    result = await ctx.elastic.search(
        ctx.index,
        query,
        size=params.max_events,
        sort=[{"@timestamp": {"order": "asc"}}],
        source=_FIELDS,
        track_total_hits=True,
    )
    hits = list(result.hits or [])
    total = int(result.total or 0)
    if total > len(hits):
        notes.append(
            f"the recent read held {total:,} logon documents. The detector scored the "
            f"oldest {len(hits):,}. A chain after them is not scored on this sweep."
        )
    logons: list[_Logon] = []
    addresses: dict[str, set[str]] = {}
    for hit in hits:
        if not isinstance(hit, dict) or not hit.get("_id"):
            continue
        body = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
        assert isinstance(body, dict)
        name = get_field(body, "host.name")
        name = name[0] if isinstance(name, list) and name else name
        source = plain_address(next(iter(_values(get_field(body, "source.ip"))), None))
        at = _stamp(get_field(body, "@timestamp"))
        shape = _classify(body)
        if not isinstance(name, str) or not name.strip() or source is None or at is None:
            continue
        for raw in _values(get_field(body, "host.ip")):
            address = plain_address(raw)
            if address and ctx.in_estate(address):
                addresses.setdefault(_fold(name), set()).add(address)
        if shape is None:
            continue
        logons.append(
            _Logon(
                doc_id=str(hit["_id"]),
                at=at,
                target=_fold(name),
                target_name=name,
                source=source,
                accepted=shape[0],
                protocol=shape[1],
            )
        )
    logons.sort(key=lambda logon: (logon.at, logon.doc_id))
    return logons, addresses


@dataclass(frozen=True)
class _Chain:
    session: _Logon
    attempt: _Logon
    learned: int


def _owners(addresses: Mapping[str, set[str]]) -> dict[str, str]:
    """Address -> the one host that reports it. An address two hosts report joins neither."""
    count: dict[str, int] = {}
    for held in addresses.values():
        for address in held:
            count[address] = count.get(address, 0) + 1
    return {a: host for host, held in addresses.items() for a in held if count[a] == 1}


def _rerun(b_name: str, b_addresses: list[str], chain: _Chain) -> str:
    """The OQL query that shows the session on B and the attempt from B."""
    start = chain.session.at - timedelta(minutes=1)
    end = chain.attempt.at + timedelta(minutes=1)
    parts = [f"host.name:{oql_value(b_name)}"]
    parts.extend(f"source.ip:{oql_value(a)}" for a in b_addresses[:4])
    return (
        f"({' OR '.join(parts)}) AND "
        f'@timestamp:["{oql_stamp(start)}" TO "{oql_stamp(end)}"] | groupby host.name'
    )


def _minutes(chain: _Chain) -> float:
    return round((chain.attempt.at - chain.session.at).total_seconds() / 60.0, 1)


def _number(value: float) -> str:
    return f"{value:.0f}" if abs(value - round(value)) < 0.05 else f"{value:.1f}"


def _reason(b_name: str, chain: _Chain, *, source_label: str, learning_days: int) -> str:
    gap = _minutes(chain)
    word = "minute" if _number(gap) == "1" else "minutes"
    outcome = "accepted" if chain.attempt.accepted else "failed"
    return (
        f"{b_name} received a session from {source_label} at "
        f"{chain.session.at.strftime('%H:%M')} UTC. {_number(gap)} {word} later {b_name} "
        f"made its first {chain.attempt.protocol} attempt to {chain.attempt.target_name}, "
        f"and the attempt was {outcome}. The learned edge set of {b_name} held "
        f"{plural(chain.learned, 'outbound edge')} over {plural(learning_days, 'day')}."
    )


def _chains(
    b: str,
    logons: list[_Logon],
    *,
    b_addresses: set[str],
    learned_out: set[str],
    owners: Mapping[str, str],
    params: LogonChainParams,
) -> list[_Chain]:
    """Every first attempt from B to a new third host that follows a session on B."""
    window = timedelta(minutes=params.chain_minutes)
    sessions = [x for x in logons if x.target == b and x.accepted and x.source not in b_addresses]
    seen: set[str] = set()
    out: list[_Chain] = []
    for attempt in logons:
        if attempt.source not in b_addresses or attempt.target == b:
            continue
        if attempt.target in seen:
            # Not B's first attempt to this host in the read.
            continue
        seen.add(attempt.target)
        if attempt.target in learned_out:
            continue
        session = next(
            (
                s
                for s in reversed(sessions)
                if s.at <= attempt.at <= s.at + window
                # A third host: the attempt does not go back to the session's source.
                and owners.get(s.source) != attempt.target
            ),
            None,
        )
        if session is not None:
            out.append(_Chain(session=session, attempt=attempt, learned=len(learned_out)))
    return out


def _first_sight(b: str, targets: Mapping[str, _Target], b_addresses: set[str]) -> datetime | None:
    """When the edge set first saw B, as a target or as a source."""
    stamps: list[datetime] = []
    own = targets.get(b)
    if own is not None and own.first is not None:
        stamps.append(own.first)
    for target in targets.values():
        stamps.extend(at for address, at in target.sources.items() if address in b_addresses)
    return min(stamps) if stamps else None


async def detect(params: LogonChainParams, ctx: DetectorContext) -> DetectorRun:
    """Score every host the logon plane names. Raises when a grid read fails."""
    notes: list[str] = []
    until = ctx.now
    since = until - timedelta(hours=params.window_hours, minutes=params.chain_minutes)
    learn_from = since - timedelta(days=params.learning_days)
    targets = await _read_edges(ctx, since=learn_from, until=since, notes=notes)
    logons, recent_addresses = await _read_recent(
        ctx, params, since=since, until=until, notes=notes
    )
    if not targets and not logons:
        return DetectorRun(
            notes=tuple(notes),
            blind=(
                "no logon plane holds an accepted session with a source address in "
                f"the last {plural(params.learning_days, 'day')}"
            ),
        )

    addresses: dict[str, set[str]] = {k: set(t.addresses) for k, t in targets.items()}
    for host, held in recent_addresses.items():
        addresses.setdefault(host, set()).update(held)
    owners = _owners(addresses)
    names = {k: t.name for k, t in targets.items()}
    names.update({x.target: x.target_name for x in logons})
    estate_first = min((t.first for t in targets.values() if t.first is not None), default=None)
    warm = timedelta(days=params.warm_days)
    estate_warm = estate_first is not None and until - estate_first >= warm

    entities: list[EntityState] = []
    for b in sorted(names):
        b_name = names[b]
        b_addresses = {a for a in addresses.get(b, set()) if owners.get(a) == b}
        if not b_addresses:
            entities.append(
                EntityState(
                    entity_key=b_name,
                    state=STATE_UNMEASURABLE,
                    note=(
                        "soc-ai knows no address of this host, so it cannot see the "
                        "attempts the host makes."
                    ),
                )
            )
            continue
        first = _first_sight(b, targets, b_addresses)
        if not estate_warm or first is None or until - first < warm:
            entities.append(
                EntityState(
                    entity_key=b_name,
                    state=STATE_LEARNING,
                    note=f"learning: the edge set holds under {plural(params.warm_days, 'day')}.",
                )
            )
            continue
        learned_out = {
            k
            for k, t in targets.items()
            if k != b and any(address in b_addresses for address in t.sources)
        }
        chains = _chains(
            b,
            logons,
            b_addresses=b_addresses,
            learned_out=learned_out,
            owners=owners,
            params=params,
        )
        hits: list[ModelHit] = []
        for chain in chains:
            source_owner = owners.get(chain.session.source)
            source_label = (
                f"{names.get(source_owner, source_owner)} ({chain.session.source})"
                if source_owner
                else chain.session.source
            )
            ordered = sorted(b_addresses)
            hits.append(
                ModelHit(
                    entity_key=b_name,
                    kind=Kind.LOGON_CHAIN,
                    fingerprint=(DETECTOR_ID, chain.attempt.target),
                    statistic=STATISTIC_CHAIN_MINUTES,
                    statistic_value=_minutes(chain),
                    baseline_value=float(chain.learned),
                    document_ids=(chain.session.doc_id, chain.attempt.doc_id),
                    rerun_query=_rerun(b_name, ordered, chain),
                    reason=_reason(
                        b_name,
                        chain,
                        source_label=source_label,
                        learning_days=params.learning_days,
                    ),
                    features={
                        "gap_minutes": _minutes(chain),
                        "learned_edges": chain.learned,
                        "attempt_target": chain.attempt.target_name,
                        "attempt_outcome": "accepted" if chain.attempt.accepted else "failed",
                        "session_source": chain.session.source,
                        "session_at": iso(chain.session.at),
                        "attempt_at": iso(chain.attempt.at),
                        "protocol": chain.attempt.protocol,
                    },
                    observed_at=chain.attempt.at,
                )
            )
        entities.append(
            EntityState(
                entity_key=b_name,
                state=STATE_MEASURED,
                note=" ".join(h.reason for h in hits) or "Nothing departed.",
                hits=tuple(hits),
            )
        )
    edges = sum(len(t.sources) for t in targets.values())
    notes.append(
        f"read {plural(edges, 'learned edge')} into {plural(len(targets), 'host')} and "
        f"{plural(len(logons), 'logon document')} in the recent read."
    )
    return DetectorRun(entities=tuple(entities), notes=tuple(notes))
