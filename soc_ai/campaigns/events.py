"""The events of a campaign: the alert events of the grid between its machines.

A member of a campaign is one investigation of soc-ai. The analyst counts
events: an event is one record of the grid, and an alert is an event of a
detection rule. This module counts the alert events between each pair of
machines of a campaign, by rule.

:func:`stored_events` counts the alert documents that the true positive
members hold. It is pure. :func:`read_events` reads the grid: one search for
the whole campaign, bounded by :data:`READ_TIMEOUT_S`. The read covers the
:data:`MAX_PAIRS` pairs of machines with the most member investigations, 20.
A campaign with more pairs shows the grid events of those 20 pairs only. A
failed or slow read gives None and one warning, and never raises.

A **confirmed rule** of a pair is a rule name that a true positive alert
investigation of the campaign has between the two machines, in either
direction, or that an alert document between the two machines holds in a true
positive finding investigation. The alert count of a pair counts the alert
events of its confirmed rules. ``other_alerts`` counts every other rule. The
service reads the verdict of each other rule from the store.

Every time is a naive UTC ``datetime``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from soc_ai.campaigns.types import (
    DIRECTION_REVERSE,
    KIND_ALERT,
    KIND_FINDING,
    CampaignDraft,
    DocFacts,
    Member,
    naive_utc,
)
from soc_ai.so_client.fields import ENVELOPE_FIELD
from soc_ai.store.authorized_activity import rule_name_key
from soc_ai.tools._synth_scope import synth_scope_must_not

if TYPE_CHECKING:
    from soc_ai.config import Settings
    from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)

SOURCE_GRID = "grid"
SOURCE_STORED = "stored"
SOURCE_NONE = "none"
SOURCES = frozenset({SOURCE_GRID, SOURCE_STORED, SOURCE_NONE})

VERDICT_CONFIRMED = "true_positive"
VERDICT_NOT_JUDGED = "not_judged"
VERDICTS = frozenset({VERDICT_CONFIRMED, "false_positive", "needs_more_info", VERDICT_NOT_JUDGED})

# The most pairs of machines that one grid read covers: the pairs with the
# most member investigations.
MAX_PAIRS = 20
# The most rules and datasets that the read lists for one pair.
MAX_RULES = 50
MAX_DATASETS = 8
# The most bucket slots that the window of one pair spans. The grid returns
# only the buckets that hold an alert, and an attack is short bursts, so the
# answer holds far fewer. The interval decides how far the timeline of the
# console can zoom in: 19 days read in steps of 15 minutes.
MAX_BUCKETS = 2000
# The read reaches this far before the first event and after the last one.
WINDOW_PAD = timedelta(minutes=30)
# The bound of the whole grid read, in seconds.
READ_TIMEOUT_S = 10.0
# The bucket of the stored events: the minute of the document.
STORED_BUCKET_SECONDS = 60
# The fixed intervals of the timeline, shortest first.
INTERVALS: tuple[tuple[str, int], ...] = (
    ("1m", 60),
    ("5m", 300),
    ("15m", 900),
    ("1h", 3600),
    ("3h", 10800),
    ("6h", 21600),
    ("12h", 43200),
    ("1d", 86400),
)

# An alert event: a record of a dataset whose name ends in ".alert", the rule
# that the facts of a run apply to a stored document.
_ALERT_CLAUSE: dict[str, Any] = {"wildcard": {"event.dataset": {"value": "*.alert"}}}

_READ_LINE = (
    "campaigns: soc-ai could not read the events of the campaign from the grid. "
    "The page shows the events that the investigations hold."
)


# ── Records ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RuleEvents:
    """The alert events of one rule between two machines.

    ``verdict`` is ``true_positive`` for a confirmed rule. The service gives
    every other rule ``false_positive``, ``needs_more_info`` or ``not_judged``.
    """

    name: str
    alerts: int
    first_at: datetime
    last_at: datetime
    verdict: str = VERDICT_NOT_JUDGED


@dataclass(frozen=True)
class DatasetRecords:
    name: str
    records: int


@dataclass(frozen=True)
class PairEvents:
    """The events between two machines. ``source`` is the actor side of the pair.

    ``alerts`` counts the alert events of the confirmed rules, and
    ``other_alerts`` the alert events of every other rule. ``first_at`` and
    ``last_at`` bound the alert events of the confirmed rules. ``records`` is
    every grid record between the two machines, and None for stored events.
    """

    source: str
    target: str
    alerts: int = 0
    other_alerts: int = 0
    records: int | None = None
    first_at: datetime | None = None
    last_at: datetime | None = None
    rules: tuple[RuleEvents, ...] = ()
    datasets: tuple[DatasetRecords, ...] = ()


@dataclass(frozen=True)
class Bucket:
    at: datetime
    alerts: int


@dataclass(frozen=True)
class Lane:
    """The alert events of the confirmed rules of the pairs of one actor side."""

    machine_key: str
    buckets: tuple[Bucket, ...] = ()


@dataclass(frozen=True)
class Timeline:
    bucket_seconds: int = STORED_BUCKET_SECONDS
    lanes: tuple[Lane, ...] = ()


@dataclass(frozen=True)
class CampaignEvents:
    """The events of a campaign.

    ``source`` is ``grid`` for a grid read, ``stored`` for the events that the
    investigations hold, and ``none`` for a merged or withdrawn campaign.
    ``alerts`` sums the alerts of the pairs, and ``rules`` counts the distinct
    confirmed rules with an event. ``findings`` counts the true positive
    finding investigations. ``records`` sums the records of the pairs, and is
    None unless the source is the grid.
    """

    source: str = SOURCE_NONE
    read_at: datetime | None = None
    alerts: int = 0
    rules: int = 0
    findings: int = 0
    records: int | None = None
    pairs: tuple[PairEvents, ...] = ()
    timeline: Timeline = field(default_factory=Timeline)

    @classmethod
    def from_json(cls, data: Any) -> CampaignEvents:
        """The events of a stored value. A value that is no event record reads as none."""
        try:
            return _events_of(data)
        except Exception:
            return cls()


@dataclass(frozen=True)
class PairSpec:
    """What the grid read needs of one pair of machines.

    ``confirmed`` holds the confirmed rule names, whitespace folded.
    ``investigations`` counts the true positive members of the pair.
    """

    source: str
    target: str
    source_addresses: tuple[str, ...]
    target_addresses: tuple[str, ...]
    confirmed: frozenset[str] = frozenset()
    investigations: int = 0


# ── The pairs of a campaign ────────────────────────────────────────────────


def _positives(draft_or_members: CampaignDraft | Iterable[Member]) -> list[Member]:
    members = (
        draft_or_members.members
        if isinstance(draft_or_members, CampaignDraft)
        else tuple(draft_or_members)
    )
    held = [m for m in members if not m.verdict_differs and m.run.is_true_positive]
    return sorted(held, key=lambda m: (m.run.event_time or datetime.max, m.run.run_id))


def _alert_between(doc: DocFacts, machines: set[str] | frozenset[str]) -> bool:
    """True for an alert document whose two machines are two parties."""
    return (
        doc.is_alert
        and doc.source is not None
        and doc.target is not None
        and doc.source != doc.target
        and doc.source in machines
        and doc.target in machines
    )


@dataclass
class _PairAcc:
    runs: set[str] = field(default_factory=set)
    by_run: Counter[tuple[str, str]] = field(default_factory=Counter)
    by_document: Counter[tuple[str, str]] = field(default_factory=Counter)
    order: dict[tuple[str, str], int] = field(default_factory=dict)
    confirmed: set[str] = field(default_factory=set)

    def side(self) -> tuple[str, str]:
        """The direction of the pair: the actor side first.

        The direction of most member investigations, as the engine draws the
        arrow: a run on the answer of a server counts on the arrow of its
        actor. A pair that only alert documents show takes the direction of
        most of them. The earliest decides a tie.
        """
        held = self.by_run or self.by_document
        best = max(held.values())
        return min((k for k, n in held.items() if n == best), key=lambda k: self.order[k])


def _index(members: Sequence[Member], machines: set[str]) -> dict[frozenset[str], _PairAcc]:
    acc: dict[frozenset[str], _PairAcc] = defaultdict(_PairAcc)
    step = 0

    def note(counts: Counter[tuple[str, str]], a: _PairAcc, key: tuple[str, str]) -> None:
        nonlocal step
        counts[key] += 1
        a.order.setdefault(key, step)
        step += 1

    for m in members:
        r = m.run
        if (
            r.source is not None
            and r.target is not None
            and r.source != r.target
            and r.source in machines
            and r.target in machines
        ):
            reverse = m.direction == DIRECTION_REVERSE
            key = (r.target, r.source) if reverse else (r.source, r.target)
            a = acc[frozenset(key)]
            a.runs.add(r.run_id)
            note(a.by_run, a, key)
            if r.kind == KIND_ALERT:
                a.confirmed.update(r.rules)
        for doc in r.documents:
            if not _alert_between(doc, machines):
                continue
            assert doc.source is not None
            assert doc.target is not None
            a = acc[frozenset((doc.source, doc.target))]
            a.runs.add(r.run_id)
            note(a.by_document, a, (doc.source, doc.target))
            if r.kind != KIND_ALERT and doc.rule_key:
                # A finding confirms the rule of each alert document that it holds.
                a.confirmed.add(doc.rule_key)
    return acc


def campaign_pairs(
    draft_or_members: CampaignDraft | Iterable[Member],
    addresses: Mapping[str, Sequence[str]],
) -> tuple[PairSpec, ...]:
    """The pairs of machines of a campaign, the most member investigations first.

    ``addresses`` maps each party to its addresses.
    """
    members = _positives(draft_or_members)
    out: list[PairSpec] = []
    for acc in _index(members, set(addresses)).values():
        source, target = acc.side()
        out.append(
            PairSpec(
                source=source,
                target=target,
                source_addresses=tuple(addresses.get(source, ())),
                target_addresses=tuple(addresses.get(target, ())),
                confirmed=frozenset(acc.confirmed),
                investigations=len(acc.runs),
            )
        )
    return tuple(sorted(out, key=lambda p: (-p.investigations, p.source, p.target)))


def findings_of(draft_or_members: CampaignDraft | Iterable[Member]) -> int:
    """The true positive finding investigations of a campaign."""
    return sum(1 for m in _positives(draft_or_members) if m.run.kind == KIND_FINDING)


def events_basis(pairs: Iterable[PairSpec], start: datetime, end: datetime) -> str:
    """A SHA-1 over what a grid read reads: the pairs, their addresses, their confirmed rules
    and the window. A new basis needs a new read."""
    content = {
        "window": [start.isoformat(), end.isoformat()],
        "pairs": sorted(
            [
                p.source,
                p.target,
                sorted(p.source_addresses),
                sorted(p.target_addresses),
                sorted(p.confirmed),
            ]
            for p in pairs
        ),
    }
    text = json.dumps(content, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(text.encode(), usedforsecurity=False).hexdigest()


# ── The stored events ──────────────────────────────────────────────────────


@dataclass
class _RuleAcc:
    alerts: int = 0
    first: datetime | None = None
    last: datetime | None = None

    def add(self, at: datetime, count: int = 1) -> None:
        self.alerts += count
        self.first = at if self.first is None else min(self.first, at)
        self.last = at if self.last is None else max(self.last, at)


def _minute(at: datetime) -> datetime:
    return at.replace(second=0, microsecond=0)


def _pair_events(
    source: str,
    target: str,
    rules: Mapping[str, _RuleAcc],
    confirmed: frozenset[str] | set[str],
    *,
    records: int | None = None,
    datasets: tuple[DatasetRecords, ...] = (),
    alerts: int | None = None,
    other_alerts: int | None = None,
) -> PairEvents:
    listed: list[RuleEvents] = []
    for name, acc in rules.items():
        if acc.first is None or acc.last is None:
            continue
        verdict = VERDICT_CONFIRMED if rule_name_key(name) in confirmed else VERDICT_NOT_JUDGED
        listed.append(RuleEvents(name, acc.alerts, acc.first, acc.last, verdict))
    listed.sort(key=lambda r: (-r.alerts, r.name))
    held = [r for r in listed if r.verdict == VERDICT_CONFIRMED]
    return PairEvents(
        source=source,
        target=target,
        alerts=sum(r.alerts for r in held) if alerts is None else alerts,
        other_alerts=(
            sum(r.alerts for r in listed if r.verdict != VERDICT_CONFIRMED)
            if other_alerts is None
            else other_alerts
        ),
        records=records,
        first_at=min((r.first_at for r in held), default=None),
        last_at=max((r.last_at for r in held), default=None),
        rules=tuple(listed),
        datasets=datasets,
    )


def _timeline(seconds: int, lanes: Mapping[str, Mapping[datetime, int]]) -> Timeline:
    out = [
        Lane(key, tuple(Bucket(at, n) for at, n in sorted(buckets.items()) if n > 0))
        for key, buckets in lanes.items()
    ]
    out = [lane for lane in out if lane.buckets]
    out.sort(key=lambda lane: (lane.buckets[0].at, lane.machine_key))
    return Timeline(seconds, tuple(out))


def _summary(
    source: str,
    pairs: Sequence[PairEvents],
    timeline: Timeline,
    *,
    findings: int,
    read_at: datetime | None = None,
    records: int | None = None,
) -> CampaignEvents:
    ordered = sorted(pairs, key=lambda p: (-p.alerts, -p.other_alerts, p.source, p.target))
    confirmed = {
        rule_name_key(r.name) for p in ordered for r in p.rules if r.verdict == VERDICT_CONFIRMED
    }
    return CampaignEvents(
        source=source,
        read_at=read_at,
        alerts=sum(p.alerts for p in ordered),
        rules=len(confirmed),
        findings=findings,
        records=records,
        pairs=tuple(ordered),
        timeline=timeline,
    )


def stored_events(
    draft_or_members: CampaignDraft | Iterable[Member],
    parties: Iterable[str],
) -> CampaignEvents:
    """The events that the true positive members hold. Pure.

    Each alert document whose two machines are parties is one alert event of
    its rule, on the pair of its two machines. One document id counts once in
    the campaign. A bucket of the timeline is the minute of the document.
    """
    members = _positives(draft_or_members)
    machines = set(parties)
    index = _index(members, machines)
    sides = {pair: acc.side() for pair, acc in index.items()}
    rules: dict[tuple[str, str], dict[str, _RuleAcc]] = defaultdict(dict)
    lanes: dict[str, Counter[datetime]] = defaultdict(Counter)
    seen: set[str] = set()
    for m in members:
        for doc in m.run.documents:
            if doc.id in seen or not doc.rule_key or doc.at is None:
                continue
            if not _alert_between(doc, machines):
                continue
            seen.add(doc.id)
            assert doc.source is not None
            assert doc.target is not None
            pair = frozenset((doc.source, doc.target))
            side = sides[pair]
            rules[side].setdefault(doc.rule_key, _RuleAcc()).add(doc.at)
            if doc.rule_key in index[pair].confirmed:
                lanes[side[0]][_minute(doc.at)] += 1
    pairs = [
        _pair_events(side[0], side[1], held, index[frozenset(side)].confirmed)
        for side, held in rules.items()
    ]
    return _summary(
        SOURCE_STORED,
        pairs,
        _timeline(STORED_BUCKET_SECONDS, lanes),
        findings=findings_of(members),
    )


# ── The grid read ──────────────────────────────────────────────────────────


def _epoch(at: datetime) -> int:
    return int(at.replace(tzinfo=UTC).timestamp())


def choose_interval(start: datetime, end: datetime) -> tuple[str, int]:
    """The shortest interval that holds the window in at most :data:`MAX_BUCKETS` buckets.

    A fixed interval aligns its buckets to the epoch, so the count is the
    count of aligned buckets that the window touches. A window too long for
    the longest interval takes that interval.
    """
    lo, hi = _epoch(start), _epoch(end)
    for name, seconds in INTERVALS:
        if hi // seconds - lo // seconds + 1 <= MAX_BUCKETS:
            return name, seconds
    return INTERVALS[-1]


def _iso(at: datetime) -> str:
    return at.isoformat() + "Z"


# The levels of a record that hold its two addresses: the top level, and the
# envelope. A Sigma alert of Security Onion holds the matched record under
# ``event_data`` (soc_ai.so_client.fields.envelope) and no address at its top
# level, so a read of the top level alone counted a confirmed Sigma rule 0.
# Production on 2026-11-16: each of 52 stored sigma.alert documents had a
# nested event_data, and none had a top-level source.ip or destination.ip. A
# level pairs its own two fields: one end never comes from the other level.
_ADDRESS_LEVELS: tuple[str, ...] = ("", f"{ENVELOPE_FIELD}.")


def _between(a: Sequence[str], b: Sequence[str]) -> dict[str, Any]:
    """The records between any address of one machine and any address of the other."""

    def way(level: str, source: Sequence[str], target: Sequence[str]) -> dict[str, Any]:
        return {
            "bool": {
                "filter": [
                    {"terms": {f"{level}source.ip": list(source)}},
                    {"terms": {f"{level}destination.ip": list(target)}},
                ]
            }
        }

    ways = [w for level in _ADDRESS_LEVELS for w in (way(level, a, b), way(level, b, a))]
    return {"bool": {"should": ways, "minimum_should_match": 1}}


def _search(
    pairs: Sequence[PairSpec], lo: datetime, hi: datetime, interval: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The query and the aggregations of one read for all pairs.

    The aggregation names avoid ``rules``, ``out``, ``in`` and ``volume``: the
    demo grid answers those names with the Alerts page and the host page.
    """
    clauses = {
        str(n): _between(p.source_addresses, p.target_addresses) for n, p in enumerate(pairs)
    }
    query: dict[str, Any] = {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": _iso(lo), "lte": _iso(hi)}}},
                {"bool": {"should": list(clauses.values()), "minimum_should_match": 1}},
            ],
            "must_not": synth_scope_must_not(False),
        }
    }
    aggs: dict[str, Any] = {
        "pairs": {
            "filters": {"filters": clauses},
            "aggs": {
                "datasets": {"terms": {"field": "event.dataset", "size": MAX_DATASETS}},
                "alerts": {
                    "filter": _ALERT_CLAUSE,
                    "aggs": {
                        "by_rule": {
                            "terms": {"field": "rule.name", "size": MAX_RULES},
                            "aggs": {
                                "first": {"min": {"field": "@timestamp"}},
                                "last": {"max": {"field": "@timestamp"}},
                            },
                        }
                    },
                },
            },
        }
    }
    confirmed = {
        str(n): {
            "bool": {
                "filter": [
                    clauses[str(n)],
                    _ALERT_CLAUSE,
                    {"terms": {"rule.name": sorted(p.confirmed)}},
                ]
            }
        }
        for n, p in enumerate(pairs)
        if p.confirmed
    }
    if confirmed:
        aggs["confirmed"] = {
            "filters": {"filters": confirmed},
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": interval,
                        "min_doc_count": 1,
                    }
                }
            },
        }
    return query, aggs


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _list(value: Any) -> list[Mapping[str, Any]]:
    return [v for v in value if isinstance(v, Mapping)] if isinstance(value, list) else []


def _metric_time(value: Any) -> datetime | None:
    """The time of a ``min`` or ``max`` of a date field."""
    held = _mapping(value)
    at = naive_utc(held.get("value_as_string"))
    if at is None and isinstance(held.get("value"), int | float):
        at = datetime.fromtimestamp(float(held["value"]) / 1000, UTC).replace(tzinfo=None)
    return at


def _key_time(bucket: Mapping[str, Any]) -> datetime | None:
    key = bucket.get("key")
    if isinstance(key, int | float) and not isinstance(key, bool):
        return datetime.fromtimestamp(float(key) / 1000, UTC).replace(tzinfo=None)
    return naive_utc(bucket.get("key_as_string"))


def _parse(
    pairs: Sequence[PairSpec],
    aggregations: Mapping[str, Any],
    seconds: int,
    read_at: datetime,
) -> CampaignEvents:
    by_pair = _mapping(_mapping(aggregations.get("pairs")).get("buckets"))
    by_confirmed = _mapping(_mapping(aggregations.get("confirmed")).get("buckets"))
    out: list[PairEvents] = []
    lanes: dict[str, Counter[datetime]] = defaultdict(Counter)
    for n, spec in enumerate(pairs):
        bucket = _mapping(by_pair.get(str(n)))
        alerts = _mapping(bucket.get("alerts"))
        rules: dict[str, _RuleAcc] = {}
        for item in _list(_mapping(alerts.get("by_rule")).get("buckets")):
            name, first = item.get("key"), _metric_time(item.get("first"))
            last = _metric_time(item.get("last")) or first
            if not isinstance(name, str) or not name or first is None or last is None:
                continue
            rules[name] = _RuleAcc(_count(item.get("doc_count")), first, last)
        confirmed = _mapping(by_confirmed.get(str(n)))
        held = _count(confirmed.get("doc_count"))
        for slot in _list(_mapping(confirmed.get("timeline")).get("buckets")):
            at = _key_time(slot)
            if at is not None:
                lanes[spec.source][at] += _count(slot.get("doc_count"))
        datasets = tuple(
            DatasetRecords(str(item["key"]), _count(item.get("doc_count")))
            for item in _list(_mapping(bucket.get("datasets")).get("buckets"))
            if isinstance(item.get("key"), str) and item.get("key")
        )
        out.append(
            _pair_events(
                spec.source,
                spec.target,
                rules,
                spec.confirmed,
                records=_count(bucket.get("doc_count")),
                datasets=datasets,
                alerts=held,
                other_alerts=max(0, _count(alerts.get("doc_count")) - held),
            )
        )
    return _summary(
        SOURCE_GRID,
        out,
        _timeline(seconds, lanes),
        findings=0,
        read_at=read_at,
        records=sum(p.records or 0 for p in out),
    )


async def _read(
    elastic: ElasticClient,
    settings: Settings,
    pairs: Sequence[PairSpec],
    start: datetime,
    end: datetime,
) -> CampaignEvents:
    lo, hi = start - WINDOW_PAD, end + WINDOW_PAD
    interval, seconds = choose_interval(lo, hi)
    read_at = datetime.now(UTC).replace(tzinfo=None)
    if not pairs:
        return CampaignEvents(source=SOURCE_GRID, read_at=read_at, records=0)
    query, aggs = _search(pairs, lo, hi, interval)
    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=0,
        aggs=aggs,
        track_total_hits=True,
        require_complete=True,
    )
    aggregations = result.aggregations or {}
    if not isinstance(aggregations.get("pairs"), Mapping):
        # A grid that did not evaluate the aggregations states no count.
        raise ValueError("the grid answered with no aggregation of the pairs")
    return _parse(pairs, aggregations, seconds, read_at)


async def read_events(
    elastic: ElasticClient,
    settings: Settings,
    *,
    pairs: Sequence[PairSpec],
    start: datetime,
    end: datetime,
) -> CampaignEvents | None:
    """The events of the grid between the pairs, from ``start`` less 30 minutes to ``end``
    plus 30 minutes. None when the read fails or takes more than :data:`READ_TIMEOUT_S`.

    The read covers the :data:`MAX_PAIRS` pairs with the most investigations.
    ``findings`` is 0: the caller knows the members. A partial result of the
    grid is a failure. The read never raises.
    """
    covered = sorted(
        (p for p in pairs if p.source_addresses and p.target_addresses),
        key=lambda p: (-p.investigations, p.source, p.target),
    )[:MAX_PAIRS]
    try:
        return await asyncio.wait_for(
            _read(elastic, settings, covered, start, end), timeout=READ_TIMEOUT_S
        )
    except Exception:
        _LOGGER.warning(_READ_LINE, exc_info=True)
        return None


# ── The alerts that a close acknowledges ───────────────────────────────────

# The most alert events that one close acknowledges.
CLOSE_SCOPE_MAX = 2000

_SCOPE_LINE = (
    "campaigns: soc-ai could not read the alerts that a close of the campaign acknowledges. "
    "The count is unknown."
)


@dataclass(frozen=True)
class CloseScope:
    """The alert events that a close of a campaign acknowledges.

    ``alerts`` and ``rules`` are None when the grid read failed: the count
    is unknown, never zero. ``capped`` is true when more than
    :data:`CLOSE_SCOPE_MAX` alert events wait. ``alert_ids`` holds the ids
    of the alert events, at most :data:`CLOSE_SCOPE_MAX`.
    """

    alerts: int | None
    rules: int | None
    capped: bool = False
    alert_ids: tuple[str, ...] = ()


def _dig(source: Mapping[str, Any], path: str) -> Any:
    """A field of a document, nested or flat."""
    if path in source:
        return source[path]
    held: Any = source
    for part in path.split("."):
        if not isinstance(held, Mapping):
            return None
        held = held.get(part)
    return held


def _scope_query(pairs: Sequence[PairSpec], lo: datetime, hi: datetime) -> dict[str, Any]:
    """The alert events of the confirmed rules between the pairs, not yet acknowledged."""
    clauses = [
        {
            "bool": {
                "filter": [
                    _between(p.source_addresses, p.target_addresses),
                    {"terms": {"rule.name": sorted(p.confirmed)}},
                ]
            }
        }
        for p in pairs
    ]
    return {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": _iso(lo), "lte": _iso(hi)}}},
                _ALERT_CLAUSE,
                {"bool": {"should": clauses, "minimum_should_match": 1}},
                {
                    "bool": {
                        "must_not": [
                            {"term": {"event.acknowledged": True}},
                            {"term": {"event.escalated": True}},
                        ]
                    }
                },
            ],
            "must_not": synth_scope_must_not(False),
        }
    }


async def read_close_scope(
    elastic: ElasticClient,
    settings: Settings,
    *,
    pairs: Sequence[PairSpec],
    start: datetime,
    end: datetime,
) -> CloseScope:
    """The alert events that a close acknowledges: one grid read. Never raises.

    The alert events of the confirmed rules between the machines of each
    pair, in the window of :func:`read_events`, that Security Onion has not
    acknowledged or escalated. The query leaves those out, and the flags of
    each hit leave out the rest: an index that does not map the flags still
    holds them in the document. A failed or slow read gives ``alerts`` None.
    """
    covered = sorted(
        (p for p in pairs if p.source_addresses and p.target_addresses and p.confirmed),
        key=lambda p: (-p.investigations, p.source, p.target),
    )[:MAX_PAIRS]
    if not covered:
        return CloseScope(alerts=0, rules=0)
    try:
        result = await asyncio.wait_for(
            elastic.search(
                settings.events_index_pattern,
                _scope_query(covered, start - WINDOW_PAD, end + WINDOW_PAD),
                size=CLOSE_SCOPE_MAX + 1,
                source=["rule.name", "event.acknowledged", "event.escalated"],
                sort=[{"@timestamp": {"order": "asc"}}],
                require_complete=True,
            ),
            timeout=READ_TIMEOUT_S,
        )
    except Exception:
        _LOGGER.warning(_SCOPE_LINE, exc_info=True)
        return CloseScope(alerts=None, rules=None)
    ids: list[str] = []
    rules: set[str] = set()
    for hit in result.hits:
        source = hit.get("_source")
        held = source if isinstance(source, Mapping) else {}
        doc_id = hit.get("_id")
        if not isinstance(doc_id, str) or not doc_id:
            continue
        if _dig(held, "event.acknowledged") is True or _dig(held, "event.escalated") is True:
            continue
        ids.append(doc_id)
        name = _dig(held, "rule.name")
        if isinstance(name, str) and name:
            rules.add(rule_name_key(name))
    capped = len(result.hits) > CLOSE_SCOPE_MAX
    kept = tuple(ids[:CLOSE_SCOPE_MAX])
    return CloseScope(alerts=len(kept), rules=len(rules), capped=capped, alert_ids=kept)


# ── The stored value ───────────────────────────────────────────────────────


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _events_of(data: Any) -> CampaignEvents:
    held = _mapping(data)
    if not held:
        return CampaignEvents()
    pairs: list[PairEvents] = []
    for item in _list(held.get("pairs")):
        source, target = _text(item.get("source")), _text(item.get("target"))
        if source is None or target is None:
            continue
        rules: list[RuleEvents] = []
        for rule in _list(item.get("rules")):
            name = _text(rule.get("name"))
            first, last = naive_utc(rule.get("first_at")), naive_utc(rule.get("last_at"))
            if name is None or first is None or last is None:
                continue
            verdict = str(rule.get("verdict") or "")
            rules.append(
                RuleEvents(
                    name,
                    _count(rule.get("alerts")),
                    first,
                    last,
                    verdict if verdict in VERDICTS else VERDICT_NOT_JUDGED,
                )
            )
        records = item.get("records")
        pairs.append(
            PairEvents(
                source=source,
                target=target,
                alerts=_count(item.get("alerts")),
                other_alerts=_count(item.get("other_alerts")),
                records=_count(records) if isinstance(records, int) else None,
                first_at=naive_utc(item.get("first_at")),
                last_at=naive_utc(item.get("last_at")),
                rules=tuple(rules),
                datasets=tuple(
                    DatasetRecords(name, _count(d.get("records")))
                    for d in _list(item.get("datasets"))
                    if (name := _text(d.get("name"))) is not None
                ),
            )
        )
    timeline = _mapping(held.get("timeline"))
    lanes: list[Lane] = []
    for lane in _list(timeline.get("lanes")):
        key = _text(lane.get("machine_key"))
        if key is None:
            continue
        buckets = tuple(
            Bucket(at, _count(b.get("alerts")))
            for b in _list(lane.get("buckets"))
            if (at := naive_utc(b.get("at"))) is not None
        )
        lanes.append(Lane(key, buckets))
    seconds = timeline.get("bucket_seconds")
    source = str(held.get("source") or "")
    records = held.get("records")
    return CampaignEvents(
        source=source if source in SOURCES else SOURCE_NONE,
        read_at=naive_utc(held.get("read_at")),
        alerts=_count(held.get("alerts")),
        rules=_count(held.get("rules")),
        findings=_count(held.get("findings")),
        records=_count(records) if isinstance(records, int) else None,
        pairs=tuple(pairs),
        timeline=Timeline(
            _count(seconds) or STORED_BUCKET_SECONDS,
            tuple(lanes),
        ),
    )


__all__ = [
    "CLOSE_SCOPE_MAX",
    "INTERVALS",
    "MAX_PAIRS",
    "READ_TIMEOUT_S",
    "Bucket",
    "CampaignEvents",
    "CloseScope",
    "DatasetRecords",
    "Lane",
    "PairEvents",
    "PairSpec",
    "RuleEvents",
    "Timeline",
    "campaign_pairs",
    "choose_interval",
    "events_basis",
    "findings_of",
    "read_close_scope",
    "read_events",
    "stored_events",
]
