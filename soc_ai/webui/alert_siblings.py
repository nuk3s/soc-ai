"""Alert groups that share a flow: the same-flow links of the Alerts page.

On the range an SQL injection alert and a Geoserver alert shared one
``network.community_id`` and showed as two unrelated rows. The NTLMv1 group (a
false positive) and the WMIExec group (a true positive) fired 2.6 s apart
between the same two hosts, and neither row named the other, so one attack
sequence carried opposite verdicts with no pointer (dogfood 2026-10-19, R2-I9,
R2-D9).

Two signals link two groups. The rule, and why:

``flow``
    An alert of each group carries the same ``network.community_id``, and
    the two alerts come within :data:`FLOW_SPAN` of each other. The
    community id is the hash of the five-tuple, so two alerts close in time
    saw one network session. The hash is not a session id: fixed-port
    traffic such as NTP or mDNS repeats one five-tuple across days, so one id
    with no time bound linked alerts days apart.

``hosts``
    An alert of one group and an alert of the other run between the same two
    addresses, in either direction, within :data:`SIBLING_SPAN` of each
    other. A second signal is needed because one attack step often opens
    several sessions: the NTLMv1 response and the WMIExec request ran on
    different sessions between one pair. Direction is ignored because a
    response rule fires from the server to the client.

The first read linked two groups when the spans of their alert times on a
pair overlapped, and it listed the 10 groups of a pair with the most alerts.
It named a scan 28 minutes away as a sibling of NTLMv1, it cut NTLMv1 and
WMIExec (one alert each) off a pair of 13 groups, and 50 of 64 rows of a 90
day window carried a chip (dogfood 2026-10-19, V3-N1, V3-N5). The rule is
exact now. The page pays at most two searches for it:

1. The candidate read: the flows of two alerts or more, and the pairs of
   addresses, each with a count of its groups. The pairs come from two
   views, by source and by destination, so a cut in one view is often whole
   in the other. The read carries no group names, so it reaches far.
2. The group read, only when a flow or a pair holds two groups or more. For
   each such flow and pair it reads each group with its first and last
   alert, and the slots that hold its alerts, with the first and the last
   alert of each slot. A slot is as long as the time bound of the signal:
   1 hour for a flow, 5 minutes for a pair. Two alerts within the bound sit
   in one slot or in two neighbour slots, and the first and last alerts of
   the slots give the distance exactly. A flow or a pair with more alerts
   than the slot budget left gets the first and last alert of each group
   only. Those decide most links. A link they cannot decide is left out,
   and the two groups say that their list can be partial.

Each cap that can cut a link sets the partial flag. A terms aggregation
ordered by a sub-aggregation is cut on each shard by that shard's own values,
and Security Onion keeps Suricata alerts and Zeek notices in different indices.
So a flag rests on ``sum_other_doc_count``, the count of what a cut left out,
and never on the order of the buckets. The read never claims a link on an
estimate. Grids that refuse scripts rule out a computed pair key or a computed
time bucket, so the read uses none.

The read covers the page window and the alert sources of the page. It leaves
out the severity filter, the OQL filter and the hide-acknowledged filter of the
page: a sibling stays a sibling when the analyst narrows the list. The NTLMv1
false positive of the range was auto-acknowledged, and the WMIExec row must
still name it. The page polls every 10 s, so the route keeps a read for
:data:`SIBLING_CACHE_TTL` per window.

Nothing here reaches the model. The links are a console aid, and no verdict
changes because of them.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.webui.alerts_query import (
    UNKNOWN_DATASET,
    UNNAMED_KIND,
    build_filter,
    feed_sources,
)

_LOGGER = logging.getLogger(__name__)

# Two groups between the same two hosts are siblings when an alert of each
# comes this close. Five minutes holds one hands-on step of an attack (the
# NTLMv1 and WMIExec alerts of the range were 2.6 s apart) and stays short of
# the next scheduled scan or beacon on a busy pair.
SIBLING_SPAN = timedelta(minutes=5)
_SPAN_MS = SIBLING_SPAN.total_seconds() * 1000.0

# Two groups on one community id are siblings when an alert of each comes
# this close. A community id is the hash of the five-tuple, and fixed-port
# traffic such as NTP (port 123 to port 123) or mDNS repeats one five-tuple
# across days. One id with no time bound linked alerts days apart. One hour
# holds a long session and keeps the next day's repeat out.
FLOW_SPAN = timedelta(hours=1)
_FLOW_MS = FLOW_SPAN.total_seconds() * 1000.0

# The caps of the two searches. Each search stays under the default
# ``search.max_buckets`` of 65,536 in the worst case:
#   candidate read: 5,000 flows, and
#                   2 views x 200 addresses x (1 + 50) = 20,400 buckets.
#   group read:     300 flows x (1 + 20 x 2 + 10 + 10) = 18,300 buckets,
#                   100 pairs x (1 + 50 x 2 + 10 + 10) = 12,100 buckets, and
#                   at most SLOT_BUDGET slots for the flows and the pairs.
# The terms are ordered so the buckets that hold two groups or more come
# first, which keeps a cut off the buckets that can hold a link.
FLOW_BUCKETS = 5_000
FLOW_CANDIDATES = 300
FLOW_MEMBERS = 20
PAIR_SOURCES = 200
PAIR_PEERS = 50
PAIR_CANDIDATES = 100
PAIR_MEMBERS = 50
OTHER_MEMBERS = 10
# A flow or a pair cannot hold more slots than alerts, so its alert count is
# the bound the budget spends.
SLOT_BUDGET = 20_000

# How long the route keeps a page read. The page polls every 10 s, and the
# read cost 0.2 s to 1.2 s on the range.
SIBLING_CACHE_TTL = timedelta(seconds=60)
# How long a failed or degraded read stands before the next poll reads again.
# A slow grid then gets one read per window in this time, from all tabs.
SIBLING_RETRY = timedelta(seconds=15)

_NOTICE_DATASET = "zeek.notice"
_COMMUNITY_ID = "network.community_id"
# A value for the documents that carry no rule name, so the member count of a
# bucket counts the notices and the unnamed alerts as one more member.
_NO_RULE = "(no rule name)"

FLOW = "flow"
HOSTS = "hosts"
# The aggregations of the group read: the flows and the pairs with slots,
# and the flows and the pairs with the first and the last alert of each group
# only.
FLOW_GROUPS = "flow_groups"
FLOW_SPANNED = "flow_spanned"
SLOTTED = "slotted"
SPANNED = "spanned"
GROUP_READ_AGGS = (FLOW_GROUPS, FLOW_SPANNED, SLOTTED, SPANNED)


@dataclass(frozen=True, order=True)
class GroupRef:
    """The identity of an Alerts group across the three name fields.

    ``field`` is ``rule`` for a group named by ``rule.name``, ``notice`` for a
    Zeek notice named by ``notice.note`` and ``unnamed`` for alerts with
    neither, named by their dataset. The page builds its rows the same way.
    """

    field: str
    name: str


def group_ref(kind: str, name: str) -> GroupRef:
    """The identity of a page row of ``kind`` named ``name``."""
    if kind == "notice":
        return GroupRef("notice", name)
    if kind == UNNAMED_KIND:
        return GroupRef("unnamed", name)
    return GroupRef("rule", name)


@dataclass
class SiblingIndex:
    """Which groups link to which, by what signals, and how sure the read is."""

    _links: dict[GroupRef, dict[GroupRef, set[str]]] = field(default_factory=dict)
    # The dataset of a rule group, for the type of a sibling off the page.
    _datasets: dict[GroupRef, str] = field(default_factory=dict)
    # A cap cut the read where any group can lose a link.
    cut: bool = False
    # The groups with a link the read could not decide.
    _undecided: set[GroupRef] = field(default_factory=set)
    # The group read failed. The index holds no link, and a cache keeps it for
    # SIBLING_RETRY only.
    degraded: bool = False
    # When the read started. A row whose newest alert is later can have a
    # sibling the read did not see.
    read_at: datetime | None = None

    def links(self, ref: GroupRef) -> dict[GroupRef, set[str]]:
        """The siblings of ``ref`` and the signals of each. Never ``ref``."""
        return {k: set(v) for k, v in self._links.get(ref, {}).items()}

    def dataset(self, ref: GroupRef) -> str | None:
        return self._datasets.get(ref)

    def partial(self, ref: GroupRef, latest: datetime | None = None) -> bool:
        """True when the list of ``ref`` can miss a sibling.

        ``latest`` is the newest alert of the group, when the caller knows it.
        An alert after the read can make a sibling the read did not see.
        """
        newer = latest is not None and self.read_at is not None and latest > self.read_at
        return self.cut or ref in self._undecided or newer

    def _link(self, a: GroupRef, b: GroupRef, signal: str) -> None:
        if a == b:
            return
        self._links.setdefault(a, {}).setdefault(b, set()).add(signal)
        self._links.setdefault(b, {}).setdefault(a, set()).add(signal)


def sibling_query(
    settings: Settings,
    *,
    time_range: str,
    abs_from: str | None,
    abs_to: str | None,
    time_zone: str | None,
) -> dict[str, Any]:
    """The filter of the sibling read: the page window over the page sources.

    The same sources the page reads: the configured alert filter, and Sigma
    and the Zeek ATTACK notices when the page reads them.
    """
    return build_filter(
        settings,
        time_range=time_range,
        severity=None,
        oql=None,
        dataset_oqls=feed_sources(settings),
        abs_from=abs_from,
        abs_to=abs_to,
        time_zone=time_zone,
        hide_acked=False,
    )


# ── The request ─────────────────────────────────────────────────────────────


def _span() -> dict[str, Any]:
    return {
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}},
    }


def _member_count() -> dict[str, Any]:
    return {"cardinality": {"field": "rule.name", "missing": _NO_RULE, "precision_threshold": 100}}


def _distinct(name: str, missing: str | None = None) -> dict[str, Any]:
    spec: dict[str, Any] = {"field": name, "precision_threshold": 100}
    if missing is not None:
        spec["missing"] = missing
    return {"cardinality": spec}


# The alerts with no rule name that are not Zeek notices: named by dataset.
_UNNAMED: dict[str, Any] = {
    "bool": {
        "must_not": [
            {"exists": {"field": "rule.name"}},
            {"term": {"event.dataset": _NOTICE_DATASET}},
        ]
    }
}


def _member_aggs(
    *, rules: int, times: bool = False, slots: bool = False, width: timedelta = SIBLING_SPAN
) -> dict[str, Any]:
    """The groups inside one bucket, each by the field that names it.

    ``times`` adds the first and the last alert of each group. ``slots`` adds
    the slots of ``width`` that hold its alerts, with the first and the last
    alert of each slot.
    """
    per_name: dict[str, Any] = {}
    if times:
        per_name.update(_span())
    if slots:
        per_name["slots"] = {
            "date_histogram": {
                "field": "@timestamp",
                "fixed_interval": f"{int(width.total_seconds())}s",
                "min_doc_count": 1,
            },
            "aggs": _span(),
        }
    extra = {"aggs": per_name} if per_name else {}
    return {
        "named": {
            "filter": {"bool": {"must_not": [{"term": {"event.dataset": _NOTICE_DATASET}}]}},
            "aggs": {
                "names": {
                    "terms": {"field": "rule.name", "size": rules},
                    "aggs": {
                        "datasets": {"terms": {"field": "event.dataset", "size": 1}},
                        **per_name,
                    },
                }
            },
        },
        "notices": {
            "filter": {"term": {"event.dataset": _NOTICE_DATASET}},
            "aggs": {"names": {"terms": {"field": "notice.note", "size": OTHER_MEMBERS}, **extra}},
        },
        "unnamed": {
            "filter": _UNNAMED,
            "aggs": {
                "names": {
                    "terms": {
                        "field": "event.dataset",
                        "size": OTHER_MEMBERS,
                        "missing": UNKNOWN_DATASET,
                    },
                    **extra,
                }
            },
        },
    }


def _group_count() -> dict[str, Any]:
    """How many groups a bucket holds, with no names.

    ``members`` orders the buckets. It counts every alert with no rule name
    as one more group. The count itself adds the rule names, the notice
    names, and the datasets of the alerts with neither.
    """
    return {
        "members": _member_count(),
        "rules": _distinct("rule.name"),
        "notes": _distinct("notice.note"),
        "unnamed": {
            "filter": _UNNAMED,
            "aggs": {"datasets": _distinct("event.dataset", UNKNOWN_DATASET)},
        },
    }


def _groups(bucket: Mapping[str, Any]) -> int:
    """The group count of a bucket. A notice that carries a rule name counts
    twice, and the group read then finds one group. It never counts one too
    few."""
    unnamed = _number(_dict(bucket.get("unnamed")).get("datasets")) or 0
    return (
        int(_number(bucket.get("rules")) or 0)
        + int(_number(bucket.get("notes")) or 0)
        + int(unnamed)
    )


def candidate_aggs() -> dict[str, Any]:
    """The aggregations of the candidate read: the flows and the pairs."""
    by_members: list[dict[str, str]] = [{"members": "desc"}, {"_count": "desc"}]

    def view(top: str, peer: str) -> dict[str, Any]:
        return {
            "terms": {"field": top, "size": PAIR_SOURCES, "order": by_members},
            "aggs": {
                "members": _member_count(),
                "peers": {
                    "terms": {"field": peer, "size": PAIR_PEERS, "order": by_members},
                    "aggs": _group_count(),
                },
            },
        }

    return {
        "flows": {
            # A flow of one alert cannot hold two groups. min_doc_count keeps
            # it out of the buckets and out of the cut count, so the many
            # one-alert flows of a scan cut nothing.
            "terms": {
                "field": _COMMUNITY_ID,
                "size": FLOW_BUCKETS,
                "min_doc_count": 2,
                "order": by_members,
            },
            "aggs": _group_count(),
        },
        "sent": view("source.ip", "destination.ip"),
        "received": view("destination.ip", "source.ip"),
    }


def _direction(src: str, dst: str) -> dict[str, Any]:
    return {"bool": {"filter": [{"term": {"source.ip": src}}, {"term": {"destination.ip": dst}}]}}


def _pair_clause(a: str, b: str) -> dict[str, Any]:
    return {"bool": {"should": [_direction(a, b), _direction(b, a)], "minimum_should_match": 1}}


# ── The answer ──────────────────────────────────────────────────────────────


def _dict(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _buckets(agg: Any) -> list[Mapping[str, Any]]:
    raw = _dict(agg).get("buckets")
    return [b for b in raw if isinstance(b, Mapping)] if isinstance(raw, list) else []


def _number(agg: Any) -> float | None:
    value = _dict(agg).get("value")
    return float(value) if isinstance(value, int | float) else None


def _other(agg: Any) -> int:
    """The documents a terms aggregation left out of its buckets."""
    value = _dict(agg).get("sum_other_doc_count")
    return int(value) if isinstance(value, int | float) else 0


@dataclass(frozen=True)
class _Times:
    """The alert times of one group on one pair, in epoch milliseconds."""

    first: float | None
    last: float | None
    # Slot number to the first and the last alert in the slot. None when the
    # read asked for no slots.
    slots: Mapping[int, tuple[float, float]] | None = None


def _slots(bucket: Mapping[str, Any], width_ms: float) -> dict[int, tuple[float, float]] | None:
    if "slots" not in bucket:
        return None
    out: dict[int, tuple[float, float]] = {}
    for slot in _buckets(bucket.get("slots")):
        key, lo, hi = slot.get("key"), _number(slot.get("first")), _number(slot.get("last"))
        if isinstance(key, int | float) and lo is not None and hi is not None:
            out[int(key // width_ms)] = (lo, hi)
    return out


_MEMBER_FIELDS = (("rule", "named"), ("notice", "notices"), ("unnamed", "unnamed"))


def _members(
    bucket: Mapping[str, Any], index: SiblingIndex, width_ms: float = _SPAN_MS
) -> tuple[dict[GroupRef, _Times], bool]:
    """The groups of one bucket with their alert times, and whether the
    bucket held more groups than the read lists."""
    found: dict[GroupRef, _Times] = {}
    cut = False
    for kind, key in _MEMBER_FIELDS:
        names = _dict(bucket.get(key)).get("names")
        cut = cut or _other(names) > 0
        for b in _buckets(names):
            name = b.get("key")
            if not isinstance(name, str) or not name:
                continue
            ref = GroupRef(kind, name)
            datasets = _buckets(b.get("datasets"))
            if datasets and isinstance(datasets[0].get("key"), str):
                index._datasets.setdefault(ref, str(datasets[0]["key"]))
            found[ref] = _Times(
                _number(b.get("first")), _number(b.get("last")), _slots(b, width_ms)
            )
    return found, cut


def _near(a: _Times, b: _Times, span_ms: float = _SPAN_MS) -> bool | None:
    """True when an alert of ``a`` and an alert of ``b`` come within
    ``span_ms``. None when the read cannot tell. The slots must be as long as
    the span.

    The first and the last alert of a group are alerts, so two of them within
    the span link the groups. Two spans further apart than the span cannot
    link. Between those two cases the slots decide: two alerts in one slot are
    less than a span apart, alerts two slots apart are more, and for two
    neighbour slots the last alert of the first slot and the first alert of
    the second are the closest pair.
    """
    ends_a = [t for t in (a.first, a.last) if t is not None]
    ends_b = [t for t in (b.first, b.last) if t is not None]
    if not ends_a or not ends_b:
        return False
    if any(abs(x - y) <= span_ms for x in ends_a for y in ends_b):
        return True
    if min(ends_a) - max(ends_b) > span_ms or min(ends_b) - max(ends_a) > span_ms:
        return False
    if a.slots is None or b.slots is None:
        return None
    for k, (lo, hi) in a.slots.items():
        if k in b.slots:
            return True
        after = b.slots.get(k + 1)
        if after is not None and after[0] - hi <= span_ms:
            return True
        before = b.slots.get(k - 1)
        if before is not None and lo - before[1] <= span_ms:
            return True
    return False


@dataclass
class _Pair:
    """Two addresses and what the candidate read counted on them."""

    a: str
    b: str
    groups: int = 0
    docs: int = 0
    # Both directions are known, so ``docs`` bounds the slots of the pair.
    whole: bool = True


def _peer_counts(view: Any, *, reverse: bool, seen: dict[tuple[str, str], tuple[int, int]]) -> bool:
    """Add the directional buckets of one view to ``seen``, as
    (source, destination) to (groups, alerts). True when the view lists every
    pair of the window."""
    whole = _other(view) == 0
    for top in _buckets(view):
        peers = _dict(top.get("peers"))
        whole = whole and _other(peers) == 0
        for peer in _buckets(peers):
            a, b = str(top.get("key") or ""), str(peer.get("key") or "")
            if not a or not b:
                continue
            src, dst = (b, a) if reverse else (a, b)
            groups = _groups(peer)
            docs = int(peer.get("doc_count") or 0)
            old = seen.get((src, dst), (0, 0))
            seen[(src, dst)] = (max(old[0], groups), max(old[1], docs))
    return whole


@dataclass
class Candidates:
    """What the group read must name and decide."""

    index: SiblingIndex
    # The community id and the alert count of each shared flow.
    flows: list[tuple[str, int]]
    pairs: list[_Pair]


def read_candidates(aggregations: Any) -> Candidates:
    """The flows and the pairs that hold two groups or more.

    An answer with no aggregation block, or one in an odd shape, links
    nothing. The caller tells "no siblings" apart from "no data" by whether
    the search answered at all.
    """
    index = SiblingIndex()
    aggs = _dict(aggregations)
    flows = _dict(aggs.get("flows"))
    # Any flow of two alerts or more that the cut left out can hold a link.
    # The order of the flows cannot rule that out: each shard orders by its
    # own counts.
    index.cut = _other(flows) > 0
    shared = sorted(
        (
            (_groups(b), str(b.get("key")), int(b.get("doc_count") or 0))
            for b in _buckets(flows)
            if b.get("key") and _groups(b) >= 2
        ),
        key=lambda item: (-item[0], item[2], item[1]),
    )
    if len(shared) > FLOW_CANDIDATES:
        index.cut = True
        shared = shared[:FLOW_CANDIDATES]

    seen: dict[tuple[str, str], tuple[int, int]] = {}
    sent = _peer_counts(aggs.get("sent"), reverse=False, seen=seen)
    received = _peer_counts(aggs.get("received"), reverse=True, seen=seen)
    # A view that lists every pair shows each direction of each pair. When
    # both views were cut, a direction can hide in both of them.
    whole = sent or received
    index.cut = index.cut or not whole
    merged: dict[tuple[str, str], _Pair] = {}
    for (src, dst), (groups, docs) in seen.items():
        if src == dst:
            continue
        low, high = sorted((src, dst))
        pair = merged.setdefault((low, high), _Pair(low, high))
        pair.groups += groups
        pair.docs += docs
        pair.whole = whole or ((high, low) in seen and (low, high) in seen)
    pairs = sorted(
        (p for p in merged.values() if p.groups >= 2),
        key=lambda p: (-p.groups, p.docs, p.a, p.b),
    )
    if len(pairs) > PAIR_CANDIDATES:
        index.cut = True
        pairs = pairs[:PAIR_CANDIDATES]
    return Candidates(index=index, flows=[(key, docs) for _, key, docs in shared], pairs=pairs)


def _flow_terms(keys: list[str], *, slots: bool) -> dict[str, Any]:
    return {
        "terms": {"field": _COMMUNITY_ID, "include": keys, "size": len(keys)},
        "aggs": _member_aggs(rules=FLOW_MEMBERS, times=True, slots=slots, width=FLOW_SPAN),
    }


def group_aggs(found: Candidates) -> tuple[dict[str, Any], dict[str, Any]]:
    """The filter and the aggregations of the group read.

    The flows spend the slot budget first, then the pairs.
    """
    budget = SLOT_BUDGET
    flows_slotted: list[str] = []
    flows_spanned: list[str] = []
    for key, docs in found.flows:
        if docs <= budget:
            flows_slotted.append(key)
            budget -= docs
        else:
            flows_spanned.append(key)
    pairs = found.pairs
    slotted: dict[str, Any] = {}
    spanned: dict[str, Any] = {}
    addresses: set[str] = set()
    for i, pair in enumerate(pairs):
        clause = _pair_clause(pair.a, pair.b)
        if pair.whole and pair.docs <= budget:
            slotted[f"p{i}"] = clause
            budget -= pair.docs
        else:
            spanned[f"p{i}"] = clause
        addresses.update((pair.a, pair.b))
    aggs: dict[str, Any] = {}
    reach: list[dict[str, Any]] = []
    if flows_slotted:
        aggs[FLOW_GROUPS] = _flow_terms(flows_slotted, slots=True)
    if flows_spanned:
        aggs[FLOW_SPANNED] = _flow_terms(flows_spanned, slots=False)
    if found.flows:
        reach.append({"terms": {_COMMUNITY_ID: [key for key, _ in found.flows]}})
    if slotted:
        aggs[SLOTTED] = {
            "filters": {"filters": slotted},
            "aggs": _member_aggs(rules=PAIR_MEMBERS, times=True, slots=True),
        }
    if spanned:
        aggs[SPANNED] = {
            "filters": {"filters": spanned},
            "aggs": _member_aggs(rules=PAIR_MEMBERS, times=True),
        }
    if addresses:
        listed = sorted(addresses)
        reach.append(
            {
                "bool": {
                    "filter": [
                        {"terms": {"source.ip": listed}},
                        {"terms": {"destination.ip": listed}},
                    ]
                }
            }
        )
    return {"bool": {"should": reach, "minimum_should_match": 1}}, aggs


def _decide(index: SiblingIndex, bucket: Mapping[str, Any], signal: str, span: timedelta) -> None:
    """Link the groups of one flow or one pair whose alerts come within ``span``."""
    span_ms = span.total_seconds() * 1000.0
    members, cut = _members(bucket, index, span_ms)
    index.cut = index.cut or cut
    refs = sorted(members)
    for i, a in enumerate(refs):
        for b in refs[i + 1 :]:
            near = _near(members[a], members[b], span_ms)
            if near is None:
                index._undecided.update((a, b))
            elif near:
                index._link(a, b, signal)


def apply_groups(index: SiblingIndex, aggs: Mapping[str, Any], aggregations: Any) -> None:
    """Link the groups of each shared flow within :data:`FLOW_SPAN`, and the
    groups of each pair within :data:`SIBLING_SPAN`."""
    answer = _dict(aggregations)
    for name in (FLOW_GROUPS, FLOW_SPANNED):
        if name not in aggs:
            continue
        listed = {str(b.get("key")): b for b in _buckets(answer.get(name))}
        for key in aggs[name]["terms"]["include"]:
            bucket = listed.get(key)
            if bucket is None:
                # The grid did not answer for this flow.
                index.cut = True
                continue
            _decide(index, bucket, FLOW, FLOW_SPAN)
    for name in (SLOTTED, SPANNED):
        if name not in aggs:
            continue
        buckets = _dict(_dict(answer.get(name)).get("buckets"))
        for key in _dict(_dict(aggs[name].get("filters")).get("filters")):
            bucket = buckets.get(key)
            if not isinstance(bucket, Mapping):
                # The grid did not answer for this pair.
                index.cut = True
                continue
            _decide(index, bucket, HOSTS, SIBLING_SPAN)


async def fetch_sibling_index(
    elastic: ElasticClient,
    settings: Settings,
    *,
    time_range: str,
    abs_from: str | None,
    abs_to: str | None,
    time_zone: str | None,
    timeout_s: float | None = None,
) -> SiblingIndex:
    """Read the links of every group in the window, in two searches at most.

    Both searches share one budget of ``timeout_s``, the grid timeout by
    default. The candidate read raises what the grid raises, and the route
    turns that into "no sibling data". A failed group read claims no link and
    marks every list partial.
    """
    budget = settings.webui_grid_timeout_s if timeout_s is None else timeout_s
    deadline = asyncio.get_running_loop().time() + budget
    read_at = datetime.now(UTC)
    query = sibling_query(
        settings,
        time_range=time_range,
        abs_from=abs_from,
        abs_to=abs_to,
        time_zone=time_zone,
    )
    # A read that lost a shard misses groups and cannot tell, so both reads
    # ask for a complete answer.
    async with asyncio.timeout_at(deadline):
        first = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs=candidate_aggs(),
            require_complete=True,
        )
    found = read_candidates(first.aggregations)
    index = found.index
    index.read_at = read_at
    if not found.flows and not found.pairs:
        return index
    narrow, aggs = group_aggs(found)
    try:
        async with asyncio.timeout_at(deadline):
            second = await elastic.search(
                settings.events_index_pattern,
                {"bool": {"filter": [query, narrow]}},
                size=0,
                aggs=aggs,
                require_complete=True,
            )
    except Exception as exc:
        _LOGGER.info(
            "alerts: the same-flow group read failed (%s). No link is claimed.",
            type(exc).__name__,
        )
        index.cut = True
        index.degraded = True
        return index
    apply_groups(index, aggs, second.aggregations)
    return index


# ── The page cache ──────────────────────────────────────────────────────────


def window_key(
    settings: Settings,
    *,
    time_range: str,
    abs_from: str | None,
    abs_to: str | None,
    time_zone: str | None,
) -> str:
    """The identity of one page read: the index and the query it sends.

    A preset window reads as ``now-24h`` and keeps one key while time moves.
    The page filters are not in the read, so a filter change keeps the key.
    """
    query = sibling_query(
        settings,
        time_range=time_range,
        abs_from=abs_from,
        abs_to=abs_to,
        time_zone=time_zone,
    )
    return json.dumps([settings.events_index_pattern, query], sort_keys=True, default=str)


class SiblingCache:
    """The page reads of the last :data:`SIBLING_CACHE_TTL`, by window.

    One cache per app serves every tab, so ten open tabs that poll one window
    cost one read a minute. Tabs that ask while a read runs wait for that read.
    A failed or degraded read stands for :data:`SIBLING_RETRY`, so a slow grid
    gets no new read on every poll.
    """

    def __init__(self, *, size: int = 32, clock: Callable[[], float] = time.monotonic) -> None:
        self.size = size
        self.clock = clock
        self._entries: dict[str, tuple[float, SiblingIndex | None]] = {}
        self._reads: dict[str, asyncio.Future[SiblingIndex | None]] = {}

    def _kept(self, key: str) -> tuple[bool, SiblingIndex | None]:
        hit = self._entries.get(key)
        if hit is None:
            return False, None
        at, index = hit
        whole = index is not None and not index.degraded
        ttl = SIBLING_CACHE_TTL if whole else SIBLING_RETRY
        if self.clock() - at > ttl.total_seconds():
            del self._entries[key]
            return False, None
        return True, index

    def _keep(self, key: str, index: SiblingIndex | None) -> None:
        now = self.clock()
        ttl = SIBLING_CACHE_TTL.total_seconds()
        self._entries = {k: v for k, v in self._entries.items() if now - v[0] <= ttl}
        while len(self._entries) >= self.size:
            del self._entries[next(iter(self._entries))]
        self._entries[key] = (now, index)

    async def _load(
        self, key: str, load: Callable[[], Awaitable[SiblingIndex | None]]
    ) -> SiblingIndex | None:
        try:
            index = await load()
        except Exception:
            index = None
        finally:
            self._reads.pop(key, None)
        self._keep(key, index)
        return index

    async def read(
        self, key: str, load: Callable[[], Awaitable[SiblingIndex | None]]
    ) -> SiblingIndex | None:
        """The kept read of ``key``, the read that runs now, or a new read.

        ``load`` returns None for a read that failed. A caller that stops
        does not stop the read: the other callers and the cache still get it.
        """
        found, index = self._kept(key)
        if found:
            return index
        task = self._reads.get(key)
        if task is None:
            task = asyncio.ensure_future(self._load(key, load))
            self._reads[key] = task
        return await asyncio.shield(task)


# ── One report ──────────────────────────────────────────────────────────────


def _ip(value: str | None) -> str | None:
    """The address as text, or None when it is not an address.

    A term query on an ip field refuses a value that is not one, and the
    stored alert can hold a placeholder.
    """
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _utc(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).replace(tzinfo=None).isoformat() + "Z"


def alert_window(at: datetime | None, around: datetime) -> tuple[datetime, datetime]:
    """The window the read of one report covers: :data:`FLOW_SPAN` either
    side of the alert time, or of ``around`` when the stored alert has no
    time. The flow rule bounds the window, and the host rule sits inside it."""
    center = at or around
    return center - FLOW_SPAN, center + FLOW_SPAN


async def fetch_alert_siblings(
    elastic: ElasticClient,
    settings: Settings,
    *,
    own: GroupRef,
    community_id: str | None,
    src: str | None,
    dst: str | None,
    at: datetime | None,
    around: datetime,
) -> SiblingIndex:
    """The groups that share the flow of ONE alert, in one search.

    The report of an investigation names one alert, so both legs read the
    exact rule from the alert time: the community id within
    :data:`FLOW_SPAN`, and the same two hosts, in either direction, within
    :data:`SIBLING_SPAN`. Both rules measure from the alert. When the stored
    alert has no time, no leg has an anchor: the read claims nothing, costs
    no search, and the list says that it can be partial. ``around`` then
    anchors only the window the route reports. A leg with more groups than
    the read lists marks the list partial.
    """
    index = SiblingIndex()
    a, b = _ip(src), _ip(dst)
    if at is None:
        index.cut = bool(community_id or (a and b))
        return index
    legs: dict[str, dict[str, Any]] = {}
    if community_id:
        # The window of the read is FLOW_SPAN either side of the alert, so
        # the term needs no time clause of its own.
        legs[FLOW] = {"term": {_COMMUNITY_ID: community_id}}
    if a and b:
        legs[HOSTS] = {
            "bool": {
                "filter": [
                    _pair_clause(a, b),
                    {
                        "range": {
                            "@timestamp": {
                                "gte": _utc(at - SIBLING_SPAN),
                                "lte": _utc(at + SIBLING_SPAN),
                            }
                        }
                    },
                ]
            }
        }
    if not legs:
        return index
    lo, hi = alert_window(at, around)
    query = sibling_query(
        settings,
        time_range="24h",
        abs_from=_utc(lo),
        abs_to=_utc(hi),
        time_zone=None,
    )
    query["bool"]["filter"].append(
        {"bool": {"should": list(legs.values()), "minimum_should_match": 1}}
    )
    aggs = {
        name: {"filter": leg, "aggs": _member_aggs(rules=PAIR_MEMBERS)}
        for name, leg in legs.items()
    }
    result = await elastic.search(
        settings.events_index_pattern, query, size=0, aggs=aggs, require_complete=True
    )
    found = _dict(result.aggregations)
    for signal in legs:
        members, cut = _members(_dict(found.get(signal)), index)
        index.cut = index.cut or cut
        for ref in members:
            # An unnamed group of the same detection reads as another field.
            # The name decides that it is the alert's own group.
            if ref.name != own.name:
                index._link(own, ref, signal)
    return index
