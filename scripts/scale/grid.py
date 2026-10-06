"""An in-process grid for the scale harness: searches answered from an estate.

The demo mock (``scripts/demo/mock_es.py``) serves canned answers over HTTP.
At 20,000 hosts the harness needs the opposite: real query semantics over a
large document set, fast enough to run the whole sweep in CI. So this grid
evaluates the query DSL and the aggregations itself, over the weighted rows
of :mod:`scripts.scale.estate`. A row stands for ``pattern[h]`` documents in
hour ``h`` of each of its days, so a count, a histogram and a min or max are
exact without one object per document.

The subset is what the dossier sweep, the profile build and the prior sweep
send: ``bool`` with ``filter``, ``must``, ``should`` and ``must_not``;
``term`` and ``terms`` (a CIDR matches an address); ``exists``; ``range``;
and the aggregations ``terms``, ``composite``, ``date_histogram``, ``min``,
``max``, ``cardinality``, ``filter``, ``filters``, ``top_hits``,
``percentiles``, ``value_count``, ``sum`` and ``avg``. A clause outside the
subset raises :class:`Unsupported`. A new query shape then fails the harness
loudly. A grid that answered it with nothing would report a quiet estate.

The grid counts its searches and enforces ``search.max_buckets`` the way
Elasticsearch does: a response with more buckets than the limit is refused
with a ``too_many_buckets_exception`` body.

A composite read is one request sent once per page, each page with a new
``after``. The grid groups the keys of such a request once and keeps them for
the next page of the same request. Without that, the grid time of a paged
read grows with the square of the estate. A real cluster keeps its keys
sorted in the index.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import time
import zlib
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from scripts.scale.estate import Estate
from soc_ai.so_client.elastic import EsSearchResult

_HOUR = 3_600_000
_DAY = 24 * _HOUR
_HALF_HOUR = _HOUR // 2
_NEG = -(2**62)
_POS = 2**62
_TIME = "@timestamp"

# Fields with a postings index. A term or terms clause on one of them narrows
# the candidate rows before any predicate runs.
_INDEXED: tuple[str, ...] = (
    "event.dataset",
    "source.ip",
    "destination.ip",
    "host.name",
    "host.ip",
    "host.mac",
    "agent.id",
    "dhcp.assigned_ip",
    "client.address",
    "dns.resolved_ip",
)

Pred = Callable[[Mapping[str, Any]], bool]


class Unsupported(Exception):
    """A query or aggregation shape the grid does not model."""


class TooManyBuckets(Exception):
    """The response would hold more buckets than ``search.max_buckets``."""

    def __init__(self, count: int, limit: int) -> None:
        reason = (
            "Trying to create too many buckets. Must be less than or equal to: "
            f"[{limit}] but this number of buckets was exceeded: [{count}]."
        )
        super().__init__(reason)
        self.body = {
            "error": {
                "type": "search_phase_execution_exception",
                "reason": "",
                "root_cause": [{"type": "too_many_buckets_exception", "reason": reason}],
                "caused_by": {"type": "too_many_buckets_exception", "reason": reason},
            }
        }


@dataclass(slots=True)
class _Row:
    id: int
    doc: dict[str, Any]
    pattern: tuple[int, ...]
    hours: tuple[int, ...]
    day_sum: int
    days: tuple[int, ...]


@dataclass(slots=True)
class _Query:
    pred: Pred | None
    lo: int
    hi: int
    cand: set[int] | None
    # A union of time windows from a ``should`` of ranges with
    # ``minimum_should_match`` 1: the cross-plane silence detector reads the
    # same hours of several weeks in one query. ``lo`` and ``hi`` span the
    # union. The grid counts an hour only inside one of the windows.
    windows: tuple[tuple[int, int], ...] | None = None


Matched = list[tuple[_Row, int]]


def _page_request(index: str, query: Any, aggs: Mapping[str, Any] | None) -> str | None:
    """The request a composite page belongs to, or None for a request with no composite.

    The pages of one read differ in ``after`` and ``size`` only, so both are
    removed from every top-level composite body.
    """
    if not aggs or not any(
        isinstance(body, Mapping) and "composite" in body for body in aggs.values()
    ):
        return None
    paged: dict[str, Any] = {}
    for name, body in aggs.items():
        paged[name] = body
        if isinstance(body, Mapping) and "composite" in body:
            spec = {k: v for k, v in body["composite"].items() if k not in ("after", "size")}
            paged[name] = {**body, "composite": spec}
    return json.dumps([index, query, paged], sort_keys=True, default=str)


def _values(doc: Mapping[str, Any], name: str) -> list[Any]:
    value = doc.get(name)
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _norm(value: Any) -> str:
    return str(value)


@lru_cache(maxsize=4096)
def _network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if "/" not in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


@lru_cache(maxsize=262_144)
def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _iso(ms: int) -> str:
    stamp = datetime.fromtimestamp(ms / 1000, tz=UTC)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"


_MATH = re.compile(r"([+-])(\d+)([smhdwMy])")
_UNIT_MS = {"s": 1000, "m": 60_000, "h": _HOUR, "d": _DAY, "w": 7 * _DAY}


def _is_time_range(clause: Any) -> bool:
    """Whether ``clause`` is one ``range`` on the timestamp and nothing else."""
    if not isinstance(clause, Mapping) or list(clause) != ["range"]:
        return False
    body = clause["range"]
    return isinstance(body, Mapping) and list(body) == [_TIME]


def _date_ms(value: Any, now_ms: int) -> int:
    """An Elasticsearch date: epoch milliseconds, ISO 8601, ``now`` math or ``<iso>||<math>``."""
    if isinstance(value, bool):
        raise Unsupported(f"date value {value!r}")
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str):
        raise Unsupported(f"date value {value!r}")
    text = value.strip()
    if text.startswith("now"):
        base, math = now_ms, text[3:]
    elif "||" in text:
        head, math = text.split("||", 1)
        base = _date_ms(head, now_ms)
    else:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp() * 1000)
    rounding = None
    if "/" in math:
        math, rounding = math.split("/", 1)
    for sign, amount, unit in _MATH.findall(math):
        if unit not in _UNIT_MS:
            raise Unsupported(f"date math unit {unit!r}")
        step = int(amount) * _UNIT_MS[unit]
        base = base + step if sign == "+" else base - step
    if rounding in ("d", "h"):
        size = _DAY if rounding == "d" else _HOUR
        base -= base % size
    elif rounding:
        raise Unsupported(f"date rounding {rounding!r}")
    return base


class Grid:
    """The estate as a grid client: ``search`` and ``max_buckets``, like ``ElasticClient``."""

    def __init__(
        self,
        estate: Estate,
        *,
        max_buckets: int = 65_536,
        latency_ms: float = 0.0,
        refuse: Callable[[Any, Mapping[str, Any] | None], bool] | None = None,
    ) -> None:
        self.anchor_ms = int(estate.anchor.timestamp() * 1000)
        self.limit = max_buckets
        self.latency_ms = latency_ms
        # A test hook: return True to refuse a search for its bucket count.
        self.refuse = refuse
        self.searches = 0
        self.seconds = 0.0
        self.rows: list[_Row] = []
        for i, row in enumerate(estate.rows):
            hours = tuple(h for h in range(24) if row.pattern[h] > 0)
            self.rows.append(
                _Row(
                    id=i,
                    doc=row.doc,
                    pattern=row.pattern,
                    hours=hours,
                    day_sum=sum(row.pattern),
                    days=tuple(sorted(row.days)),
                )
            )
        self._postings: dict[str, dict[str, set[int]]] = {name: {} for name in _INDEXED}
        for row in self.rows:
            for name in _INDEXED:
                for value in _values(row.doc, name):
                    self._postings[name].setdefault(_norm(value), set()).add(row.id)
        self._now_override: int | None = None
        # The time windows of the query under evaluation, else None.
        self._windows: tuple[tuple[int, int], ...] | None = None
        # The request a composite page belongs to, with its pages' ``after``
        # and ``size`` removed, and the selection and the grouping it made.
        # One request at a time: the next one replaces it.
        self._page_request: str | None = None
        self._page_select: tuple[str, _Query, Matched] | None = None
        self._page_groups: tuple[Any, Any] | None = None

    # -- the client surface -------------------------------------------------

    async def max_buckets(self) -> int:
        return self.limit

    async def search(
        self,
        index: str,
        query: Any,
        *,
        size: int = 100,
        from_: int = 0,
        sort: list[dict[str, Any]] | None = None,
        source: list[str] | bool | None = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
        require_complete: bool = False,
    ) -> EsSearchResult:
        del track_total_hits, require_complete
        self.searches += 1
        if self.latency_ms:
            await asyncio.sleep(self.latency_ms / 1000)
        started = time.perf_counter()
        try:
            if self.refuse is not None and self.refuse(query, aggs):
                raise TooManyBuckets(self.limit + 1, self.limit)
            return self._search(index, query, size, from_, sort, source, aggs)
        finally:
            self.seconds += time.perf_counter() - started

    # -- evaluation ---------------------------------------------------------

    def now_ms(self) -> int:
        return self._now_override if self._now_override is not None else int(time.time() * 1000)

    def _search(
        self,
        index: str,
        query: Any,
        size: int,
        from_: int,
        sort: list[dict[str, Any]] | None,
        source: list[str] | bool | None,
        aggs: dict[str, Any] | None,
    ) -> EsSearchResult:
        self._page_request = _page_request(index, query, aggs)
        held = self._page_select
        if self._page_request is not None and held is not None and held[0] == self._page_request:
            _, compiled, matched = held
        else:
            compiled = self._compile(query, conj=True)
            self._windows = compiled.windows
            try:
                matched = self._select(compiled)
            finally:
                self._windows = None
            if self._page_request is not None:
                self._page_select = (self._page_request, compiled, matched)
        total = sum(c for _, c in matched)
        budget = [0]
        # The windows of the query hold for every count under it: the
        # aggregations and the hits read hours through the same mask.
        self._windows = compiled.windows
        try:
            aggregations = (
                self._aggs(aggs, matched, compiled.lo, compiled.hi, budget) if aggs else None
            )
            hits = self._hits(matched, compiled.lo, compiled.hi, size, from_, sort, source, index)
        finally:
            self._windows = None
        return EsSearchResult(total=total, took_ms=0, hits=hits, aggregations=aggregations)

    def _select(self, q: _Query) -> Matched:
        ids: Sequence[int] = sorted(q.cand) if q.cand is not None else range(len(self.rows))
        out: Matched = []
        pred = q.pred
        for i in ids:
            row = self.rows[i]
            if pred is not None and not pred(row.doc):
                continue
            count = self._count(row, q.lo, q.hi)
            if count:
                out.append((row, count))
        return out

    # -- time ---------------------------------------------------------------

    def _day_start(self, day: int) -> int:
        """The time of the first document of ``day``: 30 minutes into its first hour."""
        return self.anchor_ms - (day + 1) * _DAY + _HALF_HOUR

    def _count(self, row: _Row, lo: int, hi: int) -> int:
        total = 0
        windows = self._windows
        for day in row.days:
            start = self._day_start(day)
            first = start + row.hours[0] * _HOUR
            last = start + row.hours[-1] * _HOUR
            if last < lo or first > hi:
                continue
            if windows is None and lo <= first and last <= hi:
                total += row.day_sum
                continue
            for h in row.hours:
                t = start + h * _HOUR
                if lo <= t <= hi and (
                    windows is None or any(w_lo <= t <= w_hi for w_lo, w_hi in windows)
                ):
                    total += row.pattern[h]
        return total

    def _instances(self, row: _Row, lo: int, hi: int) -> Iterator[tuple[int, int]]:
        for day in row.days:
            start = self._day_start(day)
            if start + row.hours[-1] * _HOUR < lo or start + row.hours[0] * _HOUR > hi:
                continue
            for h in row.hours:
                t = start + h * _HOUR
                if lo <= t <= hi:
                    yield t, row.pattern[h]

    def _newest(self, row: _Row, lo: int, hi: int) -> int | None:
        for day in row.days:  # day 0 is the newest
            start = self._day_start(day)
            for h in reversed(row.hours):
                t = start + h * _HOUR
                if lo <= t <= hi:
                    return t
        return None

    def _oldest(self, row: _Row, lo: int, hi: int) -> int | None:
        for day in reversed(row.days):
            start = self._day_start(day)
            for h in row.hours:
                t = start + h * _HOUR
                if lo <= t <= hi:
                    return t
        return None

    # -- the query DSL ------------------------------------------------------

    def _compile(self, node: Any, *, conj: bool) -> _Query:
        if node is None or node == {}:
            return _Query(pred=None, lo=_NEG, hi=_POS, cand=None)
        if not isinstance(node, Mapping) or len(node) != 1:
            raise Unsupported(f"query node {node!r}")
        ((kind, body),) = node.items()
        if kind == "match_all":
            return _Query(pred=None, lo=_NEG, hi=_POS, cand=None)
        if kind == "bool":
            return self._bool(body, conj=conj)
        if kind in ("term", "terms"):
            return self._term(kind, body)
        if kind == "exists":
            name = body["field"]
            return _Query(pred=lambda d: bool(_values(d, name)), lo=_NEG, hi=_POS, cand=None)
        if kind == "range":
            return self._range(body, conj=conj)
        if kind == "prefix":
            ((name, value),) = body.items()
            want = str(value.get("value") if isinstance(value, Mapping) else value)
            return _Query(
                pred=lambda d: any(str(v).startswith(want) for v in _values(d, name)),
                lo=_NEG,
                hi=_POS,
                cand=None,
            )
        raise Unsupported(f"query clause {kind!r}")

    def _bool(self, body: Mapping[str, Any], *, conj: bool) -> _Query:
        musts = [*(_as_list(body.get("filter"))), *(_as_list(body.get("must")))]
        shoulds = _as_list(body.get("should"))
        nots = _as_list(body.get("must_not"))
        lo, hi = _NEG, _POS
        preds: list[Pred] = []
        cand: set[int] | None = None
        for clause in musts:
            q = self._compile(clause, conj=conj)
            lo, hi = max(lo, q.lo), min(hi, q.hi)
            if q.pred is not None:
                preds.append(q.pred)
            if q.cand is not None:
                cand = set(q.cand) if cand is None else cand & q.cand
        msm_raw = body.get("minimum_should_match")
        msm = (1 if shoulds and not musts else 0) if msm_raw is None else int(msm_raw)
        windows: tuple[tuple[int, int], ...] | None = None
        if shoulds and msm == 1 and all(_is_time_range(clause) for clause in shoulds):
            # A union of time windows. Each range compiles in a conjunctive
            # context of its own; the union spans them, and the count mask
            # keeps the hours between them out.
            spans = [self._compile(clause, conj=True) for clause in shoulds]
            windows = tuple((q.lo, q.hi) for q in spans)
            lo = max(lo, min(w_lo for w_lo, _ in windows))
            hi = min(hi, max(w_hi for _, w_hi in windows))
            shoulds = []
        if shoulds and msm > 0:
            compiled = [self._compile(clause, conj=False) for clause in shoulds]
            for q in compiled:
                if q.lo != _NEG or q.hi != _POS:
                    raise Unsupported("a time range inside a should clause")
            should_preds = [q.pred for q in compiled]

            def _should(d: Mapping[str, Any], ps: list[Pred | None] = should_preds) -> bool:
                hit = 0
                for p in ps:
                    if p is None or p(d):
                        hit += 1
                        if hit >= msm:
                            return True
                return False

            preds.append(_should)
            if all(q.cand is not None for q in compiled):
                union: set[int] = set()
                for q in compiled:
                    union |= q.cand or set()
                cand = union if cand is None else cand & union
        if nots:
            compiled_not = [self._compile(clause, conj=False) for clause in nots]
            for q in compiled_not:
                if q.lo != _NEG or q.hi != _POS:
                    raise Unsupported("a time range inside must_not")
            not_preds = [q.pred for q in compiled_not]

            def _none(d: Mapping[str, Any], ps: list[Pred | None] = not_preds) -> bool:
                return not any(p is None or p(d) for p in ps)

            preds.append(_none)
        if not conj and (lo != _NEG or hi != _POS):
            raise Unsupported("a time range outside a conjunctive context")
        if not preds:
            return _Query(pred=None, lo=lo, hi=hi, cand=cand, windows=windows)
        if len(preds) == 1:
            return _Query(pred=preds[0], lo=lo, hi=hi, cand=cand, windows=windows)

        def _all(d: Mapping[str, Any], ps: list[Pred] = preds) -> bool:
            return all(p(d) for p in ps)

        return _Query(pred=_all, lo=lo, hi=hi, cand=cand, windows=windows)

    def _term(self, kind: str, body: Mapping[str, Any]) -> _Query:
        items = [(k, v) for k, v in body.items() if k != "boost"]
        if len(items) != 1:
            raise Unsupported(f"{kind} body {body!r}")
        ((name, raw),) = items
        if name == _TIME:
            raise Unsupported("a term on @timestamp")
        if kind == "term":
            wanted = [raw.get("value") if isinstance(raw, Mapping) else raw]
        else:
            if not isinstance(raw, list):
                raise Unsupported(f"terms value {raw!r}")
            wanted = list(raw)
        exact = {_norm(v) for v in wanted if not (isinstance(v, str) and _network(v))}
        nets = [n for v in wanted if isinstance(v, str) and (n := _network(v)) is not None]

        def _pred(d: Mapping[str, Any]) -> bool:
            for value in _values(d, name):
                if _norm(value) in exact:
                    return True
                if nets:
                    addr = _address(str(value))
                    if addr is not None and any(
                        addr.version == n.version and addr in n for n in nets
                    ):
                        return True
            return False

        cand: set[int] | None = None
        postings = self._postings.get(name)
        if postings is not None and not nets:
            cand = set()
            for value in exact:
                cand |= postings.get(value, set())
        return _Query(pred=_pred, lo=_NEG, hi=_POS, cand=cand)

    def _range(self, body: Mapping[str, Any], *, conj: bool) -> _Query:
        ((name, spec),) = body.items()
        if name == _TIME:
            if not conj:
                raise Unsupported("a time range outside a conjunctive context")
            now = self.now_ms()
            lo, hi = _NEG, _POS
            if "gte" in spec:
                lo = _date_ms(spec["gte"], now)
            if "gt" in spec:
                lo = _date_ms(spec["gt"], now) + 1
            if "lte" in spec:
                hi = _date_ms(spec["lte"], now)
            if "lt" in spec:
                hi = _date_ms(spec["lt"], now) - 1
            return _Query(pred=None, lo=lo, hi=hi, cand=None)
        bounds = {k: float(v) for k, v in spec.items() if k in ("gte", "gt", "lte", "lt")}

        def _pred(d: Mapping[str, Any]) -> bool:
            for value in _values(d, name):
                try:
                    x = float(value)
                except (TypeError, ValueError):
                    continue
                if "gte" in bounds and x < bounds["gte"]:
                    continue
                if "gt" in bounds and x <= bounds["gt"]:
                    continue
                if "lte" in bounds and x > bounds["lte"]:
                    continue
                if "lt" in bounds and x >= bounds["lt"]:
                    continue
                return True
            return False

        return _Query(pred=_pred, lo=_NEG, hi=_POS, cand=None)

    # -- aggregations -------------------------------------------------------

    def _spend(self, budget: list[int], buckets: int) -> None:
        budget[0] += buckets
        if budget[0] > self.limit:
            raise TooManyBuckets(budget[0], self.limit)

    def _aggs(
        self,
        spec: Mapping[str, Any],
        matched: Matched,
        lo: int,
        hi: int,
        budget: list[int],
    ) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, body in spec.items():
            out[name] = self._agg(body, matched, lo, hi, budget)
        return out

    def _agg(
        self,
        body: Mapping[str, Any],
        matched: Matched,
        lo: int,
        hi: int,
        budget: list[int],
    ) -> dict[str, Any]:
        subs = body.get("aggs") or body.get("aggregations") or {}
        kinds = [k for k in body if k not in ("aggs", "aggregations", "meta")]
        if len(kinds) != 1:
            raise Unsupported(f"aggregation {body!r}")
        kind = kinds[0]
        spec = body[kind]
        if kind == "terms":
            return self._terms(spec, subs, matched, lo, hi, budget)
        if kind == "composite":
            return self._composite(spec, subs, matched, lo, hi, budget)
        if kind == "date_histogram":
            return self._histogram(spec, subs, matched, lo, hi, budget)
        if kind in ("min", "max"):
            return self._extreme(kind, spec, matched, lo, hi)
        if kind == "cardinality":
            seen = {_norm(v) for row, _ in matched for v in _values(row.doc, spec["field"])}
            return {"value": len(seen)}
        if kind == "value_count":
            return {"value": sum(c * len(_values(r.doc, spec["field"])) for r, c in matched)}
        if kind in ("sum", "avg"):
            return self._numeric(kind, spec, matched)
        if kind == "percentiles":
            return self._percentiles(spec, matched)
        if kind == "filter":
            sub_matched, s_lo, s_hi = self._narrow(spec, matched, lo, hi)
            node: dict[str, Any] = {"doc_count": sum(c for _, c in sub_matched)}
            node.update(self._aggs(subs, sub_matched, s_lo, s_hi, budget))
            return node
        if kind == "filters":
            return self._filters(spec, subs, matched, lo, hi, budget)
        if kind == "top_hits":
            return self._top_hits(spec, matched, lo, hi)
        raise Unsupported(f"aggregation type {kind!r}")

    def _narrow(self, query: Any, matched: Matched, lo: int, hi: int) -> tuple[Matched, int, int]:
        q = self._compile(query, conj=True)
        if q.windows is not None:
            raise Unsupported("a union of time windows inside an aggregation filter")
        n_lo, n_hi = max(lo, q.lo), min(hi, q.hi)
        out: Matched = []
        for row, held in matched:
            if q.pred is not None and not q.pred(row.doc):
                continue
            count = self._count(row, n_lo, n_hi) if (n_lo, n_hi) != (lo, hi) else held
            if count:
                out.append((row, count))
        return out, n_lo, n_hi

    def _terms(
        self,
        spec: Mapping[str, Any],
        subs: Mapping[str, Any],
        matched: Matched,
        lo: int,
        hi: int,
        budget: list[int],
    ) -> dict[str, Any]:
        name = spec["field"]
        size = int(spec.get("size", 10))
        groups: dict[Any, Matched] = {}
        counts: dict[Any, int] = {}
        for row, count in matched:
            for value in set(_values(row.doc, name)):
                groups.setdefault(value, []).append((row, count))
                counts[value] = counts.get(value, 0) + count
        keys = list(counts)
        include = spec.get("include")
        if isinstance(include, Mapping) and "partition" in include:
            part, parts = int(include["partition"]), int(include["num_partitions"])
            keys = [k for k in keys if zlib.crc32(_norm(k).encode()) % parts == part]
        elif isinstance(include, list):
            allowed = {_norm(v) for v in include}
            keys = [k for k in keys if _norm(k) in allowed]
        elif include is not None:
            raise Unsupported(f"terms include {include!r}")
        exclude = spec.get("exclude")
        if isinstance(exclude, list):
            denied = {_norm(v) for v in exclude}
            keys = [k for k in keys if _norm(k) not in denied]
        elif exclude is not None:
            raise Unsupported(f"terms exclude {exclude!r}")
        floor = int(spec.get("min_doc_count", 1))
        keys = [k for k in keys if counts[k] >= floor]
        keys.sort(key=_key_order)
        order = spec.get("order")
        orders = order if isinstance(order, list) else ([order] if order else [])
        if orders:
            ((by, direction),) = orders[0].items()
            reverse = direction == "desc"
            if by == "_key":
                keys.sort(key=_key_order, reverse=reverse)
            elif by == "_count":
                keys.sort(key=lambda k: counts[k], reverse=reverse)
            else:
                raise Unsupported(f"terms order {order!r}")
        else:
            keys.sort(key=lambda k: -counts[k])
        top = keys[:size]
        self._spend(budget, len(top))
        buckets = []
        for key in top:
            bucket: dict[str, Any] = {"key": key, "doc_count": counts[key]}
            bucket.update(self._aggs(subs, groups[key], lo, hi, budget))
            buckets.append(bucket)
        return {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": sum(counts[k] for k in keys[size:]),
            "buckets": buckets,
        }

    def _composite(
        self,
        spec: Mapping[str, Any],
        subs: Mapping[str, Any],
        matched: Matched,
        lo: int,
        hi: int,
        budget: list[int],
    ) -> dict[str, Any]:
        sources: list[tuple[str, str]] = []
        for source in spec["sources"]:
            ((label, body),) = source.items()
            if "terms" not in body:
                raise Unsupported(f"composite source {source!r}")
            sources.append((label, body["terms"]["field"]))
        memo = (self._page_request, tuple(sources))
        held = self._page_groups
        keys: list[tuple[Any, ...]]
        groups: dict[tuple[Any, ...], Matched]
        counts: dict[tuple[Any, ...], int]
        if self._page_request is not None and held is not None and held[0] == memo:
            keys, groups, counts = held[1]
        else:
            groups = {}
            counts = {}
            for row, count in matched:
                combos: list[tuple[Any, ...]] = [()]
                for _, name in sources:
                    values = sorted(set(_values(row.doc, name)), key=_key_order)
                    combos = [(*c, v) for c in combos for v in values]
                for combo in combos:
                    groups.setdefault(combo, []).append((row, count))
                    counts[combo] = counts.get(combo, 0) + count
            keys = sorted(counts, key=lambda k: tuple(_key_order(v) for v in k))
            if self._page_request is not None:
                self._page_groups = (memo, (keys, groups, counts))
        after = spec.get("after")
        if after:
            mark = tuple(_key_order(after[label]) for label, _ in sources)
            keys = [k for k in keys if tuple(_key_order(v) for v in k) > mark]
        size = int(spec.get("size", 10))
        page = keys[:size]
        self._spend(budget, len(page))
        buckets = []
        for key in page:
            bucket: dict[str, Any] = {
                "key": {label: value for (label, _), value in zip(sources, key, strict=True)},
                "doc_count": counts[key],
            }
            bucket.update(self._aggs(subs, groups[key], lo, hi, budget))
            buckets.append(bucket)
        out: dict[str, Any] = {"buckets": buckets}
        if buckets:
            out["after_key"] = buckets[-1]["key"]
        return out

    def _histogram(
        self,
        spec: Mapping[str, Any],
        subs: Mapping[str, Any],
        matched: Matched,
        lo: int,
        hi: int,
        budget: list[int],
    ) -> dict[str, Any]:
        if spec.get("field") != _TIME:
            raise Unsupported(f"date_histogram on {spec.get('field')!r}")
        interval = str(
            spec.get("calendar_interval") or spec.get("fixed_interval") or spec.get("interval")
        )
        step = {"hour": _HOUR, "1h": _HOUR, "60m": _HOUR, "day": _DAY, "1d": _DAY, "24h": _DAY}.get(
            interval
        )
        if step is None:
            raise Unsupported(f"date_histogram interval {interval!r}")
        counts: dict[int, int] = {}
        members: dict[int, list[_Row]] = {}
        for row, _ in matched:
            for t, n in self._instances(row, lo, hi):
                key = t - t % step
                counts[key] = counts.get(key, 0) + n
                held = members.setdefault(key, [])
                if not held or held[-1] is not row:
                    held.append(row)
        floor = int(spec.get("min_doc_count", 0))
        keys = sorted(counts)
        if floor <= 0 and keys:
            keys = list(range(keys[0], keys[-1] + step, step))
        keys = [k for k in keys if counts.get(k, 0) >= max(floor, 0)]
        self._spend(budget, len(keys))
        buckets = []
        for key in keys:
            bucket: dict[str, Any] = {
                "key_as_string": _iso(key),
                "key": key,
                "doc_count": counts.get(key, 0),
            }
            if subs:
                b_lo, b_hi = max(lo, key), min(hi, key + step - 1)
                inner: Matched = [
                    (row, c) for row in members.get(key, []) if (c := self._count(row, b_lo, b_hi))
                ]
                bucket.update(self._aggs(subs, inner, b_lo, b_hi, budget))
            buckets.append(bucket)
        return {"buckets": buckets}

    def _extreme(
        self, kind: str, spec: Mapping[str, Any], matched: Matched, lo: int, hi: int
    ) -> dict[str, Any]:
        name = spec["field"]
        if name == _TIME:
            stamps = [
                t
                for row, _ in matched
                if (
                    t := (self._oldest(row, lo, hi) if kind == "min" else self._newest(row, lo, hi))
                )
                is not None
            ]
            if not stamps:
                return {"value": None}
            value = min(stamps) if kind == "min" else max(stamps)
            return {"value": float(value), "value_as_string": _iso(value)}
        numbers = [
            float(v)
            for row, _ in matched
            for v in _values(row.doc, name)
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        ]
        if not numbers:
            return {"value": None}
        return {"value": min(numbers) if kind == "min" else max(numbers)}

    def _numeric(self, kind: str, spec: Mapping[str, Any], matched: Matched) -> dict[str, Any]:
        total = 0.0
        weight = 0
        for row, count in matched:
            for v in _values(row.doc, spec["field"]):
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    total += float(v) * count
                    weight += count
        if kind == "sum":
            return {"value": total}
        return {"value": total / weight if weight else None}

    def _percentiles(self, spec: Mapping[str, Any], matched: Matched) -> dict[str, Any]:
        percents = [float(p) for p in spec.get("percents", (1, 5, 25, 50, 75, 95, 99))]
        weighted = sorted(
            (float(v), count)
            for row, count in matched
            for v in _values(row.doc, spec["field"])
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        )
        total = sum(c for _, c in weighted)
        values: dict[str, float | None] = {}
        for p in percents:
            if not total:
                values[str(p)] = None
                continue
            target = total * p / 100
            running = 0
            pick = weighted[-1][0]
            for value, count in weighted:
                running += count
                if running >= target:
                    pick = value
                    break
            values[str(p)] = pick
        return {"values": values}

    def _filters(
        self,
        spec: Mapping[str, Any],
        subs: Mapping[str, Any],
        matched: Matched,
        lo: int,
        hi: int,
        budget: list[int],
    ) -> dict[str, Any]:
        filters = spec["filters"]
        if spec.get("other_bucket") or spec.get("other_bucket_key"):
            raise Unsupported("filters other_bucket")
        named = isinstance(filters, Mapping)
        items = list(filters.items()) if named else list(enumerate(filters))
        self._spend(budget, len(items))
        out_named: dict[str, Any] = {}
        out_list: list[dict[str, Any]] = []
        for label, query in items:
            sub_matched, s_lo, s_hi = self._narrow(query, matched, lo, hi)
            node: dict[str, Any] = {"doc_count": sum(c for _, c in sub_matched)}
            node.update(self._aggs(subs, sub_matched, s_lo, s_hi, budget))
            if named:
                out_named[str(label)] = node
            else:
                out_list.append(node)
        return {"buckets": out_named if named else out_list}

    def _top_hits(
        self, spec: Mapping[str, Any], matched: Matched, lo: int, hi: int
    ) -> dict[str, Any]:
        size = int(spec.get("size", 3))
        sort = spec.get("sort")
        hits = self._hits(matched, lo, hi, size, 0, sort, spec.get("_source", True), "logs-scale")
        return {
            "hits": {
                "total": {"value": sum(c for _, c in matched), "relation": "eq"},
                "max_score": None,
                "hits": hits,
            }
        }

    # -- hits ---------------------------------------------------------------

    def _hits(
        self,
        matched: Matched,
        lo: int,
        hi: int,
        size: int,
        from_: int,
        sort: Any,
        source: list[str] | bool | None,
        index: str,
    ) -> list[dict[str, Any]]:
        if size <= 0 or not matched:
            return []
        direction = _time_sort(sort)
        stamped: list[tuple[int, _Row]] = []
        for row, _ in matched:
            t = self._oldest(row, lo, hi) if direction == "asc" else self._newest(row, lo, hi)
            if t is not None:
                stamped.append((t, row))
        if direction is not None:
            stamped.sort(key=lambda item: (item[0], item[1].id), reverse=direction == "desc")
        page = stamped[from_ : from_ + size]
        out: list[dict[str, Any]] = []
        for t, row in page:
            hit: dict[str, Any] = {"_index": index, "_id": f"r{row.id}-{t}", "_score": None}
            if source is not False:
                hit["_source"] = _project({**row.doc, _TIME: _iso(t)}, source)
            if direction is not None:
                hit["sort"] = [t]
            out.append(hit)
        return out


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _key_order(value: Any) -> tuple[int, Any]:
    """Numbers before strings, each in its own order."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (0, value)
    return (1, str(value))


def _time_sort(sort: Any) -> str | None:
    """``desc`` or ``asc`` for a sort on ``@timestamp``, ``None`` for no sort."""
    if not sort:
        return None
    first = sort[0] if isinstance(sort, list) else sort
    if isinstance(first, str):
        if first == _TIME:
            return "asc"
        raise Unsupported(f"sort {sort!r}")
    if isinstance(first, Mapping) and _TIME in first:
        spec = first[_TIME]
        order = spec.get("order", "asc") if isinstance(spec, Mapping) else spec
        return "desc" if order == "desc" else "asc"
    raise Unsupported(f"sort {sort!r}")


def _project(doc: Mapping[str, Any], source: list[str] | bool | None) -> dict[str, Any]:
    if source is None or source is True:
        return dict(doc)
    if source is False:
        return {}
    keep: dict[str, Any] = {}
    for key, value in doc.items():
        if any(key == want or key.startswith(want + ".") for want in source):
            keep[key] = value
    return keep
