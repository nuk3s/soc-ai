"""A grid double that answers a search from documents.

The double holds alert documents and evaluates the query and the
aggregations of each search against them. A test then plants alerts, and the
code under test builds its own request. A double that answers canned buckets
can only check the parser against the answer its author expected. This one
also checks that the request asks the grid the right question.

It covers the clause and aggregation shapes the same-flow read sends
(soc_ai.webui.alert_siblings) and no more:

* query: ``bool``, ``term``, ``terms``, ``exists``, ``wildcard`` (``*`` only),
  ``range`` on ``@timestamp`` (ISO bounds or ``now-<n><unit>``), ``match_all``,
  and ``ids`` on the ``_id`` of a document.
* hits: the matched documents, up to ``size``, each with its ``_id``. The
  anchor check of soc_ai.webui.anchor_check reads them.
* aggregations: ``terms`` (``size``, ``order`` by ``_count``, ``_key`` or a
  metric sub-aggregation, ``missing``, ``min_doc_count``), ``cardinality`` (exact),
  ``min``/``max`` on ``@timestamp``, ``filter``, ``filters`` (keyed) and
  ``date_histogram`` (``fixed_interval``, ``min_doc_count``).

A document is a flat mapping of dotted field names to values. A list value
matches a term query when any item matches, as in Elasticsearch.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.so_client.elastic import EsSearchResult

_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def ms(at: datetime) -> float:
    """Epoch milliseconds, the unit the grid answers a date metric in."""
    return at.timestamp() * 1000.0


def _parse_time(value: Any, now: datetime) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    rel = re.fullmatch(r"now-(\d+)([smhd])", value)
    if rel:
        return now - timedelta(**{_UNITS[rel.group(2)]: int(rel.group(1))})
    if value == "now":
        return now
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _values(doc: Mapping[str, Any], name: str) -> list[Any]:
    value = doc.get(name)
    if value is None:
        return []
    return list(value) if isinstance(value, list | tuple) else [value]


@dataclass
class DocGrid:
    """The double. ``searches`` records each request, in order."""

    docs: list[dict[str, Any]]
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    searches: list[dict[str, Any]] = field(default_factory=list)
    # Raise this instead of an answer, from the search with this number on
    # (1 is the first search).
    fail_from: int | None = None
    error: BaseException | None = None

    async def search(self, index: str, query: Any, **kwargs: Any) -> EsSearchResult:
        aggs = kwargs.get("aggs") or {}
        self.searches.append({"index": index, "query": query, "aggs": aggs})
        if self.fail_from is not None and len(self.searches) >= self.fail_from:
            raise self.error or RuntimeError("too_many_buckets_exception")
        matched = [d for d in self.docs if self._match(query, d)]
        size = kwargs.get("size") or 0
        hits = [{"_id": d.get("_id"), "_source": d} for d in matched[:size]]
        return EsSearchResult(
            total=len(matched), took_ms=1, hits=hits, aggregations=self._aggs(aggs, matched)
        )

    # -- query ----------------------------------------------------------------

    def _match(self, clause: Any, doc: Mapping[str, Any]) -> bool:
        if not isinstance(clause, Mapping) or not clause:
            return True
        if "bool" in clause:
            node = clause["bool"]
            for key in ("must", "filter"):
                if not all(self._match(c, doc) for c in node.get(key) or []):
                    return False
            if any(self._match(c, doc) for c in node.get("must_not") or []):
                return False
            should = node.get("should") or []
            if should:
                floor = node.get("minimum_should_match")
                if floor is None:
                    floor = 0 if (node.get("must") or node.get("filter")) else 1
                if sum(1 for c in should if self._match(c, doc)) < int(floor):
                    return False
            return True
        if "match_all" in clause:
            return True
        if "ids" in clause:
            return str(doc.get("_id")) in {str(v) for v in clause["ids"]["values"]}
        if "term" in clause:
            name, value = next(iter(clause["term"].items()))
            if isinstance(value, Mapping):
                value = value.get("value")
            return any(str(v) == str(value) for v in _values(doc, name))
        if "terms" in clause:
            name, wanted = next(iter(clause["terms"].items()))
            want = {str(w) for w in wanted}
            return any(str(v) in want for v in _values(doc, name))
        if "exists" in clause:
            return bool(_values(doc, clause["exists"]["field"]))
        if "wildcard" in clause:
            name, spec = next(iter(clause["wildcard"].items()))
            pattern = spec.get("value") if isinstance(spec, Mapping) else spec
            rx = re.compile(".*".join(re.escape(p) for p in str(pattern).split("*")) + r"\Z")
            return any(rx.match(str(v)) for v in _values(doc, name))
        if "range" in clause:
            name, spec = next(iter(clause["range"].items()))
            if name != "@timestamp":
                raise NotImplementedError(f"range on {name}")
            at = _parse_time(doc.get("@timestamp"), self.now)
            if at is None:
                return False
            lo = _parse_time(spec.get("gte"), self.now)
            hi = _parse_time(spec.get("lte"), self.now)
            return (lo is None or at >= lo) and (hi is None or at <= hi)
        raise NotImplementedError(f"clause {sorted(clause)}")

    # -- aggregations -----------------------------------------------------------

    def _aggs(self, spec: Mapping[str, Any], docs: list[dict[str, Any]]) -> dict[str, Any]:
        return {name: self._agg(body, docs) for name, body in spec.items()}

    def _sub(self, body: Mapping[str, Any], docs: list[dict[str, Any]]) -> dict[str, Any]:
        return self._aggs(body.get("aggs") or {}, docs)

    def _agg(self, body: Mapping[str, Any], docs: list[dict[str, Any]]) -> dict[str, Any]:
        if "terms" in body:
            return self._terms(body, docs)
        if "cardinality" in body:
            spec = body["cardinality"]
            seen: set[str] = set()
            for d in docs:
                vals = _values(d, spec["field"]) or ([spec["missing"]] if "missing" in spec else [])
                seen.update(str(v) for v in vals)
            return {"value": len(seen)}
        if "min" in body or "max" in body:
            kind = "min" if "min" in body else "max"
            name = body[kind]["field"]
            stamps = [
                ms(t)
                for d in docs
                for v in _values(d, name)
                if (t := _parse_time(v, self.now)) is not None
            ]
            if not stamps:
                return {"value": None}
            return {"value": min(stamps) if kind == "min" else max(stamps)}
        if "filter" in body:
            inside = [d for d in docs if self._match(body["filter"], d)]
            return {"doc_count": len(inside), **self._sub(body, inside)}
        if "filters" in body:
            out: dict[str, Any] = {}
            for key, clause in body["filters"]["filters"].items():
                inside = [d for d in docs if self._match(clause, d)]
                out[key] = {"doc_count": len(inside), **self._sub(body, inside)}
            return {"buckets": out}
        if "date_histogram" in body:
            return self._histogram(body, docs)
        raise NotImplementedError(f"aggregation {sorted(body)}")

    def _terms(self, body: Mapping[str, Any], docs: list[dict[str, Any]]) -> dict[str, Any]:
        spec = body["terms"]
        groups: dict[Any, list[dict[str, Any]]] = {}
        for d in docs:
            vals = _values(d, spec["field"])
            if not vals and "missing" in spec:
                vals = [spec["missing"]]
            for v in dict.fromkeys(vals):
                groups.setdefault(v, []).append(d)
        buckets = [
            {"key": key, "doc_count": len(members), **self._sub(body, members)}
            for key, members in groups.items()
        ]
        order = spec.get("order") or [{"_count": "desc"}]
        if isinstance(order, Mapping):
            order = [order]

        def sort_key(b: dict[str, Any]) -> tuple[Any, ...]:
            parts: list[Any] = []
            for item in order:
                name, direction = next(iter(item.items()))
                if name == "_count":
                    value: Any = b["doc_count"]
                elif name == "_key":
                    value = str(b["key"])
                else:
                    value = b[name]["value"] or 0
                if direction == "desc":
                    value = -value if not isinstance(value, str) else value
                parts.append(value)
            # Elasticsearch breaks a tie by the key, ascending.
            parts.append(str(b["key"]))
            return tuple(parts)

        buckets.sort(key=sort_key)
        # A bucket under min_doc_count is left out of the answer and out of
        # sum_other_doc_count, as in the final reduce of Elasticsearch. The
        # double holds one shard, so shard_size changes nothing here.
        floor = int(spec.get("min_doc_count", 1))
        buckets = [b for b in buckets if b["doc_count"] >= floor]
        size = int(spec.get("size", 10))
        kept, dropped = buckets[:size], buckets[size:]
        return {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": sum(b["doc_count"] for b in dropped),
            "buckets": kept,
        }

    def _histogram(self, body: Mapping[str, Any], docs: list[dict[str, Any]]) -> dict[str, Any]:
        spec = body["date_histogram"]
        interval = spec["fixed_interval"]
        unit = re.fullmatch(r"(\d+)([smhd])", interval)
        if unit is None:
            raise NotImplementedError(f"interval {interval}")
        width = timedelta(**{_UNITS[unit.group(2)]: int(unit.group(1))}).total_seconds() * 1000
        slots: dict[int, list[dict[str, Any]]] = {}
        for d in docs:
            for v in _values(d, spec["field"]):
                at = _parse_time(v, self.now)
                if at is not None:
                    slots.setdefault(int(ms(at) // width), []).append(d)
        floor = int(spec.get("min_doc_count", 0))
        if floor < 1:
            raise NotImplementedError("min_doc_count 0 fills empty slots")
        return {
            "buckets": [
                {"key": k * width, "doc_count": len(members), **self._sub(body, members)}
                for k, members in sorted(slots.items())
                if len(members) >= floor
            ]
        }


def alert(
    at: datetime,
    *,
    rule: str | None = None,
    src: str | None = None,
    dst: str | None = None,
    community_id: str | None = None,
    dataset: str = "suricata.alert",
    note: str | None = None,
) -> dict[str, Any]:
    """One alert document in the shape the page sources match."""
    doc: dict[str, Any] = {
        "@timestamp": at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "event.dataset": dataset,
        "event.kind": "alert",
        "tags": ["alert"],
    }
    if rule is not None:
        doc["rule.name"] = rule
    if note is not None:
        doc["notice.note"] = note
    if src is not None:
        doc["source.ip"] = src
    if dst is not None:
        doc["destination.ip"] = dst
    if community_id is not None:
        doc["network.community_id"] = community_id
    return doc


def burst(start: datetime, count: int, every: timedelta, **fields: Any) -> Iterable[dict[str, Any]]:
    """``count`` alerts of one shape, ``every`` apart from ``start``."""
    return (alert(start + i * every, **fields) for i in range(count))
