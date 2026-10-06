"""A synthetic grid for the tier 2 replay: hourly counts and set members, no Elasticsearch.

The grid answers the request shapes the profile build and the prior sweep
send, in the style of the fakes in tests/test_prior_sweep.py and
tests/test_dossier_profile.py. It holds a model of each host, not canned
buckets: a flow count per hour and the outbound ports it used per hour. It
reads the time window of every request against its own clock, so a build at
the start of a replayed day and a sweep at a replayed hour each see the
documents of their own window.

Every address is from the documentation ranges.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.so_client.elastic import EsSearchResult

from tests.es_doubles import composite_page

HOUR = timedelta(hours=1)
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}

# A count per hour, and the outbound ports with their documents per hour.
Rate = Callable[[datetime], int]
Ports = Callable[[datetime], dict[str, int]]


@dataclass
class SyntheticHost:
    """One host of the replay estate, keyed by its address."""

    ip: str
    rate: Rate
    ports: Ports
    # The first hour the host exists. Before it the grid holds nothing for it.
    born: datetime


@dataclass
class SyntheticGrid:
    """The fake grid. ``clock`` is the present the grid answers relative to."""

    hosts: list[SyntheticHost]
    clock: datetime
    searches: int = 0
    reads: list[str] = field(default_factory=list)

    # -- the window ---------------------------------------------------------

    def _when(self, expr: Any, *, default: datetime) -> datetime:
        """One date-math bound: ``now-1440m``, ``<iso>||-1440m`` or ``<iso>``."""
        if not isinstance(expr, str) or not expr:
            return default
        base, _, math = expr.partition("||")
        if expr.startswith("now"):
            at = self.clock
            math = expr[3:]
        else:
            at = datetime.fromisoformat(base.replace("Z", "+00:00"))
            if at.tzinfo is None:
                at = at.replace(tzinfo=UTC)
        for sign, amount, unit in re.findall(r"([+-])(\d+)([mhd])", math):
            delta = timedelta(**{_UNITS[unit]: int(amount)})
            at = at - delta if sign == "-" else at + delta
        return at

    def _window(self, query: dict[str, Any]) -> tuple[datetime, datetime]:
        for clause in (query.get("bool") or {}).get("filter") or []:
            bounds = (clause.get("range") or {}).get("@timestamp")
            if bounds:
                start = self._when(bounds.get("gte"), default=self.clock - timedelta(days=3650))
                end = self._when(bounds.get("lte"), default=self.clock)
                return start, min(end, self.clock)
        return self.clock - timedelta(days=3650), self.clock

    def _hours(self, host: SyntheticHost, start: datetime, end: datetime) -> Iterator[datetime]:
        """The starts of the whole hours of ``host`` inside [start, end)."""
        at = max(start, host.born).replace(minute=0, second=0, microsecond=0)
        if at < start:
            at += HOUR
        while at + HOUR <= end:
            yield at
            at += HOUR

    # -- the shapes ---------------------------------------------------------

    @staticmethod
    def _stamp(at: datetime) -> str:
        return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _samples(self, ident: str, at: datetime, count: int) -> dict[str, Any]:
        """Up to three newest documents of one hour, with their sort value."""
        hits = [
            {
                "_id": f"{ident}-{at.strftime('%Y%m%d%H')}-{n}",
                "sort": [int((at + timedelta(minutes=50 - 10 * n)).timestamp() * 1000)],
            }
            for n in range(min(3, count))
        ]
        return {"hits": {"hits": hits}}

    def _days(self, hours: list[datetime]) -> dict[str, Any]:
        days = sorted({h.date().isoformat() for h in hours})
        return {"buckets": [{"key_as_string": d, "doc_count": 1} for d in days]}

    def _shaped_bucket(
        self, host: SyntheticHost, start: datetime, end: datetime, *, recent: bool
    ) -> dict[str, Any] | None:
        counts = [(h, host.rate(h)) for h in self._hours(host, start, end)]
        counts = [(h, c) for h, c in counts if c > 0]
        if not counts:
            return None
        hours = [
            {
                "key_as_string": self._stamp(h),
                "doc_count": c,
                **({"samples": self._samples(f"{host.ip}-flow", h, c)} if recent else {}),
            }
            for h, c in counts
        ]
        bucket: dict[str, Any] = {"key": host.ip, "doc_count": sum(c for _h, c in counts)}
        if recent:
            bucket["per_hour"] = {"buckets": hours}
        else:
            bucket["active_days"] = self._days([h for h, _c in counts])
            bucket["hours"] = {"buckets": hours}
        return bucket

    def _member_bucket(
        self, host: SyntheticHost, start: datetime, end: datetime, *, recent: bool
    ) -> dict[str, Any] | None:
        seen: dict[str, list[tuple[datetime, int]]] = {}
        for h in self._hours(host, start, end):
            for member, n in host.ports(h).items():
                if n > 0:
                    seen.setdefault(member, []).append((h, n))
        if not seen:
            return None
        members = []
        for member, rows in sorted(seen.items()):
            first, last = rows[0][0], rows[-1][0]
            entry: dict[str, Any] = {
                "key": member,
                "doc_count": sum(n for _h, n in rows),
                "first": {"value_as_string": self._stamp(first)},
                "last": {"value_as_string": self._stamp(last + timedelta(minutes=59))},
            }
            if recent:
                newest, count = rows[-1]
                entry["samples"] = self._samples(f"{host.ip}-{member}", newest, count)
            members.append(entry)
        hours = sorted({h for rows in seen.values() for h, _n in rows})
        return {
            "key": host.ip,
            "doc_count": sum(m["doc_count"] for m in members),
            "active_days": self._days(hours),
            "members": {"buckets": members},
        }

    # -- the client ---------------------------------------------------------

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        from_: int = 0,
        sort: Any = None,
        source: Any = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
    ) -> EsSearchResult:
        self.searches += 1
        aggs = aggs or {}
        key = next(iter(aggs), "")
        self.reads.append(key)
        if key == "plane_probe":
            probe = aggs["plane_probe"]["filters"]["filters"]
            return _result({"plane_probe": {"buckets": {k: {"doc_count": 100} for k in probe}}})

        start, end = self._window(query)
        if key == "entities":
            return _result({"entities": {"value": len(self.hosts)}})
        if key == "shaped":
            terms = aggs["shaped"]["terms"]
            part = terms.get("include") or {"partition": 0, "num_partitions": 1}
            buckets = [
                b
                for n, host in enumerate(self.hosts)
                if n % int(part["num_partitions"]) == int(part["partition"])
                if (b := self._shaped_bucket(host, start, end, recent=False)) is not None
            ]
            return _result({"shaped": {"buckets": buckets}})

        body = aggs.get(key) or {}
        inner = body.get("aggs") or {}
        if "per_hour" in inner:
            buckets = [
                b
                for host in self.hosts
                if (b := self._shaped_bucket(host, start, end, recent=True)) is not None
            ]
            return _result({key: _page(body, buckets)})
        if key == "consumed_ports" and "members" in inner:
            recent = "samples" in ((inner.get("members") or {}).get("aggs") or {})
            buckets = [
                b
                for host in self.hosts
                if (b := self._member_bucket(host, start, end, recent=recent)) is not None
            ]
            return _result({key: _page(body, buckets)})
        # Every other dimension: the plane answers and holds nothing.
        return _result({key: _page(body, [])} if key else {})


def _page(body: dict[str, Any], buckets: list[dict[str, Any]]) -> dict[str, Any]:
    """A composite page for the sweep's recent read, every bucket for a terms read."""
    return composite_page(body, buckets) if "composite" in body else {"buckets": buckets}


def _result(aggregations: dict[str, Any]) -> EsSearchResult:
    return EsSearchResult(
        total=0, took_ms=1, hits=[], aggregations=aggregations, total_is_lower_bound=False
    )


# ---------------------------------------------------------------------------
# The planes of a machine, for the tier 3 cross-plane silence detector
# ---------------------------------------------------------------------------

Count = Callable[[datetime], int]


@dataclass
class PlaneHost:
    """One machine: its agent name, its addresses, a count per hour per dataset.

    ``flows`` is the sensor's count per hour of flows the machine starts,
    keyed by its first address. ``born`` is the first hour it exists.
    """

    name: str
    ips: list[str]
    datasets: dict[str, Count]
    flows: Count | None = None
    born: datetime = datetime(2000, 1, 1, tzinfo=UTC)


def _parse_when(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


def _time_ranges(node: Any) -> list[tuple[datetime | None, datetime | None]]:
    """Every ``@timestamp`` range in a query tree, as ``(gte, lt)``."""
    out: list[tuple[datetime | None, datetime | None]] = []
    if isinstance(node, dict):
        bounds = (node.get("range") or {}).get("@timestamp") if "range" in node else None
        if isinstance(bounds, dict):
            out.append((_parse_when(bounds.get("gte")), _parse_when(bounds.get("lt"))))
        for value in node.values():
            out.extend(_time_ranges(value))
    elif isinstance(node, list):
        for value in node:
            out.extend(_time_ranges(value))
    return out


def _field_values(node: Any, name: str) -> list[str] | None:
    """The values of the first ``term`` or ``terms`` clause on ``name`` in a query tree."""
    if isinstance(node, dict):
        for key in ("terms", "term"):
            inner = node.get(key)
            if isinstance(inner, dict) and name in inner:
                value = inner[name]
                return [str(v) for v in value] if isinstance(value, list) else [str(value)]
        for value in node.values():
            found = _field_values(value, name)
            if found is not None:
                return found
    elif isinstance(node, list):
        for value in node:
            found = _field_values(value, name)
            if found is not None:
                return found
    return None


@dataclass
class PlaneGrid:
    """The fake grid the cross-plane silence detector reads.

    It answers the host read (a composite over ``host.name``), the flow read
    (a composite over ``source.ip``) and the one-document reads a hit makes
    for its evidence. ``clock`` is the present: nothing after it exists.
    """

    hosts: list[PlaneHost]
    clock: datetime
    searches: int = 0
    reads: list[str] = field(default_factory=list)
    # The addresses the last flow read asked for.
    flow_sources: list[str] = field(default_factory=list)

    def _hours(
        self, born: datetime, ranges: list[tuple[datetime | None, datetime | None]]
    ) -> list[datetime]:
        out: set[datetime] = set()
        for lo, hi in ranges:
            start = max(lo or born, born).replace(minute=0, second=0, microsecond=0)
            end = min(hi or self.clock, self.clock)
            at = start
            while at + HOUR <= end:
                out.add(at)
                at += HOUR
        return sorted(out)

    @staticmethod
    def _per_hour(rows: list[tuple[datetime, int]]) -> dict[str, Any]:
        return {
            "buckets": [
                {"key_as_string": SyntheticGrid._stamp(h), "doc_count": c} for h, c in rows if c > 0
            ]
        }

    def _host_bucket(
        self, host: PlaneHost, ranges: list[tuple[datetime | None, datetime | None]]
    ) -> dict[str, Any] | None:
        datasets = []
        for dataset, count in sorted(host.datasets.items()):
            rows = [(h, count(h)) for h in self._hours(host.born, ranges)]
            if any(c > 0 for _h, c in rows):
                datasets.append(
                    {
                        "key": dataset,
                        "doc_count": sum(c for _h, c in rows),
                        "per_hour": self._per_hour(rows),
                    }
                )
        if not datasets:
            return None
        return {
            "key": host.name,
            "doc_count": sum(d["doc_count"] for d in datasets),
            "datasets": {"buckets": datasets},
            # Every agent reports its loopback address too.
            "addresses": {
                "buckets": [{"key": ip, "doc_count": 1} for ip in [*host.ips, "127.0.0.1"]]
            },
        }

    def _evidence(
        self, query: dict[str, Any], ranges: list[tuple[datetime | None, datetime | None]]
    ) -> list[dict[str, Any]]:
        """The newest document of one plane of one machine inside the query's window."""
        names = _field_values(query, "host.name")
        sources = _field_values(query, "source.ip")
        candidates: list[tuple[datetime, str]] = []
        for host in self.hosts:
            if names is not None and host.name in names:
                wanted = set(_field_values(query, "event.dataset") or [])
                series = [(d, c) for d, c in host.datasets.items() if d in wanted]
            elif sources is not None and host.flows is not None and host.ips[0] in sources:
                series = [("zeek.conn", host.flows)]
            else:
                continue
            for hour in self._hours(host.born, ranges):
                for dataset, count in series:
                    at = hour + timedelta(minutes=50)
                    inside = any(
                        (lo is None or at >= lo) and (hi is None or at < hi) for lo, hi in ranges
                    )
                    if count(hour) > 0 and inside:
                        candidates.append((at, f"{host.name}-{dataset}-{hour:%Y%m%d%H}"))
        if not candidates:
            return []
        at, doc_id = max(candidates)
        return [{"_index": "logs-x", "_id": doc_id, "sort": [int(at.timestamp() * 1000)]}]

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        from_: int = 0,
        sort: Any = None,
        source: Any = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
        require_complete: bool = False,
    ) -> EsSearchResult:
        self.searches += 1
        aggs = aggs or {}
        key = next(iter(aggs), "")
        self.reads.append(key or "hits")
        ranges = _time_ranges(query)
        if key == "plane_hosts":
            buckets = [
                b for host in self.hosts if (b := self._host_bucket(host, ranges)) is not None
            ]
            return _result({key: composite_page(aggs[key], buckets)})
        if key == "plane_flows":
            wanted = set(_field_values(query, "source.ip") or [])
            self.flow_sources = sorted(wanted)
            buckets = []
            for host in self.hosts:
                if host.flows is None or host.ips[0] not in wanted:
                    continue
                rows = [(h, host.flows(h)) for h in self._hours(host.born, ranges)]
                if any(c > 0 for _h, c in rows):
                    buckets.append(
                        {
                            "key": host.ips[0],
                            "doc_count": sum(c for _h, c in rows),
                            "per_hour": self._per_hour(rows),
                        }
                    )
            return _result({key: composite_page(aggs[key], buckets)})
        if not aggs and size == 1:
            hits = self._evidence(query, ranges)
            return EsSearchResult(
                total=len(hits), took_ms=1, hits=hits, aggregations=None, total_is_lower_bound=False
            )
        return _result({key: {"buckets": []}} if key else {})


# ---------------------------------------------------------------------------
# Logon documents, for the tier 3 logon chain detector
# ---------------------------------------------------------------------------

_SSH_EVENT = {"accepted": "Accepted", "failed": "Failed", "invalid": "Invalid"}


@dataclass
class Logon:
    """One logon document: who logged on to which host, from where, and how it ended.

    ``outcome`` is accepted, failed or invalid. ``windows`` writes a 4624 or a
    4625 of ``logon_type``. Otherwise the document is an sshd line in
    ``system.auth``. ``host_ips`` are the addresses the host's agent reports.
    """

    doc_id: str
    at: datetime
    host: str
    source_ip: str
    host_ips: list[str] = field(default_factory=list)
    outcome: str = "accepted"
    windows: bool = False
    logon_type: str = "10"

    @property
    def accepted(self) -> bool:
        return self.outcome == "accepted"

    @property
    def session(self) -> bool:
        """What the edge read selects: an accepted session from another host."""
        return self.accepted and (not self.windows or self.logon_type in {"3", "10"})

    def body(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "@timestamp": SyntheticGrid._stamp(self.at),
            "host": {"name": self.host, **({"ip": list(self.host_ips)} if self.host_ips else {})},
            "source": {"ip": self.source_ip},
        }
        if self.windows:
            doc["event"] = {
                "code": "4624" if self.accepted else "4625",
                "dataset": "system.security",
            }
            doc["winlog"] = {"event_data": {"LogonType": self.logon_type}}
        else:
            doc["event"] = {
                "dataset": "system.auth",
                "outcome": "success" if self.accepted else "failure",
            }
            doc["system"] = {"auth": {"ssh": {"event": _SSH_EVENT[self.outcome]}}}
        return doc


def _bounds(query: dict[str, Any]) -> tuple[datetime | None, datetime | None, bool]:
    """The one ``@timestamp`` range of a query: (gte, upper bound, upper is inclusive)."""
    for clause in (query.get("bool") or {}).get("filter") or []:
        bounds = (clause.get("range") or {}).get("@timestamp") if isinstance(clause, dict) else None
        if isinstance(bounds, dict):
            if "lte" in bounds:
                return _parse_when(bounds.get("gte")), _parse_when(bounds["lte"]), True
            return _parse_when(bounds.get("gte")), _parse_when(bounds.get("lt")), False
    return None, None, False


def _ms_and_iso(at: datetime) -> dict[str, Any]:
    return {"value": at.timestamp() * 1000.0, "value_as_string": SyntheticGrid._stamp(at)}


@dataclass
class LogonGrid:
    """The fake grid the logon chain detector reads.

    It answers the edge read (a composite over ``host.name`` of the accepted
    sessions) and the recent read (the logon documents themselves, oldest
    first). ``clock`` is the present: nothing after it exists.
    """

    logons: list[Logon]
    clock: datetime
    searches: int = 0
    reads: list[str] = field(default_factory=list)

    def _inside(self, query: dict[str, Any]) -> list[Logon]:
        lo, hi, inclusive = _bounds(query)
        out = []
        for logon in self.logons:
            if logon.at > self.clock or (lo is not None and logon.at < lo):
                continue
            if hi is not None and (logon.at > hi if inclusive else logon.at >= hi):
                continue
            out.append(logon)
        return sorted(out, key=lambda x: (x.at, x.doc_id))

    def _edges(self, logons: list[Logon]) -> list[dict[str, Any]]:
        by_host: dict[str, list[Logon]] = {}
        for logon in logons:
            if logon.session:
                by_host.setdefault(logon.host, []).append(logon)
        buckets = []
        for host, rows in sorted(by_host.items()):
            sources: dict[str, list[Logon]] = {}
            for row in rows:
                sources.setdefault(row.source_ip, []).append(row)
            ips = sorted({ip for row in rows for ip in row.host_ips})
            buckets.append(
                {
                    "key": host,
                    "doc_count": len(rows),
                    "first": _ms_and_iso(min(r.at for r in rows)),
                    "sources": {
                        "buckets": [
                            {
                                "key": ip,
                                "doc_count": len(hits),
                                "first": _ms_and_iso(min(r.at for r in hits)),
                            }
                            for ip, hits in sorted(sources.items())
                        ],
                        "sum_other_doc_count": 0,
                    },
                    "addresses": {"buckets": [{"key": ip, "doc_count": 1} for ip in ips]},
                }
            )
        return buckets

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        from_: int = 0,
        sort: Any = None,
        source: Any = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
        require_complete: bool = False,
    ) -> EsSearchResult:
        self.searches += 1
        aggs = aggs or {}
        key = next(iter(aggs), "")
        self.reads.append(key or "hits")
        inside = self._inside(query)
        if key == "logon_edges":
            return _result({key: composite_page(aggs[key], self._edges(inside))})
        if not aggs:
            hits = [{"_index": "logs-x", "_id": x.doc_id, "_source": x.body()} for x in inside]
            return EsSearchResult(
                total=len(hits),
                took_ms=1,
                hits=hits[:size],
                aggregations=None,
                total_is_lower_bound=False,
            )
        return _result({key: {"buckets": []}})


# ---------------------------------------------------------------------------
# One client over the three fakes, for a replay of both evaluators
# ---------------------------------------------------------------------------

# A field only the recent read of the logon chain asks the grid to return.
_LOGON_FIELD = "system.auth.ssh.event"


@dataclass
class EstateGrid:
    """The flows of the profile estate, the planes and the logons behind one client.

    Each request goes to the fake that answers its shape. The plane reads and
    the one-document lookups of a plane hit go to ``planes``. The edge read
    and the recent read of the logon chain go to ``logons``. Every other
    request goes to ``flows``. Each fake keeps its own count, so a test can
    show which evaluator read the grid.
    """

    flows: SyntheticGrid
    planes: PlaneGrid
    logons: LogonGrid
    searches: int = 0

    def _route(self, aggs: dict[str, Any] | None, size: int, source: Any) -> Any:
        key = next(iter(aggs or {}), "")
        if key in ("plane_hosts", "plane_flows") or (not aggs and size == 1):
            return self.planes
        if key == "logon_edges" or (
            not aggs and isinstance(source, list) and _LOGON_FIELD in source
        ):
            return self.logons
        return self.flows

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        from_: int = 0,
        sort: Any = None,
        source: Any = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
        require_complete: bool = False,
    ) -> EsSearchResult:
        self.searches += 1
        target = self._route(aggs, size, source)
        result: EsSearchResult = await target.search(
            index,
            query,
            size=size,
            from_=from_,
            sort=sort,
            source=source,
            aggs=aggs,
            track_total_hits=track_total_hits,
        )
        return result
