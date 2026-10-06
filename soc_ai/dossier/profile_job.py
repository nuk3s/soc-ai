"""Build and persist every entity's behavioural profile: one job, two callers.

The dossier sweep ran this as a private step, and the prior sweep loop read
whatever the step had left. On the range the dossier schedule was off and the
host timer that used to run the sweep was retired, so the loop evaluated
baselines that were three days old every hour and reported them as if they
were current. The job has a name of its own so the loop can run it when the
baselines are stale, whatever the dossier schedule says.

Three things are decided here and nowhere else:

* per-host coverage for the dimensions the lane left silent (the fill);
* the ``unmeasurable`` rows for a dimension the grid refused, with the reason;
* which rows a clean build expires.

**Incremental, in batches.** The lane reads the estate with one entity terms
aggregation per dimension, and the aggregation holds 500 entities. On an
estate of more than 500 hosts the others got no profile, and no surface said
so. The job now hands the lane one batch of hosts at a time:

* the census and the machines name the hosts. A batch holds up to
  :data:`_BATCH_KEYS` addresses and as many agent names, and every search the
  lane makes for the batch carries a terms filter on its entity field. One
  search per dimension serves the whole batch;
* a host whose profile is younger than the dossier refresh interval, and whose
  last activity is older than the end of the window its build read, is
  skipped. Its rows stay, and the expiry keeps them;
* a batch search that the grid refuses for its bucket count is split in
  halves, down to one host. That is the per-host fallback. A host that the
  grid refuses alone is the dimension's error, as before;
* a last read covers the entities that the census does not hold, with every
  known host excluded. It pages a composite aggregation,
  :data:`_BEYOND_PAGE` hosts a page, up to :data:`_BEYOND_CEILING` hosts per
  dimension. A read at the ceiling writes a note with the number. On an empty
  census it reads the whole estate.

``profile_build_workers`` batches run at once. The writes take one
transaction per batch.

The batching sits in a client wrapper (:class:`_BatchGrid`) because the lane
owns its queries. The lane needs one change to drop the wrapper: an
``entity_keys`` argument that adds the terms filter itself.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.dossier.profile import PROFILE_SHAPE, ProfileSweep, collect_entity_profiles
from soc_ai.dossier.stages import StageClock, counting
from soc_ai.enrichment.discovery import _is_ip_literal
from soc_ai.so_client.elastic import DEFAULT_MAX_BUCKETS, EsSearchResult
from soc_ai.so_client.paging import read_pages
from soc_ai.store import entity_profiles
from soc_ai.store.host_machines import address_sort_key
from soc_ai.store.models import EntityProfile, HostDossier, HostMachine

_LOGGER = logging.getLogger(__name__)

__all__ = ["ProfileBuild", "build_profiles", "freshness", "shape_due"]

# Hosts per batch, per key type. Never above the lane's entity terms size
# (500): the wrapper raises the size to the batch, but a smaller batch is what
# keeps one search under the grid's bucket limit.
_BATCH_KEYS = 500
# A terms query holds at most 65,536 values by default. The last read excludes
# every known host in one clause, so past this it cannot run.
_MAX_EXCLUDED_TERMS = 60_000
# The read outside the census, per dimension: a composite aggregation over the
# entity field, read in key order, 1,000 hosts a page, up to 20,000 hosts. A
# terms read held the busiest 500. On an estate past that the quieter hosts
# outside the census got no profile. Past the ceiling the hosts last in key
# order get no row, and the build's note gives the number.
_BEYOND_PAGE = 1_000
_BEYOND_CEILING = 20_000
# The terms keys a composite source can carry. A terms read with any other key
# (an order, an include, a partition) is not paged: the composite answer would
# drop that key and still look whole.
_PAGEABLE_TERMS = frozenset({"field", "size"})
# Values per IN list, below SQLite's bound on bound parameters.
_IN_CHUNK = 400
_TOO_MANY_BUCKETS = "too_many_buckets_exception"

# The two key types an entity field holds. An address field keys a host on
# its address; ``host.name`` keys it on the name its agent ships.
_ADDRESS = "address"
_NAME = "name"
_NAME_FIELDS = frozenset({"host.name"})

# Dimensions an agent on the machine supplies, grouped by the plane that feeds
# them. A host that ships no document on a plane is BLIND for every dimension
# that plane feeds -- not empty, blind.
#
# The agent inventory used to decide this. It cannot: an agent that ships
# security logs and runs no Sysmon is listed, and the domain controller's
# process, process-pair and logon-user dimensions all read "measured, none
# observed" while nothing on that host could produce a process document.
_AGENT_PLANES: tuple[tuple[str, ...], ...] = (
    ("process_names", "process_parents"),
    ("logon_users",),
)
# Dimensions every host with flow can answer, when a plane carries them. A
# host that has flow and no row here genuinely did none of this: measured,
# and empty. A dimension no plane on the grid carries is blind on every host.
_FLOW_DIMENSIONS: tuple[str, ...] = ("served_ports", "consumed_ports", "peers_out", "dns_names")

# The shape an unmeasurable row records, so the host page renders the right row.
_SHAPE_OF: dict[str, str] = {"active_hours": "active_hours", "connection_rate": "numeric"}


@dataclass
class ProfileBuild:
    """What one run of the job did. ``errors`` are failures; ``notes`` are facts."""

    written: int = 0
    purged: int = 0
    expired: int = 0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Host keys (an address or an agent name) the build skipped as fresh.
    skipped: int = 0
    # Host keys the build read in batches, and how many batches.
    batched: int = 0
    batches: int = 0
    # Host keys the grid refused in a batch, read one at a time.
    single: int = 0
    # Host keys the last read found outside the census.
    beyond: int = 0
    # Host keys whose rows held a shape older than PROFILE_SHAPE. The build
    # read them whatever their age.
    reshaped: int = 0
    # Wall time and searches per stage, in run order.
    stages: list[dict[str, Any]] = field(default_factory=list)


def _coverage_fill(
    sweep: ProfileSweep, *, unanswered: frozenset[str]
) -> list[tuple[str, str, str, int]]:
    """Rows to write for dimensions a host has NO row for: (key, dim, coverage, support).

    The lane emits one grid-level placeholder when no plane can answer a
    dimension at all, and nothing for a host that simply has no data in it.
    On the page those two absences and "we never tried" looked identical, so
    per-host coverage is decided here:

    * an agent dimension whose plane returned no document for this host is
      ``blind``;
    * an agent dimension whose plane DID answer for this host, with no rows of
      its own, is measured and empty;
    * a flow dimension on a host that has flow rows is measured and empty,
      UNLESS no plane on the grid carries it (``unanswered``), in which case
      it is blind on every host. Production wrote 178 measured-and-empty DNS
      rows on a grid with no DNS plane before this clause existed.

    A row exists for a host only when the aggregation returned a bucket for
    it, so the presence of any row from a plane is the proof that the plane
    answered. Only a dimension the host has NO row for is filled: the lane's
    own row, whatever it holds, is the measurement and is never overwritten.
    """
    have: dict[str, set[str]] = {}
    support: dict[str, int] = {}
    for b in sweep.profiles:
        if b.entity_key == "*" or b.entity_kind != "host":
            continue
        have.setdefault(b.entity_key, set()).add(b.dimension)
        support[b.entity_key] = max(support.get(b.entity_key, 0), int(b.support_days or 0))

    fill: list[tuple[str, str, str, int]] = []
    for key, dims in have.items():
        days = support.get(key, 0)
        for plane in _AGENT_PLANES:
            measured = bool(dims & set(plane))
            for dim in plane:
                if dim in dims:
                    continue
                fill.append((key, dim, "measured" if measured else "blind", days))
        if dims & set(_FLOW_DIMENSIONS):
            for dim in _FLOW_DIMENSIONS:
                if dim in dims:
                    continue
                fill.append((key, dim, "blind" if dim in unanswered else "measured", days))
    return fill


def _unmeasurable_rows(sweep: ProfileSweep) -> list[tuple[str, str, str, str]]:
    """(key, dimension, shape, reason) for every host the sweep saw, per refused dimension.

    Every host, because the refusal was about the grid's size and not about
    any one host: a row per host is what lets the host page say "not
    measured: <reason>" instead of "nothing observed".
    """
    if not sweep.unmeasurable:
        return []
    hosts = sorted(
        {b.entity_key for b in sweep.profiles if b.entity_kind == "host" and b.entity_key != "*"}
    )
    return [
        (key, dim, _SHAPE_OF.get(dim, "categorical"), reason)
        for key in hosts
        for dim, reason in sorted(sweep.unmeasurable.items())
    ]


# ---------------------------------------------------------------------------
# The batch wrapper
# ---------------------------------------------------------------------------


def _key_kind(field_name: str) -> str | None:
    """Which key type an entity field holds. ``None`` for a field the job does not scope."""
    if field_name.endswith(".ip"):
        return _ADDRESS
    if field_name in _NAME_FIELDS:
        return _NAME
    return None


def _entity_agg(aggs: Any) -> tuple[str, str, str] | None:
    """``(name, type, field)`` of a search's one entity aggregation, else ``None``.

    The lane keys every entity read the same way: one top-level ``terms``
    aggregation on the entity field, or one ``cardinality`` on it for the
    shaped read's entity count. A plane probe is a ``filters`` aggregation and
    is not an entity read.
    """
    if not isinstance(aggs, Mapping) or len(aggs) != 1:
        return None
    ((name, body),) = aggs.items()
    if not isinstance(body, Mapping):
        return None
    for agg_type in ("terms", "cardinality"):
        spec = body.get(agg_type)
        if isinstance(spec, Mapping) and isinstance(spec.get("field"), str):
            return str(name), agg_type, str(spec["field"])
    return None


def _partitioned(aggs: Mapping[str, Any], name: str) -> bool:
    """Whether the entity terms is one slice of a partitioned read.

    The lane's shaped read splits itself into partitions and has its own
    ladder for the bucket limit. The wrapper leaves that ladder alone.
    """
    include = ((aggs.get(name) or {}).get("terms") or {}).get("include")
    return isinstance(include, Mapping) and "partition" in include


def _pageable(aggs: Mapping[str, Any], name: str) -> bool:
    """Whether composite pages can replace the entity terms.

    The lane's categorical reads carry a field and a size. The shaped read
    carries a partition and keeps its own ladder.
    """
    terms = (aggs.get(name) or {}).get("terms")
    return isinstance(terms, Mapping) and set(terms) <= _PAGEABLE_TERMS


def _too_many_buckets(exc: BaseException) -> bool:
    """Whether an Elasticsearch error is the bucket limit, read from its body."""
    body = getattr(exc, "body", None)
    error = body.get("error") if isinstance(body, dict) else None
    if not isinstance(error, dict):
        return False
    if (error.get("caused_by") or {}).get("type") == _TOO_MANY_BUCKETS:
        return True
    return any((rc or {}).get("type") == _TOO_MANY_BUCKETS for rc in error.get("root_cause") or [])


def _restricted(query: Any, *, filters: Sequence[Any] = (), must_not: Sequence[Any] = ()) -> Any:
    """The lane's query with more clauses beside it. The lane's own stays whole."""
    if not filters and not must_not:
        return query
    out: dict[str, Any] = {"filter": [query, *filters]}
    if must_not:
        out["must_not"] = list(must_not)
    return {"bool": out}


def _sized(aggs: Mapping[str, Any], name: str, keys: int) -> dict[str, Any]:
    """The aggregations, with the entity terms large enough to hold the batch."""
    out = copy.deepcopy(dict(aggs))
    terms = (out.get(name) or {}).get("terms")
    if isinstance(terms, dict):
        terms["size"] = max(int(terms.get("size") or 0), keys)
    return out


def _empty(name: str, agg_type: str) -> EsSearchResult:
    """The answer to a read the batch holds no key for. No search is made."""
    body: dict[str, Any] = (
        {"value": 0} if agg_type == "cardinality" else {"buckets": [], "sum_other_doc_count": 0}
    )
    return EsSearchResult(total=0, took_ms=0, aggregations={name: body})


def _merged(first: Any, second: Any, name: str) -> EsSearchResult:
    """Two halves of one split terms read, as the one answer the lane asked for."""
    a = (getattr(first, "aggregations", None) or {}).get(name) or {}
    b = (getattr(second, "aggregations", None) or {}).get(name) or {}
    agg = {
        **a,
        "buckets": [*(a.get("buckets") or []), *(b.get("buckets") or [])],
        "sum_other_doc_count": int(a.get("sum_other_doc_count") or 0)
        + int(b.get("sum_other_doc_count") or 0),
    }
    return EsSearchResult(
        total=int(getattr(first, "total", 0) or 0) + int(getattr(second, "total", 0) or 0),
        took_ms=int(getattr(first, "took_ms", 0) or 0) + int(getattr(second, "took_ms", 0) or 0),
        aggregations={name: agg},
    )


class _Shared:
    """What every batch of one build shares: the grid, the caches, the tallies."""

    def __init__(self, grid: Any, cidrs: Sequence[Any]) -> None:
        self.grid = grid
        self.cidrs = [str(c).strip() for c in cidrs if str(c).strip()]
        # A read that is not an entity read (the plane probes) is the same for
        # every batch. It runs once, and the batches that ask at the same time
        # wait for that one answer.
        self._cache: dict[str, asyncio.Future[tuple[bool, Any]]] = {}
        self._buckets: asyncio.Future[int] | None = None
        # Host keys a batch read one at a time after the grid refused the batch.
        self.single: set[str] = set()
        # Host keys the last read found outside the census.
        self.beyond: set[str] = set()
        # The reads outside the census that did not reach every host, by
        # aggregation name. The lane names a categorical read after its
        # dimension.
        self.capped: set[str] = set()
        # The paged reads among them. Each stopped at _BEYOND_CEILING.
        self.at_ceiling: set[str] = set()
        # Key types the last read could not exclude in one clause.
        self.unexcluded: set[str] = set()
        # Entity fields the wrapper does not scope. Each read ran estate-wide once.
        self.unscoped: set[str] = set()

    async def once(self, index: str, query: Any, kwargs: Mapping[str, Any]) -> Any:
        """Run a read that every batch makes the same way, once per build."""
        key = json.dumps([index, query, dict(kwargs)], sort_keys=True, default=str)
        held = self._cache.get(key)
        if held is None:
            held = asyncio.get_running_loop().create_future()
            self._cache[key] = held
            try:
                held.set_result((True, await self.grid.search(index, query, **kwargs)))
            except Exception as exc:
                held.set_result((False, exc))
        ok, value = await held
        if not ok:
            raise value
        return value

    async def max_buckets(self) -> int:
        """The grid's bucket limit, read once. A client that cannot say gets the default."""
        if self._buckets is None:
            self._buckets = asyncio.get_running_loop().create_future()
            reader = getattr(self.grid, "max_buckets", None)
            value = DEFAULT_MAX_BUCKETS
            if reader is not None:
                try:
                    value = int(await reader())
                except Exception:
                    value = DEFAULT_MAX_BUCKETS
            self._buckets.set_result(value)
        return await self._buckets


class _BatchGrid:
    """The grid as one batch of the build sees it.

    ``include`` scopes every entity read to the batch's keys. ``exclude``
    makes the last read: every known key is left out, and an address read
    keeps to the estate's CIDRs. The last read pages each categorical
    dimension. Exactly one of the two is set.
    """

    def __init__(
        self,
        shared: _Shared,
        *,
        include: Mapping[str, Sequence[str]] | None = None,
        exclude: Mapping[str, frozenset[str]] | None = None,
    ) -> None:
        self._shared = shared
        self._include = include
        self._exclude = exclude

    async def max_buckets(self) -> int:
        return await self._shared.max_buckets()

    async def search(self, index: str, query: Any, **kwargs: Any) -> Any:
        found = _entity_agg(kwargs.get("aggs"))
        if found is None:
            return await self._shared.once(index, query, kwargs)
        name, agg_type, field_name = found
        kind = _key_kind(field_name)
        if kind is None:
            self._shared.unscoped.add(field_name)
            return await self._shared.once(index, query, kwargs)
        if self._include is not None:
            keys = list(self._include.get(kind) or ())
            if not keys:
                return _empty(name, agg_type)
            return await self._scoped(
                index, query, kwargs, name=name, field_name=field_name, keys=keys, split=False
            )
        return await self._beyond(
            index, query, kwargs, name=name, agg_type=agg_type, field_name=field_name, kind=kind
        )

    async def _scoped(
        self,
        index: str,
        query: Any,
        kwargs: Mapping[str, Any],
        *,
        name: str,
        field_name: str,
        keys: list[str],
        split: bool,
    ) -> Any:
        aggs = kwargs["aggs"]
        body = _restricted(query, filters=[{"terms": {field_name: keys}}])
        try:
            result = await self._shared.grid.search(
                index, body, **{**kwargs, "aggs": _sized(aggs, name, len(keys))}
            )
        except Exception as exc:
            if len(keys) < 2 or _partitioned(aggs, name) or not _too_many_buckets(exc):
                raise
            # The per-host fallback: the grid refused the batch for its bucket
            # count, so read it in halves, down to one host.
            half = len(keys) // 2
            first = await self._scoped(
                index, query, kwargs, name=name, field_name=field_name, keys=keys[:half], split=True
            )
            second = await self._scoped(
                index, query, kwargs, name=name, field_name=field_name, keys=keys[half:], split=True
            )
            return _merged(first, second, name)
        if split and len(keys) == 1:
            self._shared.single.add(keys[0])
        return result

    async def _beyond(
        self,
        index: str,
        query: Any,
        kwargs: Mapping[str, Any],
        *,
        name: str,
        agg_type: str,
        field_name: str,
        kind: str,
    ) -> Any:
        excluded = (self._exclude or {}).get(kind) or frozenset()
        if len(excluded) > _MAX_EXCLUDED_TERMS:
            self._shared.unexcluded.add(kind)
            return _empty(name, agg_type)
        filters = (
            [{"terms": {field_name: self._shared.cidrs}}]
            if kind == _ADDRESS and self._shared.cidrs
            else []
        )
        must_not = [{"terms": {field_name: sorted(excluded)}}] if excluded else []
        body = _restricted(query, filters=filters, must_not=must_not)
        aggs = kwargs.get("aggs") or {}
        if agg_type == "terms" and _pageable(aggs, name):
            return await self._paged(index, body, aggs, name=name, field_name=field_name)
        result = await self._shared.grid.search(index, body, **kwargs)
        if agg_type == "terms":
            agg = (getattr(result, "aggregations", None) or {}).get(name) or {}
            if int(agg.get("sum_other_doc_count") or 0) > 0:
                self._shared.capped.add(name)
            for bucket in agg.get("buckets") or []:
                key = bucket.get("key")
                if isinstance(key, str) and key:
                    self._shared.beyond.add(key)
        return result

    async def _paged(
        self,
        index: str,
        query: Any,
        aggs: Mapping[str, Any],
        *,
        name: str,
        field_name: str,
    ) -> EsSearchResult:
        """The read outside the census in composite pages, as the terms answer the lane reads.

        Each bucket keeps the sub-aggregations the lane asked for. A read that
        stops at :data:`_BEYOND_CEILING` marks its dimension. The fill then
        writes no row for a host the read did not reach, and the build writes
        a note with the number. A failed page raises, and the lane reports the
        dimension's error. Part of the estate is never handed back as all of it.
        """
        pages = await read_pages(
            self._shared.grid,
            index,
            query,
            name=name,
            field=field_name,
            aggs=(aggs.get(name) or {}).get("aggs"),
            page_size=_BEYOND_PAGE,
            ceiling=_BEYOND_CEILING,
        )
        if pages.capped:
            self._shared.capped.add(name)
            self._shared.at_ceiling.add(name)
        for bucket in pages.buckets:
            key = bucket.get("key")
            if isinstance(key, str) and key:
                self._shared.beyond.add(key)
        return EsSearchResult(
            total=0,
            took_ms=0,
            aggregations={name: {"buckets": list(pages.buckets), "sum_other_doc_count": 0}},
        )


# ---------------------------------------------------------------------------
# The plan: which hosts to build, which to skip
# ---------------------------------------------------------------------------


def _aware_utc(value: datetime) -> datetime:
    """``value`` as an aware UTC time. A naive time is UTC already."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _naive_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


def _newer(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


@dataclass
class _Plan:
    """The host keys to build, per key type, and the keys the build skips."""

    build: dict[str, list[str]]
    skipped: set[str]
    # Every key the store knows, per type. The last read excludes them.
    known: dict[str, frozenset[str]]
    # The keys whose rows hold a shape older than PROFILE_SHAPE, and the
    # oldest shape among them. The skip rule never skips them.
    reshaped: set[str] = field(default_factory=set)
    oldest_shape: int | None = None

    def batches(self, size: int) -> list[dict[str, tuple[str, ...]]]:
        size = max(1, size)
        chunks = {
            kind: [tuple(keys[i : i + size]) for i in range(0, len(keys), size)]
            for kind, keys in self.build.items()
        }
        count = max((len(c) for c in chunks.values()), default=0)
        return [
            {kind: (c[i] if i < len(c) else ()) for kind, c in chunks.items()} for i in range(count)
        ]

    @property
    def to_build(self) -> int:
        return sum(len(keys) for keys in self.build.values())


async def _plan(db: AsyncSession, *, now: datetime, fresh_for: timedelta, lag: timedelta) -> _Plan:
    """Read the census, the machines and the stored profiles, and decide.

    A key is skipped when every row it holds was built inside ``fresh_for``
    and its newest activity is no later than the end of the window that
    build read (the build time less ``lag``). Activity newer than that sits
    in data the stored baseline never read. A key with no activity on record
    is built: an unknown date is not a quiet host.

    A key with a row of a shape older than :data:`PROFILE_SHAPE` is never
    skipped. Its rows are fresh by age and still hold a shape the readers of
    this release cannot score.
    """
    seen: dict[str, datetime | None] = {}
    census = await db.execute(select(HostDossier.host_key, HostDossier.last_seen))
    for key, last_seen in census.all():
        if key:
            seen[str(key)] = _naive_utc(last_seen)
    names: dict[str, datetime | None] = {}
    machines = await db.execute(
        select(HostMachine.agent_name, HostMachine.last_seen, HostMachine.agent_last_report).where(
            HostMachine.agent_name.is_not(None)
        )
    )
    for name, last_seen, last_report in machines.all():
        if not name:
            continue
        stamp = _newer(_naive_utc(last_seen), _naive_utc(last_report))
        names[str(name)] = _newer(names.get(str(name)), stamp)
    built: dict[str, datetime] = {}
    shapes: dict[str, int] = {}
    stored = await db.execute(
        select(
            EntityProfile.entity_key,
            func.min(EntityProfile.built_at),
            func.min(func.coalesce(EntityProfile.shape_version, entity_profiles.UNSTAMPED_SHAPE)),
        )
        .where(EntityProfile.entity_kind == "host")
        .group_by(EntityProfile.entity_key)
    )
    for key, oldest, shape in stored.all():
        stamp = _naive_utc(oldest)
        if key and stamp is not None:
            built[str(key)] = stamp
        if key and shape is not None:
            shapes[str(key)] = int(shape)
    reshaped = {key for key, shape in shapes.items() if shape < PROFILE_SHAPE}

    addresses = set(seen) | {k for k in built if _is_ip_literal(k)}
    agent_names = set(names) | {k for k in built if not _is_ip_literal(k)}
    activity = {**names, **seen}
    skipped: set[str] = set()
    for key in addresses | agent_names:
        oldest = built.get(key)
        last = activity.get(key)
        if oldest is None or last is None or key in reshaped:
            continue
        if now - oldest < fresh_for and last <= oldest - lag:
            skipped.add(key)
    return _Plan(
        build={
            _ADDRESS: sorted(addresses - skipped, key=address_sort_key),
            _NAME: sorted(agent_names - skipped),
        },
        skipped=skipped,
        known={_ADDRESS: frozenset(addresses), _NAME: frozenset(agent_names)},
        reshaped=reshaped,
        oldest_shape=min((shapes[k] for k in reshaped), default=None),
    )


# ---------------------------------------------------------------------------
# The writes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Row:
    key: str
    dimension: str
    shape: str
    vector: Any | None
    coverage: str
    support_days: int
    coverage_reason: str | None = None


def _rows_of(sweep: ProfileSweep, *, capped: frozenset[str] = frozenset()) -> list[_Row]:
    """Every row one batch writes: the lane's own, the fill, the unmeasurable ones.

    ``capped`` names the dimensions whose read filled its entity cap. A host
    with no row in one of them may only have ranked below the cut, so the fill
    writes nothing for it there. A "measured, none observed" row would be a
    claim about a read that never reached the host.
    """
    out: list[_Row] = []
    for built in sweep.profiles:
        # The blind placeholder the lane emits is keyed "*": it says the GRID
        # cannot answer this dimension, which is a note on the run, not a row
        # about an entity that does not exist.
        if built.entity_key == "*" or built.entity_kind != "host":
            continue
        out.append(
            _Row(
                key=built.entity_key,
                dimension=built.dimension,
                shape=built.shape,
                vector=built.vector,
                coverage=built.coverage,
                support_days=built.support_days,
            )
        )
    for key, dim, coverage, days in _coverage_fill(sweep, unanswered=frozenset(sweep.unanswered)):
        if dim in capped:
            continue
        out.append(
            _Row(
                key=key,
                dimension=dim,
                shape="categorical",
                vector=None if coverage == "blind" else {},
                coverage=coverage,
                support_days=days if coverage != "blind" else 0,
            )
        )
    for key, dim, shape, reason in _unmeasurable_rows(sweep):
        out.append(
            _Row(
                key=key,
                dimension=dim,
                shape=shape,
                vector=None,
                coverage=entity_profiles.COVERAGE_UNMEASURABLE,
                support_days=0,
                coverage_reason=reason,
            )
        )
    return out


def _chunks(items: Sequence[str], size: int = _IN_CHUNK) -> Iterable[Sequence[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


# The columns a build sets on every row it writes, beyond the three of the key.
_WRITTEN_COLUMNS: tuple[str, ...] = (
    "shape",
    "vector_json",
    "coverage",
    "coverage_reason",
    "support_days",
    "role",
    "role_confidence",
    "identity_fingerprint",
    "window_days",
    "first_seen",
    "last_seen",
    "built_at",
    "shape_version",
)
_KEY_COLUMNS: tuple[str, ...] = ("entity_kind", "entity_key", "dimension")


def _values_of(rows: Sequence[_Row], *, window_days: int, stamp: datetime) -> list[dict[str, Any]]:
    """One parameter set per (key, dimension). A later row for the same pair wins."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        out[(row.key, row.dimension)] = {
            "entity_kind": "host",
            "entity_key": row.key,
            "dimension": row.dimension,
            "shape": row.shape,
            "vector_json": row.vector,
            "coverage": row.coverage,
            "coverage_reason": row.coverage_reason,
            "support_days": row.support_days,
            "role": None,
            "role_confidence": None,
            "identity_fingerprint": None,
            "window_days": window_days,
            "first_seen": None,
            "last_seen": None,
            "built_at": stamp,
            "shape_version": PROFILE_SHAPE,
        }
    return list(out.values())


async def _write_rows(
    db: AsyncSession,
    rows: Sequence[_Row],
    *,
    window_days: int,
    stamp: datetime | None = None,
) -> int:
    """Upsert one batch's rows in one transaction. Returns how many.

    The same columns, with the same values, that
    :func:`entity_profiles.upsert_profile` writes for a build. That function
    reads, writes and commits once per row, and a build of 20,000 hosts writes
    about 200,000 rows: at a commit each the writes were most of the run. On
    SQLite and PostgreSQL this is one ``INSERT ... ON CONFLICT DO UPDATE``
    per chunk of rows. Another dialect takes the ORM path, one transaction
    per batch.

    ``stamp`` is the ``built_at`` of every row. None stamps the present. An
    anchored build passes its anchor.
    """
    if not rows:
        return 0
    if stamp is None:
        stamp = datetime.now(UTC).replace(tzinfo=None)
    values = _values_of(rows, window_days=window_days, stamp=stamp)
    dialect = db.get_bind().dialect.name
    if dialect in ("sqlite", "postgresql"):
        insert = sqlite_insert if dialect == "sqlite" else postgresql_insert
        statement = insert(EntityProfile)
        statement = statement.on_conflict_do_update(
            index_elements=list(_KEY_COLUMNS),
            set_={name: statement.excluded[name] for name in _WRITTEN_COLUMNS},
        )
        for start in range(0, len(values), _IN_CHUNK):
            await db.execute(statement, values[start : start + _IN_CHUNK])
        await db.commit()
        return len(values)

    keys = sorted({v["entity_key"] for v in values})
    held: dict[tuple[str, str], EntityProfile] = {}
    for chunk in _chunks(keys):
        found = await db.scalars(
            select(EntityProfile).where(
                EntityProfile.entity_kind == "host", EntityProfile.entity_key.in_(chunk)
            )
        )
        for model in found.all():
            held[(model.entity_key, model.dimension)] = model
    for value in values:
        target = held.get((value["entity_key"], value["dimension"]))
        if target is None:
            target = EntityProfile(**{k: value[k] for k in _KEY_COLUMNS})
            db.add(target)
        for name in _WRITTEN_COLUMNS:
            setattr(target, name, value[name])
    await db.commit()
    return len(values)


async def _expire(db: AsyncSession, *, built_before: datetime, keep: set[str]) -> int:
    """Delete every row stamped before ``built_before``, except the skipped hosts'.

    A skipped host's rows are older than the run by design. They are its
    current baseline, and deleting them would leave the host with none.
    """
    rows = (
        await db.execute(
            select(EntityProfile.id, EntityProfile.entity_kind, EntityProfile.entity_key).where(
                EntityProfile.built_at < built_before
            )
        )
    ).all()
    doomed = [int(i) for i, kind, key in rows if not (kind == "host" and key in keep)]
    for start in range(0, len(doomed), _IN_CHUNK):
        await db.execute(
            delete(EntityProfile).where(EntityProfile.id.in_(doomed[start : start + _IN_CHUNK]))
        )
    await db.commit()
    return len(doomed)


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------


@dataclass
class _Outcome:
    """What the batches of one build collected, folded together."""

    errors: dict[str, None] = field(default_factory=dict)
    notes: dict[str, None] = field(default_factory=dict)
    planes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    unmeasurable: dict[str, str] = field(default_factory=dict)
    written: int = 0

    def fold(self, sweep: ProfileSweep) -> None:
        for detail in sweep.errors:
            self.errors[f"entity profiles: {detail}"] = None
        for note in sweep.notes:
            self.notes[note] = None
        for label, planes in sweep.planes.items():
            if len(planes) >= len(self.planes.get(label, ())):
                self.planes[label] = planes
        for dim, reason in sweep.unmeasurable.items():
            self.unmeasurable.setdefault(dim, reason)


def _count(value: int, one: str, many: str) -> str:
    return f"{value} {one if value == 1 else many}"


def _summary(build: ProfileBuild) -> str:
    """The run-row line: rows written, then what the build skipped, batched and split."""
    detail = f"entity profiles: wrote {build.written} row(s)"
    if build.purged:
        detail += f", purged {build.purged} out of scope"
    if build.expired:
        detail += f", expired {build.expired} stale row(s)"
    detail += (
        f". Skipped {_count(build.skipped, 'fresh host', 'fresh hosts')}. "
        f"Built {_count(build.batched, 'host', 'hosts')} "
        f"in {_count(build.batches, 'batch', 'batches')}"
    )
    if build.single:
        detail += f" and {build.single} alone"
    detail += "."
    if build.beyond:
        detail += f" Found {_count(build.beyond, 'host', 'hosts')} outside the census."
    return detail


async def build_profiles(
    elastic: Any,
    sessionmaker: Any,
    settings: Any,
    cidrs: Sequence[Any] = (),
    *,
    now: datetime | None = None,
) -> ProfileBuild:
    """Build and persist behavioural profiles, if the deployment has opted in.

    The aggregations are keyed by entity, so one search per dimension serves a
    whole batch of hosts. See the module docstring for the batches, the skip
    rule and the per-host fallback.

    Gated OFF by default. The design does not let this layer influence
    anything before a shadow week has been read.

    Never raises. A caller that aborted because a baseline could not be built
    would have traded a working feature for a new one.

    Expiry: after a build that reports no error, rows stamped before the run
    started are deleted, except the rows of the hosts the build skipped. They
    describe hosts the window no longer holds or dimensions the build no
    longer writes, and the upsert never deletes. A build with an error expires
    nothing, because the dimension that failed wrote no row this run and its
    old rows are the only baseline left.

    ``now`` is the time anchor. The baseline window ends
    ``entity_profile_lag_hours`` before it. The skip rule and the expiry read
    it as the present, and every row is stamped with it. None is the present.
    A replay passes the start of each replayed day: the build had no anchor,
    so a past day could not be built.
    """
    build = ProfileBuild()
    if not getattr(settings, "entity_profiles_enabled", False):
        return build

    grid = counting(elastic)
    clock = StageClock(label="profile build", grid=grid, logger=_LOGGER)
    try:
        await _build(grid, sessionmaker, settings, cidrs, build=build, clock=clock, now=now)
    except Exception as exc:  # pragma: no cover - defence in depth; _build catches its own
        build.errors.append(f"entity profiles: {type(exc).__name__}: {exc}")
    finally:
        build.stages = clock.as_dicts()
    if build.errors:
        _LOGGER.warning("profile build: %s", "; ".join(build.errors[:3]))
    return build


async def _build(  # noqa: PLR0915 - one procedure, read top to bottom
    grid: Any,
    sessionmaker: Any,
    settings: Any,
    cidrs: Sequence[Any],
    *,
    build: ProfileBuild,
    clock: StageClock,
    now: datetime | None = None,
) -> None:
    window_days = max(1, int(getattr(settings, "entity_profile_window_days", 30)))
    lag_hours = max(0, int(getattr(settings, "entity_profile_lag_hours", 24)))
    interval_hours = max(1, int(getattr(settings, "dossier_schedule_interval_hours", 24) or 24))
    workers = max(1, int(getattr(settings, "profile_build_workers", 2) or 1))
    # The anchor as an aware UTC time for the grid, and as a naive UTC time
    # for the store. Without one the build reads and stamps the present.
    anchor = None if now is None else _aware_utc(now)
    stamp: datetime | None = None
    if anchor is None:
        started = datetime.now(UTC).replace(tzinfo=None)
    else:
        started = stamp = anchor.replace(tzinfo=None)

    with clock.stage("plan") as stage:
        try:
            async with sessionmaker() as db:
                # Before writing: drop anything the current scope excludes. The
                # builder was scoped to the estate's CIDRs, but the upsert never
                # deletes, so without this a scoping change leaves the profiles
                # it now excludes sitting in the table being reported on.
                build.purged = await entity_profiles.purge_out_of_scope(db, cidrs=cidrs)
                plan = await _plan(
                    db,
                    now=started,
                    fresh_for=timedelta(hours=interval_hours),
                    lag=timedelta(hours=lag_hours),
                )
        except Exception as exc:
            build.errors.append(f"entity profiles: could not read the census: {exc}")
            return
        batches = plan.batches(_BATCH_KEYS)
        build.skipped = len(plan.skipped)
        build.batches = len(batches)
        build.reshaped = len(plan.reshaped)
        stage.detail = (
            f"{plan.to_build} to build, {len(plan.skipped)} skipped, {len(batches)} batches"
        )
    if plan.reshaped:
        reshaped = _reshaped_note(len(plan.reshaped), plan.oldest_shape)
        build.notes.append(reshaped)
        _LOGGER.info("profile build: %s", reshaped)

    shared = _Shared(grid, cidrs)
    outcome = _Outcome()
    gate = asyncio.Semaphore(workers)
    write_lock = asyncio.Lock()

    async def _one(
        include: Mapping[str, Sequence[str]] | None,
        exclude: Mapping[str, frozenset[str]] | None,
    ) -> None:
        async with gate:
            batch_grid: Any = _BatchGrid(shared, include=include, exclude=exclude)
            try:
                sweep = await collect_entity_profiles(
                    elastic=batch_grid,
                    settings=settings,
                    window_hours=window_days * 24,
                    time_anchor=anchor,
                    # The baseline stops where the prior sweep's recent window
                    # starts. Without the gap it contains the very window it is
                    # compared against and nothing can ever be novel.
                    lag_hours=lag_hours,
                    # Host entities are scoped to the estate's own address
                    # space, or the lane profiles the internet.
                    cidrs=cidrs,
                )
            except Exception as exc:
                outcome.errors[f"entity profiles: {exc}"] = None
                return
        outcome.fold(sweep)
        # A batch read holds every key it asked for. Only the read outside the
        # census can stop before it reaches every host.
        rows = _rows_of(
            sweep, capped=frozenset(shared.capped) if exclude is not None else frozenset()
        )
        async with write_lock:
            try:
                async with sessionmaker() as db:
                    outcome.written += await _write_rows(
                        db, rows, window_days=window_days, stamp=stamp
                    )
            except Exception as exc:
                outcome.errors[f"entity profiles: persist failed: {exc}"] = None

    with clock.stage("batches") as stage:
        await asyncio.gather(*(_one(batch, None) for batch in batches))
        stage.detail = f"{len(batches)} batches, {plan.to_build} hosts, {workers} workers"
    with clock.stage("outside the census") as stage:
        await _one(None, plan.known)
        stage.detail = f"{len(shared.beyond)} hosts"

    build.errors.extend(outcome.errors)
    build.notes.extend(outcome.notes)
    for dim, reason in sorted(outcome.unmeasurable.items()):
        build.notes.append(f"{dim}: unmeasurable: {reason}")
    if outcome.planes:
        build.notes.append(
            "profile planes: "
            + "; ".join(f"{k}={','.join(v)}" for k, v in sorted(outcome.planes.items()))
        )
    if shared.at_ceiling:
        build.notes.append(
            "entity profiles: the read outside the census stopped at the ceiling of "
            f"{_BEYOND_CEILING:,} hosts on {', '.join(sorted(shared.at_ceiling))}. "
            "A host past the ceiling in key order has no row on those dimensions yet. "
            "The next build reads the hosts it found in batches and reaches further."
        )
    filled = shared.capped - shared.at_ceiling
    if filled:
        build.notes.append(
            "entity profiles: the read outside the census filled its entity cap on "
            f"{', '.join(sorted(filled))}. The next build reads the hosts it "
            "found in batches and reaches further. A host below the cut has no row "
            "on those dimensions yet."
        )
    for kind in sorted(shared.unexcluded):
        build.notes.append(
            f"entity profiles: the store knows more than {_MAX_EXCLUDED_TERMS} {kind} keys. "
            "The build did not read outside the census for them."
        )
    for name in sorted(shared.unscoped):
        build.notes.append(f"entity profiles: the build read {name} estate-wide, in one search.")
    build.written = outcome.written
    build.single = len(shared.single)
    build.batched = max(0, plan.to_build - build.single)
    build.beyond = len(shared.beyond)

    if not build.errors:
        with clock.stage("expire") as stage:
            try:
                async with sessionmaker() as db:
                    build.expired = await _expire(db, built_before=started, keep=plan.skipped)
            except Exception as exc:
                build.errors.append(f"entity profiles: expiry failed: {exc}")
            stage.detail = f"{build.expired} rows"
    if build.written or build.expired:
        with clock.stage("estate") as stage:
            stage.detail = await _refresh_estate(sessionmaker, build)
    summary = _summary(build)
    build.notes.append(summary)
    _LOGGER.info("profile build: %s", summary)


async def _refresh_estate(sessionmaker: Any, build: ProfileBuild) -> str:
    """Count the hosts that hold each member, from the rows this build left.

    The prior sweep reads the counts for estate-rare and estate-common
    members, and it refreshes them itself when a build is newer. Run here, the
    first sweep after a build reads fresh counts at no cost. A failure is a
    note: the next prior sweep finds the counts stale and refreshes them.
    """
    from soc_ai.hunting.estate import refresh_estate  # noqa: PLC0415 - avoids a cycle

    try:
        async with sessionmaker() as db:
            done = await refresh_estate(db)
    except Exception as exc:
        build.notes.append(
            f"estate prevalence: the refresh after the build failed: {exc}. "
            "The next prior sweep refreshes it."
        )
        return "failed"
    return f"{done.hosts} hosts, {done.members} members, {done.roles_stamped} roles"


async def freshness(sessionmaker: Any) -> entity_profiles.ProfileFreshness:
    """What the table says about itself, for a caller that holds a sessionmaker.

    The shapes are read against :data:`PROFILE_SHAPE`, so
    :func:`shape_due` can read the answer.
    """
    async with sessionmaker() as db:
        return await entity_profiles.freshness(db, shape=PROFILE_SHAPE)


def _reshaped_note(hosts: int, oldest: int | None) -> str:
    """The build note for the hosts whose rows held an older shape."""
    return (
        f"entity profiles: {_count(hosts, 'host', 'hosts')} held the profile shape "
        f"{oldest if oldest is not None else entity_profiles.UNSTAMPED_SHAPE}. "
        f"This release writes shape {PROFILE_SHAPE}. The build read them whatever their age."
    )


def shape_due(state: entity_profiles.ProfileFreshness) -> str | None:
    """The reason a build is due now because of the stored shape, or None.

    A build is due when the table holds host rows and none of them holds
    :data:`PROFILE_SHAPE`: no build of this release has run. The prior sweep
    loop calls this beside its age rule, and a reason here makes the build
    due whatever the age of the rows.

    One build of this release ends it. A host row that the build could not
    rewrite stays in ``outdated``, and the next build reads that host whatever
    its age. Due on every wake until each row was rewritten, a grid that
    refused one host would rebuild the estate every hour.
    """
    newest = state.newest_shape
    if newest is None or newest >= PROFILE_SHAPE:
        return None
    return (
        f"the stored profiles hold shape {newest}. This release reads shape "
        f"{PROFILE_SHAPE}. A profile build is due now."
    )
