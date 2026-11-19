"""Async Elasticsearch wrapper.

Thin façade over :class:`elasticsearch.AsyncElasticsearch` that:

- Wires basic auth + TLS verification from :class:`Settings`.
- Returns :class:`EsSearchResult` (a Pydantic model) from ``search`` so callers
  don't drift on the raw ``hits.total.value`` shape.
- Exposes ``aggs`` + ``track_total_hits`` parameters so OQL ``groupby`` /
  ``count`` pipe stages can reach ES aggregations.
- Maps a missing document to ``None`` instead of raising
  :class:`elasticsearch.NotFoundError`.
- Refuses to hand back a PARTIAL search as if it were a complete one (see
  :class:`GridPartialResultsError`).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterable
from typing import Any

from elastic_transport import TransportError
from elasticsearch import AsyncElasticsearch, NotFoundError
from pydantic import BaseModel, Field, computed_field

from soc_ai.config import Settings
from soc_ai.demo.guard import assert_loopback_only
from soc_ai.run_meter import count_search

_LOGGER = logging.getLogger(__name__)

# Elasticsearch's default ``search.max_buckets``. Read from the cluster when
# the ES user may; assumed otherwise.
DEFAULT_MAX_BUCKETS = 65536

# The field types of the grid change only when a new index maps a field, so a
# read holds for ten minutes. A read that failed is not asked again for a
# minute: each query would otherwise wait on it before its own search.
_FIELD_TYPES_TTL_S = 600.0
_FIELD_TYPES_RETRY_S = 60.0
# A field-caps read is a metadata read of a few ms on a healthy grid. The bound
# keeps a slow grid from holding the search behind it.
_FIELD_TYPES_TIMEOUT_S = 5.0
# The OQL whitelist admits field prefixes, so the cache has a bound.
_FIELD_TYPES_MAX_ENTRIES = 2048
# Field-caps entries of a parent object. They hold no value, so they are no type.
_NON_VALUE_TYPES = frozenset({"object", "nested"})


class GridPartialResultsError(TransportError):
    """Elasticsearch answered 200, but the search did not read the whole grid.

    ES defaults ``allow_partial_search_results=true``: when shards are failed or
    unassigned (a dead data node, an index still recovering after a restart) or
    the search timed out, it returns HTTP 200 carrying PARTIAL — frequently
    zero — hits and no error at all. Taken at face value that renders as "no
    detections match this view", "all quiet", "no corroborating traffic": an
    outage silently rewritten as a fact about the network, which is the one
    answer a SOC console must never invent.

    Subclassing :class:`elastic_transport.TransportError` is deliberate. Every
    ``except (TimeoutError, TransportError)`` arm in the API already maps it to
    the house 503 ``grid_unavailable``, and the agent's tool boundary already
    renders it as a structured error the model can read — so a partial read
    tells the same story as a refused connection, everywhere, with no edits.

    We detect this locally rather than passing ``allow_partial_search_results=
    False`` to ES: that makes ES answer with a search-phase error whose status
    maps to a 400 "bad query", telling the analyst their query is broken when
    their grid is.
    """

    def __init__(
        self,
        message: str,
        *,
        shards_failed: int = 0,
        shards_total: int = 0,
        timed_out: bool = False,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.shards_failed = shards_failed
        self.shards_total = shards_total
        self.timed_out = timed_out
        self.reason = reason


# The shard-failure types that the QUERY causes: a value of the wrong type for
# the field (a prefix query on an ``ip`` field, ``"TXT"`` on a ``long``), a time
# in a form the date field does not parse, a sort on a field that one index
# does not map, an aggregation on a ``match_only_text`` field. Elasticsearch
# answers 200 with ``_shards.failed > 0`` for each of them: the shards that map
# the field fail and the others answer. On production every one of 32
# ``grid_unavailable`` tool results in 30 days was one of these, on a grid that
# was up (2026-11-19). The one list; ``_query_failure`` reads it.
QUERY_FAILURE_TYPES: frozenset[str] = frozenset(
    {
        "query_shard_exception",
        "parse_exception",
        "parsing_exception",
        "illegal_argument_exception",
        "number_format_exception",
        "date_time_parse_exception",
        "x_content_parse_exception",
    }
)

# A failure that only carries the failure of another node or cluster: the type
# of the cause is the type of the failure.
_WRAPPER_FAILURE_TYPES: frozenset[str] = frozenset({"remote_transport_exception"})

# How deep a ``caused_by`` chain is read before it counts as unknown.
_MAX_CAUSE_DEPTH = 8


class GridQueryRejectedError(GridPartialResultsError):
    """The grid answered, and it rejected the query on the shards that map the field.

    Every listed shard failure is of a type that a query causes
    (:data:`QUERY_FAILURE_TYPES`), no shard timed out, and the failure list is
    not empty. The grid is up: the same query fails the same way on every
    retry, and only a corrected query reads those shards.

    A subclass of :class:`GridPartialResultsError` on purpose. Every existing
    ``except`` arm, the doctor and the audit chain treat it as today: an
    incomplete read, never an empty one. The callers that can tell the author
    of the query what to correct (the tool boundary of the model, the routes
    that run an analyst's query) catch this class first.

    The ``es_fail_on_partial_results=false`` opt-out does not apply. The shards
    that did not answer are the shards that hold the field, so the hits of the
    other shards answer a different question.
    """

    def __init__(
        self,
        message: str,
        *,
        shards_failed: int,
        shards_total: int,
        reason: str,
    ) -> None:
        super().__init__(
            message,
            shards_failed=shards_failed,
            shards_total=shards_total,
            timed_out=False,
            reason=reason,
        )
        self.reason: str = reason


def _as_int(value: Any) -> int:
    """Coerce a shard counter, defaulting to 0 — absent metadata is not failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _first_failure_reason(shards: dict[str, Any]) -> str | None:
    """The first ``_shards.failures[].reason`` rendered as ``type: reason``."""
    failures = shards.get("failures")
    if not isinstance(failures, list) or not failures:
        return None
    first = failures[0]
    if not isinstance(first, dict):
        return str(first)
    reason = first.get("reason")
    if isinstance(reason, dict):
        return _render_failure(reason)
    if reason:
        return str(reason)
    return None


def _render_failure(node: dict[str, Any]) -> str | None:
    """One failure object as ``type: reason``."""
    kind = str(node.get("type") or "").strip()
    detail = str(node.get("reason") or "").strip()
    rendered = ": ".join(part for part in (kind, detail) if part)
    return rendered or None


def _query_failure(failure: Any) -> dict[str, Any] | None:
    """The failure object of a shard failure that the query caused, or ``None``.

    A wrapper (:data:`_WRAPPER_FAILURE_TYPES`) is read through its
    ``caused_by``. Any other type that is not a query type, a chain deeper than
    :data:`_MAX_CAUSE_DEPTH`, and a failure with no failure object are not query
    failures: the read stays an incomplete read of the grid.
    """
    if not isinstance(failure, dict):
        return None
    node = failure.get("reason")
    for _ in range(_MAX_CAUSE_DEPTH):
        if not isinstance(node, dict):
            return None
        kind = str(node.get("type") or "").strip()
        if kind in QUERY_FAILURE_TYPES:
            return node
        if kind not in _WRAPPER_FAILURE_TYPES:
            return None
        node = node.get("caused_by")
    return None


def _rejected_query_reason(shards: dict[str, Any]) -> str | None:
    """``type: reason`` of the first failure when the query caused every listed failure.

    ``None`` when the list is absent or empty, or when one failure is of any
    other type: a query failure beside a node failure is still a grid that did
    not answer.
    """
    failures = shards.get("failures")
    if not isinstance(failures, list) or not failures:
        return None
    causes = [_query_failure(failure) for failure in failures]
    first = causes[0]
    if first is None or any(cause is None for cause in causes):
        return None
    return _render_failure(first) or str(first.get("type"))


class EsSearchResult(BaseModel):
    """Wrapped Elasticsearch search response."""

    total: int
    took_ms: int
    hits: list[dict[str, Any]] = Field(default_factory=list)
    aggregations: dict[str, Any] | None = None
    total_is_lower_bound: bool = False
    """True when ES returned ``relation: "gte"`` — the count is a lower bound
    (capped at 10 000 by default).  Render as ``≥N``, not ``N``."""

    counted: dict[str, Any] | None = None
    """What ``total`` and any bucket ``doc_count`` actually counted.

    A number handed to a reader with no unit gets the reader's unit. A triage
    run read ``total: 358`` off a port-22 query as "358 SSH connections" and
    closed a honeypot alert on it; 348 of the 358 were periodic packetbeat flow
    records re-emitted per interval, and the documents naming the decoy carried
    19 distinct source ports. Populated by tools that query the events index
    superset, where one query spans every sensor shipping to it. ``None`` when
    the caller did not ask for it.
    """

    window: dict[str, Any] | None = None
    """The span ``total`` and every bucket ``doc_count`` were counted over.

    Same reasoning as ``counted``, applied to time instead of unit. An
    alert-anchored query defaults to a window CENTRED on the alert, so a
    1440-minute request reaches back only 720 minutes; a published rationale
    reported 12 events "grid-wide over 24 hours" where the grid held 20, and
    the half-window reproduces 12 exactly. The descriptor names the mode, the
    two bounds, and how far the window reaches either side of the anchor, so a
    number is never handed over without the span it came from. ``None`` when
    the caller did not ask for it.
    """

    field_note: str | None = None
    """Why a zero-hit result is not evidence of absence, or ``None``.

    Set when the query filters or groups on a field that no document in the
    same dataset and window holds. Ten scheduled hunts filtered on a field
    name that the grid does not store, and six reports stated the zero as "no
    successful SSH login". ``None`` on a result with hits, and on a zero-hit
    result whose fields are all present: that zero is a zero on the value.
    """

    rewrites: list[str] | None = None
    """Each exact rewrite of the query before the search, or ``None``.

    ``destination.ip:10.* became destination.ip:"10.0.0.0/8". An IP field
    takes a CIDR.`` On production the model wrote ``10.*`` on an ``ip`` field
    and a time with a space on ``@timestamp``, and the grid rejected each one
    (:mod:`soc_ai.so_client.query_forms`). The note shows the model the form
    that the grid takes.
    """

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_display(self) -> str:
        """Human-readable total: ``≥N`` when the count is a lower bound, else ``N``.

        Included in ``model_dump`` so the LLM agent sees the formatted string
        rather than having to interpret the raw ``total_is_lower_bound`` bool.
        """
        prefix = "≥" if self.total_is_lower_bound else ""
        return f"{prefix}{self.total}"


class ElasticClient:
    """Async client for the Security Onion Elasticsearch cluster."""

    def __init__(self, settings: Settings) -> None:
        # Held (not copied) so a hot config change — e.g. the partial-results
        # opt-out — applies to the next search without a restart.
        self._settings = settings
        # (index pattern, field) -> (value types, monotonic expiry). See field_types.
        self._field_types: dict[tuple[str, str], tuple[frozenset[str], float]] = {}
        # index pattern -> monotonic time before which a failed read is not retried.
        self._field_types_failed: dict[str, float] = {}
        # Demo mode: only the bundled loopback mock ES may be reached.
        for host in settings.es_hosts:
            assert_loopback_only(settings, str(host), "elasticsearch")
        auth: tuple[str, str] | None = None
        if settings.es_username and settings.es_password:
            auth = (
                settings.es_username,
                settings.es_password.get_secret_value(),
            )
        # elasticsearch-py's `ca_certs` param is `DefaultType | str` (no `None`
        # option) -- only pass it when a bundle is actually pinned.
        ca_kwargs: dict[str, Any] = {}
        if settings.es_ca_bundle:
            ca_kwargs["ca_certs"] = str(settings.es_ca_bundle)

        self._client = AsyncElasticsearch(
            hosts=[str(h).rstrip("/") for h in settings.es_hosts],
            basic_auth=auth,
            verify_certs=settings.es_verify_ssl,
            request_timeout=settings.es_request_timeout_s,
            **ca_kwargs,
            # Transport-layer resilience for the contended SO ES on the
            # lab grid. Under batch concurrency=5, prefetch fans out
            # 25-ish simultaneous searches; the cluster sometimes
            # returns ConnectionTimeout. Built-in retry handles those
            # transparently — lower-friction than wrapping every call
            # site by hand. ``retry_on_status`` covers the 5xx bucket
            # ES returns when its search queue is briefly saturated.
            max_retries=settings.es_max_retries,
            retry_on_timeout=True,
            retry_on_status=(429, 502, 503, 504),
        )

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        from_: int = 0,
        sort: list[dict[str, Any]] | None = None,
        source: list[str] | bool | None = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
        require_complete: bool = False,
    ) -> EsSearchResult:
        """Run a search against ``index`` with a DSL ``query``.

        ``query`` is the inner ``{"query": ...}`` value (i.e. callers pass
        ``{"bool": {...}}`` directly, not the wrapping ``query`` key).

        ``require_complete=True`` makes a partial/timed-out read raise
        :class:`GridPartialResultsError` even under the grid-wide
        ``es_fail_on_partial_results=False`` opt-out. For callers whose answer
        is a safety judgement about ABSENCE (the synth containment check): a
        degraded search returning 0 hits from the surviving shards is "could
        not see", never "clean", and an operator's tolerance for partial
        ordinary reads must not soften that.
        """
        body: dict[str, Any] = {"query": query, "size": size}
        if from_:
            body["from"] = from_
        if sort is not None:
            body["sort"] = sort
        if source is not None:
            body["_source"] = source
        if aggs is not None:
            body["aggs"] = aggs
        if track_total_hits is not None:
            body["track_total_hits"] = track_total_hits

        # The run that issued this read pays for it (no-op outside a recorded run).
        count_search()
        # Be tolerant of index patterns that only partly resolve: a single-node
        # grid has no remote clusters (so the `*:logs-*` half of a both-shapes
        # pattern matches nothing) and a fresh grid may lack an index entirely.
        # Without these, such a pattern 500s instead of returning empty results.
        response = await self._client.search(
            index=index,
            body=body,
            ignore_unavailable=True,
            allow_no_indices=True,
        )

        self._check_complete(index, response, require_complete=require_complete)

        hits_data: dict[str, Any] = response.get("hits", {})
        total_raw = hits_data.get("total", 0)
        if isinstance(total_raw, dict):
            total_value = total_raw.get("value", 0)
            total_is_lower_bound = total_raw.get("relation", "eq") == "gte"
        else:
            total_value = int(total_raw)
            total_is_lower_bound = False

        aggregations_raw = response.get("aggregations")
        return EsSearchResult(
            total=total_value,
            took_ms=int(response.get("took", 0)),
            hits=list(hits_data.get("hits", [])),
            aggregations=dict(aggregations_raw) if aggregations_raw else None,
            total_is_lower_bound=total_is_lower_bound,
        )

    def _check_complete(self, index: str, response: Any, *, require_complete: bool = False) -> None:
        """Raise :class:`GridPartialResultsError` unless the search read everything.

        Parsing defaults to ZERO failures: a response with no ``_shards`` key
        (test stubs, demo replay fixtures) is treated exactly as it was before.
        Absent metadata must never be made to look like failure. Skipped shards
        are not failures either — ``can_match`` and frozen tiers skip shards on
        a perfectly healthy grid.

        ``require_complete=True`` disables the ``es_fail_on_partial_results``
        opt-out for this one response (see :meth:`search`).

        A failed read whose every listed failure the query caused raises
        :class:`GridQueryRejectedError`, under the opt-out too.
        """
        shards_raw = response.get("_shards")
        shards: dict[str, Any] = shards_raw if isinstance(shards_raw, dict) else {}
        shards_failed = _as_int(shards.get("failed"))
        shards_total = _as_int(shards.get("total"))
        timed_out = bool(response.get("timed_out") or False)
        if not shards_failed and not timed_out:
            return

        rejected = _rejected_query_reason(shards) if shards_failed and not timed_out else None
        reason = rejected or _first_failure_reason(shards)
        parts: list[str] = []
        if shards_failed:
            parts.append(f"{shards_failed} of {shards_total} shards failed")
        if timed_out:
            parts.append("the search timed out before all shards answered")
        detail = f" ({reason})" if reason else ""
        message = (
            f"partial search results from {index}: {' and '.join(parts)}{detail}. "
            "The returned hits are incomplete. An empty or short answer here means "
            "unknown."
        )

        if rejected is not None:
            # Never the opt-out: the shards that did not answer are the ones
            # that map the field, so the hits of the rest are no partial answer.
            raise GridQueryRejectedError(
                message,
                shards_failed=shards_failed,
                shards_total=shards_total,
                reason=rejected,
            )

        if not require_complete and not self._settings.es_fail_on_partial_results:
            # Knowingly opted in to partial reads (e.g. a chronically red shard).
            _LOGGER.warning("%s; returning them anyway (es_fail_on_partial_results=false)", message)
            return

        raise GridPartialResultsError(
            message,
            shards_failed=shards_failed,
            shards_total=shards_total,
            timed_out=timed_out,
            reason=reason,
        )

    async def field_types(
        self, index: str, fields: Iterable[str]
    ) -> dict[str, frozenset[str]] | None:
        """The value types of each field over ``index``, from ``_field_caps``.

        A field that no index of the pattern maps has an empty set. A field
        with one type in each index that maps it has one type; a field that two
        indices map differently has two. ``object`` and ``nested`` entries are
        parent objects and are not types. ``None`` when the grid does not
        answer, refuses the read, or answers in a shape this code does not
        know: the caller then sends its query as written.

        Each answer is cached in the process for ten minutes, keyed on the
        pattern and the field. The read itself is one request for the fields
        that the cache does not hold.
        """
        wanted = sorted({name for name in fields if name})
        now = time.monotonic()
        found: dict[str, frozenset[str]] = {}
        missing: list[str] = []
        for name in wanted:
            cached = self._field_types.get((index, name))
            if cached is not None and cached[1] > now:
                found[name] = cached[0]
            else:
                missing.append(name)
        if not missing:
            return found
        if self._field_types_failed.get(index, 0.0) > now:
            return None
        count_search()
        try:
            async with asyncio.timeout(_FIELD_TYPES_TIMEOUT_S):
                # ``fields`` goes as a list: the client sent a comma string as
                # one name, and the grid answered an empty ``fields`` object.
                response = await self._client.field_caps(
                    index=index,
                    fields=missing,
                    ignore_unavailable=True,
                    allow_no_indices=True,
                )
        except Exception as exc:
            _LOGGER.info("field-caps read of %s failed (queries go as written): %r", index, exc)
            self._field_types_failed[index] = now + _FIELD_TYPES_RETRY_S
            return None
        body = getattr(response, "body", response)
        caps = body.get("fields") if isinstance(body, dict) else None
        if not isinstance(caps, dict):
            self._field_types_failed[index] = now + _FIELD_TYPES_RETRY_S
            return None
        if len(self._field_types) + len(missing) > _FIELD_TYPES_MAX_ENTRIES:
            self._field_types = {k: v for k, v in self._field_types.items() if v[1] > now}
            if len(self._field_types) + len(missing) > _FIELD_TYPES_MAX_ENTRIES:
                self._field_types.clear()
        expires = now + _FIELD_TYPES_TTL_S
        for name in missing:
            entry = caps.get(name)
            types = (
                frozenset(str(t) for t in entry if str(t) not in _NON_VALUE_TYPES)
                if isinstance(entry, dict)
                else frozenset()
            )
            self._field_types[(index, name)] = (types, expires)
            found[name] = types
        return found

    async def ping(self) -> dict[str, Any]:
        """Return ``{"cluster": ..., "version": ...}`` from the ES ``info`` call.

        Raises on transport/auth failure so a caller (e.g. a UI connectivity
        probe) can render the error. Returns only the cluster name and version
        number — never any credential material.
        """
        info = await self._client.info()
        version = info.get("version", {}) or {}
        return {
            "cluster": info.get("cluster_name", ""),
            "version": version.get("number", ""),
        }

    async def max_buckets(self) -> int:
        """The cluster's ``search.max_buckets``, or the ES default when refused.

        A nested aggregation that creates more buckets than this answers 400
        ``too_many_buckets_exception``, not a partial result. The profile lane
        sizes its partitions from it. The grid's ES user may lack
        ``cluster:monitor/settings``; that is a debug line, not a failure,
        because the lane's retry ladder covers a wrong assumption.
        """
        try:
            raw = await self._client.cluster.get_settings(include_defaults=True, flat_settings=True)
        except Exception as exc:
            _LOGGER.debug(
                "cluster settings read refused (%s); assuming search.max_buckets=%d",
                exc,
                DEFAULT_MAX_BUCKETS,
            )
            return DEFAULT_MAX_BUCKETS
        for section in ("transient", "persistent", "defaults"):
            value = (raw.get(section) or {}).get("search.max_buckets")
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                return DEFAULT_MAX_BUCKETS
        return DEFAULT_MAX_BUCKETS

    async def get(self, index: str, doc_id: str) -> dict[str, Any] | None:
        """Fetch a single document by id. Returns ``None`` on 404."""
        count_search()
        try:
            response = await self._client.get(index=index, id=doc_id)
        except NotFoundError:
            return None
        return dict(response)

    async def aclose(self) -> None:
        """Release the underlying transport."""
        await self._client.close()
