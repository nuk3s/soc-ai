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

import logging
from typing import Any

from elastic_transport import TransportError
from elasticsearch import AsyncElasticsearch, NotFoundError
from pydantic import BaseModel, Field, computed_field

from soc_ai.config import Settings
from soc_ai.demo.guard import assert_loopback_only

_LOGGER = logging.getLogger(__name__)


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
        kind = str(reason.get("type") or "").strip()
        detail = str(reason.get("reason") or "").strip()
        rendered = ": ".join(part for part in (kind, detail) if part)
        return rendered or None
    if reason:
        return str(reason)
    return None


class EsSearchResult(BaseModel):
    """Wrapped Elasticsearch search response."""

    total: int
    took_ms: int
    hits: list[dict[str, Any]] = Field(default_factory=list)
    aggregations: dict[str, Any] | None = None
    total_is_lower_bound: bool = False
    """True when ES returned ``relation: "gte"`` — the count is a lower bound
    (capped at 10 000 by default).  Render as ``≥N``, not ``N``."""

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
    ) -> EsSearchResult:
        """Run a search against ``index`` with a DSL ``query``.

        ``query`` is the inner ``{"query": ...}`` value (i.e. callers pass
        ``{"bool": {...}}`` directly, not the wrapping ``query`` key).
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

        self._check_complete(index, response)

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

    def _check_complete(self, index: str, response: Any) -> None:
        """Raise :class:`GridPartialResultsError` unless the search read everything.

        Parsing defaults to ZERO failures: a response with no ``_shards`` key
        (test stubs, demo replay fixtures) is treated exactly as it was before.
        Absent metadata must never be made to look like failure. Skipped shards
        are not failures either — ``can_match`` and frozen tiers skip shards on
        a perfectly healthy grid.
        """
        shards_raw = response.get("_shards")
        shards: dict[str, Any] = shards_raw if isinstance(shards_raw, dict) else {}
        shards_failed = _as_int(shards.get("failed"))
        shards_total = _as_int(shards.get("total"))
        timed_out = bool(response.get("timed_out") or False)
        if not shards_failed and not timed_out:
            return

        reason = _first_failure_reason(shards)
        parts: list[str] = []
        if shards_failed:
            parts.append(f"{shards_failed} of {shards_total} shards failed")
        if timed_out:
            parts.append("the search timed out before all shards answered")
        detail = f" ({reason})" if reason else ""
        message = (
            f"partial search results from {index}: {' and '.join(parts)}{detail} — "
            f"the returned hits are incomplete, so an empty or short answer here "
            f"means 'unknown', not 'nothing happened'"
        )

        if not self._settings.es_fail_on_partial_results:
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

    async def get(self, index: str, doc_id: str) -> dict[str, Any] | None:
        """Fetch a single document by id. Returns ``None`` on 404."""
        try:
            response = await self._client.get(index=index, id=doc_id)
        except NotFoundError:
            return None
        return dict(response)

    async def aclose(self) -> None:
        """Release the underlying transport."""
        await self._client.close()
