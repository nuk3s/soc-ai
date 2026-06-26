"""Async Elasticsearch wrapper.

Thin façade over :class:`elasticsearch.AsyncElasticsearch` that:

- Wires basic auth + TLS verification from :class:`Settings`.
- Returns :class:`EsSearchResult` (a Pydantic model) from ``search`` so callers
  don't drift on the raw ``hits.total.value`` shape.
- Exposes ``aggs`` + ``track_total_hits`` parameters so OQL ``groupby`` /
  ``count`` pipe stages can reach ES aggregations.
- Maps a missing document to ``None`` instead of raising
  :class:`elasticsearch.NotFoundError`.
"""

from __future__ import annotations

from typing import Any

from elasticsearch import AsyncElasticsearch, NotFoundError
from pydantic import BaseModel, Field, computed_field

from soc_ai.config import Settings


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
        auth: tuple[str, str] | None = None
        if settings.es_username and settings.es_password:
            auth = (
                settings.es_username,
                settings.es_password.get_secret_value(),
            )
        self._client = AsyncElasticsearch(
            hosts=[str(h).rstrip("/") for h in settings.es_hosts],
            basic_auth=auth,
            verify_certs=settings.es_verify_ssl,
            request_timeout=settings.es_request_timeout_s,
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
        if sort is not None:
            body["sort"] = sort
        if source is not None:
            body["_source"] = source
        if aggs is not None:
            body["aggs"] = aggs
        if track_total_hits is not None:
            body["track_total_hits"] = track_total_hits

        response = await self._client.search(index=index, body=body)

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
