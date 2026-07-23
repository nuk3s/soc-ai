"""Tests for the ``prevalence`` local first-seen / novelty oracle.

Covers the three query modes (peer / domain / host), the rarity classification,
the empty-data clean return, the ES-error clean return (never raises), and the
ECS-first domain field projection.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.prevalence import prevalence


def _make_elastic(settings: Settings, response: dict[str, Any]) -> tuple[ElasticClient, AsyncMock]:
    """Build an ElasticClient backed by a mocked AsyncElasticsearch."""
    fake_es = AsyncMock()
    fake_es.search.return_value = response
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    return client, fake_es


def _agg_response(
    *,
    total: int,
    first_seen: str | None = None,
    last_seen: str | None = None,
    day_keys: list[str] | None = None,
    total_relation: str = "eq",
) -> dict[str, Any]:
    """Build a size=0 aggregation response in the shape ES returns."""
    buckets = [{"key_as_string": k, "key": i, "doc_count": 1} for i, k in enumerate(day_keys or [])]
    aggs: dict[str, Any] = {
        "first_seen": {"value": None, "value_as_string": first_seen}
        if first_seen
        else {"value": None},
        "last_seen": {"value": None, "value_as_string": last_seen}
        if last_seen
        else {"value": None},
        "by_day": {"buckets": buckets},
    }
    return {
        "took": 1,
        "hits": {"total": {"value": total, "relation": total_relation}, "hits": []},
        "aggregations": aggs,
    }


# =====================================================================
# Mode selection + query shape
# =====================================================================


@pytest.mark.asyncio
async def test_peer_mode_matches_both_directions(settings_kratos: Settings) -> None:
    """peer_ip mode ORs {src=ip,dst=peer} with the reverse pairing."""
    elastic, fake_es = _make_elastic(settings_kratos, _agg_response(total=0))
    out = await prevalence(
        "10.0.0.5",
        elastic=elastic,
        settings=settings_kratos,
        peer_ip="93.184.216.34",
    )
    body = fake_es.search.call_args.kwargs["body"]
    should = body["query"]["bool"]["must"][0]["bool"]["should"]
    # Two directional clauses.
    pairs = [{c["term"][k] for c in clause["bool"]["must"] for k in c["term"]} for clause in should]
    assert {"10.0.0.5", "93.184.216.34"} in pairs
    assert len([p for p in pairs if p == {"10.0.0.5", "93.184.216.34"}]) == 2
    assert out["evidence"]["mode"] == "peer"


@pytest.mark.asyncio
async def test_domain_mode_ecs_first_fields(settings_kratos: Settings) -> None:
    """domain mode ORs across ECS-first DNS/SNI/HTTP-Host candidate fields."""
    elastic, fake_es = _make_elastic(settings_kratos, _agg_response(total=0))
    out = await prevalence(
        "10.0.0.5",
        elastic=elastic,
        settings=settings_kratos,
        domain="evil.example.com",
    )
    body = fake_es.search.call_args.kwargs["body"]
    # The second must-clause is the domain OR.
    domain_should = body["query"]["bool"]["must"][0]["bool"]["must"][1]["bool"]["should"]
    matched_fields = {next(iter(c["term"])) for c in domain_should}
    # ECS-first names must be present...
    assert "dns.query.name" in matched_fields
    assert "ssl.server_name" in matched_fields
    assert "http.virtual_host" in matched_fields
    # ...and the legacy zeek fallbacks too.
    assert "zeek.dns.query" in matched_fields
    # Every clause matches the same domain value.
    assert all(next(iter(c["term"].values())) == "evil.example.com" for c in domain_should)
    assert out["evidence"]["mode"] == "domain"
    assert "dns.query.name" in out["evidence"]["domain_fields"]


@pytest.mark.asyncio
async def test_host_mode_when_neither_peer_nor_domain(settings_kratos: Settings) -> None:
    """No peer_ip / domain -> overall host summary mode (src OR dst)."""
    elastic, fake_es = _make_elastic(settings_kratos, _agg_response(total=0))
    out = await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    body = fake_es.search.call_args.kwargs["body"]
    should = body["query"]["bool"]["must"][0]["bool"]["should"]
    fields_matched = {next(iter(c["term"])) for c in should}
    assert fields_matched == {"source.ip", "destination.ip"}
    assert out["evidence"]["mode"] == "host"


@pytest.mark.asyncio
async def test_uses_configured_index_pattern(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, _agg_response(total=0))
    await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    assert fake_es.search.call_args.kwargs["index"] == settings_kratos.events_index_pattern


@pytest.mark.asyncio
async def test_query_is_size_zero_with_aggs(settings_kratos: Settings) -> None:
    """The prevalence query is aggregation-only (size=0) with first/last/by_day."""
    elastic, fake_es = _make_elastic(settings_kratos, _agg_response(total=0))
    await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    body = fake_es.search.call_args.kwargs["body"]
    assert body["size"] == 0
    assert body["track_total_hits"] is True
    aggs = body["aggs"]
    assert aggs["first_seen"]["min"]["field"] == "@timestamp"
    assert aggs["last_seen"]["max"]["field"] == "@timestamp"
    assert aggs["by_day"]["date_histogram"]["calendar_interval"] == "day"


# =====================================================================
# Time window
# =====================================================================


@pytest.mark.asyncio
async def test_lookback_default_now_relative(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, _agg_response(total=0))
    await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    body = fake_es.search.call_args.kwargs["body"]
    rng = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert rng["gte"] == "now-90d"
    assert rng["lte"] == "now"


@pytest.mark.asyncio
async def test_lookback_anchored_window(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, _agg_response(total=0))
    anchor = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    await prevalence(
        "10.0.0.5",
        elastic=elastic,
        settings=settings_kratos,
        lookback_days=30,
        time_anchor=anchor,
    )
    body = fake_es.search.call_args.kwargs["body"]
    rng = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert rng["gte"] == "2026-04-01T12:00:00+00:00"
    assert rng["lte"] == "2026-05-01T12:00:00+00:00"


# =====================================================================
# Result classification
# =====================================================================


@pytest.mark.asyncio
async def test_empty_data_returns_clean_first_seen(settings_kratos: Settings) -> None:
    """No matching events -> clean observed:False, never raises, never errors."""
    elastic, _ = _make_elastic(settings_kratos, _agg_response(total=0))
    out = await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos, peer_ip="1.2.3.4")
    assert out["observed"] is False
    assert out["total_events"] == 0
    assert out["distinct_days"] == 0
    assert out["rarity"] == "first-seen"
    assert out["first_seen"] is None
    assert out["last_seen"] is None
    assert "error" not in out


@pytest.mark.asyncio
async def test_single_day_is_novel(settings_kratos: Settings) -> None:
    """Seen on a single distinct day -> is_novel True, rarity 'first-seen'."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _agg_response(
            total=3,
            first_seen="2026-05-01T12:00:00.000Z",
            last_seen="2026-05-01T12:05:00.000Z",
            day_keys=["2026-05-01T00:00:00.000Z"],
        ),
    )
    out = await prevalence(
        "10.0.0.5", elastic=elastic, settings=settings_kratos, peer_ip="93.184.216.34"
    )
    assert out["observed"] is True
    assert out["total_events"] == 3
    assert out["distinct_days"] == 1
    assert out["is_novel"] is True
    assert out["rarity"] == "first-seen"
    assert out["first_seen"] == "2026-05-01T12:00:00.000Z"


@pytest.mark.asyncio
async def test_few_days_is_rare(settings_kratos: Settings) -> None:
    """Seen on a couple of distinct days -> rare, not novel."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _agg_response(
            total=8,
            first_seen="2026-04-28T00:00:00.000Z",
            last_seen="2026-05-01T00:00:00.000Z",
            day_keys=[
                "2026-04-28T00:00:00.000Z",
                "2026-04-30T00:00:00.000Z",
                "2026-05-01T00:00:00.000Z",
            ],
        ),
    )
    out = await prevalence(
        "10.0.0.5", elastic=elastic, settings=settings_kratos, domain="cdn.example.com"
    )
    assert out["observed"] is True
    assert out["distinct_days"] == 3
    assert out["is_novel"] is False
    assert out["rarity"] == "rare"


@pytest.mark.asyncio
async def test_heavy_volume_few_days_is_concentrated_not_rare(
    settings_kratos: Settings,
) -> None:
    """A heavy burst over only a few days is 'concentrated', never 'rare' — fixes
    the contradictory "rare — 2421 events across 3 days" wording."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _agg_response(
            total=2421,
            first_seen="2026-04-28T00:00:00.000Z",
            last_seen="2026-04-30T00:00:00.000Z",
            day_keys=[
                "2026-04-28T00:00:00.000Z",
                "2026-04-29T00:00:00.000Z",
                "2026-04-30T00:00:00.000Z",
            ],
        ),
    )
    out = await prevalence(
        "10.0.0.5", elastic=elastic, settings=settings_kratos, domain="cdn.example.com"
    )
    assert out["distinct_days"] == 3
    assert out["is_novel"] is False
    assert out["rarity"] == "concentrated"
    assert "rare" not in out["summary"]
    assert "concentrated" in out["summary"]


@pytest.mark.asyncio
async def test_heavy_single_day_is_concentrated_not_novel(settings_kratos: Settings) -> None:
    """A heavy SINGLE-day burst is not 'novel/no baseline' — it's a concentrated burst."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _agg_response(
            total=900,
            first_seen="2026-04-28T00:00:00.000Z",
            last_seen="2026-04-28T23:00:00.000Z",
            day_keys=["2026-04-28T00:00:00.000Z"],
        ),
    )
    out = await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    assert out["distinct_days"] == 1
    assert out["is_novel"] is False  # heavy volume overrides single-day novelty
    assert out["rarity"] == "concentrated"


@pytest.mark.asyncio
async def test_many_days_is_common(settings_kratos: Settings) -> None:
    """Seen across many distinct days -> established baseline, 'common'."""
    days = [f"2026-04-{d:02d}T00:00:00.000Z" for d in range(1, 21)]
    elastic, _ = _make_elastic(
        settings_kratos,
        _agg_response(
            total=500,
            first_seen="2026-04-01T00:00:00.000Z",
            last_seen="2026-04-20T00:00:00.000Z",
            day_keys=days,
        ),
    )
    out = await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    assert out["observed"] is True
    assert out["distinct_days"] == 20
    assert out["is_novel"] is False
    assert out["rarity"] == "common"
    assert out["total_events"] == 500


@pytest.mark.asyncio
async def test_lower_bound_total_rendered(settings_kratos: Settings) -> None:
    """When ES caps the count (relation gte), evidence flags it and summary uses ≥."""
    days = [f"2026-04-{d:02d}T00:00:00.000Z" for d in range(1, 11)]
    elastic, _ = _make_elastic(
        settings_kratos,
        _agg_response(
            total=10000,
            first_seen="2026-04-01T00:00:00.000Z",
            last_seen="2026-04-10T00:00:00.000Z",
            day_keys=days,
            total_relation="gte",
        ),
    )
    out = await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    assert out["evidence"]["total_is_lower_bound"] is True
    assert "≥10000" in out["summary"]


# =====================================================================
# Error / robustness — never raises
# =====================================================================


@pytest.mark.asyncio
async def test_es_error_returns_clean_error_dict(settings_kratos: Settings) -> None:
    """An ES transport/query error is caught and returned, never raised."""
    fake_es = AsyncMock()
    fake_es.search.side_effect = RuntimeError("connection refused")
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)

    out = await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    assert out["error"] is True
    assert "connection refused" in out["message"]


@pytest.mark.asyncio
async def test_non_positive_lookback_returns_error_not_raise(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, _agg_response(total=0))
    out = await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos, lookback_days=0)
    assert out["error"] is True
    assert "lookback_days" in out["message"]
    fake_es.search.assert_not_called()


@pytest.mark.asyncio
async def test_excessive_lookback_returns_error_not_raise(settings_kratos: Settings) -> None:
    """F53: an unbounded lookback_days must be rejected before the ES call —
    alert-embedded text is prompt-injection surface and could otherwise steer
    the agent into a full-history scan against the live SO cluster."""
    elastic, fake_es = _make_elastic(settings_kratos, _agg_response(total=0))
    out = await prevalence(
        "10.0.0.5", elastic=elastic, settings=settings_kratos, lookback_days=999_999_999
    )
    assert out["error"] is True
    assert "lookback_days" in out["message"]
    fake_es.search.assert_not_called()


@pytest.mark.asyncio
async def test_registered_as_read_only_tool() -> None:
    """The tool is registered in the global registry as read-only."""
    import soc_ai.tools  # noqa: F401  (force-import registers decorators)
    from soc_ai.tools._registry import get_tool

    spec = get_tool("prevalence")
    assert spec.read_only is True
    assert "prevalence" in spec.description.lower() or "first-seen" in spec.description.lower()


@pytest.mark.asyncio
async def test_min_max_numeric_value_fallback(settings_kratos: Settings) -> None:
    """When ES omits value_as_string, the numeric epoch value is stringified."""
    response = {
        "took": 1,
        "hits": {"total": {"value": 2}, "hits": []},
        "aggregations": {
            "first_seen": {"value": 1746100800000.0},
            "last_seen": {"value": 1746104400000.0},
            "by_day": {"buckets": [{"key": 0, "doc_count": 2}]},
        },
    }
    elastic, _ = _make_elastic(settings_kratos, response)
    out = await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    assert out["first_seen"] == "1746100800000.0"
    assert out["last_seen"] == "1746104400000.0"


@pytest.mark.asyncio
async def test_missing_aggregations_degrades_cleanly(settings_kratos: Settings) -> None:
    """A response with hits but no aggregations block must not raise."""
    response = {"took": 1, "hits": {"total": {"value": 5}, "hits": []}}
    elastic, _ = _make_elastic(settings_kratos, response)
    out = await prevalence("10.0.0.5", elastic=elastic, settings=settings_kratos)
    assert out["observed"] is True
    assert out["total_events"] == 5
    assert out["distinct_days"] == 0
    assert out["first_seen"] is None
    assert "error" not in out
