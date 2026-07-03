"""Tests for the ``get_alert_context`` tool - the highest-value triage tool."""

from __future__ import annotations

import copy
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.errors import SoNotFoundError
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.get_alert_context import AlertContext, get_alert_context

# A pivot response: `total: 0`, no hits.
_EMPTY_HITS = {"took": 1, "hits": {"total": {"value": 0}, "hits": []}}


def _alert_lookup_response(alert_doc: dict[str, Any]) -> dict[str, Any]:
    return {"took": 1, "hits": {"total": {"value": 1}, "hits": [alert_doc]}}


def _hits_response(hits: list[dict[str, Any]]) -> dict[str, Any]:
    return {"took": 1, "hits": {"total": {"value": len(hits)}, "hits": hits}}


def _is_behavioral_summary_query(body: dict[str, Any]) -> bool:
    """The behavioral-summary pivot is the one whose ``must`` is a pair of nested
    ``bool``/``should`` clauses (IP match + profile-``exists``), not a single
    ``term`` (the 5 tight pivots) or a top-level ``should`` (the host-risk agg)."""
    must = (body.get("query", {}).get("bool", {}) or {}).get("must")
    return isinstance(must, list) and bool(must) and "term" not in must[0]


def _make_elastic(
    settings: Settings,
    responses: list[dict[str, Any]],
    behavioral_response: dict[str, Any] | None = None,
) -> tuple[ElasticClient, AsyncMock]:
    fake_es = AsyncMock()
    # The behavioral-summary pivot (beacon / DNS-tunnel) is an ADDITIVE fan-out
    # that these tests don't script; answer it from ``behavioral_response``
    # (default empty) WITHOUT consuming a positional response, so each test's
    # response list still maps 1:1 to the lookup + 5 tight pivots + host-risk agg
    # it was written for.
    _it = iter(responses)
    _behavioral = behavioral_response if behavioral_response is not None else _EMPTY_HITS

    def _search(*args: Any, **kwargs: Any) -> dict[str, Any]:
        body = kwargs.get("body") or (args[1] if len(args) > 1 else {})
        if _is_behavioral_summary_query(body):
            return _behavioral
        return next(_it)

    fake_es.search.side_effect = _search
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        return ElasticClient(settings), fake_es


# =====================================================================
# Happy path
# =====================================================================


@pytest.mark.asyncio
async def test_happy_path_all_pivots_empty(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Alert is found; all five pivots dispatch and return empty."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )

    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert isinstance(ctx, AlertContext)
    assert ctx.alert.id == "alert-001"
    assert ctx.alert.network_community_id == "1:abc123def456=="
    assert ctx.community_id_events == []
    assert ctx.host_events == []
    assert ctx.user_events == []
    assert ctx.process_events == []
    assert ctx.file_events == []
    assert ctx.pivot_summary == {
        "community_id": 0,
        "host": 0,
        "user": 0,
        "process": 0,
        "file": 0,
    }
    assert ctx.host_alert_profile == {}
    # 1 lookup + 5 pivots + host-risk agg + 1 behavioral-summary pivot.
    assert fake_es.search.call_count == 8


@pytest.mark.asyncio
async def test_pivots_exclude_synth_docs_by_default(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Prefetch pivots exclude synth.scenario_id docs unless opted in.

    The prefetch is the synth-first pipeline's primary evidence path; a real
    alert sharing a pivot value with a lingering synth fixture must not pull it
    in."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )
    await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    pivot_queries = [
        call.kwargs["body"]["query"]
        for call in fake_es.search.call_args_list
        if "bool" in call.kwargs["body"]["query"]
    ]
    assert pivot_queries, "expected at least one pivot query"
    for q in pivot_queries:
        assert {"exists": {"field": "synth.scenario_id"}} in q["bool"]["must_not"]


@pytest.mark.asyncio
async def test_pivots_include_synth_when_opted_in(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """The eval harness opts in so a synth alert's own supporting docs stay visible."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )
    await get_alert_context(
        "alert-001", elastic=elastic, settings=settings_kratos, include_synth=True
    )

    pivot_queries = [
        call.kwargs["body"]["query"]
        for call in fake_es.search.call_args_list
        if "bool" in call.kwargs["body"]["query"]
    ]
    assert pivot_queries, "expected at least one pivot query"
    for q in pivot_queries:
        assert {"exists": {"field": "synth.scenario_id"}} not in q["bool"]["must_not"]


@pytest.mark.asyncio
async def test_pivots_populate_results(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Pivot responses with hits propagate into the AlertContext."""
    related = {
        "_id": "event-related-1",
        "_source": {
            "@timestamp": "2026-05-07T10:30:30Z",
            "network": {"community_id": "1:abc123def456=="},
            "rule": {"name": "Related Zeek conn"},
        },
    }
    elastic, _ = _make_elastic(
        settings_kratos,
        [
            _alert_lookup_response(sample_alert),
            _hits_response([related]),  # community_id pivot
            _EMPTY_HITS,  # host
            _EMPTY_HITS,  # user
            _EMPTY_HITS,  # process
            _EMPTY_HITS,  # file
        ],
    )

    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert len(ctx.community_id_events) == 1
    assert ctx.community_id_events[0].id == "event-related-1"
    assert ctx.pivot_summary["community_id"] == 1


# =====================================================================
# Skipping pivots when source field is missing
# =====================================================================


@pytest.mark.asyncio
async def test_skips_pivot_when_field_absent(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Removing community_id from the alert means we skip that pivot entirely."""
    alert_doc = copy.deepcopy(sample_alert)
    del alert_doc["_source"]["network"]

    elastic, fake_es = _make_elastic(
        settings_kratos,
        [
            _alert_lookup_response(alert_doc),
            # 4 pivots fire (host, user, process, file). community_id_events is
            # short-circuited inside _pivot before any ES call. The host-risk
            # agg still fires (it keys on the endpoint IPs, not community_id).
            *([_EMPTY_HITS] * 5),
        ],
    )

    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert ctx.pivot_summary["community_id"] == 0
    # lookup + 4 pivots + host-risk agg + behavioral-summary pivot.
    assert fake_es.search.call_count == 7


@pytest.mark.asyncio
async def test_skips_all_pivots_when_no_timestamp(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """An alert without a timestamp can't anchor a window; every pivot is skipped."""
    alert_doc = copy.deepcopy(sample_alert)
    del alert_doc["_source"]["@timestamp"]

    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(alert_doc)],
    )

    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert ctx.pivot_summary == {
        "community_id": 0,
        "host": 0,
        "user": 0,
        "process": 0,
        "file": 0,
    }
    assert fake_es.search.call_count == 1  # only the lookup


# =====================================================================
# Error paths
# =====================================================================


@pytest.mark.asyncio
async def test_alert_not_found_raises(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_EMPTY_HITS])

    with pytest.raises(SoNotFoundError, match="alert not found"):
        await get_alert_context("nonexistent", elastic=elastic, settings=settings_kratos)

    assert fake_es.search.call_count == 1  # no pivots fired


@pytest.mark.asyncio
async def test_per_pivot_failure_does_not_poison_others(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """One pivot raising after retries should NOT abort the prefetch.

    The other pivots' results still land in the AlertContext, the
    failed pivot becomes an empty list, and `prefetch_gaps` records
    the field name + exception class so the agent (and the eval
    pipeline) can see what was lost. Prevents a single pivot's
    transient ConnectionTimeout from poisoning the entire bundle.
    """
    from elasticsearch import ConnectionTimeout

    fake_es = AsyncMock()

    # Scripted: alert lookup (1), then 5 pivots in indeterminate
    # order (but the search wrapper filters them by query content).
    # Easiest: side_effect by call order. The pivot order is:
    # community_id, host, user, process, file.
    fake_es.search.side_effect = [
        _alert_lookup_response(sample_alert),  # alert lookup OK
        ConnectionTimeout("simulated"),  # community_id pivot fails
        _EMPTY_HITS,  # host pivot OK
        _EMPTY_HITS,  # user pivot OK
        _EMPTY_HITS,  # process pivot OK
        _EMPTY_HITS,  # file pivot OK
        _EMPTY_HITS,  # host-risk agg OK
    ]
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)

    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    # The alert and 4 successful pivots survive.
    assert ctx.alert.id == "alert-001"
    assert ctx.host_events == []
    assert ctx.user_events == []
    assert ctx.process_events == []
    assert ctx.file_events == []
    # The failed pivot becomes an empty list AND surfaces in
    # prefetch_gaps with its field name + exception class.
    assert ctx.community_id_events == []
    assert ctx.prefetch_gaps == {"network.community_id": "ConnectionTimeout"}


@pytest.mark.asyncio
async def test_no_prefetch_gaps_on_clean_run(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """When every pivot completes (whether non-empty or empty-because-
    no-source-field), `prefetch_gaps` is empty. We don't conflate
    'pivot value absent on alert' (returns [] silently) with 'pivot
    failed on the wire' (returns [] AND records the gap)."""
    elastic, _ = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)
    assert ctx.prefetch_gaps == {}


@pytest.mark.asyncio
async def test_invalid_window_seconds_rejected(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [])
    with pytest.raises(ValueError, match="window_seconds"):
        await get_alert_context(
            "alert-001",
            elastic=elastic,
            settings=settings_kratos,
            window_seconds=0,
        )
    fake_es.search.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_max_per_pivot_rejected(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [])
    with pytest.raises(ValueError, match="max_per_pivot"):
        await get_alert_context(
            "alert-001",
            elastic=elastic,
            settings=settings_kratos,
            max_per_pivot=-5,
        )
    fake_es.search.assert_not_called()


# =====================================================================
# Pivot query construction
# =====================================================================


@pytest.mark.asyncio
async def test_pivots_exclude_alert_id(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Every pivot's must_not should exclude the alert's own document."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )

    await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    pivot_calls = fake_es.search.call_args_list[1:]  # skip the lookup
    assert len(pivot_calls) == 7  # 5 pivots + host-risk agg + behavioral-summary
    for call in pivot_calls:
        body = call.kwargs["body"]
        must_not = body["query"]["bool"]["must_not"]
        # Every fan-out query — the 5 pivots, the host-risk agg, AND the
        # behavioral-summary pivot — excludes the alert's own document.
        assert {"ids": {"values": ["alert-001"]}} in must_not


@pytest.mark.asyncio
async def test_pivot_window_centered_on_alert_timestamp(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Pivot range filter should bracket alert.timestamp ± window_seconds."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )

    await get_alert_context(
        "alert-001",
        elastic=elastic,
        settings=settings_kratos,
        window_seconds=300,
    )

    # Inspect the first pivot call (community_id)
    pivot_call = fake_es.search.call_args_list[1]
    body = pivot_call.kwargs["body"]
    range_filter = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    # alert ts is 2026-05-07T10:30:00.123000+00:00; ±300s = 5min
    assert range_filter["gte"].startswith("2026-05-07T10:25:00")
    assert range_filter["lte"].startswith("2026-05-07T10:35:00")


@pytest.mark.asyncio
async def test_pivots_use_correct_field_names(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Each pivot should target its own ECS field, not a different one."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )

    await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    expected_fields = [
        "network.community_id",
        "host.name",
        "user.name",
        "process.entity_id",
        "file.hash.sha256",
    ]
    pivot_calls = fake_es.search.call_args_list[1:]
    seen_fields: set[str] = set()
    for call in pivot_calls:
        body = call.kwargs["body"]
        must = body["query"]["bool"].get("must")
        # The host-risk agg is a should/terms query (no `must`); the behavioral-
        # summary pivot's `must` is a pair of nested bools (no single `term`).
        # Skip both — this test only covers the 5 single-field term pivots.
        if not must or "term" not in must[0]:
            continue
        seen_fields.update(must[0]["term"].keys())
    assert seen_fields == set(expected_fields)


@pytest.mark.asyncio
async def test_pivot_size_is_max_per_pivot(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )

    await get_alert_context(
        "alert-001",
        elastic=elastic,
        settings=settings_kratos,
        max_per_pivot=7,
    )

    for call in fake_es.search.call_args_list[1:]:
        # The host-risk agg uses size=0 (aggregation-only) — only the 5 row
        # pivots honor max_per_pivot.
        if call.kwargs["body"]["size"] == 0:
            continue
        assert call.kwargs["body"]["size"] == 7


@pytest.mark.asyncio
async def test_host_risk_profile_aggregates_endpoint_rules(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """The host-risk agg buckets rule.name over the endpoint IPs (wide window)
    and lands as ``host_alert_profile`` — the signal the tight pivots miss."""
    agg_resp = {
        "took": 1,
        "hits": {"total": {"value": 60}, "hits": []},
        "aggregations": {
            "rules": {
                "buckets": [
                    {"key": "ET REMOTE_ACCESS NetSupport Remote Admin Checkin", "doc_count": 60},
                    {"key": "ET INFO HTTP POST on unusual Port Possibly Hostile", "doc_count": 46},
                ]
            }
        },
    }
    # lookup, 5 empty pivots, then the host-risk agg (dispatched last).
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 5), agg_resp],
    )

    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert ctx.host_alert_profile == {
        "ET REMOTE_ACCESS NetSupport Remote Admin Checkin": 60,
        "ET INFO HTTP POST on unusual Port Possibly Hostile": 46,
    }
    # The agg query keys on BOTH endpoint IPs (should/terms), filters to
    # suricata alerts, excludes the focus alert + synth docs, and uses size=0.
    # Find it by its aggregation (robust to fan-out dispatch order).
    agg_call = next(c for c in fake_es.search.call_args_list if "aggs" in c.kwargs.get("body", {}))
    body = agg_call.kwargs["body"]
    assert body["size"] == 0
    assert "aggs" in body
    bool_q = body["query"]["bool"]
    assert bool_q["minimum_should_match"] == 1
    should_fields = {next(iter(s["terms"])) for s in bool_q["should"]}
    assert should_fields == {"source.ip", "destination.ip"}
    assert {"exists": {"field": "synth.scenario_id"}} in bool_q["must_not"]


@pytest.mark.asyncio
async def test_behavioral_summary_pivot_surfaces_beacon_into_pivots(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """A derived beacon-summary doc (keyed on source.ip only, so the 5 tight
    pivots miss it) is fetched by the behavioral-summary pivot and prepended into
    community_id_events with its profile extracted — the decisive-evidence
    surfacer downstream reads it from there."""
    beacon_doc = {
        "_id": "beacon-sum-1",
        "_source": {
            "event.dataset": "zeek.conn_summary",
            "source.ip": "10.0.0.115",
            "destination.ip": "104.18.42.69",
            "synth": {
                "beacon_profile": {
                    "connection_count": 240,
                    "mean_interval_seconds": 60.1,
                    "interval_similarity": 0.95,
                    "orig_bytes_cv": 0.04,
                    "resp_bytes_cv": 0.06,
                }
            },
        },
    }
    elastic, _fake = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
        behavioral_response=_hits_response([beacon_doc]),
    )

    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    ids = [e.id for e in ctx.community_id_events]
    assert "beacon-sum-1" in ids
    doc = next(e for e in ctx.community_id_events if e.id == "beacon-sum-1")
    assert doc.zeek_beacon_profile is not None
    assert doc.zeek_beacon_profile.get("interval_similarity") == 0.95


@pytest.mark.asyncio
async def test_host_risk_degrades_gracefully_on_agg_failure(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """A host-risk agg failure (e.g. field-mapping) must NOT poison the prefetch
    — host_alert_profile is {} and the rest of the context is intact."""
    elastic, _ = _make_elastic(
        settings_kratos,
        [
            _alert_lookup_response(sample_alert),
            *([_EMPTY_HITS] * 5),
            RuntimeError("fielddata disabled on [rule.name]"),
        ],
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)
    assert ctx.host_alert_profile == {}
    assert ctx.alert.id == "alert-001"


# =====================================================================
# EnrichedAlertContext / get_enriched_alert_context
# =====================================================================


@pytest.mark.asyncio
async def test_get_enriched_alert_context_returns_enriched_shape(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """get_enriched_alert_context wraps get_alert_context with typed Zeek + per-indicator
    enrichments."""
    from soc_ai.enrichment.blocklists import BlocklistDB
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools.enrichment import EnrichmentContext
    from soc_ai.tools.get_alert_context import (
        EnrichedAlertContext,
        get_enriched_alert_context,
    )

    elastic, _fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )
    enrichment = EnrichmentContext(
        blocklist=BlocklistDB(),
        maxmind=MaxmindReader(),
        cloud=CloudPrefixDB(),
    )
    ctx = await get_enriched_alert_context(
        "alert-001",
        elastic=elastic,
        settings=settings_kratos,
        enrichment=enrichment,
    )
    assert isinstance(ctx, EnrichedAlertContext)
    # Inherits AlertContext fields:
    assert ctx.alert.id == "alert-001"
    assert isinstance(ctx.community_id_events, list)
    # New fields are present + typed:
    assert ctx.typed_zeek is not None
    assert isinstance(ctx.enrichments, dict)
    # Empty enrichment context produced no findings (BlocklistDB has no entries):
    assert all(not e.blocklist_hits for e in ctx.enrichments.values())


@pytest.mark.asyncio
async def test_get_enriched_alert_context_enriches_external_indicators(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """When source/destination IPs differ, both get enriched in parallel."""
    from soc_ai.enrichment.blocklists import BlocklistDB
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools.enrichment import EnrichmentContext
    from soc_ai.tools.get_alert_context import get_enriched_alert_context

    elastic, _fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )
    ctx = await get_enriched_alert_context(
        "alert-001",
        elastic=elastic,
        settings=settings_kratos,
        enrichment=EnrichmentContext(
            blocklist=BlocklistDB(),
            maxmind=MaxmindReader(),
            cloud=CloudPrefixDB(),
        ),
    )
    # The sample alert has both source_ip and destination_ip — both should be enriched.
    src = ctx.alert.source_ip
    dst = ctx.alert.destination_ip
    if src:
        assert src in ctx.enrichments
    if dst:
        assert dst in ctx.enrichments


@pytest.mark.asyncio
async def test_get_enriched_alert_context_one_enrichment_failure_doesnt_kill_others(
    monkeypatch: pytest.MonkeyPatch,
    settings_kratos: Settings,
    sample_alert: dict[str, Any],
) -> None:
    """If one indicator's enrich_* raises, the other indicators still land in ctx.enrichments."""
    from soc_ai.enrichment.blocklists import BlocklistDB
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools import enrichment as enrichment_module
    from soc_ai.tools.enrichment import EnrichmentContext, IndicatorEnrichment
    from soc_ai.tools.get_alert_context import get_enriched_alert_context

    elastic, _fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )

    src = sample_alert["_source"]["source"]["ip"]
    dst = sample_alert["_source"]["destination"]["ip"]

    real_enrich_ip = enrichment_module.enrich_ip

    async def flaky_enrich_ip(ip: str, **kwargs: Any) -> IndicatorEnrichment:
        if ip == src:
            raise RuntimeError("simulated enrichment crash")
        return await real_enrich_ip(ip, **kwargs)

    monkeypatch.setattr(
        "soc_ai.tools.get_alert_context.enrich_ip",
        flaky_enrich_ip,
    )

    ctx = await get_enriched_alert_context(
        "alert-001",
        elastic=elastic,
        settings=settings_kratos,
        enrichment=EnrichmentContext(
            blocklist=BlocklistDB(),
            maxmind=MaxmindReader(),
            cloud=CloudPrefixDB(),
        ),
    )
    # The destination IP enrichment succeeded; the source IP one was raised + swallowed.
    assert dst in ctx.enrichments
    assert src not in ctx.enrichments
