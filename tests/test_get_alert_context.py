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


def _is_endpoint_coverage_query(body: dict[str, Any]) -> bool:
    """The endpoint-coverage check is the one fan-out carrying a ``host_docs``
    filter aggregation (grid-wide endpoint-doc count + this-host sub-count)."""
    return "host_docs" in (body.get("aggs") or {})


def _coverage_response(grid_total: int, host_docs: int) -> dict[str, Any]:
    """A scripted endpoint-coverage response: ``grid_total`` endpoint docs exist
    on the grid in-window, ``host_docs`` of them belong to the alert's hosts."""
    return {
        "took": 1,
        "hits": {"total": {"value": grid_total}, "hits": []},
        "aggregations": {"host_docs": {"doc_count": host_docs}},
    }


# Default coverage answer: the grid ships endpoint telemetry AND the alert's
# hosts are covered — the shape in which NO coverage gap is recorded, so tests
# written before the coverage check keep their prefetch_gaps expectations.
_COVERED = _coverage_response(1_800_000, 42)


def _make_elastic(
    settings: Settings,
    responses: list[dict[str, Any]],
    behavioral_response: dict[str, Any] | None = None,
    coverage_response: dict[str, Any] | Exception | None = None,
) -> tuple[ElasticClient, AsyncMock]:
    fake_es = AsyncMock()
    # The behavioral-summary pivot (beacon / DNS-tunnel) and the endpoint-
    # coverage check are ADDITIVE fan-outs that these tests don't script;
    # answer them from ``behavioral_response`` / ``coverage_response``
    # (defaults: empty / covered) WITHOUT consuming a positional response, so
    # each test's response list still maps 1:1 to the lookup + 5 tight pivots
    # + host-risk agg it was written for.
    _it = iter(responses)
    _behavioral = behavioral_response if behavioral_response is not None else _EMPTY_HITS
    _coverage = coverage_response if coverage_response is not None else _COVERED

    def _search(*args: Any, **kwargs: Any) -> dict[str, Any]:
        body = kwargs.get("body") or (args[1] if len(args) > 1 else {})
        if _is_endpoint_coverage_query(body):
            if isinstance(_coverage, Exception):
                raise _coverage
            return _coverage
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
    # 1 lookup + 5 pivots + host-risk agg + 1 behavioral-summary pivot
    # + 1 endpoint-coverage check.
    assert fake_es.search.call_count == 9


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
    # lookup + 4 pivots + host-risk agg + behavioral-summary pivot
    # + endpoint-coverage check.
    assert fake_es.search.call_count == 8


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
    """When every pivot completes, `prefetch_gaps` is empty.

    The sample alert carries every pivot field and a genuine endpoint
    host.name, so nothing is skipped and nothing failed. (The host pivot
    is the one pivot that DOES record a gap when it is skipped — see the
    host-pivot guard tests below; the other pivots still return []
    silently when their alert field is absent.)"""
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
    # 5 pivots + host-risk agg + behavioral-summary + endpoint-coverage check.
    assert len(pivot_calls) == 8
    for call in pivot_calls:
        body = call.kwargs["body"]
        must_not = body["query"]["bool"]["must_not"]
        # Every fan-out query — the 5 pivots, the host-risk agg, the
        # behavioral-summary pivot, AND the endpoint-coverage check —
        # excludes the alert's own document.
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
async def test_behavioral_summary_malformed_hit_does_not_poison_prefetch(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """A behavioral-summary doc with a schema-drifted field (a list where a
    scalar string is expected, plausible on a deployment's custom RITA/DNS-tunnel
    rollup) must NOT abort the whole prefetch. Per the pivot's best-effort
    contract it degrades to [] and the rest of the context survives (regression
    for F47 — the SoAlert.from_es_hit comprehension used to raise OUTSIDE the
    pivot's try/except and propagate through the un-guarded outer gather)."""
    malformed_doc = {
        "_id": "beacon-bad-1",
        "_source": {
            "event.dataset": "zeek.conn_summary",
            "source.ip": "10.0.0.115",
            # schema drift: user.name arrives as a list, not a scalar string,
            # so SoAlert.from_es_hit raises pydantic.ValidationError.
            "user.name": ["svc-a", "svc-b"],
        },
    }
    elastic, _ = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
        behavioral_response=_hits_response([malformed_doc]),
    )

    # Must not raise; the malformed behavioral doc is dropped, not fatal.
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)
    assert ctx.alert.id == "alert-001"
    assert all(e.id != "beacon-bad-1" for e in ctx.community_id_events)


@pytest.mark.asyncio
async def test_community_pivot_capped_at_max_after_behavioral_merge(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Prepending behavioral-summary docs must not push community_id_events past
    the documented ``max_per_pivot`` cap (F74). Behavioral docs (high-signal,
    rare) keep the front slots; the OLDEST community_id events are dropped to fit."""
    community_hits = [
        {
            "_id": f"event-c{i}",
            "_source": {
                "@timestamp": f"2026-05-07T10:30:{sec}Z",
                "network": {"community_id": "1:abc123def456=="},
            },
        }
        for i, sec in ((1, "10"), (2, "20"), (3, "30"))
    ]
    beacon_docs = [
        {
            "_id": f"beacon-{j}",
            "_source": {
                "event.dataset": "zeek.conn_summary",
                "source.ip": "10.0.0.115",
                "synth": {"beacon_profile": {"interval_similarity": 0.95}},
            },
        }
        for j in (1, 2)
    ]
    elastic, _ = _make_elastic(
        settings_kratos,
        [
            _alert_lookup_response(sample_alert),
            _hits_response(community_hits),  # community_id pivot: 3 hits
            *([_EMPTY_HITS] * 4),  # host, user, process, file
            _EMPTY_HITS,  # host-risk agg
        ],
        behavioral_response=_hits_response(beacon_docs),
    )

    ctx = await get_alert_context(
        "alert-001", elastic=elastic, settings=settings_kratos, max_per_pivot=3
    )

    ids = [e.id for e in ctx.community_id_events]
    assert len(ids) == 3  # capped at max_per_pivot, not 3 + 2
    assert ids[:2] == ["beacon-1", "beacon-2"]  # behavioral keep the front slots
    assert ids[2] == "event-c3"  # newest community event kept; c1/c2 (oldest) dropped


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
# Host-pivot guard: distrust host.name when it names the SENSOR
# =====================================================================
#
# The host pivot is a strict term query on top-level ``host.name``. On a
# grid where the shipper's ``host.name`` survives on network-sensor docs
# (stock Filebeat / Elastic Agent Suricata — NOT Security Onion, which
# strips it), that field names the sensor box, so the pivot would return
# "everything that sensor observed" for every network alert. The guard
# below skips the pivot in that shape AND records why, so an empty host
# pivot is distinguishable from a pivot that found nothing.


def _host_pivot_queries(fake_es: AsyncMock) -> list[dict[str, Any]]:
    """The captured fan-out queries whose term targets ``host.name``."""
    out: list[dict[str, Any]] = []
    for call in fake_es.search.call_args_list:
        body = call.kwargs.get("body") or {}
        must = (body.get("query", {}).get("bool", {}) or {}).get("must")
        if isinstance(must, list) and must and "host.name" in must[0].get("term", {}):
            out.append(body)
    return out


@pytest.mark.asyncio
async def test_host_pivot_skipped_when_host_name_is_observer_name(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """host.name == observer.name means the SENSOR, not an endpoint: skip + record."""
    alert_doc = copy.deepcopy(sample_alert)
    alert_doc["_source"]["host"]["name"] = "so-sensor-1"
    alert_doc["_source"]["observer"] = {"name": "so-sensor-1"}

    elastic, fake_es = _make_elastic(
        settings_kratos,
        # lookup + 4 remaining tight pivots + host-risk agg (behavioral pivot
        # is answered separately by the search wrapper).
        [_alert_lookup_response(alert_doc), *([_EMPTY_HITS] * 5)],
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert _host_pivot_queries(fake_es) == []  # no host.name term query issued
    assert ctx.host_events == []
    assert ctx.pivot_summary["host"] == 0
    assert ctx.prefetch_gaps.get("host.name") == "skipped_sensor_identity"


@pytest.mark.asyncio
async def test_host_pivot_skipped_when_host_name_is_agent_name(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Stock Filebeat stamps agent.name too — same sensor identity, same skip."""
    alert_doc = copy.deepcopy(sample_alert)
    alert_doc["_source"]["host"]["name"] = "sensor-fleet-3"
    alert_doc["_source"]["agent"] = {"name": "sensor-fleet-3"}

    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(alert_doc), *([_EMPTY_HITS] * 5)],
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert _host_pivot_queries(fake_es) == []
    assert ctx.prefetch_gaps.get("host.name") == "skipped_sensor_identity"


@pytest.mark.asyncio
async def test_host_pivot_skipped_on_network_sensor_dataset(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """On a suricata./zeek. dataset, host.name can only name the shipper.

    Even when it does not literally match observer/agent (an operator may
    override those), a network-sensor document's top-level host.name is the
    sensor box, never a flow endpoint — a host-name pivot there is
    meaningless at best and a cross-context fan-out at worst."""
    alert_doc = copy.deepcopy(sample_alert)
    alert_doc["_source"]["event"]["dataset"] = "suricata.alert"
    # host.name present, matches neither observer.name nor agent.name.
    alert_doc["_source"]["host"]["name"] = "sensor-rack-9"

    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(alert_doc), *([_EMPTY_HITS] * 5)],
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert _host_pivot_queries(fake_es) == []
    assert ctx.prefetch_gaps.get("host.name") == "skipped_network_sensor_dataset"


@pytest.mark.asyncio
async def test_genuine_endpoint_host_name_still_pivots(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """An endpoint-dataset alert whose host.name differs from the sensor pivots
    normally — the guard must not blind host pivots for host-shaped detections."""
    alert_doc = copy.deepcopy(sample_alert)
    alert_doc["_source"]["event"]["dataset"] = "endpoint"
    alert_doc["_source"]["observer"] = {"name": "so-sensor-1"}
    # host.name stays the genuine endpoint "workstation-01".

    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(alert_doc), *([_EMPTY_HITS] * 6)],
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    host_queries = _host_pivot_queries(fake_es)
    assert len(host_queries) == 1
    assert host_queries[0]["query"]["bool"]["must"][0] == {"term": {"host.name": "workstation-01"}}
    assert "host.name" not in ctx.prefetch_gaps


@pytest.mark.asyncio
async def test_absent_host_name_records_gap_not_silent_empty(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """No host.name on the alert: [] is fine, but the WHY must be recorded.

    Real SO network alerts never carry host.name, so before this gap entry an
    empty host pivot was indistinguishable from a pivot that ran and found
    nothing."""
    alert_doc = copy.deepcopy(sample_alert)
    del alert_doc["_source"]["host"]

    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(alert_doc), *([_EMPTY_HITS] * 5)],
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert _host_pivot_queries(fake_es) == []
    assert ctx.host_events == []
    assert ctx.prefetch_gaps.get("host.name") == "skipped_field_absent"


# =====================================================================
# Scenario-scoped synth visibility (cross-scenario isolation)
# =====================================================================
#
# `include_synth` accepts a scenario id: the fan-out then sees real docs
# plus THAT scenario's plants only. `True` (every synth doc visible) let
# each batch-eval run read its 24 sibling scenarios' plants — the
# cross-contamination that fed b3-rmm-admin-lateral ten unrelated triage
# alerts as "corroborating evidence".


def _clause_matches(clause: dict[str, Any], doc: dict[str, Any]) -> bool:
    """Minimal ES bool-query interpreter over flat-dotted docs.

    Just enough semantics (term / exists / ids / bool) to prove what the
    emitted must_not clauses ACCEPT and EXCLUDE, instead of only asserting
    their JSON shape. `.keyword` is treated as the exact-match view of its
    parent field, mirroring ES keyword-subfield semantics."""
    if "term" in clause:
        ((field, value),) = clause["term"].items()
        return doc.get(field.removesuffix(".keyword")) == value
    if "exists" in clause:
        return doc.get(clause["exists"]["field"]) is not None
    if "ids" in clause:
        return doc.get("_id") in clause["ids"]["values"]
    if "bool" in clause:
        b = clause["bool"]
        required = list(b.get("must", [])) + list(b.get("filter", []))
        if not all(_clause_matches(c, doc) for c in required):
            return False
        return not any(_clause_matches(c, doc) for c in b.get("must_not", []))
    raise AssertionError(f"unsupported clause in test interpreter: {clause}")


def _visible(doc: dict[str, Any], must_not: list[dict[str, Any]]) -> bool:
    return not any(_clause_matches(c, doc) for c in must_not)


def _fanout_must_nots(fake_es: AsyncMock) -> list[list[dict[str, Any]]]:
    """Every captured fan-out query's must_not (skips the id lookup)."""
    out: list[list[dict[str, Any]]] = []
    for call in fake_es.search.call_args_list:
        body = call.kwargs.get("body") or {}
        bool_q = body.get("query", {}).get("bool")
        if bool_q is not None:
            out.append(list(bool_q.get("must_not", [])))
    return out


@pytest.mark.asyncio
async def test_scenario_scope_excludes_siblings_keeps_own_and_real(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """With include_synth='scn-x', EVERY fan-out (5 tight pivots, IP-keyed
    host-risk agg, behavioral-summary pivot) admits real docs and scn-x's own
    plants while excluding sibling scenarios' plants. The IP-keyed fan-outs
    matter most: 10 of the catalogue's 25 scenarios share endpoint IPs, so an
    unscoped run pulls sibling evidence through them."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )
    await get_alert_context(
        "alert-001", elastic=elastic, settings=settings_kratos, include_synth="scn-x"
    )

    own_plant = {"synth.scenario_id": "scn-x"}
    sibling_plant = {"synth.scenario_id": "scn-y"}
    real_doc: dict[str, Any] = {}

    fanouts = _fanout_must_nots(fake_es)
    # 5 tight pivots + host-risk agg + behavioral pivot + endpoint-coverage check.
    assert len(fanouts) == 8
    for must_not in fanouts:
        assert _visible(own_plant, must_not), must_not
        assert _visible(real_doc, must_not), must_not
        assert not _visible(sibling_plant, must_not), must_not


@pytest.mark.asyncio
async def test_scenario_scope_does_not_weaken_prod_default(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """include_synth=False still excludes ALL synth docs — scoping must not
    have loosened the production kill-switch."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
    )
    await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    for must_not in _fanout_must_nots(fake_es):
        assert not _visible({"synth.scenario_id": "scn-x"}, must_not)
        assert _visible({}, must_not)


@pytest.mark.asyncio
async def test_scenario_scope_isolates_sibling_triage_alert_end_to_end(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """A fake ES that EVALUATES the emitted queries returns scenario X's own
    zeek doc and drops scenario Y's triage alert, even though both share the
    alert's community_id/user window — the b3 contamination shape, keyed off
    the pivots that still run after the host-pivot guard."""
    own_doc = {
        "_id": "x-zeek-1",
        "_source": {
            "@timestamp": "2026-05-07T10:30:10Z",
            "network": {"community_id": "1:abc123def456=="},
            "synth": {"scenario_id": "scn-x"},
        },
    }
    sibling_doc = {
        "_id": "y-triage-1",
        "_source": {
            "@timestamp": "2026-05-07T10:30:20Z",
            "network": {"community_id": "1:abc123def456=="},
            "rule": {"name": "sibling scenario alert"},
            "synth": {"scenario_id": "scn-y"},
        },
    }

    def _flat(hit: dict[str, Any]) -> dict[str, Any]:
        src = hit["_source"]
        flat: dict[str, Any] = {"_id": hit["_id"]}
        if "synth" in src:
            flat["synth.scenario_id"] = src["synth"]["scenario_id"]
        flat["network.community_id"] = src.get("network", {}).get("community_id")
        return flat

    fake_es = AsyncMock()

    def _search(*args: Any, **kwargs: Any) -> dict[str, Any]:
        body = kwargs.get("body") or (args[1] if len(args) > 1 else {})
        query = body.get("query", {})
        if "ids" in query:  # the alert lookup
            return _alert_lookup_response(sample_alert)
        bool_q = query.get("bool", {})
        must = bool_q.get("must") or []
        must_not = list(bool_q.get("must_not", []))
        # Serve only the community_id term pivot from the doc store; every
        # other fan-out answers empty.
        if not (must and "network.community_id" in must[0].get("term", {})):
            return _EMPTY_HITS
        hits = [h for h in (own_doc, sibling_doc) if _visible(_flat(h), must_not)]
        return _hits_response(hits)

    fake_es.search.side_effect = _search
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)

    ctx = await get_alert_context(
        "alert-001", elastic=elastic, settings=settings_kratos, include_synth="scn-x"
    )

    ids = {e.id for e in ctx.community_id_events}
    assert "x-zeek-1" in ids  # the run's OWN plant is still visible
    assert "y-triage-1" not in ids  # the sibling scenario's plant is not


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


# =====================================================================
# Endpoint coverage: "this host has no data" vs "this host has no coverage"
# =====================================================================
#
# The 2026-08-27 eval batch had 6 runs exhaust their 25-call budget probing
# `endpoint.events.*` for hosts that ship NO endpoint telemetry: the dataset
# inventory truthfully says endpoint data exists on the grid, so the model
# kept widening windows and re-spelling host fields, unable to distinguish
# "I haven't found it yet" from "it cannot exist". The prefetch now answers
# the coverage question ONCE, with one bounded size=0 lookup, and records the
# answer in prefetch_gaps — the same channel the host-pivot guard already
# uses for honest gaps. Three states, three renderings:
#
# - grid has endpoint docs, none from this alert's hosts →
#   ``endpoint.coverage: no_endpoint_documents_for_host`` (THE budget burner);
# - grid has no endpoint docs at all in-window →
#   ``endpoint.coverage: no_endpoint_dataset_on_grid``;
# - host covered → no entry: an empty endpoint query then means what it says.


@pytest.mark.asyncio
async def test_uncovered_host_records_endpoint_coverage_gap(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Endpoint datasets exist grid-wide but the alert's hosts have zero docs:
    the gap is recorded AND rides the model-visible serialization (the enriched
    JSON that trim_enriched_for_budget hands to every analyst-model call)."""
    from soc_ai.tools.get_alert_context import (
        ENDPOINT_COVERAGE_GAP_KEY,
        ENDPOINT_COVERAGE_HOST_UNCOVERED,
    )

    elastic, _ = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
        coverage_response=_coverage_response(1_800_000, 0),
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert ctx.prefetch_gaps.get(ENDPOINT_COVERAGE_GAP_KEY) == ENDPOINT_COVERAGE_HOST_UNCOVERED
    # Model-visible: the token is in the exact JSON string the orchestrator
    # embeds in the synth and investigator prompts.
    assert ENDPOINT_COVERAGE_HOST_UNCOVERED in ctx.model_dump_json()


@pytest.mark.asyncio
async def test_covered_host_records_no_endpoint_coverage_gap(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """A host WITH endpoint documents gets no coverage gap — an empty endpoint
    query for it keeps meaning 'this particular query matched nothing'."""
    from soc_ai.tools.get_alert_context import ENDPOINT_COVERAGE_GAP_KEY

    elastic, _ = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
        coverage_response=_coverage_response(1_800_000, 977),
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert ENDPOINT_COVERAGE_GAP_KEY not in ctx.prefetch_gaps


@pytest.mark.asyncio
async def test_grid_without_endpoint_dataset_records_distinct_gap(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """Zero endpoint docs anywhere on the grid in-window is a DIFFERENT claim
    from an uncovered host, and gets its own reason token."""
    from soc_ai.tools.get_alert_context import (
        ENDPOINT_COVERAGE_DATASET_ABSENT,
        ENDPOINT_COVERAGE_GAP_KEY,
        ENDPOINT_COVERAGE_HOST_UNCOVERED,
    )

    elastic, _ = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
        coverage_response=_coverage_response(0, 0),
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert ctx.prefetch_gaps.get(ENDPOINT_COVERAGE_GAP_KEY) == ENDPOINT_COVERAGE_DATASET_ABSENT
    assert ENDPOINT_COVERAGE_DATASET_ABSENT != ENDPOINT_COVERAGE_HOST_UNCOVERED


@pytest.mark.asyncio
async def test_endpoint_coverage_signal_identical_for_synth_and_real_host(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """No evaluation tell: a planted (scenario-scoped) uncovered host and a real
    uncovered host produce the IDENTICAL gap entry and IDENTICAL prompt block —
    the reason tokens and block text are constants, never derived from synth
    markers, scenario ids, index names, or grid counts."""
    from soc_ai.agent.prompts import format_endpoint_coverage_block
    from soc_ai.tools.get_alert_context import ENDPOINT_COVERAGE_GAP_KEY

    # Real uncovered host, production scope.
    elastic_real, _ = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
        coverage_response=_coverage_response(1_800_000, 0),
    )
    real_ctx = await get_alert_context("alert-001", elastic=elastic_real, settings=settings_kratos)

    # Planted uncovered host: the alert doc carries the synth marker and the
    # run is scenario-scoped, exactly as the batch eval drives it.
    planted = copy.deepcopy(sample_alert)
    planted["_source"]["synth"] = {"scenario_id": "scn-x"}
    elastic_synth, _ = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(planted), *([_EMPTY_HITS] * 6)],
        coverage_response=_coverage_response(1_800_000, 0),
    )
    synth_ctx = await get_alert_context(
        "alert-001", elastic=elastic_synth, settings=settings_kratos, include_synth="scn-x"
    )

    real_gap = real_ctx.prefetch_gaps[ENDPOINT_COVERAGE_GAP_KEY]
    synth_gap = synth_ctx.prefetch_gaps[ENDPOINT_COVERAGE_GAP_KEY]
    assert real_gap == synth_gap  # identical token, byte for byte

    real_block = format_endpoint_coverage_block(real_gap)
    synth_block = format_endpoint_coverage_block(synth_gap)
    assert real_block == synth_block
    assert real_block  # non-empty — the signal actually renders
    for tell in ("synth", "scenario", "scn-x", "logs-synth", "planted"):
        assert tell not in real_block.lower()


@pytest.mark.asyncio
async def test_endpoint_coverage_costs_exactly_one_bounded_query(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """The coverage determination is ONE size=0 aggregation query per prefetch
    (dispatched in the same parallel fan-out), never a per-tool-call or
    per-dataset fan-out — this fixes a budget problem without spending budget."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
        coverage_response=_coverage_response(1_800_000, 0),
    )
    await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    coverage_calls = [
        c for c in fake_es.search.call_args_list if _is_endpoint_coverage_query(c.kwargs["body"])
    ]
    assert len(coverage_calls) == 1
    body = coverage_calls[0].kwargs["body"]
    assert body["size"] == 0  # counts only — no documents fetched
    # Bounded in time (window centered on the alert) and in dataset scope.
    filters = body["query"]["bool"]["filter"]
    assert any("range" in f for f in filters)
    # Total prefetch fan-out: lookup + 5 pivots + host-risk + behavioral + coverage.
    assert fake_es.search.call_count == 9


@pytest.mark.asyncio
async def test_endpoint_coverage_check_fails_soft_leaves_coverage_unknown(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """A failed coverage read is UNKNOWN, not 'uncovered': no gap is recorded
    (a false no-coverage claim would wrongly stop legitimate probing), and the
    failure never poisons the rest of the prefetch."""
    from soc_ai.tools.get_alert_context import ENDPOINT_COVERAGE_GAP_KEY

    elastic, _ = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
        coverage_response=RuntimeError("simulated coverage-read failure"),
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert ctx.alert.id == "alert-001"
    assert ENDPOINT_COVERAGE_GAP_KEY not in ctx.prefetch_gaps


@pytest.mark.asyncio
async def test_endpoint_alert_short_circuits_coverage_query(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """An alert that IS an endpoint document proves its host's coverage by
    existing — no coverage query is spent and no gap is recorded."""
    from soc_ai.tools.get_alert_context import ENDPOINT_COVERAGE_GAP_KEY

    alert_doc = copy.deepcopy(sample_alert)
    alert_doc["_source"]["event"]["dataset"] = "endpoint.events.process"

    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(alert_doc), *([_EMPTY_HITS] * 6)],
        coverage_response=_coverage_response(1_800_000, 0),  # would claim uncovered
    )
    ctx = await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    assert ENDPOINT_COVERAGE_GAP_KEY not in ctx.prefetch_gaps
    assert not any(
        _is_endpoint_coverage_query(c.kwargs["body"]) for c in fake_es.search.call_args_list
    )


@pytest.mark.asyncio
async def test_endpoint_coverage_query_carries_synth_scope_and_host_identifiers(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """The coverage query obeys the same synth-visibility scope as every other
    fan-out (prod excludes all plants) and keys its host sub-count on every
    identifier the model would probe: host.ip, source.ip, destination.ip,
    host.name."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [_alert_lookup_response(sample_alert), *([_EMPTY_HITS] * 6)],
        coverage_response=_coverage_response(1_800_000, 0),
    )
    await get_alert_context("alert-001", elastic=elastic, settings=settings_kratos)

    body = next(
        c.kwargs["body"]
        for c in fake_es.search.call_args_list
        if _is_endpoint_coverage_query(c.kwargs["body"])
    )
    must_not = body["query"]["bool"]["must_not"]
    assert {"exists": {"field": "synth.scenario_id"}} in must_not
    assert {"ids": {"values": ["alert-001"]}} in must_not
    host_should = body["aggs"]["host_docs"]["filter"]["bool"]["should"]
    seen_fields = {next(iter(c[k])) for c in host_should for k in ("terms", "term") if k in c}
    assert seen_fields == {"host.ip", "source.ip", "destination.ip", "host.name"}


def test_format_endpoint_coverage_block_variants() -> None:
    """The prompt block renders each reason distinctly, and nothing at all for
    'covered' (None) or an unrecognized token (fail-soft forward compat)."""
    from soc_ai.agent.prompts import format_endpoint_coverage_block
    from soc_ai.tools.get_alert_context import (
        ENDPOINT_COVERAGE_DATASET_ABSENT,
        ENDPOINT_COVERAGE_HOST_UNCOVERED,
    )

    host_block = format_endpoint_coverage_block(ENDPOINT_COVERAGE_HOST_UNCOVERED)
    grid_block = format_endpoint_coverage_block(ENDPOINT_COVERAGE_DATASET_ABSENT)
    assert host_block and grid_block and host_block != grid_block
    assert format_endpoint_coverage_block(None) == ""
    assert format_endpoint_coverage_block("some_future_token") == ""


def test_materialized_evidence_cites_endpoint_coverage_gap() -> None:
    """The round-1 synthesizer (no tools) gets the coverage gap as a CITABLE
    negative finding, and the citation path actually resolves against the
    bundle — computed-but-never-displayed is the historic failure mode here."""
    from soc_ai.agent.evidence import _materialize_prefetch_evidence, _path_exists_in_alert
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import (
        ENDPOINT_COVERAGE_GAP_KEY,
        ENDPOINT_COVERAGE_HOST_UNCOVERED,
    )

    ctx = AlertContext(
        alert=SoAlert(id="alert-cov-1", rule_name="ET MALWARE Suspicious User-Agent"),
        prefetch_gaps={ENDPOINT_COVERAGE_GAP_KEY: ENDPOINT_COVERAGE_HOST_UNCOVERED},
    )
    bullets = _materialize_prefetch_evidence(ctx)
    coverage_bullets = [b for b in bullets if "(path prefetch_gaps.endpoint.coverage)" in b]
    assert len(coverage_bullets) == 1
    assert "coverage" in coverage_bullets[0].lower()
    assert _path_exists_in_alert(ctx, "prefetch_gaps.endpoint.coverage")

    # And a covered bundle materializes NO coverage bullet.
    clean = AlertContext(alert=SoAlert(id="alert-cov-2"))
    assert not any(
        "prefetch_gaps.endpoint.coverage" in b for b in _materialize_prefetch_evidence(clean)
    )


@pytest.mark.asyncio
async def test_investigator_loop_message_carries_coverage_block(
    settings_kratos: Settings,
) -> None:
    """Wiring proof: when the enriched context carries the coverage gap, the
    investigation-loop investigator's user message contains the plain-language
    coverage block — the signal reaches the model that was burning the budget,
    not just a struct nobody renders."""
    from unittest.mock import MagicMock

    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import investigate
    from soc_ai.agent.prompts import format_endpoint_coverage_block
    from soc_ai.agent.triage import TriageReport
    from soc_ai.tools.get_alert_context import (
        ENDPOINT_COVERAGE_GAP_KEY,
        ENDPOINT_COVERAGE_HOST_UNCOVERED,
    )

    from tests.test_agent import (
        _fake_loop_investigator_with_zeek_call,
        _make_ctx,
        _malware_signal_enriched,
    )

    settings_kratos.investigate_when_unsure = True
    ctx = _make_ctx(settings_kratos)

    fake_investigator = _fake_loop_investigator_with_zeek_call()
    settled_report = TriageReport(
        verdict="true_positive",
        confidence=0.9,
        summary="Confirmed beacon.",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[],
    )
    loop_synth_result = MagicMock()
    loop_synth_result.output = settled_report
    loop_synth_result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))
    fake_loop_synth = MagicMock()
    fake_loop_synth.run = AsyncMock(return_value=loop_synth_result)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        enriched = _malware_signal_enriched(alert_id)
        enriched.prefetch_gaps[ENDPOINT_COVERAGE_GAP_KEY] = ENDPOINT_COVERAGE_HOST_UNCOVERED
        return enriched

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=fake_loop_synth),
        patch("soc_ai.agent.orchestrator.inventory_prompt_block", AsyncMock(return_value="")),
    ):
        [ev async for ev in investigate("beacon-001", ctx=ctx)]

    fake_investigator.iter.assert_called_once()
    prompt = fake_investigator.iter.call_args[0][0]
    block = format_endpoint_coverage_block(ENDPOINT_COVERAGE_HOST_UNCOVERED)
    assert block  # the block renders...
    assert block in prompt  # ...and lands verbatim in the loop's user message
