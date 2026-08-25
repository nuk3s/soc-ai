"""Tests for ``soc_ai.tools.analytics``.

Covers the shared ``_shannon_entropy_chars`` stat, ``beacon_profile``
(inter-arrival CV sweep over ``zeek.conn``, Task 1), ``dns_entropy_scan``
(qname-entropy sweep over ``zeek.dns``, Task 2), ``dcerpc_histogram``
(operation histogram over ``zeek.dce_rpc``, Task 3), and ``first_seen``
(novel-external-destination sweep vs a trailing baseline, Task 4). Uses the
typed ``EsSearchResult`` mock convention (``_make_elastic`` / ``_result``
copied from ``tests/test_host_summary.py``) so the aggregation payload is
shaped exactly as Elasticsearch returns a nested terms → terms → top_hits
response.
"""

from __future__ import annotations

import base64
import hashlib
import random
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client import fields as so_fields
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.tools.analytics import (
    _MAX_BASELINE_DAYS,
    _MAX_DNS_SAMPLE_IDS,
    _NON_GLOBAL_CIDRS,
    _accumulate_qname_bucket,
    _cap_by_count_ascending,
    _internal_dest_exclusion,
    _sample_ids,
    _shannon_entropy_chars,
    _window_error,
    beacon_profile,
    dcerpc_histogram,
    dns_entropy_scan,
    first_seen,
)
from soc_ai.tools.query_events import _MAX_TIME_RANGE_MINUTES


def _make_elastic(
    settings: Settings, result: EsSearchResult | Exception
) -> tuple[ElasticClient, AsyncMock]:
    """Build an ElasticClient whose ``.search`` is mocked at the wrapper level.

    Patching ``ElasticClient.search`` (rather than the raw AsyncElasticsearch)
    lets the test hand back a typed ``EsSearchResult`` directly, or raise to
    exercise the error path.
    """
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    if isinstance(result, Exception):
        client.search = AsyncMock(side_effect=result)  # type: ignore[method-assign]
    else:
        client.search = AsyncMock(return_value=result)  # type: ignore[method-assign]
    return client, fake_es


def _result(
    hits: list[dict[str, Any]],
    *,
    total: int | None = None,
    aggregations: dict[str, Any] | None = None,
) -> EsSearchResult:
    return EsSearchResult(
        total=total if total is not None else len(hits),
        took_ms=3,
        hits=[{"_id": f"e{i}", "_source": src} for i, src in enumerate(hits)],
        aggregations=aggregations,
    )


def _make_elastic_sequence(
    settings: Settings, results: list[EsSearchResult | Exception]
) -> tuple[ElasticClient, AsyncMock]:
    """Like ``_make_elastic`` but drives ``.search`` through a SEQUENCE.

    ``first_seen`` issues two queries (recent, then baseline) per call; tests
    that need a different payload per call (or a raise on only the second)
    use this instead of the single-result ``_make_elastic``.
    """
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    client.search = AsyncMock(side_effect=results)  # type: ignore[method-assign]
    return client, fake_es


# ---------------------------------------------------------------------------
# Fixture builders — hand-shape the nested pairs -> dsts -> ts top_hits agg
# response exactly as Elasticsearch would return it.
# ---------------------------------------------------------------------------

_BASE_TS = datetime(2026, 8, 23, 0, 0, 0, tzinfo=UTC)


def _iso_series(step_s: list[float], *, start: datetime = _BASE_TS) -> list[str]:
    """Build a series of ISO timestamps from a list of inter-event gaps.

    ``len(step_s) + 1`` timestamps are produced (the gaps sit BETWEEN them).
    """
    out = [start]
    cur = start
    for gap in step_s:
        cur = cur + timedelta(seconds=gap)
        out.append(cur)
    return [t.isoformat().replace("+00:00", "Z") for t in out]


def _dst_bucket(
    dst: str,
    timestamps_iso: list[str],
    *,
    id_prefix: str,
    bytes_avg: float | None = 512.0,
) -> dict[str, Any]:
    return {
        "key": dst,
        "doc_count": len(timestamps_iso),
        "ts": {
            "hits": {
                "total": {"value": len(timestamps_iso), "relation": "eq"},
                "hits": [
                    {"_id": f"{id_prefix}{i}", "_source": {"@timestamp": ts}}
                    for i, ts in enumerate(timestamps_iso)
                ],
            }
        },
        "bytes_out_avg": {"value": bytes_avg},
    }


def _pairs_agg(
    pairs: dict[str, list[dict[str, Any]]], *, sum_other_doc_count: int = 0
) -> dict[str, Any]:
    """``pairs``: ``{src_ip: [dst_bucket, ...]}`` -> full nested agg response."""
    return {
        "pairs": {
            "sum_other_doc_count": sum_other_doc_count,
            "buckets": [
                {
                    "key": src,
                    "doc_count": sum(b["doc_count"] for b in dst_buckets),
                    "dsts": {"buckets": dst_buckets},
                }
                for src, dst_buckets in pairs.items()
            ],
        }
    }


# ---------------------------------------------------------------------------
# _shannon_entropy_chars
# ---------------------------------------------------------------------------


def test_entropy_empty_string_is_zero() -> None:
    assert _shannon_entropy_chars("") == 0.0


def test_entropy_single_repeated_char_is_zero() -> None:
    assert _shannon_entropy_chars("aaaa") == 0.0


def test_entropy_four_distinct_chars_is_two_bits() -> None:
    assert _shannon_entropy_chars("abcd") == pytest.approx(2.0)


def test_entropy_high_entropy_string_exceeds_threshold() -> None:
    # 26 distinct characters, each appearing once -> entropy == log2(26) ~ 4.7 bits/char.
    assert _shannon_entropy_chars("aB3xQ9zP1kLmN7vRtYcWdEfGhJ") > 3.5


# ---------------------------------------------------------------------------
# _window_error / _sample_ids — shared helpers used by all four tools
# ---------------------------------------------------------------------------


def test_window_error_none_when_in_bounds() -> None:
    assert _window_error("window_minutes", 1440, _MAX_TIME_RANGE_MINUTES) is None


def test_window_error_non_positive() -> None:
    err = _window_error("window_minutes", 0, _MAX_TIME_RANGE_MINUTES)
    assert err == {"error": True, "message": "window_minutes must be positive, got 0"}
    assert "type" not in err


def test_window_error_over_ceiling() -> None:
    err = _window_error("baseline_days", 400, _MAX_BASELINE_DAYS)
    assert err == {
        "error": True,
        "message": f"baseline_days must be <= {_MAX_BASELINE_DAYS}, got 400",
    }
    assert "type" not in err


def test_sample_ids_dedups_preserving_order_and_caps() -> None:
    hits = [{"_id": "a"}, {"_id": "b"}, {"_id": "a"}, {"_id": "c"}, {"_id": "d"}]
    assert _sample_ids(hits, 3) == ["a", "b", "c"]


def test_sample_ids_skips_missing_id() -> None:
    hits = [{"_id": "a"}, {"no_id": True}, {"_id": None}, {"_id": "b"}]
    assert _sample_ids(hits, 5) == ["a", "b"]


def test_sample_ids_empty_hits_returns_empty_list() -> None:
    assert _sample_ids([], 5) == []


# ---------------------------------------------------------------------------
# beacon_profile
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_beacon_profile_periodic_pair_lands_in_items(settings_kratos: Settings) -> None:
    # 20 timestamps at exact 60s spacing -> cv ~ 0.
    ts = _iso_series([60.0] * 19)
    dst_bucket = _dst_bucket("8.8.8.8", ts, id_prefix="p")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["pairs_scanned"] == 1
    assert out["internal_excluded"] == 0
    assert len(out["items"]) == 1
    item = out["items"][0]
    assert item["src"] == "10.0.0.5"
    assert item["dst"] == "8.8.8.8"
    assert item["cv"] < 0.05
    assert item["mean_interval_s"] == pytest.approx(60.0, abs=0.5)
    assert item["verdict_hint"] == "periodic"
    assert set(item["sample_ids"]).issubset({f"p{i}" for i in range(20)})
    assert item["sample_ids"], "sample_ids must be non-empty so findings are citable"


@pytest.mark.asyncio
async def test_beacon_profile_bursty_pair_excluded_but_scanned(settings_kratos: Settings) -> None:
    # Alternating short/long gaps -> high cv, excluded from items.
    ts = _iso_series([1.0, 300.0, 2.0, 600.0, 1.0, 300.0, 2.0, 600.0, 1.0])
    dst_bucket = _dst_bucket("8.8.4.4", ts, id_prefix="b")
    aggs = _pairs_agg({"10.0.0.6": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=10, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["pairs_scanned"] == 1
    assert out["items"] == []


@pytest.mark.asyncio
async def test_beacon_profile_internal_dst_excluded_by_default(settings_kratos: Settings) -> None:
    ts = _iso_series([60.0] * 19)
    dst_bucket = _dst_bucket("10.0.0.9", ts, id_prefix="i")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out["pairs_scanned"] == 1
    assert out["internal_excluded"] == 1
    assert out["items"] == []


@pytest.mark.asyncio
async def test_beacon_profile_internal_dst_included_when_flagged(settings_kratos: Settings) -> None:
    ts = _iso_series([60.0] * 19)
    dst_bucket = _dst_bucket("10.0.0.9", ts, id_prefix="i")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos, include_internal=True)

    assert out["pairs_scanned"] == 1
    assert out["internal_excluded"] == 0
    assert len(out["items"]) == 1
    assert out["items"][0]["dst"] == "10.0.0.9"


@pytest.mark.asyncio
async def test_beacon_profile_min_events_respected(settings_kratos: Settings) -> None:
    # Only 7 timestamps (periodic spacing) with default min_events=8 -> excluded.
    ts = _iso_series([60.0] * 6)
    assert len(ts) == 7
    dst_bucket = _dst_bucket("8.8.8.8", ts, id_prefix="m")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=7, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out["pairs_scanned"] == 1
    assert out["items"] == []


@pytest.mark.asyncio
async def test_beacon_profile_window_over_ceiling_errors_without_query(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    out = await beacon_profile(
        elastic=elastic, settings=settings_kratos, window_minutes=_MAX_TIME_RANGE_MINUTES + 1
    )

    assert out["error"] is True
    elastic.search.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_beacon_profile_es_error_returns_structured_error(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, RuntimeError("grid partial results"))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out["error"] is True
    assert out["type"] == "RuntimeError"
    assert "grid partial results" in out["message"]


@pytest.mark.asyncio
async def test_beacon_profile_query_body_shape(settings_kratos: Settings) -> None:
    ts = _iso_series([60.0] * 19)
    dst_bucket = _dst_bucket("8.8.8.8", ts, id_prefix="p")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    await beacon_profile(elastic=elastic, settings=settings_kratos, window_minutes=720)

    # resolve_agg_field probes elastic.search once before the main aggregation
    # query; call_args is the LAST call, i.e. the actual beacon_profile query.
    call = elastic.search.call_args  # type: ignore[attr-defined]
    args, kwargs = call
    query = args[1]
    filters = query["bool"]["filter"]
    assert {"term": {"event.dataset": "zeek.conn"}} in filters
    must_not = query["bool"]["must_not"]
    assert {"exists": {"field": "synth.scenario_id"}} in must_not
    # Default include_internal=False pushes the internal-destination
    # exclusion into the query itself (CIDR terms on the ip field), so
    # internal chatter never occupies the capped agg slots.
    cidr_clauses = [c for c in must_not if "terms" in c and "destination.ip" in c["terms"]]
    assert len(cidr_clauses) == 1
    excluded = cidr_clauses[0]["terms"]["destination.ip"]
    assert "10.0.0.0/8" in excluded
    assert "100.64.0.0/10" in excluded
    assert "fe80::/10" in excluded
    # Trailing, now-relative range (no time_anchor support for this tool).
    range_filters = [f for f in filters if "range" in f]
    assert len(range_filters) == 1
    rng = range_filters[0]["range"]["@timestamp"]
    assert rng["gte"] == "now-720m"
    assert rng["lte"] == "now"

    aggs_body = kwargs["aggs"]
    bytes_field = aggs_body["pairs"]["aggs"]["dsts"]["aggs"]["bytes_out_avg"]["avg"]["field"]
    assert bytes_field in so_fields.CONN_ORIG_BYTES


@pytest.mark.asyncio
async def test_beacon_profile_include_internal_true_skips_server_side_exclusion(
    settings_kratos: Settings,
) -> None:
    ts = _iso_series([60.0] * 19)
    dst_bucket = _dst_bucket("10.0.0.9", ts, id_prefix="i")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    await beacon_profile(elastic=elastic, settings=settings_kratos, include_internal=True)

    call = elastic.search.call_args  # type: ignore[attr-defined]
    must_not = call.args[1]["bool"]["must_not"]
    assert must_not == [{"exists": {"field": "synth.scenario_id"}}]


def test_internal_dest_exclusion_merges_settings_cidrs_deduped(
    settings_kratos: Settings,
) -> None:
    # The default settings internal_cidrs (10/8, 172.16/12, 192.168/16)
    # duplicate the fixed non-global list — the clause must not repeat them.
    clause = _internal_dest_exclusion(settings_kratos)
    cidrs = clause["terms"]["destination.ip"]
    assert len(cidrs) == len(set(cidrs)), "CIDR list must be deduplicated"
    for expected in _NON_GLOBAL_CIDRS:
        assert expected in cidrs

    # An operator-configured internal-but-globally-routable range rides along.
    custom = settings_kratos.model_copy(
        update={"internal_cidrs": [*settings_kratos.internal_cidrs, IPv4Network("198.51.100.0/24")]}
    )
    cidrs_custom = _internal_dest_exclusion(custom)["terms"]["destination.ip"]
    assert "198.51.100.0/24" in cidrs_custom


@pytest.mark.asyncio
async def test_beacon_profile_identical_timestamps_burst_not_ranked_periodic(
    settings_kratos: Settings,
) -> None:
    # 20 connections all stamped the SAME instant: every gap is 0, mean 0,
    # and _compute_inter_arrival's cv fallback is 0.0 — without the
    # degenerate-cadence guard this burst would rank as the STRONGEST
    # periodic beacon on the grid. Zero cadence is not a cadence.
    same = _BASE_TS.isoformat().replace("+00:00", "Z")
    dst_bucket = _dst_bucket("8.8.8.8", [same] * 20, id_prefix="z")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["pairs_scanned"] == 1
    assert out["items"] == [], "an identically-timestamped burst must never register as periodic"


@pytest.mark.asyncio
async def test_beacon_profile_src_dst_narrowing(settings_kratos: Settings) -> None:
    ts = _iso_series([60.0] * 19)
    dst_bucket = _dst_bucket("8.8.8.8", ts, id_prefix="p")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    await beacon_profile(elastic=elastic, settings=settings_kratos, src="10.0.0.5", dst="8.8.8.8")

    call = elastic.search.call_args  # type: ignore[attr-defined]
    filters = call.args[1]["bool"]["filter"]
    assert {"term": {"source.ip": "10.0.0.5"}} in filters
    assert {"term": {"destination.ip": "8.8.8.8"}} in filters


@pytest.mark.asyncio
async def test_beacon_profile_shuffled_timestamps_still_computes_correct_cv(
    settings_kratos: Settings,
) -> None:
    # ES's top_hits sort clause is a request, not a guarantee this tool
    # enforces client-side — hand the fixture's timestamps back OUT OF ORDER
    # to prove the tool still computes the correct mean/cv, rather than
    # silently producing negative gaps that would cv=0-fallback-mislabel the
    # pair "periodic" with a garbage (negative) mean_interval_s.
    ts = _iso_series([60.0] * 19)
    shuffled = ts.copy()
    random.Random(7).shuffle(shuffled)
    dst_bucket = _dst_bucket("8.8.8.8", shuffled, id_prefix="s")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert len(out["items"]) == 1
    item = out["items"][0]
    assert item["cv"] < 0.05
    assert item["mean_interval_s"] == pytest.approx(60.0, abs=0.5)
    assert item["verdict_hint"] == "periodic"


@pytest.mark.asyncio
async def test_beacon_profile_bursty_reversed_timestamps_not_mislabeled_periodic(
    settings_kratos: Settings,
) -> None:
    # The specific bug this sort guards against: handing back a bursty pair's
    # hits in REVERSED (strictly descending) order makes every raw
    # consecutive gap negative, so the un-sorted mean is <= 0. Without the
    # defensive sort, `_compute_inter_arrival`'s `mean <= 0 -> cv = 0.0`
    # fallback would silently register this bursty pair as "periodic" — the
    # exact false negative the sort exists to prevent. With the sort, the
    # timestamps recover their true ascending (bursty) order and the pair is
    # correctly excluded, same as the in-order bursty fixture above.
    ts = _iso_series([1.0, 300.0, 2.0, 600.0, 1.0, 300.0, 2.0, 600.0, 1.0])
    reversed_ts = list(reversed(ts))
    dst_bucket = _dst_bucket("8.8.4.4", reversed_ts, id_prefix="r")
    aggs = _pairs_agg({"10.0.0.6": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=10, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["pairs_scanned"] == 1
    assert out["items"] == [], "a bursty pair must never register as periodic"


@pytest.mark.asyncio
async def test_beacon_profile_truncated_when_pairs_agg_drops_sources(
    settings_kratos: Settings,
) -> None:
    ts = _iso_series([60.0] * 19)
    dst_bucket = _dst_bucket("8.8.8.8", ts, id_prefix="p")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]}, sum_other_doc_count=37)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out["truncated"] is True


@pytest.mark.asyncio
async def test_beacon_profile_not_truncated_when_pairs_agg_complete(
    settings_kratos: Settings,
) -> None:
    ts = _iso_series([60.0] * 19)
    dst_bucket = _dst_bucket("8.8.8.8", ts, id_prefix="p")
    aggs = _pairs_agg({"10.0.0.5": [dst_bucket]})
    elastic, _ = _make_elastic(settings_kratos, _result([], total=20, aggregations=aggs))

    out = await beacon_profile(elastic=elastic, settings=settings_kratos)

    assert out["truncated"] is False


# ---------------------------------------------------------------------------
# dns_entropy_scan — fixture builders
# ---------------------------------------------------------------------------


def _qname_bucket(
    qname: str, doc_count: int, *, id_prefix: str, name_field: str = "dns.query.name"
) -> dict[str, Any]:
    n_hits = min(doc_count, 2)
    return {
        "key": qname,
        "doc_count": doc_count,
        "sample": {
            "hits": {
                "total": {"value": doc_count, "relation": "eq" if doc_count <= 2 else "gte"},
                "hits": [
                    {"_id": f"{id_prefix}{i}", "_source": {name_field: qname}}
                    for i in range(n_hits)
                ],
            }
        },
    }


def _qnames_agg(buckets: list[dict[str, Any]], *, sum_other_doc_count: int = 0) -> dict[str, Any]:
    return {
        "qnames": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": sum_other_doc_count,
            "buckets": buckets,
        }
    }


def _dga_labels(n: int, *, length: int = 20) -> list[str]:
    """Deterministic pseudo-random-looking DNS labels (high per-char entropy).

    Base32-encodes a SHA-256 hash of each index so the fixture is stable
    across runs without relying on ``random`` — the mean entropy across a
    batch of these comfortably clears the 3.5 bits/char DGA-candidacy bar
    (verified empirically: ~3.8 mean over 30 labels of length 20).
    """
    labels = []
    for i in range(n):
        raw = hashlib.sha256(f"dga-label-{i}".encode()).digest()
        while len(raw) < length * 2:
            raw += hashlib.sha256(raw).digest()
        labels.append(base64.b32encode(raw).decode().rstrip("=").lower()[:length])
    return labels


# A single label with every character distinct -> entropy = log2(36) ~ 5.17
# bits/char, comfortably over the 4.2 "extreme" bar regardless of volume.
_EXTREME_LABEL = "q9w8e7r6t5y4u3i2o1p0asdfghjklzxcvbnm"


# ---------------------------------------------------------------------------
# dns_entropy_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dns_entropy_scan_dga_shaped_parent_is_candidate(settings_kratos: Settings) -> None:
    labels = _dga_labels(30)
    buckets = [
        _qname_bucket(f"{label}.badc2.net", 20, id_prefix=f"d{i}") for i, label in enumerate(labels)
    ]
    aggs = _qnames_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=600, aggregations=aggs))

    out = await dns_entropy_scan(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["truncated"] is False
    parents = {item["parent"]: item for item in out["items"]}
    assert "badc2.net" in parents
    item = parents["badc2.net"]
    assert item["entropy_mean"] >= 3.5
    assert item["queries"] == 600
    assert item["subdomain_queries"] == 600  # every query here carries a subdomain
    assert item["unique_subdomains"] == 30
    assert item["sample_ids"], "sample_ids must be non-empty so findings are citable"
    assert len(item["example_qnames"]) <= 3


@pytest.mark.asyncio
async def test_dns_entropy_scan_benign_cdn_parent_not_a_candidate(
    settings_kratos: Settings,
) -> None:
    buckets = [
        _qname_bucket("www.cdncorp.com", 1000, id_prefix="w"),
        _qname_bucket("cdn.cdncorp.com", 1000, id_prefix="c"),
        _qname_bucket("img.cdncorp.com", 1000, id_prefix="i"),
    ]
    aggs = _qnames_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=3000, aggregations=aggs))

    out = await dns_entropy_scan(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    parents = {item["parent"] for item in out["items"]}
    assert "cdncorp.com" not in parents
    assert out["parents_scanned"] == 1  # scanned (cleared the volume floor) but not a candidate


@pytest.mark.asyncio
async def test_dns_entropy_scan_extreme_entropy_low_volume_is_candidate(
    settings_kratos: Settings,
) -> None:
    buckets = [_qname_bucket(f"{_EXTREME_LABEL}.raretunnel.io", 60, id_prefix="x")]
    aggs = _qnames_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=60, aggregations=aggs))

    out = await dns_entropy_scan(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    parents = {item["parent"]: item for item in out["items"]}
    assert "raretunnel.io" in parents
    item = parents["raretunnel.io"]
    assert item["entropy_mean"] >= 4.2
    assert item["queries"] == 60  # well under the 500-query volume bar


# Labels with exactly 12 distinct characters each appearing once ->
# entropy = log2(12) ~ 3.585 bits/char per label: over the 3.5 candidacy bar
# but safely under the 4.2 "extreme regardless of volume" bar.
_MID_ENTROPY_LABELS = ["abcdefghijkl", "mnopqrstuvwx", "yz0123456789"]


@pytest.mark.asyncio
async def test_dns_entropy_scan_apex_volume_does_not_satisfy_tunnel_volume_gate(
    settings_kratos: Settings,
) -> None:
    # A busy apex (600 direct lookups of badc2.net, no subdomain) plus a
    # HANDFUL of high-entropy subdomain queries (3 x 10 = 30). The entropy
    # signal comes only from subdomain labels, so the volume arm must gate on
    # subdomain-bearing volume (30 < 500) — counting the apex volume (total
    # 630 >= 500) would promote every busy domain with a few odd subdomains
    # to a tunnel candidate.
    buckets = [_qname_bucket("badc2.net", 600, id_prefix="a")]
    buckets += [
        _qname_bucket(f"{label}.badc2.net", 10, id_prefix=f"s{i}")
        for i, label in enumerate(_MID_ENTROPY_LABELS)
    ]
    aggs = _qnames_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=630, aggregations=aggs))

    out = await dns_entropy_scan(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["parents_scanned"] == 1  # total volume still clears the noise floor
    assert {item["parent"] for item in out["items"]} == set(), (
        "apex volume must not satisfy the tunnel-volume arm"
    )


@pytest.mark.asyncio
async def test_dns_entropy_scan_subdomain_volume_satisfies_tunnel_volume_gate(
    settings_kratos: Settings,
) -> None:
    # Control for the apex-gate test: the SAME mid-entropy labels, but with
    # the volume carried by the subdomain-bearing queries themselves
    # (3 x 200 = 600 >= 500) — now the volume arm legitimately fires.
    buckets = [
        _qname_bucket(f"{label}.badc2.net", 200, id_prefix=f"v{i}")
        for i, label in enumerate(_MID_ENTROPY_LABELS)
    ]
    aggs = _qnames_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=600, aggregations=aggs))

    out = await dns_entropy_scan(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    parents = {item["parent"]: item for item in out["items"]}
    assert "badc2.net" in parents
    assert parents["badc2.net"]["queries"] == 600
    assert parents["badc2.net"]["subdomain_queries"] == 600


def test_accumulate_qname_bucket_caps_sample_hits() -> None:
    # Only _MAX_DNS_SAMPLE_IDS ids ever reach the output; accumulation stops
    # at 2x that (dedup headroom) instead of hauling every bucket's hits.
    parents: dict[str, dict[str, Any]] = {}
    labels = _dga_labels(20)
    for i, label in enumerate(labels):
        bucket = _qname_bucket(f"{label}.badc2.net", 20, id_prefix=f"h{i}")
        _accumulate_qname_bucket(parents, bucket, parent_domain=None)

    entry = parents["badc2.net"]
    assert len(entry["sample_hits"]) <= 2 * _MAX_DNS_SAMPLE_IDS
    # The capped hits still yield a full complement of citable ids.
    assert len(_sample_ids(entry["sample_hits"], _MAX_DNS_SAMPLE_IDS)) == _MAX_DNS_SAMPLE_IDS
    # And the per-parent aggregates keep counting past the sample cap.
    assert entry["queries"] == 400
    assert entry["subdomain_queries"] == 400
    assert len(entry["subs"]) == 20


@pytest.mark.asyncio
async def test_dns_entropy_scan_min_queries_floor_skips_parent_entirely(
    settings_kratos: Settings,
) -> None:
    buckets = [_qname_bucket(f"{_EXTREME_LABEL}.quiet.example", 10, id_prefix="q")]
    aggs = _qnames_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=10, aggregations=aggs))

    out = await dns_entropy_scan(elastic=elastic, settings=settings_kratos, min_queries=50)

    assert out.get("error") is not True
    # Below the min_queries floor -> dropped entirely, not counted as scanned.
    assert out["parents_scanned"] == 0
    assert out["items"] == []


@pytest.mark.asyncio
async def test_dns_entropy_scan_parent_domain_narrows_to_matching_parent(
    settings_kratos: Settings,
) -> None:
    dga_labels = _dga_labels(30)
    matching = [
        _qname_bucket(f"{label}.badc2.net", 20, id_prefix=f"m{i}")
        for i, label in enumerate(dga_labels)
    ]
    other_labels = _dga_labels(30, length=21)
    other = [
        _qname_bucket(f"{label}.otherc2.net", 20, id_prefix=f"o{i}")
        for i, label in enumerate(other_labels)
    ]
    aggs = _qnames_agg(matching + other)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=1200, aggregations=aggs))

    out = await dns_entropy_scan(
        elastic=elastic, settings=settings_kratos, parent_domain="badc2.net"
    )

    assert out.get("error") is not True
    parents_seen = {item["parent"] for item in out["items"]}
    assert parents_seen == {"badc2.net"}
    assert out["parents_scanned"] == 1


@pytest.mark.asyncio
async def test_dns_entropy_scan_truncated_when_terms_agg_drops_buckets(
    settings_kratos: Settings,
) -> None:
    labels = _dga_labels(30)
    buckets = [
        _qname_bucket(f"{label}.badc2.net", 20, id_prefix=f"t{i}") for i, label in enumerate(labels)
    ]
    aggs = _qnames_agg(buckets, sum_other_doc_count=42)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=600, aggregations=aggs))

    out = await dns_entropy_scan(elastic=elastic, settings=settings_kratos)

    assert out["truncated"] is True


@pytest.mark.asyncio
async def test_dns_entropy_scan_query_body_shape(settings_kratos: Settings) -> None:
    labels = _dga_labels(30)
    buckets = [
        _qname_bucket(f"{label}.badc2.net", 20, id_prefix=f"q{i}") for i, label in enumerate(labels)
    ]
    aggs = _qnames_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=600, aggregations=aggs))

    await dns_entropy_scan(elastic=elastic, settings=settings_kratos, window_minutes=720)

    # resolve_agg_field probes elastic.search once before the main aggregation
    # query; call_args is the LAST call, i.e. the actual dns_entropy_scan query.
    call = elastic.search.call_args  # type: ignore[attr-defined]
    args, kwargs = call
    query = args[1]
    filters = query["bool"]["filter"]
    assert {"terms": {"event.dataset": ["zeek.dns"]}} in filters
    assert query["bool"]["must_not"] == [{"exists": {"field": "synth.scenario_id"}}]
    range_filters = [f for f in filters if "range" in f]
    assert len(range_filters) == 1
    rng = range_filters[0]["range"]["@timestamp"]
    assert rng["gte"] == "now-720m"
    assert rng["lte"] == "now"

    aggs_body = kwargs["aggs"]
    name_field = aggs_body["qnames"]["terms"]["field"]
    assert name_field in so_fields.DNS_QUERY
    assert aggs_body["qnames"]["terms"]["size"] == 200
    sample_source = aggs_body["qnames"]["aggs"]["sample"]["top_hits"]["_source"]
    assert sample_source == [name_field]


@pytest.mark.asyncio
async def test_dns_entropy_scan_window_over_ceiling_errors_without_query(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    out = await dns_entropy_scan(
        elastic=elastic, settings=settings_kratos, window_minutes=_MAX_TIME_RANGE_MINUTES + 1
    )

    assert out["error"] is True
    elastic.search.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dns_entropy_scan_es_error_returns_structured_error(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, RuntimeError("grid partial results"))

    out = await dns_entropy_scan(elastic=elastic, settings=settings_kratos)

    assert out["error"] is True
    assert out["type"] == "RuntimeError"
    assert "grid partial results" in out["message"]


# ---------------------------------------------------------------------------
# dcerpc_histogram — fixture builders
# ---------------------------------------------------------------------------


def _op_bucket(
    op: str,
    count: int,
    *,
    sources: list[str],
    id_prefix: str,
    op_field: str = "dce_rpc.operation",
) -> dict[str, Any]:
    n_hits = min(count, 2)
    per_source = max(count // max(len(sources), 1), 1)
    return {
        "key": op,
        "doc_count": count,
        "sample": {
            "hits": {
                "total": {"value": count, "relation": "eq" if count <= 2 else "gte"},
                "hits": [
                    {
                        "_id": f"{id_prefix}{i}",
                        "_source": {
                            "source.ip": sources[0] if sources else None,
                            "destination.ip": "10.0.0.9",
                            op_field: op,
                        },
                    }
                    for i in range(n_hits)
                ],
            }
        },
        "sources": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [{"key": s, "doc_count": per_source} for s in sources],
        },
    }


def _ops_agg(buckets: list[dict[str, Any]], *, sum_other_doc_count: int = 0) -> dict[str, Any]:
    return {
        "ops": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": sum_other_doc_count,
            "buckets": buckets,
        }
    }


# ---------------------------------------------------------------------------
# dcerpc_histogram
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dcerpc_histogram_zerologon_shaped_flagged_and_rare(
    settings_kratos: Settings,
) -> None:
    buckets = [
        _op_bucket("svcctl", 5000, sources=["10.0.0.1", "10.0.0.2"], id_prefix="s"),
        _op_bucket("NetrServerAuthenticate3", 4, sources=["10.0.0.50"], id_prefix="z"),
    ]
    aggs = _ops_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=5004, aggregations=aggs))

    out = await dcerpc_histogram(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    flagged = {f["operation"]: f for f in out["flagged"]}
    rare = {r["operation"]: r for r in out["rare"]}
    assert "NetrServerAuthenticate3" in flagged
    assert "NetrServerAuthenticate3" in rare
    entry = flagged["NetrServerAuthenticate3"]
    assert entry["count"] == 4
    assert entry["sources"] == ["10.0.0.50"]
    assert entry["sample_ids"], "sample_ids must be non-empty so findings are citable"
    assert len(out["items"]) == 2
    assert out["total_ops"] == 5004
    assert out["distinct_ops"] == 2
    # items carries the same (operation, count, sources, sample_ids) shape as
    # flagged/rare — a full histogram passthrough, not a stripped-down view —
    # and is sorted by count descending (busiest first).
    items_by_op = {item["operation"]: item for item in out["items"]}
    assert items_by_op["svcctl"]["sources"] == ["10.0.0.1", "10.0.0.2"]
    assert items_by_op["NetrServerAuthenticate3"]["sample_ids"]
    assert [item["operation"] for item in out["items"]] == ["svcctl", "NetrServerAuthenticate3"]


@pytest.mark.asyncio
async def test_dcerpc_histogram_items_capped_at_25_by_count_desc(
    settings_kratos: Settings,
) -> None:
    # 30 distinct operations returned by the terms agg -> `items` caps at the
    # top 25 by count, but total_ops/distinct_ops still reflect the FULL
    # histogram (all 30), and a low-volume dangerous op pushed out of the
    # top-25 slice still lands in `flagged` (evaluated against the full set).
    buckets = [
        _op_bucket(f"op{i}", 1000 - i, sources=["10.0.0.1"], id_prefix=f"o{i}") for i in range(29)
    ]
    buckets.append(_op_bucket("NetrServerAuthenticate3", 2, sources=["10.0.0.50"], id_prefix="z"))
    aggs = _ops_agg(buckets)
    total = sum(b["doc_count"] for b in buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=total, aggregations=aggs))

    out = await dcerpc_histogram(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["distinct_ops"] == 30
    assert out["total_ops"] == total
    assert len(out["items"]) == 25
    counts = [item["count"] for item in out["items"]]
    assert counts == sorted(counts, reverse=True)
    assert "NetrServerAuthenticate3" not in {item["operation"] for item in out["items"]}
    flagged_ops = {f["operation"] for f in out["flagged"]}
    assert "NetrServerAuthenticate3" in flagged_ops


@pytest.mark.asyncio
async def test_dcerpc_histogram_benign_no_flags(settings_kratos: Settings) -> None:
    buckets = [
        _op_bucket("svcctl", 5000, sources=["10.0.0.1"], id_prefix="a"),
        _op_bucket("srvsvc", 3000, sources=["10.0.0.2"], id_prefix="b"),
    ]
    aggs = _ops_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=8000, aggregations=aggs))

    out = await dcerpc_histogram(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["flagged"] == []
    assert out["rare"] == []
    assert len(out["items"]) == 2


@pytest.mark.asyncio
async def test_dcerpc_histogram_quiet_grid_no_rare_but_flags_dangerous(
    settings_kratos: Settings,
) -> None:
    # No op crosses the busy_min=100 bar -> rare is skipped entirely, even
    # though every op individually clears the rare_max<=5 doc_count bar. A
    # dangerous op still gets flagged regardless of count/baseline — flagged
    # and rare are independent signals.
    buckets = [
        _op_bucket("svcctl", 8, sources=["10.0.0.1"], id_prefix="a"),
        _op_bucket("srvsvc", 3, sources=["10.0.0.2"], id_prefix="b"),
        _op_bucket("CreateServiceW", 1, sources=["10.0.0.9"], id_prefix="c"),
    ]
    aggs = _ops_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=12, aggregations=aggs))

    out = await dcerpc_histogram(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["rare"] == []
    flagged_ops = {f["operation"] for f in out["flagged"]}
    assert "CreateServiceW" in flagged_ops


@pytest.mark.asyncio
async def test_dcerpc_histogram_truncated_when_terms_agg_drops_buckets(
    settings_kratos: Settings,
) -> None:
    buckets = [_op_bucket("svcctl", 5000, sources=["10.0.0.1"], id_prefix="a")]
    aggs = _ops_agg(buckets, sum_other_doc_count=17)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=5000, aggregations=aggs))

    out = await dcerpc_histogram(elastic=elastic, settings=settings_kratos)

    assert out["truncated"] is True


@pytest.mark.asyncio
async def test_dcerpc_histogram_rare_capped_at_25_lowest_count(
    settings_kratos: Settings,
) -> None:
    # 90 distinct low-count ops (counts 1..90) plus one busy op clears the
    # busy_min=100 bar — with rare_max=90 every one of the 90 low-count ops
    # qualifies as "rare" (busy op's count of 500 does not, since 500 >
    # rare_max). `rare` must cap at 25, `rare_total` must reflect the FULL
    # 90, `rare_truncated` must be True, and the 25 entries kept must be the
    # 25 LOWEST counts (1..25), not an arbitrary/high-count slice — this is
    # the defense against a busy AD grid blowing the 12KiB agent-side output
    # clamp, which can't shrink `rare` on its own.
    low_count_buckets = [
        _op_bucket(f"op{i}", i + 1, sources=["10.0.0.1"], id_prefix=f"r{i}") for i in range(90)
    ]
    busy_bucket = _op_bucket("busyop", 500, sources=["10.0.0.2"], id_prefix="busy")
    aggs = _ops_agg([*low_count_buckets, busy_bucket])
    total = sum(b["doc_count"] for b in [*low_count_buckets, busy_bucket])
    elastic, _ = _make_elastic(settings_kratos, _result([], total=total, aggregations=aggs))

    out = await dcerpc_histogram(elastic=elastic, settings=settings_kratos, rare_max=90)

    assert out.get("error") is not True
    assert out["rare_total"] == 90
    assert out["rare_truncated"] is True
    assert len(out["rare"]) == 25
    counts = [r["count"] for r in out["rare"]]
    assert counts == list(range(1, 26)), "kept entries must be the 25 LOWEST counts"
    assert counts == sorted(counts)
    assert "busyop" not in {r["operation"] for r in out["rare"]}


@pytest.mark.asyncio
async def test_dcerpc_histogram_rare_not_truncated_under_cap(
    settings_kratos: Settings,
) -> None:
    buckets = [
        _op_bucket(f"op{i}", i + 1, sources=["10.0.0.1"], id_prefix=f"n{i}") for i in range(5)
    ]
    busy_bucket = _op_bucket("busyop", 500, sources=["10.0.0.2"], id_prefix="busy")
    aggs = _ops_agg([*buckets, busy_bucket])
    total = sum(b["doc_count"] for b in [*buckets, busy_bucket])
    elastic, _ = _make_elastic(settings_kratos, _result([], total=total, aggregations=aggs))

    out = await dcerpc_histogram(elastic=elastic, settings=settings_kratos, rare_max=5)

    assert out["rare_total"] == 5
    assert out["rare_truncated"] is False
    assert len(out["rare"]) == 5


def test_cap_by_count_ascending_caps_and_sorts_rarest_first() -> None:
    entries = [{"count": i} for i in range(30)]
    capped, total, truncated = _cap_by_count_ascending(entries, 25)

    assert total == 30
    assert truncated is True
    assert len(capped) == 25
    assert [e["count"] for e in capped] == list(range(25))


def test_cap_by_count_ascending_under_cap_not_truncated() -> None:
    entries = [{"count": i} for i in range(10)]
    capped, total, truncated = _cap_by_count_ascending(entries, 25)

    assert total == 10
    assert truncated is False
    assert capped == sorted(entries, key=lambda e: e["count"])


@pytest.mark.asyncio
async def test_dcerpc_histogram_query_body_shape(settings_kratos: Settings) -> None:
    buckets = [_op_bucket("svcctl", 5000, sources=["10.0.0.1"], id_prefix="a")]
    aggs = _ops_agg(buckets)
    elastic, _ = _make_elastic(settings_kratos, _result([], total=5000, aggregations=aggs))

    await dcerpc_histogram(elastic=elastic, settings=settings_kratos, window_minutes=720)

    # resolve_agg_field probes elastic.search once before the main aggregation
    # query; call_args is the LAST call, i.e. the actual dcerpc_histogram query.
    call = elastic.search.call_args  # type: ignore[attr-defined]
    args, kwargs = call
    query = args[1]
    filters = query["bool"]["filter"]
    assert {"term": {"event.dataset": "zeek.dce_rpc"}} in filters
    assert query["bool"]["must_not"] == [{"exists": {"field": "synth.scenario_id"}}]
    range_filters = [f for f in filters if "range" in f]
    assert len(range_filters) == 1
    rng = range_filters[0]["range"]["@timestamp"]
    assert rng["gte"] == "now-720m"
    assert rng["lte"] == "now"

    aggs_body = kwargs["aggs"]
    op_field = aggs_body["ops"]["terms"]["field"]
    assert op_field in so_fields.DCE_RPC_OPERATION
    assert aggs_body["ops"]["terms"]["size"] == 100
    sample_source = aggs_body["ops"]["aggs"]["sample"]["top_hits"]["_source"]
    assert sample_source == ["source.ip", "destination.ip", op_field]
    assert aggs_body["ops"]["aggs"]["sources"]["terms"]["field"] == "source.ip"
    assert aggs_body["ops"]["aggs"]["sources"]["terms"]["size"] == 5


@pytest.mark.asyncio
async def test_dcerpc_histogram_window_over_ceiling_errors_without_query(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    out = await dcerpc_histogram(
        elastic=elastic, settings=settings_kratos, window_minutes=_MAX_TIME_RANGE_MINUTES + 1
    )

    assert out["error"] is True
    elastic.search.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_dcerpc_histogram_es_error_returns_structured_error(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, RuntimeError("grid partial results"))

    out = await dcerpc_histogram(elastic=elastic, settings=settings_kratos)

    assert out["error"] is True
    assert out["type"] == "RuntimeError"
    assert "grid partial results" in out["message"]


# ---------------------------------------------------------------------------
# first_seen — fixture builders
# ---------------------------------------------------------------------------


def _recent_dst_bucket(
    dst: str,
    doc_count: int,
    *,
    id_prefix: str,
    first_seen_ts: str = "2026-08-22T12:00:00Z",
    srcs: list[str] | None = None,
) -> dict[str, Any]:
    srcs = srcs or ["10.0.0.5"]
    n_hits = min(doc_count, 2)
    return {
        "key": dst,
        "doc_count": doc_count,
        "first_seen": {"value": 1755864000000, "value_as_string": first_seen_ts},
        "srcs": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [{"key": s, "doc_count": doc_count} for s in srcs],
        },
        "samples": {
            "hits": {
                "total": {"value": doc_count, "relation": "eq" if doc_count <= 2 else "gte"},
                "hits": [
                    {
                        "_id": f"{id_prefix}{i}",
                        "_source": {"@timestamp": first_seen_ts, "destination.ip": dst},
                    }
                    for i in range(n_hits)
                ],
            }
        },
    }


def _recent_dsts_agg(
    buckets: list[dict[str, Any]], *, sum_other_doc_count: int = 0
) -> dict[str, Any]:
    return {
        "dsts": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": sum_other_doc_count,
            "buckets": buckets,
        }
    }


def _baseline_dsts_agg(keys: list[str], *, sum_other_doc_count: int = 0) -> dict[str, Any]:
    return {
        "dsts": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": sum_other_doc_count,
            "buckets": [{"key": k, "doc_count": 1} for k in keys],
        }
    }


# ---------------------------------------------------------------------------
# first_seen
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_seen_novel_external_destination_lands_in_items(
    settings_kratos: Settings,
) -> None:
    recent_bucket = _recent_dst_bucket("8.8.4.9", 42, id_prefix="n", srcs=["10.0.0.5", "10.0.0.6"])
    recent = _result([], aggregations=_recent_dsts_agg([recent_bucket]))
    baseline = _result([], aggregations=_baseline_dsts_agg(["8.8.9.1"]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["recent_destinations"] == 1
    assert out["baseline_destinations"] == 1
    assert out["internal_excluded"] == 0
    assert out["baseline_empty"] is False
    assert len(out["items"]) == 1
    item = out["items"][0]
    assert item["dst"] == "8.8.4.9"
    assert item["recent_events"] == 42
    assert item["first_seen_ts"] == "2026-08-22T12:00:00Z"
    assert item["sources"] == ["10.0.0.5", "10.0.0.6"]
    assert item["sample_ids"], "sample_ids must be non-empty so findings are citable"


@pytest.mark.asyncio
async def test_first_seen_destination_in_baseline_suppressed(
    settings_kratos: Settings,
) -> None:
    recent_bucket = _recent_dst_bucket("8.8.4.9", 10, id_prefix="s")
    recent = _result([], aggregations=_recent_dsts_agg([recent_bucket]))
    baseline = _result([], aggregations=_baseline_dsts_agg(["8.8.4.9"]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["items"] == []
    assert out["recent_destinations"] == 1
    assert out["baseline_destinations"] == 1
    assert out["internal_excluded"] == 0


@pytest.mark.asyncio
async def test_first_seen_internal_destination_excluded(settings_kratos: Settings) -> None:
    # The server-side CIDR exclusion should keep internal destinations out of
    # the buckets entirely; if one leaks back anyway (a shape the CIDR list
    # misses), the belt-and-braces Python check still catches and counts it.
    recent_bucket = _recent_dst_bucket("10.0.0.50", 10, id_prefix="i")
    recent = _result([], aggregations=_recent_dsts_agg([recent_bucket]))
    baseline = _result([], aggregations=_baseline_dsts_agg(["8.8.9.1"]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["items"] == []
    assert out["internal_excluded"] == 1


@pytest.mark.asyncio
async def test_first_seen_empty_baseline_declares_gap_instead_of_mass_novelty(
    settings_kratos: Settings,
) -> None:
    # A baseline window with ZERO destinations (retention/coverage gap) must
    # NOT make every recent destination read as novel — that is a mass false
    # positive, not a finding. The tool declares the gap instead.
    buckets = [_recent_dst_bucket(f"8.8.4.{i}", 10 + i, id_prefix=f"g{i}") for i in range(3)]
    recent = _result([], aggregations=_recent_dsts_agg(buckets))
    baseline = _result([], aggregations=_baseline_dsts_agg([]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["baseline_empty"] is True
    assert out["items"] == [], "no destination may be declared novel against an empty baseline"
    assert out["recent_destinations"] == 3
    assert out["baseline_destinations"] == 0
    assert out["summary"].startswith("Baseline window contained no data")
    assert "novelty cannot be determined" in out["summary"]


@pytest.mark.asyncio
async def test_first_seen_both_windows_empty_is_not_a_baseline_gap(
    settings_kratos: Settings,
) -> None:
    # Nothing recent either -> there is no novelty question to punt on; the
    # ordinary empty result (no items, baseline_empty False) is the answer.
    recent = _result([], aggregations=_recent_dsts_agg([]))
    baseline = _result([], aggregations=_baseline_dsts_agg([]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["baseline_empty"] is False
    assert out["items"] == []
    assert out["recent_destinations"] == 0


@pytest.mark.asyncio
async def test_first_seen_baseline_truncated_flagged_and_summary_mentions_it(
    settings_kratos: Settings,
) -> None:
    recent_bucket = _recent_dst_bucket("8.8.4.9", 10, id_prefix="t")
    recent = _result([], aggregations=_recent_dsts_agg([recent_bucket]))
    baseline = _result([], aggregations=_baseline_dsts_agg(["8.8.9.1"], sum_other_doc_count=500))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out.get("error") is not True
    assert out["baseline_truncated"] is True
    assert "approx" in out["summary"].lower() or "truncat" in out["summary"].lower()


@pytest.mark.asyncio
async def test_first_seen_baseline_not_truncated_summary_silent(
    settings_kratos: Settings,
) -> None:
    recent_bucket = _recent_dst_bucket("8.8.4.9", 10, id_prefix="u")
    recent = _result([], aggregations=_recent_dsts_agg([recent_bucket]))
    baseline = _result([], aggregations=_baseline_dsts_agg(["8.8.9.1"]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out["baseline_truncated"] is False
    assert "truncat" not in out["summary"].lower()


@pytest.mark.asyncio
async def test_first_seen_recent_truncated_when_terms_agg_drops_destinations(
    settings_kratos: Settings,
) -> None:
    recent_bucket = _recent_dst_bucket("8.8.4.9", 10, id_prefix="rt")
    recent = _result([], aggregations=_recent_dsts_agg([recent_bucket], sum_other_doc_count=99))
    baseline = _result([], aggregations=_baseline_dsts_agg(["8.8.9.1"]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out["recent_truncated"] is True


@pytest.mark.asyncio
async def test_first_seen_recent_not_truncated_under_cap(settings_kratos: Settings) -> None:
    recent_bucket = _recent_dst_bucket("8.8.4.9", 10, id_prefix="rn")
    recent = _result([], aggregations=_recent_dsts_agg([recent_bucket]))
    baseline = _result([], aggregations=_baseline_dsts_agg(["8.8.9.1"]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out["recent_truncated"] is False


@pytest.mark.asyncio
async def test_first_seen_top20_sorted_by_recent_events_desc(settings_kratos: Settings) -> None:
    buckets = [_recent_dst_bucket(f"8.8.4.{i}", (25 - i), id_prefix=f"m{i}") for i in range(25)]
    recent = _result([], aggregations=_recent_dsts_agg(buckets))
    baseline = _result([], aggregations=_baseline_dsts_agg(["8.8.9.1"]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out["recent_destinations"] == 25
    assert len(out["items"]) == 20
    events = [item["recent_events"] for item in out["items"]]
    assert events == sorted(events, reverse=True)
    assert events[0] == 25


@pytest.mark.asyncio
async def test_first_seen_query_bodies_and_windows(settings_kratos: Settings) -> None:
    recent_bucket = _recent_dst_bucket("8.8.4.9", 10, id_prefix="q")
    recent = _result([], aggregations=_recent_dsts_agg([recent_bucket]))
    baseline = _result([], aggregations=_baseline_dsts_agg([]))
    elastic, _ = _make_elastic_sequence(settings_kratos, [recent, baseline])

    await first_seen(
        elastic=elastic,
        settings=settings_kratos,
        recent_minutes=720,
        baseline_days=14,
        dataset="zeek.ssl",
    )

    assert elastic.search.call_count == 2  # type: ignore[attr-defined]
    recent_call, baseline_call = elastic.search.call_args_list  # type: ignore[attr-defined]

    recent_query = recent_call.args[1]
    recent_filters = recent_query["bool"]["filter"]
    assert {"term": {"event.dataset": "zeek.ssl"}} in recent_filters
    recent_range = next(f for f in recent_filters if "range" in f)["range"]["@timestamp"]

    baseline_query = baseline_call.args[1]
    baseline_filters = baseline_query["bool"]["filter"]
    assert {"term": {"event.dataset": "zeek.ssl"}} in baseline_filters
    baseline_range = next(f for f in baseline_filters if "range" in f)["range"]["@timestamp"]

    # BOTH queries carry the synth kill-switch AND the server-side internal-
    # destination exclusion — the baseline side especially, so its 1000-slot
    # membership set holds only external destinations.
    for q in (recent_query, baseline_query):
        must_not = q["bool"]["must_not"]
        assert {"exists": {"field": "synth.scenario_id"}} in must_not
        cidr_clauses = [c for c in must_not if "terms" in c and "destination.ip" in c["terms"]]
        assert len(cidr_clauses) == 1
        excluded = cidr_clauses[0]["terms"]["destination.ip"]
        assert "10.0.0.0/8" in excluded
        assert "fc00::/7" in excluded

    # The baseline window ends EXACTLY where the recent window begins.
    assert baseline_range["lte"] == recent_range["gte"]
    # And spans baseline_days before that.
    gte = datetime.fromisoformat(baseline_range["gte"])
    lte = datetime.fromisoformat(baseline_range["lte"])
    assert (lte - gte).days == 14

    recent_aggs = recent_call.kwargs["aggs"]
    assert recent_aggs["dsts"]["terms"] == {"field": "destination.ip", "size": 100}
    assert recent_aggs["dsts"]["aggs"]["first_seen"] == {"min": {"field": "@timestamp"}}
    assert recent_aggs["dsts"]["aggs"]["srcs"]["terms"]["field"] == "source.ip"
    assert recent_aggs["dsts"]["aggs"]["samples"]["top_hits"]["_source"] == [
        "@timestamp",
        "destination.ip",
    ]

    baseline_aggs = baseline_call.kwargs["aggs"]
    assert baseline_aggs["dsts"]["terms"] == {"field": "destination.ip", "size": 1000}
    assert "aggs" not in baseline_aggs["dsts"]


@pytest.mark.asyncio
async def test_first_seen_recent_minutes_over_ceiling_errors_without_query(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    out = await first_seen(
        elastic=elastic, settings=settings_kratos, recent_minutes=_MAX_TIME_RANGE_MINUTES + 1
    )

    assert out["error"] is True
    elastic.search.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_first_seen_baseline_days_over_max_errors_without_query(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    out = await first_seen(
        elastic=elastic, settings=settings_kratos, baseline_days=_MAX_BASELINE_DAYS + 1
    )

    assert out["error"] is True
    elastic.search.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_first_seen_es_error_on_second_query_returns_structured_error(
    settings_kratos: Settings,
) -> None:
    recent_bucket = _recent_dst_bucket("8.8.4.9", 10, id_prefix="e")
    recent = _result([], aggregations=_recent_dsts_agg([recent_bucket]))
    elastic, _ = _make_elastic_sequence(
        settings_kratos, [recent, RuntimeError("grid partial results")]
    )

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out["error"] is True
    assert out["type"] == "RuntimeError"
    assert "grid partial results" in out["message"]
    assert elastic.search.call_count == 2  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_first_seen_es_error_on_first_query_returns_structured_error(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic_sequence(settings_kratos, [RuntimeError("grid partial results")])

    out = await first_seen(elastic=elastic, settings=settings_kratos)

    assert out["error"] is True
    assert out["type"] == "RuntimeError"
    assert "grid partial results" in out["message"]
    assert elastic.search.call_count == 1  # type: ignore[attr-defined]
