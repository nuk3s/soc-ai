"""Tests for read tools (currently: ``query_events_oql``)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.so_client.oql import _HARD_MAX_RESULTS
from soc_ai.tools.get_alert_context import get_alert_context
from soc_ai.tools.query_events import query_events_oql
from soc_ai.tools.query_zeek import query_zeek_logs


def _make_elastic(settings: Settings, response: dict[str, Any]) -> tuple[ElasticClient, AsyncMock]:
    """Build an ElasticClient backed by a mocked AsyncElasticsearch."""
    fake_es = AsyncMock()
    fake_es.search.return_value = response
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    return client, fake_es


@pytest.mark.asyncio
async def test_query_events_oql_happy_path(settings_kratos: Settings) -> None:
    response = {
        "took": 5,
        "hits": {
            "total": {"value": 1},
            "hits": [{"_id": "alert-1", "_source": {"foo": "bar"}}],
        },
    }
    elastic, _ = _make_elastic(settings_kratos, response)

    result = await query_events_oql(
        "rule.name:foo",
        elastic=elastic,
        settings=settings_kratos,
    )

    assert isinstance(result, EsSearchResult)
    assert result.total == 1
    assert len(result.hits) == 1


@pytest.mark.asyncio
async def test_query_events_oql_excludes_synth_docs_by_default(
    settings_kratos: Settings,
) -> None:
    """Synth kill-switch: query_events_oql MUST exclude any doc with
    `synth.scenario_id` set, so synth-TP fixtures don't pollute prod
    queries or the eval sampler's idea of "real" alerts.
    """
    response = {"took": 0, "hits": {"total": 0, "hits": []}}
    elastic, fake_es = _make_elastic(settings_kratos, response)

    await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=60,
    )

    body = fake_es.search.call_args.kwargs["body"]
    wrapped = body["query"]["bool"]
    must_not = wrapped.get("must_not", [])
    assert any(
        clause.get("exists", {}).get("field") == "synth.scenario_id" for clause in must_not
    ), (
        f"expected must_not clause excluding synth.scenario_id, got "
        f"must_not={must_not}; full wrapped={wrapped}"
    )


@pytest.mark.asyncio
async def test_query_events_oql_include_synth_opt_in_disables_filter(
    settings_kratos: Settings,
) -> None:
    """When the caller explicitly opts in (synth eval batch triaging a
    synth alert), no must_not synth filter is emitted."""
    response = {"took": 0, "hits": {"total": 0, "hits": []}}
    elastic, fake_es = _make_elastic(settings_kratos, response)

    await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=60,
        include_synth=True,
    )

    body = fake_es.search.call_args.kwargs["body"]
    wrapped = body["query"]["bool"]
    must_not = wrapped.get("must_not", [])
    assert not any(
        clause.get("exists", {}).get("field") == "synth.scenario_id" for clause in must_not
    )


@pytest.mark.asyncio
async def test_query_events_oql_wraps_with_time_filter(settings_kratos: Settings) -> None:
    response = {"took": 0, "hits": {"total": 0, "hits": []}}
    elastic, fake_es = _make_elastic(settings_kratos, response)

    await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=60,
    )

    body = fake_es.search.call_args.kwargs["body"]
    wrapped = body["query"]
    assert wrapped["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-60m"
    assert wrapped["bool"]["filter"][0]["range"]["@timestamp"]["lte"] == "now"


@pytest.mark.asyncio
async def test_query_events_oql_anchored_window(settings_kratos: Settings) -> None:
    """When ``time_anchor`` is provided, the @timestamp filter is
    centered on the anchor as `[anchor - rng/2, anchor + rng/2]` instead of
    the now-relative default. Critical for batch eval — alerts are usually
    minutes-to-days old; "now-60m" returns empty."""
    from datetime import UTC, datetime

    response = {"took": 0, "hits": {"total": 0, "hits": []}}
    elastic, fake_es = _make_elastic(settings_kratos, response)

    anchor = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=60,
        time_anchor=anchor,
    )

    body = fake_es.search.call_args.kwargs["body"]
    rng = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    # ±30 min window around 12:00 UTC.
    assert rng["gte"] == "2026-05-01T11:30:00+00:00"
    assert rng["lte"] == "2026-05-01T12:30:00+00:00"


@pytest.mark.asyncio
async def test_query_events_oql_no_anchor_falls_back_to_now(
    settings_kratos: Settings,
) -> None:
    """When time_anchor is None (CLI / WebUI live monitoring), original
    now-relative filter applies. Both forms must keep working."""
    response = {"took": 0, "hits": {"total": 0, "hits": []}}
    elastic, fake_es = _make_elastic(settings_kratos, response)

    await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=120,
        time_anchor=None,
    )

    body = fake_es.search.call_args.kwargs["body"]
    rng = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert rng["gte"] == "now-120m"
    assert rng["lte"] == "now"


@pytest.mark.asyncio
async def test_query_events_oql_uses_configured_index_pattern(
    settings_kratos: Settings,
) -> None:
    response = {"took": 0, "hits": {"total": 0, "hits": []}}
    elastic, fake_es = _make_elastic(settings_kratos, response)

    await query_events_oql(
        "*",
        elastic=elastic,
        settings=settings_kratos,
    )

    assert fake_es.search.call_args.kwargs["index"] == settings_kratos.events_index_pattern


@pytest.mark.asyncio
async def test_query_events_oql_groupby_uses_aggs(settings_kratos: Settings) -> None:
    response = {
        "took": 0,
        "hits": {"total": 0, "hits": []},
        "aggregations": {
            "by_host_name": {
                "buckets": [
                    {"key": "workstation-01", "doc_count": 5},
                    {"key": "workstation-02", "doc_count": 3},
                ]
            }
        },
    }
    elastic, fake_es = _make_elastic(settings_kratos, response)

    result = await query_events_oql(
        "* | groupby host.name | sortby count desc | head 10",
        elastic=elastic,
        settings=settings_kratos,
    )

    body = fake_es.search.call_args.kwargs["body"]
    assert body["size"] == 0
    assert "aggs" in body
    assert result.aggregations is not None
    assert len(result.aggregations["by_host_name"]["buckets"]) == 2


@pytest.mark.asyncio
async def test_query_events_oql_count_sets_track_total_hits(
    settings_kratos: Settings,
) -> None:
    """F72: `count` must cap `track_total_hits` at the same hard ceiling as
    `head` (bounded integer), not `True` — `True` forces an exact count with
    no cost ceiling across a broad, unbounded time window."""
    response = {"took": 0, "hits": {"total": {"value": 42}, "hits": []}}
    elastic, fake_es = _make_elastic(settings_kratos, response)

    result = await query_events_oql(
        "event.kind:alert | count",
        elastic=elastic,
        settings=settings_kratos,
    )

    body = fake_es.search.call_args.kwargs["body"]
    assert body["track_total_hits"] == _HARD_MAX_RESULTS
    assert body["track_total_hits"] is not True
    assert body["size"] == 0
    assert result.total == 42


@pytest.mark.asyncio
async def test_query_events_oql_rejects_unknown_field(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})
    with pytest.raises(OqlValidationError, match="unknown or forbidden field"):
        await query_events_oql(
            "totally_made_up:value",
            elastic=elastic,
            settings=settings_kratos,
        )
    fake_es.search.assert_not_called()


@pytest.mark.asyncio
async def test_query_events_oql_rejects_excessive_head(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})
    with pytest.raises(OqlValidationError, match="exceeds max_results"):
        await query_events_oql(
            "* | head 1000",
            elastic=elastic,
            settings=settings_kratos,
            max_results=100,
        )


@pytest.mark.asyncio
async def test_query_events_oql_invalid_time_range_rejected(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})
    with pytest.raises(ValueError, match="time_range_minutes"):
        await query_events_oql(
            "*",
            elastic=elastic,
            settings=settings_kratos,
            time_range_minutes=0,
        )


@pytest.mark.asyncio
async def test_query_events_oql_excessive_time_range_rejected(
    settings_kratos: Settings,
) -> None:
    """F53: an unbounded time_range_minutes must be rejected before the ES
    call — alert-embedded text is prompt-injection surface and could
    otherwise steer the agent into a full-history scan against the live SO
    cluster."""
    elastic, fake_es = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})
    with pytest.raises(ValueError, match="time_range_minutes"):
        await query_events_oql(
            "*",
            elastic=elastic,
            settings=settings_kratos,
            time_range_minutes=999_999_999,
        )
    fake_es.search.assert_not_called()


@pytest.mark.asyncio
async def test_query_events_oql_caps_size_at_max_results(
    settings_kratos: Settings,
) -> None:
    """When OQL has no head/limit and is non-aggregating, default size = max_results."""
    elastic, fake_es = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})

    await query_events_oql(
        "host.name:foo",
        elastic=elastic,
        settings=settings_kratos,
        max_results=25,
    )

    body = fake_es.search.call_args.kwargs["body"]
    assert body["size"] == 25


# =====================================================================
# C6: query_zeek_logs projection includes zeek.conn.history
# =====================================================================


@pytest.mark.asyncio
async def test_query_zeek_logs_excessive_time_range_rejected(settings_kratos: Settings) -> None:
    """F53: an unbounded time_range_minutes must be rejected before the ES
    call — alert-embedded text is prompt-injection surface and could
    otherwise steer the agent into a full-history scan against the live SO
    cluster."""
    elastic, fake_es = _make_elastic(settings_kratos, {"took": 0, "hits": {"total": 0, "hits": []}})
    with pytest.raises(ValueError, match="time_range_minutes"):
        await query_zeek_logs(
            "1:abc123==",
            elastic=elastic,
            settings=settings_kratos,
            time_range_minutes=999_999_999,
        )
    fake_es.search.assert_not_called()


@pytest.mark.asyncio
async def test_query_zeek_logs_projection_includes_history(settings_kratos: Settings) -> None:
    """query_zeek_logs must request zeek.conn.history from ES (C6)."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        {"took": 0, "hits": {"total": 0, "hits": []}},
    )
    await query_zeek_logs(
        "1:abc123==",
        elastic=elastic,
        settings=settings_kratos,
    )
    body = fake_es.search.call_args.kwargs["body"]
    assert "zeek.conn.history" in body["_source"]


# =====================================================================
# ECS field resolution: projection requests the full candidate set and
# the output coalesces ECS-first onto the stable legacy keys.
# =====================================================================


@pytest.mark.asyncio
async def test_query_zeek_logs_projection_includes_ecs_candidates(
    settings_kratos: Settings,
) -> None:
    """The _source projection must request the ECS candidate fields too, so real
    conn bytes / ja3 / sni / dns are returned on a modern grid."""
    elastic, fake_es = _make_elastic(
        settings_kratos,
        {"took": 0, "hits": {"total": 0, "hits": []}},
    )
    await query_zeek_logs("1:abc123==", elastic=elastic, settings=settings_kratos)
    source = fake_es.search.call_args.kwargs["body"]["_source"]
    for ecs_field in (
        "dns.query.name",
        "client.bytes",
        "server.bytes",
        "hash.ja3",
        "hash.ja3s",
        "ssl.server_name",
        "http.virtual_host",
        "file.hash.sha256",
    ):
        assert ecs_field in source, f"{ecs_field} missing from projection"
    # and the legacy zeek.* names stay in the projection (old SO / synth).
    assert "zeek.conn.orig_bytes" in source
    assert "zeek.ssl.ja3s" in source


@pytest.mark.asyncio
async def test_query_zeek_logs_coalesces_ecs_sample_doc(settings_kratos: Settings) -> None:
    """An ECS-shaped doc is coalesced onto the stable legacy keys the agent reads."""
    ecs_doc = {
        "event.dataset": "zeek.conn",
        "client.bytes": 1234,
        "server.bytes": 5678,
        "connection.state": "SF",
        "dns": {"query": {"name": "app.corp.acme.com"}},
        "hash": {"ja3s": "abc123ja3s"},
        "ssl": {"server_name": "app.corp.acme.com"},
        "http": {"virtual_host": "app.corp.acme.com", "status_code": 200},
        "file": {"hash": {"sha256": "deadbeef"}},
    }
    elastic, _ = _make_elastic(
        settings_kratos,
        {"took": 0, "hits": {"total": 1, "hits": [{"_id": "z1", "_source": ecs_doc}]}},
    )
    out = await query_zeek_logs("1:abc==", elastic=elastic, settings=settings_kratos)
    rec = out[0]
    assert rec["zeek.conn.orig_bytes"] == 1234
    assert rec["zeek.conn.resp_bytes"] == 5678
    assert rec["zeek.conn.conn_state"] == "SF"
    assert rec["zeek.dns.query"] == "app.corp.acme.com"
    assert rec["zeek.ssl.ja3s"] == "abc123ja3s"
    assert rec["zeek.ssl.server_name"] == "app.corp.acme.com"
    assert rec["zeek.http.host"] == "app.corp.acme.com"
    assert rec["zeek.http.status_code"] == 200
    assert rec["zeek.files.sha256"] == "deadbeef"


@pytest.mark.asyncio
async def test_query_zeek_logs_coalesce_preserves_zero_bytes(settings_kratos: Settings) -> None:
    """A 0-byte conn count is a REAL value and must be preserved, not dropped."""
    ecs_doc = {"event.dataset": "zeek.conn", "client.bytes": 0, "server.bytes": 0}
    elastic, _ = _make_elastic(
        settings_kratos,
        {"took": 0, "hits": {"total": 1, "hits": [{"_id": "z1", "_source": ecs_doc}]}},
    )
    out = await query_zeek_logs("1:abc==", elastic=elastic, settings=settings_kratos)
    assert out[0]["zeek.conn.orig_bytes"] == 0
    assert out[0]["zeek.conn.resp_bytes"] == 0


@pytest.mark.asyncio
async def test_query_zeek_logs_coalesce_legacy_zeek_doc(settings_kratos: Settings) -> None:
    """A legacy zeek.* doc (synth / old SO) still resolves onto the same keys."""
    legacy_doc = {
        "event.dataset": "zeek.conn",
        "zeek": {"conn": {"orig_bytes": 99, "conn_state": "S0"}},
    }
    elastic, _ = _make_elastic(
        settings_kratos,
        {"took": 0, "hits": {"total": 1, "hits": [{"_id": "z1", "_source": legacy_doc}]}},
    )
    out = await query_zeek_logs("1:abc==", elastic=elastic, settings=settings_kratos)
    assert out[0]["zeek.conn.orig_bytes"] == 99
    assert out[0]["zeek.conn.conn_state"] == "S0"


# =====================================================================
# C6: get_alert_context docstring corrects max_per_pivot default (LLM-facing)
# =====================================================================


def test_get_alert_context_docstring_says_default_10() -> None:
    """LLM-facing tool docstring must say Default 10, not Default 50 (C6)."""
    doc = get_alert_context.__doc__ or ""
    assert "Default 10" in doc
    assert "Default 50" not in doc
