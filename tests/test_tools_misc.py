"""Tests for the remaining read tools: cases, detections, zeek, playbooks, runbook."""

from __future__ import annotations

import copy
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.get_playbooks import get_playbooks
from soc_ai.tools.lookup_runbook import lookup_runbook
from soc_ai.tools.query_cases import query_cases
from soc_ai.tools.query_detections import query_detections
from soc_ai.tools.query_zeek import DEFAULT_LOG_TYPES, query_zeek_logs


def _hits(docs: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "took": 1,
        "hits": {"total": {"value": len(docs)}, "hits": docs},
    }


def _doc(source: dict[str, Any], doc_id: str = "x") -> dict[str, Any]:
    return {"_id": doc_id, "_source": source}


def _make_elastic(
    settings: Settings, responses: list[dict[str, Any]]
) -> tuple[ElasticClient, AsyncMock]:
    fake_es = AsyncMock()
    fake_es.search.side_effect = responses
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        return ElasticClient(settings), fake_es


# =====================================================================
# query_cases
# =====================================================================


@pytest.mark.asyncio
async def test_query_cases_full_text(
    settings_kratos: Settings, sample_case: dict[str, Any]
) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([_doc(sample_case)])])

    cases = await query_cases("malware", elastic=elastic, settings=settings_kratos)

    assert len(cases) == 1
    assert cases[0].title == "Investigate suspicious outbound traffic"
    body = fake_es.search.call_args.kwargs["body"]
    assert body["query"]["bool"]["must"][0]["multi_match"]["query"] == "malware"
    assert fake_es.search.call_args.kwargs["index"] == settings_kratos.cases_index_pattern


@pytest.mark.asyncio
async def test_query_cases_with_status_filter(
    settings_kratos: Settings, sample_case: dict[str, Any]
) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([_doc(sample_case)])])

    await query_cases("malware", elastic=elastic, settings=settings_kratos, status="closed")

    body = fake_es.search.call_args.kwargs["body"]
    must_clauses = body["query"]["bool"]["must"]
    assert any(c.get("term", {}).get("status") == "closed" for c in must_clauses)


@pytest.mark.asyncio
async def test_query_cases_match_all_when_query_is_star(
    settings_kratos: Settings,
) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([])])

    await query_cases("*", elastic=elastic, settings=settings_kratos)

    body = fake_es.search.call_args.kwargs["body"]
    assert body["query"] == {"match_all": {}}


@pytest.mark.asyncio
async def test_query_cases_max_results_validation(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, [])
    with pytest.raises(ValueError, match="max_results"):
        await query_cases("x", elastic=elastic, settings=settings_kratos, max_results=0)


# =====================================================================
# query_detections
# =====================================================================


@pytest.mark.asyncio
async def test_query_detections_full_text(
    settings_kratos: Settings, sample_detection: dict[str, Any]
) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([_doc(sample_detection)])])

    detections = await query_detections("ET MALWARE", elastic=elastic, settings=settings_kratos)

    assert len(detections) == 1
    assert detections[0].title == "ET MALWARE Suspicious User-Agent"
    assert fake_es.search.call_args.kwargs["index"] == settings_kratos.detections_index_pattern


@pytest.mark.asyncio
async def test_query_detections_match_all(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([])])
    await query_detections("*", elastic=elastic, settings=settings_kratos)
    body = fake_es.search.call_args.kwargs["body"]
    assert body["query"] == {"match_all": {}}


# =====================================================================
# query_zeek_logs
# =====================================================================


@pytest.mark.asyncio
async def test_query_zeek_basic(settings_kratos: Settings) -> None:
    zeek_doc = {
        "@timestamp": "2026-05-07T10:30:00Z",
        "event": {"module": "zeek", "dataset": "zeek.conn"},
        "network": {"community_id": "1:abc=="},
    }
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([_doc(zeek_doc)])])

    rows = await query_zeek_logs("1:abc==", elastic=elastic, settings=settings_kratos)

    assert len(rows) == 1
    assert rows[0]["network"]["community_id"] == "1:abc=="
    body = fake_es.search.call_args.kwargs["body"]
    must = body["query"]["bool"]["must"]
    assert {"term": {"network.community_id": "1:abc=="}} in must
    assert {"term": {"event.module": "zeek"}} in must


@pytest.mark.asyncio
async def test_query_zeek_default_log_types(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([])])

    await query_zeek_logs("1:abc==", elastic=elastic, settings=settings_kratos)

    body = fake_es.search.call_args.kwargs["body"]
    terms_clause = next(c for c in body["query"]["bool"]["must"] if "terms" in c)
    expected_datasets = [f"zeek.{t}" for t in DEFAULT_LOG_TYPES]
    assert terms_clause["terms"]["event.dataset"] == expected_datasets


@pytest.mark.asyncio
async def test_query_zeek_custom_log_types(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([])])

    await query_zeek_logs(
        "1:abc==",
        elastic=elastic,
        settings=settings_kratos,
        log_types=["dns", "http"],
    )

    body = fake_es.search.call_args.kwargs["body"]
    terms_clause = next(c for c in body["query"]["bool"]["must"] if "terms" in c)
    assert terms_clause["terms"]["event.dataset"] == ["zeek.dns", "zeek.http"]


@pytest.mark.asyncio
async def test_query_zeek_validation(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, [])
    with pytest.raises(ValueError, match="community_id"):
        await query_zeek_logs("", elastic=elastic, settings=settings_kratos)
    with pytest.raises(ValueError, match="time_range_minutes"):
        await query_zeek_logs("x", elastic=elastic, settings=settings_kratos, time_range_minutes=-1)


@pytest.mark.asyncio
async def test_query_zeek_anchored_window(settings_kratos: Settings) -> None:
    """Issue #12: when ``time_anchor`` is set, the @timestamp filter is
    centered on the anchor. The orchestrator passes alert.timestamp here
    so Zeek pivots on batch-eval alerts actually find the right window."""
    from datetime import UTC, datetime

    elastic, fake_es = _make_elastic(settings_kratos, [_hits([])])
    anchor = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    await query_zeek_logs(
        "1:abc==",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=60,
        time_anchor=anchor,
    )
    body = fake_es.search.call_args.kwargs["body"]
    rng = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert rng["gte"] == "2026-05-01T11:30:00+00:00"
    assert rng["lte"] == "2026-05-01T12:30:00+00:00"


@pytest.mark.asyncio
async def test_query_zeek_no_anchor_uses_now_relative(
    settings_kratos: Settings,
) -> None:
    """Direct callers (CLI / WebUI / tests) leave time_anchor=None and
    keep the now-relative semantics for live monitoring."""
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([])])
    await query_zeek_logs(
        "1:abc==",
        elastic=elastic,
        settings=settings_kratos,
        time_range_minutes=60,
    )
    body = fake_es.search.call_args.kwargs["body"]
    rng = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert rng["gte"] == "now-60m"
    assert rng["lte"] == "now"


# =====================================================================
# get_playbooks
# =====================================================================


@pytest.mark.asyncio
async def test_get_playbooks_no_alert_returns_all(
    settings_kratos: Settings, sample_playbook: dict[str, Any]
) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([_doc(sample_playbook)])])

    pbs = await get_playbooks(elastic=elastic, settings=settings_kratos)

    assert len(pbs) == 1
    body = fake_es.search.call_args.kwargs["body"]
    assert body["query"] == {"match_all": {}}
    assert fake_es.search.call_args.kwargs["index"] == settings_kratos.playbooks_index_pattern


@pytest.mark.asyncio
async def test_get_playbooks_alert_id_filters_by_rule_uuid(
    settings_kratos: Settings,
    sample_alert: dict[str, Any],
    sample_playbook: dict[str, Any],
) -> None:
    elastic, fake_es = _make_elastic(
        settings_kratos,
        [
            _hits([sample_alert]),  # alert lookup
            _hits([_doc(sample_playbook)]),  # playbook search
        ],
    )

    pbs = await get_playbooks(elastic=elastic, settings=settings_kratos, alert_id="alert-001")

    assert len(pbs) == 1
    # The second call queries playbooks by linkedRules == alert's rule.uuid
    pb_call = fake_es.search.call_args_list[1]
    assert pb_call.kwargs["body"]["query"] == {"term": {"linkedRules": "rule-abc-123"}}


@pytest.mark.asyncio
async def test_get_playbooks_alert_not_found_returns_empty(
    settings_kratos: Settings,
) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([])])

    pbs = await get_playbooks(elastic=elastic, settings=settings_kratos, alert_id="nope")

    assert pbs == []
    assert fake_es.search.call_count == 1  # only the alert lookup


@pytest.mark.asyncio
async def test_get_playbooks_alert_without_rule_uuid_returns_empty(
    settings_kratos: Settings, sample_alert: dict[str, Any]
) -> None:
    """An alert that exists but has no rule.uuid means no linkable playbooks."""
    alert_doc = copy.deepcopy(sample_alert)
    del alert_doc["_source"]["rule"]["uuid"]

    elastic, fake_es = _make_elastic(settings_kratos, [_hits([alert_doc])])

    pbs = await get_playbooks(elastic=elastic, settings=settings_kratos, alert_id="alert-001")

    assert pbs == []
    assert fake_es.search.call_count == 1


# =====================================================================
# lookup_runbook (stub)
# =====================================================================


@pytest.mark.asyncio
async def test_lookup_runbook_returns_empty_in_v1() -> None:
    result = await lookup_runbook("how do I triage a beaconing alert")
    assert result == []


@pytest.mark.asyncio
async def test_lookup_runbook_invalid_k_rejected() -> None:
    with pytest.raises(ValueError, match="k must be positive"):
        await lookup_runbook("anything", k=0)
