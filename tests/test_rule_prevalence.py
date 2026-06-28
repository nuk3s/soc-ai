"""Tests for the ``rule_prevalence`` read tool.

Core guarantee under test: the tool tells a noisy rule (fires constantly across
the estate → a firing is weak evidence HERE) apart from a rare / first-seen rule
(a firing is notable). Plus the robustness contract shared by the read tools:
empty data → a clean ``observed: False`` / ``first-seen`` result (NOT an
exception); an ES error or bad input → a clean error dict (NOT a raised
exception). The tool is READ-ONLY and ZERO-EGRESS — every test mocks ES.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.tools.rule_prevalence import rule_prevalence

RULE = "ET MALWARE Cobalt Strike Beacon Observed"


def _make_elastic(
    settings: Settings, result: EsSearchResult | Exception
) -> tuple[ElasticClient, AsyncMock]:
    """Build an ElasticClient whose ``.search`` is mocked at the wrapper level.

    Patching ``ElasticClient.search`` lets the test hand back a typed
    ``EsSearchResult`` directly, or raise to exercise the error path.
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
    *,
    total: int,
    aggregations: dict[str, Any] | None = None,
) -> EsSearchResult:
    return EsSearchResult(total=total, took_ms=4, hits=[], aggregations=aggregations)


def _aggs(
    *,
    src: int,
    dest: int,
    first: str = "2026-06-01T00:00:00Z",
    last: str = "2026-06-27T00:00:00Z",
) -> dict[str, Any]:
    return {
        "distinct_src_hosts": {"value": src},
        "distinct_dest_hosts": {"value": dest},
        "first_seen": {"value_as_string": first},
        "last_seen": {"value_as_string": last},
    }


# ---------------------------------------------------------------------------
# The headline: noisy vs occasional vs rare vs first-seen.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_noisy_rule_fires_constantly(settings_kratos: Settings) -> None:
    """A rule firing thousands of times across many hosts → 'noisy' (weak here)."""
    elastic, _ = _make_elastic(
        settings_kratos, _result(total=6000, aggregations=_aggs(src=120, dest=80))
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["observed"] is True
    assert out["total_fires"] == 6000
    assert out["distinct_src_hosts"] == 120
    assert out["distinct_dest_hosts"] == 80
    assert out["fires_per_day"] == 200.0  # 6000 / 30
    assert out["noisiness"] == "noisy"
    assert out["first_seen"] == "2026-06-01T00:00:00Z"
    assert out["last_seen"] == "2026-06-27T00:00:00Z"
    assert "error" not in out


@pytest.mark.asyncio
async def test_occasional_rule(settings_kratos: Settings) -> None:
    """A rule firing a few times a day → 'occasional'."""
    elastic, _ = _make_elastic(
        settings_kratos, _result(total=90, aggregations=_aggs(src=4, dest=3))
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["fires_per_day"] == 3.0  # 90 / 30
    assert out["noisiness"] == "occasional"


@pytest.mark.asyncio
async def test_rare_rule_is_notable(settings_kratos: Settings) -> None:
    """A rule firing less than once a day → 'rare' (a firing is notable)."""
    elastic, _ = _make_elastic(settings_kratos, _result(total=3, aggregations=_aggs(src=1, dest=1)))

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["total_fires"] == 3
    assert out["fires_per_day"] == 0.1  # 3 / 30
    assert out["noisiness"] == "rare"


@pytest.mark.asyncio
async def test_first_seen_when_no_prior_fires(settings_kratos: Settings) -> None:
    """No fires in the window → 'first-seen': the next firing is the notable one."""
    elastic, _ = _make_elastic(settings_kratos, _result(total=0))

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["observed"] is False
    assert out["total_fires"] == 0
    assert out["distinct_src_hosts"] == 0
    assert out["distinct_dest_hosts"] == 0
    assert out["first_seen"] is None
    assert out["last_seen"] is None
    assert out["fires_per_day"] == 0.0
    assert out["noisiness"] == "first-seen"
    assert "notable" in out["summary"]
    assert "error" not in out


# ---------------------------------------------------------------------------
# Query shape: dataset scope, rule-name resolution, lookback window, synth guard.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_scopes_to_suricata_and_resolves_rule_name_fields(
    settings_kratos: Settings,
) -> None:
    """The query must scope to event.dataset == suricata.alert and OR the rule
    name across the ECS-first candidates (rule.name / rule.rule / signature)."""
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured["index"] = index
        captured["query"] = query
        captured["kwargs"] = kwargs
        return _result(total=0)

    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos)

    assert captured["index"] == settings_kratos.events_index_pattern
    bool_q = captured["query"]["bool"]
    # dataset is pinned to suricata.alert
    assert {"term": {"event.dataset": "suricata.alert"}} in bool_q["must"]
    # rule name OR'd across every ECS/legacy candidate field
    should = next(m["bool"]["should"] for m in bool_q["must"] if "bool" in m)
    # rule.name uses match_phrase (mirrors the alert resolver in routes.py);
    # the legacy fields use term.
    matched_fields = {next(iter(next(iter(s.values())))) for s in should}
    assert "rule.name" in matched_fields
    assert {"match_phrase": {"rule.name": RULE}} in should
    assert "rule.rule" in matched_fields
    assert "signature" in matched_fields
    # synth-eval kill-switch present
    assert {"exists": {"field": "synth.scenario_id"}} in bool_q["must_not"]
    # size=0 + cardinality aggs for distinct host counts
    assert captured["kwargs"]["size"] == 0
    aggs = captured["kwargs"]["aggs"]
    assert aggs["distinct_src_hosts"]["cardinality"]["field"] == "source.ip"
    assert aggs["distinct_dest_hosts"]["cardinality"]["field"] == "destination.ip"


@pytest.mark.asyncio
async def test_lookback_window_in_query_and_normalisation(settings_kratos: Settings) -> None:
    """A custom lookback must drive both the @timestamp filter and fires_per_day."""
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured["query"] = query
        return _result(total=14, aggregations=_aggs(src=2, dest=2))

    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=7)

    ts_filter = captured["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert ts_filter["gte"] == "now-7d"
    assert ts_filter["lte"] == "now"
    assert out["lookback_days"] == 7
    assert out["fires_per_day"] == 2.0  # 14 / 7


# ---------------------------------------------------------------------------
# Robustness contract.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_es_error_is_clean_error_dict(settings_kratos: Settings) -> None:
    """An ES failure → a clean error dict the agent can read, NOT a raised exception."""
    elastic, _ = _make_elastic(settings_kratos, RuntimeError("cluster_block_exception"))

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos)

    assert out["error"] is True
    assert out["type"] == "RuntimeError"
    assert "cluster_block_exception" in out["message"]


@pytest.mark.asyncio
async def test_empty_rule_name_returns_error(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result(total=0))

    out = await rule_prevalence("   ", elastic=elastic, settings=settings_kratos)

    assert out["error"] is True
    assert "rule_name" in out["message"]


@pytest.mark.asyncio
async def test_non_positive_lookback_returns_error(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result(total=0))

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=0)

    assert out["error"] is True
    assert "lookback_days" in out["message"]


@pytest.mark.asyncio
async def test_rule_name_is_stripped(settings_kratos: Settings) -> None:
    """A padded rule name is trimmed and matched on the trimmed value."""
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured["query"] = query
        return _result(total=0)

    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    out = await rule_prevalence(f"  {RULE}  ", elastic=elastic, settings=settings_kratos)

    assert out["rule_name"] == RULE
    should = next(m["bool"]["should"] for m in captured["query"]["bool"]["must"] if "bool" in m)
    assert {"match_phrase": {"rule.name": RULE}} in should
