"""Tests for the ``suggest_rule_tuning`` read tool.

The tool answers "should this signature be muted for noise?" from Elasticsearch
dispositions. Its volume floors mean "this rule keeps coming back", and until
the burst test was wired in it could not tell that apart from one episode: the
same 1531-fires-in-59-seconds burst that broke ``rule_prevalence`` clears the
mute bar here by 15x. Muting on that would suppress the signature that fired on
the intrusion. Every test mocks ES; the tool is READ-ONLY and ZERO-EGRESS.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.tools.rule_tuning import suggest_rule_tuning

RULE = "ET INFO Possible Lateral Movement - File Creation Request in Remote System32 Directory"

_BURST_FIRST = "2026-09-01T00:38:18.475Z"
_BURST_LAST = "2026-09-01T00:39:17.352Z"


def _make_elastic(settings: Settings, result: EsSearchResult) -> ElasticClient:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    client.search = AsyncMock(return_value=result)  # type: ignore[method-assign]
    return client


def _aggs(
    *,
    acked: int,
    escalated: int,
    first: str,
    last: str,
    active_days: int,
) -> dict[str, Any]:
    return {
        "acked": {"doc_count": acked},
        "escalated": {"doc_count": escalated},
        "first_seen": {"value_as_string": first},
        "last_seen": {"value_as_string": last},
        "by_day": {"buckets": [{"doc_count": 1} for _ in range(active_days)]},
    }


@pytest.mark.asyncio
async def test_a_burst_is_not_a_tuning_problem(settings_kratos: Settings) -> None:
    """1531 fires inside 59s must not be read as a high-volume nuisance."""
    elastic = _make_elastic(
        settings_kratos,
        EsSearchResult(
            total=1531,
            took_ms=3,
            aggregations=_aggs(
                acked=12, escalated=0, first=_BURST_FIRST, last=_BURST_LAST, active_days=1
            ),
        ),
    )

    out = await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    assert out["is_burst"] is True
    assert out["recommendation"] == "none"
    assert out["observed_span_seconds"] == pytest.approx(58.877, abs=0.001)
    assert out["active_days"] == 1
    assert "burst" in out["reason"]
    assert "burst" in out["summary"]


@pytest.mark.asyncio
async def test_negative_control_a_steady_nuisance_is_still_muted(
    settings_kratos: Settings,
) -> None:
    """Same volume, same dispositions, spread across the window: still mute."""
    elastic = _make_elastic(
        settings_kratos,
        EsSearchResult(
            total=1531,
            took_ms=3,
            aggregations=_aggs(
                acked=12,
                escalated=0,
                first="2026-08-25T00:00:00Z",
                last="2026-09-01T00:00:00Z",
                active_days=7,
            ),
        ),
    )

    out = await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    assert out["is_burst"] is False
    assert out["recommendation"] == "mute"


@pytest.mark.asyncio
async def test_untriaged_alerts_are_not_counted_as_data_points(
    settings_kratos: Settings,
) -> None:
    """The reason must not claim a rule nobody dispositioned was examined 1531x."""
    elastic = _make_elastic(
        settings_kratos,
        EsSearchResult(
            total=1531,
            took_ms=3,
            aggregations=_aggs(
                acked=0,
                escalated=0,
                first="2026-08-25T00:00:00Z",
                last="2026-09-01T00:00:00Z",
                active_days=7,
            ),
        ),
    )

    out = await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    assert out["triaged"] == 0
    assert out["nmi"] == 1531
    assert "0 triaged" in out["reason"]
    assert "1531 triaged" not in out["reason"]
    assert "investigated" not in out["reason"]


@pytest.mark.asyncio
async def test_query_asks_for_the_span_and_the_day_histogram(
    settings_kratos: Settings,
) -> None:
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        # First call only. With no alerts the tool runs a second search, the
        # import-volume probe behind "that is an absence of evidence, not
        # evidence of absence" — a bare count with no aggregations of its own.
        captured.setdefault("kwargs", kwargs)
        captured.setdefault("query", query)
        return EsSearchResult(total=0, took_ms=1)

    elastic = _make_elastic(settings_kratos, EsSearchResult(total=0, took_ms=1))
    elastic.search = _capture  # type: ignore[method-assign]

    await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    aggs = captured["kwargs"]["aggs"]
    assert aggs["first_seen"]["min"]["field"] == "@timestamp"
    assert aggs["last_seen"]["max"]["field"] == "@timestamp"
    assert aggs["by_day"]["date_histogram"]["calendar_interval"] == "day"


@pytest.mark.asyncio
async def test_no_alerts_is_a_clean_nothing_to_tune(settings_kratos: Settings) -> None:
    elastic = _make_elastic(settings_kratos, EsSearchResult(total=0, took_ms=1))

    out = await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    assert out["alert_count"] == 0
    assert out["recommendation"] == "none"
    assert out["is_burst"] is False
    assert "error" not in out
    # A zero here is "I did not look there", not "it does not fire". This tool
    # reads suricata.alert only and never said so, so for a Sigma or endpoint
    # rule it reported "fired 0x — recommendation: none" however noisy the rule
    # really was. On the range that produced one reasoning trace where
    # t_rule_prevalence said 214 fires and this said 0 for the same rule moments
    # apart, with nothing to explain the gap.
    assert out["searched_dataset"] == "suricata.alert"
    assert "suricata.alert" in out["summary"]
    assert "absence of evidence, not evidence of absence" in out["summary"]


@pytest.mark.asyncio
async def test_a_nonzero_count_names_its_dataset_without_the_caveat(
    settings_kratos: Settings,
) -> None:
    """When the tool DID find fires, the scope is still named — a count is only
    meaningful next to what it counted — but the absence caveat is dropped,
    because nothing is absent."""
    elastic = _make_elastic(settings_kratos, EsSearchResult(total=12, took_ms=1))

    out = await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    assert out["searched_dataset"] == "suricata.alert"
    assert "in suricata.alert" in out["summary"]
    assert "absence of evidence" not in out["summary"]


# ---------------------------------------------------------------------------
# Provenance: a mute recommendation is about THIS network.
#
# This tool produces the most consequential output on the read surface — a
# recommendation to silence a detection — and an imported alert pushes it the
# wrong way twice at once. It counts toward alert_count (past the mute floor)
# and it carries no analyst disposition (so it lands in the untriaged
# remainder). High volume plus little dispositioned evidence is exactly the
# shape the heuristic reads as a nuisance rule.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_tuning_verdict_counts_this_grids_own_alerts(
    settings_kratos: Settings,
) -> None:
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured.setdefault("query", query)
        return EsSearchResult(total=0, took_ms=1)

    elastic = _make_elastic(settings_kratos, EsSearchResult(total=0, took_ms=1))
    elastic.search = _capture  # type: ignore[method-assign]

    await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    must_not = captured["query"]["bool"]["must_not"]
    assert {"exists": {"field": "import.id"}} in must_not
    assert {"term": {"tags": "replayed-corpus"}} in must_not
    # The synth kill-switch this query already carried is untouched.
    assert {"exists": {"field": "synth.scenario_id"}} in must_not


@pytest.mark.asyncio
async def test_the_summary_names_the_population_behind_the_recommendation(
    settings_kratos: Settings,
) -> None:
    elastic = _make_elastic(settings_kratos, EsSearchResult(total=12, took_ms=1))

    out = await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    assert out["provenance"] == "live"
    assert "live telemetry only" in out["summary"]


@pytest.mark.asyncio
async def test_a_zero_earned_by_excluding_an_import_says_so(
    settings_kratos: Settings,
) -> None:
    """The branch already distinguishes "did not look" from "does not fire".

    A zero earned by excluding backfill is the same distinction one axis over,
    so it gets the same treatment rather than passing for a quiet rule.
    """
    elastic = _make_elastic(settings_kratos, EsSearchResult(total=0, took_ms=1))
    elastic.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=[EsSearchResult(total=0, took_ms=1), EsSearchResult(total=2_400, took_ms=1)]
    )

    out = await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    assert out["alert_count"] == 0
    assert out["imported_alerts"] == 2_400
    assert "2400 imported or replayed document(s)" in out["summary"]


@pytest.mark.asyncio
async def test_a_rule_with_live_fires_pays_for_no_extra_query(
    settings_kratos: Settings,
) -> None:
    """The probe answers an absence, so it only runs when there is one.

    And a probe that was never run must not be reported as one that failed:
    the first version of this appended the unmeasured-backfill caveat to every
    result, telling a reader that 12 real fires were an unconfirmed absence.
    """
    elastic = _make_elastic(settings_kratos, EsSearchResult(total=12, took_ms=1))

    out = await suggest_rule_tuning(RULE, elastic=elastic, settings=settings_kratos)

    assert elastic.search.await_count == 1  # type: ignore[attr-defined]
    assert out["imported_alerts"] is None
    assert "could not be measured" not in out["summary"]
    assert "absence" not in out["summary"]
