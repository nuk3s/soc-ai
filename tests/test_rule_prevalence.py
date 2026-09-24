"""Tests for the ``rule_prevalence`` read tool.

Core guarantee under test: the tool tells a noisy rule (fires constantly across
the network → a firing is weak evidence HERE) apart from a rare / first-seen rule
(a firing is notable) apart from a BURST (a pile of fires inside one short
episode, which is not a background rate at all). Plus the robustness contract
shared by the read tools: empty data → a clean ``observed: False`` /
``first-seen`` result (NOT an exception); an ES error or bad input → a clean
error dict (NOT a raised exception). The tool is READ-ONLY and ZERO-EGRESS —
every test mocks ES.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
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


def _day_buckets(first: str, count: int) -> list[dict[str, Any]]:
    """``count`` consecutive calendar-day buckets starting at ``first``'s day."""
    start = datetime.fromisoformat(first.replace("Z", "+00:00")).astimezone(UTC)
    start = start.replace(hour=0, minute=0, second=0, microsecond=0)
    return [
        {
            "key_as_string": (start + timedelta(days=i)).strftime("%Y-%m-%dT00:00:00.000Z"),
            "doc_count": 1,
        }
        for i in range(count)
    ]


def _aggs(
    *,
    src: int,
    dest: int,
    first: str = "2026-06-01T00:00:00Z",
    last: str = "2026-06-27T00:00:00Z",
    ports: int = 2,
    active_days: int = 26,
) -> dict[str, Any]:
    return {
        "distinct_src_hosts": {"value": src},
        "distinct_dest_hosts": {"value": dest},
        "distinct_src_ports": {"value": ports},
        "first_seen": {"value_as_string": first},
        "last_seen": {"value_as_string": last},
        "by_day": {"buckets": _day_buckets(first, active_days)},
    }


# ---------------------------------------------------------------------------
# The headline: noisy vs occasional vs rare vs burst vs first-seen.
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
    # Rate is over the 26 days actually observed, not the 30-day lookback.
    assert out["fires_per_day"] == pytest.approx(230.769, abs=0.001)
    assert out["rate_basis"] == "observed_span"
    assert out["is_burst"] is False
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

    assert out["fires_per_day"] == pytest.approx(3.462, abs=0.001)  # 90 over 26 observed days
    assert out["noisiness"] == "occasional"


@pytest.mark.asyncio
async def test_rare_rule_is_notable(settings_kratos: Settings) -> None:
    """A rule firing less than once a day → 'rare' (a firing is notable)."""
    elastic, _ = _make_elastic(
        settings_kratos, _result(total=3, aggregations=_aggs(src=1, dest=1, active_days=3))
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["total_fires"] == 3
    assert out["fires_per_day"] == pytest.approx(0.115, abs=0.001)  # 3 over 26 observed days
    assert out["noisiness"] == "rare"
    # Three fires is below the burst floor even though they are clumped: the
    # honest answer for a handful of fires is "rare", not "burst".
    assert out["is_burst"] is False


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
    assert out["fires_per_day"] is None
    assert out["rate_basis"] is None
    assert out["is_burst"] is False
    assert out["observed_span_seconds"] is None
    assert out["active_days"] == 0
    assert out["noisiness"] == "first-seen"
    assert "notable" in out["summary"]
    assert "error" not in out


# ---------------------------------------------------------------------------
# The burst defect: 1531 fires inside 59 seconds were reported as 51.033/day
# "occasional" because the count was divided by the 30-day lookback. The rate
# was wrong by the ratio of the window to the burst (~43000x) and the verdict
# closed a real intrusion as a false positive on it.
# ---------------------------------------------------------------------------

# The measured shape of that alert, verbatim from the grid.
_BURST_FIRST = "2026-09-01T00:38:18.475Z"
_BURST_LAST = "2026-09-01T00:39:17.352Z"
_BURST_FIRES = 1531


@pytest.mark.asyncio
async def test_burst_refuses_to_emit_a_per_day_rate(settings_kratos: Settings) -> None:
    """1531 fires inside 59s must NOT be described as a per-day rate at all."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=_BURST_FIRES,
            aggregations=_aggs(
                src=1, dest=1, ports=1, first=_BURST_FIRST, last=_BURST_LAST, active_days=1
            ),
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["total_fires"] == _BURST_FIRES
    assert out["is_burst"] is True
    assert out["noisiness"] == "burst"
    # The whole point: no per-day rate, because there is no meaningful one.
    assert out["fires_per_day"] is None
    assert out["rate_basis"] is None
    # And the fabricated number must not survive anywhere in the payload.
    assert "51.03" not in json.dumps(out)

    assert out["observed_span_seconds"] == pytest.approx(58.877, abs=0.001)
    assert out["active_days"] == 1
    assert out["distinct_src_ports"] == 1
    assert out["burst_fires_per_minute"] == pytest.approx(1560.2, abs=0.1)


@pytest.mark.asyncio
async def test_burst_summary_says_what_was_actually_seen(settings_kratos: Settings) -> None:
    """The summary must carry the count, the span, the day and the port spread."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=_BURST_FIRES,
            aggregations=_aggs(
                src=1, dest=1, ports=1, first=_BURST_FIRST, last=_BURST_LAST, active_days=1
            ),
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    summary = out["summary"]
    assert "1531" in summary
    assert "59s" in summary
    assert "2026-09-01" in summary
    assert "1 source port" in summary
    assert "burst" in summary
    assert "no per-day rate" in summary.lower()


@pytest.mark.asyncio
async def test_two_bursts_far_apart_are_still_a_burst(settings_kratos: Settings) -> None:
    """A wide first/last span does not make a rate honest if the days are clumped.

    1500 fires split across two days 28 days apart spans 93% of the window, so a
    span-based rate would read ~54/day. The rule was active on 2 of 29 days: that
    is two episodes, not a background rate.
    """
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=1500,
            aggregations={
                "distinct_src_hosts": {"value": 2},
                "distinct_dest_hosts": {"value": 2},
                "distinct_src_ports": {"value": 4},
                "first_seen": {"value_as_string": "2026-06-01T00:00:00Z"},
                "last_seen": {"value_as_string": "2026-06-29T00:00:00Z"},
                "by_day": {
                    "buckets": [
                        {"key_as_string": "2026-06-01T00:00:00.000Z", "doc_count": 700},
                        {"key_as_string": "2026-06-29T00:00:00.000Z", "doc_count": 800},
                    ]
                },
            },
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["is_burst"] is True
    assert out["noisiness"] == "burst"
    assert out["fires_per_day"] is None
    assert out["active_days"] == 2
    assert "2 active day" in out["summary"]
    # The span here is 28 days of mostly silence, so it is not a denominator for
    # a per-minute burst intensity either.
    assert out["burst_fires_per_minute"] is None
    assert out["fires_per_active_day"] == pytest.approx(750.0, abs=0.001)


# ---------------------------------------------------------------------------
# The same defect one field over: `burst_fires_per_minute` divided the burst by
# the whole window that held it. 335 fires clumped onto 4 days of a 25.4-day
# span came out as 0.01 fires per minute, under a name that says burst.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clumped_burst_reports_no_per_minute_intensity(
    settings_kratos: Settings,
) -> None:
    """When the span is mostly the gaps between episodes, it is not a burst rate."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=335,
            aggregations=_aggs(
                src=3,
                dest=2,
                ports=12,
                first="2026-08-01T00:00:00Z",
                last="2026-08-26T09:36:00Z",
                active_days=4,
            ),
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["is_burst"] is True
    assert out["active_days"] == 4
    assert out["observed_span_seconds"] == pytest.approx(2194560.0, abs=1.0)
    # 335 / (25.4 days in minutes) = 0.01, and it must not be offered as a burst.
    assert out["burst_fires_per_minute"] is None
    assert "0.01" not in json.dumps(out)
    # The honest magnitude for a clumped burst is the per-active-day figure.
    assert out["fires_per_active_day"] == pytest.approx(83.75, abs=0.001)
    assert "83.75" in out["summary"]
    assert "no per-day rate" in out["summary"].lower()


@pytest.mark.asyncio
async def test_single_fire_reports_no_rate_and_stays_rare(settings_kratos: Settings) -> None:
    """One fire has a zero-length span: no rate exists, and it is rare, not a burst."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=1,
            aggregations=_aggs(
                src=1,
                dest=1,
                ports=1,
                first="2026-06-20T11:00:00Z",
                last="2026-06-20T11:00:00Z",
                active_days=1,
            ),
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["total_fires"] == 1
    assert out["fires_per_day"] is None
    assert out["is_burst"] is False
    assert out["noisiness"] == "rare"
    assert out["burst_fires_per_minute"] is None


# ---------------------------------------------------------------------------
# NEGATIVE CONTROL. Same volume, same lookback, same nominal 51/day — but the
# fires are genuinely spread across the window. This one MUST still report a
# steady rate, or the burst fix has just replaced one wrong answer with another.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_negative_control_steady_rule_same_volume_keeps_its_rate(
    settings_kratos: Settings,
) -> None:
    """1531 fires spread over 30 days is a real 51/day and must be reported as one."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=_BURST_FIRES,
            aggregations=_aggs(
                src=1,
                dest=1,
                ports=40,
                first="2026-08-02T00:00:00Z",
                last="2026-09-01T00:00:00Z",
                active_days=30,
            ),
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["total_fires"] == _BURST_FIRES
    assert out["is_burst"] is False
    assert out["fires_per_day"] == pytest.approx(51.033, abs=0.001)
    assert out["rate_basis"] == "observed_span"
    assert out["noisiness"] == "occasional"
    assert out["active_days"] == 30
    assert "51.033" in out["summary"]


# ---------------------------------------------------------------------------
# The wording defect: the rate moved to the observed span but the sentence kept
# the old words. A rule firing 438x across 17 of 30 days was reported as
# "about 14.612/day while active". 14.612 is 438 over the 30-day span, and
# while active it is 25.765. Two real quantities, one name, and the name was on
# the wrong one.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_span_rate_is_not_described_as_a_rate_while_active(
    settings_kratos: Settings,
) -> None:
    """438 fires over a 30d span on 17 days: the sentence must name each denominator."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=438,
            aggregations=_aggs(
                src=6,
                dest=6,
                ports=90,
                first="2026-08-01T00:00:00Z",
                last="2026-08-31T00:00:00Z",
                active_days=17,
            ),
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    # The span-basis number is unchanged: 438 over the 30 days it spans.
    assert out["fires_per_day"] == pytest.approx(14.6, abs=0.001)
    assert out["rate_basis"] == "observed_span"
    assert out["active_days"] == 17
    # The quantity the old sentence claimed, now computed and named for itself.
    assert out["fires_per_active_day"] == pytest.approx(25.765, abs=0.001)

    summary = out["summary"]
    # The span figure must not be labelled with the active-day denominator.
    assert "14.6/day while active" not in summary
    assert "14.6" in summary
    assert "25.765" in summary
    assert "17 active days" in summary


@pytest.mark.asyncio
async def test_active_day_rate_clause_is_dropped_when_it_equals_the_span_rate(
    settings_kratos: Settings,
) -> None:
    """A rule active every day it spans has one rate, so the sentence says it once."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=_BURST_FIRES,
            aggregations=_aggs(
                src=1,
                dest=1,
                ports=40,
                first="2026-08-02T00:00:00Z",
                last="2026-09-01T00:00:00Z",
                active_days=30,
            ),
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["fires_per_day"] == pytest.approx(51.033, abs=0.001)
    assert out["fires_per_active_day"] == pytest.approx(51.033, abs=0.001)
    assert out["summary"].count("51.033") == 1


@pytest.mark.asyncio
async def test_negative_control_steady_high_volume_stays_noisy(
    settings_kratos: Settings,
) -> None:
    """A genuinely constant, network-wide nuisance keeps its 'noisy' label."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=30_000,
            aggregations=_aggs(
                src=60,
                dest=45,
                ports=900,
                first="2026-08-02T00:00:00Z",
                last="2026-09-01T00:00:00Z",
                active_days=30,
            ),
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["is_burst"] is False
    assert out["noisiness"] == "noisy"
    assert out["fires_per_day"] == pytest.approx(1000.0, abs=0.001)


@pytest.mark.asyncio
async def test_high_span_rate_but_thin_window_volume_is_not_noisy(
    settings_kratos: Settings,
) -> None:
    """Both denominators must agree before a rule is called background noise.

    12 fires over 6 hours is 48/day while active, but 0.4/day across the window.
    Calling that 'noisy' would be the inverse of the burst bug.
    """
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=12,
            aggregations=_aggs(
                src=8,
                dest=9,
                ports=12,
                first="2026-06-20T00:00:00Z",
                last="2026-06-20T06:00:00Z",
                active_days=1,
            ),
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    # 6h of 30d is under the span floor, so this reads as a burst, not as noise.
    assert out["is_burst"] is True
    assert out["noisiness"] == "burst"
    assert out["fires_per_day"] is None


@pytest.mark.asyncio
async def test_missing_span_aggs_refuse_a_rate_rather_than_invent_one(
    settings_kratos: Settings,
) -> None:
    """With no first/last seen there is no span, so there is no honest rate."""
    elastic, _ = _make_elastic(
        settings_kratos,
        _result(
            total=900,
            aggregations={
                "distinct_src_hosts": {"value": 3},
                "distinct_dest_hosts": {"value": 3},
            },
        ),
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["total_fires"] == 900
    assert out["observed_span_seconds"] is None
    assert out["fires_per_day"] is None
    assert out["rate_basis"] is None
    assert out["active_days"] is None
    # Unknown is not the same as bursty: do not claim a burst we cannot measure.
    assert out["is_burst"] is False
    assert "span" in out["summary"].lower()


# ---------------------------------------------------------------------------
# Query shape: dataset scope, rule-name resolution, lookback window, synth guard.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_covers_every_detection_dataset_and_rule_name_field(
    settings_kratos: Settings,
) -> None:
    """The query must cover every dataset that carries detections, not only
    Suricata, and OR the rule name across the ECS/legacy/Zeek candidates."""
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        # setdefault, not assignment: on an empty result the tool issues a
        # SECOND search — the import-volume probe that decides whether "has not
        # fired" means quiet or means every firing was backfill. Overwriting
        # would leave these assertions pointed at the probe.
        captured.setdefault("index", index)
        captured.setdefault("query", query)
        captured.setdefault("kwargs", kwargs)
        return _result(total=0)

    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos)

    assert captured["index"] == settings_kratos.events_index_pattern
    bool_q = captured["query"]["bool"]
    datasets = next(m["terms"]["event.dataset"] for m in bool_q["must"] if "terms" in m)
    assert set(datasets) == {
        "suricata.alert",
        "sigma.alert",
        "zeek.notice",
        "endpoint.alerts",
    }
    # rule name OR'd across every ECS/legacy candidate field
    should = next(m["bool"]["should"] for m in bool_q["must"] if "bool" in m)
    # rule.name uses match_phrase (mirrors the alert resolver in routes.py);
    # the legacy fields use term.
    matched_fields = {next(iter(next(iter(s.values())))) for s in should}
    assert "rule.name" in matched_fields
    assert {"match_phrase": {"rule.name": RULE}} in should
    assert "rule.rule" in matched_fields
    assert "signature" in matched_fields
    # Zeek names its notices on notice.note, not rule.name.
    assert "notice.note" in matched_fields
    # synth-eval kill-switch present
    assert {"exists": {"field": "synth.scenario_id"}} in bool_q["must_not"]
    # size=0 + cardinality aggs for distinct host counts
    assert captured["kwargs"]["size"] == 0
    aggs = captured["kwargs"]["aggs"]
    assert aggs["distinct_src_hosts"]["cardinality"]["field"] == "source.ip"
    assert aggs["distinct_dest_hosts"]["cardinality"]["field"] == "destination.ip"
    # Concentration signals: source-port spread and the day histogram that tells
    # a burst apart from a background rate.
    assert aggs["distinct_src_ports"]["cardinality"]["field"] == "source.port"
    assert aggs["by_day"]["date_histogram"]["field"] == "@timestamp"
    assert aggs["by_day"]["date_histogram"]["calendar_interval"] == "day"
    # The breakdown that keeps sources from being silently pooled.
    assert aggs["by_dataset"]["terms"]["field"] == "event.dataset"


@pytest.mark.asyncio
async def test_a_sigma_rule_is_observed_not_reported_as_first_seen(
    settings_kratos: Settings,
) -> None:
    """A rule the grid shows firing 48x must not come back as never seen."""
    aggs = _aggs(
        src=1,
        dest=1,
        ports=8,
        first="2026-08-31T11:18:56Z",
        last="2026-09-07T13:02:04Z",
        active_days=4,
    )
    aggs["by_dataset"] = {"buckets": [{"key": "sigma.alert", "doc_count": 48}]}
    elastic, _ = _make_elastic(settings_kratos, _result(total=48, aggregations=aggs))

    out = await rule_prevalence(
        "Security Onion - Grid Node Login Failure (SSH)",
        elastic=elastic,
        settings=settings_kratos,
        lookback_days=30,
    )

    assert out["observed"] is True
    assert out["total_fires"] == 48
    assert out["noisiness"] != "first-seen"
    assert out["fires_by_dataset"] == {"sigma.alert": 48}
    assert "sigma.alert" in out["summary"]


@pytest.mark.asyncio
async def test_absence_names_the_datasets_that_were_searched(
    settings_kratos: Settings,
) -> None:
    """'first-seen' is a claim about the network, so it must say where it looked."""
    elastic, _ = _make_elastic(settings_kratos, _result(total=0))

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["searched_datasets"] == [
        "suricata.alert",
        "sigma.alert",
        "zeek.notice",
        "endpoint.alerts",
    ]
    summary = out["summary"]
    assert "suricata.alert" in summary
    assert "zeek.notice" in summary
    # And it must not let a reader take silence here for silence everywhere.
    assert "did not look" in summary


@pytest.mark.asyncio
async def test_fires_spanning_two_sources_are_not_pooled_silently(
    settings_kratos: Settings,
) -> None:
    """One name matching two detection engines gives a total that mixes cadences."""
    aggs = _aggs(src=4, dest=4, active_days=26)
    aggs["by_dataset"] = {
        "buckets": [
            {"key": "suricata.alert", "doc_count": 60},
            {"key": "zeek.notice", "doc_count": 30},
        ]
    }
    elastic, _ = _make_elastic(settings_kratos, _result(total=90, aggregations=aggs))

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["fires_by_dataset"] == {"suricata.alert": 60, "zeek.notice": 30}
    summary = out["summary"]
    assert "suricata.alert" in summary
    assert "zeek.notice" in summary
    assert "not comparable" in summary


@pytest.mark.asyncio
async def test_absent_host_fields_are_not_reported_as_zero_hosts(
    settings_kratos: Settings,
) -> None:
    """Sigma and Zeek docs carry no source.ip, and that is not "0 source hosts"."""
    aggs = _aggs(
        src=0,
        dest=0,
        ports=0,
        first="2026-08-29T16:02:13Z",
        last="2026-08-31T23:49:25Z",
        active_days=2,
    )
    aggs["by_dataset"] = {"buckets": [{"key": "zeek.notice", "doc_count": 841}]}
    elastic, _ = _make_elastic(settings_kratos, _result(total=841, aggregations=aggs))

    out = await rule_prevalence(
        "CaptureLoss::Too_Little_Traffic",
        elastic=elastic,
        settings=settings_kratos,
        lookback_days=30,
    )

    # A cardinality of zero over 841 matched docs means the field is absent, not
    # that 841 detections involved no host.
    assert out["distinct_src_hosts"] is None
    assert out["distinct_dest_hosts"] is None
    assert out["distinct_src_ports"] is None
    summary = out["summary"]
    assert "0 source host" not in summary
    assert "no source or destination address" in summary
    # The noisy bucket needs host spread, which is unmeasurable here, so it must
    # neither be awarded nor withheld silently.
    assert out["noisiness"] != "noisy"
    assert "host spread" in summary


@pytest.mark.asyncio
async def test_negative_control_measured_host_spread_still_reaches_noisy(
    settings_kratos: Settings,
) -> None:
    """Where the spread IS measured, the noisy bucket is unchanged."""
    elastic, _ = _make_elastic(
        settings_kratos, _result(total=6000, aggregations=_aggs(src=120, dest=80))
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=30)

    assert out["distinct_src_hosts"] == 120
    assert out["noisiness"] == "noisy"
    assert "host spread" not in out["summary"]


@pytest.mark.asyncio
async def test_lookback_window_in_query_and_normalisation(settings_kratos: Settings) -> None:
    """A custom lookback must drive the @timestamp filter and the span fraction."""
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured["query"] = query
        return _result(
            total=14,
            aggregations=_aggs(
                src=2,
                dest=2,
                first="2026-06-21T00:00:00Z",
                last="2026-06-28T00:00:00Z",
                active_days=7,
            ),
        )

    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, lookback_days=7)

    ts_filter = captured["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert ts_filter["gte"] == "now-7d"
    assert ts_filter["lte"] == "now"
    assert out["lookback_days"] == 7
    assert out["fires_per_day"] == 2.0  # 14 over the 7 days observed
    assert out["span_fraction_of_window"] == 1.0


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
        # First call only — the empty branch also runs the import-volume probe.
        captured.setdefault("query", query)
        return _result(total=0)

    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    out = await rule_prevalence(f"  {RULE}  ", elastic=elastic, settings=settings_kratos)

    assert out["rule_name"] == RULE
    should = next(m["bool"]["should"] for m in captured["query"]["bool"]["must"] if "bool" in m)
    assert {"match_phrase": {"rule.name": RULE}} in should


# =====================================================================
# Provenance: a base rate is a rate on SOME network
# =====================================================================
#
# An imported capture fires the same rules a sensor does, and lands in the same
# index. The bucket at stake is `noisy`, which tells a reader the next firing is
# weak evidence — so a signature that saturates an imported PCAP and has never
# fired here read as background nuisance, which is the opposite of the truth.


@pytest.mark.asyncio
async def test_the_base_rate_counts_this_grid_only(settings_kratos: Settings) -> None:
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured.setdefault("query", query)
        return _result(total=0)

    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos)

    must_not = captured["query"]["bool"]["must_not"]
    assert {"exists": {"field": "import.id"}} in must_not
    assert {"term": {"tags": "replayed-corpus"}} in must_not


@pytest.mark.asyncio
async def test_measuring_an_import_on_purpose_is_still_possible(
    settings_kratos: Settings,
) -> None:
    """Asking what an import contains is a legitimate question, asked explicitly."""
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured.setdefault("query", query)
        return _result(total=0)

    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos, provenance="any")

    assert {"exists": {"field": "import.id"}} not in captured["query"]["bool"]["must_not"]
    assert out["provenance"] == "any"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "by_dataset",
    [
        # Every shape the source clause can take, because the population note
        # rides in that clause and each shape builds it separately. The first
        # draft of this test asserted only against the third: the dataset
        # aggregation was absent, so it exercised the degraded path and would
        # have passed with the note stripped off both branches that normally run.
        pytest.param({"buckets": [{"key": "suricata.alert", "doc_count": 438}]}, id="one-source"),
        pytest.param(
            {
                "buckets": [
                    {"key": "suricata.alert", "doc_count": 400},
                    {"key": "zeek.notice", "doc_count": 38},
                ]
            },
            id="two-sources",
        ),
        pytest.param(None, id="no-dataset-agg"),
    ],
)
async def test_the_noisiness_sentence_names_the_population(
    settings_kratos: Settings, by_dataset: dict[str, Any] | None
) -> None:
    """`noisy` and `rare` are claims about a network. Which one has to be said."""
    aggregations = _aggs(src=9, dest=12, active_days=17)
    if by_dataset is not None:
        aggregations["by_dataset"] = by_dataset
    elastic, _ = _make_elastic(settings_kratos, _result(total=438, aggregations=aggregations))
    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos)

    assert out["provenance"] == "live"
    assert "live telemetry only" in out["summary"]


@pytest.mark.asyncio
async def test_a_first_seen_earned_by_hiding_an_import_says_so(
    settings_kratos: Settings,
) -> None:
    """'Has not fired, a firing now is notable' is the claim the filter can invert.

    A rule with 8,000 imported firings and none live has not been seen by this
    grid, but calling that first-seen invites an analyst to treat the next hit
    as novel when the tool is holding evidence it is not.
    """
    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=[_result(total=0), _result(total=8_000)]
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos)

    assert out["observed"] is False
    assert out["noisiness"] == "first-seen"
    assert out["imported_fires"] == 8_000
    assert "8000 imported or replayed document(s)" in out["summary"]


@pytest.mark.asyncio
async def test_an_unmeasured_import_volume_stays_unmeasured(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result(total=0))
    elastic.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=[_result(total=0), RuntimeError("shard failure")]
    )

    out = await rule_prevalence(RULE, elastic=elastic, settings=settings_kratos)

    assert out["imported_fires"] is None
    assert "could not be measured" in out["summary"]
    assert "error" not in out
