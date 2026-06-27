"""Unit tests for the alerts-console query service."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.webui import alerts_query as aq


def test_build_filter_defaults(settings_kratos: Settings) -> None:
    q = aq.build_filter(settings_kratos, time_range="24h", severity=None, oql=None)
    b = q["bool"]
    # base query (tags:alert) produces {"term": {"tags": "alert"}} via filter_to_dsl
    assert {"term": {"tags": "alert"}} in b["must"]
    # time range applied
    assert {"range": {"@timestamp": {"gte": "now-24h"}}} in b["filter"]
    # synth rows excluded
    assert {"exists": {"field": "synth.scenario_id"}} in b["must_not"]


def test_build_filter_severity_and_unknown_range(settings_kratos: Settings) -> None:
    q = aq.build_filter(settings_kratos, time_range="bogus", severity="high", oql=None)
    b = q["bool"]
    assert {"term": {"event.severity_label": "high"}} in b["filter"]
    # unknown range falls back to the default
    assert {"range": {"@timestamp": {"gte": "now-24h"}}} in b["filter"]


def test_build_filter_rejects_pipes(settings_kratos: Settings) -> None:
    with pytest.raises(OqlValidationError, match="pipes"):
        aq.build_filter(settings_kratos, time_range="24h", severity=None, oql="foo | groupby bar")


def test_build_filter_rejects_non_whitelisted_field(settings_kratos: Settings) -> None:
    with pytest.raises(OqlValidationError):
        aq.build_filter(settings_kratos, time_range="24h", severity=None, oql="_internal_nope:1")


def _fake_elastic(payload: dict[str, Any]) -> AsyncMock:
    elastic = AsyncMock()
    elastic.search.return_value = EsSearchResult(
        total=payload.get("total", 0),
        took_ms=1,
        hits=payload.get("hits", []),
        aggregations=payload.get("aggregations"),
    )
    return elastic


GROUP_BUCKETS = {
    "total": 23,
    "aggregations": {
        "rules": {
            "buckets": [
                {
                    "key": "ET MALWARE BPFDoor Magic Packet (ICMP)",
                    "doc_count": 12,
                    "latest_ts": {"value": 1781246460000},
                    "latest": {
                        "hits": {
                            "hits": [
                                {
                                    "_id": "x7KpQ2",
                                    "_source": {
                                        "@timestamp": "2026-06-12T06:41:00.000Z",
                                        "event": {"severity_label": "high"},
                                    },
                                }
                            ]
                        }
                    },
                }
            ]
        }
    },
}


def _suricata_only(settings: Settings) -> Settings:
    """Suricata-only feed (one aggregation) for the legacy single-source tests."""
    return settings.model_copy(update={"webui_extra_detections": False})


async def test_fetch_groups_parses_buckets(settings_kratos: Settings) -> None:
    elastic = _fake_elastic(GROUP_BUCKETS)
    groups, total = await aq.fetch_groups(
        elastic, _suricata_only(settings_kratos), time_range="24h"
    )
    assert total == 23
    assert len(groups) == 1
    g = groups[0]
    assert g.rule_name == "ET MALWARE BPFDoor Magic Packet (ICMP)"
    assert g.count == 12
    assert g.severity == "high"
    assert g.latest_id == "x7KpQ2"
    # one search (extra detections off) against the events index with size=0 + aggs
    assert elastic.search.call_count == 1
    call = elastic.search.call_args
    assert call.args[0] == settings_kratos.events_index_pattern
    assert call.kwargs["size"] == 0
    assert "rules" in call.kwargs["aggs"]


async def test_fetch_groups_sort_latest_orders_by_ts(settings_kratos: Settings) -> None:
    elastic = _fake_elastic(GROUP_BUCKETS)
    await aq.fetch_groups(elastic, _suricata_only(settings_kratos), time_range="24h", sort="latest")
    aggs = elastic.search.call_args.kwargs["aggs"]
    assert aggs["rules"]["terms"]["order"] == {"latest_ts": "desc"}


# --- #49 Phase 1: multi-source feed (Suricata + Sigma + Zeek ATTACK notices) ---

_SURICATA_AGG = {
    "total": 12,
    "aggregations": {
        "rules": {
            "buckets": [
                {
                    "key": "ET MALWARE X",
                    "doc_count": 12,
                    "latest": {
                        "hits": {
                            "hits": [
                                {
                                    "_id": "a1",
                                    "_source": {
                                        "@timestamp": "2026-06-17T06:41:00.000Z",
                                        "event": {
                                            "severity_label": "high",
                                            "dataset": "suricata.alert",
                                        },
                                    },
                                }
                            ]
                        }
                    },
                }
            ]
        }
    },
}
_NOTICE_AGG = {
    "total": 3,
    "aggregations": {
        "rules": {
            "buckets": [
                {
                    "key": "ATTACK::Discovery",
                    "doc_count": 3,
                    "latest": {
                        "hits": {
                            "hits": [
                                {
                                    "_id": "n1",
                                    "_source": {
                                        "@timestamp": "2026-06-17T06:50:00.000Z",
                                        "event": {"dataset": "zeek.notice"},
                                    },
                                }
                            ]
                        }
                    },
                }
            ]
        }
    },
}


def _fake_elastic_seq(payloads: list[dict[str, Any]]) -> AsyncMock:
    elastic = AsyncMock()
    elastic.search.side_effect = [
        EsSearchResult(
            total=p.get("total", 0),
            took_ms=1,
            hits=p.get("hits", []),
            aggregations=p.get("aggregations"),
        )
        for p in payloads
    ]
    return elastic


async def test_fetch_groups_merges_multisource(settings_kratos: Settings) -> None:
    """extra detections ON → two aggregations (rule.name + notice.note) merged,
    each group tagged by kind; totals summed."""
    elastic = _fake_elastic_seq([_SURICATA_AGG, _NOTICE_AGG])  # agg A, then agg B
    groups, total = await aq.fetch_groups(elastic, settings_kratos, time_range="24h")
    assert elastic.search.call_count == 2
    assert total == 15  # 12 + 3
    by_name = {g.rule_name: g for g in groups}
    assert by_name["ET MALWARE X"].kind == "suricata"
    assert by_name["ATTACK::Discovery"].kind == "notice"
    # sorted by count desc → suricata (12) before notice (3)
    assert [g.rule_name for g in groups] == ["ET MALWARE X", "ATTACK::Discovery"]


async def test_fetch_group_events_notice_kind_filters_note(settings_kratos: Settings) -> None:
    elastic = _fake_elastic(FLAT_HITS)
    await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="ATTACK::Discovery", kind="notice", time_range="24h"
    )
    query = elastic.search.call_args.args[1]
    # filters on notice.note (not rule.name); source scope is the notice OQL.
    assert {"term": {"notice.note": "ATTACK::Discovery"}} in query["bool"]["filter"]


FLAT_HITS = {
    "total": 3,
    "hits": [
        {
            "_id": "ev1",
            "_source": {
                "@timestamp": "2026-06-12T06:41:00.000Z",
                "source": {"ip": "10.0.0.41", "port": 51515},
                "destination": {"ip": "10.0.0.1", "port": 443},
                "event": {"severity_label": "medium"},
                "host": {"name": "sensor1"},
            },
        },
        {
            "_id": "ev2",
            "_source": {"@timestamp": "2026-06-12T06:40:00.000Z"},
        },
        {
            "_id": "ev3",
            "_source": {
                "@timestamp": "2026-06-12T06:39:00.000Z",
                "source": {"ip": "10.0.0.7"},
            },
        },
    ],
}


async def test_fetch_group_events(settings_kratos: Settings) -> None:
    elastic = _fake_elastic(FLAT_HITS)
    events = await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="ET SCAN thing", time_range="24h"
    )
    assert [e.es_id for e in events] == ["ev1", "ev2", "ev3"]
    assert events[0].src == "10.0.0.41:51515"
    assert events[0].dst == "10.0.0.1:443"
    assert events[0].severity == "medium"
    assert events[1].src == "—"  # missing fields render as em-dash
    assert events[2].src == "10.0.0.7"
    # rule.name term filter was added
    query = elastic.search.call_args.args[1]
    assert {"term": {"rule.name": "ET SCAN thing"}} in query["bool"]["filter"]


def test_build_filter_star_base_skips_base_query(settings_kratos: Settings) -> None:
    settings = settings_kratos.model_copy(update={"webui_alerts_query": "*"})
    q = aq.build_filter(settings, time_range="24h", severity=None, oql=None)
    assert q["bool"]["must"] == [{"match_all": {}}]


async def test_fetch_group_events_clamps_size(settings_kratos: Settings) -> None:
    elastic = _fake_elastic(FLAT_HITS)
    await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="r", time_range="24h", size=10_000
    )
    assert elastic.search.call_args.kwargs["size"] == aq.MAX_EVENTS
    # synth exclusion survives into the flat path
    query = elastic.search.call_args.args[1]
    assert {"exists": {"field": "synth.scenario_id"}} in query["bool"]["must_not"]


async def test_fetch_group_events_hide_acked_injects_must_not(settings_kratos: Settings) -> None:
    """hide_acked=True must add the acknowledged/escalated must_not filter to the DSL,
    so the bulk-ack path never re-acks already-acknowledged events."""
    elastic = _fake_elastic(FLAT_HITS)
    await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="ET SCAN thing", time_range="24h", hide_acked=True
    )
    query = elastic.search.call_args.args[1]
    hide_acked_clause = {
        "bool": {
            "must_not": [
                {"term": {"event.acknowledged": True}},
                {"term": {"event.escalated": True}},
            ]
        }
    }
    assert hide_acked_clause in query["bool"]["filter"], (
        "hide_acked=True must inject the acknowledged/escalated exclusion filter"
    )


async def test_fetch_group_events_hide_acked_default_off(settings_kratos: Settings) -> None:
    """hide_acked defaults to False — the row-expand view must still show acked events."""
    elastic = _fake_elastic(FLAT_HITS)
    await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="ET SCAN thing", time_range="24h"
    )
    query = elastic.search.call_args.args[1]
    # No acknowledged/escalated must_not clause should be present in filter
    for clause in query["bool"].get("filter", []):
        inner = clause.get("bool", {}).get("must_not", [])
        for c in inner:
            assert c != {"term": {"event.acknowledged": True}}, (
                "hide_acked=False (default) must NOT inject the acknowledged exclusion filter"
            )


@pytest.mark.asyncio
async def test_fetch_group_events_passes_offset_and_size(settings_kratos: Settings) -> None:
    """F5: size + offset flow through to the ES query (size + from_) so large
    groups can be paged ("load more") instead of silently truncated."""
    from soc_ai.webui import alerts_query as aq

    elastic = AsyncMock()
    elastic.search.return_value = EsSearchResult(
        total=0, took_ms=0, hits=[], aggregations=None, total_is_lower_bound=False
    )
    await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="ET TEST", size=25, offset=50
    )
    kw = elastic.search.call_args.kwargs
    assert kw["size"] == 25
    assert kw["from_"] == 50
