"""Unit tests for the alerts-console query service."""

from __future__ import annotations

import copy
from typing import Any
from unittest.mock import AsyncMock

import pytest
from soc_ai.config import DEFAULT_ALERT_LABELS, DEFAULT_ALERTS_QUERY, Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.so_client.oql import filter_to_dsl, parse_oql
from soc_ai.tools._synth_scope import synth_scope_must_not
from soc_ai.webui import alerts_query as aq


def test_build_filter_defaults(settings_kratos: Settings) -> None:
    q = aq.build_filter(settings_kratos, time_range="24h", severity=None, oql=None)
    b = q["bool"]
    # base query is a union of alert labels; see the test below for why
    assert b["must"][0]["bool"]["minimum_should_match"] == 1
    # time range applied
    assert {"range": {"@timestamp": {"gte": "now-24h"}}} in b["filter"]
    # synth rows excluded
    assert {"exists": {"field": "synth.scenario_id"}} in b["must_not"]


def test_build_filter_default_sees_both_ways_a_grid_labels_an_alert(
    settings_kratos: Settings,
) -> None:
    """Either label on its own is a blind spot the feed cannot report.

    Security Onion's own ingest pipelines tag Suricata, Sigma/ElastAlert,
    Wazuh and Strelka detections ``tags:alert`` and never set ``event.kind``
    at all, so an ECS-only default would empty the queue on a stock grid.
    Elastic Defend endpoint alerts arrive through Elastic's package pipeline
    carrying ``event.kind:alert`` and no Security Onion tag, so the singular
    tag on its own cannot see them. The default has to carry both.
    """
    q = aq.build_filter(settings_kratos, time_range="24h", severity=None, oql=None)
    sources = q["bool"]["must"][0]["bool"]["should"]
    assert {"term": {"tags": "alert"}} in sources
    assert {"term": {"event.kind": "alert"}} in sources


def test_build_filter_severity_and_unknown_range(settings_kratos: Settings) -> None:
    q = aq.build_filter(settings_kratos, time_range="bogus", severity="high", oql=None)
    b = q["bool"]
    assert {"term": {"event.severity_label": "high"}} in b["filter"]
    # unknown range falls back to the default
    assert {"range": {"@timestamp": {"gte": "now-24h"}}} in b["filter"]


def test_build_filter_selects_documents_that_carry_no_severity_label(
    settings_kratos: Settings,
) -> None:
    """``severity="unknown"`` selects the documents the four ladder values cannot.

    Measured on a live grid on 2026-09-06: every alert in the 24 hour queue (38
    Elastic Defend endpoint alerts, 3 OpenCanary honeypot hits) carries no
    ``event.severity_label`` at all. A term query on that field cannot reach
    them and neither can the absence of a filter reach them ALONE, which is
    what a per-severity sweep needs. The selector is an absence test, not a
    term, and it has to be the one field the display reads so the two agree.
    """
    q = aq.build_filter(settings_kratos, time_range="24h", severity=aq.UNKNOWN_SEVERITY, oql=None)
    b = q["bool"]
    assert {"exists": {"field": "event.severity_label"}} in b["must_not"]
    # Not ALSO a term on the field it just required to be absent.
    assert not [f for f in b["filter"] if "event.severity_label" in f.get("term", {})]
    # The synthetic-row exclusion is still there — appended to, not replaced.
    assert {"exists": {"field": "synth.scenario_id"}} in b["must_not"]


def test_build_filter_labelled_severity_is_byte_identical_to_before(
    settings_kratos: Settings,
) -> None:
    """Negative control for the unlabelled selector: a labelled severity is
    unchanged. Most of the grid's history carries a label (3,960 documents over
    30 days on the measured range, all four ladder values), and the selector
    must not have widened, narrowed or reordered the query those rows come back
    on."""
    for severity in aq.SEVERITIES:
        b = aq.build_filter(settings_kratos, time_range="24h", severity=severity, oql=None)["bool"]
        assert {"term": {"event.severity_label": severity}} in b["filter"]
        assert b["must_not"] == synth_scope_must_not(False)


def test_build_filter_excludes_a_plant_nested_under_the_sigma_envelope(
    settings_kratos: Settings,
) -> None:
    """The queue is where the leak surfaced, so it builds its exclusion from the
    one module that knows every position the marker can occupy.

    Two planted DCSync documents reached the live queue as a critical Sigma
    detection because this filter named the top-level position only, and SO's
    Sigma pipeline had re-nested the marker under ``event_data``.
    """
    b = aq.build_filter(settings_kratos, time_range="24h", severity=None, oql=None)["bool"]
    assert {"exists": {"field": "event_data.synth.scenario_id"}} in b["must_not"]
    assert b["must_not"] == synth_scope_must_not(False)


def test_build_filter_rejects_pipes(settings_kratos: Settings) -> None:
    with pytest.raises(OqlValidationError, match="pipes"):
        aq.build_filter(settings_kratos, time_range="24h", severity=None, oql="foo | groupby bar")


def test_build_filter_rejects_non_whitelisted_field(settings_kratos: Settings) -> None:
    with pytest.raises(OqlValidationError):
        aq.build_filter(settings_kratos, time_range="24h", severity=None, oql="_internal_nope:1")


def test_build_filter_rejects_non_iso_abs_range(settings_kratos: Settings) -> None:
    """A non-ISO absolute range (raw junk, or ES date-math like ``now-100y``) is
    rejected in build_filter as an OqlValidationError.

    abs_from/abs_to went verbatim into an ES ``range`` with no format check, so a
    bad value made ES 400 — and a ``BadRequestError`` is an ApiError, not a
    TransportError, so it escaped the route handler as a 500. Rejecting here maps
    it to a clean 400 via the routes' existing OqlValidationError handler.
    """
    with pytest.raises(OqlValidationError):
        aq.build_filter(
            settings_kratos,
            time_range="24h",
            severity=None,
            oql=None,
            abs_from="lol",
            abs_to="lol",
        )
    with pytest.raises(OqlValidationError):
        aq.build_filter(
            settings_kratos,
            time_range="24h",
            severity=None,
            oql=None,
            abs_from="now-100y",
            abs_to="now",
        )


def _abs_ts_range(q: dict[str, Any]) -> dict[str, Any]:
    for f in q["bool"]["filter"]:
        rng = f.get("range", {})
        if "@timestamp" in rng:
            return rng["@timestamp"]  # type: ignore[no-any-return]
    raise AssertionError("no @timestamp range in filter")


def test_build_filter_abs_range_within_window_passes_through(settings_kratos: Settings) -> None:
    """An in-window absolute range is passed through verbatim (with time_zone)."""
    q = aq.build_filter(
        settings_kratos,
        time_range="24h",
        severity=None,
        oql=None,
        abs_from="2026-08-01T00:00:00Z",
        abs_to="2026-08-05T00:00:00Z",
        time_zone="UTC",
    )
    assert _abs_ts_range(q) == {
        "gte": "2026-08-01T00:00:00Z",
        "lte": "2026-08-05T00:00:00Z",
        "time_zone": "UTC",
    }


def test_build_filter_clamps_oversized_abs_span(settings_kratos: Settings) -> None:
    """A century-wide absolute range is clamped to the max window so a stale
    bookmark can't issue an unbounded aggregation across the shared grid."""
    from datetime import datetime

    q = aq.build_filter(
        settings_kratos,
        time_range="24h",
        severity=None,
        oql=None,
        abs_from="1926-01-01T00:00:00Z",
        abs_to="2026-01-01T00:00:00Z",
    )
    ts = _abs_ts_range(q)
    assert ts["lte"] == "2026-01-01T00:00:00Z"  # upper bound preserved
    assert ts["gte"] != "1926-01-01T00:00:00Z"  # lower bound pulled up
    lo = datetime.fromisoformat(ts["gte"].replace("Z", "+00:00"))
    hi = datetime.fromisoformat(ts["lte"].replace("Z", "+00:00"))
    assert (hi - lo).days <= 366  # retained span is at most the max window


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
    page = await aq.fetch_groups(elastic, _suricata_only(settings_kratos), time_range="24h")
    groups, total = page.groups, page.total
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


# ---------------------------------------------------------------------------
# The group cap, and what a capped page is allowed to claim.
#
# The grid caps every terms aggregation at MAX_GROUPS and reports the rest as a
# lump sum. The console renders "N detections · M events in window" off the
# rows it gets, so past the cap both numbers are floors — and a floor rendered
# as a total is the one under-report an analyst acts on wrongly: the queue
# looks smaller and calmer than it is.


def _copy_with(payload: dict[str, Any], **agg_over: Any) -> dict[str, Any]:
    """``GROUP_BUCKETS`` with keys set on its ``rules`` aggregation."""
    out = copy.deepcopy(payload)
    out["aggregations"]["rules"].update(agg_over)
    return out


async def test_a_capped_page_says_it_is_capped(settings_kratos: Settings) -> None:
    """The count is the grid's own, never inferred from the bucket length.

    A count from the aggregation is a fact; one derived from ``len(buckets)``
    would be a guess that maxes out at whatever ceiling was requested, would
    read an exactly-full page as a cut one, and would go quietly false the day
    the cap moves.
    """
    elastic = _fake_elastic(_copy_with(GROUP_BUCKETS, sum_other_doc_count=1408))
    page = await aq.fetch_groups(elastic, _suricata_only(settings_kratos), time_range="24h")
    assert page.truncated is True
    assert page.other_docs == 1408
    assert page.total == 23, "the matched total is the grid's, unaffected by the cap"


async def test_an_uncut_page_claims_nothing(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. Every ordinary page must read as complete.

    A truncation mark on every screen is a mark nobody reads, and this is the
    normal case: a queue with fewer distinct detections than the ceiling. Zero
    and absent both mean nothing was dropped — the key is missing only on a
    response with no aggregation block, and reading that as "something was
    lost" would put the warning on every page served by one.
    """
    elastic = _fake_elastic(_copy_with(GROUP_BUCKETS, sum_other_doc_count=0))
    page = await aq.fetch_groups(elastic, _suricata_only(settings_kratos), time_range="24h")
    assert (page.truncated, page.other_docs) == (False, 0)

    absent = _fake_elastic(GROUP_BUCKETS)  # no sum_other_doc_count key at all
    page = await aq.fetch_groups(absent, _suricata_only(settings_kratos), time_range="24h")
    assert (page.truncated, page.other_docs) == (False, 0)


async def test_every_capped_aggregation_on_the_page_is_counted(
    settings_kratos: Settings,
) -> None:
    """Three terms aggregations run per page, each with its own ceiling.

    Named alerts, the unnamed sibling grouped by dataset, and the Zeek notices.
    Reading only the first would report a page as complete while the honeypot
    rows or the notice rows were the ones being cut — and on the measured range
    the honeypot hits were the highest-signal alerts on the grid.
    """
    a = copy.deepcopy(GROUP_BUCKETS)
    a["aggregations"]["rules"]["sum_other_doc_count"] = 10
    a["aggregations"]["unnamed"] = {"rules": {"buckets": [], "sum_other_doc_count": 200}}
    b = {"total": 5, "aggregations": {"rules": {"buckets": [], "sum_other_doc_count": 3000}}}
    elastic = _fake_elastic(a)
    elastic.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=[
            EsSearchResult(total=a["total"], took_ms=1, aggregations=a["aggregations"]),
            EsSearchResult(total=b["total"], took_ms=1, aggregations=b["aggregations"]),
        ]
    )
    page = await aq.fetch_groups(elastic, settings_kratos, time_range="24h")
    assert page.other_docs == 3210, "one aggregation's cap is not the page's"
    assert page.truncated is True


async def test_the_merge_re_cut_is_a_truncation_too(settings_kratos: Settings) -> None:
    """The one cut the grid gives no signal for at all.

    The merged list can hold up to three already-capped aggregations' worth of
    rows, and is trimmed back to one cap here. Those rows WERE returned, so
    ``sum_other_doc_count`` says nothing about them and their documents stay
    inside ``total`` — but they are not on screen, and the page is not the
    whole queue.
    """
    buckets = [
        {
            "key": f"rule-{i:04d}",
            "doc_count": 1,
            "latest_ts": {"value": 1781246460000},
            "latest": {"hits": {"hits": [{"_id": f"id-{i}", "_source": {}}]}},
        }
        for i in range(aq.MAX_GROUPS + 5)
    ]
    payload = {"total": len(buckets), "aggregations": {"rules": {"buckets": buckets}}}
    elastic = _fake_elastic(payload)
    page = await aq.fetch_groups(elastic, _suricata_only(settings_kratos), time_range="24h")
    assert len(page.groups) == aq.MAX_GROUPS
    assert page.truncated is True, "the rows on screen are not the whole queue"
    assert page.other_docs == 0, (
        "these rows came back and were dropped here; their documents are still in total"
    )


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
    page = await aq.fetch_groups(elastic, settings_kratos, time_range="24h")
    groups, total = page.groups, page.total
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
    # src/dst are BARE endpoints (no embedded port): they feed the /entity/<value>
    # pivot, and the frontend renders the destination port once from dst_port.
    assert events[0].src == "10.0.0.41"
    assert events[0].dst == "10.0.0.1"
    assert events[0].dst_port == 443
    assert events[0].severity == "medium"
    assert events[1].src == "—"  # missing fields render as em-dash
    assert events[2].src == "10.0.0.7"
    # rule.name term filter was added
    query = elastic.search.call_args.args[1]
    assert {"term": {"rule.name": "ET SCAN thing"}} in query["bool"]["filter"]


# ── host-shaped detections: the machine lives under event_data ──────────────
#
# Shape taken from a live Security Onion 3.x doc (logs-detections.alerts-so,
# rule "Potential Exploitation of CVE-2024-3094 - Suspicious SSH Child
# Process"): the whole originating endpoint document is nested under
# `event_data`, so there is NO top-level host.* and NO source/destination at
# all. All 27 sigma.alert docs in the prod window matched this shape.
HOST_SHAPED_HITS = {
    "total": 1,
    "hits": [
        {
            "_id": "sigma-host-1",
            "_source": {
                "@timestamp": "2026-08-07T01:10:37.000Z",
                "sigma_level": "high",
                "rule": {"name": "Potential Exploitation of CVE-2024-3094"},
                "event": {"dataset": "sigma.alert", "severity_label": "high"},
                "event_data": {
                    "host": {"name": "test-ubuntu24", "os": {"type": "linux"}},
                    "metadata": {"input": {"beats": {"host": {"ip": "192.168.10.150"}}}},
                },
            },
        }
    ],
}


async def test_fetch_group_events_host_falls_back_to_nested_event_data(
    settings_kratos: Settings,
) -> None:
    """A host-shaped Sigma detection must name its machine, not show "—".

    Reading only top-level ``host.name`` left AlertEvent.host as the em-dash
    placeholder for every endpoint/process detection — the Host column was blank
    for exactly the class SO's host-log shipping is growing.
    """
    elastic = _fake_elastic(HOST_SHAPED_HITS)
    events = await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="Potential Exploitation of CVE-2024-3094"
    )
    assert events[0].host == "test-ubuntu24"


async def test_fetch_group_events_top_level_host_name_still_wins(
    settings_kratos: Settings,
) -> None:
    """Top-level ``host.name`` keeps precedence over the nested fallback.

    On a Suricata alert host.name is the SENSOR name and the grid is read that
    way; the nested endpoint document is only consulted when there is no
    top-level host at all.
    """
    hit = {
        "_id": "both-1",
        "_source": {
            "@timestamp": "2026-08-07T01:10:37.000Z",
            "host": {"name": "so-sensor-1"},
            "event_data": {"host": {"name": "test-ubuntu24"}},
            "event": {"dataset": "suricata.alert", "severity_label": "high"},
        },
    }
    elastic = _fake_elastic({"total": 1, "hits": [hit]})
    events = await aq.fetch_group_events(elastic, settings_kratos, rule_name="ET SENSOR")
    assert events[0].host == "so-sensor-1"


async def test_fetch_group_events_host_ip_is_not_a_flow_endpoint(
    settings_kratos: Settings,
) -> None:
    """The endpoint agent's address rides ``host_ip`` — NEVER src_ip/dst_ip.

    src_ip/dst_ip mean FLOW endpoints and are the cluster key the sweep planner
    and the pair-inheritance lookups key on. Feeding an agent address into them
    would invent a flow that was never observed and desync that key from the
    investigation the recorder writes for these alerts (which carries no flow at
    all), so every sweep would miss its own prior verdict.
    """
    elastic = _fake_elastic(HOST_SHAPED_HITS)
    events = await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="Potential Exploitation of CVE-2024-3094"
    )
    ev = events[0]
    assert ev.host_ip == "192.168.10.150"
    assert ev.src_ip is None
    assert ev.dst_ip is None
    assert ev.src == "—"
    assert ev.dst == "—"


async def test_fetch_group_events_host_ip_prefers_the_endpoint_over_the_shipper(
    settings_kratos: Settings,
) -> None:
    """The nested endpoint address, not the beats input metadata.

    The envelope's ``host.ip`` is the machine the detection fired on;
    ``metadata.input.beats.host.ip`` under the same envelope is whichever box
    shipped the log to the grid, and on a forwarded Windows event log they are
    different machines. Reading only the beats path put the shipper's address on
    the row, and an investigation pulled a host dossier for the shipper believing
    it was the domain controller. The neighbouring name resolver already prefers
    the endpoint's own field; this one never tried it.
    """
    hit = {
        "_id": "sigma-dcsync-1",
        "_source": {
            "@timestamp": "2026-09-04T16:36:12.000Z",
            "rule": {"name": "Active Directory Replication from Non Machine Account"},
            "event": {"dataset": "sigma.alert", "severity_label": "critical"},
            "event_data": {
                "host": {"name": "dc01", "ip": ["192.168.10.11"]},
                "metadata": {"input": {"beats": {"host": {"ip": "192.168.99.5"}}}},
            },
        },
    }
    elastic = _fake_elastic({"total": 1, "hits": [hit]})
    events = await aq.fetch_group_events(elastic, settings_kratos, rule_name="AD Replication")
    assert events[0].host_ip == "192.168.10.11"
    assert events[0].host == "dc01"


async def test_fetch_group_events_host_ip_skips_an_unroutable_first_address(
    settings_kratos: Settings,
) -> None:
    """The envelope's ``host.ip`` is every address the machine claims, in no
    useful order, and the row's address is a live pivot to ``/entity/<ip>``.

    Measured on the range: one endpoint's list is a routable v4, a link-local
    v6 and two container-bridge addresses. Taking position zero blindly would
    hand the analyst a dead pivot the moment the list happens to start with the
    link-local. Loopback and link-local are skipped; nothing else is ranked,
    because a bridge address is still an address that host answers on.
    """
    hit = {
        "_id": "sigma-linklocal-1",
        "_source": {
            "@timestamp": "2026-09-04T16:36:12.000Z",
            "rule": {"name": "SSH login failure"},
            "event": {"dataset": "sigma.alert", "severity_label": "low"},
            "event_data": {
                "host": {"name": "sensor", "ip": ["fe80::be24:11ff:fe45:a75", "192.168.10.46"]}
            },
        },
    }
    elastic = _fake_elastic({"total": 1, "hits": [hit]})
    events = await aq.fetch_group_events(elastic, settings_kratos, rule_name="SSH login failure")
    assert events[0].host_ip == "192.168.10.46"


async def test_fetch_group_events_host_ip_falls_back_to_the_shipper_address(
    settings_kratos: Settings,
) -> None:
    """Negative control for the preference: where the nested endpoint document
    carries no address of its own, the beats path is still better than nothing.

    On an agent that ships its own logs the two are the same machine anyway,
    which is why the fallback was right often enough to hide the bug.
    """
    elastic = _fake_elastic(HOST_SHAPED_HITS)
    events = await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="Potential Exploitation of CVE-2024-3094"
    )
    assert events[0].host_ip == "192.168.10.150"


async def test_fetch_group_events_reads_flow_endpoints_out_of_the_envelope(
    settings_kratos: Settings,
) -> None:
    """A nested detection that DID observe a flow must report it.

    ``source.ip`` under the envelope is a real observed endpoint, not the
    agent's own address, so it belongs in ``src_ip`` — which is where the
    cluster key and the recorded investigation both read it from. While it was
    unread, every one of these events keyed as ``(rule, "", "")`` and the whole
    rule collapsed into a single inheritance cluster for all time.
    """
    hit = {
        "_id": "sigma-flow-1",
        "_source": {
            "@timestamp": "2026-09-07T13:02:04.000Z",
            "rule": {"name": "Grid Node Login Failure (SSH)"},
            "event": {"dataset": "sigma.alert", "severity_label": "high"},
            "event_data": {
                "source": {"ip": "192.0.2.77", "port": 47108},
                "destination": {"ip": "198.51.100.10", "port": 22},
                "host": {"name": "grid-node-01"},
            },
        },
    }
    elastic = _fake_elastic({"total": 1, "hits": [hit]})
    events = await aq.fetch_group_events(
        elastic, settings_kratos, rule_name="Grid Node Login Failure (SSH)"
    )
    ev = events[0]
    assert ev.src_ip == "192.0.2.77"
    assert ev.dst_ip == "198.51.100.10"
    assert ev.dst_port == 22
    assert ev.src == "192.0.2.77"
    assert ev.dst == "198.51.100.10"
    assert ev.host == "grid-node-01"


async def test_fetch_group_events_top_level_endpoints_beat_the_envelope(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. An alert that carries its own endpoints is read exactly
    as before, whatever the envelope says."""
    hit = {
        "_id": "both-endpoints",
        "_source": {
            "@timestamp": "2026-09-07T13:02:04.000Z",
            "source": {"ip": "10.0.0.1"},
            "destination": {"ip": "10.0.0.2", "port": 443},
            "event": {"dataset": "suricata.alert", "severity_label": "high"},
            "event_data": {
                "source": {"ip": "192.0.2.77"},
                "destination": {"ip": "198.51.100.10", "port": 22},
            },
        },
    }
    elastic = _fake_elastic({"total": 1, "hits": [hit]})
    events = await aq.fetch_group_events(elastic, settings_kratos, rule_name="ET FLOW")
    ev = events[0]
    assert ev.src_ip == "10.0.0.1"
    assert ev.dst_ip == "10.0.0.2"
    assert ev.dst_port == 443


async def test_fetch_group_events_host_ip_none_without_an_agent_address(
    settings_kratos: Settings,
) -> None:
    """A flow-shaped alert has no endpoint agent — host_ip stays None rather than
    borrowing one of the flow endpoints."""
    elastic = _fake_elastic(FLAT_HITS)
    events = await aq.fetch_group_events(elastic, settings_kratos, rule_name="ET SCAN thing")
    assert events[0].host_ip is None


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
    await aq.fetch_group_events(elastic, settings_kratos, rule_name="ET TEST", size=25, offset=50)
    kw = elastic.search.call_args.kwargs
    assert kw["size"] == 25
    assert kw["from_"] == 50


# --- alerts that carry no rule.name at all -----------------------------------


def _named_bucket(key: str, count: int, *, ts: str, dataset: str) -> dict[str, Any]:
    return {
        "key": key,
        "doc_count": count,
        "latest_ts": {"value": 1781246460000},
        "latest": {
            "hits": {
                "hits": [
                    {
                        "_id": f"id-{key[:6]}",
                        "_source": {"@timestamp": ts, "event": {"dataset": dataset}},
                    }
                ]
            }
        },
    }


# The measured grid, 2026-09-06: 38 documents matched the shipped default
# filter over 24 hours. 35 of them carry a rule.name (two Elastic Defend
# endpoint rules and the Sigma DCSync rule); 3 are OpenCanary honeypot alerts
# that carry none. A terms aggregation over rule.name buckets the 35 and drops
# the 3, so the console showed 35 in a window the filter says holds 38 — and
# the 3 it dropped are the ones nothing benign on that range touches.
_UNNAMED_AGG: dict[str, Any] = {
    "total": 38,
    "aggregations": {
        "rules": {
            "buckets": [
                _named_bucket(
                    "Execution via Interactive Secondary Logon",
                    17,
                    ts="2026-09-06T09:00:00.000Z",
                    dataset="endpoint.alerts",
                ),
                _named_bucket(
                    "Ingress Tool Transfer via CURL",
                    16,
                    ts="2026-09-06T08:00:00.000Z",
                    dataset="endpoint.alerts",
                ),
                _named_bucket(
                    "Active Directory Replication from Non Machine Account",
                    2,
                    ts="2026-09-05T17:32:18.000Z",
                    dataset="sigma.alert",
                ),
            ]
        },
        "unnamed": {
            "doc_count": 3,
            "rules": {
                "buckets": [
                    _named_bucket(
                        "opencanary.events",
                        3,
                        ts="2026-09-06T07:00:00.000Z",
                        dataset="opencanary.events",
                    )
                ]
            },
        },
    },
}


async def test_fetch_groups_shows_alerts_that_have_no_rule_name(
    settings_kratos: Settings,
) -> None:
    """A document with no bucket produced no row, and the row was the one to read.

    Measured on 2026-09-06: the shipped filter matched 38 documents in 24
    hours and the console could show at most 35, because three OpenCanary
    honeypot alerts carry no ``rule.name`` and a terms aggregation over that
    field has nowhere to put them. On this range a honeypot hit is the one
    surface nothing benign touches, so the alerts the queue silently dropped
    were its highest-signal ones. The counters said so and nobody could tell:
    the doctor counted the filter's matches, the console counted its rows, and
    the two numbers were never compared.
    """
    elastic = _fake_elastic(_UNNAMED_AGG)
    page = await aq.fetch_groups(elastic, _suricata_only(settings_kratos), time_range="24h")
    groups, total = page.groups, page.total
    by_name = {g.rule_name: g for g in groups}
    assert "opencanary.events" in by_name
    unnamed = by_name["opencanary.events"]
    assert unnamed.count == 3
    # Its own kind, not a detector's: the SPA posts this back to fetch the
    # group's events, and every other kind resolves the name against
    # rule.name, which is the field these documents do not have.
    assert unnamed.kind == "unnamed"
    # The reconciliation. Every document the filter matched is now on a row,
    # so the rows add up to the number the doctor and the empty-reason route
    # report for the same window.
    assert total == 38
    assert sum(g.count for g in groups) == total


async def test_fetch_groups_invents_no_unnamed_row_when_every_alert_has_a_name(
    settings_kratos: Settings,
) -> None:
    """The negative control: an empty missing-bucket must stay invisible.

    An always-present "(no rule name)" row would be worse than the bug it
    fixes. It reads as a real detection group, it sits in the queue on every
    grid whose alerts are all named, and an analyst who opens it once and
    finds nothing stops opening it, which is how the genuine one gets skipped
    the day it appears.
    """
    payload: dict[str, Any] = {
        "total": 12,
        "aggregations": {
            "rules": {
                "buckets": [
                    _named_bucket(
                        "ET MALWARE X", 12, ts="2026-09-06T09:00:00.000Z", dataset="suricata.alert"
                    )
                ]
            },
            # What Elasticsearch actually answers when nothing is missing the
            # field: the filter agg is present with a zero doc_count and no
            # buckets under it, NOT absent.
            "unnamed": {"doc_count": 0, "rules": {"buckets": []}},
        },
    }
    elastic = _fake_elastic(payload)
    page = await aq.fetch_groups(elastic, _suricata_only(settings_kratos), time_range="24h")
    groups, total = page.groups, page.total
    assert [g.rule_name for g in groups] == ["ET MALWARE X"]
    assert sum(g.count for g in groups) == total == 12


async def test_fetch_groups_asks_for_the_unnamed_bucket_scoped_to_the_missing_field(
    settings_kratos: Settings,
) -> None:
    """Pin the aggregation, since the fixture above cannot prove ES was asked.

    A test that only reads buckets out of a canned response passes whether or
    not the request that would produce them was ever sent.
    """
    elastic = _fake_elastic(_UNNAMED_AGG)
    await aq.fetch_groups(elastic, _suricata_only(settings_kratos), time_range="24h")
    aggs = elastic.search.call_args.kwargs["aggs"]
    unnamed = aggs["unnamed"]
    assert unnamed["filter"] == {"bool": {"must_not": [{"exists": {"field": "rule.name"}}]}}
    # Grouped by the dataset that produced them, which is the most specific
    # thing true of a document with no rule name, with a bucket of last resort
    # for one that has no dataset either. Same sub-aggregations as a named
    # group so the row is not a second-class one.
    terms = unnamed["aggs"]["rules"]["terms"]
    assert terms["field"] == "event.dataset"
    assert terms["missing"] == aq.UNKNOWN_DATASET
    assert set(unnamed["aggs"]["rules"]["aggs"]) == set(aggs["rules"]["aggs"])


async def test_fetch_group_events_unnamed_kind_filters_the_dataset_not_the_rule_name(
    settings_kratos: Settings,
) -> None:
    """Expanding the row has to find the documents the row counted.

    The name on an unnamed group is a dataset, so resolving it against
    rule.name (what every other kind does) matches nothing and the row expands
    to an empty list — a group that says 3 and shows 0.
    """
    elastic = _fake_elastic(FLAT_HITS)
    await aq.fetch_group_events(
        elastic,
        settings_kratos,
        rule_name="opencanary.events",
        kind="unnamed",
        time_range="24h",
    )
    query = elastic.search.call_args.args[1]
    assert {"term": {"event.dataset": "opencanary.events"}} in query["bool"]["filter"]
    assert {"exists": {"field": "rule.name"}} in query["bool"]["must_not"]
    assert not any("rule.name" in c.get("term", {}) for c in query["bool"]["filter"])


async def test_fetch_group_events_unnamed_kind_bucket_of_last_resort(
    settings_kratos: Settings,
) -> None:
    """The sentinel key is a placeholder for an absent field, not a value.

    Filtering ``event.dataset`` for the literal text of the placeholder would
    match nothing, which is the same empty-row failure one level down.
    """
    elastic = _fake_elastic(FLAT_HITS)
    await aq.fetch_group_events(
        elastic,
        settings_kratos,
        rule_name=aq.UNKNOWN_DATASET,
        kind="unnamed",
        time_range="24h",
    )
    must_not = elastic.search.call_args.args[1]["bool"]["must_not"]
    assert {"exists": {"field": "rule.name"}} in must_not
    assert {"exists": {"field": "event.dataset"}} in must_not


# --- widening the operator's alerts filter rather than replacing it ----------


def test_the_generic_alert_kind_selects_the_same_documents_suricata_does(
    settings_kratos: Settings,
) -> None:
    """Defect 3, the write question: could the wrong kind land an ack somewhere
    else?

    ``kind`` is not cosmetic. It is posted back when a group is expanded or
    acknowledged, and it picks the source scope and the name field the write is
    resolved against. But :func:`_group_query` branches on exactly two values,
    ``notice`` and ``unnamed``; everything else takes the same rule.name-scoped
    default. So a group mislabelled ``suricata`` when it was really the generic
    ``alert`` resolved to a byte-identical query, and no acknowledge or escalate
    ever landed on a document set the analyst had not seen. Pinned here because
    it stops being true the moment anyone gives a third kind its own branch, and
    at that point a coercion upstream would silently redirect a write.
    """
    kwargs: dict[str, Any] = {
        "rule_name": "Ingress Tool Transfer via CURL",
        "time_range": "24h",
        "severity": None,
        "oql": None,
        "abs_from": None,
        "abs_to": None,
        "time_zone": None,
        "hide_acked": True,
    }
    generic = aq._group_query(settings_kratos, kind="alert", **kwargs)
    suricata = aq._group_query(settings_kratos, kind="suricata", **kwargs)
    assert generic == suricata
    # The two kinds that DO branch are still different, or the equality above
    # would be proving nothing.
    assert aq._group_query(settings_kratos, kind="notice", **kwargs) != suricata
    assert aq._group_query(settings_kratos, kind=aq.UNNAMED_KIND, **kwargs) != suricata


def test_widen_alert_filter_is_a_superset_of_a_compound_filter() -> None:
    """No parentheses, and none needed: OR is OQL's lowest-precedence operator.

    The output gets pasted into a config field, so it stays readable. That is
    only safe if ``a AND b OR c`` groups as ``(a AND b) OR c``; if OQL ever
    bound OR tighter than AND, this widening would silently NARROW a compound
    filter to ``a AND (b OR c)``. Proven on the compiled DSL rather than on the
    string, because the string is not what queries the grid.
    """
    widened = aq.widen_alert_filter("tags:alert AND host.name:sensor01", "event.kind:alert")
    assert widened == "tags:alert AND host.name:sensor01 OR event.kind:alert"
    dsl = filter_to_dsl(parse_oql(widened).filter_)
    should = dsl["bool"]["should"]
    assert dsl["bool"]["minimum_should_match"] == 1
    assert {"term": {"event.kind": "alert"}} in should
    # The operator's whole compound filter survives as one branch of the OR,
    # not as a term the new label was ANDed against.
    assert {
        "bool": {"must": [{"term": {"tags": "alert"}}, {"term": {"host.name": "sensor01"}}]}
    } in should


def test_widen_alert_filter_leaves_nothing_to_widen_alone() -> None:
    """A feed that already sees everything, or an addition that adds nothing.

    ``*`` and the empty string both mean "no source scope" to
    :func:`~soc_ai.webui.alerts_query.build_filter`, so ORing a label onto
    them would narrow the feed to that label. The already-present case matters
    for the same reason in reverse: a hint that reads ``tags:alert OR
    tags:alert`` is a hint an operator distrusts.
    """
    assert aq.widen_alert_filter("*", "event.kind:alert") == "event.kind:alert"
    assert aq.widen_alert_filter("", "event.kind:alert") == "event.kind:alert"
    assert aq.widen_alert_filter("tags:alert", "") == "tags:alert"
    assert aq.widen_alert_filter("tags:alert", "tags:alert") == "tags:alert"


def test_shipped_default_is_the_union_of_its_named_labels() -> None:
    """The default and the labels two surfaces recommend cannot drift apart.

    ``DEFAULT_ALERT_LABELS`` is what the doctor and the empty-queue hint prefer
    on a tie; ``DEFAULT_ALERTS_QUERY`` is what a fresh install runs. If someone
    edits one, this says so.
    """
    assert Settings.model_fields["webui_alerts_query"].default == DEFAULT_ALERTS_QUERY
    should = filter_to_dsl(parse_oql(DEFAULT_ALERTS_QUERY).filter_)["bool"]["should"]
    assert should == [filter_to_dsl(parse_oql(label).filter_) for label in DEFAULT_ALERT_LABELS]
    # Every default label is one the doctor actually counts, or the row could
    # recommend a label it has no number for.
    assert set(DEFAULT_ALERT_LABELS) <= set(aq.ALERT_LABEL_CANDIDATES)
