"""Tests for scripts/demo/mock_es.py FIXTURES MODE (the demo-container path).

Dataset mode (the screenshot harness) is exercised end-to-end by the browser
smoke; these cover the docs-mode ``_search`` contract the public demo serves
from the ``alerts[]`` section of a packaged soc_ai/demo/fixtures.json.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from scripts.demo import mock_es
from scripts.demo.mock_es import (
    DETECTION_FIXTURE_DOCS,
    _search_response_from_docs,
    load_fixture_docs,
)


def _doc(
    doc_id: str,
    *,
    rule: str | None = None,
    notice: str | None = None,
    ts: str = "2026-07-10T12:00:00.000Z",
    acked: bool = False,
    escalated: bool = False,
) -> dict:
    source: dict = {
        "@timestamp": ts,
        "event": {
            "dataset": "zeek.notice" if notice else "suricata.alert",
            "severity_label": "low",
            "acknowledged": acked,
            "escalated": escalated,
        },
        "source": {"ip": "192.0.2.10", "port": 49001},
        "destination": {"ip": "198.51.100.20", "port": 443},
    }
    if rule:
        source["rule"] = {"name": rule}
    if notice:
        source["notice"] = {"note": notice}
    return {"_index": "logs-demo", "_id": doc_id, "_source": source}


DOCS = [
    _doc("a1", rule="ET MALWARE Beacon", ts="2026-07-10T12:00:00.000Z"),
    _doc("a2", rule="ET MALWARE Beacon", ts="2026-07-10T13:00:00.000Z"),
    _doc("a3", rule="ET INFO Lookup", ts="2026-07-09T08:00:00.000Z", acked=True),
    _doc("n1", notice="ATTACK_DISCOVERY", ts="2026-07-10T09:00:00.000Z"),
]

_RULES_AGG_BODY = {"size": 0, "aggs": {"rules": {"terms": {"field": "rule.name"}}}}
_NOTICE_AGG_BODY = {"size": 0, "aggs": {"rules": {"terms": {"field": "notice.note"}}}}
_HIDE_ACKED = {"bool": {"must_not": [{"term": {"event.acknowledged": True}}]}}


def test_rules_agg_groups_counts_and_orders_newest_first():
    resp = _search_response_from_docs(_RULES_AGG_BODY, DOCS)
    buckets = resp["aggregations"]["rules"]["buckets"]
    assert [b["key"] for b in buckets] == ["ET MALWARE Beacon", "ET INFO Lookup"]
    beacon, lookup = buckets
    assert beacon["doc_count"] == 2
    assert beacon["latest"]["hits"]["hits"][0]["_id"] == "a2"  # newest member
    assert beacon["acked"]["doc_count"] == 0
    assert lookup["doc_count"] == 1
    assert lookup["acked"]["doc_count"] == 1
    # The total counts every match, as real ES does. The notice doc has no
    # rule.name, so it makes no bucket, but the query matches it.
    assert resp["hits"]["total"]["value"] == 4


def test_rules_agg_hides_acked_groups_when_asked():
    resp = _search_response_from_docs({**_RULES_AGG_BODY, "query": _HIDE_ACKED}, DOCS)
    buckets = resp["aggregations"]["rules"]["buckets"]
    assert [b["key"] for b in buckets] == ["ET MALWARE Beacon"]


def test_notice_agg_groups_by_note():
    resp = _search_response_from_docs(_NOTICE_AGG_BODY, DOCS)
    buckets = resp["aggregations"]["rules"]["buckets"]
    assert [b["key"] for b in buckets] == ["ATTACK_DISCOVERY"]
    assert buckets[0]["doc_count"] == 1


def test_ids_lookup_returns_acked_state_and_drops_unknown_ids():
    body = {"query": {"ids": {"values": ["a3", "a1", "no-such-doc"]}}}
    resp = _search_response_from_docs(body, DOCS)
    hits = {h["_id"]: h["_source"]["event"]["acknowledged"] for h in resp["hits"]["hits"]}
    assert hits == {"a3": True, "a1": False}


def test_flat_listing_newest_first_with_size_cap_and_true_total():
    term = {"term": {"rule.name": "ET MALWARE Beacon"}}
    body = {"size": 1, "query": {"bool": {"filter": [term]}}}
    resp = _search_response_from_docs(body, DOCS)
    assert resp["hits"]["total"]["value"] == 2  # total counts matches, not the page
    assert [h["_id"] for h in resp["hits"]["hits"]] == ["a2"]


def test_unrecognized_query_is_empty_not_an_error():
    resp = _search_response_from_docs({"query": {"match_all": {}}}, DOCS)
    assert resp["hits"]["hits"] == []


def test_search_docs_rebased_to_now():
    """Every served doc's @timestamp is shifted so the newest lands at 'now',
    keeping the demo grid perpetually current — without mutating the input docs."""
    old = "2026-07-01T00:00:00.000Z"
    docs = [
        {"_index": "logs-demo", "_id": "a", "_source": {"@timestamp": old, "rule": {"name": "R"}}},
    ]
    body = {"size": 10, "query": {"bool": {"filter": [{"term": {"rule.name": "R"}}]}}}
    resp = _search_response_from_docs(body, docs)
    hits = resp["hits"]["hits"]
    ts = hits[0]["_source"]["@timestamp"]
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert (datetime.now(UTC) - parsed).total_seconds() < 300
    # The input docs are copied, never mutated in place.
    assert docs[0]["_source"]["@timestamp"] == old


def test_search_docs_rebase_preserves_relative_ordering():
    """Rebasing shifts every doc by the same delta, so the newest bucket member
    and the flat-listing order are unchanged (only the absolute times move)."""
    resp = _search_response_from_docs(_RULES_AGG_BODY, DOCS)
    beacon = resp["aggregations"]["rules"]["buckets"][0]
    assert beacon["latest"]["hits"]["hits"][0]["_id"] == "a2"  # still the newest member
    # DOCS untouched by the per-request rebase.
    assert [d["_source"]["@timestamp"] for d in DOCS] == [
        "2026-07-10T12:00:00.000Z",
        "2026-07-10T13:00:00.000Z",
        "2026-07-09T08:00:00.000Z",
        "2026-07-10T09:00:00.000Z",
    ]


def test_load_fixture_docs_reads_alerts_section(tmp_path: Path):
    fx = tmp_path / "fixtures.json"
    fx.write_text(json.dumps({"version": 1, "alerts": DOCS, "investigations": []}))
    assert [d["_id"] for d in load_fixture_docs(fx)] == ["a1", "a2", "a3", "n1"]


def test_load_fixture_docs_missing_file_is_fail_soft(tmp_path: Path):
    assert load_fixture_docs(tmp_path / "absent.json") == []


def test_load_fixture_docs_invalid_json_is_fail_soft(tmp_path: Path):
    fx = tmp_path / "fixtures.json"
    fx.write_text("{not json")
    assert load_fixture_docs(fx) == []


# ---------------------------------------------------------------------------
# Generic aggregation + count/hit matching (detection-bridge slice, Task 8).
#
# Beyond the two hardcoded Alerts-console aggs, the mock now answers the request
# shapes the detection bridge (dry_run_detection's `| count` / `| head`) and the
# slice-2 analytics tools (+ resolve_agg_field's exists probe) issue against the
# DETECTION_FIXTURE_DOCS. These assert the mock's response CONTRACT for those
# shapes; test_detection_bridge_e2e.py drives the real producers through it.
# ---------------------------------------------------------------------------

# The Zerologon draft's OQL, translated to ES DSL and wrapped exactly as
# query_events_oql wraps it (must=[filter expr], filter=[time], must_not=[synth]).
# `dce_rpc.operation` lives under `zeek.*` because the OQL whitelist admits only
# that form (see the fixture docstring).
_TIME_FILTER = {"range": {"@timestamp": {"gte": "now-43200m", "lte": "now"}}}
_SYNTH_KILL = {"exists": {"field": "synth.scenario_id"}}
_ZEROLOGON_OPS = {
    "bool": {
        "must": [
            {"term": {"event.dataset": "zeek.dce_rpc"}},
            {
                "bool": {
                    "should": [
                        {"term": {"zeek.dce_rpc.operation": "NetrServerAuthenticate3"}},
                        {"term": {"zeek.dce_rpc.operation": "NetrServerReqChallenge"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        ]
    }
}


def _wrapped(inner: dict) -> dict:
    return {"bool": {"must": [inner], "filter": [_TIME_FILTER], "must_not": [_SYNTH_KILL]}}


def test_generic_terms_agg_dispatches_on_any_named_field():
    """Not just rule.name/notice.note: a terms agg groups by whatever field it
    names. dce_rpc.operation resolves to the whitelisted zeek.* form."""
    for field, expected in [
        (
            "zeek.dce_rpc.operation",
            {"NetrServerAuthenticate3": 8, "NetrLogonSamLogonEx": 4, "NetrServerReqChallenge": 3},
        ),
        ("destination.ip", {"192.0.2.10": 16, "192.0.2.53": 4, "203.0.113.77": 3}),
    ]:
        body = {"size": 0, "query": {"match_all": {}}, "aggs": {"g": {"terms": {"field": field}}}}
        resp = _search_response_from_docs(body, DETECTION_FIXTURE_DOCS)
        counts = {b["key"]: b["doc_count"] for b in resp["aggregations"]["g"]["buckets"]}
        for key, n in expected.items():
            assert counts.get(key) == n, (field, key)

    # dns.query.name groups each distinct qname (one doc apiece here).
    body = {
        "size": 0,
        "query": {"terms": {"event.dataset": ["zeek.dns"]}},
        "aggs": {"q": {"terms": {"field": "dns.query.name", "size": 200}}},
    }
    resp = _search_response_from_docs(body, DETECTION_FIXTURE_DOCS)
    keys = {b["key"] for b in resp["aggregations"]["q"]["buckets"]}
    assert "www.example.test" in keys and "api.example.test" in keys


def test_terms_agg_carries_nested_top_hits_and_sub_terms():
    """The nested sub-aggs the histogram/beacon tools rely on: a per-bucket
    top_hits (citable _ids) and a source.ip sub-terms (peer attribution)."""
    body = {
        "size": 0,
        "query": _wrapped({"term": {"event.dataset": "zeek.dce_rpc"}}),
        "aggs": {
            "ops": {
                "terms": {"field": "zeek.dce_rpc.operation", "size": 100},
                "aggs": {
                    "sample": {"top_hits": {"size": 3}},
                    "sources": {"terms": {"field": "source.ip", "size": 5}},
                },
            }
        },
    }
    resp = _search_response_from_docs(body, DETECTION_FIXTURE_DOCS)
    buckets = {b["key"]: b for b in resp["aggregations"]["ops"]["buckets"]}
    auth = buckets["NetrServerAuthenticate3"]
    assert auth["doc_count"] == 8
    sample_ids = [h["_id"] for h in auth["sample"]["hits"]["hits"]]
    assert len(sample_ids) == 3
    assert all(s.startswith("zl-dce") for s in sample_ids)
    assert [b["key"] for b in auth["sources"]["buckets"]] == ["198.51.100.23"]


def test_count_query_returns_a_real_matching_total():
    """dry_run_detection's `| count`: size=0, no aggs → the real number of docs
    the drafted rule would have fired on (the malicious ops only, not benign)."""
    body = {"query": _wrapped(_ZEROLOGON_OPS), "size": 0, "track_total_hits": 10000}
    resp = _search_response_from_docs(body, DETECTION_FIXTURE_DOCS)
    assert resp["hits"]["total"]["value"] == 11  # 8 Authenticate3 + 3 ReqChallenge
    assert resp["hits"]["hits"] == []


def test_exists_probe_counts_field_presence_like_resolve_agg_field():
    """resolve_agg_field probes each candidate with a size=0 exists count; only
    the field the docs actually carry comes back non-zero."""

    def _total(field: str) -> int:
        body = {"query": {"exists": {"field": field}}, "size": 0}
        return _search_response_from_docs(body, DETECTION_FIXTURE_DOCS)["hits"]["total"]["value"]

    assert _total("zeek.dce_rpc.operation") == 16  # the form the docs carry
    assert _total("dce_rpc.operation") == 0  # the ECS form is absent → probe moves on


def test_head_query_returns_matching_docs_newest_first():
    """dry_run_detection's `| head 5`: size>0 bool query → the matching docs,
    newest first, capped to size — the sample-id evidence the dry run cites."""
    body = {"query": _wrapped(_ZEROLOGON_OPS), "size": 5}
    resp = _search_response_from_docs(body, DETECTION_FIXTURE_DOCS)
    ids = [h["_id"] for h in resp["hits"]["hits"]]
    assert len(ids) == 5
    assert all(s.startswith("zl-dce") for s in ids)
    assert resp["hits"]["total"]["value"] == 11  # total counts matches, not the page


def test_matchall_without_size_still_answers_empty():
    """The unknown-query contract is unchanged: a bare match_all is not matched
    doc-by-doc, so it answers empty rather than dumping the whole fixture."""
    resp = _search_response_from_docs({"query": {"match_all": {}}}, DETECTION_FIXTURE_DOCS)
    assert resp["hits"]["hits"] == []


# ---------------------------------------------------------------------------
# Degraded-grid control endpoint. The security constraint is the test: this file
# also serves the PUBLIC demo container, where an unauthenticated switch into a
# fabricated Security Onion outage would let any visitor break the demo for
# everyone else. The endpoint must not exist unless --degraded-control was
# passed, and the four states must present the way real Elasticsearch does,
# because the app's guards key off the transport/HTTP shape.
# ---------------------------------------------------------------------------


@contextmanager
def _serving() -> Iterator[str]:
    """The real handler on a loopback ephemeral port; yields the base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), mock_es.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _post(url: str) -> tuple[int, str]:
    req = urllib.request.Request(url, data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, resp.read().decode()


def test_control_endpoint_is_absent_unless_the_flag_was_passed():
    """THE security invariant: no --degraded-control, no way in.

    The public demo container runs this file WITHOUT the flag, so a visitor
    posting to /__degrade must get the same "unknown path" answer as any other
    made-up URL — never a state switch. Asserted against the real handler rather
    than against the routing expression, so a refactor that mounts the endpoint
    unconditionally fails here instead of shipping.
    """
    assert mock_es.CONTROL_ENABLED is False, "the flag must default to OFF"
    with _serving() as base:
        status, body = _post(f"{base}/__degrade/down")
        assert (status, json.loads(body)) == (200, {"acknowledged": True})
        assert mock_es.degrade_state() == "healthy", "an unmounted route changed state"


def test_control_endpoint_switches_state_when_the_flag_is_on(monkeypatch):
    monkeypatch.setattr(mock_es, "CONTROL_ENABLED", True)
    try:
        with _serving() as base:
            status, body = _post(f"{base}/__degrade/half-read")
            assert status == 200
            assert json.loads(body)["state"] == "half-read"
            assert mock_es.degrade_state() == "half-read"
            # An unknown state is rejected, not silently accepted as healthy.
            with pytest.raises(urllib.error.HTTPError) as err:
                _post(f"{base}/__degrade/bananas")
            assert err.value.code == 400
    finally:
        mock_es.set_degrade_state("healthy")


def test_degraded_states_are_the_documented_five():
    assert mock_es.DEGRADE_STATES == ("healthy", "down", "half-read", "saturated", "stalled")


def test_half_read_is_a_200_that_hides_failed_shards():
    """The sneakiest state: no exception, no error status — only `_shards`."""
    body = mock_es.half_read_response()
    assert body["timed_out"] is True
    assert body["_shards"]["failed"] == 2
    assert body["_shards"]["successful"] == 2
    assert body["_shards"]["total"] == 4
    assert len(body["_shards"]["failures"]) == 2
    # Zero hits on purpose — the shape a quiet, healthy grid also returns.
    assert body["hits"]["hits"] == []
    assert body["hits"]["total"]["value"] == 0


def test_id_sort_is_rejected_like_a_real_es9_cluster():
    """Regression for the audit-verify fix (soc_ai/audit/verify.py, found 2026-08-20).

    `_fetch_audit_records`'s `search_after` tiebreak used to sort on `_id`, which a
    real ES 9 grid refuses (`indices.id_field_data.enabled=false`) on every
    data-bearing shard. This mock answers `_search` for ANY index — including
    `soc-ai-audit-*`, which `soc-ai audit verify` hits directly against the demo
    stack — so it has to mirror that refusal unconditionally, not just under an
    opt-in degraded state, or a reintroduced `_id` sort would silently pass here.
    """
    id_sort_body = {"sort": [{"seq": {"order": "asc"}}, {"_id": {"order": "asc"}}]}
    rejected = mock_es.id_sort_rejected_response(id_sort_body)
    assert rejected is not None
    assert rejected["_shards"]["failed"] == 58
    assert rejected["_shards"]["failures"][0]["reason"]["type"] == "illegal_argument_exception"
    assert rejected["hits"]["hits"] == []

    timestamp_sort_body = {"sort": [{"seq": {"order": "asc"}}, {"timestamp": {"order": "asc"}}]}
    assert mock_es.id_sort_rejected_response(timestamp_sort_body) is None
    assert mock_es.id_sort_rejected_response({}) is None


def test_saturated_is_a_retryable_circuit_breaker_not_a_bad_query():
    body = mock_es.saturated_response()
    assert body["status"] == 429
    assert body["error"]["type"] == "circuit_breaking_exception"
    assert body["error"]["durability"] == "TRANSIENT"
    assert body["error"]["root_cause"][0]["type"] == "circuit_breaking_exception"


def test_set_degrade_state_round_trips_and_releases_the_tarpit():
    """Switching state must wake anything parked in `stalled`, or the next
    screen queues behind an outage that is already over."""
    released = threading.Event()

    def parked() -> None:
        mock_es._state_changed.wait(10)
        released.set()

    try:
        mock_es.set_degrade_state("stalled")
        t = threading.Thread(target=parked, daemon=True)
        t.start()
        time.sleep(0.1)
        assert mock_es.degrade_state() == "stalled"
        mock_es.set_degrade_state("healthy")
        assert released.wait(10), "a state change did not release the stalled waiter"
        assert mock_es.degrade_state() == "healthy"
    finally:
        mock_es.set_degrade_state("healthy")


# ---------------------------------------------------------------------------
# The demo refresh: fixture version 2 and a faithful query engine.
#
# Every console page of the public demo reads the mock. The tests below drive
# the request shapes those pages send, most of them built by the producer's
# own builder, so a producer change that the mock cannot answer fails here.
# Times are seeded relative to now.
# ---------------------------------------------------------------------------

_SYNTH_MUST_NOT = [
    {"exists": {"field": "synth.scenario_id"}},
    {"exists": {"field": "event_data.synth.scenario_id"}},
]


def _iso_at(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _ago(**delta: float) -> str:
    return _iso_at(datetime.now(UTC) - timedelta(**delta))


def _alert(
    doc_id: str,
    *,
    hours_ago: float,
    rule: str | None = None,
    notice: str | None = None,
    dataset: str | None = None,
    src: str = "192.0.2.10",
    dst: str = "198.51.100.20",
    port: int = 443,
    cid: str | None = None,
    acked: bool = False,
    escalated: bool = False,
) -> dict:
    source: dict = {
        "@timestamp": _ago(hours=hours_ago),
        "tags": ["alert"],
        "event": {
            "kind": "alert",
            "dataset": dataset or ("zeek.notice" if notice else "suricata.alert"),
            "severity_label": "high",
            "acknowledged": acked,
            "escalated": escalated,
        },
        "source": {"ip": src, "port": 49001},
        "destination": {"ip": dst, "port": port},
        "network": {"community_id": cid or f"1:{doc_id}"},
        "host": {"name": "sensor-01"},
        "observer": {"name": "sensor-01"},
    }
    if rule:
        source["rule"] = {"name": rule}
    if notice:
        source["notice"] = {"note": notice}
    return {"_index": "logs-demo", "_id": doc_id, "_source": source}


def _feed_query(window: str = "now-24h", *, hide_acked: bool = False) -> dict:
    """The alert feed query fetch_groups sends (captured from the demo)."""
    flt: list[dict] = [{"range": {"@timestamp": {"gte": window}}}]
    if hide_acked:
        flt.append(
            {
                "bool": {
                    "must_not": [
                        {"term": {"event.acknowledged": True}},
                        {"term": {"event.escalated": True}},
                    ]
                }
            }
        )
    alert_sources = {
        "bool": {
            "should": [
                {
                    "bool": {
                        "should": [{"term": {"tags": "alert"}}, {"term": {"event.kind": "alert"}}],
                        "minimum_should_match": 1,
                    }
                },
                {"term": {"event.dataset": "sigma.alert"}},
            ],
            "minimum_should_match": 1,
        }
    }
    return {"bool": {"must": [alert_sources], "filter": flt, "must_not": list(_SYNTH_MUST_NOT)}}


def _grouped_body(window: str = "now-24h", *, hide_acked: bool = False) -> dict:
    from soc_ai.webui.alerts_query import _group_aggs

    return {
        "query": _feed_query(window, hide_acked=hide_acked),
        "size": 0,
        "aggs": _group_aggs("count", include_unnamed=True, escalated_ids=True),
        "track_total_hits": True,
    }


GRID = [
    _alert("b1", hours_ago=1, rule="ET MALWARE Beacon", src="192.0.2.10"),
    _alert("b2", hours_ago=2, rule="ET MALWARE Beacon", src="192.0.2.11", escalated=True),
    _alert("b3", hours_ago=3, rule="ET MALWARE Beacon", src="192.0.2.10", acked=True),
    _alert("s1", hours_ago=9, rule="ET SCAN Nmap", src="203.0.113.5"),
    _alert("old", hours_ago=5 * 24, rule="ET POLICY Old Lookup"),
    _alert("hp1", hours_ago=4, dataset="opencanary"),
]


def test_grouped_path_drops_alerts_outside_the_window():
    """A last 24 hours view must not list a five-day-old alert."""
    resp = _search_response_from_docs(_grouped_body("now-24h"), GRID)
    keys = [b["key"] for b in resp["aggregations"]["rules"]["buckets"]]
    assert keys == ["ET MALWARE Beacon", "ET SCAN Nmap"]
    assert resp["hits"]["total"]["value"] == 5  # the unnamed honeypot alert counts too
    unnamed = resp["aggregations"]["unnamed"]["rules"]["buckets"]
    assert [(b["key"], b["doc_count"]) for b in unnamed] == [("opencanary", 1)]
    # A seven-day view lists it.
    week = _search_response_from_docs(_grouped_body("now-7d"), GRID)
    assert "ET POLICY Old Lookup" in [b["key"] for b in week["aggregations"]["rules"]["buckets"]]


def test_grouped_path_answers_the_request_sub_aggs_per_bucket():
    resp = _search_response_from_docs(_grouped_body("now-24h"), GRID)
    beacon = resp["aggregations"]["rules"]["buckets"][0]
    assert beacon["doc_count"] == 3
    assert beacon["sources"] == {"value": 2}
    assert beacon["datasets"]["buckets"] == [{"key": "suricata.alert", "doc_count": 3}]
    assert beacon["acked"]["doc_count"] == 1
    assert beacon["escalated"]["doc_count"] == 1
    assert [h["_id"] for h in beacon["escalated"]["ids"]["hits"]["hits"]] == ["b2"]
    assert "_source" not in beacon["escalated"]["ids"]["hits"]["hits"][0]  # _source: false
    latest = beacon["latest"]["hits"]["hits"][0]
    assert latest["_id"] == "b1"
    # The latest hit carries only the requested _source fields.
    kept = {"@timestamp", "event", "source", "destination", "host", "observer"}
    assert set(latest["_source"]) <= kept
    assert "tags" not in latest["_source"]
    assert latest["_source"]["event"] == {"severity_label": "high", "dataset": "suricata.alert"}
    assert beacon["latest_ts"]["value_as_string"] == latest["_source"]["@timestamp"]


def test_grouped_path_hides_handled_alerts_only_when_asked():
    """The All view keeps an acknowledged alert; the hide view drops acked and escalated."""
    every = _search_response_from_docs(_grouped_body("now-24h"), GRID)
    assert every["aggregations"]["rules"]["buckets"][0]["doc_count"] == 3
    hidden = _search_response_from_docs(_grouped_body("now-24h", hide_acked=True), GRID)
    beacon = hidden["aggregations"]["rules"]["buckets"][0]
    assert beacon["key"] == "ET MALWARE Beacon"
    assert beacon["doc_count"] == 1  # b2 escalated and b3 acked are hidden


def test_grouped_buckets_come_newest_first():
    docs = [
        _alert("x1", hours_ago=6, rule="Busy"),
        _alert("x2", hours_ago=7, rule="Busy"),
        _alert("y1", hours_ago=1, rule="Recent"),
    ]
    resp = _search_response_from_docs(_grouped_body("now-24h"), docs)
    assert [b["key"] for b in resp["aggregations"]["rules"]["buckets"]] == ["Recent", "Busy"]


def test_notice_aggregation_reads_the_wildcard_scope():
    query = {
        "bool": {
            "must": [
                {
                    "bool": {
                        "must": [
                            {"term": {"event.dataset": "zeek.notice"}},
                            {"wildcard": {"notice.note": {"value": "ATTACK*"}}},
                        ]
                    }
                }
            ],
            "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}],
            "must_not": list(_SYNTH_MUST_NOT),
        }
    }
    docs = [
        _alert("n1", hours_ago=1, notice="ATTACK::Discovery"),
        _alert("n2", hours_ago=2, notice="Scan::Port_Scan"),
    ]
    body = {"query": query, "size": 0, "aggs": {"rules": {"terms": {"field": "notice.note"}}}}
    resp = _search_response_from_docs(body, docs)
    assert [b["key"] for b in resp["aggregations"]["rules"]["buckets"]] == ["ATTACK::Discovery"]


def test_range_filter_drops_an_old_doc():
    docs = [_alert("new", hours_ago=1, rule="R"), _alert("old", hours_ago=72, rule="R")]

    def ids(rng: dict) -> list[str]:
        body = {"query": {"bool": {"filter": [{"range": {"@timestamp": rng}}]}}, "size": 10}
        return [h["_id"] for h in mock_es.search_docs(body, docs)["hits"]["hits"]]

    assert ids({"gte": "now-24h"}) == ["new"]
    assert ids({"gte": "now-1440m", "lte": "now"}) == ["new"]
    assert ids({"lt": "now-24h"}) == ["old"]
    assert ids({"gte": "now-7d"}) == ["new", "old"]
    assert ids({"gte": "now+1h"}) == []
    cut = datetime.now(UTC) - timedelta(hours=2)
    assert ids({"gt": _iso_at(cut)}) == ["new"]
    assert ids({"lte": int(cut.timestamp() * 1000)}) == ["old"]
    assert ids({"gte": cut.strftime("%Y-%m-%dT%H:%M:%S")}) == ["new"]  # naive means UTC
    assert ids({"format": "strict_date_optional_time"}) == ["new", "old"]  # no bound: true


def test_date_math_rounds_down_for_gte_and_up_for_lte():
    now = datetime(2026, 10, 22, 15, 30, 12, tzinfo=UTC)
    start_of_yesterday = datetime(2026, 10, 21, tzinfo=UTC).timestamp() * 1000
    end_of_yesterday = datetime(2026, 10, 22, tzinfo=UTC).timestamp() * 1000 - 1
    assert mock_es._date_ms("now-1d/d", now) == start_of_yesterday
    assert mock_es._date_ms("now-1d/d", now, round_up=True) == end_of_yesterday
    assert mock_es._date_ms("now-30d", now) == (now - timedelta(days=30)).timestamp() * 1000
    assert mock_es._date_ms("2026-10-01T00:00:00Z||+1M", now) == (
        datetime(2026, 11, 1, tzinfo=UTC).timestamp() * 1000
    )
    assert mock_es._date_ms("now/w", now) == datetime(2026, 10, 19, tzinfo=UTC).timestamp() * 1000
    assert mock_es._date_ms("1700000000000", now) == 1700000000000.0
    assert mock_es._date_ms("not a date", now) is None


def test_range_on_a_numeric_field_compares_numbers():
    docs = [
        _alert("p443", hours_ago=1, rule="R", port=443),
        _alert("p8080", hours_ago=1, rule="R", port=8080),
    ]
    # The OQL translator sends the bounds as strings.
    body = {"query": {"range": {"destination.port": {"gte": "1", "lte": "1024"}}}, "size": 10}
    assert [h["_id"] for h in mock_es.search_docs(body, docs)["hits"]["hits"]] == ["p443"]


def test_ids_inside_bool_returns_the_full_source():
    """The citation drawer reads one event through get_event_raw's query shape."""
    body = {
        "query": {"bool": {"must": [{"ids": {"values": ["b2"]}}], "must_not": _SYNTH_MUST_NOT}},
        "size": 1,
    }
    resp = _search_response_from_docs(body, GRID)
    hits = resp["hits"]["hits"]
    assert [h["_id"] for h in hits] == ["b2"]
    assert hits[0]["_source"]["rule"]["name"] == "ET MALWARE Beacon"
    assert hits[0]["_source"]["network"]["community_id"] == "1:b2"


def test_wildcard_prefix_and_multi_match_clauses():
    docs = [
        _alert("n1", hours_ago=1, notice="ATTACK::Discovery"),
        _alert("n2", hours_ago=2, notice="attack::lateral"),
        _alert("n3", hours_ago=3, notice="Scan::Port_Scan"),
    ]

    def ids(clause: dict) -> list[str]:
        resp = mock_es.search_docs({"query": clause, "size": 10}, docs)
        return [h["_id"] for h in resp["hits"]["hits"]]

    assert ids({"wildcard": {"notice.note": {"value": "ATTACK*"}}}) == ["n1"]
    assert ids({"wildcard": {"notice.note": "ATTACK*"}}) == ["n1"]
    assert ids({"wildcard": {"notice.note": {"value": "attack*", "case_insensitive": True}}}) == [
        "n1",
        "n2",
    ]
    assert ids({"wildcard": {"notice.note": "Scan::Port_Sca?"}}) == ["n3"]
    assert ids({"prefix": {"notice.note": "Scan::"}}) == ["n3"]
    assert ids({"prefix": {"notice.note": {"value": "ATTACK"}}}) == ["n1"]
    assert ids({"match_none": {}}) == []
    multi = {"multi_match": {"query": "lateral", "fields": ["notice.note", "notice.note.text"]}}
    assert ids(multi) == ["n2"]


def test_terms_agg_takes_a_list_order_and_min_doc_count():
    """The sibling candidate read orders by a sub-agg, then by count."""
    from soc_ai.webui.alert_siblings import candidate_aggs

    docs = [
        _alert("a1", hours_ago=1, rule="R1", cid="1:A"),
        _alert("a2", hours_ago=2, rule="R1", cid="1:A"),
        _alert("a3", hours_ago=3, rule="R1", cid="1:A"),
        _alert("b1", hours_ago=1, rule="R1", cid="1:B"),
        _alert("b2", hours_ago=2, rule="R2", cid="1:B"),
        _alert("c1", hours_ago=1, rule="R3", cid="1:C"),
    ]
    body = {"query": _feed_query("now-24h"), "size": 0, "aggs": candidate_aggs()}
    resp = mock_es.search_docs(body, docs)
    flows = resp["aggregations"]["flows"]
    # B holds two groups, A one; C holds one alert and min_doc_count drops it.
    assert [(b["key"], b["members"]["value"]) for b in flows["buckets"]] == [("1:B", 2), ("1:A", 1)]
    assert flows["buckets"][0]["rules"] == {"value": 2}
    sent = resp["aggregations"]["sent"]["buckets"]
    assert sent[0]["key"] == "192.0.2.10"
    assert sent[0]["peers"]["buckets"][0]["key"] == "198.51.100.20"


def test_terms_agg_include_exclude_and_missing():
    docs = [
        _alert("u1", hours_ago=1, rule="R"),
        _alert("u2", hours_ago=1, dataset="opencanary"),
    ]
    docs[1]["_source"]["event"].pop("dataset")

    def keys(spec: dict) -> list:
        resp = mock_es.search_docs({"size": 0, "aggs": {"t": {"terms": spec}}}, docs)
        return [b["key"] for b in resp["aggregations"]["t"]["buckets"]]

    assert keys({"field": "event.dataset", "missing": "(unknown dataset)"}) == [
        "(unknown dataset)",
        "suricata.alert",
    ]
    assert keys({"field": "network.community_id", "include": ["1:u2"]}) == ["1:u2"]
    assert keys({"field": "network.community_id", "exclude": r".*u1"}) == ["1:u2"]
    assert keys({"field": "network.community_id", "include": r"1:u.*", "size": 1}) == ["1:u1"]


def test_filter_filters_cardinality_and_value_count():
    body = {
        "query": _feed_query("now-24h"),
        "size": 0,
        "aggs": {
            "flow": {
                "filter": {"term": {"rule.name": "ET MALWARE Beacon"}},
                "aggs": {"src": {"cardinality": {"field": "source.ip"}}},
            },
            "pairs": {
                "filters": {
                    "filters": {
                        "p0": {"term": {"source.ip": "192.0.2.10"}},
                        "p1": {"term": {"source.ip": "203.0.113.5"}},
                    }
                },
                "aggs": {"first": {"min": {"field": "@timestamp"}}},
            },
            "anon": {"filters": {"filters": [{"term": {"event.acknowledged": True}}]}},
            "names": {"cardinality": {"field": "rule.name", "missing": "(no rule)"}},
            "ports": {"value_count": {"field": "destination.port"}},
        },
    }
    aggs = _search_response_from_docs(body, GRID)["aggregations"]
    assert aggs["flow"]["doc_count"] == 3
    assert aggs["flow"]["src"]["value"] == 2
    assert aggs["pairs"]["buckets"]["p0"]["doc_count"] == 3  # b1, b3 and the honeypot alert
    assert aggs["pairs"]["buckets"]["p1"]["doc_count"] == 1
    assert aggs["pairs"]["buckets"]["p0"]["first"]["value_as_string"]
    assert aggs["anon"]["buckets"] == [{"doc_count": 1}]
    assert aggs["names"]["value"] == 3  # two rules and the unnamed honeypot alert
    assert aggs["ports"]["value"] == 5


def test_date_histogram_fills_the_bounds_at_the_interval():
    docs = [
        _alert("h1", hours_ago=1, rule="R"),
        _alert("h2", hours_ago=1.1, rule="R"),
        _alert("h5", hours_ago=5, rule="R"),
    ]
    histogram = {
        "field": "@timestamp",
        "calendar_interval": "hour",
        "min_doc_count": 0,
        "extended_bounds": {"min": "now-24h", "max": "now"},
    }
    body = {"size": 0, "aggs": {"v": {"date_histogram": histogram}}}
    buckets = mock_es.search_docs(body, docs)["aggregations"]["v"]["buckets"]
    assert len(buckets) == 25
    assert sum(b["doc_count"] for b in buckets) == 3
    assert all(b["key"] % 3_600_000 == 0 for b in buckets)
    first = datetime.fromtimestamp(buckets[0]["key"] / 1000, UTC)
    assert buckets[0]["key_as_string"] == first.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert [b["key"] for b in buckets] == sorted(b["key"] for b in buckets)

    sparse = {"field": "@timestamp", "fixed_interval": "3600s", "min_doc_count": 1}
    body = {"size": 0, "aggs": {"v": {"date_histogram": sparse, "aggs": _span_aggs()}}}
    buckets = mock_es.search_docs(body, docs)["aggregations"]["v"]["buckets"]
    assert sum(b["doc_count"] for b in buckets) == 3
    assert all(b["doc_count"] >= 1 for b in buckets)
    assert buckets[-1]["last"]["value_as_string"] == docs[0]["_source"]["@timestamp"]

    daily = {"field": "@timestamp", "interval": "1d", "extended_bounds": {"min": "now-7d"}}
    body = {"size": 0, "aggs": {"v": {"date_histogram": daily}}}
    buckets = mock_es.search_docs(body, docs)["aggregations"]["v"]["buckets"]
    # No upper bound, so the last bucket is the day of the newest record, one
    # hour ago. From 00:00 to 01:00 UTC that day is yesterday, and the test
    # failed in that hour with 7 buckets. Count the days the bounds hold.
    newest = datetime.fromisoformat(docs[0]["_source"]["@timestamp"].replace("Z", "+00:00"))
    first_day = (datetime.now(UTC) - timedelta(days=7)).date()
    assert len(buckets) == (newest.date() - first_day).days + 1
    assert all(b["key"] % 86_400_000 == 0 for b in buckets)


def _span_aggs() -> dict:
    return {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}


def test_from_pages_sort_and_source_filter():
    docs = [_alert(f"e{i}", hours_ago=i + 1, rule="R", port=1000 - i) for i in range(5)]
    term = {"bool": {"filter": [{"term": {"rule.name": "R"}}]}}
    body = {"query": term, "size": 2, "from": 2, "sort": [{"@timestamp": {"order": "desc"}}]}
    resp = mock_es.search_docs(body, docs)
    assert [h["_id"] for h in resp["hits"]["hits"]] == ["e2", "e3"]
    assert resp["hits"]["total"]["value"] == 5

    by_port = {"query": term, "size": 2, "sort": [{"destination.port": "asc"}]}
    assert [h["_id"] for h in mock_es.search_docs(by_port, docs)["hits"]["hits"]] == ["e4", "e3"]
    by_port = {"query": term, "size": 1, "sort": "destination.port"}
    assert [h["_id"] for h in mock_es.search_docs(by_port, docs)["hits"]["hits"]] == ["e4"]

    narrow = {"query": {"ids": {"values": ["e1"]}}, "size": 1, "_source": ["event.acknowledged"]}
    hit = mock_es.search_docs(narrow, docs)["hits"]["hits"][0]
    assert hit["_source"] == {"event": {"acknowledged": False}}
    assert docs[1]["_source"]["rule"] == {"name": "R"}  # the stored doc is not changed


def test_metric_aggs_and_the_aggregations_spelling():
    docs = [_alert(f"m{i}", hours_ago=i + 1, rule="R", port=100 * (i + 1)) for i in range(3)]
    body = {
        "size": 0,
        "aggregations": {
            "newest": {"max": {"field": "@timestamp"}},
            "oldest": {"min": {"field": "@timestamp"}},
            "avg_port": {"avg": {"field": "destination.port"}},
            "sum_port": {"sum": {"field": "destination.port"}},
            "top": {
                "top_hits": {
                    "size": 2,
                    "sort": [{"destination.port": {"order": "desc"}}],
                    "_source": {"includes": ["destination.*"]},
                }
            },
        },
    }
    aggs = mock_es.search_docs(body, docs)["aggregations"]
    assert aggs["newest"]["value_as_string"] == docs[0]["_source"]["@timestamp"]
    assert aggs["oldest"]["value_as_string"] == docs[2]["_source"]["@timestamp"]
    assert aggs["avg_port"]["value"] == 200.0
    assert aggs["sum_port"]["value"] == 600.0
    top = aggs["top"]["hits"]["hits"]
    assert [h["_id"] for h in top] == ["m2", "m1"]
    assert top[0]["_source"] == {"destination": {"ip": "198.51.100.20", "port": 300}}


# --- fixture version 2: load and time shift ---------------------------------

_ANCHOR = "2026-10-22T12:00:00+00:00"


def _write_v2(tmp_path: Path, **sections: object) -> Path:
    data = {"version": 2, "anchor": _ANCHOR, "alerts": [], "documents": [], "traffic": {}}
    data.update(sections)
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(data))
    return path


def test_v2_load_shifts_every_time_relative_to_the_anchor(tmp_path: Path):
    alert = {
        "_index": "logs-demo",
        "_id": "a1",
        "_source": {
            "@timestamp": "2026-10-22T11:00:00.250Z",
            "event": {"created": "2026-10-21T12:00:00+00:00", "kind": "alert"},
            "note": "2026-10-22",
            "2026-10-22T11:00:00Z": "key stays",
            "seen": ["2026-10-22T10:30:00.123456", "plain text"],
        },
    }
    doc = {"_index": "logs-zeek", "_id": "d1", "_source": {"@timestamp": "2026-10-22T09:00:00Z"}}
    silent = {"start": "2026-10-22T06:00:00Z", "end": "2026-10-22T08:00:00Z"}
    path = _write_v2(tmp_path, alerts=[alert], documents=[doc], traffic={"silent": [silent]})
    now = datetime.now(UTC).replace(microsecond=0)

    grid = mock_es.load_fixture(path, now=now)

    assert grid.version == 2
    assert grid.shifted is True
    a1, d1 = grid.docs
    src = a1["_source"]
    assert src["@timestamp"] == _iso_at(now - timedelta(hours=1)).replace(".000Z", ".250Z")
    assert src["event"]["created"] == (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    assert src["note"] == "2026-10-22"  # a date alone is no instant
    assert src["2026-10-22T11:00:00Z"] == "key stays"  # keys never shift
    naive = (now - timedelta(minutes=90)).strftime("%Y-%m-%dT%H:%M:%S") + ".123456"
    assert src["seen"] == [naive, "plain text"]
    assert d1["_source"]["@timestamp"] == (now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    shifted_silent = grid.traffic["silent"][0]
    assert shifted_silent["start"] == (now - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # The file on disk is not changed.
    assert json.loads(path.read_text())["alerts"][0]["_source"]["@timestamp"].startswith(
        "2026-10-22T11"
    )


def test_v2_load_defaults_to_the_real_now(tmp_path: Path):
    alert = {"_index": "l", "_id": "a", "_source": {"@timestamp": _ANCHOR}}
    grid = mock_es.load_fixture(_write_v2(tmp_path, alerts=[alert]))
    stamp = datetime.fromisoformat(grid.docs[0]["_source"]["@timestamp"])
    assert abs((datetime.now(UTC) - stamp).total_seconds()) < 60


def test_v1_file_still_rebases_the_newest_doc_to_now(tmp_path: Path):
    fx = tmp_path / "fixtures.json"
    fx.write_text(json.dumps({"version": 1, "alerts": DOCS}))
    grid = mock_es.load_fixture(fx)
    assert grid.version == 1
    assert grid.shifted is False
    assert [d["_id"] for d in grid.docs] == ["a1", "a2", "a3", "n1"]
    term = {"bool": {"filter": [{"term": {"rule.name": "ET MALWARE Beacon"}}]}}
    resp = mock_es.fixture_search({"query": term, "size": 5}, grid)
    newest = datetime.fromisoformat(resp["hits"]["hits"][0]["_source"]["@timestamp"])
    assert abs((datetime.now(UTC) - newest).total_seconds()) < 60
    assert DOCS[1]["_source"]["@timestamp"] == "2026-07-10T13:00:00.000Z"


def test_v2_search_serves_the_shifted_docs_without_a_copy(tmp_path: Path, monkeypatch):
    alert = _alert("a1", hours_ago=1, rule="R")
    grid = mock_es.load_fixture(_write_v2(tmp_path, alerts=[alert]))

    def no_copy(_value: object) -> object:
        raise AssertionError("the v2 path copied the docs")

    monkeypatch.setattr(mock_es.copy, "deepcopy", no_copy)
    term = {"bool": {"filter": [{"term": {"rule.name": "R"}}]}}
    resp = mock_es.fixture_search({"query": term, "size": 5}, grid)
    assert [h["_id"] for h in resp["hits"]["hits"]] == ["a1"]
    assert resp["hits"]["hits"][0]["_source"] is grid.docs[0]["_source"]


# --- the host page: the connection pass and the users pass -----------------

_HOST = "192.0.2.20"


def _hour_floor(when: datetime) -> datetime:
    return when.replace(minute=0, second=0, microsecond=0)


def _traffic(pattern: str = "always", silent: list | None = None) -> dict:
    return {
        "silent": silent or [],
        "hosts": {
            _HOST: {
                "pattern": pattern,
                "peers": [
                    {"ip": "192.0.2.10", "direction": "out", "port": 445, "per_day": 240},
                    {"ip": "198.51.100.7", "direction": "in", "port": 22, "per_day": 48},
                ],
                "agent": "fs-01",
                "users": [["it-admin-07", 14], ["svc-backup", 96], ["FS-01$", 70]],
            }
        },
    }


def _conn_body(ip: str = _HOST, time_range: str = "24h") -> dict:
    from soc_ai.webui.host_activity import _VOLUME_INTERVAL, _conn_aggs, _conn_query

    window = f"now-{time_range}"
    return {
        "query": _conn_query(ip, window),
        "size": 0,
        "aggs": _conn_aggs(ip, _VOLUME_INTERVAL[time_range], window),
    }


def _conn_total_agrees(resp: dict) -> int:
    aggs = resp["aggregations"]
    total = resp["hits"]["total"]["value"]
    volume = sum(b["doc_count"] for b in aggs["volume"]["buckets"])
    by_dataset = sum(b["doc_count"] for b in aggs["by_dataset"]["buckets"])
    sides = aggs["out"]["doc_count"] + aggs["in"]["doc_count"]
    peers = sum(b["doc_count"] for s in ("out", "in") for b in aggs[s]["peers"]["buckets"])
    assert volume == by_dataset == sides == peers == total
    return total


def test_conn_pass_counts_agree_and_a_silent_span_reads_zero():
    top = _hour_floor(datetime.now(UTC))
    gap = {"start": _iso_at(top - timedelta(hours=6)), "end": _iso_at(top - timedelta(hours=3))}
    resp = mock_es.search_docs(_conn_body(), [], traffic=_traffic(silent=[gap]))
    aggs = resp["aggregations"]

    assert _conn_total_agrees(resp) == 252  # 21 live hours of 240 + 48 a day
    assert [(b["key"], b["doc_count"]) for b in aggs["out"]["peers"]["buckets"]] == [
        ("192.0.2.10", 210)
    ]
    port = aggs["in"]["peers"]["buckets"][0]["ports"]["buckets"]
    assert port == [{"key": 22, "doc_count": 42}]
    volume = aggs["volume"]["buckets"]
    assert len(volume) == 25
    by_key = {b["key"]: b["doc_count"] for b in volume}
    for hours in (6, 5, 4):
        assert by_key[int((top - timedelta(hours=hours)).timestamp() * 1000)] == 0
    assert by_key[int((top - timedelta(hours=3)).timestamp() * 1000)] > 0
    assert aggs["by_dataset"]["buckets"] == [{"key": "zeek.conn", "doc_count": 252}]
    newest = datetime.fromisoformat(aggs["newest"]["value_as_string"])
    assert newest <= datetime.now(UTC)


def test_conn_pass_newest_steps_back_out_of_a_silent_span():
    now = datetime.now(UTC)
    # The mock gives each hour slot whole records. A gap that opens in the
    # first three minutes of an hour leaves that slot no record, so the newest
    # record is the end of the hour before. The test failed in those minutes,
    # about one run in twenty. The gap now opens at half past the hour.
    start = (now - timedelta(hours=2)).replace(minute=30, second=0, microsecond=0)
    gap = {"start": _iso_at(start), "end": _iso_at(now + timedelta(hours=1))}
    resp = mock_es.search_docs(_conn_body(), [], traffic=_traffic(silent=[gap]))
    _conn_total_agrees(resp)
    assert resp["aggregations"]["newest"]["value_as_string"] == gap["start"]
    assert resp["aggregations"]["volume"]["buckets"][-1]["doc_count"] == 0


def test_conn_pass_scales_with_the_window_and_the_pattern():
    day = mock_es.search_docs(_conn_body(), [], traffic=_traffic("always"))
    week = mock_es.search_docs(_conn_body(time_range="7d"), [], traffic=_traffic("always"))
    assert _conn_total_agrees(day) == 288
    assert _conn_total_agrees(week) == 7 * 288
    assert len(week["aggregations"]["volume"]["buckets"]) == 8
    assert all(b["key"] % 86_400_000 == 0 for b in week["aggregations"]["volume"]["buckets"])

    office = mock_es.search_docs(_conn_body(time_range="7d"), [], traffic=_traffic("office"))
    assert 5 * 288 <= _conn_total_agrees(office) < 7 * 288  # a quiet weekend
    server = mock_es.search_docs(_conn_body(), [], traffic=_traffic("server"))
    assert _conn_total_agrees(server) == 288
    hourly = {
        datetime.fromtimestamp(b["key"] / 1000, UTC).hour: b["doc_count"]
        for b in server["aggregations"]["volume"]["buckets"][1:-1]
    }
    if 2 in hourly and 12 in hourly:
        assert hourly[2] > hourly[12]  # the night peak


def test_conn_pass_peer_since_and_until_bound_the_peer():
    """A peer counts only inside its own since/until span."""
    top = _hour_floor(datetime.now(UTC))
    since, until = top - timedelta(hours=10), top - timedelta(hours=12)
    traffic = {
        "silent": [],
        "hosts": {
            _HOST: {
                "pattern": "always",
                "peers": [
                    {
                        "ip": "203.0.113.80",
                        "direction": "out",
                        "port": 443,
                        "per_day": 240,
                        "since": _iso_at(since),
                    },
                    {
                        "ip": "198.51.100.7",
                        "direction": "in",
                        "port": 22,
                        "per_day": 48,
                        "until": _iso_at(until),
                    },
                ],
            }
        },
    }
    resp = mock_es.search_docs(_conn_body(), [], traffic=traffic)
    total = _conn_total_agrees(resp)
    aggs = resp["aggregations"]
    beacon = aggs["out"]["peers"]["buckets"][0]["doc_count"]
    assert 100 <= beacon <= 110  # ten hours and a part, at 10 an hour
    late = aggs["in"]["peers"]["buckets"][0]["doc_count"]
    assert 22 <= late <= 24  # about twelve hours at 2 an hour
    assert total == beacon + late
    by_key = {b["key"]: b["doc_count"] for b in aggs["volume"]["buckets"]}
    # The hour after the until of one peer and before the since of the other.
    assert by_key[int((top - timedelta(hours=11)).timestamp() * 1000)] == 0
    assert by_key[int((top - timedelta(hours=10)).timestamp() * 1000)] > 0
    assert by_key[int((top - timedelta(hours=13)).timestamp() * 1000)] > 0


def test_conn_pass_for_an_unlisted_host_reads_the_docs():
    resp = mock_es.search_docs(_conn_body("192.0.2.99"), GRID, traffic=_traffic())
    assert resp["hits"]["total"]["value"] == 0
    assert resp["aggregations"]["out"]["doc_count"] == 0
    assert len(resp["aggregations"]["volume"]["buckets"]) == 25
    assert resp["aggregations"]["newest"]["value"] is None


def _users_body(ip: str = _HOST, window: str = "now-24h") -> dict:
    """The query and the aggs of host_activity._fetch_users."""
    datasets = ["windows.security", "system.auth"]
    query = {
        "bool": {
            "filter": [
                {
                    "bool": {
                        "should": [
                            {"terms": {"event.dataset": datasets}},
                            {"terms": {"data_stream.dataset": datasets}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                {"term": {"host.ip": ip}},
                {"range": {"@timestamp": {"gte": window}}},
            ],
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }
    aggs = {
        "agents": {"terms": {"field": "host.name", "size": 2}},
        "users": {
            "terms": {"field": "user.name", "size": 26, "exclude": r".*\$"},
            "aggs": {"last": {"max": {"field": "@timestamp"}}},
        },
    }
    return {"query": query, "size": 0, "aggs": aggs, "track_total_hits": True}


def test_users_pass_names_the_agent_and_scales_to_the_window():
    resp = mock_es.search_docs(_users_body(), [], traffic=_traffic())
    aggs = resp["aggregations"]
    assert [(b["key"], b["doc_count"]) for b in aggs["users"]["buckets"]] == [
        ("svc-backup", 14),
        ("it-admin-07", 2),
    ]
    assert aggs["agents"]["buckets"] == [{"key": "fs-01", "doc_count": 26}]
    assert resp["hits"]["total"]["value"] == 26  # the machine account counts, unlisted
    lo = datetime.now(UTC) - timedelta(hours=24)
    for bucket in aggs["users"]["buckets"]:
        last = datetime.fromisoformat(bucket["last"]["value_as_string"])
        assert lo < last <= datetime.now(UTC)

    week = mock_es.search_docs(_users_body(window="now-7d"), [], traffic=_traffic())
    counts = {b["key"]: b["doc_count"] for b in week["aggregations"]["users"]["buckets"]}
    assert counts == {"svc-backup": 96, "it-admin-07": 14}

    other = mock_es.search_docs(_users_body("192.0.2.99"), [], traffic=_traffic())
    assert other["hits"]["total"]["value"] == 0
    assert other["aggregations"]["users"]["buckets"] == []


async def test_host_page_folds_the_mock_answers(settings_kratos):
    """The real host page reads the three passes from the mock and agrees."""
    from unittest.mock import AsyncMock, patch

    from soc_ai.so_client.elastic import ElasticClient
    from soc_ai.webui.host_activity import fetch_host_activity

    traffic = _traffic()
    traffic["hosts"][_HOST]["users"] = [["it-admin-07", 14], ["svc-backup", 96]]
    docs = [_alert("x1", hours_ago=2, rule="R", src="192.0.2.10", dst=_HOST)]
    fake = AsyncMock()
    fake.search = AsyncMock(
        side_effect=lambda **kw: mock_es.search_docs(kw.get("body") or {}, docs, traffic=traffic)
    )
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake):
        elastic = ElasticClient(settings_kratos)
    activity = await fetch_host_activity(elastic, settings_kratos, _HOST, range="24h")

    assert [(p.ip, p.events, p.ports) for p in activity.peers] == [
        ("192.0.2.10", 240, [445]),
        ("198.51.100.7", 48, [22]),
    ]
    assert activity.peers[0].alerted is True
    assert sum(point.events for point in activity.volume) == 288
    assert activity.conn_datasets == ["zeek.conn"]
    assert activity.alerts_7d == 1
    assert activity.users is not None
    assert [u.name for u in activity.users] == ["svc-backup", "it-admin-07"]
    assert activity.newest_event is not None


async def test_alerts_page_reads_the_mock_groups(settings_kratos):
    from unittest.mock import AsyncMock, patch

    from soc_ai.so_client.elastic import ElasticClient
    from soc_ai.webui.alerts_query import fetch_group_events, fetch_groups

    fake = AsyncMock()
    fake.search = AsyncMock(side_effect=lambda **kw: mock_es.search_docs(kw["body"], GRID))
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake):
        elastic = ElasticClient(settings_kratos)
    page = await fetch_groups(elastic, settings_kratos, time_range="24h")
    names = [g.rule_name for g in page.groups]
    assert "ET POLICY Old Lookup" not in names
    assert names[0] == "ET MALWARE Beacon"
    assert page.total == 5
    events = await fetch_group_events(
        elastic, settings_kratos, rule_name="ET MALWARE Beacon", size=2, offset=1
    )
    assert [e.es_id for e in events] == ["b2", "b3"]


def test_count_endpoint_answers_with_the_same_matcher(monkeypatch, tmp_path: Path):
    anchor = _iso_at(datetime.now(UTC))  # GRID already sits relative to now
    grid = mock_es.load_fixture(_write_v2(tmp_path, alerts=GRID, anchor=anchor))
    monkeypatch.setattr(mock_es, "FIXTURE", grid)
    body = json.dumps({"query": _feed_query("now-24h")}).encode()
    with _serving() as base:
        req = urllib.request.Request(
            f"{base}/logs-*/_count",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            answer = json.loads(resp.read())
    assert answer["count"] == 5
    assert answer["_shards"]["failed"] == 0
