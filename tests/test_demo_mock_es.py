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
from datetime import UTC, datetime
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
    assert resp["hits"]["total"]["value"] == 3  # notice doc has no rule.name


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
        assert released.wait(2), "a state change did not release the stalled waiter"
        assert mock_es.degrade_state() == "healthy"
    finally:
        mock_es.set_degrade_state("healthy")
