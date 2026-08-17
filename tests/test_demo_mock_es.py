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
from scripts.demo.mock_es import _search_response_from_docs, load_fixture_docs


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
