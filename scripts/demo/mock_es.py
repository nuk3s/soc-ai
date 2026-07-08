"""Tiny mock of the Elasticsearch + LiteLLM endpoints for the screenshot demo.

README
======
Part of the docs-screenshot harness (see run_demo_capture.sh). Serves, on ONE
local port (default 19200):

  GET  /                    → an Elasticsearch-flavoured info document (with the
                              ``X-Elastic-Product`` header the ES client checks)
  GET  /v1/models           → a LiteLLM-style model list containing the default
                              ``soc-ai-analyst`` alias (turns the LLM health dot
                              green — no model is ever actually called)
  POST/GET *_search         → canned, TEST-NET-only alert data from
                              demo_dataset.py:
                                * the grouped-by-rule aggregation the Alerts
                                  console renders (incl. the Zeek notice agg)
                                * flat per-group event listings (row expansion)
                                * the ``ids`` acked-state lookup used by the
                                  investigation detail page
  anything else             → 200 {"acknowledged": true} (index bootstrap,
                              audit writes, bulk, templates, …)

Every value returned is synthetic (RFC 5737 TEST-NET IPs, fictional hosts).
Run: .venv/bin/python scripts/demo/mock_es.py [port]
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import demo_dataset as dd

# Enough rows for the expanded-group screenshot while still leaving the lower
# groups (curl's E2.1 "last retry error" hint, stream retrans) in the viewport.
MAX_EVENTS_PER_GROUP = 5

# Deterministic inter-event spacing (minutes) per group prefix; the Emotet
# beacon keeps its ~7.4-minute cadence so the story matches the investigation.
_STEP_MIN = {
    "demo-ev-emotet": 7.4,
    "demo-ev-retrans": 11.0,
    "demo-ev-curl": 47.0,
    "demo-ev-dnstop": 9.0,
    "demo-ev-nmap": 2.0,
    "demo-ev-attackdisc": 1.0,
    "demo-ev-selfsigned": 6.0,
}


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _event_source(g: dict, ts: datetime) -> dict:
    src: dict = {
        "@timestamp": _iso(ts),
        "event": {
            "dataset": g["dataset"],
            "severity_label": g["sev"],
            "acknowledged": bool(g["acked"]),
            "escalated": False,
        },
        "source": {"ip": g["src"], "port": 49000 + (hash(g["prefix"]) % 3000)},
        "destination": {"ip": g["dst"], "port": g["dport"]},
        "host": {"name": g["host"]},
    }
    if g["kind"] == "notice":
        src["notice"] = {"note": g["rule"]}
    else:
        src["rule"] = {"name": g["rule"]}
    return src


def _events_for(g: dict) -> list[dict]:
    now = datetime.now(UTC)
    newest = now - timedelta(minutes=g["latest_min"])
    step = _STEP_MIN.get(g["prefix"], 10.0)
    out = []
    for n in range(1, min(g["count"], MAX_EVENTS_PER_GROUP) + 1):
        ts = newest - timedelta(minutes=step * (n - 1))
        out.append(
            {
                "_index": "logs-demo",
                "_id": dd.event_id(g, n),
                "_source": _event_source(g, ts),
            }
        )
    return out


def _bucket(g: dict) -> dict:
    now = datetime.now(UTC)
    newest = now - timedelta(minutes=g["latest_min"])
    return {
        "key": g["rule"],
        "doc_count": g["count"],
        "latest_ts": {"value": newest.timestamp() * 1000.0, "value_as_string": _iso(newest)},
        "latest": {
            "hits": {
                "hits": [
                    {
                        "_index": "logs-demo",
                        "_id": dd.event_id(g, 1),
                        "_source": _event_source(g, newest),
                    }
                ]
            }
        },
        "acked": {"doc_count": g["count"] if g["acked"] else 0},
        "escalated": {"doc_count": 0},
    }


def _search_response(body: dict) -> dict:
    aggs = body.get("aggs") or {}
    query = body.get("query") or {}
    body_str = json.dumps(body)
    hide_acked = '"event.acknowledged"' in body_str and '"must_not"' in body_str

    # --- grouped aggregation (Alerts console) --------------------------------
    rules_agg = aggs.get("rules") or {}
    terms_field = (rules_agg.get("terms") or {}).get("field")
    if terms_field == "rule.name":
        groups = [g for g in dd.GROUPS if not (hide_acked and g["acked"])]
        return {
            "took": 3,
            "timed_out": False,
            "hits": {
                "total": {"value": sum(g["count"] for g in groups), "relation": "eq"},
                "hits": [],
            },
            "aggregations": {"rules": {"buckets": [_bucket(g) for g in groups]}},
        }
    if terms_field == "notice.note":
        groups = [g for g in dd.NOTICE_GROUPS if not (hide_acked and g["acked"])]
        return {
            "took": 2,
            "timed_out": False,
            "hits": {
                "total": {"value": sum(g["count"] for g in groups), "relation": "eq"},
                "hits": [],
            },
            "aggregations": {"rules": {"buckets": [_bucket(g) for g in groups]}},
        }

    # --- ids lookup (acked-state probe on the investigation detail page) -----
    ids = query.get("ids") or {}
    if ids.get("values"):
        hits = [
            {
                "_index": "logs-demo",
                "_id": i,
                "_source": {"event": {"acknowledged": i in dd.ACKED_EVENT_IDS}},
            }
            for i in ids["values"]
        ]
        return {
            "took": 1,
            "timed_out": False,
            "hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits},
        }

    # --- flat per-group event listing (row expansion) -------------------------
    def _terms_in(node) -> dict:
        found: dict = {}
        if isinstance(node, dict):
            term = node.get("term")
            if isinstance(term, dict):
                found.update(term)
            for v in node.values():
                found.update(_terms_in(v))
        elif isinstance(node, list):
            for v in node:
                found.update(_terms_in(v))
        return found

    terms = _terms_in(query)
    rule = terms.get("rule.name") or terms.get("notice.note")
    if rule:
        try:
            g = dd.group_by_rule(str(rule))
        except KeyError:
            g = None
        if g is not None:
            hits = _events_for(g)
            return {
                "took": 2,
                "timed_out": False,
                "hits": {"total": {"value": g["count"], "relation": "eq"}, "hits": hits},
            }

    # --- anything else: empty result ------------------------------------------
    return {
        "took": 1,
        "timed_out": False,
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
    }


ES_INFO = {
    "name": "demo-node",
    "cluster_name": "demo-grid",
    "cluster_uuid": "AAAAAAAAAAAAAAAAAAAAAA",
    "version": {
        "number": "8.14.3",
        "build_flavor": "default",
        "build_type": "docker",
        "lucene_version": "9.10.0",
        "minimum_wire_compatibility_version": "7.17.0",
        "minimum_index_compatibility_version": "7.0.0",
    },
    "tagline": "You Know, for Search",
}

MODELS = {
    "object": "list",
    "data": [
        {"id": "soc-ai-analyst", "object": "model", "owned_by": "demo"},
    ],
}


class Handler(BaseHTTPRequestHandler):
    server_version = "MockES/1.0"

    def _send(self, payload: dict, status: int = 200) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("X-Elastic-Product", "Elasticsearch")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except ValueError:
            return {}

    def _route(self) -> None:
        path = self.path.split("?")[0]
        if path == "/":
            self._send(ES_INFO)
        elif path == "/v1/models":
            self._send(MODELS)
        elif "_search" in path:
            self._send(_search_response(self._body()))
        elif "_bulk" in path:
            self._body()
            self._send({"errors": False, "took": 1, "items": []})
        elif "_doc" in path or "_create" in path:
            self._body()
            self._send({"result": "created", "_id": "demo", "_index": "demo"})
        else:
            self._body()
            self._send({"acknowledged": True})

    def do_GET(self) -> None:
        self._route()

    def do_POST(self) -> None:
        self._route()

    def do_PUT(self) -> None:
        self._route()

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("X-Elastic-Product", "Elasticsearch")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt: str, *args) -> None:  # quiet
        pass


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19200
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock ES+LLM listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
