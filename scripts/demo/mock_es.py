"""Tiny mock of the Elasticsearch + LiteLLM endpoints for the demo stacks.

README
======
Part of the docs-screenshot harness (see run_demo_capture.sh) AND the public
demo container (docker/demo-entrypoint.sh). Serves, on ONE local port
(default 19200):

  GET  /                    → an Elasticsearch-flavoured info document (with the
                              ``X-Elastic-Product`` header the ES client checks)
  GET  /v1/models           → a LiteLLM-style model list containing the default
                              ``soc-ai-analyst`` alias (turns the LLM health dot
                              green — no model is ever actually called)
  POST/GET *_search         → canned alert data:
                                * the grouped-by-rule aggregation the Alerts
                                  console renders (incl. the Zeek notice agg)
                                * flat per-group event listings (row expansion)
                                * the ``ids`` acked-state lookup used by the
                                  investigation detail page
                              Source: demo_dataset.py's TEST-NET groups by
                              default, or — with ``--fixtures FILE`` — the
                              sanitized ``alerts[]`` documents of a packaged
                              soc_ai/demo/fixtures.json (the demo container).
  anything else             → 200 {"acknowledged": true} (index bootstrap,
                              audit writes, bulk, templates, …)

Every value returned is synthetic or sanitized-and-owner-reviewed.
Run: .venv/bin/python scripts/demo/mock_es.py [port]
     python scripts/demo/mock_es.py --port 9200 --fixtures soc_ai/demo/fixtures.json
"""

from __future__ import annotations

import argparse
import copy
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


def _terms_in(node) -> dict:
    """Every ``{"term": {field: value}}`` filter found anywhere in a query tree."""
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


# ---------------------------------------------------------------------------
# Fixtures mode (the public demo container, docker/demo-entrypoint.sh):
# serve the sanitized ``alerts[]`` mock-ES documents of a packaged
# soc_ai/demo/fixtures.json instead of demo_dataset's canned groups. Same
# ``_search`` response contract as :func:`_search_response` — the app is the
# shared consumer — but grouped/filtered from real documents.
# ---------------------------------------------------------------------------

FIXTURE_DOCS: list[dict] | None = None  # set by main() when --fixtures is given


def load_fixture_docs(path: Path) -> list[dict]:
    """The ``alerts[]`` documents from a fixture file — fail-soft to ``[]``.

    Mirrors the app's own fail-soft fixture seeding (soc_ai/main.py): a
    missing or unparseable fixtures.json must not stop the mock; the demo then
    serves an empty, honest grid rather than fictional filler data.
    """
    try:
        data = json.loads(path.read_text())
        docs = data.get("alerts") or []
        return [d for d in docs if isinstance(d, dict)]
    except (OSError, ValueError):
        print(f"mock ES: no usable fixtures at {path}; serving an empty grid", file=sys.stderr)
        return []


def _doc_source(doc: dict) -> dict:
    src = doc.get("_source")
    return src if isinstance(src, dict) else {}


def _doc_acked(doc: dict) -> bool:
    return bool((_doc_source(doc).get("event") or {}).get("acknowledged"))


def _doc_escalated(doc: dict) -> bool:
    return bool((_doc_source(doc).get("event") or {}).get("escalated"))


def _doc_ts(doc: dict) -> datetime:
    raw = _doc_source(doc).get("@timestamp")
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:  # fixture docs always carry one; stay sortable anyway
        return datetime.now(UTC)


def _doc_group_key(doc: dict, field: str) -> str | None:
    """The doc's value for a grouping field (``rule.name`` / ``notice.note``)."""
    src = _doc_source(doc)
    if field == "rule.name":
        value = (src.get("rule") or {}).get("name")
    elif field == "notice.note":
        value = (src.get("notice") or {}).get("note")
    else:
        value = None
    return str(value) if value else None


def _docs_bucket(key: str, members: list[dict]) -> dict:
    newest = max(members, key=_doc_ts)
    newest_ts = _doc_ts(newest)
    return {
        "key": key,
        "doc_count": len(members),
        "latest_ts": {
            "value": newest_ts.timestamp() * 1000.0,
            "value_as_string": _iso(newest_ts),
        },
        "latest": {"hits": {"hits": [newest]}},
        "acked": {"doc_count": sum(1 for m in members if _doc_acked(m))},
        "escalated": {"doc_count": sum(1 for m in members if _doc_escalated(m))},
    }


def _rebase_docs_to_now(docs: list[dict]) -> list[dict]:
    """Return copies of ``docs`` with ``@timestamp`` shifted so the newest lands
    at 'now', preserving relative ordering — keeps the demo alerts queue
    perpetually current regardless of container uptime. Inputs are never mutated,
    and the return is always a fresh list of copies (even when no doc carries a
    timestamp, so callers can treat the result as owned unconditionally).
    """
    stamps = [_doc_ts(d) for d in docs if _doc_source(d).get("@timestamp") is not None]
    delta = datetime.now(UTC) - max(stamps) if stamps else timedelta(0)
    out = []
    for d in docs:
        d2 = copy.deepcopy(d)
        if _doc_source(d).get("@timestamp") is not None:
            d2["_source"]["@timestamp"] = _iso(_doc_ts(d) + delta)
        out.append(d2)
    return out


def _search_response_from_docs(body: dict, docs: list[dict]) -> dict:
    docs = _rebase_docs_to_now(docs)
    aggs = body.get("aggs") or {}
    query = body.get("query") or {}
    body_str = json.dumps(body)
    hide_acked = '"event.acknowledged"' in body_str and '"must_not"' in body_str
    visible = [d for d in docs if not (hide_acked and _doc_acked(d))]

    # --- grouped aggregation (Alerts console; rules AND Zeek notices) --------
    rules_agg = aggs.get("rules") or {}
    terms_field = (rules_agg.get("terms") or {}).get("field")
    if terms_field in ("rule.name", "notice.note"):
        groups: dict[str, list[dict]] = {}
        for doc in visible:
            key = _doc_group_key(doc, terms_field)
            if key is not None:
                groups.setdefault(key, []).append(doc)
        buckets = [_docs_bucket(key, members) for key, members in groups.items()]
        buckets.sort(key=lambda b: b["latest_ts"]["value"], reverse=True)
        return {
            "took": 3,
            "timed_out": False,
            "hits": {
                # Total counts only bucketed docs (those with the agg field), not
                # every query match as real ES would — fine here since the app
                # only reads this total alongside the buckets it summarizes.
                "total": {"value": sum(b["doc_count"] for b in buckets), "relation": "eq"},
                "hits": [],
            },
            "aggregations": {"rules": {"buckets": buckets}},
        }

    # --- ids lookup (acked-state probe on the investigation detail page) -----
    ids = query.get("ids") or {}
    if ids.get("values"):
        by_id = {doc.get("_id"): doc for doc in docs}
        hits = [
            {
                "_index": "logs-demo",
                "_id": i,
                "_source": {"event": {"acknowledged": _doc_acked(by_id[i])}},
            }
            for i in ids["values"]
            if i in by_id  # real-ES semantics: unknown ids simply return no hit
        ]
        return {
            "took": 1,
            "timed_out": False,
            "hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits},
        }

    # --- flat per-group event listing (row expansion) -------------------------
    terms = _terms_in(query)
    rule = terms.get("rule.name") or terms.get("notice.note")
    if rule:
        field = "rule.name" if terms.get("rule.name") else "notice.note"
        matching = sorted(
            (d for d in visible if _doc_group_key(d, field) == str(rule)),
            key=_doc_ts,
            reverse=True,
        )
        size = body.get("size")
        hits = matching[:size] if isinstance(size, int) and size >= 0 else matching
        return {
            "took": 2,
            "timed_out": False,
            "hits": {"total": {"value": len(matching), "relation": "eq"}, "hits": hits},
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
            body = self._body()
            if FIXTURE_DOCS is not None:
                self._send(_search_response_from_docs(body, FIXTURE_DOCS))
            else:
                self._send(_search_response(body))
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
    parser = argparse.ArgumentParser(
        description="Mock Elasticsearch + LiteLLM endpoint for the demo stacks."
    )
    # Positional port kept for the existing harness callers
    # (run_demo_capture.sh, tests/browser/conftest.py: `mock_es.py 19200`).
    parser.add_argument("port_pos", nargs="?", type=int, default=None, metavar="PORT")
    parser.add_argument("--port", type=int, default=None, help="listen port (default 19200)")
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=None,
        metavar="FILE",
        help="serve the alerts[] documents of this fixtures.json (the demo "
        "container passes soc_ai/demo/fixtures.json) instead of the canned "
        "screenshot dataset; a missing file serves an empty grid (fail-soft)",
    )
    args = parser.parse_args()
    port = 19200
    if args.port_pos is not None:
        port = args.port_pos
    if args.port is not None:
        port = args.port
    if args.fixtures is not None:
        global FIXTURE_DOCS  # noqa: PLW0603 — one-shot CLI wiring before serve_forever
        FIXTURE_DOCS = load_fixture_docs(args.fixtures)
        print(f"mock ES: fixtures mode — {len(FIXTURE_DOCS)} alert doc(s) from {args.fixtures}")
    # Loopback bind on purpose: in the demo container the app connects over
    # 127.0.0.1 (the demo egress guard's one sanctioned ES path); the port is
    # never published.
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock ES+LLM listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
