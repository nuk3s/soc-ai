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

Degraded-grid modes (OPT-IN, off by default)
--------------------------------------------
``--degraded-control`` adds ``/__degrade`` so one running app can be walked
through every grid failure with no restart (scripts/dogfood_degraded.mjs):

    GET  /__degrade          → {"state": "...", "stall_seconds": N}
    POST /__degrade/<state>  → switch to healthy | down | half-read |
                               saturated | stalled

WHY IT IS OFF BY DEFAULT, AND MUST STAY OFF: this same file serves the PUBLIC
demo container (docker/demo-entrypoint.sh). An unauthenticated control endpoint
there would let any visitor flip the live demo into a fabricated Security Onion
outage — a stranger could make the product look broken to every other visitor,
and the screenshots people take of it would be of a fake failure. So the route
only exists when the flag is passed. With the flag absent, ``/__degrade`` is not
special-cased at all: it falls through to the same catch-all
``{"acknowledged": true}`` every other unknown path already gets, so this file's
behaviour is byte-for-byte what it was before the flag existed. The demo
entrypoint never passes it.

The states model how a real Elasticsearch presents each failure, because the
app's guards key off the transport/HTTP shape, not off a message:

  healthy    todays behaviour — the known-good baseline to compare against.
  down       a hard TCP reset (SO_LINGER 0) before any response byte, so the ES
             client raises a genuine transport error rather than parsing a tidy
             503 body. The listener stays bound so /__degrade can switch back;
             closing the socket outright would strand the walkthrough.
  half-read  HTTP 200, ``timed_out: true``, ``_shards`` 2-of-4 failed, and NO
             hits. The sneakiest state in the product: nothing raises at the
             transport layer and the data quietly is not all there. Zero hits on
             purpose — that is the shape that renders an outage as a calm night.
  saturated  HTTP 429 with an ES ``circuit_breaking_exception`` body. The grid is
             UP and over its limits; this is retryable and must never read to the
             analyst as "your query is wrong".
  stalled    accept, then answer nothing for ``--stall-seconds`` (default 40 —
             comfortably past settings.webui_grid_timeout_s of 12, and long
             enough that a route which forgot that budget burns the full ES
             retry budget instead). The wait aborts early when the state changes,
             so flipping back to healthy releases the tarpit instead of leaving
             the next screen queued behind it.

Only the Elasticsearch surface degrades. ``/v1/*`` (the LiteLLM mock) stays
healthy in every state: a sick Security Onion grid is not a sick model gateway,
and conflating them would make it impossible to tell which dependency a screen
is complaining about.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import json
import socket
import struct
import sys
import threading
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


# ---------------------------------------------------------------------------
# Degraded-grid state (see the module docstring for the security rationale).
# ---------------------------------------------------------------------------

DEGRADE_STATES = ("healthy", "down", "half-read", "saturated", "stalled")

CONTROL_ENABLED = False  # set by main() only when --degraded-control is passed
STALL_SECONDS = 40.0

_state = "healthy"
_state_lock = threading.Lock()
# Set on every state change so in-flight `stalled` waits abort instead of
# holding the next state's first request behind a stale tarpit.
_state_changed = threading.Event()


def degrade_state() -> str:
    with _state_lock:
        return _state


def set_degrade_state(new: str) -> str:
    """Switch state and release anything currently tarpitted."""
    global _state  # noqa: PLW0603 — module-level switch, guarded by _state_lock
    with _state_lock:
        _state = new
    _state_changed.set()
    _state_changed.clear()
    return new


# A 200 that is not the whole truth: some shards answered, some did not, and
# Elasticsearch says so ONLY in `_shards` / `timed_out` — never by raising.
HALF_READ_SHARDS = {
    "total": 4,
    "successful": 2,
    "skipped": 0,
    "failed": 2,
    "failures": [
        {
            "shard": 2,
            "index": "logs-demo-000001",
            "node": "demo-node-2",
            "reason": {
                "type": "node_disconnected_exception",
                "reason": "[demo-node-2][127.0.0.1:9300][indices:data/read/search[phase/query]] "
                "disconnected",
            },
        },
        {
            "shard": 3,
            "index": "logs-demo-000001",
            "node": None,
            "reason": {
                "type": "no_shard_available_action_exception",
                "reason": "No shard available for [get [logs-demo-000001]]",
            },
        },
    ],
}


def half_read_response() -> dict:
    """200 OK, two of four shards unread, zero hits, no aggregations.

    Deliberately the maximum-danger shape rather than a partial one: zero hits
    is what a healthy-but-quiet grid also returns, so any surface that reads the
    body without reading `_shards` renders the outage as a calm network.
    """
    return {
        "took": 41,
        "timed_out": True,
        "_shards": copy.deepcopy(HALF_READ_SHARDS),
        "hits": {"total": {"value": 0, "relation": "eq"}, "max_score": None, "hits": []},
    }


def saturated_response() -> dict:
    """The parent circuit breaker tripping — HTTP 429, and RETRYABLE."""
    reason = (
        "[parent] Data too large, data for [<http_request>] would be [7936000000/7.3gb], "
        "which is larger than the limit of [7818182655/7.2gb], "
        "real usage: [7900000000/7.3gb], new bytes reserved: [36000000/34.3mb]"
    )
    cause = {
        "type": "circuit_breaking_exception",
        "reason": reason,
        "bytes_wanted": 7936000000,
        "bytes_limit": 7818182655,
        "durability": "TRANSIENT",
    }
    return {"error": {"root_cause": [cause], **cause}, "status": 429}


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

    # -- degraded-grid plumbing ------------------------------------------------

    def _reset_connection(self) -> None:
        """Hard TCP reset before any response byte — a transport-level failure.

        SO_LINGER with a zero timeout makes close() send RST instead of FIN, so
        the ES client raises a connection error rather than seeing a clean EOF
        it might read as an empty response. That distinction is the point: the
        app's guards catch transport errors, and a tidy 503 body would exercise
        a different path entirely.
        """
        with contextlib.suppress(OSError):
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.close_connection = True
        with contextlib.suppress(OSError):
            self.connection.close()

    def _stall(self) -> None:
        """Accept the request and never answer it.

        Waits on the state-change event rather than sleeping outright, so
        switching back to healthy frees every tarpitted connection at once
        instead of making the next screen queue behind this one.
        """
        _state_changed.wait(STALL_SECONDS)
        self._reset_connection()

    def _handle_control(self, path: str) -> None:
        """GET/POST /__degrade[/<state>] — only mounted with --degraded-control."""
        self._body()  # drain, so the client sees the response and not a reset
        parts = [p for p in path.split("/") if p]
        if len(parts) == 1:
            self._send({"state": degrade_state(), "stall_seconds": STALL_SECONDS})
            return
        want = parts[1].replace("_", "-")
        if want not in DEGRADE_STATES:
            self._send({"error": "unknown state", "known": list(DEGRADE_STATES)}, status=400)
            return
        set_degrade_state(want)
        print(f"mock ES: grid state → {want}", flush=True)
        self._send({"state": want, "stall_seconds": STALL_SECONDS})

    def _degrade(self, path: str) -> bool:
        """Apply the current degraded state; True when the request is finished.

        Scope: the Elasticsearch surface only. ``/v1/*`` is the LiteLLM mock and
        stays healthy in every state, so a screen complaining about the model
        gateway can never be mistaken for a screen complaining about the grid.
        """
        state = degrade_state()
        if state == "healthy" or path.startswith("/v1/"):
            return False
        if state == "down":
            self._reset_connection()
            return True
        if state == "stalled":
            self._stall()
            return True
        if state == "saturated":
            self._body()
            self._send(saturated_response(), status=429)
            return True
        if state == "half-read":
            # A half-read cluster still answers info and still accepts writes —
            # it is reads that come back incomplete. Degrading the ping too would
            # make this indistinguishable from `down` on the health surfaces.
            if "_search" in path or "_count" in path:
                self._body()
                self._send(half_read_response())
                return True
            return False
        return False

    def _route(self) -> None:
        path = self.path.split("?")[0]
        if CONTROL_ENABLED and (path == "/__degrade" or path.startswith("/__degrade/")):
            self._handle_control(path)
            return
        if self._degrade(path):
            return
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
        # Index-existence probes are grid reads too: degrade them, or a down
        # grid still reports every index present.
        if self._degrade(self.path.split("?")[0]):
            return
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
    parser.add_argument(
        "--degraded-control",
        action="store_true",
        help="mount POST /__degrade/<state> so a walkthrough can switch the "
        "simulated grid failure without restarting the app. OFF BY DEFAULT and "
        "never passed by the public demo container: with the endpoint mounted, "
        "any visitor could fake an outage for everyone else. Local harnesses "
        "only (scripts/dogfood_degraded.mjs).",
    )
    parser.add_argument(
        "--stall-seconds",
        type=float,
        default=40.0,
        metavar="N",
        help="how long the 'stalled' state holds a request before resetting it "
        "(default 40 — past settings.webui_grid_timeout_s of 12, and long enough "
        "for a route missing that budget to burn the full ES retry budget)",
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
    if args.degraded_control:
        global CONTROL_ENABLED, STALL_SECONDS  # noqa: PLW0603 — CLI wiring before serve_forever
        CONTROL_ENABLED = True
        STALL_SECONDS = args.stall_seconds
        print(
            "mock ES: degraded control ON — POST /__degrade/"
            f"{{{'|'.join(DEGRADE_STATES)}}} (stall {STALL_SECONDS:g}s). "
            "Local harness only; never enable this on a public demo."
        )
    # Loopback bind on purpose: in the demo container the app connects over
    # 127.0.0.1 (the demo egress guard's one sanctioned ES path); the port is
    # never published.
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock ES+LLM listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
