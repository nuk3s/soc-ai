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


# ---------------------------------------------------------------------------
# Query matching + generic aggregation (the detection-bridge slice, Task 8).
#
# The Alerts-console paths above answer only the two hardcoded ``rule.name`` /
# ``notice.note`` shapes. The detection bridge and the slice-2 behavioral-
# analytics tools issue a WIDER — but still small and fixed — set of request
# shapes this mock has to serve from the same fixture docs:
#
#   * ``dry_run_detection`` (soc_ai.detection.validators) runs a drafted OQL as
#     a would-have-fired ``| count`` (``size=0`` + ``track_total_hits``) and a
#     ``| head 5`` sample — so we need to actually MATCH the translated ES DSL
#     against the docs and return a real ``hits.total.value`` / hit list.
#   * the analytics tools (soc_ai.tools.analytics) and ``resolve_agg_field``
#     (soc_ai.so_client.fields) issue generic ``terms`` aggregations (nested
#     ``terms`` / ``top_hits`` / ``avg`` / ``min`` sub-aggs) and ``size=0``
#     ``exists`` count probes.
#
# The matcher below covers EXACTLY the DSL clause shapes those two producers
# emit (soc_ai.so_client.oql.ast_to_es_dsl + the analytics query bodies) — no
# general-purpose ES engine, just enough to answer them faithfully. A ``range``
# on ``@timestamp`` is treated as always-true: fixture docs are rebased to
# 'now' (:func:`_rebase_docs_to_now`), so any recent/count window contains them.
# ---------------------------------------------------------------------------


def _is_absent(value) -> bool:
    """A value is absent iff ``None`` / ``""`` / empty collection (a ``0`` is real)."""
    if value is None:
        return True
    if isinstance(value, (str, list, tuple, dict)):
        return len(value) == 0
    return False


def _get_field(source: dict, path: str):
    """Read a dotted ECS path from a doc ``_source`` (flat-dotted first, then nested).

    Local twin of :func:`soc_ai.so_client.fields.get_dotted`, kept here so this
    mock stays importable standalone (it only imports ``demo_dataset``) — the
    same reason :func:`_doc_group_key` navigates nested docs by hand.
    """
    if path in source:
        return source[path]
    value = source
    for segment in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(segment)
        if value is None:
            return None
    return value


def _value_matches(actual, expected) -> bool:
    """``term``/``terms`` equality, string-coerced; membership when the doc value is a list."""
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(str(a) == str(expected) for a in actual)
    return str(actual) == str(expected)


def _bool_matches(node: dict, source: dict) -> bool:
    """Evaluate an ES ``bool`` clause (must / filter / must_not / should)."""
    if any(not _doc_matches(c, source) for c in node.get("must") or []):
        return False
    if any(not _doc_matches(c, source) for c in node.get("filter") or []):
        return False
    if any(_doc_matches(c, source) for c in node.get("must_not") or []):
        return False
    should = node.get("should") or []
    if should:
        msm = node.get("minimum_should_match")
        if msm is None:
            # ES default: 1 when `should` stands alone, 0 alongside must/filter.
            msm = 0 if (node.get("must") or node.get("filter")) else 1
        if sum(1 for c in should if _doc_matches(c, source)) < int(msm):
            return False
    return True


def _doc_matches(clause: dict, source: dict) -> bool:
    """True iff ``source`` satisfies one ES query DSL ``clause``.

    Supports the bounded clause set the OQL translator and the analytics tools
    emit: ``bool``, ``term``, ``terms``, ``match``/``match_phrase`` (substring),
    ``exists``, ``match_all``, and ``range`` (always-true, see the module note).
    """
    if not isinstance(clause, dict) or not clause:
        return True  # {} == match_all (ES default)
    if "bool" in clause:
        return _bool_matches(clause["bool"], source)
    if "match_all" in clause:
        return True
    if "term" in clause:
        field, value = next(iter(clause["term"].items()))
        return _value_matches(_get_field(source, field), value)
    if "terms" in clause:
        field, values = next(iter(clause["terms"].items()))
        actual = _get_field(source, field)
        return any(_value_matches(actual, v) for v in values or [])
    if "match" in clause or "match_phrase" in clause:
        op = "match" if "match" in clause else "match_phrase"
        field, text = next(iter(clause[op].items()))
        actual = _get_field(source, field)
        return actual is not None and str(text).lower() in str(actual).lower()
    if "exists" in clause:
        return not _is_absent(_get_field(source, clause["exists"].get("field", "")))
    # A range (only ever on @timestamp here) is always-true: rebased-to-now
    # fixtures fall inside any real window. Any other clause type: no match.
    return "range" in clause


def _is_matchable(query: dict) -> bool:
    """True when a query is worth evaluating doc-by-doc (i.e. not a bare match_all).

    Keeps ``{"match_all": {}}`` / ``{}`` answering EMPTY the way the demo app's
    unknown-query contract expects, while a ``bool``/``term``/… query gets
    matched against the docs.
    """
    return isinstance(query, dict) and any(
        k in query for k in ("bool", "term", "terms", "match", "match_phrase", "exists", "range")
    )


def _sorted_by_sort(docs: list[dict], sort) -> list[dict]:
    """Order ``docs`` by a top_hits ``sort`` clause — only ``@timestamp`` is honoured."""
    if not isinstance(sort, list) or not sort or not isinstance(sort[0], dict) or not sort[0]:
        return list(docs)
    field, spec = next(iter(sort[0].items()))
    order = spec.get("order") if isinstance(spec, dict) else spec
    if field == "@timestamp":
        return sorted(docs, key=_doc_ts, reverse=str(order).lower() == "desc")
    return list(docs)


def _top_hits_agg(opts: dict, docs: list[dict]) -> dict:
    """A ``top_hits`` sub-agg: the (sorted, sliced) raw hits, each with its ``_id``."""
    ordered = _sorted_by_sort(docs, opts.get("sort"))
    size = int(opts.get("size", 3))
    hits = [
        {"_index": d.get("_index", "logs-demo"), "_id": d.get("_id"), "_source": _doc_source(d)}
        for d in ordered[:size]
    ]
    return {"hits": {"total": {"value": len(docs), "relation": "eq"}, "hits": hits}}


def _metric_agg(field: str, docs: list[dict], kind: str) -> dict:
    """A single-value metric sub-agg (``avg`` / ``min`` / ``max``).

    ``@timestamp`` returns the ES date shape (``value`` epoch-millis +
    ``value_as_string``) so ``first_seen``'s ``min`` first-seen read works.
    """
    if field == "@timestamp":
        stamps = [_doc_ts(d) for d in docs if _doc_source(d).get("@timestamp") is not None]
        if not stamps:
            return {"value": None}
        chosen = min(stamps) if kind == "min" else max(stamps)
        return {"value": chosen.timestamp() * 1000.0, "value_as_string": _iso(chosen)}
    values = [
        float(v)
        for d in docs
        if isinstance((v := _get_field(_doc_source(d), field)), (int, float))
        and not isinstance(v, bool)
    ]
    if not values:
        return {"value": None}
    if kind == "avg":
        return {"value": sum(values) / len(values)}
    return {"value": min(values) if kind == "min" else max(values)}


def _terms_agg(body: dict, docs: list[dict]) -> dict:
    """A ``terms`` agg over ``docs``: buckets by field value, with nested sub-aggs.

    ES default bucket order (doc_count desc, term asc) unless an explicit
    ``order: {"_count": "asc"}`` is given; ``sum_other_doc_count`` reflects docs
    dropped by the ``size`` cap.
    """
    spec = body["terms"]
    field = spec["field"]
    size = int(spec.get("size", 10))
    count_asc = (spec.get("order") or {}).get("_count") == "asc"

    groups: dict = {}
    for doc in docs:
        key = _get_field(_doc_source(doc), field)
        if _is_absent(key):
            continue
        groups.setdefault(key, []).append(doc)

    items = sorted(
        groups.items(),
        key=lambda kv: (len(kv[1]), str(kv[0])) if count_asc else (-len(kv[1]), str(kv[0])),
    )
    kept, dropped = items[:size], items[size:]
    nested = body.get("aggs")
    buckets = []
    for key, members in kept:
        bucket = {"key": key, "doc_count": len(members)}
        if nested:
            bucket.update(_run_aggs(nested, members))
        buckets.append(bucket)
    return {
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": sum(len(m) for _, m in dropped),
        "buckets": buckets,
    }


def _run_aggs(aggs_spec: dict, docs: list[dict]) -> dict:
    """Evaluate a named-agg spec against ``docs`` — the bounded set the tools emit."""
    out: dict = {}
    for name, body in (aggs_spec or {}).items():
        if "terms" in body:
            out[name] = _terms_agg(body, docs)
        elif "top_hits" in body:
            out[name] = _top_hits_agg(body["top_hits"], docs)
        elif "avg" in body:
            out[name] = _metric_agg(body["avg"]["field"], docs, "avg")
        elif "min" in body:
            out[name] = _metric_agg(body["min"]["field"], docs, "min")
        elif "max" in body:
            out[name] = _metric_agg(body["max"]["field"], docs, "max")
        else:
            out[name] = {}
    return out


def _build_detection_fixture_docs() -> list[dict]:
    """A small, self-contained fixture for the detection-bridge slice's tests.

    A Zerologon-shaped ``zeek.dce_rpc`` cluster (a burst of
    ``NetrServerAuthenticate3`` — plus the ``NetrServerReqChallenge`` that
    precedes each — from one workstation against a domain controller's netlogon
    pipe, alongside benign DCE-RPC noise so the operation histogram is
    discriminating and a would-have-fired count on the dangerous operations is
    meaningful), plus a handful of ``zeek.dns`` and ``zeek.conn`` docs so the
    slice-2 behavioral-analytics tools have something to read.

    Addressing is RFC5737 / RFC2606 placeholder space ONLY (192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24, ``example.test``) so this fixture carries
    no lab identifier and ``tests/test_demo_leak_gate.py`` stays green. The
    operation lives under ``zeek.dce_rpc.operation`` (not the ECS
    ``dce_rpc.operation``) because that is the only form the OQL field whitelist
    admits — so a drafted rule keying on it can actually dry-run against these.
    """
    dc = "192.0.2.10"  # the domain controller under attack
    attacker = "198.51.100.23"  # the workstation running the Zerologon burst
    workstation = "198.51.100.50"  # a benign internal host
    resolver = "192.0.2.53"
    external = "203.0.113.77"
    base = datetime(2026, 8, 23, 9, 0, 0, tzinfo=UTC)
    docs: list[dict] = []

    def _dce(op: str, *, src: str, minute: int) -> None:
        seq = len(docs) + 1
        docs.append(
            {
                "_index": "logs-detection",
                "_id": f"zl-dce-{seq:06d}",
                "_source": {
                    "@timestamp": _iso(base + timedelta(minutes=minute)),
                    "event": {"dataset": "zeek.dce_rpc"},
                    "source": {"ip": src, "port": 50000 + seq},
                    "destination": {"ip": dc, "port": 135},
                    "host": {"name": "dc01.example.test"},
                    "zeek": {"dce_rpc": {"operation": op, "endpoint": "netlogon"}},
                },
            }
        )

    for minute in range(8):  # the malicious burst — the discriminating signal
        _dce("NetrServerAuthenticate3", src=attacker, minute=minute)
    for minute in range(3):
        _dce("NetrServerReqChallenge", src=attacker, minute=minute)
    for i in range(4):  # benign DCE-RPC noise (must NOT match the drafted rule)
        _dce("NetrLogonSamLogonEx", src=workstation, minute=20 + i)
    _dce("SamrConnect5", src=workstation, minute=30)

    for i, qname in enumerate(
        ["www.example.test", "mail.example.test", "api.example.test", "cdn.example.test"]
    ):
        docs.append(
            {
                "_index": "logs-detection",
                "_id": f"zl-dns-{i + 1:02d}",
                "_source": {
                    "@timestamp": _iso(base + timedelta(minutes=40 + i)),
                    "event": {"dataset": "zeek.dns"},
                    "source": {"ip": workstation, "port": 40000 + i},
                    "destination": {"ip": resolver, "port": 53},
                    "host": {"name": "ws50.example.test"},
                    "dns": {"query": {"name": qname}},
                },
            }
        )

    for i in range(3):
        docs.append(
            {
                "_index": "logs-detection",
                "_id": f"zl-conn-{i + 1:02d}",
                "_source": {
                    "@timestamp": _iso(base + timedelta(minutes=50 + i)),
                    "event": {"dataset": "zeek.conn"},
                    "source": {"ip": workstation, "port": 45000 + i},
                    "destination": {"ip": external, "port": 443},
                    "host": {"name": "ws50.example.test"},
                    "client": {"bytes": 512 + i},
                },
            }
        )
    return docs


# The detection-bridge slice's shared fixture — imported by the mock-ES agg
# tests and the hermetic Zerologon draft e2e. Not wired into the running server
# by default (that serves --fixtures / demo_dataset); it is a test constant.
DETECTION_FIXTURE_DOCS: list[dict] = _build_detection_fixture_docs()


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

    # --- generic aggregation (behavioral-analytics tools + resolve_agg_field) --
    # Any terms agg OTHER than the two console shapes above: match the query
    # against the docs, then run the (possibly nested) aggs over what matched.
    if aggs:
        matched = [d for d in visible if _doc_matches(query, _doc_source(d))]
        return {
            "took": 3,
            "timed_out": False,
            "hits": {"total": {"value": len(matched), "relation": "eq"}, "hits": []},
            "aggregations": _run_aggs(aggs, matched),
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

    # --- count (dry_run `| count`; resolve_agg_field's exists probe) ----------
    # A size=0 query with no aggregation asks only for a total: match the query
    # against the docs and return the real count, so a drafted rule's
    # would-have-fired dry run reports a true `hits.total.value`.
    if body.get("size") == 0:
        matched = [d for d in visible if _doc_matches(query, _doc_source(d))]
        return {
            "took": 1,
            "timed_out": False,
            "hits": {"total": {"value": len(matched), "relation": "eq"}, "hits": []},
        }

    # --- generic hit listing (dry_run `| head N`) ----------------------------
    # Any other bool/term/… query (not a bare match_all): return the matching
    # docs newest-first, capped to `size`, so the dry run's sample-id fetch
    # resolves against real evidence. A match_all/empty query stays EMPTY here,
    # preserving the demo's "unknown query answers empty, not an error" contract.
    if _is_matchable(query):
        matching = sorted(
            (d for d in visible if _doc_matches(query, _doc_source(d))),
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


# A sort on `_id` needs fielddata, which stock ES 9 ships disabled
# (`indices.id_field_data.enabled=false`) — every data-bearing shard fails.
# Unlike the opt-in /__degrade states above, this is not a simulated outage: it
# is what a real ES 9 cluster does on ANY request that asks for it, healthy or
# not, so the check below runs unconditionally wherever `_search` is dispatched.
ID_SORT_REJECTED_SHARDS = {
    "total": 76,
    "successful": 18,
    "skipped": 0,
    "failed": 58,
    "failures": [
        {
            "shard": 0,
            "index": "soc-ai-audit-000001",
            "node": None,
            "reason": {
                "type": "illegal_argument_exception",
                "reason": "Fielddata access on the _id field is disallowed, you can "
                "re-enable it by updating the dynamic cluster setting: "
                "indices.id_field_data.enabled",
            },
        }
    ],
}


def id_sort_rejected_response(body: dict) -> dict | None:
    """The ES 9 shard-failure shape for a search that sorts on ``_id``, or None.

    Regression guard for the audit-verify fix (``soc_ai/audit/verify.py``, found
    2026-08-20): ``_fetch_audit_records``'s ``search_after`` tiebreak used to sort
    on ``_id``, which a real 93M-doc ES 9 grid refused on every data-bearing shard
    ("58 of 76 shards failed"). Reproduced here so this mock stays faithful to a
    real ES 9 cluster and a reintroduced ``_id`` sort fails against the demo/CI
    replay path too, not only on a live upgrade.
    """
    sort = body.get("sort")
    if not isinstance(sort, list) or not any(
        isinstance(clause, dict) and "_id" in clause for clause in sort
    ):
        return None
    return {
        "took": 4,
        "timed_out": False,
        "_shards": copy.deepcopy(ID_SORT_REJECTED_SHARDS),
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
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
            rejected = id_sort_rejected_response(body)
            if rejected is not None:
                self._send(rejected)
            elif FIXTURE_DOCS is not None:
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
