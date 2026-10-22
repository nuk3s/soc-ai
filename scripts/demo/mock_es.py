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
                                * the host page's conversation and account
                                  passes for the hosts in demo_dataset.py's
                                  HOST_PEERS / HOST_USERS (dataset mode only)
                              Source: demo_dataset.py's TEST-NET groups by
                              default, or — with ``--fixtures FILE`` — the
                              sanitized documents of a packaged
                              soc_ai/demo/fixtures.json (the demo container).
  POST/GET *_count          → {"count": N} (fixtures mode only)
  anything else             → 200 {"acknowledged": true} (index bootstrap,
                              audit writes, bulk, templates, …)

Every value returned is synthetic or sanitized-and-owner-reviewed.
Run: .venv/bin/python scripts/demo/mock_es.py [port]
     python scripts/demo/mock_es.py --port 9200 --fixtures soc_ai/demo/fixtures.json

Fixture files
-------------
Fixtures mode reads a fixture file into a ``FixtureGrid`` with
``load_fixture`` and answers each search with ``fixture_search``.

Version 1 holds ``alerts[]``. Each search moves the newest alert to now.

Version 2 holds ``alerts[]``, ``documents[]`` and ``traffic``. Every ISO-8601
instant in the file is written relative to ``anchor``. The load moves each one
by ``now - anchor`` once. ``traffic.hosts`` gives the host page its peers,
volume and accounts. ``traffic.silent`` gives the spans in which the sensor
recorded nothing. A search then reads the documents with no copy.

The engine evaluates the query clauses, the request options and the nestable
aggregations that the console pages send. ``search_docs`` lists them. A range
on ``@timestamp`` is real, so a 24 hour view drops an older alert.

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
import calendar
import contextlib
import copy
import dataclasses
import fnmatch
import functools
import ipaddress
import json
import operator
import re
import socket
import struct
import sys
import threading
import zoneinfo
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

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


# Share of a day's connections per UTC hour: an office that browses 08-18.
_HOUR_WEIGHT = [2, 1, 1, 1, 1, 2, 4, 7, 11, 12, 12, 11, 9, 11, 12, 12, 11, 9, 6, 4, 3, 3, 2, 2]


def _spread(total: int, weights: list[int]) -> list[int]:
    """Split ``total`` over ``weights``; the counts sum to ``total`` exactly."""
    whole = sum(weights) or 1
    counts = [total * w // whole for w in weights]
    counts[-1] += total - sum(counts)
    return counts


def _host_conn_response(aggs: dict[str, Any]) -> dict[str, Any] | None:
    """The host page's conversation pass: peers both ways, the dataset, the volume.

    Answers only a host listed in ``demo_dataset.HOST_PEERS``. ``None`` for any
    other host, so it falls through to the empty answer it always had.
    """
    out_term = ((aggs.get("out") or {}).get("filter") or {}).get("term") or {}
    peers = dd.HOST_PEERS.get(str(out_term.get("source.ip") or ""))
    if peers is None:
        return None
    interval = ((aggs.get("volume") or {}).get("date_histogram") or {}).get("calendar_interval")
    daily = interval in ("day", "1d")
    scale = 6 if daily else 1  # a week holds five working days and a quiet weekend

    def side(direction: str) -> dict[str, Any]:
        rows = sorted(
            ((ip, port, n * scale) for ip, d, port, n in peers if d == direction),
            key=lambda row: -row[2],
        )
        return {
            "doc_count": sum(n for _, _, n in rows),
            "peers": {
                "buckets": [
                    {
                        "key": ip,
                        "doc_count": n,
                        "ports": {"buckets": [{"key": port, "doc_count": n}]},
                    }
                    for ip, port, n in rows
                ]
            },
        }

    total = sum(n for _, _, _, n in peers) * scale
    now = datetime.now(UTC)
    if daily:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=6)
        stamps = [start + timedelta(days=i) for i in range(7)]
        weights = [10 if ts.weekday() < 5 else 3 for ts in stamps]
    else:
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
        stamps = [start + timedelta(hours=i) for i in range(24)]
        weights = [_HOUR_WEIGHT[ts.hour] for ts in stamps]
    volume = [
        {"key": int(ts.timestamp() * 1000), "key_as_string": _iso(ts), "doc_count": n}
        for ts, n in zip(stamps, _spread(total, weights), strict=True)
    ]
    return {
        "took": 4,
        "timed_out": False,
        "hits": {"total": {"value": total, "relation": "eq"}, "hits": []},
        "aggregations": {
            "by_dataset": {"buckets": [{"key": "zeek.conn", "doc_count": total}]},
            "by_stream_dataset": {"buckets": []},
            "out": side("out"),
            "in": side("in"),
            "volume": {"buckets": volume},
        },
    }


def _host_users_response(aggs: dict[str, Any], query: dict[str, Any]) -> dict[str, Any] | None:
    """The host page's auth pass: the accounts and the one agent that wrote them."""
    held = dd.HOST_USERS.get(str(_terms_in(query).get("host.ip") or ""))
    if held is None or "users" not in aggs or "agents" not in aggs:
        return None
    agent, users = held
    total = sum(n for _, n in users)
    last = _iso(datetime.now(UTC) - timedelta(minutes=17))
    return {
        "took": 2,
        "timed_out": False,
        "hits": {"total": {"value": total, "relation": "eq"}, "hits": []},
        "aggregations": {
            "agents": {"buckets": [{"key": agent, "doc_count": total}]},
            "users": {
                "buckets": [
                    {"key": name, "doc_count": n, "last": {"value_as_string": last}}
                    for name, n in users
                ]
            },
        },
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

    # --- host page: conversations and accounts of a listed host --------------
    if "out" in aggs and "in" in aggs and "volume" in aggs:
        conn = _host_conn_response(aggs)
        if conn is not None:
            return conn
    if "users" in aggs:
        users = _host_users_response(aggs, query)
        if users is not None:
            return users

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
# Fixtures mode (the public demo container, docker/demo-entrypoint.sh).
#
# The mock serves the documents of a packaged soc_ai/demo/fixtures.json and
# answers each search with a small query and aggregation engine. A version 2
# file adds telemetry documents and a traffic model for the host page. Its
# times move once at load, so that the anchor of the file lands at now. A
# version 1 file keeps the older rule: each search moves the newest alert to
# now. Same ``_search`` response contract as :func:`_search_response` (the app
# is the shared consumer), computed from real documents.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class FixtureGrid:
    """The documents and the traffic model of one fixture file.

    ``shifted`` is True for a version 2 file. Its times already sit relative
    to now, so a search reads the documents with no copy.
    """

    docs: list[dict]
    traffic: dict[str, Any] = dataclasses.field(default_factory=dict)
    version: int = 1
    shifted: bool = False


FIXTURE: FixtureGrid | None = None  # set by main() when --fixtures is given

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_HOUR_MS = 3_600_000
_DAY_MS = 86_400_000
# An instant as the fixture builder writes it. Only a full match moves at load.
_INSTANT = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})?")
_NUMBER = re.compile(r"-?\d+(\.\d+)?")


def _doc_list(raw: Any) -> list[dict]:
    return [d for d in raw if isinstance(d, dict)] if isinstance(raw, list) else []


def _shift_text(text: str, delta: timedelta) -> str:
    found = _INSTANT.fullmatch(text)
    if found is None:
        return text
    base, fraction, zone = found.groups()
    try:
        wall = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
        if fraction:
            wall = wall.replace(microsecond=int(fraction[1:].ljust(6, "0")))
        wall += delta
    except (ValueError, OverflowError):
        return text
    out = wall.strftime("%Y-%m-%dT%H:%M:%S")
    if fraction:
        out += "." + f"{wall.microsecond:06d}"[: len(fraction) - 1]
    return out + (zone or "")


def shift_times(value: Any, delta: timedelta) -> Any:
    """Return a copy of ``value`` with each ISO-8601 instant moved by ``delta``.

    The walk goes through dicts and lists. It moves string values and never
    keys. A moved string keeps its zone suffix and its count of fraction
    digits. A string with no zone is UTC, and it stays with no zone.
    """
    if isinstance(value, str):
        return _shift_text(value, delta)
    if isinstance(value, dict):
        return {key: shift_times(item, delta) for key, item in value.items()}
    if isinstance(value, list):
        return [shift_times(item, delta) for item in value]
    return value


def load_fixture(path: Path, *, now: datetime | None = None) -> FixtureGrid:
    """Read a fixture file into a :class:`FixtureGrid`. Fail-soft to an empty grid.

    Version 2: the grid holds ``alerts`` and ``documents``, and the traffic
    model. Every time moves once by ``now - anchor``, cut to whole seconds, so
    that two forms of one instant stay equal. Version 1: the grid holds the
    ``alerts`` as written, and each search moves the newest one to now.

    A missing or unparseable file must not stop the mock. The demo then
    serves an empty grid with no invented data. The app seeds its own
    fixtures in the same fail-soft way.
    """
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        data = None
    if not isinstance(data, dict):
        print(f"mock ES: no usable fixtures at {path}; serving an empty grid", file=sys.stderr)
        return FixtureGrid(docs=[])
    alerts = _doc_list(data.get("alerts"))
    version = data.get("version")
    version = version if isinstance(version, int) and not isinstance(version, bool) else 1
    if version < 2:
        return FixtureGrid(docs=alerts, version=version)
    docs = alerts + _doc_list(data.get("documents"))
    traffic = data.get("traffic") if isinstance(data.get("traffic"), dict) else {}
    anchor = data.get("anchor")
    anchor_ms = _text_ms(anchor) if isinstance(anchor, str) else None
    if anchor_ms is None:
        # No usable anchor: the newest document stands in for it.
        stamps = [_value_ms(_doc_source(d).get("@timestamp")) for d in docs]
        anchor_ms = max((s for s in stamps if s is not None), default=None)
    now_ms = _dt_ms(now or datetime.now(UTC))
    delta = timedelta(seconds=(now_ms - anchor_ms) // 1000 if anchor_ms is not None else 0)
    return FixtureGrid(
        docs=shift_times(docs, delta),
        traffic=shift_times(traffic, delta),
        version=version,
        shifted=True,
    )


def load_fixture_docs(path: Path) -> list[dict]:
    """The documents of a fixture file. Fail-soft to ``[]``.

    A version 1 file gives its ``alerts`` as written. A version 2 file gives
    its ``alerts`` and ``documents``, moved relative to now.
    """
    return load_fixture(path).docs


def _doc_source(doc: dict) -> dict:
    src = doc.get("_source")
    return src if isinstance(src, dict) else {}


def _doc_ts(doc: dict) -> datetime:
    raw = _doc_source(doc).get("@timestamp")
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:  # fixture docs always carry one; stay sortable anyway
        return datetime.now(UTC)


def _rebase_docs_to_now(docs: list[dict]) -> list[dict]:
    """Return copies of ``docs`` with ``@timestamp`` shifted so the newest lands
    at 'now', preserving relative ordering — keeps the demo alerts queue
    perpetually current regardless of container uptime. Inputs are never mutated,
    and the return is always a fresh list of copies (even when no doc carries a
    timestamp, so callers can treat the result as owned unconditionally).

    The version 1 path only. A version 2 file moves its times once at load.
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
# Time: epoch milliseconds, ISO-8601 text and ES date math.
# ---------------------------------------------------------------------------


def _dt_ms(when: datetime) -> int:
    """Epoch milliseconds of an aware datetime, exact to the millisecond."""
    delta = when - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1000 + delta.microseconds // 1000


def _ms_dt(ms: float) -> datetime:
    return _EPOCH + timedelta(milliseconds=int(ms))


def _ms_text(ms: float) -> str:
    """The ES text of an instant: UTC, three fraction digits and a ``Z``."""
    whole = int(ms)
    return _ms_dt(whole).strftime("%Y-%m-%dT%H:%M:%S") + f".{whole % 1000:03d}Z"


@functools.lru_cache(maxsize=16384)
def _text_ms(text: str) -> int | None:
    """Epoch milliseconds of an ISO-8601 string, or of a string of digits.

    A string with no zone is UTC. Any other string gives ``None``.
    """
    if text.lstrip("-").isdigit():
        return int(text)
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return _dt_ms(when)


def _value_ms(value: Any) -> int | None:
    """Epoch milliseconds of a document date value: a number or a string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        return _text_ms(value)
    return None


def _plain_ms(text: str, zone: tzinfo | None) -> int | None:
    if zone is None or text.lstrip("-").isdigit():
        return _text_ms(text)
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=zone)
    return _dt_ms(when)


def _zone(name: Any) -> tzinfo | None:
    """The ``time_zone`` of a range: an offset, ``UTC`` or an IANA name."""
    if not isinstance(name, str) or not name:
        return None
    if name in ("Z", "UTC", "utc"):
        return UTC
    found = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", name)
    if found:
        offset = timedelta(hours=int(found[2]), minutes=int(found[3]))
        return timezone(-offset if found[1] == "-" else offset)
    try:
        return zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError, OSError):
        return None


_MATH_STEP = re.compile(r"([+-])(\d+)([yMwdhHms])|/([yMwdhHms])")
_STEP_ARG = {"w": "weeks", "d": "days", "h": "hours", "H": "hours", "m": "minutes", "s": "seconds"}


def _add_unit(when: datetime, amount: int, unit: str) -> datetime:
    if unit in ("y", "M"):
        months = when.month - 1 + amount * (12 if unit == "y" else 1)
        year, month = when.year + months // 12, months % 12 + 1
        return when.replace(
            year=year, month=month, day=min(when.day, calendar.monthrange(year, month)[1])
        )
    return when + timedelta(**{_STEP_ARG[unit]: amount})


def _floor_unit(when: datetime, unit: str) -> datetime:
    """The start of the unit that holds ``when``, in UTC. A week starts on Monday."""
    when = when.astimezone(UTC)
    if unit == "s":
        return when.replace(microsecond=0)
    if unit == "m":
        return when.replace(second=0, microsecond=0)
    if unit in ("h", "H"):
        return when.replace(minute=0, second=0, microsecond=0)
    day = when.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == "d":
        return day
    if unit == "w":
        return day - timedelta(days=day.weekday())
    if unit == "q":
        return day.replace(month=(day.month - 1) // 3 * 3 + 1, day=1)
    if unit == "M":
        return day.replace(day=1)
    return day.replace(month=1, day=1)


def _date_ms(
    value: Any, now: datetime, *, round_up: bool = False, zone: tzinfo | None = None
) -> float | None:
    """Epoch milliseconds of an ES date value, or ``None`` for an unknown form.

    The value is an epoch number, an ISO-8601 string, or date math such as
    ``now-24h``, ``now-30d/d`` or ``2026-10-01T00:00:00Z||+1M``. A rounding
    moves to the start of the unit. With ``round_up`` it moves to the last
    millisecond of the unit. A range uses ``round_up`` for ``gt`` and ``lte``,
    as ES does.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("now"):
        when, steps = now.astimezone(UTC), text[3:]
    elif "||" in text:
        head, steps = text.split("||", 1)
        base = _plain_ms(head, zone)
        if base is None:
            return None
        when = _ms_dt(base)
    else:
        plain = _plain_ms(text, zone)
        return None if plain is None else float(plain)
    pos = 0
    while pos < len(steps):
        step = _MATH_STEP.match(steps, pos)
        if step is None:
            return None
        sign, amount, unit, rounding = step.groups()
        if rounding:
            when = _floor_unit(when, rounding)
            if round_up:
                when = _add_unit(when, 1, rounding) - timedelta(milliseconds=1)
        else:
            when = _add_unit(when, int(amount) if sign == "+" else -int(amount), unit)
        pos = step.end()
    return float(_dt_ms(when))


@functools.lru_cache(maxsize=1024)
def _bound_ms(value: str | float, now_ms: int, round_up: bool, zone: tzinfo | None) -> float | None:
    # One request resolves the same bound once for every document.
    return _date_ms(value, _ms_dt(now_ms), round_up=round_up, zone=zone)


# ---------------------------------------------------------------------------
# Query matching.
#
# The clause set covers what the app sends: bool, term, terms, match,
# match_phrase, multi_match, exists, ids, wildcard, prefix, range, match_all,
# match_none and constant_score. Any other clause matches nothing. A range is
# real: date math, ISO strings and epoch numbers on a date field, numbers on a
# numeric field. A range with no bound it can read stays true.
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
    mock stays importable standalone (it only imports ``demo_dataset``).
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


def _values(source: dict, path: Any) -> list:
    """The values of a field as a list. A list field gives each element."""
    if not isinstance(path, str) or not path:
        return []
    raw = _get_field(source, path)
    if raw is None:
        return []
    if isinstance(raw, list):
        return [v for v in raw if v is not None]
    return [raw]


def _norm(value: Any) -> str:
    """The text that ``term`` equality compares. ``true`` is a JSON boolean."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and _NUMBER.fullmatch(value.strip()):
        return float(value)
    return None


@functools.lru_cache(maxsize=256)
def _network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _ip_number(text: str) -> int | None:
    try:
        return int(ipaddress.ip_address(text))
    except ValueError:
        return None


def _equals(actual: Any, expected: Any, insensitive: bool = False) -> bool:
    left, right = _norm(actual), _norm(expected)
    if insensitive:
        return left.lower() == right.lower()
    if left == right:
        return True
    if "/" in right:  # an ip field matches a CIDR term
        net = _network(right)
        try:
            return net is not None and ipaddress.ip_address(left) in net
        except ValueError:
            return False
    return False


def _listed(value: Any) -> list:
    if isinstance(value, list):
        return value
    return [value] if isinstance(value, dict) else []


def _field_spec(spec: Any) -> tuple[str | None, Any]:
    """The field and its value of a one-field clause, past ``boost`` and ``_name``."""
    if isinstance(spec, dict):
        for key, value in spec.items():
            if key not in ("boost", "_name"):
                return key, value
    return None, None


def _min_should(raw: Any, count: int, default: int) -> int:
    if raw is None:
        return default
    text = str(raw).strip()
    try:
        if text.endswith("%"):
            pct = int(text[:-1])
            need = count * pct // 100 if pct >= 0 else count - count * -pct // 100
        else:
            need = int(text)
            need = count + need if need < 0 else need
    except ValueError:
        return default
    return max(need, 0)


def _q_bool(spec: Any, doc: dict, now: datetime) -> bool:
    if not isinstance(spec, dict):
        return True
    scoped = _listed(spec.get("must")) + _listed(spec.get("filter"))
    if not all(_matches(c, doc, now) for c in scoped):
        return False
    if any(_matches(c, doc, now) for c in _listed(spec.get("must_not"))):
        return False
    should = _listed(spec.get("should"))
    if not should:
        return True
    # ES default: 1 when `should` stands alone, 0 beside must/filter.
    need = _min_should(spec.get("minimum_should_match"), len(should), 0 if scoped else 1)
    found = 0
    for clause in should:
        if found >= need:
            break
        if _matches(clause, doc, now):
            found += 1
    return found >= need


def _q_term(spec: Any, doc: dict, now: datetime) -> bool:
    field, raw = _field_spec(spec)
    insensitive = False
    if isinstance(raw, dict):
        insensitive = bool(raw.get("case_insensitive"))
        raw = raw.get("value")
    if field is None or raw is None:
        return False
    return any(_equals(v, raw, insensitive) for v in _values(_doc_source(doc), field))


def _q_terms(spec: Any, doc: dict, now: datetime) -> bool:
    field, wanted = _field_spec(spec)
    if field is None or not isinstance(wanted, list):
        return False  # a terms lookup is not served
    values = _values(_doc_source(doc), field)
    return any(_equals(v, w) for v in values for w in wanted)


def _q_match(spec: Any, doc: dict, now: datetime) -> bool:
    # Case-insensitive substring: close enough to an analyzed match here.
    field, raw = _field_spec(spec)
    if isinstance(raw, dict):
        raw = raw.get("query")
    if field is None or raw is None:
        return False
    text = str(raw).lower()
    return any(text in str(v).lower() for v in _values(_doc_source(doc), field))


def _q_multi_match(spec: Any, doc: dict, now: datetime) -> bool:
    if not isinstance(spec, dict) or spec.get("query") is None:
        return False
    text = str(spec["query"]).lower()
    source = _doc_source(doc)
    for name in spec.get("fields") or []:
        path = str(name).split("^", 1)[0]
        values = _values(source, path)
        if not values and path.endswith(".text"):  # the analyzed sibling of a keyword
            values = _values(source, path[: -len(".text")])
        if any(text in str(v).lower() for v in values):
            return True
    return False


def _q_exists(spec: Any, doc: dict, now: datetime) -> bool:
    name = spec.get("field") if isinstance(spec, dict) else None
    return isinstance(name, str) and not _is_absent(_get_field(_doc_source(doc), name))


def _q_ids(spec: Any, doc: dict, now: datetime) -> bool:
    wanted = spec.get("values") if isinstance(spec, dict) else None
    return isinstance(wanted, list) and str(doc.get("_id")) in {str(w) for w in wanted}


def _pattern_of(raw: Any, key: str) -> tuple[str | None, bool]:
    if isinstance(raw, dict):
        value = raw.get("value", raw.get(key))
        return (None if value is None else str(value)), bool(raw.get("case_insensitive"))
    return (None if raw is None else str(raw)), False


def _glob(text: str, pattern: str) -> bool:
    """Match ``*`` and ``?`` wildcards in O(len(text) * len(pattern)) time.

    A regex compiled from a visitor's OQL wildcard can backtrack without end.
    This loop cannot, so the public demo stays fast.
    """
    t = p = 0
    star, mark = -1, 0
    while t < len(text):
        if p < len(pattern) and pattern[p] in ("?", text[t]):
            t, p = t + 1, p + 1
        elif p < len(pattern) and pattern[p] == "*":
            star, mark, p = p, t, p + 1
        elif star >= 0:
            mark += 1
            t, p = mark, star + 1
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _q_wildcard(spec: Any, doc: dict, now: datetime) -> bool:
    field, raw = _field_spec(spec)
    pattern, insensitive = _pattern_of(raw, "wildcard")
    if field is None or pattern is None:
        return False
    if insensitive:
        pattern = pattern.lower()
    values = _values(_doc_source(doc), field)
    return any(_glob(str(v).lower() if insensitive else str(v), pattern) for v in values)


def _q_prefix(spec: Any, doc: dict, now: datetime) -> bool:
    field, raw = _field_spec(spec)
    prefix, insensitive = _pattern_of(raw, "prefix")
    if field is None or prefix is None:
        return False
    if insensitive:
        prefix = prefix.lower()
    values = _values(_doc_source(doc), field)
    return any((str(v).lower() if insensitive else str(v)).startswith(prefix) for v in values)


_RANGE_CHECK = {"gt": operator.gt, "gte": operator.ge, "lt": operator.lt, "lte": operator.le}


def _range_ops(bounds: dict) -> list[tuple[str, Any]]:
    ops = [(op, bounds[op]) for op in ("gt", "gte", "lt", "lte") if bounds.get(op) is not None]
    if bounds.get("from") is not None:
        ops.append(("gte" if bounds.get("include_lower", True) else "gt", bounds["from"]))
    if bounds.get("to") is not None:
        ops.append(("lte" if bounds.get("include_upper", True) else "lt", bounds["to"]))
    return ops


def _compare(value: Any, op: str, bound: Any, now: datetime, zone: tzinfo | None) -> bool | None:
    """One bound against one document value. ``None`` means an unknown form."""
    if isinstance(bound, (dict, list, bool)):
        return None
    check = _RANGE_CHECK[op]
    left, right = _number(value), _number(bound)
    if left is not None and right is not None:
        return check(left, right)
    moment = _value_ms(value)
    if moment is not None:
        limit = _bound_ms(bound, _dt_ms(now), op in ("gt", "lte"), zone)
        return None if limit is None else check(moment, limit)
    if isinstance(value, str) and isinstance(bound, str):
        left_ip, right_ip = _ip_number(value), _ip_number(bound)
        if left_ip is not None and right_ip is not None:
            return check(left_ip, right_ip)
        return check(value, bound)
    return None


def _q_range(spec: Any, doc: dict, now: datetime) -> bool:
    field, bounds = _field_spec(spec)
    if field is None or not isinstance(bounds, dict):
        return True
    ops = _range_ops(bounds)
    if not ops:
        return True  # an unknown range form stays true
    zone = _zone(bounds.get("time_zone"))
    for value in _values(_doc_source(doc), field):
        if all(_compare(value, op, bound, now, zone) is not False for op, bound in ops):
            return True
    return False


_CLAUSES: dict[str, Callable[[Any, dict, datetime], bool]] = {
    "bool": _q_bool,
    "match_all": lambda spec, doc, now: True,
    "match_none": lambda spec, doc, now: False,
    "term": _q_term,
    "terms": _q_terms,
    "match": _q_match,
    "match_phrase": _q_match,
    "multi_match": _q_multi_match,
    "exists": _q_exists,
    "ids": _q_ids,
    "wildcard": _q_wildcard,
    "prefix": _q_prefix,
    "range": _q_range,
    "constant_score": lambda spec, doc, now: _matches(
        spec.get("filter") if isinstance(spec, dict) else None, doc, now
    ),
}


def _matches(clause: Any, doc: dict, now: datetime) -> bool:
    """True when the document satisfies one ES query clause.

    An empty clause is ``match_all``, as in ES. A clause of a type this mock
    does not know matches nothing.
    """
    if not isinstance(clause, dict) or not clause:
        return True
    for kind, spec in clause.items():
        handler = _CLAUSES.get(kind)
        if handler is not None:
            return handler(spec, doc, now)
    return False


def _bare_match_all(query: Any) -> bool:
    return not isinstance(query, dict) or not query or set(query) == {"match_all"}


# ---------------------------------------------------------------------------
# Hits: sort, page and _source filtering.
# ---------------------------------------------------------------------------


def _int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return default


def _comparable(value: Any) -> tuple[int, Any] | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    if isinstance(value, (bool, int, float)):
        return (0, float(value))
    moment = _text_ms(str(value))
    return (0, float(moment)) if moment is not None else (1, str(value))


def _sort_keys(sort: Any) -> list[tuple[str, bool]]:
    keys: list[tuple[str, bool]] = []
    for item in sort if isinstance(sort, list) else [sort]:
        if isinstance(item, str):
            keys.append((item, item == "_score"))
        elif isinstance(item, dict):
            for name, spec in item.items():
                order = spec.get("order") if isinstance(spec, dict) else spec
                descending = str(order).lower() == "desc" if order else name == "_score"
                keys.append((name, descending))
    return keys


def _sorted_docs(docs: list[dict], sort: Any) -> list[dict]:
    """Order ``docs`` by an ES ``sort``. A document with no value sorts last."""
    ordered = list(docs)
    for name, descending in reversed(_sort_keys(sort)):
        if name in ("_doc", "_score", "_id"):
            continue
        present: list[tuple[tuple[int, Any], dict]] = []
        absent: list[dict] = []
        for doc in ordered:
            ranks = [r for v in _values(_doc_source(doc), name) if (r := _comparable(v))]
            if ranks:
                present.append(((max if descending else min)(ranks), doc))
            else:
                absent.append(doc)
        present.sort(key=operator.itemgetter(0), reverse=descending)
        ordered = [doc for _, doc in present] + absent
    return ordered


def _source_spec(spec: Any) -> tuple[list[str], list[str]] | None:
    """The includes and excludes of a ``_source`` option. ``None`` means no source."""
    if spec is False:
        return None
    if isinstance(spec, str):
        return [spec], []
    if isinstance(spec, list):
        return [str(s) for s in spec], []
    if isinstance(spec, dict):
        if spec.get("enabled") is False:
            return None
        includes = spec.get("includes", spec.get("include", []))
        excludes = spec.get("excludes", spec.get("exclude", []))
        return (
            [includes] if isinstance(includes, str) else list(includes or []),
            [excludes] if isinstance(excludes, str) else list(excludes or []),
        )
    return [], []


def _path_hit(path: str, patterns: list[str]) -> bool:
    return any(
        path == p or path.startswith(p + ".") or ("*" in p and fnmatch.fnmatchcase(path, p))
        for p in patterns
    )


def _filter_source(
    source: dict, includes: list[str], excludes: list[str], prefix: str = ""
) -> dict:
    out: dict = {}
    for key, value in source.items():
        path = prefix + key
        if excludes and _path_hit(path, excludes):
            continue
        if not includes or _path_hit(path, includes):
            nested = excludes and isinstance(value, dict)
            out[key] = _filter_source(value, [], excludes, path + ".") if nested else value
        elif isinstance(value, dict):
            inner = _filter_source(value, includes, excludes, path + ".")
            if inner:
                out[key] = inner
    return out


def _hit(doc: dict, source: tuple[list[str], list[str]] | None) -> dict:
    """One search hit. The ``_source`` is the stored dict itself unless filtered."""
    hit: dict = {"_index": doc.get("_index", "logs-demo"), "_id": doc.get("_id"), "_score": None}
    if source is None:
        return hit
    includes, excludes = source
    stored = _doc_source(doc)
    hit["_source"] = _filter_source(stored, includes, excludes) if source != ([], []) else stored
    return hit


# ---------------------------------------------------------------------------
# Aggregations, nestable: terms, filter, filters, date_histogram, top_hits,
# cardinality, value_count, max, min, avg and sum.
# ---------------------------------------------------------------------------


def _sub_aggs(body: dict) -> dict:
    sub = body.get("aggs") or body.get("aggregations") or {}
    return sub if isinstance(sub, dict) else {}


def _run_aggs(aggs_spec: Any, docs: list[dict], now: datetime) -> dict:
    """Evaluate a named-agg spec against ``docs``."""
    if not isinstance(aggs_spec, dict):
        return {}
    return {name: _one_agg(body, docs, now) for name, body in aggs_spec.items()}


def _one_agg(body: Any, docs: list[dict], now: datetime) -> dict:
    if not isinstance(body, dict):
        return {}
    sub = _sub_aggs(body)
    if isinstance(body.get("terms"), dict):
        return _terms_agg(body["terms"], sub, docs, now)
    if "filter" in body:
        kept = [doc for doc in docs if _matches(body["filter"], doc, now)]
        return {"doc_count": len(kept), **_run_aggs(sub, kept, now)}
    if isinstance(body.get("filters"), dict):
        return _filters_agg(body["filters"], sub, docs, now)
    if isinstance(body.get("date_histogram"), dict):
        return _histogram_agg(body["date_histogram"], sub, docs, now)
    if isinstance(body.get("top_hits"), dict):
        return _top_hits(body["top_hits"], docs)
    if isinstance(body.get("cardinality"), dict):
        return _cardinality(body["cardinality"], docs)
    if isinstance(body.get("value_count"), dict):
        name = body["value_count"].get("field")
        return {"value": sum(len(_values(_doc_source(d), name)) for d in docs)}
    for kind in ("max", "min", "avg", "sum"):
        if isinstance(body.get(kind), dict):
            return _metric(kind, body[kind], docs)
    return {}


def _bucket_key(value: Any) -> Any:
    return value if isinstance(value, (str, int, float)) else None


def _key_fields(key: Any) -> dict:
    if isinstance(key, bool):  # ES answers a boolean term as 1 / 0
        return {"key": int(key), "key_as_string": "true" if key else "false"}
    return {"key": key}


def _key_rank(key: Any) -> tuple[int, Any]:
    if isinstance(key, (int, float)):
        return (0, float(key))
    return (1, str(key))


def _term_rule(rule: Any) -> Callable[[str], bool] | None:
    if isinstance(rule, list):
        wanted = {_norm(r) for r in rule}
        return wanted.__contains__
    if isinstance(rule, str):
        compiled = _regex(rule)
        if compiled is not None:
            return lambda text: compiled.fullmatch(text) is not None
    return None


@functools.lru_cache(maxsize=256)
def _regex(pattern: str) -> re.Pattern[str] | None:
    # Include and exclude patterns come from the app's own code, not a visitor.
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _order_keys(order: Any) -> list[tuple[str, bool]]:
    if order is None:
        return [("_count", True)]
    keys: list[tuple[str, bool]] = []
    for item in order if isinstance(order, list) else [order]:
        if isinstance(item, dict):
            keys += [(str(name), str(way).lower() == "desc") for name, way in item.items()]
    return keys or [("_count", True)]


def _order_value(name: str, key: Any, members: list[dict], early: dict) -> Any:
    if name == "_count":
        return len(members)
    if name in ("_key", "_term"):
        return _key_rank(key)
    head, _, prop = name.partition(".")
    agg = early.get(key, {}).get(head.split(">", 1)[0])
    if not isinstance(agg, dict):
        return None
    if prop:
        return agg.get(prop)
    return agg["value"] if "value" in agg else agg.get("doc_count")


def _sort_rows(rows: list, name: str, descending: bool, early: dict) -> None:
    def rank(row: tuple[Any, list[dict]]) -> tuple[int, Any]:
        value = _order_value(name, row[0], row[1], early)
        if value is None:  # an empty metric sorts last both ways
            return (0, 0) if descending else (1, 0)
        return (1, value) if descending else (0, value)

    rows.sort(key=rank, reverse=descending)


def _terms_agg(spec: dict, sub: dict, docs: list[dict], now: datetime) -> dict:
    """A ``terms`` agg: buckets by value, with ``size``, ``order``, ``missing``,
    ``include``, ``exclude``, ``min_doc_count`` and nested sub-aggs.

    The default order is the doc count, high first, then the key. An ``order``
    can name ``_count``, ``_key`` or a sub-agg, as a dict or a list of dicts.
    ``sum_other_doc_count`` counts the documents of the buckets the ``size`` cut.
    """
    name = spec.get("field")
    size = _int(spec.get("size"), 10)
    floor = max(_int(spec.get("min_doc_count"), 1), 1)
    missing = spec.get("missing")
    include, exclude = _term_rule(spec.get("include")), _term_rule(spec.get("exclude"))
    groups: dict[Any, list[dict]] = {}
    for doc in docs:
        keys = {k for v in _values(_doc_source(doc), name) if (k := _bucket_key(v)) is not None}
        if not keys and missing is not None:
            keys = {missing}
        for key in keys:
            text = _norm(key)
            if (include is None or include(text)) and (exclude is None or not exclude(text)):
                groups.setdefault(key, []).append(doc)
    rows = [(key, members) for key, members in groups.items() if len(members) >= floor]
    order = _order_keys(spec.get("order"))
    wanted = {
        n.partition(".")[0].split(">", 1)[0]
        for n, _ in order
        if n not in ("_count", "_key", "_term")
    }
    early_spec = {n: sub[n] for n in wanted if n in sub}
    early = (
        {key: _run_aggs(early_spec, members, now) for key, members in rows} if early_spec else {}
    )
    rows.sort(key=lambda row: _key_rank(row[0]))  # the last tie-break: the key
    for order_name, descending in reversed(order):
        _sort_rows(rows, order_name, descending, early)
    late_spec = {n: body for n, body in sub.items() if n not in early_spec}
    buckets = []
    for key, members in rows[:size]:
        bucket = _key_fields(key)
        bucket["doc_count"] = len(members)
        bucket.update(early.get(key, {}))
        bucket.update(_run_aggs(late_spec, members, now))
        buckets.append(bucket)
    return {
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": sum(len(members) for _, members in rows[size:]),
        "buckets": buckets,
    }


def _filters_agg(spec: dict, sub: dict, docs: list[dict], now: datetime) -> dict:
    """A ``filters`` agg: the keyed form gives a dict of buckets, the list form a list."""
    named = spec.get("filters")
    clauses = list(named.values()) if isinstance(named, dict) else _listed(named)

    def bucket(clause: Any) -> dict:
        kept = [doc for doc in docs if _matches(clause, doc, now)]
        return {"doc_count": len(kept), **_run_aggs(sub, kept, now)}

    other_key = spec.get("other_bucket_key")
    other = None
    if spec.get("other_bucket") or other_key:
        rest = [d for d in docs if not any(_matches(c, d, now) for c in clauses)]
        other = {"doc_count": len(rest), **_run_aggs(sub, rest, now)}
    if isinstance(named, dict):
        keyed = {str(key): bucket(clause) for key, clause in named.items()}
        if other is not None:
            keyed[str(other_key or "_other_")] = other
        return {"buckets": keyed}
    listed = [bucket(clause) for clause in clauses]
    if other is not None:
        listed.append(other)
    return {"buckets": listed}


def _top_hits(spec: dict, docs: list[dict]) -> dict:
    """A ``top_hits`` agg: ``size``, ``from``, ``sort`` on any field and ``_source``.

    With no ``sort`` the hits keep the input order.
    """
    ordered = _sorted_docs(docs, spec["sort"]) if spec.get("sort") else docs
    start, size = _int(spec.get("from"), 0), _int(spec.get("size"), 3)
    source = _source_spec(spec.get("_source"))
    return {
        "hits": {
            "total": {"value": len(docs), "relation": "eq"},
            "max_score": None,
            "hits": [_hit(doc, source) for doc in ordered[start : start + size]],
        }
    }


def _cardinality(spec: dict, docs: list[dict]) -> dict:
    name, missing = spec.get("field"), spec.get("missing")
    seen: set[str] = set()
    for doc in docs:
        values = _values(_doc_source(doc), name)
        if values:
            seen.update(_norm(v) for v in values)
        elif missing is not None:
            seen.add(_norm(missing))
    return {"value": len(seen)}


def _metric(kind: str, spec: dict, docs: list[dict]) -> dict:
    """A single-value metric: ``max``, ``min``, ``avg`` or ``sum``.

    A date field gives the ES date shape: ``value`` in epoch milliseconds and
    ``value_as_string``.
    """
    name = spec.get("field")
    numbers: list[float] = []
    dated = False
    for doc in docs:
        for value in _values(_doc_source(doc), name):
            number = _number(value)
            if number is None and isinstance(value, str):
                moment = _text_ms(value)
                if moment is not None:
                    number, dated = float(moment), True
            if number is not None:
                numbers.append(number)
    if not numbers:
        return {"value": 0.0} if kind == "sum" else {"value": None}
    if kind == "max":
        value = max(numbers)
    elif kind == "min":
        value = min(numbers)
    elif kind == "sum":
        value = sum(numbers)
    else:
        value = sum(numbers) / len(numbers)
    out: dict = {"value": float(value)}
    if dated and kind != "sum":
        out["value_as_string"] = _ms_text(value)
    return out


_CALENDAR_UNITS = {
    "minute": "m",
    "1m": "m",
    "hour": "h",
    "1h": "h",
    "day": "d",
    "1d": "d",
    "week": "w",
    "1w": "w",
    "month": "M",
    "1M": "M",
    "quarter": "q",
    "1q": "q",
    "year": "y",
    "1y": "y",
}
_FIXED = re.compile(r"(\d+)(ms|s|m|h|d)")
_FIXED_MS = {"ms": 1, "s": 1000, "m": 60_000, "h": _HOUR_MS, "d": _DAY_MS}
_MAX_BUCKETS = 10_000  # far past any demo page; stops a runaway bounds loop


def _interval(spec: dict) -> tuple[str | None, int] | None:
    """The step of a date_histogram: ``(unit, 0)`` on the calendar, ``(None, ms)`` fixed."""
    for key in ("calendar_interval", "interval", "fixed_interval"):
        raw = spec.get(key)
        if raw is None:
            continue
        text = str(raw)
        if key != "fixed_interval" and text in _CALENDAR_UNITS:
            return _CALENDAR_UNITS[text], 0
        found = _FIXED.fullmatch(text)
        if found and int(found[1]) > 0:
            return None, int(found[1]) * _FIXED_MS[found[2]]
        return None
    return None


def _step_floor(ms: int, step: tuple[str | None, int]) -> int:
    unit, fixed = step
    if unit is None:
        return ms - ms % fixed
    return _dt_ms(_floor_unit(_ms_dt(ms), unit))


def _step_next(ms: int, step: tuple[str | None, int]) -> int:
    unit, fixed = step
    if unit is None:
        return ms + fixed
    if unit == "q":
        return _dt_ms(_add_unit(_ms_dt(ms), 3, "M"))
    return _dt_ms(_add_unit(_ms_dt(ms), 1, unit))


def _step_keys(first: int, last: int, step: tuple[str | None, int]) -> list[int]:
    keys: list[int] = []
    key = first
    while key <= last and len(keys) < _MAX_BUCKETS:
        keys.append(key)
        key = _step_next(key, step)
    return keys


def _key_text(ms: int, fmt: Any) -> str:
    if fmt == "epoch_millis":
        return str(ms)
    if fmt == "epoch_second":
        return str(ms // 1000)
    if fmt in ("yyyy-MM-dd", "strict_date", "date"):
        return _ms_dt(ms).strftime("%Y-%m-%d")
    return _ms_text(ms)


def _histogram_agg(spec: dict, sub: dict, docs: list[dict], now: datetime) -> dict:
    """A ``date_histogram``: calendar, fixed or legacy interval.

    With ``min_doc_count`` 0, the default, the buckets run with no gap from
    the first to the last document. ``extended_bounds`` widens that run. A key
    is epoch milliseconds, and ``key_as_string`` is ISO-8601 UTC.
    """
    step = _interval(spec)
    if step is None:
        return {"buckets": []}
    name = spec.get("field") or "@timestamp"
    members: dict[int, list[dict]] = {}
    for doc in docs:
        values = _values(_doc_source(doc), name)
        keys = {_step_floor(ms, step) for v in values if (ms := _value_ms(v)) is not None}
        for key in keys:
            members.setdefault(key, []).append(doc)
    floor = _int(spec.get("min_doc_count"), 0)
    keys = sorted(members)
    if floor == 0:
        bounds = (
            spec.get("extended_bounds") if isinstance(spec.get("extended_bounds"), dict) else {}
        )
        edges = keys[:1] + keys[-1:]
        for raw in (bounds.get("min"), bounds.get("max")):
            ms = _date_ms(raw, now)
            if ms is not None:
                edges.append(_step_floor(int(ms), step))
        keys = _step_keys(min(edges), max(edges), step) if edges else []
    buckets = []
    for key in keys:
        group = members.get(key, [])
        if len(group) < floor:
            continue
        bucket = {"key_as_string": _key_text(key, spec.get("format")), "key": key}
        bucket["doc_count"] = len(group)
        bucket.update(_run_aggs(sub, group, now))
        buckets.append(bucket)
    order = spec.get("order")
    if isinstance(order, dict):
        if "_count" in order:
            descending = str(order["_count"]).lower() == "desc"
            buckets.sort(key=operator.itemgetter("doc_count"), reverse=descending)
        elif str(order.get("_key", "asc")).lower() == "desc":
            buckets.reverse()
    return {"buckets": buckets}


# ---------------------------------------------------------------------------
# The search: hits, total, aggregations, the Alerts groups and the host page.
# ---------------------------------------------------------------------------

_GROUP_FIELDS = ("rule.name", "notice.note")
# The per-group answers the Alerts console reads. A request that names its own
# sub-aggs wins; these fill the gaps, so an older or smaller request still gets
# the newest member and the handled counts.
_GROUP_DEFAULTS: dict[str, Any] = {
    "latest_ts": {"max": {"field": "@timestamp"}},
    "latest": {"top_hits": {"size": 1, "sort": [{"@timestamp": {"order": "desc"}}]}},
    "acked": {"filter": {"term": {"event.acknowledged": True}}},
    "escalated": {"filter": {"term": {"event.escalated": True}}},
}


def _with_group_defaults(agg: dict) -> dict:
    return {**agg, "aggs": {**_GROUP_DEFAULTS, **_sub_aggs(agg)}}


def _newest_first(agg: Any) -> None:
    if not isinstance(agg, dict) or not isinstance(agg.get("buckets"), list):
        return

    def newest(bucket: dict) -> float:
        value = (bucket.get("latest_ts") or {}).get("value")
        return float(value) if value is not None else float("-inf")

    agg["buckets"].sort(key=newest, reverse=True)


def _alert_groups(aggs: dict, docs: list[dict], now: datetime) -> dict:
    """The grouped Alerts path: the generic aggs, groups newest first.

    The groups are the ``rules`` terms buckets and the buckets of the sibling
    ``unnamed`` filter agg. Each bucket answers the request's own sub-aggs.
    """
    spec = dict(aggs)
    spec["rules"] = _with_group_defaults(aggs["rules"])
    unnamed = aggs.get("unnamed")
    if isinstance(unnamed, dict) and isinstance(_sub_aggs(unnamed).get("rules"), dict):
        inner = dict(_sub_aggs(unnamed))
        inner["rules"] = _with_group_defaults(inner["rules"])
        spec["unnamed"] = {**unnamed, "aggs": inner}
    out = _run_aggs(spec, docs, now)
    _newest_first(out.get("rules"))
    _newest_first((out.get("unnamed") or {}).get("rules"))
    return out


def _total(count: int, track: Any) -> dict:
    if isinstance(track, int) and not isinstance(track, bool) and count > track:
        return {"value": track, "relation": "gte"}
    return {"value": count, "relation": "eq"}


def search_docs(
    body: dict,
    docs: list[dict],
    *,
    traffic: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict:
    """Answer one ``_search`` body from ``docs``, with no copy of the docs.

    The request options are ``query``, ``size``, ``from``, ``sort``,
    ``_source``, ``track_total_hits``, and ``aggs`` or ``aggregations``. The
    default size is 10. The default sort is newest first. ``hits.total.value``
    counts every match.

    A bare ``match_all`` listing with no aggs answers empty. The mock serves
    one set of documents for every index, and a case or playbook read must
    not list alerts.

    ``traffic`` is the traffic model of a version 2 file. It answers the host
    page connection pass and users pass for the hosts it lists.
    """
    now = now or datetime.now(UTC)
    body = body if isinstance(body, dict) else {}
    aggs = body.get("aggs") or body.get("aggregations") or {}
    aggs = aggs if isinstance(aggs, dict) else {}
    query = body.get("query") or {}
    if traffic:
        answer = _traffic_answer(aggs, query, traffic, now)
        if answer is not None:
            return answer
    size, start = _int(body.get("size"), 10), _int(body.get("from"), 0)
    if not aggs and size > 0 and _bare_match_all(query):
        matched: list[dict] = []
    else:
        matched = [doc for doc in docs if _matches(query, doc, now)]
    hits: list[dict] = []
    if size > 0 and matched:
        ordered = _sorted_docs(matched, body.get("sort") or [{"@timestamp": "desc"}])
        source = _source_spec(body.get("_source"))
        hits = [_hit(doc, source) for doc in ordered[start : start + size]]
    response: dict = {
        "took": 2,
        "timed_out": False,
        "hits": {
            "total": _total(len(matched), body.get("track_total_hits")),
            "max_score": None,
            "hits": hits,
        },
    }
    if aggs:
        rules = ((aggs.get("rules") or {}).get("terms") or {}).get("field")
        grouped = rules in _GROUP_FIELDS
        response["aggregations"] = (
            _alert_groups(aggs, matched, now) if grouped else _run_aggs(aggs, matched, now)
        )
    return response


# ---------------------------------------------------------------------------
# The host page from the traffic model of a version 2 file.
#
# traffic.hosts[ip] holds a pattern, the peers with a daily rate and the
# accounts with a weekly logon count. traffic.silent holds the spans in which
# the sensor recorded nothing. The connection pass counts by the hour: each
# hour of the window gets the pattern weight times its live share, and a peer
# counts only inside its own since/until span. Every total agrees with the
# others: the volume buckets, the dataset bucket, the two sides and hits.total.
# ---------------------------------------------------------------------------

_MONDAY = datetime(2024, 1, 1, tzinfo=UTC)  # a busy weekday, the rate reference
_SERVER_PEAK = (1, 2)  # the server pattern peaks 01:00 to 03:00 UTC


def _pattern_weight(pattern: str, slot: datetime) -> int:
    """The weight of one hour. ``office`` has quiet nights and a quiet weekend."""
    if pattern == "office":
        weight = _HOUR_WEIGHT[slot.hour]
        return weight if slot.weekday() < 5 else max(1, weight // 4)
    if pattern == "server":
        return 12 if slot.hour in _SERVER_PEAK else 4
    return 4


def _spans(raw: Any) -> list[tuple[int, int]]:
    """The silent spans as sorted, merged epoch-millisecond pairs."""
    spans: list[tuple[int, int]] = []
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, dict):
            start, end = _value_ms(item.get("start")), _value_ms(item.get("end"))
            if start is not None and end is not None and end > start:
                spans.append((start, end))
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _live_ms(start: int, end: int, silent: list[tuple[int, int]]) -> int:
    """The milliseconds of ``[start, end)`` outside every silent span."""
    if end <= start:
        return 0
    live = end - start
    for low, high in silent:
        live -= max(0, min(end, high) - max(start, low))
    return live


def _live_end(start: int, end: int, silent: list[tuple[int, int]]) -> int | None:
    """The latest instant of ``(start, end]`` outside every silent span."""
    moment = end
    for low, high in reversed(silent):
        if low < moment <= high:
            moment = low
    return moment if moment > start else None


def _apportion(total: int, weights: list[float]) -> list[int]:
    """Split ``total`` over ``weights`` by the largest remainder.

    The counts sum to ``total``. A zero weight always gets zero.
    """
    counts = [0] * len(weights)
    whole = sum(weights)
    live = [i for i, w in enumerate(weights) if w > 0]
    if total <= 0 or whole <= 0 or not live:
        return counts
    shares = [total * w / whole for w in weights]
    for i in live:
        counts[i] = int(shares[i])
    live.sort(key=lambda i: (counts[i] - shares[i], i))
    for n in range(total - sum(counts)):
        counts[live[n % len(live)]] += 1
    return counts


def _range_bounds(node: Any, name: str) -> dict | None:
    """The bounds of the first ``range`` on ``name`` anywhere in a query tree."""
    if isinstance(node, dict):
        found = node.get("range")
        if isinstance(found, dict) and isinstance(found.get(name), dict):
            return found[name]
        children: Any = node.values()
    elif isinstance(node, list):
        children = node
    else:
        return None
    for child in children:
        bounds = _range_bounds(child, name)
        if bounds is not None:
            return bounds
    return None


def _window(query: Any, now: datetime) -> tuple[int, int]:
    """The ``@timestamp`` window of a query. With no range: the last 24 hours."""
    bounds = _range_bounds(query, "@timestamp") or {}
    now_ms = _dt_ms(now)
    low = _date_ms(bounds.get("gte", bounds.get("gt")), now)
    high = _date_ms(bounds.get("lte", bounds.get("lt")), now, round_up=True)
    low_ms = int(low) if low is not None else now_ms - _DAY_MS
    high_ms = int(high) if high is not None else now_ms
    return low_ms, max(high_ms, low_ms)


def _term_text(raw: Any) -> str | None:
    if isinstance(raw, dict):
        raw = raw.get("value")
    return None if raw is None else str(raw)


def _traffic_answer(aggs: dict, query: Any, traffic: dict, now: datetime) -> dict | None:
    hosts = traffic.get("hosts")
    if not isinstance(hosts, dict) or not hosts:
        return None
    if all(name in aggs for name in ("out", "in", "volume")):
        return _conn_answer(aggs, query, hosts, traffic.get("silent"), now)
    if "users" in aggs and "agents" in aggs:
        return _users_answer(aggs, query, hosts, now)
    return None


def _conn_host(aggs: dict, query: Any) -> str | None:
    out_term = ((aggs.get("out") or {}).get("filter") or {}).get("term") or {}
    found = _term_text(out_term.get("source.ip"))
    if found is None:
        terms = _terms_in(query)
        found = _term_text(terms.get("source.ip", terms.get("destination.ip")))
    return found


def _terms_body(agg: Any) -> dict:
    terms = agg.get("terms") if isinstance(agg, dict) else None
    return terms if isinstance(terms, dict) else {}


def _side(peers: list[dict], direction: str, agg: Any) -> dict:
    """One direction of the connection pass: the peers and their ports."""
    rows: dict[str, dict[Any, int]] = {}
    for peer in peers:
        if peer["side"] == direction and peer["count"] > 0:
            ports = rows.setdefault(peer["ip"], {})
            ports[peer["port"]] = ports.get(peer["port"], 0) + peer["count"]
    ranked = sorted(rows.items(), key=lambda row: (-sum(row[1].values()), row[0]))
    size = _int(_terms_body(_sub_aggs(agg).get("peers")).get("size"), 10)
    buckets = []
    for ip, ports in ranked[:size]:
        listed = sorted(
            ((port, n) for port, n in ports.items() if port is not None),
            key=lambda row: (-row[1], str(row[0])),
        )
        buckets.append(
            {
                "key": ip,
                "doc_count": sum(ports.values()),
                "ports": {
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0,
                    "buckets": [{"key": port, "doc_count": n} for port, n in listed],
                },
            }
        )
    return {
        "doc_count": sum(sum(ports.values()) for ports in rows.values()),
        "peers": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": sum(sum(ports.values()) for _, ports in ranked[size:]),
            "buckets": buckets,
        },
    }


def _conn_answer(
    aggs: dict, query: Any, hosts: dict, silent_raw: Any, now: datetime
) -> dict | None:
    """The host page connection pass for a host of the traffic model.

    ``None`` for any other host, and for a volume step under one hour: the
    model counts by the hour, so the generic engine answers those.
    """
    host = hosts.get(_conn_host(aggs, query) or "")
    histogram = (aggs.get("volume") or {}).get("date_histogram")
    step = _interval(histogram) if isinstance(histogram, dict) else None
    if not isinstance(host, dict) or step is None or step[0] == "m":
        return None
    if step[0] is None and step[1] < _HOUR_MS:
        return None
    low, high = _window(query, now)
    silent = _spans(silent_raw)
    pattern = str(host.get("pattern") or "always")
    day = sum(_pattern_weight(pattern, _MONDAY + timedelta(hours=h)) for h in range(24))
    slots = list(range(low - low % _HOUR_MS, high, _HOUR_MS)) or [low - low % _HOUR_MS]
    weights = [_pattern_weight(pattern, _ms_dt(slot)) for slot in slots]

    peers: list[dict] = []
    for raw in host.get("peers") or []:
        if not isinstance(raw, dict) or not raw.get("ip"):
            continue
        rate = _number(raw.get("per_day")) or 0.0
        since, until = _value_ms(raw.get("since")), _value_ms(raw.get("until"))
        start = max(low, since) if since is not None else low
        end = min(high, until) if until is not None else high
        share = [
            weight * _live_ms(max(slot, start), min(slot + _HOUR_MS, end), silent) / _HOUR_MS
            for slot, weight in zip(slots, weights, strict=True)
        ]
        share = [rate * s / day for s in share]
        peers.append(
            {
                "side": "in" if raw.get("direction") == "in" else "out",
                "ip": str(raw["ip"]),
                "port": raw.get("port"),
                "count": int(sum(share) + 0.5),
                "share": share,
                "start": start,
                "end": end,
            }
        )
    total = sum(peer["count"] for peer in peers)

    edges = [_step_floor(low, step), _step_floor(high, step)]
    bounds = histogram.get("extended_bounds") if isinstance(histogram, dict) else None
    for raw in (bounds or {}).values():
        edge = _date_ms(raw, now)
        if edge is not None:
            edges.append(_step_floor(int(edge), step))
    keys = _step_keys(min(edges), max(edges), step)
    position = {key: i for i, key in enumerate(keys)}
    slot_bucket = [position.get(_step_floor(slot, step)) for slot in slots]
    expected = [0.0] * len(keys)
    for i, bucket in enumerate(slot_bucket):
        if bucket is not None:
            expected[bucket] += sum(peer["share"][i] for peer in peers)
    counts = _apportion(total, expected)

    # The newest record: the last live instant of the last bucket that holds one.
    newest: int | None = None
    filled = [b for b, n in enumerate(counts) if n > 0]
    if filled:
        for i in range(len(slots) - 1, -1, -1):
            if slot_bucket[i] != filled[-1]:
                continue
            ends = [
                _live_end(max(slots[i], p["start"]), min(slots[i] + _HOUR_MS, p["end"]), silent)
                for p in peers
                if p["share"][i] > 0
            ]
            found = [e for e in ends if e is not None]
            if found:
                newest = max(found)
                break

    floor = _int(histogram.get("min_doc_count"), 0) if isinstance(histogram, dict) else 0
    fmt = histogram.get("format") if isinstance(histogram, dict) else None
    datasets = [{"key": "zeek.conn", "doc_count": total}] if total else []
    computed: dict[str, Any] = {
        "by_dataset": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": datasets,
        },
        "by_stream_dataset": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [],
        },
        "out": _side(peers, "out", aggs.get("out")),
        "in": _side(peers, "in", aggs.get("in")),
        "volume": {
            "buckets": [
                {"key_as_string": _key_text(key, fmt), "key": key, "doc_count": n}
                for key, n in zip(keys, counts, strict=True)
                if n >= floor
            ]
        },
        "newest": (
            {"value": float(newest), "value_as_string": _ms_text(newest)}
            if newest is not None
            else {"value": None}
        ),
    }
    return {
        "took": 3,
        "timed_out": False,
        "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None, "hits": []},
        "aggregations": {
            name: computed[name] if name in computed else _one_agg(body, [], now)
            for name, body in aggs.items()
        },
    }


def _users_answer(aggs: dict, query: Any, hosts: dict, now: datetime) -> dict | None:
    """The host page users pass: the accounts of the host and the agent that wrote them.

    A weekly logon count scales to the window. ``None`` for a host the traffic
    model does not list.
    """
    host = hosts.get(_term_text(_terms_in(query).get("host.ip")) or "")
    if not isinstance(host, dict) or not isinstance(host.get("users"), list):
        return None
    low, high = _window(query, now)
    days = (high - low) / _DAY_MS
    rows: list[tuple[str, int]] = []
    for item in host["users"]:
        if isinstance(item, list) and len(item) == 2 and _number(item[1]) is not None:
            count = int(float(item[1]) * days / 7 + 0.5)
            if count > 0:
                rows.append((str(item[0]), count))
    total = sum(count for _, count in rows)
    users_agg = aggs.get("users") if isinstance(aggs.get("users"), dict) else {}
    spec = _terms_body(users_agg)
    include, exclude = _term_rule(spec.get("include")), _term_rule(spec.get("exclude"))
    listed = sorted(
        (
            (name, count)
            for name, count in rows
            if (include is None or include(name)) and (exclude is None or not exclude(name))
        ),
        key=lambda row: (-row[1], row[0]),
    )
    size = _int(spec.get("size"), 10)
    buckets = []
    for i, (name, count) in enumerate(listed[:size]):
        # A recent logon per account, a little older for each quieter account.
        last = max(low + 1, high - (17 + 53 * i) * 60_000)
        bucket: dict = {"key": name, "doc_count": count}
        for sub_name, sub_body in _sub_aggs(users_agg).items():
            dated = isinstance(sub_body, dict) and ("max" in sub_body or "min" in sub_body)
            bucket[sub_name] = (
                {"value": float(last), "value_as_string": _ms_text(last)}
                if dated
                else _one_agg(sub_body, [], now)
            )
        buckets.append(bucket)
    agent = host.get("agent")
    computed: dict[str, Any] = {
        "agents": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [{"key": str(agent), "doc_count": total}] if agent and total else [],
        },
        "users": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": sum(count for _, count in listed[size:]),
            "buckets": buckets,
        },
    }
    return {
        "took": 2,
        "timed_out": False,
        "hits": {"total": {"value": total, "relation": "eq"}, "max_score": None, "hits": []},
        "aggregations": {
            name: computed[name] if name in computed else _one_agg(body, [], now)
            for name, body in aggs.items()
        },
    }


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
    """The version 1 path: move the newest doc to now, then search a copy.

    The tests and the detection bridge e2e call this with their own docs.
    """
    return search_docs(body, _rebase_docs_to_now(docs))


def fixture_search(body: dict, grid: FixtureGrid) -> dict:
    """Answer a ``_search`` body from a loaded fixture file.

    A version 2 grid answers from its shifted docs and its traffic model, with
    no copy. A version 1 grid moves its newest doc to now on each search.
    """
    if grid.shifted:
        return search_docs(body, grid.docs, traffic=grid.traffic)
    return _search_response_from_docs(body, grid.docs)


def fixture_count(body: dict, grid: FixtureGrid) -> dict:
    """Answer a ``_count`` body with the same matcher as a search."""
    query = body.get("query") if isinstance(body, dict) else None
    probe = {"query": query or {"match_all": {}}, "size": 0, "track_total_hits": True}
    total = fixture_search(probe, grid)["hits"]["total"]["value"]
    return {"count": total, "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0}}


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
            elif FIXTURE is not None:
                self._send(fixture_search(body, FIXTURE))
            else:
                self._send(_search_response(body))
        elif "_count" in path and FIXTURE is not None:
            # Fixtures mode only: dataset mode keeps its catch-all answer.
            self._send(fixture_count(self._body(), FIXTURE))
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
        help="serve the documents of this fixtures.json. The demo container "
        "passes soc_ai/demo/fixtures.json. A missing file serves an empty grid.",
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
        global FIXTURE  # noqa: PLW0603 (one-shot CLI wiring before serve_forever)
        FIXTURE = load_fixture(args.fixtures)
        print(
            f"mock ES: fixtures mode. Version {FIXTURE.version}, "
            f"{len(FIXTURE.docs)} doc(s) from {args.fixtures}"
        )
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
