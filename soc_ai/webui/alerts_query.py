"""Alerts-console queries: grouped-by-rule aggregation + flat event listing.

All user input (the filter box) goes through the existing OQL trust
boundary (parse → field-whitelist validation) before touching ES; only
the filter part of OQL is accepted here — grouping is built in.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.oql import filter_to_dsl, parse_oql, validate_oql

TIME_RANGES: dict[str, str] = {
    "15m": "now-15m",
    "1h": "now-1h",
    "4h": "now-4h",
    "24h": "now-24h",
    "3d": "now-3d",
    "7d": "now-7d",
    "30d": "now-30d",
}
DEFAULT_RANGE = "24h"
SEVERITIES = ("critical", "high", "medium", "low")
GROUP_SORTS = ("count", "latest")
MAX_GROUPS = 200
EVENTS_PER_GROUP = 50
MAX_EVENTS = 200

# Broaden the triage feed beyond Suricata to SO's other detection
# outputs. These are UNIONED with the configured `webui_alerts_query` (the
# Suricata primary) when `webui_extra_detections` is on. Each source groups by a
# "name" field: Suricata/Sigma carry `rule.name`; Zeek notices carry `notice.note`
# (e.g. "ATTACK::Discovery"), so they get their own aggregation + merge.
SIGMA_SOURCE_OQL = 'event.dataset:"sigma.alert"'
# Only ATTACK::* notices — the behavioral threat notices (e.g. ATTACK::Discovery);
# excludes operational noise (CaptureLoss, cert warnings, dropped packets).
NOTICE_SOURCE_OQL = 'event.dataset:"zeek.notice" AND notice.note:ATTACK*'

# event.dataset → triage "kind" badge.
_KIND_BY_DATASET = {
    "suricata.alert": "suricata",
    "sigma.alert": "sigma",
    "zeek.notice": "notice",
}


def _kind_for(dataset: str | None) -> str:
    return _KIND_BY_DATASET.get((dataset or "").lower(), "alert")


@dataclass
class AlertGroup:
    rule_name: str
    count: int
    severity: str
    latest_ts: str
    latest_id: str
    kind: str = "suricata"
    acked_count: int = 0
    escalated_count: int = 0


@dataclass
class AlertEvent:
    es_id: str
    timestamp: str
    src: str
    dst: str
    severity: str
    host: str
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    kind: str = "suricata"


def _dig(source: dict[str, Any], path: str) -> Any:
    """Read a dotted path from an ES _source that may be nested or flat."""
    if path in source:
        return source[path]
    cur: Any = source
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _oql_filter_dsl(oql: str) -> dict[str, Any]:
    ast = parse_oql(oql)
    validate_oql(ast)
    return filter_to_dsl(ast.filter_)


def build_filter(
    settings: Settings,
    *,
    time_range: str,
    severity: str | None,
    oql: str | None,
    dataset_oqls: list[str] | None = None,
    abs_from: str | None = None,
    abs_to: str | None = None,
    time_zone: str | None = None,
    hide_acked: bool = False,
) -> dict[str, Any]:
    """Build the bool query shared by the grouped and flat views.

    ``dataset_oqls`` is the list of source-scope OQL filters to OR together
    (e.g. the Suricata primary + Sigma); defaults to ``[webui_alerts_query]`` so
    the single-Suricata-source behavior is unchanged. Raises OqlValidationError
    on bad user OQL (including pipe stages — grouping is built into the page).

    When ``abs_from`` and ``abs_to`` are both given they define an absolute
    @timestamp range (interpreted in ``time_zone``); otherwise the ``time_range``
    preset is used.
    """
    must: list[dict[str, Any]] = []
    sources = dataset_oqls if dataset_oqls is not None else [settings.webui_alerts_query]
    source_dsls = [_oql_filter_dsl(s) for s in sources if s.strip() and s.strip() != "*"]
    if len(source_dsls) == 1:
        must.append(source_dsls[0])
    elif source_dsls:
        must.append({"bool": {"should": source_dsls, "minimum_should_match": 1}})
    if oql and oql.strip():
        # Deliberate over-block: rejects "|" even inside quoted values; pipe stages are
        # meaningless here and quoted-pipe rule names are rare. Revisit if it bites.
        if "|" in oql:
            raise OqlValidationError("pipes are not supported here — grouping is built in")
        must.append(_oql_filter_dsl(oql))
    if abs_from and abs_to:
        ts_range: dict[str, Any] = {"gte": abs_from, "lte": abs_to}
        if time_zone:
            ts_range["time_zone"] = time_zone
    else:
        ts_range = {"gte": TIME_RANGES.get(time_range, TIME_RANGES[DEFAULT_RANGE])}
    bool_query: dict[str, Any] = {
        "must": must or [{"match_all": {}}],
        "filter": [{"range": {"@timestamp": ts_range}}],
        "must_not": [{"exists": {"field": "synth.scenario_id"}}],
    }
    if severity in SEVERITIES:
        bool_query["filter"].append({"term": {"event.severity_label": severity}})
    if hide_acked:
        bool_query["filter"].append(
            {
                "bool": {
                    "must_not": [
                        {"term": {"event.acknowledged": True}},
                        {"term": {"event.escalated": True}},
                    ]
                }
            }
        )
    return {"bool": bool_query}


def _group_aggs(sort: str, field: str = "rule.name") -> dict[str, Any]:
    order = {"latest_ts": "desc"} if sort == "latest" else {"_count": "desc"}
    return {
        "rules": {
            "terms": {"field": field, "size": MAX_GROUPS, "order": order},
            "aggs": {
                "latest_ts": {"max": {"field": "@timestamp"}},
                "latest": {
                    "top_hits": {
                        "size": 1,
                        "sort": [{"@timestamp": {"order": "desc"}}],
                        "_source": ["@timestamp", "event.severity_label", "event.dataset"],
                    }
                },
                "acked": {"filter": {"term": {"event.acknowledged": True}}},
                "escalated": {"filter": {"term": {"event.escalated": True}}},
            },
        }
    }


def _group_from_bucket(bucket: dict[str, Any], *, kind: str | None = None) -> AlertGroup:
    top = bucket.get("latest", {}).get("hits", {}).get("hits", [])
    src = top[0].get("_source", {}) if top else {}
    return AlertGroup(
        rule_name=str(bucket.get("key", "")),
        count=int(bucket.get("doc_count", 0)),
        severity=str(_dig(src, "event.severity_label") or "unknown").lower(),
        latest_ts=str(_dig(src, "@timestamp") or ""),
        latest_id=str(top[0].get("_id", "")) if top else "",
        kind=kind or _kind_for(_dig(src, "event.dataset")),
        acked_count=int((bucket.get("acked") or {}).get("doc_count", 0)),
        escalated_count=int((bucket.get("escalated") or {}).get("doc_count", 0)),
    )


async def fetch_groups(
    elastic: ElasticClient,
    settings: Settings,
    *,
    time_range: str = DEFAULT_RANGE,
    severity: str | None = None,
    oql: str | None = None,
    sort: str = "count",
    abs_from: str | None = None,
    abs_to: str | None = None,
    time_zone: str | None = None,
    hide_acked: bool = False,
) -> tuple[list[AlertGroup], int]:
    """Grouped view. Returns (groups, total matching events).

    Suricata + Sigma group by ``rule.name`` (one aggregation); Zeek ATTACK
    notices group by ``notice.note`` (a second aggregation) since they carry no
    rule.name. The two bucket sets are merged, tagged by ``kind``, re-sorted, and
    capped. Extra (non-Suricata) sources are gated by ``webui_extra_detections``.
    """
    sort = sort if sort in GROUP_SORTS else "count"
    idx = settings.events_index_pattern
    extra = settings.webui_extra_detections

    # Aggregation A — rule.name sources: the configured Suricata primary (+ Sigma).
    a_sources = [settings.webui_alerts_query] + ([SIGMA_SOURCE_OQL] if extra else [])
    qa = build_filter(
        settings,
        time_range=time_range,
        severity=severity,
        oql=oql,
        dataset_oqls=a_sources,
        abs_from=abs_from,
        abs_to=abs_to,
        time_zone=time_zone,
        hide_acked=hide_acked,
    )
    ra = await elastic.search(idx, qa, size=0, aggs=_group_aggs(sort), track_total_hits=True)
    a_buckets = ((ra.aggregations or {}).get("rules") or {}).get("buckets", [])
    groups: list[AlertGroup] = [_group_from_bucket(b) for b in a_buckets]
    total = ra.total

    # Aggregation B — Zeek ATTACK notices (notice.note), if enabled.
    if extra:
        qb = build_filter(
            settings,
            time_range=time_range,
            severity=severity,
            oql=oql,
            dataset_oqls=[NOTICE_SOURCE_OQL],
            abs_from=abs_from,
            abs_to=abs_to,
            time_zone=time_zone,
            hide_acked=hide_acked,
        )
        rb = await elastic.search(
            idx,
            qb,
            size=0,
            aggs=_group_aggs(sort, field="notice.note"),
            track_total_hits=True,
        )
        b_buckets = ((rb.aggregations or {}).get("rules") or {}).get("buckets", [])
        groups += [_group_from_bucket(b, kind="notice") for b in b_buckets]
        total += rb.total

    # Merge-sort the two source sets the same way the page asked for.
    if sort == "latest":
        groups.sort(key=lambda g: g.latest_ts, reverse=True)
    else:
        groups.sort(key=lambda g: g.count, reverse=True)
    return groups[:MAX_GROUPS], total


def _endpoint(source: dict[str, Any], side: str) -> str:
    ip = _dig(source, f"{side}.ip")
    if ip is None:
        return "—"
    port = _dig(source, f"{side}.port")
    return f"{ip}:{port}" if port is not None else str(ip)


async def fetch_group_events(
    elastic: ElasticClient,
    settings: Settings,
    *,
    rule_name: str,
    kind: str = "suricata",
    time_range: str = DEFAULT_RANGE,
    severity: str | None = None,
    oql: str | None = None,
    size: int = EVENTS_PER_GROUP,
    abs_from: str | None = None,
    abs_to: str | None = None,
    time_zone: str | None = None,
    hide_acked: bool = False,
) -> list[AlertEvent]:
    """Flat event list for one group, newest first. ``kind`` selects the source
    scope + the name field: notices filter ``notice.note`` within zeek.notice;
    everything else filters ``rule.name`` within the Suricata/Sigma sources.

    Pass ``hide_acked=True`` to exclude already-acknowledged/escalated events
    (used by the bulk-ack path so re-running a capped group makes progress)."""
    size = min(max(size, 1), MAX_EVENTS)
    if kind == "notice":
        dataset_oqls = [NOTICE_SOURCE_OQL]
        name_field = "notice.note"
    else:
        dataset_oqls = [settings.webui_alerts_query]
        if settings.webui_extra_detections:
            dataset_oqls.append(SIGMA_SOURCE_OQL)
        name_field = "rule.name"
    query = build_filter(
        settings,
        time_range=time_range,
        severity=severity,
        oql=oql,
        dataset_oqls=dataset_oqls,
        abs_from=abs_from,
        abs_to=abs_to,
        time_zone=time_zone,
        hide_acked=hide_acked,
    )
    query["bool"]["filter"].append({"term": {name_field: rule_name}})
    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=size,
        sort=[{"@timestamp": {"order": "desc"}}],
    )
    events: list[AlertEvent] = []
    for hit in result.hits:
        source = hit.get("_source", {})
        src_ip_raw = _dig(source, "source.ip")
        dst_ip_raw = _dig(source, "destination.ip")
        dst_port_raw = _dig(source, "destination.port")
        events.append(
            AlertEvent(
                es_id=str(hit.get("_id", "")),
                timestamp=str(_dig(source, "@timestamp") or ""),
                src=_endpoint(source, "source"),
                dst=_endpoint(source, "destination"),
                severity=str(_dig(source, "event.severity_label") or "unknown").lower(),
                host=str(_dig(source, "host.name") or "—"),
                src_ip=str(src_ip_raw) if src_ip_raw is not None else None,
                dst_ip=str(dst_ip_raw) if dst_ip_raw is not None else None,
                dst_port=int(dst_port_raw) if dst_port_raw is not None else None,
                kind=_kind_for(_dig(source, "event.dataset")),
            )
        )
    return events
