"""``get_alert_context`` - the highest-value triage tool.

Given a Security Onion alert ID, fetch the alert document and fan out to
related events along five typed pivot axes:

- ``network.community_id`` (the canonical SO pivot - hashes the network 5-tuple
  so it correlates alerts with Zeek conn/dns/http/ssl/files records)
- ``host.name`` (events on the same host, useful for non-network alerts)
- ``user.name`` (events for the same identity)
- ``process.entity_id`` (Sysmon-style process-tree correlation)
- ``file.hash.sha256`` (file-touching events)

Each pivot is bounded by ``±window_seconds`` around the alert's ``@timestamp``,
sorted chronologically, capped at ``max_per_pivot`` rows. Pivots whose source
field is absent from the alert resolve to an empty list. All five pivot
queries dispatch via :func:`asyncio.gather` for end-to-end latency.

**Resilience.** Transient ``ConnectionTimeout`` / 5xx from a contended ES
cluster are retried at the transport layer by elasticsearch-py
(see :class:`ElasticClient`'s ``max_retries`` + ``retry_on_timeout`` +
``retry_on_status`` config). On top of that, this function uses
``asyncio.gather(..., return_exceptions=True)`` so a single pivot failing
after retries doesn't poison the others — the surviving pivots still land
in the AlertContext, and failed pivots surface in
:attr:`AlertContext.prefetch_gaps` as ``{field_name: exception_class}``.
The alert lookup itself is the only required call; if it fails after
retries, raise (no alert means nothing to investigate against).

Output is :class:`AlertContext` - a Pydantic model the agent can serialize
into its own context as JSON.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from pydantic import BaseModel, Field

from soc_ai.config import Settings
from soc_ai.enrichment.zeek_parser import TypedZeekFields, parse_typed_zeek_fields
from soc_ai.errors import SoNotFoundError
from soc_ai.so_client import fields
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert
from soc_ai.tools._registry import tool
from soc_ai.tools.enrichment import (
    EnrichmentContext,
    IndicatorEnrichment,
    enrich_domain,
    enrich_hash,
    enrich_ip,
)

_LOGGER = logging.getLogger(__name__)


class AlertContext(BaseModel):
    """Triage context: the alert plus parallel pivots into related events."""

    alert: SoAlert
    community_id_events: list[SoAlert] = Field(default_factory=list)
    host_events: list[SoAlert] = Field(default_factory=list)
    user_events: list[SoAlert] = Field(default_factory=list)
    process_events: list[SoAlert] = Field(default_factory=list)
    file_events: list[SoAlert] = Field(default_factory=list)
    pivot_summary: dict[str, int] = Field(default_factory=dict)
    # Histogram of rule_name → count of alerts that fired on this IP recently
    # (wide ±host_risk_window_hours window). DATA ONLY, not a verdict — each
    # listed rule is an independent alert and its presence is NOT confirmation
    # that THIS alert is malicious. Unlike the 5 tight pivots (community_id/
    # host.name/user.name, ±5 min), this is keyed on the endpoint IPs that
    # network-sensor alerts always carry and spans a wide window so concurrent
    # activity hours away is visible. Empty when the host has no other alerts
    # in-window or the lookup failed.
    host_alert_profile: dict[str, int] = Field(default_factory=dict)
    # Pivots that failed AFTER retries and were swallowed so the agent
    # could still get partial context. Maps pivot field name → exception
    # class name (e.g., ``"network.community_id": "ConnectionTimeout"``).
    # Empty when every pivot completed cleanly OR when its alert field
    # was absent (those return empty lists silently — that's expected).
    prefetch_gaps: dict[str, str] = Field(default_factory=dict)


class EnrichedAlertContext(AlertContext):
    """Fattened prefetch consumed by the synth-first pipeline.

    Extends AlertContext with: typed Zeek fields parsed from the pivot
    message JSONs, and per-indicator enrichments (BlocklistDB hits +
    MaxMind ASN/GeoIP + cloud-provider tag + optional MISP).

    Spec note: playbook / runbook / related_cases / rule_history fields
    are stubbed for v1. They'll be wired up in a follow-up after Task 17's
    v8 measurement validates the redesign.
    """

    typed_zeek: TypedZeekFields = Field(default_factory=TypedZeekFields)
    enrichments: dict[str, IndicatorEnrichment] = Field(default_factory=dict)


@tool(
    read_only=True,
    description="Fetch a SOC alert and fan out to related events via 5 typed pivots.",
)
async def get_alert_context(
    alert_id: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    window_seconds: int = 300,
    max_per_pivot: int = 10,
    include_synth: bool = False,
) -> AlertContext:
    """Fetch ``alert_id`` and fan out to five related-event pivots.

    Args:
        alert_id: ES document ID of the alert.
        elastic: client for the SO ES cluster.
        settings: app settings (used for the events index pattern).
        window_seconds: ±N-second window centered on the alert's ``@timestamp``
            for every pivot. Default 300s = 5min.
        max_per_pivot: hard cap on rows returned per pivot. Default 10.
        include_synth: when False (the prod default), pivots exclude
            synthetic-eval docs (``synth.scenario_id``) so fixtures can't leak
            into a real investigation. The eval harness sets True when triaging
            a synth alert so the scenario's supporting docs stay visible.

    Raises:
        SoNotFoundError: if no document with ``alert_id`` exists.
        ValueError: on non-positive ``window_seconds`` or ``max_per_pivot``.
    """
    if window_seconds <= 0:
        raise ValueError(f"window_seconds must be positive, got {window_seconds}")
    if max_per_pivot <= 0:
        raise ValueError(f"max_per_pivot must be positive, got {max_per_pivot}")

    lookup = await elastic.search(
        settings.events_index_pattern,
        {"ids": {"values": [alert_id]}},
        size=1,
    )
    if not lookup.hits:
        raise SoNotFoundError(f"alert not found: {alert_id}")
    alert = SoAlert.from_es_hit(lookup.hits[0])

    # Each pivot is paired with a stable ``key`` so we can map an
    # exception back to a slot in the result. asyncio.gather with
    # ``return_exceptions=True`` lets one failed pivot not poison the
    # rest — they get swallowed into ``prefetch_gaps``.
    pivot_specs: tuple[tuple[str, str | None, str], ...] = (
        ("community_id", alert.network_community_id, "network.community_id"),
        ("host", alert.host_name, "host.name"),
        ("user", alert.user_name, "user.name"),
        ("process", alert.process_entity_id, "process.entity_id"),
        ("file", alert.file_hash_sha256, "file.hash.sha256"),
    )
    pivot_calls = tuple(
        _pivot(
            value,
            field,
            alert,
            elastic,
            settings,
            window_seconds,
            max_per_pivot,
            include_synth=include_synth,
        )
        for _, value, field in pivot_specs
    )
    # The wide host-risk aggregation runs alongside the 5 tight pivots — it keys
    # on the endpoint IPs (which network alerts always carry) over a much wider
    # window, so it catches a compromised host the narrow pivots miss. Gathered
    # in a separate inner call so the pivots keep return_exceptions semantics
    # while host-risk (which swallows its own failures) keeps its dict type.
    raw_results, host_alert_profile, behavioral_summaries = await asyncio.gather(
        asyncio.gather(*pivot_calls, return_exceptions=True),
        _host_risk(
            alert,
            elastic,
            settings,
            settings.host_risk_window_hours,
            include_synth=include_synth,
        ),
        _behavioral_summary_pivot(
            alert,
            elastic,
            settings,
            window_seconds,
            max_per_pivot,
            include_synth=include_synth,
        ),
    )

    events_by_key: dict[str, list[SoAlert]] = {}
    gaps: dict[str, str] = {}
    for (key, _value, field_name), result in zip(pivot_specs, raw_results, strict=True):
        if isinstance(result, BaseException):
            gaps[field_name] = type(result).__name__
            events_by_key[key] = []
            _LOGGER.warning(
                "prefetch pivot %s for alert %s gave up after retries: %s",
                field_name,
                alert_id,
                type(result).__name__,
            )
        else:
            events_by_key[key] = result

    # Prepend behavioral-summary docs (beacon / DNS-tunnel profiles) to the
    # community-id pivot list so the materializer surfaces their decisive bullet.
    # They are high-signal and rare, so they win the front slots; dedupe by id
    # against whatever the community_id pivot already returned.
    if behavioral_summaries:
        seen_ids = {e.id for e in events_by_key.get("community_id", [])}
        fresh = [e for e in behavioral_summaries if e.id not in seen_ids]
        events_by_key["community_id"] = fresh + events_by_key.get("community_id", [])

    return AlertContext(
        alert=alert,
        community_id_events=events_by_key["community_id"],
        host_events=events_by_key["host"],
        user_events=events_by_key["user"],
        process_events=events_by_key["process"],
        file_events=events_by_key["file"],
        pivot_summary={
            k: len(events_by_key[k]) for k in ("community_id", "host", "user", "process", "file")
        },
        host_alert_profile=host_alert_profile,
        prefetch_gaps=gaps,
    )


async def get_enriched_alert_context(
    alert_id: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    enrichment: EnrichmentContext,
    misp: Any = None,  # MispClient | None — typed as Any to dodge circular import
    window_seconds: int = 300,
    max_per_pivot: int = 10,
    include_synth: bool = False,
    internal_cidrs: Sequence[Any] | None = None,
) -> EnrichedAlertContext:
    """Fattened prefetch: AlertContext + typed Zeek + per-indicator enrichments.

    Built on top of `get_alert_context` so the existing 5-pivot logic
    is reused as-is. Then runs typed-Zeek parsing + per-indicator
    enrichments in parallel via `asyncio.gather`.

    The returned `EnrichedAlertContext` is what the synth-first pipeline
    (Task 15) feeds to the synth — the synth gets all evidence pre-computed
    and only needs to write the verdict + summary.

    ``internal_cidrs`` is forwarded to :func:`enrich_ip` so each IP's
    ``internal`` flag is computed against the orchestrator's *effective* CIDR
    set (``settings.internal_cidrs`` union active ``cidr`` rows minus muted) rather than
    ``settings.internal_cidrs`` alone. ``None`` ⇒ enrich_ip reads
    ``settings.internal_cidrs`` (behavior unchanged). DB access stays in the
    orchestrator; this function only threads the already-resolved set down.
    """
    # 1. Reuse the existing 5-pivot prefetch.
    base = await get_alert_context(
        alert_id,
        elastic=elastic,
        settings=settings,
        window_seconds=window_seconds,
        max_per_pivot=max_per_pivot,
        include_synth=include_synth,
    )

    # 2. Parse typed Zeek fields from the community_id pivot.
    typed_zeek = parse_typed_zeek_fields(base.community_id_events)

    # 3. Collect every indicator we might want enriched.
    indicators_to_enrich: dict[str, str] = {}  # indicator → indicator_type
    if base.alert.source_ip:
        indicators_to_enrich.setdefault(base.alert.source_ip, "ip")
    if base.alert.destination_ip:
        indicators_to_enrich.setdefault(base.alert.destination_ip, "ip")
    for d in typed_zeek.dns_queries + typed_zeek.sni_servers + typed_zeek.http_hosts:
        indicators_to_enrich.setdefault(d, "domain")
    for d in typed_zeek.dns_answers:
        # Answers can be IPs (A/AAAA) or domain names (CNAME) — cheap heuristic.
        try:
            ipaddress.ip_address(d)
            indicators_to_enrich.setdefault(d, "ip")
        except ValueError:
            indicators_to_enrich.setdefault(d, "domain")
    if base.alert.file_hash_sha256:
        indicators_to_enrich.setdefault(base.alert.file_hash_sha256, "sha256")

    # 4. Enrich each indicator in parallel.
    async def _do_enrich(ind: str, ind_type: str) -> tuple[str, IndicatorEnrichment]:
        if ind_type == "ip":
            r = await enrich_ip(
                ind,
                settings=settings,
                misp=misp,
                blocklist=enrichment.blocklist,
                maxmind=enrichment.maxmind,
                cloud=enrichment.cloud,
                internal_cidrs=internal_cidrs,
            )
        elif ind_type == "domain":
            r = await enrich_domain(
                ind,
                settings=settings,
                misp=misp,
                blocklist=enrichment.blocklist,
            )
        else:  # sha256
            r = await enrich_hash(
                ind,
                algo="sha256",
                settings=settings,
                misp=misp,
                blocklist=enrichment.blocklist,
            )
        return ind, r

    if indicators_to_enrich:
        tasks = [_do_enrich(ind, t) for ind, t in indicators_to_enrich.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        enrichments: dict[str, IndicatorEnrichment] = {}
        for r in results:
            if isinstance(r, BaseException):
                _LOGGER.warning("enrichment task raised: %s", r)
                continue
            ind, enrich = r
            enrichments[ind] = enrich
    else:
        enrichments = {}

    return EnrichedAlertContext(
        alert=base.alert,
        community_id_events=base.community_id_events,
        host_events=base.host_events,
        user_events=base.user_events,
        process_events=base.process_events,
        file_events=base.file_events,
        pivot_summary=base.pivot_summary,
        host_alert_profile=base.host_alert_profile,
        prefetch_gaps=base.prefetch_gaps,
        typed_zeek=typed_zeek,
        enrichments=enrichments,
    )


async def _pivot(
    field_value: str | None,
    field_name: str,
    alert: SoAlert,
    elastic: ElasticClient,
    settings: Settings,
    window_seconds: int,
    max_results: int,
    *,
    include_synth: bool = False,
) -> list[SoAlert]:
    """Run one pivot query, or return ``[]`` if the alert lacks the pivot value."""
    if not field_value or alert.timestamp is None:
        return []

    delta = timedelta(seconds=window_seconds)
    gte = (alert.timestamp - delta).isoformat()
    lte = (alert.timestamp + delta).isoformat()

    # Always exclude the alert under triage from its own fan-out. By default
    # also exclude synthetic-eval docs: the prefetch is the
    # synth-first pipeline's PRIMARY evidence path, and a real alert sharing a
    # community_id / host.name / user.name with lingering synth fixtures would
    # otherwise pull fabricated evidence into a production investigation. The
    # eval harness opts in (`include_synth=True`) so it can still see a synth
    # scenario's own supporting docs when triaging that synth alert.
    must_not: list[dict[str, Any]] = [{"ids": {"values": [alert.id]}}]
    if not include_synth:
        must_not.append({"exists": {"field": "synth.scenario_id"}})

    query: dict[str, Any] = {
        "bool": {
            "must": [{"term": {field_name: field_value}}],
            "filter": [{"range": {"@timestamp": {"gte": gte, "lte": lte}}}],
            "must_not": must_not,
        }
    }

    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=max_results,
        sort=[{"@timestamp": {"order": "asc"}}],
    )
    return [SoAlert.from_es_hit(h) for h in result.hits]


_BEHAVIORAL_PROFILE_FIELDS: tuple[str, ...] = fields.BEACON_PROFILE + fields.DNS_TUNNEL_PROFILE


async def _behavioral_summary_pivot(
    alert: SoAlert,
    elastic: ElasticClient,
    settings: Settings,
    window_seconds: int,
    max_results: int,
    *,
    include_synth: bool = False,
) -> list[SoAlert]:
    """Fetch derived BEHAVIORAL-SUMMARY docs for the alert's endpoint IPs.

    The five tight pivots key on ``community_id`` / ``host.name`` / ``user.name``;
    a RITA-style beacon summary or a DNS-tunnel aggregate carries neither (it is a
    per-host rollup written with only ``source.ip`` and a behavioral-profile
    object). So the decisive beacon / DNS-tunnel signal was invisible to the
    prefetch even though the detection logic downstream knows how to read it.

    This pivot closes that gap: match any doc in the window whose source OR
    destination IP is an alert endpoint AND that carries one of the behavioral-
    profile objects (``exists`` on the candidate paths). The profile object is
    rare — only summary docs have it — so this stays naturally low-volume without
    a dataset-name whitelist. Best-effort: any failure returns ``[]`` rather than
    poisoning the prefetch."""
    ips = [ip for ip in (alert.source_ip, alert.destination_ip) if ip]
    if not ips or alert.timestamp is None:
        return []

    delta = timedelta(seconds=window_seconds)
    gte = (alert.timestamp - delta).isoformat()
    lte = (alert.timestamp + delta).isoformat()

    must_not: list[dict[str, Any]] = [{"ids": {"values": [alert.id]}}]
    if not include_synth:
        must_not.append({"exists": {"field": "synth.scenario_id"}})

    query: dict[str, Any] = {
        "bool": {
            "must": [
                {
                    "bool": {
                        "should": [
                            {"terms": {"source.ip": ips}},
                            {"terms": {"destination.ip": ips}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                {
                    "bool": {
                        "should": [{"exists": {"field": f}} for f in _BEHAVIORAL_PROFILE_FIELDS],
                        "minimum_should_match": 1,
                    }
                },
            ],
            "filter": [{"range": {"@timestamp": {"gte": gte, "lte": lte}}}],
            "must_not": must_not,
        }
    }

    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=min(max_results, 8),
            sort=[{"@timestamp": {"order": "asc"}}],
        )
    except Exception as exc:  # best-effort: never poison the prefetch (BLE001 ok)
        _LOGGER.warning(
            "behavioral-summary pivot for alert %s failed: %s", alert.id, type(exc).__name__
        )
        return []
    return [SoAlert.from_es_hit(h) for h in result.hits]


async def _host_risk(
    alert: SoAlert,
    elastic: ElasticClient,
    settings: Settings,
    window_hours: int,
    *,
    include_synth: bool = False,
) -> dict[str, int]:
    """Aggregate the recent alert histogram for the alert's endpoint IPs.

    Returns ``{rule_name: count}`` for every Suricata alert touching the alert's
    source OR destination IP within ±``window_hours`` (the focus alert and, by
    default, synthetic-eval docs excluded). This is the wide host-risk signal the
    5 tight pivots miss: they key on community_id/host.name/user.name (absent on
    so-import-pcap / network-sensor alerts) and span only ±5 min, so a
    compromised host's RAT/C2 check-ins fired hours away are invisible to them.
    Keyed on the IPs a network alert always carries instead.

    Best-effort: any failure (field-mapping, timeout) returns ``{}`` rather than
    poisoning the prefetch — host-risk is additive context, never a hard gate.
    """
    ips = [ip for ip in (alert.source_ip, alert.destination_ip) if ip]
    if not ips or alert.timestamp is None or window_hours <= 0:
        return {}

    delta = timedelta(hours=window_hours)
    gte = (alert.timestamp - delta).isoformat()
    lte = (alert.timestamp + delta).isoformat()

    must_not: list[dict[str, Any]] = [{"ids": {"values": [alert.id]}}]
    if not include_synth:
        must_not.append({"exists": {"field": "synth.scenario_id"}})

    query: dict[str, Any] = {
        "bool": {
            "should": [
                {"terms": {"source.ip": ips}},
                {"terms": {"destination.ip": ips}},
            ],
            "minimum_should_match": 1,
            "filter": [
                {"term": {"event.dataset": "suricata.alert"}},
                {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
            ],
            "must_not": must_not,
        }
    }
    aggs = {"rules": {"terms": {"field": "rule.name", "size": 50}}}

    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs=aggs,
        )
    except Exception as exc:
        _LOGGER.warning("host-risk aggregation failed for alert %s: %s", alert.id, exc)
        return {}

    buckets = ((result.aggregations or {}).get("rules") or {}).get("buckets") or []
    profile: dict[str, int] = {}
    for b in buckets:
        key = b.get("key")
        count = b.get("doc_count")
        if key and isinstance(count, int):
            profile[str(key)] = count
    return profile


__all__ = [
    "AlertContext",
    "EnrichedAlertContext",
    "get_alert_context",
    "get_enriched_alert_context",
]
