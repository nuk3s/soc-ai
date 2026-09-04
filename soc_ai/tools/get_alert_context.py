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

The ``host.name`` pivot carries a structural guard: on a network-sensor
document (``suricata.*`` / ``zeek.*``), or whenever ``host.name`` equals the
sensor identity (``observer.name`` / ``agent.name``), the top-level
``host.name`` names the SENSOR BOX, not a flow endpoint — Security Onion
strips it entirely from network-sensor docs, but a stock Filebeat/Elastic
Agent Suricata pipeline ships it through, and pivoting on it there returns
"everything that sensor observed". The guard skips the pivot and records why
in :attr:`AlertContext.prefetch_gaps` (``skipped_*`` reasons), so an empty
host pivot is distinguishable from a pivot that ran and found nothing.

An **endpoint-coverage check** rides the same fan-out: one bounded ``size=0``
lookup (:func:`_endpoint_coverage`) that decides whether the alert's hosts
ship endpoint/host-agent telemetry at all, recording
``endpoint.coverage: no_endpoint_documents_for_host`` /
``no_endpoint_dataset_on_grid`` in ``prefetch_gaps`` when they do not — so
the agent can stop distinguishing "no data yet" from "no coverage" by
burning its tool budget on guaranteed-empty ``endpoint.events.*`` probes.

The ``community_id`` pivot is the one exception to strict chronological order:
rare behavioral-summary docs (beacon / DNS-tunnel profiles) are prepended at its
head so their decisive bullet surfaces first, so it reads decisive-first, not
time-ordered. It is still capped at ``max_per_pivot`` (the oldest correlated
events are dropped to make room for the prepended summaries).

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
from soc_ai.tools._synth_scope import SynthScope, synth_scope_must_not
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
    # Pivots that did NOT contribute evidence, with why. Three value shapes:
    # an exception class name for a pivot that failed AFTER retries and was
    # swallowed so the agent could still get partial context (e.g.
    # ``"network.community_id": "ConnectionTimeout"``); a ``skipped_*``
    # reason for the host pivot's structural guard —
    # ``skipped_field_absent`` (no ``host.name`` on the alert, the normal
    # Security Onion network-alert shape), ``skipped_sensor_identity``
    # (``host.name`` equals ``observer.name``/``agent.name``), or
    # ``skipped_network_sensor_dataset`` (a ``suricata.*``/``zeek.*`` doc,
    # where top-level ``host.name`` can only name the sensor); or the
    # endpoint-coverage verdict under ``"endpoint.coverage"`` —
    # ``no_endpoint_documents_for_host`` (the grid ships endpoint telemetry
    # but NONE of it comes from this alert's hosts, so endpoint queries
    # scoped to them cannot match) or ``no_endpoint_dataset_on_grid`` (the
    # grid holds no endpoint telemetry at all in the surrounding window).
    # No ``endpoint.coverage`` entry means covered-or-unknown: an empty
    # endpoint query then means only "this particular query matched none".
    # The OTHER pivots still return [] silently when their alert field is
    # absent.
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
    include_synth: SynthScope = False,
) -> AlertContext:
    """Fetch ``alert_id`` and fan out to five related-event pivots.

    Args:
        alert_id: ES document ID of the alert.
        elastic: client for the SO ES cluster.
        settings: app settings (used for the events index pattern).
        window_seconds: ±N-second window centered on the alert's ``@timestamp``
            for every pivot. Default 300s = 5min.
        max_per_pivot: hard cap on rows returned per pivot. Default 10.
        include_synth: synth-doc visibility. False (the prod default): pivots
            exclude all synthetic-eval docs (``synth.scenario_id``) so
            fixtures can't leak into a real investigation. A scenario id
            (str): the batch eval's scope — only THAT scenario's own
            supporting docs are visible, so concurrently-planted sibling
            scenarios can't contaminate each other's pivots. True: every
            synth doc visible (hunt-journey eval only).

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

    # The host pivot's structural guard: pivot on host.name only when it can
    # plausibly name an ENDPOINT. Skipping resolves the pivot to [] without
    # an ES call; the reason lands in prefetch_gaps below so the skip is
    # visible downstream (an honest gap, not a silent empty).
    host_skip_reason = _host_pivot_skip_reason(alert)

    # Each pivot is paired with a stable ``key`` so we can map an
    # exception back to a slot in the result. asyncio.gather with
    # ``return_exceptions=True`` lets one failed pivot not poison the
    # rest — they get swallowed into ``prefetch_gaps``.
    pivot_specs: tuple[tuple[str, str | None, str], ...] = (
        ("community_id", alert.network_community_id, "network.community_id"),
        ("host", None if host_skip_reason else alert.host_name, "host.name"),
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
    (
        raw_results,
        host_alert_profile,
        behavioral_summaries,
        endpoint_coverage_gap,
    ) = await asyncio.gather(
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
        _endpoint_coverage(
            alert,
            elastic,
            settings,
            include_synth=include_synth,
        ),
    )

    events_by_key: dict[str, list[SoAlert]] = {}
    gaps: dict[str, str] = {}
    if host_skip_reason is not None:
        gaps["host.name"] = host_skip_reason
    if endpoint_coverage_gap is not None:
        gaps[ENDPOINT_COVERAGE_GAP_KEY] = endpoint_coverage_gap
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
        existing = events_by_key.get("community_id", [])
        seen_ids = {e.id for e in existing}
        fresh = [e for e in behavioral_summaries if e.id not in seen_ids]
        # Re-cap the merged list to max_per_pivot so the documented "at most
        # max_per_pivot rows" contract still holds after the prepend (otherwise
        # the list could reach max_per_pivot + 8 and, in the fail-open path where
        # context-budget window discovery fails, reach the prompt untrimmed).
        # The behavioral docs keep the head slots; trim the OLDEST community_id
        # events (they are sorted ascending) to make room.
        keep = max(max_per_pivot - len(fresh), 0)
        events_by_key["community_id"] = (
            fresh[:max_per_pivot] + existing[max(len(existing) - keep, 0) :]
        )

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
    include_synth: SynthScope = False,
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


# Datasets written by a network sensor. Their originating document describes
# a FLOW; where a top-level host.name exists on one at all (a stock Filebeat /
# Elastic Agent pipeline — Security Onion strips it), it names the shipper.
_NETWORK_SENSOR_DATASET_PREFIXES: tuple[str, ...] = ("suricata.", "zeek.")
_NETWORK_SENSOR_MODULES: frozenset[str] = frozenset({"suricata", "zeek"})


def _host_pivot_skip_reason(alert: SoAlert) -> str | None:
    """Why the host pivot must not run for ``alert``, or None to run it.

    The pivot is a strict term query on top-level ``host.name``; it is only
    meaningful when that field names an ENDPOINT. Three shapes where it does
    not (each returns the ``skipped_*`` token recorded in prefetch_gaps):

    - ``skipped_field_absent`` — no ``host.name`` at all. The normal SO
      network-alert shape; recorded so an empty host pivot is
      distinguishable from one that ran and found nothing.
    - ``skipped_sensor_identity`` — ``host.name`` equals ``observer.name``
      or ``agent.name``: the shipper stamped its own identity, so a pivot
      would fan out to everything that sensor observed.
    - ``skipped_network_sensor_dataset`` — a ``suricata.*``/``zeek.*``
      document. Whatever a surviving top-level ``host.name`` says there, it
      is the sensor box, never a flow endpoint.
    """
    if not alert.host_name:
        return "skipped_field_absent"
    raw = alert.raw or {}
    sensor_names = {
        name
        for field in ("observer.name", "agent.name")
        if isinstance(name := fields.get_dotted(raw, field), str) and name
    }
    if alert.host_name in sensor_names:
        return "skipped_sensor_identity"
    dataset = alert.event_dataset or ""
    if dataset.startswith(_NETWORK_SENSOR_DATASET_PREFIXES):
        return "skipped_network_sensor_dataset"
    if (alert.event_module or "") in _NETWORK_SENSOR_MODULES:
        return "skipped_network_sensor_dataset"
    return None


# ---------------------------------------------------------------------------
# Endpoint coverage: "this host has no data" vs "this host has no coverage".
#
# The 2026-08-27 eval batch had 6 runs exhaust their 25-call tool budget
# probing ``endpoint.events.*`` for hosts that ship NO endpoint telemetry:
# the dataset inventory truthfully reports that endpoint data exists on the
# grid, so the model — reasoning correctly from what it was told — retried
# the probe across field spellings and widening windows, unable to tell
# "I haven't found it yet" from "it cannot exist". On a real grid every
# EDR-uncovered host (servers outside the agent rollout, contractor laptops,
# appliances, IoT) drains an investigation the same way.
#
# The prefetch therefore answers the coverage question ONCE, with one bounded
# ``size=0`` lookup dispatched alongside the other fan-outs, and records the
# answer in ``prefetch_gaps`` — the channel the host-pivot guard already uses
# for honest gaps. The dataset-name classes below say which datasets COUNT AS
# endpoint/host-agent telemetry (mirroring the inventory docstring's
# host-logging examples); whether any of them exist on THIS grid, and whether
# any of their documents come from THIS alert's hosts, is answered by the
# query, never by this list.
_ENDPOINT_DATASET_EXACT: tuple[str, ...] = ("endpoint", "sysmon", "osquery")
_ENDPOINT_DATASET_PREFIXES: tuple[str, ...] = (
    "endpoint.",
    "windows.",
    "sysmon.",
    "osquery.",
    "system.",
)
_ENDPOINT_MODULES: frozenset[str] = frozenset(
    {"endpoint", "sysmon", "osquery", "windows", "system"}
)

# The prefetch_gaps key + reason tokens. CONSTANTS on purpose: the tokens (and
# the prompt blocks keyed on them in soc_ai.agent.prompts) carry no grid
# counts, dataset lists, index names or host identifiers, so the signal reads
# byte-identically for a real uncovered host and a planted one — no
# evaluation tell.
ENDPOINT_COVERAGE_GAP_KEY = "endpoint.coverage"
ENDPOINT_COVERAGE_HOST_UNCOVERED = "no_endpoint_documents_for_host"
ENDPOINT_COVERAGE_DATASET_ABSENT = "no_endpoint_dataset_on_grid"

# Total window (minutes) centered on the alert. 1440 (±12 h) is the widest
# window the budget-exhausted runs probed, and matches the inventory's default
# discovery window: an endpoint agent that covered this host would have
# shipped SOMETHING within half a day of the alert.
ENDPOINT_COVERAGE_WINDOW_MINUTES = 1440


def _alert_is_endpoint_document(alert: SoAlert) -> bool:
    """The alert itself IS endpoint telemetry — its host is trivially covered."""
    dataset = alert.event_dataset or ""
    if dataset in _ENDPOINT_DATASET_EXACT or dataset.startswith(_ENDPOINT_DATASET_PREFIXES):
        return True
    return (alert.event_module or "") in _ENDPOINT_MODULES


async def _endpoint_coverage(
    alert: SoAlert,
    elastic: ElasticClient,
    settings: Settings,
    *,
    include_synth: SynthScope = False,
) -> str | None:
    """Does the alert's host ship endpoint telemetry at all? One bounded lookup.

    Returns a ``prefetch_gaps`` reason token, or ``None`` for covered/unknown:

    - :data:`ENDPOINT_COVERAGE_HOST_UNCOVERED` — the grid holds endpoint
      documents in the window, but none matching ANY of this alert's host
      identifiers (``host.ip`` / ``source.ip`` / ``destination.ip`` against
      both alert IPs, plus ``host.name`` when it names a genuine endpoint).
      Every endpoint probe keyed on those identifiers is then guaranteed
      empty — the wild-goose-chase case.
    - :data:`ENDPOINT_COVERAGE_DATASET_ABSENT` — zero endpoint documents on
      the whole grid in the window: a network-only deployment (around this
      alert's time, which is what matters for triaging it).
    - ``None`` — covered, or undeterminable (no timestamp / no identifiers /
      the read failed or was partial). A failed read must NEVER claim "no
      coverage": that claim stops the agent from probing, so it is only made
      from a COMPLETE successful read (``require_complete=True`` — a
      partial-shard zero is "could not see", not "not there").

    Cost: one ``size=0`` search (no documents fetched) bounded by the
    ±``ENDPOINT_COVERAGE_WINDOW_MINUTES``/2 range filter and the endpoint
    dataset filter, carrying a single ``filter`` sub-aggregation for the
    host-scoped count — the same order of cost as the existing host-risk
    aggregation it runs beside. Zero queries when the alert is itself an
    endpoint document. It runs once per prefetch, never per tool call, and
    spends nothing from the investigation's tool budget.
    """
    if alert.timestamp is None:
        return None
    if _alert_is_endpoint_document(alert):
        return None

    ips = [ip for ip in (alert.source_ip, alert.destination_ip) if ip]
    host_clauses: list[dict[str, Any]] = [
        {"terms": {field: ips}} for field in ("host.ip", "source.ip", "destination.ip") if ips
    ]
    if alert.host_name and _host_pivot_skip_reason(alert) is None:
        host_clauses.append({"term": {"host.name": alert.host_name}})
    if not host_clauses:
        return None

    delta = timedelta(minutes=ENDPOINT_COVERAGE_WINDOW_MINUTES / 2)
    gte = (alert.timestamp - delta).isoformat()
    lte = (alert.timestamp + delta).isoformat()

    dataset_clause: dict[str, Any] = {
        "bool": {
            "should": [
                *({"term": {"event.dataset": d}} for d in _ENDPOINT_DATASET_EXACT),
                *({"prefix": {"event.dataset": p}} for p in _ENDPOINT_DATASET_PREFIXES),
            ],
            "minimum_should_match": 1,
        }
    }
    query: dict[str, Any] = {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": gte, "lte": lte}}},
                dataset_clause,
            ],
            # Same exclusions as every other fan-out: the alert's own doc
            # (harmless here — the endpoint-document short-circuit above
            # already returned — but uniform), and the run's synth scope, so
            # a scenario-scoped eval sees exactly its own plants and prod
            # sees none.
            "must_not": [
                {"ids": {"values": [alert.id]}},
                *synth_scope_must_not(include_synth),
            ],
        }
    }
    aggs: dict[str, Any] = {
        "host_docs": {"filter": {"bool": {"should": host_clauses, "minimum_should_match": 1}}}
    }

    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs=aggs,
            require_complete=True,
        )
    except Exception as exc:  # best-effort: unknown coverage, never a false claim
        _LOGGER.warning(
            "endpoint-coverage check for alert %s failed (coverage unknown): %s",
            alert.id,
            type(exc).__name__,
        )
        return None

    if result.total == 0:
        return ENDPOINT_COVERAGE_DATASET_ABSENT
    host_docs = (result.aggregations or {}).get("host_docs") or {}
    count = host_docs.get("doc_count")
    if isinstance(count, int) and count == 0:
        return ENDPOINT_COVERAGE_HOST_UNCOVERED
    # Covered — or a malformed agg response, which reads as unknown, not as a claim.
    return None


async def _pivot(
    field_value: str | None,
    field_name: str,
    alert: SoAlert,
    elastic: ElasticClient,
    settings: Settings,
    window_seconds: int,
    max_results: int,
    *,
    include_synth: SynthScope = False,
) -> list[SoAlert]:
    """Run one pivot query, or return ``[]`` if the alert lacks the pivot value."""
    if not field_value or alert.timestamp is None:
        return []

    delta = timedelta(seconds=window_seconds)
    gte = (alert.timestamp - delta).isoformat()
    lte = (alert.timestamp + delta).isoformat()

    # Always exclude the alert under triage from its own fan-out, plus
    # whatever the synth-visibility scope excludes: the prefetch is the
    # synth-first pipeline's PRIMARY evidence path, so in prod (scope False)
    # a real alert sharing a community_id / host.name / user.name with
    # lingering synth fixtures must not pull fabricated evidence in, and in
    # the batch eval (scope = a scenario id) a synth alert must not pull in
    # its SIBLING scenarios' plants either.
    must_not: list[dict[str, Any]] = [
        {"ids": {"values": [alert.id]}},
        *synth_scope_must_not(include_synth),
    ]

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
    include_synth: SynthScope = False,
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

    must_not: list[dict[str, Any]] = [
        {"ids": {"values": [alert.id]}},
        *synth_scope_must_not(include_synth),
    ]

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
        # Materialize inside the try: a single schema-drifted summary doc (a
        # list/dict where SoAlert expects a scalar) would otherwise raise
        # pydantic.ValidationError here and, because the outer gather is NOT
        # return_exceptions=True, abort the ENTIRE prefetch. Best-effort means
        # a bad hit costs this pivot's evidence, not the whole investigation.
        return [SoAlert.from_es_hit(h) for h in result.hits]
    except Exception as exc:  # best-effort: never poison the prefetch (BLE001 ok)
        _LOGGER.warning(
            "behavioral-summary pivot for alert %s failed: %s", alert.id, type(exc).__name__
        )
        return []


async def _host_risk(
    alert: SoAlert,
    elastic: ElasticClient,
    settings: Settings,
    window_hours: int,
    *,
    include_synth: SynthScope = False,
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

    must_not: list[dict[str, Any]] = [
        {"ids": {"values": [alert.id]}},
        *synth_scope_must_not(include_synth),
    ]

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
    "ENDPOINT_COVERAGE_DATASET_ABSENT",
    "ENDPOINT_COVERAGE_GAP_KEY",
    "ENDPOINT_COVERAGE_HOST_UNCOVERED",
    "ENDPOINT_COVERAGE_WINDOW_MINUTES",
    "AlertContext",
    "EnrichedAlertContext",
    "get_alert_context",
    "get_enriched_alert_context",
]
