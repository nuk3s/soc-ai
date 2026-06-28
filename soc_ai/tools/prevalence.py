"""``prevalence`` tool — local first-seen / novelty oracle (READ-ONLY, ZERO-EGRESS).

Answers the analyst's core triage question — *"has THIS host ever talked to THIS
destination / domain before, and how rare is it?"* — purely from the events index.
No external calls, no API keys, no egress: the verdict is learned entirely from
what Security Onion has already observed on this network.

Three query modes, selected by which optional arg is passed:

- ``peer_ip``  — count flows between ``ip`` and ``peer_ip`` in either direction
  (``{source.ip==ip, destination.ip==peer_ip}`` OR the reverse).
- ``domain``   — count this host's resolutions / SNI / HTTP-Host matches for the
  domain (``dns.query`` / ``ssl.server_name`` / ``http.host``, ECS-first).
- neither      — summarize the host's overall activity over the window.

The return shape is stable across modes::

    {observed, first_seen, last_seen, total_events, distinct_days,
     is_novel, rarity, summary, evidence}

``rarity`` is a coarse human label:

- ``"first-seen"`` — the pairing/domain/host first appears inside the lookback
  window (``is_novel`` is True): no prior baseline, treat as new.
- ``"rare"``       — seen on only a handful of distinct days.
- ``"common"``     — seen on many distinct days (an established baseline).

Field resolution is ECS-first (``soc_ai.so_client.fields``) so the same logical
question resolves on a modern Elastic-Agent 9.x grid and on the legacy ``zeek.*``
synth fixtures. The tool NEVER raises: empty data returns a clean
``{observed: False, ...}`` dict; an ES / query error returns
``{error: True, message: ...}``.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client import fields
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools._registry import tool

_LOGGER = logging.getLogger(__name__)

# Distinct-day thresholds for the coarse rarity label. A host/pairing seen on
# only a couple of distinct days is "rare"; one seen on a week-plus of distinct
# days has an established baseline and is "common". These are deliberately
# coarse — the label is a triage hint, not a statistic.
_RARE_MAX_DISTINCT_DAYS = 3

# Cap on the number of distinct-day buckets we materialize. A 90-day window can
# only ever have 90 day-buckets, but pin a hard ceiling so a misconfigured
# lookback can't ask ES for an unbounded histogram.
_MAX_DAY_BUCKETS = 400

# Domain-match candidate fields, ECS-first. A host "talks to" a domain when it
# resolves it (dns.query), negotiates TLS to it (ssl.server_name / SNI), or
# sends an HTTP request to it (http.host / virtual_host). We OR across all
# candidate field names so the match lands regardless of SO schema version.
_DOMAIN_FIELDS: tuple[str, ...] = tuple(
    dict.fromkeys(
        (
            *fields.DNS_QUERY,
            *fields.SSL_SNI,
            *fields.HTTP_HOST,
        )
    )
)


def _peer_query(ip: str, peer_ip: str) -> dict[str, Any]:
    """Match flows between ``ip`` and ``peer_ip`` in either direction."""
    return {
        "bool": {
            "should": [
                {
                    "bool": {
                        "must": [
                            {"term": {"source.ip": ip}},
                            {"term": {"destination.ip": peer_ip}},
                        ]
                    }
                },
                {
                    "bool": {
                        "must": [
                            {"term": {"source.ip": peer_ip}},
                            {"term": {"destination.ip": ip}},
                        ]
                    }
                },
            ],
            "minimum_should_match": 1,
        }
    }


def _domain_query(ip: str, domain: str) -> dict[str, Any]:
    """Match this host's events that reference ``domain`` (DNS/SNI/HTTP-Host)."""
    return {
        "bool": {
            "must": [
                {
                    "bool": {
                        "should": [
                            {"term": {"source.ip": ip}},
                            {"term": {"destination.ip": ip}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                {
                    "bool": {
                        "should": [{"term": {f: domain}} for f in _DOMAIN_FIELDS],
                        "minimum_should_match": 1,
                    }
                },
            ]
        }
    }


def _host_query(ip: str) -> dict[str, Any]:
    """Match every event touching ``ip`` as source or destination."""
    return {
        "bool": {
            "should": [
                {"term": {"source.ip": ip}},
                {"term": {"destination.ip": ip}},
            ],
            "minimum_should_match": 1,
        }
    }


def _lookback_filter(lookback_days: int, anchor: datetime | None) -> dict[str, Any]:
    """Range filter on ``@timestamp`` over the lookback window.

    When ``anchor`` is given (the alert's @timestamp), the window is
    ``[anchor - lookback, anchor]`` so the baseline reflects what was known
    *before and up to* the alert. Without an anchor, fall back to
    ``[now - lookback, now]`` for live-monitoring callers.
    """
    if anchor is not None:
        from datetime import timedelta  # noqa: PLC0415

        gte = (anchor - timedelta(days=lookback_days)).isoformat()
        lte = anchor.isoformat()
        return {"range": {"@timestamp": {"gte": gte, "lte": lte}}}
    return {"range": {"@timestamp": {"gte": f"now-{lookback_days}d", "lte": "now"}}}


def _classify_rarity(distinct_days: int, is_novel: bool) -> str:
    """Coarse human rarity label from distinct-day count + novelty flag."""
    if is_novel:
        return "first-seen"
    if distinct_days <= _RARE_MAX_DISTINCT_DAYS:
        return "rare"
    return "common"


def _empty_result(summary: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Clean not-observed result (never an error)."""
    return {
        "observed": False,
        "first_seen": None,
        "last_seen": None,
        "total_events": 0,
        "distinct_days": 0,
        "is_novel": False,
        "rarity": "first-seen",
        "summary": summary,
        "evidence": evidence,
    }


@tool(
    read_only=True,
    description=(
        "Local first-seen / prevalence oracle: has this host talked to this "
        "dest/domain before, and how rare is it? Learned from the events index "
        "only (no external calls)."
    ),
)
async def prevalence(
    ip: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    peer_ip: str | None = None,
    domain: str | None = None,
    lookback_days: int = 90,
    time_anchor: datetime | None = None,
) -> dict[str, Any]:
    """Answer "has THIS host seen THIS dest/domain before, and how rare is it?".

    Queries ``settings.events_index_pattern`` over the last ``lookback_days``
    days and returns a prevalence/novelty summary. The mode is chosen by which
    optional arg is set:

    - ``peer_ip`` given: count flows between ``ip`` and ``peer_ip`` (either
      direction).
    - ``domain`` given: count this host's DNS-query / SSL-SNI / HTTP-Host
      matches for ``domain`` (ECS-first field resolution).
    - neither given: summarize the host's overall activity in the window.

    Args:
        ip: the host under investigation (matched on source.ip / destination.ip).
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        peer_ip: when set, scope to flows between ``ip`` and this peer.
        domain: when set, scope to this host's references to this domain.
        lookback_days: window size in days. Default 90.
        time_anchor: when set, anchor the window's upper bound on this timestamp
            (``[anchor - lookback, anchor]``) instead of "now". The orchestrator
            passes ``alert.timestamp`` so the baseline reflects what was known up
            to the alert; CLI/live callers leave it ``None``.

    Returns:
        On success::

            {observed: bool, first_seen, last_seen, total_events, distinct_days,
             is_novel, rarity, summary, evidence}

        - ``observed`` — whether any matching event exists in the window.
        - ``first_seen`` / ``last_seen`` — ISO timestamps (None when unobserved).
        - ``distinct_days`` — number of distinct calendar days with ≥1 match.
        - ``is_novel`` — True when there is no prior baseline (unobserved) or the
          first match falls inside the lookback window with no earlier sighting
          available — treat the pairing/domain/host as new.
        - ``rarity`` — ``"first-seen"`` | ``"rare"`` | ``"common"``.
        - ``evidence`` — the resolved mode, the indicators, and the raw counts,
          so the agent can cite what was actually queried.

        On empty data: a clean ``{observed: False, ...}`` summary (never raises).
        On an ES / query error: ``{error: True, message: ...}`` (never raises).
    """
    mode = "host"
    if peer_ip:
        mode = "peer"
        query = _peer_query(ip, peer_ip)
        subject = f"{ip} ↔ {peer_ip}"
    elif domain:
        mode = "domain"
        query = _domain_query(ip, domain)
        subject = f"{ip} → {domain}"
    else:
        query = _host_query(ip)
        subject = ip

    if lookback_days <= 0:
        # Don't raise — return a clean error the agent can read and correct.
        return {
            "error": True,
            "message": f"lookback_days must be positive, got {lookback_days}",
        }

    evidence: dict[str, Any] = {
        "mode": mode,
        "ip": ip,
        "peer_ip": peer_ip,
        "domain": domain,
        "lookback_days": lookback_days,
        "index_pattern": settings.events_index_pattern,
    }
    if mode == "domain":
        evidence["domain_fields"] = list(_DOMAIN_FIELDS)

    wrapped: dict[str, Any] = {
        "bool": {
            "must": [query],
            "filter": [_lookback_filter(lookback_days, time_anchor)],
            # Never let synthetic-eval fixtures (logs-synth-*) pollute the
            # prevalence/novelty baseline — every other events reader excludes them.
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }

    aggs: dict[str, Any] = {
        "first_seen": {"min": {"field": "@timestamp"}},
        "last_seen": {"max": {"field": "@timestamp"}},
        "by_day": {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "day",
                "min_doc_count": 1,
            }
        },
    }

    try:
        result = await elastic.search(
            settings.events_index_pattern,
            wrapped,
            size=0,
            aggs=aggs,
            track_total_hits=True,
        )
    except Exception as e:
        # Never let a query/transport error crash the agent loop — surface it
        # as a structured result the model (and audit) can read.
        _LOGGER.warning("prevalence query failed (%s): %s", subject, e)
        return {"error": True, "message": str(e)}

    total = result.total
    if total <= 0:
        summary = (
            f"No prior events for {subject} in the last {lookback_days}d — "
            f"first-seen (no baseline). This pairing/host appears novel."
        )
        return _empty_result(summary, evidence)

    aggregations = result.aggregations or {}
    first_seen = _agg_value_as_string(aggregations.get("first_seen"))
    last_seen = _agg_value_as_string(aggregations.get("last_seen"))
    buckets = (aggregations.get("by_day") or {}).get("buckets") or []
    distinct_days = min(len(buckets), _MAX_DAY_BUCKETS)

    # Novelty: with the window anchored on (or ending at) the alert, a pairing
    # whose first sighting is the FIRST distinct day of an otherwise short
    # history has no established baseline. We treat "seen on a single distinct
    # day" as novel (it only happened the once, around the alert) and otherwise
    # rely on the distinct-day spread for rarity.
    is_novel = distinct_days <= 1

    rarity = _classify_rarity(distinct_days, is_novel)
    evidence["total_events"] = total
    evidence["total_is_lower_bound"] = result.total_is_lower_bound

    count_str = result.total_display  # "≥N" when ES capped the count
    if is_novel:
        summary = (
            f"{subject}: seen on a single day only "
            f"({count_str} event(s), first/last {first_seen}) — novel, no baseline."
        )
    else:
        summary = (
            f"{subject}: {rarity} — {count_str} event(s) across {distinct_days} "
            f"distinct day(s) (first {first_seen}, last {last_seen}) in the last "
            f"{lookback_days}d."
        )

    return {
        "observed": True,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "total_events": total,
        "distinct_days": distinct_days,
        "is_novel": is_novel,
        "rarity": rarity,
        "summary": summary,
        "evidence": evidence,
    }


def _agg_value_as_string(agg: Any) -> str | None:
    """Extract a date min/max aggregation value as an ISO string.

    ES date min/max aggs return ``{"value": <epoch_millis>, "value_as_string":
    <iso>}``. Prefer ``value_as_string``; fall back to the numeric ``value``
    rendered as a string. Returns None when the agg is absent or has no value
    (e.g. no matching docs).
    """
    if not isinstance(agg, dict):
        return None
    as_string = agg.get("value_as_string")
    if isinstance(as_string, str) and as_string:
        return as_string
    value = agg.get("value")
    if value is None:
        return None
    return str(value)
