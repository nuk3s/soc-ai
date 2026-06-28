"""``rule_prevalence`` tool — base-rate / noisiness oracle for a detection rule.

The investigator (and analyst) constantly need one piece of context the alert
itself never carries: *how often does THIS rule fire across the estate?* A rule
that fires thousands of times a day on this network is almost certainly tuned
poorly or matching benign-here traffic — its next hit is weak evidence. A rule
that has NEVER fired before is the opposite: the very first firing is notable and
deserves a closer look. soc-ai was over-trusting rule *labels* (e.g. anchoring on
an ``ET MALWARE …`` signature name) without ever asking whether that signature is
a constant-firing nuisance on this grid. This READ-ONLY, ZERO-EGRESS tool answers
the base-rate question directly from Elasticsearch.

What it derives for one rule name over a lookback window:

- ``total_fires`` — how many ``suricata.alert`` docs matched the rule name.
- ``distinct_src_hosts`` / ``distinct_dest_hosts`` — cardinality of the source /
  destination IPs the rule fired on (a rule firing across the whole estate is
  noise; one firing on a single host pair is focused).
- ``first_seen`` / ``last_seen`` — the span the rule has been active in the window.
- ``fires_per_day`` — ``total_fires`` normalised over the lookback window.
- ``noisiness`` — a coarse bucket (``noisy`` / ``occasional`` / ``rare`` /
  ``first-seen``) derived from ``fires_per_day``, the single headline the agent
  should weigh: a *noisy* rule firing again is weak evidence; a *first-seen* or
  *rare* rule firing is notable.
- ``summary`` — a one-line natural-language gloss the agent can quote.

Robustness contract (mirrors ``host_summary`` and the other read tools):

- **Empty data** → a clean ``{"observed": False, "noisiness": "first-seen", …}``
  result (absence is a real answer: this rule has not fired in the window — its
  next firing is notable), NEVER an exception.
- **ES error / bad input** → a clean ``{"error": True, "message": …}`` dict,
  NEVER a raised exception (the agent reads the dict and moves on).
- The rule-name field is resolved **ECS-first** (``rule.name`` → ``rule.rule`` →
  ``signature``) so the same rule resolves whether the grid populates the modern
  ECS ``rule.name`` or the legacy Suricata ``signature`` field.
"""

from __future__ import annotations

import logging
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools._registry import tool

_LOGGER = logging.getLogger(__name__)

# Rule-name field candidates, ECS-first. Modern SO/Elastic-Agent populates
# ``rule.name``; ``rule.rule`` carries the full Suricata rule text on some
# deployments; ``signature`` is the legacy Suricata field name. We match the rule
# across ALL of these so one signature resolves regardless of schema. ``.keyword``
# multi-fields are appended so the term match works on analysed text mappings too.
_RULE_NAME_FIELDS: tuple[str, ...] = ("rule.name", "rule.rule", "signature")

# Only suricata IDS alerts carry a meaningful "rule fired" base rate. Zeek/notice
# datasets have their own cadence; scoping to suricata.alert keeps the number
# interpretable.
_DATASET = "suricata.alert"

# noisiness thresholds, in fires-per-day over the lookback window. Deliberately
# coarse — this is a hint to weight the evidence, not a verdict. A rule firing
# tens of times a day across the estate is background noise here; a rule firing
# a handful of times is occasional; less than ~once a day is rare; zero is the
# special "first-seen" bucket (its very next firing is the notable one).
_NOISY_PER_DAY = 10.0
_OCCASIONAL_PER_DAY = 1.0
# "Noisy" also requires broad host-spread, not just a high rate — a high rate at
# a single host pair is focused, not background nuisance.
_NOISY_MIN_HOSTS = 5


def _rule_match_query(rule_name: str, lookback_days: int) -> dict[str, Any]:
    """Match ``suricata.alert`` docs whose rule name equals ``rule_name``.

    The rule-name match is an OR across every ECS/legacy candidate field (and
    their ``.keyword`` sub-fields) so the same signature resolves whatever the
    grid populated. Synthetic-eval fixtures are excluded — a synth scenario must
    never inflate a real rule's base rate.
    """
    # match_phrase on rule.name (the real, populated field) mirrors the alert
    # resolver in routes.py — `term` silently returns 0 on a text-analyzed
    # mapping, which would misreport a noisy rule as first-seen. The legacy
    # fields are speculative no-match fallbacks.
    should: list[dict[str, Any]] = [{"match_phrase": {"rule.name": rule_name}}]
    for field_name in ("rule.rule", "signature"):
        should.append({"term": {field_name: rule_name}})
    return {
        "bool": {
            "must": [
                {"term": {"event.dataset": _DATASET}},
                {"bool": {"should": should, "minimum_should_match": 1}},
            ],
            "filter": [
                {"range": {"@timestamp": {"gte": f"now-{lookback_days}d", "lte": "now"}}},
            ],
            # Synthetic-eval kill-switch — same convention as query_events_oql /
            # host_summary: never let a synth fixture leak into a real base rate.
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }


def _agg_value(agg: dict[str, Any] | None) -> int | None:
    """Read a cardinality aggregation's integer ``value`` (or ``None``)."""
    if not agg:
        return None
    value = agg.get("value")
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _agg_time(agg: dict[str, Any] | None) -> str | None:
    """Read a min/max date aggregation (prefer the ISO ``value_as_string``)."""
    if not agg:
        return None
    as_string = agg.get("value_as_string")
    if isinstance(as_string, str) and as_string:
        return as_string
    value = agg.get("value")
    return str(value) if value is not None else None


def _classify_noisiness(total_fires: int, fires_per_day: float, distinct_hosts: int) -> str:
    """Bucket a rule by how often AND how broadly it fires across the estate.

    ``first-seen`` is reserved for a rule that has NOT fired in the window — its
    next firing is the notable one. ``noisy`` (background nuisance — a firing is
    weak evidence) requires BOTH a high firing rate AND broad host-spread: a high
    rate concentrated on a single host pair is focused, not noise, so it stays
    ``occasional``. ``rare`` = a firing is notable.
    """
    if total_fires <= 0:
        return "first-seen"
    if fires_per_day >= _NOISY_PER_DAY and distinct_hosts >= _NOISY_MIN_HOSTS:
        return "noisy"
    if fires_per_day >= _OCCASIONAL_PER_DAY:
        return "occasional"
    return "rare"


def _empty_result(rule_name: str, lookback_days: int) -> dict[str, Any]:
    """The clean no-data result — absence is a real, useful answer.

    A rule that has not fired in the lookback window is ``first-seen``: its very
    next firing is notable, which is exactly the signal the caller wants.
    """
    return {
        "rule_name": rule_name,
        "observed": False,
        "lookback_days": lookback_days,
        "total_fires": 0,
        "distinct_src_hosts": 0,
        "distinct_dest_hosts": 0,
        "first_seen": None,
        "last_seen": None,
        "fires_per_day": 0.0,
        "noisiness": "first-seen",
        "summary": (
            f"'{rule_name}' has not fired in the last {lookback_days}d — "
            "a firing now is notable (first-seen in window)"
        ),
    }


@tool(
    read_only=True,
    description=(
        "Base-rate / noisiness of a Suricata detection rule across the estate:"
        " is it noisy (fires constantly -> a firing is weak evidence here) or"
        " rare/first-seen (a firing is notable)? Returns total_fires,"
        " distinct src/dest hosts, first/last seen, fires_per_day, noisiness."
    ),
)
async def rule_prevalence(
    rule_name: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    lookback_days: int = 30,
) -> dict[str, Any]:
    """How prevalent is a detection rule across the estate over a lookback window?

    Answers: is this rule *noisy* (fires constantly across many hosts → its next
    firing is likely benign HERE and weak evidence) or *rare / first-seen* (a
    firing is notable)? This is the base-rate context the alert itself never
    carries — weigh it BEFORE trusting a rule label as a verdict driver.

    READ-ONLY and ZERO-EGRESS: a single aggregation query against the Security
    Onion events index. It never raises — the caller is an LLM tool boundary.

    Args:
        rule_name: the exact detection-rule / signature name to look up (the
            value carried on the alert's ``rule.name`` / ``signature`` field).
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        lookback_days: window size in days. Default 30.

    Returns:
        A dict with ``observed`` / ``total_fires`` / ``distinct_src_hosts`` /
        ``distinct_dest_hosts`` / ``first_seen`` / ``last_seen`` /
        ``fires_per_day`` / ``noisiness`` (``noisy`` | ``occasional`` | ``rare``
        | ``first-seen``) / ``summary``. On no data: a clean ``observed: False``,
        ``noisiness: 'first-seen'`` result (absence is a real answer). On an ES
        error or bad input: a clean ``{"error": True, "message": …}`` dict.
        NEVER raises.
    """
    if not isinstance(rule_name, str) or not rule_name.strip():
        return {
            "error": True,
            "type": "ValueError",
            "message": "rule_name must be a non-empty string",
        }
    rule_name = rule_name.strip()

    if lookback_days <= 0:
        return {
            "error": True,
            "type": "ValueError",
            "message": f"lookback_days must be positive, got {lookback_days}",
        }

    index = settings.events_index_pattern
    query = _rule_match_query(rule_name, lookback_days)

    # cardinality aggs give distinct source/dest host counts in one round trip;
    # min/max give the active span. size=0 — we never need the docs themselves,
    # only the volume + spread numbers, which keeps the next-turn context tiny.
    aggs: dict[str, Any] = {
        "distinct_src_hosts": {"cardinality": {"field": "source.ip"}},
        "distinct_dest_hosts": {"cardinality": {"field": "destination.ip"}},
        "first_seen": {"min": {"field": "@timestamp"}},
        "last_seen": {"max": {"field": "@timestamp"}},
    }

    try:
        result = await elastic.search(
            index,
            query,
            size=0,
            aggs=aggs,
            track_total_hits=True,
        )
    except Exception as e:
        _LOGGER.warning("rule_prevalence ES search failed for %r: %s", rule_name, e)
        return {"error": True, "type": type(e).__name__, "message": str(e)}

    total_fires = int(result.total)
    if total_fires == 0:
        return _empty_result(rule_name, lookback_days)

    aggregations = result.aggregations or {}
    distinct_src = _agg_value(aggregations.get("distinct_src_hosts")) or 0
    distinct_dest = _agg_value(aggregations.get("distinct_dest_hosts")) or 0
    first_seen = _agg_time(aggregations.get("first_seen"))
    last_seen = _agg_time(aggregations.get("last_seen"))

    # Normalise volume over the FULL lookback window (not the observed span): the
    # question is "how often does this fire on this estate", and a rule that fired
    # 100 times in one hour 20 days ago is still rare across a 30-day window.
    fires_per_day = round(total_fires / lookback_days, 3)
    noisiness = _classify_noisiness(total_fires, fires_per_day, max(distinct_src, distinct_dest))

    summary = (
        f"'{rule_name}' fired {total_fires}x in {lookback_days}d "
        f"(~{fires_per_day}/day) across {distinct_src} source / "
        f"{distinct_dest} dest host(s) - {noisiness}"
    )

    return {
        "rule_name": rule_name,
        "observed": True,
        "lookback_days": lookback_days,
        "total_fires": total_fires,
        "distinct_src_hosts": distinct_src,
        "distinct_dest_hosts": distinct_dest,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "fires_per_day": fires_per_day,
        "noisiness": noisiness,
        "summary": summary,
    }
