"""``suggest_rule_tuning`` tool — is a detection rule a noisy FP nuisance?

Companion to ``rule_prevalence``. Where that answers *how often* a rule fires,
this answers the operator's tuning question directly: *is this rule a noisy,
mostly-benign nuisance that should be muted / re-tuned, or is it pulling its
weight?* It is the read-only signal an investigation cites when a verdict leans
on a rule label — "this signature has fired 412× this week and 96% of those were
already acknowledged-without-escalation, so its firing here is weak evidence."

Data the tool can reach (a tool boundary only receives ``elastic`` + ``settings``
— it has no clean local-DB session, and we do NOT invent a new injection just for
this tool), so the FP trend is approximated from Elasticsearch:

* ``alert_count`` — how many ``suricata.alert`` docs the rule produced in the
  window (volume).
* ``acked`` / ``escalated`` — how many were acknowledged vs escalated. On a
  Security Onion grid an analyst *acknowledges* an alert they have dispositioned
  as benign and *escalates* one that warranted a case — so a high
  acknowledged-and-never-escalated rate is the ES-visible proxy for "keeps coming
  back false-positive". ``escalated > 0`` blocks a mute recommendation (the rule
  has caught something worth a case).

The ``fp`` / ``tp`` / ``nmi`` fields in the return map onto that proxy
(``fp`` = acknowledged-not-escalated, ``tp`` = escalated, ``nmi`` = the rest) so
the tool's shape matches the Detection Tuning panel's verdict-trend nomination.
The richer verdict trend (actual completed-investigation verdicts) lives behind
the ``/api/v1/detection-tuning`` endpoint, which has DB access.

READ-ONLY and zero-egress: a single aggregation query against the SO events
index. It never raises — the caller is an LLM tool boundary.
"""

from __future__ import annotations

import logging
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools._registry import tool
from soc_ai.tools.tuning_heuristic import assess

_LOGGER = logging.getLogger(__name__)

# Only suricata IDS alerts carry a meaningful rule base rate / disposition trend
# (mirrors rule_prevalence — Zeek/notice datasets have their own cadence).
_DATASET = "suricata.alert"


def _rule_disposition_query(rule_name: str, lookback_days: int) -> dict[str, Any]:
    """Match this rule's ``suricata.alert`` docs over the lookback window.

    Mirrors ``rule_prevalence._rule_match_query``: a phrase match on ``rule.name``
    plus speculative ``term`` fallbacks on the legacy fields, scoped to the
    suricata dataset and the window, with the synthetic-eval kill-switch.
    """
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
            "must_not": [{"exists": {"field": "synth.scenario_id"}}],
        }
    }


def _agg_count(agg: dict[str, Any] | None) -> int:
    """Read a ``filter`` aggregation's ``doc_count`` (0 when absent)."""
    if not agg:
        return 0
    try:
        return int(agg.get("doc_count", 0))
    except (TypeError, ValueError):
        return 0


@tool(
    read_only=True,
    description=(
        "Detection tuning: is this Suricata rule a noisy, mostly-benign nuisance "
        "that should be muted/re-tuned, or is it pulling its weight? Returns the "
        "rule's alert volume, its acknowledged-vs-escalated disposition trend "
        "(the ES proxy for false-positive vs true-positive), and a "
        "mute/monitor/none recommendation with a one-line reason. READ-ONLY: it "
        "nominates, it does not change Security Onion."
    ),
)
async def suggest_rule_tuning(
    rule_name: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    lookback_days: int = 7,
) -> dict[str, Any]:
    """Should this detection rule be muted / re-tuned for noise?

    Derives the rule's alert volume and acknowledged-vs-escalated disposition
    trend from Elasticsearch and runs the shared
    :func:`soc_ai.tools.tuning_heuristic.assess` heuristic to produce a
    ``mute`` / ``monitor`` / ``none`` recommendation. ``fp`` (acknowledged,
    not escalated) / ``tp`` (escalated) / ``nmi`` (the remainder) approximate the
    false-positive / true-positive / needs-more-info verdict trend from the
    analyst dispositions visible in ES.

    Args:
        rule_name: the exact detection-rule / signature name (the alert's
            ``rule.name`` / ``signature`` value).
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        lookback_days: window size in days. Default 7.

    Returns:
        ``{rule_name, alert_count, fp, tp, nmi, recommendation, reason, summary}``.
        On no data: a clean ``alert_count: 0`` / ``recommendation: 'none'`` result
        (absence is a real answer — nothing to tune). On an ES error or bad input:
        a clean ``{"error": True, "message": …}`` dict. NEVER raises.
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

    query = _rule_disposition_query(rule_name, lookback_days)
    aggs: dict[str, Any] = {
        "acked": {"filter": {"term": {"event.acknowledged": True}}},
        "escalated": {"filter": {"term": {"event.escalated": True}}},
    }
    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs=aggs,
            track_total_hits=True,
        )
    except Exception as e:
        _LOGGER.warning("suggest_rule_tuning ES search failed for %r: %s", rule_name, e)
        return {"error": True, "type": type(e).__name__, "message": str(e)}

    alert_count = int(result.total)
    aggregations = result.aggregations or {}
    acked = _agg_count(aggregations.get("acked"))
    escalated = _agg_count(aggregations.get("escalated"))

    # Map ES dispositions onto the verdict-trend buckets assess() expects:
    #   tp  = escalated (analyst raised a case — a real positive)
    #   fp  = acknowledged but NOT escalated (dispositioned benign)
    #   nmi = neither acknowledged nor escalated (untriaged remainder)
    tp = escalated
    fp = max(acked - escalated, 0)
    nmi = max(alert_count - acked - max(escalated - acked, 0), 0)

    _is_noisy, recommendation, reason = assess(alert_count, fp, tp, nmi)

    summary = (
        f"'{rule_name}' fired {alert_count}× in {lookback_days}d "
        f"({fp} acked-benign / {tp} escalated / {nmi} untriaged) — "
        f"recommendation: {recommendation}"
    )

    return {
        "rule_name": rule_name,
        "alert_count": alert_count,
        "fp": fp,
        "tp": tp,
        "nmi": nmi,
        "recommendation": recommendation,
        "reason": reason,
        "summary": summary,
    }
