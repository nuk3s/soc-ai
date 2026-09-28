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
``triaged`` is ``fp + tp`` — the alerts that actually carry a disposition, which
is what the heuristic's data-point floor is about. The untriaged remainder is
not evidence of anything.
The richer verdict trend (actual completed-investigation verdicts) lives behind
the ``/api/v1/detection-tuning`` endpoint, which has DB access.

**Volume is not the same as recurrence.** The heuristic's floors mean "this rule
keeps coming back", and alert_count alone cannot say that: 1531 fires of a
lateral-movement signature inside 59 seconds clears the mute bar by 15x and is a
single episode. So the query also asks for the first and last sighting and a
calendar-day histogram, and ``soc_ai.tools._burstiness`` decides whether the
alerts are a rate or a burst. A burst is never a mute candidate — muting there
would suppress the signature that fired on the thing worth investigating.

**Nor is volume the same as volume HERE.** This tool's output is a
recommendation to silence a detection, which is the most consequential thing a
read tool in this codebase produces, and every input to it was counted over
whatever the grid holds. Security Onion's ``so-import-pcap`` /
``so-import-evtx`` and a replayed corpus write ``suricata.alert`` documents that
carry no analyst disposition, so an import both inflates ``alert_count`` past
the mute floor and lands entirely in the untriaged remainder — pushing volume
up and dispositioned evidence down, which is the exact shape the heuristic reads
as a nuisance rule. A recommendation to mute a rule on this network cannot be
computed over documents this network never produced, so the query counts live
telemetry only (:mod:`soc_ai.tools._provenance`) and says which population it
counted.

READ-ONLY and zero-egress: a single aggregation query against the SO events
index. It never raises — the caller is an LLM tool boundary.
"""

from __future__ import annotations

import logging
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools import _burstiness as burst
from soc_ai.tools._provenance import (
    ANY,
    LIVE,
    Provenance,
    count_imports,
    denominator_note,
    imports_note,
    provenance_must_not,
)
from soc_ai.tools._registry import tool
from soc_ai.tools.tuning_heuristic import assess

_LOGGER = logging.getLogger(__name__)

# Only suricata IDS alerts carry a meaningful rule base rate / disposition trend
# (mirrors rule_prevalence — Zeek/notice datasets have their own cadence).
_DATASET = "suricata.alert"

# Cap the caller-supplied lookback window. This is an LLM-callable read tool and
# alert-embedded text is in-scope prompt-injection surface, so an unbounded
# lookback_days would let the agent turn a tuning check into a full-retention
# aggregation (track_total_hits, the day histogram, and on the zero branch a
# second import-count search) against the live SO grid. 365d is ample for a
# disposition trend and mirrors the sibling read tools' ceilings.
_MAX_LOOKBACK_DAYS = 365


def _rule_disposition_query(
    rule_name: str, lookback_days: int, provenance: Provenance = LIVE
) -> dict[str, Any]:
    """Match this rule's ``suricata.alert`` docs over the lookback window.

    Mirrors ``rule_prevalence._rule_match_query``: a phrase match on ``rule.name``
    plus speculative ``term`` fallbacks on the legacy fields, scoped to the
    suricata dataset and the window, with the synthetic-eval kill-switch and the
    provenance scope. Backfill is excluded for a reason specific to this tool:
    an imported alert carries no analyst disposition, so it pushes ``alert_count``
    up and the dispositioned fraction down at the same time, which is precisely
    the shape :func:`~soc_ai.tools.tuning_heuristic.assess` reads as a nuisance.
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
            "must_not": [
                {"exists": {"field": "synth.scenario_id"}},
                *provenance_must_not(provenance),
            ],
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
        "mute/monitor/none recommendation with a one-line reason. Also reports "
        "whether the alerts arrived as a recurring rate or as one burst "
        "(is_burst) — a burst is never a tuning problem, and may be the event "
        "worth investigating. READ-ONLY: it nominates, it does not change "
        "Security Onion."
    ),
)
async def suggest_rule_tuning(
    rule_name: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    lookback_days: int = 7,
    provenance: Provenance = LIVE,
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
        lookback_days: window size in days. Default 7, at most 365.
        provenance: which population the volume and disposition trend are
            measured over (:mod:`soc_ai.tools._provenance`). ``"live"`` (the
            default) counts only alerts this grid's own sensors raised, because
            a recommendation to silence a detection HERE cannot rest on
            documents this network never produced. ``"any"`` includes backfill.

    Returns:
        ``{rule_name, searched_dataset, provenance, alert_count, imported_alerts,
        fp, tp, nmi, triaged, first_seen, last_seen, observed_span_seconds,
        active_days, is_burst, recommendation, reason, summary}``. When
        ``is_burst`` is true the alerts are one episode rather than a recurring
        rate and the recommendation is never ``mute``.
        On no data: a clean ``alert_count: 0`` / ``recommendation: 'none'`` result
        (absence is a real answer — nothing to tune), with ``imported_alerts``
        carrying how many firings the live scope held back (``None`` when that
        could not be measured). On an ES error or bad input: a clean
        ``{"error": True, "message": …}`` dict. NEVER raises.
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
    if lookback_days > _MAX_LOOKBACK_DAYS:
        return {
            "error": True,
            "type": "ValueError",
            "message": f"lookback_days must be <= {_MAX_LOOKBACK_DAYS}, got {lookback_days}",
        }

    query = _rule_disposition_query(rule_name, lookback_days, provenance)
    # The disposition counts answer "how did analysts call this rule". The span
    # and day histogram answer the question the volume floors silently assume:
    # did these alerts arrive as a recurring rate, or as one episode?
    aggs: dict[str, Any] = {
        "acked": {"filter": {"term": {"event.acknowledged": True}}},
        "escalated": {"filter": {"term": {"event.escalated": True}}},
        "first_seen": {"min": {"field": "@timestamp"}},
        "last_seen": {"max": {"field": "@timestamp"}},
        "by_day": burst.day_histogram_agg(),
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
    # Only the acked/escalated alerts are data points. Folding the untriaged
    # remainder into the count makes the MIN_TRIAGED floor vacuous and tells the
    # reader a rule nobody dispositioned was examined once per alert document.
    triaged = fp + tp

    first_seen = burst.agg_time(aggregations.get("first_seen"))
    last_seen = burst.agg_time(aggregations.get("last_seen"))
    first_epoch = burst.agg_epoch_seconds(aggregations.get("first_seen"))
    last_epoch = burst.agg_epoch_seconds(aggregations.get("last_seen"))
    span_seconds: float | None = None
    if first_epoch is not None and last_epoch is not None:
        span_seconds = max(0.0, last_epoch - first_epoch)
    active_days = burst.active_days_from(aggregations.get("by_day"))
    shape = burst.measure(
        total=alert_count,
        span_seconds=span_seconds,
        active_days=active_days,
        lookback_days=lookback_days,
    )

    _is_noisy, recommendation, reason = assess(
        alert_count, fp, tp, nmi, triaged=triaged, is_burst=shape.is_burst
    )

    if shape.is_burst and span_seconds is not None:
        shape_clause = (
            f" — all of it inside {burst.span_phrase(span_seconds)} on "
            f"{burst.plural(active_days or 1, 'active day')}, one burst rather than a"
            " recurring rate"
        )
    else:
        shape_clause = ""
    # Name the dataset this looked in, ALWAYS, and say what a zero means when
    # zero is what came back.
    #
    # This tool reads suricata.alert and nothing else, by design. It never said
    # so, so for a Sigma or endpoint rule it reported "fired 0× in 7d —
    # recommendation: none" no matter how noisy the rule actually was. On the
    # range that produced a reasoning trace where t_rule_prevalence said 214
    # fires and this tool said 0 for the same rule, moments apart, with nothing
    # to explain the gap — an analyst reading that has to distrust one of them
    # and cannot tell which.
    #
    # A zero here is "I did not look there", not "it does not fire". Those are
    # opposite conclusions and the reader was getting the wrong one.
    # Two scopes, always both. The dataset one was already here; the population
    # one is the same kind of sentence about a different axis, and a mute
    # recommendation is unreadable without either.
    scope = f" in {_DATASET}, {denominator_note(provenance)}"
    imported: int | None = None
    # ``imports_note`` answers a question about an ABSENCE, and its ``None``
    # branch says "could not be measured". On a rule that did fire there is no
    # absence to qualify, so the note is not merely redundant there — it would
    # report a probe that was never run as a probe that failed. Built here
    # rather than appended unconditionally for exactly that reason.
    absence_note = ""
    if alert_count == 0:
        scope += (
            f"; this tool reads {_DATASET} only, so a rule carried by any other "
            "source reads 0 here whatever it is really doing — that is an absence "
            "of evidence, not evidence of absence"
        )
        # The same distinction, one axis over: a zero earned by excluding an
        # import is also an absence of evidence, and this branch already exists
        # to say so about the dataset scope. Measured only here, where the tool
        # is about to report nothing.
        imported = await count_imports(
            elastic,
            settings.events_index_pattern,
            _rule_disposition_query(rule_name, lookback_days, ANY),
        )
        absence_note = imports_note(imported)
    summary = (
        f"'{rule_name}' fired {alert_count}× in {lookback_days}d{shape_clause} "
        f"({fp} acked-benign / {tp} escalated / {nmi} untriaged){scope} — "
        f"recommendation: {recommendation}" + absence_note
    )

    return {
        "rule_name": rule_name,
        # Machine-readable twin of the scope clause in `summary`, so a consumer
        # that renders fields rather than prose can still tell the reader which
        # dataset this count is a count OF — and, beside it, whose documents.
        "searched_dataset": _DATASET,
        "provenance": provenance,
        "imported_alerts": imported,
        "alert_count": alert_count,
        "fp": fp,
        "tp": tp,
        "nmi": nmi,
        "triaged": triaged,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "observed_span_seconds": (None if span_seconds is None else round(span_seconds, 3)),
        "active_days": active_days,
        "is_burst": shape.is_burst,
        "recommendation": recommendation,
        "reason": reason,
        "summary": summary,
    }
