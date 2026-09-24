"""``rule_prevalence`` tool — base-rate / burstiness oracle for a detection rule.

The investigator (and analyst) constantly need one piece of context the alert
itself never carries: *how often does THIS rule fire across the network?* A rule
that fires thousands of times a day on this network is almost certainly tuned
poorly or matching benign-here traffic — its next hit is weak evidence. A rule
that has NEVER fired before is the opposite: the very first firing is notable and
deserves a closer look. soc-ai was over-trusting rule *labels* (e.g. anchoring on
an ``ET MALWARE …`` signature name) without ever asking whether that signature is
a constant-firing nuisance on this grid. This READ-ONLY, ZERO-EGRESS tool answers
the base-rate question directly from Elasticsearch.

**A rate needs the right denominator.** This tool used to divide the fire count
by the lookback window no matter what the timestamps said. On a lateral-movement
alert it reported 1531 fires as ``51.033/day, occasional`` when every one of
those 1531 fires landed inside a 59-second window, from one source port, in one
TCP session. That is not a background rate off by a rounding error, it is a
different quantity: the answer was wrong by the ratio of the window to the burst,
about 43000 to 1, and the verdict closed a real intrusion as a false positive on
the strength of it. So:

- the rate is computed over the span the fires **actually occupy**, not over the
  lookback window, and
- when the fires occupy only a sliver of the window, or are clumped onto a
  handful of days inside it, **no per-day rate is emitted at all**
  (``fires_per_day`` is ``None``). A per-day rate is not a meaningful quantity
  for an episode, and any number offered in its place invites exactly the
  mistake above.

What it derives for one rule name over a lookback window:

- ``total_fires`` counts the detection docs that matched the rule name.
- ``fires_by_dataset`` / ``searched_datasets`` name which detection sources the
  fires came from, and which ones were looked in. The scope used to be Suricata
  alone and the output did not say so, so a Sigma rule, a Zeek notice or an
  endpoint rule came back ``first-seen`` no matter how often it had fired.
- ``distinct_src_hosts`` / ``distinct_dest_hosts`` / ``distinct_src_ports`` —
  cardinality of the source / destination IPs and source ports the rule fired
  on. A rule firing across the whole network is noise; a rule firing from one
  source port is one session. ``None`` when the matched docs do not carry the
  field: Sigma alerts and Zeek notices keep their addresses elsewhere, and zero
  distinct hosts over hundreds of detections is a missing field, not a count.
- ``first_seen`` / ``last_seen`` / ``observed_span_seconds`` / ``active_days`` /
  ``span_fraction_of_window`` — where in the window the fires actually sit.
- ``is_burst`` / ``burst_fires_per_minute`` — burstiness as a first-class signal.
  A detection that fired 1531 times in 59 seconds and never again is interesting
  in a way a steady 51 a day is not, and the old shape erased exactly that. The
  per-minute figure is reported only when the observed span IS the episode. A
  burst clumped onto a few days of a long span has a span made mostly of
  silence, and 335 fires divided by 25.4 days of it read 0.01 a minute under a
  name that says burst; there is no sub-day timing in a day histogram to put in
  its place, so ``fires_per_active_day`` carries the magnitude instead.
- ``fires_per_day`` — fires per day **over the observed span**, or ``None`` when
  the span will not support one. ``rate_basis`` names the denominator that was
  used, or is ``None`` when no rate is reported.
- ``fires_per_active_day`` counts fires per day **over the days the rule
  actually fired on**, a different number whenever the rule was quiet on some
  of the days its span covers. 438 fires across 17 of the 30 days they span is
  14.6/day over the span and 25.765/day on the days it fired; both are true,
  and each is reported under the denominator that produced it. The summary used
  to print the span figure under the words "while active", which named the
  wrong denominator on a real number.
- ``noisiness`` — a coarse bucket (``noisy`` / ``occasional`` / ``rare`` /
  ``burst`` / ``first-seen``): a *noisy* rule firing again is weak evidence; a
  *first-seen*, *rare* or *burst* rule firing is notable.
- ``summary`` — a one-line gloss that says what was actually seen, in the shape
  "1531 fires in 59s on one day, from one source port, nothing before or after".

**And the right population.** The same sentence applies to the numerator: a
base rate over a grid's whole disk is a base rate of whatever was loaded onto
it. Security Onion's ``so-import-pcap`` / ``so-import-evtx`` and a replayed
corpus land alongside live telemetry and fire the same rules, so an imported
capture full of one signature made that signature read ``noisy`` — background
nuisance, weak evidence — on a network where it had never fired at all. Which
inverts the tool: ``noisy`` is the bucket that tells a reader to discount the
next firing. So the query counts live telemetry only
(:mod:`soc_ai.tools._provenance`), ``provenance`` says which population the
counts came from, and a caller measuring an import on purpose passes
``provenance="any"``.

Robustness contract (mirrors ``host_summary`` and the other read tools):

- **Empty data** → a clean ``{"observed": False, "noisiness": "first-seen", …}``
  result (absence is a real answer: this rule has not fired in the window — its
  next firing is notable), NEVER an exception. The summary names the datasets
  that were searched, because "first-seen" reads as a claim about the network
  and is only ever a claim about where the query looked.
- **ES error / bad input** → a clean ``{"error": True, "message": …}`` dict,
  NEVER a raised exception (the agent reads the dict and moves on).
- The rule-name field is resolved **ECS-first** (``rule.name`` → ``rule.rule`` →
  ``signature`` → ``notice.note``) so the same rule resolves whether the grid
  populates the modern ECS ``rule.name``, the legacy Suricata ``signature``
  field, or Zeek's ``notice.note``.
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
from soc_ai.tools._synth_scope import SynthScope, synth_scope_must_not

_LOGGER = logging.getLogger(__name__)

# Rule-name field candidates, ECS-first. Modern SO/Elastic-Agent populates
# ``rule.name``; ``rule.rule`` carries the full Suricata rule text on some
# deployments; ``signature`` is the legacy Suricata field name. We match the rule
# across ALL of these so one signature resolves regardless of schema. ``.keyword``
# multi-fields are appended so the term match works on analysed text mappings too.
_RULE_NAME_FIELDS: tuple[str, ...] = ("rule.name", "rule.rule", "signature", "notice.note")

# Every dataset that carries a detection, which is every dataset a rule name can
# be looked up in. Mirrors the detector-dataset set the hunt routes already use,
# plus the Elastic Defend alert stream.
#
# This used to be ``suricata.alert`` alone, on the reasoning that Zeek and Sigma
# have their own cadence and one source keeps the number interpretable. The
# scope was defensible; reporting it was not. Any Sigma rule, Zeek notice or
# endpoint rule came back ``observed: false, total_fires: 0, noisiness:
# "first-seen"``: a statement about the network, made about a rule the query
# could not even see. The grading oracle caught it on a rule the grid showed firing
# 25 times, and the reading a model takes from "first-seen" is the opposite of
# the truth.
#
# So the query looks where detections actually live, and comparability is
# handled by naming the source rather than by narrowing the search: the rule
# name is the join key and in practice belongs to one engine, ``fires_by_dataset``
# breaks the total down whenever it does not, and the summary says so.
# ``windows.sysmon_operational`` populates ``rule.name`` too, but that is
# Sysmon's operator-supplied config tag rather than a detection, which is why
# this stays an allowlist instead of dropping the dataset filter.
_DETECTION_DATASETS: tuple[str, ...] = (
    "suricata.alert",
    "sigma.alert",
    "zeek.notice",
    "endpoint.alerts",
)

# noisiness thresholds, in fires-per-day. Deliberately coarse — this is a hint to
# weight the evidence, not a verdict. A rule firing tens of times a day across
# the network is background noise here; a rule firing a handful of times is
# occasional; less than ~once a day is rare; zero is the special "first-seen"
# bucket (its very next firing is the notable one). They were set against IDS
# alert volume, so the summary names the detection source the count came from
# and a reader can weight the bucket against that engine's cadence.
_NOISY_PER_DAY = 10.0
_OCCASIONAL_PER_DAY = 1.0
# "Noisy" also requires broad host-spread, not just a high rate — a high rate at
# a single host pair is focused, not background nuisance.
_NOISY_MIN_HOSTS = 5

# Whether a per-day rate is meaningful at all is decided by
# :mod:`soc_ai.tools._burstiness`, shared with ``suggest_rule_tuning`` because
# both tools were built on the same assumption that a rule's fires are spread
# through the window they are measured over.

# Cap the caller-supplied lookback window. Alert-embedded text is in-scope
# prompt-injection surface, so an unbounded lookback_days lets the agent turn a
# rarity check into a full-history ES scan (track_total_hits + two cardinality
# aggs) against the same live SO grid production hunting depends on. 365d is
# ample for a base-rate signal and mirrors the sibling read tools' ceilings.
_MAX_LOOKBACK_DAYS = 365


def _rule_match_query(
    rule_name: str,
    lookback_days: int,
    include_synth: SynthScope = False,
    provenance: Provenance = LIVE,
) -> dict[str, Any]:
    """Match detection docs whose rule name equals ``rule_name``.

    The rule-name match is an OR across every ECS/legacy candidate field (and
    their ``.keyword`` sub-fields) so the same signature resolves whatever the
    grid populated. Synthetic-eval fixtures are excluded — a synth scenario must
    never inflate a real rule's base rate — and so, by default, is backfill,
    for exactly the same reason with a much larger number behind it.
    """
    # match_phrase on rule.name (the real, populated field) mirrors the alert
    # resolver in routes.py — `term` silently returns 0 on a text-analyzed
    # mapping, which would misreport a noisy rule as first-seen. The legacy
    # fields are speculative no-match fallbacks. notice.note is where Zeek puts
    # a notice's identity; nothing else populates it, so it cannot cross-match.
    should: list[dict[str, Any]] = [{"match_phrase": {"rule.name": rule_name}}]
    for field_name in ("rule.rule", "signature", "notice.note"):
        should.append({"term": {field_name: rule_name}})
    return {
        "bool": {
            "must": [
                {"terms": {"event.dataset": list(_DETECTION_DATASETS)}},
                {"bool": {"should": should, "minimum_should_match": 1}},
            ],
            "filter": [
                {"range": {"@timestamp": {"gte": f"now-{lookback_days}d", "lte": "now"}}},
            ],
            # Synth scope, threaded: prod keeps a real base rate clean of plants;
            # a batch eval scopes to its own scenario so a run measures a rule's
            # prevalence including the plants it is graded on. Provenance scope
            # beside it: a rule's firing rate ON THIS NETWORK cannot be measured
            # over documents this network never produced.
            "must_not": [
                *synth_scope_must_not(include_synth),
                *provenance_must_not(provenance),
            ],
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


def _measured_cardinality(agg: dict[str, Any] | None, total_fires: int) -> int | None:
    """A cardinality that is zero over matched docs means the field is absent.

    Sigma alerts and Zeek notices carry their addresses somewhere other than
    ``source.ip`` / ``destination.ip``, so the aggregation returns 0 across
    hundreds of real detections. Reporting that as "0 source hosts" states
    something about the network that the query never measured. ``None`` says
    what actually happened: nothing was measured.
    """
    value = _agg_value(agg)
    if value is None or (value == 0 and total_fires > 0):
        return None
    return value


def _spread_phrase(src: int | None, dest: int | None, ports: int | None) -> str:
    """The concentration clause: how many hosts and ports the fires came from."""
    parts = []
    if src is not None:
        parts.append(burst.plural(src, "source host"))
    if dest is not None:
        parts.append(burst.plural(dest, "dest host"))
    if ports is not None:
        parts.append(burst.plural(ports, "source port"))
    if not parts:
        return "docs that carry no source or destination address"
    return " / ".join(parts)


def _classify_noisiness(
    *,
    total_fires: int,
    fires_per_day: float | None,
    window_average_per_day: float,
    distinct_hosts: int | None,
    is_burst: bool,
) -> str:
    """Bucket a rule by how often, how broadly AND how evenly it fires.

    ``first-seen`` is reserved for a rule that has NOT fired in the window — its
    next firing is the notable one. ``burst`` means the fires are one or two
    episodes rather than a rate at all. ``noisy`` (background nuisance — a firing
    is weak evidence) needs three things to agree: a high rate while the rule was
    active, a high average across the whole window, and broad host-spread. Any
    one of those alone is a way to be wrong. Requiring the window average as well
    as the span rate is what stops the fix inverting the bug: 12 fires in six
    hours is 48/day while active but 0.4/day across a 30-day window, and calling
    that background noise would be the same error pointing the other way.

    ``distinct_hosts`` of ``None`` means the matched docs do not carry addresses,
    so the spread test cannot run. It is withheld rather than assumed either way:
    a rule is not promoted to ``noisy`` on an untested condition, because
    ``noisy`` is the bucket that tells a reader a firing is weak evidence. The
    summary says the test could not be applied, so the caller can see that the
    bucket is the conservative one rather than a measurement.
    """
    if total_fires <= 0:
        return "first-seen"
    if is_burst:
        return "burst"
    if fires_per_day is None:
        # No usable span. Fall back to volume over the window, which can only
        # ever justify the two quiet buckets at this point.
        return "occasional" if window_average_per_day >= _OCCASIONAL_PER_DAY else "rare"
    if (
        fires_per_day >= _NOISY_PER_DAY
        and window_average_per_day >= _NOISY_PER_DAY
        and distinct_hosts is not None
        and distinct_hosts >= _NOISY_MIN_HOSTS
    ):
        return "noisy"
    if fires_per_day >= _OCCASIONAL_PER_DAY and window_average_per_day >= _OCCASIONAL_PER_DAY:
        return "occasional"
    return "rare"


def _fires_by_dataset(agg: Any) -> dict[str, int]:
    """Read the ``by_dataset`` terms aggregation into ``{dataset: fires}``."""
    if not isinstance(agg, dict):
        return {}
    buckets = agg.get("buckets")
    if not isinstance(buckets, list):
        return {}
    out: dict[str, int] = {}
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        key = bucket.get("key")
        count = bucket.get("doc_count")
        if isinstance(key, str) and isinstance(count, int):
            out[key] = count
    return out


def _source_clause(fires_by_dataset: dict[str, int], provenance: Provenance) -> str:
    """Name the detection source(s) and the population the count came from.

    One source is the ordinary case and only needs naming, so a reader knows
    which engine's cadence the noisiness bucket is describing. More than one
    means the same name resolved on two engines and the total pools counts
    that do not measure the same thing, which the sentence has to say outright.

    The population rides here because this is the one clause every branch of
    :func:`_summarize` already prints. It is unconditional even when the dataset
    breakdown is missing: a degraded aggregation costs the reader the source
    name, and it must not also quietly cost them the denominator.
    """
    scope = denominator_note(provenance)
    if not fires_by_dataset:
        return f", counted over {scope}"
    names = sorted(fires_by_dataset)
    if len(names) == 1:
        return f", seen in {names[0]} ({scope})"
    parts = ", ".join(f"{name} {fires_by_dataset[name]}x" for name in names)
    return (
        f", split across {parts} ({scope}) - separate detection sources whose firing "
        f"rates are not comparable, so read the split rather than the total"
    )


def _empty_result(
    rule_name: str, lookback_days: int, provenance: Provenance, imported: int | None
) -> dict[str, Any]:
    """The clean no-data result — absence is a real, useful answer.

    A rule that has not fired in the lookback window is ``first-seen``: its very
    next firing is notable, which is exactly the signal the caller wants. The
    sentence names the datasets that were searched, because "first-seen" reads
    as a claim about the network and it is only a claim about those.

    It now names the population for the same reason, and ``imported`` carries
    what the population excluded. "Has not fired here" and "has fired 8,000
    times, every one of them inside an imported capture" are opposite readings
    of the same empty result set, and the second one is not a first-seen.
    """
    searched = ", ".join(_DETECTION_DATASETS)
    return {
        "rule_name": rule_name,
        "observed": False,
        "lookback_days": lookback_days,
        "total_fires": 0,
        "distinct_src_hosts": 0,
        "distinct_dest_hosts": 0,
        "distinct_src_ports": 0,
        "first_seen": None,
        "last_seen": None,
        "observed_span_seconds": None,
        "active_days": 0,
        "span_fraction_of_window": None,
        "is_burst": False,
        "burst_fires_per_minute": None,
        "fires_per_day": None,
        "fires_per_active_day": None,
        "rate_basis": None,
        "fires_by_dataset": {},
        "searched_datasets": list(_DETECTION_DATASETS),
        "provenance": provenance,
        "imported_fires": imported,
        "noisiness": "first-seen",
        "summary": (
            f"'{rule_name}' has not fired in the last {lookback_days}d in the detection "
            f"data this tool reads ({searched}, {denominator_note(provenance)}) - a firing "
            f"now is notable (first-seen in window). If this rule is carried by some other "
            f"source, the tool did not look there and this says nothing about it."
            + imports_note(imported)
        ),
    }


@tool(
    read_only=True,
    description=(
        "Base-rate / burstiness of a detection rule across the network, over"
        " every dataset that carries detections (Suricata, Sigma, Zeek notices,"
        " endpoint alerts):"
        " is it noisy (fires constantly -> a firing is weak evidence here),"
        " rare/first-seen (a firing is notable), or a burst (all its fires sit in"
        " one short episode, so it has no per-day rate)? Returns total_fires,"
        " distinct src/dest hosts and source ports, first/last seen, the observed"
        " span, active_days, is_burst, fires_per_day over the observed span (null"
        " for a burst), and fires_per_active_day over the days it actually fired."
    ),
)
async def rule_prevalence(
    rule_name: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    lookback_days: int = 30,
    include_synth: SynthScope = False,
    provenance: Provenance = LIVE,
) -> dict[str, Any]:
    """How prevalent is a detection rule across the network over a lookback window?

    Answers: is this rule *noisy* (fires constantly across many hosts → its next
    firing is likely benign HERE and weak evidence), *rare / first-seen* (a firing
    is notable), or a *burst* (every fire inside one short episode, which is not a
    rate at all and often IS the incident)? This is the base-rate context the
    alert itself never carries — weigh it BEFORE trusting a rule label as a
    verdict driver, and read ``summary``, not a single number, as the headline.

    ``fires_per_day`` is normalised over the span the fires actually occupy, and
    is ``None`` whenever that span is too small a fraction of the window, or too
    few days inside it, for a per-day figure to mean anything.
    ``fires_per_active_day`` is the same count over the days the rule fired on,
    which is a larger number whenever the rule was quiet inside its span. Both
    are reported, each named for its own denominator.

    The query covers every dataset that carries detections, and
    ``searched_datasets`` says which. ``fires_by_dataset`` breaks the total down
    by source: a rule name normally belongs to one engine, and when it does not,
    the summary says the total pools sources whose firing rates are not
    comparable.

    READ-ONLY and ZERO-EGRESS: a single aggregation query against the Security
    Onion events index. It never raises — the caller is an LLM tool boundary.

    Args:
        rule_name: the exact detection-rule / signature name to look up (the
            value carried on the alert's ``rule.name`` / ``signature`` field).
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        lookback_days: window size in days. Default 30.
        include_synth: synth-doc visibility (``SynthScope``).
        provenance: which population the base rate is measured over
            (:mod:`soc_ai.tools._provenance`). ``"live"`` (the default) counts
            only what this grid's own sensors detected, because "how often does
            this rule fire HERE" is a question about this network. ``"any"``
            counts imported captures and replayed corpora too — for measuring
            what an import contains, on purpose.

    Returns:
        A dict with ``observed`` / ``total_fires`` / ``distinct_src_hosts`` /
        ``distinct_dest_hosts`` / ``distinct_src_ports`` (each ``None`` when the
        matched docs do not carry that field) / ``first_seen`` /
        ``last_seen`` / ``observed_span_seconds`` / ``active_days`` /
        ``span_fraction_of_window`` / ``is_burst`` / ``burst_fires_per_minute`` /
        ``fires_per_day`` (may be ``None``) / ``fires_per_active_day`` (may be
        ``None``) / ``rate_basis`` / ``fires_by_dataset`` / ``searched_datasets``
        / ``provenance`` (the population every count above was drawn from)
        / ``noisiness``
        (``noisy`` | ``occasional`` | ``rare`` | ``burst`` | ``first-seen``) /
        ``summary``. On no data: a clean ``observed: False``,
        ``noisiness: 'first-seen'`` result (absence is a real answer) carrying
        ``imported_fires`` — how many firings the live scope held back, so a
        first-seen earned by hiding an import cannot pass for a quiet rule.
        ``None`` there means the volume could not be measured, which is not the
        same as none. On an ES error or bad input: a clean
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
            "message": (f"lookback_days must be <= {_MAX_LOOKBACK_DAYS}, got {lookback_days}"),
        }

    index = settings.events_index_pattern
    query = _rule_match_query(rule_name, lookback_days, include_synth, provenance)

    # cardinality aggs give distinct source/dest host and source-port counts in
    # one round trip; min/max give the active span; the day histogram tells a
    # burst apart from a background rate. size=0 — we never need the docs
    # themselves, only the volume + spread + shape numbers, which keeps the
    # next-turn context tiny.
    aggs: dict[str, Any] = {
        "distinct_src_hosts": {"cardinality": {"field": "source.ip"}},
        "distinct_dest_hosts": {"cardinality": {"field": "destination.ip"}},
        "distinct_src_ports": {"cardinality": {"field": "source.port"}},
        "first_seen": {"min": {"field": "@timestamp"}},
        "last_seen": {"max": {"field": "@timestamp"}},
        "by_day": {
            "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "day",
                "min_doc_count": 1,
            }
        },
        # Which detection sources the fires came from. Bounded by the allowlist,
        # so it cannot truncate and its counts always sum to the total.
        "by_dataset": {"terms": {"field": "event.dataset", "size": len(_DETECTION_DATASETS)}},
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
        # "first-seen" is the loudest thing this tool says — it tells the reader
        # the next firing is the notable one. Earned by excluding an import, it
        # says the opposite of the truth, so the volume that was excluded gets
        # measured before the claim is made. ``ANY`` reproduces the query above
        # without its provenance clauses, which is exactly the population the
        # probe has to ask about; building it any other way would let the two
        # drift and the number would stop being about this rule.
        imported = await count_imports(
            elastic, index, _rule_match_query(rule_name, lookback_days, include_synth, ANY)
        )
        return _empty_result(rule_name, lookback_days, provenance, imported)

    aggregations = result.aggregations or {}
    distinct_src = _measured_cardinality(aggregations.get("distinct_src_hosts"), total_fires)
    distinct_dest = _measured_cardinality(aggregations.get("distinct_dest_hosts"), total_fires)
    distinct_ports = _measured_cardinality(aggregations.get("distinct_src_ports"), total_fires)
    first_seen = burst.agg_time(aggregations.get("first_seen"))
    last_seen = burst.agg_time(aggregations.get("last_seen"))

    active_days = burst.active_days_from(aggregations.get("by_day"))
    fires_by_dataset = _fires_by_dataset(aggregations.get("by_dataset"))

    # The span the fires ACTUALLY occupy. None when the timestamps are missing —
    # unknown is not the same as bursty, and we say so rather than guess.
    first_epoch = burst.agg_epoch_seconds(aggregations.get("first_seen"))
    last_epoch = burst.agg_epoch_seconds(aggregations.get("last_seen"))
    span_seconds: float | None = None
    if first_epoch is not None and last_epoch is not None:
        span_seconds = max(0.0, last_epoch - first_epoch)

    # Burstiness is a signal in its own right: a rule that fired 1531 times in 59
    # seconds and never again is interesting in a way a steady 51 a day is not.
    shape = burst.measure(
        total=total_fires,
        span_seconds=span_seconds,
        active_days=active_days,
        lookback_days=lookback_days,
    )
    is_burst = shape.is_burst

    # The lookback-normalised average. Kept as a FLOOR on the noisy/occasional
    # buckets and never reported: this is precisely the number that fabricated
    # "51.033/day" out of a 59-second burst.
    window_average_per_day = total_fires / lookback_days

    fires_per_day: float | None = None
    rate_basis: str | None = None
    if shape.rate_is_meaningful and span_seconds:
        fires_per_day = round(total_fires / (span_seconds / burst.SECONDS_PER_DAY), 3)
        rate_basis = "observed_span"

    # The other real rate: fires per day ON THE DAYS THE RULE FIRED. It differs
    # from the span rate by exactly the quiet days inside the span, and it is
    # the quantity the summary used to print the span figure under. Reported as
    # its own field so neither number has to carry the other's name.
    fires_per_active_day: float | None = None
    if active_days:
        fires_per_active_day = round(total_fires / active_days, 3)

    # The burst's own intensity, and only when the span IS the burst. A burst
    # that clumps onto a few days of a long span has a span made mostly of
    # silence, and dividing by it is the same window-over-burst error the daily
    # rate was carrying: 335 fires on 4 days of 25.4 came out as 0.01 a minute.
    # The day histogram cannot see how long each episode lasted, so nothing is
    # offered in its place and fires_per_active_day carries the magnitude.
    burst_fires_per_minute: float | None = None
    if is_burst and span_seconds and shape.fires_fill_span:
        burst_fires_per_minute = round(total_fires / (span_seconds / 60.0), 2)

    noisiness = _classify_noisiness(
        total_fires=total_fires,
        fires_per_day=fires_per_day,
        window_average_per_day=window_average_per_day,
        distinct_hosts=(
            None
            if distinct_src is None and distinct_dest is None
            else max(distinct_src or 0, distinct_dest or 0)
        ),
        is_burst=is_burst,
    )

    summary = _summarize(
        rule_name=rule_name,
        lookback_days=lookback_days,
        total_fires=total_fires,
        distinct_src=distinct_src,
        distinct_dest=distinct_dest,
        distinct_ports=distinct_ports,
        first_seen=first_seen,
        last_seen=last_seen,
        span_seconds=span_seconds,
        active_days=active_days,
        is_burst=is_burst,
        fires_per_day=fires_per_day,
        fires_per_active_day=fires_per_active_day,
        fires_by_dataset=fires_by_dataset,
        noisiness=noisiness,
        provenance=provenance,
    )

    return {
        "rule_name": rule_name,
        "observed": True,
        "lookback_days": lookback_days,
        "total_fires": total_fires,
        "distinct_src_hosts": distinct_src,
        "distinct_dest_hosts": distinct_dest,
        "distinct_src_ports": distinct_ports,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "observed_span_seconds": (None if span_seconds is None else round(span_seconds, 3)),
        "active_days": active_days,
        "span_fraction_of_window": (
            None if shape.span_fraction is None else round(shape.span_fraction, 6)
        ),
        "is_burst": is_burst,
        "burst_fires_per_minute": burst_fires_per_minute,
        "fires_per_day": fires_per_day,
        "fires_per_active_day": fires_per_active_day,
        "rate_basis": rate_basis,
        "fires_by_dataset": fires_by_dataset,
        "searched_datasets": list(_DETECTION_DATASETS),
        # Beside ``searched_datasets`` deliberately: that field answers "where
        # did you look", this one answers "whose documents did you count", and
        # a base rate is unreadable without both.
        "provenance": provenance,
        "noisiness": noisiness,
        "summary": summary,
    }


def _summarize(
    *,
    rule_name: str,
    lookback_days: int,
    total_fires: int,
    distinct_src: int | None,
    distinct_dest: int | None,
    distinct_ports: int | None,
    first_seen: str | None,
    last_seen: str | None,
    span_seconds: float | None,
    active_days: int | None,
    is_burst: bool,
    fires_per_day: float | None,
    fires_per_active_day: float | None,
    fires_by_dataset: dict[str, int],
    noisiness: str,
    provenance: Provenance,
) -> str:
    """The one line the model reads. It says what was actually seen.

    The verdict this tool broke would have flipped on a sentence of the shape
    "1531 fires in 59s on one day, from one source port, nothing before or
    after" — so that is the sentence, and the arithmetic that is not supportable
    is named as absent rather than quietly filled in.

    Every rate in the sentence carries the denominator it was divided by. The
    span rate and the active-day rate are different numbers whenever the rule
    was quiet on some of the days its span covers, and the sentence used to
    print the first under the name of the second. The detection source is named
    for the same reason: the noisiness buckets were set against IDS volume, and
    a reader has to know which engine's cadence produced the number. The
    POPULATION is the third denominator on the same footing, and the last one to
    get named — a fire count is a count of documents somebody's sensors wrote,
    and until this clause existed the sentence never said whose.
    """
    spread = _spread_phrase(distinct_src, distinct_dest, distinct_ports)
    active = None if active_days is None else burst.plural(active_days, "active day")
    source = _source_clause(fires_by_dataset, provenance)
    # The noisy bucket needs host spread. When the docs do not carry addresses
    # the test cannot run, so the sentence says which condition went untested
    # rather than letting the bucket read as a measurement.
    untested = (
        distinct_src is None
        and distinct_dest is None
        and fires_per_day is not None
        and fires_per_day >= _NOISY_PER_DAY
    )
    spread_note = (
        " (host spread is not carried on these docs, so the noisy test could not be applied)"
        if untested
        else ""
    )

    if is_burst and span_seconds is not None:
        span = burst.span_phrase(span_seconds)
        if active_days is not None and active_days <= 1:
            day = (first_seen or "")[:10]
            on_day = f" on {day}" if day else ""
            return (
                f"'{rule_name}' fired {total_fires}x in {span}{on_day} - one burst, "
                f"{active} of the {lookback_days}d window, from {spread}{source}, and nothing "
                f"before or after it. That is a single episode, not a background rate, "
                f"so no per-day rate is reported."
            )
        clumped = f" clumped into {active}" if active else ""
        # The span here is mostly the silence between episodes, so it is the
        # denominator for neither a per-day nor a per-minute figure. The days
        # the rule fired on are a real denominator, and they carry the size.
        on_days = (
            ""
            if fires_per_active_day is None
            else f", about {fires_per_active_day}/day on the days it fired"
        )
        return (
            f"'{rule_name}' fired {total_fires}x in the last {lookback_days}d,{clumped} "
            f"spanning {span} ({first_seen} to {last_seen}), from {spread}{source}{on_days}. "
            f"bursty, not a background rate: no per-day rate is reported, and most of that "
            f"span is silence rather than firing, so no per-minute burst rate either."
        )

    if total_fires == 1:
        return (
            f"'{rule_name}' fired once, at {first_seen}, in the last {lookback_days}d, "
            f"from {spread}{source} - {noisiness}. A single fire has no rate."
        )

    if fires_per_day is None:
        if span_seconds is None:
            return (
                f"'{rule_name}' fired {total_fires}x in the last {lookback_days}d{source}, but "
                f"the observed span is unknown, so no per-day rate is reported - {noisiness}"
            )
        return (
            f"'{rule_name}' fired {total_fires}x in the last {lookback_days}d{source}, all "
            f"within an observed span of {burst.span_phrase(span_seconds)}, too short to support "
            f"a per-day rate - {noisiness}"
        )

    span_clause = "" if span_seconds is None else f" over {burst.span_phrase(span_seconds)}"
    active_clause = f" ({active})" if active else ""
    # Two denominators, each named. The second clause is dropped when the rule
    # fired on every day it spans, because then it is the same number twice.
    rate_clause = f"about {fires_per_day}/day across that span"
    if fires_per_active_day is not None and fires_per_active_day != fires_per_day:
        on_days = "the day it fired" if active_days == 1 else f"the {active_days} days it fired"
        rate_clause += f", {fires_per_active_day}/day on {on_days}"
    return (
        f"'{rule_name}' fired {total_fires}x{span_clause}{active_clause} in the last "
        f"{lookback_days}d - {rate_clause} - from {spread}{source} - {noisiness}"
        f"{spread_note}"
    )
