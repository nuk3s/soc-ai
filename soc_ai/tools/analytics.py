"""Deterministic behavioral analytics for the hunt agent.

The hunt agent's evidence problem is different from triage's: triage pivots
around ONE alert; a hunt has to sweep an entire grid for a pattern with no
seed indicator. Eyeballing raw event rows doesn't scale to that, and it
tempts the model into asserting a pattern ("this looks periodic") it never
actually measured. This module's tools instead run a bounded aggregation,
compute the statistic in Python, and hand the agent a small, CITABLE
candidate set — the LLM reasons over the measured candidates, never the
underlying rows.

All tools here issue **raw structured Elasticsearch DSL**, not OQL — OQL is
the trust boundary for MODEL-AUTHORED query strings (alert-embedded text is
prompt-injection surface); these tools' query shapes are fixed by the
implementation, so there is nothing for OQL to gate. Every query threads a
:data:`~soc_ai.tools._synth_scope.SynthScope` (``include_synth``) through
:func:`_hunt_must_not`: ``False`` (the prod default) excludes all planted
eval docs so fixtures never leak into a hunt's findings, ``True`` (the
hunt-journey eval) sees every plant, and a scenario id (the batch eval) sees
only THAT scenario's plants — the same contract as every other events reader
(:func:`soc_ai.tools.query_events.query_events_oql`). Every tool self-bounds
its output (top-N) and returns a structured ``{"error": True, ...}`` dict
rather than raising, matching the rest of the read-tool surface (see
:mod:`soc_ai.tools.prevalence`, :mod:`soc_ai.tools.discover`).

This module also holds the family's shared statistics helpers, starting with
:func:`_shannon_entropy_chars` (char-level Shannon entropy).

Task 1 shipped :func:`_shannon_entropy_chars` and :func:`beacon_profile` (an
inter-arrival coefficient-of-variation sweep over ``zeek.conn``). Task 2 added
:func:`dns_entropy_scan` (a qname-entropy/volume sweep over ``zeek.dns`` for
DGA/tunnel candidates), reusing the same shared entropy helper. Task 3 added
:func:`dcerpc_histogram` (an operation histogram over ``zeek.dce_rpc`` that
flags individually-dangerous and rare-against-a-busy-baseline operations).
Task 4 adds :func:`first_seen` (a novel-external-destination sweep: recent
window vs a trailing baseline, generalizing :mod:`soc_ai.tools.prevalence`'s
single-indicator oracle to a bounded candidate set).
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client import fields
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import resolve_agg_field
from soc_ai.tools._registry import tool
from soc_ai.tools._synth_scope import SynthScope, synth_scope_must_not
from soc_ai.tools.online import is_internal_ip
from soc_ai.tools.pcap_decode import _compute_inter_arrival
from soc_ai.tools.query_events import _MAX_TIME_RANGE_MINUTES, _build_time_filter

_LOGGER = logging.getLogger(__name__)

# beacon_profile candidacy thresholds. A pair must clear min_events (the
# caller's floor, default 8) AND have cv <= _CV_MAX to be considered a
# cadence candidate at all; within that, cv <= _CV_PERIODIC earns the
# stronger "periodic" hint over "semi-regular". These mirror the
# evidence.py conventions (beacon interval similarity >= 0.75 / byte-cv
# <= 0.15) at the coarser tool-output granularity this sweep produces.
_CV_MAX = 0.4
_CV_PERIODIC = 0.15
# The default per-pair sample floor (the `min_events` arg): fewer raw
# timestamps than this make cv meaningless. A named constant rather than a
# bare signature default because the confidence floor-raise's beacon-profile
# ground (soc_ai.agent.gates) derives its "decisive" bar from THIS module's
# thresholds — the tool and the gate must never disagree on what counts as a
# measured periodic beacon.
_MIN_EVENTS_DEFAULT = 8

# Cap on how many candidate pairs the terms aggs walk (bounded ES cost) and
# how many top_hits raw timestamps are pulled per pair (bounded payload —
# 100 timestamps is comfortably enough to measure cadence over a day window
# without hauling the whole bucket's docs back).
_SRC_TERMS_SIZE = 20
_DST_TERMS_SIZE = 10
_TOP_HITS_SIZE = 100

# How many of a candidate pair's top_hits ids ride along as citable evidence.
_MAX_SAMPLE_IDS = 3

# Top-N candidates returned in `items`, sorted by cv ascending (strongest
# cadence first) — keeps the result self-bounded and clamp-friendly.
_MAX_ITEMS = 10


def _shannon_entropy_chars(s: str) -> float:
    """Char-level Shannon entropy (bits/char).

    The string twin of :func:`soc_ai.tools.decode_payload._entropy_bits_per_byte`,
    which is byte-oriented; this operates on a ``str`` (e.g. a DNS label) via a
    ``Counter`` over characters rather than raw bytes.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _parse_epoch(value: Any) -> float | None:
    """Parse an ES ``@timestamp`` ISO string to an epoch float.

    Handles a trailing ``Z`` (UTC designator) that pre-3.11-style ISO strings
    use. Returns ``None`` on anything malformed so the caller can drop the
    sample rather than crash the sweep on one bad doc.
    """
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _window_error(name: str, value: int, ceiling: int) -> dict[str, Any] | None:
    """Validate a window-size arg; return a structured error dict, or ``None`` if in-bounds.

    Shared by all four tools' window-clamp blocks (``window_minutes`` in
    three of them, plus ``first_seen``'s ``recent_minutes`` AND
    ``baseline_days`` — hence ``ceiling`` is a parameter rather than a
    module constant, since ``baseline_days`` checks against
    ``_MAX_BASELINE_DAYS`` while everything else checks against
    ``_MAX_TIME_RANGE_MINUTES``). Deliberately does NOT include a ``type``
    key — this is an argument-validation error raised before any query
    runs, not a caught exception (see :func:`beacon_profile`'s ``except
    Exception`` block for that shape) — matching the pre-existing
    bounds-error contract every tool here already returned before this
    helper existed.

    Callers use the walrus-guard idiom::

        if (
            err := _window_error("window_minutes", window_minutes, _MAX_TIME_RANGE_MINUTES)
        ) is not None:
            return err
    """
    if value <= 0:
        return {"error": True, "message": f"{name} must be positive, got {value}"}
    if value > ceiling:
        return {"error": True, "message": f"{name} must be <= {ceiling}, got {value}"}
    return None


# Non-globally-routable destination ranges excluded SERVER-SIDE (ES `ip`
# fields accept CIDR values in term/terms queries) so internal chatter never
# occupies terms-agg bucket slots or top_hits payload in the first place —
# the whole point of beacon_profile/first_seen is EXTERNAL candidates, and
# filtering client-side after the fan-out both hauls thousands of internal
# docs back and lets internal pairs crowd external ones out of the capped
# aggs. Mirrors the ranges `ipaddress.is_global` rejects (RFC1918, loopback,
# link-local, CGNAT, benchmarking, multicast, reserved, plus the IPv6 ULA and
# link-local blocks); :func:`soc_ai.tools.online.is_internal_ip` stays as the
# belt-and-braces client-side check for anything this list misses (e.g.
# TEST-NET/documentation ranges, unparseable keys).
_NON_GLOBAL_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "fc00::/7",
    "fe80::/10",
)


def _internal_dest_exclusion(settings: Settings) -> dict[str, Any]:
    """Build a ``must_not`` clause excluding internal ``destination.ip`` in ES.

    Combines the fixed non-global ranges (:data:`_NON_GLOBAL_CIDRS`) with the
    operator-configured ``settings.internal_cidrs`` (internal-but-globally-
    routable space), deduplicated preserving order — the settings default
    duplicates the RFC1918 blocks. Returned as ONE ``terms`` clause (ES
    treats each CIDR value as its own range match on an ``ip`` field), ready
    to append to a query's ``must_not`` list.
    """
    cidrs = list(_NON_GLOBAL_CIDRS)
    for net in settings.internal_cidrs:
        cidr = str(net)
        if cidr not in cidrs:
            cidrs.append(cidr)
    return {"terms": {"destination.ip": cidrs}}


def _hunt_must_not(
    settings: Settings, *, exclude_internal_dest: bool, include_synth: SynthScope = False
) -> list[dict[str, Any]]:
    """The shared ``must_not`` clause set for this module's queries.

    ``include_synth`` is a :data:`~soc_ai.tools._synth_scope.SynthScope`,
    built into clauses by :func:`~soc_ai.tools._synth_scope.synth_scope_must_not`
    — the same single decision point every other events reader uses: ``False``
    (the prod default) excludes ALL planted eval docs so fixtures never leak
    into a hunt's findings; ``True`` (the hunt-journey eval) excludes none; a
    scenario id (the batch eval) excludes every OTHER scenario's plants, so a
    scoped sweep sees its own plants and never a sibling's. With
    ``exclude_internal_dest`` it also carries the server-side
    internal-destination CIDR exclusion (:func:`_internal_dest_exclusion`).
    """
    must_not: list[dict[str, Any]] = list(synth_scope_must_not(include_synth))
    if exclude_internal_dest:
        must_not.append(_internal_dest_exclusion(settings))
    return must_not


def _sample_ids(hits: list[dict[str, Any]], cap: int) -> list[str]:
    """Extract ES ``_id``s from a list of raw ``top_hits`` hit dicts.

    Shared by all four tools' sample-id extraction — every ``top_hits``
    sub-agg here returns the same ``{"_id": ..., "_source": {...}}`` hit
    shape, and every tool caps + dedups the resulting id list the same
    way before handing it back as a candidate's citable evidence.
    Dedup-preserving-order (first occurrence wins) then capped at ``cap``;
    a hit missing ``_id`` is skipped rather than raising or contributing a
    ``"None"`` string.
    """
    out: list[str] = []
    for hit in hits:
        hit_id = hit.get("_id")
        if hit_id is None:
            continue
        hit_id = str(hit_id)
        if hit_id in out:
            continue
        out.append(hit_id)
        if len(out) >= cap:
            break
    return out


def _beacon_summary(
    candidates: list[dict[str, Any]],
    items: list[dict[str, Any]],
    *,
    pairs_scanned: int,
    internal_excluded: int,
) -> str:
    external_pairs = pairs_scanned - internal_excluded
    if not items:
        return (
            f"No periodic or semi-regular cadence found across {external_pairs} "
            f"external pair(s) scanned ({pairs_scanned} pair(s) total, "
            f"{internal_excluded} internal excluded)."
        )
    strongest = items[0]
    return (
        f"{len(candidates)} of {external_pairs} external pairs show periodic or "
        f"semi-regular cadence; strongest {strongest['src']}→{strongest['dst']} "
        f"every ~{strongest['mean_interval_s']:.0f}s (cv {strongest['cv']:.2f})."
    )


@tool(
    read_only=True,
    description="Beacon-cadence sweep over zeek.conn: inter-arrival CV per src→dst pair.",
)
async def beacon_profile(
    *,
    elastic: ElasticClient,
    settings: Settings,
    window_minutes: int = 1440,
    src: str | None = None,
    dst: str | None = None,
    min_events: int = _MIN_EVENTS_DEFAULT,
    include_internal: bool = False,
    include_synth: SynthScope = False,
) -> dict[str, Any]:
    """Measure connection cadence per src→dst pair and flag periodic ones.

    Runs a bounded two-level terms aggregation over ``zeek.conn`` (source.ip
    -> destination.ip, each pair's raw ``@timestamp``s pulled via a capped
    ``top_hits``) and computes the inter-arrival coefficient of variation
    (``cv = stdev / mean``) per pair in Python. A low cv is the measured
    signature of a periodic beacon; this tool exists so the agent measures
    cadence BEFORE claiming a beacon, instead of eyeballing raw rows.

    Args:
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        window_minutes: trailing window size in minutes. Default 1440 (24h),
            capped at ``_MAX_TIME_RANGE_MINUTES`` (43_200 = 30 days).
        src: optional exact ``source.ip`` to narrow the sweep to.
        dst: optional exact ``destination.ip`` to narrow the sweep to.
        min_events: minimum raw timestamps required for a pair to be
            considered at all (too few samples make cv meaningless). Default 8.
        include_internal: when False (default), internal destinations
            (non-global ranges plus ``settings.internal_cidrs``) are excluded
            SERVER-SIDE — a ``must_not`` CIDR clause on ``destination.ip``
            (:func:`_internal_dest_exclusion`) keeps internal chatter from
            ever occupying the capped terms-agg slots or the per-pair
            top_hits payload — beaconing is primarily an EXTERNAL C2 signal.
            :func:`soc_ai.tools.online.is_internal_ip` still runs per bucket
            as a belt-and-braces catch for internal shapes the CIDR clause
            misses (TEST-NET/documentation ranges, unparseable keys). When
            True, no exclusion is applied and internal destinations are
            scored too.
        include_synth: synth-doc visibility (``SynthScope``). False (the
            prod default): the sweep excludes ALL synthetic-eval docs
            (``synth.scenario_id``) so fixtures can't leak into a hunt's
            findings. True (the hunt-journey eval): every plant visible. A
            scenario id (the batch eval): only THAT scenario's plants
            visible — a scoped sweep can never read a sibling scenario's
            plants as network-wide truth.

    Returns:
        On success::

            {window_minutes, pairs_scanned, internal_excluded, truncated,
             items: [{src, dst, events, mean_interval_s, stdev_s, cv,
                      bytes_out_avg, sample_ids, verdict_hint}, ...],
             thresholds: {min_events, cv_max}, summary}

        ``items`` holds up to 10 candidates (cv <= 0.4 and events >=
        min_events), sorted by cv ascending (strongest cadence first).
        ``sample_ids`` are ES ``_id``s from the pair's top_hits, so a hunt
        finding citing this pair's cadence can resolve against real evidence.
        ``verdict_hint`` is ``"periodic"`` (cv <= 0.15) or ``"semi-regular"``
        (cv <= 0.4) — a hint, not a verdict; the agent still corroborates. A
        pair whose measured mean interval is not positive (a burst of
        identically-timestamped connections) is never a candidate — zero
        cadence is not a cadence, and the cv fallback of 0.0 there would
        otherwise rank the burst as the strongest beacon on the grid.
        ``internal_excluded`` counts only the destinations the belt-and-
        braces Python check caught — with the default server-side exclusion
        it is normally 0, since internal pairs never come back at all.
        ``truncated`` is True when the source.ip terms agg's (size 20) or any
        pair's destination.ip sub-terms agg's (size 10) ``sum_other_doc_count``
        is nonzero — the caps dropped source or destination candidates (with
        the default exclusion, all external ones), so a low-and-slow beacon
        outside the top-N sources/destinations could be invisible to this
        sweep even when ``items`` comes back empty.

        On an over-cap ``window_minutes`` or an ES/query error:
        ``{"error": True, "message": ...}`` (never raises).
    """
    if (
        err := _window_error("window_minutes", window_minutes, _MAX_TIME_RANGE_MINUTES)
    ) is not None:
        return err

    filters: list[dict[str, Any]] = [
        _build_time_filter(window_minutes, None),
        {"term": {"event.dataset": "zeek.conn"}},
    ]
    if src:
        filters.append({"term": {"source.ip": src}})
    if dst:
        filters.append({"term": {"destination.ip": dst}})

    # Synth-scope exclusion (prod hides all plants; a scenario scope hides
    # every sibling's), plus (by
    # default) the SERVER-SIDE internal-destination exclusion so internal
    # chatter never occupies the capped terms-agg slots or the per-pair
    # top_hits payload (~20k docs of internal chatter would otherwise crowd
    # out the external C2 candidates this tool exists to find).
    query: dict[str, Any] = {
        "bool": {
            "filter": filters,
            "must_not": _hunt_must_not(
                settings,
                exclude_internal_dest=not include_internal,
                include_synth=include_synth,
            ),
        }
    }

    try:
        bytes_field = await resolve_agg_field(
            elastic, settings.events_index_pattern, fields.CONN_ORIG_BYTES
        )

        aggs: dict[str, Any] = {
            "pairs": {
                "terms": {"field": "source.ip", "size": _SRC_TERMS_SIZE},
                "aggs": {
                    "dsts": {
                        "terms": {"field": "destination.ip", "size": _DST_TERMS_SIZE},
                        "aggs": {
                            "ts": {
                                "top_hits": {
                                    "size": _TOP_HITS_SIZE,
                                    "sort": [{"@timestamp": "asc"}],
                                    "_source": ["@timestamp"],
                                }
                            },
                            "bytes_out_avg": {"avg": {"field": bytes_field}},
                        },
                    }
                },
            }
        }

        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs=aggs,
        )
    except Exception as exc:
        # Never let a query/transport error (including a partial-results grid
        # exception) crash the agent loop — surface it as a structured result.
        _LOGGER.warning("beacon_profile query failed: %s", exc)
        return {"error": True, "type": type(exc).__name__, "message": str(exc)}

    pairs_scanned = 0
    internal_excluded = 0
    candidates: list[dict[str, Any]] = []

    pairs_agg = (result.aggregations or {}).get("pairs") or {}
    pair_buckets = pairs_agg.get("buckets") or []
    # True when EITHER the top-level source.ip terms agg (size 20) or any
    # pair's nested destination.ip terms agg (size 10) dropped candidates —
    # a low-and-slow beacon outside the top-N of either cap has no signal
    # otherwise that this sweep's view of the grid was capped.
    truncated = bool((pairs_agg.get("sum_other_doc_count") or 0) > 0)
    for pair_bucket in pair_buckets:
        src_ip = pair_bucket.get("key")
        dsts_agg = pair_bucket.get("dsts") or {}
        dst_buckets = dsts_agg.get("buckets") or []
        if (dsts_agg.get("sum_other_doc_count") or 0) > 0:
            truncated = True
        for dst_bucket in dst_buckets:
            pairs_scanned += 1
            dst_ip = dst_bucket.get("key")

            # Belt-and-braces: the server-side CIDR exclusion already keeps
            # internal destinations out of the buckets; this catches shapes
            # the CIDR list misses (TEST-NET/documentation, unparseable keys).
            if not include_internal and is_internal_ip(str(dst_ip), settings):
                internal_excluded += 1
                continue

            ts_hits = ((dst_bucket.get("ts") or {}).get("hits") or {}).get("hits") or []
            timestamps: list[float] = []
            valid_hits: list[dict[str, Any]] = []
            for hit in ts_hits:
                epoch = _parse_epoch((hit.get("_source") or {}).get("@timestamp"))
                if epoch is None:
                    continue
                timestamps.append(epoch)
                valid_hits.append(hit)

            if len(timestamps) < min_events:
                continue

            # Correctness must not depend on ES honoring the top_hits sort
            # clause — unsorted hits would produce negative gaps and the
            # cv=0 fallback would mislabel the pair "periodic".
            timestamps.sort()
            inter_arrival = _compute_inter_arrival(timestamps)
            # Degenerate-cadence guard: a burst of identically-timestamped
            # connections has mean interval 0, where _compute_inter_arrival's
            # cv fallback of 0.0 would otherwise rank the burst as the
            # STRONGEST periodic beacon on the grid. Zero cadence is not a
            # cadence — require a positive measured mean.
            if inter_arrival is None or inter_arrival.mean_s <= 0 or inter_arrival.cv > _CV_MAX:
                continue

            verdict_hint = "periodic" if inter_arrival.cv <= _CV_PERIODIC else "semi-regular"
            candidates.append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "events": len(timestamps),
                    "mean_interval_s": inter_arrival.mean_s,
                    "stdev_s": inter_arrival.stdev_s,
                    "cv": inter_arrival.cv,
                    "bytes_out_avg": (dst_bucket.get("bytes_out_avg") or {}).get("value"),
                    "sample_ids": _sample_ids(valid_hits, _MAX_SAMPLE_IDS),
                    "verdict_hint": verdict_hint,
                }
            )

    candidates.sort(key=lambda c: c["cv"])
    items = candidates[:_MAX_ITEMS]

    return {
        "window_minutes": window_minutes,
        "pairs_scanned": pairs_scanned,
        "internal_excluded": internal_excluded,
        "truncated": truncated,
        "items": items,
        "thresholds": {"min_events": min_events, "cv_max": _CV_MAX},
        "summary": _beacon_summary(
            candidates, items, pairs_scanned=pairs_scanned, internal_excluded=internal_excluded
        ),
    }


# ---------------------------------------------------------------------------
# dns_entropy_scan
# ---------------------------------------------------------------------------

# Candidacy thresholds — evidence.py conventions (see the DNS-tunnel aggregate
# check in soc_ai/agent/evidence.py: entropy >= 3.5 AND (volume >= 500 OR
# unique subdomains >= 200)). The volume arm counts SUBDOMAIN-BEARING queries
# only — apex (no-subdomain) lookups contribute no entropy signal, so they
# don't get to satisfy the volume bar either. An extreme MEAN subdomain-label entropy
# (entropy_mean >= 4.2, averaged across every subdomain seen under the
# parent) is decisive on its own, regardless of volume — a freshly-started
# tunnel/DGA channel hasn't racked up volume yet, but a parent whose
# subdomains average 5 bits/char is not a normal hostname pattern either.
_ENTROPY_MIN = 3.5
_QUERIES_MIN = 500
_UNIQUE_SUBDOMAINS_MIN = 200
_ENTROPY_EXTREME_MIN = 4.2

# How many distinct qnames the terms agg walks (bounded ES cost), and how
# many sample hits ride along per qname (just enough for a couple of citable
# ids without hauling the whole bucket back).
_QNAME_TERMS_SIZE = 200
_SAMPLE_HITS_SIZE = 2

# Per-parent caps on what rides along in a candidate's `items` entry.
_MAX_EXAMPLE_QNAMES = 3
_MAX_DNS_SAMPLE_IDS = 3

# Top-N candidates returned in `items`, sorted by entropy_mean descending.
_MAX_DNS_ITEMS = 10


def _split_registrable(qname: str) -> tuple[str, str]:
    """Naive registrable-domain split for grouping qname candidates.

    Not PSL-aware (no public-suffix-list lookup — ``fields.DNS_REGISTERED_DOMAIN``
    is the SO-computed field when precision matters): the last two
    dot-separated labels are treated as the parent (registrable) domain and
    everything before them as the subdomain part. Good enough to group
    DGA/tunnel candidates by apex for a hunt-only sweep; a two-part public
    suffix (``co.uk``-style) over-groups (the suffix itself is treated as the
    parent), an acceptable false grouping here.

    Returns ``(parent, sub)``; ``sub`` is ``""`` when the qname has at most
    two labels (querying the apex directly, no subdomain).

    Caveat: ``parent`` is ALWAYS exactly one or two labels — never more —
    so a caller narrowing by parent domain (:func:`dns_entropy_scan`'s
    ``parent_domain`` arg) must match against that same two-label shape
    (e.g. ``"badc2.net"``); a coarser single-label value (e.g. ``"net"``)
    will never equal a two-label parent and so will never match.
    """
    qname = qname.strip(".").lower()
    labels = [lbl for lbl in qname.split(".") if lbl]
    if not labels:
        return "", ""
    if len(labels) <= 2:
        return ".".join(labels), ""
    return ".".join(labels[-2:]), ".".join(labels[:-2])


def _dns_summary(items: list[dict[str, Any]], *, parents_scanned: int) -> str:
    if not items:
        return (
            f"No DGA/tunnel-shaped parent domain found across {parents_scanned} parent(s) scanned."
        )
    strongest = items[0]
    return (
        f"{len(items)} of {parents_scanned} parent(s) scanned show DGA/tunnel-shaped "
        f"qname entropy; strongest {strongest['parent']} (entropy "
        f"{strongest['entropy_mean']:.2f}, {strongest['queries']} queries, "
        f"{strongest['unique_subdomains']} unique subdomains)."
    )


def _accumulate_qname_bucket(
    parents: dict[str, dict[str, Any]],
    bucket: dict[str, Any],
    *,
    parent_domain: str | None,
) -> None:
    """Fold one qname terms-agg bucket into its parent's running aggregate.

    Mutates ``parents`` in place — a helper so :func:`dns_entropy_scan` stays
    under the statement-count lint bar; the per-bucket logic (split, narrow,
    accumulate volume/entropy/examples/sample hits) has no meaningful
    sub-steps of its own to unit-test in isolation from the tool.

    ``parent_domain`` narrowing is an EXACT match against the resolved
    parent — :func:`_split_registrable` always returns a parent of at most
    two labels, so there is no longer-than-two-label parent a suffix match
    could ever catch beyond exact equality; see :func:`_split_registrable`'s
    docstring for the two-label caveat.
    """
    qname = bucket.get("key")
    if not isinstance(qname, str) or not qname:
        return
    parent, sub = _split_registrable(qname)
    if not parent:
        return
    if parent_domain and parent != parent_domain:
        return

    doc_count = int(bucket.get("doc_count") or 0)
    entry = parents.setdefault(
        parent,
        {
            "queries": 0,
            "subdomain_queries": 0,
            "subs": set(),
            "longest_label": 0,
            "example_qnames": [],
            "sample_hits": [],
            "entropies": [],
        },
    )
    entry["queries"] += doc_count
    if sub:
        # Subdomain-bearing volume is tracked SEPARATELY from total volume:
        # the entropy signal comes only from subdomain labels, so the
        # tunnel-volume candidacy arm must be gated on this count — apex
        # (sub == "") query volume says nothing about tunneling.
        entry["subdomain_queries"] += doc_count
        entry["subs"].add(sub)
        entry["entropies"].append(_shannon_entropy_chars(sub))
    entry["longest_label"] = max(
        entry["longest_label"],
        max((len(lbl) for lbl in qname.split(".") if lbl), default=0),
    )
    if len(entry["example_qnames"]) < _MAX_EXAMPLE_QNAMES:
        entry["example_qnames"].append(qname)

    # Only _MAX_DNS_SAMPLE_IDS ids ever make it into the output; keep 2x that
    # many raw hits (headroom for _sample_ids' dedup/missing-_id drops) and
    # stop accumulating once the cap is reached — no point hauling hundreds
    # of hit dicts along for a busy parent.
    if len(entry["sample_hits"]) < 2 * _MAX_DNS_SAMPLE_IDS:
        hits = ((bucket.get("sample") or {}).get("hits") or {}).get("hits") or []
        entry["sample_hits"].extend(hits)


def _dns_candidates(
    parents: dict[str, dict[str, Any]], *, min_queries: int
) -> tuple[int, list[dict[str, Any]]]:
    """Apply the noise floor + candidacy rule to the per-parent aggregates.

    Returns ``(parents_scanned, candidates)`` — ``parents_scanned`` counts
    only parents whose aggregate volume cleared ``min_queries`` (see
    :func:`dns_entropy_scan`'s docstring for why parents below the floor
    don't count at all), and ``candidates`` is unsorted/uncapped (the caller
    sorts and slices to the top-N ``items``).
    """
    parents_scanned = 0
    candidates: list[dict[str, Any]] = []
    for parent, entry in parents.items():
        queries = entry["queries"]
        if queries < min_queries:
            continue
        parents_scanned += 1

        entropies = entry["entropies"]
        entropy_mean = sum(entropies) / len(entropies) if entropies else 0.0
        unique_subdomains = len(entry["subs"])
        subdomain_queries = entry["subdomain_queries"]

        # The volume arm gates on SUBDOMAIN-BEARING volume, not total volume:
        # the entropy signal is measured over subdomain labels only, so a
        # parent whose traffic is overwhelmingly apex lookups must not clear
        # the tunnel-volume bar on apex noise. Total `queries` still rides
        # along for reporting.
        is_candidate = (
            entropy_mean >= _ENTROPY_MIN
            and (subdomain_queries >= _QUERIES_MIN or unique_subdomains >= _UNIQUE_SUBDOMAINS_MIN)
        ) or entropy_mean >= _ENTROPY_EXTREME_MIN
        if not is_candidate:
            continue

        candidates.append(
            {
                "parent": parent,
                "queries": queries,
                "subdomain_queries": subdomain_queries,
                "unique_subdomains": unique_subdomains,
                "entropy_mean": entropy_mean,
                "longest_label": entry["longest_label"],
                "example_qnames": entry["example_qnames"],
                "sample_ids": _sample_ids(entry["sample_hits"], _MAX_DNS_SAMPLE_IDS),
            }
        )
    return parents_scanned, candidates


_DNS_ENTROPY_DESCRIPTION = (
    "DNS-entropy sweep over zeek.dns: DGA/tunnel candidate parent domains by qname entropy."
)


@tool(read_only=True, description=_DNS_ENTROPY_DESCRIPTION)
async def dns_entropy_scan(
    *,
    elastic: ElasticClient,
    settings: Settings,
    window_minutes: int = 1440,
    parent_domain: str | None = None,
    min_queries: int = 50,
    include_synth: SynthScope = False,
) -> dict[str, Any]:
    """Measure per-parent-domain qname entropy/volume and flag DGA/tunnel candidates.

    Runs a bounded terms aggregation over ``zeek.dns`` qnames (size 200, with a
    small ``top_hits`` sub-agg riding along for citable sample ids), then in
    Python groups qnames under their parent (registrable) domain via a naive
    last-two-labels split (:func:`_split_registrable`) and computes, per
    parent: total query volume, distinct non-empty subdomain count, mean
    Shannon entropy of the subdomain labels (:func:`_shannon_entropy_chars`
    over each bucket's ``sub`` part), and the longest label seen. This tool
    exists so the agent measures qname entropy BEFORE claiming a DGA/tunnel —
    the measured candidate set is the evidence, not an eyeballed "these
    subdomains look random" read of raw rows.

    A parent is a candidate when ``entropy_mean >= 3.5`` AND
    (``subdomain_queries >= 500`` OR ``unique_subdomains >= 200``) — the
    evidence.py DNS-tunnel-aggregate bar, with the volume arm gated on
    SUBDOMAIN-BEARING query volume (apex ``sub == ""`` lookups contribute no
    entropy signal, so they must not clear the tunnel-volume bar either;
    total ``queries`` is still reported) — OR when ``entropy_mean >= 4.2``
    alone (extreme, decisive regardless of volume).

    Args:
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        window_minutes: trailing window size in minutes. Default 1440 (24h),
            capped at ``_MAX_TIME_RANGE_MINUTES`` (43_200 = 30 days).
        parent_domain: optional narrowing filter — only qnames whose resolved
            parent (:func:`_split_registrable`, always at most two labels) is
            EXACTLY equal to ``parent_domain`` are kept. Applied client-side
            (Python) against the resolved parent of each qname bucket, after
            the single terms-agg query returns (no per-parent ES round trip).
            Caveat: pass ``parent_domain`` in that same two-label shape (e.g.
            ``"badc2.net"``) — a coarser single-label value (e.g. ``"net"``)
            will never match.
        min_queries: noise floor on total query volume. A parent whose
            aggregate volume is below this is dropped entirely and does NOT
            count toward ``parents_scanned`` — that count reflects only
            parents that cleared the floor (the same convention as
            ``pairs_scanned`` in :func:`beacon_profile` counting only
            fully-formed pairs, not every raw bucket seen).
        include_synth: synth-doc visibility (``SynthScope``): False (prod)
            excludes all planted eval docs, True (hunt-journey eval) sees
            every plant, a scenario id (batch eval) sees only that
            scenario's plants — see :func:`beacon_profile`.

    Returns:
        On success::

            {window_minutes, parents_scanned, truncated,
             items: [{parent, queries, subdomain_queries, unique_subdomains,
                      entropy_mean, longest_label, example_qnames,
                      sample_ids}, ...],
             thresholds: {...}, summary}

        ``items`` holds up to 10 candidates, sorted by ``entropy_mean``
        descending. ``example_qnames``/``sample_ids`` cap at 3 each;
        ``sample_ids`` are ES ``_id``s so a hunt finding citing this parent's
        entropy can resolve against real evidence. ``truncated`` is True when
        the qname terms agg's ``sum_other_doc_count`` is nonzero — the
        size=200 cap dropped qnames, so the scan is a sample, not exhaustive.

        On an over-cap ``window_minutes`` or an ES/query error:
        ``{"error": True, "message": ...}`` (never raises).
    """
    if (
        err := _window_error("window_minutes", window_minutes, _MAX_TIME_RANGE_MINUTES)
    ) is not None:
        return err

    filters: list[dict[str, Any]] = [
        _build_time_filter(window_minutes, None),
        {"terms": {"event.dataset": ["zeek.dns"]}},
    ]
    query: dict[str, Any] = {
        "bool": {
            "filter": filters,
            # Synth-scope exclusion via the shared helper (prod hides all
            # plants; a scenario scope hides every sibling's). NO
            # internal-destination exclusion here — DNS
            # resolvers are internal, so excluding internal destination.ip
            # would drop the very traffic this sweep measures.
            "must_not": _hunt_must_not(
                settings, exclude_internal_dest=False, include_synth=include_synth
            ),
        }
    }

    try:
        name_field = await resolve_agg_field(
            elastic, settings.events_index_pattern, fields.DNS_QUERY
        )

        aggs: dict[str, Any] = {
            "qnames": {
                "terms": {"field": name_field, "size": _QNAME_TERMS_SIZE},
                "aggs": {
                    "sample": {
                        "top_hits": {
                            "size": _SAMPLE_HITS_SIZE,
                            "_source": [name_field],
                        }
                    }
                },
            }
        }

        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs=aggs,
        )
    except Exception as exc:
        # Never let a query/transport error (including a partial-results grid
        # exception) crash the agent loop — surface it as a structured result.
        _LOGGER.warning("dns_entropy_scan query failed: %s", exc)
        return {"error": True, "type": type(exc).__name__, "message": str(exc)}

    qnames_agg = (result.aggregations or {}).get("qnames") or {}
    qname_buckets = qnames_agg.get("buckets") or []
    truncated = bool((qnames_agg.get("sum_other_doc_count") or 0) > 0)

    parents: dict[str, dict[str, Any]] = {}
    for bucket in qname_buckets:
        _accumulate_qname_bucket(parents, bucket, parent_domain=parent_domain)

    parents_scanned, candidates = _dns_candidates(parents, min_queries=min_queries)
    candidates.sort(key=lambda c: c["entropy_mean"], reverse=True)
    items = candidates[:_MAX_DNS_ITEMS]

    return {
        "window_minutes": window_minutes,
        "parents_scanned": parents_scanned,
        "truncated": truncated,
        "items": items,
        "thresholds": {
            "entropy_mean_min": _ENTROPY_MIN,
            "subdomain_queries_min": _QUERIES_MIN,
            "unique_subdomains_min": _UNIQUE_SUBDOMAINS_MIN,
            "entropy_extreme_min": _ENTROPY_EXTREME_MIN,
            "min_queries_floor": min_queries,
        },
        "summary": _dns_summary(items, parents_scanned=parents_scanned),
    }


# ---------------------------------------------------------------------------
# dcerpc_histogram
# ---------------------------------------------------------------------------

# Operations that are individually decisive when rare: DC secret extraction /
# Zerologon / DCSync / remote service creation. Sourced from the 2026-06-17
# hunting-agent design and standard tradecraft references.
_DANGEROUS_OPS = {
    "NetrServerAuthenticate3",
    "NetrServerAuthenticate2",
    "NetrServerPasswordSet2",
    "DRSGetNCChanges",
    "DsGetNCChanges",
    "CreateServiceW",
    "CreateServiceA",
    "StartServiceW",
    "SamrSetInformationUser2",
    "SamrChangePasswordUser",
}

# A candidate op must clear this doc_count to be "rare" — rare is only
# meaningful relative to a busy baseline (a quiet grid where every op fires a
# handful of times has no baseline to be rare AGAINST, so the rare list is
# skipped entirely below this bar; see dcerpc_histogram's docstring).
_RARE_MAX_DEFAULT = 5
_BUSY_MIN = 100

# How many distinct operations the terms agg walks (bounded ES cost), how
# many source.ip peers ride along per operation (size 5, just enough to show
# who is issuing it), and how many sample hits ride along per operation (size
# 3, matching the sample-id cap the other three tools use — just enough for
# citable ids without hauling the whole bucket back).
_OPS_TERMS_SIZE = 100
_OP_SOURCES_TERMS_SIZE = 5
_OP_SAMPLE_HITS_SIZE = 3

# Top-N operations returned in `items`, sorted by count descending (busiest
# first) — keeps the full histogram self-bounded and clamp-friendly even
# when the terms agg walks the full 100-operation cap.
_MAX_DCERPC_ITEMS = 25

# Defensive caps on `rare`/`flagged` — both are evaluated against the FULL
# histogram (up to 100 operations), not the capped `items` slice, so without
# their own cap either list could still carry up to 100 entries on a busy
# grid and blow the agent-side per-tool output clamp
# (:func:`soc_ai.agent.toolset._clamp_tool_result`, 12KiB), which only
# bisects the `items` list and has no way to shrink `rare`/`flagged`. Both
# sort ascending by count (rarest first — the more interesting end of either
# list) before capping.
_MAX_RARE_ITEMS = 25
_MAX_FLAGGED_ITEMS = 25


def _op_entry(bucket: dict[str, Any]) -> dict[str, Any]:
    """Build a flagged/rare entry from one operation's terms-agg bucket.

    Pulls the busiest ``source.ip`` peers (sub-terms bucket keys) and the
    ``top_hits`` sample's ``_id``s so the entry is citable — mirrors the
    sample-id convention in :func:`beacon_profile`/:func:`dns_entropy_scan`.
    """
    sources = [b.get("key") for b in ((bucket.get("sources") or {}).get("buckets") or [])]
    hits = ((bucket.get("sample") or {}).get("hits") or {}).get("hits") or []
    return {
        "operation": bucket.get("key"),
        "count": int(bucket.get("doc_count") or 0),
        "sources": sources,
        "sample_ids": _sample_ids(hits, _OP_SAMPLE_HITS_SIZE),
    }


def _cap_by_count_ascending(
    entries: list[dict[str, Any]], cap: int
) -> tuple[list[dict[str, Any]], int, bool]:
    """Sort ``entries`` by ``count`` ascending (rarest first) and cap to ``cap``.

    Shared by :func:`dcerpc_histogram`'s ``rare``/``flagged`` capping —
    both need the same "rarest/lowest-count entries are the signal, keep
    those when the full set exceeds the output budget" treatment. Returns
    ``(capped, total, was_truncated)``.
    """
    ordered = sorted(entries, key=lambda item: item["count"])
    total = len(ordered)
    return ordered[:cap], total, total > cap


def _dcerpc_summary(
    flagged: list[dict[str, Any]],
    rare: list[dict[str, Any]],
    *,
    distinct_ops: int,
    flagged_total: int,
    rare_total: int,
) -> str:
    if not flagged_total and not rare_total:
        return (
            f"No dangerous or rare DCE-RPC operations found across "
            f"{distinct_ops} distinct operation(s)."
        )
    parts = []
    if flagged_total:
        names = ", ".join(str(f["operation"]) for f in flagged[:3])
        parts.append(f"{flagged_total} dangerous operation(s) seen ({names})")
    if rare_total:
        parts.append(f"{rare_total} rare-against-busy-baseline operation(s)")
    return "; ".join(parts) + f" — {distinct_ops} distinct operation(s) total."


_DCERPC_HISTOGRAM_DESCRIPTION = (
    "Operation histogram over zeek.dce_rpc: flags individually-dangerous ops "
    "(Zerologon/DCSync/service creation) and ops rare against a busy baseline."
)


@tool(read_only=True, description=_DCERPC_HISTOGRAM_DESCRIPTION)
async def dcerpc_histogram(
    *,
    elastic: ElasticClient,
    settings: Settings,
    window_minutes: int = 1440,
    rare_max: int = 5,
    include_synth: SynthScope = False,
) -> dict[str, Any]:
    """Histogram DCE-RPC operations and flag dangerous / rare-against-busy ones.

    Runs a bounded terms aggregation over ``zeek.dce_rpc`` operations (size
    100, with a small ``top_hits`` sample and a ``source.ip`` sub-terms riding
    along per operation), then in Python classifies each operation bucket:

    * ``flagged`` — the operation is in a fixed dangerous set (Zerologon-style
      ``NetrServerAuthenticate*``, DCSync's ``DRSGetNCChanges``/
      ``DsGetNCChanges``, and remote service creation) — exact membership
      against the bucket key.
    * ``rare`` — the operation's count is ``<= rare_max`` (default 5) while
      the single busiest operation on the grid has ``>= 100`` events. Rare is
      only meaningful against a BUSY baseline: on a quiet grid where every
      operation fires a handful of times, nothing stands out as rare, so the
      rare list is skipped entirely (returned empty) when the busiest
      operation is below the 100-event bar — documented via ``thresholds``.

    An operation can land in BOTH lists (e.g. a Zerologon-shaped
    ``NetrServerAuthenticate3`` burst is both individually dangerous and rare
    next to routine ``svcctl`` noise) — this tool exists so the agent
    measures the operation mix BEFORE claiming a DCE-RPC attack pattern.

    Args:
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        window_minutes: trailing window size in minutes. Default 1440 (24h),
            capped at ``_MAX_TIME_RANGE_MINUTES`` (43_200 = 30 days).
        rare_max: doc_count ceiling for an operation to be considered rare.
            Default 5.
        include_synth: synth-doc visibility (``SynthScope``): False (prod)
            excludes all planted eval docs, True (hunt-journey eval) sees
            every plant, a scenario id (batch eval) sees only that
            scenario's plants — see :func:`beacon_profile`.

    Returns:
        On success::

            {window_minutes, total_ops, distinct_ops, truncated,
             items: [{operation, count, sources, sample_ids}, ...],
             flagged: [{operation, count, sources, sample_ids}, ...],
             flagged_total, flagged_truncated,
             rare: [{operation, count, sources, sample_ids}, ...],
             rare_total, rare_truncated,
             thresholds: {rare_max, busy_min}, summary}

        ``total_ops``/``distinct_ops`` are computed over the FULL histogram —
        every operation bucket the size=100 terms agg returned, not just the
        top-25 slice below. ``items`` holds up to 25 of those buckets, sorted
        by ``count`` descending (busiest first) — self-bounded so a chatty
        grid with many distinct operations still returns a clamp-friendly
        result. ``flagged``/``rare`` are evaluated against the full histogram
        too, so a low-volume dangerous operation stays visible even when
        higher-volume benign operations would otherwise push it out of the
        top-25 ``items`` slice — but each is ITSELF capped at 25 entries
        (sorted by ``count`` ascending, rarest first) as a defensive bound
        against a pathological grid with many rare or many dangerous
        operations; ``flagged_total``/``rare_total`` carry the FULL
        (uncapped) counts and ``flagged_truncated``/``rare_truncated`` are
        True when the cap actually dropped entries. ``truncated`` is True
        when the terms agg's ``sum_other_doc_count`` is nonzero — the
        size=100 cap dropped operations, so the histogram itself is a
        sample, not exhaustive. ``sources``/``sample_ids`` on every entry
        are, respectively, the busiest ``source.ip`` peers issuing that
        operation and ES ``_id``s from its ``top_hits`` sample — so a hunt
        finding citing this operation can resolve against real evidence.

        On an over-cap ``window_minutes`` or an ES/query error:
        ``{"error": True, "message": ...}`` (never raises).
    """
    if (
        err := _window_error("window_minutes", window_minutes, _MAX_TIME_RANGE_MINUTES)
    ) is not None:
        return err

    filters: list[dict[str, Any]] = [
        _build_time_filter(window_minutes, None),
        {"term": {"event.dataset": "zeek.dce_rpc"}},
    ]
    query: dict[str, Any] = {
        "bool": {
            "filter": filters,
            # Synth-scope exclusion via the shared helper (prod hides all
            # plants; a scenario scope hides every sibling's). NO
            # internal-destination exclusion here —
            # DCE-RPC traffic is lateral movement between INTERNAL hosts, so
            # excluding internal destination.ip would blind the histogram.
            "must_not": _hunt_must_not(
                settings, exclude_internal_dest=False, include_synth=include_synth
            ),
        }
    }

    try:
        op_field = await resolve_agg_field(
            elastic, settings.events_index_pattern, fields.DCE_RPC_OPERATION
        )

        aggs: dict[str, Any] = {
            "ops": {
                "terms": {"field": op_field, "size": _OPS_TERMS_SIZE},
                "aggs": {
                    "sample": {
                        "top_hits": {
                            "size": _OP_SAMPLE_HITS_SIZE,
                            "_source": ["source.ip", "destination.ip", op_field],
                        }
                    },
                    "sources": {
                        "terms": {"field": "source.ip", "size": _OP_SOURCES_TERMS_SIZE},
                    },
                },
            }
        }

        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs=aggs,
        )
    except Exception as exc:
        # Never let a query/transport error (including a partial-results grid
        # exception) crash the agent loop — surface it as a structured result.
        _LOGGER.warning("dcerpc_histogram query failed: %s", exc)
        return {"error": True, "type": type(exc).__name__, "message": str(exc)}

    ops_agg = (result.aggregations or {}).get("ops") or {}
    op_buckets = ops_agg.get("buckets") or []
    truncated = bool((ops_agg.get("sum_other_doc_count") or 0) > 0)

    # Full histogram first — flagged/rare are evaluated against this, not the
    # capped `items` slice below, so a low-volume dangerous op doesn't fall
    # out of sight behind a wall of high-volume benign ones.
    full_items = [_op_entry(bucket) for bucket in op_buckets]
    total_ops = sum(item["count"] for item in full_items)
    distinct_ops = len(full_items)
    busiest = max((item["count"] for item in full_items), default=0)

    flagged_all = [item for item in full_items if item["operation"] in _DANGEROUS_OPS]
    rare_all = (
        [item for item in full_items if item["count"] <= rare_max] if busiest >= _BUSY_MIN else []
    )
    flagged, flagged_total, flagged_truncated = _cap_by_count_ascending(
        flagged_all, _MAX_FLAGGED_ITEMS
    )
    rare, rare_total, rare_truncated = _cap_by_count_ascending(rare_all, _MAX_RARE_ITEMS)

    items = sorted(full_items, key=lambda item: item["count"], reverse=True)[:_MAX_DCERPC_ITEMS]

    return {
        "window_minutes": window_minutes,
        "total_ops": total_ops,
        "distinct_ops": distinct_ops,
        "truncated": truncated,
        "items": items,
        "flagged": flagged,
        "flagged_total": flagged_total,
        "flagged_truncated": flagged_truncated,
        "rare": rare,
        "rare_total": rare_total,
        "rare_truncated": rare_truncated,
        "thresholds": {"rare_max": rare_max, "busy_min": _BUSY_MIN},
        "summary": _dcerpc_summary(
            flagged,
            rare,
            distinct_ops=distinct_ops,
            flagged_total=flagged_total,
            rare_total=rare_total,
        ),
    }


# ---------------------------------------------------------------------------
# first_seen
# ---------------------------------------------------------------------------

# How many distinct destinations each terms agg walks. The recent side's cap
# (100) doubles as the candidate pool before novelty filtering, and each
# bucket carries substantive sub-aggs (first-seen ts, peers, samples). The
# baseline side exists purely as a MEMBERSHIP SET ("have we ever seen this
# destination before"), so it carries no sub-aggs and can afford a much
# larger cap (1000) at bounded ES cost.
_RECENT_DST_TERMS_SIZE = 100
_BASELINE_DST_TERMS_SIZE = 1000

# How many source.ip peers and sample hits ride along per recent destination
# bucket (bounded payload — just enough for attribution + citable evidence).
_FIRST_SEEN_SRCS_TERMS_SIZE = 3
_FIRST_SEEN_SAMPLE_HITS_SIZE = 2
_MAX_FIRST_SEEN_SAMPLE_IDS = 3

# Top-N novel destinations returned in `items`, sorted by recent_events
# (the recent window's doc_count) descending.
_MAX_FIRST_SEEN_ITEMS = 20

# Hard ceiling on the baseline window, mirroring prevalence.py's
# _MAX_LOOKBACK_DAYS (365d) — same rationale: an LLM-callable read tool must
# not let an unbounded lookback turn a bounded sweep into a full-history ES
# scan against the live grid.
_MAX_BASELINE_DAYS = 365


def _first_seen_windows(
    recent_minutes: int, baseline_days: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the recent and baseline ``@timestamp`` range filters.

    Both filters are derived from a single ``now`` anchor captured once, so
    the baseline window ends EXACTLY where the recent window begins — two
    separate ES round trips a few milliseconds apart would otherwise each
    resolve their own "now" and skew the boundary. Recent covers
    ``[now - recent_minutes, now]``; baseline covers
    ``[now - recent_minutes - baseline_days, now - recent_minutes]``.
    """
    now = datetime.now(UTC)
    recent_start = now - timedelta(minutes=recent_minutes)
    baseline_start = recent_start - timedelta(days=baseline_days)
    recent_filter = {
        "range": {"@timestamp": {"gte": recent_start.isoformat(), "lte": now.isoformat()}}
    }
    baseline_filter = {
        "range": {
            "@timestamp": {"gte": baseline_start.isoformat(), "lte": recent_start.isoformat()}
        }
    }
    return recent_filter, baseline_filter


def _min_agg_timestamp(agg: Any) -> str | None:
    """Extract a ``min`` date aggregation's value as an ISO string.

    Same shape as :mod:`soc_ai.tools.prevalence`'s ``_agg_value_as_string``
    (duplicated locally rather than imported — that helper is module-private
    and the shape is a two-line ES aggregation convention, not a real
    cross-module dependency). ES date min/max aggs return ``{"value":
    <epoch_millis>, "value_as_string": <iso>}``; prefer ``value_as_string``,
    fall back to the numeric ``value`` rendered as a string, and return
    ``None`` when the agg is absent or has no value.
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


def _first_seen_summary(
    items: list[dict[str, Any]],
    *,
    recent_destinations: int,
    baseline_destinations: int,
    internal_excluded: int,
    baseline_truncated: bool,
) -> str:
    if not items:
        summary = (
            f"No novel external destinations among {recent_destinations} recent "
            f"destination(s) ({baseline_destinations} baseline destination(s) scanned, "
            f"{internal_excluded} internal excluded)."
        )
    else:
        strongest = items[0]
        summary = (
            f"{len(items)} novel external destination(s) among {recent_destinations} "
            f"recent destination(s), absent from the {baseline_destinations}-destination "
            f"baseline ({internal_excluded} internal excluded); busiest new destination "
            f"{strongest['dst']} ({strongest['recent_events']} event(s))."
        )
    if baseline_truncated:
        summary += (
            " Baseline was truncated (more distinct baseline destinations exist than "
            "the scan captured), so novelty here is approximate — a destination could "
            "have an uncaptured prior baseline."
        )
    return summary


_FIRST_SEEN_DESCRIPTION = (
    "Novelty sweep: external destinations seen in a recent window that never "
    "appeared in a trailing baseline, vs zeek.conn (or another dataset)."
)


@tool(read_only=True, description=_FIRST_SEEN_DESCRIPTION)
async def first_seen(
    *,
    elastic: ElasticClient,
    settings: Settings,
    recent_minutes: int = 1440,
    baseline_days: int = 30,
    dataset: str = "zeek.conn",
    include_synth: SynthScope = False,
) -> dict[str, Any]:
    """Diff recent external destinations against a trailing baseline.

    Generalizes :func:`soc_ai.tools.prevalence.prevalence`'s oracle from one
    indicator to a sweep: "which external destinations appeared in the
    recent window that never appeared in the baseline?" Runs two bounded
    terms aggregations over ``destination.ip`` (no composite agg exists to
    do this in one round trip) — a "recent" query over the trailing
    ``recent_minutes`` window, and a "baseline" query over the
    ``baseline_days`` window immediately BEFORE it (built so the baseline
    ends exactly where the recent window begins, see
    :func:`_first_seen_windows`) — then, in Python, takes the recent
    destination keys not present in the baseline key set. This tool exists
    so the agent measures novelty BEFORE claiming "first seen", instead of
    eyeballing whether a destination looks new.

    Args:
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        recent_minutes: trailing window size in minutes for the "recent"
            side. Default 1440 (24h), capped at ``_MAX_TIME_RANGE_MINUTES``
            (43_200 = 30 days).
        baseline_days: size in days of the baseline window, which ends
            exactly where the recent window begins. Default 30, capped at
            ``_MAX_BASELINE_DAYS`` (365 — mirrors
            :mod:`soc_ai.tools.prevalence`'s lookback ceiling).
        dataset: ``event.dataset`` value both queries are scoped to. Default
            ``"zeek.conn"``.
        include_synth: synth-doc visibility (``SynthScope``), applied to
            BOTH queries: False (prod) excludes all planted eval docs, True
            (hunt-journey eval) sees every plant, a scenario id (batch
            eval) sees only that scenario's plants — see
            :func:`beacon_profile`.

    Returns:
        On success::

            {recent_minutes, baseline_days, dataset,
             recent_destinations, baseline_destinations, internal_excluded,
             baseline_empty, baseline_truncated, recent_truncated,
             items: [{dst, recent_events, first_seen_ts, sources,
                      sample_ids}, ...],
             summary}

        ``items`` holds up to 20 novel EXTERNAL destinations — internal
        destinations are excluded SERVER-SIDE on BOTH queries (a ``must_not``
        CIDR clause on ``destination.ip``, :func:`_internal_dest_exclusion`),
        so the 1000-slot baseline membership set holds only external
        destinations instead of burning slots on internal chatter;
        :func:`soc_ai.tools.online.is_internal_ip` still runs per recent
        bucket as a belt-and-braces catch (those catches are what
        ``internal_excluded`` counts — normally 0) — sorted by
        ``recent_events`` (the recent window's doc_count) descending.
        ``baseline_empty`` is True when the baseline window returned ZERO
        destinations while the recent window has some: novelty cannot be
        determined against an empty baseline (a retention/coverage gap would
        make EVERY recent destination falsely read as first-seen), so
        ``items`` comes back empty and the ``summary`` leads with the gap
        instead.
        ``sources`` are the busiest ``source.ip`` peers that talked to the
        destination; ``sample_ids`` are ES ``_id``s from the destination's
        ``top_hits`` sample, so a hunt finding citing it can resolve against
        real evidence. ``baseline_truncated`` is True when the baseline
        terms agg's ``sum_other_doc_count`` is nonzero — the size=1000 cap
        dropped baseline destinations, so a destination's absence from the
        baseline (and thus its presence in ``items``) is only APPROXIMATE;
        the ``summary`` says so when True. ``recent_truncated`` is True when
        the RECENT terms agg's (size 100) ``sum_other_doc_count`` is
        nonzero — ``recent_destinations`` is then a FLOOR, not the true
        count of distinct destinations in the recent window, since the
        size=100 cap dropped some.

        On an over-cap ``recent_minutes``/``baseline_days``, or an ES/query
        error on EITHER query: ``{"error": True, "message": ...}`` (never
        raises).
    """
    if (
        err := _window_error("recent_minutes", recent_minutes, _MAX_TIME_RANGE_MINUTES)
    ) is not None:
        return err
    if (err := _window_error("baseline_days", baseline_days, _MAX_BASELINE_DAYS)) is not None:
        return err

    recent_range, baseline_range = _first_seen_windows(recent_minutes, baseline_days)
    dataset_term = {"term": {"event.dataset": dataset}}
    # Synth-scope exclusion (prod hides all plants; a scenario scope hides
    # every sibling's) plus the
    # SERVER-SIDE internal-destination exclusion (this tool only ever reports
    # external destinations, so both sides exclude internal ones up front) —
    # on the baseline side that means the 1000-slot membership set holds only
    # external destinations, instead of internal chatter eating slots and
    # forcing spurious baseline_truncated caveats.
    must_not = _hunt_must_not(settings, exclude_internal_dest=True, include_synth=include_synth)

    recent_query: dict[str, Any] = {
        "bool": {"filter": [recent_range, dataset_term], "must_not": must_not}
    }
    baseline_query: dict[str, Any] = {
        "bool": {"filter": [baseline_range, dataset_term], "must_not": must_not}
    }

    recent_aggs: dict[str, Any] = {
        "dsts": {
            "terms": {"field": "destination.ip", "size": _RECENT_DST_TERMS_SIZE},
            "aggs": {
                "first_seen": {"min": {"field": "@timestamp"}},
                "srcs": {"terms": {"field": "source.ip", "size": _FIRST_SEEN_SRCS_TERMS_SIZE}},
                "samples": {
                    "top_hits": {
                        "size": _FIRST_SEEN_SAMPLE_HITS_SIZE,
                        "_source": ["@timestamp", "destination.ip"],
                    }
                },
            },
        }
    }
    baseline_aggs: dict[str, Any] = {
        "dsts": {"terms": {"field": "destination.ip", "size": _BASELINE_DST_TERMS_SIZE}}
    }

    try:
        # Two bounded queries, no composite agg — recent runs first (it's the
        # substantive side); a baseline failure after a successful recent
        # query still surfaces as one structured error, not a partial result.
        recent_result = await elastic.search(
            settings.events_index_pattern, recent_query, size=0, aggs=recent_aggs
        )
        baseline_result = await elastic.search(
            settings.events_index_pattern, baseline_query, size=0, aggs=baseline_aggs
        )
    except Exception as exc:
        # Never let a query/transport error (including a partial-results grid
        # exception) crash the agent loop — surface it as a structured result.
        _LOGGER.warning("first_seen query failed: %s", exc)
        return {"error": True, "type": type(exc).__name__, "message": str(exc)}

    recent_agg = (recent_result.aggregations or {}).get("dsts") or {}
    recent_buckets = recent_agg.get("buckets") or []
    recent_destinations = len(recent_buckets)
    recent_truncated = bool((recent_agg.get("sum_other_doc_count") or 0) > 0)

    baseline_agg = (baseline_result.aggregations or {}).get("dsts") or {}
    baseline_buckets = baseline_agg.get("buckets") or []
    baseline_destinations = len(baseline_buckets)
    baseline_truncated = bool((baseline_agg.get("sum_other_doc_count") or 0) > 0)
    baseline_keys = {b.get("key") for b in baseline_buckets}

    if recent_buckets and not baseline_buckets:
        # An EMPTY baseline (retention/coverage gap) would make every recent
        # destination read as "novel" — a mass false positive, not a finding.
        # Say so explicitly instead of returning a wall of spurious novelty.
        return {
            "recent_minutes": recent_minutes,
            "baseline_days": baseline_days,
            "dataset": dataset,
            "recent_destinations": recent_destinations,
            "baseline_destinations": 0,
            "internal_excluded": 0,
            "baseline_empty": True,
            "baseline_truncated": baseline_truncated,
            "recent_truncated": recent_truncated,
            "items": [],
            "summary": (
                "Baseline window contained no data (retention/coverage gap) — "
                "novelty cannot be determined: with nothing to compare against, "
                f"every one of the {recent_destinations} recent destination(s) "
                "would falsely read as first-seen. Shorten baseline_days to fit "
                "the data actually retained, or verify the dataset's coverage, "
                "before drawing first-seen conclusions."
            ),
        }

    internal_excluded = 0
    novel: list[dict[str, Any]] = []
    for bucket in recent_buckets:
        dst = bucket.get("key")
        if dst is None:
            continue
        if is_internal_ip(str(dst), settings):
            internal_excluded += 1
            continue
        if dst in baseline_keys:
            continue

        sources = [b.get("key") for b in ((bucket.get("srcs") or {}).get("buckets") or [])]
        sample_hits = ((bucket.get("samples") or {}).get("hits") or {}).get("hits") or []

        novel.append(
            {
                "dst": dst,
                "recent_events": int(bucket.get("doc_count") or 0),
                "first_seen_ts": _min_agg_timestamp(bucket.get("first_seen")),
                "sources": sources,
                "sample_ids": _sample_ids(sample_hits, _MAX_FIRST_SEEN_SAMPLE_IDS),
            }
        )

    novel.sort(key=lambda n: n["recent_events"], reverse=True)
    items = novel[:_MAX_FIRST_SEEN_ITEMS]

    # This envelope is deliberately non-uniform with the other three tools':
    # recent_/baseline_-prefixed keys instead of a shared field name, and no
    # top-level `thresholds` (first_seen's only "threshold" is baseline
    # membership, not a numeric cutoff worth echoing back). Don't "fix" it
    # into matching beacon_profile/dns_entropy_scan/dcerpc_histogram's shape
    # without checking every caller/test first.
    return {
        "recent_minutes": recent_minutes,
        "baseline_days": baseline_days,
        "dataset": dataset,
        "recent_destinations": recent_destinations,
        "baseline_destinations": baseline_destinations,
        "internal_excluded": internal_excluded,
        "baseline_empty": False,
        "baseline_truncated": baseline_truncated,
        "recent_truncated": recent_truncated,
        "items": items,
        "summary": _first_seen_summary(
            items,
            recent_destinations=recent_destinations,
            baseline_destinations=baseline_destinations,
            internal_excluded=internal_excluded,
            baseline_truncated=baseline_truncated,
        ),
    }


__all__ = ["beacon_profile", "dcerpc_histogram", "dns_entropy_scan", "first_seen"]
