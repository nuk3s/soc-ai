"""Diverse-alert sampler for the eval batch runner.

Walks an OQL query result and yields up to ``n`` alert IDs whose
diversity-key tuples are all distinct. The default diversity key is
``("rule.name", "host.name")`` so the batch runner doesn't end up
critiquing 1000 instances of the same rule firing on the same host.

Lazy by design: yields alert IDs as the consumer pulls them, so the
batch loop's bounded-concurrency scheduler can call ``harness.run``
on each ID without buffering the whole list. The OQL query itself is
issued once with ``max_results=10_000`` (the OQL grammar's hard cap)
— sufficient for ``n`` up to a few thousand at this lab's scale. If
the operator needs more, they can widen ``time_range_minutes`` or
relax the diversity tuple.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.query_events import query_events_oql

_LOGGER = logging.getLogger(__name__)

DEFAULT_DIVERSITY_KEYS: tuple[str, ...] = ("rule.name", "host.name")

# Hard ceiling on hits scanned per request to the OQL execution path.
# 10_000 is the OQL validator's `_HARD_MAX_RESULTS`; larger values are
# rejected.
_OQL_MAX_RESULTS = 10_000


def _read_dotted(source: dict[str, Any], dotted: str) -> str | None:
    """Read a dotted-path field off an ES `_source` dict.

    Supports both flat keys (``"rule.name": "..."`` — common in SO's
    schema where keys are escaped dots) AND nested objects
    (``rule.name`` → ``source["rule"]["name"]``). Tries flat first
    since SO indexes events that way.
    """
    if dotted in source:
        v = source[dotted]
        return str(v) if v is not None else None
    cur: object = source
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    if cur is None:
        return None
    if isinstance(cur, list) and cur:
        cur = cur[0]
    return str(cur)


def _diversity_tuple(source: dict[str, Any], keys: tuple[str, ...]) -> tuple[str, ...]:
    """Build the diversity tuple for a hit's ``_source``.

    Missing fields don't break diversity — they hash the full source
    so unkeyed alerts cluster together (a single representative per
    "missing key" cluster gets through). Use a short hash so debugging
    prints stay readable.
    """
    out: list[str] = []
    has_any = False
    for k in keys:
        v = _read_dotted(source, k)
        if v is None:
            continue
        has_any = True
        out.append(f"{k}={v}")
    if has_any:
        return tuple(out)
    blob = json.dumps(source, sort_keys=True, default=str).encode("utf-8")
    return (f"unkeyed:{hashlib.sha256(blob).hexdigest()[:16]}",)


async def sample_diverse_alerts(
    oql: str,
    *,
    n: int,
    settings: Settings,
    elastic: ElasticClient,
    diversity_keys: tuple[str, ...] = DEFAULT_DIVERSITY_KEYS,
    time_range_minutes: int = 10_080,
    max_rule_share: float = 0.25,
) -> AsyncIterator[str]:
    """Yield up to ``n`` alert IDs whose diversity tuples are distinct.

    Args:
        oql: query string. Must return alerts (not aggregation buckets).
            E.g. ``event.kind:alert AND _index:*so-detection*``.
        n: target number of distinct-tuple alert IDs to yield.
        settings: app settings (passed to ``query_events_oql``).
        elastic: shared ES client.
        diversity_keys: tuple of dotted field paths used to dedupe.
            Default: ``("rule.name", "host.name")``.
        time_range_minutes: window for the OQL ``@timestamp`` filter.
            Default: 7 days. Wider windows scan more hits but increase
            the chance of finding ``n`` diverse alerts.
        max_rule_share: fraction of the batch any single rule.name can
            occupy. Default: 0.25 (25%). Soft cap — if the batch can
            only be filled by exceeding the cap, skipped candidates are
            added in a second pass. Prevents a single noisy rule from
            saturating agreement_rate measurement.

    Yields:
        Alert IDs (ES ``_id``), one per distinct diversity tuple, in
        the order encountered. Stops early if the OQL result stream
        is exhausted before ``n`` distinct tuples are collected.

    The caller can stop pulling at any time; this function does not
    over-fetch.
    """
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}")

    result = await query_events_oql(
        query=oql,
        elastic=elastic,
        settings=settings,
        time_range_minutes=time_range_minutes,
        max_results=_OQL_MAX_RESULTS,
    )
    hits = result.hits
    _LOGGER.info(
        "sampler: OQL returned %d hits (total=%d); seeking %d diverse alerts",
        len(hits),
        result.total,
        n,
    )

    # Per-rule cap: each rule.name is allowed at most this many rows.
    # Hard floor of 1 so every rule gets at least one representative.
    per_rule_cap = max(1, int(n * max_rule_share))

    seen: set[tuple[str, ...]] = set()
    per_rule_counts: dict[str, int] = {}
    # cap_overflow_hits: raw hit dicts skipped due to per-rule cap in the
    # first pass, held for a soft-fail second pass if the batch runs short.
    cap_overflow_hits: list[dict[str, Any]] = []
    yielded = 0

    for hit in hits:
        if yielded >= n:
            break
        alert_id = hit.get("_id")
        if not alert_id:
            continue
        source = hit.get("_source") or {}
        key = _diversity_tuple(source, diversity_keys)
        if key in seen:
            continue
        rule_name = _read_dotted(source, "rule.name") or ""
        if per_rule_counts.get(rule_name, 0) >= per_rule_cap:
            # Defer to second pass — don't mark seen so diversity tracking
            # stays accurate for the second pass too.
            cap_overflow_hits.append(hit)
            continue
        seen.add(key)
        per_rule_counts[rule_name] = per_rule_counts.get(rule_name, 0) + 1
        yielded += 1
        yield alert_id

    # Second pass: fill remaining slots from cap-overflow candidates so the
    # cap is soft (no under-fill). Diversity deduplication still applies.
    if yielded < n and cap_overflow_hits:
        _LOGGER.warning(
            "sampler: per-rule cap (%d) reached; filling remaining %d "
            "slot(s) from %d overflow candidates",
            per_rule_cap,
            n - yielded,
            len(cap_overflow_hits),
        )
        for hit in cap_overflow_hits:
            if yielded >= n:
                break
            alert_id = hit.get("_id")
            if not alert_id:
                continue
            source = hit.get("_source") or {}
            key = _diversity_tuple(source, diversity_keys)
            if key in seen:
                continue
            seen.add(key)
            yielded += 1
            yield alert_id

    if yielded < n:
        _LOGGER.warning(
            "sampler: requested %d diverse alerts but only found %d "
            "(scanned %d hits, %d distinct tuples). Widen "
            "time_range_minutes or relax diversity_keys.",
            n,
            yielded,
            len(hits),
            len(seen),
        )
