"""In-memory enrichment cache for the rule-class fast-path gate.

The fast-path classifier (``soc_ai/agent/classifier.py``)
fast-paths any ``informational_visibility + severity_label==low`` alert
regardless of whether the destination IP is internal or external. Review
flagged this as a risk: "ET INFO Newly Registered Domain" or
"ET INFO External IP Lookup" could fast-path through despite being
potential early-C2 indicators.

This module provides a small LRU cache the classifier consults: fast-path
eligibility for alerts with an external destination requires that IP to
have been enriched at least once before (i.e. we've seen and verdicted
this IP previously in the batch / process lifetime). First-encounter
external IPs route to the full pipeline at least once to establish a
baseline.

The cache is intentionally simple and process-local. Two reasons:

- **Process-local**: persistence across restarts isn't a goal — fresh
  processes should treat every IP as first-encounter and route to the
  full pipeline (defensive). Persisting across restarts would risk
  promoting stale verdicts.
- **Bounded**: capacity defaults to 500 entries. The lab grid sees
  thousands of distinct destination IPs per day; we don't want this to
  grow unboundedly.

The cache value is the most recent ``EnrichmentResult.findings`` summary
so the orchestrator can short-circuit a redundant call when the same IP
shows up again within the same process.
"""

from __future__ import annotations

from collections import OrderedDict
from threading import RLock
from typing import Any


class EnrichmentCache:
    """Simple LRU cache keyed by indicator string (e.g. IP, domain).

    Not thread-safe by default; the orchestrator runs
    investigations concurrently via asyncio, so use the ``RLock`` to
    keep get/put atomic. The lock is uncontended in the common path
    (cache hits are reads only).
    """

    def __init__(self, capacity: int = 500) -> None:
        self._capacity = capacity
        self._cache: OrderedDict[str, Any] = OrderedDict()
        self._lock = RLock()
        self.hits = 0
        self.misses = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    def contains(self, key: str) -> bool:
        """Membership check that refreshes LRU recency on a hit.

        Moves the entry to most-recent when found so that probing an
        indicator's presence (the fast-path eligibility gate) keeps it
        alive across subsequent inserts.  This matches ``get``'s
        recency-bump semantics.

        Note: ``contains`` and ``put`` are separately locked, not atomic.
        A theoretical cross-coroutine contains→put race exists where two
        callers could each see a miss and both do a put. At capacity=500
        with lab load this race is harmless — the second put simply
        overwrites the first with the same value. An atomic check-and-mark
        is YAGNI here.
        """
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return True
            return False

    def get(self, key: str) -> Any | None:
        """Fetch + bump-to-most-recent. None on miss."""
        with self._lock:
            if key not in self._cache:
                self.misses += 1
                return None
            self.hits += 1
            value = self._cache.pop(key)
            self._cache[key] = value
            return value

    def put(self, key: str, value: Any) -> None:
        """Insert or refresh. Evicts least-recent entry when over capacity."""
        with self._lock:
            if key in self._cache:
                self._cache.pop(key)
            self._cache[key] = value
            while len(self._cache) > self._capacity:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0


_GLOBAL_CACHE: EnrichmentCache | None = None


def get_global_cache() -> EnrichmentCache:
    """Return the process-wide singleton cache.

    Lazy-initialized so tests can replace it via ``reset_global_cache``
    without import-order gymnastics.
    """
    global _GLOBAL_CACHE  # noqa: PLW0603 - module-level singleton is intentional
    if _GLOBAL_CACHE is None:
        _GLOBAL_CACHE = EnrichmentCache()
    return _GLOBAL_CACHE


def reset_global_cache() -> None:
    """Drop the singleton (test hook)."""
    global _GLOBAL_CACHE  # noqa: PLW0603 - module-level singleton is intentional
    _GLOBAL_CACHE = None


__all__ = [
    "EnrichmentCache",
    "get_global_cache",
    "reset_global_cache",
]
