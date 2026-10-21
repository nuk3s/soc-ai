"""Whether the anchor document of a promotion is a Security Onion alert.

The anchor rule refuses a Security Onion write on a document that a promoted
finding or lead uses as its anchor. An anchor is often plain telemetry: a Zeek
or host-log record with no alert behind it. A later run on the same document
must not turn that record into a write. The rule refused real alerts too. On
the range lead 17 cites the Suricata alert WMIExec, and "Escalate to case" on
the investigation of that alert was refused (dogfood 2026-10-21).

The rule now refuses only an anchor that is not an alert. A document is an
alert when the alert feed holds it: the filter of the Alerts page and of the
doctor's "alerts feed filter" row (:func:`alerts_query.feed_sources`), with no
time window. :func:`alert_status` answers a batch of ids with one grid search,
so a list page pays one search, and the answers stay in a cache per app.

A grid failure answers :data:`UNKNOWN`, and the rule refuses an unknown anchor
with its own sentence. A failure is not a "no": the grid can hold the alert.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from typing import Any

from soc_ai.webui import alerts_query

_LOGGER = logging.getLogger(__name__)

# The answers of :func:`alert_status`.
ALERT = "alert"
NOT_ALERT = "not_alert"
UNKNOWN = "unknown"

# How long an answer stands. A document does not move in or out of the feed,
# so the bound is for memory and for a filter change.
ANSWER_TTL_S = 6 * 3600.0
# How long a failed read stands. The needs-you count polls every 15 seconds
# from each tab. A sick grid then gets one read in this time, from all tabs.
FAILURE_HOLD_S = 15.0
CACHE_SIZE = 4096
# The most ids one search asks about. The pending-action scan of the needs-you
# count reads at most 500 runs, so one search covers it.
BATCH_SIZE = 500

_Key = tuple[str, str]


class AnchorAlertCache:
    """The answers of :func:`alert_status`, by feed filter and document id.

    A bounded LRU. An answer stands for :data:`ANSWER_TTL_S`, an unknown for
    :data:`FAILURE_HOLD_S`.
    """

    def __init__(self, *, size: int = CACHE_SIZE, clock: Callable[[], float] = time.monotonic):
        self.size = size
        self.clock = clock
        self._entries: OrderedDict[_Key, tuple[float, str]] = OrderedDict()

    def get(self, key: _Key) -> str | None:
        hit = self._entries.get(key)
        if hit is None:
            return None
        at, status = hit
        ttl = FAILURE_HOLD_S if status == UNKNOWN else ANSWER_TTL_S
        if self.clock() - at > ttl:
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return status

    def put(self, key: _Key, status: str) -> None:
        self._entries[key] = (self.clock(), status)
        self._entries.move_to_end(key)
        while len(self._entries) > self.size:
            self._entries.popitem(last=False)


def _cache(state: Any) -> AnchorAlertCache:
    """The cache of the app, made on first use."""
    cache = getattr(state, "anchor_alert_cache", None)
    if not isinstance(cache, AnchorAlertCache):
        cache = AnchorAlertCache()
        state.anchor_alert_cache = cache
    return cache


def _feed_key(settings: Any) -> str:
    """The identity of the feed: the index and the sources it reads.

    A filter change in Settings starts new answers, and the old ones age out.
    """
    return json.dumps(
        [settings.events_index_pattern, alerts_query.feed_sources(settings)], sort_keys=True
    )


async def _read(state: Any, ids: list[str]) -> dict[str, str]:
    """One grid search for ``ids``. Every id is UNKNOWN when the read fails."""
    settings = state.settings
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            result = await state.elastic.search(
                settings.events_index_pattern,
                alerts_query.feed_ids_query(settings, ids),
                size=len(ids),
                source=False,
                # A shard that failed can hold the alert. A partial read is
                # "could not see", never "not an alert".
                require_complete=True,
            )
    except Exception:
        _LOGGER.warning("anchor check: the grid did not answer for %d ids", len(ids), exc_info=True)
        return dict.fromkeys(ids, UNKNOWN)
    found = {str(hit.get("_id")) for hit in result.hits}
    return {i: ALERT if i in found else NOT_ALERT for i in ids}


async def alert_status(state: Any, ids: Iterable[str]) -> dict[str, str]:
    """Each id: :data:`ALERT`, :data:`NOT_ALERT` or :data:`UNKNOWN`.

    ``state`` is the app state: it holds the grid client, the settings and
    the cache. The ids the cache does not hold cost one grid search for each
    :data:`BATCH_SIZE` ids. A blank id gets no answer.
    """
    wanted = list(dict.fromkeys(i for i in ids if i))
    if not wanted:
        return {}
    cache = _cache(state)
    feed = _feed_key(state.settings)
    out: dict[str, str] = {}
    missing: list[str] = []
    for doc_id in wanted:
        status = cache.get((feed, doc_id))
        if status is None:
            missing.append(doc_id)
        else:
            out[doc_id] = status
    for start in range(0, len(missing), BATCH_SIZE):
        answers = await _read(state, missing[start : start + BATCH_SIZE])
        for doc_id, status in answers.items():
            cache.put((feed, doc_id), status)
        out.update(answers)
    return out
