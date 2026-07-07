"""Proactive input-size accounting for the analyst model.

The reactive guard already exists — a ContextWindowExceeded from the gateway is
classified and hinted by ``_hint_for`` — but by then the investigation has
burned a round-trip and landed a fallback verdict. This module prevents the
dominant overflow case up front: an enriched alert context whose pivot event
lists are so large that the FIRST synth call cannot fit the model's window
(busy hosts can pivot to hundreds of related events).

Window discovery: LiteLLM publishes per-route limits on ``GET /model/info``
(``model_info.max_input_tokens`` / ``max_tokens``). We resolve the analyst
model's window from there, cached with a TTL, fail-soft to "unknown" (no
trimming). ``settings.model_context_window_tokens`` > 0 overrides discovery.

Token estimation is a chars/4 heuristic — deliberately tokenizer-free (the
gateway may serve any model family) and conservative for JSON-ish English.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

_LOGGER = logging.getLogger(__name__)

_CHARS_PER_TOKEN = 4
# Leave headroom for the system prompt, the materialized-evidence section, the
# tool results a loop run accumulates, and the response itself.
_INPUT_BUDGET_FRACTION = 0.75
# Never trim a pivot below this many events — the synth needs SOME correlation
# signal, and the reactive guard still backstops a pathological single event.
_MIN_EVENTS_PER_PIVOT = 2

_PIVOT_FIELDS = (
    "community_id_events",
    "host_events",
    "user_events",
    "process_events",
    "file_events",
)

_WINDOW_CACHE_TTL_S = 300.0
# (base_url, model) -> (resolved_window_or_None, monotonic_deadline)
_window_cache: dict[tuple[str, str], tuple[int | None, float]] = {}


def estimate_tokens(text: str) -> int:
    """Cheap, tokenizer-free token estimate (chars/4)."""
    return max(1, len(text) // _CHARS_PER_TOKEN)


def input_budget_tokens(window: int | None) -> int | None:
    """The share of a model window we allow the enriched context to occupy."""
    if not window or window <= 0:
        return None
    return int(window * _INPUT_BUDGET_FRACTION)


async def resolve_model_window(settings: Any) -> int | None:
    """The analyst model's input window in tokens, or None when unknown.

    ``settings.model_context_window_tokens`` > 0 wins outright. Otherwise ask
    the LiteLLM gateway's ``/model/info`` (TTL-cached); any failure returns
    None — accounting simply stays off, never blocks an investigation.
    """
    override = int(getattr(settings, "model_context_window_tokens", 0) or 0)
    if override > 0:
        return override

    base = str(settings.litellm_base_url).rstrip("/")
    model = str(getattr(settings, "analyst_model", "") or "")
    if not model:
        return None
    key = (base, model)
    cached = _window_cache.get(key)
    now = time.monotonic()
    if cached is not None and now < cached[1]:
        return cached[0]

    window = await _fetch_window(settings, base, model)
    _window_cache[key] = (window, now + _WINDOW_CACHE_TTL_S)
    return window


async def _fetch_window(settings: Any, base: str, model: str) -> int | None:
    api_key = ""
    secret = getattr(settings, "litellm_api_key", None)
    if secret is not None:
        api_key = secret.get_secret_value()
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    verify = bool(getattr(settings, "litellm_verify_ssl", True))
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=verify) as client:
            resp = await client.get(f"{base}/model/info", headers=headers)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception:  # discovery is best-effort — never fail an investigation
        return None
    rows = data.get("data") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return None
    for row in rows:
        if not isinstance(row, dict) or row.get("model_name") != model:
            continue
        info = row.get("model_info") or {}
        for field in ("max_input_tokens", "max_tokens"):
            val = info.get(field)
            if isinstance(val, (int, float)) and val > 0:
                return int(val)
    return None


def trim_enriched_for_budget(
    enriched: Any, budget_tokens: int | None
) -> tuple[str, dict[str, Any] | None]:
    """Serialize *enriched* (an ``EnrichedAlertContext``), trimming pivot event
    lists tail-first until the JSON fits the token budget.

    Pivots are trimmed round-robin from the longest, keeping at least
    ``_MIN_EVENTS_PER_PIVOT`` each (events arrive newest-first, so the tail is
    the oldest / least relevant). Returns ``(json, note)`` where ``note`` is a
    ``context_trimmed`` event payload describing what was dropped, or None when
    nothing was trimmed. If the minimal shape still exceeds the budget it is
    returned anyway — the reactive ContextWindowExceeded classifier backstops.
    """
    js = enriched.model_dump_json()
    if budget_tokens is None or estimate_tokens(js) <= budget_tokens:
        return js, None

    work = enriched.model_copy(deep=True)
    original_counts = {f: len(getattr(work, f, []) or []) for f in _PIVOT_FIELDS}
    while estimate_tokens(js := work.model_dump_json()) > budget_tokens:
        # Longest pivot list still above the floor loses its last (oldest) event.
        longest = max(
            _PIVOT_FIELDS,
            key=lambda f: len(getattr(work, f, []) or []),
        )
        events = list(getattr(work, longest, []) or [])
        if len(events) <= _MIN_EVENTS_PER_PIVOT:
            break  # nothing left to trim — return the minimal shape
        setattr(work, longest, events[:-1])

    dropped = {
        f: original_counts[f] - len(getattr(work, f, []) or [])
        for f in _PIVOT_FIELDS
        if original_counts[f] - len(getattr(work, f, []) or []) > 0
    }
    if not dropped:
        return js, None
    note = {
        "budget_tokens": budget_tokens,
        "estimated_tokens": estimate_tokens(js),
        "dropped_events": dropped,
        "detail": (
            "Enriched context exceeded the analyst model's input budget; the "
            "oldest related events were dropped per pivot: "
            + ", ".join(f"{f} -{n}" for f, n in sorted(dropped.items()))
        ),
    }
    return js, note
