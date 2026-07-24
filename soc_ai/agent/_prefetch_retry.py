"""A bounded async retry wrapper around the Phase-A prefetch call.

:func:`soc_ai.tools.get_alert_context.get_enriched_alert_context` already rides
out a short retry budget INSIDE each individual pivot query, via
:class:`~soc_ai.so_client.elastic.ElasticClient`'s ``max_retries`` +
``retry_on_timeout`` + ``retry_on_status`` (``es_max_retries``, default 2).
That protects a single query from a momentary hiccup. It does not help when
the blip outlasts that budget (a restarting ES node, a few seconds of network
flap): the whole prefetch call raises straight through to
:func:`~soc_ai.agent.orchestrator.investigate`, which — unlike every
synthesis-phase failure — has no fallback report for a failed prefetch (no
evidence was ever gathered, so fabricating a verdict would be dishonest). The
run ends in a bare ``status=error`` row that today only a human noticing it
can recover from.

This module adds ONE more retry layer around the *whole call*, at the
orchestrator level, same spirit as :mod:`soc_ai.agent._gateway_retry` for the
model-gateway path but a plain async wrapper — ``get_enriched_alert_context``
isn't HTTP-shaped at this layer. It is deliberately narrow: only
transient-infra exceptions are retried. Everything else — most importantly
:class:`~soc_ai.errors.SoNotFoundError` (the alert genuinely doesn't exist —
retrying wastes the whole budget on a wall no amount of waiting moves) and any
validation error — propagates on the first attempt, so the caller's terminal
no-fabricated-verdict handler still fires immediately for a non-transient
failure.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable

from elastic_transport import TransportError

_LOGGER = logging.getLogger(__name__)

# elasticsearch-py's ConnectionTimeout is a TransportError subclass, so
# catching TransportError alone covers it too. ConnectionError is the plain
# Python / aiohttp-flavored connection-refused case the SO API client raises.
_RETRYABLE_EXC: tuple[type[BaseException], ...] = (ConnectionError, TransportError)


def _backoff_s(attempt: int, *, base: float, cap: float) -> float:
    """Exponential backoff with full jitter: random in [0, min(cap, base*2**attempt)]."""
    ceiling = min(cap, base * (2.0**attempt))
    return random.random() * ceiling  # noqa: S311 - jitter, not security-sensitive


async def retry_prefetch[T](
    fn: Callable[[], Awaitable[T]],
    *,
    max_retries: int,
    base_delay_s: float,
    max_backoff_s: float = 30.0,
) -> T:
    """Await ``fn()``, retrying a transient-infra exception up to ``max_retries`` times.

    ``max_retries`` counts RETRIES after the first attempt (2 ⇒ up to 3 total
    attempts). Any exception outside :data:`_RETRYABLE_EXC` — notably
    ``SoNotFoundError`` and validation errors — propagates immediately without
    consuming any of the retry budget.
    """
    attempt = 0
    while True:
        try:
            return await fn()
        except _RETRYABLE_EXC as exc:
            if attempt >= max_retries:
                raise
            delay = _backoff_s(attempt, base=base_delay_s, cap=max_backoff_s)
            _LOGGER.warning(
                "prefetch transient error (%s) — retry %d/%d in %.1fs",
                type(exc).__name__,
                attempt + 1,
                max_retries,
                delay,
            )
            await asyncio.sleep(delay)
            attempt += 1
