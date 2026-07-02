"""A retrying httpx transport for the LiteLLM gateway (primary model path).

The Oracle client (:mod:`soc_ai.oracle.client`) already wraps its calls in an
exponential-backoff retry with a retryable/terminal split. The PRIMARY model path
(investigator / synthesizer / hunt / chat) runs inside pydantic-ai, so we can't
wrap each call the same way — but we CAN make the underlying HTTP transport
resilient, which covers every primary-path call transparently.

This transport retries transient gateway failures — HTTP 429/502/503/504 and
connection/read/timeout transport errors — with exponential backoff + jitter,
honoring a ``Retry-After`` header when present. Terminal 4xx (auth / bad request)
and any 2xx/3xx pass straight through. It is the single retry authority for the
primary path, so the ``AsyncOpenAI`` client is built with ``max_retries=0``.
"""

from __future__ import annotations

import asyncio
import logging
import random

import httpx

_LOGGER = logging.getLogger(__name__)

# Transient gateway statuses worth retrying (mirrors the Oracle client's
# "5xx/transport = retryable, 4xx = terminal" split, plus 429 rate-limit).
_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})

_RETRYABLE_EXC = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadError,
    httpx.ReadTimeout,
    httpx.WriteError,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)


def _backoff_s(attempt: int, *, base: float, cap: float) -> float:
    """Exponential backoff with full jitter: random in [0, min(cap, base*2**attempt)]."""
    ceiling = min(cap, base * (2.0**attempt))
    return random.random() * ceiling  # noqa: S311 - jitter, not security-sensitive


class RetryingAsyncTransport(httpx.AsyncBaseTransport):
    """Wraps an ``httpx.AsyncHTTPTransport``, retrying transient gateway failures.

    ``max_retries`` is the number of RETRIES after the first attempt (so a value
    of 5 means up to 6 total attempts). Backoff grows 0.5, 1, 2, 4, capped at
    ``max_backoff_s`` and jittered; a ``Retry-After`` header (429) overrides it.
    """

    def __init__(
        self,
        *,
        max_retries: int,
        verify: bool = True,
        base_delay_s: float = 0.5,
        max_backoff_s: float = 8.0,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._inner = inner if inner is not None else httpx.AsyncHTTPTransport(verify=verify)
        self._max_retries = max(0, int(max_retries))
        self._base = base_delay_s
        self._cap = max_backoff_s

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        attempt = 0
        while True:
            try:
                response = await self._inner.handle_async_request(request)
            except _RETRYABLE_EXC as exc:
                if attempt >= self._max_retries:
                    raise
                delay = _backoff_s(attempt, base=self._base, cap=self._cap)
                _LOGGER.warning(
                    "gateway transport error (%s) — retry %d/%d in %.1fs",
                    type(exc).__name__,
                    attempt + 1,
                    self._max_retries,
                    delay,
                )
            else:
                if response.status_code not in _RETRYABLE_STATUS or attempt >= self._max_retries:
                    return response
                # Must release the connection before retrying the request.
                retry_after = _parse_retry_after(response.headers.get("retry-after"))
                await response.aclose()
                delay = retry_after if retry_after is not None else _backoff_s(
                    attempt, base=self._base, cap=self._cap
                )
                _LOGGER.warning(
                    "gateway returned %d — retry %d/%d in %.1fs",
                    response.status_code,
                    attempt + 1,
                    self._max_retries,
                    delay,
                )
            await asyncio.sleep(delay)
            attempt += 1


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a numeric ``Retry-After`` (seconds) header; ignore HTTP-date form."""
    if not value:
        return None
    try:
        secs = float(value.strip())
    except (TypeError, ValueError):
        return None
    # Clamp to a sane bound so a hostile/huge value can't stall the run.
    return max(0.0, min(secs, 30.0))
