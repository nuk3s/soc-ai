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
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

import httpx

_LOGGER = logging.getLogger(__name__)

# Which BACKEND actually served the most recent gateway call on this run.
#
# soc-ai asks LiteLLM for one alias (``analyst_model``) and the gateway may route
# that to a different deployment, or fall back to another one entirely, without
# changing anything the client can see: the response body's ``model`` field and
# pydantic-ai's ``ModelResponse.model_name`` both echo back the ALIAS. So a
# failure recorded against "the model" names what we asked for, not what ran —
# which is exactly why "the lower-tier fallback models fail more" was
# unfalsifiable from the error log.
#
# LiteLLM does report the truth, but only in response HEADERS, which pydantic-ai
# does not surface (``ModelResponse.provider_details`` carries just finish_reason
# and a timestamp). This transport is the one place soc-ai owns that sees them.
#
# The ContextVar holds a MUTABLE dict rather than a value: a ContextVar set
# inside a child task is invisible to its parent, but mutating a shared dict is
# visible everywhere the reference reached. That keeps attribution working
# regardless of how pydantic-ai schedules the request.
_ATTRIBUTION: ContextVar[dict[str, Any] | None] = ContextVar(
    "soc_ai_gateway_attribution", default=None
)

# LiteLLM response headers -> the key we record. `api_base` is the load-bearing
# one (it identifies the serving engine); `attempted_fallbacks` answers "did this
# request get demoted to another deployment?" directly.
_ATTRIBUTION_HEADERS = {
    "x-litellm-model-api-base": "api_base",
    "x-litellm-model-group": "model_group",
    "x-litellm-model-id": "deployment_id",
    "x-litellm-attempted-fallbacks": "attempted_fallbacks",
    "x-litellm-attempted-retries": "attempted_retries",
}


@contextmanager
def capture_backend_attribution() -> Iterator[dict[str, Any]]:
    """Collect which backend served the gateway calls made inside this block.

    Yields the sink dict; it is populated as calls complete, so read it AFTER the
    block's work (including from an exception handler — the last attempt's
    headers are already in there).
    """
    sink: dict[str, Any] = {}
    token = _ATTRIBUTION.set(sink)
    try:
        yield sink
    finally:
        _ATTRIBUTION.reset(token)


def _record_attribution(response: httpx.Response) -> None:
    """Stash the gateway's backend headers into the active sink (no-op if none).

    Fail-soft on purpose: attribution is diagnostics, and must never be able to
    break a model call that otherwise succeeded.
    """
    try:
        sink = _ATTRIBUTION.get()
        if sink is None:
            return
        for header, key in _ATTRIBUTION_HEADERS.items():
            value = response.headers.get(header)
            if value:
                sink[key] = value
    except Exception:  # pragma: no cover - diagnostics must never raise
        _LOGGER.debug("failed to record gateway attribution", exc_info=True)


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
                # Record on EVERY response, including the ones we go on to retry:
                # if the final attempt raises a transport error, the last headers
                # we saw are still the best attribution available.
                _record_attribution(response)
                if response.status_code not in _RETRYABLE_STATUS or attempt >= self._max_retries:
                    return response
                # Must release the connection before retrying the request.
                retry_after = _parse_retry_after(response.headers.get("retry-after"))
                await response.aclose()
                delay = (
                    retry_after
                    if retry_after is not None
                    else _backoff_s(attempt, base=self._base, cap=self._cap)
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
