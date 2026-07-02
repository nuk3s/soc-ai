"""Tests for the primary-path gateway retry transport."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from soc_ai.agent._gateway_retry import RetryingAsyncTransport, _parse_retry_after


class _ScriptedTransport(httpx.AsyncBaseTransport):
    """Returns a scripted sequence of status codes (or raises), one per call."""

    def __init__(self, statuses: list[Any]) -> None:
        self._statuses = list(statuses)
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        item = self._statuses.pop(0)
        if isinstance(item, Exception):
            raise item
        return httpx.Response(item, request=request, content=b"{}")


@pytest.mark.asyncio
async def test_retries_transient_5xx_then_succeeds() -> None:
    inner = _ScriptedTransport([502, 503, 200])
    t = RetryingAsyncTransport(max_retries=5, base_delay_s=0.0, max_backoff_s=0.0, inner=inner)
    resp = await t.handle_async_request(httpx.Request("POST", "https://gw/v1/chat"))
    assert resp.status_code == 200
    assert inner.calls == 3  # 2 retries + success


@pytest.mark.asyncio
async def test_retries_transport_errors_then_succeeds() -> None:
    inner = _ScriptedTransport([httpx.ConnectError("boom"), 200])
    t = RetryingAsyncTransport(max_retries=3, base_delay_s=0.0, max_backoff_s=0.0, inner=inner)
    resp = await t.handle_async_request(httpx.Request("POST", "https://gw/v1/chat"))
    assert resp.status_code == 200
    assert inner.calls == 2


@pytest.mark.asyncio
async def test_terminal_4xx_not_retried() -> None:
    inner = _ScriptedTransport([401, 200])
    t = RetryingAsyncTransport(max_retries=5, base_delay_s=0.0, max_backoff_s=0.0, inner=inner)
    resp = await t.handle_async_request(httpx.Request("POST", "https://gw/v1/chat"))
    assert resp.status_code == 401  # returned immediately, no retry
    assert inner.calls == 1


@pytest.mark.asyncio
async def test_exhausts_retries_and_returns_last_5xx() -> None:
    inner = _ScriptedTransport([502, 502, 502])
    t = RetryingAsyncTransport(max_retries=2, base_delay_s=0.0, max_backoff_s=0.0, inner=inner)
    resp = await t.handle_async_request(httpx.Request("POST", "https://gw/v1/chat"))
    assert resp.status_code == 502  # gave up after 2 retries (3 attempts)
    assert inner.calls == 3


@pytest.mark.asyncio
async def test_exhausts_retries_and_raises_last_transport_error() -> None:
    inner = _ScriptedTransport([httpx.ReadError("x"), httpx.ReadError("y")])
    t = RetryingAsyncTransport(max_retries=1, base_delay_s=0.0, max_backoff_s=0.0, inner=inner)
    with pytest.raises(httpx.ReadError):
        await t.handle_async_request(httpx.Request("POST", "https://gw/v1/chat"))
    assert inner.calls == 2


def test_parse_retry_after() -> None:
    assert _parse_retry_after("2.5") == 2.5
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT") is None  # HTTP-date ignored
    assert _parse_retry_after("9999") == 30.0  # clamped
