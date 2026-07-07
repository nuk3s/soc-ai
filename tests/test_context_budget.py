"""Proactive context budgeting: window discovery, estimation, enriched-context trim."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from pydantic import SecretStr
from soc_ai.agent import context_budget as cb
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext


def _alert(i: int = 0) -> SoAlert:
    return SoAlert(
        id=f"ev{i}",
        rule_name="ET SCAN thing",
        source_ip="10.0.0.41",
        destination_ip="10.0.0.1",
        message="x" * 400,  # bulk so trimming has something to reclaim
    )


def _enriched(n_host_events: int = 30, n_user_events: int = 10) -> EnrichedAlertContext:
    return EnrichedAlertContext(
        alert=_alert(),
        host_events=[_alert(i) for i in range(n_host_events)],
        user_events=[_alert(1000 + i) for i in range(n_user_events)],
    )


def test_estimate_tokens_is_chars_over_four() -> None:
    assert cb.estimate_tokens("x" * 400) == 100
    assert cb.estimate_tokens("") == 1  # never zero


def test_input_budget_fraction() -> None:
    assert cb.input_budget_tokens(None) is None
    assert cb.input_budget_tokens(0) is None
    assert cb.input_budget_tokens(100_000) == 75_000


def test_trim_noop_when_within_budget() -> None:
    enriched = _enriched(3, 2)
    js, note = cb.trim_enriched_for_budget(enriched, 10_000_000)
    assert note is None
    assert js == enriched.model_dump_json()


def test_trim_noop_when_window_unknown() -> None:
    enriched = _enriched(30, 10)
    js, note = cb.trim_enriched_for_budget(enriched, None)
    assert note is None
    assert js == enriched.model_dump_json()


def test_trim_drops_oldest_pivot_events_until_fit() -> None:
    enriched = _enriched(30, 10)
    full_tokens = cb.estimate_tokens(enriched.model_dump_json())
    budget = full_tokens // 2
    js, note = cb.trim_enriched_for_budget(enriched, budget)
    assert note is not None
    assert cb.estimate_tokens(js) <= budget
    # The longest pivot (host_events) lost the most; nothing below the floor.
    assert note["dropped_events"]["host_events"] > 0
    assert "host_events -" in note["detail"]
    # The original object is untouched (trim works on a deep copy).
    assert len(enriched.host_events) == 30
    # Newest-first order: the SURVIVORS are the head of the list.
    import json

    kept = json.loads(js)["host_events"]
    assert [e["id"] for e in kept] == [f"ev{i}" for i in range(len(kept))]


def test_trim_keeps_pivot_floor_and_returns_minimal_shape() -> None:
    """An absurdly small budget can't trim below the per-pivot floor — the
    minimal shape is returned and the reactive guard backstops."""
    enriched = _enriched(6, 6)
    js, note = cb.trim_enriched_for_budget(enriched, 1)
    assert note is not None
    import json

    doc = json.loads(js)
    assert len(doc["host_events"]) == 2
    assert len(doc["user_events"]) == 2


def _settings(**kw: Any) -> SimpleNamespace:
    base = {
        "litellm_base_url": "http://gw:4000",
        "litellm_api_key": SecretStr("sk-x"),
        "litellm_verify_ssl": True,
        "analyst_model": "deepseek-v4-flash",
        "model_context_window_tokens": 0,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_resolve_window_override_wins() -> None:
    s = _settings(model_context_window_tokens=131072)
    with patch.object(cb, "_fetch_window", AsyncMock(return_value=999)) as m:
        assert asyncio.run(cb.resolve_model_window(s)) == 131072
    m.assert_not_awaited()


def test_resolve_window_discovers_and_caches() -> None:
    cb._window_cache.clear()
    s = _settings()
    fetch = AsyncMock(return_value=1_000_000)
    with patch.object(cb, "_fetch_window", fetch):
        assert asyncio.run(cb.resolve_model_window(s)) == 1_000_000
        assert asyncio.run(cb.resolve_model_window(s)) == 1_000_000  # cached
    assert fetch.await_count == 1
    cb._window_cache.clear()


def test_fetch_window_parses_model_info() -> None:
    class _Resp:
        status_code = 200

        @staticmethod
        def json() -> dict[str, Any]:
            return {
                "data": [
                    {"model_name": "other", "model_info": {"max_input_tokens": 5}},
                    {
                        "model_name": "deepseek-v4-flash",
                        "model_info": {"max_input_tokens": 1_000_000},
                    },
                ]
            }

    client = AsyncMock()
    client.get = AsyncMock(return_value=_Resp())
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    s = _settings()
    with patch.object(cb.httpx, "AsyncClient", return_value=client):
        win = asyncio.run(cb._fetch_window(s, "http://gw:4000", "deepseek-v4-flash"))
    assert win == 1_000_000
    # Bearer header sent, path correct
    assert client.get.await_args.args[0] == "http://gw:4000/model/info"


def test_fetch_window_fail_soft() -> None:
    s = _settings()
    with patch.object(cb.httpx, "AsyncClient", side_effect=RuntimeError("boom")):
        assert asyncio.run(cb._fetch_window(s, "http://gw:4000", "m")) is None
