"""Tests for the ``host_summary`` read tool.

Core guarantee under test: a host whose HTTP User-Agent is a mobile-Safari
string (which contains ``like Mac OS X``) is identified as an **iPhone**, NOT a
Mac. That is the defect this tool exists to fix. Plus the robustness contract:
empty data → a clean no-observations result (not an exception); an ES error →
a clean error dict (not a raised exception).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.tools.host_summary import classify_user_agent, host_summary

# A real iPhone Safari User-Agent. Note the "like Mac OS X" — the naive substring
# match that caused the original "iPhone called a Mac" defect.
IPHONE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
)
MAC_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
ANDROID_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
)


def _make_elastic(
    settings: Settings, result: EsSearchResult | Exception
) -> tuple[ElasticClient, AsyncMock]:
    """Build an ElasticClient whose ``.search`` is mocked at the wrapper level.

    Patching ``ElasticClient.search`` (rather than the raw AsyncElasticsearch)
    lets the test hand back a typed ``EsSearchResult`` directly, or raise to
    exercise the error path.
    """
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
    if isinstance(result, Exception):
        client.search = AsyncMock(side_effect=result)  # type: ignore[method-assign]
    else:
        client.search = AsyncMock(return_value=result)  # type: ignore[method-assign]
    return client, fake_es


def _result(
    hits: list[dict[str, Any]],
    *,
    total: int | None = None,
    aggregations: dict[str, Any] | None = None,
) -> EsSearchResult:
    return EsSearchResult(
        total=total if total is not None else len(hits),
        took_ms=3,
        hits=[{"_id": f"e{i}", "_source": src} for i, src in enumerate(hits)],
        aggregations=aggregations,
    )


# ---------------------------------------------------------------------------
# Pure classifier — the heart of the iPhone-vs-Mac fix.
# ---------------------------------------------------------------------------


def test_classify_iphone_ua_is_iphone_not_mac() -> None:
    assert classify_user_agent(IPHONE_UA) == "iPhone"


def test_classify_macintosh_ua_is_macos() -> None:
    assert classify_user_agent(MAC_UA) == "macOS"


def test_classify_android_beats_linux() -> None:
    # Android UAs contain "Linux" — Android must win.
    assert classify_user_agent(ANDROID_UA) == "Android"


def test_classify_ipad() -> None:
    ua = "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"
    assert classify_user_agent(ua) == "iPad"


def test_classify_windows() -> None:
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0"
    assert classify_user_agent(ua) == "Windows"


def test_classify_unknown_returns_none() -> None:
    assert classify_user_agent("curl/8.4.0") is None
    assert classify_user_agent("") is None


# ---------------------------------------------------------------------------
# host_summary — the iPhone-vs-Mac assertion end to end.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_host_summary_identifies_iphone_not_mac(settings_kratos: Settings) -> None:
    """The whole point: an iPhone UA must yield device_os_guess == 'iPhone',
    and the backing evidence string must be present (never a fabricated guess)."""
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "source.ip": "10.20.30.50",
            "destination.ip": "93.184.216.34",
            "destination.port": 443,
            "user_agent.original": IPHONE_UA,
        }
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.20.30.50", elastic=elastic, settings=settings_kratos)

    assert out["observations"] is True
    assert out["device_os_guess"] == "iPhone"
    assert out["device_os_guess"] != "macOS"
    # Evidence is load-bearing: the UA string must back the guess.
    ua_evidence = out["evidence"]["device_os_guess"]
    assert any("iPhone" in e and "iPhone OS 17_5" in e for e in ua_evidence)


@pytest.mark.asyncio
async def test_host_summary_legacy_zeek_user_agent_field(settings_kratos: Settings) -> None:
    """On an older SO / synth grid the UA lives under zeek.http.user_agent — the
    ECS-first resolver must still find it (and still say iPhone)."""
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "source.ip": "10.20.30.50",
            "destination.ip": "93.184.216.34",
            "zeek": {"http": {"user_agent": IPHONE_UA}},
        }
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.20.30.50", elastic=elastic, settings=settings_kratos)

    assert out["device_os_guess"] == "iPhone"


@pytest.mark.asyncio
async def test_host_summary_hostname_from_dhcp(settings_kratos: Settings) -> None:
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "source.ip": "10.20.30.50",
            "destination.ip": "10.20.30.1",
            "destination.port": 67,
            "zeek": {"dhcp": {"host_name": "demo-iphone"}},
            "user_agent.original": IPHONE_UA,
        }
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.20.30.50", elastic=elastic, settings=settings_kratos)

    assert out["hostname"] == "demo-iphone"
    assert "dhcp" in out["evidence"]["hostname"]


@pytest.mark.asyncio
async def test_host_summary_role_server_from_responder_port(settings_kratos: Settings) -> None:
    """Host that RESPONDS on 443 (is the destination) → server."""
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "event.dataset": "zeek.conn",
            "source.ip": "10.20.30.77",
            "destination.ip": "10.20.30.10",
            "destination.port": 443,
        }
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.20.30.10", elastic=elastic, settings=settings_kratos)

    assert out["role_guess"] == "server"


@pytest.mark.asyncio
async def test_host_summary_role_workstation_from_originator(settings_kratos: Settings) -> None:
    """Host that ORIGINATES to 443 (is the source) → workstation."""
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "event.dataset": "zeek.conn",
            "source.ip": "10.20.30.10",
            "destination.ip": "93.184.216.34",
            "destination.port": 443,
        }
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.20.30.10", elastic=elastic, settings=settings_kratos)

    assert out["role_guess"] == "workstation"


@pytest.mark.asyncio
async def test_host_summary_role_ignores_suricata_alert(settings_kratos: Settings) -> None:
    """A Suricata alert fired AT the host on 443 (host = destination) must not
    flip a workstation to 'server' — only zeek.conn records inform the role."""
    hits = [
        {  # inbound IDS alert against the host on 443 — ignored for role
            "@timestamp": "2026-06-27T10:00:00Z",
            "event.dataset": "suricata.alert",
            "source.ip": "45.9.0.1",
            "destination.ip": "10.20.30.10",
            "destination.port": 443,
        },
        {  # the host's real behaviour: originates out to 443 → workstation
            "@timestamp": "2026-06-27T10:01:00Z",
            "event.dataset": "zeek.conn",
            "source.ip": "10.20.30.10",
            "destination.ip": "1.1.1.1",
            "destination.port": 443,
        },
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.20.30.10", elastic=elastic, settings=settings_kratos)

    assert out["role_guess"] == "workstation"


@pytest.mark.asyncio
async def test_host_summary_aggregations_peers_ports_dns(settings_kratos: Settings) -> None:
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "source.ip": "10.20.30.50",
            "destination.ip": "8.8.8.8",
            "destination.port": 53,
            "dns": {"query": {"name": "example.com"}},
        },
        {
            "@timestamp": "2026-06-27T10:05:00Z",
            "source.ip": "10.20.30.50",
            "destination.ip": "8.8.8.8",
            "destination.port": 53,
            "dns": {"query": {"name": "example.com"}},
        },
    ]
    aggs = {
        "peers_src": {"buckets": [{"key": "10.20.30.50", "doc_count": 2}]},
        "peers_dst": {"buckets": [{"key": "8.8.8.8", "doc_count": 2}]},
        "resp_ports": {"ports": {"buckets": []}},
        "first_seen": {"value_as_string": "2026-06-27T10:00:00Z"},
        "last_seen": {"value_as_string": "2026-06-27T10:05:00Z"},
    }
    elastic, _ = _make_elastic(settings_kratos, _result(hits, total=2, aggregations=aggs))

    out = await host_summary("10.20.30.50", elastic=elastic, settings=settings_kratos)

    # Self (10.20.30.50) is dropped from peers; the real peer survives.
    peer_values = [p["value"] for p in out["top_peers"]]
    assert "8.8.8.8" in peer_values
    assert "10.20.30.50" not in peer_values
    dns_values = [d["value"] for d in out["top_dns"]]
    assert "example.com" in dns_values
    assert out["first_seen"] == "2026-06-27T10:00:00Z"
    assert out["last_seen"] == "2026-06-27T10:05:00Z"


# ---------------------------------------------------------------------------
# Robustness contract.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_host_summary_empty_data_is_clean_result(settings_kratos: Settings) -> None:
    """No observations → a clean structured result, NOT an exception."""
    elastic, _ = _make_elastic(settings_kratos, _result([], total=0))

    out = await host_summary("10.20.30.99", elastic=elastic, settings=settings_kratos)

    assert out["observations"] is False
    assert "no observations for 10.20.30.99" in out["summary"]
    assert out["hostname"] is None
    assert out["device_os_guess"] is None
    assert out["role_guess"] == "unknown"
    assert out["top_peers"] == []
    assert "error" not in out


@pytest.mark.asyncio
async def test_host_summary_es_error_is_clean_error_dict(settings_kratos: Settings) -> None:
    """An ES failure → a clean error dict the agent can read, NOT a raised exception."""
    elastic, _ = _make_elastic(settings_kratos, RuntimeError("cluster_block_exception"))

    out = await host_summary("10.20.30.50", elastic=elastic, settings=settings_kratos)

    assert out["error"] is True
    assert out["type"] == "RuntimeError"
    assert "cluster_block_exception" in out["message"]


@pytest.mark.asyncio
async def test_host_summary_invalid_ip_returns_error(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    out = await host_summary("not-an-ip", elastic=elastic, settings=settings_kratos)

    assert out["error"] is True
    assert "invalid IP" in out["message"]


@pytest.mark.asyncio
async def test_host_summary_centers_window_on_time_anchor(settings_kratos: Settings) -> None:
    """When a time_anchor is passed, the @timestamp filter is centered on it
    (so an old alert still finds evidence) — verify the query the tool built."""
    from datetime import UTC, datetime

    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured["query"] = query
        return _result([], total=0)

    elastic, _ = _make_elastic(settings_kratos, _result([], total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    anchor = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    await host_summary("10.20.30.50", elastic=elastic, settings=settings_kratos, time_anchor=anchor)

    time_filter = captured["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    # Anchored mode produces an explicit gte/lte straddling the anchor.
    assert "gte" in time_filter and "lte" in time_filter
    assert time_filter["gte"] < anchor.isoformat() < time_filter["lte"]
