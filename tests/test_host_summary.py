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


@pytest.mark.asyncio
async def test_top_dns_counts_name_the_sample_they_came_from(
    settings_kratos: Settings,
) -> None:
    """top_dns counts a 200-doc sample, top_peers counts the whole window.

    They used to arrive in the identical ``{value, count}`` shape side by side,
    so a host with 50000 events in the window handed the model "evil.example 12"
    as a full-window figure that was short by three orders of magnitude. The key
    now names its denominator, and the sample size travels with it.
    """
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
        "peers_dst": {"buckets": [{"key": "8.8.8.8", "doc_count": 50_000}]},
        "resp_ports": {"ports": {"buckets": []}},
        "first_seen": {"value_as_string": "2026-06-27T10:00:00Z"},
        "last_seen": {"value_as_string": "2026-06-27T10:05:00Z"},
    }
    elastic, _ = _make_elastic(settings_kratos, _result(hits, total=50_000, aggregations=aggs))

    out = await host_summary("10.20.30.50", elastic=elastic, settings=settings_kratos)

    entry = next(d for d in out["top_dns"] if d["value"] == "example.com")
    assert entry["count_in_sample"] == 2
    assert "count" not in entry
    assert out["top_dns_sample_size"] == 2
    # The full-window counts keep the plain key, because they really are one.
    assert next(p for p in out["top_peers"] if p["value"] == "8.8.8.8")["count"] == 50_000


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
async def test_host_summary_excessive_lookback_hours_returns_error(
    settings_kratos: Settings,
) -> None:
    """F53: an unbounded lookback_hours must be rejected before the ES call —
    alert-embedded text is prompt-injection surface and could otherwise steer
    the agent into a full-history scan against the live SO cluster."""
    elastic, _ = _make_elastic(settings_kratos, _result([]))

    out = await host_summary(
        "10.20.30.50", elastic=elastic, settings=settings_kratos, lookback_hours=876_000
    )

    assert out["error"] is True
    assert "lookback_hours" in out["message"]
    elastic.search.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_host_summary_centers_window_on_time_anchor(settings_kratos: Settings) -> None:
    """When a time_anchor is passed, the @timestamp filter is centered on it
    (so an old alert still finds evidence) — verify the query the tool built."""
    from datetime import UTC, datetime

    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        # First call only. With no observations the tool runs a second search,
        # the import-volume probe that tells "this grid never watched this
        # address" apart from "this address is only in a loaded capture", and
        # that query wraps this one rather than being it.
        captured.setdefault("query", query)
        return _result([], total=0)

    elastic, _ = _make_elastic(settings_kratos, _result([], total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    anchor = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    await host_summary("10.20.30.50", elastic=elastic, settings=settings_kratos, time_anchor=anchor)

    time_filter = captured["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    # Anchored mode produces an explicit gte/lte straddling the anchor.
    assert "gte" in time_filter and "lte" in time_filter
    assert time_filter["gte"] < anchor.isoformat() < time_filter["lte"]


# ---------------------------------------------------------------------------
# Telemetry-domain OS hint — the BPFDoor-vs-MacBook fix. A TLS-only host with no
# User-Agent must still get an OS from its Apple/Windows/Linux/Android telemetry.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_host_summary_tls_only_apple_dns_backfills_os_guess(
    settings_kratos: Settings,
) -> None:
    """A TLS-only host with NO User-Agent but Apple telemetry DNS → the os_hint
    becomes device_os_guess (basis telemetry-domains), with the matched domains
    as evidence. This is the case where device_os_guess was previously None and a
    'Linux backdoor' alert on a MacBook went unchallenged."""
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "source.ip": "192.0.2.15",
            "destination.ip": "17.253.5.202",
            "destination.port": 443,
            "dns": {"query": {"name": "gdmf.apple.com"}},
        },
        {
            "@timestamp": "2026-06-27T10:01:00Z",
            "source.ip": "192.0.2.15",
            "destination.ip": "17.253.5.203",
            "destination.port": 443,
            "dns": {"query": {"name": "gateway.icloud.com"}},
        },
        {
            "@timestamp": "2026-06-27T10:02:00Z",
            "source.ip": "192.0.2.15",
            "destination.ip": "17.253.5.204",
            "destination.port": 443,
            "dns": {"query": {"name": "_aaplcache._tcp.local"}},
        },
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("192.0.2.15", elastic=elastic, settings=settings_kratos)

    # No UA was present, so the telemetry hint BECOMES the device_os_guess.
    assert out["os_hint"] is not None
    assert out["os_hint"]["os"] == "macos"
    assert out["os_hint"]["confidence"] == "strong"
    assert out["os_hint"]["basis"] == "telemetry-domains"
    assert out["device_os_guess"] == "macos"
    # Evidence is load-bearing: the matched Apple domains must be visible.
    os_evidence = out["evidence"]["os_hint"]
    assert any("apple.com" in e or "icloud.com" in e or "aaplcache" in e for e in os_evidence)
    # And crucially — this is a MacBook, NEVER a Linux host.
    assert out["device_os_guess"] != "Linux"
    assert out["os_hint"]["os"] != "linux"


@pytest.mark.asyncio
async def test_host_summary_tls_only_apple_sni_backfills_os_guess(
    settings_kratos: Settings,
) -> None:
    """When the grid never sees plaintext DNS (DoH/upstream resolver) the TLS SNI
    server-name still carries the telemetry domain → os_hint from SNI alone."""
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "source.ip": "192.0.2.15",
            "destination.ip": "17.253.5.202",
            "destination.port": 443,
            "ssl": {"server_name": "gdmf.apple.com"},
        },
        {
            "@timestamp": "2026-06-27T10:01:00Z",
            "source.ip": "192.0.2.15",
            "destination.ip": "17.253.5.203",
            "destination.port": 443,
            "ssl": {"server_name": "gateway.icloud.com"},
        },
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("192.0.2.15", elastic=elastic, settings=settings_kratos)

    assert out["os_hint"] is not None
    assert out["os_hint"]["os"] == "apple"
    assert out["device_os_guess"] == "apple"
    assert out["os_hint"]["basis"] == "telemetry-domains"


@pytest.mark.asyncio
async def test_host_summary_ua_wins_over_conflicting_dns_hint(
    settings_kratos: Settings,
) -> None:
    """A host WITH a Windows UA but Apple telemetry DNS → the UA stays PRIMARY
    (device_os_guess == 'Windows'), and the conflict is NOTED, not silently
    resolved. A weak/other-family DNS hint never overwrites a UA signal."""
    windows_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0"
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "source.ip": "192.0.2.20",
            "destination.ip": "93.184.216.34",
            "destination.port": 443,
            "user_agent.original": windows_ua,
        },
        {
            "@timestamp": "2026-06-27T10:01:00Z",
            "source.ip": "192.0.2.20",
            "destination.ip": "17.253.5.202",
            "destination.port": 443,
            "dns": {"query": {"name": "gdmf.apple.com"}},
        },
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("192.0.2.20", elastic=elastic, settings=settings_kratos)

    # UA wins primary — existing device_os_guess consumers see the UA label.
    assert out["device_os_guess"] == "Windows"
    # The DNS hint is still surfaced, basis user-agent, with a noted conflict.
    assert out["os_hint"] is not None
    assert out["os_hint"]["os"] == "apple"
    assert out["os_hint"]["basis"] == "user-agent"
    assert "conflict" in out["os_hint"]
    assert "apple" in out["os_hint"]["conflict"]


@pytest.mark.asyncio
async def test_host_summary_ua_corroborated_by_dns_hint(settings_kratos: Settings) -> None:
    """An iPhone UA + Apple telemetry DNS → UA primary (device_os_guess ==
    'iPhone'), hint agrees, basis 'both', no conflict. Existing consumers see the
    unchanged 'iPhone' label."""
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "source.ip": "192.0.2.30",
            "destination.ip": "93.184.216.34",
            "destination.port": 443,
            "user_agent.original": IPHONE_UA,
        },
        {
            "@timestamp": "2026-06-27T10:01:00Z",
            "source.ip": "192.0.2.30",
            "destination.ip": "17.253.5.202",
            "destination.port": 443,
            "dns": {"query": {"name": "gateway.icloud.com"}},
        },
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("192.0.2.30", elastic=elastic, settings=settings_kratos)

    # The iPhone-vs-Mac fix still holds and is untouched by the hint.
    assert out["device_os_guess"] == "iPhone"
    assert out["os_hint"] is not None
    assert out["os_hint"]["os"] == "apple"
    assert out["os_hint"]["basis"] == "both"
    assert "conflict" not in out["os_hint"]


@pytest.mark.asyncio
async def test_host_summary_no_os_telemetry_leaves_os_hint_none(
    settings_kratos: Settings,
) -> None:
    """A host whose DNS is only non-OS services (no vendor telemetry) → os_hint
    None, and device_os_guess is whatever the UA said (here None). Never a Linux
    label invented from the absence of Apple/Windows/Android."""
    hits = [
        {
            "@timestamp": "2026-06-27T10:00:00Z",
            "source.ip": "192.0.2.40",
            "destination.ip": "1.1.1.1",
            "destination.port": 443,
            "dns": {"query": {"name": "drive-api.proton.me"}},
        },
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("192.0.2.40", elastic=elastic, settings=settings_kratos)

    assert out["os_hint"] is None
    assert out["device_os_guess"] is None
    assert "os_hint" not in out["evidence"]


@pytest.mark.asyncio
async def test_host_summary_os_hint_present_in_empty_result(settings_kratos: Settings) -> None:
    """The no-observations result carries os_hint: None for a stable shape."""
    elastic, _ = _make_elastic(settings_kratos, _result([], total=0))

    out = await host_summary("192.0.2.99", elastic=elastic, settings=settings_kratos)

    assert out["observations"] is False
    assert out["os_hint"] is None


# ---------------------------------------------------------------------------
# Sensor-shipped identity: a network-sensor document names the SHIPPER
#
# Found on the live attack range 2026-09-04. Two agentless Vulhub targets
# (10.1.10.41/.42) were both reported as "SR-router" — the range's Debian
# router, which is also the Zeek/Suricata sensor. Every document mentioning an
# agentless host is shipped BY the sensor, so its top-level host.name/host.hostname
# is the sensor's own. Reading it as the endpoint's name hands every agentless
# host on the segment its sensor's identity.
# ---------------------------------------------------------------------------

SENSOR_HITS: list[dict[str, Any]] = [
    {
        "@timestamp": "2026-09-04T10:00:00Z",
        "event.dataset": "zeek.conn",
        "source.ip": "10.1.10.41",
        "destination.ip": "10.1.10.21",
        "destination.port": 8161,
        "host.name": "SR-router",
        "host.hostname": "SR-router",
        "observer.name": "SR-router",
        "agent.name": "SR-router",
    }
]


@pytest.mark.asyncio
async def test_host_summary_does_not_borrow_the_network_sensors_name(
    settings_kratos: Settings,
) -> None:
    """An agentless host must not inherit the hostname of the sensor watching it."""
    elastic, _ = _make_elastic(settings_kratos, _result(SENSOR_HITS))

    out = await host_summary("10.1.10.41", elastic=elastic, settings=settings_kratos)

    assert out["hostname"] is None
    assert out["evidence"].get("hostname") is None


@pytest.mark.asyncio
async def test_host_summary_never_forges_dhcp_provenance_from_host_hostname(
    settings_kratos: Settings,
) -> None:
    """``host.hostname`` is ECS host identity, never a DHCP observation.

    It used to sit in the DHCP candidate table, so a sensor's own hostname was
    returned as ``SR-router (from dhcp)`` — a source string naming evidence that
    was never read.
    """
    elastic, _ = _make_elastic(settings_kratos, _result(SENSOR_HITS))

    out = await host_summary("10.1.10.41", elastic=elastic, settings=settings_kratos)

    assert "dhcp" not in (out["evidence"].get("hostname") or "")


@pytest.mark.asyncio
async def test_host_summary_rejects_host_name_when_host_ip_excludes_the_query(
    settings_kratos: Settings,
) -> None:
    """``host.ip`` is the shipper's own address list; if the query is absent, so is its identity."""
    hits = [
        {
            "@timestamp": "2026-09-04T10:00:00Z",
            "event.dataset": "network_traffic.flow",
            "source.ip": "10.1.10.42",
            "destination.ip": "10.1.10.21",
            "host.name": "SR-router",
            "host.ip": ["10.1.10.254", "192.0.2.101"],
        }
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.1.10.42", elastic=elastic, settings=settings_kratos)

    assert out["hostname"] is None


@pytest.mark.asyncio
async def test_host_summary_keeps_host_name_from_a_real_endpoint_document(
    settings_kratos: Settings,
) -> None:
    """The guard must not cost the case it exists to serve: an agent ON the host."""
    hits = [
        {
            "@timestamp": "2026-09-04T10:00:00Z",
            "event.dataset": "windows.sysmon_operational",
            "source.ip": "10.1.10.21",
            "destination.ip": "10.1.10.11",
            "host.name": "SR-WS01",
            "host.ip": ["10.1.10.21"],
            "agent.name": "SR-WS01",
        }
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.1.10.21", elastic=elastic, settings=settings_kratos)

    assert out["hostname"] == "SR-WS01"
    assert "host.name" in out["evidence"]["hostname"]


@pytest.mark.asyncio
async def test_host_summary_prefers_a_dhcp_lease_over_a_sensor_stamp(
    settings_kratos: Settings,
) -> None:
    """A real DHCP observation still wins, and the sensor stamp never displaces it."""
    hits = [
        *SENSOR_HITS,
        {
            "@timestamp": "2026-09-04T09:00:00Z",
            "event.dataset": "zeek.dhcp",
            "source.ip": "10.1.10.41",
            "destination.ip": "10.1.10.254",
            "destination.port": 67,
            "host.name": "SR-router",
            "observer.name": "SR-router",
            "zeek": {"dhcp": {"host_name": "sr-vuln2"}},
        },
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.1.10.41", elastic=elastic, settings=settings_kratos)

    assert out["hostname"] == "sr-vuln2"
    assert "dhcp" in out["evidence"]["hostname"]


# ---------------------------------------------------------------------------
# Provenance: whose 10.0.0.5 is this?
#
# RFC1918 space collides across networks by construction. An imported PCAP of
# somebody else's lab is full of addresses this grid also uses, so before the
# scope existed an import could hand the local host a foreign hostname, a
# foreign peer list, a foreign role and a first-seen belonging to a capture
# file — with nothing in the output to tell that from an observation.
# ---------------------------------------------------------------------------

_IMPORT_MARKER = {"exists": {"field": "import.id"}}


@pytest.mark.asyncio
async def test_identity_is_derived_from_this_grids_own_observations(
    settings_kratos: Settings,
) -> None:
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured.setdefault("query", query)
        return _result([], total=0)

    elastic, _ = _make_elastic(settings_kratos, _result([], total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    await host_summary("10.0.0.5", elastic=elastic, settings=settings_kratos)

    must_not = captured["query"]["bool"]["must_not"]
    assert _IMPORT_MARKER in must_not
    assert {"term": {"tags": "replayed-corpus"}} in must_not


@pytest.mark.asyncio
async def test_reading_an_import_on_purpose_is_available(settings_kratos: Settings) -> None:
    """And it is where the empty result points a caller, so it has to work."""
    captured: dict[str, Any] = {}

    async def _capture(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        captured.setdefault("query", query)
        return _result([], total=0)

    elastic, _ = _make_elastic(settings_kratos, _result([], total=0))
    elastic.search = _capture  # type: ignore[method-assign]

    out = await host_summary(
        "10.0.0.5", elastic=elastic, settings=settings_kratos, provenance="any"
    )

    assert _IMPORT_MARKER not in captured["query"]["bool"]["must_not"]
    assert out["provenance"] == "any"


@pytest.mark.asyncio
async def test_an_answered_summary_says_which_documents_described_the_host(
    settings_kratos: Settings,
) -> None:
    """A hostname is a claim about a machine, and which machine depends on this."""
    hits = [
        {
            "@timestamp": "2026-09-04T09:00:00Z",
            "event.dataset": "zeek.dhcp",
            "source.ip": "10.1.10.41",
            "zeek": {"dhcp": {"host_name": "sr-vuln2"}},
        }
    ]
    elastic, _ = _make_elastic(settings_kratos, _result(hits))

    out = await host_summary("10.1.10.41", elastic=elastic, settings=settings_kratos)

    assert out["provenance"] == "live"
    assert "live telemetry only" in out["evidence"]["population"]


@pytest.mark.asyncio
async def test_no_observations_distinguishes_unwatched_from_import_only(
    settings_kratos: Settings,
) -> None:
    """A host that exists only inside a loaded capture is not an unseen host.

    For an analyst holding an alert about that address the two readings point
    opposite ways, and "no observations" is the one most likely to be believed.
    """
    elastic, _ = _make_elastic(settings_kratos, _result([], total=0))
    elastic.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=[_result([], total=0), _result([], total=12_000)]
    )

    out = await host_summary("10.0.0.5", elastic=elastic, settings=settings_kratos)

    assert out["observations"] is False
    assert out["imported_matches"] == 12_000
    assert "12000 imported or replayed document(s)" in out["summary"]
    assert "provenance='any'" in out["summary"]


@pytest.mark.asyncio
async def test_a_genuinely_unwatched_host_gets_no_extra_sentence(
    settings_kratos: Settings,
) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([], total=0))

    out = await host_summary("10.0.0.5", elastic=elastic, settings=settings_kratos)

    assert out["imported_matches"] == 0
    assert "imported or replayed document(s) matching it" not in out["summary"]
    assert "live telemetry only" in out["summary"]


@pytest.mark.asyncio
async def test_an_unmeasurable_import_volume_stays_unmeasured(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, _result([], total=0))
    elastic.search = AsyncMock(  # type: ignore[method-assign]
        side_effect=[_result([], total=0), RuntimeError("shard failure")]
    )

    out = await host_summary("10.0.0.5", elastic=elastic, settings=settings_kratos)

    assert out["imported_matches"] is None
    assert "could not be measured" in out["summary"]
    assert "error" not in out


def test_top_peers_exclude_multicast_and_link_local() -> None:
    """224.0.0.251 and 224.0.0.252 were the DC's top "external peers": mDNS
    and LLMNR are the host addressing the segment, not a peer."""
    from soc_ai.tools.host_summary import _collect_top_peers

    aggs = {
        "peers_src": {
            "buckets": [
                {"key": "224.0.0.251", "doc_count": 900},
                {"key": "224.0.0.252", "doc_count": 800},
                {"key": "169.254.1.1", "doc_count": 5},
                {"key": "8.8.8.8", "doc_count": 9},
                {"key": "10.1.10.255", "doc_count": 3},
            ]
        },
        "peers_dst": {"buckets": [{"key": "10.0.0.1", "doc_count": 50}]},
    }
    peers = [p["value"] for p in _collect_top_peers("10.0.0.1", aggs)]
    assert peers == ["8.8.8.8", "10.1.10.255"]
