"""Tests for soc_ai.enrichment.zeek_parser."""

from __future__ import annotations

import json

from soc_ai.enrichment.zeek_parser import parse_typed_zeek_fields
from soc_ai.so_client.models import SoAlert


def _make_zeek_pivot(dataset: str, message_dict: dict) -> SoAlert:
    return SoAlert(
        id="test_id",
        event_dataset=dataset,
        event_module="zeek",
        message=json.dumps(message_dict),
    )


def test_parse_typed_zeek_dns_query() -> None:
    pivots = [
        _make_zeek_pivot(
            "zeek.dns",
            {
                "query": "evil.example.com",
                "answers": ["198.51.100.10"],
                "rcode_name": "NOERROR",
            },
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert "evil.example.com" in typed.dns_queries
    assert "198.51.100.10" in typed.dns_answers
    assert "NOERROR" in typed.dns_rcode_names


def test_parse_typed_zeek_icmp_echo_request_reply() -> None:
    """Zeek encodes ICMP type in the pseudo-ports. orig_p=8
    (echo request) + resp_p=0 (echo reply) is a solicited ping exchange —
    flag it so the post-synth validator can downgrade false BPFDoor-style
    'outbound heartbeat' escalations."""
    pivots = [
        _make_zeek_pivot(
            "zeek.conn",
            {
                "proto": "icmp",
                "id.orig_p": 8,
                "id.resp_p": 0,
                "conn_state": "OTH",
            },
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert typed.icmp_echo_request_reply is True


def test_parse_typed_zeek_icmp_non_echo_not_flagged() -> None:
    """A non-echo ICMP conn (e.g. type-3 unreachable, orig_p=3) is NOT a
    solicited ping and must not set the flag."""
    pivots = [
        _make_zeek_pivot("zeek.conn", {"proto": "icmp", "id.orig_p": 3, "id.resp_p": 3}),
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert typed.icmp_echo_request_reply is False


def test_parse_typed_zeek_tcp_conn_not_icmp_echo() -> None:
    """A normal TCP conn must not set the ICMP echo flag (guards against
    a port-8 TCP flow being misread as an echo request)."""
    pivots = [
        _make_zeek_pivot(
            "zeek.conn",
            {"proto": "tcp", "id.orig_p": 8, "id.resp_p": 0, "conn_state": "SF"},
        ),
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert typed.icmp_echo_request_reply is False


def test_parse_typed_zeek_ssl_sni() -> None:
    pivots = [_make_zeek_pivot("zeek.ssl", {"server_name": "api.giphy.com"})]
    typed = parse_typed_zeek_fields(pivots)
    assert "api.giphy.com" in typed.sni_servers


def test_parse_typed_zeek_http() -> None:
    pivots = [
        _make_zeek_pivot(
            "zeek.http",
            {"host": "example.com", "uri": "/path", "method": "GET", "status_code": 200},
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert "example.com" in typed.http_hosts
    assert "/path" in typed.http_uris
    assert "GET" in typed.http_methods
    assert 200 in typed.http_status_codes


def test_parse_typed_zeek_conn() -> None:
    pivots = [
        _make_zeek_pivot(
            "zeek.conn",
            {"conn_state": "SF", "service": "ssl"},
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert "SF" in typed.conn_states
    assert "ssl" in typed.app_protos


def test_parse_typed_zeek_handles_malformed_message() -> None:
    """Non-JSON message field doesn't break the parser."""
    p = SoAlert(id="x", event_dataset="zeek.dns", event_module="zeek", message="not json")
    typed = parse_typed_zeek_fields([p])
    assert typed.dns_queries == []


def test_parse_typed_zeek_empty_input() -> None:
    typed = parse_typed_zeek_fields([])
    assert typed.dns_queries == []
    assert typed.sni_servers == []


def test_parse_typed_zeek_skips_non_zeek_pivots() -> None:
    """Non-Zeek datasets (suricata.alert, etc.) don't contribute to typed fields."""
    p = SoAlert(
        id="x",
        event_dataset="suricata.alert",
        event_module="suricata",
        message=json.dumps({"query": "should_not_appear.com"}),
    )
    typed = parse_typed_zeek_fields([p])
    assert typed.dns_queries == []


# ---------------------------------------------------------------------------
# B6: ECS source/destination.port fallbacks for ICMP echo detection
# ---------------------------------------------------------------------------


def test_parse_typed_zeek_icmp_echo_ecs_flat_ports() -> None:
    """B6: ECS flat-dotted field paths source.port / destination.port are
    recognised as fallbacks when id.orig_p / id.resp_p are absent.
    SO 3.0 Filebeat module may map ICMP pseudo-ports to ECS fields."""
    pivots = [
        _make_zeek_pivot(
            "zeek.conn",
            {
                "proto": "icmp",
                "source.port": 8,
                "destination.port": 0,
                "conn_state": "OTH",
            },
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert typed.icmp_echo_request_reply is True


def test_parse_typed_zeek_icmp_echo_ecs_nested_ports() -> None:
    """B6: ECS nested dict field paths source.port / destination.port via
    {'source': {'port': 8}, 'destination': {'port': 0}} are also recognised."""
    pivots = [
        _make_zeek_pivot(
            "zeek.conn",
            {
                "proto": "icmp",
                "source": {"port": 8},
                "destination": {"port": 0},
                "network": {"transport": "icmp"},
            },
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert typed.icmp_echo_request_reply is True


def test_parse_typed_zeek_icmp_zeek_native_still_works_with_ecs_present() -> None:
    """B6: Zeek-native id.orig_p / id.resp_p still takes priority when present
    even if ECS fields are also in the record."""
    pivots = [
        _make_zeek_pivot(
            "zeek.conn",
            {
                "proto": "icmp",
                "id.orig_p": 8,
                "id.resp_p": 0,
                # ECS fields present too — Zeek-native should win (same result here).
                "source.port": 8,
                "destination.port": 0,
                "conn_state": "OTH",
            },
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert typed.icmp_echo_request_reply is True


def test_parse_typed_zeek_icmp_ecs_non_echo_not_flagged() -> None:
    """B6: ECS ports that are NOT 8/0 (e.g. type-3/code-3 unreachable) must
    not set the echo flag even when only ECS paths are present."""
    pivots = [
        _make_zeek_pivot(
            "zeek.conn",
            {
                "proto": "icmp",
                "source.port": 3,
                "destination.port": 3,
            },
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert typed.icmp_echo_request_reply is False


def test_parse_typed_zeek_icmp_zeek_native_overrides_conflicting_ecs_ports() -> None:
    """B6 conflict-priority: Zeek-native id.orig_p / id.resp_p OVERRIDE conflicting
    ECS source.port / destination.port when both are present in the same document.

    doc: id.orig_p=3, id.resp_p=3 (non-echo type/code) AND source.port=8,
    destination.port=0 (echo-looking ECS values).
    Zeek-native wins → icmp_echo_request_reply must be False."""
    pivots = [
        _make_zeek_pivot(
            "zeek.conn",
            {
                "proto": "icmp",
                "id.orig_p": 3,
                "id.resp_p": 3,
                # ECS fields look like echo (8/0) but Zeek-native must win.
                "source.port": 8,
                "destination.port": 0,
            },
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert typed.icmp_echo_request_reply is False
