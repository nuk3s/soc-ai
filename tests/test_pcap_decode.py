"""Tests for soc_ai.tools.pcap_decode — in-process dpkt PCAP decoder.

All pcap fixtures are generated programmatically via dpkt.pcap.Writer so no
binary files are committed.  The test suite covers:

* TLS ClientHello SNI extraction
* DNS QNAME extraction
* HTTP Host header extraction
* Periodic beacon inter-arrival (low cv) vs jittery flow (high cv)
* Five-tuple aggregation and per-flow byte/packet counts
* max_packets cap → truncated=True
* Robustness: truncated pcap bytes, random garbage, malformed TLS/DNS
"""

from __future__ import annotations

import io
import random
import socket
import struct

import dpkt
import pytest
from soc_ai.tools.pcap_decode import (
    PcapFacts,
    decode_pcap,
)

# ---------------------------------------------------------------------------
# Helpers — build raw protocol bytes
# ---------------------------------------------------------------------------

_ETHER_IP4 = 0x0800
_ETHER_IP6 = 0x86DD


def _eth_hdr(src_mac: bytes, dst_mac: bytes, etype: int) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", etype)


def _ip4_hdr(
    src: str,
    dst: str,
    proto: int,
    payload: bytes,
    ttl: int = 64,
) -> bytes:
    """Minimal IPv4 header (no options) — computes correct total length."""
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    total_len = 20 + len(payload)
    # version+ihl, dscp, total_len, id, flags+frag, ttl, proto, checksum=0, src, dst
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0x1234,
        0,
        ttl,
        proto,
        0,
        src_b,
        dst_b,
    )
    return hdr + payload


def _tcp_hdr(sport: int, dport: int, payload: bytes, flags: int = 0x02) -> bytes:
    """Minimal TCP segment (no options).  seq/ack/window zeroed."""
    # sport dport seq ack data_offset_flags window checksum urgent
    hdr = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        0,
        0,
        0x50,  # data offset = 5 (20 bytes), reserved
        flags,
        0xFFFF,
        0,
        0,
    )
    return hdr + payload


def _udp_hdr(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def _make_packet(
    src: str,
    sport: int,
    dst: str,
    dport: int,
    proto: str,  # "tcp" | "udp"
    payload: bytes = b"",
    flags: int = 0x02,
) -> bytes:
    """Build an Ethernet+IPv4+TCP/UDP frame."""
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    dst_mac = b"\x66\x77\x88\x99\xaa\xbb"
    if proto == "tcp":
        l4 = _tcp_hdr(sport, dport, payload, flags)
        ip_proto = 6
    else:
        l4 = _udp_hdr(sport, dport, payload)
        ip_proto = 17
    ip = _ip4_hdr(src, dst, ip_proto, l4)
    eth = _eth_hdr(src_mac, dst_mac, _ETHER_IP4)
    return eth + ip


def _build_pcap(frames: list[tuple[float, bytes]]) -> bytes:
    """Write (timestamp, raw_frame) list to a pcap buffer.

    Note: dpkt.pcap.Writer.close() also closes the underlying BytesIO, so we
    capture the value *before* close() is called.
    """
    buf = io.BytesIO()
    w = dpkt.pcap.Writer(buf)
    for ts, frame in frames:
        w.writepkt(frame, ts=ts)
    # Flush manually: the Writer has a buffered file handle; calling w._Writer__f
    # is private, so we just grab the value before close() tears down the BytesIO.
    raw = buf.getvalue()
    w.close()
    return raw


# ---------------------------------------------------------------------------
# TLS ClientHello builder
# ---------------------------------------------------------------------------


def _tls_client_hello(sni: str) -> bytes:
    """Craft a minimal TLS 1.2 ClientHello with the given SNI."""
    sni_b = sni.encode()
    # server_name extension payload: list_len(2) + name_type(1) + name_len(2) + name
    name_payload = struct.pack("!BH", 0, len(sni_b)) + sni_b
    sni_list_payload = struct.pack("!H", len(name_payload)) + name_payload
    ext_sni = struct.pack("!HH", 0, len(sni_list_payload)) + sni_list_payload

    # ClientHello body: version(2) random(32) sid_len(1) cipher_len(2)
    #                   ciphers(2) comp_len(1) comp(1) ext_total(2) extensions
    random32 = b"\x00" * 32
    ciphers = struct.pack("!H", 0xC02B)  # one cipher
    hello_body = (
        b"\x03\x03"  # TLS 1.2
        + random32
        + b"\x00"  # session id length = 0
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"  # one compression method (null)
        + struct.pack("!H", len(ext_sni))
        + ext_sni
    )
    # Handshake header: type(1)=ClientHello + length(3)
    hs = struct.pack("!B", 1) + struct.pack("!I", len(hello_body))[1:] + hello_body
    # TLS record header: type(1)=22 + version(2) + length(2)
    return struct.pack("!BHH", 0x16, 0x0303, len(hs)) + hs


# ---------------------------------------------------------------------------
# DNS query builder
# ---------------------------------------------------------------------------


def _dns_query(qname: str) -> bytes:
    """Build a minimal DNS A-query message."""
    # Header: id txid flags qdcount ancount nscount arcount
    header = struct.pack("!HHHHHH", 0xAAAA, 0x0100, 1, 0, 0, 0)
    # QNAME: each label prefixed with its length, terminated by 0x00
    labels = b""
    for label in qname.split("."):
        lb = label.encode()
        labels += bytes([len(lb)]) + lb
    labels += b"\x00"
    # QTYPE=A(1) QCLASS=IN(1)
    question = labels + struct.pack("!HH", 1, 1)
    return header + question


# ---------------------------------------------------------------------------
# Tests — L7 extraction
# ---------------------------------------------------------------------------


def test_tls_sni_extraction() -> None:
    """decode_pcap returns sni_list containing the SNI from a ClientHello."""
    sni = "evil.example.com"
    payload = _tls_client_hello(sni)
    frame = _make_packet("10.0.0.1", 54321, "10.0.0.2", 443, "tcp", payload, flags=0x18)
    pcap = _build_pcap([(1000.0, frame)])

    facts = decode_pcap(pcap)

    assert any(entry.value == sni for entry in facts.sni_list), (
        f"Expected SNI '{sni}' in {facts.sni_list}"
    )


def test_dns_qname_extraction() -> None:
    """decode_pcap returns dns_qnames containing the queried name."""
    qname = "c2.example.net"
    payload = _dns_query(qname)
    frame = _make_packet("10.0.0.1", 55000, "8.8.8.8", 53, "udp", payload)
    pcap = _build_pcap([(1000.0, frame)])

    facts = decode_pcap(pcap)

    assert any(entry.value == qname for entry in facts.dns_qnames), (
        f"Expected '{qname}' in {facts.dns_qnames}"
    )


def test_http_host_extraction() -> None:
    """decode_pcap returns http_hosts containing the Host header value."""
    host = "intranet"
    request = (f"GET /path HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    frame = _make_packet("10.0.0.1", 54321, "192.168.1.5", 80, "tcp", request, flags=0x18)
    pcap = _build_pcap([(1000.0, frame)])

    facts = decode_pcap(pcap)

    assert any(entry.value == host for entry in facts.http_hosts), (
        f"Expected '{host}' in {facts.http_hosts}"
    )


# ---------------------------------------------------------------------------
# Tests — inter-arrival timing
# ---------------------------------------------------------------------------


def test_beacon_flow_low_cv() -> None:
    """A perfectly periodic flow should have cv ≈ 0."""
    interval = 60.0  # 60 second beacon
    n_packets = 11  # 10 gaps
    frames = []
    for i in range(n_packets):
        ts = 1000.0 + i * interval
        frame = _make_packet("10.0.0.1", 12345, "10.0.0.2", 4444, "tcp", b"beacon", flags=0x18)
        frames.append((ts, frame))

    facts = decode_pcap(_build_pcap(frames))

    assert facts.inter_arrival is not None, "Expected inter_arrival to be computed"
    assert facts.inter_arrival.cv < 0.01, (
        f"Expected near-zero cv for beacon flow, got {facts.inter_arrival.cv}"
    )
    assert facts.inter_arrival.count == n_packets - 1


def test_jittery_flow_high_cv() -> None:
    """A jittery flow (random gaps) should have a clearly higher cv than a beacon."""
    rng = random.Random(42)
    n_packets = 20
    # Random gaps between 0.1s and 100s — very high jitter
    ts = 1000.0
    frames = []
    for _ in range(n_packets):
        frame = _make_packet("10.0.0.3", 22222, "10.0.0.4", 9999, "tcp", b"jitter", flags=0x18)
        frames.append((ts, frame))
        ts += rng.uniform(0.1, 100.0)

    facts = decode_pcap(_build_pcap(frames))

    assert facts.inter_arrival is not None
    assert facts.inter_arrival.cv > 0.5, (
        f"Expected high cv for jittery flow, got {facts.inter_arrival.cv}"
    )


def test_beacon_cv_clearly_lower_than_jitter() -> None:
    """Beacon cv must be clearly lower than jitter cv on a combined pcap."""
    interval = 60.0
    n = 12  # 11 gaps

    # Build a beacon flow (src port 11111 → dst port 5000)
    beacon_frames: list[tuple[float, bytes]] = []
    for i in range(n):
        ts = 1000.0 + i * interval
        frame = _make_packet("10.1.1.1", 11111, "10.1.1.2", 5000, "tcp", b"B", flags=0x18)
        beacon_frames.append((ts, frame))

    # Build a jitter flow using a different tuple (src port 22222 → dst port 6000)
    rng = random.Random(99)
    jitter_ts = 1000.0
    jitter_frames: list[tuple[float, bytes]] = []
    for _ in range(n):
        frame = _make_packet("10.2.2.1", 22222, "10.2.2.2", 6000, "tcp", b"J", flags=0x18)
        jitter_frames.append((jitter_ts, frame))
        jitter_ts += rng.uniform(0.5, 120.0)

    # The dominant flow is whichever has more packets — we make beacon dominant.
    # The inter_arrival stats are for the dominant flow only; test each pcap separately.
    beacon_facts = decode_pcap(_build_pcap(beacon_frames))
    jitter_facts = decode_pcap(_build_pcap(jitter_frames))

    assert beacon_facts.inter_arrival is not None
    assert jitter_facts.inter_arrival is not None

    beacon_cv = beacon_facts.inter_arrival.cv
    jitter_cv = jitter_facts.inter_arrival.cv

    assert beacon_cv < jitter_cv, f"Beacon cv {beacon_cv:.4f} should be < jitter cv {jitter_cv:.4f}"
    # Beacon should be near-zero; jitter should be substantial.
    assert beacon_cv < 0.01
    assert jitter_cv > 0.5


# ---------------------------------------------------------------------------
# Tests — five-tuple aggregation
# ---------------------------------------------------------------------------


def test_five_tuple_aggregation() -> None:
    """Multiple flows are correctly separated with right packet/byte counts."""
    frames: list[tuple[float, bytes]] = []

    # Flow A: 3 TCP packets from 10.0.0.1:1000 → 10.0.0.2:80
    for i in range(3):
        pkt = _make_packet("10.0.0.1", 1000, "10.0.0.2", 80, "tcp", b"AAAA", flags=0x18)
        frames.append((1000.0 + i, pkt))

    # Flow B: 2 UDP packets from 10.0.0.1:2000 → 8.8.8.8:53
    for i in range(2):
        pkt = _make_packet("10.0.0.1", 2000, "8.8.8.8", 53, "udp", _dns_query("x.test"))
        frames.append((2000.0 + i, pkt))

    facts = decode_pcap(_build_pcap(frames))

    assert facts.packets == 5

    # Find flow A in five_tuples
    tcp_flows = [ft for ft in facts.five_tuples if ft.proto == "tcp" and ft.sport == 1000]
    assert tcp_flows, "Expected TCP flow A in five_tuples"
    assert tcp_flows[0].packets == 3

    # Find flow B
    udp_flows = [ft for ft in facts.five_tuples if ft.proto == "udp" and ft.sport == 2000]
    assert udp_flows, "Expected UDP flow B in five_tuples"
    assert udp_flows[0].packets == 2

    # proto_breakdown
    assert facts.proto_breakdown.get("tcp", 0) == 3
    assert facts.proto_breakdown.get("udp", 0) == 2


def test_five_tuple_byte_counts() -> None:
    """Per-flow byte totals in FiveTuple.bytes are non-zero."""
    payload = b"X" * 100
    frame = _make_packet("1.2.3.4", 9000, "5.6.7.8", 12345, "tcp", payload, flags=0x18)
    pcap = _build_pcap([(1.0, frame), (2.0, frame)])

    facts = decode_pcap(pcap)

    assert facts.five_tuples
    ft = facts.five_tuples[0]
    assert ft.bytes > 0
    assert ft.packets == 2


# ---------------------------------------------------------------------------
# Tests — max_packets cap
# ---------------------------------------------------------------------------


def test_max_packets_sets_truncated() -> None:
    """Stopping at max_packets sets truncated=True."""
    frames = [
        (float(i), _make_packet("1.1.1.1", 100, "2.2.2.2", 200, "tcp", b"x", flags=0x18))
        for i in range(20)
    ]
    pcap = _build_pcap(frames)

    facts = decode_pcap(pcap, max_packets=10)

    assert facts.truncated is True
    assert facts.packets == 10


def test_max_packets_no_truncation_within_limit() -> None:
    """No truncation when total packets are within the cap."""
    frames = [
        (float(i), _make_packet("1.1.1.1", 100, "2.2.2.2", 200, "tcp", b"x", flags=0x18))
        for i in range(5)
    ]
    pcap = _build_pcap(frames)

    facts = decode_pcap(pcap, max_packets=10)

    assert facts.truncated is False
    assert facts.packets == 5


# ---------------------------------------------------------------------------
# Tests — robustness
# ---------------------------------------------------------------------------


def test_truncated_pcap_bytes_does_not_raise() -> None:
    """A pcap file truncated mid-packet must not raise."""
    frames = [
        (1000.0, _make_packet("1.2.3.4", 1234, "5.6.7.8", 80, "tcp", b"hello", flags=0x18))
        for _ in range(5)
    ]
    full_pcap = _build_pcap(frames)

    # Cut the pcap at 60% — guaranteed to land mid-packet.
    truncated = full_pcap[: int(len(full_pcap) * 0.6)]

    # Must not raise
    facts = decode_pcap(truncated)
    assert isinstance(facts, PcapFacts)
    # Partial result: either some packets decoded, or parser_errors set, or empty
    # but never an exception.


def test_random_garbage_bytes_does_not_raise() -> None:
    """Random bytes must not cause decode_pcap to raise."""
    rng = random.Random(0)
    garbage = bytes(rng.getrandbits(8) for _ in range(256))

    facts = decode_pcap(garbage)

    assert isinstance(facts, PcapFacts)
    assert facts.packets == 0


def test_completely_empty_input_does_not_raise() -> None:
    """Empty bytes input returns empty PcapFacts."""
    facts = decode_pcap(b"")
    assert isinstance(facts, PcapFacts)
    assert facts.packets == 0


def test_malformed_tls_counted_as_parser_error_or_skipped() -> None:
    """A syntactically invalid TLS record does not halt the walk."""
    bad_tls = b"\x16\x03\x03" + b"\xff" * 100  # truncated TLS record
    frame = _make_packet("1.2.3.4", 11111, "5.6.7.8", 443, "tcp", bad_tls, flags=0x18)
    # Good packet after the bad one
    good_frame = _make_packet(
        "1.2.3.4",
        11111,
        "5.6.7.8",
        80,
        "tcp",
        b"GET / HTTP/1.1\r\nHost: ok.host\r\n\r\n",
        flags=0x18,
    )
    pcap = _build_pcap([(1.0, frame), (2.0, good_frame)])

    facts = decode_pcap(pcap)

    assert isinstance(facts, PcapFacts)
    # The walk must have continued — second packet should be seen.
    assert facts.packets >= 1
    # The good HTTP packet should produce a host hit.
    assert any(e.value == "ok.host" for e in facts.http_hosts)


def test_malformed_dns_does_not_halt_walk() -> None:
    """A malformed DNS payload is skipped gracefully."""
    bad_dns = b"\xaa\xaa\x01\x00" + b"\xff" * 8  # garbage after header
    bad_frame = _make_packet("1.2.3.4", 55000, "8.8.8.8", 53, "udp", bad_dns)
    good_dns = _dns_query("legit.example.com")
    good_frame = _make_packet("1.2.3.4", 55001, "8.8.8.8", 53, "udp", good_dns)
    pcap = _build_pcap([(1.0, bad_frame), (2.0, good_frame)])

    facts = decode_pcap(pcap)

    assert isinstance(facts, PcapFacts)
    assert any(e.value == "legit.example.com" for e in facts.dns_qnames)


def test_pcap_with_only_non_ip_frames() -> None:
    """ARP-only pcap returns zero five_tuples but does not raise."""
    # Build a fake ARP frame (ethertype 0x0806) — dpkt will see non-IP.
    arp_frame = b"\x00" * 6 + b"\xff" * 6 + b"\x08\x06" + b"\x00" * 28
    pcap = _build_pcap([(1.0, arp_frame), (2.0, arp_frame)])

    facts = decode_pcap(pcap)

    assert isinstance(facts, PcapFacts)
    assert facts.five_tuples == []
    assert facts.packets == 2


# ---------------------------------------------------------------------------
# Tests — timestamps and duration
# ---------------------------------------------------------------------------


def test_first_last_ts_and_duration() -> None:
    """first_ts, last_ts, duration_s are computed correctly."""
    frame = _make_packet("10.0.0.1", 1111, "10.0.0.2", 22, "tcp", b"ssh")
    pcap = _build_pcap([(1000.0, frame), (1005.0, frame), (1010.0, frame)])

    facts = decode_pcap(pcap)

    assert facts.first_ts == pytest.approx(1000.0, abs=0.01)
    assert facts.last_ts == pytest.approx(1010.0, abs=0.01)
    assert facts.duration_s == pytest.approx(10.0, abs=0.01)


# ---------------------------------------------------------------------------
# Tests — TCP flags breakdown
# ---------------------------------------------------------------------------


def test_tcp_flags_breakdown() -> None:
    """SYN and SYN-ACK flags appear in tcp_flags_breakdown."""
    syn_frame = _make_packet("10.0.0.1", 1111, "10.0.0.2", 443, "tcp", b"", flags=0x02)
    synack_frame = _make_packet("10.0.0.2", 443, "10.0.0.1", 1111, "tcp", b"", flags=0x12)
    pcap = _build_pcap([(1.0, syn_frame), (1.001, synack_frame)])

    facts = decode_pcap(pcap)

    assert "S" in facts.tcp_flags_breakdown  # SYN only
    assert "SA" in facts.tcp_flags_breakdown  # SYN-ACK


# ---------------------------------------------------------------------------
# Tests — pcapng format (if supported by dpkt version)
# ---------------------------------------------------------------------------


def test_single_packet_bytes_total() -> None:
    """bytes_total accumulates the raw frame lengths."""
    payload = b"P" * 50
    frame = _make_packet("1.1.1.1", 1000, "2.2.2.2", 2000, "tcp", payload, flags=0x18)
    pcap = _build_pcap([(1.0, frame)])

    facts = decode_pcap(pcap)

    assert facts.packets == 1
    assert facts.bytes_total == len(frame)


def test_single_packet_flow_inter_arrival_is_none() -> None:
    """A single-packet flow has no gaps → inter_arrival is None (no n<2 crash)."""
    frame = _make_packet("1.1.1.1", 1000, "2.2.2.2", 53, "udp", b"\x00" * 12)
    facts = decode_pcap(_build_pcap([(1.0, frame)]))
    assert facts.packets == 1
    assert facts.inter_arrival is None


def test_identical_timestamps_no_div_by_zero() -> None:
    """A flow whose every packet shares one timestamp → mean gap 0 → cv 0.0.

    Adversarial: identical timestamps make the mean inter-arrival 0; the cv
    formula must guard ``mean == 0`` rather than dividing by zero.
    """
    frames = [
        (5.0, _make_packet("1.1.1.1", 1000, "2.2.2.2", 53, "udp", b"\x00" * 12)) for _ in range(30)
    ]
    facts = decode_pcap(_build_pcap(frames))
    assert facts.inter_arrival is not None
    assert facts.inter_arrival.mean_s == 0.0
    assert facts.inter_arrival.cv == 0.0  # guarded, not NaN/inf/ZeroDivisionError


def test_all_unique_flows_memory_bounded_by_max_packets() -> None:
    """Millions-of-tiny-flows shape: aggregation is bounded by max_packets.

    Each packet contributes at most one new flow key + one timestamp, so the
    five-tuple dicts can never exceed ``max_packets`` entries.  Decode stays
    bounded and reports only the top-20 flows.
    """
    frames = []
    for i in range(500):
        src = f"10.{(i >> 8) & 0xFF}.{i & 0xFF}.1"
        frames.append((float(i), _make_packet(src, 1000 + i, "2.2.2.2", 53, "udp", b"")))
    facts = decode_pcap(_build_pcap(frames), max_packets=100)
    assert facts.truncated is True
    assert facts.packets == 100
    assert len(facts.five_tuples) <= 20  # only the top-N are surfaced
