"""In-process dpkt PCAP decoder — decode-only, no I/O, no subprocess.

``decode_pcap(data: bytes) -> PcapFacts`` is the public surface.  Pass it
raw pcap bytes (from memory/SSH fetch/unit test) and get back a fully
structured ``PcapFacts`` document.

Design principles
-----------------
* **Never raises on malformed input.**  A hostile or truncated pcap yields a
  partial ``PcapFacts`` with ``parser_errors > 0`` and/or ``truncated=True``.
  Every per-packet decode path is try/excepted.
* **No I/O.**  The function operates on ``bytes``; the caller owns fetch/file.
* **Bounded inner loops.**  DNS label walks, TLS extension walks, and all other
  variable-length parses have explicit iteration caps against adversarial input.
* **Link-type agnostic.**  Handles ``DLT_EN10MB`` (Ethernet), ``DLT_RAW`` /
  ``DLT_IPV4`` (raw IP), and ``DLT_LINUX_SLL`` / ``DLT_LINUX_SLL2``
  (Linux cooked captures) defensively; unknown link types accumulate a note
  and skip L3 decode.
"""

from __future__ import annotations

import io
import math
import socket
import struct
from collections import Counter, defaultdict
from typing import Any

import dpkt
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class FiveTuple(BaseModel):
    """One aggregated flow observed in the pcap."""

    src: str
    sport: int
    dst: str
    dport: int
    proto: str
    packets: int
    bytes: int


class InterArrival(BaseModel):
    """Inter-packet timing stats for the dominant flow.

    A low ``cv`` (coefficient of variation = stdev/mean) indicates a periodic
    beacon-style flow; a high ``cv`` indicates bursty / human-driven traffic.
    """

    mean_s: float
    stdev_s: float
    cv: float  # stdev / mean; 0 ⟹ perfectly periodic, >1 ⟹ very bursty
    count: int  # number of gaps measured (= packets_in_flow - 1)


class Counted(BaseModel):
    """A string value with an observation count."""

    value: str
    count: int


class PcapFacts(BaseModel):
    """Structured output of a single ``decode_pcap`` call."""

    # --- packet-level totals -------------------------------------------------
    packets: int = 0
    bytes_total: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    duration_s: float | None = None

    # --- flow inventory ------------------------------------------------------
    five_tuples: list[FiveTuple] = Field(default_factory=list)

    # --- breakdown counters --------------------------------------------------
    proto_breakdown: dict[str, int] = Field(default_factory=dict)
    tcp_flags_breakdown: dict[str, int] = Field(default_factory=dict)

    # --- inter-arrival timing for the dominant flow -------------------------
    inter_arrival: InterArrival | None = None

    # --- L7 hints ------------------------------------------------------------
    sni_list: list[Counted] = Field(default_factory=list)
    dns_qnames: list[Counted] = Field(default_factory=list)
    http_hosts: list[Counted] = Field(default_factory=list)

    # --- meta ----------------------------------------------------------------
    notes: list[str] = Field(default_factory=list)
    parser_errors: int = 0
    truncated: bool = False


# ---------------------------------------------------------------------------
# Link-type constants
# ---------------------------------------------------------------------------

_DLT_EN10MB = 1  # Ethernet
_DLT_RAW = 12  # Raw IP (BSD)
_DLT_RAW_101 = 101  # Raw IP (Linux)
_DLT_LINUX_SLL = 113  # Linux cooked capture v1
_DLT_LINUX_SLL2 = 276  # Linux cooked capture v2

_RAW_LINK_TYPES = frozenset({_DLT_RAW, _DLT_RAW_101})
_COOKED_LINK_TYPES = frozenset({_DLT_LINUX_SLL, _DLT_LINUX_SLL2})


# ---------------------------------------------------------------------------
# Internal helpers — pure functions, all try/excepted by callers
# ---------------------------------------------------------------------------


def _safe_addr(raw: bytes) -> str | None:
    """Convert 4- or 16-byte address blob to text.  Returns None on failure."""
    try:
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw)
        if len(raw) == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        pass
    return None


def _try_decode_http(payload: bytes) -> str | None:
    """Extract the HTTP ``Host`` header value.  Returns None if not an HTTP request."""
    if len(payload) < 16:
        return None
    head = payload[:2048]
    try:
        text = head.decode("ascii", errors="replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    first_parts = lines[0].split(" ", 2)
    if len(first_parts) < 3 or not first_parts[2].startswith("HTTP/"):
        return None
    for line in lines[1:30]:
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        if key.strip().lower() == "host":
            return val.strip()[:256]
    return None


def _try_decode_dns(payload: bytes) -> str | None:
    """Extract the first QNAME from a DNS message.  Returns None on failure."""
    if len(payload) < 12:
        return None
    try:
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount < 1:
            return None
        i = 12
        labels: list[str] = []
        for _ in range(64):  # bound against pointer loops
            if i >= len(payload):
                return None
            length = payload[i]
            if length == 0:
                break
            if length & 0xC0:  # compression pointer — return what we have
                break
            i += 1
            if i + length > len(payload):
                return None
            labels.append(payload[i : i + length].decode("ascii", errors="replace"))
            i += length
        return ".".join(labels) if labels else None
    except (struct.error, IndexError, UnicodeDecodeError):
        return None


def _try_decode_tls_sni(payload: bytes) -> str | None:
    """Extract SNI from a TLS 1.x ClientHello.  Returns None on failure.

    Bounds-checked at every step; never allocates more than the input size.
    """
    if len(payload) < 43 or payload[0] != 0x16:  # TLS Handshake record
        return None
    try:
        # TLS record: type(1) version(2) length(2) | Handshake: type(1) length(3)
        if payload[5] != 0x01:  # ClientHello
            return None
        i = 5 + 4  # skip record header + handshake header
        i += 2 + 32  # skip ClientHello version(2) + random(32)
        if i + 1 > len(payload):
            return None
        sid_len = payload[i]
        i += 1 + sid_len
        if i + 2 > len(payload):
            return None
        cs_len = struct.unpack("!H", payload[i : i + 2])[0]
        i += 2 + cs_len
        if i + 1 > len(payload):
            return None
        cm_len = payload[i]
        i += 1 + cm_len
        if i + 2 > len(payload):
            return None
        ext_total = struct.unpack("!H", payload[i : i + 2])[0]
        i += 2
        end = min(i + ext_total, len(payload))
        for _ in range(64):  # bound extension walk
            if i + 4 > end:
                return None
            ext_type, ext_len = struct.unpack("!HH", payload[i : i + 4])
            i += 4
            if i + ext_len > end:
                return None
            if ext_type == 0:  # server_name extension
                if ext_len < 5:
                    return None
                name_len = struct.unpack("!H", payload[i + 3 : i + 5])[0]
                if i + 5 + name_len > end:
                    return None
                return payload[i + 5 : i + 5 + name_len].decode("ascii", errors="replace")
            i += ext_len
    except (struct.error, IndexError, UnicodeDecodeError):
        return None
    return None


def _extract_ip(buf: bytes, link_type: int) -> tuple[Any, Any] | None:
    """Unwrap the link layer and return (ip_obj, l4_obj) or None.

    Handles Ethernet (DLT_EN10MB), raw IP (DLT_RAW / 101), and Linux cooked
    captures (DLT_LINUX_SLL / SLL2).  Returns None for non-IP frames or on
    parse error.
    """
    try:
        if link_type == _DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
        elif link_type in _RAW_LINK_TYPES:
            if not buf:
                return None
            version = (buf[0] >> 4) & 0xF
            if version == 4:
                ip = dpkt.ip.IP(buf)
            elif version == 6:
                ip = dpkt.ip6.IP6(buf)
            else:
                return None
        elif link_type == _DLT_LINUX_SLL:
            # Linux cooked v1: 2+2+2+8+2 = 16 bytes header, then IP
            if len(buf) < 17:
                return None
            proto = struct.unpack("!H", buf[14:16])[0]
            payload = buf[16:]
            if proto == 0x0800:
                ip = dpkt.ip.IP(payload)
            elif proto == 0x86DD:
                ip = dpkt.ip6.IP6(payload)
            else:
                return None
        elif link_type == _DLT_LINUX_SLL2:
            # Linux cooked v2: 20-byte header (proto+reserved+ifindex+arphrd+pkttype+addrlen+addr)
            if len(buf) < 21:
                return None
            proto = struct.unpack("!H", buf[0:2])[0]
            payload = buf[20:]
            if proto == 0x0800:
                ip = dpkt.ip.IP(payload)
            elif proto == 0x86DD:
                ip = dpkt.ip6.IP6(payload)
            else:
                return None
        else:
            return None
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None
        return (ip, ip.data)
    except Exception:
        return None


def _flag_label(flags: int) -> str:
    """Convert TCP flags bitmask to a short label like ``'SA'`` or ``'S'``."""
    label = (
        ("S" if flags & 0x02 else "")
        + ("A" if flags & 0x10 else "")
        + ("F" if flags & 0x01 else "")
        + ("R" if flags & 0x04 else "")
        + ("P" if flags & 0x08 else "")
    )
    return label or "_"


def _compute_inter_arrival(timestamps: list[float]) -> InterArrival | None:
    """Compute inter-packet gap stats for a single flow's timestamp list.

    The coefficient of variation (``cv = stdev / mean``) is the key signal:
    * ``cv ≈ 0`` ⟹ perfectly periodic (likely a beacon).
    * ``cv > 1`` ⟹ highly bursty / human-driven.
    """
    if len(timestamps) < 2:
        return None
    gaps = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    n = len(gaps)
    mean = sum(gaps) / n
    stdev = 0.0 if n == 1 else math.sqrt(sum((g - mean) ** 2 for g in gaps) / (n - 1))
    cv = stdev / mean if mean > 0 else 0.0
    return InterArrival(mean_s=mean, stdev_s=stdev, cv=cv, count=n)


# ---------------------------------------------------------------------------
# Accumulator type aliases
# ---------------------------------------------------------------------------

_FlowKey = tuple[str, int, str, int, str]  # src, sport, dst, dport, proto


def _process_l7(
    proto_name: str,
    sport: int,
    dport: int,
    payload: bytes,
    sni_counter: Counter[str],
    dns_counter: Counter[str],
    http_counter: Counter[str],
    parser_errors_ref: list[int],
) -> None:
    """Best-effort L7 hint extraction.  All errors increment parser_errors_ref[0]."""
    if proto_name == "tcp" and payload:
        if dport in (443, 8443) or sport in (443, 8443):
            try:
                sni = _try_decode_tls_sni(payload)
                if sni:
                    sni_counter[sni] += 1
            except Exception:
                parser_errors_ref[0] += 1
        elif dport in (80, 8080) or sport in (80, 8080):
            try:
                host = _try_decode_http(payload)
                if host:
                    http_counter[host] += 1
            except Exception:
                parser_errors_ref[0] += 1
    elif proto_name == "udp" and payload and (sport == 53 or dport == 53):
        try:
            qname = _try_decode_dns(payload)
            if qname:
                dns_counter[qname] += 1
        except Exception:
            parser_errors_ref[0] += 1


def _process_packet(
    buf: bytes,
    link_type: int,
    ts: float,
    flow_pkts: Counter[_FlowKey],
    flow_bytes: Counter[_FlowKey],
    flow_ts: dict[_FlowKey, list[float]],
    proto_counter: Counter[str],
    flag_counter: Counter[str],
    sni_counter: Counter[str],
    dns_counter: Counter[str],
    http_counter: Counter[str],
    parser_errors_ref: list[int],
) -> None:
    """Parse one packet frame and accumulate into the provided counters.

    Never raises — exceptions increment parser_errors_ref[0].
    """
    try:
        result = _extract_ip(buf, link_type)
        if result is None:
            proto_counter["non_ip"] += 1
            return

        ip, l4 = result
        src = _safe_addr(ip.src)
        dst = _safe_addr(ip.dst)
        if not src or not dst:
            parser_errors_ref[0] += 1
            return

        proto_name = "other"
        sport = 0
        dport = 0
        payload: bytes = b""

        if isinstance(l4, dpkt.tcp.TCP):
            proto_name = "tcp"
            sport, dport = int(l4.sport), int(l4.dport)
            flag_counter[_flag_label(int(l4.flags))] += 1
            payload = bytes(l4.data) if l4.data else b""
        elif isinstance(l4, dpkt.udp.UDP):
            proto_name = "udp"
            sport, dport = int(l4.sport), int(l4.dport)
            payload = bytes(l4.data) if l4.data else b""
        elif isinstance(l4, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
            proto_name = "icmp"
        else:
            proto_name = type(l4).__name__.lower() if l4 is not None else "other"

        proto_counter[proto_name] += 1

        if sport or dport:
            key: _FlowKey = (src, sport, dst, dport, proto_name)
            flow_pkts[key] += 1
            flow_bytes[key] += len(buf)
            flow_ts[key].append(ts)

        _process_l7(
            proto_name,
            sport,
            dport,
            payload,
            sni_counter,
            dns_counter,
            http_counter,
            parser_errors_ref,
        )

    except Exception:
        parser_errors_ref[0] += 1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def decode_pcap(data: bytes, *, max_packets: int = 50000) -> PcapFacts:
    """Decode raw pcap bytes into a ``PcapFacts`` document.

    Args:
        data: Raw pcap bytes (not a file path — the caller owns I/O).
        max_packets: Walk at most this many packets; sets ``truncated=True``
            if the cap is hit.

    Returns:
        ``PcapFacts`` — always.  Never raises, even on garbage input.

    Robustness guarantees
    ---------------------
    * Any exception during per-packet processing is caught; the packet
      increments ``parser_errors`` and the walk continues.
    * Truncated or garbage pcap headers return an empty-ish ``PcapFacts``.
    * Bounded inner loops prevent adversarial inputs from spinning forever.
    * No subprocess, no network, no file I/O.
    """
    facts = PcapFacts()

    # Open the pcap reader from in-memory bytes.
    try:
        fh = io.BytesIO(data)
        reader = dpkt.pcap.Reader(fh)
        link_type: int = reader.datalink()
    except Exception:
        facts.notes.append("pcap header parse failed; no packets decoded")
        return facts

    if link_type not in (
        _DLT_EN10MB,
        *_RAW_LINK_TYPES,
        *_COOKED_LINK_TYPES,
    ):
        facts.notes.append(f"unknown link type {link_type}; L3 decode skipped")

    # Counters / accumulators
    flow_pkts: Counter[_FlowKey] = Counter()
    flow_bytes: Counter[_FlowKey] = Counter()
    flow_ts: dict[_FlowKey, list[float]] = defaultdict(list)
    proto_counter: Counter[str] = Counter()
    flag_counter: Counter[str] = Counter()
    sni_counter: Counter[str] = Counter()
    dns_counter: Counter[str] = Counter()
    http_counter: Counter[str] = Counter()
    parser_errors_ref = [0]  # mutable cell passed to per-packet helper

    # Main packet walk — dpkt.pcap.Reader is a lazy iterator.
    for ts, buf in reader:
        facts.packets += 1
        facts.bytes_total += len(buf)

        if facts.packets > max_packets:
            facts.truncated = True
            # Back-correct: this packet is beyond the cap, don't count it.
            facts.packets -= 1
            facts.bytes_total -= len(buf)
            break

        if facts.first_ts is None:
            facts.first_ts = ts
        facts.last_ts = ts

        _process_packet(
            buf,
            link_type,
            ts,
            flow_pkts,
            flow_bytes,
            flow_ts,
            proto_counter,
            flag_counter,
            sni_counter,
            dns_counter,
            http_counter,
            parser_errors_ref,
        )

    facts.parser_errors = parser_errors_ref[0]

    # Finalise aggregates
    if facts.first_ts is not None and facts.last_ts is not None:
        facts.duration_s = facts.last_ts - facts.first_ts

    facts.proto_breakdown = dict(proto_counter.most_common(20))
    facts.tcp_flags_breakdown = dict(flag_counter.most_common(10))

    # Five-tuples: top-20 by packet count, include per-flow byte total.
    facts.five_tuples = [
        FiveTuple(src=s, sport=sp, dst=d, dport=dp, proto=pr, packets=n, bytes=flow_bytes[k])
        for k, n in flow_pkts.most_common(20)
        for (s, sp, d, dp, pr) in [k]
    ]

    # Inter-arrival timing: computed for the dominant flow (most packets).
    if flow_pkts:
        dominant = flow_pkts.most_common(1)[0][0]
        facts.inter_arrival = _compute_inter_arrival(flow_ts[dominant])

    facts.sni_list = [Counted(value=v, count=n) for v, n in sni_counter.most_common(50)]
    facts.dns_qnames = [Counted(value=v, count=n) for v, n in dns_counter.most_common(50)]
    facts.http_hosts = [Counted(value=v, count=n) for v, n in http_counter.most_common(50)]

    return facts
