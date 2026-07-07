"""``decode_payload`` — decode payload bytes already in evidence into facts.

Suricata alert documents carry the matched packet bytes as base64 in
``payload`` (and a lossy printable rendering in ``payload_printable``). The
prefetch keeps only the printable form; the raw form is one
``t_get_event_raw`` away. This tool turns either into concrete, citable
facts — printable strings, embedded indicators (domains / URLs / IPs),
Shannon entropy, and L7 protocol hints — so the agent decodes evidence
instead of eyeballing raw bytes. Unlike ``t_get_pcap`` it needs no SSH and
works after the pcap ring buffer has rotated: the bytes live in ES forever.

Design principles (shared with :mod:`soc_ai.tools.pcap_decode`):

* **Never raises on malformed input.** Garbage in ⟹ a sparse
  :class:`PayloadFacts` with a note, not an exception.
* **No I/O.** Pure in-process compute; the caller owns fetch.
* **Bounded output.** Strings/indicator lists and the preview are capped so
  a hostile payload cannot blow up the model context.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import struct
from collections import Counter

from pydantic import BaseModel, Field

from soc_ai.tools._registry import tool
from soc_ai.tools.pcap_decode import (
    _try_decode_dns,
    _try_decode_http,
    _try_decode_tls_sni,
)

_MAX_INPUT_CHARS = 1_000_000
_MAX_STRINGS = 40
_MAX_STRING_LEN = 200
_MAX_INDICATORS = 20
_PREVIEW_BYTES = 256

_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e]{4,}")
_URL_RE = re.compile(r"https?://[^\s\"'<>\x00-\x1f]{3,300}")
_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Domain-regex false positives: filenames whose extension parses as a "TLD".
_NOT_TLDS = frozenset(
    {
        "asp",
        "aspx",
        "bin",
        "css",
        "dat",
        "dll",
        "exe",
        "gif",
        "htm",
        "html",
        "jpg",
        "js",
        "jsp",
        "php",
        "png",
        "tmp",
        "txt",
        "zip",
    }
)


class PayloadFacts(BaseModel):
    """Structured output of a single ``decode_payload`` call."""

    encoding_used: str  # how the input was interpreted: base64 | hex | text
    decoded_bytes: int = 0
    entropy_bits_per_byte: float = 0.0
    printable_ratio: float = 0.0
    # Printable-escaped rendering of the first bytes (non-printables => '.').
    preview: str = ""
    strings: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    ipv4_addresses: list[str] = Field(default_factory=list)
    # L7 sniff over the decoded bytes (best-effort, may all be None).
    protocol_guess: str | None = None  # tls-client-hello | http-request | dns-message
    dns_qname: str | None = None
    http_host: str | None = None
    tls_sni: str | None = None
    notes: list[str] = Field(default_factory=list)


def _decode_input(data: str, encoding: str, notes: list[str]) -> tuple[bytes, str]:
    """Interpret ``data`` per ``encoding`` (auto: hex > base64 > text).

    An all-hex-charset input is preferred as hex — every hex string is also
    valid base64, so base64-first would silently mis-decode hex dumps.
    Invalid explicit encodings fall back to text with a note, never raise.
    """
    compact = "".join(data.split())

    def _try_hex() -> bytes | None:
        if len(compact) >= 2 and len(compact) % 2 == 0 and _HEX_RE.fullmatch(compact):
            try:
                return bytes.fromhex(compact)
            except ValueError:
                return None
        return None

    def _try_b64() -> bytes | None:
        if len(compact) >= 4 and len(compact) % 4 == 0 and _BASE64_RE.fullmatch(compact):
            try:
                return base64.b64decode(compact, validate=True)
            except (binascii.Error, ValueError):
                return None
        return None

    if encoding == "hex":
        raw = _try_hex()
        if raw is not None:
            return raw, "hex"
        notes.append("input is not valid hex — treated it as text instead")
    elif encoding == "base64":
        raw = _try_b64()
        if raw is not None:
            return raw, "base64"
        notes.append("input is not valid base64 — treated it as text instead")
    elif encoding == "auto":
        raw = _try_hex()
        if raw is not None:
            return raw, "hex"
        raw = _try_b64()
        if raw is not None:
            return raw, "base64"
    elif encoding != "text":
        notes.append(f"unknown encoding {encoding!r} — treated input as text")
    return data.encode("utf-8", errors="replace"), "text"


def _entropy_bits_per_byte(raw: bytes) -> float:
    if not raw:
        return 0.0
    counts = Counter(raw)
    n = len(raw)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _sniff_dns(raw: bytes) -> str | None:
    """Gate the DNS sniff so arbitrary text/binary can't misfire as a qname."""
    if len(raw) < 17:
        return None
    try:
        qdcount = struct.unpack("!H", raw[4:6])[0]
    except struct.error:
        return None
    if not 1 <= qdcount <= 4:
        return None
    qname = _try_decode_dns(raw)
    if qname and "." in qname and len(qname) >= 4 and _DOMAIN_RE.fullmatch(qname):
        return qname
    return None


def _dedupe_capped(values: list[str], cap: int = _MAX_INDICATORS) -> list[str]:
    seen: dict[str, None] = {}
    for v in values:
        if v not in seen:
            seen[v] = None
        if len(seen) >= cap:
            break
    return list(seen)


@tool(
    read_only=True,
    description=(
        "Decode payload bytes (base64/hex/text) into printable strings, embedded "
        "indicators, entropy, and protocol hints — local, no egress."
    ),
)
async def decode_payload(data: str, encoding: str = "auto") -> PayloadFacts:
    """Decode payload bytes into structured, citable facts.

    Args:
        data: the payload — base64 (Suricata ``payload``), a hex dump, or
            printable text (``payload_printable``).
        encoding: ``"auto"`` (default; hex > base64 > text), or force one of
            ``"base64"`` / ``"hex"`` / ``"text"``.

    Returns:
        :class:`PayloadFacts` — always. Never raises, even on garbage input.
    """
    notes: list[str] = []
    if len(data) > _MAX_INPUT_CHARS:
        notes.append(f"input truncated to {_MAX_INPUT_CHARS} chars before decoding")
        data = data[:_MAX_INPUT_CHARS]

    raw, encoding_used = _decode_input(data, encoding, notes)
    if not raw:
        notes.append("empty input — nothing to decode")
        return PayloadFacts(encoding_used=encoding_used, notes=notes)

    entropy = _entropy_bits_per_byte(raw)
    printable = sum(1 for b in raw if 0x20 <= b <= 0x7E)
    printable_ratio = printable / len(raw)

    runs = [m.group().decode("ascii")[:_MAX_STRING_LEN] for m in _PRINTABLE_RUN_RE.finditer(raw)]
    text_projection = "\n".join(runs)

    urls = _dedupe_capped(_URL_RE.findall(text_projection))
    domains = _dedupe_capped(
        [
            d
            for d in _DOMAIN_RE.findall(text_projection)
            if d.rsplit(".", 1)[-1].lower() not in _NOT_TLDS
            # Path components of an extracted URL are not standalone domains.
            and not any(d in u.split("//", 1)[-1].split("/", 1)[-1] for u in urls)
        ]
    )
    ipv4 = _dedupe_capped(
        [
            ip
            for ip in _IPV4_RE.findall(text_projection)
            if all(int(o) <= 255 for o in ip.split("."))
        ]
    )

    tls_sni = _try_decode_tls_sni(raw)
    http_host = _try_decode_http(raw)
    dns_qname = _sniff_dns(raw)
    protocol_guess = (
        "tls-client-hello"
        if tls_sni
        else "http-request"
        if http_host
        else "dns-message"
        if dns_qname
        else None
    )

    if entropy >= 7.3 and len(raw) >= 64:
        notes.append("high entropy (>=7.3 bits/byte) — likely encrypted or compressed content")
    elif printable_ratio >= 0.9 and len(raw) >= 16:
        notes.append("mostly printable text")

    return PayloadFacts(
        encoding_used=encoding_used,
        decoded_bytes=len(raw),
        entropy_bits_per_byte=round(entropy, 3),
        printable_ratio=round(printable_ratio, 3),
        preview="".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in raw[:_PREVIEW_BYTES]),
        strings=runs[:_MAX_STRINGS],
        domains=domains,
        urls=urls,
        ipv4_addresses=ipv4,
        protocol_guess=protocol_guess,
        dns_qname=dns_qname,
        http_host=http_host,
        tls_sni=tls_sni,
        notes=notes,
    )
