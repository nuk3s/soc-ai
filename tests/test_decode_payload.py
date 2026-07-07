"""Tests for the standalone payload decoder (``t_decode_payload``).

The decoder takes payload bytes ALREADY in evidence (the Suricata ``payload``
field is base64; ``payload_printable`` is text) and returns concrete facts:
printable strings, embedded indicators, entropy, and protocol hints. It must
never raise, whatever the input.
"""

from __future__ import annotations

import base64
import struct

import pytest
from soc_ai.tools.decode_payload import decode_payload


def _dns_query_bytes(qname: str) -> bytes:
    """Minimal DNS query message (header + one question) for ``qname``."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in qname.split("."):
        q += bytes([len(label)]) + label.encode("ascii")
    return header + q + b"\x00" + struct.pack("!HH", 1, 1)


@pytest.mark.asyncio
async def test_base64_http_request_auto_detected() -> None:
    raw = b"GET /gate.php HTTP/1.1\r\nHost: evil.example.com\r\nUser-Agent: x\r\n\r\n"
    facts = await decode_payload(base64.b64encode(raw).decode("ascii"))
    assert facts.encoding_used == "base64"
    assert facts.decoded_bytes == len(raw)
    assert facts.http_host == "evil.example.com"
    assert facts.protocol_guess == "http-request"
    assert "evil.example.com" in facts.domains
    assert any("Host: evil.example.com" in s for s in facts.strings)


@pytest.mark.asyncio
async def test_hex_auto_detected_extracts_strings() -> None:
    raw = b"whoami\x00\x01/bin/sh\x00"
    facts = await decode_payload(raw.hex())
    assert facts.encoding_used == "hex"
    assert facts.decoded_bytes == len(raw)
    assert "whoami" in facts.strings
    assert "/bin/sh" in facts.strings


@pytest.mark.asyncio
async def test_hex_preferred_over_base64_for_hex_charset() -> None:
    # "deadbeef" is ALSO valid base64; an all-hex-charset input must decode as hex.
    facts = await decode_payload("deadbeef")
    assert facts.encoding_used == "hex"
    assert facts.decoded_bytes == 4


@pytest.mark.asyncio
async def test_plain_text_indicator_extraction() -> None:
    text = "beacon to http://198.51.100.7:8080/gate.php then resolve c2.badguy.example ok"
    facts = await decode_payload(text)
    assert facts.encoding_used == "text"
    assert "http://198.51.100.7:8080/gate.php" in facts.urls
    assert "198.51.100.7" in facts.ipv4_addresses
    assert "c2.badguy.example" in facts.domains


@pytest.mark.asyncio
async def test_dns_message_qname_extracted() -> None:
    raw = _dns_query_bytes("c2.badguy.example")
    facts = await decode_payload(base64.b64encode(raw).decode("ascii"))
    assert facts.dns_qname == "c2.badguy.example"
    assert facts.protocol_guess == "dns-message"


@pytest.mark.asyncio
async def test_high_entropy_binary_noted() -> None:
    raw = bytes(range(256)) * 4  # uniform byte histogram => 8.0 bits/byte
    facts = await decode_payload(base64.b64encode(raw).decode("ascii"))
    assert facts.entropy_bits_per_byte > 7.9
    assert facts.printable_ratio < 0.5
    assert any("entropy" in n.lower() for n in facts.notes)


@pytest.mark.asyncio
async def test_empty_input_never_raises() -> None:
    facts = await decode_payload("")
    assert facts.decoded_bytes == 0
    assert facts.notes  # says why there is nothing to report


@pytest.mark.asyncio
async def test_invalid_explicit_base64_falls_back_to_text() -> None:
    facts = await decode_payload("!!!not base64 at all!!!", encoding="base64")
    assert facts.encoding_used == "text"
    assert any("base64" in n.lower() for n in facts.notes)


@pytest.mark.asyncio
async def test_strings_list_is_capped() -> None:
    # NUL separators split the input into 200 distinct printable runs.
    raw = "\x00".join(f"word{i:04d}" for i in range(200)).encode("ascii")
    facts = await decode_payload(base64.b64encode(raw).decode("ascii"))
    assert 0 < len(facts.strings) <= 40


@pytest.mark.asyncio
async def test_garbage_binary_never_raises() -> None:
    raw = b"\x00\xff\xfe\x01" * 50
    facts = await decode_payload(base64.b64encode(raw).decode("ascii"))
    assert facts.decoded_bytes == 200
    assert facts.protocol_guess is None
