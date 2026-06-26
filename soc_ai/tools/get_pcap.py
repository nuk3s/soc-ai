"""PCAP fetch via SSH + Suricata pcap-log ring buffer.

Public surface
--------------
``fetch_pcap_bytes(settings, src_ip, dst_ip, ...)``
    SSH into the SO sensor, find candidate so-pcap.* files in the alert
    window, run ``sudo tcpdump -r <file> -w - <bpf>`` on each, merge the
    libpcap chunks, and return raw pcap bytes.

``get_pcap_facts(settings, src_ip, dst_ip, ...)``
    Thin wrapper: calls ``fetch_pcap_bytes`` then ``decode_pcap``.  Returns
    a ``PcapFacts`` on success or ``{"ok": False, "error": "..."}`` on every
    failure path — including when ``pcap_enabled=False``.

Security notes
--------------
* SSH/tcpdump commands are **arg-list subprocess calls** (``shell=False``).
  No f-string is ever interpolated into a shell command string that a
  subprocess will execute.
* ``src_ip`` / ``dst_ip`` are validated with ``ipaddress.ip_address()``
  before use.  Ports are coerced to ``int``.  Any value that fails
  validation short-circuits to an error dict without spawning a process.
* ``-o UserKnownHostsFile=<data_dir>/known_hosts`` pins the sensor host key
  to a service-owned, persistent file (not the read-only homedir). First
  contact is accepted (``StrictHostKeyChecking=accept-new``) and *remembered*,
  so a later sensor key swap is rejected rather than silently trusted (TOFU).

This module has **no I/O side-effects** when ``pcap_enabled=False`` — the
early-return path is exercised by the unit tests without any mocking of
subprocess.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import shlex
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from soc_ai.tools.pcap_decode import PcapFacts, decode_pcap

if TYPE_CHECKING:
    from soc_ai.config import Settings

_LOGGER = logging.getLogger(__name__)

# libpcap global header is exactly 24 bytes.
_PCAP_HEADER_LEN = 24

# Recognised libpcap magic numbers (little-endian native, big-endian native,
# nanosecond variants in both byte orders).
_PCAP_MAGICS: frozenset[bytes] = frozenset(
    {
        b"\xd4\xc3\xb2\xa1",  # LE microsecond (most common)
        b"\xa1\xb2\xc3\xd4",  # BE microsecond
        b"\x4d\x3c\xb2\xa1",  # LE nanosecond
        b"\xa1\xb2\x3c\x4d",  # BE nanosecond
    }
)


# ---------------------------------------------------------------------------
# SSH command builder
# ---------------------------------------------------------------------------


def _known_hosts_path(settings: Settings) -> Path:
    """Resolve the persistent SSH ``known_hosts`` path and ensure its parent exists.

    Defaults to ``<soc_ai_data_dir>/known_hosts`` when ``so_ssh_known_hosts`` is
    unset. The parent directory is created (the data dir normally already
    exists); the file itself is created by ssh on first contact.
    """
    path = settings.so_ssh_known_hosts or (settings.soc_ai_data_dir / "known_hosts")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _ssh_base_args(settings: Settings) -> list[str]:
    """Build the ``ssh <options> user@host`` arg-list prefix.

    All values come from validated ``Settings`` fields — no shell
    interpolation, no f-strings passed to a shell.
    """
    known_hosts = _known_hosts_path(settings)
    args: list[str] = [
        "ssh",
        "-o",
        # Persistent, service-owned known_hosts: accept the sensor key on first
        # contact and remember it, so a later key swap is rejected (not TOFU).
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={settings.so_ssh_timeout_s}",
    ]
    if settings.so_ssh_key is not None:
        args += ["-i", str(settings.so_ssh_key)]
    args.append(f"{settings.so_ssh_user}@{settings.so_ssh_host}")
    return args


# ---------------------------------------------------------------------------
# BPF construction (pure strings — fed as a single arg, not shell=True)
# ---------------------------------------------------------------------------


def _build_bpf(src_ip: str, dst_ip: str, src_port: int | None, dst_port: int | None) -> str:
    """Build a VLAN-aware BPF filter string.

    At minimum the two validated IPs are required.  Ports refine the filter
    when provided.  The filter uses the ``(F) or (vlan and F)`` VLAN-OR
    idiom so tagged 802.1Q frames are handled by tcpdump correctly.

    The returned string is passed as **one arg** to tcpdump via an arg-list
    (not shell=True), so embedded spaces and parentheses are fine.
    """
    # Host clause — bidirectional: must match BOTH endpoints.
    inner = f"host {src_ip} and host {dst_ip}"
    if src_port is not None and dst_port is not None:
        inner += f" and (port {src_port} and port {dst_port})"
    elif src_port is not None:
        inner += f" and port {src_port}"
    elif dst_port is not None:
        inner += f" and port {dst_port}"
    return f"({inner}) or (vlan and {inner})"


# ---------------------------------------------------------------------------
# Remote-file listing
# ---------------------------------------------------------------------------


def _build_find_command(settings: Settings, start_ts: datetime, end_ts: datetime) -> str:
    """Build the remote shell command for ``find`` + ``awk`` file enumeration.

    The command is a single string passed as the remote-command arg to ssh
    (ssh executes it via the remote shell).  No user-supplied values are
    interpolated — only settings fields and datetime values from the
    orchestrator's own computation.

    Returns a remote shell command string that:
    1. Finds so-pcap.* files with mtime >= window_start (find -newermt).
    2. Filters to files whose embedded unix-ts <= window_end (awk on
       the last dot-separated field in the filename).
    """
    after = start_ts.strftime("%Y-%m-%d %H:%M:%S")
    end_epoch = int(end_ts.timestamp())
    # ``so_suripcap_dir`` is operator config, not user input, and ``after`` is a
    # server-side timestamp — but we ``shlex.quote`` the dir as defense-in-depth
    # against operator-config self-injection into the remote shell string. The
    # ``after`` value is a fixed-format strftime so it cannot contain a quote.
    suripcap_dir = shlex.quote(settings.so_suripcap_dir)
    return (
        f"find {suripcap_dir} -name 'so-pcap.*' "
        f"-newermt '{after}' -printf '%p\\n' "
        f"| awk -F. -v end={end_epoch} '$NF+0 <= end+0 {{print}}'"
    )


def _list_remote_files(
    settings: Settings,
    start_ts: datetime,
    end_ts: datetime,
) -> list[str]:
    """SSH + find: return candidate so-pcap file paths on the sensor."""
    ssh_args = _ssh_base_args(settings)
    remote_cmd = _build_find_command(settings, start_ts, end_ts)
    proc = subprocess.run(  # noqa: S603 - arg-list, no shell; IPs pre-validated
        [*ssh_args, remote_cmd],
        capture_output=True,
        check=False,
        timeout=settings.so_ssh_timeout_s,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or b"").decode(errors="replace")[:400]
        low = stderr.lower()
        if "permission denied" in low or "publickey" in low or "authentication failed" in low:
            raise PermissionError(f"SSH auth failed to {settings.so_ssh_host}: {stderr}")
        raise RuntimeError(
            f"remote find exit={proc.returncode} on {settings.so_ssh_host}: {stderr}"
        )
    return [ln.strip() for ln in proc.stdout.decode().splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# Per-file tcpdump streaming
# ---------------------------------------------------------------------------


def _stream_filtered(settings: Settings, remote_path: str, bpf: str) -> bytes:
    """Run tcpdump on one remote pcap file with the BPF filter.

    Returns raw filtered pcap bytes (may be just the 24-byte global header
    if nothing matched — that is not an error).

    tcpdump exits 1 when the BPF matches no packets.  We treat that the
    same as exit 0 (empty but valid output).  Any other non-zero exit with
    stderr is treated as an error and logged (but callers skip the file and
    continue, not abort).

    The ``sudo_prefix`` is the first element of the remote command if
    ``settings.so_ssh_sudo`` is non-empty.  The command is built as a
    single remote-shell string (so the remote shell can split sudo from
    tcpdump), which is safe because ``remote_path`` comes from the trusted
    ``_list_remote_files`` output (a server filesystem path, not
    user-supplied) and ``bpf`` is built from validated IPs/ports only.
    """
    # ``so_ssh_sudo`` is operator config — shlex.quote it as defense-in-depth
    # against self-injection.  It may legitimately be a multi-word string (e.g.
    # ``sudo -n``); split on whitespace first, then quote each token so a normal
    # value is unchanged while an embedded metacharacter cannot break out.
    sudo_prefix = ""
    if settings.so_ssh_sudo:
        sudo_prefix = " ".join(shlex.quote(tok) for tok in settings.so_ssh_sudo.split()) + " "
    # remote_path is from the server's own filesystem listing; bpf is built
    # from validated ipaddress objects + int ports only.  Quote both with
    # shlex.quote in the remote shell command string for robustness against
    # spaces and as defense-in-depth.
    remote_cmd = (
        f"{sudo_prefix}tcpdump -nn -r {shlex.quote(remote_path)} "
        f"-w - {shlex.quote(bpf)} 2>/dev/null"
    )
    ssh_args = _ssh_base_args(settings)
    proc = subprocess.run(  # noqa: S603 - arg-list, no shell; path from server listing, BPF from validated IPs
        [*ssh_args, remote_cmd],
        capture_output=True,
        check=False,
        timeout=settings.so_ssh_timeout_s,
    )
    if proc.returncode not in (0, 1):
        # exit 1 = no BPF match (treated as empty); anything else is a
        # real error (file missing, sudo denied, read error, etc.).
        stderr = (proc.stderr or b"").decode(errors="replace")[:200]
        _LOGGER.warning("tcpdump on %s exit=%d: %s", remote_path, proc.returncode, stderr)
        return b""
    return proc.stdout or b""


# ---------------------------------------------------------------------------
# Chunk merge
# ---------------------------------------------------------------------------


def _merge_pcaps(chunks: list[bytes]) -> bytes:
    """Merge a list of libpcap byte streams into one.

    Keeps the 24-byte global header from the FIRST valid chunk; strips it
    from all subsequent chunks.  All chunks must have the same link-type and
    snap-length — they do, since they all originate from the same Suricata
    pcap-log ring.
    """
    out = bytearray()
    header_written = False
    for chunk in chunks:
        if not chunk or len(chunk) < _PCAP_HEADER_LEN:
            continue
        if chunk[:4] not in _PCAP_MAGICS:
            _LOGGER.warning("pcap chunk has unexpected magic %r — skipping", chunk[:4])
            continue
        if not header_written:
            out.extend(chunk)
            header_written = True
        else:
            out.extend(chunk[_PCAP_HEADER_LEN:])
    return bytes(out)


# ---------------------------------------------------------------------------
# Public fetch surface
# ---------------------------------------------------------------------------


def fetch_pcap_bytes(
    settings: Settings,
    src_ip: str,
    dst_ip: str,
    src_port: int | None,
    dst_port: int | None,
    start_ts: datetime,
    end_ts: datetime,
) -> bytes:
    """Fetch filtered pcap bytes from the SO sensor via SSH.

    Parameters
    ----------
    settings:
        Must have ``pcap_enabled=True`` (callers should check; this function
        assumes it).
    src_ip, dst_ip:
        **Pre-validated** IP strings (callers must run ``ipaddress.ip_address``
        before calling this).
    src_port, dst_port:
        Optional port numbers (already coerced to ``int``).
    start_ts, end_ts:
        UTC datetimes bounding the pcap-file search window.

    Returns
    -------
    bytes
        Merged libpcap bytes (may be empty if no files or no BPF match).

    Raises
    ------
    PermissionError
        SSH authentication failure.
    RuntimeError
        Remote find failure or any other subprocess error.
    """
    bpf = _build_bpf(src_ip, dst_ip, src_port, dst_port)
    files = _list_remote_files(settings, start_ts, end_ts)
    if not files:
        _LOGGER.info(
            "pcap fetch: no so-pcap files in window %s→%s on %s",
            start_ts.isoformat(),
            end_ts.isoformat(),
            settings.so_ssh_host,
        )
        return b""
    _LOGGER.info(
        "pcap fetch: %d candidate file(s) for BPF %r on %s",
        len(files),
        bpf,
        settings.so_ssh_host,
    )
    chunks: list[bytes] = []
    for f in files:
        data = _stream_filtered(settings, f, bpf)
        if data and len(data) > _PCAP_HEADER_LEN:
            chunks.append(data)
    return _merge_pcaps(chunks)


# ---------------------------------------------------------------------------
# Agent-facing tool entry point
# ---------------------------------------------------------------------------


async def get_pcap_facts(
    *,
    settings: Settings,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    window_minutes: int = 2,
    alert_ts: datetime | None = None,
) -> PcapFacts | dict[str, Any]:
    """Fetch + decode packets for a flow from the Security Onion sensor.

    **Disabled by default** (``settings.pcap_enabled=False``).  When
    disabled this returns a plain dict describing why without spawning
    any subprocess.

    On any failure (SSH error, no files, no BPF match, decode error)
    returns ``{"ok": False, "error": "..."}`` — never raises.

    Parameters
    ----------
    settings:
        Provides SSH coordinates and the ``pcap_enabled`` gate.
    src_ip, dst_ip:
        Flow endpoints.  **Both are required** and validated with
        ``ipaddress.ip_address()`` — any non-IP value returns an error
        dict immediately (injection-safe boundary).
    src_port, dst_port:
        Optional; coerced to ``int`` (``None`` skips port filtering).
    window_minutes:
        Search window half-width.  The window is centred on ``alert_ts``
        (or ``datetime.now(UTC)`` if omitted): ``[ts - window_minutes,
        ts + window_minutes]``.
    alert_ts:
        UTC timestamp of the alert.  Defaults to ``datetime.now(UTC)``.
    """
    # ------------------------------------------------------------------
    # Gate: pcap_enabled=False → no subprocess, no SSH
    # ------------------------------------------------------------------
    if not settings.pcap_enabled:
        return {
            "ok": False,
            "error": (
                "pcap retrieval disabled (set PCAP_ENABLED=true + provision "
                "the sensor SSH key via SO_SSH_KEY)"
            ),
        }

    # ------------------------------------------------------------------
    # Injection-safety: validate IPs, coerce ports
    # ------------------------------------------------------------------
    if not src_ip or not dst_ip:
        return {"ok": False, "error": "src_ip and dst_ip are both required"}

    try:
        validated_src = str(ipaddress.ip_address(src_ip.strip()))
    except ValueError:
        return {"ok": False, "error": f"invalid src_ip {src_ip!r} (not an IP address)"}

    try:
        validated_dst = str(ipaddress.ip_address(dst_ip.strip()))
    except ValueError:
        return {"ok": False, "error": f"invalid dst_ip {dst_ip!r} (not an IP address)"}

    try:
        coerced_src_port: int | None = int(src_port) if src_port is not None else None
    except (TypeError, ValueError):
        return {"ok": False, "error": f"invalid src_port {src_port!r}"}

    try:
        coerced_dst_port: int | None = int(dst_port) if dst_port is not None else None
    except (TypeError, ValueError):
        return {"ok": False, "error": f"invalid dst_port {dst_port!r}"}

    # ------------------------------------------------------------------
    # Time window
    # ------------------------------------------------------------------
    # ``alert_ts`` is typed ``datetime | None`` (the orchestrator passes
    # ``alert.timestamp``).  Guard the arithmetic anyway so a non-datetime
    # value can never raise out of this "never raises" surface — and so a
    # hostile string anchor short-circuits to an error dict without spawning
    # a subprocess (it could never reach the remote shell regardless, since
    # the command embeds only ``strftime``/``int(timestamp())`` output).
    anchor = alert_ts if alert_ts is not None else datetime.now(UTC)
    try:
        delta = timedelta(minutes=max(1, int(window_minutes)))
        start_ts = anchor - delta
        end_ts = anchor + delta
    except (TypeError, ValueError) as exc:
        return {"ok": False, "error": f"invalid alert_ts/window_minutes: {exc}"}

    # ------------------------------------------------------------------
    # Blocking SSH + tcpdump via asyncio.to_thread
    # ------------------------------------------------------------------
    try:
        raw_bytes: bytes = await asyncio.to_thread(
            fetch_pcap_bytes,
            settings,
            validated_src,
            validated_dst,
            coerced_src_port,
            coerced_dst_port,
            start_ts,
            end_ts,
        )
    except PermissionError as exc:
        _LOGGER.warning("get_pcap_facts: SSH auth failure: %s", exc)
        return {"ok": False, "error": f"SSH auth failure: {exc}"}
    except subprocess.TimeoutExpired:
        _LOGGER.warning(
            "get_pcap_facts: SSH/tcpdump timed out after %ds", settings.so_ssh_timeout_s
        )
        return {
            "ok": False,
            "error": f"SSH/tcpdump timed out after {settings.so_ssh_timeout_s}s",
        }
    except Exception as exc:
        _LOGGER.warning("get_pcap_facts: fetch error: %s", exc)
        return {"ok": False, "error": f"pcap fetch error: {type(exc).__name__}: {exc}"}

    # ------------------------------------------------------------------
    # tcpdump exit 1 (no match) → empty bytes → empty PcapFacts
    # ------------------------------------------------------------------
    if not raw_bytes:
        _LOGGER.info(
            "get_pcap_facts: no packets matched BPF for %s ↔ %s in window",
            validated_src,
            validated_dst,
        )
        facts = PcapFacts()
        facts.notes.append(
            f"no packets matched BPF for {validated_src} ↔ {validated_dst} "
            f"in window {start_ts.isoformat()} → {end_ts.isoformat()}"
        )
        return facts

    # ------------------------------------------------------------------
    # Decode
    # ------------------------------------------------------------------
    try:
        facts = decode_pcap(raw_bytes, max_packets=settings.pcap_max_packets)
    except Exception as exc:
        _LOGGER.warning("get_pcap_facts: decode error: %s", exc)
        return {"ok": False, "error": f"pcap decode error: {type(exc).__name__}: {exc}"}

    _LOGGER.info(
        "get_pcap_facts: decoded %d packets, %d bytes, %d flows for %s ↔ %s",
        facts.packets,
        facts.bytes_total,
        len(facts.five_tuples),
        validated_src,
        validated_dst,
    )
    return facts


__all__ = [
    "fetch_pcap_bytes",
    "get_pcap_facts",
]
