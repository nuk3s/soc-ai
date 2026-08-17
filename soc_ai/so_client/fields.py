"""ECS-first Zeek/ECS field-resolution layer.

Modern Security Onion (Elastic-Agent 9.x) populates ECS field names —
``dns.query.name``, ``client.bytes``, ``hash.ja3s``, ``http.virtual_host`` —
while the ``zeek.*`` fields are *mapped but empty* (confirmed against the live
grid by doc-count: ``zeek.dns.query`` = 9 docs vs ``dns.query.name`` = 11.9M).
The synth eval fixtures, however, write the legacy ``zeek.*`` names. This module
gives every logical field an **ordered** candidate list (ECS first, ``zeek.*``
last) plus two coalescing readers so callers resolve the same logical value
regardless of which schema a given document/deployment uses:

- :func:`first_present` — per-document read: walk the candidates and return the
  first non-empty value (a ``0`` byte-count *is* a value; only ``None`` / ``""``
  / ``[]`` count as absent).
- :func:`resolve_agg_field` — per-deployment, cached: probe the cluster and
  return the first candidate that actually has data, for use as an aggregation
  / sort field name. Falls back to ``candidates[0]`` (the ECS default) on any
  error or all-zero so it can never crash a query path; ``on_probe_error``
  lets a caller observe the swallowed failure (a blind field CHOICE must not
  read as a grounded one to callers that gate irreversible writes on it).

``get_dotted`` lives here (not in :mod:`soc_ai.so_client.models`) so this module
is import-cycle-free: ``models.py`` imports *from* ``fields.py``, never the
reverse. The dotted-getter is the single canonical implementation; ``models.py``
re-exports it for backward compatibility.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from soc_ai.so_client.elastic import ElasticClient


def get_dotted(d: Mapping[str, Any], path: str) -> Any:
    """Navigate a dotted ECS path through nested or flat-dotted dicts.

    Returns ``None`` when any segment is missing or a non-dict is encountered
    mid-path. Tries the flat-dotted form first (``d["rule.name"]``) before
    descending into nested dicts (``d["rule"]["name"]``).
    """
    if path in d:
        return d[path]
    value: Any = d
    for segment in path.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(segment)
        if value is None:
            return None
    return value


# ---------------------------------------------------------------------------
# Candidate tables — logical field -> ORDERED ES field names (ECS first).
#
# Coalesce/resolve MUST try in this order. ECS names reflect what modern SO /
# Elastic-Agent 9.x populates (confirmed live by counts+samples); the trailing
# ``zeek.*`` names are the fallback for older SO and for synth eval fixtures.
# ---------------------------------------------------------------------------

# --- DNS ---
DNS_QUERY: tuple[str, ...] = ("dns.query.name", "dns.question.name", "zeek.dns.query")
DNS_RESOLVED_IP: tuple[str, ...] = ("dns.resolved_ip", "zeek.dns.answers")
# SO-computed registrable domain; PREFER this for suffix derivation when present.
DNS_REGISTERED_DOMAIN: tuple[str, ...] = ("dns.highest_registered_domain",)
DNS_TOP_LEVEL_DOMAIN: tuple[str, ...] = ("dns.top_level_domain",)
DNS_RCODE: tuple[str, ...] = ("dns.response.code_name", "zeek.dns.rcode_name")
DNS_QTYPE: tuple[str, ...] = ("dns.query.type_name", "zeek.dns.qtype_name")

# --- conn ---
CONN_ORIG_BYTES: tuple[str, ...] = ("client.bytes", "source.bytes", "zeek.conn.orig_bytes")
CONN_RESP_BYTES: tuple[str, ...] = ("server.bytes", "destination.bytes", "zeek.conn.resp_bytes")
CONN_TOTAL_BYTES: tuple[str, ...] = ("network.bytes",)
# NOTE: on Security Onion, event.duration carries Zeek's native SECONDS (verified
# against a live grid: avg ~40, max ~1.12e6 = ~13d). Do NOT add a nanosecond
# normalization — raw Elastic Zeek integrations may write ns, but SO does not.
CONN_DURATION: tuple[str, ...] = ("event.duration", "zeek.conn.duration")
CONN_STATE: tuple[str, ...] = ("connection.state", "zeek.conn.conn_state", "zeek.conn.state")
CONN_HISTORY: tuple[str, ...] = ("connection.history", "zeek.conn.history")
CONN_SERVICE: tuple[str, ...] = ("network.protocol", "zeek.conn.service")
CONN_TRANSPORT: tuple[str, ...] = ("network.transport", "zeek.conn.proto")
CONN_LOCAL_ORIG: tuple[str, ...] = ("connection.local.originator", "zeek.conn.local_orig")
CONN_LOCAL_RESP: tuple[str, ...] = ("connection.local.responder", "zeek.conn.local_resp")

# --- ssl / tls ---
SSL_JA3: tuple[str, ...] = ("hash.ja3", "tls.client.ja3", "zeek.ssl.ja3")
SSL_JA3S: tuple[str, ...] = ("hash.ja3s", "tls.server.ja3s", "zeek.ssl.ja3s")
SSL_SNI: tuple[str, ...] = ("ssl.server_name", "tls.client.server_name", "zeek.ssl.server_name")
SSL_VERSION: tuple[str, ...] = ("ssl.version", "tls.version", "zeek.ssl.version")
SSL_ESTABLISHED: tuple[str, ...] = ("ssl.established", "zeek.ssl.established")

# --- http ---
HTTP_HOST: tuple[str, ...] = ("http.virtual_host", "url.domain", "zeek.http.host", "http.host")
HTTP_METHOD: tuple[str, ...] = ("http.method", "http.request.method", "zeek.http.method")
HTTP_URI: tuple[str, ...] = ("http.uri", "url.path", "zeek.http.uri")
HTTP_STATUS: tuple[str, ...] = (
    "http.status_code",
    "http.response.status_code",
    "zeek.http.status_code",
)
HTTP_USER_AGENT: tuple[str, ...] = (
    "user_agent.original",
    "http.user_agent",
    "zeek.http.user_agent",
)

# --- files ---
FILE_MIME: tuple[str, ...] = ("file.mime_type", "zeek.files.mime_type")
FILE_MD5: tuple[str, ...] = ("file.hash.md5", "zeek.files.md5")
FILE_SHA256: tuple[str, ...] = ("file.hash.sha256", "zeek.files.sha256")
FILE_SIZE: tuple[str, ...] = ("file.size", "zeek.files.total_bytes")

# --- kerberos (credential-access: Kerberoasting / AS-REP roasting) ---
# The DECISIVE Kerberoasting signal is the ticket cipher — RC4-HMAC (etype 23,
# often rendered "rc4-hmac" / "0x17") requested for a service principal. No stable
# ECS mapping on SO, so read zeek.kerberos.* directly (ECS `kerberos.*` first in
# case a future integration populates it).
KERBEROS_CIPHER: tuple[str, ...] = ("kerberos.cipher", "zeek.kerberos.cipher")
KERBEROS_SERVICE: tuple[str, ...] = ("kerberos.service", "zeek.kerberos.service")
KERBEROS_CLIENT: tuple[str, ...] = ("kerberos.client", "zeek.kerberos.client")
KERBEROS_REQUEST_TYPE: tuple[str, ...] = ("kerberos.request_type", "zeek.kerberos.request_type")
KERBEROS_SUCCESS: tuple[str, ...] = ("kerberos.success", "zeek.kerberos.success")
# Domain membership: the realm a host authenticates INTO. SO populates
# ``client_realm``; the bare ``realm`` is a last-resort variant seen on raw
# Zeek integrations, so it trails.
KERBEROS_REALM: tuple[str, ...] = (
    "kerberos.realm",
    "zeek.kerberos.client_realm",
    "zeek.kerberos.realm",
)

# --- smb / dce-rpc (lateral movement: PsExec-style service creation) ---
# smb_files.name=PSEXESVC.exe + action=SMB::FILE_WRITE onto smb_mapping.service
# ADMIN$, then dce_rpc svcctl / CreateServiceW — the PsExec execution chain.
SMB_FILE_ACTION: tuple[str, ...] = ("smb.file.action", "zeek.smb_files.action")
SMB_FILE_NAME: tuple[str, ...] = ("smb.file.name", "zeek.smb_files.name")
SMB_FILE_PATH: tuple[str, ...] = ("smb.file.path", "zeek.smb_files.path")
SMB_MAPPING_SERVICE: tuple[str, ...] = ("smb.mapping.service", "zeek.smb_mapping.service")
SMB_MAPPING_SHARE_TYPE: tuple[str, ...] = ("smb.mapping.share_type", "zeek.smb_mapping.share_type")
DCE_RPC_ENDPOINT: tuple[str, ...] = ("dce_rpc.endpoint", "zeek.dce_rpc.endpoint")
DCE_RPC_OPERATION: tuple[str, ...] = ("dce_rpc.operation", "zeek.dce_rpc.operation")
# The NetBIOS name a host announces over SMB — an identity signal, not a
# lateral-movement one. ``zeek.dce_rpc.named_pipe`` is DELIBERATELY EXCLUDED:
# it carries ``srvsvc`` / ``svcctl`` / ``lsarpc``, which are endpoint names, so
# reading it as a hostname (as ``host_summary._SMB_HOSTNAME`` does, first in its
# list) reports the pipe as the machine's name.
SMB_HOST_NAME: tuple[str, ...] = ("smb.host_name", "zeek.smb.host_name")

# --- ssh (interactive lateral movement; a completed auth from a bad-reputation
# source is a confirmed intrusion) ---
SSH_AUTH_SUCCESS: tuple[str, ...] = ("ssh.auth_success", "zeek.ssh.auth_success")
SSH_AUTH_ATTEMPTS: tuple[str, ...] = ("ssh.auth_attempts", "zeek.ssh.auth_attempts")
SSH_CLIENT: tuple[str, ...] = ("ssh.client", "zeek.ssh.client")
SSH_SERVER: tuple[str, ...] = ("ssh.server", "zeek.ssh.server")
# The SSH banner is the strongest OS signal a headless Linux box emits:
# ``OpenSSH_9.6p1 Debian-3`` names the distribution outright, on a host that has
# no User-Agent and no vendor DNS telemetry to hint from. ``version`` is the
# protocol version and ``direction`` says which side of the handshake this
# record describes (a client banner identifies the ORIGINATOR, a server banner
# the RESPONDER) — reading the banner without the direction attributes the
# wrong OS to the wrong host.
SSH_VERSION: tuple[str, ...] = ("ssh.version", "zeek.ssh.version")
SSH_DIRECTION: tuple[str, ...] = ("ssh.direction", "zeek.ssh.direction")

# --- dhcp (lease-derived identity: the first-party name a host announces) ---
# A DHCP lease is the only signal that positively proves an address is
# dynamically assigned; its ABSENCE proves nothing unless the grid carries
# ``zeek.dhcp`` at all. ECS-first matters more here than anywhere else: on a
# modern SO grid the ``zeek.dhcp.*`` fields are mapped but empty, so a
# zeek-first read (``host_summary._DHCP_HOSTNAME``) sees no lease on a host
# that renews hourly.
DHCP_HOSTNAME: tuple[str, ...] = ("dhcp.hostname", "zeek.dhcp.host_name", "dhcp.host_name")
DHCP_CLIENT_FQDN: tuple[str, ...] = ("dhcp.client_fqdn", "zeek.dhcp.client_fqdn")
DHCP_DOMAIN: tuple[str, ...] = ("dhcp.domain", "zeek.dhcp.domain")
DHCP_MAC: tuple[str, ...] = ("dhcp.client.mac", "zeek.dhcp.mac")
# The hardware address, wherever the document happens to carry it. No zeek.*
# fallback exists: Zeek's conn log has no MAC, so the endpoint fields are the
# fallback rather than a legacy schema.
HOST_MAC: tuple[str, ...] = ("host.mac", "source.mac", "destination.mac")

# --- ntlm (Windows identity: the machine's own announcement of itself) ---
# NTLM negotiation carries the client's hostname, its domain, and the server's
# NetBIOS computer name — first-party identity claims that survive on a
# network-only grid where no host logs are shipped.
NTLM_HOSTNAME: tuple[str, ...] = ("ntlm.hostname", "zeek.ntlm.hostname")
NTLM_DOMAIN: tuple[str, ...] = ("ntlm.domainname", "zeek.ntlm.domainname")
NTLM_SERVER_NB: tuple[str, ...] = (
    "ntlm.server_nb_computer_name",
    "zeek.ntlm.server_nb_computer_name",
)

# --- software (Zeek's passive version detection) ---
# ``unparsed_version`` is the full banner ("Apache/2.4.58 (Debian)"); ``name``
# and ``software_type`` are Zeek's parse of it. All three are read because the
# banner often names the OS the parsed fields drop.
SOFTWARE_NAME: tuple[str, ...] = ("software.name", "zeek.software.name")
SOFTWARE_VERSION: tuple[str, ...] = ("software.unparsed_version", "zeek.software.unparsed_version")
SOFTWARE_TYPE: tuple[str, ...] = ("software.software_type", "zeek.software.software_type")

# --- behavioral-summary pivots (derived/aggregated docs) ---
# Some deployments surface a per-(host,dest) BEHAVIORAL SUMMARY document rather
# than only raw per-connection rows: RITA-style beacon scoring (interval + data-
# size consistency over a window) and DNS-tunnel aggregation (query volume +
# subdomain entropy + qtype mix). These are the decisive signals for C2 beacons
# and DNS covert channels — a single ET HUNTING/Informational alert plus one of
# these profiles is a confirmed detection. We read the whole profile OBJECT (a
# nested dict) via the candidate path; realistic integration names first, the
# eval fixture name last. Absent on ordinary docs (returns None).
BEACON_PROFILE: tuple[str, ...] = (
    "rita.beacon",
    "beacon.profile",
    "network.beacon_profile",
    "synth.beacon_profile",
)
DNS_TUNNEL_PROFILE: tuple[str, ...] = (
    "dns.tunnel_profile",
    "dns.summary",
    "network.dns_profile",
    "synth.dns_profile",
)


def _is_absent(value: Any) -> bool:
    """A value is *absent* iff it's ``None``, an empty string, or an empty list.

    A ``0`` byte-count, ``False``, and ``0.0`` are all REAL values — only
    ``None`` / ``""`` / ``[]`` (and other empty sequences) count as missing.
    """
    if value is None:
        return True
    if isinstance(value, str):
        return value == ""
    if isinstance(value, (list, tuple)):
        return len(value) == 0
    return False


def first_present(source: Mapping[str, Any], candidates: Sequence[str]) -> Any:
    """Return the first non-empty value among ``candidates`` read from ``source``.

    Each candidate is a dotted ECS path resolved via :func:`get_dotted` (handles
    both nested and flat-dotted document layouts). Empty values
    (``None`` / ``""`` / ``[]``) are skipped; a ``0`` byte-count is returned as a
    real value. Returns ``None`` when no candidate yields a value.
    """
    for candidate in candidates:
        value = get_dotted(source, candidate)
        if not _is_absent(value):
            return value
    return None


# Per-(index, candidates) cache of the resolved aggregation field. Once a
# candidate is confirmed to carry data on this deployment, repeated calls are
# free until the TTL lapses. Keyed on (index, tuple(candidates)) so distinct
# logical fields and index patterns never collide. Same TTL pattern as
# inventory.py's dataset-discovery cache, so a live schema migration (e.g. an
# Elastic-Agent upgrade moving data onto a different field) self-heals within
# minutes instead of requiring a process restart.
_AGG_FIELD_CACHE_TTL_SECONDS = 300.0
_AGG_FIELD_CACHE: dict[tuple[str, tuple[str, ...]], tuple[float, str]] = {}


async def _candidate_has_data(es_client: ElasticClient, index: str, field: str) -> bool:
    """True iff at least one doc in ``index`` has a value for ``field``.

    Cheapest correct probe: a ``size=0`` search with an ``exists`` filter,
    reading ``total``. Reuses :meth:`ElasticClient.search` (the only query
    method this client exposes) rather than a dedicated ``_count`` endpoint.
    """
    result = await es_client.search(
        index,
        {"exists": {"field": field}},
        size=0,
        track_total_hits=True,
    )
    return result.total > 0


async def resolve_agg_field(
    es_client: ElasticClient,
    index: str,
    candidates: Sequence[str],
    *,
    ttl_seconds: float = _AGG_FIELD_CACHE_TTL_SECONDS,
    on_probe_error: Callable[[Exception], None] | None = None,
) -> str:
    """Return the first candidate that actually has data on this deployment.

    Probes each candidate in order with the cheapest correct ``exists`` count
    and stops at the first with ``count > 0``, caching the result per
    ``(index, tuple(candidates))`` for ``ttl_seconds`` so repeated calls are
    free until the deployment's schema might plausibly have changed. On any
    error, or when no candidate has data, returns ``candidates[0]`` — the
    ECS-first default — so a query path can proceed (it never raises).

    ``on_probe_error`` makes the swallowed failure OBSERVABLE without changing
    the never-raise contract: when a probe raises, the exception is passed to
    the callback (once — the first failure aborts the walk) before the default
    is returned. A caller whose correctness depends on the field CHOICE being
    grounded — discovery's retirement gate must not treat "aggregated the
    ECS default because the probe blew up" as having read the estate — hooks
    this to count the resolution as a failed read. The all-zero fallback does
    NOT fire it: probes that ran and found no data are an observation of the
    grid, not a blind read. The callback must not raise.
    """
    cand_tuple = tuple(candidates)
    default = cand_tuple[0]
    cache_key = (index, cand_tuple)
    now = time.monotonic()
    cached = _AGG_FIELD_CACHE.get(cache_key)
    if cached is not None and now < cached[0]:
        return cached[1]

    resolved = default
    try:
        for field in cand_tuple:
            if await _candidate_has_data(es_client, index, field):
                resolved = field
                break
    except Exception as exc:
        # Never let field probing crash a query path — fall back to the
        # ECS-first default. (BLE001 is project-wide ignored; bare-broad is the
        # right call for a best-effort resolver.)
        if on_probe_error is not None:
            on_probe_error(exc)
        return default

    _AGG_FIELD_CACHE[cache_key] = (now + ttl_seconds, resolved)
    return resolved


def _clear_agg_field_cache() -> None:
    """Reset the resolver cache (test hook only)."""
    _AGG_FIELD_CACHE.clear()
