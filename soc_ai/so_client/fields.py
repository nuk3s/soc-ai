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
  error or all-zero so it can never crash a query path.

``get_dotted`` lives here (not in :mod:`soc_ai.so_client.models`) so this module
is import-cycle-free: ``models.py`` imports *from* ``fields.py``, never the
reverse. The dotted-getter is the single canonical implementation; ``models.py``
re-exports it for backward compatibility.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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
# free. Keyed on (index, tuple(candidates)) so distinct logical fields and
# index patterns never collide.
_AGG_FIELD_CACHE: dict[tuple[str, tuple[str, ...]], str] = {}


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
) -> str:
    """Return the first candidate that actually has data on this deployment.

    Probes each candidate in order with the cheapest correct ``exists`` count
    and stops at the first with ``count > 0``, caching the result per
    ``(index, tuple(candidates))`` so repeated calls are free. On any error, or
    when no candidate has data, returns ``candidates[0]`` — the ECS-first
    default — so a query path can proceed (it never raises).
    """
    cand_tuple = tuple(candidates)
    default = cand_tuple[0]
    cache_key = (index, cand_tuple)
    cached = _AGG_FIELD_CACHE.get(cache_key)
    if cached is not None:
        return cached

    resolved = default
    try:
        for field in cand_tuple:
            if await _candidate_has_data(es_client, index, field):
                resolved = field
                break
    except Exception:
        # Never let field probing crash a query path — fall back to the
        # ECS-first default. (BLE001 is project-wide ignored; bare-broad is the
        # right call for a best-effort resolver.)
        return default

    _AGG_FIELD_CACHE[cache_key] = resolved
    return resolved


def _clear_agg_field_cache() -> None:
    """Reset the resolver cache (test hook only)."""
    _AGG_FIELD_CACHE.clear()
