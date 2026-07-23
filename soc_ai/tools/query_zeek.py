"""``query_zeek_logs`` tool - pivot into Zeek logs by ``network.community_id``.

The community_id is a hash of the network 5-tuple, computed identically by
Zeek and Suricata, which makes it the canonical pivot key for joining alerts
to the underlying connection record and any Zeek protocol-decoder output
(``conn``, ``dns``, ``http``, ``ssl``, ``files``, …).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client import fields
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import first_present
from soc_ai.tools._registry import tool
from soc_ai.tools.query_events import _MAX_TIME_RANGE_MINUTES, _build_time_filter

DEFAULT_LOG_TYPES: tuple[str, ...] = ("conn", "dns", "http", "ssl", "files", "ssh")

# Logical-field -> ordered ES candidate names. Coalesced onto a STABLE logical
# key on output so the agent reads the same key regardless of SO version. The
# value is taken ECS-first via :func:`first_present`; the ``zeek.*`` form is the
# fallback for older SO and the synth fixtures. The keys are the legacy
# ``zeek.<ds>.<field>`` names the prompts/agent already cite, so existing
# guidance keeps working while the VALUE now resolves on a modern grid.
_COALESCE_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("zeek.conn.duration", fields.CONN_DURATION),
    ("zeek.conn.orig_bytes", fields.CONN_ORIG_BYTES),
    ("zeek.conn.resp_bytes", fields.CONN_RESP_BYTES),
    ("zeek.conn.conn_state", fields.CONN_STATE),
    ("zeek.conn.history", fields.CONN_HISTORY),
    ("zeek.dns.query", fields.DNS_QUERY),
    ("zeek.dns.answers", fields.DNS_RESOLVED_IP),
    ("zeek.dns.rcode_name", fields.DNS_RCODE),
    ("zeek.http.method", fields.HTTP_METHOD),
    ("zeek.http.host", fields.HTTP_HOST),
    ("zeek.http.uri", fields.HTTP_URI),
    ("zeek.http.status_code", fields.HTTP_STATUS),
    ("zeek.http.user_agent", fields.HTTP_USER_AGENT),
    ("zeek.ssl.server_name", fields.SSL_SNI),
    ("zeek.ssl.ja3", fields.SSL_JA3),
    ("zeek.ssl.ja3s", fields.SSL_JA3S),
    ("zeek.ssl.version", fields.SSL_VERSION),
    ("zeek.files.mime_type", fields.FILE_MIME),
    ("zeek.files.md5", fields.FILE_MD5),
    ("zeek.files.sha256", fields.FILE_SHA256),
    ("zeek.files.total_bytes", fields.FILE_SIZE),
)

# The full _source projection: the stable 5-tuple/identity fields plus EVERY
# candidate name across all logical fields, so data is returned regardless of
# which schema this SO version populates. De-duplicated, order-stable.
_STABLE_SOURCE_FIELDS: tuple[str, ...] = (
    "@timestamp",
    "event.dataset",
    "network.community_id",
    "network.transport",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "host.name",
    # Zeek-only fields with no ECS coalesce target but still useful to the agent.
    "zeek.ssl.subject",
    "zeek.ssl.issuer",
    "zeek.files.filename",
    # SSH — the lateral-movement workhorse. Without these on the projection an
    # ssh hit came back field-stripped, reinforcing a false "no SSH" conclusion.
    "zeek.ssh.auth_success",
    "zeek.ssh.auth_attempts",
    "zeek.ssh.client",
    "zeek.ssh.server",
    "zeek.ssh.version",
    "zeek.ssh.direction",
)


def _build_source_projection() -> list[str]:
    """Stable fields + every candidate name across all coalesced logical fields.

    Requesting the full candidate set means real data is returned whether the
    grid populates ECS names (``dns.query.name``) or legacy ``zeek.*`` names.
    Order-stable + de-duplicated.
    """
    seen: dict[str, None] = {}
    for f in _STABLE_SOURCE_FIELDS:
        seen.setdefault(f, None)
    for _key, candidates in _COALESCE_FIELDS:
        for c in candidates:
            seen.setdefault(c, None)
    return list(seen)


def _coalesce_source(source: dict[str, Any]) -> dict[str, Any]:
    """Add a stable logical key for each coalesced field, ECS-first.

    The raw ``_source`` is preserved as-is; for each logical field we set the
    legacy ``zeek.<ds>.<field>`` key to the first present candidate value (ECS
    first), so the agent reads the same key on every SO version. A ``0``
    byte-count is a real value (preserved); an all-absent field is skipped (the
    key is simply not added).
    """
    enriched = dict(source)
    for key, candidates in _COALESCE_FIELDS:
        value = first_present(source, candidates)
        if value is not None:
            enriched[key] = value
    return enriched


@tool(read_only=True, description="Pivot into Zeek logs by network.community_id.")
async def query_zeek_logs(
    community_id: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    log_types: list[str] | None = None,
    time_range_minutes: int = 60,
    max_results: int = 100,
    time_anchor: datetime | None = None,
) -> list[dict[str, Any]]:
    """Fetch Zeek log records sharing a Community ID, sorted oldest-first.

    Args:
        community_id: the value to match against ``network.community_id``.
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern``).
        log_types: Zeek dataset suffixes to include (e.g. ``["conn", "dns"]``).
            Defaults to ``conn``, ``dns``, ``http``, ``ssl``, ``files``.
        time_range_minutes: window size in minutes. Default 60, capped at
            ``_MAX_TIME_RANGE_MINUTES`` (43_200 = 30 days).
        max_results: hard cap on returned records.
        time_anchor: when set, center the window on this timestamp
            (``[anchor - rng/2, anchor + rng/2]``) instead of the
            now-relative default. The orchestrator passes
            ``alert.timestamp`` here so batch-eval queries actually find
            evidence (issue #12).

    Returns:
        A list of raw ``_source`` dicts. The agent typically reads a handful
        of fields per record (`event.dataset`, source/destination 5-tuple,
        `zeek.<dataset>.*`) without needing a typed model wrapper.
    """
    if not community_id:
        raise ValueError("community_id is required")
    if max_results <= 0:
        raise ValueError(f"max_results must be positive, got {max_results}")
    if time_range_minutes <= 0:
        raise ValueError(f"time_range_minutes must be positive, got {time_range_minutes}")
    if time_range_minutes > _MAX_TIME_RANGE_MINUTES:
        raise ValueError(
            f"time_range_minutes must be <= {_MAX_TIME_RANGE_MINUTES}, got {time_range_minutes}"
        )

    types = tuple(log_types) if log_types else DEFAULT_LOG_TYPES
    datasets = [f"zeek.{t}" for t in types]

    query: dict[str, Any] = {
        "bool": {
            "must": [
                {"term": {"network.community_id": community_id}},
                {"term": {"event.module": "zeek"}},
                {"terms": {"event.dataset": datasets}},
            ],
            "filter": [_build_time_filter(time_range_minutes, time_anchor)],
        }
    }

    result = await elastic.search(
        settings.events_index_pattern,
        query,
        size=max_results,
        sort=[{"@timestamp": {"order": "asc"}}],
        # Project only the fields the agent actually reads (full `_source` blobs
        # for 100 zeek logs blow past a small model's context on the next turn),
        # but request the FULL ECS+zeek candidate set so real conn bytes / ja3 /
        # sni / dns are returned regardless of SO version.
        source=_build_source_projection(),
    )
    # Coalesce each logical field ECS-first onto its stable legacy key so the
    # agent reads the same field on a modern (ECS) grid as on an old / synth one.
    return [_coalesce_source(hit.get("_source", {})) for hit in result.hits]
