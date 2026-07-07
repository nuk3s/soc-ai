"""Runtime context and event types for investigations.

Shared by the pipeline, the toolset, and the API layer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.audit.logger import AuditLogger
from soc_ai.config import Settings
from soc_ai.enrichment.blocklists import BlocklistDB
from soc_ai.enrichment.cloud_tags import CloudPrefixDB
from soc_ai.enrichment.maxmind import MaxmindReader
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.enrichment import MispClient


class _DedupTracker:
    """Per-investigation tool-call dedup gate.

    Tracks ``(tool_name, normalized_args)`` tuples seen during the run.
    The investigator's tool wrappers consult :meth:`is_duplicate` and
    short-circuit with a structured ``{"duplicate_call": True, ...}``
    payload instead of re-running the underlying tool. This stops the
    "10 identical t_query_zeek_logs calls in a row" failure mode that
    analysis surfaced as the top driver of long-tail
    investigation latency.
    """

    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()

    def _key(self, tool_name: str, args: dict[str, Any]) -> tuple[str, str]:
        # Sort keys so {"a": 1, "b": 2} and {"b": 2, "a": 1} hash the same.
        return tool_name, json.dumps(args, sort_keys=True, default=str)

    def is_duplicate(self, tool_name: str, args: dict[str, Any]) -> bool:
        key = self._key(tool_name, args)
        if key in self._seen:
            return True
        self._seen.add(key)
        return False


@dataclass
class InvestigationContext:
    """Runtime dependencies shared by all tools in one investigation."""

    settings: Settings
    auth: SoAuthClient
    elastic: ElasticClient
    misp: MispClient | None = None
    audit: AuditLogger | None = None
    # Default time-window anchor for query tools. Set by the
    # orchestrator to ``alert.timestamp`` immediately after prefetch, so
    # the investigator's `t_query_*` tools center their search on the
    # alert's @timestamp instead of "last N minutes from now". Direct
    # callers (CLI / WebUI / tests) leave this ``None`` for live-monitor
    # behavior. Tools fall back to now-relative when this is absent.
    default_time_anchor: datetime | None = None
    # Dedup tracker. Per-investigation set of seen tool-call
    # signatures. The orchestrator builds a fresh one per `investigate()`
    # call so dedup state never leaks across runs.
    dedup: _DedupTracker = field(default_factory=_DedupTracker)
    # Pre-fetched community_ids (prefetch-first rule). The
    # orchestrator populates this from the alert's `community_id_events`
    # right after prefetch. The `t_query_zeek_logs` wrapper short-circuits
    # when the requested community_id is already covered by the prefetch.
    prefetched_community_ids: set[str] = field(default_factory=set)
    # Local enrichment sources (Task 15 of synth-first redesign). The
    # synth-first pipeline path constructs these from settings.blocklist_data_dir
    # / settings.maxmind_data_dir / settings.cloud_prefix_data_dir at startup.
    # Legacy callers pass empty defaults — the new t_enrich_* tools degrade
    # gracefully when blocklist/maxmind/cloud are empty.
    blocklist: BlocklistDB = field(default_factory=BlocklistDB)
    maxmind: MaxmindReader = field(default_factory=MaxmindReader)
    cloud: CloudPrefixDB = field(default_factory=CloudPrefixDB)
    # When True, the prefetch pivots are allowed to see synthetic
    # eval docs (`synth.scenario_id`). Prod leaves this False so synth
    # fixtures can never contaminate a real investigation; the eval harness
    # sets it True only when triaging a known synth alert.
    include_synth: bool = False
    # Internal-identifier discovery (increment 2c). The session factory for the
    # local store, threaded so the Oracle escalation path can resolve the
    # *effective* internal-identifier set (env-config union active detected/manual
    # identifiers, minus muted) from the ``internal_identifier`` table before
    # sanitizing the egress payload. ``None`` for direct callers (CLI / eval /
    # tests) that have no DB — the Oracle path then falls back to the raw
    # ``settings.oracle_internal_suffixes`` / ``oracle_extra_hosts`` tuples, so
    # behavior is unchanged when no DB (or an empty table) is present.
    db_sessionmaker: async_sessionmaker[AsyncSession] | None = None
    # Cloud-egress guard for the ANALYST model path. Set by the entrypoints
    # (orchestrator pipeline / hunt runner / chat managers) when
    # settings.analyst_cloud_redaction is on; None = no redaction (the
    # default — everything reaches the analyst model verbatim, correct for a
    # local model). When set, the toolset wraps every read tool so the model
    # only sees sanitized results, and the entrypoints sanitize prompts /
    # desanitize outputs against the same per-run label mapping.
    egress_guard: EgressGuard | None = None


class StepEvent(BaseModel):
    """One event emitted to the SSE stream."""

    kind: str
    session_id: str
    sequence: int
    payload: dict[str, Any]
