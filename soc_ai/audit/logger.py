"""Audit logger - writes :class:`AuditEvent` records to Elasticsearch.

Index naming: ``{audit_index_alias}-YYYY.MM.dd`` (e.g. ``soc-ai-audit-2026.05.07``)
- a date-stamped index per UTC day so the operator can ILM/rotate easily. The
write alias ``audit_index_alias`` is configured separately in ES (manually for
v1; an ILM helper lands later if needed).

Tamper-evidence: each record carries a ``seq``/``prev_hash``/``hash`` hash chain
(see :mod:`soc_ai.audit.chain`). The chain head (``_last_hash``/``_seq``) is held
in memory and, on the first write after startup, recovered from the most-recent
record in ES so the chain continues across restarts. The increment is guarded by
an :class:`asyncio.Lock` so concurrent events cannot race the chain.

Fail policy: a READ/triage audit write that fails is logged locally and dropped
(audit loss is preferable to crashing an in-flight read). A *mutating* audit
write (an SO-state-changing ack/escalate/comment) that fails raises
:class:`AuditWriteError` when ``audit_fail_closed`` is True, so the caller aborts
the mutation rather than performing a state change with no audit record.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from soc_ai.audit.chain import GENESIS_PREV_HASH, GENESIS_SEQ, compute_hash
from soc_ai.audit.redact import redact_value
from soc_ai.audit.schemas import AuditEvent
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)


def _top_source(resp: Any) -> dict[str, Any]:
    """Extract ``hits.hits[0]._source`` from an ES search response as a dict.

    Returns ``{}`` for any non-conforming response (no hits, or — under a test
    double — a non-mapping object), so the caller falls back to genesis.
    """
    if not isinstance(resp, dict):
        return {}
    hits_outer = resp.get("hits")
    if not isinstance(hits_outer, dict):
        return {}
    hits = hits_outer.get("hits")
    if not isinstance(hits, list) or not hits:
        return {}
    first = hits[0]
    if not isinstance(first, dict):
        return {}
    src = first.get("_source")
    return src if isinstance(src, dict) else {}


class AuditWriteError(RuntimeError):
    """Raised when a *mutating* audit write fails and fail-closed is enabled.

    The caller (a write-tool / approval / auto-ack path) must treat this as a
    hard abort of the SO state change — no acknowledged/escalated alert without
    an audit record.
    """


class AuditLogger:
    """Indexes :class:`AuditEvent` records into the SO ES cluster."""

    def __init__(self, settings: Settings, elastic: ElasticClient) -> None:
        self._settings = settings
        self._elastic = elastic
        self._template_ensured = False
        # Hash-chain head. ``_seq`` is the seq of the LAST written record (so the
        # next record is ``_seq + 1``); -1 means "not yet initialised". Recovered
        # from ES on first write via _ensure_chain_head(), then maintained
        # in-memory. Guarded by ``_chain_lock`` so concurrent log() calls can't
        # race the increment / linkage.
        self._last_hash = GENESIS_PREV_HASH
        self._seq = -1
        self._chain_lock = asyncio.Lock()

    def _index_for(self, ts: datetime) -> str:
        return f"{self._settings.audit_index_alias}-{ts.strftime('%Y.%m.%d')}"

    async def _ensure_template(self) -> None:
        """Install (once) a composable index template mapping ``payload`` as
        ``flattened`` for the date-stamped audit indices.

        The audit ``payload`` is free-form per event kind: ``payload.result`` is
        an object for some tool results and a scalar (string/number) for others.
        Under ES dynamic mapping the first shape wins and every later doc with a
        different shape is rejected with ``document_parsing_exception`` — i.e.
        every hunt was silently dropping audit events. ``flattened`` stores the
        whole object as keyword key/value pairs, so it never conflicts on a
        sub-field's type while staying queryable.

        Best-effort + once per process: a failure (e.g. no template privilege)
        is logged and we fall back to dynamic mapping exactly as before. NOTE:
        templates only apply to NEWLY created indices — an already-broken
        date-stamped index must be deleted to recover (it is then recreated
        clean on the next write); it otherwise rolls over at the next UTC day.
        """
        if self._template_ensured:
            return
        self._template_ensured = True  # attempt exactly once (set before await)
        alias = self._settings.audit_index_alias
        try:
            await self._elastic._client.indices.put_index_template(
                name=f"{alias}-template",
                index_patterns=[f"{alias}-*"],
                template={"mappings": {"properties": {"payload": {"type": "flattened"}}}},
            )
        except Exception as e:
            _LOGGER.warning("audit index template install failed (continuing): %s", e)

    async def _ensure_chain_head(self) -> None:
        """Recover the hash-chain head from ES on the first write after startup.

        Reads the most-recent audit record (highest ``seq``) across all
        date-stamped indices and continues the chain from it, so the linkage
        survives a restart. If no chained record exists (fresh deployment, or an
        ES read error), the chain starts from genesis. Called under
        ``_chain_lock`` so it runs exactly once before the first increment.
        """
        if self._seq != -1:
            return
        alias = self._settings.audit_index_alias
        try:
            resp = await self._elastic._client.search(
                index=f"{alias}-*",
                body={
                    "size": 1,
                    "sort": [{"seq": {"order": "desc"}}],
                    # Only records that actually carry a seq (skip legacy docs).
                    "query": {"exists": {"field": "seq"}},
                },
            )
            src = _top_source(resp)
            last_seq = src.get("seq")
            last_hash = src.get("hash")
            if isinstance(last_seq, int) and isinstance(last_hash, str):
                self._seq = last_seq
                self._last_hash = last_hash
                return
        except Exception as e:
            # Index may not exist yet, or no read privilege — start from genesis.
            _LOGGER.info("audit chain head not recovered (starting from genesis): %s", e)
        self._seq = GENESIS_SEQ - 1
        self._last_hash = GENESIS_PREV_HASH

    async def log(self, event: AuditEvent, *, mutating: bool = False) -> None:
        """Index ``event`` into the date-stamped audit index.

        Applies redaction in-place if ``AUDIT_REDACT=true``, stamps the
        tamper-evident hash chain (``seq``/``prev_hash``/``hash``), then writes.

        Fail policy depends on ``mutating``:
        - ``mutating=False`` (read/triage/enrichment): swallow ES errors — audit
          must never crash a read-only investigation.
        - ``mutating=True`` (an SO-state-changing write): if the ES write fails
          AND ``audit_fail_closed`` is True, raise :class:`AuditWriteError` so
          the caller aborts the state change. If ``audit_fail_closed`` is False,
          behave fail-open (log + drop) like a read.
        """
        await self._ensure_template()
        if self._settings.audit_redact:
            redacted_payload, was_redacted = redact_value(event.payload)
            event.payload = redacted_payload
            if event.reasoning_trace is not None:
                new_trace, trace_redacted = redact_value(event.reasoning_trace)
                event.reasoning_trace = new_trace
                was_redacted = was_redacted or trace_redacted
            event.redacted = was_redacted

        index_name = self._index_for(event.timestamp)

        # Stamp the hash chain under the lock so the seq/prev_hash/hash are
        # assigned atomically and the in-memory head advances exactly once per
        # successfully-built record. The ES write happens inside the lock too so
        # the head only advances for a record we actually attempt to persist in
        # chain order (concurrency is low — one investigation at a time).
        async with self._chain_lock:
            await self._ensure_chain_head()
            seq = self._seq + 1
            prev_hash = self._last_hash
            event.seq = seq
            event.prev_hash = prev_hash

            body: dict[str, Any] = event.model_dump(mode="json")
            content = {k: v for k, v in body.items() if k != "hash"}
            digest = compute_hash(content, prev_hash)
            event.hash = digest
            body["hash"] = digest

            try:
                await self._elastic._client.index(index=index_name, body=body)
            except Exception as e:
                if mutating and self._settings.audit_fail_closed:
                    # Do NOT advance the chain head — this record was not
                    # persisted, so the next record links from the same prev.
                    _LOGGER.error(
                        "mutating audit write failed and fail-closed is on — "
                        "aborting the action: %s",
                        e,
                    )
                    raise AuditWriteError(
                        "audit write failed; mutating action aborted (fail-closed). "
                        "Check the audit ES index/credential and retry."
                    ) from e
                _LOGGER.warning("audit log write failed (event dropped): %s", e)
                return

            # Persisted — advance the in-memory head.
            self._seq = seq
            self._last_hash = digest

    async def log_kind(
        self,
        session_id: str,
        kind: str,
        payload: dict[str, Any],
        *,
        user: str = "unknown",
        approved_by: str | None = None,
        reasoning_trace: str | None = None,
        model_alias: str | None = None,
        reasoning_mode: str | None = None,
        mutating: bool = False,
    ) -> None:
        """Convenience wrapper - construct and index a single :class:`AuditEvent`.

        Pass ``mutating=True`` for an SO-state-changing write (ack/escalate/
        comment/auto-ack) so the fail-closed policy applies; leave it False for
        read/triage/enrichment events. ``approved_by`` records the resolved
        approver identity on a write-tool execution (None elsewhere).
        """
        event = AuditEvent(
            session_id=session_id,
            user=user,
            approved_by=approved_by,
            timestamp=datetime.now(UTC),
            kind=kind,  # type: ignore[arg-type]
            payload=payload,
            reasoning_trace=reasoning_trace,
            model_alias=model_alias,
            reasoning_mode=reasoning_mode,
        )
        await self.log(event, mutating=mutating)
