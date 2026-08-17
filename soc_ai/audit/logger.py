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

Every write is bounded — see :data:`_BEST_EFFORT_WRITE_BUDGET` and
:meth:`AuditLogger._write_timeout_s`. Without a bound of its own an audit write
rides the ES client's retry budget (``(1 + es_max_retries) x
es_request_timeout_s``, ~90 s at shipped defaults) on top of whatever the caller
already spent, which is how ``GET /config/model-fitness`` came to be abandoned by
the browser at 20 s instead of answered by the server. A bound makes one outcome
ambiguous — the request was on the wire when it expired — so an expired write
leaves the chain head UNKNOWN and the next write re-reads it from the index,
rather than reusing a ``seq`` that may already be taken.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from soc_ai.audit.chain import GENESIS_PREV_HASH, GENESIS_SEQ, compute_hash
from soc_ai.audit.redact import redact_value
from soc_ai.audit.schemas import AuditEvent
from soc_ai.audit.verify import _raise_if_partial
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, GridPartialResultsError

_LOGGER = logging.getLogger(__name__)

# Share of ``webui_grid_timeout_s`` a best-effort (non-mutating) audit write may
# spend. One small index call, and its documented failure policy is already "log
# locally and drop" — so waiting longer buys nothing, while holding a console
# request open costs the operator their page. A mutating write is a different
# animal and gets the whole budget (see :meth:`AuditLogger._write_timeout_s`).
# Floored at 1 s in that method so a small ``webui_grid_timeout_s`` can never
# round the bound down to an instant expiry.
_BEST_EFFORT_WRITE_BUDGET = 0.25


def _top_source(resp: Any) -> dict[str, Any]:
    """Extract ``hits.hits[0]._source`` from an ES search response as a dict.

    Returns ``{}`` for any non-conforming response (no hits, or — under a test
    double — a non-mapping object), so the caller falls back to genesis.

    elasticsearch-py 8.x answers :class:`elastic_transport.ObjectApiResponse`,
    which is neither a ``dict`` nor a ``Mapping`` — it has to be unwrapped via
    ``.body`` or the REAL client's response reads as non-conforming and every
    process restart "recovers" an empty head and renumbers the chain from
    genesis. A Mock double's ``.body`` is another Mock, not a dict, so the
    tolerance for test doubles is unchanged.
    """
    if not isinstance(resp, dict):
        resp = getattr(resp, "body", None)
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

    The caller (a write-tool / auto-ack path) must treat this as a
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
        # Set when a write's outcome could not be classified (its bound expired
        # with the index request already on the wire). The head then has to be
        # re-read from ES before the next record is stamped — see
        # _ensure_chain_head() and log()'s TimeoutError arm.
        self._head_uncertain = False
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
        """Recover the hash-chain head from ES when it is unknown.

        Reads the most-recent audit record (highest ``seq``) across all
        date-stamped indices and continues the chain from it, so the linkage
        survives a restart. With no head to hold on to and no chained record to
        find (fresh deployment, or an ES read error on the first write), the
        chain starts from genesis. Called under ``_chain_lock``, so it settles
        the head before any increment and never races one.

        Two things make the head unknown: process start (``_seq == -1``), and a
        write whose outcome nobody can classify (``_head_uncertain`` — see
        :meth:`log`). The second is why this is not a once-per-process recovery:
        a record that landed after its bound expired is IN the index, and reading
        the head back is the only way to continue after it rather than on top of
        it. One search, on the next write's own budget.

        Recovery is attempted once per uncertainty, not once per write: a healthy
        grid must not pay a round trip per audit event to guard against an
        outcome that did not happen. If the re-read fails and a head is already
        held, that head is kept — the same guess the logger made before this
        recovery existed, so a failed recovery is never worse than no recovery.

        A HALF-read is neither a found head nor a failure, and it must not be
        allowed to masquerade as either: ES answers 200 off the surviving shards,
        so without the :func:`~soc_ai.audit.verify._raise_if_partial` check below
        a stale top hit resumes the chain from an old seq (reusing seqs still
        live on the dead shards) and an empty page restarts it at genesis on top
        of the existing records — both of which every later verify reports as
        TAMPER, permanently, for a grid that was merely degraded. So a partial
        read keeps a held head (like any failed re-read) and, with no head to
        hold, raises :class:`GridPartialResultsError` so :meth:`_write` defers
        the record instead of stamping it with a guessed seq.
        """
        if self._seq != -1 and not self._head_uncertain:
            return
        uncertain = self._head_uncertain
        self._head_uncertain = False
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
            # Raw _client handle — the wrapper's partial-read guard never runs
            # here, so carry it explicitly (see the docstring for what a
            # half-read head costs).
            _raise_if_partial(
                f"{alias}-*",
                resp,
                consequence="the chain head cannot be recovered from a partial read",
            )
            src = _top_source(resp)
            last_seq = src.get("seq")
            last_hash = src.get("hash")
            if isinstance(last_seq, int) and isinstance(last_hash, str):
                self._seq = last_seq
                self._last_hash = last_hash
                return
        except GridPartialResultsError as e:
            if uncertain and self._seq != -1:
                # Same stance as a failed re-read below: keep the last known
                # head rather than adopt whatever the surviving shards showed.
                _LOGGER.warning(
                    "audit chain head could not be re-read after an unacknowledged "
                    "write (%s) — continuing from the last known head (seq=%s); if "
                    "that write did land, its seq is reused and verify-chain will "
                    "report the trail broken there",
                    e,
                    self._seq,
                )
                return
            _LOGGER.warning(
                "audit chain head recovery read only part of the audit index (%s) — "
                "refusing to resume from a stale head or restart at genesis; the "
                "record is deferred until the index can be fully read",
                e,
            )
            raise
        except Exception as e:
            # Index may not exist yet, or no read privilege — start from genesis.
            _LOGGER.info("audit chain head not recovered (starting from genesis): %s", e)
        if uncertain and self._seq != -1:
            # A re-read that found nothing must not restart a chain that already
            # exists at genesis: that renumbers every future record from 0 and
            # breaks the trail far worse than the one seq this is recovering
            # from. Keep the last known head and carry on.
            _LOGGER.warning(
                "audit chain head could not be re-read after an unacknowledged write — "
                "continuing from the last known head (seq=%s); if that write did land, "
                "its seq is reused and verify-chain will report the trail broken there",
                self._seq,
            )
            return
        self._seq = GENESIS_SEQ - 1
        self._last_hash = GENESIS_PREV_HASH

    def _write_timeout_s(self, *, mutating: bool) -> float:
        """Wall-clock bound for one audit write, derived from the console budget.

        A mutating write gets the FULL ``webui_grid_timeout_s`` — four times the
        best-effort slice — because it GATES a state change: under fail-closed,
        giving up on it aborts an ack the analyst asked for. Trading a real action
        away to save a caller a few seconds is the wrong side of that bargain, so
        it waits as long as an interactive grid read is allowed to. A best-effort
        write buys nothing by waiting (it is dropped on any error today), so it
        gets a slice.
        """
        budget = float(self._settings.webui_grid_timeout_s)
        return budget if mutating else max(1.0, budget * _BEST_EFFORT_WRITE_BUDGET)

    async def log(self, event: AuditEvent, *, mutating: bool = False) -> None:
        """Index ``event`` into the date-stamped audit index, under a bound.

        Applies redaction in-place if ``AUDIT_REDACT=true``, stamps the
        tamper-evident hash chain (``seq``/``prev_hash``/``hash``), then writes.

        Fail policy depends on ``mutating``:
        - ``mutating=False`` (read/triage/enrichment): swallow ES errors — audit
          must never crash a read-only investigation.
        - ``mutating=True`` (an SO-state-changing write): if the ES write fails
          AND ``audit_fail_closed`` is True, raise :class:`AuditWriteError` so
          the caller aborts the state change. If ``audit_fail_closed`` is False,
          behave fail-open (log + drop) like a read.

        A write that never comes back is a THIRD outcome and gets the same policy
        as a failure, deliberately: bounding a write must not quietly turn
        fail-closed into fail-open, so a mutating write that expires still aborts
        its caller's state change. What differs is what is said about it. A failed
        write is known not to have landed; an expired one is UNKNOWN — the request
        went out and was never acknowledged — so the log says so instead of
        asserting a drop.

        That unknown reaches the hash chain, and it is not allowed to be guessed
        there. A stalled grid answers late; it does not refuse. So the record
        whose acknowledgement never arrived is quite likely IN the index, while
        the in-memory head still points at its predecessor — and simply carrying
        on would stamp the next record with the same ``seq``, which
        :func:`~soc_ai.audit.chain.verify_chain` reports as an inserted or edited
        record, permanently, for a grid that was merely slow. Neither guess is
        safe (skipping a seq leaves a gap, which reads the same way), so the head
        is marked UNKNOWN and re-read from the index before the next record is
        stamped: correct whichever way the ambiguous write went.
        """
        budget = self._write_timeout_s(mutating=mutating)
        try:
            async with asyncio.timeout(budget):
                await self._write(event, mutating=mutating)
        except TimeoutError as exc:
            # Whatever is said below, the chain head is no longer trustworthy.
            self._head_uncertain = True
            if mutating and self._settings.audit_fail_closed:
                _LOGGER.error(
                    "mutating audit write did not answer within %.1fs and fail-closed is on "
                    "— aborting the action (kind=%s, seq=%s; the record may or may not "
                    "have landed)",
                    budget,
                    event.kind,
                    event.seq,
                )
                raise AuditWriteError(
                    "audit write did not answer within the write budget; mutating action "
                    "aborted (fail-closed). Check the audit ES index/credential and retry."
                ) from exc
            _LOGGER.warning(
                "audit log write did not answer within %.1fs (event dropped: kind=%s, "
                "seq=%s) — the record may or may not have landed in the index",
                budget,
                event.kind,
                event.seq,
            )

    async def _write(self, event: AuditEvent, *, mutating: bool) -> None:
        """Redact, chain-stamp and index one event. Bounded by :meth:`log`."""
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
            try:
                await self._ensure_chain_head()
            except GridPartialResultsError as e:
                # A half-read audit index with no head to fall back on: there is
                # no trustworthy seq to stamp, and a guessed one manufactures a
                # permanent false TAMPER (see _ensure_chain_head). Same fail
                # policy as a failed index write — fail-closed aborts a mutating
                # action, everything else is logged and dropped. The head stays
                # unknown, so the next write retries recovery.
                if mutating and self._settings.audit_fail_closed:
                    _LOGGER.error(
                        "audit chain head could not be recovered from a half-read "
                        "index and fail-closed is on — aborting the action: %s",
                        e,
                    )
                    raise AuditWriteError(
                        "audit chain head could not be recovered (the audit index "
                        "was only partially readable); mutating action aborted "
                        "(fail-closed). Check the audit index health and retry."
                    ) from e
                _LOGGER.warning(
                    "audit log write dropped rather than stamped with a guessed "
                    "seq — the chain head could not be recovered from a half-read "
                    "index: %s",
                    e,
                )
                return
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
