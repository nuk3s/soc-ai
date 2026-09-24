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

Claiming a seq: the lock above serialises the tasks inside ONE logger, and that
is all it can do. It does not reach a second logger in the same process (the
nightly quality alarm builds one), a ``soc-ai`` CLI process running beside the
server, or the gap between reading the head and the record landing in the
index. Measured on a live deployment, 2026-09-06: 41 duplicated ``seq`` values
across 51 extra documents in seven days, the duplicates sharing a ``prev_hash``
— two writers continuing from the same head — and ``audit verify`` reporting
the current epoch tampered. Reproduced against a real grid: three processes
writing 60 records each produced 60 duplicated seqs; the same load in one
process produced none.

So the seq is not claimed in memory at all. Each record is written with
``op_type=create`` at a deterministic ``_id`` (``seq-<n>``), which makes the
grid itself the arbiter: the first writer to reach a seq gets it, and every
other writer is refused with a version conflict, re-reads the head and tries
the next one. Allocation and persistence become the same atomic operation, so
there is no window to lose a race in and no allocation that can be left
dangling as a gap when a write fails. The one thing it cannot cover is two
writers colliding across a UTC midnight, where the two records land in
different date-stamped indices and ``_id`` uniqueness is per-index; that
collision is still reported by ``audit verify`` rather than silently kept.

This also settles the ambiguous write below without guessing. A record whose
acknowledgement never arrived is either in the index or not; the next claim on
its seq either conflicts (it landed — adopt its hash and move on) or succeeds
(it did not).

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
import random
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from elasticsearch import ConflictError

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

# How many seqs one record may try to claim before it is given up on. A claim
# fails only when another writer got there first, and each refusal moves this
# writer's head forward, so a handful of attempts covers a realistic pile-up
# (the live grid's worst observed collision was four writers on one seq)
# without letting a pathological index turn one audit write into an unbounded
# retry loop inside the caller's timeout budget.
_SEQ_CLAIM_ATTEMPTS = 8

# Backoff between refused claims: uniform random in ``[0, min(base * 2**n,
# cap)]`` seconds. A writer that has just lost a race is, by construction, a
# round trip behind the writer that won it — it has to read where the chain got
# to before it can claim again, while the winner simply writes — so without a
# pause the loser can be lapped on every attempt and spend its whole budget
# never catching up. The pause lets the burst ahead of it drain. Random,
# because two writers that back off by the same amount collide again; short,
# because it is spent inside the caller's write budget.
_CLAIM_BACKOFF_BASE_S = 0.01
_CLAIM_BACKOFF_CAP_S = 0.1

# How many consecutive ids a refused claim reads back in one multi-get to find
# where the chain actually ends (see
# :meth:`AuditLogger._resync_after_claim_conflict`). Wide enough that a writer
# which lost a whole burst catches up in a single round trip, small enough that
# the probe stays one cheap realtime read.
_CLAIM_PROBE_SPAN = 16


def _doc_id(seq: int) -> str:
    """The ``_id`` a record at *seq* is written under.

    Deterministic, because that is the whole mechanism: two writers that both
    believe they are at *seq* address the same document, and ``op_type=create``
    lets exactly one of them create it. Prefixed rather than a bare number so
    it is obvious in an ES console that the id is deliberate, and so it can
    never be confused with the auto-generated ids on pre-2026-09 records.
    """
    return f"seq-{seq}"


@dataclass
class _WriteAttempt:
    """Per-call scratch space shared between :meth:`AuditLogger.log` and ``_write``.

    Carries one fact: whether an index request was on the wire when the call
    was abandoned. It has to be per-call rather than per-logger because a task
    can be cancelled while merely QUEUED behind another task's write, and that
    task learned nothing about the head — marking the head unknown on its
    behalf costs a re-read per write exactly when the grid is already too slow
    to answer one.
    """

    request_in_flight: bool = False


def _seq_already_claimed(exc: BaseException) -> bool:
    """True iff *exc* is the grid refusing a create because the ``_id`` exists.

    Matches the client's own :class:`~elasticsearch.ConflictError` first, and
    falls back to the HTTP status so a transport wrapper, a different client
    major, or a test double that answers 409 without the class is still
    understood. A conflict is not a failure — it is the answer to "is this seq
    taken", and mistaking it for one would drop the record instead of moving it
    to the next seq.
    """
    if isinstance(exc, ConflictError):
        return True
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(exc, "status", None)
    return status == 409


def _mget_docs(resp: Any) -> list[Any]:
    """The ``docs`` list from an ES multi-get response (``[]`` if absent).

    Same ``ObjectApiResponse`` unwrapping as :func:`_top_source`.
    """
    if not isinstance(resp, dict):
        resp = getattr(resp, "body", None)
    if not isinstance(resp, dict):
        return []
    docs = resp.get("docs")
    return docs if isinstance(docs, list) else []


def _doc_source(resp: Any) -> dict[str, Any]:
    """Extract ``_source`` from an ES GET response as a dict (``{}`` if absent).

    Same ``ObjectApiResponse`` unwrapping as :func:`_top_source` — see there for
    why ``isinstance(resp, dict)`` alone is not enough against the real client.
    """
    if not isinstance(resp, dict):
        resp = getattr(resp, "body", None)
    if not isinstance(resp, dict):
        return {}
    src = resp.get("_source")
    return src if isinstance(src, dict) else {}


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

        ``number_of_replicas`` is pinned to 0 because the target is a
        single-node Security Onion ES. Left unset, ES applies its default of 1,
        the replica is unassignable on a one-node cluster (``same_shard``
        decider), and each daily index pins the cluster yellow — which trips
        ``soup``'s green-cluster precondition and blocks SO upgrades. This call
        replaces the whole template, so the setting has to be re-stated here;
        fixing it only in ES is undone by the next process start.

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
                template={
                    "settings": {"index": {"number_of_replicas": 0}},
                    "mappings": {"properties": {"payload": {"type": "flattened"}}},
                },
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

        The head only ever moves FORWARD. ES search is near-real-time: a record
        written a moment ago is not searchable until the next refresh, so this
        read can legitimately answer with a seq lower than the one already
        held, and adopting it would hand the next record a seq the index
        already has. A read that is not ahead of what we hold is therefore
        ignored rather than applied — the same stance as a failed read, for the
        same reason.

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
                if last_seq > self._seq:
                    self._seq = last_seq
                    self._last_hash = last_hash
                elif self._seq >= GENESIS_SEQ:
                    _LOGGER.debug(
                        "audit chain head re-read is behind the head already held "
                        "(index says seq=%s, holding seq=%s) — keeping the held head",
                        last_seq,
                        self._seq,
                    )
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
        stamped. The re-read is now an optimisation rather than the guard: the
        deterministic ``_id`` means the next record's claim conflicts if the
        ambiguous write landed and succeeds if it did not, so the chain comes
        out right even when the re-read is served a stale head.

        Only a call that actually had an index request on the wire marks the
        head unknown. A task cancelled while QUEUED behind another task's write
        never touched the head, and saying otherwise buys a wasted head re-read
        on the next write — a second round trip to a grid that just proved it
        cannot answer the first one in time.
        """
        budget = self._write_timeout_s(mutating=mutating)
        attempt = _WriteAttempt()
        try:
            async with asyncio.timeout(budget):
                await self._write(event, mutating=mutating, attempt=attempt)
        except TimeoutError as exc:
            if attempt.request_in_flight:
                # A record may have landed under a seq this logger does not know
                # it used; re-read the head before stamping the next one.
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

    async def _write(self, event: AuditEvent, *, mutating: bool, attempt: _WriteAttempt) -> None:
        """Redact, chain-stamp and index one event. Bounded by :meth:`log`."""
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
            # Inside the lock, not before it. The template install is a
            # once-per-process await that only the FIRST writer pays for, and
            # outside the lock it lets every later writer overtake that one:
            # the record with the earliest timestamp then carries a higher seq
            # than records written after it. The verifier fetches
            # timestamp-ascending and starts a new epoch at every seq 0
            # (soc_ai.audit.verify._partition_epochs), so that inversion cuts
            # one healthy chain into two and reports a break that never
            # happened. Measured on a test grid: twelve concurrent first
            # writes, 180 records, zero duplicate seqs, and "TAMPER, 2 epochs,
            # both broken" purely from this ordering.
            await self._ensure_template()
            for claim_attempt in range(_SEQ_CLAIM_ATTEMPTS):
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
                    attempt.request_in_flight = True
                    await self._elastic._client.index(
                        index=index_name,
                        id=_doc_id(seq),
                        op_type="create",
                        body=body,
                    )
                except Exception as e:
                    attempt.request_in_flight = False
                    if _seq_already_claimed(e):
                        # Another writer holds this seq. Not a failure: find out
                        # where the chain actually is and claim the next one.
                        await self._resync_after_claim_conflict(index_name, seq)
                        await self._claim_backoff(claim_attempt)
                        continue
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
                attempt.request_in_flight = False
                self._seq = seq
                self._last_hash = digest
                return

            # Every seq this record reached for was already taken. Dropping it
            # loses one audit record; forcing it in at a seq someone else holds
            # is what "tamper detected" is made of, so the chain wins.
            if mutating and self._settings.audit_fail_closed:
                _LOGGER.error(
                    "mutating audit write could not claim a chain position in %d "
                    "attempts and fail-closed is on — aborting the action (kind=%s)",
                    _SEQ_CLAIM_ATTEMPTS,
                    event.kind,
                )
                raise AuditWriteError(
                    "audit write could not claim a position in the hash chain "
                    f"({_SEQ_CLAIM_ATTEMPTS} sequence numbers were already taken); "
                    "mutating action aborted (fail-closed). Check for another writer "
                    "against this audit index and retry."
                )
            _LOGGER.warning(
                "audit log write dropped: could not claim a chain position in %d "
                "attempts (kind=%s) — another writer is claiming seqs against this "
                "index faster than this one can follow",
                _SEQ_CLAIM_ATTEMPTS,
                event.kind,
            )

    async def _claim_backoff(self, attempt: int) -> None:
        """Pause before re-claiming, so the writer ahead can finish its burst.

        See :data:`_CLAIM_BACKOFF_BASE_S` for why a refused claim needs a pause
        at all. Bounded and randomised; the whole thing is spent inside the
        caller's write budget, so it stays in the tens of milliseconds.
        """
        ceiling = min(_CLAIM_BACKOFF_BASE_S * (2**attempt), _CLAIM_BACKOFF_CAP_S)
        await asyncio.sleep(random.uniform(0.0, ceiling))  # noqa: S311 - not a secret

    async def _resync_after_claim_conflict(self, index_name: str, seq: int) -> None:
        """Catch up to whichever writer won the race for *seq*.

        Reads the run of records starting at *seq* by ``_id`` in one multi-get.
        Two properties of that call are the point of it. It is REALTIME in
        Elasticsearch (a get reads the translog), so it can see records the
        near-real-time search in :meth:`_ensure_chain_head` cannot yet — a
        writer whose search keeps landing in the refresh window would otherwise
        re-claim the same taken seq on every attempt and stand still. And it
        reads a SPAN rather than one document, so a writer that lost a race to
        a burst catches up in one round trip instead of crawling forward one
        seq per attempt while the winner keeps writing. Crawling is how a loser
        exhausts its retry budget and gets its record dropped.

        Only a CONTIGUOUS run is adopted. A gap in the ids means some seq
        between here and there was never written, and jumping over it would
        leave the chain missing a link, which
        :func:`~soc_ai.audit.chain.verify_chain` reports exactly as loudly as a
        duplicate. Better to re-claim the gap.

        Best-effort: a probe that fails or answers nothing usable leaves the
        head marked unknown, so the next attempt falls back to a search. It
        never moves the head backwards.
        """
        ids = [_doc_id(seq + offset) for offset in range(_CLAIM_PROBE_SPAN)]
        try:
            resp = await self._elastic._client.mget(index=index_name, ids=ids)
        except Exception as e:
            _LOGGER.debug(
                "audit seq %s is taken but the records holding it could not be read "
                "(%s) — re-reading the chain head instead",
                seq,
                e,
            )
            self._head_uncertain = True
            return
        advanced = False
        for doc in _mget_docs(resp):
            src = _doc_source(doc)
            found_seq = src.get("seq")
            found_hash = src.get("hash")
            if not isinstance(found_seq, int) or not isinstance(found_hash, str):
                break  # gap in the run — stop here and re-claim it
            if found_seq > self._seq:
                self._seq = found_seq
                self._last_hash = found_hash
                advanced = True
        if not advanced:
            # The seq is taken but nothing readable sits at or past our head:
            # fall back to a full head re-read on the next attempt.
            self._head_uncertain = True

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
