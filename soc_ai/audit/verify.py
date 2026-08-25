"""Fetch-and-verify the audit hash chain against the live ES audit index.

The tamper-evident chain itself lives in :mod:`soc_ai.audit.chain`
(:func:`verify_chain` recomputes every record's hash and checks linkage). This
module is the *operator-facing* half: it pulls the stored records back out of
the date-stamped audit indices (``{audit_index_alias}-*``) and runs them through
:func:`verify_chain`, so a ``soc-ai audit verify`` CLI run and the admin
``GET /config/audit/verify-chain`` endpoint share one ES-fetch path.

Paging: the chain can be large (one record per LLM I/O + tool call), so a single
``size`` search would hit ES's 10 000-hit ``from``+``size`` ceiling. We page with
``search_after`` on ``timestamp`` ascending (``seq`` tiebreak — see "Epochs"
below for why), which has no window limit, and stop when a page returns fewer
than the page size. A ``max_records`` safety cap bounds a pathological run; if
it is hit we set ``capped=True`` and the caller MUST surface it (a capped scan
cannot claim the whole chain was verified). We never silently truncate.

Time window: ``days=N`` bounds the scan to records with ``timestamp >= now-Nd``
(the audit field is ``timestamp``; ``verify_chain`` still checks that ``seq`` is
contiguous *within* the returned window, but a windowed scan cannot verify
linkage across the window boundary — the record before the window is not fetched,
so its ``hash`` can't be confirmed against the first in-window ``prev_hash``).

Epochs: the chain head (``soc_ai.audit.logger.AuditLogger._ensure_chain_head``)
is recovered from ES on every process restart, so in principle it continues
seq/hash linkage across restarts — but a bug in that recovery
(``_top_source``'s ``isinstance(resp, dict)`` never matched the real client's
``ObjectApiResponse``, fixed 2026-08-17 in commit 8032258) instead reset it to
genesis on EVERY restart for ~8 weeks, 2026-06-24 → 2026-08-16, leaving prod's
chain with 134 genesis (``seq=0``) records. Every one of those restarts is a
legitimate, frozen-in-history epoch boundary, not tamper, so this module
verifies PER EPOCH: every record with ``seq == GENESIS_SEQ`` starts a new one,
and linkage is only ever expected to hold *within* an epoch — a genesis
record's ``prev_hash`` is the all-zero hash by construction (see
:mod:`soc_ai.audit.chain`), so it never links back to whatever epoch preceded
it, and treating that as a break would be reporting history as tamper. See
:func:`_partition_epochs` for the boundary-detection and same-millisecond
reasoning, and :class:`ChainVerifyResult` for what ``ok=True`` means once more
than one epoch is in play.

Partial reads: every page is checked against ``_shards``/``timed_out`` and a
page the grid did not fully read raises :class:`GridPartialResultsError` (see
:func:`_raise_if_partial` for why the ``es_fail_on_partial_results`` opt-out
deliberately does not apply here). The paging in this module goes through the
raw ``elastic._client`` handle — :meth:`ElasticClient.search` does not expose
``search_after`` — so it does NOT inherit the wrapper's own partial-read check
and must carry its own.

Blast radius, not just existence: EVERY epoch is checked, never just the
first broken one. Live prod, 2026-08-21: ``soc-ai audit verify`` reported
"TAMPER — chain broke at seq 38 in the epoch starting 2026-06-26T21:55:52Z" —
verified by hand as a REAL duplicate-seq artifact (two interleaved series
both claiming seq 38/39/40, one starting 2026-06-26T22:17, the other
2026-06-27T02:13) from the historic pre-1.2.8 write-side stale-head seq-reuse
bug (a stalled write left the in-memory chain head stale; the next write
reused its seq — fixed before the epoch-recovery bug above even existed). Not
a false positive: that scar genuinely IS a break. But pre-1.2.8 history can
carry BOTH bug classes — genesis-reset fragmentation AND mid-epoch seq reuse —
and the old code stopped at the first broken epoch it found while scanning
oldest-first, leaving an operator unable to tell whether a June scar was the
only damage or whether something more recent (possibly the live, current
epoch) was ALSO broken. So every epoch is verified regardless of earlier
breaks, every break is tallied (:attr:`ChainVerifyResult.epochs_broken`), and
the newest one is named specifically
(:attr:`ChainVerifyResult.newest_broken_epoch_start`) — that is the field
that actually answers "am I sound right now".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.audit.chain import GENESIS_SEQ, verify_chain
from soc_ai.so_client.elastic import (
    ElasticClient,
    GridPartialResultsError,
    _as_int,
    _first_failure_reason,
)

_LOGGER = logging.getLogger(__name__)

# Per-page hit count for the search_after scan. 1000 keeps each round trip small
# while paging a large chain in few requests.
_PAGE_SIZE = 1000

# Absolute safety cap on records pulled in one verification. A real audit chain
# can be long, but an unbounded pull on a misconfigured index shouldn't be able
# to OOM the process. 500k records ≈ a very active deployment's multi-week trail;
# beyond that, bound with days=. Hitting it sets capped=True (never silent).
_MAX_RECORDS = 500_000


@dataclass(frozen=True)
class ChainVerifyResult:
    """Outcome of a fetch-and-verify pass over the audit chain.

    - ``ok`` — True iff ``epochs_broken == 0``: EVERY epoch (see
      :func:`_partition_epochs`) in the fetched set is internally intact.
      Cross-epoch linkage is never checked — a genesis record's ``prev_hash``
      is the all-zero hash by construction, so there is nothing to check — so
      ``ok=True`` with ``epochs > 1`` means "no tamper found within any
      restart's own trail", a genuinely weaker claim than "one unbroken chain"
      and one every consumer must render as such (amber, not green — see each
      consumer's tri-state verdict logic).
    - ``records_verified`` — number of chained records fetched (not merely those
      checked before a break — same convention as before epochs existed).
    - ``first_broken_seq`` — the seq where the OLDEST broken epoch's own
      linkage first failed, LOCAL to that epoch (every epoch renumbers from
      0), else None. Kept for compatibility with the single-break era; when
      more than one epoch is broken, ``epochs_broken`` /
      ``newest_broken_epoch_start`` carry the rest of the picture.
    - ``first_seq`` / ``last_seq`` — the seq span actually covered (None on an
      empty/legacy-only result). With more than one epoch these are no longer a
      single chain's span (seq resets at every genesis) — they stay for the
      single-epoch case consumers already render ("seq X..Y"), and the
      multi-epoch verdict deliberately doesn't feature them (see each
      consumer's amber-branch wording).
    - ``capped`` — True iff the ``max_records`` cap was hit, so the scan did NOT
      reach the end of the chain (``ok`` then covers only the fetched prefix —
      now the oldest EPOCHS, not just the oldest records; see
      :func:`_fetch_audit_records`). The blast-radius fields below (
      ``epochs_broken``, ``newest_broken_epoch_start``, ``latest_epoch_broken``)
      cover only what was actually scanned when capped — a consumer must not
      read a clean tail among the scanned epochs as proof the chain is
      currently sound; there may be more, unseen, past the cap (the cap always
      truncates the NEWEST end, since the fetch is oldest-first).
    - ``epochs`` — count of epochs found in the fetched set (0 for an empty
      scan, 1 for an ordinary unbroken chain or a windowed scan that never
      crosses a restart boundary, >1 once more than one process incarnation is
      in the fetched window). Counts every epoch the fetch actually reached,
      regardless of how many broke — mirrors ``records_verified``'s existing
      "everything fetched" convention.
    - ``first_broken_epoch_start`` — the ISO ``timestamp`` of the OLDEST broken
      epoch's first (genesis, except possibly epoch 0 of a windowed scan)
      record, so an operator can find WHICH restart the oldest break happened
      in instead of just which locally-renumbered seq. None iff ``ok`` is True.
    - ``epochs_broken`` — count of epochs whose own linkage failed. Every epoch
      is checked, never just the first broken one found — a chain's history
      can carry more than one distinct tamper-shaped scar (prod's actual
      2026-08-21 finding: a chain-head-recovery-bug epoch fragmentation
      PLUS a genuinely separate, real duplicate-seq artifact from the historic
      pre-1.2.8 write-side stale-head seq-reuse bug, mid-epoch), and stopping
      at the first one would leave "is anything MORE recent also broken"
      unanswered — the operator's actual question.
    - ``newest_broken_epoch_start`` — the ISO ``timestamp`` of the MOST RECENT
      broken epoch's genesis (None iff ``ok`` is True). This, not
      ``first_broken_epoch_start``, is what tells an operator whether the
      trail is sound right now: a break with nothing broken after it (or with
      an old ``newest_broken_epoch_start`` and other epochs that verified
      clean since) is a historical scar, not an active problem.
    - ``latest_epoch_broken`` — True iff the temporally LAST epoch actually
      fetched failed its own check. False (including vacuously, for an empty
      scan) otherwise. This is what lets a consumer tell "every epoch after
      the newest break verified intact" (informative, reassuring) apart from
      "the break IS the most recent epoch" (nothing to reassure with) —
      without needing the full epoch list itself. Computed the same way
      whether or not the scan was ``capped``; it is the RENDERING layer's job
      to decide this field is only trustworthy for that reassurance when
      ``capped`` is False (see ``capped`` above).
    """

    ok: bool
    records_verified: int
    first_broken_seq: int | None
    first_seq: int | None
    last_seq: int | None
    capped: bool
    epochs: int
    first_broken_epoch_start: str | None
    epochs_broken: int
    newest_broken_epoch_start: str | None
    latest_epoch_broken: bool


def _raise_if_partial(
    index: str,
    response: Any,
    *,
    consequence: str = "the chain cannot be verified from a partial read",
) -> None:
    """Refuse to hash a page the grid did not fully read.

    Mirrors the tolerant parse of :meth:`ElasticClient._check_complete` — no
    ``_shards`` key (test stubs, replay fixtures) means zero failures, and
    skipped shards are a healthy grid's business — but deliberately does NOT
    honor the ``es_fail_on_partial_results`` opt-out. On every other read a
    partial answer degrades one panel; here it corrupts the verdict itself, in
    one of two ways depending on which records went missing. A missing tail (or
    a fully empty read) verifies as an INTACT chain — a tamper-evidence check
    handing out a clean bill of health from records it never read. A missing
    middle leaves a ``seq`` gap that :func:`verify_chain` reports as TAMPERED —
    an outage rendered as the most expensive false alarm this product can raise.
    Both are worse than the honest answer, which is that the chain cannot be
    verified from a partial read; so a partial page always raises, and the
    callers map it to CLI exit-2 / a 502 — never to ``ok=true`` and never to a
    ``first_broken_seq``.

    The logger's chain-head recovery reads the same audit index through the same
    raw ``_client`` handle and shares this guard (see
    :meth:`soc_ai.audit.logger.AuditLogger._ensure_chain_head`), passing its own
    ``consequence`` clause so the raised message names what a half-read actually
    cost there — a head that cannot be recovered, not a chain that cannot be
    verified.
    """
    shards_raw = response.get("_shards")
    shards: dict[str, Any] = shards_raw if isinstance(shards_raw, dict) else {}
    shards_failed = _as_int(shards.get("failed"))
    shards_total = _as_int(shards.get("total"))
    # `is True`, not truthiness: a Mock double answers every .get with a truthy
    # child object, and absent/garbled metadata must never be made to look like
    # a timeout (the same stance _as_int takes on the shard counters).
    timed_out = response.get("timed_out") is True
    if not shards_failed and not timed_out:
        return

    parts: list[str] = []
    if shards_failed:
        parts.append(f"{shards_failed} of {shards_total} shards failed")
    if timed_out:
        parts.append("the search timed out before all shards answered")
    reason = _first_failure_reason(shards)
    detail = f" ({reason})" if reason else ""
    raise GridPartialResultsError(
        f"could not read the whole audit index ({index}): {' and '.join(parts)}{detail} — "
        f"{consequence}",
        shards_failed=shards_failed,
        shards_total=shards_total,
        timed_out=timed_out,
        reason=reason,
    )


async def _search_page(
    elastic: ElasticClient,
    index: str,
    query: dict[str, Any],
    *,
    size: int,
    sort: list[dict[str, Any]],
    search_after: list[Any] | None,
) -> list[dict[str, Any]]:
    """Run one ``search_after`` page directly on the low-level ES client.

    :class:`ElasticClient.search` does not expose ``search_after``, so drop to the
    underlying client (mirroring the tolerant ``ignore_unavailable`` /
    ``allow_no_indices`` flags the wrapper sets) and return the raw hit dicts —
    each carries ``_source`` (the stored record) and ``sort`` (the next cursor).

    Because this bypasses the wrapper it also bypasses the wrapper's partial-read
    check, so every page is re-checked here: a half-read page raises
    :class:`GridPartialResultsError` before a single hit from it is hashed.
    """
    body: dict[str, Any] = {
        "query": query,
        "size": size,
        "sort": sort,
        # Accurate total isn't needed (we page to exhaustion), but asking keeps the
        # semantics obvious and cheap for the small pages we pull.
        "track_total_hits": False,
    }
    if search_after is not None:
        body["search_after"] = search_after
    response = await elastic._client.search(
        index=index,
        body=body,
        ignore_unavailable=True,
        allow_no_indices=True,
    )
    _raise_if_partial(index, response)
    return list(response.get("hits", {}).get("hits", []))


async def _fetch_audit_records(
    elastic: ElasticClient,
    audit_index_alias: str,
    *,
    days: int | None,
    max_records: int,
) -> tuple[list[dict[str, Any]], bool]:
    """Pull audit ``_source`` bodies from ``{alias}-*`` sorted ascending by time.

    Pages with ``search_after`` on ``timestamp`` (no 10k window limit). Returns
    ``(records, capped)`` where ``capped`` is True iff ``max_records`` was reached
    before the scan exhausted the index (so the caller must not claim the whole
    chain was verified).
    """
    index = f"{audit_index_alias}-*"
    # Only records that carry a seq — legacy pre-chain docs have none and
    # verify_chain would ignore them anyway; excluding them here keeps paging
    # tight AND is what keeps a legacy doc from ever reaching the epoch
    # partition below (it has no seq to be mistaken for a genesis marker, or
    # anything else).
    filters: list[dict[str, Any]] = [{"exists": {"field": "seq"}}]
    if days is not None:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        filters.append({"range": {"timestamp": {"gte": since}}})
    query: dict[str, Any] = {"bool": {"filter": filters}}
    # Sort is timestamp-major, seq-minor — NOT seq-major. This used to sort on
    # `seq` first (see below for why the tiebreak avoids `_id`), which is fine
    # for a single unbroken chain (seq is monotonic and unique) but wrong once
    # an index holds multiple epochs (see this module's docstring): `seq`
    # resets to 0 at every genesis, so sorting seq-major interleaves ALL
    # epochs' seq=0 records first, then all their seq=1 records, and so on —
    # there is no contiguous run of "one epoch's records" to partition at all.
    # Epochs were written sequentially in time (one process incarnation's
    # entire trail, then the next's), so `timestamp` is the field that actually
    # groups them, with `seq` breaking ties — the SAME field pair as before,
    # just swapped in priority, so this carries the ES 9 fix below unchanged.
    #
    # Tie-break on the record's own `seq`, not `_id`. Two records can share an
    # ES-visible timestamp (write-rate can exceed clock granularity); `seq` is
    # unique *within* an epoch and, crucially, is exactly the field the epoch
    # partition and verify_chain need in the right relative order — so the
    # tiebreak serves the consumer, not just determinism. `_id` would also
    # give a deterministic order, but sorting on it requires fielddata, which
    # stock ES 9 ships disabled (`indices.id_field_data.enabled=false`), so
    # that tiebreak used to fail every data-bearing shard on a real ES 9 grid
    # (found on a 93M-doc prod grid: "58 of 76 shards failed") and the correct
    # partial-read guard below then refused the whole scan — turning
    # `soc-ai audit verify` into permanent couldn't-verify on any ES 9 install.
    # A PIT + `_shard_doc` tiebreak is the canonical fix for search_after's own
    # ordering caveats, but it drags PIT support into every mock/fake in this
    # suite for a tiebreak `seq` already gives us for free.
    sort: list[dict[str, Any]] = [{"timestamp": {"order": "asc"}}, {"seq": {"order": "asc"}}]

    records: list[dict[str, Any]] = []
    search_after: list[Any] | None = None
    while True:
        remaining = max_records - len(records)
        if remaining <= 0:
            return records, True  # cap reached — scan did NOT exhaust the index
        page_size = min(_PAGE_SIZE, remaining)
        hits = await _search_page(
            elastic, index, query, size=page_size, sort=sort, search_after=search_after
        )
        if not hits:
            break
        for hit in hits:
            src = hit.get("_source")
            if isinstance(src, dict):
                records.append(src)
        if len(hits) < page_size:
            break  # last (partial) page — index exhausted
        cursor = hits[-1].get("sort")
        if not isinstance(cursor, list) or not cursor:
            # ES echoes `sort` on every hit when a sort is set; if it didn't, stop
            # rather than risk an infinite loop re-fetching the same page.
            _LOGGER.warning("audit verify: page missing sort cursor, stopping scan early")
            break
        search_after = cursor

    return records, False


def _partition_epochs(records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Split a timestamp-ascending record stream into epochs at each genesis.

    ``records`` must already be in the order :func:`_fetch_audit_records` fetches
    them (timestamp-major, ``seq``-tiebroken — see its ``sort``): a chain
    fragment written by one process incarnation stays contiguous in the stream
    before the next incarnation's records begin. Every record whose ``seq``
    equals :data:`GENESIS_SEQ` (0) STARTS a new group — a genesis record's
    ``prev_hash`` is the all-zero hash by construction (:mod:`soc_ai.audit.chain`),
    so it never links back to whatever came before it, and grouping at exactly
    that field is what turns "the fetch order" into "the epoch order".

    Within a group, members are handed to :func:`verify_chain` in stream order,
    but that function re-sorts by ``seq`` itself before checking anything — so a
    burst of records sharing one ES-visible millisecond (the fetch sort's `seq`
    tiebreak already orders them correctly; this is belt and suspenders) can
    never scramble an epoch's *internal* check. What neither sort nor
    ``verify_chain`` can repair is a record landing in the wrong GROUP: if a
    new genesis write and the tail of the epoch before it ever shared a
    timestamp, the tiebreak (`seq` ascending) would sort the genesis record
    (seq 0) ahead of that tail record (a high seq), so the cut happens one
    record too early and the tail record is evaluated against the new epoch's
    numbering instead of its own. It will not silently pass: the tail record's
    seq does not fit the new epoch's sequence, and ``verify_chain`` reports a
    break there. That is the correct failure mode for a genuinely ambiguous
    order — surfaced as a break, never absorbed into a false "intact" — and in
    practice it cannot arise, because the old process must exit before the new
    one starts and recovers a fresh chain head (see
    :meth:`soc_ai.audit.logger.AuditLogger._ensure_chain_head`), so one epoch's
    last write and the next's genesis write are never truly concurrent.

    Records with no ``seq`` never reach this function — the ES fetch filters
    ``exists: seq`` (see :func:`_fetch_audit_records`) — so a legacy, pre-chain
    record can neither start nor hide inside a group; ``verify_chain`` would
    also have ignored it (its own ``chained`` filter requires both ``seq`` and
    ``hash``), so this is defence in depth, not the only guard.
    """
    epochs: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for rec in records:
        if rec.get("seq") == GENESIS_SEQ and current:
            epochs.append(current)
            current = []
        current.append(rec)
    if current:
        epochs.append(current)
    return epochs


def _epoch_start(epoch: list[dict[str, Any]]) -> str | None:
    """ISO ``timestamp`` of an epoch's first fetched record (its genesis, except
    possibly epoch 0 of a windowed scan — see :func:`_partition_epochs`)."""
    if not epoch:
        return None
    ts = epoch[0].get("timestamp")
    return ts if isinstance(ts, str) else None


async def verify_audit_chain(
    elastic: ElasticClient,
    audit_index_alias: str,
    *,
    days: int | None = None,
    max_records: int = _MAX_RECORDS,
) -> ChainVerifyResult:
    """Fetch every audit record from ES and verify the tamper-evident chain.

    Queries ``{audit_index_alias}-*`` for all chained records (optionally the last
    ``days`` days), sorted ascending by timestamp, partitions them into epochs at
    each genesis marker (:func:`_partition_epochs`), and runs :func:`verify_chain`
    over EVERY epoch — never stopping at the first break, so a break in old
    history cannot hide whether anything more recent is also broken (see this
    module's docstring for the prod finding that makes this a real requirement,
    not a hypothetical). An empty index (no chained records) is intact by
    definition, with zero epochs.

    Shared by the ``soc-ai audit verify`` CLI and the admin verify-chain endpoint.
    Raises on a transport/ES error (the caller maps that to exit-2 / a 5xx) — this
    is a *verification*, so an unreachable index is "could not run", NOT "intact".
    A half-read index is the same refusal with a quieter cause: ES answers 200
    with only the surviving shards' records, and :class:`GridPartialResultsError`
    (raised per page, see :func:`_raise_if_partial`) keeps that from being scored
    as either an intact chain or a tampered one.
    """
    records, capped = await _fetch_audit_records(
        elastic, audit_index_alias, days=days, max_records=max_records
    )

    epochs = _partition_epochs(records)

    ok = True
    epochs_broken = 0
    first_broken_seq: int | None = None
    first_broken_epoch_start: str | None = None
    newest_broken_epoch_start: str | None = None
    # Tracks whichever epoch was checked most recently; after the loop it
    # holds the LAST (temporally newest) epoch's own result. Vacuously True
    # for zero epochs — nothing exists to be "the broken latest epoch".
    last_epoch_ok = True
    for i, epoch in enumerate(epochs):
        # Only epoch 0 can be a legitimately-unfetched boundary — a windowed
        # (days=N) scan may start mid-epoch, with its first record's predecessor
        # filtered out of the fetch, so `expect_genesis` there follows the same
        # rule as before epochs existed (True only for a full scan). Every
        # LATER epoch's first record is, by construction, the one that started
        # the group (seq == GENESIS_SEQ) — verify_chain's own
        # `expected_seq == GENESIS_SEQ` check already forces the genesis-hash
        # requirement regardless of this flag, but passing True explicitly
        # (rather than leaning on that fallthrough) also holds if a crafted
        # record with a negative/duplicate seq ever tried to hide inside a
        # group under cover of a real genesis marker — expect_genesis=True
        # never lets that boundary go unverified the way False would.
        expect_genesis = True if i > 0 else days is None
        epoch_ok, epoch_broken = verify_chain(epoch, expect_genesis=expect_genesis)
        last_epoch_ok = epoch_ok
        if not epoch_ok:
            ok = False
            epochs_broken += 1
            epoch_start = _epoch_start(epoch)
            if first_broken_seq is None:
                # First (oldest, since epochs are in time order) break — set
                # once, kept for the single-break-era fields' compatibility.
                first_broken_seq = epoch_broken
                first_broken_epoch_start = epoch_start
            # Keeps being overwritten by every later break found, so after the
            # loop it holds the MOST RECENT (temporally newest) broken epoch —
            # never break out of this loop early; a later epoch's status is
            # exactly the thing "am I sound now" needs.
            newest_broken_epoch_start = epoch_start

    latest_epoch_broken = bool(epochs) and not last_epoch_ok

    # Seq span actually covered (over ALL fetched chained records, regardless of
    # where — or whether — a break was found; same "everything fetched" convention
    # records_verified already used before epochs existed). With more than one
    # epoch this is no longer one chain's span (seq resets at every genesis); see
    # ChainVerifyResult's docstring.
    seqs = [r["seq"] for r in records if isinstance(r.get("seq"), int)]
    first_seq = min(seqs) if seqs else None
    last_seq = max(seqs) if seqs else None

    return ChainVerifyResult(
        ok=ok,
        records_verified=len(seqs),
        first_broken_seq=first_broken_seq,
        first_seq=first_seq,
        last_seq=last_seq,
        capped=capped,
        epochs=len(epochs),
        first_broken_epoch_start=first_broken_epoch_start,
        epochs_broken=epochs_broken,
        newest_broken_epoch_start=newest_broken_epoch_start,
        latest_epoch_broken=latest_epoch_broken,
    )
