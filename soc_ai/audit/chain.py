"""Tamper-evident hash chain for audit records.

Each :class:`~soc_ai.audit.schemas.AuditEvent` is linked to its predecessor by
a SHA-256 hash computed over the canonicalised record *content* (every field
except ``hash`` itself) plus the previous record's ``hash``. Any edit, reorder,
insertion, or deletion of a record breaks the recomputed linkage, so an
operator (or :func:`verify_chain`) can detect tampering even though the records
live in a mutable ES index.

The genesis ``prev_hash`` is 64 zero hex chars; the genesis ``seq`` is 0.

Canonicalisation: ``json.dumps(content, sort_keys=True, separators=(",", ":"),
default=str)``. ``default=str`` makes datetimes/Decimals/etc. stable, and
``sort_keys`` makes the digest independent of dict insertion order. The hash is
computed over the *stored* content (i.e. after redaction), so verification runs
against exactly what ES holds.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any, Literal

GENESIS_PREV_HASH = "0" * 64
GENESIS_SEQ = 0

#: What kind of damage a break is. "The chain is broken" is one sentence for
#: several very different facts, and an operator has to act on them
#: differently — a duplicated position is what a second writer leaves behind,
#: while a record whose content no longer matches its own hash is what an edit
#: leaves behind. Reporting both as "TAMPER DETECTED" and nothing else is how a
#: known concurrency defect and a genuine alteration become indistinguishable.
BreakKind = Literal[
    "duplicate_seq",  # two or more records claim the same position
    "missing_seq",  # a position in the run is absent
    "orphan_head",  # the run does not start where it says it does
    "relinked",  # a record points at a predecessor that is not the one before it
    "content_altered",  # a record no longer hashes to its own stored hash
]


@dataclass(frozen=True)
class ChainBreak:
    """Where a chain failed, and in what way.

    ``seq`` is the offending sequence number, LOCAL to the epoch being checked.
    ``detail`` is one operator-facing sentence, safe to print or send: it names
    what was found, never any record content.
    """

    seq: int
    kind: BreakKind
    detail: str


@dataclass(frozen=True)
class ChainCensus:
    """How widespread the damage in a run of records is, not just where it starts.

    :func:`verify_chain_detail` walks the run in order and stops at the first
    thing that does not fit, which is the right shape for "is this chain
    sound". It is the wrong shape for the question an operator asks next: how
    much of the trail is affected, and is any of it recent. A single collision
    and a forked stretch of a whole afternoon produce the same sentence from
    the same field, and the difference is the difference between a bounded
    historical artifact and something happening now.

    - ``duplicate_seqs``: distinct positions claimed by more than one record.
    - ``extra_records``: records beyond the first at each of those positions.
    - ``max_claimants``: the most records claiming any single position (0 when
      nothing is duplicated). Two is a race; four is a fork that stayed open.
    - ``altered_records``: records that no longer hash to the hash stored on
      them. Counted apart from the duplicates on purpose: a duplicated position
      is what a second writer leaves behind, and a record whose content no
      longer matches its own hash is what an edit leaves behind. See
      :data:`BreakKind`.
    - ``missing_seqs``: positions absent from the run's own span.
    - ``oldest_break_at`` / ``newest_break_at``: the ``timestamp`` bounds over
      the records actually involved in a break (duplicated or altered), or None
      when nothing is. ``newest_break_at`` is what says whether the damage is
      historical: if the newest affected record predates a fix, nothing has
      broken since.
    """

    duplicate_seqs: int
    extra_records: int
    max_claimants: int
    altered_records: int
    missing_seqs: int
    oldest_break_at: str | None
    newest_break_at: str | None


_EMPTY_CENSUS = ChainCensus(
    duplicate_seqs=0,
    extra_records=0,
    max_claimants=0,
    altered_records=0,
    missing_seqs=0,
    oldest_break_at=None,
    newest_break_at=None,
)


def census_chain(records: list[dict[str, Any]]) -> ChainCensus:
    """Count every break in *records*, rather than reporting the first.

    Runs over the same set :func:`verify_chain_detail` checks, under the same
    "legacy records without chain fields are ignored" rule. Call it on ONE
    epoch: ``seq`` restarts at zero on every process incarnation, so a position
    claimed by two records in two different epochs is not a duplicate.

    An intact run censuses to all zeros, so a caller can skip this on an epoch
    that verified clean.
    """
    chained = [r for r in records if r.get("hash") is not None and r.get("seq") is not None]
    if not chained:
        return _EMPTY_CENSUS

    counts: Counter[Any] = Counter(r["seq"] for r in chained)
    duplicated = {seq for seq, n in counts.items() if n > 1}
    extra = sum(counts[seq] - 1 for seq in duplicated)
    max_claimants = max((counts[seq] for seq in duplicated), default=0)

    altered = [r for r in chained if not _self_consistent(r)]

    # Absent positions, over the run's own span. Integer seqs only, because a
    # classification a writer invented has no position in a numbered run.
    int_seqs = [seq for seq in counts if isinstance(seq, int)]
    missing = 0
    if int_seqs:
        missing = max((max(int_seqs) - min(int_seqs) + 1) - len(int_seqs), 0)

    involved = [r for r in chained if r["seq"] in duplicated]
    involved.extend(r for r in altered if r["seq"] not in duplicated)
    stamps = sorted(str(r["timestamp"]) for r in involved if isinstance(r.get("timestamp"), str))

    return ChainCensus(
        duplicate_seqs=len(duplicated),
        extra_records=extra,
        max_claimants=max_claimants,
        altered_records=len(altered),
        missing_seqs=missing,
        oldest_break_at=stamps[0] if stamps else None,
        newest_break_at=stamps[-1] if stamps else None,
    )


def canonicalize(content: dict[str, Any]) -> str:
    """Stable JSON string for a record's content (``hash`` excluded by caller)."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(content: dict[str, Any], prev_hash: str) -> str:
    """SHA-256 over ``canonicalize(content)`` + ``prev_hash``.

    ``content`` MUST NOT contain a ``hash`` key (the digest is over everything
    *but* the hash). It SHOULD contain the ``seq`` and ``prev_hash`` that were
    stamped on the record, so a swapped ``seq`` or relinked ``prev_hash`` also
    changes the digest.
    """
    material = canonicalize(content) + prev_hash
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _content_without_hash(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "hash"}


def _self_consistent(record: dict[str, Any]) -> bool:
    """True iff *record* still hashes to the ``hash`` stored on it."""
    prev = record.get("prev_hash")
    if not isinstance(prev, str):
        return False
    return compute_hash(_content_without_hash(record), prev) == record.get("hash")


def _describe_duplicate(records: list[dict[str, Any]], seq: int) -> str:
    """The operator-facing sentence for two or more records at one *seq*.

    The distinction that matters is whether the copies were EDITED. Two writers
    that both continued from the same head each wrote a record that is
    internally sound — every field still hashes to the hash stored on it — and
    the damage is that the position is claimed twice. A record whose own hash
    no longer matches its content is a different event entirely, and saying so
    here is what lets an operator tell a known concurrency defect from someone
    changing the record of a decision.
    """
    copies = [r for r in records if r.get("seq") == seq]
    intact = sum(1 for r in copies if _self_consistent(r))
    return _duplicate_sentence(seq, len(copies), intact)


def _duplicate_sentence(seq: int, copies: int, intact: int) -> str:
    """The duplicate sentence from the counts alone (shared with the streaming checker)."""
    if intact == copies:
        return (
            f"{copies} records claim sequence {seq}. Each record still matches its own hash, "
            "so the records were not altered. The cause is two writers that continued the "
            "chain from the same point"
        )
    return (
        f"{copies} records claim sequence {seq}. {copies - intact} of them no longer match "
        "their own hash, so the content was altered after it was written"
    )


def _missing_sentence(expected_seq: int, seq: int) -> str:
    missing = expected_seq if seq == expected_seq + 1 else f"{expected_seq}..{seq - 1}"
    return f"Sequence {missing} is absent. A record was deleted, or it never arrived in the index"


def _orphan_sentence(seq: int) -> str:
    return (
        f"The oldest record found is at sequence {seq} and does not start a chain. "
        "The records before it are missing from the index"
    )


def _relinked_sentence(seq: int) -> str:
    return (
        f"The record at sequence {seq} points at a predecessor that is not the record "
        "before it. The order was changed"
    )


def _altered_sentence(seq: int) -> str:
    return (
        f"The record at sequence {seq} no longer matches its own hash. Its content was "
        "changed after it was written"
    )


def verify_chain_detail(
    records: list[dict[str, Any]], *, expect_genesis: bool = True
) -> ChainBreak | None:
    """:func:`verify_chain`, but returning WHAT broke as well as where.

    Returns ``None`` for an intact chain, else a :class:`ChainBreak`. See
    :data:`BreakKind` for why the distinction is load-bearing and
    :func:`verify_chain` for the checking rules themselves.
    """
    chained = [r for r in records if r.get("hash") is not None and r.get("seq") is not None]
    if not chained:
        return None

    chained.sort(key=lambda r: r["seq"])

    expected_seq = chained[0]["seq"]
    expected_prev: str | None = (
        GENESIS_PREV_HASH if expected_seq == GENESIS_SEQ or expect_genesis else None
    )
    for position, rec in enumerate(chained):
        seq = rec["seq"]
        if seq != expected_seq:
            if seq == chained[position - 1]["seq"]:
                return ChainBreak(seq, "duplicate_seq", _describe_duplicate(chained, seq))
            return ChainBreak(seq, "missing_seq", _missing_sentence(expected_seq, seq))
        if expected_prev is not None and rec.get("prev_hash") != expected_prev:
            if position == 0 and seq != GENESIS_SEQ:
                return ChainBreak(seq, "orphan_head", _orphan_sentence(seq))
            return ChainBreak(seq, "relinked", _relinked_sentence(seq))
        recomputed = compute_hash(_content_without_hash(rec), rec["prev_hash"])
        if recomputed != rec["hash"]:
            return ChainBreak(seq, "content_altered", _altered_sentence(seq))
        expected_prev = rec["hash"]
        expected_seq = seq + 1

    return None


def verify_chain(
    records: list[dict[str, Any]], *, expect_genesis: bool = True
) -> tuple[bool, int | None]:
    """Recompute every record's hash and verify linkage.

    ``records`` is a list of audit records (dicts, e.g. ES ``_source`` bodies or
    ``AuditEvent.model_dump(mode="json")`` outputs). They are sorted by ``seq``
    before checking so caller ordering does not matter.

    ``expect_genesis`` controls how the FIRST record's inbound linkage is judged
    when the set does not begin at :data:`GENESIS_SEQ`:
    - ``True`` (default — a full-index scan): the fetched set is expected to reach
      back to genesis, so a first record with ``seq > 0`` (its predecessor is
      gone) or a first ``prev_hash`` that is not the genesis hash is a real
      tamper (head deletion) and is reported.
    - ``False`` (a windowed ``days=N`` scan): the record immediately preceding the
      window was deliberately NOT fetched, so its hash cannot be confirmed against
      the first in-window ``prev_hash``. That single boundary linkage is left
      UNVERIFIED rather than falsely reported as tampered; every record's own hash
      and every *in-window* link is still fully checked.

    Returns ``(ok, first_broken_seq)``:
    - ``(True, None)`` — the chain is intact.
    - ``(False, seq)`` — the record at ``seq`` failed (its stored ``hash`` does
      not match the recomputed value, its ``prev_hash`` does not match the
      predecessor's ``hash``, or a ``seq`` is missing/duplicated — i.e. a record
      was inserted, deleted, reordered, or edited). ``seq`` is the first
      offending sequence number. ``first_broken_seq`` may be ``None`` only when
      ``ok`` is ``True``.

    Legacy records that predate the hash chain (no ``seq``/``hash``) are ignored
    — the chain is verified only over the records that carry chain fields.

    The checking itself lives in :func:`verify_chain_detail`, which also says
    WHAT broke; this is the two-value form its callers already speak.
    """
    brk = verify_chain_detail(records, expect_genesis=expect_genesis)
    return (True, None) if brk is None else (False, brk.seq)


class EpochStreamChecker:
    """:func:`verify_chain_detail` and :func:`census_chain` over ONE epoch, streamed.

    The records arrive one page at a time in ``seq`` order (``timestamp`` as the
    tiebreak), which is the order :func:`verify_chain_detail` sorts into, so the
    walk below makes the same decisions on the same records without ever holding
    more than the page it is handed. The census is folded in on the same pass:
    duplicated positions arrive as one contiguous run, so a run is everything the
    duplicate count, the claimant count and the duplicate sentence need.

    ``first_break`` is the verdict :func:`verify_chain_detail` would return.
    ``newest_break`` is the HIGHEST-seq damage the census saw (a duplicated
    position, an altered record or a gap), so a report about "the newest break"
    describes the newest one and not the first one again. It falls back to
    ``first_break`` for the kinds the census does not count (a relinked record,
    a missing head).
    """

    def __init__(self, *, expect_genesis: bool) -> None:
        self._expect_genesis = expect_genesis
        self.first_break: ChainBreak | None = None
        self._last_event: ChainBreak | None = None
        self._pending_dup: int | None = None
        self._started = False
        self._position0 = True
        self._expected_seq: Any = None
        self._expected_prev: str | None = None
        self._prev_seq: Any = None
        # The run of records at the current seq.
        self._run_seq: Any = None
        self._run_n = 0
        self._run_intact = 0
        self._run_ts_min: str | None = None
        self._run_ts_max: str | None = None
        # Census accumulators.
        self.duplicate_seqs = 0
        self.extra_records = 0
        self.max_claimants = 0
        self.altered_records = 0
        self._distinct_int = 0
        self._min_int: int | None = None
        self._max_int: int | None = None
        self._oldest: str | None = None
        self._newest: str | None = None
        self.min_timestamp: str | None = None
        self.chained = 0

    def feed_page(self, records: list[dict[str, Any]]) -> None:
        """Check one page. CPU-bound (one SHA-256 per record): run it off the event loop."""
        for rec in records:
            self._feed(rec)

    def _feed(self, rec: dict[str, Any]) -> None:
        if rec.get("hash") is None or rec.get("seq") is None:
            return
        self.chained += 1
        seq = rec["seq"]
        ts = rec.get("timestamp")
        if isinstance(ts, str) and (self.min_timestamp is None or ts < self.min_timestamp):
            self.min_timestamp = ts
        ok_self = _self_consistent(rec)

        if self._run_n == 0 or seq != self._run_seq:
            before = self._run_seq if self._run_n else None
            self._close_run()
            if isinstance(seq, int) and isinstance(before, int) and seq > before + 1:
                self._last_event = ChainBreak(
                    seq, "missing_seq", _missing_sentence(before + 1, seq)
                )
            self._run_seq = seq
            self._run_n = 0
            self._run_intact = 0
            self._run_ts_min = None
            self._run_ts_max = None
            if isinstance(seq, int):
                self._distinct_int += 1
                self._min_int = seq if self._min_int is None else min(self._min_int, seq)
                self._max_int = seq if self._max_int is None else max(self._max_int, seq)
        self._run_n += 1
        if ok_self:
            self._run_intact += 1
        else:
            self.altered_records += 1
        if isinstance(ts, str):
            if self._run_ts_min is None or ts < self._run_ts_min:
                self._run_ts_min = ts
            if self._run_ts_max is None or ts > self._run_ts_max:
                self._run_ts_max = ts

        self._check_link(rec, seq, ok_self)
        self._prev_seq = seq

    def _check_link(self, rec: dict[str, Any], seq: Any, ok_self: bool) -> None:
        """The :func:`verify_chain_detail` walk, one record at a time."""
        if self.first_break is not None or self._pending_dup is not None:
            return
        if not self._started:
            self._started = True
            self._expected_seq = seq
            self._expected_prev = (
                GENESIS_PREV_HASH if seq == GENESIS_SEQ or self._expect_genesis else None
            )
        position0 = self._position0
        self._position0 = False
        if seq != self._expected_seq:
            if seq == self._prev_seq:
                # The sentence needs every copy at this seq: settle it when the run ends.
                self._pending_dup = seq
                return
            self.first_break = ChainBreak(
                seq, "missing_seq", _missing_sentence(self._expected_seq, seq)
            )
            return
        if self._expected_prev is not None and rec.get("prev_hash") != self._expected_prev:
            if position0 and seq != GENESIS_SEQ:
                self.first_break = ChainBreak(seq, "orphan_head", _orphan_sentence(seq))
            else:
                self.first_break = ChainBreak(seq, "relinked", _relinked_sentence(seq))
            return
        if not ok_self:
            self.first_break = ChainBreak(seq, "content_altered", _altered_sentence(seq))
            return
        self._expected_prev = rec["hash"]
        self._expected_seq = seq + 1

    def _close_run(self) -> None:
        n = self._run_n
        if n == 0:
            return
        seq = self._run_seq
        if n > 1:
            self.duplicate_seqs += 1
            self.extra_records += n - 1
            self.max_claimants = max(self.max_claimants, n)
            self._last_event = ChainBreak(
                seq, "duplicate_seq", _duplicate_sentence(seq, n, self._run_intact)
            )
        elif self._run_intact == 0:
            self._last_event = ChainBreak(seq, "content_altered", _altered_sentence(seq))
        if (n > 1 or self._run_intact < n) and self._run_ts_min is not None:
            if self._oldest is None or self._run_ts_min < self._oldest:
                self._oldest = self._run_ts_min
            if self._newest is None or (
                self._run_ts_max is not None and self._run_ts_max > self._newest
            ):
                self._newest = self._run_ts_max
        if self._pending_dup is not None and self._pending_dup == seq:
            self.first_break = ChainBreak(
                seq, "duplicate_seq", _duplicate_sentence(seq, n, self._run_intact)
            )
            self._pending_dup = None
        self._run_n = 0

    def finish(self) -> None:
        """Settle the last run. Call once, after the last page."""
        self._close_run()

    @property
    def newest_break(self) -> ChainBreak | None:
        if self.first_break is None:
            return None
        return self._last_event or self.first_break

    def census(self) -> ChainCensus:
        missing = 0
        if self._min_int is not None and self._max_int is not None:
            missing = max((self._max_int - self._min_int + 1) - self._distinct_int, 0)
        return ChainCensus(
            duplicate_seqs=self.duplicate_seqs,
            extra_records=self.extra_records,
            max_claimants=self.max_claimants,
            altered_records=self.altered_records,
            missing_seqs=missing,
            oldest_break_at=self._oldest,
            newest_break_at=self._newest,
        )
