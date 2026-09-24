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
    if intact == len(copies):
        return (
            f"{len(copies)} records claim sequence {seq}, and each one still matches its "
            "own hash — the records were not altered; two writers continued the chain "
            "from the same point"
        )
    return (
        f"{len(copies)} records claim sequence {seq}, and {len(copies) - intact} of them "
        "no longer match their own hash — content was altered, not merely duplicated"
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
            missing = expected_seq if seq == expected_seq + 1 else f"{expected_seq}..{seq - 1}"
            return ChainBreak(
                seq,
                "missing_seq",
                f"sequence {missing} is absent — a record was deleted, or never landed",
            )
        if expected_prev is not None and rec.get("prev_hash") != expected_prev:
            if position == 0 and seq != GENESIS_SEQ:
                return ChainBreak(
                    seq,
                    "orphan_head",
                    f"the oldest record found is at sequence {seq} and does not start a "
                    "chain — everything before it is missing from the index",
                )
            return ChainBreak(
                seq,
                "relinked",
                f"the record at sequence {seq} points at a predecessor that is not the "
                "record before it — the order was changed",
            )
        recomputed = compute_hash(_content_without_hash(rec), rec["prev_hash"])
        if recomputed != rec["hash"]:
            return ChainBreak(
                seq,
                "content_altered",
                f"the record at sequence {seq} no longer matches its own hash — its "
                "content was changed after it was written",
            )
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
