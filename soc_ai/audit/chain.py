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
from typing import Any

GENESIS_PREV_HASH = "0" * 64
GENESIS_SEQ = 0


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
    """
    chained = [r for r in records if r.get("hash") is not None and r.get("seq") is not None]
    if not chained:
        return True, None

    chained.sort(key=lambda r: r["seq"])

    # The first record's inbound link can only be checked when we actually hold
    # its predecessor: either this IS the genesis record, or a full scan is
    # expected to start at genesis (so a missing head is a real tamper). A
    # windowed scan that legitimately starts mid-stream has no fetched
    # predecessor — leave that one boundary UNVERIFIED (``expected_prev = None``)
    # rather than force the genesis hash and false-positive a tamper.
    expected_seq = chained[0]["seq"]
    expected_prev: str | None = (
        GENESIS_PREV_HASH if expected_seq == GENESIS_SEQ or expect_genesis else None
    )
    for rec in chained:
        seq = rec["seq"]
        # Detect a gap / duplicate / reorder: seq must advance by exactly 1.
        if seq != expected_seq:
            return False, seq
        # prev_hash must point at the predecessor's stored hash (skipped only for
        # an unverified windowed boundary, where expected_prev is None).
        if expected_prev is not None and rec.get("prev_hash") != expected_prev:
            return False, seq
        # Recompute the hash over the stored content and compare.
        recomputed = compute_hash(_content_without_hash(rec), rec["prev_hash"])
        if recomputed != rec["hash"]:
            return False, seq
        expected_prev = rec["hash"]
        expected_seq = seq + 1

    return True, None
