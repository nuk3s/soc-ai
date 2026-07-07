"""Repository for the managed internal-identifier list.

Async store functions over :class:`~soc_ai.store.models.InternalIdentifier`
rows — internal domain suffixes, bare hostnames, and CIDRs tracked as
``detected``|``manual`` / ``active``|``muted``|``dismissed``. The Oracle egress
sanitizer consumes the *effective* merged set (see ``soc_ai.oracle.identifiers``).

The three states:

* ``active`` — applied by the effective set.
* ``muted``  — a visible suggestion the operator declined (subtracts from the
  effective set); survives re-scans.
* ``dismissed`` — a TERMINAL tombstone for ``detected`` rows only. The row is
  hidden from listings, never refreshed and never resurrected by a scan; only
  an explicit ``add_manual`` of the same value reactivates it. This is how
  vestigial detections (rows created by rules that no longer exist) are retired
  without deleting the audit trail. Manual rows are deleted, never dismissed.

Behavioral invariants enforced here:

* ``upsert_detected`` refreshes evidence on re-scan but **preserves** the
  existing ``state`` — an operator's mute/unmute survives a re-scan, so a muted
  detected row stays muted (a tombstone). A ``dismissed`` row is returned
  UNTOUCHED — not even its evidence is refreshed. It never edits a ``manual``
  row's source/state.
* ``add_manual`` un-mutes / un-dismisses (ensures an active row exists) — an
  explicit operator act outranks a mute or a dismissal.
* ``delete_manual`` refuses to delete a ``detected`` row — operators mute or
  dismiss detected rows, they never delete them.
* ``dismiss`` refuses ``manual`` rows (returns ``None``) — those are deleted
  via ``delete_manual`` instead.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import InternalIdentifier

VALID_KINDS = ("suffix", "host", "cidr")


def normalize(kind: str, value: str) -> str:
    """Validate *kind* and return the normalized *value* for storage.

    * ``suffix`` — lowercased with a single leading dot ("`.corp.acme.com`").
    * ``host``   — trimmed, stored as-given (case preserved); callers compare
      case-insensitively.
    * ``cidr``   — parsed via ``ipaddress.ip_network(strict=False)`` and stored
      as its canonical network string ("`10.50.0.0/24`").

    Raises ``ValueError`` on an unknown *kind* or an invalid/empty *value*.
    """
    if kind not in VALID_KINDS:
        raise ValueError(f"invalid kind {kind!r}; expected one of {VALID_KINDS}")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"empty value for kind {kind!r}")

    if kind == "suffix":
        lowered = stripped.lower().lstrip(".")
        if not lowered:
            raise ValueError(f"invalid suffix {value!r}")
        return "." + lowered
    if kind == "host":
        return stripped
    # cidr
    try:
        network = ipaddress.ip_network(stripped, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid cidr {value!r}: {exc}") from exc
    return str(network)


async def list_identifiers(
    db: AsyncSession,
    kind: str | None = None,
    *,
    include_dismissed: bool = False,
) -> list[InternalIdentifier]:
    """Return identifier rows, optionally filtered by *kind*, ordered.

    Dismissed tombstones are EXCLUDED by default — neither the config-console
    list nor the oracle effective-set resolver must ever see them. Pass
    ``include_dismissed=True`` only for maintenance paths that need the full
    table (e.g. audit/debug).
    """
    stmt = select(InternalIdentifier)
    if not include_dismissed:
        stmt = stmt.where(InternalIdentifier.state != "dismissed")
    if kind is not None:
        stmt = stmt.where(InternalIdentifier.kind == kind)
    stmt = stmt.order_by(InternalIdentifier.kind, InternalIdentifier.value)
    return list((await db.scalars(stmt)).all())


async def _get(db: AsyncSession, kind: str, value: str) -> InternalIdentifier | None:
    """Fetch the row for a normalized (kind, value) pair, or ``None``."""
    row: InternalIdentifier | None = await db.scalar(
        select(InternalIdentifier).where(
            InternalIdentifier.kind == kind,
            InternalIdentifier.value == value,
        )
    )
    return row


async def upsert_detected(
    db: AsyncSession,
    kind: str,
    value: str,
    evidence: dict[str, Any],
    initial_state: str,
) -> InternalIdentifier:
    """Insert or refresh a ``detected`` row, preserving operator state.

    * Absent (kind, value) → insert ``source='detected'`` with *initial_state*
      and *evidence*.
    * Present and ``state=='dismissed'`` → returned UNTOUCHED: a dismissed row
      is a terminal tombstone — never refreshed, never resurrected by a scan.
      Only an explicit ``add_manual`` reactivates it.
    * Present and ``source=='detected'`` → refresh *evidence* (and updated_at)
      but **preserve the existing state** (an operator's mute/unmute survives a
      re-scan).
    * Present and ``source=='manual'`` → refresh *evidence* only; leave
      source/state untouched.
    """
    norm = normalize(kind, value)
    row = await _get(db, kind, norm)
    if row is None:
        row = InternalIdentifier(
            kind=kind,
            value=norm,
            source="detected",
            state=initial_state,
            evidence=evidence,
        )
        db.add(row)
    elif row.state == "dismissed":
        # Terminal tombstone: a scan must never touch it (not even evidence),
        # or the "retired" provenance would be silently overwritten and the
        # row would look freshly supported again.
        return row
    else:
        # Refresh evidence for both detected and manual rows; never change
        # source/state here (detected: preserve operator mute; manual: sticky).
        row.evidence = evidence
    await db.commit()
    await db.refresh(row)
    return row


async def add_manual(db: AsyncSession, kind: str, value: str) -> InternalIdentifier:
    """Ensure an active ``manual``-intent row exists for (kind, value).

    Absent → insert ``source='manual'``, ``state='active'``. Present (whatever
    its source or state — INCLUDING a ``dismissed`` tombstone) → set
    ``state='active'``: a manual add un-mutes, and an explicit operator act
    outranks a dismissal.
    """
    norm = normalize(kind, value)
    row = await _get(db, kind, norm)
    if row is None:
        row = InternalIdentifier(
            kind=kind,
            value=norm,
            source="manual",
            state="active",
            evidence=None,
        )
        db.add(row)
    else:
        row.state = "active"
    await db.commit()
    await db.refresh(row)
    return row


async def set_state(db: AsyncSession, ident_id: int, state: str) -> InternalIdentifier | None:
    """Set a row's *state* to ``active`` or ``muted``. ``None`` if not found.

    Deliberately NOT a path to ``dismissed`` — dismissal is a distinct terminal
    act with its own semantics (see :func:`dismiss`).
    """
    if state not in ("active", "muted"):
        raise ValueError(f"invalid state {state!r}; expected 'active' or 'muted'")
    row = await db.get(InternalIdentifier, ident_id)
    if row is None:
        return None
    row.state = state
    await db.commit()
    await db.refresh(row)
    return row


async def dismiss(db: AsyncSession, ident_id: int) -> InternalIdentifier | None:
    """Terminally dismiss a DETECTED row (``state='dismissed'`` tombstone).

    A dismissed row is hidden from listings by default (``list_identifiers``),
    is never refreshed or resurrected by a re-scan (``upsert_detected`` returns
    it untouched), and only an explicit ``add_manual`` of the same value
    reactivates it. Returns the dismissed row, or ``None`` when the id is
    unknown OR the row is ``manual`` — manual rows are removed via
    :func:`delete_manual`, never dismissed.
    """
    row = await db.get(InternalIdentifier, ident_id)
    if row is None or row.source != "detected":
        return None
    row.state = "dismissed"
    await db.commit()
    await db.refresh(row)
    return row


async def delete_manual(db: AsyncSession, ident_id: int) -> bool:
    """Delete a row only if it is ``manual``.

    Returns ``True`` if a manual row was deleted; ``False`` if the row is
    missing or is ``detected`` (operators mute detected rows, never delete
    them).
    """
    row = await db.get(InternalIdentifier, ident_id)
    if row is None or row.source != "manual":
        return False
    await db.delete(row)
    await db.commit()
    return True
