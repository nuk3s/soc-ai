"""Managed internal-identifier (suffix/host/CIDR) endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.deps import get_settings_dep
from soc_ai.api.webui._shared import (
    require_admin_api,
    router,
)
from soc_ai.api.webui.routes_discovery import (
    DiscoveryStatusOut,
    _discovery_status_out,
    _get_discovery_status,
)
from soc_ai.config import Settings
from soc_ai.store import internal_identifiers as ids_store

_LOGGER = logging.getLogger(__name__)

# ── Internal-identifier managed list: REST CRUD ────────────────────────────────
#
# Surfaces the ``internal_identifier`` table to the config console. Each kind
# ('suffix' | 'host' | 'cidr') is presented as a group of MUTABLE DB rows plus
# read-only ALWAYS-ON entries (the env/reserved identifiers from the effective
# set that have no DB row). The always-on entries have no id, so the
# deactivate/delete routes below (which take an id) cannot suppress a
# reserved/env default — that enforces the spec's "deactivating cannot remove an
# env/reserved default (the floor wins)" contract at the API surface.
# Kind-generic: increment 3 adds a 'cidr' group with no rework here.

# Reserved special-use suffixes that the egress sanitizer always re-adds as a
# floor (mirrors ``soc_ai.oracle.sanitize._DEFAULT_SUFFIXES`` and the default
# ``Settings.oracle_internal_suffixes``). Always-on suffixes in this set are
# labeled 'reserved'; operator-configured env identifiers beyond it are 'env'.
_RESERVED_SUFFIXES = (".lan", ".local", ".internal", ".corp")


class InternalIdentifierRowOut(BaseModel):
    """One managed-list entry. Mutable rows carry an ``id``; always-on don't."""

    id: int | None = None
    value: str
    source: str  # 'detected' | 'manual' | 'reserved' | 'env'
    state: str  # 'active' | 'muted'
    evidence: dict[str, Any] | None = None
    mutable: bool


class InternalIdentifierGroupOut(BaseModel):
    kind: str  # 'suffix' | 'host' | 'cidr'
    rows: list[InternalIdentifierRowOut]


class InternalIdentifiersOut(BaseModel):
    groups: list[InternalIdentifierGroupOut]
    last_scan: DiscoveryStatusOut


class InternalIdentifierIn(BaseModel):
    kind: str
    # Domains / hostnames / IPs / CIDRs only — blocks injection payloads while
    # allowing every legitimate identifier shape (the cidr path validates further).
    value: str = Field(min_length=1, max_length=253, pattern=r"^[\w.\-:/]+$")


_IDENTIFIER_KINDS = ("suffix", "host", "cidr")


def _always_on_source(kind: str, value: str) -> str:
    """Classify an always-on (no-DB-row) identifier as 'reserved' or 'env'.

    Only suffixes have a hardcoded reserved floor; for those, a value in
    ``_RESERVED_SUFFIXES`` is 'reserved', anything else is operator-set 'env'.
    Hosts/CIDRs have no reserved defaults, so they're always 'env'.
    """
    if kind == "suffix" and value in _RESERVED_SUFFIXES:
        return "reserved"
    return "env"


@router.get(
    "/internal-identifiers",
    response_model=InternalIdentifiersOut,
    dependencies=[Depends(require_admin_api)],
)
async def list_internal_identifiers(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> InternalIdentifiersOut:
    """Managed internal-identifier list grouped by kind.

    Each group is the mutable DB rows (``list_identifiers``) plus the read-only
    always-on env/reserved entries: the values in the effective set that are NOT
    represented by a DB row. Always-on entries have no id and no active toggle —
    that's why ``.lan`` shows as an always-on row the operator can't deactivate.
    Also returns the discovery ``last_scan`` status (reusing the 2b status object).
    """
    from soc_ai.oracle.identifiers import (  # noqa: PLC0415 - lazy
        effective_internal_identifiers,
    )

    async with request.app.state.db_sessionmaker() as db:
        effective = await effective_internal_identifiers(db, settings)
        effective_by_kind: dict[str, list[str]] = {
            "suffix": list(effective.suffixes),
            "host": list(effective.hosts),
            "cidr": [str(net) for net in effective.cidrs],
        }
        groups: list[InternalIdentifierGroupOut] = []
        for kind in _IDENTIFIER_KINDS:
            db_rows = await ids_store.list_identifiers(db, kind)
            rows: list[InternalIdentifierRowOut] = [
                InternalIdentifierRowOut(
                    id=r.id,
                    value=r.value,
                    source=r.source,
                    state=r.state,
                    evidence=r.evidence,
                    mutable=True,
                )
                for r in db_rows
            ]
            # Always-on = effective values not already present as a DB row. (An
            # active DB row whose value is also an env default appears as its
            # mutable row, not duplicated as always-on.)
            db_values = {r.value for r in db_rows}
            for value in effective_by_kind[kind]:
                if value in db_values:
                    continue
                rows.append(
                    InternalIdentifierRowOut(
                        id=None,
                        value=value,
                        source=_always_on_source(kind, value),
                        state="active",
                        evidence=None,
                        mutable=False,
                    )
                )
            groups.append(InternalIdentifierGroupOut(kind=kind, rows=rows))

    last_scan = _discovery_status_out(_get_discovery_status(request.app.state))
    return InternalIdentifiersOut(groups=groups, last_scan=last_scan)


@router.post(
    "/internal-identifiers",
    response_model=InternalIdentifierRowOut,
    dependencies=[Depends(require_admin_api)],
)
async def add_internal_identifier(
    request: Request, body: InternalIdentifierIn
) -> InternalIdentifierRowOut:
    """Add a manual identifier. Bad kind / invalid value → 400."""
    async with request.app.state.db_sessionmaker() as db:
        try:
            row = await ids_store.add_manual(db, body.kind, body.value)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail={"reason": "invalid_identifier", "hint": str(exc)}
            ) from exc
        return InternalIdentifierRowOut(
            id=row.id,
            value=row.value,
            source=row.source,
            state=row.state,
            evidence=row.evidence,
            mutable=True,
        )


async def _set_identifier_state(
    request: Request, ident_id: int, state: str
) -> InternalIdentifierRowOut:
    async with request.app.state.db_sessionmaker() as db:
        row = await ids_store.set_state(db, ident_id, state)
        if row is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        return InternalIdentifierRowOut(
            id=row.id,
            value=row.value,
            source=row.source,
            state=row.state,
            evidence=row.evidence,
            mutable=True,
        )


@router.post(
    "/internal-identifiers/{ident_id}/deactivate",
    response_model=InternalIdentifierRowOut,
    dependencies=[Depends(require_admin_api)],
)
async def deactivate_internal_identifier(
    request: Request, ident_id: int
) -> InternalIdentifierRowOut:
    return await _set_identifier_state(request, ident_id, "muted")


@router.post(
    "/internal-identifiers/{ident_id}/activate",
    response_model=InternalIdentifierRowOut,
    dependencies=[Depends(require_admin_api)],
)
async def activate_internal_identifier(request: Request, ident_id: int) -> InternalIdentifierRowOut:
    return await _set_identifier_state(request, ident_id, "active")


@router.delete(
    "/internal-identifiers/{ident_id}",
    dependencies=[Depends(require_admin_api)],
)
async def delete_internal_identifier(request: Request, ident_id: int) -> dict[str, Any]:
    """Delete a manual identifier. Refuses a detected row → 409 (deactivate it)."""
    async with request.app.state.db_sessionmaker() as db:
        deleted = await ids_store.delete_manual(db, ident_id)
        if not deleted:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "not_deletable",
                    "hint": "Detected identifiers cannot be deleted — deactivate them instead.",
                },
            )
    return {"ok": True}
