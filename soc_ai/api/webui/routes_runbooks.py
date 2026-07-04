"""Runbook CRUD endpoints."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    _iso_utc,
    require_admin_api,
    router,
)
from soc_ai.store import runbooks as runbooks_svc

_LOGGER = logging.getLogger(__name__)

# ── Operator runbooks ──────────────────────────────────────────────────────────
#
# The org's own guidance the triage agent can cite (the ``lookup_runbook`` tool
# searches these). Reads are analyst-readable; writes are admin-gated. Purely
# local — nothing is ever written to Security Onion.


# Bound stored runbooks: content is loaded + tokenized in-process on EVERY agent
# ``lookup_runbook`` call, so an unbounded blob is a latency/memory footgun even
# though writes are admin-only. Cap the body and both the count and per-item length
# of the tag / linked-rule lists.
_RB_LABEL = Annotated[str, Field(max_length=256)]
_RB_CONTENT_MAX = 65536
_RB_LIST_MAX = 128


class RunbookIn(BaseModel):
    title: str = Field(min_length=1, max_length=512)
    content: str = Field(default="", max_length=_RB_CONTENT_MAX)
    tags: list[_RB_LABEL] = Field(default_factory=list, max_length=_RB_LIST_MAX)
    linked_rules: list[_RB_LABEL] = Field(default_factory=list, max_length=_RB_LIST_MAX)


class RunbookPatch(BaseModel):
    """All fields optional — only the provided ones are updated."""

    title: str | None = Field(default=None, min_length=1, max_length=512)
    content: str | None = Field(default=None, max_length=_RB_CONTENT_MAX)
    tags: list[_RB_LABEL] | None = Field(default=None, max_length=_RB_LIST_MAX)
    linked_rules: list[_RB_LABEL] | None = Field(default=None, max_length=_RB_LIST_MAX)


class RunbookOut(BaseModel):
    id: int
    title: str
    content: str
    tags: list[str]
    linked_rules: list[str]
    created_by: str
    created_at: str
    updated_at: str


def _runbook_out(row: Any) -> RunbookOut:
    return RunbookOut(
        id=row.id,
        title=row.title,
        content=row.content or "",
        tags=list(row.tags or []),
        linked_rules=list(row.linked_rules or []),
        created_by=row.created_by,
        created_at=_iso_utc(row.created_at),
        updated_at=_iso_utc(row.updated_at),
    )


@router.get("/runbooks", response_model=list[RunbookOut])
async def list_runbooks(request: Request) -> list[RunbookOut]:
    """All operator runbooks, most-recently-updated first (analyst-readable)."""
    async with request.app.state.db_sessionmaker() as db:
        rows = await runbooks_svc.list_all(db)
    return [_runbook_out(r) for r in rows]


@router.post(
    "/runbooks",
    response_model=RunbookOut,
    dependencies=[Depends(require_admin_api)],
)
async def create_runbook(request: Request, body: RunbookIn) -> RunbookOut:
    """Author a new runbook the triage agent can search + cite."""
    created_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        row = await runbooks_svc.create(
            db,
            title=body.title,
            content=body.content,
            tags=body.tags,
            linked_rules=body.linked_rules,
            created_by=created_by,
        )
    return _runbook_out(row)


@router.put(
    "/runbooks/{runbook_id}",
    response_model=RunbookOut,
    dependencies=[Depends(require_admin_api)],
)
async def update_runbook(request: Request, runbook_id: int, body: RunbookPatch) -> RunbookOut:
    """Update a runbook's fields. 404 if it doesn't exist."""
    async with request.app.state.db_sessionmaker() as db:
        row = await runbooks_svc.update(
            db,
            runbook_id,
            title=body.title,
            content=body.content,
            tags=body.tags,
            linked_rules=body.linked_rules,
        )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found", "hint": "no runbook with that id"},
        )
    return _runbook_out(row)


@router.delete(
    "/runbooks/{runbook_id}",
    dependencies=[Depends(require_admin_api)],
)
async def delete_runbook(request: Request, runbook_id: int) -> dict[str, bool]:
    """Delete a runbook. 404 if it doesn't exist."""
    async with request.app.state.db_sessionmaker() as db:
        ok = await runbooks_svc.delete(db, runbook_id)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found", "hint": "no runbook with that id"},
        )
    return {"deleted": True}
