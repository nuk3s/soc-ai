"""Runbook CRUD + starter-pack endpoints."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    _iso_utc,
    require_admin_api,
    router,
)
from soc_ai.config import Settings
from soc_ai.rag import runbook_embeddings as rag_svc
from soc_ai.store import runbook_pack
from soc_ai.store import runbooks as runbooks_svc
from soc_ai.store.models import RunbookEmbedding

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
    # True for an unapproved promotion draft (machine-authored from
    # investigation history): shown badged in the Runbooks page but EXCLUDED
    # from every agent retrieval tier until the admin approve endpoint flips it.
    draft: bool = False
    created_by: str
    created_at: str
    updated_at: str
    # Semantic-tier status (E4.1 surfaced): BOTH are None while the tier is off
    # (``rag_embed_model`` unset) so the UI can distinguish "not applicable"
    # from "missing". ``embedded`` = a vector row exists; ``stale`` = it was
    # produced by a DIFFERENT model than the one currently configured (skipped
    # at query time — the "Re-embed runbooks" admin pass refreshes it).
    embedded: bool | None = None
    stale: bool | None = None


def _runbook_out(
    row: Any,
    *,
    embed_models: dict[int, str] | None = None,
    rag_model: str = "",
) -> RunbookOut:
    """Serialize a Runbook row; ``embed_models`` maps runbook_id → vector's model.

    ``rag_model`` empty (tier off) leaves the status fields None — callers that
    don't care (delete paths, tier off) simply omit both kwargs.
    """
    embedded: bool | None = None
    stale: bool | None = None
    if rag_model:
        vector_model = (embed_models or {}).get(row.id)
        embedded = vector_model is not None
        stale = embedded and vector_model != rag_model
    return RunbookOut(
        id=row.id,
        title=row.title,
        content=row.content or "",
        tags=list(row.tags or []),
        linked_rules=list(row.linked_rules or []),
        draft=bool(row.draft),
        created_by=row.created_by,
        created_at=_iso_utc(row.created_at),
        updated_at=_iso_utc(row.updated_at),
        embedded=embedded,
        stale=stale,
    )


def _rag_model(settings: Settings) -> str:
    """The configured embed model id, or "" when the semantic tier is off."""
    return (settings.rag_embed_model or "").strip()


async def _embed_model_of(db: AsyncSession, runbook_id: int) -> dict[int, str]:
    """Single-row ``embed_models`` map for a just-written runbook (one PK get)."""
    row = await db.get(RunbookEmbedding, runbook_id)
    return {runbook_id: row.model} if row is not None else {}


@router.get("/runbooks", response_model=list[RunbookOut])
async def list_runbooks(request: Request) -> list[RunbookOut]:
    """All operator runbooks, most-recently-updated first (analyst-readable).

    When the semantic tier is on, each row also carries its embed status —
    computed from ONE bulk query over ``runbook_embedding`` (id → model), never
    a per-row lookup.
    """
    rag_model = _rag_model(request.app.state.settings)
    embed_models: dict[int, str] | None = None
    async with request.app.state.db_sessionmaker() as db:
        rows = await runbooks_svc.list_all(db)
        if rag_model:
            pairs = await db.execute(select(RunbookEmbedding.runbook_id, RunbookEmbedding.model))
            embed_models = {int(rid): str(model) for rid, model in pairs.all()}
    return [_runbook_out(r, embed_models=embed_models, rag_model=rag_model) for r in rows]


@router.post(
    "/runbooks",
    response_model=RunbookOut,
    dependencies=[Depends(require_admin_api)],
)
async def create_runbook(request: Request, body: RunbookIn) -> RunbookOut:
    """Author a new runbook the triage agent can search + cite."""
    created_by = await identify_caller(request)
    rag_model = _rag_model(request.app.state.settings)
    embed_models: dict[int, str] = {}
    async with request.app.state.db_sessionmaker() as db:
        row = await runbooks_svc.create(
            db,
            title=body.title,
            content=body.content,
            tags=body.tags,
            linked_rules=body.linked_rules,
            created_by=created_by,
        )
        # Opt-in semantic tier: keep the vector fresh at write time. Fail-SOFT —
        # a down gateway must never fail a runbook save (the row just lacks an
        # embedding until the next write or an admin re-embed). No-op when
        # rag_embed_model is unset.
        await rag_svc.embed_runbook_safe(db, row, settings=request.app.state.settings)
        if rag_model:
            # Report honest embed status on the response (the UI shows it
            # without a refetch) — read back rather than assuming success.
            embed_models = await _embed_model_of(db, row.id)
    return _runbook_out(row, embed_models=embed_models, rag_model=rag_model)


class StarterPackOut(BaseModel):
    created: int  # runbooks added this call
    skipped: int  # pack titles already present (idempotent no-ops)


@router.post(
    "/runbooks/starter-pack",
    response_model=StarterPackOut,
    dependencies=[Depends(require_admin_api)],
)
async def install_starter_pack(request: Request) -> StarterPackOut:
    """Load the shipped starter-pack runbooks (``runbooks/starter-pack/*.md``).

    IDEMPOTENT by title (case-insensitive): a pack runbook whose title already
    exists in the store is skipped, so re-clicking the button never duplicates
    — and an operator-EDITED copy of a pack runbook is left alone (same title,
    their content wins). Each created runbook goes through the same write path
    as manual authoring, including the fail-soft write-time embed.
    """
    pack = runbook_pack.load_starter_pack()
    if not pack:
        # A missing/empty pack dir is a broken install (image built without the
        # runbooks/ COPY), not "nothing to do" — surface it, don't zero-count.
        raise HTTPException(
            status_code=404,
            detail={
                "reason": "starter_pack_missing",
                "hint": f"no runbook files under {runbook_pack.STARTER_PACK_DIR}",
            },
        )
    created_by = await identify_caller(request)
    created = 0
    skipped = 0
    async with request.app.state.db_sessionmaker() as db:
        existing = {r.title.strip().casefold() for r in await runbooks_svc.list_all(db)}
        for parsed in pack:
            key = parsed.title.strip().casefold()
            if key in existing:
                skipped += 1
                continue
            row = await runbooks_svc.create(
                db,
                title=parsed.title,
                content=parsed.content,
                tags=parsed.tags,
                linked_rules=parsed.linked_rules,
                created_by=created_by,
            )
            # Same fail-soft write-time embed as manual create (no-op tier-off).
            await rag_svc.embed_runbook_safe(db, row, settings=request.app.state.settings)
            existing.add(key)  # guards against duplicate titles WITHIN the pack
            created += 1
    return StarterPackOut(created=created, skipped=skipped)


@router.put(
    "/runbooks/{runbook_id}",
    response_model=RunbookOut,
    dependencies=[Depends(require_admin_api)],
)
async def update_runbook(request: Request, runbook_id: int, body: RunbookPatch) -> RunbookOut:
    """Update a runbook's fields. 404 if it doesn't exist."""
    rag_model = _rag_model(request.app.state.settings)
    embed_models: dict[int, str] = {}
    async with request.app.state.db_sessionmaker() as db:
        row = await runbooks_svc.update(
            db,
            runbook_id,
            title=body.title,
            content=body.content,
            tags=body.tags,
            linked_rules=body.linked_rules,
        )
        if row is not None:
            # Same fail-soft write-time embed as create — an edited runbook's
            # stale vector would otherwise mis-rank semantic retrieval. SKIPPED
            # for drafts: a draft is excluded from retrieval by contract, so a
            # vector for it is dead weight — the approve endpoint embeds it the
            # moment it becomes retrievable.
            if not row.draft:
                await rag_svc.embed_runbook_safe(db, row, settings=request.app.state.settings)
            if rag_model:
                embed_models = await _embed_model_of(db, row.id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found", "hint": "no runbook with that id"},
        )
    return _runbook_out(row, embed_models=embed_models, rag_model=rag_model)


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


# ── Promotion: investigation history → DRAFT runbook ──────────────────────────
#
# The distillation sibling of detection tuning (E4.3): the deployment's own
# verdict history becomes a runbook SUGGESTION the operator reviews. Drafts are
# invisible to agent retrieval until approved (see soc_ai/store/runbooks.py) —
# these endpoints only ever create/flip drafts, never publish silently. All
# admin-gated: promotion spends an analyst-model call and approve changes what
# the agent can cite.


class PromotableRuleOut(BaseModel):
    """One rule whose history is deep enough to distill into a runbook."""

    rule_name: str
    investigations: int  # completed, verdict-bearing, non-fallback
    false_positive: int
    true_positive: int
    needs_more_info: int
    dominant_verdict: str
    last_activity: str  # ISO-8601 of the newest counted investigation


class PromoteIn(BaseModel):
    # Same bounds as the investigations column the rule names come from.
    rule_name: str = Field(min_length=1, max_length=512)


@router.get(
    "/runbooks/promotable",
    response_model=list[PromotableRuleOut],
    dependencies=[Depends(require_admin_api)],
)
async def get_promotable_rules(request: Request) -> list[PromotableRuleOut]:
    """Rules with enough completed history and no runbook covering them yet.

    Pure local read (SQLite only) — safe to call on every panel open. A rule
    disappears from this list the moment ANY runbook (draft included) links it,
    which is what makes the "Draft it" button naturally idempotent.
    """
    from soc_ai.webui import runbook_promotion as promo  # noqa: PLC0415 - lazy

    async with request.app.state.db_sessionmaker() as db:
        rules = await promo.promotable_rules(db)
    return [
        PromotableRuleOut(
            rule_name=r["rule_name"],
            investigations=r["investigations"],
            false_positive=r["false_positive"],
            true_positive=r["true_positive"],
            needs_more_info=r["needs_more_info"],
            dominant_verdict=r["dominant_verdict"],
            last_activity=_iso_utc(r["last_activity"]),
        )
        for r in rules
    ]


@router.post(
    "/runbooks/promote",
    response_model=RunbookOut,
    dependencies=[Depends(require_admin_api)],
)
async def promote_runbook(request: Request, body: PromoteIn) -> RunbookOut:
    """Distill one rule's investigation history into a DRAFT runbook.

    SYNCHRONOUS by design: this is ONE structured-output model call (seconds to
    ~a minute on the local gateway), unlike the chat routes' multi-turn agent
    loops (which background + poll via a pending message row). There is no
    generic async-job idiom in the app to reuse, and inventing one for a single
    call isn't worth the moving parts — the model client's own read timeout
    (``Settings.litellm_request_timeout_s``, 300s default, with gateway retries
    baked into the transport) is the binding ceiling, well under uvicorn's
    patience. The frontend shows a per-rule progress state while it waits.

    Failure mapping: no usable history → 404; fail-closed redaction blocked the
    outbound prompt → 502 ``egress_blocked`` (count only, never the values);
    any model/validation failure → 502 ``draft_failed``. No partial rows — the
    draft is only written after a valid structured output.
    """
    from soc_ai.agent.egress_guard import EgressResidueError  # noqa: PLC0415 - lazy
    from soc_ai.webui import runbook_promotion as promo  # noqa: PLC0415 - lazy

    created_by = await identify_caller(request)
    rag_model = _rag_model(request.app.state.settings)
    async with request.app.state.db_sessionmaker() as db:
        try:
            drafted = await promo.draft_runbook_for_rule(
                db,
                request.app.state.settings,
                body.rule_name,
                created_by=created_by,
                audit=getattr(request.app.state, "audit", None),
            )
        except promo.NoPromotableHistoryError as exc:
            raise HTTPException(
                status_code=404,
                detail={
                    "reason": "no_history",
                    "hint": "no completed non-fallback investigations for that rule",
                },
            ) from exc
        except EgressResidueError as exc:
            # Fail-closed redaction refused the egress. Surface only the COUNT
            # — echoing the leaked values would defeat the block itself.
            raise HTTPException(
                status_code=502,
                detail={"reason": "egress_blocked", "leaked_count": len(exc.leaked)},
            ) from exc
        except HTTPException:
            raise
        except Exception as exc:
            # One model call, many failure shapes (gateway down, schema retries
            # exhausted, timeout). The draft never landed; tell the UI honestly.
            _LOGGER.warning("runbook promotion failed for %r", body.rule_name, exc_info=True)
            raise HTTPException(
                status_code=502,
                detail={"reason": "draft_failed", "hint": "analyst model call failed"},
            ) from exc
    # Deliberately NOT embedded here (draft ⇒ invisible to retrieval); the
    # response still carries honest tier status (embedded=False when tier on).
    return _runbook_out(drafted.runbook, rag_model=rag_model)


@router.post(
    "/runbooks/{runbook_id}/approve",
    response_model=RunbookOut,
    dependencies=[Depends(require_admin_api)],
)
async def approve_runbook(request: Request, runbook_id: int) -> RunbookOut:
    """Approve a draft: flip ``draft=False`` and embed it (tier on, fail-soft).

    THE single gate where a promotion draft becomes retrievable — the store's
    ``update`` is the only writer of the flag and this route is its only
    caller. Embedding happens here (not at draft time) so a vector exists
    exactly when the row is searchable. Idempotent on an already-published
    runbook (re-flips to False, refreshes the embed).
    """
    rag_model = _rag_model(request.app.state.settings)
    embed_models: dict[int, str] = {}
    async with request.app.state.db_sessionmaker() as db:
        row = await runbooks_svc.update(db, runbook_id, draft=False)
        if row is not None:
            # Same fail-soft write-time embed as create/update — a gateway
            # outage must never block an approval (the row just lacks a vector
            # until the next write or an admin re-embed).
            await rag_svc.embed_runbook_safe(db, row, settings=request.app.state.settings)
            if rag_model:
                embed_models = await _embed_model_of(db, row.id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found", "hint": "no runbook with that id"},
        )
    return _runbook_out(row, embed_models=embed_models, rag_model=rag_model)
