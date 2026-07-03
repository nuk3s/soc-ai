"""Persistence + keyword search for operator-authored runbooks.

A :class:`~soc_ai.store.models.Runbook` row is the org's own guidance for a
class of alert — how *this* team triages it, what "normal" looks like here,
which hosts are known-benign, the confirm/dismiss steps. The triage agent's
``lookup_runbook`` tool calls :func:`search` so an investigation can cite the
operator's real runbooks instead of hallucinating a false-positive from thin
data.

**Search is deliberately embedding-free in v1** — a robust, air-gapped,
dependency-free keyword/tag/rule-link ranker over SQLite. Ranking, strongest
first:

1. **rule-link match** — the runbook lists the alert's rule (name/UUID) in
   ``linked_rules``; this is the operator saying "for *this* rule, do *this*".
2. **tag match** — a query token equals one of the runbook's tags.
3. **keyword overlap** — case-insensitive token overlap in title (weighted) and
   content.

Upgrade path (v1.1): swap :func:`search` for a Qwen3-Embedding-8B dense index
(alias ``soc-ai-embed``) over Qdrant, keeping this function's return shape so
the tool surface is unchanged. The keyword path stays as the air-gapped
fallback.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import Runbook

SOURCE = "operator_runbook"

# Ranking weights — rule-link dominates tag, which dominates keyword overlap.
_W_RULE_LINK = 100.0
_W_TAG = 10.0
_W_TITLE_TOKEN = 3.0
_W_CONTENT_TOKEN = 1.0

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric tokens (2+ chars) — the keyword unit for scoring."""
    return [t for t in _TOKEN_RE.findall(text.lower()) if len(t) >= 2]


def _norm_list(values: Any) -> list[str]:
    """Coerce tags / linked_rules into a clean list of non-empty strings."""
    if not values:
        return []
    if isinstance(values, str):
        parts: list[str] = re.split(r"[,\n]", values)
    elif isinstance(values, (list, tuple, set)):
        parts = [str(v) for v in values]
    else:
        return []
    return [p.strip() for p in parts if p and p.strip()]


# ── CRUD ─────────────────────────────────────────────────────────────────────


async def create(
    db: AsyncSession,
    *,
    title: str,
    content: str = "",
    tags: list[str] | None = None,
    linked_rules: list[str] | None = None,
    created_by: str = "anonymous",
) -> Runbook:
    """Create a runbook. ``tags`` / ``linked_rules`` are normalized to str lists."""
    runbook = Runbook(
        title=title[:512],
        content=content,
        tags=_norm_list(tags),
        linked_rules=_norm_list(linked_rules),
        created_by=created_by[:128],
    )
    db.add(runbook)
    await db.commit()
    await db.refresh(runbook)
    return runbook


async def get(db: AsyncSession, runbook_id: int) -> Runbook | None:
    return await db.get(Runbook, runbook_id)


async def list_all(db: AsyncSession, *, limit: int = 500) -> list[Runbook]:
    """All runbooks, most-recently-updated first."""
    rows = await db.scalars(
        select(Runbook).order_by(Runbook.updated_at.desc(), Runbook.id.desc()).limit(limit)
    )
    return list(rows.all())


async def update(
    db: AsyncSession,
    runbook_id: int,
    *,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
    linked_rules: list[str] | None = None,
) -> Runbook | None:
    """Patch the given fields (``None`` = leave unchanged). Returns the row or None."""
    runbook = await db.get(Runbook, runbook_id)
    if runbook is None:
        return None
    if title is not None:
        runbook.title = title[:512]
    if content is not None:
        runbook.content = content
    if tags is not None:
        runbook.tags = _norm_list(tags)
    if linked_rules is not None:
        runbook.linked_rules = _norm_list(linked_rules)
    await db.commit()
    await db.refresh(runbook)
    return runbook


async def delete(db: AsyncSession, runbook_id: int) -> bool:
    """Hard-delete a runbook. Returns True if it existed."""
    runbook = await db.get(Runbook, runbook_id)
    if runbook is None:
        return False
    await db.delete(runbook)
    await db.commit()
    return True


# ── Search (embedding-free keyword/tag/rule-link ranker) ─────────────────────


def _score(
    runbook: Runbook,
    query_tokens: set[str],
    *,
    rule_name: str | None,
) -> float:
    """Rank one runbook against the query. See module docstring for the scheme."""
    score = 0.0

    rules = {r.lower() for r in _norm_list(runbook.linked_rules)}
    if rule_name and rules:
        rn = rule_name.lower().strip()
        # Exact or substring match against a linked rule — the strongest signal.
        if rn in rules or any(rn in r or r in rn for r in rules):
            score += _W_RULE_LINK

    tags = {t.lower() for t in _norm_list(runbook.tags)}
    score += _W_TAG * len(query_tokens & tags)

    if query_tokens:
        title_tokens = set(_tokenize(runbook.title))
        content_tokens = set(_tokenize(runbook.content or ""))
        score += _W_TITLE_TOKEN * len(query_tokens & title_tokens)
        score += _W_CONTENT_TOKEN * len(query_tokens & content_tokens)

    return score


async def search(
    db: AsyncSession,
    query: str,
    *,
    k: int = 5,
    rule_name: str | None = None,
) -> list[dict[str, Any]]:
    """Return up to ``k`` matching runbooks, best first, in the tool's shape.

    Ranking (strongest first): rule-link match > tag match > keyword overlap in
    title/content. When ``query`` has no usable tokens and ``rule_name`` is
    given, rule-linked runbooks still match; when neither yields any signal the
    result is empty. ``k <= 0`` returns ``[]`` (the tool's ``k`` guard raises
    before calling this, so it's a defensive no-op here).

    Each entry: ``{"id", "title", "content", "score", "source": "operator_runbook"}``.
    """
    if k <= 0:
        return []

    query_tokens = set(_tokenize(query or ""))
    if not query_tokens and not rule_name:
        return []

    # Cap the working set (matches ``list_all``); scoring is in-process, so an
    # unbounded fetch is a latency/memory footgun on every agent tool call.
    rows = list((await db.scalars(select(Runbook).limit(500))).all())
    scored = [(s, rb) for rb in rows if (s := _score(rb, query_tokens, rule_name=rule_name)) > 0]
    # Highest score first; break ties by most-recent id for determinism.
    scored.sort(key=lambda pair: (pair[0], pair[1].id), reverse=True)

    return [
        {
            "id": rb.id,
            "title": rb.title,
            "content": rb.content or "",
            "score": round(score, 4),
            "source": SOURCE,
        }
        for score, rb in scored[:k]
    ]
