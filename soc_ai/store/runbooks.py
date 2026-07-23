"""Persistence + tiered search for operator-authored runbooks.

A :class:`~soc_ai.store.models.Runbook` row is the org's own guidance for a
class of alert — how *this* team triages it, what "normal" looks like here,
which hosts are known-benign, the confirm/dismiss steps. The triage agent's
``lookup_runbook`` tool calls :func:`search` so an investigation can cite the
operator's real runbooks instead of hallucinating a false-positive from thin
data.

**Retrieval is FTS5-first (E4.1)** — always-on, zero-dependency, zero-egress:

1. **rule-link match** — the runbook lists the alert's rule (name/UUID) in
   ``linked_rules``; this is the operator saying "for *this* rule, do *this*".
   Fetched separately and boosted ABOVE every text hit, exactly as before.
2. **FTS5 BM25** over title/content/tags (the ``runbook_fts`` external-content
   index, migration 0017) with per-column weights mirroring the legacy ranker:
   tags ≫ title > content. The MATCH expression is built ONLY from quoted
   alphanumeric tokens — raw user text never reaches FTS syntax.
3. **legacy in-process scorer** (:func:`_score`) — the automatic fallback when
   this SQLite lacks FTS5 / the index doesn't exist (a pre-0017 DB). Same
   contract, same ranking scheme, kept tested.

**Opt-in semantic tier** (:mod:`soc_ai.rag.runbook_embeddings`): when the
caller passes ``settings`` and ``rag_embed_model`` is configured, semantic
top-k hits are UNIONED into the candidates with a weighted score
(``_W_SEMANTIC * cosine``, additive — a row that matches both keyword and
meaning ranks above either alone); when ``rag_rerank_model`` is also set the
merged candidates are reranked via the gateway ``/rerank`` (fail-soft to the
merged order). The rule-link boost dominates every tier by construction.

**Draft exclusion (migration 0020):** rows with ``draft=True`` — machine-
authored promotion drafts awaiting operator approval — are filtered out of
EVERY retrieval tier here (FTS SQL, the legacy scorer's scan, the rule-link
scan) and out of :func:`~soc_ai.rag.runbook_embeddings.semantic_search`'s
candidate join. That filter IS the "nothing auto-applies" guarantee: a draft
can sit in the store indefinitely without ever reaching a prompt.
:func:`list_all` deliberately still returns drafts (the Runbooks page shows
them, badged, for review).

The public signature/return shape is the agent-tool contract — unchanged
(``settings`` is an injected keyword like ``rule_name``, invisible to the LLM).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.rag import runbook_embeddings as rag_svc
from soc_ai.store.models import Runbook

if TYPE_CHECKING:
    from soc_ai.config import Settings

_LOGGER = logging.getLogger(__name__)

SOURCE = "operator_runbook"

# Ranking weights — rule-link dominates tag, which dominates keyword overlap.
# The same three text weights parameterize bm25()'s per-column weighting on the
# FTS path (columns title, content, tags), so both rankers share one scheme.
_W_RULE_LINK = 100.0
_W_TAG = 10.0
_W_TITLE_TOKEN = 3.0
_W_CONTENT_TOKEN = 1.0
# Semantic-tier weight: a cosine hit (≤1.0) contributes at most 5.0 — between a
# title token (3) and a tag (10), and always below the rule-link boost. Additive
# with the text score so keyword+meaning agreement ranks highest.
_W_SEMANTIC = 5.0

# How many BM25 hits to pull as candidates. Plenty above any tool k (≤5) so the
# merge/rerank stages have material, while keeping the row fetch bounded.
_FTS_CANDIDATES = 50

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# BM25 candidates joined back to the base table for ORM ids. FTS5's bm25() is
# smaller-is-better (≤ 0), so it's negated into a higher-is-better score. The
# per-column weights are trusted module constants formatted in below — the ONLY
# runtime parameter is the (token-sanitized) MATCH expression.
_FTS_SQL = f"""
SELECT rb.id AS id, -bm25(runbook_fts, {_W_TITLE_TOKEN}, {_W_CONTENT_TOKEN}, {_W_TAG}) AS score
FROM runbook_fts
JOIN runbook AS rb ON rb.id = runbook_fts.rowid
WHERE runbook_fts MATCH :match AND rb.draft = 0
ORDER BY score DESC
LIMIT :limit
"""  # noqa: S608 — constants + bound params only; no user text is interpolated


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
    draft: bool = False,
) -> Runbook:
    """Create a runbook. ``tags`` / ``linked_rules`` are normalized to str lists.

    ``draft=True`` is used ONLY by the promotion path
    (:mod:`soc_ai.webui.runbook_promotion`): the row is stored but invisible to
    every retrieval tier until approved. Operator authoring keeps the default.
    """
    runbook = Runbook(
        title=title[:512],
        content=content,
        tags=_norm_list(tags),
        linked_rules=_norm_list(linked_rules),
        created_by=created_by[:128],
        draft=draft,
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
    draft: bool | None = None,
) -> Runbook | None:
    """Patch the given fields (``None`` = leave unchanged). Returns the row or None.

    ``draft`` is deliberately NOT exposed through the PUT route's patch body —
    the only caller that passes it is the admin approve endpoint (``draft=False``),
    so the draft→published transition stays a single explicit gate (which also
    owns the embed-on-approve step) rather than a side effect of a field edit.
    """
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
    if draft is not None:
        runbook.draft = draft
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


# ── Search (FTS5 BM25 first; legacy keyword ranker as the fallback) ───────────


def _rule_link_match(runbook: Runbook, rule_name: str | None) -> bool:
    """True when the runbook's ``linked_rules`` names the alert's rule.

    Exact or substring match, either direction — a runbook linked to
    "ET MALWARE Beacon" should match rule_name "ET MALWARE Beacon (group 1)"
    and vice versa. The strongest retrieval signal in every path.
    """
    if not rule_name:
        return False
    rules = {r.lower() for r in _norm_list(runbook.linked_rules)}
    if not rules:
        return False
    rn = rule_name.lower().strip()
    return rn in rules or any(rn in r or r in rn for r in rules)


def _score(
    runbook: Runbook,
    query_tokens: set[str],
    *,
    rule_name: str | None,
) -> float:
    """LEGACY in-process ranker (the FTS5-less fallback). Scheme unchanged:
    rule-link (100) > tag (10/each) > title token (3/each) > content token (1/each)."""
    score = 0.0

    if _rule_link_match(runbook, rule_name):
        score += _W_RULE_LINK

    tags = {t.lower() for t in _norm_list(runbook.tags)}
    score += _W_TAG * len(query_tokens & tags)

    if query_tokens:
        title_tokens = set(_tokenize(runbook.title))
        content_tokens = set(_tokenize(runbook.content or ""))
        score += _W_TITLE_TOKEN * len(query_tokens & title_tokens)
        score += _W_CONTENT_TOKEN * len(query_tokens & content_tokens)

    return score


def _fts_match_expr(tokens: list[str]) -> str:
    """Build a SAFE FTS5 MATCH expression from sanitized query tokens.

    Every token is already ``[a-z0-9]+`` (see :func:`_tokenize`) so quoting it
    is injection-proof — no user-controlled quote/paren/operator can reach the
    FTS parser. Tokens are OR'd (recall over precision; BM25 handles precision)
    and the LAST token gets the prefix form (``"beaco"*``) so a partially-typed
    trailing word still matches.
    """
    quoted = [f'"{t}"' for t in tokens]
    quoted[-1] += "*"
    return " OR ".join(quoted)


async def _fts_hits(
    db: AsyncSession, tokens: list[str], *, limit: int
) -> list[tuple[int, float]] | None:
    """BM25-ranked ``(runbook_id, score)`` candidates, best first.

    Returns ``None`` when FTS5 isn't available here — the virtual table is
    missing (migration 0017 skipped it on an FTS5-less SQLite) or the module
    itself is absent — which tells :func:`search` to use the legacy scorer.
    The session is rolled back on that error so it stays usable.
    """
    try:
        rows = await db.execute(text(_FTS_SQL), {"match": _fts_match_expr(tokens), "limit": limit})
    except OperationalError:
        # "no such table: runbook_fts" / "no such module: fts5" → legacy path.
        await db.rollback()
        return None
    return [(int(rid), float(score)) for rid, score in rows.all()]


async def search(
    db: AsyncSession,
    query: str,
    *,
    k: int = 5,
    rule_name: str | None = None,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    """Return up to ``k`` matching runbooks, best first, in the tool's shape.

    Ranking (strongest first): rule-link match > text relevance (FTS5 BM25 with
    tag ≫ title > content column weights; the legacy token scorer on an
    FTS5-less SQLite) > semantic similarity (opt-in). When ``query`` has no
    usable tokens and ``rule_name`` is given, rule-linked runbooks still match;
    when neither yields any signal the result is empty. ``k <= 0`` returns
    ``[]`` (the tool's ``k`` guard raises before calling this, so it's a
    defensive no-op here).

    ``settings`` is an injected keyword (like ``rule_name`` — never part of the
    LLM-facing tool surface): when provided AND ``rag_embed_model`` is set,
    semantic top-k hits are unioned in; when ``rag_rerank_model`` is also set
    the merged candidates are reranked via the gateway (both fail-SOFT — any
    gateway trouble degrades to the local ranking, never an error). ``None``
    (CLI / tests / tier off) keeps retrieval 100% local.

    Each entry: ``{"id", "title", "content", "score", "source": "operator_runbook"}``.
    """
    if k <= 0:
        return []

    ordered_tokens = list(dict.fromkeys(_tokenize(query or "")))
    query_tokens = set(ordered_tokens)
    if not query_tokens and not rule_name:
        return []

    candidates: dict[int, Runbook] = {}
    scores: dict[int, float] = {}
    linked_ids: set[int] = set()

    # ── Text tier: FTS5 BM25, falling back to the legacy in-process scorer ────
    fts_pairs = await _fts_hits(db, ordered_tokens, limit=_FTS_CANDIDATES) if query_tokens else []
    if fts_pairs is None:
        # Legacy fallback — identical to the pre-FTS behavior. Cap the working
        # set (matches ``list_all``); scoring is in-process, so an unbounded
        # fetch is a latency/memory footgun on every agent tool call. _score
        # already folds in the rule-link boost. Drafts are excluded IN SQL
        # (mirrors the FTS SQL's ``rb.draft = 0``) so they never consume the
        # scan cap either.
        rows = list(
            (await db.scalars(select(Runbook).where(Runbook.draft.is_(False)).limit(500))).all()
        )
        for rb in rows:
            s = _score(rb, query_tokens, rule_name=rule_name)
            if s > 0:
                candidates[rb.id] = rb
                scores[rb.id] = s
            if _rule_link_match(rb, rule_name):
                linked_ids.add(rb.id)
    else:
        by_score = dict(fts_pairs)
        if by_score:
            hit_rows = await db.scalars(select(Runbook).where(Runbook.id.in_(by_score)))
            for rb in hit_rows:
                candidates[rb.id] = rb
                scores[rb.id] = by_score[rb.id]
        if rule_name:
            # Rule-linked runbooks rank first even with ZERO text overlap, so
            # they're fetched independently of the MATCH (same bounded scan as
            # the legacy path) and boosted above every BM25 hit. Draft-filtered
            # like every other tier — a promotion draft ALWAYS links its rule,
            # so without this filter the strongest boost would be the exact
            # path that leaks unapproved drafts into prompts.
            rows = list(
                (await db.scalars(select(Runbook).where(Runbook.draft.is_(False)).limit(500))).all()
            )
            for rb in rows:
                if _rule_link_match(rb, rule_name):
                    linked_ids.add(rb.id)
                    candidates[rb.id] = rb
                    scores[rb.id] = scores.get(rb.id, 0.0) + _W_RULE_LINK

    # ── Semantic tier (opt-in): union gateway-embedding hits, weighted ────────
    if settings is not None and settings.rag_embed_model and query.strip():
        try:
            sem = await rag_svc.semantic_search(db, query, settings=settings, k=k)
        except rag_svc.RagGatewayError as exc:
            _LOGGER.warning("semantic tier skipped (fail-soft): %s", exc)
            sem = []
        for rb, cos in sem:
            if cos <= 0.0:
                continue
            candidates.setdefault(rb.id, rb)
            scores[rb.id] = scores.get(rb.id, 0.0) + _W_SEMANTIC * cos

    if not candidates:
        return []

    # ── Optional rerank of the merged candidates (fail-soft) ──────────────────
    if settings is not None and settings.rag_rerank_model and query.strip() and len(candidates) > 1:
        ordered = list(candidates.values())
        docs = [f"{rb.title}\n{(rb.content or '')[: rag_svc.RERANK_DOC_CHARS]}" for rb in ordered]
        try:
            relevance = await rag_svc.rerank_scores(query, docs, settings=settings)
        except rag_svc.RagGatewayError as exc:
            _LOGGER.warning("rerank skipped (fail-soft): %s", exc)
        else:
            # Recompose: rerank owns the text/semantic ordering (relevance is
            # 0..1), but the rule-link boost still dominates by construction.
            scores = {
                rb.id: (_W_RULE_LINK if rb.id in linked_ids else 0.0) + relevance[i]
                for i, rb in enumerate(ordered)
            }

    # Highest score first; break ties by most-recent id for determinism.
    # Rounding is SIGNIFICANT-digit (not fixed-decimal): on a tiny corpus where
    # every doc contains the term, BM25's IDF collapses toward 0 and scores land
    # in the 1e-6 range — round(x, 4) would flatten a strict ordering to 0.0.
    ranked = sorted(candidates.values(), key=lambda rb: (scores[rb.id], rb.id), reverse=True)
    return [
        {
            "id": rb.id,
            "title": rb.title,
            "content": rb.content or "",
            "score": float(f"{scores[rb.id]:.6g}"),
            "source": SOURCE,
        }
        for rb in ranked[:k]
    ]
