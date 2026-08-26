"""Opt-in semantic tier for runbook retrieval — gateway embeddings + rerank (E4.1).

The DEFAULT runbook retrieval (:func:`soc_ai.store.runbooks.search`) is SQLite
FTS5 BM25: zero dependencies, zero egress, always on. This module adds the
OPTIONAL semantic tier on top, gated entirely on two Settings knobs that default
empty (= off):

* ``rag_embed_model`` — an OpenAI-compatible ``/v1/embeddings`` model id on the
  operator's gateway (``litellm_base_url``, the SAME gateway the analyst model
  uses — no new egress destination is introduced, and the egress-policy page
  lists it). Runbook writes embed **fail-soft** (a down gateway logs and moves
  on; the row just lacks a vector until the next write or an admin re-embed),
  and :func:`semantic_search` embeds the query then cosines over the stored
  vectors **in pure Python** — the corpus is a few hundred operator-authored
  documents at most, so numpy/a vector DB would be dead weight.

* ``rag_rerank_model`` — a Cohere-shape ``/rerank`` model id used by
  ``search()`` to rerank the merged keyword+semantic candidates; also fail-soft
  (the merged order stands on any error).

Vectors live in the ``runbook_embedding`` table (migration 0017) as float32
little-endian bytes, stamped with the producing ``model`` — rows whose model no
longer matches the configured ``rag_embed_model`` are STALE and skipped (mixing
vector spaces produces garbage cosines); ``reembed_missing`` (the admin
"Re-embed runbooks" button) refreshes missing + stale rows in one pass.

Gateway calls raise :class:`RagGatewayError` (a single catchable class wrapping
HTTP/transport/shape failures); CALLERS decide the failure posture — write
paths and ``search()`` swallow it (fail-soft), the re-embed endpoint reports it
as failed counts.

Egress redaction: the gateway may be a CLOUD provider, so this tier honours
``analyst_cloud_redaction`` exactly like every other analyst-model call site.
:func:`embed_texts` and :func:`rerank_scores` — the module's ONLY two egress
functions — sanitize every outbound string through an
:class:`~soc_ai.agent.egress_guard.EgressGuard` and run the independent
fail-closed residue sweep before any bytes leave. Callers with a DB session in
hand thread a guard built over the deployment's EFFECTIVE identifier set (via
:func:`rag_egress_guard`); when none is threaded the egress functions build an
env-floor guard themselves, so no caller can forget the boundary. Nothing is
desanitized on the way back — the responses are vectors and scores, not text.
"""

from __future__ import annotations

import logging
import math
import struct
from typing import TYPE_CHECKING, Any

import httpx
from sqlalchemy import select

from soc_ai.demo.guard import assert_egress_allowed
from soc_ai.store.models import Runbook, RunbookEmbedding

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession

    from soc_ai.agent.egress_guard import EgressGuard
    from soc_ai.config import Settings

_LOGGER = logging.getLogger(__name__)

# Per-request timeout for embeddings/rerank calls. Retrieval sits on the agent's
# tool path, so it must fail FAST when the gateway is wedged — the FTS/keyword
# tier already has the answer and a hung semantic call would stall the whole
# investigation turn. Deliberately far below litellm_request_timeout_s (300s,
# sized for heavy completions, not embeddings).
_RAG_TIMEOUT_S = 30.0

# Cap on the content slice sent per document to the rerank endpoint (consumed
# by search() when it builds the doc list). Runbook bodies can be up to 64 KiB;
# a cross-encoder only needs the head to judge relevance, and shipping whole
# bodies inflates latency for no ranking gain.
RERANK_DOC_CHARS = 2000


class RagGatewayError(RuntimeError):
    """A gateway embeddings/rerank call failed (HTTP error, transport error,
    or a response that doesn't match the expected shape). One class so callers
    have a single thing to catch when deciding their fail-soft posture."""


# ── Vector plumbing (pure Python — the corpus is small by design) ─────────────


def vector_to_bytes(vec: Sequence[float]) -> bytes:
    """Encode a vector as float32 little-endian bytes (the storage format)."""
    return struct.pack(f"<{len(vec)}f", *vec)


def bytes_to_vector(raw: bytes) -> list[float]:
    """Decode float32 little-endian bytes back to a list of floats."""
    return list(struct.unpack(f"<{len(raw) // 4}f", raw))


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity in pure Python. 0.0 for a zero/degenerate vector."""
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _runbook_text(runbook: Runbook) -> str:
    """The text embedded for a runbook: title + tags + content, one document.

    Tags are folded in so a semantically-tagged runbook ("beacon", "c2") matches
    queries about that topic even when the body never repeats the word.
    """
    tags = ", ".join(str(t) for t in (runbook.tags or []))
    return f"{runbook.title}\n{tags}\n{runbook.content or ''}"


# ── Gateway calls (the ONLY egress in this module — both to litellm_base_url) ─


async def rag_egress_guard(db: AsyncSession | None, settings: Settings) -> EgressGuard | None:
    """The cloud-egress guard for this tier's gateway calls; ``None`` = off.

    ``is True`` (not truthiness) so a non-Settings test double can never flip
    redaction on — the same guard-rail every other egress site uses. With a
    session in hand, the guard covers the deployment's EFFECTIVE identifier set
    (env config unioned with DB-discovered identifiers), mirroring the
    runbook-promotion builder; on any DB trouble — or with no session — it
    falls back to the env-config floor via
    :meth:`~soc_ai.agent.egress_guard.EgressGuard.for_settings`.

    A fresh guard per call is correct here: nothing this tier receives back is
    text (vectors and scores carry no labels to restore), so mapping stability
    with the agent run's guard buys nothing.
    """
    if settings.analyst_cloud_redaction is not True:
        return None
    # Local imports: soc_ai.agent's package __init__ pulls the orchestrator, and
    # soc_ai.store.runbooks imports this module at module scope — importing the
    # guard lazily keeps that cycle broken (same idiom as lookup_runbook).
    from soc_ai.agent.egress_guard import EgressGuard  # noqa: PLC0415

    if db is not None:
        try:
            from soc_ai.oracle.identifiers import (  # noqa: PLC0415
                effective_internal_identifiers,
            )

            effective = await effective_internal_identifiers(db, settings)
            return EgressGuard(extra_hosts=effective.hosts, extra_suffixes=effective.suffixes)
        except Exception:
            _LOGGER.warning(
                "rag: effective-identifier resolution failed; falling back to "
                "env-config hosts/suffixes",
                exc_info=True,
            )
    return await EgressGuard.for_settings(settings)


async def _guarded_texts(
    texts: list[str], *, settings: Settings, guard: EgressGuard | None
) -> list[str]:
    """Sanitize + fail-closed-sweep *texts* for egress; raw when redaction is off.

    The shared outbound boundary for :func:`embed_texts` and
    :func:`rerank_scores`. When no guard was threaded, one is built here
    (env-floor) so a caller that forgot cannot egress raw identifiers. Raises
    :class:`~soc_ai.agent.egress_guard.EgressResidueError` when fail-closed
    redaction is on and an identifier survived sanitization — before any bytes
    leave the process.
    """
    if guard is None:
        guard = await rag_egress_guard(None, settings)
    if guard is None:
        return texts
    fail_closed = settings.analyst_redaction_fail_closed is True
    out: list[str] = []
    for text in texts:
        clean = guard.sanitize_text(text)
        guard.check_or_raise(clean, fail_closed=fail_closed)
        out.append(clean)
    return out


def _gateway(settings: Settings) -> tuple[str, dict[str, str], bool]:
    """(base_url, auth headers, verify) — mirrors the probes.py gateway wiring
    so the semantic tier reaches exactly the host the analyst model uses."""
    base = str(settings.litellm_base_url).rstrip("/")
    api_key = ""
    secret = getattr(settings, "litellm_api_key", None)
    if secret is not None:
        api_key = secret.get_secret_value()
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    verify = bool(getattr(settings, "litellm_verify_ssl", True))
    return base, headers, verify


async def embed_texts(
    texts: list[str], *, settings: Settings, guard: EgressGuard | None = None
) -> list[list[float]]:
    """Embed *texts* via ``POST {gateway}/v1/embeddings`` (OpenAI shape).

    Returns one vector per input, in input order (the response's ``index``
    field is honoured, not the array order). Raises :class:`RagGatewayError`
    on any HTTP/transport/shape failure — callers pick the fail-soft posture.

    With ``analyst_cloud_redaction`` on, *texts* are sanitized (and swept
    fail-closed) via *guard* — or a guard built here when none is threaded —
    before they leave for the gateway;
    :class:`~soc_ai.agent.egress_guard.EgressResidueError` propagates distinctly
    from :class:`RagGatewayError` so a redaction block is never mistaken for a
    gateway outage.
    """
    assert_egress_allowed(settings, "embeddings")
    texts = await _guarded_texts(texts, settings=settings, guard=guard)
    base, headers, verify = _gateway(settings)
    payload = {"model": settings.rag_embed_model, "input": texts}
    try:
        async with httpx.AsyncClient(timeout=_RAG_TIMEOUT_S, verify=verify) as client:
            resp = await client.post(f"{base}/v1/embeddings", headers=headers, json=payload)
    except httpx.HTTPError as exc:
        raise RagGatewayError(f"embeddings call failed: {type(exc).__name__}") from exc
    if resp.status_code != 200:
        raise RagGatewayError(f"embeddings call returned HTTP {resp.status_code}")
    try:
        data = resp.json()["data"]
        by_index = {int(item["index"]): list(item["embedding"]) for item in data}
        vectors = [[float(x) for x in by_index[i]] for i in range(len(texts))]
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise RagGatewayError("embeddings response had an unexpected shape") from exc
    if any(not v for v in vectors):
        raise RagGatewayError("embeddings response contained an empty vector")
    return vectors


async def rerank_scores(
    query: str,
    documents: list[str],
    *,
    settings: Settings,
    guard: EgressGuard | None = None,
) -> list[float]:
    """Score *documents* against *query* via ``POST {gateway}/rerank`` (Cohere shape).

    Returns one relevance score per document, in DOCUMENT order (a document the
    endpoint omits scores 0.0). Raises :class:`RagGatewayError` on failure —
    ``search()`` catches it and keeps the pre-rerank merged order (fail-soft).

    Same egress redaction as :func:`embed_texts`: with
    ``analyst_cloud_redaction`` on, the query and every document are sanitized
    and swept before any bytes leave for the gateway.
    """
    assert_egress_allowed(settings, "embeddings")
    guarded = await _guarded_texts([query, *documents], settings=settings, guard=guard)
    query, documents = guarded[0], guarded[1:]
    base, headers, verify = _gateway(settings)
    payload = {
        "model": settings.rag_rerank_model,
        "query": query,
        "documents": documents,
        "top_n": len(documents),
    }
    try:
        async with httpx.AsyncClient(timeout=_RAG_TIMEOUT_S, verify=verify) as client:
            resp = await client.post(f"{base}/rerank", headers=headers, json=payload)
    except httpx.HTTPError as exc:
        raise RagGatewayError(f"rerank call failed: {type(exc).__name__}") from exc
    if resp.status_code != 200:
        raise RagGatewayError(f"rerank call returned HTTP {resp.status_code}")
    scores = [0.0] * len(documents)
    try:
        for item in resp.json()["results"]:
            idx = int(item["index"])
            if 0 <= idx < len(documents):
                scores[idx] = float(item["relevance_score"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RagGatewayError("rerank response had an unexpected shape") from exc
    return scores


# ── Store operations ──────────────────────────────────────────────────────────


async def embed_runbook(db: AsyncSession, runbook: Runbook, *, settings: Settings) -> None:
    """Embed one runbook and upsert its ``runbook_embedding`` row (commits).

    Raises :class:`RagGatewayError` on gateway failure — use
    :func:`embed_runbook_safe` on write paths that must not fail the write.
    """
    guard = await rag_egress_guard(db, settings)
    vec = (await embed_texts([_runbook_text(runbook)], settings=settings, guard=guard))[0]
    row = await db.get(RunbookEmbedding, runbook.id)
    if row is None:
        db.add(
            RunbookEmbedding(
                runbook_id=runbook.id,
                model=settings.rag_embed_model,
                dim=len(vec),
                vector=vector_to_bytes(vec),
            )
        )
    else:
        row.model = settings.rag_embed_model
        row.dim = len(vec)
        row.vector = vector_to_bytes(vec)
    await db.commit()


async def embed_runbook_safe(db: AsyncSession, runbook: Runbook, *, settings: Settings) -> bool:
    """Fail-SOFT :func:`embed_runbook` for the create/update write paths.

    A gateway outage must never fail a runbook save — the row simply lacks an
    embedding until the next write or an admin re-embed. Returns whether the
    embedding landed. NO rollback on failure: :func:`embed_runbook` calls the
    gateway BEFORE touching the session, so a ``RagGatewayError`` leaves no
    pending DB mutation — and a rollback here would expire the caller's
    just-created ``runbook`` instance mid-request (its attributes are still
    needed to serialize the route response).
    """
    if not settings.rag_embed_model:
        return False
    from soc_ai.agent.egress_guard import EgressResidueError  # noqa: PLC0415 - import cycle

    runbook_id = runbook.id  # captured up front — never triggers a lazy load later
    try:
        await embed_runbook(db, runbook, settings=settings)
    except (RagGatewayError, EgressResidueError) as exc:
        # EgressResidueError = fail-closed redaction refused the outbound text;
        # like a gateway outage, it must never fail the SAVE — the row simply
        # stays unembedded. The exception string names a count, never a value.
        _LOGGER.warning("runbook %s embedding skipped (fail-soft): %s", runbook_id, exc)
        return False
    return True


async def reembed_missing(db: AsyncSession, *, settings: Settings) -> dict[str, int]:
    """Embed every runbook whose embedding is MISSING or STALE (wrong model).

    The admin "Re-embed runbooks" pass: rows already embedded by the current
    ``rag_embed_model`` are skipped; the rest are embedded in ONE batched
    gateway call (the corpus is small — chunking would be premature). A gateway
    failure marks all pending rows failed rather than raising, so the endpoint
    always returns honest counts.

    Returns ``{"total", "embedded", "skipped", "failed"}``.

    Drafts are excluded from the pass entirely (not even counted in ``total``):
    an unapproved promotion draft is invisible to retrieval by contract, so a
    vector for it is dead weight — the approve endpoint embeds it the moment it
    becomes retrievable.
    """
    runbooks = list((await db.scalars(select(Runbook).where(Runbook.draft.is_(False)))).all())
    existing = {e.runbook_id: e for e in (await db.scalars(select(RunbookEmbedding))).all()}

    pending = [
        rb
        for rb in runbooks
        if rb.id not in existing or existing[rb.id].model != settings.rag_embed_model
    ]
    skipped = len(runbooks) - len(pending)
    if not pending:
        return {"total": len(runbooks), "embedded": 0, "skipped": skipped, "failed": 0}

    from soc_ai.agent.egress_guard import EgressResidueError  # noqa: PLC0415 - import cycle

    try:
        guard = await rag_egress_guard(db, settings)
        vectors = await embed_texts(
            [_runbook_text(rb) for rb in pending], settings=settings, guard=guard
        )
    except (RagGatewayError, EgressResidueError) as exc:
        # A redaction block reports as failed counts exactly like an outage —
        # honest numbers, and the exception string never carries a value.
        _LOGGER.warning("re-embed failed at the gateway: %s", exc)
        return {
            "total": len(runbooks),
            "embedded": 0,
            "skipped": skipped,
            "failed": len(pending),
        }

    for rb, vec in zip(pending, vectors, strict=True):
        row = existing.get(rb.id)
        if row is None:
            db.add(
                RunbookEmbedding(
                    runbook_id=rb.id,
                    model=settings.rag_embed_model,
                    dim=len(vec),
                    vector=vector_to_bytes(vec),
                )
            )
        else:
            row.model = settings.rag_embed_model
            row.dim = len(vec)
            row.vector = vector_to_bytes(vec)
    await db.commit()
    return {
        "total": len(runbooks),
        "embedded": len(pending),
        "skipped": skipped,
        "failed": 0,
    }


async def semantic_search(
    db: AsyncSession,
    query: str,
    *,
    settings: Settings,
    k: int = 5,
    guard: EgressGuard | None = None,
) -> list[tuple[Runbook, float]]:
    """Top-``k`` runbooks by cosine similarity between *query* and stored vectors.

    Embeds the query (ONE gateway call), then scores in pure Python over every
    non-stale ``runbook_embedding`` row (stale = stored ``model`` differs from
    the configured ``rag_embed_model``, or the dimension doesn't match the query
    vector — both mean a different vector space, where cosine is meaningless).
    Raises :class:`RagGatewayError` if the query embedding fails; ``search()``
    catches it and proceeds keyword-only (fail-soft).

    Draft runbooks (unapproved promotion drafts, migration 0020) are excluded
    at the JOIN — the semantic tier honors the same "a draft never reaches a
    prompt" guarantee as the FTS/legacy/rule-link tiers in
    :func:`soc_ai.store.runbooks.search`, even if a draft somehow acquired a
    vector (e.g. it was edited through a write path that embeds).

    ``guard`` lets ``search()`` thread one effective-set egress guard across
    the semantic + rerank calls of a single retrieval; when ``None`` and
    redaction is on, one is built here from the session.
    """
    if k <= 0 or not query.strip() or not settings.rag_embed_model:
        return []

    rows: list[Any] = list(
        (
            await db.execute(
                select(Runbook, RunbookEmbedding)
                .join(RunbookEmbedding, RunbookEmbedding.runbook_id == Runbook.id)
                .where(Runbook.draft.is_(False))
            )
        ).all()
    )
    usable = [(rb, emb) for rb, emb in rows if emb.model == settings.rag_embed_model]
    if not usable:
        return []

    if guard is None:
        # No caller-threaded guard: build one over the effective identifier
        # set (the session is right here). ``None`` when redaction is off.
        guard = await rag_egress_guard(db, settings)
    query_vec = (await embed_texts([query], settings=settings, guard=guard))[0]
    scored = [
        (rb, cosine(query_vec, bytes_to_vector(emb.vector)))
        for rb, emb in usable
        if emb.dim == len(query_vec)
    ]
    scored.sort(key=lambda pair: (pair[1], pair[0].id), reverse=True)
    return scored[:k]
