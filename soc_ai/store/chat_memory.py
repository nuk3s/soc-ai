"""Chat-transcript memory: projection sync + FTS5 BM25 retrieval.

Past analyst↔AI chat threads carry real institutional knowledge ("we know that
host, it's the vuln scanner"). This module surfaces relevant snippets from past
chats to the synthesis step — under the operator's hard rule that NOTHING from
a transcript can ground a verdict: **transcripts are context, never evidence.**
The user in a transcript is not always right, so user turns are surfaced as
unverified operator opinion (the orchestrator's block header + per-line USER
labels carry that framing; the citation gate independently refuses to resolve
citations against prompt-context text).

Two halves:

- :func:`record_message` — the application-level dual-write that keeps the
  ``chat_memory`` projection (migration 0018) in step with the two chat source
  tables. App-level rather than triggers-on-source-tables because the hunt
  side stores role/content/status inside a JSON payload — extracting that in
  SQL trigger bodies is opaque and untestable next to three lines of Python.
- :func:`relevant_chat_snippets` — BM25 retrieval over ``chat_memory_fts``
  (external-content FTS5, synced from the projection by SQL triggers), with
  window / thread-exclusion / limit filters applied against the projection
  columns. Returns light digests, never full transcripts.

The MATCH expression mirrors :mod:`soc_ai.store.runbooks`' injection-proof
construction (only quoted ``[a-z0-9]+`` tokens ever reach FTS syntax), with
one deliberate difference: a multi-token term (an IP like ``10.0.0.1``) becomes
a quoted PHRASE ("10 0 0 1"), because FTS5's unicode61 tokenizer splits on the
dots — a phrase matches the IP exactly where OR'd single octets would match
almost any text containing small numbers.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.auth import utcnow
from soc_ai.store.models import ChatMemory

# The two chat sources. thread_id is the investigation / hunt ULID.
SOURCE_INVESTIGATION = "investigation"
SOURCE_HUNT = "hunt"

# Hard cap on snippets returned per retrieval — each one is prompt-context
# spend and (mislabeled-)anchoring surface, same rationale as memory_max_items.
_MAX_SNIPPETS = 5

# How many BM25 hits to pull as candidates before the window/exclude filters.
# The filters run AFTER the FTS pass (FTS5 can only rank text), so over-fetch
# enough that a page of recent-but-excluded rows can't starve the result.
_FTS_CANDIDATES = 50

# Snippet budget (chars). ~240 keeps one snippet to a single compact prompt
# line; truncation lands on a word boundary (mirrors the E4.2 rationale digest).
_SNIPPET_CHARS = 240

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# BM25 candidate pass only — window/exclude/limit are applied via the ORM
# against the projection afterwards (created_at/thread_id are not FTS columns).
# bm25() is smaller-is-better (≤ 0), so it's negated into higher-is-better.
# The ONLY runtime parameters are the token-sanitized MATCH expression and the
# candidate bound; no user text is interpolated.
_FTS_SQL = """
SELECT rowid AS id, -bm25(chat_memory_fts) AS score
FROM chat_memory_fts
WHERE chat_memory_fts MATCH :match
ORDER BY score DESC
LIMIT :candidates
"""


# ── Write-time projection sync ────────────────────────────────────────────────


def record_message(
    db: AsyncSession,
    *,
    source: str,
    thread_id: str,
    role: str,
    content: str,
) -> None:
    """Stage one COMPLETED chat message into the ``chat_memory`` projection.

    Deliberately synchronous and commit-free: it only ``db.add``s the row, so
    it joins the caller's in-flight transaction — the source message and its
    projection land (or roll back) atomically, and there is no window where
    the FTS index disagrees with the thread. The ``chat_memory_fts`` sync is
    the migration-0018 triggers' job, firing on this INSERT.

    Callers pass only ``done`` messages with non-empty content (a pending
    assistant row is empty; an errored one is an apology string — neither is
    institutional knowledge worth recalling). The empty-content guard here is
    a backstop so a stray call can never index a blank row.
    """
    if not content:
        return
    db.add(ChatMemory(source=source, thread_id=thread_id, role=role, content=content))


async def delete_thread(db: AsyncSession, thread_id: str) -> None:
    """Delete a thread's projection rows (commit-free — joins the caller's txn).

    Called from the investigation/hunt delete paths inside THEIR transaction,
    so the source rows and the projection disappear together (the FTS index
    follows via the 0018 delete trigger). ``thread_id`` is a ULID — unique
    across both sources, so no source qualifier is needed.
    """
    from sqlalchemy import delete as sa_delete  # noqa: PLC0415 - lazy: delete-path only

    await db.execute(sa_delete(ChatMemory).where(ChatMemory.thread_id == thread_id))


# ── Retrieval ─────────────────────────────────────────────────────────────────


def _fts_match_expr(query_terms: list[str]) -> str:
    """Build a SAFE FTS5 MATCH expression from caller-supplied query terms.

    Mirrors :func:`soc_ai.store.runbooks._fts_match_expr`'s injection-proofing:
    every emitted token is ``[a-z0-9]+`` (extracted, lowercased), then quoted —
    no user-controlled quote/paren/operator can reach the FTS parser. Terms are
    OR'd (recall over precision; BM25 handles precision).

    Differences from the runbooks helper, both deliberate:

    - a term that tokenizes to MULTIPLE tokens (an IP, a dotted hostname)
      becomes one quoted phrase (``"10 0 0 1"``) — adjacency is what makes an
      IP selective once the tokenizer strips the dots;
    - single-token terms shorter than 2 chars are dropped (pure noise), but
      short tokens INSIDE a phrase are kept (an IP's octets);
    - no trailing prefix-``*``: terms come from structured alert fields, not a
      human mid-keystroke.

    Returns ``""`` when nothing usable survives — callers treat that as
    "no query, no snippets".
    """
    phrases: list[str] = []
    for term in query_terms:
        tokens = _TOKEN_RE.findall(term.lower())
        if not tokens:
            continue
        if len(tokens) == 1:
            if len(tokens[0]) < 2:
                continue
            phrases.append(f'"{tokens[0]}"')
        else:
            phrases.append('"' + " ".join(tokens) + '"')
    return " OR ".join(phrases)


def _snippet(content: str, *, max_chars: int = _SNIPPET_CHARS) -> str:
    """Collapse + truncate message content into a compact single-line snippet.

    Mirrors the E4.2 rationale digest: whitespace (incl. newlines) collapses to
    single spaces so one snippet is one prompt line; over-long text is cut at
    the last WORD BOUNDARY at or before ``max_chars`` and marked with an
    ellipsis (a mid-word fragment reads like corruption). Falls back to a hard
    cut only when the boundary would discard more than half the budget (one
    enormous unbroken token, e.g. a pasted base64 blob).
    """
    collapsed = " ".join(content.split())
    if len(collapsed) <= max_chars:
        return collapsed
    cut = collapsed.rfind(" ", 0, max_chars + 1)
    if cut < max_chars // 2:
        cut = max_chars
    return collapsed[:cut].rstrip() + "…"


async def relevant_chat_snippets(
    db: AsyncSession,
    *,
    query_terms: list[str],
    exclude_thread: str | None,
    window_days: int,
    limit: int,
) -> list[dict[str, Any]]:
    """The most relevant past-chat snippets for a set of alert-derived terms.

    Two passes, mirroring :mod:`soc_ai.store.runbooks`' FTS path:

    1. BM25 over ``chat_memory_fts`` (candidates bounded at ``_FTS_CANDIDATES``)
       with the injection-proof MATCH from :func:`_fts_match_expr`;
    2. an ORM filter over the projection — ``created_at`` inside
       ``window_days``, minus ``exclude_thread`` (the caller's own thread must
       never echo back into its own prompt), minus empties — then best-score
       order, cut to ``limit`` (hard-capped at ``_MAX_SNIPPETS``).

    **FTS5-less SQLite / pre-0018 DB:** the MATCH raises ``OperationalError``
    ("no such module/table") — roll back so the session stays usable and
    return ``[]``. Chat memory is advisory context; unlike runbook search
    there is no legacy scorer worth maintaining for it.

    Returns light digests, best first::

        {source, thread_id, role,
         snippet (content collapsed + word-boundary-truncated ~240),
         created_at, score}
    """
    if limit <= 0 or not query_terms:
        return []
    match = _fts_match_expr(query_terms)
    if not match:
        return []
    try:
        rows = await db.execute(text(_FTS_SQL), {"match": match, "candidates": _FTS_CANDIDATES})
    except OperationalError:
        # "no such table: chat_memory_fts" / "no such module: fts5" — this
        # install has no chat index; memory just contributes nothing.
        await db.rollback()
        return []
    scores = {int(rid): float(score) for rid, score in rows.all()}
    if not scores:
        return []

    cutoff = utcnow() - timedelta(days=window_days)
    q = select(ChatMemory).where(
        ChatMemory.id.in_(scores),
        ChatMemory.created_at >= cutoff,
        ChatMemory.content != "",
    )
    if exclude_thread is not None:
        q = q.where(ChatMemory.thread_id != exclude_thread)
    kept = list((await db.scalars(q)).all())
    kept.sort(key=lambda m: (-scores[m.id], -m.id))  # best BM25 first; newest tiebreak
    return [
        {
            "source": m.source,
            "thread_id": m.thread_id,
            "role": m.role,
            "snippet": _snippet(m.content),
            "created_at": m.created_at,
            "score": scores[m.id],
        }
        for m in kept[: min(limit, _MAX_SNIPPETS)]
    ]
