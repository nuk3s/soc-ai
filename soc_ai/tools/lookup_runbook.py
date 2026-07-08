"""``lookup_runbook`` tool - tiered search over operator runbooks.

The operator authors runbooks (procedures / notes / "what normal looks like on
*this* network") in the Runbooks config panel; they persist in the local store
(:mod:`soc_ai.store.runbooks`). This tool searches them so an investigation can
cite the org's *own* guidance instead of hallucinating a false-positive from
thin data. Ranking is FTS5-first (rule-link > BM25 with tag ≫ title > content
weights; the legacy token scorer on an FTS5-less SQLite) — robust and fully
air-gapped by default. An OPT-IN semantic tier (gateway embeddings + rerank,
E4.1) joins in only when the orchestrator passes ``settings`` with
``rag_embed_model`` configured; it degrades fail-soft to the local ranking.

The tool needs a DB session but is a ``@tool_plain`` with no ``RunContext``, so
the orchestrator wrapper injects the app's ``db_sessionmaker`` (threaded through
:class:`~soc_ai.agent.orchestrator.InvestigationContext`). When no sessionmaker
is available (CLI / eval / tests with no DB), it returns ``[]`` — the agent then
falls back to ``query_cases`` / ``get_playbooks`` exactly as before.

The function's LLM-facing signature is fixed at ``(query, k)`` so the agent's
tool surface is stable. Return shape is fixed too: a list of
``{"id", "title", "content", "score", "source": "operator_runbook"}``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from soc_ai.tools._registry import tool

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from soc_ai.config import Settings


@tool(
    read_only=True,
    description="Search the operator's own runbooks (keyword/tag/rule-linked).",
)
async def lookup_runbook(
    query: str,
    k: int = 5,
    *,
    db_sessionmaker: async_sessionmaker[AsyncSession] | None = None,
    rule_name: str | None = None,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    """Return up to ``k`` operator runbooks matching ``query``.

    Args:
        query: natural-language description of the situation (may include the
            detection rule name — keyword/tag overlap will pick it up).
        k: maximum number of runbooks to return.
        db_sessionmaker: injected by the orchestrator wrapper; the store session
            factory. ``None`` (CLI / eval / no DB) yields ``[]``.
        rule_name: optional exact rule to prefer via ``linked_rules`` (strongest
            signal). Not part of the LLM-facing signature; the orchestrator may
            pass the alert's rule when known.
        settings: injected by the orchestrator wrapper (never LLM-facing);
            enables the opt-in semantic tier when ``rag_embed_model`` is set.
            ``None`` keeps retrieval 100% local.

    Returns:
        A list of ``{"id", "title", "content", "score", "source"}`` entries,
        best match first. Empty when nothing matches or no DB is available.
    """
    if k <= 0:
        raise ValueError(f"k must be positive, got {k}")
    if db_sessionmaker is None:
        return []

    from soc_ai.store import runbooks as runbooks_svc  # noqa: PLC0415 - avoid import cycle

    async with db_sessionmaker() as db:
        return await runbooks_svc.search(db, query, k=k, rule_name=rule_name, settings=settings)
