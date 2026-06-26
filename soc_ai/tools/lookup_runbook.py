"""``lookup_runbook`` tool - semantic search over indexed runbooks.

**STUB for v1.** The real implementation lands in v1.1 using
Qwen3-Embedding-8B (alias ``soc-ai-embed``) over a Qdrant dense index built
from the operator's runbook collection. v1 ships the interface so the agent
prompt can reference the tool without surprising it with a runtime error -
the agent learns to fall back to ``query_cases`` / ``get_playbooks`` when the
runbook search returns nothing.

The function signature is fixed: changing it in v1.1 would break the agent's
expected tool surface.
"""

from __future__ import annotations

from typing import Any

from soc_ai.tools._registry import tool


@tool(
    read_only=True,
    description="Semantic search over indexed runbooks (v1: stub returns []).",
)
async def lookup_runbook(query: str, k: int = 5) -> list[dict[str, Any]]:
    """Return up to ``k`` runbook fragments matching ``query`` semantically.

    Args:
        query: natural-language description of the situation.
        k: maximum number of fragments to return.

    Returns:
        v1: always an empty list. v1.1 will return entries shaped like
        ``{"id": ..., "title": ..., "content": ..., "score": float, "source": ...}``.
    """
    if k <= 0:
        raise ValueError(f"k must be positive, got {k}")
    _ = query  # silence "unused" - retained for v1.1 signature compatibility
    return []
