"""``get_rule_content`` — fetch a detection's full rule text by SID or title.

``query_detections`` returns rule *metadata* (title/publicId/severity); this
tool returns the rule *body* (``so_detection.content``) — what the signature
actually matches: content strings, ports, dsize, PCRE. Reading the rule text
is the antidote to label anchoring: a rule NAMED "ET MALWARE <family>" that
merely matches a short generic byte pattern is weak corroboration, while a
tight match on a family-specific token is strong.

Live SO 3.x nests detection fields under ``so_detection.*``; older/flat docs
keep them top-level. Both shapes are searched and parsed.
"""

from __future__ import annotations

from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools._registry import tool

_MAX_CONTENT_CHARS = 6_000
_MAX_DESCRIPTION_CHARS = 1_000


def _clamped(text: Any, limit: int) -> tuple[str | None, bool]:
    if not isinstance(text, str) or not text:
        return None, False
    if len(text) <= limit:
        return text, False
    return text[:limit], True


@tool(
    read_only=True,
    description="Fetch a detection rule's full text (content) by SID/publicId or exact title.",
)
async def get_rule_content(
    rule_id: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
) -> dict[str, Any]:
    """Return the rule body + metadata for ONE detection.

    Args:
        rule_id: the Suricata SID / detection ``publicId`` (e.g. ``"2054989"``,
            usually the alert's ``rule.uuid``) or the exact rule title
            (``rule.name``).
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``detections_index_pattern``).

    Returns:
        ``{"found": True, "content": <rule text>, ...metadata}`` or
        ``{"found": False, "rule_id": ..., "hint": ...}``.
    """
    if not rule_id or not rule_id.strip():
        raise ValueError("rule_id must be a non-empty SID/publicId or rule title")
    rule_id = rule_id.strip()

    # One bool/should across both doc shapes and both identifier kinds. The
    # SO 3.x nested fields are keyword-mapped (exact-value `term`); the flat
    # legacy shape gets match/match_phrase. A numeric SID won't match any
    # title and a title won't match any publicId, so the extra clauses are
    # harmless. `so-detection*` also matches so-detectionhistory (every past
    # revision of a rule) — sorting newest-first makes the current revision
    # win regardless of which index a hit came from.
    query: dict[str, Any] = {
        "bool": {
            "should": [
                {"term": {"so_detection.publicId": rule_id}},
                {"match": {"publicId": rule_id}},
                {"term": {"so_detection.title": rule_id}},
                {"match_phrase": {"title": rule_id}},
            ],
            "minimum_should_match": 1,
        }
    }
    result = await elastic.search(
        settings.detections_index_pattern,
        query,
        size=5,
        sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    )
    if not result.hits:
        return {
            "found": False,
            "rule_id": rule_id,
            "hint": (
                "no detection matched this publicId/SID or exact title — check the "
                "alert's rule.uuid, or free-text search with t_query_detections"
            ),
        }

    source: dict[str, Any] = result.hits[0].get("_source", {})
    det = source.get("so_detection")
    if not isinstance(det, dict):
        det = source

    content, content_truncated = _clamped(det.get("content"), _MAX_CONTENT_CHARS)
    description, _ = _clamped(det.get("description"), _MAX_DESCRIPTION_CHARS)

    out: dict[str, Any] = {
        "found": True,
        "matches": len(result.hits),
        "public_id": det.get("publicId"),
        "title": det.get("title"),
        "severity": det.get("severity"),
        "engine": det.get("engine"),
        "language": det.get("language"),
        "ruleset": det.get("ruleset"),
        "category": det.get("category"),
        "is_enabled": det.get("isEnabled"),
        "author": det.get("author"),
        "tags": list(det.get("tags") or []),
        "description": description,
        "content": content,
        "content_truncated": content_truncated,
    }
    if len(result.hits) > 1:
        out["note"] = f"{len(result.hits)} detections matched; returning the best-ranked one"
    return out
