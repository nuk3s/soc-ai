"""``add_case_comment`` write tool - append a comment to an existing case.

Routes via ``POST /api/case/comments`` with ``{"caseId": ..., "description": ...}``.

v1 posted to ``/connect/case/{id}/comment``, which is wrong twice over: SO 3.x
takes the case id in the BODY, not the path, and ``/connect/*`` is an nginx
alias for ``/api/*`` that only exists on a grid carrying the licensed ``api``
feature. Measured against a live SO 3.2.0 grid on 2026-09-06:
``POST /connect/case/{id}/comment`` -> 404 (nginx), ``POST /api/case/{id}/comment``
-> 404 (no such route), ``POST /api/case/comments`` -> 200 with the stored
comment document.

Approval-gated.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from soc_ai.errors import SoApiError
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.tools._registry import tool

# SOC/ES case ids are URL-safe doc-id tokens (e.g. ``case-001`` or a 20-char
# ES ``_id``). The id now travels in the body rather than the request path, so
# this is no longer a re-routing guard; it is still worth keeping, because a
# hallucinated id turns into an opaque SO 500 and this turns it into a clear
# ValueError before any write goes out.
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")

_COMMENT_URL = "/api/case/comments"


@tool(read_only=False, description="Append a comment to an existing SOC case.")
async def add_case_comment(
    case_id: str,
    comment: str,
    *,
    auth: SoAuthClient,
) -> dict[str, Any]:
    """POST /api/case/comments with the case id and the supplied comment text."""
    if not _CASE_ID_RE.match(case_id):
        raise ValueError(
            f"invalid case_id {case_id!r}: expected a SOC case id matching [A-Za-z0-9_-]+"
        )
    if not comment.strip():
        raise ValueError("comment must not be empty")

    resp = await auth.request(
        "POST",
        _COMMENT_URL,
        json={"caseId": case_id, "description": comment.strip()},
    )
    if resp.status_code >= httpx.codes.BAD_REQUEST:
        raise SoApiError(
            f"add_case_comment returned {resp.status_code}: {resp.text[:200]}",
            status_code=resp.status_code,
            url=_COMMENT_URL,
        )
    try:
        return dict(resp.json())
    except ValueError:
        return {"case_id": case_id, "added": True}
