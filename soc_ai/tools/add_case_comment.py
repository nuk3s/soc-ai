"""``add_case_comment`` write tool - append a comment to an existing case.

Routes via ``POST /connect/case/{id}/comment`` with the comment body.
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
# ES ``_id``). Unlike ack_alert / escalate_to_case (which carry ids in the JSON
# body), this id is interpolated into the request PATH, so a hallucinated or
# hostile value containing ``/``, ``?``, ``#`` or ``..`` could re-route the
# authenticated POST to another SO endpoint. Validate the shape before use.
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@tool(read_only=False, description="Append a comment to an existing SOC case.")
async def add_case_comment(
    case_id: str,
    comment: str,
    *,
    auth: SoAuthClient,
) -> dict[str, Any]:
    """POST /connect/case/{case_id}/comment with the supplied comment text."""
    if not _CASE_ID_RE.match(case_id):
        raise ValueError(
            f"invalid case_id {case_id!r}: expected a SOC case id matching "
            r"[A-Za-z0-9_-]+ (it is interpolated into the request path)"
        )
    if not comment.strip():
        raise ValueError("comment must not be empty")

    resp = await auth.request(
        "POST",
        f"/connect/case/{case_id}/comment",
        json={"description": comment.strip()},
    )
    if resp.status_code >= httpx.codes.BAD_REQUEST:
        raise SoApiError(
            f"add_case_comment returned {resp.status_code}: {resp.text[:200]}",
            status_code=resp.status_code,
            url=f"/connect/case/{case_id}/comment",
        )
    try:
        return dict(resp.json())
    except ValueError:
        return {"case_id": case_id, "added": True}
