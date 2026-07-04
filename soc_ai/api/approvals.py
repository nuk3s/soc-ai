"""Shared approval logic extracted from /approve for reuse by the web UI.

The core gate.get → gate.decide → gate.consume → tool-execution sequence
lives here so that both the JSON API endpoint and the htmx approval form can
call the same code path without duplicating the filtering/infra-injection logic.

The tool-execution primitive itself (``execute_write_tool`` + ``WRITE_TOOLS``)
lives in the neutral :mod:`soc_ai.tools.write_exec` — below both the api and
agent packages — and is re-exported here for compatibility with existing
callers and tests.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException, status

from soc_ai.api.schemas import ApproveResponse
from soc_ai.config import Settings
from soc_ai.errors import ApprovalRejected, ApprovalRequired
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.tools._registry import ApprovalGate
from soc_ai.tools.write_exec import WRITE_TOOLS, execute_write_tool

if TYPE_CHECKING:
    from soc_ai.audit.logger import AuditLogger

__all__ = ["WRITE_TOOLS", "apply_approval", "execute_write_tool"]


async def apply_approval(
    *,
    gate: ApprovalGate,
    auth: SoAuthClient,
    settings: Settings,
    token: str,
    approved: bool,
    reason: str | None = None,
    audit: AuditLogger | None = None,
    user: str = "unknown",
) -> ApproveResponse:
    """Apply the user's decision to a pending write-tool approval.

    Raises HTTPException(404) if the token is unknown, HTTPException(409) if
    the approval state is inconsistent.  Mirrors the exact behaviour of the
    original ``approve_endpoint`` body so existing tests pass unchanged.

    When ``audit`` is provided, the executed write is audited fail-closed (see
    :func:`execute_write_tool`); a failed audit under ``audit_fail_closed``
    surfaces as ``ApproveResponse(status="executed", error=...)`` and the SO
    state change does not run.
    """
    pending = await gate.get(token)
    if pending is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown approval token: {token}",
        )

    try:
        await gate.decide(token, approved=approved, reason=reason)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    if not approved:
        return ApproveResponse(status="rejected")

    try:
        consumed = await gate.consume(token)
    except ApprovalRejected as e:
        # Already consumed (idempotent): tell the caller cleanly.
        return ApproveResponse(status="already_decided", error=str(e))
    except ApprovalRequired:
        # Should not happen since we just decided approved; surface defensively.
        raise HTTPException(status_code=409, detail="approval state inconsistent") from None

    result, error = await execute_write_tool(
        consumed.tool_name,
        consumed.tool_args,
        auth=auth,
        settings=settings,
        audit=audit,
        session_id=getattr(consumed, "session_id", None) or "approval",
        user=user,
    )
    if error is not None:
        return ApproveResponse(status="executed", error=error)
    return ApproveResponse(status="executed", result=result)
