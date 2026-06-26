"""Shared approval logic extracted from /approve for reuse by the web UI.

The core gate.get → gate.decide → gate.consume → tool-execution sequence
lives here so that both the JSON API endpoint and the htmx approval form can
call the same code path without duplicating the filtering/infra-injection logic.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, status

from soc_ai.api.schemas import ApproveResponse
from soc_ai.audit.logger import AuditWriteError
from soc_ai.config import Settings
from soc_ai.errors import ApprovalRejected, ApprovalRequired, SoApiError
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.tools._registry import ApprovalGate, get_tool

if TYPE_CHECKING:
    from soc_ai.audit.logger import AuditLogger

# The only tools that may ever be executed via an approval / direct action.
WRITE_TOOLS = frozenset({"ack_alert", "escalate_to_case", "add_case_comment"})


async def execute_write_tool(
    tool_name: str,
    tool_args: dict[str, Any],
    *,
    auth: SoAuthClient,
    settings: Settings,
    audit: AuditLogger | None = None,
    session_id: str = "write-tool",
    user: str = "unknown",
) -> tuple[Any, str | None]:
    """Execute one write tool against Security Onion.

    Filters ``tool_args`` to the tool's real signature (models invent extra
    kwargs), injects ``auth``/``settings`` when declared, and returns
    ``(result, error)`` — ``error`` is a string on a tool failure, never a raise.
    Refuses anything outside :data:`WRITE_TOOLS`.

    Audit/fail-closed: when ``audit`` is provided, a *mutating* audit record is
    written BEFORE the SO call (the intent), so under ``audit_fail_closed`` a
    failed audit write aborts the mutation — the SO state change never runs
    without an audit record. The audit failure surfaces as the ``error`` string
    (the SO write is not attempted). A second audit record captures the result.
    """
    if tool_name not in WRITE_TOOLS:
        return None, f"not an executable write tool: {tool_name!r}"

    # The approver/executor identity resolved by the endpoint (identify_caller):
    # a token or username, or the literal "anonymous" when no auth is present.
    # Recorded as the structured ``approved_by`` so an SO write is always
    # attributable. Normalize the bare "unknown" default to "anonymous" so an
    # executed write is never attributed to the missing-field sentinel.
    approver = user if user != "unknown" else "anonymous"

    if audit is not None:
        try:
            await audit.log_kind(
                session_id,
                "tool_call",
                {"tool": tool_name, "args": tool_args, "phase": "intent"},
                user=user,
                approved_by=approver,
                mutating=True,
            )
        except AuditWriteError as e:
            # Fail-closed: do NOT touch Security Onion without an audit record.
            return None, f"aborted: {e}"

    spec = get_tool(tool_name)
    sig = inspect.signature(spec.func)
    allowed = {
        name
        for name, param in sig.parameters.items()
        if param.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    }
    filtered_args = {k: v for k, v in tool_args.items() if k in allowed}
    dropped = set(tool_args) - set(filtered_args)

    infra_kwargs: dict[str, Any] = {}
    if "auth" in sig.parameters:
        infra_kwargs["auth"] = auth
    if "settings" in sig.parameters:
        infra_kwargs["settings"] = settings

    try:
        result = await spec.func(**filtered_args, **infra_kwargs)
    except SoApiError as e:
        return None, (f"{e}; dropped_args={sorted(dropped)}" if dropped else str(e))
    except (TypeError, ValueError) as e:
        return None, f"tool invocation failed: {e}; dropped_args={sorted(dropped)}"

    if audit is not None:
        # Result record is best-effort (fail-open): the SO state change already
        # happened and the intent record above already proved auditability.
        await audit.log_kind(
            session_id,
            "tool_result",
            {"tool": tool_name, "args": filtered_args, "phase": "result", "ok": True},
            user=user,
            approved_by=approver,
            mutating=False,
        )
    return result, None


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
