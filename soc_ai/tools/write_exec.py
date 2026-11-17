"""Write-tool execution primitive shared by the HTTP layer and the agent.

:func:`execute_write_tool` is the single audited path through which ANY
SO-mutating tool runs — the web UI's direct actions (ack-group /
escalate-group / apply-recommended-action) and the orchestrator's opt-in
auto-ack all call it. It lives here — below both the api and agent
packages — so the agent never has to import the HTTP layer to write an ack.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any, Final

from soc_ai.audit.logger import AuditWriteError
from soc_ai.config import Settings
from soc_ai.errors import SoApiError
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.tools._registry import get_tool

if TYPE_CHECKING:
    from soc_ai.audit.logger import AuditLogger

# The tools a report may recommend, and the only names the execute route takes
# from a recommended action.
WRITE_TOOLS = frozenset({"ack_alert", "escalate_to_case", "add_case_comment"})

# The write the execute route makes for a promoted hunt finding: a case built
# from the stored finding (soc_ai.tools.escalate_to_case.open_finding_case).
# Deliberately NOT in WRITE_TOOLS. That set is what a recommended action may
# name, and every argument of this tool is a write target (the alerts to
# attach) that must come from the stored finding. A report or a chat proposal
# that names this tool is refused as "not a write" before any argument is read.
FINDING_CASE_TOOL: Final = "open_finding_case"

# The write of "Open one case" on a campaign: one case built from the stored
# campaign (soc_ai.tools.escalate_to_case.open_campaign_case). Not in
# WRITE_TOOLS for the same reason as FINDING_CASE_TOOL: the alerts it attaches
# are a write target that must come from the store.
CAMPAIGN_CASE_TOOL: Final = "open_campaign_case"

# Everything execute_write_tool will run.
_EXECUTABLE_TOOLS = WRITE_TOOLS | {FINDING_CASE_TOOL, CAMPAIGN_CASE_TOOL}


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
    Refuses anything outside :data:`WRITE_TOOLS`, :data:`FINDING_CASE_TOOL`
    and :data:`CAMPAIGN_CASE_TOOL`.

    Audit/fail-closed: when ``audit`` is provided, a *mutating* audit record is
    written BEFORE the SO call (the intent), so under ``audit_fail_closed`` a
    failed audit write aborts the mutation — the SO state change never runs
    without an audit record. The audit failure surfaces as the ``error`` string
    (the SO write is not attempted). A second audit record captures the result.
    """
    if tool_name not in _EXECUTABLE_TOOLS:
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
    except Exception as e:
        # Everything else the tool can throw is still a tool failure the caller
        # must see as ``error``: an SO that is unreachable (httpx transport
        # errors are not SoApiError — the client never got a response to wrap)
        # and model-authored arguments of the wrong type (``case_title: null``
        # reaches ``.strip()`` as AttributeError). The endpoint renders the
        # string; a raise here would turn the analyst's Execute into a bare 500
        # and abort an unattended ack batch on its first failure.
        return (
            None,
            f"tool invocation failed: {type(e).__name__}: {e}; dropped_args={sorted(dropped)}",
        )

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


__all__ = ["CAMPAIGN_CASE_TOOL", "FINDING_CASE_TOOL", "WRITE_TOOLS", "execute_write_tool"]
