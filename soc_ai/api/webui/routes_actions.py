"""Verdict/action mutations: approve, execute-action, resolve, override."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.approvals import WRITE_TOOLS, apply_approval, execute_write_tool
from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui import _timeline
from soc_ai.api.webui._shared import (
    router,
)
from soc_ai.api.webui._timeline import (
    _ACTION_TITLE,
    _executed_actions,
)
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import chat as chat_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Investigation

_LOGGER = logging.getLogger(__name__)


class ApproveIn(BaseModel):
    token: str
    approved: bool
    reason: str | None = None


@router.post("/approve")
async def approve(request: Request, body: ApproveIn) -> dict[str, Any]:
    """Apply an analyst decision to a pending write-tool approval."""
    result = await apply_approval(
        gate=request.app.state.gate,
        auth=request.app.state.auth,
        settings=request.app.state.settings,
        token=body.token,
        approved=body.approved,
        reason=body.reason,
        audit=request.app.state.audit,
        user=await identify_caller(request),
    )
    return result.model_dump()


# ── Advisory action execution ──────────────────────────────────────────────
# Synth-first investigations recommend write actions in the report rather than
# pausing the agent on an approval gate, so the analyst executes them on demand
# from the report. These run through the *same* execute_write_tool path as the
# gate, restricted to the three write tools, with the alert id defaulted from
# the investigation when the model left it off.


class ExecuteActionResult(BaseModel):
    status: str  # "executed" | "error"
    title: str
    detail: str = ""
    error: str | None = None


def _action_detail(tool_name: str, result: Any) -> str:
    """One-line, analyst-facing confirmation of what the write tool did."""
    if not isinstance(result, dict):
        return ""
    if tool_name == "ack_alert":
        return "Alert acknowledged in Security Onion."
    if tool_name == "escalate_to_case":
        case_id = result.get("id") or result.get("caseId") or result.get("case_id") or ""
        return f"Case created: {case_id}" if case_id else "Case created in Security Onion."
    if tool_name == "add_case_comment":
        case_id = result.get("case_id") or ""
        return f"Comment added to case {case_id}." if case_id else "Comment added to case."
    return ""


async def _persist_action_executed(
    request: Request,
    inv_real_id: str,
    sequence: int,
    payload: dict[str, Any],
) -> None:
    """Durably record an advisory-action execution as an investigation event.

    FR-030: without this a reload re-offered an already-executed escalate
    (duplicate SO cases). ``_build_actions`` reads the event back to mark the
    card applied. Best-effort: the write already happened in SO, so a failed
    bookkeeping insert must not turn the response into an error.
    """
    try:
        async with request.app.state.db_sessionmaker() as db:
            await inv_svc.append_events(
                db,
                inv_real_id,
                [{"sequence": sequence, "kind": "action_executed", "payload": payload}],
            )
    except Exception:
        _LOGGER.warning(
            "failed to persist action_executed event for %s (action still executed)",
            inv_real_id,
            exc_info=True,
        )


@router.post(
    "/investigations/{inv_id}/actions/{index}/execute",
    response_model=ExecuteActionResult,
)
async def execute_action(
    request: Request,
    inv_id: str,
    index: int,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> ExecuteActionResult:
    """Execute one report-recommended write action against Security Onion.

    ``index`` is the position in ``report.recommended_actions`` (the SPA's
    advisory action cards are built in that order). Token-gated approvals use
    ``/approve`` instead; this path is for the advisory recommendations.

    Idempotent: a previously executed action (persisted ``action_executed``
    event) or an ack of an already-acked alert returns ok-with-note instead of
    writing again — no duplicate SO cases, no double acks.
    """
    async with request.app.state.db_sessionmaker() as db:
        got = await inv_svc.get_with_events(db, inv_id)
        if got is None:
            by_alert = await inv_svc.latest_for_alerts(db, [inv_id])
            inv0 = by_alert.get(inv_id)
            if inv0 is not None:
                got = await inv_svc.get_with_events(db, inv0.id)
        if got is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        inv, events = got
        report = inv.report or {}
        alert_es_id = inv.alert_es_id
        inv_real_id = inv.id
        next_seq = max((e.sequence for e in events), default=0) + 1

    recs = report.get("recommended_actions") or []
    if index < 0 or index >= len(recs):
        raise HTTPException(status_code=404, detail={"reason": "no_such_action"})

    rec = recs[index]
    tool_name = rec.get("tool_name", "")
    title = _ACTION_TITLE.get(tool_name, tool_name or "Action")
    if tool_name not in WRITE_TOOLS:
        raise HTTPException(
            status_code=400,
            detail={"reason": "not_executable", "tool": tool_name},
        )

    # Already executed through this endpoint? Never write twice (the escalate
    # case would open a duplicate SO case) — confirm instead.
    if index in _executed_actions(events):
        return ExecuteActionResult(
            status="executed",
            title=title,
            detail="Already executed — not repeated.",
        )

    tool_args = dict(rec.get("tool_args") or {})
    # The model usually fills alert_id, but default it from the investigation's
    # own alert when missing so an ack/escalate never silently targets nothing.
    if tool_name in ("ack_alert", "escalate_to_case") and not tool_args.get("alert_id"):
        if not alert_es_id:
            raise HTTPException(
                status_code=400,
                detail={"reason": "missing_alert_id", "tool": tool_name},
            )
        tool_args["alert_id"] = alert_es_id

    user = await identify_caller(request)

    # Acking an alert that is ALREADY acked in SO (group-ack, auto-ack of
    # another run, the SO web UI): ok-with-note, and persist the execution so
    # the card reads applied from now on. ES-error fallback inside the helper
    # means a probe failure just runs the (harmless, idempotent) ack as before.
    if tool_name == "ack_alert" and await _timeline._alert_currently_acked(
        elastic, settings, tool_args.get("alert_id") or alert_es_id
    ):
        await _persist_action_executed(
            request,
            inv_real_id,
            next_seq,
            {
                "index": index,
                "tool_name": tool_name,
                "title": title,
                "success": True,
                "by": user,
                "note": "already_acknowledged",
            },
        )
        return ExecuteActionResult(
            status="executed",
            title=title,
            detail="Alert was already acknowledged in Security Onion.",
        )

    result, error = await execute_write_tool(
        tool_name,
        tool_args,
        auth=request.app.state.auth,
        settings=request.app.state.settings,
        audit=request.app.state.audit,
        session_id=f"action:{inv_id}",
        user=user,
    )
    if error is not None:
        return ExecuteActionResult(status="error", title=title, error=error)
    detail = _action_detail(tool_name, result)
    await _persist_action_executed(
        request,
        inv_real_id,
        next_seq,
        {
            "index": index,
            "tool_name": tool_name,
            "title": title,
            "success": True,
            "by": user,
            "detail": detail,
        },
    )
    return ExecuteActionResult(status="executed", title=title, detail=detail)


# ── Chat verdict resolution ────────────────────────────────────────────────


class ResolveIn(BaseModel):
    message_id: int
    token: str


@router.post("/investigations/{inv_id}/resolve")
async def resolve_investigation(request: Request, inv_id: str, body: ResolveIn) -> dict[str, Any]:
    """Apply a validated chat verdict proposal. Token + message gated, idempotent."""
    # Not owner-scoped: any authenticated caller may apply a proposal, consistent
    # with /approve and the action-execute route. The actor is recorded for audit.
    resolved_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        msg = await chat_svc.get_message(db, body.message_id)
        if msg is None or msg.investigation_id != inv_id:
            raise HTTPException(status_code=404, detail={"reason": "proposal_not_found"})
        meta = msg.meta or {}
        if meta.get("kind") != "verdict_proposal" or meta.get("validation") != "pass":
            raise HTTPException(status_code=400, detail={"reason": "not_applyable"})
        if meta.get("token") != body.token:
            raise HTTPException(status_code=403, detail={"reason": "bad_token"})
        if meta.get("applied"):
            raise HTTPException(status_code=409, detail={"reason": "already_applied"})
        proposal = meta.get("proposal") or {}
        verdict = proposal.get("verdict")
        if not verdict:
            raise HTTPException(status_code=400, detail={"reason": "malformed_proposal"})
        updated = await inv_svc.resolve(
            db,
            inv_id,
            verdict=verdict,
            confidence=proposal.get("confidence"),
            rationale=proposal.get("rationale"),
            recommended_actions=proposal.get("recommended_actions"),
            resolved_by=resolved_by,
            source_message_id=body.message_id,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
    return {"ok": True, "verdict": verdict}


# ── Manual verdict override ────────────────────────────────────────────────

_VALID_VERDICTS = {"true_positive", "false_positive", "needs_more_info"}


class OverrideVerdictIn(BaseModel):
    verdict: str
    rationale: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


@router.post("/investigations/{inv_id}/override")
async def override_verdict(
    request: Request, inv_id: str, body: OverrideVerdictIn
) -> dict[str, Any]:
    """Manually override a completed investigation's verdict with analyst provenance."""
    if body.verdict not in _VALID_VERDICTS:
        raise HTTPException(
            status_code=400,
            detail={"reason": "invalid_verdict", "valid": sorted(_VALID_VERDICTS)},
        )
    resolved_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if inv.status == "running":
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "investigation_running",
                    "hint": "Wait for the investigation to complete before overriding.",
                },
            )
        updated = await inv_svc.resolve(
            db,
            inv_id,
            verdict=body.verdict,
            confidence=body.confidence if body.confidence is not None else 1.0,
            rationale=body.rationale,
            recommended_actions=None,
            resolved_by=resolved_by,
            resolved_via="manual",
            source_message_id=None,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
    return {"ok": True, "verdict": body.verdict, "confidence": updated.confidence}
