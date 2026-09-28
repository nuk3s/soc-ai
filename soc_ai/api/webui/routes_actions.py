"""Verdict/action mutations: execute-action, resolve, override."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from weakref import WeakValueDictionary

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui import _timeline
from soc_ai.api.webui._shared import (
    router,
)
from soc_ai.api.webui._timeline import (
    _ACTION_TITLE,
    _action_identity,
    _executed_actions,
)
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import chat as chat_svc
from soc_ai.store import escalations as esc_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Investigation
from soc_ai.tools.write_exec import WRITE_TOOLS, execute_write_tool
from soc_ai.webui import alerts_query as aq

_LOGGER = logging.getLogger(__name__)

# Window for the group-scoped ack below. The drawer doesn't know which time
# window the Alerts screen is showing, so use a generous fixed one — wide
# enough to cover any realistic queue view, still bounded by _ACK_CAP.
_GROUP_ACK_RANGE = "7d"


# ── Advisory action execution ──────────────────────────────────────────────
# Synth-first investigations recommend write actions in the report rather than
# pausing the agent mid-run, so the analyst executes them on demand from the
# report. These run through the single audited execute_write_tool path,
# restricted to the three write tools, with the alert id defaulted from
# the investigation when the model left it off.


class ExecuteActionResult(BaseModel):
    status: str  # "executed" | "error"
    title: str
    detail: str = ""
    error: str | None = None


def _case_id_from_result(result: Any) -> str:
    """The SO case id from an ``escalate_to_case`` tool result (id/caseId/case_id)."""
    if not isinstance(result, dict):
        return ""
    return str(result.get("id") or result.get("caseId") or result.get("case_id") or "")


def _observed_case_id(events: list[Any]) -> str | None:
    """The SO case id THIS investigation itself opened, if any.

    Scans persisted successful ``action_executed`` events for an
    ``escalate_to_case`` execution and returns the case id the system observed
    from SO's response (persisted as ``case_id``). This is the ONLY case id an
    ``add_case_comment`` action may target: ``RecommendedAction.tool_args`` is
    fully model-authored and attacker-influenceable, so the model's free-form
    ``case_id`` is never trusted as a write target (F07). Returns the most
    recent one, or ``None`` when this investigation opened no case.
    """
    found: str | None = None
    for e in events:
        if e.kind != "action_executed":
            continue
        p = e.payload or {}
        if not p.get("success") or p.get("tool_name") != "escalate_to_case":
            continue
        cid = p.get("case_id")
        if isinstance(cid, str) and cid:
            found = cid
    return found


def _escalate_outcome(result: Any) -> tuple[bool, str]:
    """``(linked, sentence)`` for an ``escalate_to_case`` result.

    An escalate is three writes and only the first is guaranteed. Creating the
    case always succeeds once Security Onion answers, so reading the outcome off
    that alone reported success for a press that put the alert on nothing: on
    the range, an alert that was no longer on the grid produced a case, an
    accepted attach that attached nothing, and "Case created: ...".

    ``linked`` is the only thing that decides whether an escalate happened, and
    it is what the caller keys the count and the ledger claim on. The three
    outcomes get three different sentences:

    * attached and stamped: the ordinary escalate.
    * attached, not stamped: the alert IS case work, but Security Onion's own
      alert list still shows it untriaged, so somebody will meet it there.
    * not attached: no escalate happened, and an empty case is now sitting in
      the queue under a title that reads like an incident. Name it, because
      only the operator can close or reuse it.
    """
    if not isinstance(result, dict):
        return False, "Security Onion returned no answer to the escalate."
    case_id = _case_id_from_result(result)
    named = f"case {case_id}" if case_id else "the case"
    if not result.get("alert_linked"):
        reason = (
            str(result.get("link_error") or "").strip().rstrip(".")
            or f"{named} exists and the alert is not attached to it"
        )
        return False, (
            f"{reason[0].upper()}{reason[1:]}. soc-ai recorded no escalation. "
            f"Close or reuse {named}."
        )
    created = (
        f"soc-ai created case {case_id}." if case_id else "soc-ai created a Security Onion case."
    )
    if not result.get("marked_escalated"):
        return True, (
            f"{created} The alert is attached to it. Security Onion did not mark the "
            "alert escalated. The alert still reads as untriaged in the alert list."
        )
    return True, f"{created} The alert is attached to it and marked escalated."


def _action_detail(tool_name: str, result: Any) -> str:
    """One-line, analyst-facing confirmation of what the write tool did."""
    if not isinstance(result, dict):
        return ""
    if tool_name == "ack_alert":
        return "Alert acknowledged in Security Onion."
    if tool_name == "escalate_to_case":
        return _escalate_outcome(result)[1]
    if tool_name == "add_case_comment":
        case_id = result.get("case_id") or ""
        return f"Comment added to case {case_id}." if case_id else "Comment added to case."
    return ""


async def _group_ack_result(
    request: Request,
    *,
    rule_name: str,
    settings: Settings,
    elastic: ElasticClient,
    user: str,
) -> tuple[str, int] | None:
    """Group-scoped ack: acknowledge every unacked event of *rule_name*.

    The recommendation card says "Acknowledge alert", but the analyst's intent
    is "this detection is handled" — a single-event ack left the rest of the
    group sitting in the queue after a successful "Executed ✓" (dogfood
    2026-07-15). Same contract as the settled bar / POST /alerts/ack-group.

    Returns ``(detail, acked)`` when the group fetch found unacked events and
    acked them. Returns ``None`` — so the caller falls back to the single-alert
    ack — both when the group fetch FAILED and when it came back EMPTY: an empty
    result is ambiguous (an already-clear Suricata group, OR a wrong-field miss on
    a non-Suricata detection, since ``kind`` is hardcoded ``suricata`` and a Zeek
    notice's name lives in ``notice.note``, not ``rule.name``). The single-alert
    path is dataset-agnostic and idempotent, so it is correct for both (F28).
    """
    from soc_ai.api.webui.routes_alert_actions import _ACK_CAP, _ack_many  # noqa: PLC0415

    try:
        events = await aq.fetch_group_events(
            elastic,
            settings,
            rule_name=rule_name,
            kind="suricata",
            time_range=_GROUP_ACK_RANGE,
            size=_ACK_CAP,
            time_zone=settings.so_timezone,
            hide_acked=True,
        )
    except Exception:
        _LOGGER.warning(
            "group ack: event fetch failed for rule %r — falling back to single-alert ack",
            rule_name,
            exc_info=True,
        )
        return None
    if not events:
        # Ambiguous empty result — do NOT claim group success with acked=0 (that
        # falsely marks a non-Suricata alert handled while it stays unacked in SO,
        # F28). Fall back to the single-alert ack keyed on this investigation's own
        # alert_es_id, which is dataset-agnostic and idempotent.
        return None
    acked, failed = await _ack_many(
        request,
        [ev.es_id for ev in events],
        session_id=f"action-ack-group:{rule_name}",
        caller=user,
    )
    if failed:
        detail = (
            f"Acknowledged {acked} of {acked + failed} alerts in this "
            f"detection group. {failed} failed."
        )
    else:
        detail = f"Acknowledged {acked} alert{'s' if acked != 1 else ''} in this detection group."
    return (detail, acked)


async def _reserve_escalate(
    request: Request,
    elastic: ElasticClient,
    settings: Settings,
    alert_id: str,
    *,
    user: str,
    inv_real_id: str,
    sequence: int,
    receipt: dict[str, Any],
) -> ExecuteActionResult | None:
    """Reserve ``alert_id`` in the escalation ledger BEFORE a case is opened.

    Returns ``None`` when the claim is ours and the caller may write, or the
    answer to give the analyst when it is not.

    This is the half of the duplicate-case guard the single-alert path did not
    have. Its own idempotency is the persisted ``action_executed`` marker, which
    is keyed to one investigation and one action, and the per-``(investigation,
    action)`` lock above, which is process-local. Neither can see a group
    escalate over the same alert running in the same instant, and the group path
    could not see this one either, because nothing reserved the alert until
    after the case was already open. Both presses passed their own check and
    Security Onion ended with two cases pointing at one alert — the same outcome
    the ledger was introduced to stop, reached through the door it did not
    cover.

    :func:`~soc_ai.api.webui.routes_alert_actions._reserve` is reused rather
    than reimplemented for one alert, so both paths answer "is this already on a
    case" from the same three sources in the same order (ledger, then Security
    Onion's case links, then a claim somebody else holds), and a stale claim the
    grid can disprove is released and retaken here exactly as it is there. A
    second reservation policy would be a second set of answers.
    """
    from soc_ai.api.webui.routes_alert_actions import _reserve  # noqa: PLC0415 — circular

    title = str(receipt.get("title") or "")
    reserved = await _reserve(request, elastic, settings, [alert_id], caller=user)
    if alert_id in reserved.claimed:
        return None
    if reserved.unresolved:
        # An earlier escalate claimed this alert and never came back with a case
        # id, and the grid could not be asked whether one exists. Opening a case
        # now might duplicate one; refusing leaves the alert where it is. Only
        # the second of those is reversible. Answered as an error rather than an
        # execution, so the card stays pressable once the grid is readable.
        return ExecuteActionResult(
            status="error",
            title=title,
            error=(
                "An earlier escalate of this alert is not settled. soc-ai could not read "
                "the Security Onion case index. soc-ai opened no case. Try again once "
                "the grid is readable."
            ),
        )
    # A case already exists. Same shape as the already-acknowledged arm in the
    # caller: ok-with-note, and persist the marker so the card reads applied
    # from now on rather than re-offering a duplicate.
    await _persist_action_executed(
        request, inv_real_id, sequence, {**receipt, "success": True, "by": user}
    )
    return ExecuteActionResult(
        status="executed",
        title=title,
        detail="This alert is already on a Security Onion case. soc-ai opened no second case.",
    )


async def _record_escalation(
    request: Request,
    *,
    alert_id: Any,
    case_id: str,
    linked: bool,
) -> None:
    """Resolve this alert's ledger claim with the case that was opened for it.

    The claim itself was taken by :func:`_reserve_escalate` before the write, so
    there is a row here already and this only writes the answer onto it.

    A case id goes on the row only when the alert is genuinely attached to that
    case. Writing one for a case that attached nothing is the poisoning half of
    the range defect: the ledger would then refuse the case actually needed, on
    the strength of a link that does not exist. An unattached escalate leaves
    the bare claim standing, which reads as "soc-ai tried, outcome unknown", and
    the next press of either escalate settles it against the grid.

    Best-effort: the case exists either way, and a store failure must not change
    what the operator is told about the write.
    """
    if not isinstance(alert_id, str) or not alert_id or not linked or not case_id:
        return
    try:
        async with request.app.state.db_sessionmaker() as db:
            await esc_svc.record_case(db, alert_id, case_id)
    except Exception:
        _LOGGER.warning("escalation ledger write failed", exc_info=True)


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


# Per-(inv_id, index) execution locks serialize concurrent execute-action calls
# for the SAME advisory action (double-click, client retry, flaky-network
# auto-retry). Without this, two concurrent escalates both pass the "already
# executed?" idempotency check on the same pre-write snapshot and both POST
# /connect/case → duplicate SO cases (F029 — the very outcome the persisted
# ``action_executed`` marker exists to prevent, but the marker alone only covers
# the reload-replay case, not a concurrent race). Holding the lock across the
# whole handler makes the second caller read the FRESH event stream (with the
# first call's persisted marker) and return ok-with-note instead of writing
# again. A WeakValueDictionary auto-evicts a key's lock once no in-flight call
# references it, so the map can't grow unbounded.
_ACTION_LOCKS: WeakValueDictionary[tuple[str, int], asyncio.Lock] = WeakValueDictionary()


def _action_lock(inv_id: str, index: int) -> asyncio.Lock:
    """The shared ``asyncio.Lock`` for one ``(investigation, action index)``.

    Safe under single-threaded asyncio: the get-or-create never awaits, so two
    coroutines racing for the same key can't interleave and always receive the
    SAME lock object.
    """
    key = (inv_id, index)
    lock = _ACTION_LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _ACTION_LOCKS[key] = lock
    return lock


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
    advisory action cards are built in that order). This is the single
    analyst write path — the report recommends, the analyst executes here.

    Idempotent: a previously executed action (persisted ``action_executed``
    event) or an ack of an already-acked alert returns ok-with-note instead of
    writing again — no duplicate SO cases, no double acks. Concurrent executes of
    the same action are serialized (F029) so a double-click can't race the write.
    """
    # Serialize per (inv_id, index): a second concurrent caller blocks here, then
    # re-reads the event stream inside `_execute_action_locked` and sees the first
    # call's persisted marker — so it never fires a duplicate write.
    async with _action_lock(inv_id, index):
        return await _execute_action_locked(
            request, inv_id=inv_id, index=index, settings=settings, elastic=elastic
        )


async def _execute_action_locked(  # noqa: PLR0915 — linear single-analyst write path
    request: Request,
    *,
    inv_id: str,
    index: int,
    settings: Settings,
    elastic: ElasticClient,
) -> ExecuteActionResult:
    """Execute the write action. MUST run under ``_action_lock(inv_id, index)``.

    The event stream (carrying the ``action_executed`` idempotency marker) is read
    AFTER the caller acquired the lock, so a concurrent double-click can't pass the
    "already executed?" check on a stale pre-write snapshot.
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
        rule_name = inv.rule_name
        inv_real_id = inv.id
        next_seq = max((e.sequence for e in events), default=0) + 1
        # Anchor-keyed hunt check: a fresh non-hunt row over a promoted
        # finding's or lead's anchor (a POST /investigate re-run) must not
        # launder the document past the kind-keyed guard below — the anchor is
        # still cited telemetry with no SO alert behind it, whatever THIS
        # row's kind says.
        anchors_a_hunt = inv_svc.is_promoted(inv) or (
            alert_es_id is not None and bool(await inv_svc.hunt_anchor_ids(db, [alert_es_id]))
        )

    recs = report.get("recommended_actions") or []
    if index < 0 or index >= len(recs):
        raise HTTPException(status_code=404, detail={"reason": "no_such_action"})

    rec = recs[index]
    # Idempotency identity is the action's CONTENT, not its list position: a
    # chat-resolve can replace recommended_actions and shift indexes (F04).
    action_key = _action_identity(rec)
    tool_name = rec.get("tool_name", "")
    title = _ACTION_TITLE.get(tool_name, tool_name or "Action")
    if tool_name not in WRITE_TOOLS:
        raise HTTPException(
            status_code=400,
            detail={"reason": "not_executable", "tool": tool_name},
        )

    if anchors_a_hunt:
        # A promoted finding's anchor is cited telemetry, not an SO alert —
        # there is nothing to ack/escalate, and the rule-keyed group ack below
        # must never see a finding title as a rule_name. Keyed off the ANCHOR
        # document (any hunt-kind investigation over this alert_es_id), not
        # just this row's own kind — see anchors_a_hunt above. No `and
        # tool_name in WRITE_TOOLS` conjunct here: the check above already
        # 400s any non-write tool, so by this point tool_name is proven to be
        # a write tool — restating the condition would just be dead weight.
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "hunt_kind_no_so_target",
                "hint": "A promoted finding has no Security Onion alert to act on.",
            },
        )

    # Already executed through this endpoint? Never write twice (the escalate
    # case would open a duplicate SO case) — confirm instead.
    executed = _executed_actions(events)
    if action_key in executed or f"#idx:{index}" in executed:
        return ExecuteActionResult(
            status="executed",
            title=title,
            detail="Already executed. soc-ai did not repeat it.",
        )

    tool_args = dict(rec.get("tool_args") or {})
    # SECURITY (F07): the write TARGET is bound server-side, never taken from the
    # model. ``RecommendedAction.tool_args`` is fully model-authored (no
    # validator) and assembled from attacker-influenceable enriched-alert context,
    # so a present-but-wrong alert_id/case_id would ack/escalate/comment on a
    # DIFFERENT SO object than the one the analyst approved in this investigation.
    if tool_name in ("ack_alert", "escalate_to_case"):
        # Always OVERWRITE (not default-when-missing): the target is this
        # investigation's own alert, even when the model supplied an alert_id.
        if not alert_es_id:
            raise HTTPException(
                status_code=400,
                detail={"reason": "missing_alert_id", "tool": tool_name},
            )
        tool_args["alert_id"] = alert_es_id
    elif tool_name == "add_case_comment":
        # Bind to a case THIS investigation itself opened (a prior escalate the
        # system executed and observed), never the model's free-form case_id. No
        # such case → refuse rather than comment on an arbitrary/hostile case id.
        bound_case_id = _observed_case_id(events)
        if not bound_case_id:
            raise HTTPException(
                status_code=400,
                detail={"reason": "no_case_for_comment", "tool": tool_name},
            )
        tool_args["case_id"] = bound_case_id

    user = await identify_caller(request)

    # Group-scoped ack (rule-keyed): the analyst's intent is "this detection is
    # handled", not "ack one event of it" — a single-event ack left the rest of
    # the group in the queue after a successful "Executed ✓". Falls back to the
    # single-alert ack when the run has no rule_name or the group fetch fails.
    if tool_name == "ack_alert" and rule_name:
        group = await _group_ack_result(
            request, rule_name=rule_name, settings=settings, elastic=elastic, user=user
        )
        if group is not None:
            detail, acked = group
            await _persist_action_executed(
                request,
                inv_real_id,
                next_seq,
                {
                    "index": index,
                    "action_key": action_key,
                    "tool_name": tool_name,
                    "title": title,
                    "success": True,
                    "by": user,
                    "detail": detail,
                    "group": True,
                    "acked": acked,
                },
            )
            return ExecuteActionResult(status="executed", title=title, detail=detail)

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
                "action_key": action_key,
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
            detail="This alert is already acknowledged in Security Onion.",
        )

    if tool_name == "escalate_to_case":
        # Reserve the alert BEFORE opening the case, so a group escalate racing
        # this press collides on the ledger's unique index instead of on
        # Security Onion's case queue. See _reserve_escalate.
        refused = await _reserve_escalate(
            request,
            elastic,
            settings,
            str(tool_args["alert_id"]),
            user=user,
            inv_real_id=inv_real_id,
            sequence=next_seq,
            receipt={
                "index": index,
                "action_key": action_key,
                "tool_name": tool_name,
                "title": title,
                "note": "already_escalated",
            },
        )
        if refused is not None:
            return refused

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
    # An escalate that put the alert on no case is a failed escalate, whatever
    # Security Onion answered the case create with. It decides the status, the
    # persisted receipt and which ledger row is written.
    escalated = tool_name != "escalate_to_case" or _escalate_outcome(result)[0]
    exec_payload: dict[str, Any] = {
        "index": index,
        "action_key": action_key,
        "tool_name": tool_name,
        "title": title,
        "success": escalated,
        "by": user,
        "detail": detail,
    }
    if tool_name == "escalate_to_case":
        # Persist the SO-created case id so a later add_case_comment can bind its
        # write target to a case THIS investigation opened (F07). Recorded on an
        # unattached case too, so the empty case an operator has to deal with is
        # not only in a response they may have navigated away from. The
        # success=False on the receipt keeps it out of _observed_case_id.
        case_id = _case_id_from_result(result)
        if case_id:
            exec_payload["case_id"] = case_id
        await _record_escalation(
            request,
            alert_id=tool_args.get("alert_id"),
            case_id=case_id,
            linked=escalated,
        )
    await _persist_action_executed(request, inv_real_id, next_seq, exec_payload)
    if not escalated:
        return ExecuteActionResult(status="error", title=title, error=detail)
    return ExecuteActionResult(status="executed", title=title, detail=detail)


# ── Chat verdict resolution ────────────────────────────────────────────────


class ResolveIn(BaseModel):
    message_id: int
    token: str


@router.post("/investigations/{inv_id}/resolve")
async def resolve_investigation(request: Request, inv_id: str, body: ResolveIn) -> dict[str, Any]:
    """Apply a validated chat verdict proposal. Token + message gated, idempotent."""
    # Not owner-scoped: any authenticated caller may apply a proposal, consistent
    # with the action-execute route. The actor is recorded for audit.
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
                    "hint": "Wait for the investigation to complete before you override.",
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
