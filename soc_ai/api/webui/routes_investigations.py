"""Investigation list/detail/cancel/delete/rehunt/request-more-info endpoints."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui import _timeline, routes_hunts
from soc_ai.api.webui._shared import (
    _ago,
    _iso_utc,
    _sev,
    _verdict,
    require_admin_api,
    router,
)
from soc_ai.api.webui._timeline import (
    InvestigationOut,
    InvMetaOut,
    _alert_meta,
    _build_actions,
    _build_oracle,
    _build_timeline,
    _chat_msg_out,
    _collect_reasoning,
    _entity_graph,
    _host_signals,
)
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import chat as chat_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Investigation
from soc_ai.webui import (
    hunt_manager,
)

_LOGGER = logging.getLogger(__name__)

# ── Investigations ─────────────────────────────────────────────────────────

# Statuses actually written by the backend: running | complete | error |
# cancelled | interrupted. (The frontend union also lists a legacy "awaiting"
# that is never produced.)
_STATUS = {
    "running": "running",
    "complete": "complete",
    "error": "error",
    "cancelled": "cancelled",
    "interrupted": "interrupted",
}


def _row_status(inv: Investigation) -> str:
    """Effective display status for an investigation row.

    An unknown stored status falls back to 'error' (never silently 'complete'),
    and a finished run that produced NO verdict is reported as 'error' — it never
    reached a triage decision, so labelling it 'complete' would be a lie (the
    verdict shows 'untriaged'). A real verdict — including needs_more_info — keeps
    the stored status.
    """
    status = _STATUS.get(inv.status, "error")
    if status == "complete" and not (inv.verdict or "").strip():
        return "error"
    return status


class InvestigationRowOut(BaseModel):
    id: str
    name: str
    kind: str
    verdict: str
    conf: float | None = None
    host: str
    # Destination IP — paired with ``host`` (the source) so the list shows the
    # full source → destination flow, not just one end.
    dst: str | None = None
    status: str
    when: str
    ts: str = ""
    chatCount: int = 0
    # The alert this run investigated — lets the UI cluster retries of the SAME
    # alert so errored/cancelled re-runs nest under the one that produced a verdict.
    alertId: str = ""
    # The canonical run for its alert: the latest COMPLETE run, else the latest of
    # any status. The UI surfaces this row and tucks the rest away as "earlier runs".
    isPrimary: bool = True


def _elapsed_sec(inv: Investigation) -> int:
    created = inv.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    end = inv.finished_at or datetime.now(UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    return max(0, int((end - created).total_seconds()))


def _elapsed(inv: Investigation) -> str:
    s = _elapsed_sec(inv)
    return f"{s}s" if s < 60 else f"{s // 60}m {s % 60}s"


def _row(
    inv: Investigation, chat_count: int = 0, *, is_primary: bool = True
) -> InvestigationRowOut:
    return InvestigationRowOut(
        id=inv.id,
        name=inv.rule_name or f"Alert {(getattr(inv, 'alert_es_id', None) or inv.id)[:12]}…",
        kind="suricata",
        verdict=_verdict(inv.verdict),
        conf=inv.confidence,
        host=inv.src_ip or "—",
        dst=getattr(inv, "dest_ip", None),
        status=_row_status(inv),
        when=_ago(_iso_utc(inv.created_at)),
        # tz-AWARE ISO so the browser localizes correctly (naive → parsed as local).
        ts=_iso_utc(inv.created_at),
        chatCount=chat_count,
        alertId=getattr(inv, "alert_es_id", None) or inv.id,
        isPrimary=is_primary,
    )


def _primary_run_ids(rows: list[Investigation]) -> set[str]:
    """The canonical run id per alert: the most recent COMPLETE run, else the most
    recent run of any status. ``rows`` are newest-first (``list_recent`` order)."""
    best_complete: dict[str, str] = {}
    best_any: dict[str, str] = {}
    for inv in rows:  # newest-first, so first-seen per key is the most recent
        key = getattr(inv, "alert_es_id", None) or inv.id
        best_any.setdefault(key, inv.id)
        if inv.status == "complete":
            best_complete.setdefault(key, inv.id)
    return {best_complete.get(key, run_id) for key, run_id in best_any.items()}


@router.get("/investigations", response_model=list[InvestigationRowOut])
async def list_investigations(
    request: Request,
    status: str | None = None,
    limit: int = 100,
) -> list[InvestigationRowOut]:
    if status not in (None, "running", "complete", "error", "cancelled", "interrupted"):
        status = None
    async with request.app.state.db_sessionmaker() as db:
        rows = await inv_svc.list_recent(db, status=status, limit=min(max(limit, 1), 500))
        chat_counts = await chat_svc.counts_for(db, [inv.id for inv in rows])
    primary = _primary_run_ids(rows)
    return [_row(inv, chat_counts.get(inv.id, 0), is_primary=inv.id in primary) for inv in rows]


@router.get("/investigations/{inv_id}", response_model=InvestigationOut)
async def get_investigation(
    request: Request,
    inv_id: str,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> InvestigationOut:
    async with request.app.state.db_sessionmaker() as db:
        got = await inv_svc.get_with_events(db, inv_id)
        if got is None:
            # The drawer opens groups by alert es-id — resolve to its latest run.
            by_alert = await inv_svc.latest_for_alerts(db, [inv_id])
            inv0 = by_alert.get(inv_id)
            if inv0 is not None:
                got = await inv_svc.get_with_events(db, inv0.id)
        if got is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        inv, events = got
        chat = await chat_svc.list_messages(db, inv.id)
    pending_tokens = {p.token for p in await request.app.state.gate.pending()}

    report = inv.report or {}
    # Live acked state so an ack performed OUTSIDE this run (group-ack, another
    # run's auto-ack, the SO web UI) marks the ack action applied. False on any
    # ES error — the action is simply offered as before.
    alert_acked = await _timeline._alert_currently_acked(elastic, settings, inv.alert_es_id)
    actions = _build_actions(events, report, pending_tokens, alert_acked=alert_acked)

    # The enriched-alert-context event carries the alert, the host's alert
    # profile, and indicator enrichments — everything the rail + graph need.
    enr_p: dict[str, Any] = {}
    for e in events:
        if e.kind in ("enriched_alert_context", "alert_context"):
            enr_p = e.payload or {}
            break
    _ao_raw = enr_p.get("alert") or {}
    alert_obj: dict[str, Any] = _ao_raw if isinstance(_ao_raw, dict) else {}
    _hp_raw = enr_p.get("host_alert_profile") or {}
    host_profile: dict[str, Any] = _hp_raw if isinstance(_hp_raw, dict) else {}
    _en_raw = enr_p.get("enrichments") or {}
    enrichments: dict[str, Any] = _en_raw if isinstance(_en_raw, dict) else {}

    timeline, tool_calls, pivots, has_oracle = _build_timeline(events)
    nodes, edges, graph_note = _entity_graph(alert_obj, enrichments, inv)
    summary_text = report.get("summary") or inv.summary or ""
    meta = InvMetaOut(
        model=settings.analyst_model,
        oracle="escalated to Oracle" if has_oracle else "not escalated — local verdict",
        ranBy=inv.started_by or "—",
        # tz-AWARE ISO (with +00:00) so the value is unambiguous UTC — the raw
        # naive string had no offset, so it couldn't be localized/interpreted.
        ranAt=_iso_utc(inv.created_at),
        toolCalls=tool_calls,
        pivots=pivots,
    )
    return InvestigationOut(
        id=inv.id,
        groupId=inv.alert_es_id or inv.id,
        name=inv.rule_name or f"Alert {(getattr(inv, 'alert_es_id', None) or inv.id)[:12]}…",
        kind="suricata",
        host=alert_obj.get("host_name") or inv.src_ip or "—",
        ip=inv.dest_ip or inv.src_ip or "—",
        verdict=_verdict(inv.verdict),
        conf=inv.confidence if inv.confidence is not None else 0.0,
        rationale=inv.rationale or summary_text,
        summary=[{"t": "text", "v": summary_text}],
        status=(
            "investigating"
            if inv.status == "running"
            # Reaped/stuck runs are persisted as ``error`` — surface that to the
            # drawer so it can render a terminal "failed/interrupted" state
            # instead of an empty "complete" verdict.
            else "error"
            if inv.status == "error"
            # Operator-cancelled runs: a distinct terminal state, not a crash.
            else "cancelled"
            if inv.status == "cancelled"
            # Restart-interrupted runs: benign, re-huntable, not a failure.
            else "interrupted"
            if inv.status == "interrupted"
            else "complete"
        ),
        elapsedLabel=_elapsed(inv),
        elapsedSec=_elapsed_sec(inv),
        actions=actions,
        timeline=timeline,
        reasoning=_collect_reasoning(events),
        nodes=nodes,
        edges=edges,
        seedChat=[_chat_msg_out(m) for m in chat],
        meta=meta,
        oracle=_build_oracle(events),
        sev=_sev(alert_obj.get("severity_label")) if alert_obj else None,
        alert=_alert_meta(alert_obj, host_profile, inv),
        hostContext=_host_signals(host_profile),
        graphNote=graph_note,
        openQuestions=report.get("open_questions") or [],
        resolution=report.get("resolution") or None,
        validatorNote=report.get("validator_note") or None,
        alertAcked=alert_acked,
    )


@router.post("/investigations/{inv_id}/cancel")
async def cancel_hunt(inv_id: str, request: Request) -> dict[str, bool]:
    """Cancel an in-flight hunt for an investigation.

    200 ``{"cancelled": true}`` if a running background task was stopped (the
    run lands as ``cancelled``); 404 if there is no in-flight hunt to cancel
    (it already finished, errored, or completed).
    """
    cancelled = hunt_manager.get_manager(request.app.state).cancel(inv_id)
    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail={
                "reason": "not_running",
                "hint": "no in-flight hunt to cancel — it already finished",
            },
        )
    return {"cancelled": True}


@router.delete("/investigations/{inv_id}", dependencies=[Depends(require_admin_api)])
async def delete_investigation(inv_id: str, request: Request) -> dict[str, bool]:
    """Delete an investigation and its events + chat messages (admin only).

    For clearing broken/orphaned runs. Refuses to delete a still-``running``
    investigation (409) — cancel it first — so its background worker can't write
    rows back after the delete.
    """
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            raise HTTPException(
                status_code=404, detail={"reason": "not_found", "hint": "investigation not found"}
            )
        if inv.status == "running":
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "still_running",
                    "hint": "cancel the running hunt before deleting it",
                },
            )
        await inv_svc.delete(db, inv_id)
    return {"deleted": True}


_REHUNT_CAP = 50


class RehuntIn(BaseModel):
    # Cap at the input boundary so an oversized payload is rejected before the
    # dedup loop deserializes/iterates it.
    inv_ids: list[str] = Field(max_length=_REHUNT_CAP)


class RehuntResultOut(BaseModel):
    started: list[dict[str, str]]  # [{invId, newInvId, alertEsId}]
    skipped: list[dict[str, str]]  # [{invId, reason}]


@router.post("/investigations/rehunt", response_model=RehuntResultOut)
async def bulk_rehunt(
    request: Request,
    body: RehuntIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> RehuntResultOut:
    """Re-launch a fresh investigation for each of the supplied investigation ids.

    Deduplicates the input list. The cap is enforced by request validation
    (``RehuntIn.inv_ids`` has ``max_length=_REHUNT_CAP``, so an oversized
    request is rejected with 422 before reaching here).  Unknown ids are skipped
    with ``"not_found"``; ids whose investigation has no ``alert_es_id`` are
    skipped with ``"no_alert"``.  Successful entries receive a new investigation
    id via the same path as ``POST /hunt``.
    """
    started_by = await identify_caller(request)
    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique_ids: list[str] = []
    for inv_id in body.inv_ids:
        if inv_id not in seen:
            seen.add(inv_id)
            unique_ids.append(inv_id)

    started: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    # The cap is already guaranteed by RehuntIn's max_length validation;
    # all rows are fetched in a SINGLE query (was one session-open + one
    # SELECT per id — an N+1).
    eligible = unique_ids

    inv_by_id: dict[str, Investigation] = {}
    if eligible:
        async with request.app.state.db_sessionmaker() as db:
            rows = (
                (await db.execute(select(Investigation).where(Investigation.id.in_(eligible))))
                .scalars()
                .all()
            )
            inv_by_id = {inv.id: inv for inv in rows}

    for inv_id in eligible:
        inv = inv_by_id.get(inv_id)
        if inv is None:
            skipped.append({"invId": inv_id, "reason": "not_found"})
            continue

        if not inv.alert_es_id:
            skipped.append({"invId": inv_id, "reason": "no_alert"})
            continue

        # Prefer the stored name; if this row was itself created nameless (a pre-fix
        # row, or a selected-id run that died early), re-resolve from ES so the new
        # row is named rather than inheriting the NULL.
        rehunt_name = inv.rule_name
        if not rehunt_name:
            _, rehunt_name = await routes_hunts.resolve_alert_for_hunt(
                elastic, settings, inv.alert_es_id
            )
        new_inv_id = await hunt_manager.get_manager(request.app.state).start(
            request.app.state,
            alert_id=inv.alert_es_id,
            started_by=started_by,
            rule_name=rehunt_name,
        )
        if new_inv_id is None:
            skipped.append({"invId": inv_id, "reason": "could_not_start"})
            continue

        started.append({"invId": inv_id, "newInvId": new_inv_id, "alertEsId": inv.alert_es_id})

    return RehuntResultOut(started=started, skipped=skipped)


def _open_questions_of(inv: Investigation) -> list[str]:
    """Pull the prior run's open questions off the stored report JSON."""
    report = inv.report if isinstance(inv.report, dict) else {}
    raw = report.get("open_questions") or []
    return [str(q).strip() for q in raw if isinstance(q, str) and q.strip()]


def _focus_hint_from_questions(questions: list[str]) -> str:
    """Render prior open questions as a numbered focus block for the seed prompt."""
    return "\n".join(f"{i}. {q}" for i, q in enumerate(questions, 1))


@router.post("/investigations/{inv_id}/request-more-info")
async def request_more_info(
    inv_id: str,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> dict[str, str]:
    """Launch a FOCUSED re-investigation to close a ``needs_more_info`` verdict.

    "One-click request more info": re-runs the investigation on the SAME alert
    as *inv_id* (identical mechanism to ``POST /hunt`` / rehunt), but SEEDS the
    fresh run with the prior investigation's open questions as a ``focus_hint``
    so the new investigation TARGETS those specific gaps instead of starting
    cold.

    Only valid when the source investigation landed ``needs_more_info`` — any
    other verdict is a 409 (the button is only shown for that verdict, but we
    guard server-side too). Returns ``{"investigation_id": <new_inv_id>}`` so
    the SPA can navigate + poll it exactly like a re-hunt.
    """
    started_by = await identify_caller(request)

    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)

    if inv is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    if not inv.alert_es_id:
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "no_alert",
                "hint": "this investigation has no alert reference to re-investigate",
            },
        )
    # `inconclusive` (a self-consistency vote split) is grouped with
    # needs_more_info here: both are terminal NON-committed verdicts, and a
    # focused re-investigation is exactly the right next step for either.
    if (inv.verdict or "").strip() not in ("needs_more_info", "inconclusive"):
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "not_needs_more_info",
                "hint": (
                    "request-more-info only applies to a needs_more_info or "
                    f"inconclusive verdict; this investigation is "
                    f"'{inv.verdict or 'untriaged'}'"
                ),
            },
        )

    questions = _open_questions_of(inv)
    focus_hint = _focus_hint_from_questions(questions) if questions else None

    # Re-resolve the display name if the source row was created nameless.
    rmi_name = inv.rule_name
    if not rmi_name:
        _, rmi_name = await routes_hunts.resolve_alert_for_hunt(elastic, settings, inv.alert_es_id)

    new_inv_id = await hunt_manager.get_manager(request.app.state).start(
        request.app.state,
        alert_id=inv.alert_es_id,
        started_by=started_by,
        rule_name=rmi_name,
        focus_hint=focus_hint,
    )
    if new_inv_id is None:
        raise HTTPException(status_code=503, detail={"reason": "could_not_start"})
    return {"investigation_id": new_inv_id}
