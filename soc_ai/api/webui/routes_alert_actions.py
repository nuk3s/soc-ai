"""Alert mutations: ack-group, escalate-group, ack-events, assign."""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    router,
)
from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import assignments as assign_svc
from soc_ai.tools.write_exec import execute_write_tool
from soc_ai.webui import alerts_query as aq

_LOGGER = logging.getLogger(__name__)

_ACK_CAP = 200  # maximum events acknowledged per ack-group call
_ACK_CONCURRENCY = 8  # bounded fan-out for bulk ack to keep ES/SO round-trips parallel-but-capped


async def _ack_many(
    request: Request,
    alert_ids: list[str],
    *,
    session_id: str,
    caller: str,
) -> tuple[int, int]:
    """Acknowledge ``alert_ids`` concurrently under a bounded semaphore.

    Each id goes through the same ``execute_write_tool`` write path as the
    serial version (identical auth/audit/correctness), but the calls fan out
    via ``asyncio.gather`` capped at ``_ACK_CONCURRENCY`` so a 200-event group
    no longer blocks the HTTP response on hundreds of sequential round-trips.

    Returns ``(acked, failed)``.  A write that returns an error tuple OR raises
    counts as a failure; exceptions never escape (``return_exceptions=True``).
    """
    sem = asyncio.Semaphore(_ACK_CONCURRENCY)

    async def _one(alert_id: str) -> bool:
        async with sem:
            _result, error = await execute_write_tool(
                "ack_alert",
                {"alert_id": alert_id},
                auth=request.app.state.auth,
                settings=request.app.state.settings,
                audit=request.app.state.audit,
                session_id=session_id,
                user=caller,
            )
            return error is None

    results = await asyncio.gather(
        *(_one(alert_id) for alert_id in alert_ids),
        return_exceptions=True,
    )
    acked = 0
    failed = 0
    for r in results:
        if r is True:
            acked += 1
        else:
            # error tuple (r is False) OR a raised exception (BaseException)
            failed += 1
            if isinstance(r, BaseException):
                _LOGGER.warning("bulk-ack write raised (session=%s): %r", session_id, r)
    return acked, failed


class AckGroupIn(BaseModel):
    rule_name: str
    kind: str = "suricata"
    range: str = aq.DEFAULT_RANGE
    q: str | None = None
    severity: str | None = None
    from_: str | None = None
    to: str | None = None

    model_config = {"populate_by_name": True}


class AckGroupOut(BaseModel):
    acked: int
    failed: int
    total: int
    capped: bool = False


@router.post("/alerts/ack-group", response_model=AckGroupOut)
async def ack_group(
    request: Request,
    body: AckGroupIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> AckGroupOut:
    """Acknowledge all events for a detection group in Security Onion.

    Fetches up to ``_ACK_CAP`` events matching the rule+filters and calls
    ``ack_alert`` for each via the write-tool path.  Returns counts of
    successes, failures, and whether the cap was hit.
    """
    caller = await identify_caller(request)
    try:
        events = await aq.fetch_group_events(
            elastic,
            settings,
            rule_name=body.rule_name,
            kind=body.kind,
            time_range=body.range,
            severity=body.severity,
            oql=body.q,
            size=_ACK_CAP + 1,  # fetch one extra to detect capping
            abs_from=body.from_,
            abs_to=body.to,
            time_zone=settings.so_timezone,
            hide_acked=True,
        )
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc

    capped = len(events) > _ACK_CAP
    events = events[:_ACK_CAP]

    if not events:
        return AckGroupOut(acked=0, failed=0, total=0)

    acked, failed = await _ack_many(
        request,
        [ev.es_id for ev in events],
        session_id=f"ack-group:{body.rule_name}",
        caller=caller,
    )

    total = acked + failed
    if capped:
        logging.getLogger(__name__).warning(
            "ack-group capped at %d events for rule %r (caller=%s)",
            _ACK_CAP,
            body.rule_name,
            caller,
        )

    return AckGroupOut(acked=acked, failed=failed, total=total, capped=capped)


# Escalate is capped far tighter than ack: each escalate opens a SOC case, so a
# group escalate must not spray hundreds of cases. One case per matching event
# mirrors the single-alert escalate_to_case action; the cap bounds the blast.
_ESCALATE_CAP = 25


async def _escalate_many(
    request: Request,
    events: list[Any],
    *,
    rule_name: str,
    session_id: str,
    caller: str,
) -> tuple[int, int]:
    """Escalate ``events`` to Security Onion cases under a bounded semaphore.

    Each event goes through the same ``execute_write_tool`` write path as the
    per-action escalate (identical auth/audit/correctness), fanning out via
    ``asyncio.gather`` capped at ``_ACK_CONCURRENCY``. The escalate tool needs a
    title + description, which the model supplies for the single-alert action;
    here we synthesize a compact, secret-free case title/description from the
    rule name and the event's endpoints. Returns ``(escalated, failed)``.
    """
    sem = asyncio.Semaphore(_ACK_CONCURRENCY)

    async def _one(ev: Any) -> bool:
        async with sem:
            endpoints = f"{ev.src} → {ev.dst}" if getattr(ev, "src", None) else ""
            _result, error = await execute_write_tool(
                "escalate_to_case",
                {
                    "alert_id": ev.es_id,
                    "case_title": f"{rule_name}"[:120] or "Escalated alert",
                    "case_description": (
                        f"Escalated from soc-ai: {rule_name}"
                        + (f" ({endpoints})" if endpoints else "")
                    ),
                },
                auth=request.app.state.auth,
                settings=request.app.state.settings,
                audit=request.app.state.audit,
                session_id=session_id,
                user=caller,
            )
            return error is None

    results = await asyncio.gather(
        *(_one(ev) for ev in events),
        return_exceptions=True,
    )
    escalated = 0
    failed = 0
    for r in results:
        if r is True:
            escalated += 1
        else:
            failed += 1
            if isinstance(r, BaseException):
                _LOGGER.warning("bulk-escalate write raised (session=%s): %r", session_id, r)
    return escalated, failed


class EscalateGroupOut(BaseModel):
    escalated: int
    failed: int
    total: int
    capped: bool = False


@router.post("/alerts/escalate-group", response_model=EscalateGroupOut)
async def escalate_group(
    request: Request,
    body: AckGroupIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> EscalateGroupOut:
    """Escalate a detection group to Security Onion cases.

    Sibling of :func:`ack_group` — same auth/CSRF/signature and the same
    ``fetch_group_events`` filters. Each matching event opens a case via the
    ``escalate_to_case`` write tool; ``_ESCALATE_CAP`` bounds the number of
    cases so a group escalate can never spray hundreds.
    """
    caller = await identify_caller(request)
    try:
        events = await aq.fetch_group_events(
            elastic,
            settings,
            rule_name=body.rule_name,
            kind=body.kind,
            time_range=body.range,
            severity=body.severity,
            oql=body.q,
            size=_ESCALATE_CAP + 1,  # fetch one extra to detect capping
            abs_from=body.from_,
            abs_to=body.to,
            time_zone=settings.so_timezone,
            hide_acked=True,
        )
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc

    capped = len(events) > _ESCALATE_CAP
    events = events[:_ESCALATE_CAP]

    if not events:
        return EscalateGroupOut(escalated=0, failed=0, total=0)

    escalated, failed = await _escalate_many(
        request,
        events,
        rule_name=body.rule_name,
        session_id=f"escalate-group:{body.rule_name}",
        caller=caller,
    )

    if capped:
        logging.getLogger(__name__).warning(
            "escalate-group capped at %d events for rule %r (caller=%s)",
            _ESCALATE_CAP,
            body.rule_name,
            caller,
        )

    return EscalateGroupOut(
        escalated=escalated, failed=failed, total=escalated + failed, capped=capped
    )


_ES_ID = Annotated[str, Field(max_length=512)]  # ES ``_id`` values are <=512 bytes


class AckEventsIn(BaseModel):
    # Cap at the input boundary (mirrors RehuntIn.inv_ids) so an oversized
    # payload is rejected by validation before the dedup/truncate logic below
    # ever parses or iterates it.
    es_ids: list[_ES_ID] = Field(max_length=_ACK_CAP)


@router.post("/alerts/ack-events", response_model=AckGroupOut)
async def ack_events(
    request: Request,
    body: AckEventsIn,
    settings: Settings = Depends(get_settings_dep),
) -> AckGroupOut:
    """Acknowledge a specific set of events by ES id (per-event selection)."""
    caller = await identify_caller(request)
    ids = list(dict.fromkeys(body.es_ids))[:_ACK_CAP]  # dedupe, cap
    capped = len(body.es_ids) > _ACK_CAP
    if not ids:
        return AckGroupOut(acked=0, failed=0, total=0)
    acked, failed = await _ack_many(
        request,
        ids,
        session_id="ack-events",
        caller=caller,
    )

    if capped:
        logging.getLogger(__name__).warning(
            "ack-events capped at %d events (caller=%s)",
            _ACK_CAP,
            caller,
        )

    return AckGroupOut(acked=acked, failed=failed, total=acked + failed, capped=capped)


# ── Alert assignment ───────────────────────────────────────────────────────


class AssignIn(BaseModel):
    rule_name: str
    unassign: bool = False
    # Optional triage-state transition (E2.3). When omitted on an assign the state
    # defaults to "owned"; passing e.g. "in_review"/"done" moves an ALREADY-owned
    # rule through the triage flow without changing the owner. Ignored on unassign
    # (clearing the row drops the state with it).
    state: str | None = None


class AssignOut(BaseModel):
    rule_name: str
    owner: str | None
    state: str | None = None


async def _audit_assignment(
    request: Request,
    *,
    rule_name: str,
    action: str,
    owner: str | None,
    state: str | None,
) -> None:
    """Best-effort audit of an assignment change (assign / state / unassign).

    Mirrors E1.1's model_fitness audit: a failed audit index must never turn a
    successful assignment into a 500, so the whole thing is wrapped and logged,
    never raised. ``action`` is one of ``assign`` | ``state`` | ``unassign``.
    """
    try:
        caller = await identify_caller(request)
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(
                session_id=f"assignment:{rule_name}",
                kind="assignment",
                payload={
                    "rule_name": rule_name,
                    "action": action,
                    "owner": owner,
                    "state": state,
                },
                user=caller,
            )
    except Exception:  # audit is best-effort — an assignment must never 500 on it
        _LOGGER.warning("assignment audit write failed (continuing)", exc_info=True)


@router.post("/alerts/assign", response_model=AssignOut)
async def assign_alert(
    request: Request,
    body: AssignIn,
) -> AssignOut:
    """Persist (or clear) the owner + triage state for a detection rule.

    Three shapes, all through the one endpoint (an analyst action — same auth as
    the surrounding ack/escalate routes, not admin-only):

    * ``unassign=True`` — remove the row (owner + state gone; back to the
      "unassigned" no-row state).
    * ``state`` set (no unassign) — move an EXISTING assignment through the
      triage flow (``owned`` → ``in_review`` → ``done``) without changing owner.
      A 404 if the rule has no owner (state requires an owner).
    * otherwise — assign the caller as owner (resetting state to ``owned``). The
      owner value is a plain username when authenticated via session,
      ``token:<name>`` for a bearer token, or ``"anonymous"`` when auth is off.

    Every change is audited best-effort (``assignment`` kind).
    """
    async with request.app.state.db_sessionmaker() as db:
        if body.unassign:
            await assign_svc.clear_assignment(db, body.rule_name)
            await _audit_assignment(
                request, rule_name=body.rule_name, action="unassign", owner=None, state=None
            )
            return AssignOut(rule_name=body.rule_name, owner=None, state=None)

        # State-only transition on an existing assignment (owner unchanged).
        if body.state is not None:
            try:
                applied = await assign_svc.set_state(db, body.rule_name, body.state)
            except ValueError as exc:
                raise HTTPException(
                    status_code=400, detail={"reason": "bad_state", "hint": str(exc)}
                ) from exc
            if not applied:
                raise HTTPException(
                    status_code=404,
                    detail={
                        "reason": "not_assigned",
                        "hint": "assign an owner before setting a triage state",
                    },
                )
            record = await assign_svc.assignments_for_rules(db, [body.rule_name])
            rec = record.get(body.rule_name, {})
            await _audit_assignment(
                request,
                rule_name=body.rule_name,
                action="state",
                owner=rec.get("owner"),
                state=body.state,
            )
            return AssignOut(rule_name=body.rule_name, owner=rec.get("owner"), state=body.state)

        # Plain assign: caller becomes owner, state resets to "owned".
        owner = await identify_caller(request)
        await assign_svc.set_assignment(db, body.rule_name, owner)
    await _audit_assignment(
        request, rule_name=body.rule_name, action="assign", owner=owner, state="owned"
    )
    return AssignOut(rule_name=body.rule_name, owner=owner, state="owned")
