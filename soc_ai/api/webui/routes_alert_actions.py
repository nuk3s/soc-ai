"""Alert mutations: ack-group, escalate-group, ack-events, assign."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel

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


class AckEventsIn(BaseModel):
    es_ids: list[str]


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


class AssignOut(BaseModel):
    rule_name: str
    owner: str | None


@router.post("/alerts/assign", response_model=AssignOut)
async def assign_alert(
    request: Request,
    body: AssignIn,
) -> AssignOut:
    """Persist (or clear) the owner for a detection rule.

    When ``unassign`` is False the caller is resolved via
    :func:`~soc_ai.api.security.identify_caller` and stored as the owner.
    When ``unassign`` is True the row is removed.  The owner value is a plain
    username when the caller is authenticated via session, or ``token:<name>``
    when using a bearer token, or ``"anonymous"`` when API auth is off.
    """
    async with request.app.state.db_sessionmaker() as db:
        if body.unassign:
            await assign_svc.clear_assignment(db, body.rule_name)
            return AssignOut(rule_name=body.rule_name, owner=None)
        owner = await identify_caller(request)
        await assign_svc.set_assignment(db, body.rule_name, owner)
    return AssignOut(rule_name=body.rule_name, owner=owner)
