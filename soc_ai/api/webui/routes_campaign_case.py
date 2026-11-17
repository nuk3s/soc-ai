"""The one Security Onion case of a campaign.

``GET /campaigns/{id}/case-scope`` states what "Open one case" writes before
the press: the title, the count of the alerts that go on the case, the alerts
that it skips, and the case that soc-ai opened already.

``POST /campaigns/{id}/case`` opens the case. The order:

1. The intent: one ``case_intent`` change, committed. No intent, no call.
2. Each alert of the plan is reserved in the escalation ledger
   (``routes_alert_actions._reserve``), so one alert is on one case.
3. The three Security Onion calls of the escalate path, through
   :func:`soc_ai.tools.write_exec.execute_write_tool` with its intent and
   result audit records: the create, the attach and the mark of each alert.
4. The result: one ``case`` change, ``campaigns.case_id`` and the decision
   ``case``, after the audit record ``campaign_case_opened``. Or one
   ``case_failed`` change when the press is known to have opened no case.

A result that soc-ai cannot read keeps the intent open. A second press then
opens no case until ``POST /campaigns/{id}/case/retry`` clears the intent
with an audit record. A press on a campaign whose case soc-ai opened already
opens none: it records the decision again on the same case.

The record of a press lives in ``campaign_changes`` (:mod:`soc_ai.campaigns.case`).
Code decides each field from stored facts. The model writes none.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4
from weakref import WeakValueDictionary

from fastapi import Body, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._decision_commit import commit_after_record, record_failed
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import _request_is_https, router
from soc_ai.api.webui.routes_campaigns import AUDIT_SESSION, CampaignOut, _note, _read_out
from soc_ai.campaigns import case as campaign_case
from soc_ai.campaigns import decisions
from soc_ai.campaigns import service as campaign_svc
from soc_ai.campaigns.facts import chunked
from soc_ai.campaigns.types import KIND_ALERT, KIND_FINDING, TRUE_POSITIVE
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import escalations as esc_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Campaign, CampaignMember, Investigation
from soc_ai.tools.escalate_to_case import _EVENT_ID_RE
from soc_ai.tools.write_exec import CAMPAIGN_CASE_TOOL, execute_write_tool
from soc_ai.webui import alerts_query as aq
from soc_ai.webui import case_links

_LOGGER = logging.getLogger(__name__)

# The fields of a member alert that the attach plan reads.
_PLAN_FIELDS = ["event.acknowledged", "event.escalated"]
# The most ids of one grid read.
_READ_CHUNK = 200


class CampaignCaseRefOut(BaseModel):
    """A Security Onion case. ``url`` is null when the settings name no host."""

    id: str
    url: str | None = None


class CaseSkippedOut(BaseModel):
    """The alerts that the case skips. ``acknowledged``: Security Onion
    acknowledged the alert. ``escalated``: the alert is on a case already,
    by its flag or by the ledger of soc-ai. ``noAlert``: the investigation
    names no Security Onion alert."""

    acknowledged: int = 0
    escalated: int = 0
    noAlert: int = 0


class CaseScopeOut(BaseModel):
    """What "Open one case" writes. ``alerts`` counts the alerts that go on
    the case, at most 25, and is null when soc-ai could not read the grid.
    ``capped`` is true when more alerts wait than the case takes.
    ``existing`` is the case that soc-ai opened for the campaign already: a
    press then opens no case and attaches no alert."""

    title: str
    alerts: int | None = None
    capped: bool = False
    skipped: CaseSkippedOut = Field(default_factory=CaseSkippedOut)
    existing: CampaignCaseRefOut | None = None


@dataclass(frozen=True)
class AttachPlan:
    """The alerts of the true positive alert investigations of a campaign, the newest first."""

    attach: list[str] = field(default_factory=list)
    capped: bool = False
    acknowledged: int = 0
    escalated: int = 0
    no_alert: int = 0


def _not_found() -> Exception:
    return api_error(404, "campaign_not_found", "No campaign has this id. Open the campaign list.")


# The days around the events of the alerts that the grid read covers. An alert
# investigation is dated by its alert, so one day each side is wide.
_WINDOW_PAD = timedelta(days=1)


async def _member_alerts(
    db: AsyncSession, campaign_id: int
) -> tuple[list[str], int, tuple[datetime, datetime] | None]:
    """The alert ids of the true positive alert investigations that the campaign holds.

    The newest event first, each id once. The second value counts the
    investigations that name no Security Onion alert: a finding, a lead and
    an investigation with no alert id. The third value is the period of the
    events of those alerts, or None when no alert has a time: the grid read
    then covers every index.
    """
    members = (
        await db.execute(
            select(CampaignMember.run_id, CampaignMember.event_time).where(
                CampaignMember.campaign_id == campaign_id,
                CampaignMember.verdict_differs.is_(False),
            )
        )
    ).all()
    event_at = {str(run_id): at for run_id, at in members}
    invs: list[Investigation] = []
    for ids in chunked(sorted(event_at)):
        invs.extend(
            (
                await db.scalars(
                    select(Investigation).where(
                        Investigation.id.in_(ids),
                        Investigation.verdict == TRUE_POSITIVE,
                        Investigation.status == "complete",
                    )
                )
            ).all()
        )

    def newest(inv: Investigation) -> tuple[datetime, str]:
        return (event_at.get(inv.id) or inv.created_at or datetime.min, inv.id)

    alerts: list[str] = []
    times: list[datetime] = []
    no_alert = 0
    for inv in sorted(invs, key=newest, reverse=True):
        alert_id = inv.alert_es_id
        if inv_svc.is_promoted(inv) or not alert_id or not _EVENT_ID_RE.match(alert_id):
            no_alert += 1
        elif alert_id not in alerts:
            alerts.append(alert_id)
            at = event_at.get(inv.id) or inv.event_at
            if at is not None:
                times.append(at)
    # One alert with no time: the period is not known, so the read has no window.
    window = (min(times), max(times)) if times and len(times) == len(alerts) else None
    return alerts, no_alert, window


def _alerts_query(
    settings: Settings, ids: list[str], window: tuple[datetime, datetime] | None
) -> dict[str, Any]:
    """The alert feed over the ids, inside the period of their events.

    The feed query has no time window, so the grid opens every index for it.
    A first read after a quiet hour passed the grid timeout on production
    (2026-11-16). The alerts of a campaign have known event times, so the
    read names their period and the grid opens the indices of those days only.
    """
    query = aq.feed_ids_query(settings, ids)
    if window is not None:
        start, end = window
        query["bool"]["filter"].append(
            {
                "range": {
                    "@timestamp": {
                        "gte": (start - _WINDOW_PAD).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "lte": (end + _WINDOW_PAD).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                }
            }
        )
    return query


async def attach_plan(
    request: Request, campaign_id: int, elastic: ElasticClient, settings: Settings
) -> AttachPlan | None:
    """Which member alerts the case of a campaign attaches. None: the grid did not answer.

    The alerts of the true positive alert investigations that the campaign
    holds, the newest first, at most :data:`campaign_case.ATTACH_CAP`. An
    alert that Security Onion acknowledged or escalated, an alert that the
    ledger has on a case and a document that the alert feed does not hold
    are skipped. The grid read holds no transaction of the store.
    """
    maker = request.app.state.db_sessionmaker
    async with maker() as db:
        ids, no_alert, window = await _member_alerts(db, campaign_id)
    sources: dict[str, dict[str, Any]] = {}
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            for chunk in chunked(ids, _READ_CHUNK):
                result = await elastic.search(
                    settings.events_index_pattern,
                    _alerts_query(settings, list(chunk), window),
                    size=len(chunk),
                    source=_PLAN_FIELDS,
                    # A shard that failed can hold the alert, and its decision.
                    require_complete=True,
                )
                sources.update({str(h.get("_id")): h.get("_source") or {} for h in result.hits})
    except Exception:
        _LOGGER.warning("campaign case: the grid did not answer for the alerts", exc_info=True)
        return None
    in_feed = [a for a in ids if a in sources]
    async with maker() as db:
        ledger = await esc_svc.cases_for_alerts(db, in_feed)
    attach: list[str] = []
    acknowledged = escalated = 0
    capped = False
    for alert_id in in_feed:
        source = sources[alert_id]
        if aq._source_escalated(source) or ledger.get(alert_id):
            escalated += 1
        elif aq._source_acknowledged(source):
            acknowledged += 1
        elif len(attach) >= campaign_case.ATTACH_CAP:
            capped = True
        else:
            attach.append(alert_id)
    return AttachPlan(
        attach=attach,
        capped=capped,
        acknowledged=acknowledged,
        escalated=escalated,
        no_alert=no_alert + len(ids) - len(in_feed),
    )


def existing_out(state: campaign_case.CaseState, settings: Settings) -> CampaignCaseRefOut | None:
    """The case that soc-ai opened for the campaign, or None."""
    record = state.record
    if record is None:
        return None
    return CampaignCaseRefOut(
        id=record.case_id, url=record.url or case_links.case_url(settings, record.case_id)
    )


@router.get("/campaigns/{campaign_id}/case-scope", response_model=CaseScopeOut)
async def campaign_case_scope(
    request: Request,
    campaign_id: int,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> CaseScopeOut:
    """What "Open one case" on a campaign writes, before the press.

    The title of the case, the count of the alerts that go on the case and
    the alerts that it skips (:func:`attach_plan`). A failed grid read gives
    ``alerts`` null, never 0. When soc-ai opened a case for the campaign
    already, ``existing`` names it: a press opens no second case and
    attaches no alert, so ``alerts`` is 0. A campaign that is not active
    takes no case: ``alerts`` is 0. An unknown id gives 404.
    """
    async with request.app.state.db_sessionmaker() as db:
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        title = campaign_case.case_title(row.title)
        active = row.status == campaign_svc.STATUS_ACTIVE
        state = await campaign_case.state_of(db, row)
    existing = existing_out(state, settings)
    if existing is not None or not active:
        return CaseScopeOut(title=title, alerts=0, existing=existing)
    plan = await attach_plan(request, campaign_id, elastic, settings)
    if plan is None:
        return CaseScopeOut(title=title, alerts=None)
    return CaseScopeOut(
        title=title,
        alerts=len(plan.attach),
        capped=plan.capped,
        skipped=CaseSkippedOut(
            acknowledged=plan.acknowledged, escalated=plan.escalated, noAlert=plan.no_alert
        ),
    )


# ── Open one case ──────────────────────────────────────────────────────────


class CaseIn(BaseModel):
    """The press of "Open one case". ``note`` goes into the description of the case."""

    note: str = Field(default="", max_length=2000)


# One lock for each campaign. A press and a "Try again" of one campaign never
# run at the same time in this process. The intent covers the rest.
_CASE_LOCKS: WeakValueDictionary[int, asyncio.Lock] = WeakValueDictionary()


def _case_lock(campaign_id: int) -> asyncio.Lock:
    lock = _CASE_LOCKS.get(campaign_id)
    if lock is None:
        lock = asyncio.Lock()
        _CASE_LOCKS[campaign_id] = lock
    return lock


def _campaign_link(request: Request, campaign_id: int) -> str:
    """The campaign page in the console, from the address that the analyst used.

    Behind a proxy that ends TLS, the request reaches the app as ``http``
    while the analyst used ``https``. The scheme that a trusted proxy reports
    counts (:func:`_request_is_https`), so the link in the case opens the page
    that the analyst knows.
    """
    base = str(request.base_url).rstrip("/")
    if base.startswith("http://") and _request_is_https(request):
        base = "https://" + base[len("http://") :]
    return f"{base}/app/campaigns/{campaign_id}"


def pending_hint(title: str) -> str:
    """The answer while an intent has no result: a case can exist, and where to look."""
    return (
        "soc-ai could not read the answer of Security Onion. A case can exist. Look in the "
        f'Cases page of Security Onion for the title "{title}". Press Try again only if no '
        "case has the title."
    )


_REFUSED_RE = re.compile(r"^open_campaign_case returned (\d{3}): ?(.*)$", re.DOTALL)


def refusal_reason(error: str) -> str:
    """The reason of a press that is known to have opened no case, in words."""
    if error.startswith("aborted:"):
        return "soc-ai could not write the audit record of the write, so it made no call."
    refused = _REFUSED_RE.match(error)
    if refused is not None:
        text = refused.group(2).strip()
        return f"Security Onion refused the case with the status {refused.group(1)}." + (
            f" It answered: {text[:200]}" if text else ""
        )
    return f"soc-ai refused the case text before the call: {error[:200]}"


async def _case_text(
    db: AsyncSession, campaign_id: int, *, note: str, link: str
) -> tuple[str, str] | None:
    """The title and the description of the case, from the stored campaign. None: no campaign."""
    from soc_ai.api.webui.routes_campaigns import _headlines  # noqa: PLC0415 - private helper

    view = await campaign_svc.get_campaign(db, campaign_id)
    if view is None:
        return None
    reached = [step for step in view.ladder if step.reached]
    heads = await _headlines(db, [s.proof_run_id for s in reached if s.proof_run_id])
    stages = [
        campaign_case.StageLine(
            stage=step.stage,
            at=step.first_at,
            what=heads.get(step.proof_run_id or "") or step.proof_label,
        )
        for step in reached
    ]
    machines = [
        campaign_case.MachineLine(
            name=p.name or (p.addresses[0] if p.addresses else p.machine_key),
            role=p.role,
            addresses=p.addresses,
        )
        for p in view.parties
    ]
    held = [m for m in view.members if not m.verdict_differs and m.verdict == TRUE_POSITIVE]
    description = campaign_case.case_description(
        campaign_id=campaign_id,
        bottom_line=view.bottom_line,
        stages=stages,
        machines=machines,
        first_event=view.first_event,
        last_event=view.last_event,
        alerts=sum(1 for m in held if m.kind == KIND_ALERT),
        findings=sum(1 for m in held if m.kind == KIND_FINDING),
        note=note,
        link=link,
    )
    return campaign_case.case_title(view.title), description


def _refuse_decided(row: Campaign) -> None:
    if row.status != campaign_svc.STATUS_ACTIVE:
        raise api_error(
            409,
            "campaign_not_active",
            f"This campaign is {row.status}. Open the case on the campaign that holds it.",
        )
    if row.decision is not None:
        raise api_error(
            409,
            "campaign_decided",
            "This campaign holds a decision. Open it again, or revoke its authorization, "
            "before a case.",
        )


async def _audit_best_effort(request: Request, kind: str, payload: dict[str, Any], by: str) -> None:
    try:
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(AUDIT_SESSION, kind, payload, user=by)
    except Exception:
        _LOGGER.warning("%s audit write failed (continuing)", kind, exc_info=True)


async def _settle_failed(
    request: Request, campaign_id: int, intent_id: str, by: str, reason: str
) -> None:
    """Settle an intent as failed: the press is known to have opened no case. Best effort."""
    try:
        async with request.app.state.db_sessionmaker() as db:
            db.add(
                decisions.change(
                    campaign_id,
                    decisions.CHANGE_CASE_FAILED,
                    {"reason": reason, "intentId": intent_id, "by": by},
                    utcnow(),
                )
            )
            await db.commit()
    except Exception:
        _LOGGER.warning(
            "campaign case: the failed press of campaign %s was not stored", campaign_id
        )


async def _release(request: Request, alert_ids: list[str]) -> None:
    """Free the ledger claims of a press that opened no case. Best effort."""
    if not alert_ids:
        return
    try:
        async with request.app.state.db_sessionmaker() as db:
            await esc_svc.release(db, alert_ids)
    except Exception:
        _LOGGER.warning("campaign case: the ledger claims were not released", exc_info=True)


@router.post("/campaigns/{campaign_id}/case", response_model=CampaignOut)
async def open_campaign_case(
    request: Request,
    campaign_id: int,
    body: CaseIn | None = Body(default=None),
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> CampaignOut:
    """Open one Security Onion case for a campaign. A signed-in analyst may open it.

    The order is in the module docstring. A campaign that holds the decision
    ``case`` answers with itself and writes nothing. A campaign whose case
    soc-ai opened already records the decision again and opens no case.

    Refusals: 404 ``campaign_not_found``; 409 ``campaign_not_active``,
    ``campaign_decided`` and ``case_pending``; 502 ``security_onion_refused``
    with a ``case_failed`` change and no decision, and ``case_unknown`` with
    the intent open; 503 ``grid_unavailable``, ``audit_unavailable`` and
    ``store_unavailable``.
    """
    by = await identify_caller(request)
    note = _note((body or CaseIn()).note)
    async with _case_lock(campaign_id):
        return await _open_locked(
            request, campaign_id, note=note, by=by, settings=settings, elastic=elastic
        )


async def _open_locked(
    request: Request,
    campaign_id: int,
    *,
    note: str,
    by: str,
    settings: Settings,
    elastic: ElasticClient,
) -> CampaignOut:
    maker = request.app.state.db_sessionmaker
    audit = getattr(request.app.state, "audit", None)
    link = _campaign_link(request, campaign_id)
    text: tuple[str, str] | None = None
    async with maker() as db:
        fresh = await campaign_svc.ensure_fresh(db, audit=audit)
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        if row.status == campaign_svc.STATUS_ACTIVE and row.decision == decisions.DECISION_CASE:
            # Rule 1: a second press finds the case and opens none.
            return await _read_out(db, campaign_id, fresh=fresh)
        _refuse_decided(row)
        state = await campaign_case.state_of(db, row)
        if state.open_intent is not None:
            title = str(dict(state.open_intent.detail or {}).get("title") or row.title)
            raise api_error(409, "case_pending", pending_hint(title))
        basis = await decisions.basis_for(db, row)
        if state.record is None:
            text = await _case_text(db, campaign_id, note=note, link=link)
            if text is None:
                raise _not_found()
        # End the read snapshot: each write below opens its own session.
        await db.rollback()
    if state.record is not None:
        return await _record_existing(request, campaign_id, state.record, note, by, basis, fresh)
    assert text is not None
    title, description = text
    plan = await attach_plan(request, campaign_id, elastic, settings)
    if plan is None:
        raise api_error(
            503,
            "grid_unavailable",
            "soc-ai could not read the alerts of the campaign from the grid, so it opened no "
            "case. Try again when the grid answers.",
        )
    # Rule 2: the intent first, committed. No intent, no call.
    intent_id = uuid4().hex
    try:
        async with maker() as db:
            db.add(
                decisions.change(
                    campaign_id,
                    decisions.CHANGE_CASE_INTENT,
                    {"intentId": intent_id, "by": by, "title": title, "alerts": len(plan.attach)},
                    utcnow(),
                )
            )
            await db.commit()
    except Exception as exc:
        _LOGGER.warning(
            "campaign case: the intent of campaign %s was not stored: %s", campaign_id, exc
        )
        raise api_error(
            503,
            "store_unavailable",
            "soc-ai could not record the press, so it opened no case. Try again.",
        ) from exc
    claimed = await _reserve_plan(request, campaign_id, intent_id, plan, by, settings, elastic)
    result, error = await execute_write_tool(
        CAMPAIGN_CASE_TOOL,
        {"case_title": title, "case_description": description, "alert_ids": claimed},
        auth=request.app.state.auth,
        settings=settings,
        audit=audit,
        session_id=campaign_case.session_id(campaign_id),
        user=by,
    )
    if error is not None:
        await _fail(request, campaign_id, intent_id, title, claimed, error, by)
    answer = result if isinstance(result, dict) else {}
    case_id = str(answer.get("case_id") or "")
    if not case_id:
        # Security Onion took the create and named no case. The intent stays
        # open: a case can exist, and soc-ai cannot name it.
        raise api_error(
            502,
            "case_unknown",
            f"Security Onion accepted the case and returned no case id. {pending_hint(title)}",
        )
    attached = [a for a in (answer.get("alerts_attached") or []) if isinstance(a, str)]
    await _ledger(request, attached, case_id)
    detail = {
        "caseId": case_id,
        "alerts": len(attached),
        "by": by,
        "intentId": intent_id,
        "url": case_links.case_url(settings, case_id),
        "link": link,
    }
    opened = {
        "campaign_id": campaign_id,
        "case_id": case_id,
        "title": title,
        "alerts": len(attached),
        "note": note,
        "basis": basis,
    }
    return await _record_opened(request, campaign_id, detail, opened, note, by, basis, fresh)


async def _reserve_plan(
    request: Request,
    campaign_id: int,
    intent_id: str,
    plan: AttachPlan,
    by: str,
    settings: Settings,
    elastic: ElasticClient,
) -> list[str]:
    """Reserve each alert of the plan in the ledger. A failure settles the intent and refuses."""
    from soc_ai.api.webui.routes_alert_actions import _reserve  # noqa: PLC0415 - cycle

    if not plan.attach:
        return []
    try:
        reserved = await _reserve(request, elastic, settings, plan.attach, caller=by)
    except Exception as exc:
        _LOGGER.warning("campaign case: the ledger refused the claims", exc_info=True)
        await _settle_failed(
            request,
            campaign_id,
            intent_id,
            by,
            "soc-ai could not reserve the alerts in its ledger, so it made no call.",
        )
        raise api_error(
            503,
            "store_unavailable",
            "soc-ai could not reserve the alerts in its ledger, so it opened no case. Try again.",
        ) from exc
    held = set(reserved.claimed)
    return [a for a in plan.attach if a in held]


async def _fail(
    request: Request,
    campaign_id: int,
    intent_id: str,
    title: str,
    claimed: list[str],
    error: str,
    by: str,
) -> None:
    """Refuse a press whose write failed. Raises always."""
    from soc_ai.api.webui.routes_actions import _no_case_was_opened  # noqa: PLC0415 - cycle

    if not _no_case_was_opened(error):
        # The call may have reached Security Onion. The intent stays open.
        raise api_error(502, "case_unknown", pending_hint(title))
    reason = refusal_reason(error)
    await _release(request, claimed)
    await _settle_failed(request, campaign_id, intent_id, by, reason)
    await _audit_best_effort(
        request,
        "campaign_case_failed",
        {"campaign_id": campaign_id, "title": title, "reason": reason, "intent_id": intent_id},
        by,
    )
    if error.startswith("aborted:"):
        raise api_error(
            503,
            "audit_unavailable",
            "soc-ai could not write the audit record of the write, so it opened no case. "
            "Try again when the grid answers.",
        )
    raise api_error(502, "security_onion_refused", f"{reason} soc-ai opened no case.")


async def _ledger(request: Request, attached: list[str], case_id: str) -> None:
    """Write the case onto the ledger claim of each attached alert. Best effort."""
    from soc_ai.api.webui.routes_actions import _record_escalation  # noqa: PLC0415 - cycle

    for alert_id in attached:
        await _record_escalation(request, alert_id=alert_id, case_id=case_id, linked=True)


async def _record_opened(
    request: Request,
    campaign_id: int,
    detail: dict[str, Any],
    opened: dict[str, Any],
    note: str,
    by: str,
    basis: dict[str, Any],
    fresh: bool,
) -> CampaignOut:
    """Record the case that Security Onion opened: the ``case`` change, the id and the decision.

    The decision hides work, so the audit record ``campaign_case_opened``
    comes first. When that record fails, the store still records the case
    and its id with no decision: the campaign waits in Needs you, and a
    second press finds the case and opens none. When the store fails, the
    intent stays open and the page offers "Try again".
    """
    case_id = str(detail["caseId"])
    audit = getattr(request.app.state, "audit", None)
    recorded = True
    try:
        if audit is not None:
            await audit.log_kind(
                AUDIT_SESSION, "campaign_case_opened", opened, user=by, mutating=True
            )
    except Exception as exc:
        recorded = False
        _LOGGER.warning("campaign case: the case record failed, no decision saved: %s", exc)
    async with request.app.state.db_sessionmaker() as db:
        decided = False
        try:
            row = await db.get(Campaign, campaign_id, populate_existing=True)
            if row is None:
                raise _not_found()
            now = utcnow()
            if recorded and row.status == campaign_svc.STATUS_ACTIVE and row.decision is None:
                decisions.write_case(
                    db, row, case_id=case_id, by=by, note=note, basis=basis, detail=detail, now=now
                )
                decided = True
            else:
                row.case_id = case_id
                db.add(decisions.change(campaign_id, decisions.CHANGE_CASE, detail, now))
            await db.commit()
        except Exception as exc:
            with contextlib.suppress(Exception):
                await db.rollback()
            if recorded:
                await record_failed(
                    request,
                    AUDIT_SESSION,
                    "campaign_case_opened",
                    opened,
                    by=by,
                    cause=f"store: {type(exc).__name__}",
                )
            raise api_error(
                503,
                "store_unavailable",
                f"soc-ai opened case {case_id} in Security Onion and could not save it. "
                f"Look in Security Onion for case {case_id} before you press Try again.",
            ) from exc
        if not recorded:
            raise api_error(
                503,
                "audit_unavailable",
                f"soc-ai opened case {case_id} in Security Onion and could not write the audit "
                "record, so the campaign holds no decision. Press Open one case again to "
                "record the decision. soc-ai opens no second case.",
            )
        if not decided:
            await record_failed(
                request,
                AUDIT_SESSION,
                "campaign_case_opened",
                opened,
                by=by,
                cause="campaign_decided",
            )
        return await _read_out(db, campaign_id, fresh=fresh)


async def _record_existing(
    request: Request,
    campaign_id: int,
    record: campaign_case.CaseRecord,
    note: str,
    by: str,
    basis: dict[str, Any],
    fresh: bool,
) -> CampaignOut:
    """Record the decision ``case`` on the case that soc-ai opened before. No Security Onion call.

    Rule 6: "Open again" clears the decision and keeps ``case_id``. The press
    then finds the case and opens none. The audit record comes first and
    fails closed.
    """
    audit = getattr(request.app.state, "audit", None)
    opened = {
        "campaign_id": campaign_id,
        "case_id": record.case_id,
        "alerts": 0,
        "note": note,
        "basis": basis,
        "existing": True,
    }
    try:
        if audit is not None:
            await audit.log_kind(
                AUDIT_SESSION, "campaign_case_opened", opened, user=by, mutating=True
            )
    except Exception as exc:
        _LOGGER.warning("campaign case: the case record failed, nothing saved: %s", exc)
        raise api_error(
            503,
            "audit_unavailable",
            "soc-ai could not write the audit record, so the campaign holds no decision. "
            "Try again when the grid answers.",
        ) from exc
    async with request.app.state.db_sessionmaker() as db:
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None or row.status != campaign_svc.STATUS_ACTIVE or row.decision is not None:
            await db.rollback()
            await record_failed(
                request,
                AUDIT_SESSION,
                "campaign_case_opened",
                opened,
                by=by,
                cause="campaign_decided",
            )
            raise api_error(
                409, "campaign_decided", "An analyst decided on this campaign a moment ago."
            )
        decisions.write_case(
            db,
            row,
            case_id=record.case_id,
            by=by,
            note=note,
            basis=basis,
            detail={
                "caseId": record.case_id,
                "alerts": 0,
                "by": by,
                "existing": True,
                "url": record.url,
                "link": record.link,
            },
            now=utcnow(),
        )
        await commit_after_record(
            request,
            db,
            AUDIT_SESSION,
            "campaign_case_opened",
            opened,
            by=by,
            action="case decision",
        )
        return await _read_out(db, campaign_id, fresh=fresh)


@router.post("/campaigns/{campaign_id}/case/retry", response_model=CampaignOut)
async def retry_campaign_case(request: Request, campaign_id: int) -> CampaignOut:
    """Clear the open intent of a press whose result soc-ai could not read. A signed-in analyst may.

    The analyst looked in Security Onion and found no case with the title.
    The audit record ``campaign_case_retry`` comes first and fails closed.
    One ``case_failed`` change then settles the intent, and the next press
    can open the case.

    Refusals: 404 ``campaign_not_found``; 409 ``no_case_pending``; 503
    ``audit_unavailable`` and ``store_unavailable``.
    """
    by = await identify_caller(request)
    audit = getattr(request.app.state, "audit", None)
    async with _case_lock(campaign_id), request.app.state.db_sessionmaker() as db:
        fresh = await campaign_svc.ensure_fresh(db, audit=audit)
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        state = await campaign_case.state_of(db, row)
        intent = state.open_intent
        if intent is None:
            raise api_error(409, "no_case_pending", "No press of this campaign waits on Try again.")
        held = dict(intent.detail or {})
        intent_id = str(held.get("intentId") or "")
        cleared = {
            "campaign_id": campaign_id,
            "intent_id": intent_id,
            "title": held.get("title"),
            "pressed_by": held.get("by"),
        }
        await db.rollback()
        try:
            if audit is not None:
                await audit.log_kind(
                    AUDIT_SESSION, "campaign_case_retry", cleared, user=by, mutating=True
                )
        except Exception as exc:
            _LOGGER.warning("campaign case: the retry record failed, nothing saved: %s", exc)
            raise api_error(
                503,
                "audit_unavailable",
                "soc-ai could not write the audit record, so the press still waits. "
                "Try again when the grid answers.",
            ) from exc
        db.add(
            decisions.change(
                campaign_id,
                decisions.CHANGE_CASE_FAILED,
                {
                    "reason": campaign_case.CLEARED_REASON,
                    "intentId": intent_id,
                    "by": by,
                    "cleared": True,
                },
                utcnow(),
            )
        )
        await commit_after_record(
            request, db, AUDIT_SESSION, "campaign_case_retry", cleared, by=by, action="retry"
        )
        return await _read_out(db, campaign_id, fresh=fresh)


__all__ = [
    "AttachPlan",
    "CampaignCaseRefOut",
    "CaseIn",
    "CaseScopeOut",
    "CaseSkippedOut",
    "attach_plan",
    "campaign_case_scope",
    "existing_out",
    "open_campaign_case",
    "pending_hint",
    "refusal_reason",
    "retry_campaign_case",
]
