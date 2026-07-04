"""Hunt console: hunt rows/detail/chat + starting hunts on alerts."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from soc_ai.api.deps import ctx_from_state, get_elastic, get_settings_dep
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.api.hunt_runner import sse_encode as hunt_sse_encode
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    _ago,
    _iso_utc,
    require_admin_api,
    router,
)
from soc_ai.api.webui._timeline import (
    TimelineStepOut,
    _compact,
    _tool_step,
)
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import get_dotted
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Hunt, HuntEvent
from soc_ai.webui import (
    hunt_console_manager,
    hunt_manager,
    timeline_labels,
)

_LOGGER = logging.getLogger(__name__)

# ── Hunts (Hunt Console) ─────────────────────────────────────────────────────
# A Hunt is broader than an Investigation: it correlates across hosts/time or a
# free-form objective and lands findings + a narrative (HuntReport), rather than
# a single-alert verdict. Read-only in this phase. The chat-driven hunt runs on
# the hunt agent (soc_ai.agent.hunt) via the HuntConsoleManager background task.


class HuntStatOut(BaseModel):
    label: str
    value: str
    sub: str
    tone: str


class HuntRowOut(BaseModel):
    id: str
    objective: str
    kind: str
    status: str
    findingCount: int = 0
    affectedHosts: int = 0
    confidence: float | None = None
    startedBy: str = ""
    when: str = ""
    ts: str = ""


# Hunt-timeline grouping. The hunt agent emits the same generic tool_call /
# tool_result / model_response kinds as the investigator, so the shared
# _tool_step / _compact formatters apply; only the group buckets differ.
_HUNT_TL_GROUP = {
    "hunt_started": "Objective",
    "tool_call": "Tool calls",
    "hunt_report": "Findings",
    "error": "Findings",
}
# chat_user/chat_assistant carry the follow-up "Chat about this hunt" thread —
# surfaced via GET /hunts/{id}/chat, NOT the execution timeline.
_HUNT_TL_SKIP = {"tool_result", "model_response", "done", "chat_user", "chat_assistant"}


class HuntFindingOut(BaseModel):
    title: str
    detail: str
    severity: str = "info"
    hosts: list[str] = []
    citations: list[str] = []


class HuntActionOut(BaseModel):
    title: str
    rationale: str


class HuntOut(BaseModel):
    id: str
    objective: str
    kind: str
    status: str
    narrative: str
    findings: list[HuntFindingOut] = []
    affectedHosts: list[str] = []
    mitreTechniques: list[str] = []
    recommendedActions: list[HuntActionOut] = []
    confidence: float = 0.0
    startedBy: str = ""
    elapsedLabel: str = ""
    elapsedSec: int = 0
    ts: str = ""
    timeline: list[TimelineStepOut] = []


_HUNT_STATUS = {
    "running": "running",
    "complete": "complete",
    "error": "error",
    "cancelled": "cancelled",
    "interrupted": "interrupted",
}


def _hunt_elapsed_sec(hunt: Hunt) -> int:
    created = hunt.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    end = hunt.finished_at or datetime.now(UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    return max(0, int((end - created).total_seconds()))


def _hunt_report(hunt: Hunt) -> dict[str, Any]:
    return hunt.report if isinstance(hunt.report, dict) else {}


def _hunt_row(hunt: Hunt) -> HuntRowOut:
    report = _hunt_report(hunt)
    findings = report.get("findings") or []
    return HuntRowOut(
        id=hunt.id,
        objective=hunt.objective,
        kind=hunt.kind,
        status=_HUNT_STATUS.get(hunt.status, "error"),
        findingCount=len(findings) if isinstance(findings, list) else 0,
        affectedHosts=len(report.get("affected_hosts") or []),
        confidence=report.get("confidence"),
        startedBy=hunt.started_by or "—",
        when=_ago(_iso_utc(hunt.created_at)),
        # tz-AWARE ISO so the browser localizes correctly (naive → parsed as local).
        ts=_iso_utc(hunt.created_at),
    )


def _build_hunt_timeline(events: list[HuntEvent]) -> list[TimelineStepOut]:
    """Reuse the shared tool-step formatter; bucket by the hunt group map."""
    result_by_call = {
        (e.payload or {}).get("tool_call_id"): (e.payload or {}).get("result")
        for e in events
        if e.kind == "tool_result"
    }
    timeline: list[TimelineStepOut] = []
    for e in events:
        if e.kind in _HUNT_TL_SKIP:
            continue
        p = e.payload or {}
        if e.kind == "tool_call":
            tn = str(p.get("tool_name", ""))
            result = result_by_call.get(p.get("tool_call_id"))
            title, detail = _tool_step(tn, p.get("args") or {}, result)
        elif e.kind == "hunt_started":
            title = "Objective"
            detail = _compact(p.get("objective") or "", 400)
        elif e.kind == "hunt_report":
            findings = p.get("findings") or []
            n = len(findings) if isinstance(findings, list) else 0
            title = f"Hunt report: {n} finding" + ("" if n == 1 else "s")
            detail = _compact(p.get("narrative") or "", 400)
        elif e.kind == "error":
            title = "Hunt failed"
            detail = _compact(p.get("message") or p.get("error") or "", 240)
        else:
            title = timeline_labels.title_for(e.kind, p)
            detail = _compact(p, 220)
        timeline.append(
            TimelineStepOut(
                id=f"h{e.sequence}",
                group=_HUNT_TL_GROUP.get(e.kind, "Tool calls"),
                title=title,
                detail=detail,
            )
        )
    return timeline


@router.get("/hunts", response_model=list[HuntRowOut])
async def list_hunts(
    request: Request, status: str | None = None, limit: int = 100
) -> list[HuntRowOut]:
    if status not in (None, "running", "complete", "error", "cancelled", "interrupted"):
        status = None
    async with request.app.state.db_sessionmaker() as db:
        rows = await hunt_svc.list_recent(db, status=status, limit=min(max(limit, 1), 500))
    return [_hunt_row(h) for h in rows]


@router.get("/hunts/stats", response_model=list[HuntStatOut])
async def hunt_stats(request: Request) -> list[HuntStatOut]:
    async with request.app.state.db_sessionmaker() as db:
        recent = await hunt_svc.list_recent(db, status=None, limit=500)
    total = len(recent)
    running = sum(1 for h in recent if h.status == "running")
    findings = sum(
        len(_hunt_report(h).get("findings") or []) for h in recent if h.status == "complete"
    )
    return [
        HuntStatOut(label="Hunts", value=str(total), sub="recent", tone="accent"),
        HuntStatOut(label="Findings", value=str(findings), sub="surfaced", tone="warn"),
        HuntStatOut(label="In progress", value=str(running), sub="running now", tone="sigma"),
    ]


@router.get("/hunts/{hunt_id}", response_model=HuntOut)
async def get_hunt(request: Request, hunt_id: str) -> HuntOut:
    async with request.app.state.db_sessionmaker() as db:
        got = await hunt_svc.get_with_events(db, hunt_id)
    if got is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    hunt, events = got
    report = _hunt_report(hunt)
    findings = report.get("findings") or []
    actions = report.get("recommended_actions") or []
    elapsed = _hunt_elapsed_sec(hunt)  # compute once, not four times inline below
    return HuntOut(
        id=hunt.id,
        objective=hunt.objective,
        kind=hunt.kind,
        status=_HUNT_STATUS.get(hunt.status, "error"),
        narrative=hunt.narrative or report.get("narrative") or "",
        findings=[
            HuntFindingOut(
                title=str(f.get("title") or ""),
                detail=str(f.get("detail") or ""),
                severity=str(f.get("severity") or "info"),
                hosts=[str(h) for h in (f.get("hosts") or [])],
                citations=[str(c) for c in (f.get("citations") or [])],
            )
            for f in findings
            if isinstance(f, dict)
        ],
        affectedHosts=[str(h) for h in (report.get("affected_hosts") or [])],
        mitreTechniques=[str(m) for m in (report.get("mitre_techniques") or [])],
        recommendedActions=[
            HuntActionOut(title=str(a.get("title") or ""), rationale=str(a.get("rationale") or ""))
            for a in actions
            if isinstance(a, dict)
        ],
        confidence=float(report.get("confidence") or 0.0),
        startedBy=hunt.started_by or "—",
        elapsedLabel=(f"{elapsed}s" if elapsed < 60 else f"{elapsed // 60}m {elapsed % 60}s"),
        elapsedSec=elapsed,
        # tz-AWARE ISO so the browser localizes correctly (naive → parsed as local).
        ts=_iso_utc(hunt.created_at),
        timeline=_build_hunt_timeline(events),
    )


class HuntChatIn(BaseModel):
    # Non-blank objective — an empty hunt objective is a no-op that would burn a
    # model call for nothing.
    objective: str = Field(min_length=1, max_length=2000)
    # Optional prior hunt id for a follow-up turn: its narrative seeds the new
    # hunt so the agent can pivot within the thread.
    prior_hunt_id: str | None = None


@router.post("/hunts/chat")
async def start_hunt_chat(request: Request, body: HuntChatIn) -> dict[str, str]:
    """Start a background chat-driven hunt; returns its id immediately.

    The Hunt Console UI opens the new hunt's detail and polls it live (mirrors
    the investigation-hunt POST /hunt flow). A dedicated SSE endpoint isn't used
    by the SPA because a POST can't drive an EventSource; the background drainer
    persists every event and the detail view polls the timeline.
    """
    started_by = await identify_caller(request)
    prior: str | None = None
    if body.prior_hunt_id:
        async with request.app.state.db_sessionmaker() as db:
            got = await hunt_svc.get_with_events(db, body.prior_hunt_id)
        if got is not None:
            prior_hunt, _ = got
            prior = prior_hunt.narrative or _hunt_report(prior_hunt).get("narrative")
    hunt_id = await hunt_console_manager.get_manager(request.app.state).start(
        request.app.state, objective=body.objective, started_by=started_by, prior=prior
    )
    if hunt_id is None:
        raise HTTPException(status_code=503, detail={"reason": "could_not_start"})
    return {"hunt_id": hunt_id}


@router.post("/hunts/chat/stream")
async def stream_hunt_chat(request: Request, body: HuntChatIn) -> EventSourceResponse:
    """Stream a chat-driven hunt as Server-Sent Events (mirror of /investigate).

    Each SSE message is ``event: {kind}`` / ``data: {json}``. The stream is teed
    into the hunts store so the run is persisted regardless of caller; the leading
    ``hunt_created`` event carries the new row's id. The SPA uses the poll-based
    ``POST /hunts/chat`` above (a POST can't drive an ``EventSource``); this route
    is the streaming interface for API/CLI callers that read the trace live.
    """
    started_by = await identify_caller(request)
    ctx = ctx_from_state(request.app.state)
    prior: str | None = None
    if body.prior_hunt_id:
        async with request.app.state.db_sessionmaker() as db:
            got = await hunt_svc.get_with_events(db, body.prior_hunt_id)
        if got is not None:
            prior_hunt, _ = got
            prior = prior_hunt.narrative or _hunt_report(prior_hunt).get("narrative")

    async def stream() -> Any:
        async for name, data in hunt_recorded_run(
            request.app.state,
            ctx=ctx,
            objective=body.objective,
            started_by=started_by,
            prior=prior,
        ):
            yield hunt_sse_encode(name, data)

    return EventSourceResponse(stream())


@router.post("/hunts/{hunt_id}/cancel")
async def cancel_hunt_chat(hunt_id: str, request: Request) -> dict[str, bool]:
    """Cancel an in-flight hunt (marks it ``cancelled``); 404 if none is live."""
    cancelled = hunt_console_manager.get_manager(request.app.state).cancel(hunt_id)
    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail={"reason": "no_live_hunt", "hint": "no in-flight hunt to cancel"},
        )
    return {"cancelled": True}


@router.delete("/hunts/{hunt_id}", dependencies=[Depends(require_admin_api)])
async def delete_hunt(hunt_id: str, request: Request) -> dict[str, bool]:
    """Delete a hunt and its events (admin only).

    For clearing broken/orphaned or no-longer-wanted hunts. Refuses to delete a
    still-``running`` hunt (409) — cancel it first — so its background drainer
    can't write rows back after the delete (mirrors delete_investigation).
    """
    async with request.app.state.db_sessionmaker() as db:
        hunt = await db.get(Hunt, hunt_id)
        if hunt is None:
            raise HTTPException(
                status_code=404, detail={"reason": "not_found", "hint": "hunt not found"}
            )
        if hunt.status == "running":
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "still_running",
                    "hint": "cancel the running hunt before deleting it",
                },
            )
        await hunt_svc.delete(db, hunt_id)
    return {"deleted": True}


# ── "Chat about this hunt" — read-only follow-up Q&A on a COMPLETED hunt ──────
#
# Mirrors the investigation follow-up chat (GET+POST /investigations/{id}/chat):
# a background turn writes a pending assistant row, the SPA polls the thread until
# !pending. The thread lives as hunt_events (keyed by the hunt id); the agent is
# the SAME read-only chat agent — no write tools, no Oracle, no verdict proposals
# (a hunt never acks/escalates).


class HuntChatMessageOut(BaseModel):
    role: str  # "user" | "assistant"
    text: str
    tools: str | None = None


class HuntChatThreadOut(BaseModel):
    messages: list[HuntChatMessageOut]
    pending: bool


def _hunt_chat_msg_out(ev: HuntEvent) -> HuntChatMessageOut:
    p = ev.payload or {}
    meta = p.get("meta") if isinstance(p.get("meta"), dict) else {}
    tool_names = (meta or {}).get("tools") or []
    tools = ", ".join(tool_names) if tool_names else None
    role = "user" if ev.kind == "chat_user" else "assistant"
    return HuntChatMessageOut(role=role, text=str(p.get("content") or ""), tools=tools)


def _hunt_chat_thread(events: list[HuntEvent]) -> HuntChatThreadOut:
    return HuntChatThreadOut(
        messages=[_hunt_chat_msg_out(e) for e in events],
        pending=any((e.payload or {}).get("status") == "pending" for e in events),
    )


@router.get("/hunts/{hunt_id}/chat", response_model=HuntChatThreadOut)
async def get_hunt_chat(request: Request, hunt_id: str) -> HuntChatThreadOut:
    """Poll target — the hunt's follow-up chat thread, with a pending flag while
    the assistant works."""
    async with request.app.state.db_sessionmaker() as db:
        if await db.get(Hunt, hunt_id) is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        msgs = await hunt_svc.list_chat_messages(db, hunt_id)
    return _hunt_chat_thread(msgs)


class HuntChatIn2(BaseModel):
    # Bound the follow-up turn: the value is stored and forwarded verbatim to the
    # LLM, so an unbounded body burns tokens / can blow the context window.
    message: str = Field(min_length=1, max_length=4000)


@router.post("/hunts/{hunt_id}/chat", response_model=HuntChatThreadOut)
async def post_hunt_chat(request: Request, hunt_id: str, body: HuntChatIn2) -> HuntChatThreadOut:
    """Ask a follow-up about a COMPLETED hunt. Writes the user turn + a pending
    assistant turn, spawns the background chat task, and returns the thread (poll
    GET .../chat until !pending). Read-only — a hunt chat never acks/escalates."""
    text = body.message.strip()
    if not text:
        raise HTTPException(status_code=400, detail={"reason": "empty_message"})
    async with request.app.state.db_sessionmaker() as db:
        hunt = await db.get(Hunt, hunt_id)
        if hunt is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if hunt.status == "running":
            # Can't chat about a hunt that hasn't landed its report yet.
            raise HTTPException(status_code=409, detail={"reason": "still_running"})
        existing = await hunt_svc.list_chat_messages(db, hunt_id)
        if any((e.payload or {}).get("status") == "pending" for e in existing):
            # A prior turn's assistant is still working — one in-flight turn at a
            # time, or a second POST orphans a duplicate pending row.
            raise HTTPException(status_code=409, detail={"reason": "chat_busy"})
        await hunt_svc.add_chat_user_message(db, hunt_id, text)
        pending = await hunt_svc.create_pending_chat_assistant(db, hunt_id)
        msgs = await hunt_svc.list_chat_messages(db, hunt_id)
    hunt_console_manager.get_chat_manager(request.app.state).start(
        request.app.state, hunt_id=hunt_id, assistant_event_id=pending.id
    )
    return _hunt_chat_thread(msgs)


# ── Mutations ──────────────────────────────────────────────────────────────
# CSRF: these are same-origin (the SPA at /app calls /api/v1) and the session
# cookie is SameSite=lax, which blocks cross-site cookie-bearing POSTs — the same
# protection the existing /approve JSON route relies on.


class HuntStartIn(BaseModel):
    # Non-blank: an empty id reaches ES as `ids:[""]` and 500s ("Ids can't be empty").
    alert_id: str = Field(min_length=1)


async def resolve_alert_for_hunt(
    elastic: ElasticClient, settings: Settings, alert_id: str
) -> tuple[bool, str | None]:
    """Resolve ``alert_id`` to ``(exists, rule_name)`` in one ES lookup.

    Mirrors the ``ids`` lookup ``get_alert_context`` does before fanning out
    pivots. Used to guard ``/hunt`` so a bad id (e.g. an AlertGroup whose
    ``latest_id`` was empty and fell back to the rule NAME, see alerts_query.py
    ``_group_from_bucket`` + the ``id=g.latest_id or g.rule_name`` mapping)
    fails VISIBLY with a 4xx instead of recording a synthetic 0.0 investigation.

    Returns the doc's ``rule.name`` (falling back to ``event.dataset`` /
    ``event.category`` for non-Suricata detections) so the caller can seed the
    investigation's display name at creation — the row is then never anonymous,
    even if the run dies before its first alert_context event.
    """
    lookup = await elastic.search(
        settings.events_index_pattern,
        {"ids": {"values": [alert_id]}},
        size=1,
    )
    if not lookup.hits:
        return False, None
    source = lookup.hits[0].get("_source", {})
    name = (
        get_dotted(source, "rule.name")
        or get_dotted(source, "event.dataset")
        or get_dotted(source, "event.category")
    )
    return True, str(name) if name else None


@router.post("/hunt")
async def start_hunt(
    request: Request,
    body: HuntStartIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> dict[str, str]:
    """Start a background investigation for an alert; returns its id immediately.

    The supplied ``alert_id`` must resolve to a real ES document. A group whose
    ``latest_id`` was blank surfaces its RULE NAME as the id (webui_api mapping
    ``g.latest_id or g.rule_name``); hunting that would otherwise SoNotFoundError
    deep in the prefetch and silently persist a degraded needs_more_info/0.0
    investigation. We resolve up front and 404 instead.
    """
    started_by = await identify_caller(request)
    exists, rule_name = await resolve_alert_for_hunt(elastic, settings, body.alert_id)
    if not exists:
        raise HTTPException(
            status_code=404,
            detail={
                "reason": "alert_not_found",
                "hint": ("alert not found — it may have aged out; re-open from the alerts list"),
            },
        )
    # Block a duplicate hunt: if one is already running for this alert, send the
    # caller to it instead of spawning a second investigation for the same alert.
    async with request.app.state.db_sessionmaker() as db:
        existing = (await inv_svc.latest_for_alerts(db, [body.alert_id])).get(body.alert_id)
    if existing is not None and existing.status == "running":
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "hunt_in_progress",
                "running_inv_id": existing.id,
                "hint": (
                    "a hunt is already running for this alert — open it or cancel "
                    "it before starting a new one"
                ),
            },
        )
    inv_id = await hunt_manager.get_manager(request.app.state).start(
        request.app.state, alert_id=body.alert_id, started_by=started_by, rule_name=rule_name
    )
    if inv_id is None:
        raise HTTPException(status_code=503, detail={"reason": "could_not_start"})
    return {"investigation_id": inv_id}
