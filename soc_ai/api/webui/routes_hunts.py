"""Hunt console: hunt rows/detail/chat + starting hunts on alerts."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
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
from soc_ai.demo.hunt_replay import pick_canned_hunt, start_background_hunt_replay
from soc_ai.demo.replay import find_replay, start_background_replay
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import get_dotted
from soc_ai.so_client.inventory import discover_datasets
from soc_ai.store import hunt_schedules as hs_svc
from soc_ai.store import hunt_templates as ht_svc
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Hunt, HuntEvent, HuntSchedule, HuntTemplate
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
    # Follow-up chat messages on this hunt — lets the list show a chat badge
    # (same affordance as the investigations list).
    chatCount: int = 0


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
# citation_validation is the E1.3 post-hunt gate's bookkeeping count (per-hunt
# tally of capped findings / stripped citations) — an audit record, not a hunt
# trace step, so it is skipped from the timeline (the validator's effect shows on
# the findings themselves via validatorNote).
_HUNT_TL_SKIP = {
    "tool_result",
    "model_response",
    "done",
    "chat_user",
    "chat_assistant",
    "citation_validation",
}


class HuntFindingOut(BaseModel):
    title: str
    detail: str
    severity: str = "info"
    # 'threat' | 'visibility_gap' | 'observation' — drives the disposition
    # headline (only THREAT findings may read as malicious/suspicious activity).
    category: str = "threat"
    hosts: list[str] = []
    citations: list[str] = []
    # Set by the E1.3 post-hunt citation gate when it stripped non-resolving
    # citations or capped the severity (mirrors InvestigationOut.validatorNote).
    validatorNote: str | None = None


# Legacy reports predate the finding `category` field. A coverage/visibility
# finding mis-read as a threat produces the trust-destroying "Malicious activity
# found" headline over a telemetry gap, so infer the gap category for old rows.
_GAP_TITLE_RE = re.compile(
    r"visibility gap|telemetry|coverage gap|blind spot|no .*(logs|logging|data)|"
    r"data.source.* (absent|missing|unavailable)",
    re.IGNORECASE,
)


def _finding_category(f: dict[str, Any]) -> str:
    raw = str(f.get("category") or "").strip().lower()
    if raw in ("threat", "visibility_gap", "observation"):
        return raw
    return "visibility_gap" if _GAP_TITLE_RE.search(str(f.get("title") or "")) else "threat"


# Charts are stored inside the report dict already validated (the post-hunt chart
# gate dropped any that didn't resolve). Serialize defensively — a malformed
# stored point is skipped, never 500s the detail response — and drop a chart that
# ended up with no plottable series.
_CHART_KINDS = ("bar", "line", "timeline")


def _chart_point_out(p: Any) -> HuntChartPointOut | None:
    if not isinstance(p, dict):
        return None
    y = p.get("y")
    if y is None:
        return None
    try:
        return HuntChartPointOut(x=str(p.get("x") or ""), y=float(y))
    except (TypeError, ValueError):
        return None


def _chart_out(c: dict[str, Any]) -> HuntChartOut | None:
    kind = str(c.get("kind") or "").strip().lower()
    if kind not in _CHART_KINDS:
        return None
    series = [pt for p in (c.get("series") or []) if (pt := _chart_point_out(p)) is not None]
    if not series:  # nothing to plot — don't ship an empty chart
        return None
    return HuntChartOut(
        kind=kind,
        title=str(c.get("title") or ""),
        xLabel=str(c.get("x_label") or ""),
        yLabel=str(c.get("y_label") or ""),
        series=series,
        sourceCitations=[str(s) for s in (c.get("source_citations") or [])],
    )


class HuntActionOut(BaseModel):
    title: str
    rationale: str


class HuntChartPointOut(BaseModel):
    x: str
    y: float


class HuntChartOut(BaseModel):
    # Mirrors soc_ai.agent.hunt.HuntChart. Only charts that SURVIVED the E3.3
    # post-hunt chart gate (source_citations resolved to gathered evidence) are
    # serialized here — an invented series is dropped upstream and never reaches
    # the client.
    kind: str  # 'bar' | 'line' | 'timeline'
    title: str
    xLabel: str = ""
    yLabel: str = ""
    series: list[HuntChartPointOut] = []
    sourceCitations: list[str] = []


class HuntDiffEntryOut(BaseModel):
    # A single finding in a diff bucket — kept light: just enough to render the
    # "vs last run" strip's expandable list (title + severity + category).
    title: str
    severity: str = "info"
    category: str = "threat"


class HuntDiffOut(BaseModel):
    # The finding-level diff of THIS hunt vs the previous COMPLETE run of the same
    # objective (same objective_hash). ``new`` = findings with no match in the
    # prior run; ``persisting`` = findings that matched a prior finding;
    # ``resolved`` = prior findings with no match in this run. Present only when a
    # previous completed run exists (else HuntOut.diff is None).
    new: list[HuntDiffEntryOut] = []
    persisting: list[HuntDiffEntryOut] = []
    resolved: list[HuntDiffEntryOut] = []
    # The baseline run the diff is against (for the "· vs run from {ago}" label).
    previousHuntId: str = ""
    previousTs: str = ""
    previousWhen: str = ""


class HuntOut(BaseModel):
    id: str
    objective: str
    kind: str
    status: str
    narrative: str
    findings: list[HuntFindingOut] = []
    charts: list[HuntChartOut] = []
    affectedHosts: list[str] = []
    mitreTechniques: list[str] = []
    recommendedActions: list[HuntActionOut] = []
    confidence: float = 0.0
    startedBy: str = ""
    elapsedLabel: str = ""
    elapsedSec: int = 0
    ts: str = ""
    timeline: list[TimelineStepOut] = []
    # "vs last run" finding-level diff — None when this is the first run of the
    # objective (no prior COMPLETE run with the same objective_hash to diff).
    diff: HuntDiffOut | None = None


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


def _hunt_row(hunt: Hunt, chat_count: int = 0) -> HuntRowOut:
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
        chatCount=chat_count,
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


def _naive_utc(dt: datetime | None) -> datetime | None:
    """Normalize an (optionally tz-aware) query datetime to naive UTC.

    Stored timestamps are naive UTC (``store.auth.utcnow``); comparing them
    against a tz-aware bound is wrong on Postgres and undefined on SQLite
    (string-compared), so convert to UTC and strip the offset first.
    """
    if dt is None or dt.tzinfo is None:
        return dt
    return dt.astimezone(UTC).replace(tzinfo=None)


@router.get("/hunts", response_model=list[HuntRowOut])
async def list_hunts(
    request: Request,
    status: str | None = None,
    limit: int = 100,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[HuntRowOut]:
    """Hunt rows, newest first. ``since``/``until`` (ISO datetimes) bound
    ``created_at`` inclusively on both ends; absent params keep the original
    unbounded behavior. An unparseable datetime is a 422 (FastAPI-validated)."""
    if status not in (None, "running", "complete", "error", "cancelled", "interrupted"):
        status = None
    async with request.app.state.db_sessionmaker() as db:
        rows = await hunt_svc.list_recent(
            db,
            status=status,
            limit=min(max(limit, 1), 500),
            since=_naive_utc(since),
            until=_naive_utc(until),
        )
        chat_counts = await hunt_svc.chat_counts_for(db, [h.id for h in rows])
    return [_hunt_row(h, chat_counts.get(h.id, 0)) for h in rows]


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


# ── E3.4: hunt diffing ("what changed since the last run of this objective") ──
#
# Finding identity is a FUZZY match on (normalized title + hosts set): a finding
# is the "same" finding across two runs when its normalized title AND its set of
# hosts match. Normalization is forgiving of case/whitespace/punctuation so a
# minor re-word doesn't spuriously flip persisting↔new, but two genuinely
# distinct findings (different hosts, or a different title) stay distinct.

_FINDING_PUNCT_RE = re.compile(r"[^a-z0-9\s]+")
_FINDING_WS_RE = re.compile(r"\s+")


def _norm_title(title: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace — the title half of a
    finding's fuzzy identity."""
    low = _FINDING_PUNCT_RE.sub(" ", str(title or "").strip().lower())
    return _FINDING_WS_RE.sub(" ", low).strip()


def _finding_identity(f: dict[str, Any]) -> tuple[str, frozenset[str]]:
    """A finding's fuzzy identity key: (normalized title, sorted hosts set).

    Hosts are lowercased + de-duplicated into a frozenset so host ORDER never
    matters and ["A","B"] == ["b","a"]. Two findings are the "same" finding iff
    their identities are equal.
    """
    hosts = frozenset(str(h).strip().lower() for h in (f.get("hosts") or []) if str(h).strip())
    return _norm_title(f.get("title") or ""), hosts


def _diff_entry(f: dict[str, Any]) -> HuntDiffEntryOut:
    return HuntDiffEntryOut(
        title=str(f.get("title") or ""),
        severity=str(f.get("severity") or "info"),
        category=_finding_category(f),
    )


def _compute_hunt_diff(
    current: list[dict[str, Any]],
    previous: list[dict[str, Any]],
    prev_hunt: Hunt,
) -> HuntDiffOut:
    """Finding-level diff of ``current`` vs ``previous`` findings (both raw dicts).

    O(n·m) over small finding lists — fine. A current finding is ``persisting``
    if a previous finding shares its fuzzy identity, else ``new``; a previous
    finding with no match in the current run is ``resolved``.
    """
    prev_ids = [_finding_identity(f) for f in previous]
    prev_matched = [False] * len(previous)

    new: list[HuntDiffEntryOut] = []
    persisting: list[HuntDiffEntryOut] = []
    for f in current:
        ident = _finding_identity(f)
        match_idx = next(
            (i for i, pid in enumerate(prev_ids) if pid == ident and not prev_matched[i]),
            None,
        )
        if match_idx is None:
            new.append(_diff_entry(f))
        else:
            prev_matched[match_idx] = True
            persisting.append(_diff_entry(f))

    resolved = [_diff_entry(previous[i]) for i, hit in enumerate(prev_matched) if not hit]

    prev_ts = _iso_utc(prev_hunt.created_at)
    return HuntDiffOut(
        new=new,
        persisting=persisting,
        resolved=resolved,
        previousHuntId=prev_hunt.id,
        previousTs=prev_ts,
        previousWhen=_ago(prev_ts),
    )


@router.get("/hunts/{hunt_id}", response_model=HuntOut)
async def get_hunt(request: Request, hunt_id: str) -> HuntOut:
    diff: HuntDiffOut | None = None
    async with request.app.state.db_sessionmaker() as db:
        got = await hunt_svc.get_with_events(db, hunt_id)
        if got is not None:
            hunt, _ = got
            # Diff vs the previous COMPLETE run of the same objective. Only a
            # completed current hunt has settled findings worth diffing.
            if hunt.status == "complete":
                prev = await hunt_svc.previous_completed_run(
                    db,
                    objective_hash=hunt.objective_hash,
                    before_created_at=hunt.created_at,
                    exclude_id=hunt.id,
                )
                if prev is not None:
                    cur_findings = [
                        f for f in (_hunt_report(hunt).get("findings") or []) if isinstance(f, dict)
                    ]
                    prev_findings = [
                        f for f in (_hunt_report(prev).get("findings") or []) if isinstance(f, dict)
                    ]
                    diff = _compute_hunt_diff(cur_findings, prev_findings, prev)
    if got is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    hunt, events = got
    report = _hunt_report(hunt)
    findings = report.get("findings") or []
    charts = report.get("charts") or []
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
                category=_finding_category(f),
                hosts=[str(h) for h in (f.get("hosts") or [])],
                citations=[str(c) for c in (f.get("citations") or [])],
                validatorNote=f.get("validator_note") or None,
            )
            for f in findings
            if isinstance(f, dict)
        ],
        charts=[out for c in charts if isinstance(c, dict) and (out := _chart_out(c)) is not None],
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
        diff=diff,
    )


class HuntChatIn(BaseModel):
    # Non-blank objective — an empty hunt objective is a no-op that would burn a
    # model call for nothing.
    objective: str = Field(min_length=1, max_length=2000)
    # Optional prior hunt id for a follow-up turn: its narrative seeds the new
    # hunt so the agent can pivot within the thread.
    prior_hunt_id: str | None = None


@router.post("/hunts/chat")
async def start_hunt_chat(
    request: Request,
    body: HuntChatIn,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, str]:
    """Start a background chat-driven hunt; returns its id immediately.

    The Hunt Console UI opens the new hunt's detail and polls it live (mirrors
    the investigation-hunt POST /hunt flow). A dedicated SSE endpoint isn't used
    by the SPA because a POST can't drive an EventSource; the background drainer
    persists every event and the detail view polls the timeline.
    """
    started_by = await identify_caller(request)
    # Demo mode (SOC_AI_DEMO): replay a RECORDED canned hunt instead of building
    # the egress-blocked hunt agent — returns a real hunt_id the SPA polls exactly
    # like a live hunt, and the row lands complete WITH its narrative + report.
    # Zero egress: HuntRecorder writes the store only, no model is built. Mirrors
    # the investigation replay branch in start_hunt (POST /hunt) above. With no
    # eventful/reportful canned hunt seeded (rare once fixtures are rebuilt), fall
    # through to the live path (unchanged): hunt_recorded_run emits hunt_created —
    # creating the row and returning a real hunt_id with a 200 — BEFORE run_hunt
    # builds the egress-blocked model, so the row then lands status='error' in the
    # background drain (not a 503). Same reporting a live hunt-start had in demo
    # before this branch existed.
    if settings.soc_ai_demo:
        hunt = pick_canned_hunt(getattr(request.app.state, "demo_fixtures", None))
        if hunt is not None:
            hid = await start_background_hunt_replay(
                request.app.state, body.objective, started_by, hunt
            )
            if hid is None:
                raise HTTPException(status_code=503, detail={"reason": "could_not_start"})
            return {"hunt_id": hid}
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


# ── Bulk hunt actions (re-hunt / delete selected) ────────────────────────────
#
# Mirrors routes_investigations.py::bulk_rehunt, with one CRITICAL difference:
# a re-hunt is a CLEAN re-run of the objective — it starts a fresh hunt via the
# same path as a brand-new hunt (``hunt_console_manager.start(objective=…)`` with
# ``prior=None``), NEVER seeding the prior hunt's (possibly broken) narrative.
# Seeding a failed/partial run's narrative as a follow-up turn would poison the
# re-run; the objective_hash still matches, so the fresh run automatically gets
# the "vs last run" diff.
#
# CONCURRENCY GUARD: ``hunt_console_manager.start()`` is FIRE-AND-FORGET — it
# spawns one unbounded background ``asyncio.Task`` per call with no queue or
# semaphore (see soc_ai.webui.hunt_console_manager.HuntConsoleManager). Launching
# every selected hunt at once would put N concurrent hunts on the single model
# route; a real incident showed 7 simultaneous hunts all hitting the wall-clock
# and producing garbage. So the bulk endpoint starts at most ``_REHUNT_START_CAP``
# hunts per call and skips the rest with reason ``"queued"`` (re-hunt them in a
# smaller batch once these land) — it does NOT silently fire the whole selection.

_REHUNT_CAP = 50
# How many hunts a single bulk re-hunt actually STARTS. The rest are returned as
# skipped/"queued" so the operator re-hunts them in a follow-up batch — bounding
# concurrent load on the one model route (the 7-concurrent-hunts garbage incident).
_REHUNT_START_CAP = 3


class HuntRehuntIn(BaseModel):
    # Cap at the input boundary so an oversized payload is rejected before the
    # dedup loop deserializes/iterates it (mirrors RehuntIn on investigations).
    hunt_ids: list[str] = Field(max_length=_REHUNT_CAP)


class HuntRehuntResultOut(BaseModel):
    started: list[dict[str, str]]  # [{old_id, new_id, objective}]
    skipped: list[dict[str, str]]  # [{id, reason}]


@router.post("/hunts/rehunt", response_model=HuntRehuntResultOut)
async def bulk_rehunt(request: Request, body: HuntRehuntIn) -> HuntRehuntResultOut:
    """Re-run each supplied hunt as a CLEAN fresh hunt of the same objective.

    Deduplicates the input (order-preserving). The ``_REHUNT_CAP`` input cap is
    enforced by request validation (``HuntRehuntIn.hunt_ids`` ``max_length``, so
    an oversized request 422s before reaching here). A hunt that is unknown is
    skipped ``"not_found"``; one currently ``running`` is skipped ``"running"``
    (nothing to re-run yet — cancel/let it finish first). To bound concurrent
    load on the single model route, at most ``_REHUNT_START_CAP`` hunts are
    actually STARTED; any eligible ids past that cap are skipped ``"queued"`` so
    the operator re-hunts them in a smaller follow-up batch.

    A re-hunt starts via the same path as a brand-new hunt (``prior=None``) — it
    NEVER seeds the prior hunt's narrative, so a failed/partial run's broken
    narrative can't poison the re-run. The objective_hash still matches, so the
    fresh run automatically gets the "vs last run" diff.
    """
    started_by = await identify_caller(request)
    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique_ids: list[str] = []
    for hunt_id in body.hunt_ids:
        if hunt_id not in seen:
            seen.add(hunt_id)
            unique_ids.append(hunt_id)

    started: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    # Fetch all rows in a SINGLE query (no N+1), then re-run in input order.
    hunt_by_id: dict[str, Hunt] = {}
    if unique_ids:
        async with request.app.state.db_sessionmaker() as db:
            rows = (await db.scalars(select(Hunt).where(Hunt.id.in_(unique_ids)))).all()
            hunt_by_id = {h.id: h for h in rows}

    manager = hunt_console_manager.get_manager(request.app.state)
    for hunt_id in unique_ids:
        hunt = hunt_by_id.get(hunt_id)
        if hunt is None:
            skipped.append({"id": hunt_id, "reason": "not_found"})
            continue
        if hunt.status == "running":
            skipped.append({"id": hunt_id, "reason": "running"})
            continue
        # Concurrency guard: only start up to _REHUNT_START_CAP hunts this call —
        # the manager is fire-and-forget with no internal limit, so the cap lives
        # here. Ids past the cap are eligible but deferred ("queued").
        if len(started) >= _REHUNT_START_CAP:
            skipped.append({"id": hunt_id, "reason": "queued"})
            continue
        # CLEAN re-run: fresh-start path, NO prior seeding (prior defaults None).
        new_id = await manager.start(
            request.app.state, objective=hunt.objective, started_by=started_by
        )
        if new_id is None:
            skipped.append({"id": hunt_id, "reason": "could_not_start"})
            continue
        started.append({"old_id": hunt_id, "new_id": new_id, "objective": hunt.objective})

    return HuntRehuntResultOut(started=started, skipped=skipped)


class HuntBulkDeleteIn(BaseModel):
    hunt_ids: list[str] = Field(max_length=_REHUNT_CAP)


class HuntBulkDeleteResultOut(BaseModel):
    deleted: list[str]
    not_found: list[str]


@router.post("/hunts/bulk-delete", dependencies=[Depends(require_admin_api)])
async def bulk_delete_hunts(request: Request, body: HuntBulkDeleteIn) -> HuntBulkDeleteResultOut:
    """Delete each supplied hunt (admin — mirrors the single DELETE /hunts/{id}).

    Deduplicates the input (order-preserving). Each id is removed via the store's
    ``delete`` (hunt + events + chat projection, one transaction); a row that
    isn't there is reported in ``not_found`` rather than failing the batch. A
    still-``running`` hunt is NOT deleted — its background drainer could write
    rows back after the delete (same guard the single DELETE enforces with a 409)
    — and is reported in ``not_found`` so the caller re-lists it; the bulk UI only
    selects terminal rows, so this is the belt-and-braces path.
    """
    seen: set[str] = set()
    unique_ids: list[str] = []
    for hunt_id in body.hunt_ids:
        if hunt_id not in seen:
            seen.add(hunt_id)
            unique_ids.append(hunt_id)

    deleted: list[str] = []
    not_found: list[str] = []
    async with request.app.state.db_sessionmaker() as db:
        for hunt_id in unique_ids:
            hunt = await db.get(Hunt, hunt_id)
            if hunt is None:
                not_found.append(hunt_id)
                continue
            # Refuse a still-running hunt (its drainer can still write rows) —
            # report it as not-removed via not_found so the caller re-lists.
            if hunt.status == "running":
                not_found.append(hunt_id)
                continue
            if await hunt_svc.delete(db, hunt_id):
                deleted.append(hunt_id)
            else:
                not_found.append(hunt_id)
    return HuntBulkDeleteResultOut(deleted=deleted, not_found=not_found)


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
# protection the other /api/v1 JSON mutation routes rely on.


class HuntStartIn(BaseModel):
    # Non-blank: an empty id reaches ES as `ids:[""]` and 500s ("Ids can't be empty").
    alert_id: str = Field(min_length=1)
    # Force the full tool-driven loop for THIS run (the drawer's "deep re-run"
    # of a heuristic verdict). Ignored by the demo replay path.
    deep: bool = False


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
    # Demo mode (SOC_AI_DEMO): replay this alert's RECORDED run instead of a live
    # one — no ES resolve, no LLM. An alert with no recording reports through the
    # SAME 404 below (a recording-less alert IS an unknown alert to the demo), and
    # the 409 duplicate-guard / 503 / response contract are shared unchanged.
    demo_replay = None
    if settings.soc_ai_demo:
        demo_replay = find_replay(getattr(request.app.state, "demo_fixtures", None), body.alert_id)
        exists, rule_name = demo_replay is not None, None
    else:
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
    if demo_replay is not None:
        inv_id = await start_background_replay(
            request.app.state, replay=demo_replay, started_by=started_by
        )
    else:
        inv_id = await hunt_manager.get_manager(request.app.state).start(
            request.app.state,
            alert_id=body.alert_id,
            started_by=started_by,
            rule_name=rule_name,
            deep=body.deep,
        )
    if inv_id is None:
        raise HTTPException(status_code=503, detail={"reason": "could_not_start"})
    return {"investigation_id": inv_id}


# ── E3.1: scheduled hunts (recurring hunts on an interval) ────────────────────
#
# A HuntSchedule row is one recurring hunt: an objective re-run every
# ``intervalMinutes`` by ``soc_ai.main._hunt_schedule_loop`` when the
# ``hunt_schedules_enabled`` master switch is on. Reads are analyst-readable;
# mutate is admin-gated (mirrors the runbook CRUD). Interval is MINUTES (not cron)
# and floored at the store's sane minimum — full cron is deliberately YAGNI.


class HuntScheduleIn(BaseModel):
    objective: str = Field(min_length=1, max_length=2000)
    interval_minutes: int = Field(
        default=hs_svc.MIN_INTERVAL_MINUTES, ge=hs_svc.MIN_INTERVAL_MINUTES, le=43200
    )
    enabled: bool = True


class HuntSchedulePatch(BaseModel):
    """All fields optional — only the provided ones are updated."""

    objective: str | None = Field(default=None, min_length=1, max_length=2000)
    interval_minutes: int | None = Field(default=None, ge=hs_svc.MIN_INTERVAL_MINUTES, le=43200)
    enabled: bool | None = None


class HuntScheduleOut(BaseModel):
    id: int
    objective: str
    intervalMinutes: int
    enabled: bool
    lastRunAt: str | None = None
    createdBy: str
    createdAt: str


def _schedule_out(row: HuntSchedule) -> HuntScheduleOut:
    return HuntScheduleOut(
        id=row.id,
        objective=row.objective,
        intervalMinutes=row.interval_minutes,
        enabled=row.enabled,
        lastRunAt=_iso_utc(row.last_run_at) if row.last_run_at is not None else None,
        createdBy=row.created_by,
        createdAt=_iso_utc(row.created_at),
    )


@router.get("/hunt-schedules", response_model=list[HuntScheduleOut])
async def list_hunt_schedules(request: Request) -> list[HuntScheduleOut]:
    """All recurring hunt schedules, most-recently-created first (analyst-readable)."""
    async with request.app.state.db_sessionmaker() as db:
        rows = await hs_svc.list_all(db)
    return [_schedule_out(r) for r in rows]


@router.post(
    "/hunt-schedules",
    response_model=HuntScheduleOut,
    dependencies=[Depends(require_admin_api)],
)
async def create_hunt_schedule(request: Request, body: HuntScheduleIn) -> HuntScheduleOut:
    """Create a recurring hunt schedule (admin)."""
    created_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        row = await hs_svc.create(
            db,
            objective=body.objective,
            interval_minutes=body.interval_minutes,
            enabled=body.enabled,
            created_by=created_by,
        )
    return _schedule_out(row)


@router.put(
    "/hunt-schedules/{schedule_id}",
    response_model=HuntScheduleOut,
    dependencies=[Depends(require_admin_api)],
)
async def update_hunt_schedule(
    request: Request, schedule_id: int, body: HuntSchedulePatch
) -> HuntScheduleOut:
    """Update a schedule's fields (admin). 404 if it doesn't exist."""
    async with request.app.state.db_sessionmaker() as db:
        row = await hs_svc.update(
            db,
            schedule_id,
            objective=body.objective,
            interval_minutes=body.interval_minutes,
            enabled=body.enabled,
        )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found", "hint": "no hunt schedule with that id"},
        )
    return _schedule_out(row)


@router.delete(
    "/hunt-schedules/{schedule_id}",
    dependencies=[Depends(require_admin_api)],
)
async def delete_hunt_schedule(request: Request, schedule_id: int) -> dict[str, bool]:
    """Delete a schedule (admin). 404 if it doesn't exist."""
    async with request.app.state.db_sessionmaker() as db:
        ok = await hs_svc.delete(db, schedule_id)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found", "hint": "no hunt schedule with that id"},
        )
    return {"deleted": True}


# ── E3.2: hunt template library (curated, telemetry-filtered hunt starters) ───
#
# A HuntTemplate is a REUSABLE hunt objective the operator picks to seed a new
# hunt — the evolution of the Hunt Console's six static "canned pill" strings.
# ``GET /hunt-templates`` annotates each with ``available``/``missingDatasets``
# against the LIVE, TTL-cached grid inventory: a template needing telemetry the
# grid lacks renders FLAGGED ("missing telemetry: zeek.rdp"), NEVER hidden —
# honesty over hiding. Reads are analyst-readable; custom-template mutate is
# admin-gated (mirrors the runbook/schedule CRUD). Deleting a builtin is refused
# (409); custom templates delete freely.


class HuntTemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    objective_template: str = Field(min_length=1, max_length=2000)
    # The `event.dataset` names this hunt correlates over — a grid missing one
    # flags the template. Bounded so a custom template can't carry a runaway list.
    required_datasets: list[str] = Field(default_factory=list, max_length=32)
    default_window_minutes: int = Field(default=1440, ge=1, le=43200)


class HuntTemplatePatch(BaseModel):
    """All fields optional — only the provided ones are updated."""

    name: str | None = Field(default=None, min_length=1, max_length=256)
    objective_template: str | None = Field(default=None, min_length=1, max_length=2000)
    required_datasets: list[str] | None = Field(default=None, max_length=32)
    default_window_minutes: int | None = Field(default=None, ge=1, le=43200)


class HuntTemplateOut(BaseModel):
    id: int
    name: str
    objectiveTemplate: str
    requiredDatasets: list[str]
    defaultWindowMinutes: int
    builtin: bool
    createdBy: str
    createdAt: str
    # Availability annotation vs the live grid inventory (E3.2's whole point):
    # ``available`` is False iff any requiredDataset is absent from the grid;
    # ``missingDatasets`` lists exactly which telemetry is absent. On an inventory
    # DISCOVERY failure both default to available/[] — we never HIDE (or falsely
    # flag) a template on an inventory error.
    available: bool = True
    missingDatasets: list[str] = []


def _template_out(row: HuntTemplate, present: set[str] | None) -> HuntTemplateOut:
    """Serialize a template, annotating availability against ``present`` dataset names.

    ``present is None`` means the inventory couldn't be discovered — the template
    is reported ``available=True, missingDatasets=[]`` (best-effort: an inventory
    error must never hide or falsely flag a template).
    """
    required = [str(d) for d in (row.required_datasets or [])]
    if present is None:
        missing: list[str] = []
    else:
        missing = [d for d in required if d not in present]
    return HuntTemplateOut(
        id=row.id,
        name=row.name,
        objectiveTemplate=row.objective_template or "",
        requiredDatasets=required,
        defaultWindowMinutes=row.default_window_minutes,
        builtin=row.builtin,
        createdBy=row.created_by,
        createdAt=_iso_utc(row.created_at),
        available=not missing,
        missingDatasets=missing,
    )


async def _present_dataset_names(request: Request) -> set[str] | None:
    """The set of `event.dataset` names live on the grid, or ``None`` on failure.

    Reuses the TTL-cached :func:`discover_datasets` (300s) — annotating the whole
    template list is ONE inventory read, not one per template. Best-effort: any
    discovery failure returns ``None`` so the caller reports every template
    available rather than hiding them on an inventory error.
    """
    try:
        elastic = request.app.state.elastic
        settings = request.app.state.settings
        inv = await discover_datasets(elastic, settings)
    except Exception:
        _LOGGER.warning("hunt-template availability: inventory discovery failed", exc_info=True)
        return None
    return set(inv.dataset_names())


@router.get("/hunt-templates", response_model=list[HuntTemplateOut])
async def list_hunt_templates(request: Request) -> list[HuntTemplateOut]:
    """All hunt templates, builtins first, ANNOTATED with grid availability.

    Each template is flagged ``available``/``missingDatasets`` against the live
    (TTL-cached) grid inventory: a template needing telemetry this grid doesn't
    have is FLAGGED, never hidden. The inventory is read ONCE for the whole list.
    """
    present = await _present_dataset_names(request)
    async with request.app.state.db_sessionmaker() as db:
        rows = await ht_svc.list_all(db)
    return [_template_out(r, present) for r in rows]


@router.post(
    "/hunt-templates",
    response_model=HuntTemplateOut,
    dependencies=[Depends(require_admin_api)],
)
async def create_hunt_template(request: Request, body: HuntTemplateIn) -> HuntTemplateOut:
    """Save a custom hunt template (admin; always ``builtin=False``)."""
    created_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        row = await ht_svc.create(
            db,
            name=body.name,
            objective_template=body.objective_template,
            required_datasets=body.required_datasets,
            default_window_minutes=body.default_window_minutes,
            builtin=False,
            created_by=created_by,
        )
    # Annotate the freshly-created row too (cheap — the inventory is TTL-cached).
    present = await _present_dataset_names(request)
    return _template_out(row, present)


@router.put(
    "/hunt-templates/{template_id}",
    response_model=HuntTemplateOut,
    dependencies=[Depends(require_admin_api)],
)
async def update_hunt_template(
    request: Request, template_id: int, body: HuntTemplatePatch
) -> HuntTemplateOut:
    """Update a template's fields (admin). 404 if it doesn't exist; 409 on a builtin.

    A builtin's content is code-owned (re-seeded every startup), so editing one
    through the API would silently revert on the next restart — refuse it instead.
    """
    async with request.app.state.db_sessionmaker() as db:
        existing = await ht_svc.get(db, template_id)
        if existing is None:
            raise HTTPException(
                status_code=404,
                detail={"reason": "not_found", "hint": "no hunt template with that id"},
            )
        if existing.builtin:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "builtin_immutable",
                    "hint": "builtin templates are code-owned; save a custom template instead",
                },
            )
        row = await ht_svc.update(
            db,
            template_id,
            name=body.name,
            objective_template=body.objective_template,
            required_datasets=body.required_datasets,
            default_window_minutes=body.default_window_minutes,
        )
    present = await _present_dataset_names(request)
    assert row is not None  # existed above + same session; narrow for mypy
    return _template_out(row, present)


@router.delete(
    "/hunt-templates/{template_id}",
    dependencies=[Depends(require_admin_api)],
)
async def delete_hunt_template(request: Request, template_id: int) -> dict[str, bool]:
    """Delete a CUSTOM template (admin). 404 if none; 409 refusing a builtin.

    Builtin templates are code-owned (re-seeded on every startup) — deleting one
    would just resurrect it next restart, so refuse it (the picker flags an
    unavailable builtin rather than removing it anyway). Only custom
    (``builtin=False``) templates delete.
    """
    async with request.app.state.db_sessionmaker() as db:
        existing = await ht_svc.get(db, template_id)
        if existing is None:
            raise HTTPException(
                status_code=404,
                detail={"reason": "not_found", "hint": "no hunt template with that id"},
            )
        if existing.builtin:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "builtin_undeletable",
                    "hint": "builtin templates are code-owned and cannot be deleted",
                },
            )
        await ht_svc.delete(db, template_id)
    return {"deleted": True}
