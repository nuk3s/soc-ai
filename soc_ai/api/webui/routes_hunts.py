"""Hunt console: hunt rows/detail/chat + starting hunts on alerts."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Sequence
from datetime import UTC, datetime, time, timedelta
from typing import Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sse_starlette.sse import EventSourceResponse

from soc_ai.agent.context import HuntSubject, build_hunt_subject
from soc_ai.agent.prompts import FocusOrigin
from soc_ai.api.deps import ctx_from_state, get_elastic, get_settings_dep
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.api.hunt_runner import sse_encode as hunt_sse_encode
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import (
    _ago,
    _iso_utc,
    observation_source,
    require_admin_api,
    router,
)
from soc_ai.api.webui._timeline import (
    TimelineStepOut,
    _compact,
    _tool_step,
)
from soc_ai.api.webui.kind_labels import kind_label
from soc_ai.api.webui.routes_alerts import _es_api_error_http, _grid_unavailable
from soc_ai.config import Settings
from soc_ai.demo.guard import is_demo
from soc_ai.demo.hunt_replay import pick_canned_hunt
from soc_ai.demo.replay import find_replay, start_background_replay
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import get_dotted
from soc_ai.so_client.inventory import discover_datasets
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store import hunt_schedules as hs_svc
from soc_ai.store import hunt_templates as ht_svc
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import (
    Hunt,
    HuntEvent,
    HuntSchedule,
    HuntTemplate,
    Investigation,
    Lead,
)
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


# One sentence for the three places a console refuses to start a run. The
# console returns None when no model is reachable or the manager is saturated,
# and "could_not_start" alone sent the second dogfood to the server log.
_COULD_NOT_START_HINT = (
    "The console did not start the run. Check the model gateway on the Config screen."
)


def _could_not_start() -> HTTPException:
    return api_error(503, "could_not_start", _COULD_NOT_START_HINT)


def _lead_not_found(lead_id: int) -> HTTPException:
    return api_error(
        404,
        "lead_not_found",
        f"No lead has the id {lead_id}. The Hunts page lists the open leads.",
    )


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
    # Findings that claim a threat, and how the hunt ended. A hunt whose only
    # finding is the record that it could not run is not "Complete · 1
    # finding": six rows read that way on one screen in the second dogfood.
    threatFindingCount: int = 0
    outcome: str = ""
    # The words the list prints for that outcome. Computed here so the bell,
    # the list and the dossier all say "No threat observed · visibility gap".
    # The screen had its own wording and a gap read as "No telemetry" on one
    # surface and as a finding on another.
    outcome_label: str = ""
    affectedHosts: int = 0
    confidence: float | None = None
    startedBy: str = ""
    # The class that started the hunt: analyst, schedule, lead or catalog.
    # startedBy keeps the actor name. A lead-started hunt names its lead.
    starter: str = "analyst"
    leadId: int | None = None
    when: str = ""
    ts: str = ""
    # Follow-up chat messages on this hunt — lets the list show a chat badge
    # (same affordance as the investigations list).
    chatCount: int = 0
    # Migration 0032's synthetic-evaluation marker: this hunt ran against
    # PLANTED synthetic attack scenarios. Surfaced wherever the row is
    # displayed — the SPA badges it so a planted attack can never be read as
    # real activity.
    isSynthEval: bool = False


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


class HuntFindingInvOut(BaseModel):
    id: str
    status: str  # running | complete | error | cancelled | interrupted
    verdict: str | None  # true_positive | false_positive | needs_more_info | inconclusive | None
    conf: float | None


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
    # A CATALOG finding's detail is two things joined: the spec's prose, written
    # when the detection was authored, and this run's result. Read as one
    # paragraph the author's measurements pass for fresh ones, so the page sets
    # them apart — and it used to find the seam by matching the sentence a
    # candidate finding ends with, which no visibility-gap finding contains.
    # ``soc_ai.hunting.findings`` knows where the seam is and now says so:
    # ``specRationale`` is the authored half, always the head of ``detail``.
    # Null for a model's finding, which has no authored half, and for a hunt
    # recorded before the composer carried it.
    specRationale: str | None = None
    # Documents the candidate matched, for the "3 of 4 matching documents" note
    # beside the citation chips. Null on a gap finding, which counted no
    # candidate documents, and on a model's finding.
    matchedDocs: int | None = None
    # Promotion state: the newest investigation promoted from this finding, or
    # null when never promoted. An errored/cancelled promotion frees the slot
    # (mirrors the promotion route's idempotency), so the UI shows Investigate
    # again — status is included so the card can tell running from complete.
    investigation: HuntFindingInvOut | None = None


# The classifier lives in soc_ai.hunting.findings so the notifications bell and
# this page cannot disagree about what a gap is.
from soc_ai.hunting.findings import finding_category as _finding_category  # noqa: E402
from soc_ai.hunting.findings import threat_finding_count  # noqa: E402
from soc_ai.hunting.wording import reword_legacy_summary  # noqa: E402


def _finding_rationale(f: dict[str, Any]) -> str | None:
    """The authored half of a catalog finding's detail, or None.

    Checked against the detail rather than trusted: the two are separate keys
    in a stored JSON document, and cutting the detail on a prefix it does not
    start with would drop text the analyst is meant to read. A mismatch renders
    whole, which is what a model's finding does anyway.
    """
    rationale = str(f.get("spec_rationale") or "").strip()
    if not rationale:
        return None
    detail = str(f.get("detail") or "").strip()
    return rationale if detail.startswith(rationale) and detail != rationale else None


def _finding_matched_docs(f: dict[str, Any]) -> int | None:
    matched = f.get("matched_docs")
    if isinstance(matched, bool) or not isinstance(matched, int) or matched < 0:
        return None
    return matched


def _finding_inv_out(inv: Investigation | None) -> HuntFindingInvOut | None:
    """A finding's promotion-state card, or None when never promoted.

    ``status`` reuses ``_HUNT_STATUS`` (declared further down, same five-value
    vocabulary an Investigation and a Hunt share) rather than
    ``routes_investigations._row_status``: that module already imports THIS one
    (for the hunt-kind guards), so importing back would cycle. ``verdict`` is
    passed through RAW — unlike ``_verdict`` (which coerces None to the display
    sentinel "untriaged" for the investigations list), a promoted-but-undecided
    finding must stay a genuine ``null`` here so the client can tell "no verdict
    yet" from an actual untriaged badge.
    """
    if inv is None:
        return None
    return HuntFindingInvOut(
        id=inv.id,
        status=_HUNT_STATUS.get(inv.status, "error"),
        verdict=inv.verdict,
        conf=inv.confidence,
    )


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
    # None when the report carries no confidence at all, which is the catalog
    # path: ``spec_report`` omits the key on purpose (a predicate matched or it
    # did not). Coercing that to 0.0 here made the detail page read "the
    # system has zero confidence in this" and forced the page to infer "no
    # model ran" from the actor. Same nullability as HuntRowOut, so the list
    # and the detail say the same thing about the same report.
    confidence: float | None = None
    startedBy: str = ""
    elapsedLabel: str = ""
    elapsedSec: int = 0
    ts: str = ""
    timeline: list[TimelineStepOut] = []
    # "vs last run" finding-level diff — None when this is the first run of the
    # objective (no prior COMPLETE run with the same objective_hash to diff).
    diff: HuntDiffOut | None = None
    # Synthetic-evaluation marker (migration 0032) — see HuntRowOut.isSynthEval.
    isSynthEval: bool = False


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


def _report_confidence(report: dict[str, Any]) -> float | None:
    """The report's confidence as stored, or None when it has none.

    One reader for both the list row and the detail, so a report with no
    confidence (the catalog path) is absent on both rather than absent on one
    and 0.0 on the other. A stored 0.0 is a measurement and comes back as 0.0.
    """
    value = report.get("confidence")
    return None if value is None else float(value)


def _hunt_outcome(status: str, findings: Any) -> tuple[int, str]:
    """(threat findings, outcome) for a hunt row.

    ``outcome`` is empty unless the hunt completed; then ``threats``, ``clean``,
    ``gap`` (the precondition saw no telemetry) or ``failed`` (a query raised).
    The last two are the ones the list must not paint green.
    """
    if not isinstance(findings, list):
        return 0, ""
    rows = [f for f in findings if isinstance(f, dict)]
    threats = threat_finding_count(rows)
    if status != "complete":
        return threats, ""
    if threats:
        return threats, "threats"
    gaps = [f for f in rows if _finding_category(f) == "visibility_gap"]
    if not gaps:
        return 0, "clean"
    failed = any(str(f.get("title") or "").endswith(": could not run") for f in gaps)
    return 0, "failed" if failed else "gap"


# One phrase per outcome, written once. Section 6 of the 1.5.1 design names
# the gap outcome "No threat observed · visibility gap" and every surface has
# to use that phrase.
OUTCOME_LABEL: dict[str, str] = {
    "threats": "Threat findings",
    "clean": "No threat observed",
    "gap": "No threat observed · visibility gap",
    "failed": "Could not run",
}

# The bell says the same thing about the same hunt.
GAP_NOTIFICATION_TITLE = f"Hunt finished: {OUTCOME_LABEL['gap'].lower()}"


def _hunt_row(hunt: Hunt, chat_count: int = 0) -> HuntRowOut:
    report = _hunt_report(hunt)
    findings = report.get("findings") or []
    status = _HUNT_STATUS.get(hunt.status, "error")
    threats, outcome = _hunt_outcome(status, findings)
    return HuntRowOut(
        id=hunt.id,
        objective=hunt.objective,
        kind=hunt.kind,
        status=status,
        findingCount=len(findings) if isinstance(findings, list) else 0,
        threatFindingCount=threats,
        outcome=outcome,
        outcome_label=OUTCOME_LABEL.get(outcome, ""),
        affectedHosts=len(report.get("affected_hosts") or []),
        confidence=_report_confidence(report),
        startedBy=hunt.started_by or "—",
        starter=str(hunt.starter or "analyst"),
        leadId=hunt.lead_id,
        when=_ago(_iso_utc(hunt.created_at)),
        # tz-AWARE ISO so the browser localizes correctly (naive → parsed as local).
        ts=_iso_utc(hunt.created_at),
        chatCount=chat_count,
        isSynthEval=bool(hunt.is_synth_eval),
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


# The hunt list and the Hunt Console subtitle count agent runs: analyst,
# schedule, lead. A catalog run is a recorded analytic hit, not an agent run.
_AGENT_RUN_EXCLUDES: tuple[str, ...] = ("triggered",)


@router.get("/hunts", response_model=list[HuntRowOut])
async def list_hunts(
    request: Request,
    status: str | None = None,
    kind: str | None = None,
    limit: int = 100,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[HuntRowOut]:
    """Hunt rows, newest first. ``kind`` narrows to chat | scheduled | triggered
    | lead (an unknown value is ignored, like an unknown ``status``). ``since``/``until``
    (ISO datetimes) bound ``created_at`` inclusively on both ends; absent params
    keep the original unbounded behavior. An unparseable datetime is a 422
    (FastAPI-validated).

    A list with no ``kind`` holds the runs an agent made. It leaves out the
    catalog runs, the rows the sweep recorded for each analytic hit before
    1.5.0. A hit is an observation and the Analytic hits section shows it.
    ``kind=triggered`` still lists those rows, so a bookmark still works."""
    if status not in (None, "running", "complete", "error", "cancelled", "interrupted"):
        status = None
    if kind not in (None, "chat", "scheduled", "triggered", "lead"):
        kind = None
    async with request.app.state.db_sessionmaker() as db:
        rows = await hunt_svc.list_recent(
            db,
            status=status,
            kind=kind,
            exclude_kinds=() if kind else _AGENT_RUN_EXCLUDES,
            limit=min(max(limit, 1), 500),
            since=_naive_utc(since),
            until=_naive_utc(until),
        )
        chat_counts = await hunt_svc.chat_counts_for(db, [h.id for h in rows])
    return [_hunt_row(h, chat_counts.get(h.id, 0)) for h in rows]


@router.get("/hunts/stats", response_model=list[HuntStatOut])
async def hunt_stats(request: Request) -> list[HuntStatOut]:
    """The counts the Hunt Console subtitle reads. Agent runs only."""
    async with request.app.state.db_sessionmaker() as db:
        recent = await hunt_svc.list_recent(
            db, status=None, exclude_kinds=_AGENT_RUN_EXCLUDES, limit=500
        )
    total = len(recent)
    running = sum(1 for h in recent if h.status == "running")
    findings = sum(
        len(_hunt_report(h).get("findings") or []) for h in recent if h.status == "complete"
    )
    return [
        HuntStatOut(label="Hunts", value=str(total), sub="recent", tone="accent"),
        HuntStatOut(label="Findings", value=str(findings), sub="recorded", tone="warn"),
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
    inv_map: dict[int, Investigation] = {}
    async with request.app.state.db_sessionmaker() as db:
        got = await hunt_svc.get_with_events(db, hunt_id)
        if got is not None:
            hunt, _ = got
            # Per-finding promotion state (newest investigation per ordinal) —
            # the card's Investigate/Investigating…/Open state.
            inv_map = await inv_svc.latest_per_finding(db, hunt_id)
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
                specRationale=_finding_rationale(f),
                matchedDocs=_finding_matched_docs(f),
                investigation=_finding_inv_out(inv_map.get(i)),
            )
            for i, f in enumerate(findings)
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
        confidence=_report_confidence(report),
        startedBy=hunt.started_by or "—",
        elapsedLabel=(f"{elapsed}s" if elapsed < 60 else f"{elapsed // 60}m {elapsed % 60}s"),
        elapsedSec=elapsed,
        # tz-AWARE ISO so the browser localizes correctly (naive → parsed as local).
        ts=_iso_utc(hunt.created_at),
        timeline=_build_hunt_timeline(events),
        diff=diff,
        isSynthEval=bool(hunt.is_synth_eval),
    )


# Objective length cap, shared by the console, schedules and templates (the same
# analyst-written text lands in all three). Raised 2000 -> 12000 (dogfood
# 2026-08-06): 2000 chars is about one paragraph, and a real hunt brief — scope,
# exclusions, the specific behaviors to look for — routinely runs longer. It was
# rejected with a bare 422. Still bounded: the objective is prepended to the
# agent's prompt, so an unbounded paste would eat the context budget.
MAX_OBJECTIVE_CHARS = 12000


class HuntChatIn(BaseModel):
    # Non-blank objective — an empty hunt objective is a no-op that would burn a
    # model call for nothing.
    objective: str = Field(min_length=1, max_length=MAX_OBJECTIVE_CHARS)
    # Optional prior hunt id for a follow-up turn: its narrative seeds the new
    # hunt so the agent can pivot within the thread.
    prior_hunt_id: str | None = None
    # The starter this objective came from. It is read for ONE thing: the
    # analytics the starter names, which the start path renders into the
    # objective. The objective itself still arrives as text, so an analyst who
    # edited the starter's wording gets what they typed.
    template_id: int | None = None


# The window a starter's analytics run over. Seven days is wide enough for a
# weekly pattern and narrow enough to stay inside one sweep's cost.
STARTER_ANALYTIC_WINDOW_DAYS = 7


def _objective_with_analytics(objective: str, analytic_ids: list[str]) -> str:
    """Prepend the starter's analytics to the objective it will run under.

    The objective is the agent's prompt. Naming the analytics there is how a
    starter steers the first tool call. A starter that names none is unchanged.
    """
    ids = [a for a in analytic_ids if a]
    if not ids:
        return objective
    return (
        "First run these analytics with t_run_analytic over the last "
        f"{STARTER_ANALYTIC_WINDOW_DAYS} days: " + ", ".join(ids) + ". "
        "Investigate every entity they return. Then: " + objective
    )


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
    # Demo mode (SOC_AI_DEMO): return the SEEDED canned hunt's own id — a read, not
    # a write. That hunt is already a complete store row (seed_fixtures at startup)
    # carrying the narrative + timeline + report a run would produce, so the SPA
    # polls GET /hunts/{id} and renders a finished hunt. No new Hunt row and no
    # background task per POST: the hunt-side mirror of routes_chat._demo_thread,
    # which is what keeps an unauthenticated visitor from growing the Hunt table
    # (and the replay-task set) without bound. Finding:
    # demo-readonly-contract-violated-by-hunt-start. With no reportful canned hunt
    # seeded (not the shipped demo shape) fall through to the live path unchanged.
    if settings.soc_ai_demo:
        hunt = pick_canned_hunt(getattr(request.app.state, "demo_fixtures", None))
        hid = hunt.get("id") if hunt else None
        if hid is not None:
            return {"hunt_id": str(hid)}
    prior: str | None = None
    if body.prior_hunt_id:
        async with request.app.state.db_sessionmaker() as db:
            got = await hunt_svc.get_with_events(db, body.prior_hunt_id)
        if got is not None:
            prior_hunt, _ = got
            prior = prior_hunt.narrative or _hunt_report(prior_hunt).get("narrative")
    objective = body.objective
    if body.template_id is not None:
        async with request.app.state.db_sessionmaker() as db:
            tpl = await ht_svc.get(db, body.template_id)
        objective = _objective_with_analytics(objective, tpl.analytics if tpl else [])
    hunt_id = await hunt_console_manager.get_manager(request.app.state).start(
        request.app.state, objective=objective, started_by=started_by, prior=prior
    )
    if hunt_id is None:
        raise _could_not_start()
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
            detail={
                "reason": "no_live_hunt",
                "hint": "No hunt is running, so there is nothing to cancel.",
            },
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
                    "hint": "Cancel the running hunt before you delete it.",
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
    # Tools the in-flight turn has called so far, oldest first — the hunt-chat
    # mirror of ``ChatThreadOut.progress_tools`` (routes_chat.py). The SPA's
    # HuntChatPanel renders it as a live progress footer during a long follow-up
    # instead of a bare typing indicator. Empty unless a turn is pending.
    progress_tools: list[str] = []


def _hunt_chat_msg_out(ev: HuntEvent) -> HuntChatMessageOut:
    p = ev.payload or {}
    meta = p.get("meta") if isinstance(p.get("meta"), dict) else {}
    tool_names = (meta or {}).get("tools") or []
    tools = ", ".join(tool_names) if tool_names else None
    role = "user" if ev.kind == "chat_user" else "assistant"
    return HuntChatMessageOut(role=role, text=str(p.get("content") or ""), tools=tools)


def _hunt_chat_thread(events: list[HuntEvent]) -> HuntChatThreadOut:
    # Read live progress off the pending assistant row's meta, the same shape
    # the general/host chat expose (routes_chat.py:_thread). The shared turn
    # engine writes it there via ``hunt_svc.set_progress``.
    pending_evs = [e for e in events if (e.payload or {}).get("status") == "pending"]
    progress: list[str] = []
    if pending_evs:
        meta = (pending_evs[-1].payload or {}).get("meta")
        if isinstance(meta, dict):
            raw = meta.get("progress_tools")
            if isinstance(raw, list):
                progress = [str(t) for t in raw]
    return HuntChatThreadOut(
        messages=[_hunt_chat_msg_out(e) for e in events],
        pending=bool(pending_evs),
        progress_tools=progress,
    )


def _demo_hunt_chat_thread(text: str, reply: str) -> HuntChatThreadOut:
    """One ephemeral turn — the visitor's question and the canned *reply*.

    The hunt chat's twin of :func:`soc_ai.api.webui.routes_chat._demo_thread`,
    and it exists for the same reason: on the public demo ``api_auth_required``
    is false, so every visitor is the same caller, and this thread is keyed on a
    hunt they ALL share. Persisted, that means visitor two reads visitor one's
    typed question and can be handed a 409 ``chat_busy`` from a turn they did not
    start. There is no per-browser identity to key on instead (no cookie is
    issued without a login, and anything client-supplied would be
    attacker-chosen), so the demo stores nothing at all: no rows, nothing to
    collide over, and the property holds under concurrency by construction.

    The visitor still sees a working conversation — the SPA renders the thread
    this POST returns. Only persistence across a reload is lost, which a canned
    reply should arguably not have.

    Not shared with ``routes_chat._demo_thread`` because the wire types differ:
    this surface serializes ``HuntChatMessageOut`` (which carries ``tools``) off
    ``hunt_events``, not ``ChatMessageOut`` off ``chat_messages``.
    """
    return HuntChatThreadOut(
        messages=[
            HuntChatMessageOut(role="user", text=text),
            # Sourced from the manager so the demo has ONE answer for this
            # surface, not two that can drift; the manager keeps its own
            # short-circuit as the backstop for any future path that does spawn a
            # turn (it must never build a model — the demo egress guard raises).
            HuntChatMessageOut(role="assistant", text=reply),
        ],
        pending=False,
    )


@router.get("/hunts/{hunt_id}/chat", response_model=HuntChatThreadOut)
async def get_hunt_chat(request: Request, hunt_id: str) -> HuntChatThreadOut:
    """Poll target — the hunt's follow-up chat thread, with a pending flag while
    the assistant works.

    On the public demo it is always empty — see :func:`_demo_hunt_chat_thread`.
    """
    async with request.app.state.db_sessionmaker() as db:
        if await db.get(Hunt, hunt_id) is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if is_demo(request.app.state.settings):
            # Empty rather than a read of the shared thread — kept AFTER the 404
            # so a bogus hunt id still 404s as it does live. Returning empty
            # unconditionally makes "no visitor sees another's messages" a
            # property of this route instead of a bet on the table having stayed
            # empty.
            return _hunt_chat_thread([])
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
    GET .../chat until !pending). Read-only — a hunt chat never acks/escalates.

    On the public demo it neither writes nor spawns anything — see
    :func:`_demo_hunt_chat_thread`.
    """
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
        if is_demo(request.app.state.settings):
            # AFTER the 404/still-running checks, so the demo rejects the same
            # requests a real deployment does — it answers differently, it does
            # not validate differently. Before the busy check and the writes,
            # which are the two that cross demo visitors.
            return _demo_hunt_chat_thread(
                text, hunt_console_manager.demo_chat_reply(request.app.state, hunt_id)
            )
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

    Grid errors PROPAGATE, and every caller both BOUNDS this call in
    ``asyncio.timeout(webui_grid_timeout_s)`` and maps the error onto the house
    503/400. Neither belongs in here. The outage must never leave as the 404
    "alert not found" this returns for a genuinely absent alert — "I could not
    look" is not "not there" — and an unbounded caller holds Investigate, the
    most-clicked button in the product, for the ES client's whole retry budget
    (~90 s at shipped defaults) against an accepting-but-silent grid.
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
        try:
            async with asyncio.timeout(settings.webui_grid_timeout_s):
                exists, rule_name = await resolve_alert_for_hunt(elastic, settings, body.alert_id)
        except (TimeoutError, TransportError) as exc:
            # A down grid is a retryable 503, never the 404 below: telling the
            # analyst "alert not found — it may have aged out" when the sensor is
            # simply unreadable is a statement about their estate we cannot make.
            raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
        except ApiError as exc:
            # An ES ApiError is NOT a TransportError — without this arm an ES 4xx
            # still escapes the tuple above as an unhandled 500.
            raise _es_api_error_http(exc) from exc
    if not exists:
        raise HTTPException(
            status_code=404,
            detail={
                "reason": "alert_not_found",
                "hint": (
                    "The alert is not on the grid. It may have aged out. Re-open it "
                    "from the alerts list."
                ),
            },
        )
    # Block a duplicate hunt: if one is already running for this alert, send the
    # caller to it instead of spawning a second investigation for the same alert.
    async with request.app.state.db_sessionmaker() as db:
        existing = (await inv_svc.latest_for_alerts(db, [body.alert_id])).get(body.alert_id)
        # Reuse decision keys off ANY completed replay row for this alert, not the
        # newest row of any status — otherwise an `error` row left by a mid-stream
        # /investigate abort becomes "latest" and defeats reuse (same guard the
        # /investigate path uses).
        completed = await inv_svc.complete_for_alert(db, body.alert_id)
    if existing is not None and existing.kind == "hunt":
        # Promotion already owns this doc as a finding's anchor — an ad-hoc
        # POST /hunt against the same alert_id would mint an unlabeled
        # kind='suricata' duplicate and re-enable SO writes on an event a
        # promoted finding already claims. Re-promotion from the hunt page is
        # the sanctioned re-run (mirrors bulk_rehunt/request_more_info, 4fbe8132).
        # An alert_id promotion never touched (existing is None, or its latest
        # row isn't kind='hunt') is unaffected — this only fires once
        # promotion owns the latest row for the doc.
        hunt_kind_detail: dict[str, str] = {
            "reason": "hunt_kind_no_rerun",
            "hint": (
                "This event is a promoted finding's anchor. Re-promote the finding from its hunt."
            ),
        }
        # The row this guard is blocking a re-run of may itself still be
        # running — carry its id the same way the hunt_in_progress branch
        # below does, so a caller that only checks for a deep-link (not the
        # specific reason) doesn't lose it to this guard firing first.
        if existing.status == "running":
            hunt_kind_detail["running_inv_id"] = existing.id
        raise HTTPException(status_code=409, detail=hunt_kind_detail)
    if existing is not None and existing.status == "running":
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "hunt_in_progress",
                "running_inv_id": existing.id,
                "hint": (
                    "A hunt is already running for this alert. Open it, or cancel it "
                    "before you start a new one."
                ),
            },
        )
    # Demo replay: reuse this alert's already-completed replay row instead of
    # persisting a fresh one per POST. The SPA polls GET /investigations/{id}, so
    # the row must exist — returning the completed one (no new row, no background
    # task) bounds demo replay rows to the recorded-alert set, the read-only
    # mirror the hunt-start path already uses. The first replay per alert (no
    # existing complete row) still creates it below.
    if demo_replay is not None and completed is not None:
        return {"investigation_id": completed.id}
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
        raise _could_not_start()
    return {"investigation_id": inv_id}


# ── Task 5: promote a hunt finding into an investigation of its cited evidence ──
# Not in the demo write-allowlist (main.py `_DEMO_WRITE_ALLOW*`) — a public demo
# has no recorded replay for a promoted finding, so the read-only middleware
# refuses it with the standard demo_mode 403 before this handler ever runs. No
# demo branch belongs here.

# Detector-flag datasets: an anchor from these is another detector's CLAIM, not
# raw telemetry — prefer any cited telemetry doc over them (a promoted finding
# should be investigated from its evidence).
_DETECTOR_DATASETS = {"suricata.alert", "sigma.alert", "zeek.notice"}
# Long-alphanumeric citation shapes only — prose citations can't be ES ids.
_ID_SHAPED = re.compile(r"^[A-Za-z0-9_\-:.]{12,128}$")


async def _resolve_finding_anchor(
    elastic: ElasticClient, settings: Settings, citations: list[str]
) -> str | None:
    """Pick the finding's anchor doc: the cited ES id the promoted
    investigation runs against. Citation order is preserved within each class;
    telemetry beats detector docs. None when nothing resolves.

    Only ``event.dataset`` is read from each hit (the telemetry-vs-detector
    call), so the lookup asks for exactly that field — never full ``_source``
    — and caps the id list: a pathological report with hundreds of citations
    must not turn one anchor pick into a bulk document fetch."""
    ids = [c for c in citations if _ID_SHAPED.match(c)][:100]
    if not ids:
        return None
    lookup = await elastic.search(
        settings.events_index_pattern,
        {"ids": {"values": ids}},
        size=len(ids),
        source=["event.dataset"],
    )
    hits = list(lookup.hits or [])
    if not hits:
        return None
    by_id = {h.get("_id"): h for h in hits}
    ordered = [by_id[i] for i in ids if i in by_id]
    for h in ordered:
        ds = str(get_dotted(h.get("_source", {}), "event.dataset") or "").lower()
        if ds not in _DETECTOR_DATASETS:
            return h.get("_id")
    return ordered[0].get("_id")


def _anchor_from_subject(subject: HuntSubject) -> str | None:
    """The anchor document of a hunt-subject run, from the documents the
    subject already holds.

    Same rule as :func:`_resolve_finding_anchor`: the promoted finding's
    documents come first and telemetry beats a detector's claim. No second
    grid read, because the subject builder fetched these documents already.
    """
    for doc in subject.documents:
        if str(doc.event_dataset or "").lower() not in _DETECTOR_DATASETS:
            return doc.id
    return subject.documents[0].id if subject.documents else None


async def _hunt_subject_for(
    request: Request,
    *,
    settings: Settings,
    elastic: ElasticClient,
    hunt_id: str,
    finding_ordinal: int | None = None,
    lead_id: int | None = None,
    related_leads: Sequence[dict[str, Any]] | None = None,
) -> HuntSubject:
    """Build the subject of a promoted investigation: the hunt as a whole.

    One grid read, under the same timeout and with the same grid-failure
    answers as the anchor resolution, so a promotion has one refusal shape.
    """
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            async with request.app.state.db_sessionmaker() as db:
                return await build_hunt_subject(
                    db,
                    elastic=elastic,
                    settings=settings,
                    hunt_id=hunt_id,
                    finding_ordinal=finding_ordinal,
                    lead_id=lead_id,
                    related_leads=related_leads,
                )
    except (TimeoutError, TransportError) as exc:
        # The 503 body names the failure class. The log names the failure.
        _LOGGER.warning("hunt subject for hunt %s: grid read failed: %r", hunt_id, exc)
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        raise _es_api_error_http(exc) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail={"reason": "not_found"}) from exc


async def _start_promotion(
    request: Request,
    *,
    settings: Settings,
    elastic: ElasticClient,
    started_by: str,
    title: str,
    detail: str,
    hosts: list[str],
    citations: list[str],
    kind: str,
    hunt_id: str | None,
    finding_ordinal: int | None,
    focus_origin: FocusOrigin,
    is_synth_eval: bool,
    subject: HuntSubject | None = None,
) -> str:
    """Start an investigation of the hunt and return its id.

    A hunt finding and a lead both promote through this function. One path
    means one anchor rule, one grid-failure shape and one focus block.

    ``subject`` (D2) carries the hunt. The run reads the hunt's objective, its
    findings and every document they cite. The anchor is still one document,
    because the pipeline anchors its time windows on one timestamp, but the
    subject of the verdict is the hunt.
    """
    anchor_id = _anchor_from_subject(subject) if subject is not None else None
    if anchor_id is None:
        try:
            async with asyncio.timeout(settings.webui_grid_timeout_s):
                anchor_id = await _resolve_finding_anchor(elastic, settings, citations)
        except (TimeoutError, TransportError) as exc:
            raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
        except ApiError as exc:
            raise _es_api_error_http(exc) from exc
    if anchor_id is None:
        raise HTTPException(
            status_code=422,
            detail={
                "reason": "no_promotable_evidence",
                "hint": "None of the citations resolve to an event on the grid.",
            },
        )
    host_text = ", ".join(hosts) or "—"
    if subject is not None:
        focus = (
            f"Promoted {focus_origin.replace('_', ' ')}: {title}. {detail} Hosts involved: "
            f"{host_text}. The subject of this investigation is the hunt, not one event. "
            "Answer the hunt's objective. Do not assume the framing is correct."
        )
    else:
        focus = (
            f"Promoted {focus_origin.replace('_', ' ')}: {title}. {detail} Hosts involved: "
            f"{host_text}. This investigation targets the cited evidence event. Assess whether "
            "the activity is malicious. Do not assume the framing is correct."
        )
    inv_id = await hunt_manager.get_manager(request.app.state).start(
        request.app.state,
        alert_id=anchor_id,
        started_by=started_by,
        rule_name=title,
        focus_hint=focus,
        kind=kind,
        hunt_id=hunt_id,
        finding_ordinal=finding_ordinal,
        # A promoted anchor is cited telemetry, not an SO alert — no unattended
        # write can ever apply to it — and its focus text is the promoter's own
        # framing, not a prior investigation's open questions.
        allow_so_writes=False,
        focus_origin=focus_origin,
        is_synth_eval=is_synth_eval,
        subject=subject,
    )
    if inv_id is None:
        raise _could_not_start()
    return inv_id


@router.post("/hunts/{hunt_id}/findings/{ordinal}/investigate")
async def promote_finding(
    request: Request,
    hunt_id: str,
    ordinal: int,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> dict[str, Any]:
    """Promote one hunt finding into a full investigation of the hunt.

    The finding is the reason the analyst pressed the button and its documents
    are read first, but the subject is the hunt: its objective, all of its
    findings and every document they cite. Idempotent: while a promotion for
    this exact finding is running or landed a verdict, re-posting returns it;
    only an errored/cancelled one frees the slot.

    ``ordinal`` is the finding's index into ``hunt.report["findings"]`` — the
    FastAPI ``int`` path convertor already refuses a negative segment with a
    bare 404 before this body runs, so the ``0 <= ordinal`` check below only
    has to catch a positive ordinal past the end of the list.
    """
    started_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        hunt = await db.get(Hunt, hunt_id)
        if hunt is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if hunt.status == "running":
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "still_running",
                    "hint": (
                        "The hunt is still running. Findings promote after it lands its report."
                    ),
                },
            )
        findings = _hunt_report(hunt).get("findings") or []
        if not (0 <= ordinal < len(findings)) or not isinstance(findings[ordinal], dict):
            raise HTTPException(
                status_code=404,
                detail={
                    "reason": "finding_not_found",
                    "hint": "That finding is not in this hunt's report.",
                },
            )
        finding = findings[ordinal]
        # Captured inside the session: a synth-eval hunt's finding is planted
        # evidence, so the promoted investigation must inherit the marker or a
        # planted attack could later be read back as a real verdict.
        hunt_is_synth_eval = bool(hunt.is_synth_eval)
        # The lead that started this hunt, when one did. Its observations and
        # its document ids join the subject, so a lead hunt is investigated
        # with the evidence that formed the lead in front of the model.
        lead_row = (
            await db.execute(select(Lead).where(Lead.hunt_id == hunt_id).limit(1))
        ).scalar_one_or_none()
        lead_id: int | None = int(lead_row.id) if lead_row is not None else None
        # Idempotency probe: a running or already-complete promotion of this
        # exact finding is returned as-is; only an error/cancelled one frees
        # the slot for a fresh promotion (mirrors POST /hunt's re-hunt guard).
        existing = await inv_svc.latest_for_finding(db, hunt_id, ordinal)
    if existing is not None and inv_svc.blocks_rehunt(existing):
        return {"investigation_id": existing.id, "existing": True}

    citations = finding.get("citations")
    if not isinstance(citations, list):
        citations = []
    # Stored report JSON isn't schema-enforced — a legacy or partially-written
    # report can carry a stray int/None in `citations`. Coerce to str (dropping
    # anything else) before `_ID_SHAPED.match`, which requires a str and would
    # otherwise TypeError on the first non-str entry — the same
    # don't-trust-stored-JSON posture as the ordinal/dict guards above.
    citations = [str(c) for c in citations if isinstance(c, (str, int))]
    subject = await _hunt_subject_for(
        request,
        settings=settings,
        elastic=elastic,
        hunt_id=hunt_id,
        finding_ordinal=ordinal,
        lead_id=lead_id,
    )
    inv_id = await _start_promotion(
        request,
        settings=settings,
        elastic=elastic,
        started_by=started_by,
        title=str(finding.get("title") or "Hunt finding"),
        detail=str(finding.get("detail") or ""),
        hosts=[str(h) for h in (finding.get("hosts") or [])],
        citations=citations,
        kind="hunt",
        hunt_id=hunt_id,
        finding_ordinal=ordinal,
        focus_origin="hunt_finding",
        subject=subject,
        # Inherit the source hunt's synth-eval marker (migration 0032): a
        # finding a synth-eval hunt surfaced is planted evidence, and its
        # promoted investigation must stay marked as such forever.
        is_synth_eval=hunt_is_synth_eval,
    )

    # The analyst read this finding and acted on it. That judgement is worth as
    # much as a catalog hit, so it joins the same observations table and counts
    # toward leads on the hosts the finding names.
    from soc_ai.hunting.sources import observe_hunt_finding  # noqa: PLC0415 - lazy

    try:
        async with request.app.state.db_sessionmaker() as db:
            await observe_hunt_finding(
                db, hunt_id=hunt_id, ordinal=ordinal, finding=finding, now=datetime.now(UTC)
            )
    except Exception:
        _LOGGER.exception("hunt finding observation failed for %s/%s", hunt_id, ordinal)
    return {"investigation_id": inv_id}


# ── E3.1: scheduled hunts (recurring hunts on an interval) ────────────────────
#
# A HuntSchedule row is one recurring hunt: an objective re-run every
# ``intervalMinutes`` by ``soc_ai.main._hunt_schedule_loop`` when the
# ``hunt_schedules_enabled`` master switch is on. Reads are analyst-readable;
# mutate is admin-gated (mirrors the runbook CRUD). Interval is MINUTES (not cron)
# and floored at the store's sane minimum — full cron is deliberately YAGNI.


class HuntScheduleIn(BaseModel):
    objective: str = Field(min_length=1, max_length=MAX_OBJECTIVE_CHARS)
    interval_minutes: int = Field(
        default=hs_svc.MIN_INTERVAL_MINUTES, ge=hs_svc.MIN_INTERVAL_MINUTES, le=43200
    )
    enabled: bool = True


class HuntSchedulePatch(BaseModel):
    """All fields optional — only the provided ones are updated."""

    objective: str | None = Field(default=None, min_length=1, max_length=MAX_OBJECTIVE_CHARS)
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


class HuntScheduleListOut(BaseModel):
    """Schedule rows plus the ``hunt_schedules_enabled`` global master switch, so
    the frontend can render an honest "paused globally" banner/pill without a
    second round trip to /config."""

    schedules: list[HuntScheduleOut]
    masterSwitchEnabled: bool


@router.get("/hunt-schedules", response_model=HuntScheduleListOut)
async def list_hunt_schedules(
    request: Request, settings: Settings = Depends(get_settings_dep)
) -> HuntScheduleListOut:
    """All recurring hunt schedules, most-recently-created first (analyst-readable),
    plus whether the ``hunt_schedules_enabled`` master switch is currently on."""
    async with request.app.state.db_sessionmaker() as db:
        rows = await hs_svc.list_all(db)
    return HuntScheduleListOut(
        schedules=[_schedule_out(r) for r in rows],
        masterSwitchEnabled=bool(getattr(settings, "hunt_schedules_enabled", False)),
    )


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
    objective_template: str = Field(min_length=1, max_length=MAX_OBJECTIVE_CHARS)
    # The `event.dataset` names this hunt correlates over — a grid missing one
    # flags the template. An element may name alternatives separated by "|":
    # any one present satisfies it. Bounded so a custom template can't carry a
    # runaway list.
    required_datasets: list[str] = Field(default_factory=list, max_length=32)
    # The catalog analytics this starter runs BEFORE the investigation. The
    # start path renders them into the objective.
    analytics: list[str] = Field(default_factory=list, max_length=ht_svc.MAX_TEMPLATE_ANALYTICS)
    default_window_minutes: int = Field(default=1440, ge=1, le=43200)


class HuntTemplatePatch(BaseModel):
    """All fields optional — only the provided ones are updated."""

    name: str | None = Field(default=None, min_length=1, max_length=256)
    objective_template: str | None = Field(
        default=None, min_length=1, max_length=MAX_OBJECTIVE_CHARS
    )
    required_datasets: list[str] | None = Field(default=None, max_length=32)
    analytics: list[str] | None = Field(default=None, max_length=ht_svc.MAX_TEMPLATE_ANALYTICS)
    default_window_minutes: int | None = Field(default=None, ge=1, le=43200)


class HuntTemplateOut(BaseModel):
    id: int
    name: str
    objectiveTemplate: str
    requiredDatasets: list[str]
    # The analytic ids the starter runs first, in the order it runs them.
    analytics: list[str] = Field(default_factory=list)
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
    # Requirements the grid satisfies ONLY with imported documents: present and
    # queryable, and no sensor here is producing them. The template stays
    # available — hunting history is legitimate — but "available" alone reads
    # as "this grid is seeing it", and on the measured grid zeek.dns was 88%
    # backfill and system.security 98%. Each entry is the requirement as
    # written, so an alternatives element is labelled as a whole.
    backfillOnlyDatasets: list[str] = []
    # Was the availability axis actually EVALUATED? False when inventory
    # discovery failed, which is exactly when ``available`` fails open to True
    # for every template. Fail-open is right — an unreadable inventory must not
    # hide or falsely flag a hunt — but on its own it is indistinguishable from
    # "checked, and the telemetry is there", and the picker was drawing the
    # confident version: six highlighted chips on a grid whose datasets nobody
    # could read, and a hunt launched against telemetry the grid cannot see.
    # Unknown is not available. The client renders a third, neutral state off
    # this flag; the annotation stays absent rather than invented.
    availabilityKnown: bool = True
    # Environment-fit annotation — a SECOND, independent axis (hunt-fit).
    # ``available`` says the grid can SEE the telemetry; ``applicable`` says the
    # network HAS the machinery the hunt is about (a Windows host, a domain).
    # False iff a requirement in ht_svc.BUILTIN_ENV_REQUIREMENTS is met by NO
    # resolved dossier. ``missingEnvironment`` carries the human phrases
    # ("a domain-joined host"). A not-applicable template is DEMOTED in the
    # picker, never hidden, and stays fully runnable. Fail-open: custom
    # templates, profile errors and a never-built dossier table are all True.
    applicable: bool = True
    missingEnvironment: list[str] = []


def _environment_fit(
    row: HuntTemplate, profile: dossier_store.EnvironmentProfile | None
) -> tuple[bool, list[str]]:
    """``(applicable, missing-environment phrases)`` for one template.

    FAIL-OPEN, all three rules mandatory:

    * a custom (non-builtin) template is always applicable — the operator knows
      their network better than the dossier table does;
    * ``profile is None`` (the query raised) → applicable: a broken profile
      must never demote a hunt;
    * ``built_hosts == 0`` → applicable: a table nothing ever built describes
      an UNKNOWN network, not an empty one.

    A requirement is met by EVEN ONE resolved host. An unknown requirement
    token (a future map entry this build doesn't understand) counts as met, in
    the same fail-open spirit.
    """
    if not row.builtin:
        return True, []
    requirements = ht_svc.BUILTIN_ENV_REQUIREMENTS.get(row.name, ())
    if not requirements:
        return True, []
    if profile is None or profile.built_hosts == 0:
        return True, []
    met = {
        ht_svc.ENV_WINDOWS: profile.windows_hosts > 0,
        ht_svc.ENV_DOMAIN: profile.domain_joined_hosts > 0,
    }
    missing = [
        ht_svc.ENV_REQUIREMENT_PHRASES.get(req, req)
        for req in requirements
        if not met.get(req, True)
    ]
    return not missing, missing


def _template_out(
    row: HuntTemplate,
    present: tuple[set[str], set[str]] | None,
    profile: dossier_store.EnvironmentProfile | None = None,
) -> HuntTemplateOut:
    """Serialize a template, annotating availability against ``present`` dataset names
    and environment fit against ``profile``.

    ``present is None`` means the inventory couldn't be discovered — the template
    is reported ``available=True, missingDatasets=[]`` (best-effort: an inventory
    error must never hide or falsely flag a template) and, crucially,
    ``availabilityKnown=False``, so the fail-open value is never mistaken for a
    measured one. ``profile is None`` fails open the same way on the environment
    axis (see :func:`_environment_fit`).
    """
    required = [str(d) for d in (row.required_datasets or [])]
    if present is None:
        missing: list[str] = []
        backfill_only: list[str] = []
    else:
        present_names, live_names = present
        # A requirement is met by ANY of its alternatives; what is reported
        # missing is the whole requirement, verbatim, so the operator sees
        # every plane that would have satisfied it.
        missing = [
            d for d in required if not any(alt in present_names for alt in ht_svc.alternatives(d))
        ]
        # Met, but by no live plane: every alternative that is present is an
        # import. Reported as the requirement, not the plane, for the same
        # reason ``missing`` is.
        backfill_only = [
            d
            for d in required
            if d not in missing and not any(alt in live_names for alt in ht_svc.alternatives(d))
        ]
    applicable, missing_environment = _environment_fit(row, profile)
    return HuntTemplateOut(
        id=row.id,
        name=row.name,
        objectiveTemplate=row.objective_template or "",
        requiredDatasets=required,
        analytics=row.analytics,
        defaultWindowMinutes=row.default_window_minutes,
        builtin=row.builtin,
        createdBy=row.created_by,
        createdAt=_iso_utc(row.created_at),
        available=not missing,
        missingDatasets=missing,
        backfillOnlyDatasets=backfill_only,
        availabilityKnown=present is not None,
        applicable=applicable,
        missingEnvironment=missing_environment,
    )


async def _present_dataset_names(request: Request) -> tuple[set[str], set[str]] | None:
    """``(present, live)`` dataset-name sets, or ``None`` on failure.

    ``present`` is every dataset on the grid, backfill included — the
    availability question. ``live`` is the subset a sensor here is still
    producing — the disclosure question. Both come from the one inventory read.

    Reuses the TTL-cached :func:`discover_datasets` (300s) — annotating the whole
    template list is ONE inventory read, not one per template. Best-effort: any
    discovery failure returns ``None`` so the caller reports every template
    available rather than hiding them on an inventory error.

    Bounded by ``webui_grid_timeout_s``: on a cache miss this is a live grid read
    on a console route, and against a grid that accepts but never answers the ES
    client's retry budget would hold the Hunt Console for ~90 s. The timeout lands
    in the same fail-open branch as any other discovery failure.
    """
    try:
        elastic = request.app.state.elastic
        settings = request.app.state.settings
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            inv = await discover_datasets(elastic, settings)
    except Exception:
        _LOGGER.warning("hunt-template availability: inventory discovery failed", exc_info=True)
        return None
    return set(inv.dataset_names()), set(inv.live_dataset_names())


async def _environment_profile(request: Request) -> dossier_store.EnvironmentProfile | None:
    """The network's resolved-dossier environment counts, or ``None`` on failure.

    One small two-query read per request, under the resolver's own gates
    (``dossier_min_confidence`` / ``dossier_staleness_hours``, read hot).
    Best-effort like :func:`_present_dataset_names`: any failure returns
    ``None`` and the caller reports every template applicable — a broken
    profile must never demote a hunt.
    """
    try:
        settings = request.app.state.settings
        async with request.app.state.db_sessionmaker() as db:
            return await dossier_store.environment_profile(
                db,
                min_confidence=float(
                    getattr(
                        settings, "dossier_min_confidence", dossier_store.DEFAULT_MIN_CONFIDENCE
                    )
                ),
                staleness_hours=int(
                    getattr(
                        settings, "dossier_staleness_hours", dossier_store.DEFAULT_STALENESS_HOURS
                    )
                ),
            )
    except Exception:
        _LOGGER.warning("hunt-template environment fit: profile query failed", exc_info=True)
        return None


@router.get("/hunt-templates", response_model=list[HuntTemplateOut])
async def list_hunt_templates(request: Request) -> list[HuntTemplateOut]:
    """All hunt templates, builtins first, ANNOTATED on two independent axes.

    * ``available``/``missingDatasets`` — can the GRID see the telemetry? Flagged
      against the live (TTL-cached) inventory, read ONCE for the whole list.
      ``availabilityKnown=False`` when that read failed: the values below it are
      fail-open defaults, not measurements, and the picker must say so instead of
      presenting an unchecked template as one that matches live telemetry.
    * ``applicable``/``missingEnvironment`` — does the NETWORK have the machinery
      the hunt targets (a Windows host, a domain)? Computed per request from the
      resolved dossier store, so it re-evaluates automatically after every
      dossier sweep — the moment the first domain join appears, the hunt
      reopens, with no cache to wait out.

    Neither axis ever hides a template: missing telemetry is flagged, a
    non-applicable hunt is demoted — and both stay fully runnable. An
    attacker's first domain join must not be invisible because the catalogue
    decided this network "doesn't do domains".
    """
    present = await _present_dataset_names(request)
    profile = await _environment_profile(request)
    async with request.app.state.db_sessionmaker() as db:
        rows = await ht_svc.list_all(db)
    return [_template_out(r, present, profile) for r in rows]


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
            analytics=body.analytics,
            default_window_minutes=body.default_window_minutes,
            builtin=False,
            created_by=created_by,
        )
    # Annotate the freshly-created row too (cheap — the inventory is TTL-cached,
    # the profile two small queries; a custom row is always applicable anyway).
    present = await _present_dataset_names(request)
    profile = await _environment_profile(request)
    return _template_out(row, present, profile)


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
                    "hint": "Builtin templates are code-owned. Save a custom template.",
                },
            )
        row = await ht_svc.update(
            db,
            template_id,
            name=body.name,
            objective_template=body.objective_template,
            required_datasets=body.required_datasets,
            analytics=body.analytics,
            default_window_minutes=body.default_window_minutes,
        )
    present = await _present_dataset_names(request)
    profile = await _environment_profile(request)
    assert row is not None  # existed above + same session; narrow for mypy
    return _template_out(row, present, profile)


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
                    "hint": "Builtin templates are code-owned. You cannot delete them.",
                },
            )
        await ht_svc.delete(db, template_id)
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Leads — several observations that together are worth looking at
# ---------------------------------------------------------------------------


class LeadObservationOut(BaseModel):
    kind: str
    # The analyst's words for `kind`. The chip prints this one.
    kind_label: str = ""
    summary: str | None
    occurrences: int
    born_at: str | None
    first_seen_at: str | None
    # Which adapter wrote it, and whether its analytic is live.
    source: str = "profile"
    shadow: bool = False


class LeadOut(BaseModel):
    id: int
    status: str
    formed_at: str | None
    updated_at: str | None
    entities: list[list[str]]
    kinds: list[str]
    # The same kinds in the analyst's words, in the same order. `kinds` stays
    # the identifier list the app filters on.
    kind_labels: list[str] = []
    weight_at_formation: float
    scope_count: int
    hunt_id: str | None
    # Shadow leads are recorded and never surfaced as actions. The strip shows
    # them with the flag because the whole point of the shadow week is to READ
    # them; hiding them would make the week unreadable.
    shadow: bool
    dismissed_reason: str | None = None
    investigation_id: str | None = None
    # Whether the investigation the lead names is still in the table. The
    # column carries no foreign key, so a deleted investigation leaves the id
    # behind and Open investigation led to a page that says the thing is not
    # there. False when the lead names none.
    investigation_exists: bool = False
    # The attached hunt, so a lead can read Hunted once its hunt finished.
    hunt_status: str | None = None
    hunt_outcome_label: str | None = None
    dismissed_at: str | None = None
    # True if one kind formed the lead by itself, by repeating until its weight
    # reached 1.0. The shadow week shows whether this flag is noise.
    single_signal: bool = False
    # How many open leads share an analytic, an external network or a
    # technique with this one. The row shows a chip that links to the lead
    # page, where the leads are named.
    related_count: int = 0
    # True when the auto-hunt loop will start this lead's hunt. The New pill
    # reads "New . hunt queued" from it, so the analyst can tell a lead nobody
    # has touched from a lead soc-ai is about to hunt.
    hunt_queued: bool = False
    observations: list[LeadObservationOut]


class LeadRelatedOut(BaseModel):
    """One open lead that shares something with the lead on the page.

    ``reason`` is the analyst's sentence for the share. It names the thing:
    the analytic, the network or the technique.

    The two hunt fields are the ones :class:`LeadOut` carries, for the same
    reason: a lead whose hunt finished keeps the stored status ``hunting``,
    so a row that reads the status alone says In progress for ever. The panel
    and the strip must read the same state for the same lead.
    """

    lead_id: int
    entities: list[list[str]]
    reason: str
    formed_at: str | None = None
    status: str
    hunt_status: str | None = None
    hunt_outcome_label: str | None = None


class LeadObservationDetailOut(LeadObservationOut):
    """One observation on the lead detail page.

    The detail page shows the analytic, the live weight and the evidence ids.
    The strip shows none of these.
    """

    id: int
    spec_id: str
    weight_now: float
    birth_weight: float
    evidence: dict[str, Any] | None = None
    # Whether ``spec_id`` is an analytic the catalog lists. An alert verdict
    # and a promoted hunt finding are recorded under a spec id that names the
    # adapter, so the timeline row links to no analytic. Six of thirteen leads
    # on the range linked to a drawer that could not be read.
    analytic_exists: bool = False


class LeadDetailOut(LeadOut):
    """One lead with its timeline, its live weight and its dismissal."""

    weight_now: float
    single_signal: bool = False
    dismissed_reason: str | None = None
    dismissed_note: str | None = None
    dismissed_by: str | None = None
    dismissed_at: str | None = None
    investigation_id: str | None = None
    dismiss_reasons: list[str]
    # The open leads this one shares an analytic, an external network or a
    # technique with, newest first. Computed on read.
    related: list[LeadRelatedOut] = []
    observations: list[LeadObservationDetailOut]  # type: ignore[assignment]


class LeadDismissIn(BaseModel):
    reason: str
    note: str | None = None


def _iso(dt: Any) -> str | None:
    return dt.isoformat() + "Z" if isinstance(dt, datetime) else None


@router.get("/leads", response_model=list[LeadOut])
async def list_leads(request: Request, status: str = "open", limit: int = 50) -> list[LeadOut]:
    """Leads, newest first, each with the observations that formed it.

    ``status`` takes a stored value (``open``, ``hunting``, ``dismissed``,
    ``promoted``), ``all``, or one of four aliases the tabs read:

    - ``new``: the same rows as ``open``.
    - ``closed``: dismissed or promoted.
    - ``needs_decision``: a hunt that finished, or a lead no loop will hunt.
    - ``in_progress``: hunting with a hunt that runs or is queued.

    The last two name what the analyst must do, so the tab and the Needs-you
    strip read the same rule. The rule itself lives in the lead store, and it
    reads the ``lead_auto_hunt`` setting: with the loop on, a new lead waits
    on soc-ai rather than on the analyst.
    """
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - lazy
    from soc_ai.store.models import EntityObservation, Lead  # noqa: PLC0415 - lazy

    limit = max(1, min(int(limit), 200))
    auto_hunt = _auto_hunt(request)
    async with request.app.state.db_sessionmaker() as db:
        stmt = select(Lead).order_by(Lead.formed_at.desc(), Lead.id.desc()).limit(limit)
        if status == "closed":
            stmt = stmt.where(Lead.status.in_(("dismissed", "promoted")))
        elif status == "new":
            stmt = stmt.where(Lead.status == "open")
        elif status == "needs_decision":
            stmt = stmt.outerjoin(Hunt, Hunt.id == Lead.hunt_id).where(
                leads_store.needs_decision_clause(auto_hunt=auto_hunt)
            )
        elif status == "in_progress":
            stmt = stmt.outerjoin(Hunt, Hunt.id == Lead.hunt_id).where(
                leads_store.in_progress_clause()
            )
        elif status != "all":
            stmt = stmt.where(Lead.status == status)
        leads = (await db.scalars(stmt)).all()
        if not leads:
            return []
        obs_rows = (
            await db.scalars(
                select(EntityObservation)
                .where(EntityObservation.lead_id.in_([lead.id for lead in leads]))
                .order_by(EntityObservation.born_at.desc())
            )
        ).all()
        hunt_ids = [lead.hunt_id for lead in leads if lead.hunt_id]
        hunts_by_id: dict[str, Hunt] = {}
        if hunt_ids:
            hunts_by_id = {
                h.id: h for h in (await db.scalars(select(Hunt).where(Hunt.id.in_(hunt_ids)))).all()
            }
        # One query for the page, not one per promoted lead.
        live_investigations = await _investigations_that_exist(
            db, [lead.investigation_id for lead in leads]
        )
        # Two more queries for the page, not two per row.
        related_count = await leads_store.related_counts(db, leads)
    by_lead: dict[int, list[EntityObservation]] = {}
    for o in obs_rows:
        by_lead.setdefault(int(o.lead_id or 0), []).append(o)

    return [
        LeadOut(
            id=lead.id,
            hunt_status=_lead_hunt_state(hunts_by_id.get(lead.hunt_id or ""))[0],
            hunt_outcome_label=_lead_hunt_state(hunts_by_id.get(lead.hunt_id or ""))[1],
            investigation_id=lead.investigation_id,
            investigation_exists=lead.investigation_id in live_investigations,
            status=lead.status,
            formed_at=_iso(lead.formed_at),
            updated_at=_iso(lead.updated_at),
            entities=[list(e) for e in (lead.entities_json or [])],
            kinds=list(lead.kinds_json or []),
            kind_labels=[kind_label(k) for k in (lead.kinds_json or [])],
            weight_at_formation=float(lead.weight_at_formation or 0.0),
            scope_count=int(lead.scope_count or 0),
            hunt_id=lead.hunt_id,
            shadow=bool(lead.shadow),
            dismissed_reason=lead.dismissed_reason,
            dismissed_at=_iso(lead.dismissed_at),
            single_signal=bool(lead.single_signal),
            related_count=related_count.get(lead.id, 0),
            hunt_queued=leads_store.hunt_is_queued(lead, auto_hunt=auto_hunt),
            observations=[
                LeadObservationOut(
                    kind=o.kind,
                    kind_label=kind_label(o.kind),
                    summary=reword_legacy_summary(o.summary),
                    occurrences=int(o.occurrences or 1),
                    born_at=_iso(o.born_at),
                    first_seen_at=_iso(o.first_seen_at),
                    source=observation_source(o.source),
                    shadow=bool(o.shadow),
                )
                for o in by_lead.get(lead.id, [])
            ],
        )
        for lead in leads
    ]


async def _investigations_that_exist(db: Any, ids: Sequence[str | None]) -> set[str]:
    """Which of these investigation ids are still rows.

    ``Lead.investigation_id`` carries no foreign key, so a deleted
    investigation leaves the id on the lead. The lead then offered Open
    investigation and the link answered 404. One query answers the whole page.
    """
    from soc_ai.store.models import Investigation  # noqa: PLC0415 - lazy

    wanted = [str(i) for i in ids if i]
    if not wanted:
        return set()
    rows = await db.scalars(select(Investigation.id).where(Investigation.id.in_(wanted)))
    return {str(r) for r in rows.all()}


def _lead_hunt_state(hunt: Hunt | None) -> tuple[str | None, str | None]:
    """The state and outcome of the hunt attached to a lead.

    A lead reads Hunted once its hunt finished. The list and the detail page
    both need this. The detail page said "Hunting" after the hunt was done,
    because only the list computed it.
    """
    if hunt is None:
        return None, None
    status = _HUNT_STATUS.get(hunt.status, "error")
    _threats, outcome = _hunt_outcome(status, (_hunt_report(hunt).get("findings") or []))
    return status, OUTCOME_LABEL.get(outcome) if outcome else None


def _auto_hunt(request: Request) -> bool:
    """Whether a lead starts its own hunt. Read live, like every hot setting."""
    return bool(getattr(request.app.state.settings, "lead_auto_hunt", False))


async def _lead_detail_from_db(
    db: Any, lead: Any, lead_id: int, *, auto_hunt: bool = False
) -> LeadDetailOut:
    """The detail page for one lead: its timeline and the hunt attached to it."""
    from soc_ai.hunting.catalog_tiers import effective_catalog  # noqa: PLC0415 - lazy
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - lazy

    rows = await leads_store.timeline(db, lead_id)
    hunt = await db.get(Hunt, lead.hunt_id) if lead.hunt_id else None
    live = await _investigations_that_exist(db, [lead.investigation_id])
    cat = await effective_catalog(db)
    related = await leads_store.related_leads(db, lead)
    # One query for every related lead's hunt, never one per row.
    related_hunt_ids = [r.hunt_id for r in related if r.hunt_id]
    related_hunts: dict[str, Hunt] = {}
    if related_hunt_ids:
        related_hunts = {
            h.id: h
            for h in (await db.scalars(select(Hunt).where(Hunt.id.in_(related_hunt_ids)))).all()
        }
    return _lead_detail(
        lead,
        rows,
        datetime.now(UTC),
        hunt,
        investigation_exists=lead.investigation_id in live,
        analytics=set(cat.listed),
        related=related,
        related_hunts=related_hunts,
        auto_hunt=auto_hunt,
    )


def _lead_detail(
    lead: Any,
    rows: Sequence[Any],
    now: datetime,
    hunt: Hunt | None = None,
    *,
    investigation_exists: bool = False,
    analytics: set[str] | None = None,
    related: Sequence[Any] | None = None,
    related_hunts: dict[str, Hunt] | None = None,
    auto_hunt: bool = False,
) -> LeadDetailOut:
    """One lead, its observations and what each one is worth now.

    The live weight is computed on read. The page shows the weight now beside
    the weight at formation, because a lead that has gone quiet reads the same
    as a fresh one without both numbers.
    """
    from soc_ai.hunting.weight import live_weight  # noqa: PLC0415 - lazy
    from soc_ai.store.leads import DISMISS_REASONS, hunt_is_queued  # noqa: PLC0415 - lazy

    obs = []
    total = 0.0
    for o in rows:
        w = live_weight(
            float(o.birth_weight or 0.0),
            born_at=o.born_at,
            count=int(o.occurrences or 1),
            now=now,
        )
        total += w
        obs.append(
            LeadObservationDetailOut(
                id=o.id,
                kind=o.kind,
                kind_label=kind_label(o.kind),
                spec_id=o.spec_id,
                summary=reword_legacy_summary(o.summary),
                occurrences=int(o.occurrences or 1),
                born_at=_iso(o.born_at),
                first_seen_at=_iso(o.first_seen_at),
                source=observation_source(o.source),
                shadow=bool(o.shadow),
                weight_now=round(w, 3),
                birth_weight=float(o.birth_weight or 0.0),
                evidence=o.evidence_json if isinstance(o.evidence_json, dict) else None,
                analytic_exists=o.spec_id in (analytics or set()),
            )
        )
    hunt_status, hunt_outcome_label = _lead_hunt_state(hunt)
    related_out: list[LeadRelatedOut] = []
    for r in related or []:
        # The related lead's OWN hunt, read once. The panel says Hunted where
        # the strip says Hunted.
        r_status, r_label = _lead_hunt_state((related_hunts or {}).get(r.hunt_id or ""))
        related_out.append(
            LeadRelatedOut(
                lead_id=int(r.lead_id),
                entities=[list(e) for e in (r.entities or [])],
                reason=r.reason,
                formed_at=_iso(r.formed_at),
                status=r.status,
                hunt_status=r_status,
                hunt_outcome_label=r_label,
            )
        )
    return LeadDetailOut(
        id=lead.id,
        hunt_status=hunt_status,
        hunt_outcome_label=hunt_outcome_label,
        status=lead.status,
        formed_at=_iso(lead.formed_at),
        updated_at=_iso(lead.updated_at),
        entities=[list(e) for e in (lead.entities_json or [])],
        kinds=list(lead.kinds_json or []),
        kind_labels=[kind_label(k) for k in (lead.kinds_json or [])],
        weight_at_formation=float(lead.weight_at_formation or 0.0),
        weight_now=round(total, 3),
        scope_count=int(lead.scope_count or 0),
        hunt_id=lead.hunt_id,
        shadow=bool(lead.shadow),
        dismissed_reason=lead.dismissed_reason,
        dismissed_at=_iso(lead.dismissed_at),
        single_signal=bool(lead.single_signal),
        hunt_queued=hunt_is_queued(lead, auto_hunt=auto_hunt),
        dismissed_note=lead.dismissed_note,
        dismissed_by=lead.dismissed_by,
        investigation_id=lead.investigation_id,
        investigation_exists=investigation_exists,
        dismiss_reasons=list(DISMISS_REASONS),
        related=related_out,
        related_count=len(related_out),
        observations=obs,
    )


@router.get("/hunts/leads/{lead_id}", response_model=LeadDetailOut)
async def get_lead(request: Request, lead_id: int) -> LeadDetailOut:
    """One lead with its timeline and its live weight."""
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - lazy

    async with request.app.state.db_sessionmaker() as db:
        lead = await leads_store.get(db, lead_id)
        if lead is None:
            raise _lead_not_found(lead_id)
        return await _lead_detail_from_db(db, lead, lead_id, auto_hunt=_auto_hunt(request))


def _lead_is_closed(lead: Any, verb: str) -> HTTPException:
    """The 409 a closed lead answers a start with. It names the close and the way back.

    A dismissal is a decision. Starting work on a dismissed lead silently would
    lose it. The hint names the day and the reason, so the analyst can tell
    their own dismissal from a colleague's.
    """
    if lead is None:
        was = "This lead is closed."
    elif lead.status == "promoted":
        was = f"Lead {lead.id} was promoted to investigation {lead.investigation_id}."
    else:
        day = lead.dismissed_at.date().isoformat() if lead.dismissed_at else "an earlier day"
        was = f"Lead {lead.id} was dismissed on {day} as '{lead.dismissed_reason or 'other'}'."
    return api_error(409, "lead_is_closed", f"{was} Reopen it before you {verb} it.")


@router.post("/hunts/leads/{lead_id}/dismiss", response_model=LeadDetailOut)
async def dismiss_lead(request: Request, lead_id: int, body: LeadDismissIn) -> LeadDetailOut:
    """Close the lead with a reason. The reason is required.

    A second dismissal answers 200 and changes nothing. The analyst clicked a
    button that was already true, and a 409 there teaches them to distrust the
    button.
    """
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - lazy

    by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        existing = await leads_store.get(db, lead_id)
        if existing is not None and existing.status == "dismissed":
            # The same read as the detail route, so the second click answers
            # with the same body as the first.
            return await _lead_detail_from_db(db, existing, lead_id, auto_hunt=_auto_hunt(request))
        try:
            await leads_store.dismiss(db, lead_id, reason=body.reason, note=body.note, by=by)
        except ValueError as exc:
            raise api_error(
                422,
                "unknown_dismiss_reason",
                f"'{body.reason}' is not a dismissal reason. "
                f"Use one of: {', '.join(leads_store.DISMISS_REASONS)}.",
            ) from exc
        except LookupError as exc:
            raise _lead_not_found(lead_id) from exc
        lead = await leads_store.get(db, lead_id)
        return await _lead_detail_from_db(db, lead, lead_id, auto_hunt=_auto_hunt(request))


@router.post("/hunts/leads/{lead_id}/hunt")
async def hunt_lead(
    request: Request, lead_id: int, settings: Settings = Depends(get_settings_dep)
) -> dict[str, str]:
    """Start a hunt from the lead. A second call returns the same hunt.

    The body of the start lives in :mod:`soc_ai.hunting.lead_hunt`, because the
    auto-hunt loop starts the same hunt. This route turns the refusals into
    HTTP and does nothing else.
    """
    from soc_ai.hunting import lead_hunt  # noqa: PLC0415 - lazy

    started_by = await identify_caller(request)
    try:
        out = await lead_hunt.start_lead_hunt(
            request.app.state, lead_id=lead_id, started_by=started_by
        )
    except lead_hunt.LeadHuntRefused as exc:
        if exc.reason == "lead_not_found":
            raise _lead_not_found(lead_id) from exc
        if exc.reason == "lead_is_closed":
            raise _lead_is_closed(exc.lead, "hunt") from exc
        raise _could_not_start() from exc
    if out.existing:
        return {"hunt_id": out.hunt_id, "existing": "true"}
    return {"hunt_id": out.hunt_id}


@router.post("/hunts/leads/{lead_id}/promote")
async def promote_lead(
    request: Request,
    lead_id: int,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> dict[str, str]:
    """Start an investigation of the lead's hunt.

    The lead is hunted first and the investigation reads the hunt: its
    objective, its findings, every document they cite and the lead's own
    observations. A lead with no finished hunt is refused, because an
    investigation of one document answers a smaller question than the one the
    lead asks.
    """
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - lazy

    started_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        lead = await leads_store.get(db, lead_id)
        if lead is None:
            raise _lead_not_found(lead_id)
        if lead.investigation_id:
            return {"investigation_id": lead.investigation_id, "existing": "true"}
        if lead.status in leads_store.CLOSED_STATUSES:
            raise _lead_is_closed(lead, "promote")
        rows = await leads_store.timeline(db, lead_id)
        hunt = await db.get(Hunt, lead.hunt_id) if lead.hunt_id else None
        # Related leads, when the lead payload carries them. Fail-soft: the
        # panel is context for the hunt, never a reason to refuse a promotion.
        related: list[dict[str, Any]] = []
        try:
            detail_out = await _lead_detail_from_db(db, lead, lead_id)
            related = [
                r.model_dump() if hasattr(r, "model_dump") else dict(r)
                for r in (getattr(detail_out, "related", None) or [])
            ]
        except Exception:
            _LOGGER.exception("related leads unavailable for lead %s", lead_id)
    if hunt is None or hunt.status != "complete":
        # D1 starts a hunt as soon as a lead forms, so this is the rare path:
        # the loop is off, or behind, or the hunt is still running.
        raise api_error(
            409,
            "lead_not_hunted",
            (
                "The hunt is still running. The investigation reads the hunt's findings."
                if hunt is not None and hunt.status == "running"
                else "Hunt this lead first. The investigation reads the hunt's findings."
            ),
        )
    subject = await _hunt_subject_for(
        request,
        settings=settings,
        elastic=elastic,
        hunt_id=hunt.id,
        lead_id=lead_id,
        related_leads=related,
    )
    if not subject.documents:
        # Refused before any further grid call. An investigation with no cited
        # document spends a model call and lands a verdict on nothing.
        raise api_error(
            422,
            "no_citations",
            "This lead's hunt and observations cite no documents. Hunt it again to record them.",
        )
    hosts = [
        str(e[1])
        for e in (lead.entities_json or [])
        if isinstance(e, (list, tuple)) and len(e) == 2
    ]
    inv_id = await _start_promotion(
        request,
        settings=settings,
        elastic=elastic,
        started_by=started_by,
        title=f"Lead {lead_id} on {', '.join(hosts) or 'an entity'}",
        detail=" ".join((o.summary or "") for o in rows[:6]),
        hosts=hosts,
        citations=subject.document_ids,
        kind="lead",
        hunt_id=hunt.id,
        finding_ordinal=None,
        subject=subject,
        focus_origin="lead",
        is_synth_eval=False,
    )
    async with request.app.state.db_sessionmaker() as db:
        try:
            await leads_store.mark_promoted(db, lead_id, investigation_id=inv_id)
        except ValueError as exc:
            # The lead closed while the console was starting the investigation.
            lead = await leads_store.get(db, lead_id)
            raise _lead_is_closed(lead, "promote") from exc
    return {"investigation_id": inv_id}


@router.post("/hunts/leads/{lead_id}/reopen", response_model=LeadDetailOut)
async def reopen_lead(request: Request, lead_id: int) -> LeadDetailOut:
    """Put a closed lead back to open. The dismissal stays as history.

    A dismissal is reversible. The reason, the note, the hand and the time of
    the dismissal are kept on the row, so the page can show it as a timeline
    event and the sharpening loop can read the reason.
    """
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - lazy

    by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        try:
            lead = await leads_store.reopen(db, lead_id, by)
        except LookupError as exc:
            raise _lead_not_found(lead_id) from exc
        return await _lead_detail_from_db(db, lead, lead_id, auto_hunt=_auto_hunt(request))


# ---------------------------------------------------------------------------
# Lead quality — the rule is instrumented, not moved
# ---------------------------------------------------------------------------

# The one sentence the block states, built from the constants themselves so
# the page cannot say one number while the rule uses another.
LEAD_QUALITY_NOTE = "A threshold moves on a week of data, never on a day."

# The label for a lead whose row carries no observation types.
NO_TYPES_RECORDED = "none recorded"
# The label for a dismissal with no reason on the row. The store demands a
# reason, so this counts the rows that predate it.
NO_REASON_RECORDED = "not_recorded"


def _lead_rule_sentence() -> str:
    """The formation rule in one sentence, read off the constants that decide it."""
    from soc_ai.hunting.leads import SINGLE_SIGNAL_THRESHOLD  # noqa: PLC0415 - lazy
    from soc_ai.hunting.weight import DEFAULT_LEAD_THRESHOLD  # noqa: PLC0415 - lazy

    return (
        f"A lead forms at {DEFAULT_LEAD_THRESHOLD} over two or more types, on a finding "
        f"with no benign baseline, or on one type repeated to {SINGLE_SIGNAL_THRESHOLD}."
    )


class LeadQualityWeekOut(BaseModel):
    """One ISO week of lead outcomes."""

    week: str
    formed: int = 0
    hunted: int = 0
    threat: int = 0
    promoted: int = 0
    # Reason to count, for the reasons that occurred. A reason nobody gave is
    # absent rather than zero.
    dismissed: dict[str, int] = {}


class LeadQualityTypesOut(BaseModel):
    """One observation-type pair, and what the leads it formed came to."""

    types: str
    formed: int = 0
    dismissed: int = 0
    threat: int = 0


class LeadQualityOut(BaseModel):
    """The lead rule, and what it did over the last few weeks."""

    weeks: list[LeadQualityWeekOut]
    by_types: list[LeadQualityTypesOut]
    rule: str
    note: str


def _iso_week(at: datetime) -> str:
    """``2026-W38``. The ISO year, which is not always the calendar year."""
    year, week, _weekday = at.isocalendar()
    return f"{year}-W{week:02d}"


def _types_label(kinds: Any) -> str:
    """The observation types that formed a lead, sorted and joined with ``+``.

    Sorted, so ``off_hours`` then ``analytic_match`` and the reverse are one
    pair. The analyst reads which combinations produce threats and which
    produce dismissals, which is the whole point of the breakdown.
    """
    values = sorted({str(k) for k in (kinds or []) if str(k)})
    return "+".join(values) if values else NO_TYPES_RECORDED


async def lead_quality(db: Any, *, weeks: int = 4, now: datetime | None = None) -> LeadQualityOut:
    """What the lead rule produced, per ISO week and per observation-type pair.

    A threat finding is the hunt outcome the Hunts page paints as "Threat
    findings", read from :func:`_hunt_outcome`, so the number here and the
    label there can never disagree.

    Weeks are newest first, and a week with no leads is still a row: an empty
    week is a measurement, and dropping it would make a quiet week look like a
    week that was never swept.
    """
    from soc_ai.store.leads import DISMISS_REASONS  # noqa: PLC0415 - lazy
    from soc_ai.store.models import Lead  # noqa: PLC0415 - lazy

    weeks = max(1, min(int(weeks), 26))
    at = now or datetime.now(UTC)
    if at.tzinfo is not None:
        at = at.replace(tzinfo=None)
    this_monday = datetime.combine(at.date() - timedelta(days=at.date().isoweekday() - 1), time.min)
    start = this_monday - timedelta(weeks=weeks - 1)

    rows = list(
        (
            await db.scalars(
                select(Lead).where(Lead.formed_at >= start).order_by(Lead.formed_at.desc())
            )
        ).all()
    )
    hunt_ids = [str(lead.hunt_id) for lead in rows if lead.hunt_id]
    hunts_by_id: dict[str, Hunt] = {}
    if hunt_ids:
        hunts_by_id = {
            h.id: h for h in (await db.scalars(select(Hunt).where(Hunt.id.in_(hunt_ids)))).all()
        }

    def a_threat(lead: Any) -> bool:
        hunt = hunts_by_id.get(str(lead.hunt_id or ""))
        if hunt is None:
            return False
        status = _HUNT_STATUS.get(hunt.status, "error")
        _threats, outcome = _hunt_outcome(status, (_hunt_report(hunt).get("findings") or []))
        return outcome == "threats"

    labels = [_iso_week(this_monday - timedelta(weeks=i)) for i in range(weeks)]
    by_week: dict[str, LeadQualityWeekOut] = {
        label: LeadQualityWeekOut(week=label) for label in labels
    }
    by_types: dict[str, LeadQualityTypesOut] = {}

    for lead in rows:
        week = by_week.get(_iso_week(lead.formed_at))
        pair = _types_label(lead.kinds_json)
        types = by_types.setdefault(pair, LeadQualityTypesOut(types=pair))
        types.formed += 1
        if week is not None:
            week.formed += 1
        if lead.hunt_id and week is not None:
            week.hunted += 1
        if a_threat(lead):
            types.threat += 1
            if week is not None:
                week.threat += 1
        if lead.status == "promoted" and week is not None:
            week.promoted += 1
        if lead.status == "dismissed":
            types.dismissed += 1
            reason = str(lead.dismissed_reason or NO_REASON_RECORDED)
            if week is not None:
                week.dismissed[reason] = week.dismissed.get(reason, 0) + 1

    order = {reason: i for i, reason in enumerate(DISMISS_REASONS)}
    for week_row in by_week.values():
        week_row.dismissed = dict(
            sorted(week_row.dismissed.items(), key=lambda kv: (order.get(kv[0], 99), kv[0]))
        )

    return LeadQualityOut(
        weeks=[by_week[label] for label in labels],
        by_types=sorted(by_types.values(), key=lambda t: (-t.formed, t.types)),
        rule=_lead_rule_sentence(),
        note=LEAD_QUALITY_NOTE,
    )


@router.get("/leads/quality", response_model=LeadQualityOut)
async def get_lead_quality(request: Request, weeks: int = 4) -> LeadQualityOut:
    """The lead rule and what it produced, for the Analytics tab and the CLI.

    The block states the rule and the noise floor beside the numbers. A
    threshold that moves on one day of data moves on noise: the detection
    work measured a band of plus or minus 0.20 at a single batch.
    """
    async with request.app.state.db_sessionmaker() as db:
        return await lead_quality(db, weeks=weeks)
