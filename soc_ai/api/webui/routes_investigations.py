"""Investigation list/detail/cancel/delete/rehunt/request-more-info endpoints."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui import _timeline, routes_hunts
from soc_ai.api.webui._errors import api_error
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
from soc_ai.api.webui.routes_alerts import _es_api_error_http, _grid_unavailable
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import chat as chat_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Hunt, Investigation
from soc_ai.triage_models import is_pipeline_fallback
from soc_ai.webui import (
    hunt_manager,
)

_LOGGER = logging.getLogger(__name__)

# ── Investigations ─────────────────────────────────────────────────────────

# The statuses the backend actually writes: running | complete | error |
# cancelled | interrupted. (The frontend union also lists a legacy "awaiting"
# that is never produced.) DERIVED from the store's tuple, not a second copy of
# it — the same tuple drives the SQL display-status CASE and this route's filter
# validation, so a status added there reaches the renderer and the filter
# together instead of leaving them to disagree about a value only one knows.
_STATUS = frozenset(inv_svc.DISPLAY_STATUSES)

# A search term longer than this is not a search, it is a payload. The columns
# it matches are a 512-char rule name and two address strings.
#
# REFUSED, not truncated. Truncating turns a substring match into a match on a
# PREFIX of what was typed, so the answer is a superset of the question — the
# screen renders rows that do not contain the search term and the header count
# agrees with them. A list quietly answering a different question is the exact
# failure this endpoint exists to have stopped doing.
_SEARCH_MAX = 200


def _note_or_none(value: object) -> str | None:
    """A validator note worth showing, or None.

    Models write the STRING "null" when they have nothing to say, and the page
    rendered "Post-validator override — null" as if that were a note.
    """
    text = str(value or "").strip()
    return text if text and text.lower() not in {"null", "none", "n/a", "nothing"} else None


def _row_status(inv: Investigation) -> str:
    """Effective display status for an investigation row.

    An unknown stored status falls back to 'error' (never silently 'complete'),
    and a finished run that produced NO verdict is reported as 'error' — it never
    reached a triage decision, so labelling it 'complete' would be a lie (the
    verdict shows 'untriaged'). A real verdict — including needs_more_info — keeps
    the stored status.

    The SQL twin is :func:`~soc_ai.store.investigations._display_status_sql`,
    which the Status filter runs on so the filter and the badge cannot part
    company; a differential test asserts the two agree row for row.
    """
    status = inv.status if inv.status in _STATUS else "error"
    if status == "complete" and not (inv.verdict or "").strip():
        return "error"
    return status


def _reached_no_verdict(inv: Investigation) -> bool:
    """This run ended in a failure state and produced no verdict.

    The Python twin of :func:`~soc_ai.store.investigations.failed_triage_sql`,
    kept beside :func:`_row_status` because it is that function's result plus
    the same blank-verdict test. One predicate behind the row flag, the dismiss
    guard and the SQL filter, so a run the Dashboard counts is a run the
    operator can clear.
    """
    return _row_status(inv) == "error" and not (inv.verdict or "").strip()


def _subject_type(inv: Investigation) -> str:
    """What this run investigated: ``"hunt"`` or ``"alert"``.

    Read off the stored subject (migration 0050), so a legacy row and an alert
    row both read ``"alert"``. Distinct from ``kind``, which says where the run
    came from and is unchanged: a run can be kind ``lead`` and subject type
    ``hunt``.
    """
    subject = getattr(inv, "subject_json", None)
    return "hunt" if isinstance(subject, dict) and subject.get("type") == "hunt" else "alert"


def _subject_out(inv: Investigation, hunt: Hunt | None) -> dict[str, Any] | None:
    """The subject the drawer reads, or None for an alert subject.

    Served from the row, not rebuilt: the hunt row carries no foreign key and
    may be deleted, and the subject is a record of what THIS run read. The
    hunt's objective is topped up from the hunt when the row is still there and
    the stored record has none (a legacy hunt-subject row).
    """
    stored = getattr(inv, "subject_json", None)
    if not isinstance(stored, dict) or stored.get("type") != "hunt":
        return None
    out = dict(stored)
    if hunt is not None and not out.get("objective"):
        out["objective"] = hunt.objective
    return out


class InvestigationRowOut(BaseModel):
    id: str
    name: str
    kind: str
    # What the run investigated (migration 0050): "alert" or "hunt". `kind`
    # says where the run came from and does not change.
    subjectType: str = "alert"
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
    # True when this run's verdict is a pipeline-failure fallback (E1.2) — a
    # needs_more_info the pipeline never actually reasoned to (model truncation,
    # gateway 5xx). The list renders it as a distinct "pipeline error — retry"
    # chip (not the amber Needs-info pill), makes it filterable, and the Dashboard
    # excludes it from the Needs-info KPI.
    fallback: bool = False
    # This run ended in a failure state having reached NO verdict: the other half
    # of "the pipeline produced nothing usable". A fallback at least wrote a
    # report to be marked; these wrote nothing at all, which is why they were
    # invisible to every count keyed on `fallback` alone. The Dashboard's
    # pipeline-error tile counts `(fallback or noVerdict) and not errorDismissed`
    # on a primary row.
    noVerdict: bool = False
    # Operator ack of a failed run (POST /investigations/{id}/dismiss-error).
    # The Dashboard's "N pipeline errors" KPI counts rows where `fallback` or
    # `noVerdict` is True AND this is False. The row stays a pipeline error
    # historically; the ack only silences the dashboard nag.
    errorDismissed: bool = False
    # What happened LAST to this row's alert, decided over the alert's WHOLE run
    # group exactly as `isPrimary` is. When it names a different run than this
    # one, the row is representative but not current — the case the list used to
    # hide entirely: a re-run that died against a down grid, folded into a bare
    # "1 earlier" chip while the row went on showing the older healthy verdict
    # (dogfood D8, 2026-08-14). Equal to this row's own id/status/when when this
    # run IS the newest, which is the ordinary case and renders nothing extra.
    latestRunId: str = ""
    latestRunStatus: str = ""
    latestRunWhen: str = ""
    # Migration 0032's synthetic-evaluation marker: this run investigated
    # PLANTED synthetic attack scenarios (directly, or promoted from a marked
    # hunt). Surfaced wherever the row is displayed — the SPA badges it so a
    # planted attack can never be read as real activity.
    isSynthEval: bool = False


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
    inv: Investigation,
    chat_count: int = 0,
    *,
    is_primary: bool = True,
    latest_run: inv_svc.RunRef | None = None,
) -> InvestigationRowOut:
    """Map one persisted run to its list row.

    Every field is read straight off the ORM row: the sole caller is
    :func:`list_investigations`, which passes ``query_page`` results, so each
    attribute below is a mapped column that always exists. (It used to carry
    ``getattr`` guards for tests that mocked ``list_recent`` with
    ``SimpleNamespace``; the list is a real SQL query now and those tests seed
    real rows, so the guards were defending against nothing.)

    ``latest_run`` is the newest run of THIS row's alert (see
    :func:`_latest_runs`); omitting it says this run is its own alert's newest,
    which is what a caller with no group to consult can honestly claim.
    """
    # A RunRef carries no verdict, so the verdict half of `_row_status` (a
    # 'complete' run that reached no verdict displays as an error) cannot be
    # applied to a SIBLING run. It does not need to be: `_primary_run_ids`
    # counts 'complete' as live, so a newest run in that state is always this
    # very row, and its own Status cell already carries the mapping. Only the
    # unknown-status guard is reachable from here, and it is kept identical.
    latest_status = (
        _row_status(inv)
        if latest_run is None
        else (latest_run.status if latest_run.status in _STATUS else "error")
    )
    return InvestigationRowOut(
        id=inv.id,
        name=inv.rule_name or f"Alert {(inv.alert_es_id or inv.id)[:12]}…",
        # Persisted since migration 0031. Legacy rows were backfilled
        # kind='suricata' regardless of their feed doc's real kind — accepted;
        # no ES-derived fallback.
        kind=inv.kind,
        subjectType=_subject_type(inv),
        verdict=_verdict(inv.verdict),
        conf=inv.confidence,
        host=inv.src_ip or "—",
        dst=inv.dest_ip,
        status=_row_status(inv),
        when=_ago(_iso_utc(inv.created_at)),
        # tz-AWARE ISO so the browser localizes correctly (naive → parsed as local).
        ts=_iso_utc(inv.created_at),
        chatCount=chat_count,
        # The group the row belongs to. A hunt-subject run groups under
        # itself: the document it anchors on is a time anchor, not its subject.
        alertId=inv_svc.alert_group_id(inv) or inv.id,
        isPrimary=is_primary,
        fallback=is_pipeline_fallback(inv.report),
        noVerdict=_reached_no_verdict(inv),
        errorDismissed=inv.error_dismissed_at is not None,
        latestRunId=inv.id if latest_run is None else latest_run.id,
        latestRunStatus=latest_status,
        latestRunWhen=_ago(
            _iso_utc(inv.created_at if latest_run is None else latest_run.created_at)
        ),
        isSynthEval=bool(inv.is_synth_eval),
    )


class _RunLike(Protocol):
    """The three scalars primacy is decided from, however they arrive.

    :func:`_primary_run_ids` is a pure function over (id, alert_es_id, status).
    In the route it is handed :class:`~soc_ai.store.investigations.RunRef`
    tuples; its unit tests drive it with ``SimpleNamespace`` stand-ins, which is
    legitimate precisely because the algorithm touches nothing else. Annotating
    the parameter as ``Sequence[RunRef]`` would state a requirement the function
    does not have and its own callers already break.
    """

    @property
    def id(self) -> str: ...

    @property
    def alert_es_id(self) -> str | None: ...

    @property
    def status(self) -> str: ...


def _primary_run_ids(rows: Sequence[_RunLike]) -> set[str]:
    """The canonical run id per alert: the most recent run that is RUNNING or
    COMPLETE, else the most recent run of any status. ``rows`` are newest-first.

    A running run that is newer than the last complete one wins — clicking
    "re-investigate" must surface the in-flight run as the alert's current
    state, not tuck it under the stale verdict as an "earlier run". Errored/
    cancelled/interrupted re-runs still nest under the run that worked.

    ``alert_es_id`` here is the GROUP key, which the caller fills through
    :func:`~soc_ai.store.investigations.alert_group_id`. A run that stands
    alone arrives with None and is its own group.
    """
    best_live: dict[str, str] = {}
    best_any: dict[str, str] = {}
    for inv in rows:  # newest-first, so first-seen per key is the most recent
        key = inv.alert_es_id or inv.id
        best_any.setdefault(key, inv.id)
        if inv.status in ("running", "complete"):
            best_live.setdefault(key, inv.id)
    return {best_live.get(key, run_id) for key, run_id in best_any.items()}


def _latest_runs(rows: Sequence[inv_svc.RunRef]) -> dict[str, inv_svc.RunRef]:
    """The newest run per alert, whatever its status. ``rows`` are newest-first.

    The twin of :func:`_primary_run_ids`, kept separate on purpose. That
    function answers which run REPRESENTS an alert, and its rule — prefer the
    newest running-or-complete run — is right: it stops a pile of failed retries
    burying the run that actually landed a verdict. This one answers a different
    question, what happened to the alert LAST, and the two disagreeing is
    precisely the state the list had no way to show. Three re-investigations
    started against a down grid came back as two unchanged rows carrying their
    old healthy verdicts and a bare "1 earlier" chip, so a batch that mostly
    died read as a mostly-calm list (dogfood D8, 2026-08-14).

    Takes :class:`~soc_ai.store.investigations.RunRef` rather than the looser
    ``_RunLike`` because it reads ``created_at``, which only RunRef carries —
    stating a requirement it genuinely has.
    """
    latest: dict[str, inv_svc.RunRef] = {}
    for run in rows:  # newest-first, so first-seen per key is the most recent
        latest.setdefault(run.alert_es_id or run.id, run)
    return latest


# The verdict-filter vocabulary, mirroring the screen's VERDICT_FILTER_VALUES:
# the stored verdicts plus the synthetic pipeline_error (fallback-marked rows).
_VERDICT_FILTERS = (
    "true_positive",
    "false_positive",
    "needs_more_info",
    "inconclusive",
    inv_svc.PIPELINE_ERROR_VERDICT,
)


def _csv_filter(raw: str | None, allowed: tuple[str, ...]) -> list[str]:
    """Parse a comma-separated multi-value filter param, dropping unknowns.

    Unknown members are dropped rather than 422'd (matching the screen's
    verdictFilterFromSearch): a mangled deep link must degrade to a broader
    query, not wedge the whole list behind an error. All-unknown → unfiltered.
    """
    if not raw:
        return []
    return [v for v in (p.strip() for p in raw.split(",")) if v in allowed]


# The two halves of a pipeline-error set. A run "needs a retry" when it produced
# nothing usable AND nobody has dealt with it: not dismissed by an operator, and
# not superseded by a later run of the same alert that did land a verdict.
# Re-running IS the fix, so a superseded error is resolved without an explicit
# ack. This is the Dashboard tile's predicate, and it lives here so the tile and
# the list it deep-links to cannot drift apart (dogfood 2026-09-07, D2).
_ERROR_STATES = ("live", "handled")


def _needs_retry(row: InvestigationRowOut) -> bool:
    """Whether this run still wants an operator's attention.

    The two shapes of "the pipeline produced nothing usable" are an E1.2
    fallback (a placeholder verdict the pipeline never reasoned to) and a run
    that died outright with no verdict at all. Either one still counts unless it
    has been dismissed or superseded.
    """
    return (row.fallback or row.noVerdict) and not row.errorDismissed and row.isPrimary


class InvestigationListOut(BaseModel):
    """One SQL page of the list, with figures counted over the right sets.

    ``total`` / ``running`` / ``truePositives`` are counted in SQL over the SAME
    filter set as ``rows`` — never tallied from the page, which is how a header
    figure ends up describing 100 rows while reading as the query's (the
    phantom-untriaged defect, twice shipped). ``totalAll`` / ``active`` describe
    the WHOLE table: "empty store vs. filter matched nothing" and "poll while
    anything is running anywhere" cannot be answered from a filtered page.

    Under ``error_state`` the figures are counted over the PARTITION instead,
    still over the whole partition rather than the page, for the same reason.
    """

    rows: list[InvestigationRowOut]
    total: int
    running: int
    truePositives: int
    totalAll: int
    active: bool
    # The clamped values the server actually used — the client pages by these.
    limit: int
    offset: int
    # True when the answer was decided over a capped read that the filter set
    # outgrew, which makes ``total`` a FLOOR. Only ``error_state`` can set it:
    # its partition is decided in Python, over one page, because "superseded"
    # is a fact about an alert's whole run group rather than a column. A count
    # that silently stops being a count is the failure this flag exists for.
    partial: bool = False


@router.get("/investigations", response_model=InvestigationListOut)
async def list_investigations(
    request: Request,
    status: str | None = None,
    verdict: str | None = None,
    q: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    error_state: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> InvestigationListOut:
    """Investigation rows, newest first — filtered, counted and paged in SQL.

    ``status`` / ``verdict`` are comma-separated multi-selects (single values —
    the old contract — parse identically). ``since``/``until`` bound
    ``created_at`` inclusively, like ``GET /hunts``. ``q`` is free text matched
    against the rule name, source and destination — the columns the table shows.
    Filtering in SQL is the point: the old newest-100 page made every older
    errored run unreachable under ANY filter once one outcome saturated the
    page, and a client-side search box would have rebuilt exactly that.

    ``isPrimary`` is decided over each alert's WHOLE run group (one extra query
    over the page's alert ids), never over the filtered page — a filter changes
    which rows come back, not what "primary" means. So a filtered page can
    contain non-primary rows whose primary sibling is absent; the client tucks a
    retry under its primary only when that primary is present, and shows it
    top-level otherwise.

    ``error_state`` splits a pipeline-error set into the runs that still need a
    retry (``live``) and the ones somebody has already dealt with (``handled``:
    dismissed, or superseded by a later run that landed a verdict). It is the
    one filter that cannot be SQL, because "superseded" is a fact about an
    alert's whole run group rather than a column, so it is decided in Python
    over one capped read and the response says when the set outgrew that cap.
    An unknown value is dropped, like an unknown ``verdict`` member.
    """
    statuses = _csv_filter(status, inv_svc.DISPLAY_STATUSES)
    verdicts = _csv_filter(verdict, _VERDICT_FILTERS)
    wanted_state = error_state if error_state in _ERROR_STATES else None
    needle = (q or "").strip()
    if len(needle) > _SEARCH_MAX:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "search_too_long",
                "hint": f"A search term may be at most {_SEARCH_MAX} characters.",
            },
        )
    limit = min(max(limit, 1), inv_svc.MAX_PAGE_LIMIT)
    offset = max(0, offset)
    # Partitioning needs the WHOLE filter set in hand, not the caller's page:
    # the split is decided per row and the count has to describe the partition.
    read_limit = inv_svc.MAX_PAGE_LIMIT if wanted_state else limit
    read_offset = 0 if wanted_state else offset
    async with request.app.state.db_sessionmaker() as db:
        page = await inv_svc.query_page(
            db,
            since=routes_hunts._naive_utc(since),
            until=routes_hunts._naive_utc(until),
            verdicts=verdicts,
            statuses=statuses,
            q=needle or None,
            limit=read_limit,
            offset=read_offset,
        )
        chat_counts = await chat_svc.counts_for(db, [inv.id for inv in page.rows])
        alert_ids = sorted({g for inv in page.rows if (g := inv_svc.alert_group_id(inv))})
        group_rows = await inv_svc.runs_for_alerts(db, alert_ids)
    # Primacy over the FULL groups. A page row that names no group — a blank
    # alert_es_id, or a hunt-subject run, whose anchor document is a time
    # anchor and not its subject — contributes no group to fan out on, so it
    # is merged in as its own one-run group; otherwise it would carry the
    # default isPrimary and the decision would be made for it rather than
    # about it. Newest-first order is what _primary_run_ids assumes.
    seen = {r.id for r in group_rows}
    combined = group_rows + [
        inv_svc.RunRef(inv.id, inv_svc.alert_group_id(inv), inv.status, inv.created_at)
        for inv in page.rows
        if inv.id not in seen
    ]
    combined.sort(key=lambda r: (r.created_at, r.id), reverse=True)
    primary = _primary_run_ids(combined)
    # Same groups, same pass, second question: what happened to each alert LAST.
    latest = _latest_runs(combined)
    rows = [
        _row(
            inv,
            chat_counts.get(inv.id, 0),
            is_primary=inv.id in primary,
            latest_run=latest.get(inv_svc.alert_group_id(inv) or inv.id),
        )
        for inv in page.rows
    ]
    if wanted_state is None:
        return InvestigationListOut(
            rows=rows,
            total=page.total,
            running=page.running,
            truePositives=page.true_positives,
            totalAll=page.total_all,
            active=page.active,
            limit=limit,
            offset=offset,
        )
    kept = [r for r in rows if _needs_retry(r) == (wanted_state == "live")]
    return InvestigationListOut(
        rows=kept[offset : offset + limit],
        total=len(kept),
        # Counted over the partition, for the same reason the SQL figures are
        # counted over the filter set: a figure tallied from the visible page
        # describes the page while reading as the query's.
        running=sum(1 for r in kept if r.status == inv_svc.VERDICTS_RUNNING),
        truePositives=sum(1 for r in kept if r.verdict == "true_positive" and not r.fallback),
        totalAll=page.total_all,
        active=page.active,
        limit=limit,
        offset=offset,
        partial=page.total > len(page.rows),
    )


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
        # Promotion provenance: hunt_id has no FK (the referenced hunt may be
        # deleted — see the Investigation model note), so this must degrade
        # gracefully rather than 404/500 when the row is gone.
        # A hunt-subject run reads its hunt too, whatever its kind: a lead
        # promotion is kind 'lead' and its subject is still a hunt.
        wants_hunt = inv.kind == "hunt" or _subject_type(inv) == "hunt"
        hunt = await db.get(Hunt, inv.hunt_id) if wants_hunt and inv.hunt_id else None

    report = inv.report or {}
    # Live acked state so an ack performed OUTSIDE this run (group-ack, another
    # run's auto-ack, the SO web UI) marks the ack action applied. False on any
    # ES error — the action is simply offered as before.
    alert_acked = await _timeline._alert_currently_acked(elastic, settings, inv.alert_es_id)
    actions = _build_actions(events, report, alert_acked=alert_acked)

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
        oracle="escalated to Oracle" if has_oracle else "not escalated, local verdict",
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
        kind=inv.kind,
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
        validatorNote=_note_or_none(report.get("validator_note")),
        # Pipeline-failure provenance (E1.2) — non-None ONLY for a synth-failure
        # fallback run; drives the drawer's "failed before reaching a verdict"
        # panel instead of the amber Needs-info block.
        fallback=_timeline._fallback_out(report),
        errorDismissed=inv.error_dismissed_at is not None,
        subject=_subject_out(inv, hunt),
        huntId=inv.hunt_id,
        huntObjective=(hunt.objective[:160] if hunt else None),
        alertAcked=alert_acked,
        isSynthEval=bool(inv.is_synth_eval),
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
                "hint": "No hunt is running. This one already finished.",
            },
        )
    return {"cancelled": True}


@router.post("/investigations/{inv_id}/dismiss-error")
async def dismiss_pipeline_error(inv_id: str, request: Request) -> dict[str, bool]:
    """Acknowledge a run that produced no verdict so the Dashboard stops counting it.

    Both shapes the pipeline-error count holds are dismissible: an E1.2 fallback
    (the run wrote a placeholder verdict and marked the report) and a run that
    died outright, leaving no verdict at all. The second could not be cleared at
    all until now, which meant a count including it could never be worked down.
    188 such runs stood on the deployed instance, none of them acknowledged.

    Nothing about the run changes but the ack stamp: it stays visible under the
    Investigations "Pipeline error" filter as a historical fact, and stays
    re-runnable. Idempotent (a repeat ack is a no-op 200). 404 for an unknown id;
    409 when the run reached a verdict and did not fail (there is no error to
    dismiss; the button is only shown where there is one, but we guard
    server-side too).
    """
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if not is_pipeline_fallback(inv.report) and not _reached_no_verdict(inv):
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "not_pipeline_error",
                    "hint": (
                        "This run reached a verdict and did not fail. There is nothing to dismiss."
                    ),
                },
            )
        await inv_svc.dismiss_error(db, inv_id)
    return {"ok": True}


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
                    "hint": "Cancel the running hunt before you delete it.",
                },
            )
        await inv_svc.delete(db, inv_id)
    return {"deleted": True}


_REHUNT_CAP = 50
# How many re-hunts a single bulk call actually STARTS. The rest are returned as
# skipped/"queued" so the operator re-runs them in a follow-up batch — bounding
# concurrent load on the single model route. Mirrors the hunts-side cap: a real
# incident showed 7 simultaneous runs all hitting the wall-clock and producing
# garbage, so fire-and-forget worker starts must be bounded here (the manager has
# no internal limit).
_REHUNT_START_CAP = 3


class RehuntIn(BaseModel):
    # Cap at the input boundary so an oversized payload is rejected before the
    # dedup loop deserializes/iterates it.
    inv_ids: list[str] = Field(max_length=_REHUNT_CAP)


class RehuntResultOut(BaseModel):
    started: list[dict[str, str]]  # [{invId, newInvId, alertEsId}]
    skipped: list[dict[str, str]]  # [{invId, reason}]


def _grid_skip_reason(exc: BaseException) -> str:
    """Label a mid-batch grid failure the way the raised guard would label it.

    Read off ``_es_api_error_http``'s own 4xx/5xx split instead of restating it,
    so one exception cannot get two diagnoses: the SAME ES rejection that answers
    400 ``bad_query`` when nothing has started yet is reported as ``bad_query``
    in the partial result too, rather than as an outage that never happened. It
    also means this label tracks that split for free if it is ever corrected.
    """
    if isinstance(exc, ApiError) and _es_api_error_http(exc).status_code == 400:
        return "bad_query"
    return "grid_unavailable"


@router.post("/investigations/rehunt", response_model=RehuntResultOut)
async def bulk_rehunt(  # noqa: PLR0915 — linear per-id skip/start loop, each guard is a short early continue
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
    # One grid budget for the WHOLE batch, not one per row. Every nameless id
    # runs the SAME resolver query, so once that has failed the rest will fail
    # the same way — and re-probing an accepting-but-silent grid costs a full
    # webui_grid_timeout_s every time. Nameless rows are exactly the runs that
    # died early, i.e. the ones an analyst bulk re-hunts to clean up AFTER an
    # outage, plausibly while the grid is still sick: at the 50-id cap that was
    # 49 consecutive timeouts, minutes past the SPA's own client timeout, with
    # the server still starting runs nobody is left watching for.
    #
    # The cost if the failure really was transient is bounded and small:
    # _REHUNT_START_CAP already limits this call to 3 starts and we only get here
    # with at least one, so at most two re-hunts are deferred — and they are
    # deferred into the skipped list, which the analyst re-runs, not dropped.
    grid_skip_reason: str | None = None

    # The cap is already guaranteed by RehuntIn's max_length validation;
    # all rows are fetched in a SINGLE query (was one session-open + one
    # SELECT per id — an N+1).
    eligible = unique_ids

    inv_by_id: dict[str, Investigation] = {}
    promoted_anchors: set[str] = set()
    if eligible:
        async with request.app.state.db_sessionmaker() as db:
            rows = (
                (await db.execute(select(Investigation).where(Investigation.id.in_(eligible))))
                .scalars()
                .all()
            )
            inv_by_id = {inv.id: inv for inv in rows}
            # Anchor-keyed, like POST /investigate and execute-action: a
            # re-investigation of a promoted finding lands an ordinary
            # kind="suricata" row over the same anchor, and relaunching THAT
            # row through the manager's default kind would run with SO writes
            # on over cited telemetry that has no SO alert behind it.
            promoted_anchors = await inv_svc.hunt_anchor_ids(
                db, [inv.alert_es_id for inv in rows if inv.alert_es_id]
            )

    for inv_id in eligible:
        inv = inv_by_id.get(inv_id)
        if inv is None:
            skipped.append({"invId": inv_id, "reason": "not_found"})
            continue

        if inv_svc.is_promoted(inv) or inv.alert_es_id in promoted_anchors:
            # A promoted finding's anchor is cited telemetry, not an SO alert —
            # relaunching it here would mint an unlabeled kind="suricata"
            # duplicate carrying the finding title as rule_name (the exact
            # string the group-ack guard exists to keep out). Re-promotion
            # from the hunt page is the sanctioned re-run.
            skipped.append({"invId": inv_id, "reason": "hunt_kind"})
            continue

        if not inv.alert_es_id:
            skipped.append({"invId": inv_id, "reason": "no_alert"})
            continue

        # Concurrency guard: start at most _REHUNT_START_CAP runs this call — the
        # hunt manager is fire-and-forget with no internal limit, so the cap lives
        # here. Eligible ids past the cap are deferred ("queued"). Checked BEFORE
        # the name-resolve below so we also avoid firing ES lookups we won't use.
        if len(started) >= _REHUNT_START_CAP:
            skipped.append({"invId": inv_id, "reason": "queued"})
            continue

        # Prefer the stored name; if this row was itself created nameless (a pre-fix
        # row, or a selected-id run that died early), re-resolve from ES so the new
        # row is named rather than inheriting the NULL.
        rehunt_name = inv.rule_name
        if not rehunt_name:
            if grid_skip_reason is not None:
                # The grid already answered for this batch. Skip — reported, never
                # started and never silently dropped — without paying to ask again.
                skipped.append({"invId": inv_id, "reason": grid_skip_reason})
                continue
            try:
                async with asyncio.timeout(settings.webui_grid_timeout_s):
                    _, rehunt_name = await routes_hunts.resolve_alert_for_hunt(
                        elastic, settings, inv.alert_es_id
                    )
            except (TimeoutError, TransportError, ApiError) as exc:
                # A down grid must not discard re-hunts this call ALREADY started:
                # raising here would report failure for live background runs and
                # invite a retry that starts each of them a second time. With
                # nothing started yet there is no write to protect, so answer with
                # the house error; otherwise degrade this id to a skip and return
                # the honest partial result.
                if started:
                    _LOGGER.warning(
                        "rehunt: name resolve failed for %s (grid) — skipping it and "
                        "every remaining nameless row this call",
                        inv_id,
                        exc_info=True,
                    )
                    grid_skip_reason = _grid_skip_reason(exc)
                    skipped.append({"invId": inv_id, "reason": grid_skip_reason})
                    continue
                if isinstance(exc, ApiError):
                    raise _es_api_error_http(exc) from exc
                raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
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
        # Anchor-keyed, like bulk re-hunt: an ordinary row over a promoted
        # anchor (a re-investigation) is as much off-limits as the promoted
        # row itself — the manager's default kind would relaunch it with SO
        # writes on over cited telemetry that has no SO alert behind it.
        over_promoted_anchor = (
            inv is not None
            and bool(inv.alert_es_id)
            and bool(await inv_svc.hunt_anchor_ids(db, [inv.alert_es_id]))
        )

    if inv is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    if inv_svc.is_promoted(inv) or over_promoted_anchor:
        # Re-promotion from the hunt page is the sanctioned re-run for a
        # promoted finding — relaunching here would mint an unlabeled
        # kind="suricata" duplicate against the same anchor telemetry doc.
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "hunt_kind_no_rerun",
                "hint": "Re-promote the finding from its hunt instead.",
            },
        )
    if not inv.alert_es_id:
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "no_alert",
                "hint": (
                    "This investigation has no alert reference. soc-ai cannot re-investigate it."
                ),
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
                    "Request-more-info applies only to a needs_more_info or "
                    "inconclusive verdict. This investigation is "
                    f"'{inv.verdict or 'untriaged'}'."
                ),
            },
        )

    questions = _open_questions_of(inv)
    focus_hint = _focus_hint_from_questions(questions) if questions else None

    # Re-resolve the display name if the source row was created nameless.
    rmi_name = inv.rule_name
    if not rmi_name:
        try:
            async with asyncio.timeout(settings.webui_grid_timeout_s):
                _, rmi_name = await routes_hunts.resolve_alert_for_hunt(
                    elastic, settings, inv.alert_es_id
                )
        except (TimeoutError, TransportError) as exc:
            raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
        except ApiError as exc:
            raise _es_api_error_http(exc) from exc

    new_inv_id = await hunt_manager.get_manager(request.app.state).start(
        request.app.state,
        alert_id=inv.alert_es_id,
        started_by=started_by,
        rule_name=rmi_name,
        focus_hint=focus_hint,
    )
    if new_inv_id is None:
        raise api_error(
            503,
            "could_not_start",
            "The console did not start the run. Check the model gateway on the Config screen.",
        )
    return {"investigation_id": new_inv_id}
