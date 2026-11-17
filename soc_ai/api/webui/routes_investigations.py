"""Investigation list/detail/cancel/delete/rehunt/request-more-info endpoints."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui import (
    _event_timeline,
    _timeline,
    action_rules,
    routes_entity,
    routes_hunts,
)
from soc_ai.api.webui._campaign_link import CampaignLinkOut, link_for
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
    CaseRefOut,
    InvestigationOut,
    InvMetaOut,
    StandingAnalystVerdictOut,
    SupersededRunOut,
    _alert_meta,
    _build_actions,
    _build_oracle,
    _build_timeline,
    _chat_msg_out,
    _collect_reasoning,
    _entity_graph,
    _graph_scope,
    _host_signals,
    action_tool_names,
)
from soc_ai.api.webui.routes_alerts import _es_api_error_http, _grid_unavailable
from soc_ai.campaigns import service as campaign_svc
from soc_ai.config import Settings
from soc_ai.demo.guard import is_demo
from soc_ai.hunting.step_words import current_activity
from soc_ai.secret_scrub import scrub_secrets, scrub_value
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store import chat as chat_svc
from soc_ai.store import first_line as first_line_svc
from soc_ai.store import host_machines
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Hunt, Investigation
from soc_ai.triage_models import IMPACT_ORDER, is_pipeline_fallback, stored_impact
from soc_ai.webui import (
    anchor_check,
    case_links,
    finding_promotion,
    hunt_manager,
    needs_you_clear,
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


def _finding_focus_ids(inv: Investigation, hunt: Hunt | None) -> list[str] | None:
    """The document ids of the finding that a finding run judges, or None.

    None for an alert run, a lead run, an older run that judged the whole
    hunt, and a run whose hunt is gone. The Event timeline of such a run keeps
    every subject document. A finding run lists only the documents of its own
    finding and the documents that its verdict cites.
    """
    from soc_ai.hunting.findings import finding_document_ids  # noqa: PLC0415 - lazy

    subject = getattr(inv, "subject_json", None)
    ordinal = getattr(inv, "finding_ordinal", None)
    if not isinstance(subject, dict) or subject.get("judges") != "finding":
        return None
    if hunt is None or ordinal is None:
        return None
    findings = routes_hunts._hunt_report(hunt).get("findings") or []
    if not (0 <= int(ordinal) < len(findings)) or not isinstance(findings[int(ordinal)], dict):
        return None
    return finding_document_ids(findings[int(ordinal)])


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
    # The machine the alert fired on (migration 0039). A host-log alert has no
    # destination, so the list names the machine and says "host log" in place
    # of an address and a dash. None on a legacy row.
    hostName: str | None = None
    status: str
    # The time when soc-ai started this run: the relative words and the ISO
    # time. Support for the analyst. The list states the event time first.
    when: str
    ts: str = ""
    # The time of the event that this run judges (migration 0072), ISO UTC,
    # and the relative words that ``when`` uses. The window, the order and
    # the When column of the list read it (owner, 2026-11-15).
    eventAt: str = ""
    eventWhen: str = ""
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
    # The budget class the run ran in (migration 0058). None on a run stored
    # before the classes existed, and on a run still in flight.
    runClass: str | None = None
    # Who started the run: an analyst's name, the scheduler, a sweep, or
    # "backtest" for a backtest replay. The console marks a replay with a chip,
    # because a replay is a measurement and the list is the live work.
    ranBy: str = ""
    # The recommended actions of this run that wait for a person, under the
    # needs-you rule. Filled only when the list is asked for
    # ``pending_action=true``. None means the list did not count them.
    pendingActions: int | None = None
    # The waiting actions themselves, under the same filter only. The console
    # offers Execute and Dismiss on the row (dogfood 2026-10-19, R1-I1). None
    # means the list did not read them.
    waitingActions: list[_timeline.WaitingActionOut] | None = None
    # The authorized activity the run matched. ``authorizationId`` is the
    # stored link. ``authorization`` holds the label, the state and the
    # expiry. Both are null on a run that matched none. A panel that folds
    # the authorized runs into one row reads the two fields. A revoked
    # authorization has the state ``revoked``, and its runs get normal handling.
    authorizationId: int | None = None
    authorization: _timeline.AuthorizationRefOut | None = None
    # H2. What the hostile action of a true positive did: ``succeeded``,
    # ``attempted``, ``unknown`` or ``none``. Null for every other verdict, and
    # for a true positive that an older release stored.
    impact: str | None = None
    # The first line of the run, built by the server: the verdict, the impact
    # of a true positive, and the source and the target as "name (role)
    # address" where the Hosts data has a name or a role. A row of an older
    # release gets the line at read time, and its impact reads "not stated".
    # Null for a run with no verdict and for a pipeline error.
    firstLine: str | None = None
    # The headline of the run: the sentence the Alerts row and the
    # investigation page state, scrubbed. The list prints it under the name.
    # Null for a run with no verdict and for a pipeline error.
    headline: str | None = None
    # The active campaign that this run is a member of, or null.
    campaign: CampaignLinkOut | None = None


def authorization_ref(mark: authorized_svc.Mark | None) -> _timeline.AuthorizationRefOut | None:
    """The mark of a run as the API states it, or None."""
    if mark is None:
        return None
    return _timeline.AuthorizationRefOut(
        id=mark.id,
        label=mark.label,
        state=mark.state,
        expiresAt=_iso_utc(mark.expires_at),
        by=mark.by,
    )


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
    labels: dict[str, first_line_svc.HostLabel] | None = None,
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
        name=inv.rule_name or f"Alert {inv.alert_es_id or inv.id}",
        # Persisted since migration 0031. Legacy rows were backfilled
        # kind='suricata' regardless of their feed doc's real kind. The list
        # route corrects them from the stored alert context before this runs
        # (heal_detection_kinds, RL5).
        kind=inv.kind,
        subjectType=_subject_type(inv),
        verdict=_verdict(inv.verdict),
        conf=inv.confidence,
        host=inv.src_ip or "—",
        dst=inv.dest_ip,
        hostName=inv.host_name,
        status=_row_status(inv),
        when=_ago(_iso_utc(inv.created_at)),
        # tz-AWARE ISO so the browser localizes correctly (naive → parsed as local).
        ts=_iso_utc(inv.created_at),
        eventAt=_iso_utc(inv.event_at or inv.created_at),
        eventWhen=_ago(_iso_utc(inv.event_at or inv.created_at)),
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
        runClass=_run_class_of(inv),
        ranBy=inv.started_by or "",
        authorizationId=inv.authorization_id,
        impact=None if is_pipeline_fallback(inv.report) else stored_impact(inv.report, inv.verdict),
        firstLine=_first_line(inv, labels),
        headline=_row_headline(inv),
    )


def _row_headline(inv: Investigation) -> str | None:
    """The headline of a run for its list row, or None.

    The same sentence the Alerts row and the investigation page state. The
    first line repeated the verdict chip and the Source to Dest cells of the
    row (polish review 2026-11-13).
    """
    if _verdict(inv.verdict) == "untriaged" or is_pipeline_fallback(inv.report):
        return None
    report = inv.report if isinstance(inv.report, dict) else {}
    _summary, headline, _model = _timeline._run_text(report, inv)
    return scrub_secrets(headline).strip() or None


def _first_line(
    inv: Investigation, labels: dict[str, first_line_svc.HostLabel] | None
) -> str | None:
    """The first line of a run for the API, with any credential scrubbed."""
    line = first_line_svc.of_run(inv, labels)
    return scrub_secrets(line) if line else None


async def _detail_first_line(request: Request, settings: Any, inv: Investigation) -> str | None:
    """The first line of one run for its page, with the Hosts data read when needed."""
    async with request.app.state.db_sessionmaker() as db:
        return _first_line(inv, await _host_labels(db, settings, [inv]))


async def _host_labels(
    db: Any, settings: Any, runs: Sequence[Investigation]
) -> dict[str, first_line_svc.HostLabel]:
    """The Hosts data labels for the runs that store no first line.

    One read for a page. A run that stores its line needs none: the line
    holds the names as they stood when the run ended.
    """
    values = [
        value
        for inv in runs
        if not (isinstance(inv.report, dict) and inv.report.get(first_line_svc.FIRST_LINE_KEY))
        or (isinstance(inv.report, dict) and inv.report.get("resolution"))
        for value in first_line_svc.run_values(inv)
    ]
    if not values:
        return {}
    return await first_line_svc.labels_for_settings(db, values, settings)


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


def _group_key(inv: Any) -> str | None:
    """The key of the group a run belongs to: its alert, or its hunt finding.

    None for a run that stands alone. The primacy rule reads one group per key.
    """
    alert = inv_svc.alert_group_id(inv)
    if alert is not None:
        return alert
    finding = inv_svc.finding_group_id(inv)
    return inv_svc.finding_group_key(finding) if finding is not None else None


async def _page_group_runs(db: Any, rows: Sequence[Any]) -> list[inv_svc.RunRef]:
    """Every run of each group that a page row names: the primacy input.

    The runs of one alert form a group, and the runs of one hunt finding form
    a group too. A retry or a Re-run of a finding left its older run on the
    list as the current answer (production, 2026-11-13).
    """
    alert_ids = sorted({g for inv in rows if (g := inv_svc.alert_group_id(inv))})
    out = list(await inv_svc.runs_for_alerts(db, alert_ids))
    finding_groups = sorted({f for inv in rows if (f := inv_svc.finding_group_id(inv))})
    for runs in (await inv_svc.runs_for_findings(db, finding_groups)).values():
        out.extend(runs)
    return out


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


def _csv_filter(name: str, raw: str | None, allowed: tuple[str, ...]) -> list[str]:
    """Parse a comma-separated multi-value filter param, refusing unknowns.

    Unknown members used to be dropped, and an all-unknown filter read as no
    filter: ``status=garbage`` answered with the unfiltered total, a count that
    looked like an answer. The console already cleans a mangled deep link on
    its side (verdictFilterFromSearch, errorStateFromSearch) before it asks, so
    the server refuses what is left with the accepted values.
    """
    if not raw:
        return []
    members = [p.strip() for p in raw.split(",") if p.strip()]
    unknown = [v for v in members if v not in allowed]
    if unknown:
        raise api_error(
            422,
            "bad_filter",
            f"{name} accepts these values: {', '.join(allowed)}. "
            "Separate two or more values with commas.",
        )
    return members


def _impact_sort_and_clock(
    impact: str | None, sort: str | None, clock: str | None
) -> tuple[list[str], str, str]:
    """The impact filter, the order and the clock of the list, each refused when unknown."""
    impacts = _csv_filter("impact", impact, IMPACT_ORDER)
    if sort and sort not in inv_svc.PAGE_SORTS:
        raise api_error(
            422,
            "bad_filter",
            f"sort accepts one of these values: {', '.join(inv_svc.PAGE_SORTS)}.",
        )
    if clock and clock not in inv_svc.PAGE_CLOCKS:
        raise api_error(
            422,
            "bad_filter",
            f"clock accepts one of these values: {', '.join(inv_svc.PAGE_CLOCKS)}.",
        )
    return impacts, sort or inv_svc.SORT_NEWEST, clock or inv_svc.CLOCK_EVENT


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
    # The backtest replays the other filters match. With ``include_backtest``
    # off (the default) the rows and the figures above leave them out, and
    # this is the count the console names beside them. With it on, the rows
    # and the figures include them, and this says how many of them are replays.
    backtestReplays: int = 0
    # Echo of the request: whether the rows and the figures include replays.
    includesBacktest: bool = False
    # Echo of the ``entity`` filter: every key the filter matched on. The
    # machine of the entity is stored under each of its addresses and names.
    # Null when the request named no entity.
    entityKeys: list[str] | None = None


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
    include_backtest: bool = False,
    pending_action: bool = False,
    entity: str | None = None,
    authorization: int | None = None,
    needs_you: bool = False,
    impact: str | None = None,
    sort: str | None = None,
    primary_only: bool = False,
    clock: str | None = None,
) -> InvestigationListOut:
    """Investigation rows, newest first — filtered, counted and paged in SQL.

    ``status`` / ``verdict`` are comma-separated multi-selects (single values —
    the old contract — parse identically). ``since``/``until`` bound the time
    of the event that a run judges (``eventAt``) inclusively, and the rows
    come newest event first. ``clock=investigated`` bounds and orders on the
    time when soc-ai started the run (``ts``) instead: the pipeline errors
    of 30 days are a list of what soc-ai did. ``q`` is free text matched
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
    An unknown value is refused with 422, like an unknown ``verdict`` member.

    ``entity`` keeps the real runs that name one machine: either end of the
    flow is one of its addresses, or the reporting host is one of its names.
    The value may be any key of the machine. A value that names no machine
    filters on itself. Synth-eval runs and backtest replays never match it,
    so the host page count and this list agree. ``q`` matched one key, and
    the host page of a domain controller found 1 of its 7 runs that way
    (dogfood 2026-10-19, R4-D3).

    ``include_backtest`` puts the backtest replays into the rows and the
    figures. Off by default: a replay is a measurement on an alert an analyst
    already closed, and the list and the Dashboard count live work. Each row
    carries ``ranBy``, so the console can mark a replay when it shows one.

    ``pending_action`` keeps only the runs with a recommended action that waits
    for a person, the runs the needs-you count counts
    (:func:`routes_meta.pending_action_runs`), inside ``since``/``until``. Each
    row then carries ``pendingActions`` and ``waitingActions``, the actions the
    console offers on the row (:func:`routes_meta.waiting_actions_by_run`). The
    needs-you line linked to the whole list, and the analyst paged through
    every run to find the actions (dogfood 2026-10-19, R1-I1). A replay never
    has a pending action, so the filter leaves replays out even with
    ``include_backtest``.

    ``authorization`` keeps only the runs that matched one authorized
    activity, by its id. The card of the authorization links here with its
    count. Each row carries ``authorizationId`` and ``authorization`` whatever
    the filter: a run inside an authorized scope stays in every list.

    ``needs_you`` keeps the runs that wait on the analyst: a verdict that
    needs more info, or a recommended action that waits for a person, inside
    ``since``/``until``. The rows carry ``pendingActions`` and
    ``waitingActions`` as under ``pending_action``. ``GET /needs-you`` counts
    ``investigations_waiting`` with this query, so the Investigations badge and
    the Needs you view state one number. The badge said 39 (9 runs plus 30
    actions) over a list of 64 other rows (production review 2026-11-12,
    ui-core 7). The other filters narrow the set.

    ``impact`` keeps the true positives whose impact is one of the values:
    ``succeeded``, ``attempted``, ``unknown``, ``none``. It is a
    comma-separated multi-select. ``unknown`` also matches a true positive
    that states no impact, which is every true positive of an older release.

    ``sort`` is ``newest`` (the default) or ``verdict``. ``verdict`` puts the
    worst verdict first: true positive, needs more info, inconclusive, false
    positive. Inside the true positives the impact is the first key, in the
    order above. The newest run is first inside each group. An unknown value
    is refused with 422.

    Each row carries ``impact`` and ``firstLine``.
    """
    statuses = _csv_filter("status", status, inv_svc.DISPLAY_STATUSES)
    verdicts = _csv_filter("verdict", verdict, _VERDICT_FILTERS)
    impacts, order, window_clock = _impact_sort_and_clock(impact, sort, clock)
    if error_state and error_state not in _ERROR_STATES:
        raise api_error(
            422,
            "bad_filter",
            f"error_state accepts one of these values: {', '.join(_ERROR_STATES)}.",
        )
    wanted_state = error_state or None
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
    wanted_entity = (entity or "").strip()
    if len(wanted_entity) > _SEARCH_MAX:
        raise api_error(
            422,
            "bad_filter",
            f"An entity may be at most {_SEARCH_MAX} characters.",
        )
    async with request.app.state.db_sessionmaker() as db:
        pending: dict[str, int] | None = None
        if pending_action or needs_you:
            from soc_ai.api.webui.routes_meta import (  # noqa: PLC0415 - cycle
                request_pending_action_runs,
            )

            # Once per request: GET /needs-you reads the same scan for its
            # pending_actions part.
            pending = await request_pending_action_runs(
                request,
                db,
                since=routes_hunts._naive_utc(since),
                until=routes_hunts._naive_utc(until),
                clock=window_clock,
            )
        entity_keys = (
            await host_machines.entity_expansion(db, wanted_entity) if wanted_entity else None
        )
        only_ids = set(pending) if pending is not None and pending_action else None
        if authorization is not None:
            matched = set(await authorized_svc.run_ids(db, authorization))
            only_ids = matched if only_ids is None else only_ids & matched
        page = await inv_svc.query_page(
            db,
            since=routes_hunts._naive_utc(since),
            until=routes_hunts._naive_utc(until),
            verdicts=verdicts,
            statuses=statuses,
            q=needle or None,
            limit=read_limit,
            offset=read_offset,
            include_backtest=include_backtest,
            ids=None if only_ids is None else sorted(only_ids),
            entity_keys=entity_keys,
            needs_you_ids=sorted(pending) if needs_you and pending is not None else None,
            impacts=impacts or None,
            sort=order,
            primary_only=primary_only,
            clock=window_clock,
        )
        marks = await authorized_svc.marks_for(db, [inv.authorization_id for inv in page.rows])
        labels = await _host_labels(db, request.app.state.settings, page.rows)
        # A row stored with the old "suricata" default shows the type its alert
        # document names (RL5). Corrected once, in place.
        await inv_svc.heal_detection_kinds(db, page.rows)
        chat_counts = await chat_svc.counts_for(db, [inv.id for inv in page.rows])
        campaigns = await campaign_svc.links_of(db, [inv.id for inv in page.rows])
        group_rows = await _page_group_runs(db, page.rows)
        waiting: dict[str, list[_timeline.WaitingActionOut]] | None = None
        if pending is not None:
            from soc_ai.api.webui.routes_meta import (  # noqa: PLC0415 - cycle
                waiting_actions_by_run,
            )

            waiting = await waiting_actions_by_run(
                db,
                [inv for inv in page.rows if inv.id in pending],
                demo=is_demo(request.app.state.settings),
                state=request.app.state,
            )
    # Primacy over the FULL groups. A page row that names no group — a blank
    # alert_es_id, or a hunt-subject run, whose anchor document is a time
    # anchor and not its subject — contributes no group to fan out on, so it
    # is merged in as its own one-run group; otherwise it would carry the
    # default isPrimary and the decision would be made for it rather than
    # about it. Newest-first order is what _primary_run_ids assumes.
    seen = {r.id for r in group_rows}
    combined = group_rows + [
        inv_svc.RunRef(inv.id, _group_key(inv), inv.status, inv.created_at)
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
            latest_run=latest.get(_group_key(inv) or inv.id),
            labels=labels,
        )
        for inv in page.rows
    ]
    _apply_marks(rows, marks, campaigns)
    if pending is not None:
        for row in rows:
            row.pendingActions = pending.get(row.id, 0)
            row.waitingActions = (waiting or {}).get(row.id, [])
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
            backtestReplays=page.backtest_replays,
            includesBacktest=include_backtest,
            entityKeys=entity_keys,
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
        # Counted over the partition like the figures above. With replays
        # left out, the partition holds none.
        backtestReplays=sum(1 for r in kept if inv_svc.is_backtest_actor(r.ranBy)),
        includesBacktest=include_backtest,
        entityKeys=entity_keys,
    )


@router.get("/investigations/{inv_id}", response_model=InvestigationOut)
async def get_investigation(  # noqa: PLR0915 - one linear read of the run and its context
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
        await inv_svc.heal_detection_kinds(db, [inv])
        chat = await chat_svc.list_messages(db, inv.id)
        group_runs = await _group_runs(db, inv)
        # The newer run that replaced this one, read whole: the page names its
        # verdict in a banner, so a bookmarked older run never reads as the
        # current answer (dogfood 2026-10-06, investigation S1). A Re-run of a
        # hunt finding replaces the older run of the finding the same way.
        superseded_by = _superseded_by(inv, group_runs) or await _answered_by(db, inv)
        newer = await db.get(Investigation, superseded_by) if superseded_by else None
        standing_analyst, live_run = await _alert_verdicts(db, inv)
        # A promoted run that uses the alert of this run as its anchor. The
        # action rule refuses every write for that alert when the anchor is
        # not a Security Onion alert (V3-N2). The grid answers below.
        anchor = (
            (await inv_svc.hunt_anchor_kinds(db, [inv.alert_es_id])).get(inv.alert_es_id)
            if inv.alert_es_id and not inv_svc.is_promoted(inv)
            else None
        )
        typical = (
            routes_hunts._typical_run(await _recent_run_seconds(db))
            if inv.status == "running"
            else None
        )
        # Promotion provenance: hunt_id has no FK (the referenced hunt may be
        # deleted — see the Investigation model note), so this must degrade
        # gracefully rather than 404/500 when the row is gone.
        # A hunt-subject run reads its hunt too, whatever its kind: a lead
        # promotion is kind 'lead' and its subject is still a hunt.
        wants_hunt = inv.kind == "hunt" or _subject_type(inv) == "hunt"
        hunt = await db.get(Hunt, inv.hunt_id) if wants_hunt and inv.hunt_id else None
        # The authorized activity the run matched, and the line of a run
        # that is outside one.
        mark, outside_line = await _authorization_of(db, inv)
        campaign = link_for(await campaign_svc.links_of(db, [inv.id]), inv.id)

    # A row stored before the store-side scrub existed can still hold a
    # credential the model quoted. Scrub the model-written text on read too.
    report = scrub_value(inv.report or {})
    # Live acked state so an ack performed OUTSIDE this run (group-ack, another
    # run's auto-ack, the SO web UI) marks the ack action applied. False on any
    # ES error — the action is simply offered as before.
    ack_state = await _timeline._alert_ack_state(elastic, settings, inv.alert_es_id)
    alert_acked = ack_state is True
    actions = _build_actions(
        events,
        report,
        alert_acked=alert_acked,
        # The grid answered and the alert is not acknowledged: an ack the
        # record calls done reads as pending, so the card and the grid agree.
        alert_unacked=ack_state is False,
        ran_at=_iso_utc(inv.finished_at or inv.created_at) or None,
        replay=inv_svc.is_backtest(inv),
    )
    anchor_status = (
        (await anchor_check.alert_status(request.app.state, [inv.alert_es_id])).get(
            inv.alert_es_id, anchor_check.UNKNOWN
        )
        if anchor is not None and inv.alert_es_id
        else anchor_check.NOT_ALERT
    )
    write_blocked, alert_cases, cases_complete = await _apply_action_rule(
        request,
        elastic,
        settings,
        inv,
        events,
        report,
        actions,
        superseded_by=superseded_by,
        analyst=standing_analyst,
        anchor=anchor,
        anchor_status=anchor_status,
        authorized=mark.label if mark is not None and mark.holds else None,
        campaign=campaign,
    )

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
    # A tool result or a host summary in the timeline can quote a credential
    # from telemetry. The row stays verbatim in the store; the page does not
    # show the value.
    for step in timeline:
        step.title = scrub_secrets(step.title)
        step.detail = scrub_secrets(step.detail)
    nodes, edges, graph_note = _entity_graph(alert_obj, enrichments, inv)
    # The text of the run. The headline never contradicts the final verdict,
    # and a row of an older release is repaired (B2).
    # A run inside a scope whose authorization holds: each sentence that
    # denies an authorization goes. The model never reads an authorization,
    # so such a sentence is ungrounded. The store keeps the report, so a
    # revoke returns the text (polish review 2026-11-13).
    summary_text, headline_text, model_text = _text_under_mark(report, inv, actions, mark)
    # The endpoints chip reads the alert's own fields. A host-reported alert
    # names a source address and a host, and no destination: the host is where
    # the alert came from, and it is never one end of the flow.
    src_addr = _str_or_none(alert_obj.get("source_ip")) or _str_or_none(inv.src_ip)
    dst_addr = _str_or_none(alert_obj.get("destination_ip")) or _str_or_none(inv.dest_ip)
    reporter = _str_or_none(alert_obj.get("host_name"))
    # Each host, address, user and domain the run names, with the page that
    # answers for it. The page renders each one as a link.
    async with request.app.state.db_sessionmaker() as db:
        entities = await routes_entity.investigation_entities(
            db,
            settings,
            src=src_addr,
            dst=dst_addr,
            reporter=reporter or _str_or_none(inv.host_name),
            subject=_subject_out(inv, hunt),
        )
    # What served the run (B4). The model line names the model that the run
    # asked for, when the run recorded it.
    served_model, requested_model, served_fallback = _timeline._served_model_of(report, events)
    meta = InvMetaOut(
        model=requested_model or settings.analyst_model,
        lowReasoning=_timeline._low_reasoning_of(report, events),
        servedModel=served_model,
        requestedModel=requested_model,
        servedFallback=served_fallback,
        oracle=_oracle_line(settings, inv, has_oracle),
        ranBy=inv.started_by or "—",
        # tz-AWARE ISO (with +00:00) so the value is unambiguous UTC — the raw
        # naive string had no offset, so it couldn't be localized/interpreted.
        ranAt=_iso_utc(inv.created_at),
        eventAt=_iso_utc(inv.event_at or inv.created_at),
        toolCalls=tool_calls,
        pivots=pivots,
    )
    # One read of the citations: the page links them, and the Event timeline
    # lists the documents they name (change D).
    citations = _timeline._citations_out(report, events)
    return InvestigationOut(
        id=inv.id,
        groupId=inv.alert_es_id or inv.id,
        name=inv.rule_name or f"Alert {getattr(inv, 'alert_es_id', None) or inv.id}",
        kind=inv.kind,
        host=src_addr or "—",
        ip=dst_addr or "—",
        srcIp=src_addr,
        dstIp=dst_addr,
        reportedBy=reporter,
        verdict=_verdict(inv.verdict),
        conf=inv.confidence if inv.confidence is not None else 0.0,
        rationale=scrub_secrets(headline_text),
        summary=[{"t": "text", "v": scrub_secrets(summary_text)}],
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
        hostContexts=_timeline._host_contexts(enr_p.get("host_alert_profiles")),
        graphNote=graph_note,
        graphScope=_graph_scope(alert_obj, enrichments, inv),
        hostContextWindowHours=settings.host_risk_window_hours,
        openQuestions=_timeline._open_questions_out(report, events),
        citations=citations,
        failure=_timeline._failure_out(inv.status, events),
        resolution=report.get("resolution") or None,
        validatorNote=_note_or_none(report.get("validator_note")),
        modelText=scrub_secrets(model_text) if model_text else None,
        verdictChange=_timeline._verdict_change_out(report, events),
        impact=None if is_pipeline_fallback(report) else stored_impact(report, inv.verdict),
        impactChange=_timeline._impact_change_out(report, inv.verdict),
        firstLine=await _detail_first_line(request, settings, inv),
        oracleReasoning=_note_or_none(report.get("oracle_reasoning")),
        # Pipeline-failure provenance (E1.2) — non-None ONLY for a synth-failure
        # fallback run; drives the drawer's "failed before reaching a verdict"
        # panel instead of the amber Needs-info block.
        fallback=_timeline._fallback_out(report),
        errorDismissed=inv.error_dismissed_at is not None,
        subject=_subject_out(inv, hunt),
        huntId=inv.hunt_id,
        huntObjective=(hunt.objective if hunt else None),
        promotedFinding=_with_evidence(routes_hunts.promoted_finding_out(inv, hunt), inv, hunt),
        alertAcked=alert_acked,
        isSynthEval=bool(inv.is_synth_eval),
        supersededBy=superseded_by,
        supersededRun=_superseded_run_out(newer),
        standingAnalystVerdict=standing_analyst,
        writeBlockedReason=write_blocked,
        promotedKind=action_rules.promoted_kind(inv),
        alertCases=alert_cases,
        alertCasesComplete=cases_complete,
        alertLiveRun=_superseded_run_out(live_run),
        currentStep=current_activity(events) if inv.status == "running" else None,
        typicalRun=typical.model_dump() if typical is not None else None,
        runClass=_run_class_of(inv),
        runClassReason=_str_or_none(report.get("run_class_reason")),
        entities=entities,
        eventTimeline=_event_timeline.investigation_event_timeline(
            events, citations, inv.status, focus_ids=_finding_focus_ids(inv, hunt)
        ),
        authorizationId=inv.authorization_id,
        authorization=authorization_ref(mark),
        outsideAuthorizedScope=outside_line,
        campaign=campaign,
        needsYouCleared=needs_you_clear.cleared_sentence(inv.report),
    )


def _apply_marks(
    rows: list[InvestigationRowOut],
    marks: dict[int, authorized_svc.Mark],
    campaigns: Mapping[str, campaign_svc.CampaignLink] | None = None,
) -> None:
    """Give each row its mark, the headline that its mark allows, and its campaign.

    A run whose authorization holds drops each sentence that denies an
    authorization (:func:`authorized_svc.run_text_for_mark`).
    """
    for row in rows:
        row.campaign = link_for(campaigns or {}, row.id)
        mark = marks.get(row.authorizationId or 0)
        row.authorization = authorization_ref(mark)
        if row.headline:
            row.headline = authorized_svc.run_text_for_mark(row.headline, mark)


def _text_under_mark(
    report: dict[str, Any],
    inv: Investigation,
    actions: Sequence[_timeline.RecommendedActionOut],
    mark: authorized_svc.Mark | None,
) -> tuple[str, str, str | None]:
    """(summary, headline, model text) of a run under its mark.

    The summary, the headline and the rationale of each action drop each
    sentence that denies an authorization when the mark holds. The rationale
    of each action changes in place. The model text is the quote under "The
    model wrote" and stays as the model wrote it.
    """
    summary, headline, model_text = _timeline._run_text(report, inv)
    for action in actions:
        action.rationale = authorized_svc.run_text_for_mark(action.rationale, mark)
    return (
        authorized_svc.run_text_for_mark(summary, mark),
        authorized_svc.run_text_for_mark(headline, mark),
        model_text,
    )


async def _authorization_of(
    db: Any, inv: Investigation
) -> tuple[authorized_svc.Mark | None, str | None]:
    """The mark of the authorization a run matched, and its outside line.

    The line is ``report["authorized_activity"]["line"]`` of a run that is
    outside a scope. It names an authorization. After a revoke that
    authorization covers nothing, so the line would point at a scope that is
    gone, and the page then shows none.
    """
    raw = inv.report.get(authorized_svc.REPORT_KEY) if isinstance(inv.report, dict) else None
    outside = (
        raw if isinstance(raw, dict) and raw.get("state") == authorized_svc.RUN_OUTSIDE else None
    )
    named = outside.get("id") if outside is not None else None
    marks = await authorized_svc.marks_for(
        db, [inv.authorization_id, named if isinstance(named, int) else None]
    )
    line = outside.get("line") if outside is not None else None
    scope = marks.get(named) if isinstance(named, int) else None
    shown = line if isinstance(line, str) and scope is not None and scope.holds else None
    return marks.get(inv.authorization_id or 0), shown


async def _apply_action_rule(
    request: Request,
    elastic: ElasticClient,
    settings: Settings,
    inv: Investigation,
    events: Sequence[Any],
    report: dict[str, Any],
    actions: Sequence[Any],
    *,
    superseded_by: str | None,
    analyst: StandingAnalystVerdictOut | None,
    anchor: str | None,
    anchor_status: str = anchor_check.NOT_ALERT,
    authorized: str | None = None,
    campaign: CampaignLinkOut | None = None,
) -> tuple[str | None, list[CaseRefOut], bool]:
    """Set the ``blockedReason`` of each action card, under the one action rule.

    The rule is :func:`action_rules.action_block`, the one the row of the
    pending-action list, the needs-you count and the execute route read, so
    the card and the row cannot disagree (V3-N2). Returns the run-level
    reason, the cases the alert is already on, and whether the grid
    confirmed that list.

    The run-level reason holds the rules with no page state of their own: a
    promotion, and the anchor of a promotion. The settled bar and the
    escalate of the chat read it. The page shows the replay and the
    superseded run on its own, and the demo note at the press.

    The cases are read only when an escalate waits. The card names each case:
    the execute route opens no second case.

    A run that a campaign holds keeps its actions executable, except its
    Escalate: the campaign opens the one case. Each card then carries the
    note ``campaign`` and the link of the campaign: the analyst decides on
    the campaign (:func:`action_rules.action_note`).
    """
    from soc_ai.api.webui.routes_actions import _observed_case_id  # noqa: PLC0415 - cycle

    facts = action_rules.ActionFacts(
        replay=inv_svc.is_backtest(inv),
        superseded_by=superseded_by,
        promoted=action_rules.promoted_kind(inv),
        anchor=anchor,
        anchor_status=anchor_status,
        alert_id=inv.alert_es_id,
        run_verdict=inv.verdict,
        analyst_verdict=analyst.verdict if analyst is not None else None,
        analyst_by=analyst.by if analyst is not None else None,
        case_id=_observed_case_id(list(events)),
        authorized=authorized,
        demo=is_demo(settings),
    )
    facts = action_rules.with_campaign(facts, campaign)
    note = action_rules.action_note(facts)
    for action, tool_name in zip(actions, action_tool_names(events, report), strict=False):
        action.blockedReason = action_rules.block_reason(facts, tool_name)
        if note is not None and not action.applied and not action.dismissed:
            action.noteCode = note.code
            action.note = note.reason
            action.noteHref = f"/campaigns/{facts.campaign_id}"
    write_blocked = action_rules.block_reason(
        dataclasses.replace(facts, replay=False, superseded_by=None, demo=False), None
    )
    if not (
        inv.alert_es_id
        and facts.promoted is None
        and not facts.replay
        and not facts.superseded_by
        and any(a.tag == "escalate" and not a.applied for a in actions)
    ):
        return write_blocked, [], False
    case_ids, complete = await case_links.cases_of_alert(
        request.app.state.db_sessionmaker, elastic, settings, inv.alert_es_id
    )
    cases = [CaseRefOut(id=c, url=case_links.case_url(settings, c)) for c in case_ids]
    return write_blocked, cases, complete


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _run_class_of(inv: Investigation) -> str | None:
    """The budget class the run ran in: the column, else the stored report.

    A run still in flight has no column value yet. Its report has no class
    either, so the answer is None: the class is not known until the run ends.
    """
    if isinstance(inv.run_class, str) and inv.run_class:
        return inv.run_class
    report = inv.report if isinstance(inv.report, dict) else {}
    return _str_or_none(report.get("run_class"))


def _str_list(value: Any) -> list[str]:
    return [str(v) for v in value if isinstance(v, str | int)] if isinstance(value, list) else []


def _with_evidence(
    finding: dict[str, Any] | None, inv: Investigation, hunt: Hunt | None
) -> dict[str, Any] | None:
    """The promoted finding with its detail and its cited documents.

    The page shows the finding's evidence first (dogfood 2026-10-06, hunting
    C4). The finding stores both, so they are read from the same report.
    """
    if finding is None or hunt is None:
        return finding
    findings = routes_hunts._hunt_report(hunt).get("findings") or []
    ordinal = finding.get("ordinal")
    f = findings[ordinal] if isinstance(ordinal, int) and 0 <= ordinal < len(findings) else None
    if not isinstance(f, dict):
        return finding
    return {
        **finding,
        "detail": str(f.get("detail") or ""),
        "citations": _str_list(f.get("citations")),
    }


async def _recent_run_seconds(db: Any, *, limit: int = 20) -> list[float]:
    """The wall time of the newest finished investigations, in seconds."""
    rows = (
        await db.execute(
            select(Investigation.created_at, Investigation.finished_at)
            .where(
                Investigation.status == "complete",
                Investigation.finished_at.is_not(None),
            )
            .order_by(Investigation.finished_at.desc())
            .limit(limit)
        )
    ).all()
    return [
        (finished - created).total_seconds()
        for created, finished in rows
        if created is not None and finished is not None
    ]


def _oracle_line(settings: Settings, inv: Investigation, has_oracle: bool) -> str:
    """One sentence on the Oracle review of this verdict.

    Every row read "not escalated, local verdict", on a deployment where the
    Oracle was off, with no word on what the Oracle is (dogfood 2026-10-06,
    O1). The line now says why no review ran, or that the Oracle is off.
    """
    if has_oracle:
        return "Oracle review: done. The Oracle card shows its answer."
    if not settings.oracle_enabled:
        return "The Oracle is off on this deployment. No verdict goes to a review."
    conf = inv.confidence
    band = settings.oracle_escalate_below_confidence
    if inv.status != "complete" or conf is None:
        return "Oracle review: none. The investigation has no verdict to review."
    if conf >= band:
        return f"Oracle review: not needed. Confidence {conf:.2f} is above the review band."
    return f"Oracle review: not run. Confidence {conf:.2f} is under {band:.2f}."


async def _alert_verdicts(
    db: Any, inv: Investigation
) -> tuple[StandingAnalystVerdictOut | None, Investigation | None]:
    """The analyst verdict that stands on the alert, and a replay's live run.

    A new run from this page can replace the verdict of the alert. The page
    asks first when an analyst verdict stands on ANY run of the alert, and it
    names it (dogfood 2026-10-19, V1-A3). On a backtest replay it also names
    the live verdict the new run replaces (V1-A2). A hunt subject names a
    cited document, and the store reads no verdict of it as the alert's.
    """
    alert_id = inv.alert_es_id
    if not alert_id or inv_svc.is_hunt_subject(inv):
        return None, None
    found = (await inv_svc.analyst_verdicts_for_alerts(db, [alert_id])).get(alert_id)
    analyst = (
        StandingAnalystVerdictOut(
            investigationId=found.investigation_id,
            verdict=_verdict(found.verdict),
            by=found.resolved_by or None,
            via=found.resolved_via,
            at=found.resolved_at,
        )
        if found is not None
        else None
    )
    live = None
    if inv_svc.is_backtest(inv):
        live = (await inv_svc.standing_for_alerts(db, [alert_id])).get(alert_id)
    return analyst, live


def _superseded_run_out(newer: Investigation | None) -> SupersededRunOut | None:
    """What the newer run reached: its status, and its verdict once it has one."""
    if newer is None:
        return None
    status = _row_status(newer)
    complete = status == "complete" and bool(newer.verdict)
    return SupersededRunOut(
        id=newer.id,
        status=status,
        verdict=_verdict(newer.verdict) if complete else None,
        conf=newer.confidence if complete else None,
    )


async def _answered_by(db: Any, inv: Investigation) -> str | None:
    """The run that answered this run's Request more info, when one exists.

    The alert group links a live run to its answer. A backtest replay stands
    alone, so its answer is read off the report (R2-D12). An answer that
    failed answers nothing, and the page keeps its actions.
    """
    fid = inv_svc.follow_up_id(inv)
    if not fid or fid == inv.id:
        return None
    answer = await db.get(Investigation, fid)
    if answer is None or answer.status not in ("running", "complete"):
        return None
    return fid


async def _group_runs(db: Any, inv: Investigation) -> list[inv_svc.RunRef]:
    """Every run of the group of *inv*, newest first: its alert, or its hunt finding.

    Empty for a run that stands alone.
    """
    group_id = inv_svc.alert_group_id(inv)
    if group_id:
        return await inv_svc.runs_for_alerts(db, [group_id])
    finding = inv_svc.finding_group_id(inv)
    if finding is not None:
        return (await inv_svc.runs_for_findings(db, [finding])).get(finding, [])
    return []


async def superseding_run_id(db: Any, inv: Investigation) -> str | None:
    """The newer run that replaced *inv*, by the rule the detail page uses."""
    return _superseded_by(inv, await _group_runs(db, inv)) or await _answered_by(db, inv)


async def superseding_run_ids(db: Any, runs: Sequence[Investigation]) -> dict[str, str]:
    """:func:`superseding_run_id` for many runs: run id to the run that replaced it.

    One read of the alert groups and one of the finding groups for every run,
    so a list row pays no query of its own. A run that stands is not in the
    answer.
    """
    group_ids = sorted({g for inv in runs if (g := inv_svc.alert_group_id(inv))})
    by_group: dict[str, list[inv_svc.RunRef]] = {}
    for ref in await inv_svc.runs_for_alerts(db, group_ids):  # newest first
        by_group.setdefault(ref.alert_es_id or "", []).append(ref)
    by_finding = await inv_svc.runs_for_findings(
        db, [f for inv in runs if (f := inv_svc.finding_group_id(inv)) is not None]
    )
    out: dict[str, str] = {}
    for inv in runs:
        group_id = inv_svc.alert_group_id(inv)
        finding = inv_svc.finding_group_id(inv)
        if group_id:
            group_runs = by_group.get(group_id, [])
        elif finding is not None:
            group_runs = by_finding.get(finding, [])
        else:
            group_runs = []
        newer = _superseded_by(inv, group_runs)
        if newer is None:
            newer = await _answered_by(db, inv)
        if newer:
            out[inv.id] = newer
    return out


def _superseded_by(inv: Investigation, group_runs: Sequence[inv_svc.RunRef]) -> str | None:
    """The newer primary run of the same alert, when one replaced this run.

    None when this run is the alert's primary run, when it stands alone, and
    when the primary run is OLDER (an errored retry of a settled alert): no
    newer run replaced that one, and the page must not say so.
    """
    if not group_runs:
        return None
    primary = _primary_run_ids(group_runs)
    if inv.id in primary:
        return None
    this = next((r for r in group_runs if r.id == inv.id), None)
    for run in group_runs:  # newest-first
        if (
            run.id in primary
            and this is not None
            and (run.created_at, run.id)
            > (
                this.created_at,
                this.id,
            )
        ):
            return run.id
    return None


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
                        "This investigation reached a verdict and did not fail. "
                        "There is nothing to dismiss."
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


def _lead_promotion(inv: Investigation, anchor_kind: str | None) -> bool:
    """Whether a refused new run concerns a promoted lead, not a finding.

    A promoted row is a lead run when it is no finding run. Another row over
    a promoted anchor follows the promotion that anchors the document
    (``anchor_kind`` from :func:`inv_svc.hunt_anchor_kinds`). The console has
    a Re-run for a finding run and none for a lead run, so the refusal names
    the remedy that exists.
    """
    if inv_svc.is_promoted(inv):
        return inv.kind != "hunt" and inv.finding_ordinal is None
    return anchor_kind == "lead"


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
    promoted_anchors: dict[str, str] = {}
    analyst_alerts: set[str] = set()
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
            # on over cited telemetry that has no SO alert behind it. An
            # anchor that is a real alert reruns (dogfood 2026-10-21).
            # The kind of the promotion picks the reason a skip names.
            promoted_anchors = await inv_svc.hunt_anchor_kinds(
                db, [inv.alert_es_id for inv in rows if inv.alert_es_id]
            )
            # A new run can replace an analyst verdict on any run of the
            # alert. The page asks first and names the verdict (dogfood
            # 2026-10-19, R2-D1 and V1-A3). This list has no confirm, so it
            # skips the alert and names the reason.
            analyst_alerts = set(
                await inv_svc.analyst_verdicts_for_alerts(
                    db, [inv.alert_es_id for inv in rows if inv.alert_es_id]
                )
            )

    # One grid search for the anchors of the batch, after the store session.
    anchor_states = await anchor_check.alert_status(
        request.app.state,
        [
            inv.alert_es_id
            for inv in inv_by_id.values()
            if inv.alert_es_id in promoted_anchors and not inv_svc.is_promoted(inv)
        ],
    )

    for inv_id in eligible:
        inv = inv_by_id.get(inv_id)
        if inv is None:
            skipped.append({"invId": inv_id, "reason": "not_found"})
            continue

        anchor_state = (
            anchor_states.get(inv.alert_es_id or "", anchor_check.UNKNOWN)
            if inv.alert_es_id in promoted_anchors
            else anchor_check.ALERT
        )
        if inv_svc.is_promoted(inv) or anchor_state == anchor_check.NOT_ALERT:
            # A promoted finding's anchor is cited telemetry, not an SO alert —
            # relaunching it here would mint an unlabeled kind="suricata"
            # duplicate carrying the finding title as rule_name (the exact
            # string the group-ack guard exists to keep out). Re-run on the
            # finding's investigation (the promote route with rerun) is the
            # sanctioned re-run. A lead run has no such Re-run, so its skip
            # names the lead.
            lead = _lead_promotion(inv, promoted_anchors.get(inv.alert_es_id or ""))
            skipped.append({"invId": inv_id, "reason": "lead_kind" if lead else "hunt_kind"})
            continue

        if anchor_state == anchor_check.UNKNOWN:
            # The grid did not say whether the anchor is an alert. The new
            # run could write to Security Onion, so the batch skips it.
            skipped.append({"invId": inv_id, "reason": "anchor_unread"})
            continue

        if not inv.alert_es_id:
            skipped.append({"invId": inv_id, "reason": "no_alert"})
            continue

        if inv.alert_es_id in analyst_alerts:
            skipped.append({"invId": inv_id, "reason": "analyst_verdict"})
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


def _open_questions_of(inv: Investigation, events: Sequence[Any] = ()) -> list[str]:
    """The prior run's open questions: the report's, else the transcript's.

    Same source as the detail's ``openQuestions`` so the focused re-run targets
    the questions the analyst read on the page.
    """
    report = inv.report if isinstance(inv.report, dict) else {}
    return _timeline._open_questions_out(report, list(events))


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
        got = await inv_svc.get_with_events(db, inv_id)
        inv, inv_events = got if got is not None else (None, [])
        # Anchor-keyed, like bulk re-hunt: an ordinary row over a promoted
        # anchor (a re-investigation) is as much off-limits as the promoted
        # row itself — the manager's default kind would relaunch it with SO
        # writes on over cited telemetry that has no SO alert behind it. An
        # anchor that is a real alert reruns (dogfood 2026-10-21). The kind
        # of the promotion picks the remedy the refusal names.
        anchor_kind = (
            (await inv_svc.hunt_anchor_kinds(db, [inv.alert_es_id])).get(inv.alert_es_id)
            if inv is not None and inv.alert_es_id and not inv_svc.is_promoted(inv)
            else None
        )
        over_promoted_anchor = anchor_kind is not None

    if inv is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    anchor_state = (
        (await anchor_check.alert_status(request.app.state, [inv.alert_es_id or ""])).get(
            inv.alert_es_id or "", anchor_check.UNKNOWN
        )
        if over_promoted_anchor
        else anchor_check.ALERT
    )
    if anchor_state == anchor_check.UNKNOWN:
        raise HTTPException(
            status_code=503,
            detail={"reason": "anchor_unread", "hint": action_rules.ANCHOR_UNREAD},
        )
    if inv_svc.is_promoted(inv) or anchor_state != anchor_check.ALERT:
        # Re-run on the finding's investigation (the promote route with
        # rerun) is the sanctioned re-run for a promoted finding —
        # relaunching here would mint an unlabeled kind="suricata" duplicate
        # against the same anchor telemetry doc. A lead run has no re-run in
        # the console, so its refusal names Resolve in chat.
        lead = _lead_promotion(inv, anchor_kind)
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "hunt_kind_no_rerun",
                "hint": (
                    finding_promotion.LEAD_NO_RERUN_HINT
                    if lead
                    else finding_promotion.FINDING_RERUN_HINT
                ),
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

    async with request.app.state.db_sessionmaker() as db:
        answered = await superseding_run_id(db, inv)
    if answered:
        # One question, one answer. A second press started a second run on a
        # run the page already called answered (R2-D12).
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "already_answered",
                "invId": answered,
                "hint": f"Investigation {answered} answers this investigation. Open it.",
            },
        )

    questions = _open_questions_of(inv, inv_events)
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
            "The console did not start the investigation. Check the model gateway in Settings.",
        )
    async with request.app.state.db_sessionmaker() as db:
        await inv_svc.record_follow_up(db, inv_id, follow_up_id=new_inv_id, requested_by=started_by)
    return {"investigation_id": new_inv_id}
