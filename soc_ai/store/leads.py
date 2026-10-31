"""Lead status changes, and the objective a lead writes for a hunt.

A lead is open until an analyst acts. Three actions close or advance it:
hunt (status hunting, a hunt row is attached), dismiss (a reason is
required), promote (an investigation exists). The sharpening loop reads
the dismissal reason later, so the reason comes from a fixed list.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import EntityObservation, Hunt, HuntEvent, Lead

__all__ = [
    "AUTO_HUNT_ACTOR",
    "AUTO_HUNT_RETRY_LIMIT",
    "BACKTEST_DECISION",
    "BACKTEST_DECISION_NOTE",
    "CLOSED_STATUSES",
    "DISMISS_REASONS",
    "GRID_GAP_REASON",
    "HOLD_EARLIER_THREAT",
    "HOLD_LEAD_LINK",
    "HOLD_NO_VERDICT",
    "HOLD_PARTIAL_READ",
    "HOLD_SENTENCES",
    "HUNT_CLEAN_REASON",
    "HUNT_FAILED_STATUSES",
    "HUNT_RUNNING_STATUSES",
    "KEPT_OPEN",
    "OBSERVATION_DISMISS_REASONS",
    "PROMOTED_FINDING_REASON",
    "RELATED_WINDOW_DAYS",
    "RelatedLead",
    "analyst_dismissed",
    "cites_documents",
    "decisions_of",
    "derived_hold_reason",
    "dismiss",
    "dismiss_observation",
    "evidence_block_for",
    "formed_from_backtest",
    "get",
    "hold_reason_of",
    "hunt_did_not_run",
    "hunt_is_queued",
    "hunt_outcome_of",
    "in_progress_clause",
    "keep_open",
    "mark_backtest_leads",
    "mark_hunting",
    "mark_promoted",
    "needs_decision_clause",
    "objective_for",
    "record_decision",
    "related_counts",
    "related_leads",
    "reopen",
    "settle_after_hunt",
    "settle_finished_hunts",
    "timeline",
]

_LOGGER = logging.getLogger(__name__)

# The reasons an analyst may give for a dismissal. ``other`` stays last: the
# form lists them in this order. The sharpening loop reads the reason, so a
# new reason is added here and nowhere else. The column holds 32 characters.
DISMISS_REASONS: tuple[str, ...] = (
    "expected_for_role",
    "known_change",
    "benign_repeat",
    "bad_baseline",
    "authorized_test",
    "duplicate",
    "bad_analytic_logic",
    "lab_host",
    "other",
)

# A closed lead does not absorb new observations. A new lead can form on the
# same entity from observations recorded after the close.
CLOSED_STATUSES: frozenset[str] = frozenset({"dismissed", "promoted"})

# The hand the loop signs its hunts with, and the hand the settle rule signs
# a closure with. Defined here, because the store reads it to tell an
# analyst's dismissal from the rule's, and soc_ai.hunting.lead_hunt imports
# this module. The loop reads it through lead_hunt, as before.
AUTO_HUNT_ACTOR = "auto-hunt"

# The reason the settle rule writes. It is not in DISMISS_REASONS: the form
# offers the analyst five reasons, and this one is the rule's own word.
HUNT_CLEAN_REASON = "hunt_clean"

# The reason the grid-gap review writes on each hit it marks benign
# (soc_ai.hunting.gap_recovery). The note names the gap and its hours. It is
# not in DISMISS_REASONS: no form offers it, and no lead takes it. A hit of a
# gap says something about the grid, and the sharpening loop must not read it
# as a fault of the analytic.
GRID_GAP_REASON = "grid_gap"

# The reasons one observation can carry: the analyst's list and the gap review's.
OBSERVATION_DISMISS_REASONS: tuple[str, ...] = (*DISMISS_REASONS, GRID_GAP_REASON)

# A hunt that ended without an answer. The lead behind one goes back to open,
# and the loop tries once more, then leaves it to the analyst.
HUNT_FAILED_STATUSES: tuple[str, ...] = ("error", "cancelled", "interrupted")
AUTO_HUNT_RETRY_LIMIT = 2

# Why the settle rule did not close a lead whose hunt answered clean. The
# lead waits on the analyst, and the lead page states the reason.
HOLD_PARTIAL_READ = "partial_read"
HOLD_EARLIER_THREAT = "earlier_threat"
# The hunt claimed a link between this lead and other leads, and the gate
# lowered that finding to an observation (change E, 2026-10-30). The claim
# says the activity is part of a campaign, so the lead is no clean answer.
HOLD_LEAD_LINK = "lead_link"
# Why the settle rule did not close a lead whose hunt investigated its subject
# findings: one of them has no verdict. The run failed, fell back, was
# cancelled or never started. The documented rule leaves the lead to the
# analyst. Prod lead 47 (2026-10-24) waited with no reason on its page.
HOLD_NO_VERDICT = "no_verdict"
HOLD_SENTENCES: dict[str, str] = {
    HOLD_PARTIAL_READ: "The hunt could not read all evidence.",
    HOLD_EARLIER_THREAT: "An earlier hunt found a threat.",
    HOLD_LEAD_LINK: "The hunt linked this lead to other leads.",
    HOLD_NO_VERDICT: "A threat finding of the hunt has no verdict.",
}

# The decision an analyst records when an investigation of one of the lead's
# hunt findings reached a verdict and the lead stays open all the same. The
# lead page asks once per investigation, and this entry is the answer.
KEPT_OPEN = "kept_open"
# The reason a promotion carries when the analyst closed the lead on the
# verdict of a promoted finding, and not by promoting the lead itself.
PROMOTED_FINDING_REASON = "finding_verdict"

# The decision that marks a lead formed from backtest replays only. Before
# 2026-10-06 a replay's verdict wrote an alert observation like a live run,
# and on the range a lead formed 74 s after the replay of the same rule.
# The store writes no such observation now. :func:`mark_backtest_leads` marks
# the leads that formed before that. The mark is a note on the lead: it
# changes no status, and :func:`hold_reason_of` reads past it.
BACKTEST_DECISION = "formed_from_backtest"
BACKTEST_DECISION_ACTOR = "soc-ai"
BACKTEST_DECISION_NOTE = (
    "This lead formed from a backtest replay. A backtest replay is a measurement "
    "on an alert an analyst already closed. It is not live evidence."
)
# Decisions that annotate the lead and decide nothing. A reader that asks for
# the last decision skips them.
_ANNOTATION_ACTIONS: frozenset[str] = frozenset({BACKTEST_DECISION, KEPT_OPEN})

# The ``done`` event key the runner sets when the budget synthesizer wrote the
# report. It is the fact the settle rule reads. The runner has written it on
# every ``done`` event since 2026-10-01.
_DONE_PARTIAL_KEY = "partial"

# FROZEN text: the first words of the note a hunt recorded before 2026-10-01
# wrote when the budget synthesizer took over. Such a row has no partial key on
# its ``done`` event, so this stored text is the only record of the partial
# read. It is compared ONLY on a row whose ``done`` event lacks the key: the
# runner's live wording never decides a settle, so an edit to it cannot make a
# partial hunt close its lead as clean.
_LEGACY_PARTIAL_TEXT = "Reached the hunt's exploration budget"

_KIND_WORDS: dict[str, str] = {
    "novel_destination": "a new destination",
    "novel_served_port": "a new served port",
    "novel_consumed_port": "a new outbound port",
    "novel_process": "a new process",
    "novel_process_pair": "a new process pair",
    "novel_binding": "a first logon",
    "rare_for_peers": "a value rare for its peers",
    "off_hours": "off-hours activity",
    "below_baseline": "a collapsed rate",
    "above_baseline": "a rate spike",
    "scope_count": "the same condition on many hosts",
    "estate_outlier": "an outlier against its learned peer group",
    "alert": "a triaged alert",
    "prior_no_baseline": "a finding with no benign baseline",
    "catalog_match": "a catalog analytic match",
    "hunt_finding": "a promoted hunt finding",
    "telemetry_silence": "a silent telemetry plane",
    "logon_chain": "a logon chain",
}


# A hunt that has not finished. Anything else is terminal: complete, error,
# cancelled and interrupted all leave the analyst a decision to take. An
# ``investigating`` hunt landed its report and still investigates its subject
# findings (migration 0063), so its lead waits for the verdicts.
HUNT_RUNNING_STATUSES: tuple[str, ...] = ("running", "queued", "investigating")

# The hand the hunt signs a close with when its findings decided the lead.
SYSTEM_HUNT_ACTOR = "system:hunt"


def _has_a_hunt() -> Any:
    """The SQL for a lead that a hunt is attached to, whatever its status.

    Two statuses carry a hunt. ``hunting`` is the lead the hunt started on.
    ``open`` carries one after a reopen: the reopen keeps the hunt, because
    the work was done and the analyst is reading it again. The tabs read the
    hunt's status from here, not the lead's, so a reopened lead lands on the
    same tab as the lead it was a minute before the dismissal.
    """
    return or_(
        Lead.status == "hunting",
        and_(Lead.status == "open", Lead.hunt_id.is_not(None)),
    )


def needs_decision_clause(*, auto_hunt: bool) -> Any:
    """The SQL for a lead that waits on a decision.

    A lead waits when its hunt has finished, and when nothing will start one
    for it. Both readers of this rule, the Needs-you count and the Needs
    decision tab, take it from here, so the strip and the tab can never
    disagree about what waits.

    ``auto_hunt`` is the live ``lead_auto_hunt`` setting. With the loop on, a
    new lead waits on soc-ai rather than on the analyst: its hunt is queued,
    and counting it would put a number on the sidebar that clears itself a
    minute later. A reopened lead is the exception, because the loop leaves a
    reopened lead to the analyst who reopened it. With the loop off nothing
    will start the hunt, so a new lead is back on the analyst.

    A finished hunt is read off the hunt, not off the lead's status. A
    reopened lead that kept its finished hunt is open with a hunt attached,
    and it used to match neither branch: the strip, the tab and the badge all
    dropped it, and the loop leaves it alone, so nothing held it at all.

    The caller LEFT JOINs the hunt. A lead with a hunt id and no hunt row
    reads as waiting, which is right: nothing is running on it.
    """
    hunt_finished = and_(
        _has_a_hunt(),
        or_(Hunt.id.is_(None), Hunt.status.not_in(HUNT_RUNNING_STATUSES)),
    )
    no_hunt_yet = and_(Lead.status == "open", Lead.hunt_id.is_(None))
    if auto_hunt:
        # The loop leaves two leads to the analyst: a reopened one, and a
        # shadow one. A shadow lead came from an analytic in shadow, which
        # records and never acts; its hunt is the analyst's call.
        left_to_analyst = or_(
            Lead.reopened_at.is_not(None),
            Lead.dismissed_at.is_not(None),
            Lead.shadow.is_(True),
        )
        return or_(and_(no_hunt_yet, left_to_analyst), hunt_finished)
    return or_(no_hunt_yet, hunt_finished)


def hunt_is_queued(lead: Lead, *, auto_hunt: bool) -> bool:
    """Whether the loop will start this lead's hunt.

    The row-level twin of the clause above, and the field the New pill reads
    as "New . hunt queued". The two live together so a lead cannot read as
    queued on the row and as waiting in the count.

    A lead that names a hunt is never queued, whatever its status. The loop
    starts a hunt on a lead that has none, and a reopened lead keeps the hunt
    it had.
    """
    return bool(
        auto_hunt
        and lead.status == "open"
        and not lead.hunt_id
        and lead.dismissed_at is None
        and lead.reopened_at is None
        and not lead.shadow
    )


def in_progress_clause() -> Any:
    """The SQL for a lead whose hunt runs or is queued. The caller LEFT JOINs the hunt.

    The twin of :func:`needs_decision_clause`: the same set of leads that
    carry a hunt, split by the hunt's status. A reopened lead the analyst hunt
    again reads In progress while that hunt runs, and waits when it lands.
    """
    return and_(_has_a_hunt(), Hunt.status.in_(HUNT_RUNNING_STATUSES))


async def get(db: AsyncSession, lead_id: int) -> Lead | None:
    return await db.get(Lead, int(lead_id))


async def timeline(db: AsyncSession, lead_id: int) -> Sequence[EntityObservation]:
    """The observations attached to the lead, newest first.

    Ordered on the time the page shows: the event time when the row has one,
    the record time when it has none.
    """
    rows = await db.scalars(
        select(EntityObservation)
        .where(EntityObservation.lead_id == int(lead_id))
        .order_by(
            func.coalesce(EntityObservation.observed_at, EntityObservation.born_at).desc(),
            EntityObservation.id.desc(),
        )
    )
    return rows.all()


def _refuse_if_closed(lead: Lead) -> None:
    """A closed lead takes no new work until an analyst reopens it.

    Both actions used to write straight over the status. A hunt started from a
    dismissed lead left the dismissal fields in place under a ``hunting``
    status, so the lead read as both answered and open, and the sharpening loop
    counted the dismissal that the analyst had changed their mind about.
    """
    if lead.status in CLOSED_STATUSES:
        raise ValueError(f"lead {lead.id} is {lead.status}. Reopen it first.")


def _iso_at(at: datetime | None) -> str | None:
    return at.replace(tzinfo=None).isoformat() if isinstance(at, datetime) else None


def decisions_of(lead: Lead) -> list[dict[str, Any]]:
    """Every decision on the lead, oldest first.

    A row written before migration 0053 that the upgrade did not reach has no
    history. Its current dismissal is the one decision it can show.
    """
    stored = lead.decisions_json
    if isinstance(stored, list):
        return [dict(d) for d in stored if isinstance(d, dict)]
    out: list[dict[str, Any]] = []
    if lead.dismissed_at is not None:
        out.append(
            {
                "action": (
                    "closed_by_hunt" if lead.dismissed_by == AUTO_HUNT_ACTOR else "dismissed"
                ),
                "at": _iso_at(lead.dismissed_at),
                "by": lead.dismissed_by,
                "reason": lead.dismissed_reason,
                "note": lead.dismissed_note,
            }
        )
    return out


def record_decision(lead: Lead, action: str, at: datetime, **fields: Any) -> None:
    """Append one decision to the lead's history.

    The list is written back whole. The JSON column does not track an
    in-place append, and a decision the session did not see is a decision
    the page never shows.
    """
    entry: dict[str, Any] = {"action": action, "at": _iso_at(at)}
    entry.update(fields)
    lead.decisions_json = [*decisions_of(lead), entry]


def _clear_dismissal(lead: Lead) -> None:
    """The lead is no longer dismissed. The dismissal lives on in the history."""
    lead.dismissed_reason = None
    lead.dismissed_note = None
    lead.dismissed_by = None
    lead.dismissed_at = None


def closed_on_verdicts(lead: Lead) -> bool:
    """Whether soc-ai closed the lead on the verdicts of its hunt's findings.

    The newest close of a promoted lead decides. :func:`settle_after_hunt`
    signs that close with :data:`SYSTEM_HUNT_ACTOR` and the reason
    :data:`PROMOTED_FINDING_REASON`. An analyst's close on a finding verdict
    carries the reason and the analyst's name.
    """
    if lead.status != "promoted":
        return False
    for decision in reversed(decisions_of(lead)):
        if decision.get("action") == "promoted":
            return (
                decision.get("by") == SYSTEM_HUNT_ACTOR
                and decision.get("reason") == PROMOTED_FINDING_REASON
            )
    return False


def hold_reason_of(lead: Lead) -> str | None:
    """Why the settle rule left the lead's current hunt to the analyst, or None.

    Read off the history: the newest ``held`` entry for the hunt the lead
    names now. A hold on an older hunt is history, and a later decision on
    the lead answers it.
    """
    # An annotation decides nothing. A kept-open entry answers the question
    # an investigation verdict asks, not the hold, so the hold stays in force.
    history = [d for d in decisions_of(lead) if d.get("action") not in _ANNOTATION_ACTIONS]
    if not history or not lead.hunt_id:
        return None
    last = history[-1]
    if last.get("action") != "held" or last.get("hunt_id") != lead.hunt_id:
        return None
    reason = last.get("reason")
    return str(reason) if reason else None


async def mark_hunting(db: AsyncSession, lead_id: int, *, hunt_id: str) -> Lead:
    lead = await db.get(Lead, int(lead_id))
    if lead is None:
        raise LookupError(lead_id)
    _refuse_if_closed(lead)
    lead.status = "hunting"
    lead.hunt_id = hunt_id
    lead.updated_at = datetime.now(UTC).replace(tzinfo=None)
    await db.commit()
    await db.refresh(lead)
    return lead


async def dismiss(
    db: AsyncSession,
    lead_id: int,
    *,
    reason: str,
    note: str | None,
    by: str,
    now: datetime | None = None,
) -> Lead:
    if reason not in DISMISS_REASONS:
        raise ValueError(f"unknown dismissal reason: {reason}")
    lead = await db.get(Lead, int(lead_id))
    if lead is None:
        raise LookupError(lead_id)
    # A dismissal is an answer, and a repeat of the request is not a second
    # answer. The route is a button: a double click overwrote the reason, the
    # note and the analyst who wrote them.
    if lead.status == "dismissed":
        return lead
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    clean_note = (note or "").strip()[:2000] or None
    # The history first. A row with no history yet reads its decisions off
    # the dismissal columns, and they must not hold this one twice.
    record_decision(lead, "dismissed", at, by=by[:80], reason=reason, note=clean_note)
    lead.status = "dismissed"
    lead.dismissed_reason = reason
    lead.dismissed_note = clean_note
    lead.dismissed_by = by[:80]
    lead.dismissed_at = at
    lead.updated_at = at
    await db.commit()
    await db.refresh(lead)
    return lead


async def mark_promoted(
    db: AsyncSession,
    lead_id: int,
    *,
    investigation_id: str,
    by: str | None = None,
    now: datetime | None = None,
    reason: str | None = None,
    verdicts: Sequence[dict[str, Any]] | None = None,
    hunt_id: str | None = None,
) -> Lead:
    """Close the lead as promoted. A promoted lead carries no dismissal.

    ``reason`` is :data:`PROMOTED_FINDING_REASON` when the analyst closed the
    lead on the verdict of a promoted hunt finding. The lead then names that
    finding's investigation.

    ``verdicts`` records the verdict of each subject finding when the hunt
    closed the lead itself (:func:`settle_after_hunt`), with the hunt.
    """
    lead = await db.get(Lead, int(lead_id))
    if lead is None:
        raise LookupError(lead_id)
    _refuse_if_closed(lead)
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    extra: dict[str, Any] = {}
    if reason:
        extra["reason"] = reason
    if verdicts is not None:
        extra["verdicts"] = [dict(v) for v in verdicts]
    if hunt_id:
        extra["hunt_id"] = hunt_id
    # The history first: a row with no history yet keeps its old dismissal.
    record_decision(
        lead,
        "promoted",
        at,
        by=(by or "")[:80] or None,
        investigation_id=investigation_id,
        **extra,
    )
    lead.status = "promoted"
    lead.investigation_id = investigation_id
    _clear_dismissal(lead)
    lead.updated_at = at
    await db.commit()
    await db.refresh(lead)
    return lead


async def dismiss_observation(
    db: AsyncSession,
    observation_id: int,
    *,
    reason: str,
    note: str | None,
    by: str,
    now: datetime | None = None,
) -> EntityObservation:
    """Mark one observation benign, in the shape a lead dismissal takes.

    The reason comes from :data:`DISMISS_REASONS`, so the sharpening loop
    reads one list. The grid-gap review writes :data:`GRID_GAP_REASON` through
    this same path. The observation then counts toward no lead (see
    ``soc_ai.hunting.leads.weigh_entity``), and a repeat of the same content
    refreshes the same row, so the mark holds for the repeats.

    A second mark answers with the row as it stands. The first reason and the
    first hand stay. ``LookupError`` for an id no row holds and ``ValueError``
    for a reason the list does not name.
    """
    if reason not in OBSERVATION_DISMISS_REASONS:
        raise ValueError(f"unknown dismissal reason: {reason}")
    row = await db.get(EntityObservation, int(observation_id))
    if row is None:
        raise LookupError(observation_id)
    if row.dismissed_at is not None:
        return row
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    row.dismissed_reason = reason
    row.dismissed_note = (note or "").strip()[:2000] or None
    row.dismissed_by = by[:80]
    row.dismissed_at = at
    await db.commit()
    await db.refresh(row)
    _LOGGER.info("observation %s marked benign by %s: %s", row.id, by[:80], reason)
    return row


async def keep_open(
    db: AsyncSession,
    lead_id: int,
    *,
    investigation_id: str,
    by: str,
    now: datetime | None = None,
) -> Lead:
    """Record that the analyst keeps the lead open over an investigation verdict.

    The lead page asks once per investigation whether to close the lead as
    promoted. This entry is the answer "no", so the page does not ask again.
    The status does not change. A second answer for the same investigation
    changes nothing.
    """
    lead = await db.get(Lead, int(lead_id))
    if lead is None:
        raise LookupError(lead_id)
    _refuse_if_closed(lead)
    if any(
        d.get("action") == KEPT_OPEN and d.get("investigation_id") == investigation_id
        for d in decisions_of(lead)
    ):
        return lead
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    record_decision(lead, KEPT_OPEN, at, by=by[:80], investigation_id=investigation_id)
    lead.updated_at = at
    await db.commit()
    await db.refresh(lead)
    return lead


async def reopen(db: AsyncSession, lead_id: int, by: str, *, now: datetime | None = None) -> Lead:
    """Open a closed lead again. The dismissal moves to the history.

    An analyst changes their mind. The reason, the note, the hand and the time
    of the dismissal stay in ``decisions_json``, and the reopen is the next
    entry there. The dismissal columns are cleared: they state the current
    dismissal, and a reopened lead has none. They used to keep it, so a
    reopened lead read as dismissed in its header and in the API.

    ``reopened_at`` marks the lead as the analyst's. The loop does not hunt
    it, and the settle rule does not close it.
    """
    lead = await db.get(Lead, int(lead_id))
    if lead is None:
        raise LookupError(lead_id)
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    if lead.status not in CLOSED_STATUSES:
        # Nothing to reopen. A repeat of the request is not a second decision.
        return lead
    # The history first: a row with no history yet keeps its old dismissal.
    record_decision(lead, "reopened", at, by=by[:80])
    lead.status = "open"
    _clear_dismissal(lead)
    lead.reopened_at = at
    lead.updated_at = at
    await db.commit()
    await db.refresh(lead)
    _LOGGER.info("lead %s reopened by %s", lead.id, by[:80])
    return lead


def hunt_outcome_of(hunt: Hunt) -> str:
    """``threats``, ``clean``, ``gap``, ``failed``, or empty for a hunt that did not complete."""
    from soc_ai.hunting.findings import hunt_outcome  # noqa: PLC0415 - avoids an import cycle

    report = hunt.report if isinstance(hunt.report, dict) else {}
    return hunt_outcome(hunt.status, report.get("findings") or [])[1]


def hunt_did_not_run(hunt: Hunt) -> bool:
    """Whether the hunt ended without an answer.

    Two shapes. The hunt row is terminal and not complete: error, cancelled,
    interrupted. Or it completed and a query raised, which the report records
    as a visibility gap titled ": could not run". Both count toward the retry
    limit, because both would otherwise be re-hunted every wake for ever.
    """
    if hunt.status in HUNT_RUNNING_STATUSES:
        return False
    return hunt.status in HUNT_FAILED_STATUSES or hunt_outcome_of(hunt) == "failed"


def analyst_dismissed(lead: Lead) -> bool:
    """Whether an analyst decided on this lead before: a dismissal, or a reopen.

    A reopen clears the dismissal columns, so ``reopened_at`` carries the
    mark. The dismissal test stays for a row the 0053 upgrade did not reach.
    """
    if lead.reopened_at is not None:
        return True
    return lead.dismissed_at is not None and lead.dismissed_by != AUTO_HUNT_ACTOR


def _tool_failed(result: Any) -> bool:
    return isinstance(result, dict) and bool(result.get("error"))


async def _clean_close_blocker(db: AsyncSession, hunt: Hunt) -> str | None:
    """Why a hunt that answered clean may not close its lead, or None.

    A hunt closes a lead as clean only when it read its evidence. The range
    closed a lead whose re-hunt ran while the grid stalled: its findings said
    "Alert documents unreadable due to grid timeout", and two earlier hunts on
    the same lead held critical threat findings. The close read as an
    all-clear that nobody had earned.

    - ``earlier_threat``: an earlier complete hunt on the same lead found a
      threat. A later clean answer does not undo it. The analyst decides.
    - ``partial_read``: the report holds a visibility gap, a tool call failed
      in the trace, the run was degraded, or the report came from the
      budget synthesizer.
    - ``lead_link``: the citation gate lowered a threat finding that linked
      this lead to other leads (``lead_links`` on the ``citation_validation``
      event). A partial read wins over it, so the reason does not depend on
      the order of the events.

    Every test reads a structured signal: the finding category, the tool
    result's error, the ``error`` event, the ``degraded`` and ``partial``
    flags on the ``done`` event, and the ``lead_links`` count. A console
    string decides nothing, because a wording edit in the runner then made a
    partial hunt close its lead as clean. The one exception is a row recorded
    before the ``partial`` flag existed (see :data:`_LEGACY_PARTIAL_TEXT`).
    """
    if hunt.lead_id is not None:
        earlier = await db.scalars(
            select(Hunt).where(
                Hunt.lead_id == hunt.lead_id,
                Hunt.id != hunt.id,
                Hunt.status == "complete",
            )
        )
        if any(hunt_outcome_of(h) == "threats" for h in earlier.all()):
            return HOLD_EARLIER_THREAT

    from soc_ai.hunting.findings import finding_category  # noqa: PLC0415 - avoids a cycle

    report = hunt.report if isinstance(hunt.report, dict) else {}
    findings = [f for f in (report.get("findings") or []) if isinstance(f, dict)]
    if any(finding_category(f) == "visibility_gap" for f in findings):
        return HOLD_PARTIAL_READ

    events = await db.scalars(
        select(HuntEvent).where(
            HuntEvent.hunt_id == hunt.id,
            HuntEvent.kind.in_(
                ("tool_result", "done", "model_response", "error", "citation_validation")
            ),
        )
    )
    rows = [(e.kind, e.payload if isinstance(e.payload, dict) else {}) for e in events.all()]
    # A ``done`` event that carries the partial key states the fact. Only a row
    # recorded before the key existed falls back to its frozen stored text.
    flagged = any(kind == "done" and _DONE_PARTIAL_KEY in payload for kind, payload in rows)
    linked = False
    for kind, payload in rows:
        if kind == "citation_validation":
            linked = linked or _int_count(payload.get("lead_links")) > 0
            continue
        if kind == "error":
            return HOLD_PARTIAL_READ
        if kind == "tool_result" and _tool_failed(payload.get("result")):
            return HOLD_PARTIAL_READ
        if kind == "done" and (payload.get("degraded") or payload.get(_DONE_PARTIAL_KEY)):
            return HOLD_PARTIAL_READ
        if (
            not flagged
            and kind == "model_response"
            and str(payload.get("text") or "").startswith(_LEGACY_PARTIAL_TEXT)
        ):
            return HOLD_PARTIAL_READ
    return HOLD_LEAD_LINK if linked else None


def _int_count(value: Any) -> int:
    """A stored count as an int. A value that is no count reads as 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    return int(value)


async def derived_hold_reason(db: AsyncSession, lead: Lead) -> str | None:
    """The hold a lead would carry today, for a row settled before the rule.

    A lead that a clean hunt closed before 2026-10-01 and that an analyst
    reopened has no ``held`` entry in its history. The page still has to say
    why the clean answer did not settle it. Read the hunt it names and apply
    :func:`_clean_close_blocker` on read. A recorded hold wins.

    A ``hunting`` lead whose hunt investigated its subject findings, and
    settled before :data:`HOLD_NO_VERDICT` existed, has no ``held`` entry
    either. When a subject finding still has no verdict, the hold is read
    on read too.
    """
    if lead.hunt_id is None or lead.status not in ("open", "hunting"):
        return None
    recorded = hold_reason_of(lead)
    if recorded is not None:
        return recorded
    hunt = await db.get(Hunt, lead.hunt_id)
    if hunt is None or hunt.status in HUNT_RUNNING_STATUSES:
        return None
    if lead.status == "hunting":
        if not _verdicts_decide(hunt) or analyst_dismissed(lead):
            return None
        links = _subject_links(hunt)
        if links and await _subject_verdicts(db, hunt, links) is None:
            return HOLD_NO_VERDICT
        return None
    if hunt_outcome_of(hunt) != "clean":
        return None
    return await _clean_close_blocker(db, hunt)


def _verdicts_decide(hunt: Hunt) -> bool:
    """Whether the verdicts of the hunt's subject findings answer its lead."""
    return hunt.status == "complete" and int(getattr(hunt, "findings_total", 0) or 0) > 0


def _subject_links(hunt: Hunt) -> dict[int, Any]:
    """The hunt's finding entries on findings that are subjects by the current rule.

    The hunt page and the verdict counts drop an entry on a finding that is
    no subject now (:func:`soc_ai.store.hunts.subject_links`). The settle
    rule read every entry, so a lead waited on the failed run of an
    observation that the page did not count.
    """
    from soc_ai.store.hunts import finding_links, subject_links  # noqa: PLC0415 - import cycle

    report = hunt.report if isinstance(hunt.report, dict) else {}
    return subject_links(finding_links(hunt), report.get("findings"))


async def _subject_verdicts(
    db: AsyncSession, hunt: Hunt, links: dict[int, Any]
) -> list[dict[str, Any]] | None:
    """The verdict of every subject finding of the hunt, or None when one has none.

    ``links`` holds the entries of the subject findings (:func:`_subject_links`).
    One entry per subject finding, in ordinal order: the ordinal, the
    investigation, its verdict and its confidence. Only a complete run that is
    not a pipeline fallback carries a verdict.
    """
    from soc_ai.store.models import Investigation  # noqa: PLC0415 - local, like the hunt reads

    if not links:
        return None
    ids = [link.investigation_id for link in links.values() if link.investigation_id]
    if len(ids) < len(links):
        return None
    rows = await db.execute(
        select(
            Investigation.id,
            Investigation.status,
            Investigation.verdict,
            Investigation.confidence,
            Investigation.is_fallback,
        ).where(Investigation.id.in_(ids))
    )
    runs = {str(r[0]): r for r in rows.all()}
    out: list[dict[str, Any]] = []
    for ordinal in sorted(links):
        run = runs.get(links[ordinal].investigation_id or "")
        if run is None:
            return None
        _id, status, verdict, confidence, fallback = run
        if status != "complete" or fallback is True or not verdict:
            return None
        out.append(
            {
                "ordinal": ordinal,
                "investigation_id": str(_id),
                "verdict": str(verdict),
                "confidence": confidence,
            }
        )
    return out


async def settle_after_hunt(db: AsyncSession, hunt: Hunt, *, now: datetime | None = None) -> str:
    """Move the lead the hunt was started on, once the hunt has finished.

    Returns what happened: ``closed``, ``reopened``, ``waits`` or ``none``.

    - ``clean``: the hunt answered no threat. The lead closes with the reason
      ``hunt_clean`` in the rule's own hand. A lead an analyst dismissed and
      reopened is theirs to decide; it waits instead. A hunt that did not
      read all its evidence, or a lead an earlier hunt found a threat on,
      waits too, and the history records why (:func:`_clean_close_blocker`).
    - ``threats`` or ``gap``: the lead waits on the analyst. A threat is a
      decision, and a gap cannot be hunted away.
    - anything else (a query raised, or the hunt ended in error, cancelled
      or interrupted): the lead returns to open and keeps the hunt it names,
      so the row reads "Could not run" and the loop may try once more.

    ``none`` when the hunt names no lead, the lead is not hunting, the lead
    names a different hunt now, or the hunt still runs. So a second call, a
    reconciliation pass and a stale hunt all change nothing.
    """
    if hunt.lead_id is None:
        return "none"
    lead = await db.get(Lead, int(hunt.lead_id))
    if lead is None or lead.status != "hunting" or lead.hunt_id != hunt.id:
        return "none"
    if hunt.status in HUNT_RUNNING_STATUSES:
        return "none"
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    # The hunt investigated its subject findings (2026-10-07). When every one
    # of them has a verdict, the verdicts answer the lead: it closes as
    # promoted, in the hunt's hand, with each verdict recorded. A subject with
    # no verdict, a failed run or one past the cap, leaves the lead to the
    # analyst, and the history records why (HOLD_NO_VERDICT). A hunt with no
    # subject settles by the rules below, as before. An entry on a finding
    # that is no subject by the current rule counts for neither.
    links = _subject_links(hunt) if _verdicts_decide(hunt) else {}
    if links:
        if analyst_dismissed(lead):
            return "waits"
        decided = await _subject_verdicts(db, hunt, links)
        if decided is None:
            # Recorded once per hunt, like the hold of a clean hunt. Prod lead
            # 47 (2026-10-24) waited on one failed run with no reason on its
            # page, while its sibling lead with every verdict closed.
            if hold_reason_of(lead) != HOLD_NO_VERDICT:
                record_decision(
                    lead,
                    "held",
                    at,
                    by=SYSTEM_HUNT_ACTOR,
                    reason=HOLD_NO_VERDICT,
                    hunt_id=hunt.id,
                )
                lead.updated_at = at
                await db.commit()
                _LOGGER.info(
                    "lead %s waits: a subject finding of hunt %s has no verdict", lead.id, hunt.id
                )
            return "waits"
        first = next((v for v in decided if v["verdict"] == "true_positive"), decided[0])
        await mark_promoted(
            db,
            lead.id,
            investigation_id=str(first["investigation_id"]),
            by=SYSTEM_HUNT_ACTOR,
            now=at,
            reason=PROMOTED_FINDING_REASON,
            verdicts=decided,
            hunt_id=hunt.id,
        )
        _LOGGER.info(
            "lead %s closed: every threat finding of hunt %s that names an entity has a verdict",
            lead.id,
            hunt.id,
        )
        return "closed"
    outcome = hunt_outcome_of(hunt)
    if outcome in ("threats", "gap"):
        return "waits"
    if outcome == "clean":
        if analyst_dismissed(lead):
            return "waits"
        blocker = await _clean_close_blocker(db, hunt)
        if blocker is not None:
            # Recorded once per hunt. The reconciliation pass calls this on
            # every wake, and a second entry would say nothing new.
            if hold_reason_of(lead) != blocker:
                record_decision(
                    lead, "held", at, by=AUTO_HUNT_ACTOR, reason=blocker, hunt_id=hunt.id
                )
                lead.updated_at = at
                await db.commit()
                _LOGGER.info("lead %s waits: hunt %s answered clean, %s", lead.id, hunt.id, blocker)
            return "waits"
        record_decision(
            lead,
            "closed_by_hunt",
            at,
            by=AUTO_HUNT_ACTOR,
            reason=HUNT_CLEAN_REASON,
            hunt_id=hunt.id,
        )
        lead.status = "dismissed"
        lead.dismissed_reason = HUNT_CLEAN_REASON
        lead.dismissed_note = None
        lead.dismissed_by = AUTO_HUNT_ACTOR
        lead.dismissed_at = at
        lead.updated_at = at
        await db.commit()
        _LOGGER.info("lead %s closed: hunt %s found no threat", lead.id, hunt.id)
        return "closed"
    lead.status = "open"
    lead.updated_at = at
    await db.commit()
    _LOGGER.info("lead %s back to open: hunt %s did not run (%s)", lead.id, hunt.id, hunt.status)
    return "reopened"


async def settle_finished_hunts(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Apply :func:`settle_after_hunt` to every hunting lead whose hunt is terminal.

    Runs at startup and at each loop wake. Returns how many leads moved. A
    lead whose hunt row is missing is left alone: it reads as waiting, which
    is the truth. Idempotent, because a lead that moved is no longer hunting.
    """
    rows = await db.execute(
        select(Lead, Hunt)
        .join(Hunt, Hunt.id == Lead.hunt_id)
        .where(Lead.status == "hunting", Hunt.status.not_in(HUNT_RUNNING_STATUSES))
        .order_by(Lead.id)
    )
    moved = 0
    for _lead, hunt in rows.all():
        if await settle_after_hunt(db, hunt, now=now) in ("closed", "reopened"):
            moved += 1
    return moved


def formed_from_backtest(lead: Lead) -> bool:
    """Whether :func:`mark_backtest_leads` marked this lead."""
    return any(d.get("action") == BACKTEST_DECISION for d in decisions_of(lead))


async def mark_backtest_leads(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Mark each lead whose observations all came from backtest replays.

    A one-time repair, run at startup. Before 2026-10-06 a replay's verdict
    wrote an alert observation like a live run did, so a replay could form a
    lead. The store writes no such observation now (see
    ``soc_ai.store.investigations._observe_verdict``), and this finds the
    leads that formed before that.

    An alert observation names its alert in ``fingerprint``. It came from a
    replay when every run of that alert that holds a verdict is a backtest
    replay. A run that holds no verdict wrote no observation. When a live run
    also holds a verdict, the observation may be the live run's, and the lead
    is left alone. A lead with any other observation type is left alone too:
    that observation is live evidence. So is a lead with no observation left,
    because nothing then says where it came from.

    The mark is a decision on the lead (:data:`BACKTEST_DECISION`), which the
    lead page lists with the others. It changes no status. Idempotent: a lead
    that holds the mark is not marked again. Returns how many leads it marked.
    """
    from soc_ai.hunting.sources import ALERT_SPEC_ID  # noqa: PLC0415 - avoids an import cycle
    from soc_ai.store.investigations import (  # noqa: PLC0415 - avoids an import cycle
        is_backtest_actor,
        not_hunt_subject,
    )
    from soc_ai.store.models import Investigation  # noqa: PLC0415 - kept beside its query

    observed = await db.execute(
        select(
            EntityObservation.lead_id, EntityObservation.spec_id, EntityObservation.fingerprint
        ).where(EntityObservation.lead_id.is_not(None))
    )
    by_lead: dict[int, list[tuple[str, str]]] = {}
    for lead_id, spec_id, fingerprint in observed.all():
        by_lead.setdefault(int(lead_id), []).append((str(spec_id), str(fingerprint or "")))
    alert_ids = sorted(
        {fp for rows in by_lead.values() for spec, fp in rows if spec == ALERT_SPEC_ID and fp}
    )
    if not alert_ids:
        return 0
    runs = await db.execute(
        select(Investigation.alert_es_id, Investigation.started_by).where(
            Investigation.alert_es_id.in_(alert_ids),
            Investigation.verdict.is_not(None),
            not_hunt_subject(),
        )
    )
    replay_flags: dict[str, set[bool]] = {}
    for alert_id, started_by in runs.all():
        replay_flags.setdefault(str(alert_id), set()).add(is_backtest_actor(started_by))
    replay_only = {alert_id for alert_id, flags in replay_flags.items() if flags == {True}}
    candidates = sorted(
        lead_id
        for lead_id, rows in by_lead.items()
        if rows and all(spec == ALERT_SPEC_ID and fp in replay_only for spec, fp in rows)
    )
    if not candidates:
        return 0
    at = (now or datetime.now(UTC)).replace(tzinfo=None)
    marked = 0
    for lead in (await db.scalars(select(Lead).where(Lead.id.in_(candidates)))).all():
        if formed_from_backtest(lead):
            continue
        record_decision(
            lead,
            BACKTEST_DECISION,
            at,
            by=BACKTEST_DECISION_ACTOR,
            reason="backtest_replay",
            note=BACKTEST_DECISION_NOTE,
        )
        marked += 1
    if marked:
        await db.commit()
    return marked


def _entity_names(entities: Any) -> list[str]:
    """The entity keys on a lead, in order. The kind rides in the chip, not the sentence."""
    return [str(e[1]) for e in (entities or []) if isinstance(e, (list, tuple)) and len(e) == 2]


def objective_for(
    lead: Lead,
    observations: Sequence[EntityObservation],
    related: Sequence[RelatedLead] | None = None,
) -> str:
    """The objective of a hunt that a lead starts.

    Names the lead, its entities, the kinds in words, and each observation's
    summary. Evidence ids ride in the hunt context, not in this sentence.

    ``related`` names the open leads that share an analytic, an external
    network or a technique with this one. A lead spans the entities one hit
    names, so a hunt that reads one lead alone cannot see an attack that
    moved. The argument is optional: a caller with no related leads to hand
    gets the objective it got before.

    The objective is written once, at the start of the hunt. The related list
    is computed on read, so the page can name a different set an hour later.
    The line says which one this is, because a hunt that ran before a fix
    kept the old list and its investigation read it as current.
    """
    entities = _entity_names(lead.entities_json)
    kinds = [_KIND_WORDS.get(str(k), str(k).replace("_", " ")) for k in (lead.kinds_json or [])]
    lines = [
        f"[lead {lead.id}] Investigate {', '.join(entities) or 'the entity'}. "
        f"The lead formed from {' and '.join(kinds) or 'several observations'}.",
        "Observations:",
    ]
    for o in observations[:12]:
        summary = (o.summary or o.kind).strip()
        lines.append(f"- {summary}")
    if related:
        lines.append("Related leads at the start of this hunt:")
        for other in list(related)[:8]:
            names = ", ".join(_entity_names(other.entities)) or "the entity"
            lines.append(f"- lead {other.lead_id} on {names}: {other.reason}")
        lines.append(
            "State in the narrative whether these leads and this one are one campaign. "
            "Name the evidence. Never write the link as a finding."
        )
    lines.append(
        "Decide whether these observations together describe malicious activity on this "
        "entity. Name what you could not check."
    )
    return "\n".join(lines)


def _evidence_ids(observation: EntityObservation) -> list[str]:
    """The documents an observation cites: the column first, then the evidence.

    The column holds up to ten ids from migration 0057 on. A row written
    before it holds its ids in the evidence alone.
    """
    ev = observation.evidence_json if isinstance(observation.evidence_json, dict) else {}
    column = observation.document_ids if isinstance(observation.document_ids, list) else []
    ids: list[str] = [str(c) for c in column if c]
    for key in ("anchor_id", "alert_id"):
        if ev.get(key):
            ids.append(str(ev[key]))
    for key in ("sample_ids", "citations"):
        ids.extend(str(c) for c in (ev.get(key) or []) if c)
    out: list[str] = []
    for i in ids:
        if i not in out:
            out.append(i)
    return out[:10]


def cites_documents(observations: Sequence[EntityObservation]) -> bool:
    """Whether any observation on the lead names a document.

    The auto-hunt loop reads this before it starts anything. A hunt of a lead
    that cites nothing has no evidence to read first, so it searches the grid
    from scratch, and the first lead hunt that did so called a real DCSync
    event a broken rule. An analyst may still hunt such a lead by hand.

    The rule lives beside :func:`evidence_block_for`, which reads the same ids.
    One of them changing alone would let the loop start a hunt whose evidence
    block says "no document ids recorded" on every line.
    """
    return any(_evidence_ids(o) for o in observations)


def evidence_block_for(
    observations: Sequence[EntityObservation], *, now: datetime | None = None
) -> str:
    """The evidence a lead hunt reads first.

    The first lead hunt on the range searched the grid on its own, found the
    status records of a Sigma rule, and called a real DCSync event a broken
    rule. The documents that formed the lead are known. The hunt reads them
    before it queries.

    An observation that carries its statistic states it in numbers, and one
    that carries a query states the query and the time range that reaches it.
    The hunt then reads the departure. It searched the grid for it again,
    because the numbers lived only in the summary sentence.
    """
    from soc_ai.hunting.rerun import window_minutes  # noqa: PLC0415 - lazy, avoids a cycle
    from soc_ai.hunting.wording import statistic_sentence  # noqa: PLC0415 - lazy

    at = now or datetime.now(UTC)
    lines = ["Evidence documents, by observation:"]
    any_ids = False
    any_query = False
    for o in observations[:12]:
        ids = _evidence_ids(o)
        summary = (o.summary or o.kind).strip()
        if ids:
            any_ids = True
            lines.append(f"- {summary}: document ids {', '.join(ids)}")
        else:
            lines.append(f"- {summary}: no document ids recorded")
        stated = statistic_sentence(o.statistic, o.statistic_value, o.baseline_value)
        if stated:
            lines.append(f"  Statistic: {stated}")
        if o.rerun_query:
            any_query = True
            # The query window starts one recent window before the sweep wrote it.
            start = o.born_at - timedelta(days=1)
            lines.append(
                f"  Query: {o.rerun_query} "
                f"(t_query_events_oql, time_range_minutes {window_minutes(start, now=at)})"
            )
    if any_ids:
        lines.append(
            "Read each document id with t_get_event_raw before you run any query. "
            "Judge the observations from these documents first. Then widen the search."
        )
    if any_query:
        lines.append(
            "Run the query of each observation to read its departure again. "
            "Do not search for the departure from the start."
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Related leads — computed on read
# ---------------------------------------------------------------------------

# How far back a related lead may have formed. One week is the dogfood window:
# past it the two leads are two stories, and an analyst reading one of them
# does not act on the other.
RELATED_WINDOW_DAYS = 7

# How far apart two observations of the same analytic may sit and still read as
# one event. A working day. The same analytic on two entities inside it is the
# shape of a lateral step. A week apart it is the shape of an analytic that
# fires often.
SAME_ANALYTIC_HOURS = 24


@dataclass(frozen=True)
class RelatedLead:
    """One open lead that shares something with the lead being read.

    ``reason`` is the analyst's sentence for the share, not a code. It names
    the thing itself: the analytic, the network or the technique.

    ``hunt_id`` is the hunt the related lead carries, when it has one. The
    stored status alone reads "In progress" for the whole life of a lead whose
    hunt finished, so the panel said one thing and every other surface said
    another. The reader joins the hunt and states what it found.
    """

    lead_id: int
    entities: list[list[str]]
    reason: str
    formed_at: datetime | None
    status: str
    hunt_id: str | None = None


@dataclass(frozen=True)
class _LeadFacts:
    """What one lead can be related BY. Built once per lead, compared many times."""

    lead_id: int
    # The entities the lead names, as (type, key). Two leads that share one
    # are not related: they are one entity's story, told twice.
    entities: frozenset[tuple[str, str]] = frozenset()
    analytics: dict[str, list[datetime]] = field(default_factory=dict)
    # Alert observations by the rule that raised them. They keep their own
    # map: every alert observation carries the one spec id "alert", and a
    # match on that id read five different attacks as one campaign.
    alert_rules: dict[str, list[datetime]] = field(default_factory=dict)
    networks: frozenset[str] = frozenset()
    techniques: frozenset[str] = frozenset()


def _naive(value: Any) -> datetime | None:
    """A stored timestamp as naive UTC. The columns are naive. An input may not be."""
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=None) if value.tzinfo is not None else value


@lru_cache(maxsize=1)
def _techniques_by_analytic() -> dict[str, tuple[str, ...]]:
    """Every shipped analytic's ATT&CK techniques, read once.

    The catalog is files on disk that change with a deploy. A lead page would
    otherwise read and validate sixteen YAML files per request.
    ``cache_clear()`` exists for a test that writes its own catalog.
    """
    from soc_ai.hunting.spec import CATALOG_DIR, load_catalog  # noqa: PLC0415 - lazy

    try:
        catalog = load_catalog(CATALOG_DIR)
    except (OSError, ValueError) as exc:  # pragma: no cover - a broken catalog
        _LOGGER.warning("the catalog did not load, so no lead relates by technique: %s", exc)
        return {}
    return {spec_id: spec.techniques for spec_id, spec in catalog.items()}


def _external_network(text: Any) -> str | None:
    """The /24 of an external IPv4 address, an external IPv6 address, or None.

    External means the estate does not hold it:
    :func:`soc_ai.hunting.sources.internal_hosts` says which addresses are
    inside, and a real unicast address it refuses is outside. Two leads that
    name neighbouring external addresses name one place far more often than
    not, so IPv4 compares on the /24.
    """
    from soc_ai.hunting.sources import internal_hosts  # noqa: PLC0415 - lazy

    value = str(text or "").strip()
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if internal_hosts([value]):
        return None
    if (
        addr.is_loopback
        or addr.is_multicast
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
    ):
        return None
    if addr.version == 4:
        return str(ipaddress.ip_network(f"{value}/24", strict=False))
    return str(addr)


def _strings_in(value: Any, depth: int = 0) -> list[str]:
    """Every string inside an evidence payload. Bounded, so a deep blob cannot hold a page."""
    if depth > 4:
        return []
    if isinstance(value, str):
        return [value]
    out: list[str] = []
    if isinstance(value, dict):
        for item in list(value.values())[:64]:
            out.extend(_strings_in(item, depth + 1))
        return out
    if isinstance(value, (list, tuple)):
        for item in list(value)[:64]:
            out.extend(_strings_in(item, depth + 1))
        return out
    return out


def _lead_facts(lead: Lead, observations: Sequence[EntityObservation]) -> _LeadFacts:
    """The three things a lead can be related by, read off the lead and its observations."""
    from soc_ai.hunting.sources import ALERT_SPEC_ID  # noqa: PLC0415 - lazy, avoids a cycle

    techniques_by_analytic = _techniques_by_analytic()
    analytics: dict[str, list[datetime]] = {}
    networks: set[str] = set()
    techniques: set[str] = set()

    entities: set[tuple[str, str]] = set()
    for entity in lead.entities_json or []:
        if isinstance(entity, (list, tuple)) and len(entity) == 2:
            entities.add((str(entity[0]), str(entity[1])))
            network = _external_network(entity[1])
            if network:
                networks.add(network)

    alert_rules: dict[str, list[datetime]] = {}
    for o in observations:
        spec_id = str(o.spec_id or "")
        born = _naive(o.born_at)
        if spec_id == ALERT_SPEC_ID:
            rule = _alert_rule_of(o)
            if rule and born is not None:
                alert_rules.setdefault(rule, []).append(born)
        elif spec_id and born is not None:
            analytics.setdefault(spec_id, []).append(born)
        techniques.update(techniques_by_analytic.get(spec_id, ()))
        network = _external_network(o.entity_key)
        if network:
            networks.add(network)
        for text in _strings_in(o.evidence_json):
            network = _external_network(text)
            if network:
                networks.add(network)

    return _LeadFacts(
        lead_id=int(lead.id),
        entities=frozenset(entities),
        analytics=analytics,
        alert_rules=alert_rules,
        networks=frozenset(networks),
        techniques=frozenset(techniques),
    )


def _alert_rule_of(o: EntityObservation) -> str | None:
    """The rule that raised an alert observation.

    New rows carry it in the evidence. Rows written before 2026-09-22 carry it
    only as the head of the summary, before the first colon.
    """
    evidence = o.evidence_json if isinstance(o.evidence_json, dict) else {}
    rule = evidence.get("rule_name")
    if isinstance(rule, str) and rule.strip():
        return rule.strip()
    head, sep, _tail = str(o.summary or "").partition(": ")
    if sep and head.strip() and head.strip() != "alert":
        return head.strip()
    return None


def _within(
    mine: dict[str, list[datetime]], theirs: dict[str, list[datetime]], window: timedelta
) -> bool:
    for key, times in sorted(mine.items()):
        others = theirs.get(key)
        if others and any(abs(a - b) <= window for a in times for b in others):
            return True
    return False


def _reason(mine: _LeadFacts, theirs: _LeadFacts) -> str | None:
    """Why these two leads are related, in the analyst's words, or None.

    The three reasons are tried in the order the design states them. The
    first is the strongest: one analytic on two entities inside a working day.

    Two entities. A lead that names an entity this lead also names is the same
    entity's story told twice: the dismissed lead on a host and the lead that
    forms on it next hour share the analytic that formed them both, and the
    panel offered the successor as a relation. Related leads answer "did this
    move?", and one entity cannot answer it.
    """
    if mine.entities & theirs.entities:
        return None
    window = timedelta(hours=SAME_ANALYTIC_HOURS)
    if _within(mine.analytics, theirs.analytics, window):
        return f"same analytic within {SAME_ANALYTIC_HOURS} h"
    if _within(mine.alert_rules, theirs.alert_rules, window):
        return f"same alert rule within {SAME_ANALYTIC_HOURS} h"

    shared_networks = sorted(mine.networks & theirs.networks)
    if shared_networks:
        return f"same external address {shared_networks[0]}"

    shared_techniques = sorted(mine.techniques & theirs.techniques)
    if shared_techniques:
        return f"same technique {shared_techniques[0]}"
    return None


async def _open_leads_since(db: AsyncSession, *, days: int, now: datetime | None) -> list[Lead]:
    """The open leads formed inside the window, newest first.

    Open means an analyst has not answered it. A dismissed or promoted lead is
    an answer, and naming it beside a new lead sends the analyst back over
    ground somebody has already covered.
    """
    cutoff = (_naive(now) or datetime.now(UTC).replace(tzinfo=None)) - timedelta(days=days)
    rows = await db.scalars(
        select(Lead)
        .where(Lead.status.not_in(tuple(CLOSED_STATUSES)), Lead.formed_at >= cutoff)
        .order_by(Lead.formed_at.desc(), Lead.id.desc())
        .limit(200)
    )
    return list(rows.all())


async def _facts_for(db: AsyncSession, leads: Sequence[Lead]) -> dict[int, _LeadFacts]:
    """One observation query for every lead named. Never one query per lead."""
    ids = [int(lead.id) for lead in leads]
    by_lead: dict[int, list[EntityObservation]] = {}
    if ids:
        rows = await db.scalars(select(EntityObservation).where(EntityObservation.lead_id.in_(ids)))
        for o in rows.all():
            by_lead.setdefault(int(o.lead_id or 0), []).append(o)
    return {int(lead.id): _lead_facts(lead, by_lead.get(int(lead.id), [])) for lead in leads}


async def related_leads(
    db: AsyncSession,
    lead: Lead,
    *,
    days: int = RELATED_WINDOW_DAYS,
    now: datetime | None = None,
) -> list[RelatedLead]:
    """The open leads this one shares something with, newest first.

    A lead spans the entities one hit names. A coordinated attack does not.
    Three shares say that two leads may be one story: the same analytic inside
    a working day, the same external network, the same ATT&CK technique. A
    lead that names one of this lead's own entities is left out, because that
    is one entity's story and not a move across two.

    Nothing is stored. The open leads are few, and a stored relation would go
    stale as soon as an analyst dismissed either lead.
    """
    candidates = [
        other
        for other in await _open_leads_since(db, days=days, now=now)
        if int(other.id) != int(lead.id)
    ]
    if not candidates:
        return []
    facts = await _facts_for(db, [lead, *candidates])
    mine = facts[int(lead.id)]
    out: list[RelatedLead] = []
    for other in candidates:
        reason = _reason(mine, facts[int(other.id)])
        if reason is None:
            continue
        out.append(
            RelatedLead(
                lead_id=int(other.id),
                entities=[list(e) for e in (other.entities_json or [])],
                reason=reason,
                formed_at=_naive(other.formed_at),
                status=str(other.status),
                hunt_id=(str(other.hunt_id) if other.hunt_id else None),
            )
        )
    return out


async def related_counts(
    db: AsyncSession,
    leads: Sequence[Lead],
    *,
    days: int = RELATED_WINDOW_DAYS,
    now: datetime | None = None,
) -> dict[int, int]:
    """How many related leads each of these leads has, in two queries for the page.

    The list shows a count per row. A call to :func:`related_leads` per row
    costs two queries per row, and the strip lists fifty.
    """
    if not leads:
        return {}
    open_leads = await _open_leads_since(db, days=days, now=now)
    by_id: dict[int, Lead] = {int(row.id): row for row in open_leads}
    for lead in leads:
        by_id.setdefault(int(lead.id), lead)
    facts = await _facts_for(db, list(by_id.values()))
    open_ids = [int(row.id) for row in open_leads]
    counts: dict[int, int] = {}
    for lead in leads:
        mine = facts[int(lead.id)]
        counts[int(lead.id)] = sum(
            1
            for other_id in open_ids
            if other_id != int(lead.id) and _reason(mine, facts[other_id]) is not None
        )
    return counts
