"""The Oracle retry queue: a failed escalation goes to the Oracle again.

Three production runs stayed needs more info from 2026-11-01 to 2026-11-09
because their Oracle call failed: two on the usage limit of the route and one
on a residue refusal (runs 01M6WEC0CG156GP1YX38YEAKV5,
01M6Y7MDY1GQ7RC00ANYEYESRJ and 01M70SYWE2EB79HN0X94BJWXS0). Nothing tried
the adjudication again. Two of the three were correct true positives that a
gate had lowered, so the analyst read a wrong verdict until a person ran the
investigation again.

The queue is the store. A run whose escalation failed carries an
``oracle_adjudication_failed`` event, and a run whose escalation the route
pause skipped carries an ``oracle_skipped`` event. Both name the end of the
pause. So the queue survives a restart, and it needs no table.

A queued escalation is sent again as a new run of the same subject. The new
run reads the grid again, reaches its local verdict and escalates through the
same pipeline, so each gate and each egress check runs as on any run. A
residue refusal is a fact of one payload, and a new run writes a new one.

The rules:

- No run starts while the route pause is open, or before the pause end that
  the failed run recorded.
- Only the newest run of a subject is in the queue. A later run of the same
  alert or finding, in any state, takes its place.
- The cap is a count for all time, for each subject. A quota, server, timeout
  or transport failure gets :data:`RETRY_LIMIT` new runs. A refusal gets
  :data:`REFUSAL_RETRY_LIMIT`: the evidence of the alert holds the residue,
  so a refusal repeats. After the cap the subject stops for good, and the run
  keeps its local verdict. The count reads every stored run of the subject,
  so a subject does not come back when an old run leaves the read window.
- A run whose escalation the pause skipped is in the queue, and it is no
  failed call: it does not use the cap.
- A subject that cannot run leaves the queue with a recorded reason
  (:func:`drop_from_queue`): the hunt of a finding is gone, or the grid no
  longer holds the alert. It never holds back the subjects behind it.
- A subject that the analyst closed is never in the queue: an analyst verdict
  on the run, an action that the analyst ran from the console, or an alert
  that the grid shows as acknowledged or escalated.
- A synthetic evaluation run and a lead run are never in the queue.
- A failure that needs the operator is never in the queue: a client error of
  the gateway, a payload that does not serialize and the demo block.

The auto-triage sweep reads the queue (:mod:`soc_ai.webui.autotriage`).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select

from soc_ai.oracle import breaker, failures
from soc_ai.store.models import Investigation, InvestigationEvent

_LOGGER = logging.getLogger(__name__)

RETRY_LIMIT = 2
"""New runs that one subject gets, for all time, after a failed Oracle call
of any class but a refusal."""

REFUSAL_RETRY_LIMIT = 1
"""New runs that one subject gets, for all time, after a refusal."""

RETRY_WINDOW = breaker.MAX_PAUSE + timedelta(days=1)
"""How far back the queue reads for the newest run of a subject. A failed run
older than the longest pause plus one day is out of the queue. The cap does
not read this window: it counts every stored run of the subject."""

RETRY_PER_SWEEP = 3
"""New runs that one sweep starts from the queue."""

STARTED_BY = "auto-triage:oracle-retry"
"""The actor of a run that the queue started."""

FAILURE_KINDS = ("oracle_adjudication_failed", "oracle_skipped")

DROPPED_KIND = "oracle_retry_dropped"
"""The event of a subject that left the queue, with the reason."""

ACTION_KIND = "action_executed"
"""The event of an action that the analyst ran from the console."""

RETRYABLE_CLASSES = frozenset(
    {
        failures.QUOTA,
        failures.SERVER,
        failures.TIMEOUT,
        failures.TRANSPORT,
        failures.REFUSED,
        failures.UNPARSEABLE,
        failures.PAUSED,
    }
)

# A lead run has no re-run: the promotion of a lead is a press of the analyst.
_NO_RETRY_KINDS = frozenset({"lead"})


@dataclass(frozen=True)
class PendingEscalation:
    """One run whose escalation the Oracle did not answer, due for a new run."""

    investigation_id: str
    kind: str
    alert_es_id: str
    rule_name: str
    hunt_id: str | None
    finding_ordinal: int | None
    lead_id: int | None
    error_class: str
    # Failed Oracle calls of this subject, for all time. A run whose
    # escalation the pause skipped is not one.
    failed_runs: int

    @property
    def is_finding(self) -> bool:
        return self.kind == "hunt"


def _naive_utc(when: datetime) -> datetime:
    return when.astimezone(UTC).replace(tzinfo=None) if when.tzinfo else when


def _parse_time(value: Any) -> datetime | None:
    """A stored ``paused_until`` time stamp as naive UTC, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _naive_utc(datetime.fromisoformat(value.strip().replace("Z", "+00:00")))
    except ValueError:
        return None


def failure_of(kind: str, payload: Any) -> tuple[str, datetime | None] | None:
    """(error class, pause end) of one stored event, or None when it is no retry.

    A skipped escalation has the class ``paused``. A failed adjudication names
    its class. An event with no class, or with a class that needs the
    operator, gives None.
    """
    body = payload if isinstance(payload, dict) else {}
    if kind == "oracle_skipped":
        error_class = failures.PAUSED
    elif kind == "oracle_adjudication_failed":
        error_class = str(body.get("error_class") or "")
    else:
        return None
    if error_class not in RETRYABLE_CLASSES:
        return None
    return error_class, _parse_time(body.get("paused_until"))


def _subject_key(inv: Investigation) -> tuple[str, str, int] | None:
    """What a run investigated: one alert, or one finding of one hunt."""
    if inv.kind in _NO_RETRY_KINDS:
        return None
    if inv.kind == "hunt":
        if not inv.hunt_id or inv.finding_ordinal is None:
            return None
        return ("finding", str(inv.hunt_id), int(inv.finding_ordinal))
    if not inv.alert_es_id:
        return None
    return ("alert", str(inv.alert_es_id), 0)


def _analyst_set(inv: Investigation) -> bool:
    report = inv.report if isinstance(inv.report, dict) else {}
    return bool(report.get("resolution"))


def retry_limit(error_class: str) -> int:
    """The new runs that a subject gets after a failure of this class."""
    return REFUSAL_RETRY_LIMIT if error_class == failures.REFUSED else RETRY_LIMIT


async def drop_from_queue(maker: Any, investigation_id: str, reason: str) -> None:
    """Take one subject out of the queue for good, with the reason. Never raises.

    Writes an ``oracle_retry_dropped`` event on the run. The queue then skips
    every run of that subject.
    """
    try:
        async with maker() as db:
            last = await db.scalar(
                select(func.max(InvestigationEvent.sequence)).where(
                    InvestigationEvent.investigation_id == investigation_id
                )
            )
            db.add(
                InvestigationEvent(
                    investigation_id=investigation_id,
                    sequence=int(last or 0) + 1,
                    kind=DROPPED_KIND,
                    payload={"reason": reason, "at": breaker.iso(breaker._now())},
                )
            )
            await db.commit()
    except Exception:
        _LOGGER.exception("the Oracle retry queue could not record why it dropped a run")


async def _load_subjects(maker: Any, cutoff: datetime) -> tuple[list[Investigation], list[Any]]:
    """Every stored run of the subjects of the queue, and their queue events.

    A subject is in the queue when one of its runs in the read window carries
    a failed or skipped escalation. The runs come back with no window, oldest
    first, because the cap is a count for all time.
    """
    async with maker() as db:
        # The runs of the read window with a failed or skipped escalation
        # name the subjects.
        recent = (
            (
                await db.execute(
                    select(Investigation)
                    .join(
                        InvestigationEvent,
                        InvestigationEvent.investigation_id == Investigation.id,
                    )
                    .where(
                        InvestigationEvent.kind.in_(FAILURE_KINDS),
                        Investigation.created_at >= cutoff,
                    )
                )
            )
            .scalars()
            .unique()
            .all()
        )
        keys = {key for inv in recent if (key := _subject_key(inv)) is not None}
        alert_ids = sorted(key[1] for key in keys if key[0] == "alert")
        hunt_ids = sorted(key[1] for key in keys if key[0] == "finding")
        clauses = []
        if alert_ids:
            clauses.append(Investigation.alert_es_id.in_(alert_ids))
        if hunt_ids:
            clauses.append(Investigation.hunt_id.in_(hunt_ids))
        if not clauses:
            return [], []
        siblings = [
            inv
            for inv in (
                await db.execute(
                    select(Investigation)
                    .where(or_(*clauses))
                    .order_by(Investigation.created_at, Investigation.id)
                )
            )
            .scalars()
            .all()
            if _subject_key(inv) in keys
        ]
        event_rows = (
            await db.execute(
                select(
                    InvestigationEvent.investigation_id,
                    InvestigationEvent.kind,
                    InvestigationEvent.payload,
                )
                .where(
                    InvestigationEvent.investigation_id.in_([str(i.id) for i in siblings]),
                    InvestigationEvent.kind.in_((*FAILURE_KINDS, DROPPED_KIND, ACTION_KIND)),
                )
                .order_by(InvestigationEvent.investigation_id, InvestigationEvent.sequence)
            )
        ).all()
    return siblings, list(event_rows)


async def pending_escalations(
    maker: Any,
    settings: Any,
    *,
    now: datetime | None = None,
    limit: int | None = None,
) -> list[PendingEscalation]:
    """The failed escalations that are due for a new run, oldest first.

    Empty while the Oracle is off and while the route pause is open. ``now``
    is aware UTC, the clock of the breaker. ``limit`` cuts the list, and None
    gives every due subject: the sweep counts the runs that start, so a
    subject that cannot start holds back no other one.
    """
    if not getattr(settings, "oracle_enabled", False):
        return []
    now = now or breaker._now()
    if breaker.BREAKER.open_until(breaker.route_key(settings), now=now) is not None:
        return []
    naive_now = _naive_utc(now)
    cutoff = naive_now - RETRY_WINDOW

    siblings, event_rows = await _load_subjects(maker, cutoff)

    # The last failure event of each run, and the runs that carry a drop or
    # an analyst action.
    failed: dict[str, tuple[str, datetime | None]] = {}
    closed_runs: set[str] = set()
    for run_id, kind, payload in event_rows:
        if kind in (DROPPED_KIND, ACTION_KIND):
            closed_runs.add(str(run_id))
            continue
        failure = failure_of(str(kind), payload)
        if failure is not None:
            failed[str(run_id)] = failure

    newest: dict[tuple[str, str, int], Investigation] = {}
    failed_calls: dict[tuple[str, str, int], int] = {}
    closed: set[tuple[str, str, int]] = set()
    for inv in siblings:
        key = _subject_key(inv)
        if key is None:
            continue
        newest[key] = inv  # ordered by creation, so the last one wins
        if str(inv.id) in closed_runs:
            closed.add(key)
        entry = failed.get(str(inv.id))
        if entry is not None and entry[0] != failures.PAUSED:
            failed_calls[key] = failed_calls.get(key, 0) + 1

    due: list[PendingEscalation] = []
    for key, inv in newest.items():
        entry = failed.get(str(inv.id))
        if entry is None or key in closed:
            continue  # a later run took the place, or the subject is closed
        error_class, not_before = entry
        if inv.status != "complete" or inv.is_synth_eval or _analyst_set(inv):
            continue
        if inv.created_at is None or inv.created_at < cutoff:
            continue
        if not_before is not None and not_before > naive_now:
            continue
        calls = failed_calls.get(key, 0)
        if calls > retry_limit(error_class):
            continue  # the subject had its new runs, and it stops for good
        subject = inv.subject_json if isinstance(inv.subject_json, dict) else {}
        lead_id = subject.get("lead_id")
        due.append(
            PendingEscalation(
                investigation_id=str(inv.id),
                kind=str(inv.kind),
                alert_es_id=str(inv.alert_es_id),
                rule_name=str(inv.rule_name or ""),
                hunt_id=str(inv.hunt_id) if inv.hunt_id else None,
                finding_ordinal=inv.finding_ordinal,
                lead_id=int(lead_id) if isinstance(lead_id, int) else None,
                error_class=error_class,
                failed_runs=calls,
            )
        )
    due.sort(key=lambda p: p.investigation_id)  # a ULID sorts by creation time
    return due if limit is None else due[:limit]


__all__ = [
    "ACTION_KIND",
    "DROPPED_KIND",
    "FAILURE_KINDS",
    "REFUSAL_RETRY_LIMIT",
    "RETRYABLE_CLASSES",
    "RETRY_LIMIT",
    "RETRY_PER_SWEEP",
    "RETRY_WINDOW",
    "STARTED_BY",
    "PendingEscalation",
    "drop_from_queue",
    "failure_of",
    "pending_escalations",
    "retry_limit",
]
