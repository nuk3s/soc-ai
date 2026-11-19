"""One decision for each rule: the open false positives of a rule.

soc-ai gives a false positive verdict, and then a guard of the automatic
acknowledge holds the write (:func:`soc_ai.agent.orchestrator.maybe_auto_ack_fp`).
The alert stays open on the grid, the investigation shows an open
Acknowledge, and no queue holds it. Production on 2026-11-18 held 1,215 such
investigations on 69 rules, and one rule alone held 471. The analyst had to
open each investigation and press once.

:func:`open_false_positives` is the one selection. Needs you, the page of a
rule, the decision and the investigation page read it, so no two surfaces
count the same rule two ways.

An open false positive is the standing false positive verdict of an alert
investigation whose acknowledge no one carried out:

* a complete false positive that is no pipeline fallback, no synthetic
  evaluation, no backtest replay, no promoted finding or lead and no hunt
  subject;
* the primary run of its alert (:func:`inv_svc.superseded_sql`);
* no analyst verdict on the alert, on this run or on any other run of it;
* the report recommends ``ack_alert``;
* no ``auto_ack`` that succeeded, no ``action_executed`` of ``ack_alert``
  that succeeded, no event of the old approval gate, and the analyst did not
  dismiss the acknowledge (the newest of ``action_dismissed`` and
  ``action_restored`` is not a dismissal).

The hold reason is the ``reason`` of the ``auto_ack_skipped`` event. A run
with no such event either has an ``auto_ack`` that failed or ran with the
automatic acknowledge off. The group ``confident`` holds the runs whose
evidence guards passed: the hold ``high_stakes``, a failed automatic
acknowledge, and an automatic acknowledge that was off for a run that meets
the threshold of now and read a record. Every other reason is the group
``weak``: soc-ai is not sure of these.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import statistics
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, false, func, not_, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns.facts import chunked
from soc_ai.so_client.fields import get_dotted
from soc_ai.store import investigations as inv_svc
from soc_ai.store import rule_decisions as rd_store
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Investigation, InvestigationEvent, RuleDecision

_LOGGER = logging.getLogger(__name__)

# The two groups of an open false positive.
CONFIDENT = "confident"
WEAK = "weak"
GROUPS: tuple[str, ...] = (CONFIDENT, WEAK)

# The reasons of a run with no ``auto_ack_skipped`` event. The automatic
# acknowledge failed, or it was off when the run ended.
REASON_AUTO_ACK_FAILED = "auto_ack_failed"
REASON_AUTO_ACK_OFF = "auto_ack_off"

# The reasons of the group ``confident``: the evidence guards passed.
CONFIDENT_REASONS = frozenset({"high_stakes", REASON_AUTO_ACK_FAILED, REASON_AUTO_ACK_OFF})

# A reason that names no Security Onion alert. A promoted finding anchors on
# cited telemetry, and nothing in Security Onion waits for an acknowledge.
_NO_ALERT_REASONS = frozenset({"promoted_finding"})

# The label of each hold reason, in the words of every surface (RS6). The
# sentence of the investigation card (``_timeline._ack_pending_note``) keeps
# its own words.
HOLD_LABELS: dict[str, str] = {
    "high_stakes": "The alert is high or critical, or a malware or exploit alert.",
    REASON_AUTO_ACK_FAILED: "The automatic acknowledge failed.",
    REASON_AUTO_ACK_OFF: "The automatic acknowledge was off.",
    "below_threshold": "The confidence is below the threshold of the automatic acknowledge.",
    "no_investigation": "The investigation retrieved nothing.",
    "uncited": "The report cites no evidence that resolves.",
    "oracle_dissent": "The Oracle gave another verdict and cited no evidence that resolves.",
    "earlier_true_positive": "An earlier investigation of the alert gave a true positive.",
    "earlier_runs_unread": "soc-ai could not read the earlier investigations of the alert.",
    "analyst_verdict": "An analyst set a verdict on the alert.",
    "analyst_verdict_unknown": "soc-ai could not read the analyst verdict of the alert.",
}
_UNKNOWN_LABEL = "soc-ai holds the acknowledge."

# The label of a hold that no longer applies to the rule (F1): soc-ai
# acknowledges the later false positives of the rule by itself.
HOLD_LABELS_PAST: dict[str, str] = {
    "high_stakes": (
        "The alert counted as high or critical, or as a malware or exploit alert, at that time."
    ),
}

# The order of the reasons on a surface: the confident reasons first.
_REASON_ORDER: tuple[str, ...] = tuple(HOLD_LABELS)

# The most runs one selection reads. The newest events first, so a cap
# leaves out the oldest. Production held 1,215.
SCAN_MAX = 20_000

# The event kinds that decide the hold reason and a dismissal.
_HOLD_EVENT_KINDS = ("auto_ack", "auto_ack_skipped", "action_dismissed", "action_restored")
_APPROVAL_KINDS = ("approval_request", "approval_required")


def hold_label(code: str | None, *, past: bool = False) -> str:
    """The label of a hold reason, for every surface.

    ``past`` gives the past tense of a hold that no longer applies to the
    rule (:func:`acknowledges_alone`). A reason with no past form keeps its
    label.
    """
    if past and (code or "") in HOLD_LABELS_PAST:
        return HOLD_LABELS_PAST[code or ""]
    return HOLD_LABELS.get(code or "", _UNKNOWN_LABEL)


def group_of(reason: str) -> str:
    """The group of a hold reason: ``confident`` or ``weak``."""
    return CONFIDENT if reason in CONFIDENT_REASONS else WEAK


def reason_rank(code: str) -> int:
    """The place of a reason in the order of a surface. An unknown code is last."""
    return _REASON_ORDER.index(code) if code in _REASON_ORDER else len(_REASON_ORDER)


# ── The key of a rule ──────────────────────────────────────────────────────


def rule_key(rule_name: str) -> str:
    """The rule name in base64url with no padding: the ``ruleKey`` of the API."""
    return base64.urlsafe_b64encode(rule_name.encode("utf-8")).decode("ascii").rstrip("=")


def rule_from_key(key: str) -> str | None:
    """The rule name of a ``ruleKey``, or None when the key does not decode."""
    text = (key or "").strip()
    if not text or len(text) > 1024:
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        name = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    if not name.strip() or rule_key(name) != text:
        return None
    return name


def rule_href(rule_name: str) -> str:
    """The console page of a rule."""
    return f"/needs-you/rule/{rule_key(rule_name)}"


# ── The selection ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class OpenFalsePositive:
    """One open false positive, with its rule, its group and its hold reason."""

    id: str
    alert_es_id: str
    rule_name: str
    group: str
    reason: str
    confidence: float | None
    event_at: datetime | None
    created_at: datetime | None
    src_ip: str | None
    dest_ip: str | None
    host_name: str | None
    kind: str
    # The index of the recommended ``ack_alert`` in the report, and the
    # action itself. A receipt names both.
    action_index: int
    action: dict[str, Any]
    # What the grid stated for the alert, and when (RS2). None when the grid
    # was not read yet: the alert then counts as open.
    grid_state: str | None = None
    grid_read_at: datetime | None = None


def _ack_index(actions: Any) -> int | None:
    """The index of the first recommended ``ack_alert``, or None."""
    if not isinstance(actions, list):
        return None
    for index, action in enumerate(actions):
        if isinstance(action, dict) and action.get("tool_name") == "ack_alert":
            return index
    return None


def _success_sql() -> Any:
    """The SQL for an ``auto_ack`` or ``action_executed`` event that succeeded."""
    # The CASE reads the flag only on the two kinds that write it as a JSON
    # boolean. PostgreSQL may evaluate the terms of an OR in any order, and a
    # cast of another kind's "success" that holds no boolean would fail.
    return (
        case(
            (
                InvestigationEvent.kind.in_(("auto_ack", "action_executed")),
                InvestigationEvent.payload["success"].as_boolean(),
            ),
            else_=false(),
        )
        == true()
    )


def _acknowledged_sql() -> Any:
    """The SQL for a run whose acknowledge an event carried out or closed.

    An ``auto_ack`` that succeeded, an ``action_executed`` of ``ack_alert``
    that succeeded, or an event of the old approval gate. The JSON paths
    render ``json_extract`` on SQLite and ``->>`` on PostgreSQL.
    """
    success = _success_sql()
    return (
        select(InvestigationEvent.id)
        .where(
            InvestigationEvent.investigation_id == Investigation.id,
            or_(
                and_(InvestigationEvent.kind == "auto_ack", success),
                and_(
                    InvestigationEvent.kind == "action_executed",
                    InvestigationEvent.payload["tool_name"].as_string() == "ack_alert",
                    success,
                ),
                InvestigationEvent.kind.in_(_APPROVAL_KINDS),
            ),
        )
        .exists()
    )


def selection_conds(rule_names: Sequence[str] | None = None) -> list[Any]:
    """The SQL half of the selection. Python reads the events after it."""
    resolved_via = Investigation.report["resolution"]["resolved_via"].as_string()
    conds: list[Any] = [
        Investigation.status == "complete",
        Investigation.verdict == "false_positive",
        Investigation.is_fallback.isnot(True),
        Investigation.is_synth_eval.isnot(True),
        inv_svc.not_backtest(),
        Investigation.kind.not_in(inv_svc.PROMOTED_KINDS),
        inv_svc.not_hunt_subject(),
        func.coalesce(Investigation.alert_es_id, "") != "",
        func.coalesce(Investigation.rule_name, "") != "",
        or_(resolved_via.is_(None), resolved_via.not_in(inv_svc.ANALYST_RESOLUTIONS)),
        not_(_acknowledged_sql()),
        not_(inv_svc.superseded_sql()),
        # The grid states the alert as acknowledged or gone (RS2).
        not_(rd_store.closed_state_sql()),
    ]
    if rule_names is not None:
        conds.append(Investigation.rule_name.in_(sorted({r for r in rule_names if r})))
    return conds


async def _hold_events(db: AsyncSession, run_ids: Sequence[str]) -> dict[str, list[Any]]:
    """The hold and dismissal events of each run, in their order."""
    out: dict[str, list[Any]] = {}
    for ids in chunked(sorted(set(run_ids))):
        rows = await db.scalars(
            select(InvestigationEvent)
            .where(
                InvestigationEvent.investigation_id.in_(ids),
                InvestigationEvent.kind.in_(_HOLD_EVENT_KINDS),
            )
            .order_by(InvestigationEvent.sequence, InvestigationEvent.id)
        )
        for event in rows.all():
            out.setdefault(event.investigation_id, []).append(event)
    return out


def _dismissed(events: Sequence[Any], action: dict[str, Any], index: int) -> bool:
    """Whether the analyst dismissed the acknowledge, by the rule of the action card."""
    from soc_ai.api.webui._timeline import (  # noqa: PLC0415 - lazy: the api package imports this module
        _action_identity,
        _dismissals,
    )

    standing = _dismissals(list(events))
    return _action_identity(action) in standing or f"#idx:{index}" in standing


def read_nothing(tool_calls: int | None, es_searches: int | None) -> bool:
    """Whether the stored counts show a run that read no record.

    No tool call and no grid search. A run with no stored count of tool
    calls (an older run) shows nothing, so it is no proof of an empty read.
    """
    return tool_calls is not None and tool_calls == 0 and not es_searches


def _reason_of(
    events: Sequence[Any],
    *,
    confidence: float | None,
    threshold: float,
    empty_read: bool,
) -> str:
    """The hold reason of a run: the newest ``auto_ack_skipped``, else the defaults.

    A run with no hold event ran while the automatic acknowledge was off, so no
    guard looked at it. Round 3, part 2 (F2): the group ``confident`` held
    such runs whatever their confidence, and a sample at 0.60 read as
    confident. Such a run now meets the two evidence guards that come first in
    :func:`soc_ai.agent.orchestrator.maybe_auto_ack_fp`, with the threshold of
    now: a confidence under the threshold gives ``below_threshold``, and a run
    that read no record gives ``no_investigation``. Both are the group
    ``weak``.
    """
    reason: str | None = None
    for event in events:
        if event.kind == "auto_ack_skipped":
            reason = str((event.payload or {}).get("reason") or "")
    if reason:
        return reason
    if any(event.kind == "auto_ack" for event in events):
        # The SQL left out every auto_ack that succeeded. The guards passed
        # on the way to the write that failed.
        return REASON_AUTO_ACK_FAILED
    if (confidence or 0.0) < threshold:
        return "below_threshold"
    if empty_read:
        return "no_investigation"
    return REASON_AUTO_ACK_OFF


async def open_false_positives(
    db: AsyncSession, *, threshold: float, rule_names: Sequence[str] | None = None
) -> list[OpenFalsePositive]:
    """The open false positives, the newest event first.

    ``threshold`` is the setting ``auto_ack_fp_threshold`` of now. It puts a
    run with no hold event in its group (:func:`_reason_of`), so every caller
    passes the same value. ``rule_names`` limits the read to those rules.
    None reads every rule.
    Four reads: the runs, their events, the analyst verdicts of their
    alerts, and the grid states of the alerts. A run that the analyst decided
    on is in no group. An alert that the grid states as acknowledged or gone
    is in no group. An alert with no stored state counts as open.
    """
    rows = (
        await db.execute(
            select(
                Investigation.id,
                Investigation.alert_es_id,
                Investigation.rule_name,
                Investigation.confidence,
                Investigation.event_at,
                Investigation.created_at,
                Investigation.src_ip,
                Investigation.dest_ip,
                Investigation.host_name,
                Investigation.kind,
                Investigation.report["recommended_actions"],
                Investigation.tool_calls,
                Investigation.es_searches,
            )
            .where(*selection_conds(rule_names))
            .order_by(Investigation.event_at.desc(), Investigation.id.desc())
            .limit(SCAN_MAX)
        )
    ).all()
    candidates = [(row, index) for row in rows if (index := _ack_index(row[10])) is not None]
    if not candidates:
        return []
    events = await _hold_events(db, [str(row[0]) for row, _i in candidates])
    analyst = await inv_svc.analyst_verdicts_for_alerts(db, [str(row[1]) for row, _i in candidates])
    states = await rd_store.states_for(db, [str(row[1]) for row, _i in candidates])
    out: list[OpenFalsePositive] = []
    for row, index in candidates:
        run_id, alert_id = str(row[0]), str(row[1])
        if alert_id in analyst:
            continue
        run_events = events.get(run_id, [])
        action = row[10][index]
        if _dismissed(run_events, action, index):
            continue
        reason = _reason_of(
            run_events,
            confidence=row[3],
            threshold=threshold,
            empty_read=read_nothing(row[11], row[12]),
        )
        if reason in _NO_ALERT_REASONS:
            continue
        grid = states.get(alert_id)
        out.append(
            OpenFalsePositive(
                id=run_id,
                alert_es_id=alert_id,
                rule_name=str(row[2]),
                group=group_of(reason),
                reason=reason,
                confidence=row[3],
                event_at=row[4],
                created_at=row[5],
                src_ip=row[6],
                dest_ip=row[7],
                host_name=row[8],
                kind=str(row[9] or "suricata"),
                action_index=index,
                action=action,
                grid_state=grid[0] if grid else None,
                grid_read_at=grid[1] if grid else None,
            )
        )
    return out


def by_rule(rows: Iterable[OpenFalsePositive]) -> dict[str, list[OpenFalsePositive]]:
    """The open false positives of each rule, in the order given."""
    out: dict[str, list[OpenFalsePositive]] = {}
    for row in rows:
        out.setdefault(row.rule_name, []).append(row)
    return out


def in_group(rows: Iterable[OpenFalsePositive], group: str) -> list[OpenFalsePositive]:
    """The rows of one group."""
    return [row for row in rows if row.group == group]


def median_confidence(rows: Sequence[OpenFalsePositive]) -> float | None:
    """The median confidence of the group ``confident``, else of all rows, or None."""
    confident = [r.confidence for r in rows if r.group == CONFIDENT and r.confidence is not None]
    values = confident or [r.confidence for r in rows if r.confidence is not None]
    return float(statistics.median(values)) if values else None


# ── A rule that soc-ai acknowledges by itself (F1) ─────────────────────────


@dataclass(frozen=True)
class AcknowledgesAlone:
    """soc-ai acknowledges the later false positives of a rule by itself.

    ``since`` is the end of the first investigation whose automatic
    acknowledge succeeded after the newest hold ``high_stakes`` of the rule.
    ``acknowledged`` counts those acknowledges.
    """

    since: datetime
    acknowledged: int


def _rule_run_conds(rule_name: str) -> list[Any]:
    """The runs of a rule whose events say what the guard did on a live alert."""
    return [
        InvestigationEvent.investigation_id == Investigation.id,
        Investigation.rule_name == rule_name,
        Investigation.is_synth_eval.isnot(True),
        inv_svc.not_backtest(),
    ]


async def acknowledges_alone(db: AsyncSession, rule_name: str) -> AcknowledgesAlone | None:
    """Whether soc-ai now acknowledges the false positives of the rule by itself.

    From stored facts only. The newest hold ``high_stakes`` of the rule is the
    last time that the guard held the rule. Each automatic acknowledge that
    succeeded after it, with no rule decision behind it, shows that the guard
    lets the rule pass now. Production, 2026-11-13: a change of the guard let
    an Informational rule of a policy classification pass, and the holds of
    the rule from before stayed open.

    None when the rule has no such hold, or no such acknowledge after it. The
    event id gives the order: the event table holds no time.
    """
    reason = InvestigationEvent.payload["reason"].as_string()
    last_hold = await db.scalar(
        select(func.max(InvestigationEvent.id)).where(
            *_rule_run_conds(rule_name),
            InvestigationEvent.kind == "auto_ack_skipped",
            reason == "high_stakes",
        )
    )
    if last_hold is None:
        return None
    count, since = (
        await db.execute(
            select(
                func.count(InvestigationEvent.id),
                func.min(func.coalesce(Investigation.finished_at, Investigation.created_at)),
            ).where(
                *_rule_run_conds(rule_name),
                InvestigationEvent.kind == "auto_ack",
                InvestigationEvent.id > last_hold,
                _success_sql(),
                InvestigationEvent.payload["rule_decision"].as_string().is_(None),
            )
        )
    ).one()
    if not count or since is None:
        return None
    return AcknowledgesAlone(since=since, acknowledged=int(count))


# ── The grid state (RS2) ───────────────────────────────────────────────────


def _threshold(app_state: Any) -> float:
    """The setting ``auto_ack_fp_threshold`` of now: a hot change applies to the next read."""
    return float(app_state.settings.auto_ack_fp_threshold)


# The most ids that one grid search asks about.
GRID_BATCH = 200
# A stored state older than this is due for a new read. The page of a rule
# asks the grid for its rule when the state is older.
STATE_MAX_AGE = timedelta(minutes=5)
# The most alerts that one background step reads.
STEP_MAX = 1000


async def _read_batch(app_state: Any, ids: list[str]) -> dict[str, str] | None:
    """One grid search for ``ids``: the state of each one, or None when the grid did not answer.

    The flag is read from ``_source``. An endpoint alert index maps no
    ``event.acknowledged``, so a query filter on it does not see the write of
    Security Onion. A shard that failed can hold the alert: a partial read is
    no answer, never ``gone``.
    """
    settings = app_state.settings
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            result = await app_state.elastic.search(
                settings.events_index_pattern,
                {"ids": {"values": ids}},
                size=len(ids),
                source=["event.acknowledged"],
                require_complete=True,
            )
    except Exception:
        _LOGGER.warning("rule decisions: the grid did not answer for %d alerts", len(ids))
        return None
    found: dict[str, str] = {}
    for hit in result.hits:
        acknowledged = bool(get_dotted(hit.get("_source") or {}, "event.acknowledged"))
        found[str(hit.get("_id"))] = (
            rd_store.STATE_ACKNOWLEDGED if acknowledged else rd_store.STATE_OPEN
        )
    return {i: found.get(i, rd_store.STATE_GONE) for i in ids}


async def read_grid_states(app_state: Any, alert_ids: Iterable[str]) -> dict[str, str] | None:
    """The state that the grid states for each alert, in bounded batches.

    None when one batch did not answer. The caller then keeps the last state.
    """
    wanted = list(dict.fromkeys(a for a in alert_ids if a))
    out: dict[str, str] = {}
    for start in range(0, len(wanted), GRID_BATCH):
        answers = await _read_batch(app_state, wanted[start : start + GRID_BATCH])
        if answers is None:
            return None
        out.update(answers)
    return out


async def refresh_states(app_state: Any, alert_ids: Iterable[str]) -> bool:
    """Ask the grid for the alerts and store each answer. True when the grid answered.

    A batch that did not answer stores nothing for its alerts, and the last
    state stays. The batches before it are stored.
    """
    wanted = list(dict.fromkeys(a for a in alert_ids if a))
    answered = True
    for start in range(0, len(wanted), GRID_BATCH):
        batch = wanted[start : start + GRID_BATCH]
        answers = await _read_batch(app_state, batch)
        if answers is None:
            answered = False
            break
        async with app_state.db_sessionmaker() as db:
            await rd_store.record_states(db, answers, at=utcnow())
    return answered


def stale_alerts(
    rows: Iterable[OpenFalsePositive], *, now: datetime, max_age: timedelta = STATE_MAX_AGE
) -> list[str]:
    """The alerts whose state is due: no read first, then the oldest read."""
    due: dict[str, datetime | None] = {}
    for row in rows:
        if row.grid_read_at is None or now - row.grid_read_at >= max_age:
            due.setdefault(row.alert_es_id, row.grid_read_at)
    return sorted(due, key=lambda a: (due[a] is not None, due[a] or now, a))


def read_at(rows: Sequence[OpenFalsePositive]) -> datetime | None:
    """The time of the oldest grid read of the rows, or None when an alert was not read yet."""
    if not rows or any(row.grid_read_at is None for row in rows):
        return None
    return min(row.grid_read_at for row in rows if row.grid_read_at is not None)


async def background_step(app_state: Any, *, limit: int = STEP_MAX) -> bool | None:
    """Ask the grid for the alerts of the selection that are due, at most ``limit``.

    One step of the minute loop of the app. It first ends each standing
    decision whose term is over or whose rule got a true positive
    (:func:`settle_decisions`). True when the grid answered, False when it
    did not, and None when no alert was due.
    """
    await settle_decisions(app_state)
    async with app_state.db_sessionmaker() as db:
        rows = await open_false_positives(db, threshold=_threshold(app_state))
    due = stale_alerts(rows, now=utcnow())[: max(0, limit)]
    if not due:
        return None
    answered = await refresh_states(app_state, due)
    invalidate(app_state)
    return answered


async def refresh_rule(app_state: Any, rule_name: str) -> bool | None:
    """Ask the grid for the alerts of one rule whose state is older than 5 minutes.

    True when the grid answered, False when it did not, and None when no
    alert was due. The page of a rule calls it.
    """
    async with app_state.db_sessionmaker() as db:
        rows = await open_false_positives(
            db, threshold=_threshold(app_state), rule_names=[rule_name]
        )
    due = stale_alerts(rows, now=utcnow())
    if not due:
        return None
    return await refresh_states(app_state, due)


# ── The decision (RS4) ─────────────────────────────────────────────────────

# The session id of the audit records of a rule decision.
AUDIT_SESSION = "rule-decisions"
# How far back the scan of the grid reads the alerts that inherit a verdict,
# and the most events that it reads. The page states the count of the open
# alerts of the rule in the same window.
CLUSTER_DAYS = 30
CLUSTER_RANGE = f"{CLUSTER_DAYS}d"
CLUSTER_SCAN_MAX = 2000
# The bounded fan-out of the writes, as on the Alerts page.
ACK_CONCURRENCY = 8
# The verdicts of an alert that a decision never acknowledges.
_HELD_VERDICTS = frozenset({"true_positive", "needs_more_info"})
# The words of the receipt on each investigation.
RECEIPT_DETAIL = "soc-ai acknowledged this alert with the decision on the rule."


# The machines of one alert or one investigation: its two ends, in no order.
MachinePair = frozenset[str]


def machine_pair(src: str | None, dst: str | None, host: str | None) -> MachinePair | None:
    """The machine pair of an alert: its source and its target. None with no end."""
    from soc_ai.store import first_line as first_line_svc  # noqa: PLC0415 - lazy

    source, target = first_line_svc.alert_ends(src, dst, host)
    ends = frozenset(end for end in (source, target) if end)
    return ends or None


async def true_positive_pairs(db: AsyncSession, rule_name: str) -> frozenset[MachinePair]:
    """The machine pair of each true positive of the rule that stands (F4)."""
    runs = await rd_store.standing_true_positives(db, rule_name, limit=SCAN_MAX)
    pairs = (machine_pair(r.src_ip, r.dest_ip, r.host_name) for r in runs)
    return frozenset(pair for pair in pairs if pair is not None)


def on_true_positive_pair(row: OpenFalsePositive, tp_pairs: frozenset[MachinePair]) -> bool:
    """Whether an open false positive is on the machine pair of a true positive of its rule."""
    return machine_pair(row.src_ip, row.dest_ip, row.host_name) in tp_pairs


def selected(
    rows: Iterable[OpenFalsePositive],
    *,
    include_weak: bool,
    tp_pairs: frozenset[MachinePair],
    include_tp_pairs: bool = False,
) -> list[OpenFalsePositive]:
    """The rows that a decision acts on.

    The group confident, and the group weak on request. A row on the machine
    pair of a true positive of the rule that stands is left out unless the
    analyst asks for it (F4): the true positive and the false positives on the
    same machines are a question for the analyst. Every caller passes the
    pairs, so no caller forgets them.
    """
    return [
        row
        for row in rows
        if (row.group == CONFIDENT or include_weak)
        and (include_tp_pairs or not on_true_positive_pair(row, tp_pairs))
    ]


@dataclass(frozen=True)
class AckPlan:
    """What a decision writes, worked out from the grid before the first write.

    ``own`` is the state that the grid states now for the alert of each
    selected investigation. ``cluster`` holds the open alerts that inherit
    the verdict of a selected investigation: the same rule and the same pair
    of machines. ``held`` counts the alerts of the cluster that the decision
    leaves open because a verdict of their own holds them. ``capped`` is
    true when the scan of the grid stopped at ``CLUSTER_SCAN_MAX`` events:
    more alerts can inherit the verdict.
    """

    own: dict[str, str]
    cluster: list[str]
    held: int
    capped: bool = False

    @property
    def own_open(self) -> int:
        """The alerts of the selected investigations that the grid holds open."""
        return sum(1 for s in self.own.values() if s == rd_store.STATE_OPEN)

    @property
    def writes(self) -> list[str]:
        """The alerts to acknowledge, each once."""
        own_open = [a for a, s in self.own.items() if s == rd_store.STATE_OPEN]
        return list(dict.fromkeys([*own_open, *self.cluster]))


def _subject_keys(rule_name: str, rows: Iterable[OpenFalsePositive]) -> set[inv_svc.PairKey]:
    """The inheritance key of each row that names a subject.

    A key with no subject says only that the rule fired. It would match every
    alert of the rule with no subject, so it lends its verdict to none.
    """
    keys = {inv_svc.pair_key(rule_name, r.src_ip, r.dest_ip, r.host_name) for r in rows}
    return {key for key in keys if inv_svc.names_a_subject(key)}


def _kind_of(rows: Sequence[OpenFalsePositive]) -> str:
    """The group type of the rule on the Alerts page: a Zeek notice, else a rule name."""
    return "notice" if rows and all(r.kind == "notice" for r in rows) else "suricata"


@dataclass(frozen=True)
class ClusterScan:
    """The open alerts of a rule whose key names a subject of a scanned row.

    ``capped`` is true when the scan stopped at ``CLUSTER_SCAN_MAX`` events.
    One scan of all the rows of a rule serves each choice of the page: a
    choice keeps the alerts of its own keys (:func:`plan_from`).
    """

    events: list[Any]
    capped: bool = False


async def _scan_cluster(
    app_state: Any, rule_name: str, rows: Sequence[OpenFalsePositive]
) -> ClusterScan | None:
    """The open alerts of the rule with the key of a row. None when the grid fails."""
    from soc_ai.webui import alerts_query as aq  # noqa: PLC0415 - lazy
    from soc_ai.webui.autotriage import _event_key  # noqa: PLC0415 - lazy: a heavy module

    keys = _subject_keys(rule_name, rows)
    if not keys:
        return ClusterScan([])
    settings = app_state.settings
    found: list[Any] = []
    offset = 0
    capped = True
    try:
        while offset < CLUSTER_SCAN_MAX:
            page = await aq.fetch_group_events(
                app_state.elastic,
                settings,
                rule_name=rule_name,
                kind=_kind_of(rows),
                time_range=CLUSTER_RANGE,
                size=aq.MAX_EVENTS,
                offset=offset,
                time_zone=settings.so_timezone,
                hide_acked=True,
            )
            for event in page:
                if event.acknowledged or event.escalated:
                    continue
                if _event_key(rule_name, event) in keys:
                    found.append(event)
            if len(page) < aq.MAX_EVENTS:
                capped = False
                break
            offset += len(page)
    except Exception:
        _LOGGER.warning("rule decisions: the grid did not answer the scan of rule %r", rule_name)
        return None
    return ClusterScan(found, capped)


async def _held_cluster(
    db: AsyncSession,
    settings: Any,
    rule_name: str,
    events: Sequence[Any],
    selected_ids: set[str],
) -> set[str]:
    """The alerts of the cluster that a verdict of their own holds open.

    The verdict of an alert is the run of that alert, else the run of the
    same rule and the same pair of machines. A true positive or a needs more
    info verdict holds it. A false positive of its own that the decision did
    not select holds it too: its acknowledge waits, was dismissed, or has
    weak evidence. An analyst verdict, and an earlier run that leaned true
    positive, hold it whatever the run says.
    """
    ids = [e.es_id for e in events]
    if not ids:
        return set()
    direct = await inv_svc.latest_for_alerts(db, ids)
    keys = {
        e.es_id: inv_svc.pair_key(rule_name, e.src_ip, e.dst_ip, e.subject_host) for e in events
    }
    pairs = await inv_svc.latest_for_pairs(
        db, list(set(keys.values())), window_days=settings.webui_inherit_window_days
    )
    analyst = await inv_svc.analyst_verdicts_for_alerts(db, ids)
    earlier = await inv_svc.earlier_true_positive_runs(db, ids)
    held: set[str] = set()
    for alert_id in ids:
        run = direct.get(alert_id)
        if run is not None and run.status == "complete":
            if run.verdict in _HELD_VERDICTS or (
                run.verdict == "false_positive" and run.id not in selected_ids
            ):
                held.add(alert_id)
        else:
            pair = pairs.get(keys[alert_id])
            if pair is not None and (pair.verdict or "") in _HELD_VERDICTS:
                held.add(alert_id)
        if alert_id in analyst or alert_id in earlier:
            held.add(alert_id)
    return held


async def plan_from(
    db: AsyncSession,
    settings: Any,
    rule_name: str,
    rows: Sequence[OpenFalsePositive],
    own: dict[str, str],
    scan: ClusterScan,
    *,
    tp_pairs: frozenset[MachinePair],
    include_tp_pairs: bool = False,
) -> AckPlan:
    """The plan of the selected ``rows`` from the grid state ``own`` and a scan.

    The cluster is each scanned alert with the key of a selected row that is
    no alert of a selected row. A verdict of its own holds an alert of the
    cluster open (:func:`_held_cluster`). An alert on the machine pair of a
    true positive of the rule stays out of the cluster unless the analyst
    asks for it (F4): the key of a row can match an alert of another host.
    """
    from soc_ai.webui.autotriage import _event_key  # noqa: PLC0415 - lazy: a heavy module

    keys = _subject_keys(rule_name, rows)
    mine = {r.alert_es_id for r in rows}
    events = [
        e
        for e in scan.events
        if e.es_id not in mine
        and _event_key(rule_name, e) in keys
        and (include_tp_pairs or machine_pair(e.src_ip, e.dst_ip, e.subject_host) not in tp_pairs)
    ]
    held = await _held_cluster(db, settings, rule_name, events, {r.id for r in rows})
    cluster = [e.es_id for e in events if e.es_id not in held]
    return AckPlan(
        own=own, cluster=list(dict.fromkeys(cluster)), held=len(held), capped=scan.capped
    )


async def plan_acknowledge(
    app_state: Any,
    rule_name: str,
    rows: Sequence[OpenFalsePositive],
    *,
    tp_pairs: frozenset[MachinePair],
    include_tp_pairs: bool = False,
) -> AckPlan | None:
    """The plan of a decision, or None when the grid did not answer.

    The grid states the alert of each row now, and the scan names the open
    alerts that inherit a verdict. A grid that does not answer gives no plan:
    the decision then writes nothing.
    """
    own = await read_grid_states(app_state, [r.alert_es_id for r in rows])
    if own is None:
        return None
    async with app_state.db_sessionmaker() as db:
        await rd_store.record_states(db, own, at=utcnow())
    scan = await _scan_cluster(app_state, rule_name, rows)
    if scan is None:
        return None
    async with app_state.db_sessionmaker() as db:
        return await plan_from(
            db,
            app_state.settings,
            rule_name,
            rows,
            own,
            scan,
            tp_pairs=tp_pairs,
            include_tp_pairs=include_tp_pairs,
        )


@dataclass(frozen=True)
class ChoicePlan:
    """The plan of one choice of the page: the groups that it selects."""

    include_weak: bool
    investigations: int
    plan: AckPlan
    include_tp_pairs: bool = False


# The plans of the page of a rule are as fresh as the grid state.
PLAN_MAX_AGE = STATE_MAX_AGE


async def plan_choices(
    app_state: Any,
    rule_name: str,
    rows: Sequence[OpenFalsePositive],
    *,
    tp_pairs: frozenset[MachinePair],
) -> list[ChoicePlan] | None:
    """The plan of each choice of the page of a rule, or None when the grid did not answer.

    The function of the decision (:func:`plan_from`) with the stored grid
    state of the rows: the page reads the state of each alert first
    (:func:`refresh_rule`). One scan of the grid serves every choice. The
    result stays in a cache for ``PLAN_MAX_AGE`` while the selection does not
    change, so the page stays fast.
    """
    signature = (
        tuple(sorted((r.id, r.group, r.alert_es_id) for r in rows)),
        tuple(sorted(tuple(sorted(pair)) for pair in tp_pairs)),
    )
    cache: dict[str, tuple[float, Any, list[ChoicePlan]]] = (
        getattr(app_state, "_rule_plan_cache", None) or {}
    )
    now = time.monotonic()
    cached = cache.get(rule_name)
    if (
        cached is not None
        and cached[1] == signature
        and now - cached[0] < PLAN_MAX_AGE.total_seconds()
    ):
        return cached[2]
    scan = await _scan_cluster(app_state, rule_name, rows)
    if scan is None:
        return None
    out: list[ChoicePlan] = []
    tp_choices = (
        (False, True) if any(on_true_positive_pair(r, tp_pairs) for r in rows) else (False,)
    )
    async with app_state.db_sessionmaker() as db:
        for include_weak in (False, True):
            for include_tp in tp_choices:
                chosen = selected(
                    rows, include_weak=include_weak, tp_pairs=tp_pairs, include_tp_pairs=include_tp
                )
                own = {r.alert_es_id: r.grid_state or rd_store.STATE_OPEN for r in chosen}
                plan = await plan_from(
                    db,
                    app_state.settings,
                    rule_name,
                    chosen,
                    own,
                    scan,
                    tp_pairs=tp_pairs,
                    include_tp_pairs=include_tp,
                )
                out.append(ChoicePlan(include_weak, len(chosen), plan, include_tp))
    if len(cache) > 256:
        cache.clear()
    cache[rule_name] = (now, signature, out)
    app_state._rule_plan_cache = cache
    return out


async def _ack_each(
    app_state: Any, alert_ids: Sequence[str], *, session_id: str, user: str
) -> dict[str, bool]:
    """Acknowledge each alert through the audited write path. True for each write that landed."""
    from soc_ai.tools.write_exec import execute_write_tool  # noqa: PLC0415 - lazy

    sem = asyncio.Semaphore(ACK_CONCURRENCY)

    async def one(alert_id: str) -> bool:
        async with sem:
            _result, error = await execute_write_tool(
                "ack_alert",
                {"alert_id": alert_id},
                auth=app_state.auth,
                settings=app_state.settings,
                audit=getattr(app_state, "audit", None),
                session_id=session_id,
                user=user,
            )
            return error is None

    results = await asyncio.gather(*(one(a) for a in alert_ids), return_exceptions=True)
    out: dict[str, bool] = {}
    for alert_id, result in zip(alert_ids, results, strict=True):
        out[alert_id] = result is True
        if isinstance(result, BaseException):
            _LOGGER.warning("rule decisions: the acknowledge of %s raised: %r", alert_id, result)
    return out


async def _next_sequences(db: AsyncSession, run_ids: Sequence[str]) -> dict[str, int]:
    """The next free event sequence of each run."""
    out: dict[str, int] = {}
    for ids in chunked(sorted(set(run_ids))):
        rows = await db.execute(
            select(InvestigationEvent.investigation_id, func.max(InvestigationEvent.sequence))
            .where(InvestigationEvent.investigation_id.in_(ids))
            .group_by(InvestigationEvent.investigation_id)
        )
        for run_id, top in rows.all():
            out[str(run_id)] = int(top or 0) + 1
    return out


def receipt(
    row: OpenFalsePositive, *, decision_id: int, by: str, at: str, already: bool
) -> dict[str, Any]:
    """The ``action_executed`` receipt that closes the Acknowledge of one investigation."""
    from soc_ai.api.webui._timeline import (  # noqa: PLC0415 - lazy: the api package imports this module
        _ACTION_TITLE,
        _action_identity,
    )

    payload: dict[str, Any] = {
        "index": row.action_index,
        "action_key": _action_identity(row.action),
        "tool_name": "ack_alert",
        "title": _ACTION_TITLE["ack_alert"],
        "success": True,
        "by": by,
        "at": at,
        "detail": RECEIPT_DETAIL,
        "rule_decision": decision_id,
        "rule_key": rule_key(row.rule_name),
    }
    if already:
        payload["note"] = "already_acknowledged"
    return payload


async def _write_receipts(
    app_state: Any,
    rows: Sequence[OpenFalsePositive],
    *,
    decision_id: int,
    by: str,
    acknowledged: set[str],
    already: set[str],
) -> int:
    """One receipt on each row whose alert the grid now holds acknowledged. The count."""
    from soc_ai.api.webui._shared import _iso_utc  # noqa: PLC0415 - lazy

    done = [r for r in rows if r.alert_es_id in acknowledged or r.alert_es_id in already]
    if not done:
        return 0
    at = _iso_utc(utcnow())
    async with app_state.db_sessionmaker() as db:
        sequences = await _next_sequences(db, [r.id for r in done])
        for row in done:
            db.add(
                InvestigationEvent(
                    investigation_id=row.id,
                    sequence=sequences.get(row.id, 1),
                    kind="action_executed",
                    payload=receipt(
                        row,
                        decision_id=decision_id,
                        by=by,
                        at=at,
                        already=row.alert_es_id in already,
                    ),
                )
            )
        await db.commit()
    return len(done)


async def _audit_result(app_state: Any, payload: dict[str, Any], by: str) -> None:
    """The record of what the background work wrote. Best effort: the writes are done."""
    try:
        audit = getattr(app_state, "audit", None)
        if audit is not None:
            await audit.log_kind(AUDIT_SESSION, "rule_decision_result", payload, user=by)
    except Exception:
        _LOGGER.warning("rule_decision_result audit write failed (continuing)", exc_info=True)


async def execute(app_state: Any, decision_id: int) -> None:
    """Carry out one decision in the background, then store and audit the result.

    The selection is read again here: the decision never takes a list from
    the client. A grid that does not answer before the first write gives the
    state ``failed`` with ``unread`` and no write and no receipt. Each write
    has its own audit records. Each investigation whose alert the grid then
    holds acknowledged gets a receipt, so no page offers its Acknowledge.
    """
    maker = app_state.db_sessionmaker
    async with maker() as db:
        row = await db.get(RuleDecision, decision_id)
        if row is None:
            return
        rule_name, by, include_weak = row.rule_name, row.decided_by, bool(row.include_weak)
        include_tp = rd_store.includes_true_positive_pairs(row)
    detail: dict[str, Any] = {rd_store.DETAIL_TP_PAIRS: True} if include_tp else {}
    state = rd_store.STATE_FAILED
    acked: set[str] = set()
    failed: set[str] = set()
    receipts = 0
    try:
        async with maker() as db:
            # The pairs are read again here, as the selection: a true positive
            # that came after the press still keeps its machines out.
            tp_pairs = await true_positive_pairs(db, rule_name)
            rows = selected(
                await open_false_positives(
                    db, threshold=_threshold(app_state), rule_names=[rule_name]
                ),
                include_weak=include_weak,
                tp_pairs=tp_pairs,
                include_tp_pairs=include_tp,
            )
        detail["selected"] = len(rows)
        plan = (
            await plan_acknowledge(
                app_state, rule_name, rows, tp_pairs=tp_pairs, include_tp_pairs=include_tp
            )
            if rows
            else AckPlan({}, [], 0)
        )
        if plan is None:
            detail["unread"] = True
        else:
            results = await _ack_each(
                app_state, plan.writes, session_id=f"rule-decision:{decision_id}", user=by
            )
            acked = {a for a, ok in results.items() if ok}
            failed = {a for a, ok in results.items() if not ok}
            already = {a for a, s in plan.own.items() if s == rd_store.STATE_ACKNOWLEDGED}
            if acked:
                async with maker() as db:
                    await rd_store.record_states(
                        db, dict.fromkeys(acked, rd_store.STATE_ACKNOWLEDGED), at=utcnow()
                    )
            receipts = await _write_receipts(
                app_state, rows, decision_id=decision_id, by=by, acknowledged=acked, already=already
            )
            detail.update(
                held=plan.held,
                cluster=len(plan.cluster),
                already=len(already),
                capped=plan.capped,
            )
            state = rd_store.STATE_FAILED if failed and not acked else rd_store.STATE_DONE
    except Exception as exc:
        _LOGGER.warning("rule decisions: decision %s failed", decision_id, exc_info=True)
        detail["error"] = type(exc).__name__
    try:
        async with maker() as db:
            await rd_store.finish(
                db,
                decision_id,
                state=state,
                alerts=len(acked),
                failed=len(failed),
                investigations=receipts,
                detail=detail,
                at=utcnow(),
            )
    except Exception:
        # The writes and their audit records stand. The record keeps the
        # state "acknowledging", and the hold on a new decision of the rule
        # ends after RUNNING_HOLD of the route.
        _LOGGER.warning("rule decisions: the result of decision %s is not stored", decision_id)
    await _audit_result(
        app_state,
        {
            "decision_id": decision_id,
            "rule_name": rule_name,
            "state": state,
            "alerts": len(acked),
            "failed": len(failed),
            "investigations": receipts,
            **detail,
        },
        by,
    )
    invalidate(app_state)


# ── The standing decision (RS5) ────────────────────────────────────────────

# The actor of an end that no person made.
SYSTEM_ACTOR = "soc-ai"


async def settle_decisions(app_state: Any) -> list[RuleDecision]:
    """End each standing decision whose term is over or whose rule got a true positive.

    Each end gets the audit record ``rule_decision_ended``, best effort: the
    end is already stored.
    """
    async with app_state.db_sessionmaker() as db:
        ended = await rd_store.settle(db, now=utcnow())
        records = [
            {
                "decision_id": int(row.id),
                "rule_name": row.rule_name,
                "cause": row.end_cause,
                "ended_at": row.ended_at.isoformat() if row.ended_at else None,
            }
            for row in ended
        ]
    audit = getattr(app_state, "audit", None)
    for record in records:
        try:
            if audit is not None:
                await audit.log_kind(
                    AUDIT_SESSION, "rule_decision_ended", record, user=SYSTEM_ACTOR
                )
        except Exception:
            _LOGGER.warning("rule_decision_ended audit write failed (continuing)", exc_info=True)
    if ended:
        invalidate(app_state)
    return ended


async def standing_for_rules(maker: Any, rule_names: Iterable[str]) -> dict[str, int] | None:
    """The id of the standing decision in force for each rule that has one.

    None when the store did not answer. The caller then holds every write
    that a standing decision would allow.
    """
    wanted = sorted({r for r in rule_names if r})
    if maker is None or not wanted:
        return {}
    out: dict[str, int] = {}
    try:
        async with maker() as db:
            now = utcnow()
            for rule_name in wanted:
                row = await rd_store.in_force(db, rule_name, now=now)
                if row is not None:
                    out[rule_name] = int(row.id)
    except Exception:
        _LOGGER.warning("rule decisions: the standing decisions are unreadable", exc_info=True)
        return None
    return out


async def count_under(maker: Any, counts: dict[int, int]) -> None:
    """Add the acknowledges under each standing decision. Best effort."""
    if maker is None:
        return
    try:
        async with maker() as db:
            for decision_id, count in counts.items():
                await rd_store.count_acknowledged(db, decision_id, count)
    except Exception:
        _LOGGER.warning("rule decisions: the count under a decision failed", exc_info=True)


# ── The cache of the summary ───────────────────────────────────────────────


def invalidate(app_state: Any) -> None:
    """Drop the cached summary of the open false positives: the next read is fresh."""
    if app_state is not None and hasattr(app_state, "_rule_summary_cache"):
        app_state._rule_summary_cache = None


__all__ = [
    "ACK_CONCURRENCY",
    "AUDIT_SESSION",
    "CLUSTER_DAYS",
    "CLUSTER_RANGE",
    "CLUSTER_SCAN_MAX",
    "CONFIDENT",
    "CONFIDENT_REASONS",
    "GRID_BATCH",
    "GROUPS",
    "HOLD_LABELS",
    "HOLD_LABELS_PAST",
    "PLAN_MAX_AGE",
    "REASON_AUTO_ACK_FAILED",
    "REASON_AUTO_ACK_OFF",
    "RECEIPT_DETAIL",
    "SCAN_MAX",
    "STATE_MAX_AGE",
    "STEP_MAX",
    "SYSTEM_ACTOR",
    "WEAK",
    "AckPlan",
    "AcknowledgesAlone",
    "ChoicePlan",
    "ClusterScan",
    "MachinePair",
    "OpenFalsePositive",
    "acknowledges_alone",
    "background_step",
    "by_rule",
    "count_under",
    "execute",
    "group_of",
    "hold_label",
    "in_group",
    "invalidate",
    "machine_pair",
    "median_confidence",
    "on_true_positive_pair",
    "open_false_positives",
    "plan_acknowledge",
    "plan_choices",
    "plan_from",
    "read_at",
    "read_grid_states",
    "reason_rank",
    "receipt",
    "refresh_rule",
    "refresh_states",
    "rule_from_key",
    "rule_href",
    "rule_key",
    "selected",
    "selection_conds",
    "settle_decisions",
    "stale_alerts",
    "standing_for_rules",
    "true_positive_pairs",
]
