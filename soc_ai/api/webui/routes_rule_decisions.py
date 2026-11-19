"""Rule decisions: the analyst decides once on the open false positives of a rule.

soc-ai gives a false positive verdict, and a guard of the automatic
acknowledge holds the write. The alert stays open on the grid, and the
analyst had to open each investigation and press once. soc-ai now prepares
the facts of the rule, and the analyst decides once
(:mod:`soc_ai.webui.rule_decisions`).

* ``GET /rule-decisions/{ruleKey}`` states the facts of one rule. The page
  asks the grid for the alerts of the rule when their state is older than
  5 minutes. When the grid does not answer, ``gridAnswered`` is false and
  ``readAt`` states the last read.
* ``POST /rule-decisions/{ruleKey}`` records a decision and acknowledges in
  the background. The server computes the selection again: it never takes a
  list from the client. The answer is 202 with the record.
* ``POST /rule-decisions/{ruleKey}/end`` ends the standing decision of the
  rule.
* ``GET /rule-decisions`` lists the standing decisions in force and the
  newest 20 that ended.

``ruleKey`` is the rule name in base64url with no padding. A signed-in
analyst may decide, as on a campaign. The audit record comes first, and a
failed record changes nothing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal
from urllib.parse import quote

from fastapi import BackgroundTasks, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui import needs_you_facts as ny_facts
from soc_ai.api.webui._decision_commit import commit_after_record
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import _iso_utc, router
from soc_ai.config import Settings
from soc_ai.secret_scrub import scrub_secrets
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import first_line as first_line_svc
from soc_ai.store import rule_decisions as rd_store
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Investigation, RuleDecision
from soc_ai.webui import rule_decisions as rd

_LOGGER = logging.getLogger(__name__)

# The most machines and samples that the page of a rule names.
MACHINES_MAX = 10
SAMPLES_MAX = 8
# A decision in the state "acknowledging" blocks a new decision of its rule
# for this long. An older one lost its work to a restart.
RUNNING_HOLD = timedelta(minutes=15)

_LOCKS: dict[str, asyncio.Lock] = {}


def _lock(rule_name: str) -> asyncio.Lock:
    """One lock for each rule in this process: two presses never decide twice."""
    lock = _LOCKS.get(rule_name)
    if lock is None:
        if len(_LOCKS) > 4096:
            _LOCKS.clear()
        lock = _LOCKS[rule_name] = asyncio.Lock()
    return lock


def _iso(value: datetime | None) -> str | None:
    return _iso_utc(value) or None if value is not None else None


def _rule_or_404(key: str) -> str:
    rule_name = rd.rule_from_key(key)
    if rule_name is None:
        raise api_error(404, "rule_not_found", "soc-ai knows no rule with this key.")
    return rule_name


# ── The shapes ─────────────────────────────────────────────────────────────


class ReasonOut(BaseModel):
    """One hold reason of a group, with its label and its count."""

    code: str
    label: str
    count: int


class GroupOut(BaseModel):
    """One group of the open false positives of a rule.

    ``sources`` and ``destinations`` count the distinct machines at each end.
    """

    count: int = 0
    reasons: list[ReasonOut] = Field(default_factory=list)
    sources: int = 0
    destinations: int = 0
    firstEvent: str | None = None
    lastEvent: str | None = None


class RuleMachineOut(BaseModel):
    """A machine of the rule: ``role`` is ``source`` or ``destination``.

    ``truePositive`` is true when the machine is an end of a true positive of
    the rule that stands (F4).
    """

    key: str
    name: str | None = None
    address: str | None = None
    role: Literal["source", "destination"]
    count: int
    truePositive: bool = False


class DayOut(BaseModel):
    """The open false positives of one UTC day, by group."""

    day: str
    confident: int = 0
    weak: int = 0


class SampleOut(BaseModel):
    """One sample investigation of a group."""

    id: str
    eventAt: str | None = None
    src: str | None = None
    dst: str | None = None
    confidence: float | None = None
    summary: str = ""
    group: str
    reason: str


class TruePositiveOut(BaseModel):
    """A true positive of the rule that stands."""

    id: str
    eventAt: str | None = None
    title: str


class PlanOut(BaseModel):
    """What the press of one choice writes, from the plan of the decision (F3).

    ``investigations`` counts the selected investigations. ``alerts`` counts
    their alerts that the grid holds open, ``inherit`` the open alerts that
    inherit their verdict, and ``held`` the alerts of the rule that a verdict
    of their own keeps open. ``capped`` is true when the scan of the grid
    stopped at its limit: more alerts can inherit the verdict.
    """

    includeWeak: bool
    investigations: int
    alerts: int
    inherit: int
    held: int
    capped: bool = False
    includeTruePositivePairs: bool = False


class PairCountOut(BaseModel):
    """The open false positives on the machine pair of a true positive, by group (F4)."""

    confident: int = 0
    weak: int = 0


class AcknowledgesAloneOut(BaseModel):
    """soc-ai acknowledges the false positives of the rule by itself (F1).

    ``since`` is the first such acknowledge after the newest hold
    ``high_stakes`` of the rule, ``acknowledged`` counts them, and ``before``
    counts the open false positives that this hold keeps from before that
    date. ``sentence`` states the fact for the analyst.
    """

    since: str | None = None
    acknowledged: int = 0
    before: int = 0
    sentence: str


class RuleDecisionOut(BaseModel):
    """One decision on a rule.

    ``state`` is ``acknowledging``, ``done`` or ``failed``. ``alerts`` counts
    the alerts that the decision acknowledged, ``failed`` the writes that
    failed, and ``investigations`` the receipts. ``endsAt``, ``endedAt`` and
    ``endCause`` hold the term and the end of a standing decision.
    ``acknowledged`` counts the acknowledges under a standing decision.
    ``unread`` is true when the grid did not answer before the first write.
    """

    id: int
    ruleKey: str
    ruleName: str
    decision: str
    includeWeak: bool = False
    by: str
    at: str | None = None
    note: str = ""
    state: str
    alerts: int = 0
    failed: int = 0
    investigations: int = 0
    unread: bool = False
    endsAt: str | None = None
    endedAt: str | None = None
    endCause: str | None = None
    acknowledged: int = 0
    href: str
    includeTruePositivePairs: bool = False


class RulePageOut(BaseModel):
    """The facts of one rule, prepared for one decision (``GET /rule-decisions/{ruleKey}``)."""

    ruleKey: str
    ruleName: str
    severity: str | None = None
    readAt: str | None = None
    gridAnswered: bool = True
    confident: GroupOut = Field(default_factory=GroupOut)
    weak: GroupOut = Field(default_factory=GroupOut)
    machines: list[RuleMachineOut] = Field(default_factory=list)
    histogram: list[DayOut] = Field(default_factory=list)
    samples: list[SampleOut] = Field(default_factory=list)
    truePositives: list[TruePositiveOut] = Field(default_factory=list)
    openAlerts: int | None = None
    standing: RuleDecisionOut | None = None
    history: list[RuleDecisionOut] = Field(default_factory=list)
    canStanding: bool = True
    canStandingWhy: str | None = None
    investigationsHref: str
    # The term of a standing decision in days: the setting rule_decision_days.
    standingDays: int = 30
    # soc-ai acknowledges the false positives of the rule by itself (F1).
    selfAcknowledging: AcknowledgesAloneOut | None = None
    # The window of ``openAlerts`` and of the scan of a decision, in days (F3).
    openAlertsDays: int = rd.CLUSTER_DAYS
    # What each choice writes (F3). ``planKnown`` is false when the grid did
    # not answer: the count of the alerts is then unknown.
    plans: list[PlanOut] = Field(default_factory=list)
    planKnown: bool = False
    # The most events that the scan of the grid reads.
    scanMax: int = rd.CLUSTER_SCAN_MAX
    # The open false positives on the machine pair of a true positive of the
    # rule (F4). The main choice leaves them out.
    truePositivePairs: PairCountOut = Field(default_factory=PairCountOut)


class RuleDecisionIn(BaseModel):
    """A decision on a rule. ``includeWeak`` adds the group with weak evidence.

    ``includeTruePositivePairs`` adds the open false positives on the machine
    pair of a true positive of the rule. The default leaves them open (F4).
    """

    decision: Literal["acknowledge", "standing"]
    includeWeak: bool = False
    includeTruePositivePairs: bool = False
    note: str = Field(default="", max_length=2000)


class RuleDecisionsOut(BaseModel):
    """The standing decisions in force, and the newest 20 that ended."""

    standing: list[RuleDecisionOut] = Field(default_factory=list)
    ended: list[RuleDecisionOut] = Field(default_factory=list)


def record_out(row: RuleDecision) -> RuleDecisionOut:
    detail = row.detail if isinstance(row.detail, dict) else {}
    return RuleDecisionOut(
        id=int(row.id),
        ruleKey=rd.rule_key(row.rule_name),
        ruleName=row.rule_name,
        decision=row.decision,
        includeWeak=bool(row.include_weak),
        by=row.decided_by,
        at=_iso(row.decided_at),
        note=row.note or "",
        state=row.state,
        alerts=int(row.alerts or 0),
        failed=int(row.failed or 0),
        investigations=int(row.investigations or 0),
        unread=bool(detail.get("unread")),
        endsAt=_iso(row.ends_at),
        endedAt=_iso(row.ended_at),
        endCause=row.end_cause,
        acknowledged=int(row.acknowledged or 0),
        href=rd.rule_href(row.rule_name),
        includeTruePositivePairs=rd_store.includes_true_positive_pairs(row),
    )


# ── The facts of a rule ────────────────────────────────────────────────────


def _ends(row: rd.OpenFalsePositive) -> tuple[str | None, str | None]:
    return first_line_svc.alert_ends(row.src_ip, row.dest_ip, row.host_name)


def group_out(rows: Sequence[rd.OpenFalsePositive], *, past: bool = False) -> GroupOut:
    """The facts of one group: its count, its reasons, its machines and its span.

    ``past`` labels a hold that no longer applies to the rule in the past
    tense (F1).
    """
    reasons = Counter(row.reason for row in rows)
    times = [row.event_at for row in rows if row.event_at is not None]
    sources = {s for s, _t in map(_ends, rows) if s}
    targets = {t for _s, t in map(_ends, rows) if t}
    return GroupOut(
        count=len(rows),
        reasons=[
            ReasonOut(code=code, label=rd.hold_label(code, past=past), count=n)
            for code, n in sorted(reasons.items(), key=lambda kv: (rd.reason_rank(kv[0]), kv[0]))
        ],
        sources=len(sources),
        destinations=len(targets),
        firstEvent=_iso(min(times)) if times else None,
        lastEvent=_iso(max(times)) if times else None,
    )


def machine_counts(rows: Sequence[rd.OpenFalsePositive]) -> list[tuple[str, str, int]]:
    """``(role, value, count)`` of each machine, the most events first."""
    counts: Counter[tuple[str, str]] = Counter()
    for row in rows:
        source, target = _ends(row)
        if source:
            counts[("source", source)] += 1
        if target:
            counts[("destination", target)] += 1
    return [
        (role, value, n)
        for (role, value), n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0][1], kv[0][0]))
    ]


def histogram(rows: Sequence[rd.OpenFalsePositive]) -> list[DayOut]:
    """The open false positives of each UTC day, by group, the oldest day first."""
    days: dict[str, DayOut] = {}
    for row in rows:
        at = row.event_at or row.created_at
        if at is None:
            continue
        day = days.setdefault(at.strftime("%Y-%m-%d"), DayOut(day=at.strftime("%Y-%m-%d")))
        if row.group == rd.CONFIDENT:
            day.confident += 1
        else:
            day.weak += 1
    return [days[d] for d in sorted(days)]


def sample_rows(rows: Sequence[rd.OpenFalsePositive]) -> list[rd.OpenFalsePositive]:
    """At most 8 samples: the newest of each reason first, then the newest rows."""
    picked: list[rd.OpenFalsePositive] = []
    seen: set[str] = set()
    order = sorted(
        {r.reason for r in rows}, key=lambda c: (rd.group_of(c) != rd.CONFIDENT, rd.reason_rank(c))
    )
    for reason in order:
        first = next(r for r in rows if r.reason == reason)
        picked.append(first)
        seen.add(first.id)
    for row in rows:
        if len(picked) >= SAMPLES_MAX:
            break
        if row.id not in seen:
            picked.append(row)
            seen.add(row.id)
    return picked[:SAMPLES_MAX]


async def _summaries(db: Any, run_ids: Sequence[str]) -> dict[str, str]:
    """The headline of each run, with no credential."""
    if not run_ids:
        return {}
    rows = await db.execute(
        select(Investigation.id, Investigation.rationale, Investigation.summary).where(
            Investigation.id.in_(list(run_ids))
        )
    )
    return {str(i): scrub_secrets(str(r or s or "")) for i, r, s in rows.all()}


async def _open_alerts(
    elastic: ElasticClient, settings: Settings, rule_name: str, rows: Sequence[rd.OpenFalsePositive]
) -> int | None:
    """The open alerts of the rule on the grid in the scan range, or None when the grid failed."""
    from soc_ai.webui import alerts_query as aq  # noqa: PLC0415 - lazy

    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            return await aq.count_group_events(
                elastic,
                settings,
                rule_name=rule_name,
                kind="notice" if rows and all(r.kind == "notice" for r in rows) else "suricata",
                time_range=rd.CLUSTER_RANGE,
                time_zone=settings.so_timezone,
                hide_acked=True,
            )
    except Exception:
        _LOGGER.warning("rule decisions: the grid did not count the alerts of rule %r", rule_name)
        return None


AUTO_ACK_OFF_WHY = (
    "Automatic acknowledge is off. A standing decision acknowledges nothing while it is off."
)


def alone_since_words(alone: rd.AcknowledgesAlone) -> str:
    """The first sentence of a rule that soc-ai acknowledges by itself."""
    return (
        "soc-ai acknowledges the false positives of this rule by itself since "
        f"{alone.since:%Y-%m-%d} UTC."
    )


def alone_out(alone: rd.AcknowledgesAlone, before: int) -> AcknowledgesAloneOut:
    """The fact of F1 for the page. ``before`` counts the open holds from before the date."""
    sentence = alone_since_words(alone)
    if before > 0:
        sentence += f" The {before:,} here {'is' if before == 1 else 'are'} from before that date."
    return AcknowledgesAloneOut(
        since=_iso(alone.since),
        acknowledged=alone.acknowledged,
        before=before,
        sentence=sentence,
    )


def standing_refusal(
    true_positives: Sequence[Any],
    standing: RuleDecision | None,
    *,
    auto_ack: bool = True,
    alone: rd.AcknowledgesAlone | None = None,
) -> str | None:
    """Why the rule takes no standing decision now, or None.

    With ``auto_ack_fp_enabled`` off a standing decision writes nothing by
    itself, so the console does not offer a choice that does nothing. A rule
    that soc-ai acknowledges by itself gains nothing from a standing decision
    either (F1): the decision lifts the hold ``high_stakes`` only.
    """
    if not auto_ack:
        return AUTO_ACK_OFF_WHY
    if true_positives:
        # The console states the refusal before the cause. The cause names no
        # refusal again: the line read "no standing decision" twice (D17).
        return "This rule holds a true positive verdict that stands."
    if standing is not None:
        return "A standing decision is in force for this rule. End it first."
    if alone is not None:
        return f"{alone_since_words(alone)} A standing decision adds nothing."
    return None


@router.get("/rule-decisions/{rule_key}", response_model=RulePageOut)
async def get_rule_decision(
    request: Request,
    rule_key: str,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> RulePageOut:
    """The facts of one rule for the decision. An unknown key gives 404 ``rule_not_found``."""
    rule_name = _rule_or_404(rule_key)
    state = request.app.state
    await rd.settle_decisions(state)
    answered = await rd.refresh_rule(state, rule_name)
    now = utcnow()
    async with state.db_sessionmaker() as db:
        rows = await rd.open_false_positives(
            db, threshold=settings.auto_ack_fp_threshold, rule_names=[rule_name]
        )
        true_positives = await rd_store.standing_true_positives(db, rule_name)
        standing = await rd_store.in_force(db, rule_name, now=now)
        history = await rd_store.history(db, rule_name)
        severities = await ny_facts.run_severities(db, [r.id for r in rows])
        samples = sample_rows(rows)
        summaries = await _summaries(db, [r.id for r in samples])
        machines = machine_counts(rows)[:MACHINES_MAX]
        labels = await ny_facts.labels_for(db, settings, [value for _r, value, _n in machines])
        tp_pairs = await rd.true_positive_pairs(db, rule_name)
        # With automatic acknowledge off, soc-ai acknowledges nothing by itself.
        alone = await rd.acknowledges_alone(db, rule_name) if settings.auto_ack_fp_enabled else None
    open_alerts = await _open_alerts(elastic, settings, rule_name, rows)
    # What each choice writes, from the function of the decision. A grid that
    # did not answer the read of this page gives no plan.
    plans = (
        await rd.plan_choices(state, rule_name, rows, tp_pairs=tp_pairs)
        if answered is not False and rows
        else None
    )
    on_pairs = [r for r in rows if rd.on_true_positive_pair(r, tp_pairs)]
    tp_machines = {end for pair in tp_pairs for end in pair}
    why = standing_refusal(
        true_positives, standing, auto_ack=settings.auto_ack_fp_enabled, alone=alone
    )
    past = alone is not None
    return RulePageOut(
        ruleKey=rd.rule_key(rule_name),
        ruleName=rule_name,
        severity=ny_facts.worst_severity(severities.values()),
        readAt=_iso(rd.read_at(rows)),
        gridAnswered=answered is not False,
        confident=group_out(rd.in_group(rows, rd.CONFIDENT), past=past),
        weak=group_out(rd.in_group(rows, rd.WEAK), past=past),
        machines=[
            RuleMachineOut(
                key=value,
                name=machine.name if machine else None,
                address=machine.address if machine else None,
                role="source" if role == "source" else "destination",
                count=n,
                truePositive=value in tp_machines,
            )
            for role, value, n in machines
            for machine in [ny_facts.machine_of(value, labels)]
        ],
        histogram=histogram(rows),
        samples=[
            SampleOut(
                id=r.id,
                eventAt=_iso(r.event_at),
                src=_ends(r)[0],
                dst=_ends(r)[1],
                confidence=r.confidence,
                summary=summaries.get(r.id, ""),
                group=r.group,
                reason=r.reason,
            )
            for r in samples
        ],
        truePositives=[
            TruePositiveOut(
                id=inv.id,
                eventAt=_iso(inv.event_at),
                title=scrub_secrets(inv.rationale or inv.summary or f"Investigation {inv.id}"),
            )
            for inv in true_positives
        ],
        openAlerts=open_alerts,
        standing=record_out(standing) if standing is not None else None,
        history=[record_out(row) for row in history],
        canStanding=why is None,
        canStandingWhy=why,
        investigationsHref=(
            f"/investigations?verdict=false_positive&range=all&q={quote(rule_name, safe='')}"
        ),
        standingDays=settings.rule_decision_days,
        selfAcknowledging=(
            alone_out(alone, sum(1 for r in rows if r.reason == "high_stakes"))
            if alone is not None
            else None
        ),
        plans=[
            PlanOut(
                includeWeak=choice.include_weak,
                investigations=choice.investigations,
                alerts=choice.plan.own_open,
                inherit=len(choice.plan.cluster),
                held=choice.plan.held,
                capped=choice.plan.capped,
                includeTruePositivePairs=choice.include_tp_pairs,
            )
            for choice in plans or []
        ],
        planKnown=plans is not None,
        truePositivePairs=PairCountOut(
            confident=len(rd.in_group(on_pairs, rd.CONFIDENT)),
            weak=len(rd.in_group(on_pairs, rd.WEAK)),
        ),
    )


# ── The rules of Needs you (RS3) ───────────────────────────────────────────

# How long one read of the summary serves. Each open tab polls the count of
# Needs you every 15 seconds. A decision and a grid step drop the cache.
SUMMARY_TTL_S = 30.0

RULE_ACTION = ny_facts.NeedsYouActionOut(
    label="Decide on the rule",
    writes=(
        "Acknowledge writes to Security Onion. A standing decision also lets soc-ai "
        "acknowledge later false positives of the rule."
    ),
)

_END_WORDS = {
    rd_store.CAUSE_EXPIRED: "The standing decision of this rule ended at the end of its term.",
    rd_store.CAUSE_ANALYST: "An analyst ended the standing decision of this rule.",
    rd_store.CAUSE_TRUE_POSITIVE: (
        "The standing decision of this rule ended, because an investigation of the rule "
        "gave a true positive verdict."
    ),
}


@dataclass(frozen=True)
class RuleSummary:
    """One rule with open false positives, as the row of Needs you states it."""

    rule_name: str
    count: int
    confident: int
    weak: int
    confidence: float | None
    severity: str | None
    machines: list[ny_facts.NeedsYouMachineOut]
    machines_more: int
    event_at: datetime | None
    since: datetime | None
    end_cause: str | None

    @property
    def key(self) -> str:
        return rd.rule_key(self.rule_name)

    @property
    def why(self) -> str:
        return rule_why(self.count, self.confident, self.weak, self.end_cause)


def _plural(n: int, one: str, many: str) -> str:
    return f"{n:,} {one if n == 1 else many}"


def rule_why(count: int, confident: int, weak: int, end_cause: str | None = None) -> str:
    """Why a rule waits: the hold, the two groups, and the end of a standing decision."""
    head = (
        f"soc-ai holds the acknowledge of "
        f"{_plural(count, 'false positive', 'false positives')} of this rule."
    )
    if weak == 0:
        groups = "It has checked evidence." if count == 1 else "Each one has checked evidence."
    elif confident == 0:
        groups = "It has weak evidence." if count == 1 else "Each one has weak evidence."
    else:
        groups = (
            f"{confident:,} {'has' if confident == 1 else 'have'} checked evidence, and "
            f"{weak:,} {'has' if weak == 1 else 'have'} weak evidence."
        )
    parts = [head, groups]
    if end_cause in _END_WORDS:
        parts.append(_END_WORDS[end_cause])
    return " ".join(parts)


async def _build_summaries(state: Any) -> list[RuleSummary]:
    settings = state.settings
    async with state.db_sessionmaker() as db:
        rows = await rd.open_false_positives(db, threshold=settings.auto_ack_fp_threshold)
        grouped = rd.by_rule(rows)
        if not grouped:
            return []
        severities = await ny_facts.run_severities(db, [r.id for r in rows])
        tops = {name: machine_counts(group) for name, group in grouped.items()}
        labels = await ny_facts.labels_for(
            db,
            settings,
            [
                value
                for counts in tops.values()
                for _r, value, _n in counts[: ny_facts.MAX_MACHINES]
            ],
        )
        now = utcnow()
        in_force = {row.rule_name for row in await rd_store.standing_rows(db, now=now)}
        ended = await rd_store.last_ended(db, [n for n in grouped if n not in in_force])
    out: list[RuleSummary] = []
    for name, group in grouped.items():
        times = [r.event_at for r in group if r.event_at is not None]
        values = list(dict.fromkeys(value for _r, value, _n in tops[name]))
        machines = [
            machine
            for value in values[: ny_facts.MAX_MACHINES]
            if (machine := ny_facts.machine_of(value, labels)) is not None
        ]
        last = ended.get(name)
        out.append(
            RuleSummary(
                rule_name=name,
                count=len(group),
                confident=len(rd.in_group(group, rd.CONFIDENT)),
                weak=len(rd.in_group(group, rd.WEAK)),
                confidence=rd.median_confidence(group),
                severity=ny_facts.worst_severity(severities.get(r.id) for r in group),
                machines=machines,
                machines_more=max(0, len(values) - ny_facts.MAX_MACHINES),
                event_at=max(times) if times else None,
                since=min(times) if times else None,
                end_cause=last.end_cause if last is not None else None,
            )
        )
    return out


async def rule_summaries(state: Any) -> list[RuleSummary]:
    """The rules with one or more open false positives, read at most once per TTL.

    ``GET /needs-you`` counts them in ``rules_waiting`` and
    ``GET /needs-you/items`` lists them, from the same read, so the count and
    the list agree.
    """
    cached = getattr(state, "_rule_summary_cache", None)
    now = time.monotonic()
    if cached is not None and now - cached[0] < SUMMARY_TTL_S:
        held: list[RuleSummary] = cached[1]
        return held
    found = await _build_summaries(state)
    state._rule_summary_cache = (now, found)
    return found


# ── The decision ───────────────────────────────────────────────────────────


@router.post("/rule-decisions/{rule_key}", response_model=RuleDecisionOut, status_code=202)
async def decide_rule(
    request: Request,
    rule_key: str,
    body: RuleDecisionIn,
    background: BackgroundTasks,
    settings: Settings = Depends(get_settings_dep),
) -> RuleDecisionOut:
    """Record a decision on the open false positives of a rule, then acknowledge in the background.

    The order: the audit record ``rule_decision_made``, then the record of the
    decision, then the commit. When the audit write fails, nothing changes and
    the route answers 503. The background work reads the selection again and
    acknowledges the alert of each selected investigation and of its
    inherited cluster. It never acknowledges an alert with a true positive, a
    needs more info or an analyst verdict. The record then states ``alerts``
    and ``failed``, and the audit record ``rule_decision_result`` follows.

    Refusals: 404 ``rule_not_found``; 409 ``rule_decision_running``,
    ``rule_nothing_open``, ``rule_has_true_positive``, ``rule_auto_ack_off``,
    ``rule_decision_standing`` and ``rule_acknowledges_alone``; 503
    ``audit_unavailable`` and ``store_unavailable``.
    """
    rule_name = _rule_or_404(rule_key)
    by = await identify_caller(request)
    note = scrub_secrets(body.note.strip())
    state = request.app.state
    audit = getattr(state, "audit", None)
    await rd.settle_decisions(state)
    async with _lock(rule_name), state.db_sessionmaker() as db:
        now = utcnow()
        if await rd_store.running(db, rule_name, since=now - RUNNING_HOLD) is not None:
            raise api_error(
                409,
                "rule_decision_running",
                "soc-ai acknowledges the alerts of an earlier decision on this rule. Wait.",
            )
        rows = await rd.open_false_positives(
            db, threshold=settings.auto_ack_fp_threshold, rule_names=[rule_name]
        )
        tp_pairs = await rd.true_positive_pairs(db, rule_name)
        chosen = rd.selected(
            rows,
            include_weak=body.includeWeak,
            tp_pairs=tp_pairs,
            include_tp_pairs=body.includeTruePositivePairs,
        )
        if body.decision == rd_store.DECISION_STANDING:
            if not settings.auto_ack_fp_enabled:
                raise api_error(409, "rule_auto_ack_off", AUTO_ACK_OFF_WHY)
            true_positives = await rd_store.standing_true_positives(db, rule_name, limit=1)
            standing = await rd_store.in_force(db, rule_name, now=now)
            if true_positives:
                raise api_error(
                    409, "rule_has_true_positive", standing_refusal(true_positives, None) or ""
                )
            if standing is not None:
                raise api_error(409, "rule_decision_standing", standing_refusal([], standing) or "")
            alone = await rd.acknowledges_alone(db, rule_name)
            if alone is not None:
                raise api_error(
                    409, "rule_acknowledges_alone", standing_refusal([], None, alone=alone) or ""
                )
        elif not chosen:
            raise api_error(
                409,
                "rule_nothing_open",
                "This rule has no open false positive to acknowledge. Reload the page.",
            )
        # End the read snapshot: the write below starts its own.
        await db.rollback()
        ends_at = (
            now + timedelta(days=settings.rule_decision_days)
            if body.decision == rd_store.DECISION_STANDING
            else None
        )
        made = {
            "rule_name": rule_name,
            "decision": body.decision,
            "include_weak": body.includeWeak,
            "note": note,
            "confident": len(rd.in_group(rows, rd.CONFIDENT)),
            "weak": len(rd.in_group(rows, rd.WEAK)),
            "selected": len(chosen),
            "ends_at": _iso(ends_at),
            "include_true_positive_pairs": body.includeTruePositivePairs,
            "on_true_positive_pairs": sum(1 for r in rows if rd.on_true_positive_pair(r, tp_pairs)),
        }
        try:
            if audit is not None:
                await audit.log_kind(
                    rd.AUDIT_SESSION, "rule_decision_made", made, user=by, mutating=True
                )
        except Exception as exc:
            _LOGGER.warning("rule decisions: the decision record failed, nothing saved: %s", exc)
            raise api_error(
                503,
                "audit_unavailable",
                "soc-ai could not write the audit record, so it did not record the decision. "
                "Try again.",
            ) from exc
        row = rd_store.new_decision(
            rule_name=rule_name,
            decision=body.decision,
            include_weak=body.includeWeak,
            note=note,
            by=by,
            at=now,
            ends_at=ends_at,
            include_true_positive_pairs=body.includeTruePositivePairs,
        )
        db.add(row)
        await commit_after_record(
            request, db, rd.AUDIT_SESSION, "rule_decision_made", made, by=by, action="decision"
        )
        await db.refresh(row)
        out = record_out(row)
    background.add_task(rd.execute, state, out.id)
    rd.invalidate(state)
    return out


@router.post("/rule-decisions/{rule_key}/end", response_model=RuleDecisionOut)
async def end_rule_decision(request: Request, rule_key: str) -> RuleDecisionOut:
    """End the standing decision in force for the rule. A signed-in analyst may end it.

    The audit record ``rule_decision_ended`` comes first and fails closed.
    From then on the hold ``high_stakes`` applies to the rule again.

    Refusals: 404 ``rule_not_found``; 409 ``rule_no_standing``; 503
    ``audit_unavailable`` and ``store_unavailable``.
    """
    rule_name = _rule_or_404(rule_key)
    by = await identify_caller(request)
    state = request.app.state
    audit = getattr(state, "audit", None)
    await rd.settle_decisions(state)
    async with _lock(rule_name), state.db_sessionmaker() as db:
        now = utcnow()
        row = await rd_store.in_force(db, rule_name, now=now)
        if row is None:
            raise api_error(
                409, "rule_no_standing", "No standing decision is in force for this rule."
            )
        ended = {"decision_id": int(row.id), "rule_name": rule_name, "cause": "analyst"}
        try:
            if audit is not None:
                await audit.log_kind(
                    rd.AUDIT_SESSION, "rule_decision_ended", ended, user=by, mutating=True
                )
        except Exception as exc:
            _LOGGER.warning("rule decisions: the end record failed, nothing saved: %s", exc)
            raise api_error(
                503,
                "audit_unavailable",
                "soc-ai could not write the audit record, so the decision stays in force. "
                "Try again.",
            ) from exc
        rd_store.end_decision(row, cause=rd_store.CAUSE_ANALYST, at=now, by=by)
        await commit_after_record(
            request, db, rd.AUDIT_SESSION, "rule_decision_ended", ended, by=by, action="end"
        )
        await db.refresh(row)
        out = record_out(row)
    rd.invalidate(state)
    return out


@router.get("/rule-decisions", response_model=RuleDecisionsOut)
async def list_rule_decisions(request: Request) -> RuleDecisionsOut:
    """The standing decisions in force, the newest first, and the newest 20 that ended."""
    await rd.settle_decisions(request.app.state)
    async with request.app.state.db_sessionmaker() as db:
        now = utcnow()
        standing = await rd_store.standing_rows(db, now=now)
        ended = await rd_store.ended_rows(db)
    return RuleDecisionsOut(
        standing=[record_out(row) for row in standing],
        ended=[record_out(row) for row in ended],
    )


# ── The investigation page (RS6) ───────────────────────────────────────────


async def rule_decision_ref(db: Any, inv: Any, *, alert_acked: bool, threshold: float) -> Any:
    """The rule decision that waits for an investigation, or None.

    Not None when the investigation is an open false positive of its rule:
    the page of the rule, the count of its open false positives, and the
    group of this one. An alert that the grid states as acknowledged on this
    read waits for nothing.
    """
    from soc_ai.api.webui._timeline import RuleDecisionRefOut  # noqa: PLC0415 - cycle

    if alert_acked or inv.verdict != "false_positive" or not inv.rule_name:
        return None
    rows = await rd.open_false_positives(db, threshold=threshold, rule_names=[inv.rule_name])
    mine = next((row for row in rows if row.id == inv.id), None)
    if mine is None:
        return None
    return RuleDecisionRefOut(href=rd.rule_href(inv.rule_name), count=len(rows), group=mine.group)


__all__ = [
    "RULE_ACTION",
    "SUMMARY_TTL_S",
    "GroupOut",
    "RuleDecisionIn",
    "RuleDecisionOut",
    "RuleDecisionsOut",
    "RulePageOut",
    "RuleSummary",
    "decide_rule",
    "end_rule_decision",
    "get_rule_decision",
    "list_rule_decisions",
    "record_out",
    "rule_decision_ref",
    "rule_summaries",
    "rule_why",
]
