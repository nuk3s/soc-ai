"""The facts of one Needs you item, so the row is prepared for a decision.

``GET /needs-you/items`` listed a title, one sentence and a time for each
decision. The analyst opened each item to learn what it was: the dogfood of
2026-11-17 found the live lead as row 31 of 31, under 30 investigations of
134 days, and no row stated a verdict, an impact or a machine.

Each item now states its verdict, confidence, impact, severity, machines,
event time, why it waits and the action that waits with what that action
writes. A value that soc-ai does not hold is None, never a guess: a lead has
no verdict, the item of the alert groups names no machine, and a campaign has
no confidence of its own.

The readers here are batch reads for one list, one or two queries for every
type. Each takes the ids of the items it fills.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select

from soc_ai.campaigns.facts import chunked
from soc_ai.store import first_line as first_line_svc
from soc_ai.store.models import CampaignMember, Investigation, InvestigationEvent
from soc_ai.triage_models import IMPACT_ORDER, TRUE_POSITIVE, is_pipeline_fallback, stored_impact

# The most machines one row names. The rest is a count.
MAX_MACHINES = 3

# The severities a stored alert document can state, the worst first. Any other
# value, and a document with none, is a severity soc-ai does not hold.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")

# The stored context events that hold the alert document of a run.
_CONTEXT_KINDS = ("enriched_alert_context", "alert_context")

# The entity types of a lead that name a machine.
_MACHINE_ENTITY_KINDS = frozenset({"host", "ip", "address"})


class NeedsYouMachineOut(BaseModel):
    """One machine of an item: its name and its address, each None when not held."""

    name: str | None = None
    address: str | None = None


class NeedsYouActionOut(BaseModel):
    """The action that waits on an item, and what the action writes.

    ``label`` is the words of the button. ``writes`` states what the action
    changes, and where: in soc-ai, or in Security Onion.
    """

    label: str
    writes: str


# ── The actions ────────────────────────────────────────────────────────────

# What each recommended action writes. The keys are the tags of the action
# card (soc_ai.api.webui._timeline._ACTION_TAG).
_ACTION_WRITES = {
    "ack": "Acknowledges the alert in Security Onion.",
    "escalate": "Opens a case in Security Onion.",
    "comment": "Adds a comment to the Security Onion case.",
}
# The escalate of a promoted finding opens a case from the stored finding.
_FINDING_ESCALATE_WRITES = "Opens a case in Security Onion from the stored finding."

CAMPAIGN_ACTION = NeedsYouActionOut(
    label="Decide on the campaign",
    writes=(
        "soc-ai stores the decision. Close can acknowledge the alerts and Case opens a case "
        "in Security Onion."
    ),
)
VERDICT_ACTION = NeedsYouActionOut(
    label="Set the verdict",
    writes="soc-ai stores the verdict. Nothing goes to Security Onion.",
)
LEAD_DECIDE_ACTION = NeedsYouActionOut(
    label="Decide on the lead",
    writes="Dismiss closes the lead in soc-ai. Promote starts an investigation.",
)
LEAD_HUNT_ACTION = NeedsYouActionOut(
    label="Hunt the lead",
    writes="soc-ai starts a hunt. Nothing goes to Security Onion.",
)
# A true positive that waits with no action that the console can execute
# (round "decide once" part 2, OW2). The card "No automatic action" of the
# investigation page offers the acknowledge and the escalate.
NO_ACTION_ACTION = NeedsYouActionOut(
    label="Acknowledge or escalate",
    writes="The analyst decides on the investigation page.",
)
ALERTS_ACTION = NeedsYouActionOut(
    label="Set a verdict on each group",
    writes=(
        "An investigation stores a verdict in soc-ai. An acknowledgement writes to Security Onion."
    ),
)


# The tags of the waiting actions, the largest effect first (round "decide
# once" part 2, OW3). An escalate opens a case, an acknowledge closes the
# alert, and a comment adds text to a case that exists.
_EFFECT_ORDER = ("escalate", "ack", "comment")


def _effect_rank(action: Any) -> int:
    tag = str(getattr(action, "type", "") or "")
    return _EFFECT_ORDER.index(tag) if tag in _EFFECT_ORDER else len(_EFFECT_ORDER)


def waiting_action(waiting: Sequence[Any]) -> NeedsYouActionOut | None:
    """The waiting action of a run with the largest effect, as the row states it, or None.

    ``waiting`` holds the :class:`~soc_ai.api.webui._timeline.WaitingActionOut`
    of the run, under the one action rule. An escalate comes before an
    acknowledge: a row of production stated the acknowledge of a true
    positive whose investigation also recommended an escalate (dogfood
    2026-11-17, N6). The order of the cards on the investigation page stays
    the order of the report. Two actions of one effect keep that order.
    """
    if not waiting:
        return None
    first = min(waiting, key=_effect_rank)
    tag = str(getattr(first, "type", "") or "")
    writes = _ACTION_WRITES.get(tag)
    if tag == "escalate" and getattr(first, "targetType", None) == "finding":
        writes = _FINDING_ESCALATE_WRITES
    label = str(getattr(first, "label", "") or "")
    if writes is None or not label:
        return None
    return NeedsYouActionOut(label=label, writes=writes)


# ── The words of why an item waits ─────────────────────────────────────────


def _plural(n: int, one: str, many: str) -> str:
    return f"{n:,} {one if n == 1 else many}"


CAMPAIGN_WHY = "The campaign has no decision."
VERDICT_WHY = "The verdict needs more info."
LEAD_HUNTED_WHY = "The hunt of the lead ended, and the lead has no decision."
LEAD_NOT_HUNTED_WHY = "No hunt read the lead, and the lead has no decision."


NO_ACTION_WHY = "soc-ai recommends no action. This true positive waits for a decision."
# soc-ai recommends one or more actions, and the console can execute none of
# them: a text-only action, or a write that a rule blocks.
NO_EXECUTABLE_ACTION_WHY = (
    "soc-ai recommends no action that the console can execute. "
    "This true positive waits for a decision."
)


def no_action_why(report: Any) -> str:
    """Why a true positive with no waiting action waits: the sentence fits its report."""
    recommended = isinstance(report, dict) and bool(report.get("recommended_actions"))
    return NO_EXECUTABLE_ACTION_WHY if recommended else NO_ACTION_WHY


def verdict_why(questions: Sequence[str]) -> str:
    """Why a verdict that needs more info waits: what soc-ai needs to know.

    ``questions`` is the list of open questions that the investigation page
    shows (:func:`open_questions_by_run`). The row read "The verdict needs
    more info." and stated no missing fact (round 3 part 2, P2). The first
    question stands whole. A report with no open question says so.
    """
    cleaned = [q.strip() for q in questions if q and q.strip()]
    if not cleaned:
        return f"{VERDICT_WHY} The investigation states no open question."
    first = cleaned[0] if cleaned[0].endswith((".", "?", "!")) else f"{cleaned[0]}."
    if len(cleaned) == 1:
        return f"{VERDICT_WHY} Open question: {first}"
    return f"{VERDICT_WHY} The first of {len(cleaned):,} open questions: {first}"


async def open_questions_by_run(db: Any, runs: Sequence[Investigation]) -> dict[str, list[str]]:
    """The open questions of each run, keyed by run id.

    The list is the one that the investigation page shows
    (:func:`_timeline._open_questions_out`): the evidence that a gate found
    missing, then the questions of the report, else of the transcript. The
    transcript is large, so the read takes its ``open_questions`` key alone.
    """
    from soc_ai.agent.gates import VERDICT_CHANGE_GATES  # noqa: PLC0415 - heavy
    from soc_ai.api.webui import _timeline  # noqa: PLC0415 - the module is large

    gate_kinds = [key for key, _field in VERDICT_CHANGE_GATES]
    events: dict[str, list[tuple[int, Any]]] = {}
    ids = sorted({str(inv.id) for inv in runs})
    for chunk in chunked(ids):
        rows = await db.execute(
            select(
                InvestigationEvent.investigation_id,
                InvestigationEvent.sequence,
                InvestigationEvent.payload["open_questions"],
            ).where(
                InvestigationEvent.investigation_id.in_(chunk),
                InvestigationEvent.kind == _TRANSCRIPT_KIND,
            )
        )
        for run_id, seq, questions in rows.all():
            payload = {"open_questions": questions}
            event = SimpleNamespace(kind=_TRANSCRIPT_KIND, payload=payload)
            events.setdefault(str(run_id), []).append((seq, event))
        gates = await db.execute(
            select(InvestigationEvent).where(
                InvestigationEvent.investigation_id.in_(chunk),
                InvestigationEvent.kind.in_(gate_kinds),
            )
        )
        for row in gates.scalars():
            events.setdefault(str(row.investigation_id), []).append((row.sequence, row))
    out: dict[str, list[str]] = {}
    for inv in runs:
        report = inv.report if isinstance(inv.report, dict) else {}
        ordered = [e for _seq, e in sorted(events.get(str(inv.id), []), key=lambda p: p[0])]
        out[str(inv.id)] = _timeline._open_questions_out(report, ordered)
    return out


_TRANSCRIPT_KIND = "investigation_transcript"


def actions_why(count: int) -> str:
    """Why an investigation with waiting actions waits."""
    return f"{_plural(count, 'recommended action waits', 'recommended actions wait')} for a person."


def beyond_why(title: str, count: int) -> str:
    """Why an investigation beyond the authorization of its campaign waits.

    One sentence holds the two facts: the row states ``why`` in place of
    ``detail``, and the count of the waiting actions must stay on the row.
    """
    head = f"The investigation is beyond the authorization of the campaign {title}"
    if not count:
        return f"{head}."
    waits = _plural(count, "recommended action waits", "recommended actions wait")
    return f"{head}, and {waits} for a person."


def alerts_why(count: int, floor: bool, window_words: str) -> str:
    """Why the item of the alert groups waits."""
    lead = "At least " if floor else ""
    groups = _plural(count, "alert group has", "alert groups have")
    return f"{lead}{groups} no verdict in the last {window_words}."


# ── Impact and severity ────────────────────────────────────────────────────


def run_impact(inv: Any) -> str | None:
    """The stored impact of a true positive, or None."""
    report = getattr(inv, "report", None)
    if is_pipeline_fallback(report):
        return None
    return stored_impact(report, getattr(inv, "verdict", None))


def worst_impact(values: Iterable[str | None]) -> str | None:
    """The worst stated impact, or None when no value states one."""
    stated = [v for v in values if v in IMPACT_ORDER]
    return min(stated, key=IMPACT_ORDER.index) if stated else None


def worst_severity(values: Iterable[str | None]) -> str | None:
    """The worst stated severity, or None when no value states one."""
    stated = [v for v in values if v in SEVERITY_ORDER]
    return min(stated, key=SEVERITY_ORDER.index) if stated else None


async def run_severities(db: Any, run_ids: Iterable[str]) -> dict[str, str]:
    """The severity of the alert document that each run stored, keyed by run id.

    The severity is ``severity_label`` of the stored alert context. A run with
    no context, and a label outside :data:`SEVERITY_ORDER`, has no entry.
    """
    label = InvestigationEvent.payload["alert"]["severity_label"].as_string()
    out: dict[str, str] = {}
    for ids in chunked(sorted({str(r) for r in run_ids if r})):
        rows = await db.execute(
            select(InvestigationEvent.investigation_id, label).where(
                InvestigationEvent.investigation_id.in_(ids),
                InvestigationEvent.kind.in_(_CONTEXT_KINDS),
            )
        )
        for run_id, value in rows.all():
            word = str(value or "").strip().lower()
            if word in SEVERITY_ORDER:
                current = out.get(str(run_id))
                out[str(run_id)] = worst_severity([current, word]) or word
    return out


async def campaign_impacts_and_severities(
    db: Any, campaign_ids: Iterable[int]
) -> dict[int, tuple[str | None, str | None]]:
    """(impact, severity) of each campaign: the worst of its true positive investigations.

    An investigation whose verdict differs from the campaign gives nothing.
    A campaign whose investigations state no impact has the impact None.
    """
    members: dict[int, list[str]] = {}
    for cids in chunked(sorted({int(c) for c in campaign_ids})):
        rows = await db.execute(
            select(CampaignMember.campaign_id, CampaignMember.run_id).where(
                CampaignMember.campaign_id.in_(cids), CampaignMember.verdict_differs.is_(False)
            )
        )
        for cid, run_id in rows.all():
            members.setdefault(int(cid), []).append(str(run_id))
    run_ids = sorted({r for runs in members.values() for r in runs})
    impacts: dict[str, str | None] = {}
    for ids in chunked(run_ids):
        found = await db.execute(
            select(Investigation.id, Investigation.verdict, Investigation.report).where(
                Investigation.id.in_(ids), Investigation.verdict == TRUE_POSITIVE
            )
        )
        for run_id, verdict, report in found.all():
            impacts[str(run_id)] = (
                None if is_pipeline_fallback(report) else stored_impact(report, verdict)
            )
    severities = await run_severities(db, run_ids)
    return {
        cid: (
            worst_impact(impacts.get(r) for r in runs),
            worst_severity(severities.get(r) for r in runs),
        )
        for cid, runs in members.items()
    }


# ── Machines ───────────────────────────────────────────────────────────────


def machine_of(
    value: str, labels: Mapping[str, first_line_svc.HostLabel]
) -> NeedsYouMachineOut | None:
    """One address or host name as a machine, with what the Hosts data adds."""
    text = value.strip()
    if not text:
        return None
    label = labels.get(text)
    if first_line_svc.is_address(text):
        return NeedsYouMachineOut(name=label.name if label else None, address=text)
    return NeedsYouMachineOut(name=text, address=label.address if label else None)


def capped(
    machines: Sequence[NeedsYouMachineOut], more: int = 0
) -> tuple[list[NeedsYouMachineOut] | None, int]:
    """At most :data:`MAX_MACHINES` machines, each once, and the count of the rest.

    No machine gives None: the item names none that soc-ai holds.
    """
    seen: set[tuple[str | None, str | None]] = set()
    unique: list[NeedsYouMachineOut] = []
    for machine in machines:
        key = (machine.name, machine.address)
        if key in seen:
            continue
        seen.add(key)
        unique.append(machine)
    if not unique:
        return None, max(0, more)
    return unique[:MAX_MACHINES], max(0, len(unique) - MAX_MACHINES) + max(0, more)


def run_machine_values(inv: Any) -> list[str]:
    """The addresses and names of a run: its source, then its target."""
    return first_line_svc.run_values(inv)


def run_directed(inv: Any, machines: Sequence[NeedsYouMachineOut] | None) -> bool:
    """True when the run holds a source and a target, and ``machines`` names the two in order.

    A row shows a direction only then (round "decide once" part 2, OW5). A
    finding run with no pair names its hosts, and the row shows no arrow.
    """
    source, target = first_line_svc.run_ends(inv)
    if not source or not target or source == target or not machines or len(machines) != 2:
        return False
    first, second = machines

    def names(machine: NeedsYouMachineOut, value: str) -> bool:
        return value in (machine.name, machine.address)

    return names(first, source) and names(second, target)


def lead_machine_values(entities: Any) -> list[str]:
    """The entity values of a lead that name a machine: a host or an address."""
    out: list[str] = []
    for entity in entities or []:
        if not isinstance(entity, list | tuple) or len(entity) != 2:
            continue
        kind, value = entity
        if str(kind or "").strip().lower() in _MACHINE_ENTITY_KINDS and str(value or "").strip():
            out.append(str(value).strip())
    return out


async def labels_for(db: Any, settings: Any, values: Iterable[str]) -> dict[str, Any]:
    """The Hosts data labels of the values, keyed as given. A failed read gives none."""
    wanted = [v for v in values if v]
    if not wanted:
        return {}
    return await first_line_svc.labels_for_settings(db, wanted, settings)


# ── Times ──────────────────────────────────────────────────────────────────


def iso(value: datetime | None) -> str | None:
    """A stored time as ISO-8601 UTC, or None."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _moment(value: str | None) -> float | None:
    """An ISO time as epoch seconds, or None when it does not parse."""
    if not value:
        return None
    try:
        at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.timestamp()


# ── The order of the list ──────────────────────────────────────────────────

# The groups of the list, the most important first (NY2). A campaign is the
# unit of work. A true positive investigation comes before a lead, because its
# verdict is a fact and a lead is a question. The alert groups end the list:
# they are one item for many groups with no verdict. A rule with open false
# positives comes after the other investigations and before the alert groups
# (round 3, RS3).
GROUP_CAMPAIGN = 0
GROUP_TRUE_POSITIVE = 1
GROUP_LEAD = 2
GROUP_OTHER = 3
GROUP_RULE = 4
GROUP_ALERTS = 5

# An impact that the item does not state sorts as "unknown": the rule of the
# verdict sort of the Investigations list (inv_svc.SORT_VERDICT).
_UNKNOWN_IMPACT = IMPACT_ORDER.index("unknown")


def group_of(item_type: str, verdict: str | None) -> int:
    """The group of an item in the order of the list."""
    if item_type == "campaign":
        return GROUP_CAMPAIGN
    if item_type == "investigation":
        return GROUP_TRUE_POSITIVE if verdict == TRUE_POSITIVE else GROUP_OTHER
    if item_type == "lead":
        return GROUP_LEAD
    if item_type == "rule":
        return GROUP_RULE
    return GROUP_ALERTS


def order_key(item: Any) -> tuple[int, int, int, float, str, str]:
    """The sort key of one item: group, impact, severity, newest event, then type and id.

    Inside a group the impact decides first: succeeded, attempted, unknown,
    none. An item with no impact sorts as unknown, so a group with no impact
    at all sorts by severity and time. Then the severity, the worst first,
    with no severity last. Then the newest event first, with no event time
    last. The type and the id keep the order stable.

    Inside the group of the rules, the count of the group ``confident``
    decides first, the largest first, and then the newest event.
    """
    impact = getattr(item, "impact", None)
    severity = getattr(item, "severity", None)
    moment = _moment(getattr(item, "eventAt", None))
    if str(getattr(item, "type", "")) == "rule":
        return (
            GROUP_RULE,
            -int(getattr(item, "confident", 0) or 0),
            0,
            -moment if moment is not None else float("inf"),
            "rule",
            str(getattr(item, "id", "")),
        )
    return (
        group_of(str(getattr(item, "type", "")), getattr(item, "verdict", None)),
        IMPACT_ORDER.index(impact) if impact in IMPACT_ORDER else _UNKNOWN_IMPACT,
        SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER),
        -moment if moment is not None else float("inf"),
        str(getattr(item, "type", "")),
        str(getattr(item, "id", "")),
    )
